"""Readiness gates for schema-v1 stats; no logs or infrastructure configuration.

The caller supplies the launched PID and an attempt start timestamp from the same
host clock as sample_unix_ms. An optional known instance_id is checked exactly;
otherwise the first fresh snapshot pins it for this wait. Server path readiness
must use the session_id returned by client readiness.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable, Mapping
import math
import time
from typing import Any


@dataclass(frozen=True)
class ReadinessRequirement:
    role: str
    process_id: int
    started_unix_ms: int
    expected_path_ids: tuple[int, ...] = ()
    session_id: str | None = None
    instance_id: str | None = None

    def __post_init__(self):
        if self.role not in {"client", "server", "relay"}:
            raise ValueError("role must be client, server or relay")
        if type(self.process_id) is not int or self.process_id <= 0:
            raise ValueError("process_id must be the launched positive PID")
        if type(self.started_unix_ms) is not int or self.started_unix_ms < 0:
            raise ValueError("started_unix_ms must be a host-clock timestamp")
        if any(type(p) is not int or p < 0 for p in self.expected_path_ids):
            raise ValueError("expected path IDs must be nonnegative integers")
        if len(set(self.expected_path_ids)) != len(self.expected_path_ids):
            raise ValueError("expected path IDs must be unique")
        if self.role == "client" and not self.expected_path_ids:
            raise ValueError("client readiness requires expected path IDs")
        if self.role == "server" and self.expected_path_ids and not self.session_id:
            raise ValueError("server path readiness requires the client session ID")
        if self.role == "relay" and self.expected_path_ids:
            raise ValueError("relay readiness has no authenticated paths")
        if self.instance_id is not None and not self.instance_id:
            raise ValueError("instance_id cannot be empty")


@dataclass(frozen=True)
class ProcessSample:
    snapshot: Mapping[str, Any] | None
    process_alive: bool
    process_id: int | None


@dataclass(frozen=True)
class ReadinessResult:
    ready: bool
    reason: str
    waited_seconds: float
    session_id: str | None
    instance_id: str | None
    snapshot: Mapping[str, Any] | None
    detail: str | None = None


def _path_status(stats, requirement):
    paths = stats.get("paths")
    if not isinstance(paths, Mapping):
        return "fail", "invalid_paths", None
    live = []
    for path in paths.values():
        if not isinstance(path, Mapping) or not isinstance(path.get("quinn"), Mapping):
            return "fail", "invalid_path", None
        sid, pid = path.get("session_id"), path.get("path_id")
        if not isinstance(sid, str) or not sid or type(pid) is not int:
            return "fail", "invalid_path_identity", None
        if type(path["quinn"].get("closed")) is not bool:
            return "fail", "invalid_path_state", None
        if requirement.role == "server" and sid != requirement.session_id:
            continue
        if not path["quinn"]["closed"] and path.get("authenticated") is True:
            live.append((sid, pid))
    sessions = {sid for sid, _ in live}
    if len(sessions) > 1:
        return "wait", "mixed_sessions", None
    session = next(iter(sessions), None)
    if requirement.session_id and session != requirement.session_id:
        return "wait", "session_not_ready", session
    ids = [pid for _, pid in live]
    if len(ids) != len(set(ids)):
        return "fail", "duplicate_path_ids", session
    expected = set(requirement.expected_path_ids)
    if not expected.issubset(ids):
        return "wait", "missing_paths", session
    if set(ids) != expected:
        return "fail", "unexpected_paths", session
    return "ready", "ready", session


def wait_for_ready(
    poll: Callable[[float], ProcessSample],
    requirement: ReadinessRequirement,
    timeout_seconds: float,
    *,
    poll_interval_seconds: float = 0.1,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> ReadinessResult:
    """Poll once per interval within one monotonic deadline; never retry an attempt.

    poll(remaining_seconds) returns parsed stats and live process information. It
    must bound its own I/O by that remaining budget: synchronous callbacks cannot
    be interrupted here. A callback returning after the deadline cannot succeed.
    No workload is started by this function; callers must check result.ready.
    """
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be finite and positive")
    if not math.isfinite(poll_interval_seconds) or poll_interval_seconds <= 0:
        raise ValueError("poll_interval_seconds must be finite and positive")
    started = monotonic()
    deadline = started + timeout_seconds
    instance = requirement.instance_id
    session = None
    snapshot = None
    pending = "snapshot_missing"

    def result(ready, reason, detail=None):
        return ReadinessResult(
            ready, reason, monotonic() - started, session, instance, snapshot, detail
        )

    while monotonic() < deadline:
        try:
            observation = poll(deadline - monotonic())
        except Exception as error:
            return result(False, "poll_failed", f"{type(error).__name__}: {error}")
        snapshot = observation.snapshot
        if monotonic() >= deadline:
            return result(False, "timeout", "poll_overran_deadline")
        if not observation.process_alive:
            return result(False, "process_exited")
        if observation.process_id != requirement.process_id:
            return result(False, "process_replaced")
        if snapshot is None:
            pending = "snapshot_missing"
        elif not isinstance(snapshot, Mapping):
            return result(False, "invalid_snapshot")
        elif snapshot.get("process_id") != requirement.process_id:
            pending = "stale_process_snapshot"
        elif type(snapshot.get("sample_unix_ms")) is not int:
            return result(False, "invalid_sample_timestamp")
        elif snapshot["sample_unix_ms"] < requirement.started_unix_ms:
            pending = "stale_attempt_snapshot"
        elif not isinstance(snapshot.get("instance_id"), str) or not snapshot["instance_id"]:
            return result(False, "invalid_instance_id")
        elif instance is not None and snapshot["instance_id"] != instance:
            pending = "stale_instance_snapshot"
        elif snapshot.get("schema_version") != 1:
            return result(False, "unsupported_schema")
        elif snapshot.get("role") != requirement.role:
            return result(False, "role_mismatch")
        else:
            instance = snapshot["instance_id"]
            if snapshot.get("final") is not False or snapshot.get("outcome") != "running":
                return result(False, "process_finished")
            stats = snapshot.get("stats")
            if not isinstance(stats, Mapping):
                return result(False, "invalid_stats")
            if stats.get("listener_bound") is not True:
                pending = "listener_not_bound"
            elif stats.get("target_configured") is not True:
                pending = "target_not_configured"
            elif stats.get("ready") is not True:
                pending = "not_ready"
            elif requirement.role == "client" and stats.get("configured_paths") != len(requirement.expected_path_ids):
                return result(False, "configured_paths_mismatch")
            elif requirement.expected_path_ids:
                status, pending, session = _path_status(stats, requirement)
                if status == "ready":
                    return result(True, "ready")
                if status == "fail":
                    return result(False, pending)
            else:
                return result(True, "ready")
        remaining = deadline - monotonic()
        if remaining > 0:
            sleep(min(poll_interval_seconds, remaining))
    return result(False, "timeout", pending)
