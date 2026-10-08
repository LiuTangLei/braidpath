"""Offline readiness contracts: fake clock, snapshots and process lifecycle."""

import copy
import unittest

from bench.readiness import ProcessSample, ReadinessRequirement, wait_for_ready


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def snapshot(role="client", ids=(0, 1, 2), session="session-a"):
    return {
        "schema_version": 1,
        "role": role,
        "final": False,
        "outcome": "running",
        "process_id": 123,
        "instance_id": "instance-a",
        "sample_unix_ms": 1000,
        "stats": {
            "ready": True,
            "listener_bound": True,
            "target_configured": True,
            "configured_paths": 3 if role == "client" else 0,
            "paths": {
                f"{session}/{pid}": {
                    "session_id": session,
                    "path_id": pid,
                    "authenticated": True,
                    "quinn": {"closed": False},
                }
                for pid in ids
            },
        },
    }


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.requirement = ReadinessRequirement("client", 123, 1000, (0, 1, 2))
        self.budgets = []

    def wait(self, source, requirement=None, timeout=3):
        def poll(remaining):
            self.budgets.append(remaining)
            value = source(self.clock.now)
            return value if isinstance(value, ProcessSample) else ProcessSample(value, True, 123)

        return wait_for_ready(
            poll,
            requirement or self.requirement,
            timeout,
            poll_interval_seconds=1,
            monotonic=self.clock.monotonic,
            sleep=self.clock.sleep,
        )

    def test_success_pins_identity_and_session(self):
        result = self.wait(lambda _: snapshot())
        self.assertTrue(result.ready)
        self.assertEqual(result.reason, "ready")
        self.assertEqual(result.session_id, "session-a")
        self.assertEqual(result.instance_id, "instance-a")
        self.assertEqual(self.budgets, [3])

    def test_delayed_ready_uses_one_total_deadline(self):
        pending = snapshot()
        pending["stats"]["ready"] = False
        result = self.wait(lambda now: pending if now < 2 else snapshot())
        self.assertTrue(result.ready)
        self.assertEqual(result.waited_seconds, 2)
        self.assertEqual(self.budgets, [3, 2, 1])

    def test_partial_paths_never_become_ready(self):
        result = self.wait(lambda _: snapshot(ids=(0, 2)))
        self.assertFalse(result.ready)
        self.assertEqual((result.reason, result.detail), ("timeout", "missing_paths"))
        self.assertEqual(result.waited_seconds, 3)

    def test_early_exit_overrides_ready_snapshot(self):
        result = self.wait(lambda _: ProcessSample(snapshot(), False, 123))
        self.assertEqual(result.reason, "process_exited")
        self.assertEqual(self.budgets, [3])

    def test_replaced_process_cannot_pass(self):
        result = self.wait(lambda _: ProcessSample(snapshot(), True, 456))
        self.assertEqual(result.reason, "process_replaced")

    def test_stale_snapshots_wait_for_current_attempt(self):
        for field, old_value, reason in [
            ("process_id", 456, "stale_process_snapshot"),
            ("sample_unix_ms", 999, "stale_attempt_snapshot"),
            ("instance_id", "old-instance", "stale_instance_snapshot"),
        ]:
            with self.subTest(field=field):
                self.clock.now = 0
                old = snapshot()
                old[field] = old_value
                requirement = ReadinessRequirement("client", 123, 1000, (0, 1, 2), instance_id="instance-a")
                result = self.wait(lambda _: old, requirement)
                self.assertEqual((result.reason, result.detail), ("timeout", reason))
                self.clock.now = 0
                result = self.wait(lambda now: old if now < 1 else snapshot(), requirement)
                self.assertTrue(result.ready)
                self.assertEqual(result.waited_seconds, 1)

    def test_missing_snapshot_times_out_without_retry(self):
        result = self.wait(lambda _: None, timeout=2.5)
        self.assertEqual((result.reason, result.detail), ("timeout", "snapshot_missing"))
        self.assertEqual(self.clock.now, 2.5)
        self.assertEqual(self.budgets, [2.5, 1.5, 0.5])

    def test_slow_poll_cannot_return_success_after_deadline(self):
        def slow(_):
            self.clock.now += 3
            return snapshot()

        result = self.wait(slow)
        self.assertEqual((result.reason, result.detail), ("timeout", "poll_overran_deadline"))

    def test_closed_unauthenticated_and_mixed_paths_cannot_pass(self):
        for changed_field, value in [("closed", True), ("authenticated", False), ("session_id", "other")]:
            with self.subTest(field=changed_field):
                self.clock.now = 0
                bad = snapshot()
                path = bad["stats"]["paths"]["session-a/1"]
                (path["quinn"] if changed_field == "closed" else path)[changed_field] = value
                self.assertFalse(self.wait(lambda _: bad).ready)

    def test_duplicate_path_entries_cannot_satisfy_count(self):
        bad = snapshot(ids=(0, 2))
        bad["stats"]["paths"]["duplicate/0"] = copy.deepcopy(bad["stats"]["paths"]["session-a/0"])
        self.assertEqual(self.wait(lambda _: bad).reason, "duplicate_path_ids")

    def test_server_requires_authenticated_paths_for_client_session(self):
        requirement = ReadinessRequirement("server", 123, 1000, (0, 1, 2), session_id="session-a")
        old = snapshot("server", session="previous-session")
        result = self.wait(lambda _: old, requirement)
        self.assertFalse(result.ready)
        self.clock.now = 0
        current = snapshot("server")
        current["stats"]["paths"].update(old["stats"]["paths"])
        self.assertTrue(self.wait(lambda _: current, requirement).ready)
        self.clock.now = 0
        current["stats"]["paths"]["session-a/1"]["authenticated"] = False
        self.assertFalse(self.wait(lambda _: current, requirement).ready)

    def test_listener_and_target_required_for_server_and_relay(self):
        for role in ("server", "relay"):
            for field in ("listener_bound", "target_configured"):
                with self.subTest(role=role, field=field):
                    self.clock.now = 0
                    requirement = ReadinessRequirement(role, 123, 1000)
                    bad = snapshot(role, ids=())
                    bad["stats"][field] = False
                    self.assertFalse(self.wait(lambda _: bad, requirement).ready)
                    self.clock.now = 0
                    self.assertTrue(self.wait(lambda _: snapshot(role, ids=()), requirement).ready)

    def test_final_snapshot_cannot_pass(self):
        final = snapshot()
        final["final"] = True
        final["outcome"] = "success"
        self.assertEqual(self.wait(lambda _: final).reason, "process_finished")

    def test_requirements_reject_ambiguous_path_ids_and_server_session(self):
        with self.assertRaises(ValueError):
            ReadinessRequirement("client", 123, 1000, (0, 0))
        with self.assertRaises(ValueError):
            ReadinessRequirement("server", 123, 1000, (0, 1, 2))


if __name__ == "__main__":
    unittest.main()
