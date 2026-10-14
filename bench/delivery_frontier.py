"""Offline original-record ledger for frozen server-to-client WAN campaigns.

No sockets, SSH, subprocesses, or runtime changes. This tool audits accounting,
not network capacity: a full local queue may be caused by host service, pacing,
transport congestion, or downstream pressure. It never calls that CPU loss.
Run: python3 -m bench.delivery_frontier --campaign PATH --output NEW_PATH
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path


MAX_JSON_BYTES = 64 * 1024 * 1024
DIRECTION = "server_to_client"


class EvidenceError(ValueError):
    """Input does not support the requested, narrow accounting interpretation."""


def integer(value, label):
    if type(value) is not int or value < 0:
        raise EvidenceError(label + " must be a nonnegative integer")
    return value


def count(mapping, key):
    if key not in mapping:
        raise EvidenceError("missing counter: " + key)
    return integer(mapping[key], key)


def finite(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(label + " must be numeric")
    if not math.isfinite(value) or value < 0:
        raise EvidenceError(label + " must be finite and nonnegative")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON key: " + key)
        result[key] = value
    return result


def _reject_constant(value):
    raise EvidenceError("nonfinite JSON number: " + value)


def read_json(path, hashes):
    path = Path(path)
    if path.stat().st_size > MAX_JSON_BYTES:
        raise EvidenceError("JSON input exceeds 64 MiB: " + str(path))
    raw = path.read_bytes()
    hashes[str(path.resolve())] = hashlib.sha256(raw).hexdigest()
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)


def record_ledger(direction):
    """Mutually exclusive first-pass dispositions, never repairs-as-records.

    This contract is the server return path, not the client's combined ingress
    channel. Encoding failures can also originate from a timer flush; reject
    those rather than treating the counter as a per-record loss attribution.
    """
    r, s = direction["records"], direction["symbols"]
    if count(r, "encoding_dropped"):
        raise EvidenceError("encoding error counter is not record-attributable")
    if count(r, "application_flow_limit_dropped"):
        raise EvidenceError("unexpected server-return flow-limit counter")
    groups = {
        "before_ingress": ["application_oversize_dropped", "ingress_queue_full_dropped",
                           "ingress_queue_closed_dropped"],
        "before_sender_enqueue": ["application_unavailable_dropped", "ingress_shutdown_dropped",
                                  "sender_queue_full_dropped", "sender_queue_closed_dropped"],
        "unconsumed_sender_input": ["input_shutdown_dropped"],
    }
    losses = {name: sum(count(r, k) for k in keys) for name, keys in groups.items()}
    losses["expired_before_encoding"] = count(s, "originals_ingress_expired_dropped")
    losses["encoded_original_queue_full"] = count(s, "originals_queue_full_dropped")
    losses["encoded_original_expired"] = count(s, "originals_expired_dropped")
    losses["encoded_original_shutdown"] = count(s, "originals_shutdown_dropped")
    nodes = {
        "application_received": count(r, "application_received"),
        "ingress_enqueued": count(r, "ingress_queue_enqueued"),
        "sender_enqueued": count(r, "sender_queue_enqueued"),
        "sender_consumed": count(r, "sender_input_consumed"),
        "originals_generated": count(s, "originals_generated"),
        "originals_enqueued": count(s, "originals_enqueued"),
        "originals_quinn_api_admitted": count(s, "originals_quinn_admitted"),
    }
    edges = [
        ("application_received", "ingress_enqueued", losses["before_ingress"]),
        ("ingress_enqueued", "sender_enqueued", losses["before_sender_enqueue"]),
        ("sender_enqueued", "sender_consumed", losses["unconsumed_sender_input"]),
        ("sender_consumed", "originals_generated", losses["expired_before_encoding"]),
        ("originals_generated", "originals_enqueued", losses["encoded_original_queue_full"]),
        ("originals_enqueued", "originals_quinn_api_admitted",
         losses["encoded_original_expired"] + losses["encoded_original_shutdown"]),
    ]
    balances = [{"from": left, "to": right, "disposed": dropped,
                 "residual": nodes[left] - nodes[right] - dropped}
                for left, right, dropped in edges]
    if any(item["residual"] for item in balances):
        raise EvidenceError("original-record ledger does not close: " + json.dumps(balances))
    pre = sum(losses[k] for k in ["before_ingress", "before_sender_enqueue",
                                 "unconsumed_sender_input", "expired_before_encoding"])
    total = sum(losses.values())
    population = nodes["application_received"]
    return {
        "nodes_records": nodes, "dispositions_records": losses, "balances": balances,
        "pre_encoding_disposed_records": pre,
        "encoded_original_disposed_records": total - pre,
        "all_local_first_pass_disposed_records": total,
        "local_first_pass_disposition_fraction": total / population if population else None,
        "api_original_admission_fraction": nodes["originals_quinn_api_admitted"] / population
                                           if population else None,
        "repair_symbols_separate": {k: count(s, k) for k in [
            "repairs_generated", "repairs_enqueued", "repairs_queue_full_dropped",
            "repairs_quinn_admitted", "repairs_budget_skipped", "repairs_expired_dropped",
            "repairs_shutdown_dropped"]},
        "interpretation": {
            "pre_encoding_disposals_never_entered_fec": True,
            "encoded_original_disposal_may_still_be_recovered": True,
            "api_admission_is_wire_transmission": False,
            "local_disposition_is_proof_of_cpu_bottleneck": False,
            "raw_udp_capacity_inferred": False,
        },
    }


def closed_endpoint(value, role):
    if value.get("role") != role or value.get("final") is not True or value.get("error"):
        raise EvidenceError("endpoint must be the expected final error-free role")
    if value.get("outcome") not in ("ok", "stopped"):
        raise EvidenceError("endpoint outcome is not a successful final outcome")
    stats = value["stats"]
    if stats.get("shutdown_complete") is not True or stats.get("drain_incomplete") is not False:
        raise EvidenceError("endpoint has unclosed shutdown accounting")
    for key in ["omitted_session_scopes", "evicted_session_scopes", "omitted_path_scopes"]:
        if count(stats, key):
            raise EvidenceError("incomplete session/path census: " + key)
    sessions = stats["sessions"]
    if len(sessions) != 1:
        raise EvidenceError("only one-session experiment windows are supported")
    return stats, next(iter(sessions))


def timeline_census(path):
    """Sample-count diagnostic only. Do not turn buffer availability into cwnd readiness."""
    sha = hashlib.sha256()
    previous = {}
    counts = {}
    with Path(path).open("rb") as stream:
        for raw in stream:
            if len(raw) > MAX_JSON_BYTES:
                raise EvidenceError("timeline row exceeds 64 MiB")
            sha.update(raw)
            row = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            for key, item in row["stats"].get("paths", {}).items():
                a = item.get("adaptive") or {}
                control = a.get("last_control") or {}
                if not control or "at_us" not in control:
                    continue
                at = integer(control["at_us"], "at_us")
                identity = (item.get("connection_id"), control.get("generation"), at)
                if previous.get(key) == identity:
                    continue
                previous[key] = identity
                c = counts.setdefault(key, Counter())
                c["distinct_control_snapshots"] += 1
                backlog = control.get("offered_backlog")
                blocked = control.get("transport_blocked")
                if backlog is True:
                    c["backlog_snapshots"] += 1
                if backlog is True and blocked is False:
                    c["backlog_with_api_buffer_not_full"] += 1
                    if control.get("queue_delay_ms") is not None:
                        delay = finite(control["queue_delay_ms"], "queue_delay_ms")
                        if delay <= 5:
                            c["backlog_api_buffer_not_full_delay_estimate_at_most_5ms"] += 1
                service = control.get("service_admission") or {}
                if service.get("deficit") is True:
                    c["controller_reported_service_deficit"] += 1
    return {
        "paths": counts,
        "sha256": sha.hexdigest(),
        "unit": "distinct sampled last_control records, NOT durations or packet percentages",
        "limiter_owner_identified": False,
        "missing_for_identification": ["exact per-opportunity rejecting gate",
                                      "transport bytes in flight / cwnd allowance",
                                      "API-admission to socket-transmission timing",
                                      "same-cohort useful original delivery"],
    }


def audit_window(root, item, hashes, timeline=False):
    label = item["window"]
    if not isinstance(label, str) or not label or Path(label).name != label or label in (".", ".."):
        raise EvidenceError("window label must be one relative path component")
    directory = root / label
    # An attempted row is not a completed business window.
    if not (directory / "metrics.json").exists():
        return {"window": label, "variant": item["variant"],
                "status": "no_completed_metrics", "has_jobs": (directory / "jobs.json").exists()}
    completion = read_json(directory / "completion.json", hashes)
    if not {"error", "cleanup_errors", "cleanup_unconfirmed"} <= completion.keys():
        raise EvidenceError("missing window completion fields")
    if completion["error"] is not None or completion["cleanup_errors"] != [] or completion["cleanup_unconfirmed"] != []:
        raise EvidenceError("window cleanup/error status is not complete")
    tx, session = closed_endpoint(read_json(directory / "server/stats.json", hashes), "server")
    rx, peer_session = closed_endpoint(read_json(directory / "client/stats.json", hashes), "client")
    if session != peer_session:
        raise EvidenceError("endpoint sessions do not match")
    ledger = record_ledger(tx["directions"][DIRECTION])
    # Session and aggregate must describe the same population, not duplicated sums.
    session_ledger = record_ledger(tx["sessions"][session][DIRECTION])
    if ledger != session_ledger:
        raise EvidenceError("session and process return ledgers differ")
    metrics = read_json(directory / "metrics.json", hashes)
    receiver = rx["directions"][DIRECTION]["records"]
    observed = {k: count(receiver, k) for k in [
        "original_packets_received", "original_records_delivered", "fec_records_recovered",
        "repair_symbols_received", "deduplicated", "receiver_queue_full_dropped",
        "invalid_symbols_dropped", "udp_target_delivered", "udp_target_send_dropped"]}
    result = {"window": label, "variant": item["variant"], "status": "closed_ledger",
              "population": "all server-return records, including bulk, echo and control records",
              "sender": ledger, "receiver_counts_separate": observed,
              "application_metrics_separate": {k: metrics[k] for k in ["bulk", "interactive"]},
              "network_loss_probability": None, "capacity_upper_bound_bps": None,
              "per_path_failure_correlation": None,
              "limitations": ["No bulk-only stage attribution from mixed counters",
                              "A recovered record is not a counterfactual net saved record",
                              "No known API-to-wire loss location",
                              "No per-path capacity without a controlled supply intervention"]}
    if timeline:
        census = timeline_census(directory / "server/stats.jsonl")
        hashes[str((directory / "server/stats.jsonl").resolve())] = census["sha256"]
        result["sampled_supply_evidence"] = census
    return result


def audit_campaign(root, timeline=False):
    root = Path(root).resolve()
    hashes = {}
    registration = read_json(root / "registration.json", hashes)
    wrapper = read_json(root / "wrapper-completion.json", hashes)
    order = registration["conditions"]["order"]
    if not order or len(order) > 32 or len({item["window"] for item in order}) != len(order):
        raise EvidenceError("invalid or unbounded registered window order")
    windows = [audit_window(root, item, hashes, timeline) for item in order]
    return {
        "schema_version": 1, "generated_utc": datetime.now(timezone.utc).isoformat(),
        "campaign": str(root), "wrapper_status": wrapper["status"],
        "continuous_protection_passed": wrapper.get("continuous_protection_passed") is True,
        "registered_windows": len(order),
        "completed_business_windows": sum(w["status"] == "closed_ledger" for w in windows),
        "windows": windows, "input_sha256": hashes,
        "scope": "offline accounting only; no cross-window causal comparison or runtime promotion",
        "source_binary_and_collector_hash_chain_revalidated": False,
        "network_operations": 0,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeline", action="store_true")
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError("refusing to replace prior evidence: " + str(args.output))
    value = audit_campaign(args.campaign, args.timeline)
    with args.output.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
    for window in value["windows"]:
        row = {k: window[k] for k in ["window", "variant", "status"]}
        if window["status"] == "closed_ledger":
            row.update({k: window["sender"][k] for k in [
                "pre_encoding_disposed_records", "encoded_original_disposed_records",
                "local_first_pass_disposition_fraction", "api_original_admission_fraction"]})
        print(json.dumps(row))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
