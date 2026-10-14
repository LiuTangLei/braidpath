"""Offline best-single-connection acceptance for predeclared, normalized windows.

This is an evidence evaluator, not a collector or a network benchmark. Metadata
and byte populations must first be verified by the experiment's raw-data reader.
It never converts an old multipath baseline into a single-connection control.
"""
import math

from bench.delivery_frontier import EvidenceError, finite, integer


COMMON = ("service", "carrier", "native_cc", "crypto", "payload_bytes",
          "total_rate_cap_bps", "offered_payload_bps", "warmup_seconds",
          "deadline_ms", "deadline_basis", "coding_profile", "host_fixture")


def _summary(windows, deadline):
    duration = payload = 0
    delays = []
    for row in windows:
        span = finite(row["actual_source_span_seconds"], "source span")
        if span <= 0:
            raise EvidenceError("positive actual source span required")
        duration += span
        delivered = integer(row["unique_application_payload_bytes"], "delivered payload")
        offered = integer(row["offered_application_payload_bytes"], "offered payload")
        if delivered > offered:
            raise EvidenceError("unique delivered payload exceeds offered cohort")
        payload += delivered
        samples = row["request_rtt_ms"]
        population = integer(row["configured_requests"], "configured requests")
        if not 1 <= population <= 100_000 or len(samples) != population:
            raise EvidenceError("all request slots, including missing, must be present")
        delays.extend(math.inf if value is None else finite(value, "request RTT") for value in samples)
    delays.sort()
    p95 = delays[math.ceil(len(delays) * .95) - 1]
    return {"goodput_bps": payload * 8 / duration,
            "actual_source_span_seconds": duration, "unique_application_payload_bytes": payload,
            "requests": len(delays), "on_time_requests": sum(d <= deadline for d in delays),
            "on_time_fraction": sum(d <= deadline for d in delays) / len(delays),
            "p95_ms": None if math.isinf(p95) else p95,
            "p95_status": "unresolved_missing_population" if math.isinf(p95) else "finite"}


def evaluate(plan, records):
    """Pure topology comparison: coding and all COMMON conditions must match.

    Product comparisons with a different FEC policy need another explicitly
    registered experiment. Suggested ratio 1.5 is an engineering target, not a
    physical law or statistical guarantee. Two windows per mode are screening,
    not independent packet-level trials or release evidence.
    """
    target = finite(plan["minimum_goodput_ratio"], "minimum_goodput_ratio")
    p95_limit = finite(plan["maximum_p95_ratio"], "maximum_p95_ratio")
    completion_target = finite(plan["minimum_on_time_fraction"], "minimum_on_time_fraction")
    if target < 1 or p95_limit <= 0 or not 0 <= completion_target <= 1:
        raise EvidenceError("invalid predeclared ratio targets")
    records = list(records)
    common = plan["common"]
    if not set(COMMON) <= common.keys():
        raise EvidenceError("missing comparison conditions")
    if common["deadline_basis"] != "source_echo_rtt":
        raise EvidenceError("this evaluator requires source-monotonic echo RTT")
    deadline = finite(common["deadline_ms"], "deadline_ms")
    if deadline <= 0:
        raise EvidenceError("positive deadline required")
    modes = plan["modes"]
    candidate = plan["candidate_mode"]
    required_routes = set(plan["required_single_routes"])
    if not 1 <= len(required_routes) <= 8 or candidate not in modes:
        raise EvidenceError("invalid route or candidate population")
    if not 1 <= len(modes) <= 24:
        raise EvidenceError("unbounded mode population")
    singles = []
    same_route_multi = []
    for name, mode in modes.items():
        routes = mode["routes"]
        n = integer(mode["connections"], "connections")
        if not routes or len(routes) > 8 or len(routes) != len(set(routes)) or not 1 <= n <= 8:
            raise EvidenceError("invalid route/connection identity")
        if mode["kind"] == "single":
            if len(routes) != 1 or n != 1:
                raise EvidenceError("a single control must have one route AND one connection")
            singles.append(name)
        elif mode["kind"] == "same_route_multi":
            if len(routes) != 1 or n < 2:
                raise EvidenceError("same-route control must actually use several connections")
            same_route_multi.append(name)
        elif mode["kind"] == "multipath":
            if len(routes) < 2 or n < len(routes):
                raise EvidenceError("multipath control must declare distinct routes")
        else:
            raise EvidenceError("unknown mode kind")
    if modes[candidate]["kind"] != "multipath":
        raise EvidenceError("candidate is not multipath")
    if any(modes[name]["connections"] != modes[candidate]["connections"] for name in same_route_multi):
        raise EvidenceError("same-route control must match the candidate connection count")
    covered_routes = {modes[name]["routes"][0] for name in singles}
    result = {"status": "not_evaluable", "accepted": False,
              "minimum_goodput_ratio": target, "absolute_300mbps_gate": False,
              "minimum_on_time_fraction": completion_target,
              "statistical_or_release_acceptance": False,
              "single_routes_missing": sorted(required_routes - covered_routes),
              "raw_cohort_and_socket_attribution_revalidated": False,
              "population": "unique application payload; no repair or duplicate byte credit"}
    if required_routes - covered_routes:
        result["reason"] = "missing_predeclared_single_connection_controls"
        return result
    if not set(modes[candidate]["routes"]) <= required_routes:
        raise EvidenceError("candidate uses an unbenchmarked route")
    order = plan["order"]
    if not 1 <= len(order) <= 96 or len({r["window"] for r in order}) != len(order):
        raise EvidenceError("duplicate or unbounded planned windows")
    expected = {r["window"]: r["mode"] for r in order}
    if any(name not in modes for name in expected.values()):
        raise EvidenceError("unknown mode in plan")
    observed = {}
    by_mode = {name: [] for name in modes}
    for row in records:
        window = row["window"]
        if window in observed or expected.get(window) != row["mode"]:
            raise EvidenceError("duplicate, unexpected or relabelled window")
        observed[window] = row
        if {k: row["common"].get(k) for k in COMMON} != {k: common[k] for k in COMMON}:
            raise EvidenceError("mismatched conditions; not a same-treatment comparison")
        by_mode[row["mode"]].append(row)
    if set(observed) != set(expected):
        result["reason"] = "incomplete_registered_window_population"
        return result
    if any(row.get("protected") is not True or row.get("cohort_complete") is not True for row in records):
        result["reason"] = "protection_or_raw_cohort_failed"
        return result
    if any(len(rows) < 2 for rows in by_mode.values()):
        result["reason"] = "fewer_than_two_windows_per_registered_mode"
        return result
    summaries = {name: _summary(rows, deadline) for name, rows in by_mode.items()}
    best_name = max(singles, key=lambda name: summaries[name]["goodput_bps"])
    base, multi = summaries[best_name], summaries[candidate]
    result.update(summaries=summaries, best_single_mode=best_name,
                  same_route_multi_controls=same_route_multi,
                  physical_path_gain_identified=False)
    if not base["goodput_bps"]:
        result["reason"] = "zero_single_goodput_is_not_infinite_gain"
        return result
    ratio = multi["goodput_bps"] / base["goodput_bps"]
    timely_ok = multi["on_time_fraction"] >= base["on_time_fraction"]
    finite_tails = base["p95_ms"] is not None and multi["p95_ms"] is not None
    p95_ok = finite_tails and multi["p95_ms"] <= base["p95_ms"] * p95_limit
    deadline_ok = multi["on_time_fraction"] >= completion_target
    result.update(status="screened", goodput_ratio=ratio, throughput_target_met=ratio >= target,
                  on_time_completion_not_worse=timely_ok, p95_gate_evaluable=finite_tails,
                  p95_gate_passed=p95_ok, deadline_target_met=deadline_ok,
                  accepted=ratio >= target and timely_ok and p95_ok and deadline_ok,
                  reason="engineering_screen_only")
    if same_route_multi:
        strongest = max(same_route_multi, key=lambda name: summaries[name]["goodput_bps"])
        rate = summaries[strongest]["goodput_bps"]
        result["best_same_route_multi_mode"] = strongest
        result["gain_over_same_route_multi"] = multi["goodput_bps"] / rate if rate else None
    return result


def legacy_campaign_coverage(registration):
    """Only handles the actual shared-PATHS campaign schema already in use."""
    routes = registration["conditions"]["paths"]
    if len(routes) < 2:
        raise EvidenceError("this adapter only diagnoses an existing multipath-only campaign")
    if any("paths" in v or "connections" in v for v in registration["variants"].values()):
        raise EvidenceError("per-variant topology requires a dedicated raw collector adapter")
    return {"status": "missing_single_connection_controls", "ratio_to_best_single": None,
            "accepted_as_aggregation_gain": False,
            "all_variants_declared_routes": routes,
            "baseline_label_is_not_single_connection": True,
            "scope": "registered topology coverage only; no new performance measurement"}
