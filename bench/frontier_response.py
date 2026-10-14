"""Shadow-only interpretation of a bounded single-path additive rate pulse.

Inputs are three independently labelled, full-cohort observations: reference
before, pulse, reference after. The collector is NOT implemented here. No
network operations, rate control or automatic bottleneck grouping occur.
"""
from bench.delivery_frontier import EvidenceError, finite, integer


def _window(value, paths):
    if set(value["paths"]) != paths:
        raise EvidenceError("path population changed within intervention")
    duration = finite(value["source_span_seconds"], "source_span_seconds")
    if duration <= 0:
        raise EvidenceError("positive source span required")
    result = {}
    for name, p in value["paths"].items():
        sent = integer(p["socket_tx_bytes"], "socket_tx_bytes")
        delivered = integer(p["unique_source_bytes"], "unique_source_bytes")
        timely = integer(p["unique_on_time_source_bytes"], "unique_on_time_source_bytes")
        if timely > delivered:
            raise EvidenceError("on-time bytes exceed unique delivered bytes")
        if delivered > sent:
            raise EvidenceError("uncoded unique source bytes exceed their complete wire cohort")
        result[name] = {"requested_bps": finite(p["requested_bps"], "requested_bps"),
                        "actual_wire_bps": sent * 8 / duration,
                        "delivered_bps": delivered * 8 / duration,
                        "on_time_bps": timely * 8 / duration,
                        "queue_p95_ms": finite(p["queue_p95_ms"], "queue_p95_ms")}
    return result


def interpret_pulse(evidence, *, max_reference_drift=.05,
                    min_realized_fraction=.5, min_marginal_yield=.1,
                    max_queue_increase_ms=5):
    """Return an observation category, never a capacity estimate or causal proof.

    No repair/duplicate IDs may enter this first identification stage. Rates
    use actual source spans and bytes of specified meaning, not configured
    Mbps alone. Reference drift and unrealized pulses are explicit outcomes.
    Thresholds must be frozen before collecting any observations.
    """
    for name, value in [("max_reference_drift", max_reference_drift),
                        ("min_realized_fraction", min_realized_fraction),
                        ("min_marginal_yield", min_marginal_yield)]:
        if not 0 < finite(value, name) <= 1:
            raise EvidenceError(name + " must be in (0,1]")
    finite(max_queue_increase_ms, "max_queue_increase_ms")
    paths = set(evidence["before"]["paths"])
    selected = evidence["pulse_path"]
    if not 1 <= len(paths) <= 8 or selected not in paths:
        raise EvidenceError("invalid bounded path set")
    if evidence["measurement_kind"] not in ("synthetic", "measured"):
        raise EvidenceError("measurement_kind must be explicit")
    if evidence.get("requested_rate_basis") != "outer_udp_bits_per_second":
        raise EvidenceError("requested rates must have the same outer-UDP byte basis as actual supply")
    result = {"measurement_kind": evidence["measurement_kind"],
              "pulse_path": selected, "classification": "unidentified",
              "capacity_upper_bound_bps": None, "shared_bottleneck_proved": False,
              "runtime_action": None, "confidence": "one bracketed observation, not statistical proof",
              "thresholds": {"max_reference_drift": max_reference_drift,
                             "min_realized_fraction": min_realized_fraction,
                             "min_marginal_yield": min_marginal_yield,
                             "max_queue_increase_ms": max_queue_increase_ms}}
    windows = [evidence[key] for key in ["before", "pulse", "after"]]
    labels = [window["label"] for window in windows]
    if len(set(labels)) != 3:
        raise EvidenceError("three distinct observation labels required")
    values = [_window(w, paths) for w in windows]
    before, during, after = values
    if evidence.get("fec_disabled") is not True or evidence.get("disjoint_original_ids") is not True:
        result["classification"] = "coding_or_duplicate_attribution_unidentified"
        return result
    if evidence.get("deadline_basis") not in ("source_echo_rtt", "bounded_one_way", "reference_model"):
        result["classification"] = "deadline_measurement_unidentified"
        return result
    if evidence["deadline_basis"] == "reference_model" and evidence["measurement_kind"] != "synthetic":
        raise EvidenceError("a reference-model clock cannot certify measured deadlines")
    if any(w.get("protection_passed") is not True or w.get("cohort_complete") is not True
           or w.get("deadline_clock_valid") is not True for w in windows):
        result["classification"] = "incomplete_or_unprotected_evidence"
        return result
    if any(integer(w["local_original_disposals"], "local_original_disposals") for w in windows):
        result["classification"] = "censored_by_local_disposition"
        return result
    if evidence.get("other_control_settings_unchanged") is not True:
        result["classification"] = "multiple_treatments_unidentified"
        return result
    for p in paths:
        if before[p]["requested_bps"] != after[p]["requested_bps"]:
            raise EvidenceError("reference offered rates changed")
        if p != selected and during[p]["requested_bps"] != before[p]["requested_bps"]:
            raise EvidenceError("only the selected path may change requested rate")
    requested_delta = during[selected]["requested_bps"] - before[selected]["requested_bps"]
    if requested_delta <= 0:
        raise EvidenceError("this contract requires one positive additive pulse")
    reference = {p: {k: (before[p][k] + after[p][k]) / 2 for k in before[p]} for p in paths}
    drift = max(abs(before[p][k] - after[p][k]) / max(before[p][k], after[p][k], 1)
                for p in paths for k in ["actual_wire_bps", "delivered_bps", "on_time_bps"])
    result["reference_relative_drift"] = drift
    if drift > max_reference_drift:
        result["classification"] = "reference_drift_unidentified"
        return result
    delta = {p: {k: during[p][k] - reference[p][k]
                 for k in ["actual_wire_bps", "delivered_bps", "on_time_bps", "queue_p95_ms"]}
             for p in sorted(paths)}
    realized = delta[selected]["actual_wire_bps"]
    result.update(path_deltas=delta, requested_delta_bps=requested_delta,
                  realized_selected_wire_delta_bps=realized,
                  realized_fraction=realized / requested_delta)
    if realized < requested_delta * min_realized_fraction:
        result["classification"] = "pulse_not_realized_limiter_unidentified"
        return result
    useful = sum(d["on_time_bps"] for d in delta.values())
    delivered = sum(d["delivered_bps"] for d in delta.values())
    other_useful = sum(d["on_time_bps"] for p, d in delta.items() if p != selected)
    queue_growth = max(d["queue_p95_ms"] for d in delta.values())
    result.update(marginal_on_time_yield=useful / realized,
                  total_delivered_delta_bps=delivered, total_on_time_delta_bps=useful,
                  other_paths_on_time_delta_bps=other_useful,
                  maximum_queue_increase_ms=queue_growth)
    if queue_growth > max_queue_increase_ms:
        result["classification"] = "queue_cost_observed_do_not_raise_low_latency_budget"
    elif useful / realized >= min_marginal_yield and other_useful >= 0:
        result["classification"] = "positive_marginal_on_time_yield_observed"
    elif other_useful < 0:
        result["classification"] = "cross_path_interference_observed_not_bottleneck_proof"
    else:
        result["classification"] = "no_useful_marginal_gain_observed"
    return result
