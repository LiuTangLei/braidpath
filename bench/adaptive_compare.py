#!/usr/bin/env python3
"""Read-only comparison of registered local adaptive experiments; writes a new summary."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATCH_FIELDS = ("topology", "paths", "rate_bps", "queue_ms", "fec", "link_mbps",
                "congested_mbps", "queue_bytes", "network_queue_ms", "delay_ms", "seed",
                "deadline_ms", "bulk_pps", "bulk_bytes", "interactive_pps",
                "interactive_bytes", "phases", "drain_seconds")


def evaluate_window(baseline, candidate):
    old_bulk, new_bulk = baseline["streams"]["bulk"], candidate["streams"]["bulk"]
    old_interactive = baseline["streams"]["interactive"]
    new_interactive = candidate["streams"]["interactive"]
    condition = baseline["condition"]
    target_ratio = (new_bulk["target_goodput_bps"] / old_bulk["target_goodput_bps"]
                    if old_bulk["target_goodput_bps"] else None)
    on_time_ratio = (new_bulk["on_time_echo_goodput_bps"] / old_bulk["on_time_echo_goodput_bps"]
                     if old_bulk["on_time_echo_goodput_bps"] else None)
    difference = new_interactive["deadline_miss_fraction"] - old_interactive["deadline_miss_fraction"]
    gates = {}
    if condition == "clean" and baseline["name"] != "warmup":
        # A zero on-time baseline cannot grant an empty-delivery candidate a pass.
        if target_ratio is None:
            gates["candidate_delivers_without_baseline_reference"] = new_bulk["target_goodput_bps"] > 0
        else:
            gates["target_goodput_retained"] = target_ratio >= .90
        gates["on_time_goodput_retained_when_comparable"] = on_time_ratio is None or on_time_ratio >= .90
        gates["interactive_no_more_than_one_pp_worse"] = difference <= .01 + 1e-12
    elif condition == "congested":
        gates["useful_payload_still_delivered"] = new_bulk["target_goodput_bps"] > 0
        gates["interactive_improves_or_remains_perfect"] = (
            difference < 0 if old_interactive["deadline_miss_fraction"] > 0
            else new_interactive["deadline_miss_fraction"] == 0)
    return {"window": baseline["name"], "condition": condition,
            "target_goodput_ratio": target_ratio, "on_time_goodput_ratio": on_time_ratio,
            "interactive_deadline_miss_difference_pp": difference * 100,
            "baseline": baseline["streams"], "candidate": candidate["streams"],
            "screening_gates": gates}


def load_run(directory):
    return (json.loads((directory / "manifest.json").read_text()),
            json.loads((directory / "result.json").read_text()))


def recovery_time(directory, manifest, result):
    recovery = next((p for p in manifest["phases"] if p["name"] == "window_g"), None)
    if not recovery or result.get("start_monotonic_ns") is None:
        return None
    offset = 0
    for phase in manifest["phases"]:
        if phase["name"] == "window_g":
            break
        offset += phase["seconds"]
    boundary = result["start_monotonic_ns"] + round(offset * 1e9)
    times = []
    with (directory / "samples.jsonl").open() as handle:
        for line in handle:
            sample = json.loads(line)
            if sample["kind"] == 2 and sample["window"] == "window_g" and sample["echo_ns"] is not None:
                times.append((sample["echo_ns"] - boundary) / 1e6)
    return min(times) if times else "infinity"


def compare(baseline_dir, candidate_dir):
    bm, br = load_run(baseline_dir)
    cm, cr = load_run(candidate_dir)
    mismatch = [key for key in MATCH_FIELDS if bm.get(key) != cm.get(key)]
    if mismatch:
        raise ValueError("unmatched registered conditions: " + ", ".join(mismatch))
    if br["outcome"] not in ("completed", "runtime_exited") or cr["outcome"] not in ("completed", "runtime_exited"):
        raise ValueError("a generator/startup error is not a completed measurement comparison")
    old = {w["name"]: w for w in br["windows"]}
    rows = [evaluate_window(old[w["name"]], w) for w in cr["windows"]]
    valid_offer = all(v["actual_offered_fraction"] >= .95
                      for run in (br, cr) for w in run["windows"] for v in w["streams"].values())
    integrity = {}
    for name, directory, result in [("baseline", baseline_dir, br), ("candidate", candidate_dir, cr)]:
        target = json.loads((directory / "target-counters.json").read_text())
        integrity[name] = target.get("corrupt_or_unknown", 0) + sum(
            counts.get("corrupt_or_unknown", 0) for counts in result["stream_counters"].values())
    return {"scope": "Single bounded local engineering screen; no statistical/default/WAN acceptance claim.",
            "baseline": str(baseline_dir), "candidate": str(candidate_dir),
            "baseline_binary_sha256": bm["sha256"], "candidate_binary_sha256": cm["sha256"],
            "harness_identical": bm.get("harness_sha256") == cm.get("harness_sha256"),
            "source_offer_valid": valid_offer, "integrity_errors": integrity,
            "baseline_outcome": br["outcome"], "candidate_outcome": cr["outcome"],
            "baseline_recovery_first_interactive_echo_ms": recovery_time(baseline_dir, bm, br),
            "candidate_recovery_first_interactive_echo_ms": recovery_time(candidate_dir, cm, cr),
            "windows": rows,
            "interpretation": [
                "Complete clean-window target goodput is also required; zero on-time baseline does not make dropping everything pass.",
                "Recovery after an old-runtime exit is an availability comparison. A zero baseline payload denominator is unavailable, not a throughput regression verdict.",
                "Missing application operations remain infinity in the RTT distribution.",
                "Nominal shaper bandwidth is not independently measured useful capacity.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or ROOT / "local" not in output.parents:
        parser.error("choose a new output file inside ignored local/")
    summary = compare(args.baseline.resolve(), args.candidate.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"output": str(output), "source_offer_valid": summary["source_offer_valid"],
                      "candidate_outcome": summary["candidate_outcome"]}))


if __name__ == "__main__":
    main()

