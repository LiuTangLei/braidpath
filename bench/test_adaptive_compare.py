"""A rate-policy comparison must keep impairment and delay policy matched."""
import unittest
import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from bench.adaptive_compare import MATCH_FIELDS, STREAM_COUNTER_FIELDS, TARGET_COUNTER_FIELDS, compare


def target_counters():
    return dict(dict.fromkeys(TARGET_COUNTER_FIELDS, 0), received_packets=4,
                unique_records=4, echoes_submitted=4)


def complete_run():
    phases = [{"name": "window_a", "seconds": 1, "condition": "clean"},
              {"name": "window_b", "seconds": 1, "condition": "congested"}]
    manifest = {key: 1 for key in MATCH_FIELDS}
    manifest.update(phases=phases, sha256="0" * 64, harness_sha256="1" * 64)
    metrics = dict(actual_offered_fraction=1, target_goodput_bps=100,
                   on_time_echo_goodput_bps=100, deadline_miss_fraction=0,
                   kernel_accepted_operations=1, echo_unique_records=1, target_unique_records=1,
                   source_pacing={"qualified": True})
    counters = dict(dict.fromkeys(STREAM_COUNTER_FIELDS, 0), sent_packets=2,
                    received_packets=2, unique_echoes=2)
    result = dict(outcome="completed", stream_counters={"1": dict(counters), "2": dict(counters)},
                  windows=[dict(p, streams={name: dict(metrics) for name in ("bulk", "interactive")})
                           for p in phases])
    return manifest, result


class MatchingConditionsTests(unittest.TestCase):
    def compared(self, baseline, candidate, target=None):
        with patch("bench.adaptive_compare.load_run", side_effect=[baseline, candidate]), \
                patch.object(Path, "read_text", return_value=json.dumps(target_counters() if target is None else target)):
            return compare(Path("unused-baseline"), Path("unused-candidate"))

    def test_complete_comparison_preserves_failed_gates(self):
        baseline, candidate = complete_run(), complete_run()
        candidate[1]["windows"][0]["streams"]["bulk"]["target_goodput_bps"] = 0
        result = self.compared(baseline, candidate)
        self.assertTrue(result["harness_identical"])
        self.assertTrue(result["source_offer_valid"])
        self.assertFalse(result["windows"][0]["screening_gates"]["target_goodput_retained"])
        self.assertEqual(len(result["windows"]), 2)

    def test_microburst_cannot_pass_only_with_a_full_offered_population(self):
        baseline, candidate = complete_run(), complete_run()
        candidate[1]["windows"][0]["streams"]["bulk"]["source_pacing"] = {"qualified": False}
        result = self.compared(baseline, candidate)
        self.assertFalse(result["source_offer_valid"])

    def test_explicit_counters_cannot_be_missing_negative_nonintegral_or_false_zero(self):
        for location, fields in (("target", TARGET_COUNTER_FIELDS), ("stream", STREAM_COUNTER_FIELDS)):
            for field in fields:
                for invalid in (None, -1, 0.5, True):
                    runs, target = [complete_run(), complete_run()], target_counters()
                    counts = target if location == "target" else runs[1][1]["stream_counters"]["1"]
                    if invalid is None:
                        counts.pop(field)
                    else:
                        counts[field] = invalid
                    with self.subTest(location=location, field=field, invalid=invalid), self.assertRaisesRegex(
                            ValueError, "not evaluable.*counters"):
                        self.compared(*runs, target=target)
            with self.subTest(location=location, empty=True), self.assertRaisesRegex(ValueError, "not evaluable"):
                runs = [complete_run(), complete_run()]
                if location == "stream":
                    runs[1][1]["stream_counters"]["1"] = {}
                self.compared(*runs, target={} if location == "target" else target_counters())

    def test_counters_reconcile_with_windows_and_integrity_includes_duplicates(self):
        baseline, candidate = complete_run(), complete_run()
        candidate[1]["stream_counters"]["1"]["sent_packets"] = 1
        with self.assertRaisesRegex(ValueError, "sent_packets disagrees"):
            self.compared(baseline, candidate)
        target = target_counters()
        target.update(received_packets=5, unique_records=5, echoes_submitted=5)
        with self.assertRaisesRegex(ValueError, "target counters disagree"):
            self.compared(complete_run(), complete_run(), target=target)
        target.update(received_packets=5, unique_records=4, duplicate_records=1)
        result = self.compared(complete_run(), complete_run(), target=target)
        self.assertEqual(result["integrity_errors"], {"baseline": 1, "candidate": 1})

    def test_binary_identity_requires_an_actual_sha256(self):
        for fingerprint in (None, "", "g" * 64):
            baseline, candidate = complete_run(), complete_run()
            candidate[0]["sha256"] = fingerprint
            with self.subTest(fingerprint=fingerprint), self.assertRaisesRegex(ValueError, "not evaluable.*binary identity"):
                self.compared(baseline, candidate)

    def test_empty_missing_duplicate_and_reordered_windows_are_rejected(self):
        for replacement in ([], [0], [0, 0], [1, 0]):
            for side in (0, 1):
                runs = [complete_run(), complete_run()]
                windows = runs[side][1]["windows"]
                runs[side][1]["windows"] = [deepcopy(windows[i]) for i in replacement]
                with self.subTest(replacement=replacement, side=side), self.assertRaisesRegex(
                        ValueError, "not evaluable.*windows"):
                    self.compared(*runs)

    def test_empty_and_duplicate_registration_is_not_evaluable(self):
        for names in ([], ["window_a", "window_a"]):
            runs = [complete_run(), complete_run()]
            for manifest, result in runs:
                manifest["phases"] = [dict(name=name, seconds=1, condition="clean") for name in names]
                result["windows"] = []
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, "registered windows"):
                self.compared(*runs)

    def test_missing_or_changed_harness_identity_is_not_evaluable(self):
        for value in (None, "", "not-a-sha256", "2" * 64):
            baseline, candidate = complete_run(), complete_run()
            candidate[0]["harness_sha256"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "harness identit"):
                self.compared(baseline, candidate)
        baseline, candidate = complete_run(), complete_run()
        baseline[0].pop("harness_sha256")
        candidate[0].pop("harness_sha256")
        with self.assertRaisesRegex(ValueError, "harness identity"):
            self.compared(baseline, candidate)

    def test_missing_streams_counters_or_measurements_are_not_evaluable(self):
        for change in ("streams", "stream_counters", "measurement", "condition"):
            baseline, candidate = complete_run(), complete_run()
            if change == "streams":
                candidate[1]["windows"][0]["streams"].pop("interactive")
            elif change == "stream_counters":
                candidate[1]["stream_counters"].pop("2")
            elif change == "condition":
                candidate[1]["windows"][0]["condition"] = "cleaned-up"
            else:
                candidate[1]["windows"][0]["streams"]["bulk"].pop("actual_offered_fraction")
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "not evaluable"):
                self.compared(baseline, candidate)

    def test_loss_or_latency_policy_mismatch_is_rejected_before_comparison(self):
        for field, changed in [("loss", 0.2), ("latency_target_ms", 100)]:
            baseline = {"loss": 0.0, "latency_target_ms": 20,
                        "sha256": "0" * 64, "phases": []}
            candidate = dict(baseline, **{field: changed})
            result = {"outcome": "completed", "windows": [], "stream_counters": {}}
            with self.subTest(field=field), patch(
                "bench.adaptive_compare.load_run",
                side_effect=[(baseline, result), (candidate, result)],
            ), patch.object(Path, "read_text", return_value="{}"):
                with self.assertRaisesRegex(ValueError, "unmatched registered conditions: " + field):
                    compare(Path("unused-baseline"), Path("unused-candidate"))


if __name__ == "__main__":
    unittest.main()
