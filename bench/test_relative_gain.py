"""Synthetic acceptance counterexamples, not network performance evidence."""
import copy
import unittest

from bench.delivery_frontier import EvidenceError
from bench.relative_gain import evaluate, legacy_campaign_coverage


def fixture():
    common = dict(service="unreliable_datagram", carrier="authenticated_h3_datagram",
                  native_cc="bbr", crypto="same_fixture", payload_bytes=1000,
                  total_rate_cap_bps=500_000_000, offered_payload_bps=320_000_000,
                  warmup_seconds=5, deadline_ms=200, deadline_basis="source_echo_rtt",
                  coding_profile="none", host_fixture="synthetic")
    modes = {"s_a": {"kind": "single", "routes": ["a"], "connections": 1},
             "s_b": {"kind": "single", "routes": ["b"], "connections": 1},
             "same": {"kind": "same_route_multi", "routes": ["b"], "connections": 2},
             "multi": {"kind": "multipath", "routes": ["a", "b"], "connections": 2}}
    names = ["s_a", "s_b", "same", "multi", "multi", "same", "s_b", "s_a"]
    order = [{"window": "window_" + chr(97 + i), "mode": name} for i, name in enumerate(names)]
    plan = dict(minimum_goodput_ratio=1.5, maximum_p95_ratio=1, minimum_on_time_fraction=.95,
                candidate_mode="multi", required_single_routes=["a", "b"],
                common=common, modes=modes, order=order)
    rates = dict(s_a=1000, s_b=2000, same=2200, multi=3200)
    rows = [{**row, "common": copy.deepcopy(common), "actual_source_span_seconds": 1,
             "unique_application_payload_bytes": rates[row["mode"]],
             "offered_application_payload_bytes": 10000, "configured_requests": 20,
             "request_rtt_ms": [80] * 20, "protected": True, "cohort_complete": True}
            for row in order]
    return plan, rows


class RelativeGainTests(unittest.TestCase):
    def test_best_single_not_average_or_weakest_and_300m_not_required(self):
        result = evaluate(*fixture())
        self.assertEqual(result["best_single_mode"], "s_b")
        self.assertEqual(result["goodput_ratio"], 1.6)
        self.assertTrue(result["accepted"])
        self.assertFalse(result["absolute_300mbps_gate"])
        self.assertFalse(result["statistical_or_release_acceptance"])
        self.assertAlmostEqual(result["gain_over_same_route_multi"], 3200 / 2200)

    def test_big_gain_over_weak_route_does_not_pass_best_route_target(self):
        plan, rows = fixture()
        for row in rows:
            if row["mode"] == "multi":
                row["unique_application_payload_bytes"] = 2800
        result = evaluate(plan, rows)
        self.assertAlmostEqual(result["goodput_ratio"], 1.4)
        self.assertFalse(result["accepted"])

    def test_average_of_rates_is_not_used_for_different_source_spans(self):
        plan, rows = fixture()
        rows[3]["actual_source_span_seconds"] = 2
        result = evaluate(plan, rows)
        self.assertAlmostEqual(result["summaries"]["multi"]["goodput_bps"], 6400 * 8 / 3)

    def test_legacy_four_path_baseline_is_never_a_single_control(self):
        result = legacy_campaign_coverage({"conditions": {"paths": ["a", "b", "c", "d"]},
                                           "variants": {"baseline": {}, "candidate": {}}})
        self.assertIsNone(result["ratio_to_best_single"])
        self.assertFalse(result["accepted_as_aggregation_gain"])

    def test_partial_population_does_not_get_relabelled_complete(self):
        plan, rows = fixture()
        result = evaluate(plan, rows[:-1])
        self.assertEqual(result["reason"], "incomplete_registered_window_population")
        self.assertFalse(result["accepted"])

    def test_missing_one_route_control_is_not_best_single_evidence(self):
        plan, rows = fixture()
        plan["required_single_routes"].append("c")
        result = evaluate(plan, rows)
        self.assertEqual(result["single_routes_missing"], ["c"])
        self.assertFalse(result["accepted"])

    def test_duplicate_relabelled_or_unprotected_window_is_rejected(self):
        plan, rows = fixture()
        with self.assertRaises(EvidenceError):
            evaluate(plan, rows + [rows[0]])
        rows[0]["protected"] = False
        self.assertEqual(evaluate(plan, rows)["reason"], "protection_or_raw_cohort_failed")

    def test_a_same_route_multi_connection_control_is_not_single(self):
        plan, rows = fixture()
        plan["modes"]["s_b"]["connections"] = 4
        with self.assertRaises(EvidenceError):
            evaluate(plan, rows)

    def test_parallel_control_must_match_candidate_connection_count(self):
        plan, rows = fixture()
        plan["modes"]["same"]["connections"] = 3
        with self.assertRaisesRegex(EvidenceError, "match the candidate connection"):
            evaluate(plan, rows)

    def test_incompatible_semantics_fec_or_total_budget_cannot_pass(self):
        for key, value in [("service", "reliable_stream"), ("coding_profile", "16+2"),
                           ("total_rate_cap_bps", 1_000_000_000)]:
            plan, rows = fixture()
            rows[3]["common"][key] = value
            with self.assertRaisesRegex(EvidenceError, "mismatched conditions"):
                evaluate(plan, rows)

    def test_missing_rtt_slots_cannot_be_dropped(self):
        plan, rows = fixture()
        rows[3]["request_rtt_ms"].pop()
        with self.assertRaises(EvidenceError):
            evaluate(plan, rows)

    def test_missing_p95_is_not_zero_or_inf_over_inf(self):
        plan, rows = fixture()
        for row in rows:
            row["request_rtt_ms"][-2:] = [None, None]
        result = evaluate(plan, rows)
        self.assertTrue(result["throughput_target_met"])
        self.assertFalse(result["p95_gate_evaluable"])
        self.assertFalse(result["accepted"])
        self.assertEqual(result["summaries"]["multi"]["on_time_fraction"], .9)

    def test_tail_regression_is_not_hidden_by_throughput(self):
        plan, rows = fixture()
        for row in rows:
            if row["mode"] == "multi":
                row["request_rtt_ms"] = [150] * 20
        result = evaluate(plan, rows)
        self.assertTrue(result["throughput_target_met"])
        self.assertFalse(result["p95_gate_passed"])
        self.assertFalse(result["accepted"])

    def test_equal_late_tails_do_not_waive_the_absolute_deadline(self):
        plan, rows = fixture()
        for row in rows:
            row["request_rtt_ms"] = [500] * 20
        result = evaluate(plan, rows)
        self.assertTrue(result["p95_gate_passed"])
        self.assertFalse(result["deadline_target_met"])
        self.assertFalse(result["accepted"])

    def test_zero_single_rate_does_not_create_infinite_success(self):
        plan, rows = fixture()
        for row in rows:
            if row["mode"].startswith("s_"):
                row["unique_application_payload_bytes"] = 0
        result = evaluate(plan, rows)
        self.assertEqual(result["reason"], "zero_single_goodput_is_not_infinite_gain")

    def test_duplicate_bytes_and_invalid_times_are_rejected(self):
        plan, rows = fixture()
        rows[0]["unique_application_payload_bytes"] = 10001
        with self.assertRaises(EvidenceError):
            evaluate(plan, rows)
        plan, rows = fixture()
        rows[0]["actual_source_span_seconds"] = 0
        with self.assertRaises(EvidenceError):
            evaluate(plan, rows)


if __name__ == "__main__":
    unittest.main()
