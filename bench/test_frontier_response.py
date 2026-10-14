"""Identifiability counterexamples, not a simulator of the public network."""
import copy
import unittest

from bench.delivery_frontier import EvidenceError
from bench.frontier_response import interpret_pulse


def fixture():
    path = dict(requested_bps=8_000_000, socket_tx_bytes=1_000_000,
                unique_source_bytes=900_000, unique_on_time_source_bytes=900_000,
                queue_p95_ms=1)
    window = dict(source_span_seconds=1, paths={"a": copy.deepcopy(path), "b": copy.deepcopy(path)},
                  protection_passed=True, cohort_complete=True, deadline_clock_valid=True,
                  local_original_disposals=0)
    e = dict(pulse_path="b", fec_disabled=True, disjoint_original_ids=True,
             other_control_settings_unchanged=True, deadline_basis="reference_model",
             measurement_kind="synthetic", requested_rate_basis="outer_udp_bits_per_second")
    for i, key in enumerate(["before", "pulse", "after"]):
        e[key] = copy.deepcopy(window)
        e[key]["label"] = "window_" + chr(97 + i)
    e["pulse"]["paths"]["b"].update(requested_bps=12_000_000, socket_tx_bytes=1_500_000,
                                    unique_source_bytes=1_350_000, unique_on_time_source_bytes=1_350_000)
    return e


class PulseTests(unittest.TestCase):
    def test_independent_extra_service_is_positive_not_capacity_proof(self):
        r = interpret_pulse(fixture())
        self.assertEqual(r["classification"], "positive_marginal_on_time_yield_observed")
        self.assertAlmostEqual(r["marginal_on_time_yield"], .9)
        self.assertIsNone(r["capacity_upper_bound_bps"])
        self.assertIsNone(r["runtime_action"])

    def test_shared_constraint_can_steal_from_other_path(self):
        e = fixture()
        e["pulse"]["paths"]["a"].update(unique_source_bytes=450_000, unique_on_time_source_bytes=450_000)
        r = interpret_pulse(e)
        self.assertEqual(r["total_on_time_delta_bps"], 0)
        self.assertEqual(r["classification"], "cross_path_interference_observed_not_bottleneck_proof")
        self.assertFalse(r["shared_bottleneck_proved"])

    def test_requested_rate_is_not_actual_supply(self):
        e = fixture()
        e["pulse"]["paths"]["b"].update(socket_tx_bytes=1_010_000,
                                        unique_source_bytes=909_000,
                                        unique_on_time_source_bytes=909_000)
        self.assertEqual(interpret_pulse(e)["classification"], "pulse_not_realized_limiter_unidentified")

    def test_local_disposals_cannot_be_called_network_capacity(self):
        e = fixture()
        e["pulse"]["local_original_disposals"] = 1
        self.assertEqual(interpret_pulse(e)["classification"], "censored_by_local_disposition")

    def test_throughput_gain_that_misses_deadline_is_not_useful_gain(self):
        e = fixture()
        e["pulse"]["paths"]["b"]["unique_on_time_source_bytes"] = 900_000
        r = interpret_pulse(e)
        self.assertGreater(r["total_delivered_delta_bps"], 0)
        self.assertEqual(r["classification"], "no_useful_marginal_gain_observed")

    def test_queue_growth_prevents_low_latency_budget_raise(self):
        e = fixture()
        e["pulse"]["paths"]["b"]["queue_p95_ms"] = 12
        self.assertEqual(interpret_pulse(e)["classification"], "queue_cost_observed_do_not_raise_low_latency_budget")

    def test_reference_drift_is_not_silently_averaged_away(self):
        e = fixture()
        e["after"]["paths"]["a"]["unique_source_bytes"] = 450_000
        e["after"]["paths"]["a"]["unique_on_time_source_bytes"] = 450_000
        self.assertEqual(interpret_pulse(e)["classification"], "reference_drift_unidentified")

    def test_protection_or_full_cohort_cannot_be_waived(self):
        for key in ["protection_passed", "cohort_complete", "deadline_clock_valid"]:
            e = fixture()
            e["pulse"][key] = False
            self.assertEqual(interpret_pulse(e)["classification"], "incomplete_or_unprotected_evidence")

    def test_fec_and_duplicates_do_not_masquerade_as_original_capacity(self):
        for key in ["fec_disabled", "disjoint_original_ids"]:
            e = fixture()
            e[key] = False
            self.assertEqual(interpret_pulse(e)["classification"], "coding_or_duplicate_attribution_unidentified")

    def test_second_requested_rate_treatment_is_rejected(self):
        e = fixture()
        e["pulse"]["paths"]["a"]["requested_bps"] += 1
        with self.assertRaises(EvidenceError):
            interpret_pulse(e)

    def test_api_byte_budgets_cannot_be_compared_to_outer_wire_bytes(self):
        e = fixture()
        e["requested_rate_basis"] = "quinn_api_bytes"
        with self.assertRaisesRegex(EvidenceError, "outer-UDP"):
            interpret_pulse(e)

    def test_unverified_deadline_and_multiple_control_changes_are_unknown(self):
        e = fixture()
        e["deadline_basis"] = "rtt_divided_by_two"
        self.assertEqual(interpret_pulse(e)["classification"], "deadline_measurement_unidentified")
        e = fixture()
        e["other_control_settings_unchanged"] = False
        self.assertEqual(interpret_pulse(e)["classification"], "multiple_treatments_unidentified")

    def test_bad_population_time_or_counter_values_are_rejected(self):
        for field, value in [("source_span_seconds", 0), ("source_span_seconds", float("nan"))]:
            e = fixture()
            e["before"][field] = value
            with self.assertRaises(EvidenceError):
                interpret_pulse(e)
        e = fixture()
        e["pulse"]["paths"]["b"]["unique_on_time_source_bytes"] = 2_000_000
        with self.assertRaises(EvidenceError):
            interpret_pulse(e)


if __name__ == "__main__":
    unittest.main()
