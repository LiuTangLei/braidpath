"""Preparation bounds and matched-control tests; synthetic route labels only."""
from collections import Counter
import unittest
from bench.delivery_frontier import EvidenceError
from bench.topology_plan import make_plan


class TopologyPlanTests(unittest.TestCase):
    def test_all_singles_and_matched_connection_control_are_present(self):
        p = make_plan(["r0", "r1", "r2", "r3"], parallel_route="r0")
        self.assertEqual(p["modes"]["parallel"]["entrances"], ["r0"] * 4)
        self.assertEqual(p["modes"]["aggregate"]["connections"], 4)
        for i in range(4):
            self.assertEqual(p["modes"]["solo_" + str(i)]["connections"], 1)
        self.assertEqual(p["limits"]["maximum_windows"], 12)
        self.assertEqual(p["limits"]["maximum_nominal_business_seconds"], 120)

    def test_mirrored_fixed_order_keeps_two_samples_per_mode(self):
        p = make_plan(["r0", "r1"], parallel_route="r1")
        order = [r["mode"] for r in p["order"]]
        self.assertEqual(order, order[::-1])
        self.assertEqual(set(Counter(order).values()), {2})
        self.assertEqual(len({r["window"] for r in p["order"]}), len(order))

    def test_cold_survey_does_not_claim_native_or_sustained_capacity(self):
        p = make_plan(["r0", "r1"], parallel_route="r0")
        self.assertFalse(p["native_reference_completed"])
        self.assertFalse(p["steady_state_confirmed"])
        self.assertFalse(p["best_parallel_route_identified"])
        self.assertEqual(p["common"]["warmup_seconds"], 0)
        self.assertFalse(p["limits"]["frontier_scheduler"])
        self.assertEqual(p["limits"]["fec"], 0)
        self.assertEqual(p["limits"]["redundancy_percent"], 0)

    def test_budget_and_source_do_not_multiply_with_connections(self):
        p = make_plan(["r0", "r1", "r2", "r3"], parallel_route="r1")
        self.assertEqual(p["common"]["total_rate_cap_bps"], 500_000_000)
        self.assertEqual(p["common"]["offered_payload_bps"], 308_480_000)
        self.assertEqual(p["source"]["bulk_count"], 400_000)
        self.assertEqual(p["source"]["echo_count"], 200)

    def test_invalid_unbounded_or_mismatched_registration_fails(self):
        for routes in [[], ["r0"], ["r0", "r0"], [str(i) for i in range(5)], ["r0", ""]]:
            with self.assertRaises(EvidenceError):
                make_plan(routes, parallel_route="r0")
        for kwargs in [{"parallel_route": "unknown"}, {"duration_seconds": 20}, {"bulk_pps": 1000}]:
            options = {"parallel_route": "r0", **kwargs}
            with self.assertRaises(EvidenceError):
                make_plan(["r0", "r1"], **options)


if __name__ == "__main__":
    unittest.main()
