"""A rate-policy comparison must keep impairment and delay policy matched."""
import unittest
from unittest.mock import patch

from bench.adaptive_compare import compare


class MatchingConditionsTests(unittest.TestCase):
    def test_loss_or_latency_policy_mismatch_is_rejected_before_comparison(self):
        for field, changed in [("loss", 0.2), ("latency_target_ms", 100)]:
            baseline = {"loss": 0.0, "latency_target_ms": 20}
            candidate = dict(baseline, **{field: changed})
            with self.subTest(field=field), patch(
                "bench.adaptive_compare.load_run",
                side_effect=[(baseline, {"outcome": "completed", "windows": []}),
                             (candidate, {"outcome": "completed", "windows": []})],
            ):
                with self.assertRaisesRegex(ValueError, "unmatched registered conditions: " + field):
                    compare("unused-baseline", "unused-candidate")


if __name__ == "__main__":
    unittest.main()
