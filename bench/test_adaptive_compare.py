"""A rate-policy comparison must keep impairment and delay policy matched."""
import unittest
from pathlib import Path
from unittest.mock import patch

from bench.adaptive_compare import compare


class MatchingConditionsTests(unittest.TestCase):
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
