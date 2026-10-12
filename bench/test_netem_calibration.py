import unittest

from bench.netem_calibration import receiver_rate


class ReceiverRate(unittest.TestCase):
    def test_uses_observed_delivery_not_sender_rate(self):
        result = {"end": {"sum_sent": {"bits_per_second": 140_000_000, "sender": True},
                          "sum_received": {"bits_per_second": 97_000_000, "sender": False}}}
        self.assertEqual(receiver_rate(result), 97)

    def test_sender_only_or_failed_results_are_invalid(self):
        for result in [{"error": "test failed"},
                       {"end": {"sum": {"bits_per_second": 140_000_000, "sender": True}}}]:
            with self.assertRaises(ValueError):
                receiver_rate(result)


if __name__ == "__main__":
    unittest.main()
