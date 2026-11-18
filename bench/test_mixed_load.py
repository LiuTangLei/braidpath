import unittest

from bench.mixed_load import compare, datagram_metrics


def window(received):
    sent = dict.fromkeys(range(100))
    replies = [(sequence, 100, True) for sequence in range(received)]
    return {"generator_valid": True, "reliable_exact": True,
            "udp": datagram_metrics(sent, replies)}


class MixedLoadTests(unittest.TestCase):
    def test_infinite_baseline_uses_absolute_gate(self):
        baseline = window(98)
        self.assertIsNone(baseline["udp"]["p99_ms"])
        self.assertEqual(compare(window(99), baseline), "pass")
        self.assertEqual(compare(window(98), baseline), "fail")

    def test_failed_transfer_is_a_failure(self):
        candidate = {**window(100), "reliable_exact": False}
        self.assertEqual(compare(candidate, window(100)), "fail")

    def test_incomplete_message_counts_as_missing(self):
        candidate = window(99)
        self.assertEqual(candidate["udp"]["missing"], 1)
        self.assertEqual(compare(candidate, window(100)), "fail")

    def test_early_byte_cap_is_invalid_fixture(self):
        candidate = {**window(100), "generator_valid": False}
        self.assertEqual(compare(candidate, window(100)), "insufficient")
