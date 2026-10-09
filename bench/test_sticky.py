import unittest
from bench.sticky_worker import ACK, DATA, HEADER, decode, packet, quantile


class StickyProtocolTests(unittest.TestCase):
    def test_exact_payload_and_small_same_tuple_receipt(self):
        token = bytes(range(16))
        data = packet(token, DATA, 1, 2, 1, 7, 374, 123456, 789)
        self.assertEqual(len(data), 1000)
        decoded = decode(data, token)
        self.assertEqual(decoded, (DATA, 1, 2, 1, 7, 374, 123456, 789))
        ack = packet(token, ACK, *decoded[1:])
        self.assertEqual(len(ack), HEADER.size)
        self.assertEqual(decode(ack, token), (ACK, *decoded[1:]))

    def test_authorization_shape_and_allocation_bounds(self):
        token = bytes(range(16))
        data = packet(token, DATA, 0, 0, 0, 0)
        self.assertIsNone(decode(data, bytes(16)))
        for truncated in [data[:HEADER.size-1], data[:-1], data + b"x"]:
            self.assertIsNone(decode(truncated, token))
        for path, round_id, direction, flow, seq in [(2,0,0,0,0),(0,3,0,0,0),(0,0,2,0,0),(0,0,0,8,0),(0,0,0,0,375)]:
            self.assertIsNone(decode(packet(token, DATA, path, round_id, direction, flow, seq), token))
        corrupt = bytearray(data)
        corrupt[-1] ^= 1
        self.assertIsNone(decode(corrupt, token))

    def test_missing_rtt_stays_in_unconditional_population(self):
        self.assertEqual(quantile([10, 20], 3, .5), 20)
        self.assertEqual(quantile([10, 20], 3, .95), "infinity")


if __name__ == "__main__":
    unittest.main()
