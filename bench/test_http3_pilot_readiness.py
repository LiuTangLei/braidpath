"""Functional-scope contracts; no network actions and no inferred capacity."""
import copy
import unittest

from bench.host_reference import CASE, SOURCE, reference_profile
from bench.http3_pilot_readiness import check_window


def fixture():
    endpoints = {}
    for role in ('client', 'server'):
        endpoints[role] = {'error': None, 'stats': {
            'shutdown_complete': True, 'drain_incomplete': False,
            'paths': {'p': {'authenticated': True, 'quinn': {
                'ack_frequency_frames_tx': int(role == 'server'),
                'ack_frequency_frames_rx': int(role == 'client')}}}}}
    return {'phase': {'business': {'source_records': 20000, 'delivered_records': 20000,
                'goodput_mbps': 15.424, 'echo': {'requests': 200, 'received': 200,
                    'on_time': 200, 'p95_ms': 2.0}}},
            'pipeline_ledger': {'source_sent': 20000, 'adapter_bulk_received': 20000,
                                'adapter_bulk_forwarded': 20000},
            'endpoint_stats': endpoints, 'raw_hashes': {}}


class PilotReadinessTests(unittest.TestCase):
    def test_prior_high_load_profile_does_not_change(self):
        case, source, rate = reference_profile()
        self.assertEqual(case, CASE)
        self.assertEqual(source, SOURCE)
        self.assertEqual(rate, 500000000)
        case['bulk_count'] = 1
        self.assertEqual(CASE['bulk_count'], 520000)

    def test_two_profiles_match_without_a_modeled_delay(self):
        self.assertEqual(reference_profile('every-two'), reference_profile('every-eight'))
        case, source, rate = reference_profile('every-two')
        self.assertEqual((case['bulk_count'], case['echo_count'], case['warmup_seconds']), (20000, 200, 0))
        self.assertEqual(source['bulk_pps'] * source['datagram_bytes'] * 8, 16000000)
        self.assertEqual(rate, 50000000)
        with self.assertRaises(ValueError):
            reference_profile('unbounded')

    def test_all_originals_and_requests_required(self):
        row = fixture()
        self.assertTrue(check_window(row, 'every-two')['passed'])
        for field in ('received', 'on_time'):
            changed = copy.deepcopy(row)
            changed['phase']['business']['echo'][field] -= 1
            self.assertFalse(check_window(changed, 'every-two')['passed'])
        row['phase']['business']['delivered_records'] -= 1
        self.assertFalse(check_window(row, 'every-two')['passed'])

    def test_adapter_loss_direction_or_shutdown_cannot_be_waived(self):
        row = fixture()
        row['pipeline_ledger']['adapter_bulk_received'] -= 1
        self.assertFalse(check_window(row, 'every-eight')['passed'])
        row = fixture()
        row['endpoint_stats']['client']['stats']['paths']['p']['quinn']['ack_frequency_frames_tx'] = 1
        self.assertFalse(check_window(row, 'every-eight')['passed'])
        row = fixture()
        row['endpoint_stats']['server']['stats']['drain_incomplete'] = True
        self.assertFalse(check_window(row, 'every-eight')['passed'])


if __name__ == '__main__':
    unittest.main()
