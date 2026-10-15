import copy
import unittest

from bench.host_reference import reference_profile
from bench.native_service_readiness import check


class NativeServiceReadinessTests(unittest.TestCase):
    def fixture(self, enabled=False):
        stats = {'paths': {'0': {'authenticated': True}},
                 'directions': {'return': {'adaptive': {
                     'native_service_recoveries': 0,
                     'last_control': {'native_service_guard_enabled': enabled}}}}}
        return {'phase': {'business': {'source_records': 100000,
                    'delivered_records': 100000, 'goodput_mbps': 77.0,
                    'echo': {'requests': 200, 'received': 200, 'on_time': 200, 'p95_ms': 2.0}}},
                'pipeline_ledger': {'source_sent': 100000,
                    'adapter_bulk_received': 100000, 'adapter_bulk_forwarded': 100000},
                'endpoint_stats': {role: {'stats': copy.deepcopy(stats)} for role in ['client', 'server']}}

    def test_profile_has_fixed_population_budget_and_no_ack_treatment(self):
        case, source, rate = reference_profile(service_profile='native-service-80')
        self.assertEqual((case['bulk_count'], case['echo_count'], case['warmup_seconds']), (100000, 200, 0))
        self.assertEqual(source['bulk_pps'], 10000)
        self.assertEqual(rate, 125000000)
        for name in ['every-two', 'every-eight']:
            with self.assertRaises(ValueError):
                reference_profile(name, service_profile='native-service-80')

    def test_complete_population_and_actual_flag_are_required(self):
        for enabled in [False, True]:
            row = self.fixture(enabled)
            self.assertTrue(check(row, enabled)['passed'])
            self.assertFalse(check(row, not enabled)['passed'])
            row['phase']['business']['echo']['received'] -= 1
            self.assertFalse(check(row, enabled)['passed'])

    def test_drops_slow_supply_and_missing_runtime_evidence_cannot_pass(self):
        for case in ['bulk', 'adapter', 'rate', 'runtime']:
            row = self.fixture()
            if case == 'bulk': row['phase']['business']['delivered_records'] -= 1
            if case == 'adapter': row['pipeline_ledger']['adapter_bulk_received'] -= 1
            if case == 'rate': row['phase']['business']['goodput_mbps'] = 70
            if case == 'runtime': row['endpoint_stats']['client']['stats'].pop('directions')
            self.assertFalse(check(row, False)['passed'], case)


if __name__ == '__main__':
    unittest.main()
