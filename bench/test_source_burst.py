import unittest

from bench.source_burst import burst_summary


class SourceBurstTests(unittest.TestCase):
    def rows(self, times):
        return [dict(seq=i, send_unix_us=t) for i, t in enumerate(times)]

    def test_uniform_source_has_exact_half_open_1ms_population(self):
        result = burst_summary(self.rows(range(0, 10000, 25)), 40000)
        self.assertEqual(result['rolling_windows_us']['1000']['max_packets'], 40)
        self.assertEqual(result['rolling_windows_us']['100']['max_packets'], 4)
        self.assertEqual(sum(result['gap_histogram_counts']), 399)
        self.assertEqual(result['gap_us']['maximum'], 25)

    def test_equal_mean_does_not_hide_a_burst_or_missing_service(self):
        times = [2000*(i//80)+(i % 80) for i in range(400)]
        result = burst_summary(self.rows(times), 40000)
        self.assertEqual(result['rolling_windows_us']['100']['max_packets'], 80)
        self.assertEqual(result['gap_us']['maximum'], 1921)
        self.assertFalse(result['causal_claim'])
        self.assertFalse(result['changes_pacing_or_acceptance'])

    def test_regression_missing_slots_and_unbounded_population_fail(self):
        for rows in [self.rows([2, 1]), [dict(seq=1, send_unix_us=1)]*2,
                     [dict(seq=0, send_unix_us=1), dict(seq=1, send_unix_us=None)]]:
            with self.assertRaises(ValueError):
                burst_summary(rows, 40000)

    def test_peaks_are_bounded_and_clock_ties_preserved(self):
        result = burst_summary(self.rows([i//4*1000 for i in range(400)]), 40000)
        self.assertEqual(len(result['largest_gaps']), 16)
        self.assertEqual(result['rolling_windows_us']['1000']['max_packets'], 4)
        self.assertEqual(result['gap_us']['p50'], 0)


if __name__ == '__main__':
    unittest.main()
