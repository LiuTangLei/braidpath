import copy
import unittest

from bench.transfer_evidence import COUNTERS, counter_delta, enclose, frame_delta, proc_counters, tcp_sockets, tcp_timeline


def sample(at, sent, lost=0, tx=None):
    return dict(unix=at, sent_packets=sent, lost_packets=lost,
                udp_tx_bytes=sent * 1000 if tx is None else tx, udp_rx_bytes=sent)


class CommonWindows(unittest.TestCase):
    def test_startup_is_not_discarded_even_if_first_active_sample_is_late(self):
        series = {'a': [sample(0, 0), sample(5, 100, 30), sample(10, 200, 31)],
                  'b': [sample(0, 0), sample(10, 100, 2)]}
        result = enclose(series, 2, 8, ['a', 'b'])
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(result['totals']['lost_packets'], 33)
        self.assertAlmostEqual(result['totals']['quinn_declared_loss_fraction'], 33 / 300)
        self.assertIsNone(result['application_to_udp_ratio'])

    def test_missing_path_start_or_tail_cannot_be_exported_as_a_complete_total(self):
        for series in [{'a': [sample(3, 1), sample(10, 2)]},
                       {'a': [sample(0, 1), sample(7, 2)]}, {}]:
            result = enclose(series, 2, 8, ['a', 'b'])
            self.assertFalse(result['coverage_complete'])
            self.assertIsNone(result['totals'])

    def test_reset_counters_and_proc_header_mismatch_are_unknown_not_zero(self):
        self.assertIsNone(counter_delta({'x': 3}, {'x': 2}))
        self.assertIsNone(proc_counters('TcpExt: A B\nTcpExt: 1\n'))
        self.assertEqual(proc_counters('TcpExt: A B\nTcpExt: 1 2\n'), {'A': 1, 'B': 2})

    def test_grouped_frame_keeps_all_paths_and_application_bytes_on_same_window(self):
        a = {'schema': 1, 'session': 'one', 'direction': 'client_to_server', 'sample_us': 0,
             'streams': {'bytes_from_application': 0, 'bytes_to_application': 0,
                         'retransmitted_bytes': 0, 'active': 2},
             'paths': [dict(path=i, connection=i+10, generation=7, pacing_bps=10_000_000,
                            writer_backlog_bytes=0, **{k: 0 for k in COUNTERS}) for i in range(4)]}
        b = copy.deepcopy(a); b['sample_us'] = 1_000_000
        b['streams'].update(bytes_from_application=200_000, retransmitted_bytes=10_000, active=0)
        for p in b['paths']:
            p.update(sent_packets=100, lost_packets=5, udp_tx_bytes=60_000, udp_rx_bytes=1000)
        result = frame_delta(a, b)
        self.assertTrue(result['complete'])
        self.assertAlmostEqual(result['application_to_udp_ratio_estimate'], 200_000 / 240_000)
        self.assertEqual(result['streams']['retransmitted_bytes'], 10_000)
        b['paths'][0]['generation'] += 1
        self.assertFalse(frame_delta(a, b)['complete'])


class SocketAttribution(unittest.TestCase):
    def test_socket_counters_and_interval_window_pressure_are_separated(self):
        def text(n, busy, rwnd, drops):
            return (f'ESTAB 0 400 127.0.0.1:4444 127.0.0.2:8080 ino:7\n'
                    f' skmem:(r0,rb2000,t0,tb3000,d{drops}) cubic bytes_received:{n} '
                    f'bytes_acked:{n*2} busy:{busy}ms rwnd_limited:{rwnd}ms(20%)')
        samples = [dict(kind='sample', unix=10, tcp=text(1000, 100, 0, 0)),
                   dict(kind='sample', unix=11, tcp=text(11000, 200, 30, 2))]
        row = tcp_timeline(samples, target_port=8080)['socket_intervals'][0]
        self.assertAlmostEqual(row['receive_mbps'], .08)
        self.assertAlmostEqual(row['rwnd_limited_fraction'], .3)
        self.assertEqual(row['socket_drop_delta'], 2)
        self.assertEqual(row['candidate_causes'], ['exit_socket_drop', 'target_receive_window'])
        self.assertIsNone(tcp_timeline(samples)['host_intervals'][0]['tcp_ext_delta'])
        self.assertEqual(tcp_sockets(text(1,1,1,0))[0]['peer_port'], '8080')

    def test_remote_socket_clock_is_aligned_before_matching_sender_evidence(self):
        samples = [dict(kind='sample', unix=t, tcp=f'ESTAB 0 0 a:1 b:8080\n bytes_received:{n}')
                   for t,n in [(104,100),(105,200)]]
        frame = dict(unix=100.5, direction='server_to_client', paths=[],
                     streams={'local_sender_queued_bytes':0,'send_retained_bytes':0})
        row = tcp_timeline(samples, offset=4, frames=[frame])['socket_intervals'][0]
        self.assertEqual(row['end_utc'], '1970-01-01T00:01:41+00:00')
        self.assertEqual(row['candidate_causes'], ['upstream_supply'])

    def test_empty_receive_queue_alone_does_not_prove_source_limitation(self):
        samples = [dict(kind='sample', unix=t, tcp=f'ESTAB 0 0 a:1 b:8080\n bytes_received:{n}')
                   for t,n in [(1,100),(2,200)]]
        self.assertEqual(tcp_timeline(samples)['socket_intervals'][0]['candidate_causes'], ['undetermined'])


if __name__ == '__main__':
    unittest.main()
