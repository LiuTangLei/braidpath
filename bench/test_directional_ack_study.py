"""Pure ACK-study contracts; no sockets or process launches."""
import copy
import unittest
from bench.directional_ack_study import plan, latency, native_interval, aggregate


class DirectionalAckContracts(unittest.TestCase):
    def test_matched_threshold_order_has_two_windows_per_link_and_profile(self):
        p=plan();self.assertEqual(len(p['order']),8)
        for rate in [0,2000]:
            self.assertEqual([r['ack_profile'] for r in p['order'] if r['reverse_pps']==rate],
                             ['every-two','every-eight','every-eight','every-two'])
        self.assertEqual(p['client_ack_profile'],'unchanged')
        self.assertEqual((p['ack_max_delay_ms'],p['ack_reorder_threshold']),(10,2))
        self.assertEqual((p['one_way_delay_ms'],p['link_queue_ms']),(20,20))
        self.assertTrue(p['no_retries']);self.assertFalse(p['capacity_or_multilink_acceptance'])

    def test_native_source_budget_and_warmup_are_not_credited_to_business(self):
        p=plan();self.assertEqual(p['bulk_pps']*p['bulk_payload_bytes']*8,80_000_000)
        self.assertEqual(p['warmup_ms']*p['bulk_pps']//1000,20_000)
        self.assertEqual(p['business_ms']*p['echo_pps']//1000,400)
        self.assertEqual(p['runtime_threads'],4)

    def test_latency_uses_issue_instead_of_hiding_local_queue_wait(self):
        samples=[{'issued_us':0,'admitted_us':190_000,'received_us':210_000}]
        result=latency(samples)
        self.assertEqual(result['on_time'],0);self.assertEqual(result['p95_ms'],210.)

    def test_missing_requests_stay_in_full_tail_population(self):
        samples=[{'issued_us':0,'admitted_us':0,'received_us':1000},
                 {'issued_us':0,'admitted_us':None,'received_us':None}]
        r=latency(samples);self.assertEqual(r['population'],2);self.assertEqual(r['received'],1)
        self.assertEqual(r['on_time_fraction'],.5);self.assertIsNone(r['p95_ms'])

    def test_response_without_admission_or_reverse_time_fails(self):
        for sample in [{'issued_us':None,'admitted_us':2,'received_us':3},
                       {'issued_us':1,'admitted_us':None,'received_us':3},
                       {'issued_us':4,'admitted_us':5,'received_us':3}]:
            with self.assertRaises(ValueError):latency([sample])

    def test_native_phase_delta_not_final_cumulative_count(self):
        keys=['udp_packets_tx','udp_packets_rx','udp_bytes_tx','udp_bytes_rx','ack_frames_tx','ack_frames_rx',
              'datagram_frames_tx','datagram_frames_rx','lost_packets','ack_frequency_tx','ack_frequency_rx']
        a={k:10 for k in keys};b={k:30 for k in keys}
        timeline=[{'elapsed_us':2_010_000,'client':a,'server':a},
                  {'elapsed_us':10_020_000,'client':b,'server':b}]
        r=native_interval(timeline,2000,8000)
        self.assertEqual(r['client']['udp_packets_tx'],20)
        self.assertAlmostEqual(r['actual_interval_seconds'],8.01)
        broken=copy.deepcopy(timeline);broken[1]['client']['ack_frames_tx']=9
        with self.assertRaises(ValueError):native_interval(broken,2000,8000)
        with self.assertRaises(ValueError):native_interval(timeline[:1],2000,8000)

    def test_partial_comparison_never_claims_mechanism_acceptance(self):
        row={'reverse_pps':0,'ack_profile':'every-two','delivered_bytes':100,'actual_business_source_seconds':1,
             'echo':{'population':20,'on_time':20},'native_business_interval':{'actual_interval_seconds':1,'client':{
                 'udp_packets_tx':20,'ack_frames_tx':20,'udp_bytes_tx':2000}}}
        rows=[row,{**copy.deepcopy(row),'ack_profile':'every-eight'}]
        s,c=aggregate(rows,plan());self.assertEqual(s['0/every-two']['windows'],1)
        self.assertFalse(c['0']['mechanism_screen_passed']);self.assertNotIn('2000',c)


if __name__=='__main__':unittest.main()
