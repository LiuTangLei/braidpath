"""Finite warmup accounting using tiny synthetic fixtures, not network evidence."""
import copy
import unittest
from bench.delivery_frontier import EvidenceError
from bench.warmup_profile import make_plan, analyze, pool


def fixture(warm=3):
    total=warm+10
    spec={'bulk_pps':2,'echo_pps':2,'datagram_bytes':1000,'net_payload_bytes':964,'echo_bytes':128}
    case={'bulk_count':2*total,'echo_count':2*total,'warmup_bulk_records':2*warm,
          'warmup_echo_requests':2*warm,'business_bulk_records':20,'business_echo_requests':20}
    source=[{'seq':i,'send_unix_us':1_000_000+i*500_000} for i in range(2*total)]
    received=[{**r,'receive_unix_us':r['send_unix_us']+1000,'missing':False} for r in source]
    echo=[{**r,'send_monotonic_ns':r['send_unix_us']*1000,
           'receive_monotonic_ns':r['send_unix_us']*1000+1_000_000,
           'receive_unix_us':r['send_unix_us']+1000,'rtt_ms':1.,'missing':False} for r in source]
    report={'requested_count':2*total,'sent':2*total,'received':2*total,'run_id':'x','outcome':'ok',
            'final':True,'corrupt':0,'duplicate':0,'actual_offered_load_bps':16000,
            'send_span_seconds':total-.5}
    er={**report,'actual_offered_load_bps':2048}
    return [source,received,echo,report,copy.deepcopy(report),er,case,spec]


class WarmupTests(unittest.TestCase):
    def test_plan_fixed_mirrored_and_extra_cost_visible(self):
        p=make_plan('r3',['r0','r1','r2','r3'])
        names=[r['mode'] for r in p['order']]
        self.assertEqual(names,names[::-1])
        self.assertEqual(p['limits']['nominal_total_source_seconds'],92)
        self.assertEqual(p['modes']['aggregate_warm']['warmup_bulk_records'],120000)
        self.assertFalse(p['warmup_cwnd_override'])
        self.assertFalse(p['selected_single_is_current_best_proven'])

    def test_prefix_not_added_to_business_and_time_closes(self):
        r=analyze(*fixture())
        self.assertEqual(r['warmup']['source_records'],6)
        self.assertEqual(r['business']['source_records'],20)
        self.assertEqual(r['complete_run']['source_records'],26)
        self.assertEqual(r['warmup']['unique_net_payload_bytes']+r['business']['unique_net_payload_bytes'],r['complete_run']['unique_net_payload_bytes'])
        self.assertLess(r['business_goodput_charging_prefix_time_mbps'],r['business']['goodput_mbps'])

    def test_cold_has_zero_prefix_and_same_business_population(self):
        r=analyze(*fixture(0))
        self.assertEqual(r['warmup']['source_span_seconds'],0)
        self.assertIsNone(r['warmup']['goodput_mbps'])
        self.assertEqual(r['business'],r['complete_run'])

    def test_missing_prefix_never_poison_or_hide_business(self):
        a=fixture();a[1][0].update(receive_unix_us=None,missing=True);a[4]['received']-=1
        a[2][0].update(receive_monotonic_ns=None,receive_unix_us=None,rtt_ms=None,missing=True);a[5]['received']-=1
        r=analyze(*a)
        self.assertEqual(r['warmup']['missing_records'],1)
        self.assertEqual(r['business']['missing_records'],0)
        self.assertEqual(r['complete_run']['echo']['missing'],1)

    def test_business_missing_stays_in_tail_population(self):
        a=fixture()
        for i in [10,11]:
            a[2][i].update(receive_monotonic_ns=None,receive_unix_us=None,rtt_ms=None,missing=True)
        a[5]['received']-=2
        r=analyze(*a)
        self.assertEqual(r['business']['echo']['missing'],2)
        self.assertIsNone(r['business']['echo']['p95_ms'])

    def test_source_clock_jump_rejected(self):
        a=fixture();a[3]['send_span_seconds']+=1
        with self.assertRaisesRegex(EvidenceError,'monotonic'):analyze(*a)
        a=fixture();a[0][3]['send_unix_us']=0;a[1][3]['send_unix_us']=0
        with self.assertRaisesRegex(EvidenceError,'regressed'):analyze(*a)

    def test_partition_error_rejected(self):
        a=fixture();a[6]['warmup_bulk_records']+=1
        with self.assertRaises(EvidenceError):analyze(*a)

    def test_pool_does_not_average_per_window_quantiles(self):
        p=analyze(*fixture())['business'];s=pool([p,p])
        self.assertEqual(s['requests'],40)
        self.assertTrue(s['p95_requires_raw_rtt_pool'])
        self.assertIsNone(s['p95_ms'])

    def test_invalid_routes_fail(self):
        for routes in [['r0'],['r0']*4,['r0','r1','r2','']]:
            with self.assertRaises(EvidenceError):make_plan('r0',routes)
        with self.assertRaises(EvidenceError):make_plan('r9',['r0','r1','r2','r3'])


if __name__=='__main__':unittest.main()
