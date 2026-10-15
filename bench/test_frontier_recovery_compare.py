import copy
import unittest
from bench.frontier_recovery_compare import pool, quantile, screen


class FrontierRecoveryCompareTests(unittest.TestCase):
    def window(self, label='a', lost=0):
        return {'window': label, 'requests': 200, 'unique_bytes': 1000000,
                'source_span_seconds': 10, 'source_qualified': True,
                'echo_samples': [{'seq': i, 'send_unix_us': i + 1,
                    'receive_unix_us': i + 1001 if i >= lost else None,
                    'rtt_ms': 1.0 if i >= lost else None} for i in range(200)]}

    def test_missing_requests_do_not_disappear_and_bytes_use_actual_span(self):
        v=pool([self.window('a',15),self.window('b',17)])
        self.assertEqual((v['requests'],v['on_time'],v['missing']),(400,368,32))
        self.assertEqual(v['p95_ms'],'infinity');self.assertEqual(v['p99_ms'],'infinity')
        self.assertEqual(v['goodput_mbps'],.8)

    def test_bad_population_or_nonfinite_evidence_cannot_score(self):
        for mode in ['short','duplicate','nan','zero_span','bad_received']:
            row=self.window()
            if mode=='short':row['echo_samples'].pop()
            if mode=='duplicate':row['echo_samples'][1]['seq']=0
            if mode=='nan':row['echo_samples'][1]['rtt_ms']=float('nan')
            if mode=='zero_span':row['source_span_seconds']=0
            if mode=='bad_received':row['echo_samples'][1]['rtt_ms']=None
            with self.assertRaises(ValueError,msg=mode):pool([row])
        with self.assertRaises(ValueError):pool([self.window(),self.window()])

    def test_success_requires_action_completeness_and_each_comparator(self):
        c=pool([self.window('a'),self.window('b')]);r=copy.deepcopy(c)
        r.update(goodput_mbps=.7,p95_ms=2.0)
        options=dict(execution_complete=True,cleanup_confirmed=True,frontier_changes=3)
        self.assertTrue(screen(c,{'incumbent':r},**options)['passed'])
        self.assertFalse(screen(c,{'incumbent':r},**{**options,'frontier_changes':0})['passed'])
        self.assertFalse(screen(c,{'incumbent':r},**{**options,'execution_complete':False})['passed'])
        self.assertFalse(screen(c,{'incumbent':r,'better_single':c},**options)['passed'])
        r['source_qualified']=False
        self.assertFalse(screen(c,{'incumbent':r},**options)['passed'])

    def test_quantile_is_full_population_not_success_only(self):
        self.assertEqual(quantile([50]*196,200,.95),50)
        self.assertEqual(quantile([50]*196,200,.99),'infinity')
        self.assertEqual(quantile([50]*189,200,.95),'infinity')


if __name__=='__main__':unittest.main()
