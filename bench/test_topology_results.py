"""Small synthetic raw-cohort contracts, not performance evidence."""
import copy
import unittest
from bench.delivery_frontier import EvidenceError
from bench.topology_results import samples_summary, topology_census


def fixture():
    spec={'bulk_count':2,'echo_count':2,'bulk_pps':2,'datagram_bytes':1000,'echo_pps':2,'echo_bytes':128}
    source=[{'seq':i,'send_unix_us':10+i} for i in range(2)]
    received=[{'seq':i,'send_unix_us':10+i,'receive_unix_us':20+i,'missing':False} for i in range(2)]
    echo=[{'seq':i,'send_unix_us':10+i,'receive_unix_us':20+i,'send_monotonic_ns':1_000_000,
           'receive_monotonic_ns':2_000_000,'rtt_ms':1.,'missing':False} for i in range(2)]
    report={'outcome':'ok','final':True,'corrupt':0,'duplicate':0,'requested_count':2,'sent':2,
            'received':2,'run_id':'r','send_span_seconds':1,'actual_offered_load_bps':16000}
    e=copy.deepcopy(report);e['actual_offered_load_bps']=2048
    return [source,received,echo,report,copy.deepcopy(report),e,spec]


class SampleTests(unittest.TestCase):
    def test_same_clock_rtt_and_unique_source_slots(self):
        r=samples_summary(*fixture())
        self.assertEqual(r['unique_delivered'],2)
        self.assertEqual(r['request_rtt_ms'],[1.,1.])

    def test_missing_keeps_original_and_request_population(self):
        a=fixture();a[1][1].update(receive_unix_us=None,missing=True);a[4]['received']=1
        a[2][1].update(receive_monotonic_ns=None,receive_unix_us=None,rtt_ms=None,missing=True);a[5]['received']=1
        r=samples_summary(*a)
        self.assertEqual(r['unique_delivered'],1)
        self.assertEqual(r['request_rtt_ms'],[1.,None])

    def test_timestamp_or_sequence_relabel_cannot_pass(self):
        for key,value in [('send_unix_us',999),('seq',99),('missing',True)]:
            a=fixture();a[1][0][key]=value
            with self.assertRaises(EvidenceError):samples_summary(*a)

    def test_reported_rtt_cannot_differ_from_monotonic_clock(self):
        a=fixture();a[2][0]['rtt_ms']=.5
        with self.assertRaisesRegex(EvidenceError,'same-clock'):samples_summary(*a)

    def test_incomplete_corrupt_or_mispaced_sources_fail(self):
        for key,value in [('sent',1),('corrupt',1),('duplicate',1),('actual_offered_load_bps',10)]:
            a=fixture();a[3][key]=value
            with self.assertRaises(EvidenceError):samples_summary(*a)
        a=fixture();a[0].pop()
        with self.assertRaises(EvidenceError):samples_summary(*a)


def endpoint(role, n=2):
    paths={str(i):{'path_id':i,'connection_id':i+100,'authenticated':True,'total_generations':1,
                   'local_socket':'0.0.0.0:'+str(10000+i),'peer_socket':'127.0.0.1:9000',
                   'quinn_admitted_originals':10,'quinn':{'udp_bytes_tx':100,'udp_bytes_rx':200}} for i in range(n)}
    return {'role':role,'outcome':'stopped','final':True,'error':None,'stats':{
        'shutdown_complete':True,'drain_incomplete':False,'omitted_session_scopes':0,
        'evicted_session_scopes':0,'omitted_path_scopes':0,'paths':paths,
        'sessions':{'s':{'direction':{'symbols':{'repairs_generated':0},
                                    'sender_frontier':{'enabled':False,'small_rank_changes':0}}}}}}


class TopologyTests(unittest.TestCase):
    def test_same_route_requires_real_distinct_connections_and_sockets(self):
        argv=['client','--entrance','127.0.0.1:9000','--entrance','127.0.0.1:9000']
        r=topology_census(endpoint('client'),endpoint('server'),argv,['127.0.0.1:9000']*2)
        self.assertEqual(r['client']['connections'],2)

    def test_wrong_socket_connection_or_generation_is_rejected(self):
        argv=['client','--entrance','127.0.0.1:9000','--entrance','127.0.0.1:9000']
        for field,value in [('local_socket','0.0.0.0:10000'),('connection_id',100),('total_generations',2)]:
            c=endpoint('client');c['stats']['paths']['1'][field]=value
            with self.assertRaises(EvidenceError):topology_census(c,endpoint('server'),argv,['127.0.0.1:9000']*2)

    def test_repair_or_rejected_preference_cannot_enter_control(self):
        argv=['client','--entrance','127.0.0.1:9000','--entrance','127.0.0.1:9000']
        c=endpoint('client');c['stats']['sessions']['s']['direction']['symbols']['repairs_generated']=1
        with self.assertRaises(EvidenceError):topology_census(c,endpoint('server'),argv,['127.0.0.1:9000']*2)


if __name__=='__main__':unittest.main()
