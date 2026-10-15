"""Synthetic health-gate contracts, not performance measurements."""
import copy
import unittest
from bench.lab_health import classify, SOCKET_ROLES


def fixture():
    counter={'application_api_admitted':10,'application_datagrams_received':10,
             'native_datagram_frames_tx':10,'native_datagram_frames_rx':10,
             'api_admitted_not_native_transmitted':0,'native_received_not_read_by_application':0,
             'model_queue_discards':0}
    result={'boundary_census':{'server_to_client':copy.deepcopy(counter),'client_to_server':copy.deepcopy(counter)},
            'business_echo':{'population':2,'received':2,'on_time_200ms':2},
            'business_population':10,'business_delivered':10,'ending_application_queues':{'bulk':0,'reply':0,'request':0},
            'final_counters':{'forward':{'maximum_timer_lateness_us':1000},'reverse':{'maximum_timer_lateness_us':1000}},
            'generator_complete':True,'generator_pacing_fraction':1.0}
    config={'socket_receive_bytes':1048576,'reverse_pps':0}
    sockets=[{'role':role,'address':'127.0.0.1:'+str(11000+i),'requested_receive_bytes':1048576,
              'effective_receive_bytes':1048576} for i,role in enumerate(sorted(SOCKET_ROLES))]
    return result,config,sockets


class LabHealthTests(unittest.TestCase):
    def test_clean_originals_and_request_deadlines_pass(self):
        value=classify(*fixture())
        self.assertTrue(value['clean_reference_passed'])
        self.assertFalse(value['network_root_cause_identified'])

    def test_native_receive_gap_is_not_called_network_loss(self):
        r,c,s=fixture();d=r['boundary_census']['server_to_client']
        d['application_datagrams_received']=9;d['native_received_not_read_by_application']=1
        value=classify(r,c,s)
        self.assertFalse(value['consumer_loss_free'])
        self.assertFalse(value['clean_reference_passed'])
        self.assertFalse(value['network_root_cause_identified'])

    def test_one_missing_or_late_request_blocks_clean_reference(self):
        for key in ['received','on_time_200ms']:
            r,c,s=fixture();r['business_echo'][key]-=1
            self.assertFalse(classify(r,c,s)['clean_reference_passed'])

    def test_source_rejection_is_not_hidden_by_api_delivery(self):
        r,c,s=fixture();r['business_delivered']=9
        self.assertFalse(classify(r,c,s)['clean_reference_passed'])
        r,c,s=fixture();r['generator_pacing_fraction']=.9
        self.assertFalse(classify(r,c,s)['clean_reference_passed'])

    def test_intentional_bottleneck_is_not_a_clean_calibration(self):
        r,c,s=fixture();c['reverse_pps']=2000
        value=classify(r,c,s)
        self.assertTrue(value['consumer_loss_free'])
        self.assertTrue(value['intentional_bottleneck'])
        self.assertFalse(value['clean_reference_passed'])

    def test_legacy_without_census_stays_unknown(self):
        value=classify({}, {}, None)
        self.assertEqual(value['status'],'unknown_legacy_measurement')
        self.assertIsNone(value['consumer_loss_free'])
        self.assertFalse(value['clean_reference_passed'])

    def test_counters_and_socket_scope_are_checked(self):
        r,c,s=fixture();r['boundary_census']['server_to_client']['application_datagrams_received']=9
        with self.assertRaises(ValueError):classify(r,c,s)
        r,c,s=fixture();s[0]['address']='192.0.2.1:1000'
        with self.assertRaises(ValueError):classify(r,c,s)
        r,c,s=fixture();s[0]['effective_receive_bytes']=4096
        self.assertFalse(classify(r,c,s)['clean_reference_passed'])

    def test_overcount_or_nan_is_not_accepted(self):
        r,c,s=fixture();r['business_delivered']=11
        with self.assertRaises(ValueError):classify(r,c,s)

    def test_timer_distortion_cannot_be_called_a_clean_network(self):
        r,c,s=fixture();r['final_counters']['forward']['maximum_timer_lateness_us']=5001
        value=classify(r,c,s)
        self.assertFalse(value['clean_reference_passed'])
        self.assertFalse(value['model_timer_fidelity_passed'])
        r,c,s=fixture();r['generator_pacing_fraction']=float('nan')
        with self.assertRaises(ValueError):classify(r,c,s)


if __name__=='__main__':unittest.main()
