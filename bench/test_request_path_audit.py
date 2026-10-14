"""Exact request-ID partition tests; no sockets or fabricated network rates."""
import unittest
from bench.delivery_frontier import EvidenceError
from bench.request_path_audit import request_ledger, bulk_adapter_ledger, native_direction_census


def fixture():
    echo={'run_id':'r','pid':123,'requested_count':4,'sent':4,'received':1,'corrupt':0,'duplicate':0}
    raw={'run_id':'r','pid':123,'samples':[{'seq':i,'send_monotonic_ns':100,
        'receive_monotonic_ns':200 if i==0 else None}for i in range(4)]}
    adapter={'echo_probe_population':{'r':4},'echo_received_sequences':{'r':[0,1,2]},
             'echo_forwarded_sequences':{'r':[0,2]}}
    return echo,adapter,raw


class RequestPathTests(unittest.TestCase):
    def test_missing_partitions_into_exact_observable_boundaries(self):
        result=request_ledger(*fixture())
        self.assertEqual(result['missing_total'],3)
        self.assertEqual(result['not_observed_at_server_application_adapter'],1)
        self.assertEqual(result['server_adapter_received_but_not_forwarded'],1)
        self.assertEqual(result['forwarded_by_server_adapter_but_not_received_by_client'],1)
        self.assertEqual(result['before_adapter_missing_sequences'],[3])
        self.assertEqual(result['after_adapter_missing_sequences'],[2])

    def test_unsent_is_not_called_forward_loss(self):
        echo,adapter,raw=fixture();echo['sent']=3;raw['samples'][3]['send_monotonic_ns']=None
        result=request_ledger(echo,adapter,raw)
        self.assertEqual(result['unsent'],1)
        self.assertEqual(result['not_observed_at_server_application_adapter'],0)

    def test_mismatched_counter_duplicate_or_non_nested_id_is_rejected(self):
        for change in ['raw','counter','duplicate','unseen']:
            echo,adapter,raw=fixture()
            if change=='raw':raw['pid']=999
            if change=='counter':echo['received']=2
            if change=='duplicate':adapter['echo_received_sequences']['r']+=[0]
            if change=='unseen':adapter['echo_forwarded_sequences']['r']+=[3]
            with self.assertRaises(EvidenceError):request_ledger(echo,adapter,raw)

    def test_bulk_adapter_gap_is_not_assigned_to_public_network(self):
        source={'sent':100,'requested_count':100}
        adapter={'bulk_count':100,'counters':{'backend_data_received':80,'bulk_data_forwarded':79}}
        result=bulk_adapter_ledger(source,adapter)
        self.assertEqual(result['source_to_adapter_gap'],20)
        self.assertEqual(result['adapter_forwarding_gap'],1)
        adapter['counters']['bulk_data_forwarded']=90
        with self.assertRaises(EvidenceError):bulk_adapter_ledger(source,adapter)

    def test_ack_frame_count_never_becomes_an_ack_byte_or_loss_claim(self):
        from bench.test_topology_results import endpoint
        client,server=endpoint('client'),endpoint('server')
        for p in client['stats']['paths'].values():
            p['quinn'].update(udp_datagrams_tx=30,udp_bytes_tx=3000,ack_frames_tx=29,
                http_datagram_frames_tx=3,ack_frequency_frames_tx=0,immediate_ack_frames_tx=0,lost_packets=2)
        for p in server['stats']['paths'].values():
            p['quinn'].update(udp_datagrams_rx=28,http_datagram_frames_rx=2)
            p.update(original_records_delivered=8,http_datagrams_received=2)
        value=native_direction_census(client,server)
        self.assertEqual(value['client_native_totals']['ack_frames_tx'],58)
        self.assertIsNone(value['ack_bytes'])
        self.assertIsNone(value['ack_only_packet_count'])
        self.assertIsNone(value['caused_request_loss'])
        self.assertEqual(value['paths'][0]['originals_not_observed_at_server'],2)
        server['stats']['paths']['0']['total_generations']=2
        with self.assertRaises(EvidenceError):native_direction_census(client,server)


if __name__=='__main__':unittest.main()
