"""Host-reference boundaries; no live network or service manipulation."""
import unittest
from unittest.mock import Mock, patch
from bench.host_reference import CASE, SOURCE, MODES, stage_fields, Owned


class HostReferenceTests(unittest.TestCase):
    def test_same_prefix_and_business_supply_for_all_modes(self):
        self.assertEqual(CASE['warmup_bulk_records'],120000)
        self.assertEqual(CASE['bulk_count']-CASE['warmup_bulk_records'],400000)
        self.assertEqual(CASE['echo_count']-CASE['warmup_echo_requests'],200)
        self.assertEqual(SOURCE['bulk_pps']*SOURCE['datagram_bytes']*8,320000000)
        self.assertEqual(set(MODES),{'udp','native_thin','native_matched','overlay_native','overlay_adaptive'})

    def test_native_census_is_conservation_not_delivery_promise(self):
        c=dict(udp_received=100,oversize=0,flow_full=0,input_enqueued=90,input_full=10,
               encoded=80,input_shutdown=10,queue_full=20,expired=10,queued_shutdown=10,
               api_admitted=40,api_error=0,carrier_received=30,invalid=0,
               target_delivered=25,target_error=5)
        self.assertTrue(stage_fields({'counters':c}))
        c['api_admitted']+=1
        self.assertFalse(stage_fields({'counters':c}))

    def test_cleanup_signals_only_owned_unfinished_groups(self):
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'done').mkdir();(root/'live').mkdir()
            owner=Owned(root)
            done=Mock(pid=1,returncode=0);done.poll.return_value=0
            live=Mock(pid=2,returncode=0);live.poll.side_effect=[None,0]
            owner.children=[('done',done),('live',live)]
            with patch('bench.host_reference.os.killpg') as kill:
                owner.stop_all()
            self.assertEqual(kill.call_count,1)
            self.assertEqual(kill.call_args.args[0],2)
            self.assertTrue(all(r['exited'] for r in owner.cleanup))


if __name__=='__main__':unittest.main()
