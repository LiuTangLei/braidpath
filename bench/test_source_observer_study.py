import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from bench import source_observer_study as study


class SourceObserverStudyTests(unittest.TestCase):
    def setUp(self):
        self.handlers = {s: signal.getsignal(s) for s in [signal.SIGINT, signal.SIGTERM]}

    def tearDown(self):
        for signum, handler in self.handlers.items():
            signal.signal(signum, handler)

    def run_main(self, root, function, profile='presence'):
        binary = root/'binary'
        binary.write_bytes(b'fixed-source')
        output = root/'results'
        with patch.dict('os.environ', {'BRAIDPATH_SOURCE_STUDY':'1'}), \
             patch.object(Path, 'exists', return_value=True), \
             patch('sys.argv', ['study','--binary',str(binary),'--output',str(output),'--study',profile]), \
             patch.object(study, 'window', side_effect=function):
            code = study.main()
        return code, json.loads((output/'result.json').read_text())

    def test_measurement_failures_are_retained_in_all_four_registered_windows(self):
        calls = []
        def run(root, binary, enabled):
            calls.append(enabled)
            return {'window':root.name, 'qualification':{'source_qualified':False}}
        with tempfile.TemporaryDirectory() as name:
            code, result = self.run_main(Path(name), run)
        self.assertEqual(calls, [False, True, True, False])
        self.assertEqual(code, 0)  # Diagnostic completion, NOT source acceptance.
        self.assertTrue(result['complete'])
        self.assertEqual(len(result['windows']), 4)
        self.assertIsNone(result['causal_conclusion'])

    def test_lifecycle_failure_stops_later_windows_without_retry(self):
        calls = []
        def run(root, binary, enabled):
            calls.append(enabled)
            if enabled:
                raise RuntimeError('owned cleanup failed')
            return {'window':root.name}
        with tempfile.TemporaryDirectory() as name:
            code, result = self.run_main(Path(name), run)
        self.assertEqual(calls, [False, True])
        self.assertEqual(code, 1)
        self.assertFalse(result['complete'])
        self.assertEqual(len(result['windows']), 1)

    def test_binary_change_invalidates_before_next_window(self):
        calls = []
        def run(root, binary, enabled):
            calls.append(enabled)
            binary.write_bytes(b'changed')
            return {'window':root.name}
        with tempfile.TemporaryDirectory() as name:
            code, result = self.run_main(Path(name), run)
        self.assertEqual(calls, [False])
        self.assertEqual(code, 1)
        self.assertIn('binary changed', result['error'])

    def test_flush_study_keeps_collection_and_fixed_buffer_in_every_arm(self):
        calls=[]
        def run(root, binary, enabled, flush_each_sample):
            calls.append((enabled,flush_each_sample))
            return {'window':root.name}
        with tempfile.TemporaryDirectory() as name:
            code,result=self.run_main(Path(name),run,'flush')
            registration=json.loads((Path(name)/'results/registration.json').read_text())
        self.assertEqual(calls,[(True,True),(True,False),(True,False),(True,True)])
        self.assertEqual(registration['file_buffer_bytes'],65536)
        self.assertEqual(code,0)
        self.assertTrue(result['complete'])

    def test_observer_close_failure_cannot_skip_owned_process_cleanup(self):
        owner = MagicMock()
        owner.cleanup = []
        owner.launch.return_value.wait.side_effect = TimeoutError('source timeout')
        observer = MagicMock()
        observer.close.side_effect = RuntimeError('observer timeout')
        with tempfile.TemporaryDirectory() as name, \
             patch.object(study, 'Owned', return_value=owner), \
             patch.object(study, 'Observer', return_value=observer), \
             patch.object(study, 'wait_ready'), \
             patch.object(study, 'port', return_value='127.0.0.1:9999'):
            with self.assertRaisesRegex(RuntimeError, 'observer timeout'):
                study.window(Path(name)/'window_a', Path('/fake-binary'), True)
        owner.stop_all.assert_called_once()


if __name__ == '__main__':
    unittest.main()
