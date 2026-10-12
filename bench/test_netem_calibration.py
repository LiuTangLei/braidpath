import unittest
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

from bench.netem_calibration import receiver_rate, calibrate_shared
from bench.netem_shared import shared_plan


class ReceiverRate(unittest.TestCase):
    def test_uses_observed_delivery_not_sender_rate(self):
        result = {"end": {"sum_sent": {"bits_per_second": 140_000_000, "sender": True},
                          "sum_received": {"bits_per_second": 97_000_000, "sender": False}}}
        self.assertEqual(receiver_rate(result), 97)

    def test_sender_only_or_failed_results_are_invalid(self):
        for result in [{"error": "test failed"},
                       {"end": {"sum": {"bits_per_second": 140_000_000, "sender": True}}}]:
            with self.assertRaises(ValueError):
                receiver_rate(result)


class SharedCalibration(unittest.TestCase):
    def test_measures_leaf_and_access_independently_at_same_rate_bounds(self):
        class Process:
            returncode = None
            def wait(self, timeout):
                self.returncode = 0
            def poll(self):
                return self.returncode

        with tempfile.TemporaryDirectory() as directory:
            jobs = []
            class Bed:
                output = Path(directory)
                client, server = "client", "server"
                def qdiscs(self):
                    return {}
                def command(self, argv):
                    return SimpleNamespace(stdout=" ".join(f":{p}" for p in [9300, 9301, 9302, 9303, 9310]))
                def spawn(self, namespace, role, argv):
                    jobs.append((namespace, role, argv))
                    if role.endswith("-source"):
                        rate = 382_000_000 if role == "calibration-access-source" else 95_000_000
                        (self.output / f"{role}.log").write_text(json.dumps({
                            "end": {"sum_received": {"bits_per_second": rate, "sender": False}}}))
                    return Process(), 0
            plan = shared_plan("client", "server", "bridge", [30, 45, 60, 80], 100, 400, 1024)
            calibrate_shared(Bed(), plan, 100)
            self.assertEqual(len(jobs), 10)
            self.assertEqual(jobs[-2][0:2], ("bridge", "calibration-access-server"))
            sources = [argv for _, role, argv in jobs if role.endswith("-source")]
            self.assertEqual([argv[argv.index("-b") + 1] for argv in sources], ["140M"] * 4 + ["560M"])
            result = json.loads((Path(directory) / "rate-calibration.json").read_text())
            self.assertTrue(result["passed"])
            self.assertEqual([p["configured_mbps"] for p in result["paths"]], [100] * 4 + [400])


if __name__ == "__main__":
    unittest.main()
