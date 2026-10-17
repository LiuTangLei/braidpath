import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from bench.native_lab import ROOT, capacity_mbps, client_arguments, parse_args, parse_step, per_second_goodput, path_rates
from types import SimpleNamespace


class Accounting(unittest.TestCase):
    def test_capacity_averages_each_path_over_its_registered_steps(self):
        steps = [parse_step("5:0:60"), parse_step("5:1:60")]
        self.assertEqual(capacity_mbps([15, 15, 60, 60], steps, 20), (15 * 5 + 60 * 15) / 20 * 2 + 120)
        self.assertEqual(capacity_mbps([10], [], 10), 10)
        # A later step on the same path replaces the earlier one.
        self.assertEqual(capacity_mbps([10], [parse_step("2:0:20"), parse_step("4:0:5")], 10),
                         (10 * 2 + 20 * 2 + 5 * 6) / 10)

    def test_per_second_goodput_counts_only_on_time_samples_by_send_time(self):
        start = 1_000_000
        samples = [{"send_unix_us": start + 10, "receive_unix_us": start + 20},
                   {"send_unix_us": start + 1_500_000, "receive_unix_us": start + 1_500_000 + 250_000},
                   {"send_unix_us": start + 1_600_000, "receive_unix_us": None},
                   {"send_unix_us": start + 1_700_000, "receive_unix_us": start + 1_800_000}]
        per_packet = 964 * 8 / 1e6
        self.assertEqual(per_second_goodput(samples, start, 2), [round(per_packet, 3), round(per_packet, 3)])

    def test_rates_are_single_or_per_path(self):
        self.assertEqual(path_rates(SimpleNamespace(rate_mbps=[60], rtt_ms=[30, 45])), [60, 60])
        self.assertEqual(path_rates(SimpleNamespace(rate_mbps=[10, 20], rtt_ms=[30, 45])), [10, 20])
        with self.assertRaises(ValueError):
            path_rates(SimpleNamespace(rate_mbps=[10, 20], rtt_ms=[30, 45, 60]))


class Arguments(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.binary = Path(self.directory.name) / "binary"
        self.binary.write_bytes(b"")
        self.common = ["--binary", str(self.binary), "--lab-binary", str(self.binary),
                       "--output", str(ROOT / "local" / "never-created")]

    def tearDown(self):
        self.directory.cleanup()

    def rejected(self, extra):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parse_args(self.common + extra)

    def test_bounded_workloads_and_local_output(self):
        args = parse_args(self.common + ["--step", "5:0:60", "--loss-percent", "50", "--rate-bps", "auto"])
        self.assertEqual(args.step, [{"at_seconds": 5.0, "path": 0, "rate_mbps": 60.0}])
        for extra in (["--pps", "50001"], ["--duration-seconds", "31"], ["--loss-percent", "91"],
                      ["--step", "5:4:60"], ["--step", "20:0:60"], ["--step", "1:0:0"],
                      ["--rate-mbps", "10", "20"], ["--rate-bps", "fast"], ["--queue-packets", "4"],
                      ["--rtt-ms", *["30"] * 9]):
            self.rejected(extra)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parse_args(["--binary", str(self.binary), "--lab-binary", str(self.binary),
                        "--output", str(Path(self.directory.name) / "run")])

    def test_modes_and_recovery_options_reach_the_client(self):
        args = parse_args(self.common + ["--legacy-recovery", "--client-extra-arg=--x"])
        argv = client_arguments(args, "cert", "token", "127.0.0.1:1", ["127.0.0.1:2", "127.0.0.1:3"], [])
        self.assertEqual(argv.count("--entrance"), 2)
        self.assertEqual(argv[argv.index("--path-group", argv.index("127.0.0.1:3")) + 1], "1")
        self.assertIn("--quality-schedule", argv)
        self.assertEqual(argv[-2:], ["--legacy-recovery", "--x"])
        adaptive = parse_args(self.common + ["--mode", "adaptive"])
        argv = client_arguments(adaptive, "cert", "token", "127.0.0.1:1", ["127.0.0.1:2"], [])
        self.assertIn("--probe-guided-recovery", argv)
        self.assertNotIn("--legacy-recovery", argv)


if __name__ == "__main__":
    unittest.main()
