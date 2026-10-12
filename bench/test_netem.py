import csv
import json
from pathlib import Path
import tempfile
import signal
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from bench.netem import Testbed, latest_complete_snapshot, parse_snmp, path_commands, shaping_errors, summarize, timeseries


def samples(count, received):
    return [{"seq": index, "send_unix_us": 1000000 + index * 100,
             "receive_unix_us": 1001000 + index * 100 if index < received else None}
            for index in range(count)]


class DeliveryAccounting(unittest.TestCase):
    def test_missing_records_remain_in_tail_and_deadline_denominator(self):
        result = summarize(samples(100, 97), {"requested_count": 100, "sent": 100, "send_span_seconds": 1}, 100)
        self.assertEqual(result["on_time_ratio"], .97)
        self.assertEqual(result["p95_ms"], 1)
        self.assertEqual(result["p99_ms"], "infinity")
        self.assertFalse(result["joint_gate_passed"])

    def test_actual_source_span_prevents_nominal_rate_false_pass(self):
        # Nominal one-second denominator would report308.48Mbps, actual1.04s <300.
        result = summarize(samples(40000, 40000), {"requested_count": 40000, "sent": 40000,
                           "send_span_seconds": 1.04}, 40000)
        self.assertAlmostEqual(result["deadline_goodput_mbps"], 308.48 / 1.04)
        self.assertFalse(result["joint_gate_passed"])

    def test_missing_slots_and_clock_inversions_invalidate_measurement(self):
        population = samples(100, 100)
        source = {"requested_count": 100, "sent": 100, "send_span_seconds": 1}
        with self.assertRaises(ValueError):
            summarize(population[:-1], source, 100)
        population[0]["receive_unix_us"] = population[0]["send_unix_us"] - 1
        with self.assertRaises(ValueError):
            summarize(population, source, 100)


class SenderModeFlags(unittest.TestCase):
    def prepared_client_arguments(self, mode):
        class ClientPrepared(Exception):
            pass
        with tempfile.TemporaryDirectory() as directory:
            bed = Testbed(Path(directory))
            captured = {}
            bed.command = lambda argv: None
            def spawn(namespace, role, argv):
                captured[role] = argv
                return SimpleNamespace(pid=123), 1000
            def ready(process, started, role, *args):
                if role == "client":
                    raise ClientPrepared()
            bed.spawn, bed.runtime_ready = spawn, ready
            args = SimpleNamespace(binary="/candidate/braidpath", mode=mode, datagram_buffer_bytes=None)
            with self.assertRaises(ClientPrepared):
                bed.run(args)
            return captured["client"]

    def test_quality_mode_only_enables_quality_schedule_with_receiver_feedback(self):
        args = self.prepared_client_arguments("quality")
        self.assertIn("--quality-schedule", args)
        self.assertIn("--receiver-feedback", args)
        self.assertEqual(args[args.index("--fec") + 1], "0")
        self.assertEqual(args[args.index("--rate-bps") + 1], "400000000")
        self.assertTrue(all(flag not in args for flag in
            ["--adaptive", "--capacity-probe-bps", "--probe-guided-recovery"]))

    def test_fixed_and_adaptive_modes_keep_their_existing_flags(self):
        fixed = self.prepared_client_arguments("fixed")
        adaptive = self.prepared_client_arguments("adaptive")
        self.assertTrue(all(flag not in fixed for flag in
            ["--quality-schedule", "--adaptive", "--capacity-probe-bps", "--probe-guided-recovery"]))
        self.assertNotIn("--quality-schedule", adaptive)
        self.assertIn("--adaptive", adaptive)
        self.assertIn("--probe-guided-recovery", adaptive)
        self.assertEqual(adaptive[adaptive.index("--capacity-probe-bps") + 1], "20000000")
        self.assertIn("--receiver-feedback", fixed)
        self.assertIn("--receiver-feedback", adaptive)


class NetworkAndCounters(unittest.TestCase):
    def test_unavailable_resource_diagnostics_do_not_block_network_or_business_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            bed = Testbed(output)
            bed.owned_namespaces = ["owned"]
            def command(argv):
                raw = "Udp: InErrors RcvbufErrors\nUdp: 0 0\n" if argv[-1] == "/proc/net/snmp" else "[]"
                return SimpleNamespace(stdout=raw)
            bed.command = command
            with patch("bench.netem.Path.read_text", side_effect=PermissionError("optional file unavailable")):
                bed.network_snapshot("network.json")
            evidence = json.loads((output / "network.json").read_text())
            self.assertEqual(evidence["namespaces"]["owned"]["snmp_counters"]["Udp"]["RcvbufErrors"], 0)
            self.assertIsNone(evidence["guest_pressure"]["memory"]["raw"])
            self.assertIn("PermissionError", evidence["container_memory"]["memory.current"]["error"])
            self.assertIsNone(evidence["container_cpu"]["cpu.stat"])
            result = summarize(samples(40000, 40000), {"requested_count": 40000, "sent": 40000,
                               "send_span_seconds": 1}, 40000)
            self.assertTrue(result["joint_gate_passed"])
            self.assertEqual(bed.sample_errors, [])

    def test_resource_scopes_and_source_main_thread_require_a_live_owned_process(self):
        with tempfile.TemporaryDirectory() as directory:
            bed = Testbed(Path(directory))
            source = SimpleNamespace(pid=123, poll=lambda: None)
            bed.jobs = [("client", SimpleNamespace(pid=999, poll=lambda: None)), ("source", source)]
            reads = []
            def read(path):
                reads.append(str(path))
                return "1000 2000 3\n"
            with patch("bench.netem.Path.read_text", side_effect=read, autospec=True):
                evidence = bed.resource_snapshot()
            self.assertEqual(evidence["guest_pressure"]["scope"], "linux_vm_guest_global")
            self.assertEqual(evidence["container_memory"]["scope"], "container_cgroup")
            self.assertEqual(evidence["source_main_thread_schedstat"]["raw"], "1000 2000 3\n")
            self.assertEqual([path for path in reads if "/task/" in path], ["/proc/123/task/123/schedstat"])
            source.poll = lambda: 0
            with patch("bench.netem.Path.read_text", side_effect=read, autospec=True):
                self.assertIsNone(bed.resource_snapshot()["source_main_thread_schedstat"]["pid"])
            with patch.object(source, "poll", side_effect=[None, 0]), \
                 patch("bench.netem.Path.read_text", side_effect=read, autospec=True):
                exited = bed.resource_snapshot()["source_main_thread_schedstat"]
            self.assertIsNone(exited["raw"])
            self.assertIn("exited during sample", exited["error"])

    def test_partial_tail_is_preserved_and_marks_diagnostic_csv_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, csv_path = Path(directory) / "raw.jsonl", Path(directory) / "path.csv"
            snapshot = {"sample_unix_ms": 1000, "stats": {"directions": {}, "paths": {
                "0": {"path_id": 0, "connection_id": 1, "send_buffer_full_attempts": 4,
                    "quinn": {"udp_bytes_tx": 1000, "congestion_window_bytes": 12000,
                              "smoothed_rtt_ms": 80}}}}}
            evidence = json.dumps(snapshot) + '\n{"sample_unix_ms":2'
            raw.write_text(evidence)
            status = timeseries(raw, csv_path)
            self.assertFalse(status["complete"])
            self.assertEqual(status["complete_snapshots"], 1)
            self.assertGreater(status["incomplete_tail_bytes"], 0)
            with csv_path.open() as source:
                self.assertEqual(len(list(csv.DictReader(source))), 1)
            self.assertEqual(raw.read_text(), evidence)

    def test_forced_stop_invalidates_orderly_shutdown_but_can_confirm_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            bed = Testbed(Path(directory))
            process = SimpleNamespace(pid=123, returncode=None)
            process.poll = lambda: process.returncode
            def wait(timeout):
                if process.returncode is None:
                    raise subprocess.TimeoutExpired("test-client", timeout)
                return process.returncode
            process.wait = wait
            bed.jobs = [("client", process)]
            bed.owned_namespaces = ["owned-namespace"]
            bed.owned_links = ["owned-link"]
            bed.command = lambda argv, **kwargs: SimpleNamespace(
                returncode=1 if argv[:3] == ["ip", "link", "show"] else 0,
                stdout="[]" if "-j" in argv else "")
            def signal_group(pid, signum):
                if signum == signal.SIGKILL:
                    process.returncode = -signal.SIGKILL
            with patch("bench.netem.os.killpg", side_effect=signal_group):
                errors, exits = bed.cleanup()
            self.assertIn("forced stop: client", errors)
            self.assertEqual(exits["client"], -signal.SIGKILL)
            self.assertFalse(bed.orderly_shutdown)
            self.assertTrue(bed.cleanup_confirmed)

    def test_successful_remove_command_is_insufficient_if_namespace_still_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            bed = Testbed(Path(directory))
            bed.owned_namespaces = ["owned-namespace"]
            bed.command = lambda argv, **kwargs: SimpleNamespace(returncode=0,
                stdout="owned-namespace\n" if argv == ["ip", "netns", "list"] else "[]")
            errors, _exits = bed.cleanup()
            self.assertTrue(bed.orderly_shutdown)
            self.assertFalse(bed.cleanup_confirmed)
            self.assertTrue(any("still present" in error for error in errors))

    def test_udp_kernel_drops_keep_their_own_counters(self):
        raw = ("Ip: InReceives InDiscards\nIp: 1000 4\n"
               "Udp: InDatagrams InErrors RcvbufErrors SndbufErrors\nUdp: 800 5 3 2\n")
        counters = parse_snmp(raw)
        self.assertEqual(counters["Udp"]["InErrors"], 5)
        self.assertEqual(counters["Udp"]["RcvbufErrors"], 3)
        self.assertEqual(counters["Udp"]["SndbufErrors"], 2)
        self.assertEqual(counters["Ip"]["InDiscards"], 4)
        # RcvbufErrors is a subset of InErrors; no synthetic sum invents8drops.
        self.assertNotIn("total_dropped", counters["Udp"])

    def test_neighbor_resolution_is_recorded_but_excluded_from_delay_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            bed = Testbed(output)
            expected = [30, 45, 60, 80]
            def command(argv):
                index = int(argv[argv.index("-I") + 1].split(".")[2]) - 1
                average = expected[index] * 2 if argv[argv.index("-c") + 1] == "1" else expected[index]
                return SimpleNamespace(stdout=f"rtt min/avg/max/mdev = {average}/{average}/{average}/0 ms")
            bed.command = command
            bed.qdiscs = lambda: {namespace: [{"kind": "netem", "drops": 0,
                "dev": f"p{index}{suffix}", "options": {"limit": 1024,
                "delay": {"delay": rtt / 2000}, "rate": {"rate": 12500000}}}
                for index, rtt in enumerate(expected)]
                for namespace, suffix in ((bed.client, "c"), (bed.server, "s"))}
            with patch("bench.netem_calibration.calibrate_links"):
                bed.validate(SimpleNamespace(rtt_ms=expected, rate_mbps=100, queue_packets=1024))
            evidence = json.loads((output / "validation.json").read_text())
            self.assertTrue(evidence["passed"])
            self.assertEqual([p["average_ms"] for p in evidence["ping"]], expected)
            self.assertTrue(all(p["neighbor_warmup_stdout"] for p in evidence["ping"]))

    def test_delay_units_and_shaped_rate_are_checked_on_both_links(self):
        rtts = [30, 45, 60, 80]
        queues = {namespace: [{"kind": "netem", "dev": f"p{i}{suffix}", "drops": 0,
            "options": {"limit": 1024, "delay": {"delay": rtt / 2000 - .000001},
            "rate": {"rate": 12500000}}} for i, rtt in enumerate(rtts)]
            for namespace, suffix in (("client", "c"), ("server", "s"))}
        self.assertEqual(shaping_errors(queues, "client", "server", rtts, 100, 1024), [])
        queues["server"][3]["options"]["delay"]["delay"] = .08
        queues["client"][0]["options"]["rate"]["rate"] = 100000000
        errors = shaping_errors(queues, "client", "server", rtts, 100, 1024)
        self.assertIn("p3s: half-RTT delay mismatch", errors)
        self.assertIn("p0c: shaped byte rate mismatch", errors)

    def test_authenticated_four_path_gate_succeeds_before_final_file_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            snapshot = {"schema_version": 1, "role": "client", "final": False,
                "outcome": "running", "process_id": 123, "instance_id": "test-instance",
                "sample_unix_ms": 1000, "stats": {"ready": True, "listener_bound": True,
                    "target_configured": True, "configured_paths": 4,
                    "paths": {str(index): {"session_id": "test-session", "path_id": index,
                        "authenticated": True, "quinn": {"closed": False}} for index in range(4)}}}
            (path / "client.jsonl").write_text(json.dumps(snapshot) + "\n")
            process = SimpleNamespace(pid=123, poll=lambda: None)
            session = Testbed(path).runtime_ready(process, 1000, "client", range(4))
            self.assertEqual(session, "test-session")
            self.assertFalse((path / "client.json").exists())

    def test_live_readiness_uses_complete_periodic_line_without_final_stats(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "client.jsonl"
            self.assertIsNone(latest_complete_snapshot(path))
            path.write_text('{"sample_unix_ms":10}\n{"sample_unix_ms":20}\n{"sample_unix_ms":3')
            self.assertEqual(latest_complete_snapshot(path)["sample_unix_ms"], 20)
            self.assertEqual(latest_complete_snapshot(path, 48)["sample_unix_ms"], 20)
            self.assertFalse((Path(directory) / "client.json").exists())

    def test_registered_rtt_is_split_across_both_directions(self):
        commands = path_commands("client", "server", 0, 80, 100, 1024)
        shaping = [argv for argv in commands if "netem" in argv]
        self.assertEqual(len(shaping), 2)
        self.assertEqual({argv[3] for argv in shaping}, {"client", "server"})
        self.assertTrue(all(argv[argv.index("delay") + 1] == "40ms" for argv in shaping))
        self.assertTrue(all(argv[argv.index("rate") + 1] == "100mbit" for argv in shaping))
        self.assertTrue(all(argv[argv.index("limit") + 1] == "1024" for argv in shaping))

    def test_cumulative_samples_become_deltas_not_repeated_drop_totals(self):
        def snapshot(at, sent_bytes, full, ingress, symbol):
            return {"sample_unix_ms": at, "stats": {
                "directions": {"client_to_server": {"records": {"sender_queue_full_dropped": ingress},
                    "symbols": {"originals_queue_full_dropped": symbol}}},
                "paths": {"path": {"path_id": 0, "connection_id": 1, "send_buffer_full_attempts": full,
                    "quinn": {"udp_bytes_tx": sent_bytes, "congestion_window_bytes": 12000, "smoothed_rtt_ms": 80}}}}}
        with tempfile.TemporaryDirectory() as directory:
            raw, csv_path = Path(directory) / "raw.jsonl", Path(directory) / "paths.csv"
            raw.write_text("\n".join(json.dumps(s) for s in [snapshot(1000, 0, 4, 2, 7),
                snapshot(1250, 250000, 10, 3, 9), snapshot(1500, 500000, 10, 3, 9)]) + "\n")
            timeseries(raw, csv_path)
            with csv_path.open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(rows[1]["udp_tx_mbps"], "8.0")
            self.assertEqual(rows[1]["full_attempts_delta"], "6")
            self.assertEqual(rows[1]["original_full_delta"], "2")
            self.assertEqual(rows[2]["original_full_delta"], "0")


if __name__ == "__main__":
    unittest.main()
