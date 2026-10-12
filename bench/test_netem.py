import csv
import json
from pathlib import Path
import tempfile
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


class NetworkAndCounters(unittest.TestCase):
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
