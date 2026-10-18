import contextlib
import hashlib
import io
import random
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

from bench.tcp_lab import (ROOT, Echo, FreshProbe, Target, parse_args, paths_ready, payload,
                           probe_phases, probe_summary, socks_connect, transfer)


def args(*extra, output="local/tcp-lab/test"):
    return parse_args(["--binary", "b", "--lab-binary", "l", "--output", str(ROOT / output),
                       "--path", "20:20", "--path", "30:10", *extra])


class Arguments(unittest.TestCase):
    def test_defaults_use_every_path_and_subsets_select_the_baseline(self):
        self.assertEqual(args().use_path, [0, 1])
        self.assertEqual(args("--use-path", "1").use_path, [1])
        self.assertEqual(args().path, [(20.0, 20.0), (30.0, 10.0)])

    def test_bounds_and_evidence_location_are_enforced(self):
        for extra, output in [(("--use-path", "2"), "local/x"), (("--bytes", "10"), "local/x"),
                              (("--loss-percent", "60"), "local/x"), ((), "results/x"),
                              (("--path", "20:0"), "local/x"), (("--tail-seconds", "5"), "local/x"),
                              (("--fresh-probe-interval-ms", "100"), "local/x"),
                              (("--loss-max-datagram-bytes", "65536"), "local/x"),
                              (("--entrance", "socks5", "--fresh-probe-interval-ms", "10"),
                               "local/x")]:
            with self.subTest(extra=extra, output=output), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    args(*extra, output=output)

    def test_duplex_requires_addressed_streams_and_keeps_total_connections_bounded(self):
        both = args("--direction", "both", "--entrance", "socks5", "--connections", "16")
        self.assertEqual(both.direction, "both")
        for extra in [("--direction", "both"),
                      ("--direction", "both", "--entrance", "socks5", "--connections", "17"),
                      ("--timeout-seconds", "0"), ("--timeout-seconds", "nan"),
                      ("--timeout-seconds", "601")]:
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    args(*extra)


class ProbeOutcomes(unittest.TestCase):
    def test_workload_requires_all_live_paths_in_one_session(self):
        def path(number, session="one", closed=False):
            return {"path_id": number, "session_id": session, "authenticated": True,
                    "quinn": {"closed": closed}}
        def snapshot(*paths):
            return {"stats": {"paths": dict(enumerate(paths))}}
        self.assertFalse(paths_ready(None, 2))
        self.assertFalse(paths_ready(snapshot(path(0)), 2))
        self.assertFalse(paths_ready(snapshot(path(0), path(1, closed=True)), 2))
        self.assertFalse(paths_ready(snapshot(path(0), path(1, session="other")), 2))
        self.assertTrue(paths_ready(snapshot(path(0), path(1)), 2))

    def test_timeouts_remain_in_the_outcome_population(self):
        attempts = [{"elapsed_seconds": .05, "outcome": "ok", "error": None},
                    {"elapsed_seconds": 5, "outcome": "timeout", "error": "timed out"}]
        result = probe_summary(attempts)
        self.assertEqual(result["p99_ms"], 50)
        self.assertEqual(result["p99_all_outcomes_ms_lower_bound"], 5000)
        self.assertEqual((result["attempts"], result["count"], result["failed"], result["timeouts"]),
                         (2, 1, 1, 1))
        self.assertTrue(result["p99_is_censored"])

    def test_cross_boundary_completion_belongs_to_request_start_phase(self):
        attempts = [{"started_monotonic": 9, "finished_monotonic": 11},
                    {"started_monotonic": 10, "finished_monotonic": 25},
                    {"started_monotonic": 20, "finished_monotonic": 21}]
        phases = probe_phases(attempts, 10, 20)
        self.assertEqual(phases, {"idle": attempts[:1], "during_transfer": attempts[1:2],
                                  "after_transfer": attempts[2:]})

    def test_fresh_probe_uses_a_new_connection_per_attempt_and_keeps_failures(self):
        echo = Echo()
        echo.start()
        proxy = socket.create_server(("127.0.0.1", 0))
        accepted = []

        def serve():
            with contextlib.suppress(OSError):
                while True:
                    conn, _ = proxy.accept()
                    accepted.append(conn)
                    conn.recv(3)
                    conn.sendall(b"\x05\x00")
                    conn.recv(10)
                    if len(accepted) == 2:
                        conn.sendall(b"\x05\x05\x00\x01" + bytes(6))
                        conn.close()
                        continue
                    conn.sendall(b"\x05\x00\x00\x01" + bytes(6))
                    threading.Thread(target=Echo.serve, args=(conn,), daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()
        stop = threading.Event()
        probe = FreshProbe("127.0.0.1:%d" % proxy.getsockname()[1], echo.address, 0, stop)
        probe.start()
        while len(probe.attempts) < 3:
            stop.wait(.01)
        stop.set()
        probe.join(5)
        proxy.close()
        echo.listener.close()
        outcomes = [a["outcome"] for a in probe.attempts[:3]]
        self.assertEqual(outcomes, ["ok", "error", "ok"])
        self.assertGreaterEqual(len(accepted), 3)

    def test_empty_window_has_no_percentile(self):
        result = probe_summary([])
        self.assertEqual(result["attempts"], 0)
        self.assertIsNone(result["p99_ms"])
        self.assertIsNone(result["p99_all_outcomes_ms_lower_bound"])


class Transfer(unittest.TestCase):
    def test_progress_does_not_extend_the_transfer_deadline(self):
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.recv.return_value = b"x"
        with patch("bench.tcp_lab.socket.create_connection", return_value=conn), \
             patch("bench.tcp_lab.time.monotonic", side_effect=[0, .25, .5, 1.25]):
            with self.assertRaises(socket.timeout):
                transfer("127.0.0.1:1", "down", b"xx", 1)
        self.assertEqual(conn.recv.call_count, 1)

    def test_payload_is_seeded(self):
        self.assertEqual(payload(1024, 7), payload(1024, 7))
        self.assertNotEqual(payload(1024, 7), payload(1024, 8))

    def test_payload_keeps_seeded_bytes_across_chunks_and_partial_words(self):
        for size in [0, 3, 1024 * 1024 + 7, 2 * 1024 * 1024 + 1]:
            self.assertEqual(payload(size, 19), random.Random(19).randbytes(size))

    def test_payload_256mib_does_not_overflow_python39_randbits_argument(self):
        generator = MagicMock()
        generator.randbytes.return_value = b""
        with patch("bench.tcp_lab.random.Random", return_value=generator):
            payload(256 * 1024 * 1024, 19)
        requests = [call.args[0] for call in generator.randbytes.call_args_list]
        self.assertEqual(sum(requests), 256 * 1024 * 1024)
        self.assertTrue(all(n * 8 < 2 ** 31 for n in requests))

    def test_upload_and_download_verify_integrity_directly_against_the_target(self):
        data = payload(300_000, 3)
        for direction in ("up", "down"):
            with self.subTest(direction=direction):
                target = Target(direction, data)
                target.start()
                result = transfer(target.address, direction, data, 10)
                target.join(5)
                self.assertTrue(result["exact"])
                self.assertEqual(result["received_bytes"], len(data))
                self.assertIsNone(target.error)

    def test_socks_handshake_is_sent_before_the_transfer(self):
        listener = socket.create_server(("127.0.0.1", 0))
        seen = []

        def serve():
            conn, _ = listener.accept()
            with conn:
                seen.append(conn.recv(3))
                conn.sendall(b"\x05\x00")
                seen.append(conn.recv(10))
                conn.sendall(b"\x05\x05\x00\x01" + bytes(6))
        thread = threading.Thread(target=serve)
        thread.start()
        conn = socket.create_connection(listener.getsockname(), timeout=5)
        with conn, self.assertRaises(RuntimeError):
            socks_connect(conn, "10.1.2.3:4660")
        thread.join()
        listener.close()
        self.assertEqual(seen, [b"\x05\x01\x00", b"\x05\x01\x00\x01\x0a\x01\x02\x03\x12\x34"])

    def test_socks_replies_can_be_split_across_tcp_reads(self):
        conn = MagicMock()
        conn.recv.side_effect = [b"\x05", b"\x00", b"\x05\x00\x00\x01", bytes(6)]
        socks_connect(conn, "127.0.0.1:8080")
        self.assertEqual(conn.recv.call_count, 4)

    def test_opposing_transfers_have_independent_targets_and_integrity(self):
        data = payload(300_000, 13)
        targets = {direction: Target(direction, data) for direction in ("up", "down")}
        results = {}
        for target in targets.values():
            target.start()

        def one(direction):
            results[direction] = transfer(targets[direction].address, direction, data, 5)
        workers = [threading.Thread(target=one, args=(direction,)) for direction in targets]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(6)
            self.assertFalse(worker.is_alive())
        for direction, target in targets.items():
            target.join(5)
            target.listener.close()
            self.assertIsNone(target.error)
            self.assertTrue(results[direction]["exact"])
            self.assertEqual(results[direction]["received_bytes"], len(data))

    def test_truncated_download_is_not_exact(self):
        data = payload(100_000, 4)
        listener = socket.create_server(("127.0.0.1", 0))

        def serve():
            conn, _ = listener.accept()
            with conn:
                conn.sendall(data[:50_000])
        thread = threading.Thread(target=serve)
        thread.start()
        result = transfer("127.0.0.1:%d" % listener.getsockname()[1], "down", data, 10)
        thread.join()
        listener.close()
        self.assertFalse(result["exact"])
        self.assertEqual(result["goodput_mbps"], 0.0)
        self.assertNotEqual(hashlib.sha256(data[:50_000]).digest(), hashlib.sha256(data).digest())


if __name__ == "__main__":
    unittest.main()
