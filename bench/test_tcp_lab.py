import contextlib
import hashlib
import io
import socket
import threading
import unittest

from bench.tcp_lab import ROOT, Target, parse_args, payload, socks_connect, transfer


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
                              (("--path", "20:0"), "local/x"), (("--tail-seconds", "5"), "local/x")]:
            with self.subTest(extra=extra, output=output), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    args(*extra, output=output)


class Transfer(unittest.TestCase):
    def test_payload_is_seeded(self):
        self.assertEqual(payload(1024, 7), payload(1024, 7))
        self.assertNotEqual(payload(1024, 7), payload(1024, 8))

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
