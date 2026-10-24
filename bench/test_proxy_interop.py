import contextlib
import io
import socket
import struct
import threading
import unittest

from bench.proxy_interop import ROOT, parse_args, socks_connect, tool_config


class Configuration(unittest.TestCase):
    def test_every_tool_forwards_its_socks_inbound_to_the_braidpath_outbound(self):
        for tool in ("mihomo", "sing-box", "xray"):
            for outbound in ("socks5", "http"):
                with self.subTest(tool=tool, outbound=outbound):
                    name, config, argv = tool_config(tool, "127.0.0.1:1081", "127.0.0.1:1080",
                                                     outbound)
                    text = str(config)
                    self.assertIn("1081", text)
                    self.assertIn("1080", text)
                    self.assertIn(f"/d/{name}", argv("/d"))
        _, mihomo, _ = tool_config("mihomo", "127.0.0.1:1", "127.0.0.1:2", "socks5")
        self.assertTrue(mihomo["proxies"][0]["udp"])
        self.assertEqual(mihomo["rules"], ["MATCH,braid"])

    def test_evidence_location_is_enforced(self):
        base = ["--binary", "b", "--tool-binary", "t", "--tool", "xray"]
        self.assertEqual(parse_args([*base, "--output", str(ROOT / "local/x")]).outbound, "socks5")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parse_args([*base, "--output", str(ROOT / "results/x")])


class Socks(unittest.TestCase):
    def test_connect_names_addresses_and_host_names(self):
        for host, expected in (("192.0.2.1", b"\x01\xc0\x00\x02\x01"),
                               ("localhost", b"\x03\x09localhost")):
            with self.subTest(host=host):
                left, right = socket.socketpair()
                seen = []

                def proxy():
                    seen.append(right.recv(3))
                    right.sendall(b"\x05\x00")
                    seen.append(right.recv(64))
                    right.sendall(b"\x05\x00\x00\x01" + bytes(6))

                thread = threading.Thread(target=proxy)
                thread.start()
                socks_connect(left, host, 80)
                thread.join()
                self.assertEqual(seen[1], b"\x05\x01\x00" + expected + struct.pack("!H", 80))
                left.close()
                right.close()


if __name__ == "__main__":
    unittest.main()
