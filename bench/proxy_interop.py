"""Third-party proxy clients chained to the BraidPath proxy entrance.

A local client tool (mihomo, sing-box or Xray) listens with its own SOCKS5
inbound and forwards everything through one BraidPath outbound: SOCKS5 (TCP and
UDP) or HTTP CONNECT (TCP). BraidPath carries the traffic over one loopback
HTTP/3 path to its server, which reaches loopback targets with
`--proxy-allow-private`. Checks:

- `tcp`: a seeded HTTP body fetched by address through the tool, verified by
  SHA-256;
- `tcp-name`: the same request naming `localhost`, so the tool forwards a name;
- `udp`: SOCKS5 UDP ASSOCIATE at the tool, echoed datagrams verified byte for
  byte (SOCKS5 outbound only).

Every process is local; this checks protocol interoperability, not performance
or reachability. The tool runs from its own working directory under `--output`.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.server
import json
from pathlib import Path
import random
import signal
import socket
import struct
import subprocess
import threading
import time

from bench.native_lab import ROOT, free_address, save
from bench.tcp_lab import wait_log

TOOLS = ("mihomo", "sing-box", "xray")
BODY_BYTES = 1024 * 1024
DATAGRAMS = 20


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "tool-binary", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--tool", choices=TOOLS, required=True)
    parser.add_argument("--outbound", choices=("socks5", "http"), default="socks5")
    parser.add_argument("--seed", type=int, default=20261017)
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    # The tool runs from its own directory.
    args.binary, args.tool_binary = args.binary.resolve(), args.tool_binary.resolve()
    if ROOT / "local" not in args.output.parents:
        parser.error("evidence must be under local/")
    return args


def split(address):
    host, _, port = address.rpartition(":")
    return host, int(port)


def tool_config(tool, inbound, braid, outbound):
    """The tool's configuration and command line arguments for `directory`."""
    (in_host, in_port), (b_host, b_port) = split(inbound), split(braid)
    if tool == "mihomo":
        proxy = {"name": "braid", "type": outbound, "server": b_host, "port": b_port}
        if outbound == "socks5":
            proxy["udp"] = True
        config = {"socks-port": in_port, "bind-address": in_host, "allow-lan": False,
                  "mode": "rule", "log-level": "info", "ipv6": False,
                  "proxies": [proxy], "rules": ["MATCH,braid"]}
        # JSON is valid YAML.
        return "config.yaml", config, lambda d: ["-d", d, "-f", f"{d}/config.yaml"]
    if tool == "sing-box":
        out = {"type": "socks" if outbound == "socks5" else "http", "tag": "braid",
               "server": b_host, "server_port": b_port}
        if outbound == "socks5":
            out["version"] = "5"
        config = {"log": {"level": "info"},
                  "inbounds": [{"type": "socks", "tag": "in", "listen": in_host,
                                "listen_port": in_port}],
                  "outbounds": [out], "route": {"final": "braid"}}
        return "config.json", config, lambda d: ["run", "-c", f"{d}/config.json",
                                                 "-D", d]
    servers = [{"address": b_host, "port": b_port}]
    config = {"log": {"loglevel": "info"},
              "inbounds": [{"listen": in_host, "port": in_port, "protocol": "socks",
                            "settings": {"auth": "noauth", "udp": True, "ip": in_host}}],
              "outbounds": [{"protocol": "socks" if outbound == "socks5" else "http",
                             "settings": {"servers": servers}}]}
    return "config.json", config, lambda d: ["run", "-c", f"{d}/config.json"]


class Http(threading.Thread):
    """Serves one seeded body on loopback."""

    def __init__(self, body):
        super().__init__(daemon=True)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.address = self.server.server_address

    def run(self):
        self.server.serve_forever()


class UdpEcho(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.address = self.socket.getsockname()

    def run(self):
        while True:
            data, peer = self.socket.recvfrom(65535)
            self.socket.sendto(b"echo:" + data, peer)


def socks_connect(conn, host, port):
    """SOCKS5 CONNECT naming an IPv4 address or a host name."""
    conn.sendall(b"\x05\x01\x00")
    if conn.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 method refused")
    try:
        address = b"\x01" + socket.inet_aton(host)
    except OSError:
        address = b"\x03" + bytes([len(host)]) + host.encode()
    conn.sendall(b"\x05\x01\x00" + address + struct.pack("!H", port))
    reply = b""
    while len(reply) < 10 and (chunk := conn.recv(10 - len(reply))):
        reply += chunk
    if reply[:2] != b"\x05\x00":
        raise RuntimeError(f"SOCKS5 CONNECT failed: {reply!r}")


def http_get(proxy, host, port, timeout=20):
    """GET / through a SOCKS5 proxy; returns the body."""
    with socket.create_connection(split(proxy), timeout=timeout) as conn:
        socks_connect(conn, host, port)
        conn.sendall(f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
                     .encode())
        response = b""
        while chunk := conn.recv(65536):
            response += chunk
    head, _, body = response.partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.1 200") and not head.startswith(b"HTTP/1.0 200"):
        raise RuntimeError(f"unexpected response {head[:80]!r}")
    return body


def socks_header(host, port):
    return b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port)


def udp_exchange(proxy, target, count, timeout=20):
    """SOCKS5 UDP ASSOCIATE; returns (sent, verified replies, malformed replies)."""
    with socket.create_connection(split(proxy), timeout=timeout) as control:
        control.sendall(b"\x05\x01\x00")
        if control.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 method refused")
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = control.recv(262)
        if len(reply) < 10 or reply[1] != 0:
            raise RuntimeError(f"UDP ASSOCIATE refused {reply!r}")
        if reply[3] == 1:
            relay = (socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:10])[0])
        elif reply[3] == 4:
            relay = (socket.inet_ntop(socket.AF_INET6, reply[4:20]),
                     struct.unpack("!H", reply[20:22])[0])
        else:
            raise RuntimeError(f"relay address type {reply[3]}")
        if relay[0] in ("0.0.0.0", "::"):
            relay = (split(proxy)[0], relay[1])
        family = socket.AF_INET6 if ":" in relay[0] else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", 0) if family == socket.AF_INET else ("::1", 0))
            udp.settimeout(0.5)
            expected, verified, malformed = {}, set(), 0
            header = socks_header(*target)
            for number in range(count):
                message = f"datagram {number:04d} ".encode() * 8
                expected[b"echo:" + message] = number
                for _ in range(4):
                    udp.sendto(header + message, relay)
                    try:
                        data, _ = udp.recvfrom(65535)
                    except TimeoutError:
                        continue
                    if data[:10] != header or data[10:] not in expected:
                        malformed += 1
                        continue
                    verified.add(expected[data[10:]])
                    if number in verified:
                        break
            return count, len(verified), malformed


def run(args):
    args.output.mkdir(parents=True, exist_ok=True)
    processes, logs = [], []

    def spawn(role, argv, **kwargs):
        log = open(args.output / f"{role}.log", "w")
        logs.append(log)
        process = subprocess.Popen([str(a) for a in argv], stdout=log, stderr=subprocess.STDOUT,
                                   **kwargs)
        processes.append(process)
        return process

    result = {"tool": args.tool, "outbound": args.outbound, "checks": {}, "error": None}
    try:
        version = subprocess.run([str(args.tool_binary),
                                  "-v" if args.tool == "mihomo" else "version"],
                                 capture_output=True, text=True, timeout=10)
        result["tool_version"] = (version.stdout or version.stderr).strip().splitlines()[0]
        identity = args.output / "identity"
        subprocess.run([str(args.binary), "init", "--dir", str(identity)], check=True,
                       capture_output=True, timeout=10)
        cert, key, token = (identity / name for name in ("cert.pem", "key.pem", "token"))
        body = random.Random(args.seed).randbytes(BODY_BYTES)
        web, echo = Http(body), UdpEcho()
        web.start()
        echo.start()
        server_addr, udp_listen, proxy_listen, inbound = (free_address() for _ in range(4))
        env = {"RUST_LOG": "braidpath=info"}
        server = spawn("server", [args.binary, "server", "--listen", server_addr, "--cert", cert,
                                  "--key", key, "--token-file", token, "--proxy",
                                  "--proxy-allow-private",
                                  "--stats-file", args.output / "server.json"], env=env)
        wait_log(args.output / "server.log", "HTTP/3 server ready", server)
        client = spawn("client", [args.binary, "client", "--listen", udp_listen,
                                  "--proxy-listen", proxy_listen, "--entrance", server_addr,
                                  "--adaptive", "--server-name", "localhost", "--ca", cert,
                                  "--token-file", token,
                                  "--stats-file", args.output / "client.json"], env=env)
        wait_log(args.output / "client.log", "UDP client ready", client)
        directory = args.output / "tool"
        directory.mkdir(exist_ok=True)
        name, config, argv = tool_config(args.tool, inbound, proxy_listen, args.outbound)
        (directory / name).write_text(json.dumps(config, indent=2))
        tool = spawn("tool", [args.tool_binary, *argv(str(directory))], cwd=directory,
                     env={"HOME": str(directory), "PATH": "/usr/bin:/bin"})
        deadline = time.monotonic() + 15
        while True:
            with contextlib.suppress(OSError), socket.create_connection(split(inbound), 0.5):
                break
            if time.monotonic() > deadline or tool.poll() is not None:
                raise RuntimeError("tool inbound not ready")
            time.sleep(0.1)
        digest = hashlib.sha256(body).hexdigest()
        checks = result["checks"]
        for check, host in (("tcp", "127.0.0.1"), ("tcp-name", "localhost")):
            started = time.monotonic()
            try:
                got = http_get(inbound, host, web.address[1])
                checks[check] = {"passed": hashlib.sha256(got).hexdigest() == digest,
                                 "bytes": len(got),
                                 "seconds": round(time.monotonic() - started, 3)}
            except Exception as error:
                checks[check] = {"passed": False, "error": repr(error)}
        if args.outbound == "socks5":
            try:
                sent, verified, malformed = udp_exchange(inbound, echo.address, DATAGRAMS)
                checks["udp"] = {"passed": verified == sent and malformed == 0, "sent": sent,
                                 "verified": verified, "malformed": malformed}
            except Exception as error:
                checks["udp"] = {"passed": False, "error": repr(error)}
    except Exception as error:
        result["error"] = repr(error)
    finally:
        # SIGINT lets BraidPath write its final statistics.
        for process in reversed(processes):
            process.send_signal(signal.SIGINT)
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        for log in logs:
            log.close()
    # Final statistics are written at exit.
    for role in ("client", "server"):
        with contextlib.suppress(OSError, ValueError, AttributeError):
            stats = json.loads((args.output / f"{role}.json").read_text())
            result[f"{role}_streams"] = {
                name: d.get("tcp_streams")
                for name, d in stats.get("stats", {}).get("directions", {}).items()
                if d.get("tcp_streams")}
    result["passed"] = (result["error"] is None and bool(result["checks"])
                        and all(c["passed"] for c in result["checks"].values()))
    save(args.output / "summary.json", result)
    return result


def main(argv=None):
    result = run(parse_args(argv))
    print(json.dumps({"tool": result["tool"], "outbound": result["outbound"],
                      "passed": result["passed"], "checks": result["checks"],
                      "error": result["error"]}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
