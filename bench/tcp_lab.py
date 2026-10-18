"""Finite single-TCP transfer through BraidPath over the native link emulator.

Runs on the development host without privileges. The emulator shapes every
path in both directions (FIFO serializer, propagation delay, optional loss).
One TCP connection carries a seeded payload; the target verifies integrity.
Selecting a subset of paths gives the matched single-path baseline on the same
emulated topology. `--entrance socks5` carries the same transfer as a SOCKS5
CONNECT stream to the target address instead of a fixed-target stream.
`--connections` runs several such transfers at once; `--probe-interval-ms`
adds an interactive echo stream beside them (SOCKS5 only) and reports its
round-trip times; `--event T:JSON` sends one emulator control line T seconds
after the transfer starts, for example a path outage. `--tail-seconds` keeps
the probe running after the transfer and reports those round trips separately,
so events can impair interactive-only traffic. Loopback shares one CPU
and kernel: this is a controlled diagnostic, not a WAN or independent-bandwidth
acceptance result.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
import random
import socket
import struct
import subprocess
import threading
import time

from bench.native_lab import ROOT, free_address, save

DIGEST = struct.Struct("!32sQ")


def parse_path(text):
    rtt, rate = (float(v) for v in text.split(":"))
    if not (0 <= rtt <= 1000 and 1 <= rate <= 1000):
        raise argparse.ArgumentTypeError("path must be RTT_MS:RATE_MBPS within bounds")
    return rtt, rate


def parse_event(text):
    at, _, line = text.partition(":")
    try:
        at, change = float(at), json.loads(line)
    except ValueError as error:
        raise argparse.ArgumentTypeError("event must be SECONDS:JSON") from error
    if not 0 <= at <= 600 or not isinstance(change, dict):
        raise argparse.ArgumentTypeError("event must be SECONDS:JSON within 600 s")
    return at, change


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "lab-binary", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--path", type=parse_path, action="append", required=True)
    parser.add_argument("--use-path", type=int, action="append",
                        help="client entrance subset by emulator path index; default all")
    parser.add_argument("--bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--direction", choices=("up", "down"), default="up")
    parser.add_argument("--entrance", choices=("fixed", "socks5"), default="fixed")
    parser.add_argument("--connections", type=int, default=1)
    parser.add_argument("--probe-interval-ms", type=float, default=0.0)
    parser.add_argument("--event", type=parse_event, action="append", default=[])
    parser.add_argument("--tail-seconds", type=float, default=0.0)
    parser.add_argument("--loss-percent", type=float, default=0.0)
    parser.add_argument("--queue-packets", type=int, default=1024)
    parser.add_argument("--seed", type=int, default=20261017)
    parser.add_argument("--timeout-seconds", type=float, default=120)
    parser.add_argument("--client-arg", action="append", default=[])
    parser.add_argument("--server-arg", action="append", default=[])
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    if ROOT / "local" not in args.output.parents:
        parser.error("evidence must be under local/")
    if not 65_536 <= args.bytes <= 512 * 1024 * 1024 or not 1 <= len(args.path) <= 4:
        parser.error("bounded bytes/path count exceeded")
    if not 0 <= args.loss_percent <= 50:
        parser.error("loss must be 0..50 percent")
    if not 1 <= args.connections <= 32:
        parser.error("connections must be 1..32")
    if args.probe_interval_ms and (args.entrance != "socks5" or not 5 <= args.probe_interval_ms <= 1000):
        parser.error("probes need --entrance socks5 and 5..1000 ms")
    if args.tail_seconds and (not args.probe_interval_ms or not 0 < args.tail_seconds <= 120):
        parser.error("a tail needs a probe and is at most 120 seconds")
    if any(event[1].get("path", -1) not in range(len(args.path)) for event in args.event):
        parser.error("event names an unknown path")
    args.use_path = args.use_path or list(range(len(args.path)))
    if any(not 0 <= i < len(args.path) for i in args.use_path):
        parser.error("unknown path index")
    return args


def payload(size, seed):
    return random.Random(seed).randbytes(size)


class Target(threading.Thread):
    """TCP target for `connections` transfers: digest uploads or serve downloads.

    For uploads it records the longest pause between received chunks."""

    def __init__(self, direction, data, connections=1):
        super().__init__(daemon=True)
        self.direction, self.data, self.connections = direction, data, connections
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.address = "127.0.0.1:%d" % self.listener.getsockname()[1]
        self.error = None
        self.max_gap_seconds = 0.0

    def run(self):
        workers = []
        try:
            for _ in range(self.connections):
                conn, _ = self.listener.accept()
                worker = threading.Thread(target=self.serve, args=(conn,), daemon=True)
                worker.start()
                workers.append(worker)
        except OSError as error:
            self.error = repr(error)
        for worker in workers:
            worker.join()

    def serve(self, conn):
        try:
            with conn:
                if self.direction == "up":
                    digest, count, last = hashlib.sha256(), 0, None
                    while chunk := conn.recv(1 << 16):
                        now = time.monotonic()
                        if last is not None:
                            self.max_gap_seconds = max(self.max_gap_seconds, now - last)
                        last = now
                        digest.update(chunk)
                        count += len(chunk)
                    conn.sendall(DIGEST.pack(digest.digest(), count))
                else:
                    conn.sendall(self.data)
                    conn.shutdown(socket.SHUT_WR)
                    conn.recv(1)
        except OSError as error:
            self.error = repr(error)


class Echo(threading.Thread):
    """Echo every byte back, for the interactive probe."""

    def __init__(self):
        super().__init__(daemon=True)
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.address = "127.0.0.1:%d" % self.listener.getsockname()[1]

    def run(self):
        with contextlib.suppress(OSError):
            conn, _ = self.listener.accept()
            with conn:
                while chunk := conn.recv(4096):
                    conn.sendall(chunk)


def rtt_summary(rtts, timeouts=0, error=None):
    rtts = sorted(rtts)

    def quantile(q):
        return rtts[min(len(rtts) - 1, int(q * len(rtts)))] * 1000 if rtts else None
    return {"count": len(rtts), "timeouts": timeouts, "error": error,
            "p50_ms": quantile(0.5), "p95_ms": quantile(0.95), "p99_ms": quantile(0.99),
            "max_ms": rtts[-1] * 1000 if rtts else None}


class Probe(threading.Thread):
    """Send a 64-byte message every interval through the proxy and time its echo."""

    def __init__(self, proxy, echo, interval, stop):
        super().__init__(daemon=True)
        self.proxy, self.echo, self.interval, self.stop = proxy, echo, interval, stop
        self.rtts, self.timeouts, self.error = [], 0, None

    def run(self):
        host, port = self.proxy.rsplit(":", 1)
        try:
            with socket.create_connection((host, int(port)), timeout=5) as conn:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                socks_connect(conn, self.echo)
                conn.settimeout(5)
                sequence = 0
                while not self.stop.is_set():
                    message = struct.pack("!Q", sequence) + bytes(56)
                    sent = time.monotonic()
                    conn.sendall(message)
                    reply = b""
                    while len(reply) < len(message):
                        chunk = conn.recv(len(message) - len(reply))
                        if not chunk:
                            raise RuntimeError("echo closed")
                        reply += chunk
                    if reply != message:
                        raise RuntimeError("echo mismatch")
                    self.rtts.append(time.monotonic() - sent)
                    sequence += 1
                    self.stop.wait(max(0.0, self.interval - (time.monotonic() - sent)))
        except socket.timeout:
            self.timeouts += 1
            self.error = "probe timed out"
        except (OSError, RuntimeError) as error:
            self.error = repr(error)




def socks_connect(conn, address):
    """SOCKS5 CONNECT to an IPv4 address; raises unless the proxy succeeds."""
    host, port = address.rsplit(":", 1)
    conn.sendall(b"\x05\x01\x00")
    if conn.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 method refused")
    conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", int(port)))
    reply = b""
    while len(reply) < 10 and (chunk := conn.recv(10 - len(reply))):
        reply += chunk
    if reply[:2] != b"\x05\x00":
        raise RuntimeError(f"SOCKS5 CONNECT failed: {reply!r}")


def transfer(address, direction, data, limit, socks_target=None):
    host, port = address.rsplit(":", 1)
    conn = socket.create_connection((host, int(port)), timeout=limit)
    started = time.monotonic()
    setup, gap = None, None
    with conn:
        if socks_target:
            socks_connect(conn, socks_target)
            setup = time.monotonic() - started
        if direction == "up":
            conn.sendall(data)
            conn.shutdown(socket.SHUT_WR)
            reply = b""
            while len(reply) < DIGEST.size and (chunk := conn.recv(DIGEST.size - len(reply))):
                reply += chunk
            elapsed = time.monotonic() - started
            digest, count = DIGEST.unpack(reply) if len(reply) == DIGEST.size else (b"", 0)
            exact = digest == hashlib.sha256(data).digest() and count == len(data)
        else:
            digest, count, last = hashlib.sha256(), 0, None
            while chunk := conn.recv(1 << 16):
                now = time.monotonic()
                if last is not None:
                    gap = max(gap or 0.0, now - last)
                last = now
                digest.update(chunk)
                count += len(chunk)
            elapsed = time.monotonic() - started
            exact = digest.digest() == hashlib.sha256(data).digest() and count == len(data)
    return {"elapsed_seconds": elapsed, "exact": exact, "received_bytes": count,
            "proxy_setup_seconds": setup, "max_gap_seconds": gap,
            "goodput_mbps": len(data) * 8 / elapsed / 1e6 if exact else 0.0}


def wait_log(path, text, process, limit=15):
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        if path.exists() and text in path.read_text(errors="replace"):
            return
        if process.poll() is not None:
            raise RuntimeError(f"{path.name}: exited before readiness")
        time.sleep(0.05)
    raise RuntimeError(f"{path.name}: not ready")


def run(args):
    args.output.mkdir(parents=True, exist_ok=False)
    save(args.output / "registration.json", {
        "utc": datetime.now(timezone.utc).isoformat(),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "lab_sha256": hashlib.sha256(args.lab_binary.read_bytes()).hexdigest(),
        "paths": args.path, "bytes_per_connection": args.bytes, "connections": args.connections,
        "seed": args.seed, "events": args.event,
    })
    processes = []

    def spawn(role, argv, **kwargs):
        log = open(args.output / f"{role}.log", "w")
        process = subprocess.Popen([str(a) for a in argv], stdout=log, stderr=subprocess.STDOUT,
                                   env={"RUST_LOG": "braidpath=info"}, **kwargs)
        processes.append(process)
        return process

    try:
        identity = args.output / "identity"
        subprocess.run([str(args.binary), "init", "--dir", str(identity)], check=True,
                       capture_output=True, timeout=10)
        cert, key, token = (identity / name for name in ("cert.pem", "key.pem", "token"))
        data = payload(args.bytes, args.seed)
        target = Target(args.direction, data, args.connections)
        target.start()
        echo = Echo() if args.probe_interval_ms else None
        if echo:
            echo.start()
        server_addr, udp_listen, tcp_listen = free_address(), free_address(), free_address()
        lab = [args.lab_binary, "--server", server_addr, "--queue-packets", args.queue_packets,
               "--seed", args.seed, "--ready-file", args.output / "link-ready.json",
               "--stats-jsonl", args.output / "link.jsonl", "--final-file", args.output / "link-final.json"]
        for rtt, rate in args.path:
            lab += ["--path", f"{rtt:g}:{rate:g}"]
        emulator = spawn("link", lab, stdin=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 10
        while not (args.output / "link-ready.json").exists():
            if time.monotonic() > deadline or emulator.poll() is not None:
                raise RuntimeError("link emulator not ready")
            time.sleep(0.05)
        time.sleep(0.1)
        ready = json.loads((args.output / "link-ready.json").read_text())
        if args.loss_percent:
            for index in range(len(args.path)):
                emulator.stdin.write(json.dumps({"path": index, "loss_percent": args.loss_percent}) + "\n")
            emulator.stdin.flush()
        server = spawn("server", [args.binary, "server", "--listen", server_addr, "--cert", cert,
                                  "--key", key, "--token-file", token,
                                  *(["--tcp-target", target.address] if args.entrance == "fixed"
                                    else ["--proxy", "--proxy-allow-private"]),
                                  "--stats-file", args.output / "server.json",
                                  "--stats-jsonl", args.output / "server.jsonl",
                                  "--stats-interval-ms", "100", *args.server_arg])
        wait_log(args.output / "server.log", "HTTP/3 server ready", server)
        entrances = [ready["paths"][i]["entrance"] for i in args.use_path]
        client = spawn("client", [args.binary, "client", "--listen", udp_listen,
                                  "--tcp-listen" if args.entrance == "fixed" else "--proxy-listen", tcp_listen,
                                  *sum((["--entrance", e] for e in entrances), []),
                                  "--server-name", "localhost", "--ca", cert, "--token-file", token,
                                  "--stats-file", args.output / "client.json",
                                  "--stats-jsonl", args.output / "client.jsonl",
                                  "--stats-interval-ms", "100", *args.client_arg])
        wait_log(args.output / "client.log", "UDP client ready", client)
        time.sleep(0.5)
        stop = threading.Event()
        probe = None
        if echo:
            probe = Probe(tcp_listen, echo.address, args.probe_interval_ms / 1000, stop)
            probe.start()
            time.sleep(1.0)  # idle baseline before the bulk transfer starts
        control = threading.Lock()
        applied = []

        def schedule(at, change):
            stop.wait(at)
            if stop.is_set():
                return
            with control:
                emulator.stdin.write(json.dumps(change) + "\n")
                emulator.stdin.flush()
            applied.append({"at_seconds": at, "change": change, "unix_ms": int(time.time() * 1000)})
        results = [None] * args.connections

        def one(index):
            results[index] = transfer(tcp_listen, args.direction, data, args.timeout_seconds,
                                      target.address if args.entrance == "socks5" else None)
        idle_rtts = len(probe.rtts) if probe else 0
        events = [threading.Thread(target=schedule, args=event, daemon=True) for event in args.event]
        workers = [threading.Thread(target=one, args=(i,)) for i in range(args.connections)]
        started = time.monotonic()
        for thread in events + workers:
            thread.start()
        for worker in workers:
            worker.join()
        wall = time.monotonic() - started
        busy_rtts = len(probe.rtts) if probe else 0
        busy_timeouts, busy_error = (probe.timeouts, probe.error) if probe else (0, None)
        stop.wait(args.tail_seconds)
        stop.set()
        if probe:
            probe.join(10)
        target.join(5)
        exact = all(r and r["exact"] for r in results)
        total = args.connections * len(data)
        result = {**results[0], "exact": exact, "elapsed_seconds": wall,
                  "goodput_mbps": total * 8 / wall / 1e6 if exact else 0.0,
                  "max_gap_seconds": max([r["max_gap_seconds"] or 0.0 for r in results if r]
                                         + [target.max_gap_seconds]),
                  "connections": results, "events_applied": applied}
        if probe:
            save(args.output / "probe-samples.json", {
                "unit": "seconds", "idle": probe.rtts[:idle_rtts],
                "during_transfer": probe.rtts[idle_rtts:busy_rtts],
                "after_transfer": probe.rtts[busy_rtts:],
                "timeouts": probe.timeouts, "error": probe.error,
            })
            idle = rtt_summary(probe.rtts[:idle_rtts])
            busy = rtt_summary(probe.rtts[idle_rtts:busy_rtts], busy_timeouts, busy_error)
            result["probe"] = {"interval_ms": args.probe_interval_ms, "idle": idle, "during_transfer": busy}
            if args.tail_seconds:
                result["probe"]["after_transfer"] = rtt_summary(
                    probe.rtts[busy_rtts:], probe.timeouts - busy_timeouts,
                    probe.error if probe.error != busy_error else None)
        for process in (client, server):
            process.send_signal(2)
        for process in (client, server):
            process.wait(timeout=10)
        emulator.stdin.close()
        emulator.wait(timeout=10)

        def streams(role):
            final = json.loads((args.output / f"{role}.json").read_text())
            directions = final.get("stats", {}).get("directions", {})
            return {name: d.get("tcp_streams") for name, d in directions.items() if d.get("tcp_streams")}
        capacity = sum(args.path[i][1] for i in args.use_path)
        result["goodput_to_used_capacity"] = result["goodput_mbps"] / capacity
        summary = {
            **result,
            "direction": args.direction, "entrance": args.entrance, "bytes": args.bytes, "paths": args.path,
            "used_paths": args.use_path, "loss_percent_each_direction": args.loss_percent,
            "used_capacity_mbps": capacity,
            "target_error": target.error, "client_args": args.client_arg, "server_args": args.server_arg,
            "client_streams": streams("client"), "server_streams": streams("server"),
            "scope": "single native loopback diagnostic; capacity counts IPv4+UDP wire bytes",
        }
        save(args.output / "summary.json", summary)
        return summary
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()


def main(argv=None):
    summary = run(parse_args(argv))
    print(json.dumps({k: summary[k] for k in ("exact", "elapsed_seconds", "goodput_mbps",
                                              "used_capacity_mbps", "goodput_to_used_capacity")}))
    return 0 if summary["exact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
