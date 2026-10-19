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
so events can impair interactive-only traffic. `--fresh-probe-interval-ms` opens
a new SOCKS5 connection per attempt and times connect, CONNECT and one 64-byte
echo, as a new request beside the load would. Loopback shares one CPU
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
from bench.netem import latest_complete_snapshot

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
    parser.add_argument("--direction", choices=("up", "down", "both"), default="up")
    parser.add_argument("--entrance", choices=("fixed", "socks5"), default="fixed")
    parser.add_argument("--connections", type=int, default=1)
    parser.add_argument("--probe-interval-ms", type=float, default=0.0)
    parser.add_argument("--fresh-probe-interval-ms", type=float, default=0.0)
    parser.add_argument("--event", type=parse_event, action="append", default=[])
    parser.add_argument("--tail-seconds", type=float, default=0.0)
    parser.add_argument("--loss-percent", type=float, default=0.0)
    parser.add_argument("--loss-max-datagram-bytes", type=int, default=0,
                        help="fault isolation: erase only short UDP payloads; 0 means all")
    parser.add_argument("--queue-packets", type=int, default=1024)
    parser.add_argument("--shared-forward-mbps", type=float, default=0.0,
                        help="one direct-drop client-to-server bucket shared by every path; 0 disables")
    parser.add_argument("--shared-forward-burst-bytes", type=int, default=32768)
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
    if not 0 <= args.loss_max_datagram_bytes <= 65_535:
        parser.error("loss datagram cutoff must be 0..65535 bytes")
    if not 1 <= args.connections <= 32:
        parser.error("connections must be 1..32")
    if args.direction == "both" and (args.entrance != "socks5" or args.connections > 16):
        parser.error("both directions need SOCKS5 and at most 16 connections per direction")
    if not 0 < args.timeout_seconds <= 600:
        parser.error("timeout must be greater than zero and at most 600 seconds")
    if args.probe_interval_ms and (args.entrance != "socks5" or not 5 <= args.probe_interval_ms <= 1000):
        parser.error("probes need --entrance socks5 and 5..1000 ms")
    if args.fresh_probe_interval_ms and (args.entrance != "socks5"
                                         or not 50 <= args.fresh_probe_interval_ms <= 5000):
        parser.error("fresh probes need --entrance socks5 and 50..5000 ms")
    if args.tail_seconds and (not args.probe_interval_ms or not 0 < args.tail_seconds <= 120):
        parser.error("a tail needs a probe and is at most 120 seconds")
    if any(event[1].get("path", -1) not in range(len(args.path)) for event in args.event):
        parser.error("event names an unknown path")
    args.use_path = args.use_path or list(range(len(args.path)))
    if any(not 0 <= i < len(args.path) for i in args.use_path):
        parser.error("unknown path index")
    return args


def payload(size, seed):
    # Python3.9 getrandbits takes a C int: one256MiB randbytes request
    # overflows its bit count. Whole-word chunks preserve the seeded bytes.
    rng = random.Random(seed)
    chunk = 1024 * 1024
    return b"".join(rng.randbytes(min(chunk, size - start))
                    for start in range(0, size, chunk))


class Target(threading.Thread):
    """TCP target for `connections` transfers: digest uploads or serve downloads.

    For uploads it records the longest pause between received chunks."""

    def __init__(self, direction, data, connections=1, timeout=120):
        super().__init__(daemon=True)
        self.direction, self.data, self.connections = direction, data, connections
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(timeout)
        self.timeout = timeout
        self.address = "127.0.0.1:%d" % self.listener.getsockname()[1]
        self.error = None
        self.max_gap_seconds = 0.0

    def run(self):
        workers = []
        try:
            for _ in range(self.connections):
                conn, _ = self.listener.accept()
                conn.settimeout(self.timeout)
                worker = threading.Thread(target=self.serve, args=(conn,), daemon=True)
                worker.start()
                workers.append(worker)
        except OSError as error:
            self.error = repr(error)
        finally:
            self.listener.close()
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
    """Echo every byte back, for the interactive probes; one thread per connection."""

    def __init__(self):
        super().__init__(daemon=True)
        self.listener = socket.create_server(("127.0.0.1", 0), backlog=64)
        self.address = "127.0.0.1:%d" % self.listener.getsockname()[1]

    @staticmethod
    def serve(conn):
        with contextlib.suppress(OSError), conn:
            while chunk := conn.recv(4096):
                conn.sendall(chunk)

    def run(self):
        with contextlib.suppress(OSError):
            while True:
                conn, _ = self.listener.accept()
                threading.Thread(target=self.serve, args=(conn,), daemon=True).start()


def rtt_summary(rtts, timeouts=0, error=None):
    rtts = sorted(rtts)

    def quantile(q):
        return rtts[min(len(rtts) - 1, int(q * len(rtts)))] * 1000 if rtts else None
    return {"count": len(rtts), "timeouts": timeouts, "error": error,
            "p50_ms": quantile(0.5), "p95_ms": quantile(0.95), "p99_ms": quantile(0.99),
            "max_ms": rtts[-1] * 1000 if rtts else None}


def probe_summary(attempts):
    """Success RTTs plus all outcomes, including censored failures."""
    failed = [a for a in attempts if a["outcome"] != "ok"]
    result = rtt_summary([a["elapsed_seconds"] for a in attempts if a["outcome"] == "ok"],
                         sum(a["outcome"] == "timeout" for a in failed),
                         failed[-1]["error"] if failed else None)
    elapsed = sorted(a["elapsed_seconds"] for a in attempts)
    result.update(attempts=len(attempts), failed=len(failed),
                  p99_all_outcomes_ms_lower_bound=(
                      elapsed[min(len(elapsed) - 1, int(len(elapsed) * .99))] * 1000
                      if elapsed else None),
                  p99_is_censored=bool(failed))
    return result


def probe_phases(attempts, started, finished):
    return {"idle": [a for a in attempts if a["started_monotonic"] < started],
            "during_transfer": [a for a in attempts if started <= a["started_monotonic"] < finished],
            "after_transfer": [a for a in attempts if a["started_monotonic"] >= finished]}


class Probe(threading.Thread):
    """Send a 64-byte message every interval through the proxy and time its echo."""

    def __init__(self, proxy, echo, interval, stop):
        super().__init__(daemon=True)
        self.proxy, self.echo, self.interval, self.stop = proxy, echo, interval, stop
        self.rtts, self.timeouts, self.error = [], 0, None
        self.attempts = []

    def run(self):
        host, port = self.proxy.rsplit(":", 1)
        try:
            with socket.create_connection((host, int(port)), timeout=5) as conn:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                socks_connect(conn, self.echo, time.monotonic() + 5)
                conn.settimeout(5)
                sequence = 0
                while not self.stop.is_set():
                    message = struct.pack("!Q", sequence) + bytes(56)
                    sent = time.monotonic()
                    outcome, error = "ok", None
                    try:
                        conn.settimeout(5)
                        conn.sendall(message)
                        reply = b""
                        while len(reply) < len(message):
                            remaining = 5 - (time.monotonic() - sent)
                            if remaining <= 0:
                                raise socket.timeout("probe deadline")
                            conn.settimeout(remaining)
                            chunk = conn.recv(len(message) - len(reply))
                            if not chunk:
                                raise RuntimeError("echo closed")
                            reply += chunk
                        if reply != message:
                            raise RuntimeError("echo mismatch")
                    except (OSError, RuntimeError) as failure:
                        outcome = "timeout" if isinstance(failure, socket.timeout) else "error"
                        error = repr(failure)
                        raise
                    finally:
                        finished = time.monotonic()
                        self.attempts.append({"sequence": sequence, "started_monotonic": sent,
                                              "finished_monotonic": finished,
                                              "elapsed_seconds": finished - sent,
                                              "outcome": outcome, "error": error})
                    self.rtts.append(finished - sent)
                    sequence += 1
                    self.stop.wait(max(0.0, self.interval - (time.monotonic() - sent)))
        except socket.timeout:
            self.timeouts += 1
            self.error = "probe timed out"
        except (OSError, RuntimeError) as error:
            self.error = repr(error)




class FreshProbe(threading.Thread):
    """Each attempt: new TCP connection, SOCKS5 CONNECT, one 64-byte echo, close."""

    def __init__(self, proxy, echo, interval, stop, limit=5.0):
        super().__init__(daemon=True)
        self.proxy, self.echo, self.interval, self.stop, self.limit = proxy, echo, interval, stop, limit
        self.attempts = []

    def run(self):
        host, port = self.proxy.rsplit(":", 1)
        sequence = 0
        while not self.stop.is_set():
            sent = time.monotonic()
            deadline = sent + self.limit
            outcome, error = "ok", None
            try:
                with socket.create_connection((host, int(port)), timeout=self.limit) as conn:
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    socks_connect(conn, self.echo, deadline)
                    message = struct.pack("!Q", sequence) + bytes(56)
                    conn.sendall(message)
                    reply = b""
                    while len(reply) < len(message):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise socket.timeout("fresh probe deadline")
                        conn.settimeout(remaining)
                        chunk = conn.recv(len(message) - len(reply))
                        if not chunk:
                            raise RuntimeError("echo closed")
                        reply += chunk
                    if reply != message:
                        raise RuntimeError("echo mismatch")
            except (OSError, RuntimeError) as failure:
                outcome = "timeout" if isinstance(failure, socket.timeout) else "error"
                error = repr(failure)
            finished = time.monotonic()
            self.attempts.append({"sequence": sequence, "started_monotonic": sent,
                                  "finished_monotonic": finished,
                                  "elapsed_seconds": finished - sent,
                                  "outcome": outcome, "error": error})
            sequence += 1
            self.stop.wait(max(0.0, self.interval - (time.monotonic() - sent)))


def socks_connect(conn, address, deadline=None):
    """SOCKS5 CONNECT to an IPv4 address; raises unless the proxy succeeds."""
    def remaining():
        if deadline is not None:
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise socket.timeout("SOCKS5 deadline")
            conn.settimeout(seconds)

    def receive(size):
        data = b""
        while len(data) < size:
            remaining()
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise RuntimeError("short SOCKS5 reply")
            data += chunk
        return data

    host, port = address.rsplit(":", 1)
    remaining()
    conn.sendall(b"\x05\x01\x00")
    if receive(2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 method refused")
    remaining()
    conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", int(port)))
    reply = receive(10)
    if reply[:2] != b"\x05\x00":
        raise RuntimeError(f"SOCKS5 CONNECT failed: {reply!r}")


def transfer(address, direction, data, limit, socks_target=None):
    host, port = address.rsplit(":", 1)
    conn = socket.create_connection((host, int(port)), timeout=limit)
    started = time.monotonic()
    setup, gap = None, None
    deadline = started + limit

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise socket.timeout("transfer deadline")
        conn.settimeout(seconds)

    with conn:
        if socks_target:
            socks_connect(conn, socks_target, deadline)
            setup = time.monotonic() - started
        if direction == "up":
            remaining()
            conn.sendall(data)
            conn.shutdown(socket.SHUT_WR)
            reply = b""
            while len(reply) < DIGEST.size:
                remaining()
                chunk = conn.recv(DIGEST.size - len(reply))
                if not chunk:
                    break
                reply += chunk
            elapsed = time.monotonic() - started
            digest, count = DIGEST.unpack(reply) if len(reply) == DIGEST.size else (b"", 0)
            exact = digest == hashlib.sha256(data).digest() and count == len(data)
        else:
            digest, count, last = hashlib.sha256(), 0, None
            while True:
                remaining()
                chunk = conn.recv(1 << 16)
                if not chunk:
                    break
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


def paths_ready(snapshot, count):
    paths = snapshot.get("stats", {}).get("paths", {}).values() if snapshot else []
    live = [p for p in paths if p.get("authenticated") and not (p.get("quinn") or {}).get("closed")]
    return (len(live) == count and len({p["path_id"] for p in live}) == count
            and len({p["session_id"] for p in live}) == 1)


def wait_paths(output, count, process, limit=15):
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        snapshot = latest_complete_snapshot(output / "client.jsonl")
        if paths_ready(snapshot, count):
            save(output / "path-ready.json", snapshot)
            return
        if process.poll() is not None:
            raise RuntimeError("client exited before every requested path authenticated")
        time.sleep(.05)
    raise RuntimeError("not every requested path authenticated before workload")


def run(args):
    args.output.mkdir(parents=True, exist_ok=False)
    save(args.output / "registration.json", {
        "utc": datetime.now(timezone.utc).isoformat(),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "lab_sha256": hashlib.sha256(args.lab_binary.read_bytes()).hexdigest(),
        "paths": args.path, "bytes_per_connection": args.bytes, "connections": args.connections,
        "direction": args.direction, "seed": args.seed, "events": args.event,
        "shared_forward_mbps": args.shared_forward_mbps,
        "shared_forward_burst_bytes": args.shared_forward_burst_bytes,
    })
    processes = []
    targets = {}
    echo = None

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
        directions = ["up", "down"] if args.direction == "both" else [args.direction]
        targets = {direction: Target(direction, data, args.connections, args.timeout_seconds)
                   for direction in directions}
        for target in targets.values():
            target.start()
        target = targets[directions[0]]
        echo = Echo() if args.probe_interval_ms or args.fresh_probe_interval_ms else None
        if echo:
            echo.start()
        server_addr, udp_listen, tcp_listen = free_address(), free_address(), free_address()
        lab = [args.lab_binary, "--server", server_addr, "--queue-packets", args.queue_packets,
               "--seed", args.seed, "--ready-file", args.output / "link-ready.json",
               "--stats-jsonl", args.output / "link.jsonl", "--final-file", args.output / "link-final.json"]
        if args.loss_max_datagram_bytes:
            lab += ["--loss-max-datagram-bytes", args.loss_max_datagram_bytes]
        if args.shared_forward_mbps:
            lab += ["--shared-forward-mbps", args.shared_forward_mbps,
                    "--shared-forward-burst-bytes", args.shared_forward_burst_bytes]
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
        wait_paths(args.output, len(entrances), client)
        time.sleep(0.5)
        stop = threading.Event()
        probe = fresh = None
        if args.probe_interval_ms:
            probe = Probe(tcp_listen, echo.address, args.probe_interval_ms / 1000, stop)
            probe.start()
        if args.fresh_probe_interval_ms:
            fresh = FreshProbe(tcp_listen, echo.address, args.fresh_probe_interval_ms / 1000, stop)
            fresh.start()
        if echo:
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
        jobs = [direction for direction in directions for _ in range(args.connections)]
        results = [None] * len(jobs)

        def one(index):
            direction = jobs[index]
            try:
                result = transfer(tcp_listen, direction, data, args.timeout_seconds,
                                  targets[direction].address if args.entrance == "socks5" else None)
                result["error"] = None
            except (OSError, RuntimeError) as error:
                result = {"exact": False, "received_bytes": 0, "goodput_mbps": 0.0,
                          "max_gap_seconds": None, "error": repr(error)}
            results[index] = {**result, "direction": direction}
        events = [threading.Thread(target=schedule, args=event, daemon=True) for event in args.event]
        workers = [threading.Thread(target=one, args=(i,)) for i in range(len(jobs))]
        started = time.monotonic()
        for thread in events + workers:
            thread.start()
        for worker in workers:
            worker.join()
        finished = time.monotonic()
        wall = finished - started
        stop.wait(args.tail_seconds)
        stop.set()
        if probe:
            probe.join(10)
        if fresh:
            fresh.join(10)
        for target in targets.values():
            target.join(5)
        exact = all(r and r["exact"] for r in results)
        total = len(jobs) * len(data)
        result = {**results[0], "exact": exact, "elapsed_seconds": wall,
                  "received_bytes": sum(r["received_bytes"] for r in results),
                  "goodput_mbps": total * 8 / wall / 1e6 if exact else 0.0,
                  "max_gap_seconds": max([r["max_gap_seconds"] or 0.0 for r in results if r]
                                         + [t.max_gap_seconds for t in targets.values()]),
                  "connections": results, "events_applied": applied}
        result["by_direction"] = {
            direction: {"exact": all(r["exact"] for r in results if r["direction"] == direction),
                        "received_bytes": sum(r["received_bytes"] for r in results
                                              if r["direction"] == direction),
                        "expected_bytes": args.connections * len(data),
                        "goodput_mbps": (args.connections * len(data) * 8 / wall / 1e6
                                         if all(r["exact"] for r in results
                                                if r["direction"] == direction) else 0.0)}
            for direction in directions}
        if probe:
            attempts = probe.attempts
            phases = probe_phases(attempts, started, finished)
            save(args.output / "probe-samples.json", {
                "unit": "seconds", **{phase: [a["elapsed_seconds"] for a in values
                                               if a["outcome"] == "ok"]
                                      for phase, values in phases.items()},
                "timeouts": probe.timeouts, "error": probe.error,
            })
            save(args.output / "probe-attempts.json", {
                "clock": "monotonic seconds; phase by request start, including boundary completions",
                "transfer_started_monotonic": started, "transfer_finished_monotonic": finished,
                "attempts": attempts, "error": probe.error})
            result["probe"] = {"interval_ms": args.probe_interval_ms, "error": probe.error,
                               **{phase: probe_summary(values) for phase, values in phases.items()}}
        if fresh:
            phases = probe_phases(fresh.attempts, started, finished)
            save(args.output / "fresh-probe-attempts.json", {
                "clock": "monotonic seconds; phase by request start, including boundary completions",
                "transfer_started_monotonic": started, "transfer_finished_monotonic": finished,
                "attempts": fresh.attempts})
            result["fresh_probe"] = {"interval_ms": args.fresh_probe_interval_ms,
                                     **{phase: probe_summary(values)
                                        for phase, values in phases.items()}}
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
        result["goodput_to_used_capacity"] = result["goodput_mbps"] / (capacity * len(directions))
        summary = {
            **result,
            "direction": args.direction, "entrance": args.entrance, "bytes": args.bytes, "paths": args.path,
            "used_paths": args.use_path, "loss_percent_each_direction": args.loss_percent,
            "used_capacity_mbps": capacity * len(directions),
            "capacity_mbps_per_direction": capacity,
            "goodput_time_basis": "one common wall interval for all transfer connections",
            "target_error": next((t.error for t in targets.values() if t.error), None),
            "client_args": args.client_arg, "server_args": args.server_arg,
            "client_streams": streams("client"), "server_streams": streams("server"),
            "scope": "single native loopback diagnostic; capacity counts IPv4+UDP wire bytes",
        }
        save(args.output / "summary.json", summary)
        return summary
    finally:
        if echo:
            echo.listener.close()
        for target in targets.values():
            target.listener.close()
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
