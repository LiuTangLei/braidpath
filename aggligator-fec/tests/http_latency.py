#!/usr/bin/env python3
"""Loopback-only HTTP latency/contract benchmark for the managed TCP tunnel.

Examples (build the binary first; this script never builds or accesses remote hosts):
  python3 aggligator-fec/tests/http_latency.py --quick --profile latency --output /tmp/latency.json
  python3 aggligator-fec/tests/http_latency.py --profile balanced --cases all --output /tmp/balanced.json
  python3 aggligator-fec/tests/http_latency.py --binary /path/to/older/binary --profile existing --quick

Each run uses temporary credentials, two identity-checked HTTP services and a
half-close TCP service. The UDP impairment proxies forward unmodified datagrams
with one NAT socket per origin; no wire-protocol knowledge, root, tc, route, SSH,
or third-party target is used. Both data paths are proxied even in the clean
case. Control-plane TLS stays on loopback and is NOT impaired, so these are
data-plane regression measurements, not an estimate of internet cold enrollment.
The first request immediately after client "ready" is first_tcp_after_ready: a
profile may already have prewarmed transport sessions before that event. Process
start-to-ready time is reported separately; it is not eliminated or hidden in
the application request latency.

JSON includes every request, failure, payload digest, scenario, binary identity,
effective tuning, and proxy counters. Small quick runs are smoke tests, not
statistically reliable p99 estimates. Failed requests are NEVER omitted from
counts; latency quantiles explicitly describe successful requests only.
"""
import argparse
from collections import Counter, deque
import concurrent.futures
import hashlib
import heapq
import json
import math
import os
from pathlib import Path
import platform
import random
import secrets
import selectors
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
PATTERN = bytes(range(251)) * 256
ALL_CASES = ("cold", "new", "keepalive", "idle", "background", "contracts", "impaired", "path_loss")
OPTIONAL_CASES = ("burst_short", "master_restart")
SECRET_KEYS = {"invitation", "ticket", "credential", "private_key", "certificate", "admin"}


def scrub(value):
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items() if k not in SECRET_KEYS}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("request or overall benchmark time budget exhausted")
    return max(.001, left)


def pause(seconds, deadline):
    if seconds > remaining(deadline):
        raise TimeoutError("insufficient overall budget for requested wait")
    time.sleep(seconds)


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def addr(port):
    return "127.0.0.1:" + str(port)


def address(text):
    host, port = text.rsplit(":", 1)
    if host != "127.0.0.1":
        raise ValueError("benchmark targets must remain on IPv4 loopback")
    return host, int(port)


def digest_for(size):
    digest = hashlib.sha256()
    for _ in range(size // len(PATTERN)):
        digest.update(PATTERN)
    digest.update(PATTERN[:size % len(PATTERN)])
    return digest.hexdigest()


def invoke(binary, args, deadline, invitation=None):
    # Short-lived commands get disk-backed bounded capture, not unbounded pipes.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        result = subprocess.run(
            [str(binary), *args], cwd=ROOT,
            input=None if invitation is None else (invitation + "\n").encode(),
            stdout=out, stderr=err, timeout=min(15, remaining(deadline)))
        out.seek(0); stdout = out.read(65537)
        err.seek(0); stderr = err.read(8193)
    if len(stdout) > 65536:
        raise RuntimeError("unexpectedly large CLI output")
    if result.returncode:
        # Do not include stdout: init/join output can contain credentials.
        raise RuntimeError("CLI %s failed (%s): %s" % (
            args[0], result.returncode, stderr[:8192].decode(errors="replace")))
    return stdout.decode()


class Node:
    """Owned subprocess with continuously drained pipes and bounded log rings."""
    def __init__(self, name, argv, deadline):
        self.name = name
        self.records = deque(maxlen=256)
        self.errors = deque(maxlen=32)
        self.events = Counter()
        self.opens = deque(maxlen=8192)
        self.warm_hits = 0
        self.warm_misses = 0
        self.pool_events = deque(maxlen=32)
        self.runtime_errors = deque(maxlen=256)
        self.completed_flows = deque(maxlen=8192)
        self.condition = threading.Condition()
        self.started = time.monotonic()
        self.ready_observed = None
        self.process = subprocess.Popen(
            argv, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        self.readers = [
            threading.Thread(target=self._drain, args=(False,), daemon=True),
            threading.Thread(target=self._drain, args=(True,), daemon=True)]
        for reader in self.readers:
            reader.start()
        try:
            self.ready = self.wait("ready", deadline)
        except BaseException:
            self.close()
            raise

    def _drain(self, errors):
        stream = self.process.stderr if errors else self.process.stdout
        try:
            for line in stream:
                if errors:
                    with self.condition:
                        self.errors.append(line.strip()[:2048])
                        self.condition.notify_all()
                else:
                    try:
                        item = scrub(json.loads(line))
                    except json.JSONDecodeError:
                        item = {"event": "text", "line": line.strip()[:2048]}
                    with self.condition:
                        self.records.append(item)
                        self.events[item.get("event", "unknown")] += 1
                        event_name = item.get("event", "")
                        if event_name.endswith("error") or "reject" in event_name:
                            self.runtime_errors.append(dict(item, observed_since_process_start_s=time.monotonic() - self.started))
                        if event_name == "managed_session":
                            fields = ("service", "session", "tx_bytes", "rx_bytes", "wire_bytes", "retries",
                                      "max_stall_ms", "source_packets", "wan_source_packets", "path_addresses",
                                      "topology_updates", "local_send_drops", "elapsed_s")
                            self.completed_flows.append({
                                **{key: item[key] for key in fields if key in item},
                                "observed_monotonic_s": time.monotonic()})
                        if item.get("event") == "ready" and self.ready_observed is None:
                            self.ready_observed = time.monotonic()
                        if item.get("event") == "session_open":
                            self.opens.append(dict(item, observed_monotonic_s=time.monotonic()))
                            if item.get("warm") is True:
                                self.warm_hits += 1
                            elif item.get("warm") is False:
                                self.warm_misses += 1
                        elif item.get("event") == "warm_pool_ready":
                            self.pool_events.append(item)
                        self.condition.notify_all()
        except (ValueError, OSError):
            pass

    def wait(self, event, deadline):
        end = min(deadline, time.monotonic() + 20)
        with self.condition:
            while True:
                for item in self.records:
                    if item.get("event") == event:
                        return item
                if self.process.poll() is not None:
                    raise RuntimeError("%s exited %s: %s" % (
                        self.name, self.process.returncode, list(self.errors)[-4:]))
                self.condition.wait(min(.1, remaining(end)))

    def summary(self):
        with self.condition:
            return {"pid": self.process.pid, "exit_code": self.process.poll(),
                    "process_start_to_ready_ms": (self.ready_observed - self.started) * 1000
                    if self.ready_observed is not None else None,
                    "events": dict(self.events), "last_records": list(self.records)[-10:],
                    "warm_hits": self.warm_hits, "warm_misses": self.warm_misses,
                    "session_open_samples": list(self.opens),
                    "session_open_samples_truncated": self.events["session_open"] > len(self.opens),
                    "warm_pool_events": list(self.pool_events),
                    "runtime_errors": list(self.runtime_errors),
                    "completed_flow_reports": list(self.completed_flows),
                    "completed_flow_reports_truncated": self.events["managed_session"] > len(self.completed_flows),
                    "stderr_tail": list(self.errors)[-8:]}

    def wait_count(self, event, count, deadline):
        end = min(deadline, time.monotonic() + 20)
        with self.condition:
            while self.events[event] < count:
                if self.process.poll() is not None:
                    raise RuntimeError(self.name + " stopped while waiting for " + event)
                self.condition.wait(min(.1, remaining(end)))

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.close()
                self.process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
        for reader in self.readers:
            reader.join(timeout=1)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except OSError:
                pass


class UdpProxy:
    """Transparent per-origin UDP NAT, with symmetric seeded impairment."""
    def __init__(self, name, destination, seed):
        self.name = name
        self.destination = destination
        self.rng = random.Random(seed)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.setblocking(False)
        self.port = self.listener.getsockname()[1]
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.listener, selectors.EVENT_READ, None)
        self.upstreams = {}
        self.exempt_origins = set()
        self.settings = {"delay_ms": 0., "jitter_ms": 0., "loss_percent": 0., "blocked": False}
        self.stats = Counter()
        self.lock = threading.Lock()
        self.heap = []
        self.sequence = 0
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def configure(self, delay_ms, jitter_ms=0., loss_percent=0., blocked=False):
        with self.lock:
            self.settings = {"delay_ms": delay_ms, "jitter_ms": jitter_ms,
                             "loss_percent": loss_percent, "blocked": blocked}

    def exempt(self, origin):
        # The master proxy must not impair the relay->master hop a second time.
        with self.lock:
            self.exempt_origins.add(origin)

    def _schedule(self, sock, destination, origin, data, direction):
        with self.lock:
            exempt = origin in self.exempt_origins
            cfg = dict(self.settings)
            self.stats[direction + "_received_packets"] += 1
            self.stats[direction + "_received_bytes"] += len(data)
            self.stats[("relay_transit_" if exempt else "impaired_") + direction + "_received_packets"] += 1
            if not exempt and cfg["blocked"]:
                self.stats["blackhole_drops"] += 1
                return
            if not exempt and self.rng.random() * 100 < cfg["loss_percent"]:
                self.stats["random_drops"] += 1
                return
            if len(self.heap) >= 8192:
                self.stats["queue_drops"] += 1
                return
            delay = 0 if exempt else max(
                0, cfg["delay_ms"] + self.rng.uniform(-cfg["jitter_ms"], cfg["jitter_ms"])) / 1000
            self.sequence += 1
            heapq.heappush(self.heap, (
                time.monotonic() + delay, self.sequence, sock, destination, origin, data, direction))
            self.stats["max_queued_datagrams"] = max(self.stats["max_queued_datagrams"], len(self.heap))

    def _run(self):
        try:
            while not self.stopping.is_set():
                while self.heap and self.heap[0][0] <= time.monotonic():
                    due, _, sock, destination, origin, data, direction = heapq.heappop(self.heap)
                    with self.lock:
                        blocked = self.settings["blocked"] and origin not in self.exempt_origins
                        if blocked:
                            self.stats["blackhole_drops"] += 1
                    if blocked:
                        continue
                    try:
                        if destination is None:
                            sent = sock.send(data)
                        else:
                            sent = sock.sendto(data, destination)
                        with self.lock:
                            self.stats[direction + "_sent_packets"] += 1
                            self.stats[direction + "_sent_bytes"] += sent
                            path_kind = "relay_transit_" if origin in self.exempt_origins else "impaired_"
                            self.stats[path_kind + direction + "_sent_packets"] += 1
                            self.stats["max_scheduler_lateness_us"] = max(
                                self.stats["max_scheduler_lateness_us"],
                                int(max(0, time.monotonic() - due) * 1e6))
                    except OSError:
                        with self.lock:
                            self.stats["send_errors"] += 1
                wait = .02 if not self.heap else max(0, min(.02, self.heap[0][0] - time.monotonic()))
                for key, _ in self.selector.select(wait):
                    try:
                        if key.fileobj is self.listener:
                            data, origin = self.listener.recvfrom(65535)
                            if origin[0] != "127.0.0.1":
                                continue
                            upstream = self.upstreams.get(origin)
                            if upstream is None:
                                if len(self.upstreams) >= 64:
                                    with self.lock:
                                        self.stats["origin_limit_drops"] += 1
                                    continue
                                upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                upstream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
                                upstream.bind(("127.0.0.1", 0))
                                upstream.connect(self.destination)
                                upstream.setblocking(False)
                                self.upstreams[origin] = upstream
                                self.selector.register(upstream, selectors.EVENT_READ, origin)
                            self._schedule(upstream, None, origin, data, "outbound")
                        else:
                            data = key.fileobj.recv(65535)
                            self._schedule(self.listener, key.data, key.data, data, "inbound")
                    except (OSError, ValueError):
                        with self.lock:
                            self.stats["receive_errors"] += 1
        except BaseException as exc:
            with self.lock:
                self.stats["thread_errors"] += 1
                self.thread_error = repr(exc)

    def snapshot(self):
        with self.lock:
            return {"name": self.name, "advertised": addr(self.port),
                    "upstream": addr(self.destination[1]), "settings": dict(self.settings),
                    "counters": dict(self.stats), "thread_alive": self.thread.is_alive(),
                    "thread_error": getattr(self, "thread_error", None)}

    def close(self):
        self.stopping.set()
        self.thread.join(timeout=2)
        self.selector.close()
        for sock in list(self.upstreams.values()) + [self.listener]:
            sock.close()
        if self.thread.is_alive():
            raise RuntimeError("UDP proxy did not stop")


class Service(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    block_on_close = False

    def __init__(self, identity, token, idle_timeout, half=False):
        super().__init__(("127.0.0.1", 0), ServiceHandler)
        self.identity = identity
        self.token = token
        self.idle_timeout = idle_timeout
        self.half = half
        self.increments = Counter()
        self.increment_total = 0
        self.increment_lock = threading.Lock()
        self.active = set()
        self.active_lock = threading.Lock()
        self.thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
        self.thread.start()

    def handle_error(self, request, client_address):
        # Intentional cancellation may reset a test TCP socket.
        pass

    def close(self):
        self.shutdown()
        with self.active_lock:
            for sock in list(self.active):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except OSError:
                    pass
        self.server_close()
        self.thread.join(timeout=1)


class ServiceHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(self.server.idle_timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with self.server.active_lock:
            self.server.active.add(sock)
        try:
            if self.server.half:
                digest = hashlib.sha256()
                size = 0
                while True:
                    data = sock.recv(65536)
                    if not data:
                        break
                    size += len(data)
                    if size > 4 * 1024 * 1024:
                        return
                    digest.update(data)
                sock.sendall(struct.pack("!Q", size) + digest.digest())
                return
            buffer = b""
            while True:
                while b"\r\n\r\n" not in buffer:
                    data = sock.recv(4096)
                    if not data:
                        return
                    buffer += data
                    if len(buffer) > 8192:
                        return
                header, buffer = buffer.split(b"\r\n\r\n", 1)
                rows = header.decode("ascii").split("\r\n")
                method, path, version = rows[0].split()
                headers = dict(line.split(":", 1) for line in rows[1:])
                headers = {k.lower(): v.strip() for k, v in headers.items()}
                if (method not in ("GET", "POST") or version != "HTTP/1.1"
                        or headers.get("authorization") != "Bearer " + self.server.token):
                    sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                close = headers.get("connection", "").lower() == "close"
                counter = None
                if method == "POST" and path.startswith("/increment/"):
                    if headers.get("content-length") != "9":
                        return
                    while len(buffer) < 9:
                        data = sock.recv(4096)
                        if not data:
                            return
                        buffer += data
                    posted, buffer = buffer[:9], buffer[9:]
                    if posted != b"increment":
                        return
                    request_id = path[len("/increment/"):]
                    with self.server.increment_lock:
                        # Deliberately do NOT deduplicate requests at the server.
                        # Any duplicated application POST changes this counter.
                        self.server.increment_total += 1
                        self.server.increments[request_id] += 1
                        counter = self.server.increment_total
                    body = (self.server.identity + ":" + path + ":" + str(counter)).encode()
                    size = len(body)
                elif method == "GET" and path.startswith("/tiny/"):
                    body = (self.server.identity + ":" + path).encode()
                    size = len(body)
                elif method == "GET" and path.startswith("/bulk/"):
                    size = int(path[len("/bulk/"):])
                    if not 1 <= size <= 32 * 1024 * 1024:
                        return
                    body = None
                else:
                    return
                reply = ("HTTP/1.1 200 OK\r\nContent-Length: %s\r\n"
                         "X-Bench-Identity: %s\r\nConnection: %s\r\n\r\n" %
                         (size, self.server.identity, "close" if close else "keep-alive")).encode()
                if body is not None:
                    # One write avoids measuring Python server header/body batching.
                    sock.sendall(reply + body)
                else:
                    sock.sendall(reply)
                    left = size
                    while left:
                        take = min(left, len(PATTERN))
                        sock.sendall(PATTERN[:take])
                        left -= take
                if close:
                    return
        except (OSError, UnicodeError, ValueError):
            return
        finally:
            with self.server.active_lock:
                self.server.active.discard(sock)


class HttpConnection:
    def __init__(self, target, deadline):
        before = time.monotonic()
        self.sock = socket.create_connection(address(target), timeout=remaining(deadline))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.connect_ms = (time.monotonic() - before) * 1000
        self.request_count = 0

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def exchange(self, identity, token, path, deadline, close, expected_digest=None, first_byte=None,
                 expected_counter=None):
        self.request_count += 1
        post = expected_counter is not None
        request = ("%s %s HTTP/1.1\r\nHost: loopback-benchmark\r\n"
                   "Authorization: Bearer %s\r\nConnection: %s\r\n%s\r\n" %
                   ("POST" if post else "GET", path, token, "close" if close else "keep-alive",
                    "Content-Length: 9\r\n" if post else "")).encode()
        if post:
            request += b"increment"
        self.sock.settimeout(remaining(deadline))
        self.sock.sendall(request)
        buffer = b""
        first = None
        while b"\r\n\r\n" not in buffer:
            self.sock.settimeout(remaining(deadline))
            data = self.sock.recv(65536)
            if not data:
                raise AssertionError("EOF before HTTP response header")
            if first is None:
                first = time.monotonic()
                if first_byte:
                    first_byte.set()
            buffer += data
            if b"\r\n\r\n" not in buffer and len(buffer) > 8192:
                raise AssertionError("oversized HTTP response header")
        header, body = buffer.split(b"\r\n\r\n", 1)
        rows = header.decode("ascii").split("\r\n")
        if rows[0] != "HTTP/1.1 200 OK":
            raise AssertionError("HTTP status: " + rows[0])
        headers = dict(line.split(":", 1) for line in rows[1:])
        headers = {k.lower(): v.strip() for k, v in headers.items()}
        if headers.get("x-bench-identity") != identity:
            raise AssertionError("wrong target identity / crossed TCP forwarding port")
        tiny = ((identity + ":" + path + ":" + str(expected_counter)).encode() if post
                else ((identity + ":" + path).encode() if path.startswith("/tiny/") else None))
        expected_size = len(tiny) if tiny is not None else int(path[len("/bulk/"):])
        if int(headers["content-length"]) != expected_size:
            raise AssertionError("wrong Content-Length")
        total = len(body)
        if total > expected_size:
            raise AssertionError("extra bytes beyond response body")
        digest = hashlib.sha256(body)
        received_tiny = bytearray(body) if tiny is not None else None
        while total < expected_size:
            self.sock.settimeout(remaining(deadline))
            data = self.sock.recv(min(65536, expected_size - total))
            if not data:
                raise AssertionError("truncated body: %s/%s" % (total, expected_size))
            total += len(data)
            digest.update(data)
            if received_tiny is not None:
                received_tiny.extend(data)
        actual_digest = digest.hexdigest()
        if tiny is not None:
            if bytes(received_tiny) != tiny:
                raise AssertionError("incorrect response identity or request sequence")
        elif actual_digest != expected_digest:
            raise AssertionError("bulk SHA-256 mismatch")
        return first, total, actual_digest


def percentile(values, p):
    if not values:
        return None
    values = sorted(values)
    point = (len(values) - 1) * p / 100
    lower = int(point)
    upper = min(lower + 1, len(values) - 1)
    return values[lower] + (values[upper] - values[lower]) * (point - lower)


def statistics(samples):
    ok = [row for row in samples if row["ok"]]
    times = [row["ttfb_ms"] for row in ok if "ttfb_ms" in row]
    return {"attempts": len(samples), "successes": len(ok),
            "failures": len(samples) - len(ok),
            "successful_ttfb_ms": {"p50": percentile(times, 50),
                                   "p95": percentile(times, 95),
                                   "p99": percentile(times, 99),
                                   "max": max(times) if times else None},
            "quantile_method": "linear interpolation, successful samples only",
            "small_sample_warning": len(times) < 100}


class Bench:
    def __init__(self, args, result):
        self.args = args
        self.result = result
        self.start = time.monotonic()
        self.deadline = self.start + args.total_timeout
        self.token = secrets.token_hex(24)
        self.nodes = {}
        self.retired_nodes = []
        self.proxies = []
        self.servers = []
        self.targets = {}
        self.samples = result["samples"]
        self.background_threads = []
        self.sample_lock = threading.Lock()
        self.sequence = 0
        self.had_direct_blackhole = False
        self.bulk_bytes = int(args.bulk_mib * 1024 * 1024)
        self.bulk_digest = digest_for(self.bulk_bytes)

    def setup(self, directory):
        states = {name: directory / (name + ".json") for name in ("master", "relay", "client")}
        self.states = states
        for name, half in (("http-a", False), ("http-b", False), ("half", True)):
            server = Service(name, self.token, self.args.total_timeout + 10, half)
            self.servers.append(server)
            self.targets[name] = addr(server.server_address[1])
        master_port = free_port(socket.SOCK_DGRAM)
        relay_port = free_port(socket.SOCK_DGRAM)
        while relay_port == master_port:
            relay_port = free_port(socket.SOCK_DGRAM)
        master_proxy = UdpProxy("direct", address(addr(master_port)), self.args.seed)
        self.proxies.append(master_proxy)
        relay_proxy = UdpProxy("relay", address(addr(relay_port)), self.args.seed + 1)
        self.proxies.append(relay_proxy)
        master_proxy.exempt(address(addr(relay_port)))
        self.impair()
        command = ["init", "--state", str(states["master"]), "--control", addr(free_port()),
                   "--bind", addr(master_port), "--advertise", addr(master_proxy.port),
                   "--wire-mbps", str(self.args.wire_mbps),
                   "--upload-wire-mbps", str(self.args.wire_mbps)]
        if self.args.profile != "existing":
            command += ["--profile", self.args.profile]
        if self.args.warm_sessions is not None:
            command += ["--warm-sessions", str(self.args.warm_sessions)]
        for name, target in self.targets.items():
            command += ["--forward", name + "=" + target]
        invitation = json.loads(invoke(self.args.binary, command, self.deadline))["invitation"]
        saved = json.loads(states["master"].read_text())
        self.result["effective_tuning"] = saved.get("settings", saved).get("tuning")
        self.nodes["master"] = self.start_node("master")
        invoke(self.args.binary, [
            "join", "--state", str(states["relay"]), "--as", "relay", "--name", "latency-relay",
            "--bind", addr(relay_port), "--advertise", addr(relay_proxy.port)],
            self.deadline, invitation)
        self.nodes["relay"] = self.start_node("relay")
        command = ["join", "--state", str(states["client"]), "--name", "latency-client"]
        for name in self.targets:
            command += ["--forward", name + "=127.0.0.1:0"]
        invoke(self.args.binary, command, self.deadline, invitation)
        self.nodes["client"] = self.start_node("client")
        ready = self.nodes["client"].ready
        self.addresses = {item["service"]: item["listen"] for item in ready["forwards"]}
        if set(self.addresses) != set(self.targets):
            raise AssertionError("not all three independent forwarded TCP services are ready")
        self.result["topology"] = {
            "services": dict(self.addresses), "physical_client_uplinks": ready.get("uplinks"),
            "udp_data_paths": 2, "control_plane_impaired": False,
            "client_ready": ready,
            "process_start_to_ready_ms": {
                name: (node.ready_observed - node.started) * 1000 for name, node in self.nodes.items()},
            "proxy_model": "per-origin UDP NAT; opaque datagrams; both directions impaired",
            "delay_definition": "configured milliseconds are ONE WAY on each data path"}
        emit("http_latency_ready", profile=self.args.profile, cases=self.args.cases)

    def start_node(self, name):
        lifetime = str(math.ceil(self.args.total_timeout + 30))
        return Node(name, [str(self.args.binary), "run", "--state", str(self.states[name]),
                          "--exit-on-stdin", "--lifetime-seconds", lifetime], self.deadline)

    def impair(self, loss=0., jitter=0., direct_blocked=False):
        self.proxies[0].configure(self.args.delay_ms, jitter, loss, direct_blocked)
        self.proxies[1].configure(self.args.delay_ms + self.args.relay_extra_ms, jitter, loss)

    def record(self, row):
        with self.sample_lock:
            self.samples.append(row)

    def request(self, case, service, connection=None, bulk=False, first_byte=None, background=False,
                expected_counter=None, scheduled_start=None):
        with self.sample_lock:
            self.sequence += 1
            sequence = self.sequence
        path = ("/increment/" + str(sequence) if expected_counter is not None
                else ("/bulk/" + str(self.bulk_bytes) if bulk else "/tiny/" + str(sequence)))
        start = time.monotonic()
        deadline = min(self.deadline, start + self.args.request_timeout)
        row = {"case": case, "service": service, "sample_id": sequence,
               "start_s": start - self.start, "new_tcp": connection is None,
               "background": background, "ok": False}
        if expected_counter is not None:
            row.update(method="POST", request_id=str(sequence), expected_counter=expected_counter)
        if scheduled_start is not None:
            row.update(scheduled_start_s=scheduled_start - self.start,
                       launch_lateness_ms=max(0, start - scheduled_start) * 1000)
        owned = connection is None
        try:
            if owned:
                connection = HttpConnection(self.addresses[service], deadline)
            row["tcp_connect_ms"] = connection.connect_ms if owned else 0.
            row["first_on_tcp"] = connection.request_count == 0
            first, total, digest = connection.exchange(
                service, self.token, path, deadline, owned, self.bulk_digest if bulk else None,
                first_byte, expected_counter)
            row.update(ok=True, ttfb_ms=(first - start) * 1000, total_ms=(time.monotonic() - start) * 1000,
                       verified_bytes=total, sha256=digest)
            if bulk:
                row["goodput_mbps"] = total * 8 / max(row["total_ms"] / 1000, .000001) / 1e6
            if scheduled_start is not None:
                row["scheduled_ttfb_ms"] = (first - scheduled_start) * 1000
        except Exception as exc:
            row.update(error=type(exc).__name__ + ": " + str(exc),
                       total_ms=(time.monotonic() - start) * 1000)
        finally:
            if owned and connection is not None:
                connection.close()
        self.record(row)
        return row

    def connection(self, service):
        return HttpConnection(self.addresses[service],
                              min(self.deadline, time.monotonic() + self.args.request_timeout))

    def parallel(self, case, count, keepalive=False, minimum_seconds=0):
        def worker(service):
            connection = None
            try:
                if keepalive:
                    connection = self.connection(service)
                end = time.monotonic() + minimum_seconds
                for index in range(count):
                    self.request(case, service, connection)
                    if index + 1 < count:
                        pause(self.args.interval_ms / 1000, self.deadline)
                # A background phase lasts long enough to see a sustained download,
                # even if all the requested minimum samples completed immediately.
                while time.monotonic() < end:
                    self.request(case, service, connection)
                    pause(self.args.interval_ms / 1000, self.deadline)
            except Exception as exc:
                self.record({"case": case, "service": service, "ok": False,
                             "start_s": time.monotonic() - self.start,
                             "error": "worker: " + type(exc).__name__ + ": " + str(exc)})
            finally:
                if connection is not None:
                    connection.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker, name) for name in ("http-a", "http-b")]
            for future in futures:
                future.result()

    def idle(self):
        connections = {}
        preconnected = {}
        preconnected_at = {}
        try:
            for service in ("http-a", "http-b"):
                connections[service] = self.connection(service)
                self.request("idle_before", service, connections[service])
                # Accept a business TCP socket but send no HTTP request at all
                # until the long idle interval has passed.
                preconnected[service] = self.connection(service)
                preconnected_at[service] = time.monotonic()
            pause(self.args.idle_seconds, self.deadline)
            for service, connection in connections.items():
                row = self.request("idle_after", service, connection)
                row["held_idle_seconds"] = self.args.idle_seconds
            for service, connection in preconnected.items():
                held = time.monotonic() - preconnected_at[service]
                row = self.request("idle_preconnected_first_request", service, connection)
                row["tcp_connected_without_http_request_seconds"] = held
            # Also consume previously unused warm sessions after the idle period.
            for service in connections:
                row = self.request("idle_new_tcp", service)
                row["pool_idle_seconds"] = self.args.idle_seconds
        finally:
            for connection in list(connections.values()) + list(preconnected.values()):
                connection.close()

    def burst_short(self):
        # Fixed launch times expose rejects/queueing instead of allowing slow
        # responses to reduce the offered connection rate (coordinated omission).
        self.impair(direct_blocked=self.args.burst_relay_only)
        if self.args.burst_relay_only:
            self.had_direct_blackhole = True
        injection_before = [proxy.snapshot() for proxy in self.proxies]
        settle_seconds = max(3., self.args.warmup_seconds) if self.args.burst_relay_only else self.args.warmup_seconds
        pause(settle_seconds, self.deadline)
        proxy_before = [proxy.snapshot() for proxy in self.proxies]
        client = self.nodes["client"]
        with client.condition:
            events_before = dict(client.events)
            warm_before = (client.warm_hits, client.warm_misses)
        start = time.monotonic() + .2
        before = len(self.samples)
        def worker(index):
            scheduled = start + index / self.args.burst_rps
            delay = max(0, scheduled - time.monotonic())
            if delay:
                pause(delay, self.deadline)
            return self.request("burst_short", "http-a" if index % 2 == 0 else "http-b",
                                scheduled_start=scheduled)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(128, self.args.burst_count)) as pool:
                futures = [pool.submit(worker, index) for index in range(self.args.burst_count)]
                for future in futures:
                    future.result()
        finally:
            proxy_after = [proxy.snapshot() for proxy in self.proxies]
            self.impair()
        rows = self.samples[before:]
        lateness = [row["launch_lateness_ms"] for row in rows]
        scheduled_ttfb = [row["scheduled_ttfb_ms"] for row in rows if row["ok"]]
        buckets = {}
        for row in rows:
            second = int(round((row["scheduled_start_s"] - (start - self.start)) * self.args.burst_rps) / self.args.burst_rps)
            bucket = buckets.setdefault(second, {"scheduled_second": second, "attempts": 0, "failures": 0})
            bucket["attempts"] += 1
            bucket["failures"] += int(not row["ok"])
        def delta(proxy_index, key, snapshots=proxy_before):
            return (proxy_after[proxy_index]["counters"].get(key, 0)
                    - snapshots[proxy_index]["counters"].get(key, 0))
        witness = {
            "configured_udp_paths": 2,
            "requested_direct_blackhole": self.args.burst_relay_only,
            "direct_proxy_observed_blocked": proxy_before[0]["settings"]["blocked"],
            "settle_seconds": settle_seconds,
            "direct_blackhole_drops_including_settle": delta(0, "blackhole_drops", injection_before),
            "direct_forwarded_packets_during_burst": sum(delta(0, "impaired_" + side + "_sent_packets")
                                                         for side in ("inbound", "outbound")),
            "relay_forwarded_packets_during_burst": {side: delta(1, side + "_sent_packets")
                                                      for side in ("inbound", "outbound")},
            "relay_to_master_passthrough_packets": delta(0, "relay_transit_outbound_sent_packets"),
            "master_to_relay_passthrough_packets": delta(0, "relay_transit_inbound_sent_packets")}
        witness["relay_only_observed"] = (
            self.args.burst_relay_only and witness["direct_proxy_observed_blocked"]
            and witness["direct_blackhole_drops_including_settle"] > 0
            and witness["direct_forwarded_packets_during_burst"] == 0
            and all(value > 0 for value in witness["relay_forwarded_packets_during_burst"].values())
            and witness["relay_to_master_passthrough_packets"] > 0
            and witness["master_to_relay_passthrough_packets"] > 0)
        if self.args.burst_relay_only:
            self.record({"case": "burst_relay_only_injection", "service": "udp-paths",
                         "ok": witness["relay_only_observed"], **witness})
        with client.condition:
            errors_after = {key: value - events_before.get(key, 0) for key, value in client.events.items()
                            if key.endswith("error") or "reject" in key}
            opens_during_burst = client.events["session_open"] - events_before.get("session_open", 0)
            warm_during_burst = {"hits": client.warm_hits - warm_before[0],
                                 "misses": client.warm_misses - warm_before[1]}
            runtime_errors = [dict(item) for item in client.runtime_errors
                              if client.started + item["observed_since_process_start_s"] >= start]
        self.result["burst_short"] = {
            "offered_connections_per_second": self.args.burst_rps,
            "scheduled_connections": self.args.burst_count,
            "issued_connections": len(rows), "failures": sum(not r["ok"] for r in rows),
            "per_scheduled_second": [buckets[key] for key in sorted(buckets)],
            "path_witness": witness, "proxy_before": proxy_before, "proxy_after": proxy_after,
            "client_error_event_counts": errors_after, "client_runtime_errors": runtime_errors,
            "client_sessions_opened": opens_during_burst, "warm_sessions_consumed": warm_during_burst,
            "launch_lateness_ms": {"p50": percentile(lateness, 50),
                                   "p99": percentile(lateness, 99), "max": max(lateness)},
            "successful_scheduled_ttfb_ms": {"p50": percentile(scheduled_ttfb, 50),
                                            "p99": percentile(scheduled_ttfb, 99),
                                            "max": max(scheduled_ttfb) if scheduled_ttfb else None}}

    def background(self):
        stop = threading.Event()
        first_byte = threading.Event()
        before = len(self.samples)
        def download():
            while not stop.is_set() and time.monotonic() < self.deadline:
                row = self.request("background_bulk", "http-a", bulk=True,
                                   first_byte=first_byte, background=True)
                if not row["ok"]:
                    first_byte.set()
                    break
        thread = threading.Thread(target=download, daemon=True)
        self.background_threads.append((thread, stop))
        thread.start()
        try:
            if not first_byte.wait(min(self.args.request_timeout, remaining(self.deadline))):
                raise TimeoutError("background download did not start")
            self.parallel("background_small", self.args.samples, keepalive=True,
                          minimum_seconds=self.args.background_seconds)
        finally:
            stop.set()
            thread.join(timeout=self.args.request_timeout + 1)
            if thread.is_alive():
                raise TimeoutError("owned background download did not finish within its request budget")
        rows = self.samples[before:]
        windows = [(r["start_s"], r["start_s"] + r["total_ms"] / 1000)
                   for r in rows if r["case"] == "background_bulk" and r["ok"]]
        for row in rows:
            if row["case"] == "background_small" and "total_ms" in row:
                row["overlapped_verified_background_download"] = any(
                    left <= row["start_s"] + row["total_ms"] / 1000 and right >= row["start_s"]
                    for left, right in windows)

    def path_loss(self):
        self.impair()
        connections = {}
        before = [proxy.snapshot() for proxy in self.proxies]
        try:
            for service in ("http-a", "http-b"):
                connections[service] = self.connection(service)
                self.request("path_loss_before", service, connections[service])
            self.impair(direct_blocked=True)
            self.had_direct_blackhole = True
            self.result["direct_blackhole_at_s"] = time.monotonic() - self.start
            def worker(service):
                for index in range(self.args.samples):
                    self.request("path_loss", service, connections[service])
                    if index + 1 < self.args.samples:
                        pause(self.args.interval_ms / 1000, self.deadline)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(worker, service) for service in connections]
                for future in futures:
                    future.result()
            # Verify new TCP service requests also work with the direct path absent.
            self.parallel("path_loss_new", max(2, self.args.samples // 4))
            after = [proxy.snapshot() for proxy in self.proxies]
            drops = (after[0]["counters"].get("blackhole_drops", 0)
                     - before[0]["counters"].get("blackhole_drops", 0))
            relay_packets = (after[1]["counters"].get("outbound_sent_packets", 0)
                             - before[1]["counters"].get("outbound_sent_packets", 0))
            transit_packets = (after[0]["counters"].get("relay_transit_outbound_received_packets", 0)
                               - before[0]["counters"].get("relay_transit_outbound_received_packets", 0))
            witnessed = drops > 0 and relay_packets > 0 and transit_packets > 0
            self.record({"case": "path_loss_injection", "service": "udp-paths", "ok": witnessed,
                         "direct_blackhole_drops": drops, "relay_forwarded_packets": relay_packets,
                         "relay_to_master_passthrough_packets": transit_packets})
        finally:
            for connection in connections.values():
                connection.close()
            self.impair()

    def contracts(self):
        self.impair()
        pause(self.args.warmup_seconds, self.deadline)
        self.result["bulk_integrity_context"] = {
            "configured_udp_paths": 2, "after_prior_direct_blackhole": self.had_direct_blackhole,
            "recovery_wait_seconds": self.args.warmup_seconds,
            "proxies_at_start": [proxy.snapshot() for proxy in self.proxies],
            "note": "Default all runs this bulk phase before deliberate network faults. A custom case order after path loss may retain recovering per-session routes."}
        bulk_started = time.monotonic()
        self.request("bulk_integrity", "http-a", bulk=True)
        self.request("bulk_integrity", "http-b", bulk=True)
        payload = PATTERN * 2
        start = time.monotonic()
        deadline = min(self.deadline, start + self.args.request_timeout)
        row = {"case": "half_close", "service": "half", "ok": False, "start_s": start - self.start}
        try:
            with socket.create_connection(address(self.addresses["half"]), timeout=remaining(deadline)) as sock:
                sock.settimeout(remaining(deadline))
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                body = bytearray()
                expected = struct.pack("!Q", len(payload)) + hashlib.sha256(payload).digest()
                while len(body) < len(expected):
                    sock.settimeout(remaining(deadline))
                    data = sock.recv(len(expected) - len(body))
                    if not data:
                        raise AssertionError("EOF before response to TCP half-close")
                    body.extend(data)
                if bytes(body) != expected:
                    raise AssertionError("half-close response count or SHA-256 mismatch")
                sock.settimeout(remaining(deadline))
                if sock.recv(1):
                    raise AssertionError("unexpected bytes after half-close response")
            row.update(ok=True, verified_bytes=len(payload) + len(expected),
                       payload_sha256=hashlib.sha256(payload).hexdigest())
        except Exception as exc:
            row["error"] = type(exc).__name__ + ": " + str(exc)
        row["total_ms"] = (time.monotonic() - start) * 1000
        self.record(row)
        # Payload copying below TCP must not duplicate non-idempotent HTTP work.
        # Impair both directions; every request is issued exactly once by this
        # client, and the server increments even when an ID was already seen.
        self.impair(loss=self.args.loss_percent, jitter=self.args.jitter_ms)
        expected = {}
        counts_before = {}
        occurrences_before = {}
        for server in self.servers:
            if server.identity in ("http-a", "http-b"):
                with server.increment_lock:
                    counts_before[server.identity] = server.increment_total
                    occurrences_before[server.identity] = dict(server.increments)
        try:
            for service in ("http-a", "http-b"):
                expected[service] = []
                with_connection = self.connection(service)
                try:
                    for count in range(1, min(self.args.samples, 25) + 1):
                        posted = self.request("post_exactly_once", service, with_connection,
                                              expected_counter=counts_before[service] + count)
                        expected[service].append(posted["request_id"])
                finally:
                    with_connection.close()
        finally:
            self.impair()
        verified = {}
        for server in self.servers:
            if server.identity not in expected:
                continue
            with server.increment_lock:
                new_requests = {request_id: 1 for request_id in expected[server.identity]}
                wanted = {**occurrences_before[server.identity], **new_requests}
                actual = dict(server.increments)
                side_effects = server.increment_total - counts_before[server.identity]
                correct = actual == wanted and side_effects == len(new_requests)
                verified[server.identity] = {
                    "ok": correct, "expected_requests": len(new_requests),
                    "observed_side_effects": side_effects,
                    "server_total_before": counts_before[server.identity],
                    "server_total_after": server.increment_total,
                    "raw_request_occurrences": actual,
                    "duplicate_request_ids": {key: value for key, value in actual.items() if value != 1}}
                self.record({"case": "post_server_counter", "service": server.identity,
                             "ok": correct, "expected_requests": len(new_requests),
                             "observed_side_effects": side_effects})
        self.result["non_idempotent_post_contract"] = verified
        with self.nodes["master"].condition:
            bulk_reports = [dict(report) for report in self.nodes["master"].completed_flows
                            if report["observed_monotonic_s"] >= bulk_started
                            and report.get("tx_bytes", 0) >= self.bulk_bytes
                            and report.get("service") in ("http-a", "http-b")]
        self.result["bulk_integrity_context"]["master_completed_bulk_flows"] = bulk_reports

    def master_restart(self):
        """Restart only the master; never resend a completed POST or old stream."""
        self.impair()
        client = self.nodes["client"]
        client_pid = client.process.pid
        warm = (self.result.get("effective_tuning") or {}).get("warm_sessions", 0) > 0
        if warm:
            client.wait_count("warm_pool_ready", 1, self.deadline)
        connections = {}
        counters_before = {}
        server_by_name = {server.identity: server for server in self.servers}
        try:
            for service in ("http-a", "http-b"):
                server = server_by_name[service]
                with server.increment_lock:
                    next_counter = server.increment_total + 1
                connections[service] = self.connection(service)
                posted = self.request("master_restart_completed_post", service, connections[service],
                                      expected_counter=next_counter)
                if not posted["ok"]:
                    raise AssertionError("pre-restart POST did not complete")
                with server.increment_lock:
                    counters_before[service] = server.increment_total
            status = lambda: json.loads(invoke(
                self.args.binary, ["status", "--state", str(self.states["master"])], self.deadline))
            epoch_before = status()["epoch"]
            with client.condition:
                topology_events = client.events["topology"]
                pool_events = client.events["warm_pool_ready"]
            old_master = self.nodes["master"]
            restarted_at = time.monotonic()
            old_master.close()
            self.retired_nodes.append(old_master)
            self.nodes["master"] = self.start_node("master")
            epoch_after = status()["epoch"]
            if epoch_after == epoch_before:
                raise AssertionError("master restart did not change the runtime epoch")
            client.wait_count("topology", topology_events + 1, self.deadline)
            if warm:
                client.wait_count("warm_pool_ready", pool_events + 1, self.deadline)
            restored_s = time.monotonic() - restarted_at
            self.parallel("master_restart_new_tcp", max(2, min(8, self.args.samples)))
            counters_after = {}
            for service, server in server_by_name.items():
                if service in counters_before:
                    with server.increment_lock:
                        counters_after[service] = server.increment_total
            same_client = client.process.pid == client_pid and client.process.poll() is None
            exact = counters_after == counters_before
            row = {"case": "master_restart_contract", "service": "both-http-services",
                   "ok": same_client and exact, "same_client_process": same_client,
                   "completed_posts_not_replayed": exact, "post_counts_before": counters_before,
                   "post_counts_after": counters_after, "epoch_before": epoch_before,
                   "epoch_after": epoch_after, "warm_pool_reprimed": warm,
                   "master_stop_to_recovery_ready_s": restored_s,
                   "listener_addresses_reused": dict(self.addresses),
                   "old_business_tcp_survival_asserted": False}
            self.result["master_restart"] = dict(row, old_master=old_master.summary())
            self.record(row)
        finally:
            for connection in connections.values():
                connection.close()

    def run(self):
        for case in self.args.cases:
            before = len(self.samples)
            proxy_before = [proxy.snapshot() for proxy in self.proxies]
            start = time.monotonic()
            if case == "cold":
                self.parallel("first_tcp_after_ready", 1)
            elif case == "new":
                pause(self.args.warmup_seconds, self.deadline)
                self.parallel("new_tcp_warm", self.args.samples)
            elif case == "keepalive":
                self.parallel("keepalive", self.args.samples, keepalive=True)
            elif case == "idle":
                self.idle()
            elif case == "background":
                self.background()
            elif case == "impaired":
                self.impair(loss=self.args.loss_percent, jitter=self.args.jitter_ms)
                try:
                    self.parallel("impaired_new", max(2, self.args.samples // 2))
                    self.parallel("impaired_keepalive", self.args.samples, keepalive=True)
                finally:
                    self.impair()
            elif case == "path_loss":
                self.path_loss()
            elif case == "contracts":
                self.contracts()
            elif case == "burst_short":
                self.burst_short()
            elif case == "master_restart":
                self.master_restart()
            dead = {name: node.process.poll() for name, node in self.nodes.items()
                    if node.process.poll() is not None}
            if dead:
                raise RuntimeError("owned tunnel processes exited during case: " + str(dead))
            after = self.samples[before:]
            self.result["scenarios"].append({
                "case": case, "elapsed_s": time.monotonic() - start,
                "attempts": len(after), "failures": sum(not r["ok"] for r in after),
                "injection": {"loss_percent": self.args.loss_percent if case in ("impaired", "contracts") else 0,
                              "jitter_ms": self.args.jitter_ms if case in ("impaired", "contracts") else 0,
                              "direct_blackhole": case == "path_loss" or (case == "burst_short" and self.args.burst_relay_only),
                              "contracts_impairment_scope": "POST phase only" if case == "contracts" else None},
                "proxy_before": proxy_before, "proxy_after": [proxy.snapshot() for proxy in self.proxies]})
            emit("http_latency_case", case=case, **statistics(after))

    def close(self):
        errors = []
        self.result["processes_before_cleanup"] = {name: node.summary() for name, node in self.nodes.items()}
        self.result["proxies_before_cleanup"] = [proxy.snapshot() for proxy in self.proxies]
        for _, stop in self.background_threads:
            stop.set()
        for name, node in reversed(list(self.nodes.items())):
            try:
                node.close()
            except Exception as exc:
                errors.append(name + ": " + repr(exc))
        for node in self.retired_nodes:
            try:
                node.close()
            except Exception as exc:
                errors.append("retired-" + node.name + ": " + repr(exc))
        for proxy in self.proxies:
            try:
                proxy.close()
            except Exception as exc:
                errors.append(proxy.name + ": " + repr(exc))
        for server in self.servers:
            try:
                server.close()
            except Exception as exc:
                errors.append(server.identity + ": " + repr(exc))
        for thread, _ in self.background_threads:
            thread.join(timeout=2)
        self.result["cleanup"] = {
            "owned_processes_stopped": all(node.process.poll() is not None
                                            for node in list(self.nodes.values()) + self.retired_nodes),
            "owned_udp_proxy_threads_stopped": all(not p.thread.is_alive() for p in self.proxies),
            "owned_background_threads_stopped": all(not t.is_alive() for t, _ in self.background_threads),
            "errors": errors}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/agg-fec-tunnel")
    parser.add_argument("--profile", default="latency",
                        help="init --profile value; 'existing' omits it for older baseline binaries")
    parser.add_argument("--warm-sessions", type=int, help="optional init override for warm-pool ablation, 0..16")
    parser.add_argument("--cases", default="all", help="comma-separated: " + ",".join(ALL_CASES)
                        + "; optional (excluded from all): " + ",".join(OPTIONAL_CASES))
    parser.add_argument("--quick", action="store_true", help="8 samples/port, 2s idle, .5MiB bulk")
    parser.add_argument("--samples", type=int)
    parser.add_argument("--idle-seconds", type=float)
    parser.add_argument("--bulk-mib", type=float)
    parser.add_argument("--warmup-seconds", type=float, default=2.)
    parser.add_argument("--background-seconds", type=float, default=3.)
    parser.add_argument("--interval-ms", type=float, default=20.)
    parser.add_argument("--delay-ms", type=float, default=10., help="one-way delay on EACH UDP data path")
    parser.add_argument("--relay-extra-ms", type=float, default=3.)
    parser.add_argument("--loss-percent", type=float, default=3., help="independent loss per direction in impaired case")
    parser.add_argument("--jitter-ms", type=float, default=6., help="uniform +/- one-way delay jitter in impaired case")
    parser.add_argument("--wire-mbps", type=int, default=80, help="shared managed upload/download wire budget; latency default is 80")
    parser.add_argument("--burst-count", type=int, default=100)
    parser.add_argument("--burst-rps", type=float, default=100.)
    parser.add_argument("--burst-relay-only", action="store_true",
                        help="in burst_short, blackhole direct for >=3s before fixed-rate requests; verify all payload uses relay")
    parser.add_argument("--request-timeout", type=float, default=12.)
    parser.add_argument("--total-timeout", type=float, default=300.)
    parser.add_argument("--seed", type=int, default=10102026)
    parser.add_argument("--minimum-goodput-mbps", type=float, default=0.,
                        help="optional acceptance floor on each bulk_integrity sample; default reports only")
    parser.add_argument("--output", type=Path, help="write complete JSON including all raw samples")
    parser.add_argument("--note", action="append", default=[], help="record run context, e.g. concurrent compiler load")
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    args.cases = list(ALL_CASES) if args.cases == "all" else args.cases.split(",")
    if not args.cases or any(case not in ALL_CASES + OPTIONAL_CASES for case in args.cases) or len(set(args.cases)) != len(args.cases):
        parser.error("cases must be unique names from: " + ",".join(ALL_CASES + OPTIONAL_CASES))
    if "cold" in args.cases and args.cases[0] != "cold":
        parser.error("cold must run first so it really is the first application request")
    args.samples = args.samples if args.samples is not None else (8 if args.quick else 50)
    args.idle_seconds = args.idle_seconds if args.idle_seconds is not None else (2. if args.quick else 25.)
    args.bulk_mib = args.bulk_mib if args.bulk_mib is not None else (.5 if args.quick else 2.)
    if not args.binary.is_file() or not os.access(args.binary, os.X_OK):
        parser.error("binary is missing or not executable; build it separately before running")
    bounds = {
        "samples": (1, 10000), "idle_seconds": (0, 600), "bulk_mib": (.0625, 32),
        "warmup_seconds": (0, 60), "background_seconds": (.1, 120), "interval_ms": (0, 5000),
        "delay_ms": (0, 1000), "relay_extra_ms": (0, 1000), "jitter_ms": (0, 1000),
        "loss_percent": (0, 50), "wire_mbps": (1, 10000), "request_timeout": (1, 120),
        "burst_count": (1, 10000), "burst_rps": (.1, 1000),
        "total_timeout": (15, 1800), "minimum_goodput_mbps": (0, 10000)}
    for name, (low, high) in bounds.items():
        if not math.isfinite(getattr(args, name)) or not low <= getattr(args, name) <= high:
            parser.error("%s must be %s..%s" % (name, low, high))
    if args.warm_sessions is not None and not 0 <= args.warm_sessions <= 16:
        parser.error("warm_sessions must be 0..16")
    return args


def main():
    args = parse_args()
    config = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    result = {
        "schema": 1, "event": "http_latency_result", "ok": False, "config": config,
        "environment": {"platform": platform.platform(), "python": sys.version,
                        "machine": platform.machine(), "cpu_count": os.cpu_count(),
                        "load_average_at_start": os.getloadavg() if hasattr(os, "getloadavg") else None,
                        "utc_started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "binary": str(args.binary), "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest()},
        "measurement_limits": [
            "Loopback data-plane simulation; control TLS/enrollment is not delayed or impaired.",
            "Python UDP proxies add scheduling and CPU cost; use identical settings when comparing profiles.",
            "Loss RNG seed is reproducible per proxy; a changed protocol changes packet order and exact drop locations.",
            "first_tcp_after_ready has one first business TCP request per port; startup/handshake time is separately reported as process_start_to_ready_ms.",
            "Successful-sample percentiles exclude failures; inspect failure counts and raw samples together.",
            "HTTP tests are plaintext inside the tunnel and do not measure end-application TLS handshakes.",
            "Quick mode's 2s idle does not verify survival beyond historical 20s idle timeouts."],
        "execution_notes": args.note, "scenarios": [], "samples": []}
    bench = Bench(args, result)
    result["environment"]["benchmark_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result["environment"]["monotonic_time_origin_s"] = bench.start
    try:
        result["environment"]["binary_version"] = invoke(args.binary, ["--version"], bench.deadline).strip()
        with tempfile.TemporaryDirectory(prefix="agg-http-latency-") as temporary:
            try:
                bench.setup(Path(temporary))
                bench.run()
            finally:
                bench.close()
        result["cleanup"]["temporary_credentials_removed"] = True
    except BaseException as exc:
        result["fatal_error"] = type(exc).__name__ + ": " + str(exc)
        # Setup can fail before the managed temporary-directory body is entered.
        if "cleanup" not in result:
            bench.close()
    groups = {}
    for row in result["samples"]:
        groups.setdefault(row["case"], []).append(row)
    result["summary"] = {name: statistics(rows) for name, rows in groups.items()}
    result["summary_by_http_service"] = {
        service: {name: statistics([r for r in rows if r["service"] == service])
                  for name, rows in groups.items() if any(r["service"] == service for r in rows)}
        for service in ("http-a", "http-b")}
    result["summary_reused_http_tcp"] = {
        name: statistics([r for r in rows if r.get("first_on_tcp") is False])
        for name, rows in groups.items() if any(r.get("first_on_tcp") is False for r in rows)}
    result["background_overlap"] = statistics([
        row for row in result["samples"]
        if row.get("overlapped_verified_background_download")])
    bulk = [r for r in result["samples"] if r["case"] == "bulk_integrity" and r["ok"]]
    result["throughput"] = {
        "bulk_success_count": len(bulk), "goodput_mbps": [r["goodput_mbps"] for r in bulk],
        "minimum_observed_mbps": min((r["goodput_mbps"] for r in bulk), default=None),
        "ten_mbps_met_on_all_bulk_samples": bool(bulk) and all(r["goodput_mbps"] >= 10 for r in bulk),
        "requested_acceptance_floor_mbps": args.minimum_goodput_mbps}
    failures = sum(not row["ok"] for row in result["samples"])
    result["failure_count"] = failures
    proxy_errors = any(p["counters"].get("thread_errors") for p in result.get("proxies_before_cleanup", []))
    throughput_ok = not args.minimum_goodput_mbps or (
        bool(bulk) and all(r["goodput_mbps"] >= args.minimum_goodput_mbps for r in bulk))
    cleanup = result.get("cleanup", {})
    result["ok"] = (not result.get("fatal_error") and bool(result["samples"]) and not failures
                    and not proxy_errors and throughput_ok and not cleanup.get("errors")
                    and cleanup.get("owned_processes_stopped", False)
                    and cleanup.get("owned_background_threads_stopped", False)
                    and cleanup.get("owned_udp_proxy_threads_stopped", False))
    result["elapsed_s"] = time.monotonic() - bench.start
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
        emit("http_latency_saved", output=str(args.output.resolve()), ok=result["ok"],
             failure_count=failures, elapsed_s=result["elapsed_s"])
    else:
        print(text, flush=True)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
