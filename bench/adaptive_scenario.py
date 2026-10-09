#!/usr/bin/env python3
"""Bounded, local, packet-shaped real-runtime experiments; no remote hosts or sudo."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import random
import signal
import socket
import struct
import time
from typing import Callable

MAGIC = b"BPADAPT1"
HEADER = struct.Struct("!8sBQQ")
IP_UDP_BYTES = 28
LATE_ACCOUNTING_BATCH = 256
ROOT = Path(__file__).resolve().parents[1]


def utc():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def quantile(values, fraction):
    if not values:
        return None
    value = sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]
    return "infinity" if math.isinf(value) else value


async def udp_send(sock, data, peer):
    """Python 3.9-compatible nonblocking UDP send with actual kernel acceptance."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            sent = sock.sendto(data, peer)
            if sent != len(data):
                raise OSError("partial UDP send")
            return sent
        except BlockingIOError:
            future = loop.create_future()
            descriptor = sock.fileno()
            loop.add_writer(descriptor, lambda: None if future.done() else future.set_result(None))
            try:
                await future
            finally:
                loop.remove_writer(descriptor)


async def udp_receive(sock, size):
    """Python 3.9-compatible receive; cancellation removes its selector reader."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            return sock.recvfrom(size)
        except BlockingIOError:
            future = loop.create_future()
            descriptor = sock.fileno()
            loop.add_reader(descriptor, lambda: None if future.done() else future.set_result(None))
            try:
                await future
            finally:
                loop.remove_reader(descriptor)


@dataclass(frozen=True)
class Shape:
    rate_bps: int
    delay_ms: float = 8.0
    queue_bytes: int = 65536
    queue_ms: float = 250.0
    loss: float = 0.0

    def validate(self):
        if not (1 <= self.rate_bps <= 100_000_000 and 0 <= self.delay_ms <= 1000
                and 1500 <= self.queue_bytes <= 1_000_000 and 1 <= self.queue_ms <= 2000
                and 0 <= self.loss <= 1):
            raise ValueError("invalid bounded link configuration")


class SerializedLink:
    """FIFO serialized IP/UDP bytes. Rate changes affect already queued packets."""
    def __init__(self, name, shape, seed):
        shape.validate()
        self.name, self.shape = name, shape
        self.random = random.Random(seed)
        self.pending = deque()
        self.queued_bytes = 0
        self.counters = Counter()
        self.ready = asyncio.Event()
        self.changed = asyncio.Event()
        self.closed = False
        self.propagating = set()
        self.task = asyncio.create_task(self._run())

    def configure(self, shape):
        shape.validate()
        self.shape = shape
        self.changed.set()

    def submit(self, data: bytes, deliver: Callable[[bytes], None]):
        size = len(data) + IP_UDP_BYTES
        self.counters["received_packets"] += 1
        self.counters["received_ip_udp_bytes"] += size
        if self.closed:
            self.counters["closed_drops"] += 1
            return False
        if self.queued_bytes + size > self.shape.queue_bytes:
            self.counters["queue_full_drops"] += 1
            return False
        self.pending.append((bytes(data), deliver, time.monotonic()))
        self.queued_bytes += size
        self.counters["admitted_packets"] += 1
        self.counters["admitted_ip_udp_bytes"] += size
        self.counters["peak_queued_bytes"] = max(self.counters["peak_queued_bytes"], self.queued_bytes)
        self.ready.set()
        return True

    async def _run(self):
        current = None
        try:
            while not self.closed:
                if not self.pending:
                    self.ready.clear()
                    await self.ready.wait()
                    continue
                current = self.pending.popleft()
                data, deliver, entered = current
                size = len(data) + IP_UDP_BYTES
                if (time.monotonic() - entered) * 1000 > self.shape.queue_ms:
                    self.counters["queue_age_drops"] += 1
                else:
                    remaining = size * 8.0
                    while remaining > 0:
                        rate = self.shape.rate_bps
                        started = time.monotonic()
                        self.changed.clear()
                        try:
                            await asyncio.wait_for(self.changed.wait(), remaining / rate)
                            remaining = max(0.0, remaining - (time.monotonic() - started) * rate)
                        except asyncio.TimeoutError:
                            remaining = 0
                    age = (time.monotonic() - entered) * 1000
                    self.counters["max_serialized_queue_ms"] = max(
                        self.counters["max_serialized_queue_ms"], age)
                    if age > self.shape.queue_ms:
                        self.counters["queue_age_drops"] += 1
                    elif self.random.random() < self.shape.loss:
                        self.counters["configured_loss_drops"] += 1
                    else:
                        # Delay is propagation after serialization. Bounded delayed tasks
                        # keep their byte reservation until send/cancel completes.
                        reservation = current
                        task = asyncio.create_task(self._propagate(reservation, self.shape.delay_ms))
                        self.propagating.add(task)
                        task.add_done_callback(self.propagating.discard)
                        current = None
                if current is not None:
                    self.queued_bytes -= size
                    current = None
        finally:
            if current is not None:
                self.queued_bytes -= len(current[0]) + IP_UDP_BYTES
                self.counters["shutdown_drops"] += 1

    async def _propagate(self, entry, delay_ms):
        data, deliver, _ = entry
        try:
            if delay_ms:
                await asyncio.sleep(delay_ms / 1000)
            deliver(data)
            self.counters["forwarded_packets"] += 1
            self.counters["forwarded_ip_udp_bytes"] += len(data) + IP_UDP_BYTES
        except asyncio.CancelledError:
            self.counters["shutdown_drops"] += 1
            raise
        except Exception:
            self.counters["send_errors"] += 1
        finally:
            self.queued_bytes -= len(data) + IP_UDP_BYTES

    async def close(self):
        self.closed = True
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)
        self.counters["shutdown_drops"] += len(self.pending)
        self.queued_bytes -= sum(len(x[0]) + IP_UDP_BYTES for x in self.pending)
        self.pending.clear()
        delayed = list(self.propagating)
        for task in delayed:
            task.cancel()
        await asyncio.gather(*delayed, return_exceptions=True)

    def snapshot(self):
        return {"name": self.name, "configuration": asdict(self.shape),
                "queued_bytes": self.queued_bytes, "counters": dict(self.counters)}

    @classmethod
    def create(cls, name, shape, seed):
        return cls(name, shape, seed)


class ReturnEndpoint(asyncio.DatagramProtocol):
    def __init__(self, proxy, peer):
        self.proxy, self.peer = proxy, peer

    def datagram_received(self, data, addr):
        self.proxy.receive_return(data, self.peer)

    def error_received(self, error):
        self.proxy.counters["socket_errors"] += 1


class Entrance(asyncio.DatagramProtocol):
    """One loopback entrance with bounded per-client upstream socket mappings."""
    def __init__(self, name, target, uplink, downlink):
        self.name, self.target = name, target
        self.uplink, self.downlink = uplink, downlink
        self.enabled = True
        self.transport = None
        self.mappings = {}
        self.pending = {}
        self.creating = set()
        self.counters = Counter()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        self.counters["forward_received_packets"] += 1
        if not self.enabled:
            self.counters["outage_forward_drops"] += 1
            return
        if peer in self.mappings:
            self.uplink.submit(data, lambda value: self._forward(value, peer))
            return
        if peer not in self.pending:
            if len(self.mappings) + len(self.pending) >= 16:
                self.counters["mapping_limit_drops"] += 1
                return
            self.pending[peer] = []
            task = asyncio.create_task(self._mapping(peer))
            self.creating.add(task)
            task.add_done_callback(self.creating.discard)
        if sum(len(item) for item in self.pending[peer]) + len(data) > 32768:
            self.counters["mapping_pending_drops"] += 1
            return
        self.pending[peer].append(bytes(data))

    async def _mapping(self, peer):
        try:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: ReturnEndpoint(self, peer), remote_addr=self.target,
                local_addr=("127.0.0.1", 0))
            self.mappings[peer] = transport
            self.counters["mappings_created"] += 1
            for data in self.pending.pop(peer):
                self.uplink.submit(data, lambda value, p=peer: self._forward(value, p))
        except Exception:
            self.counters["mapping_create_errors"] += 1
            self.pending.pop(peer, None)

    def _forward(self, data, peer):
        if self.enabled:
            self.mappings[peer].sendto(data)
        else:
            self.counters["outage_queued_forward_drops"] += 1

    def receive_return(self, data, peer):
        self.counters["return_received_packets"] += 1
        if self.enabled:
            self.downlink.submit(data, lambda value: self._return(value, peer))
        else:
            self.counters["outage_return_drops"] += 1

    def _return(self, data, peer):
        if self.enabled:
            self.transport.sendto(data, peer)
        else:
            self.counters["outage_queued_return_drops"] += 1

    async def close(self):
        for task in list(self.creating):
            task.cancel()
        await asyncio.gather(*list(self.creating), return_exceptions=True)
        for transport in self.mappings.values():
            transport.close()
        if self.transport:
            self.transport.close()


def packet(kind, seq, stamp, size):
    return HEADER.pack(MAGIC, kind, seq, stamp) + bytes([(seq + kind) % 251]) * (size - HEADER.size)


class EchoTarget(asyncio.DatagramProtocol):
    def __init__(self, streams):
        self.streams = streams
        self.counters = Counter()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        now = time.monotonic_ns()
        try:
            magic, kind, seq, stamp = HEADER.unpack_from(data)
            stream = self.streams[kind]
            sample = stream.samples[seq]
            if magic != MAGIC or data != packet(kind, seq, stamp, stream.size) or sample["send_ns"] != stamp:
                raise ValueError("integrity")
            if sample["target_ns"] is None:
                sample["target_ns"] = now
            else:
                self.counters["duplicate_records"] += 1
            self.transport.sendto(data, peer)
        except (ValueError, KeyError, IndexError, struct.error):
            self.counters["corrupt_or_unknown"] += 1


class Traffic:
    def __init__(self, kind, pps, size, destination):
        self.kind, self.pps, self.size, self.destination = kind, pps, size, destination
        self.samples = []
        self.counters = Counter()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self.socket.setblocking(False)
        self.socket.bind(("127.0.0.1", 0))

    async def receive(self):
        while True:
            try:
                data, peer = await udp_receive(self.socket, 2048)
            except OSError:
                self.counters["receive_socket_errors"] += 1
                await asyncio.sleep(.01)
                continue
            now = time.monotonic_ns()
            try:
                magic, kind, seq, stamp = HEADER.unpack_from(data)
                sample = self.samples[seq]
                if (peer != self.destination or magic != MAGIC or kind != self.kind
                        or data != packet(kind, seq, stamp, self.size) or sample["send_ns"] != stamp):
                    raise ValueError("integrity")
                if sample["echo_ns"] is None:
                    sample["echo_ns"] = now
                else:
                    self.counters["duplicate_echoes"] += 1
            except (ValueError, IndexError, struct.error):
                self.counters["corrupt_or_unknown"] += 1

    def scheduled_sample(self, seq, phases, status="scheduled"):
        planned = seq / self.pps
        sample = {"kind": self.kind, "seq": seq, "window": window_at(phases, planned),
                  "planned_seconds": planned, "send_ns": None, "target_ns": None,
                  "echo_ns": None, "status": status}
        self.samples.append(sample)
        return sample

    async def send(self, start, phases):
        total = round(sum(p["seconds"] for p in phases) * self.pps)
        seq = 0
        while seq < total:
            planned = seq / self.pps
            await asyncio.sleep(max(0, start + planned - time.monotonic()))
            # Walking one expired slot per ready-queue turn can remain behind
            # indefinitely. Preserve every slot in a finite accounting batch.
            end = min(total, seq + LATE_ACCOUNTING_BATCH)
            while seq < end:
                planned = seq / self.pps
                now = time.monotonic()
                if now - (start + planned) > 0.050:
                    self.scheduled_sample(seq, phases, "generator_late")
                    self.counters["generator_late"] += 1
                    seq += 1
                    continue
                if now < start + planned:
                    break
                # Send at most one still-current slot before yielding again. An
                # extra yield here could make that slot expire merely because
                # older missed slots needed accounting; missed packets never send.
                sample = self.scheduled_sample(seq, phases)
                stamp = time.monotonic_ns()
                sample["send_ns"] = stamp
                try:
                    await udp_send(self.socket, packet(self.kind, seq, stamp, self.size), self.destination)
                    sample["status"] = "kernel_accepted"
                except OSError as error:
                    sample["status"] = "send_error"
                    sample["error"] = type(error).__name__
                    self.counters["send_errors"] += 1
                seq += 1
                break

    def close(self):
        self.socket.close()


def window_at(phases, offset):
    end = 0.0
    for phase in phases:
        end += phase["seconds"]
        if offset < end:
            return phase["name"]
    return phases[-1]["name"]


def phases_for(args):
    phases = [{"name": "warmup", "seconds": 4.0, "condition": "clean"}]
    phases += [{"name": name, "seconds": args.phase_seconds, "condition": condition}
               for name, condition in [("window_a", "clean"), ("window_b", "congested"),
                                       ("window_c", "clean")]]
    if args.outages:
        phases += [{"name": "window_d", "seconds": 8.0, "condition": "one_outage"},
                   {"name": "window_e", "seconds": 8.0, "condition": "clean"},
                   {"name": "window_f", "seconds": 18.0, "condition": "all_outage"},
                   {"name": "window_g", "seconds": 15.0, "condition": "clean"}]
    return phases


def free_address():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()


def address(value):
    return f"{value[0]}:{value[1]}"


class Processes:
    def __init__(self, directory):
        self.directory, self.children, self.files = directory, {}, []
        self.commands = {}

    async def launch(self, name, argv):
        out = (self.directory / f"{name}.stdout.log").open("wb")
        err = (self.directory / f"{name}.stderr.log").open("wb")
        self.files += [out, err]
        self.commands[name] = list(map(str, argv))
        child = await asyncio.create_subprocess_exec(*map(str, argv), stdout=out, stderr=err,
                                                    env={**os.environ, "RUST_LOG": "braidpath=info"})
        self.children[name] = child
        return child

    async def close(self):
        records = {}
        for name, child in reversed(list(self.children.items())):
            already_exited = child.returncode is not None
            if not already_exited:
                child.send_signal(signal.SIGINT)
                try:
                    await asyncio.wait_for(child.wait(), 8)
                except asyncio.TimeoutError:
                    child.kill()
                    await child.wait()
            records[name] = {"pid": child.pid, "returncode": child.returncode,
                             "exited_before_cleanup": already_exited}
        for item in self.files:
            item.close()
        return records


def latest_snapshot(path):
    try:
        lines = path.read_text().splitlines()
        for line in reversed(lines):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    except FileNotFoundError:
        pass
    return None


async def ready(child, path, paths=None):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if child.returncode is not None:
            raise RuntimeError(f"process exited before readiness: {child.returncode}")
        snapshot = latest_snapshot(path)
        if snapshot and snapshot.get("process_id") == child.pid:
            stats = snapshot.get("stats", {})
            active = [p for p in stats.get("paths", {}).values()
                      if p.get("authenticated") and not p.get("quinn", {}).get("closed", True)]
            if stats.get("ready") and (paths is None or len(active) == paths):
                return snapshot
        await asyncio.sleep(0.025)
    raise TimeoutError("authenticated readiness exceeded 15 seconds")


def summarize(streams, phases, deadline_ms, start_ns):
    result = []
    offset = 0.0
    for phase in phases:
        row = {**phase, "start_seconds": offset, "streams": {}}
        for kind, stream in streams.items():
            samples = [s for s in stream.samples if s["window"] == phase["name"]]
            total = sum(p["seconds"] for p in phases)
            planned = sum(window_at(phases, i / stream.pps) == phase["name"]
                          for i in range(round(total * stream.pps)))
            sent = [s for s in samples if s["status"] == "kernel_accepted"]
            values = [(s["echo_ns"] - s["send_ns"]) / 1e6
                      if s["echo_ns"] is not None and s["send_ns"] is not None else math.inf
                      for s in samples]
            values += [math.inf] * (planned - len(samples))
            target = sum(s["target_ns"] is not None for s in samples)
            received = sum(s["echo_ns"] is not None for s in samples)
            on_time = sum(v <= deadline_ms for v in values)
            late_or_missing = planned - on_time
            row["streams"]["bulk" if kind == 1 else "interactive"] = {
                "planned_operations": planned, "kernel_accepted_operations": len(sent),
                "generator_not_issued_operations": planned - len(samples),
                "actual_offered_fraction": len(sent) / max(1, planned),
                "actual_offered_bps": len(sent) * stream.size * 8 / phase["seconds"],
                "target_unique_records": target, "echo_unique_records": received,
                "offered_application_bytes": len(sent) * stream.size,
                "target_unique_application_bytes": target * stream.size,
                "on_time_echo_application_bytes": on_time * stream.size,
                "target_goodput_bps": target * stream.size * 8 / phase["seconds"],
                "on_time_echo_goodput_bps": on_time * stream.size * 8 / phase["seconds"],
                "deadline_miss_fraction": late_or_missing / max(1, planned),
                "missing_echoes": planned - received,
                "rtt_p50_ms": quantile(values, .50), "rtt_p95_ms": quantile(values, .95),
                "rtt_p99_ms": quantile(values, .99),
                "quantile_population": "all planned operations; missing/not-sent = infinity",
            }
        result.append(row)
        offset += phase["seconds"]
    return result


async def experiment(args):
    output = args.output.resolve()
    if output.exists():
        raise ValueError("output already exists; preserve it and choose a new registered run ID")
    if ROOT / "local" not in output.parents:
        raise ValueError("run records must remain inside this repository's ignored local/")
    output.mkdir(parents=True)
    binary = args.binary.resolve()
    phases = phases_for(args)
    manifest = {"schema_version": 1, "registered_utc": utc(), "binary": str(binary),
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "profile": args.profile, "topology": args.topology, "paths": args.paths,
                "rate_bps": args.rate_bps, "queue_ms": args.queue_ms, "fec": args.fec,
                "link_mbps": args.link_mbps, "congested_mbps": args.congested_mbps,
                "queue_bytes": args.queue_bytes, "network_queue_ms": args.network_queue_ms,
                "delay_ms": args.delay_ms, "seed": args.seed, "deadline_ms": args.deadline_ms,
                "bulk_pps": args.bulk_pps, "bulk_bytes": 1000,
                "interactive_pps": args.interactive_pps, "interactive_bytes": 128,
                "client_extra_args": args.client_extra_arg,
                "adaptive_path_groups": (list(range(args.paths)) if args.topology == "independent"
                                         else [0] * args.paths),
                "phases": phases, "drain_seconds": 2,
                "registered_gates": {
                    "scope": "one bounded engineering screen, not a paired statistical acceptance claim",
                    "offered_fraction_minimum": .95, "integrity_errors": 0,
                    "clean_on_time_goodput_ratio_minimum": .90,
                    "clean_interactive_deadline_miss_increase_maximum": .01,
                    "impaired_interactive_deadline_miss_must_improve_when_baseline_nonzero": True,
                    "queue_bytes_maximum": args.queue_bytes,
                    "lifecycle": "candidate must deliver after >=18s all-path outage without replacing client process",
                },
                "boundaries": [
                    "Actual UDP ciphertext packets are shaped, including QUIC ACKs/handshakes.",
                    "Rate accounting boundary is IPv4+UDP bytes; no Ethernet overhead.",
                    "RTT uses this harness process's monotonic clock; no per-run minimum subtraction.",
                    "Payload goodput uses the fixed active source window; drain is only for censoring.",
                    "Kernel acceptance, runtime admissions, target receipt and echo receipt are distinct.",
                    "Independent entrances have distinct serializers; shared entrances use one per direction.",
                    "No firewall, sudo, remote node, port scan, automatic retries or overwritten result.",
                ]}
    save(output / "manifest.json", manifest)
    if args.dry_run:
        save(output / "result.json", {"outcome": "registered_only", "manifest": "manifest.json"})
        return output
    processes = Processes(output)
    links, entrances, streams, receive_tasks = [], [], {}, []
    work_tasks = []
    echo_transport = None
    snapshots = []
    error = None
    start_ns = None
    outcome = "error"
    try:
        init = await processes.launch("init", [binary, "init", "--dir", output / "identity", "--name", "localhost"])
        if await asyncio.wait_for(init.wait(), 10) != 0:
            raise RuntimeError("identity initialization failed")
        client_addr, server_addr = free_address(), free_address()
        streams = {1: Traffic(1, args.bulk_pps, 1000, client_addr),
                   2: Traffic(2, args.interactive_pps, 128, client_addr)}
        loop = asyncio.get_running_loop()
        echo_transport, echo = await loop.create_datagram_endpoint(lambda: EchoTarget(streams),
                                                                   local_addr=("127.0.0.1", 0))
        target_addr = echo_transport.get_extra_info("sockname")
        clean = Shape(round(args.link_mbps * 1e6), args.delay_ms, args.queue_bytes, args.network_queue_ms)
        lane_count = args.paths if args.topology == "independent" else 1
        for lane in range(lane_count):
            links += [SerializedLink.create(f"lane_{lane}_forward", clean, args.seed + lane * 2),
                      SerializedLink.create(f"lane_{lane}_return", clean, args.seed + lane * 2 + 1)]
        for index in range(args.paths):
            lane = index if args.topology == "independent" else 0
            proxy = Entrance(f"entrance_{index}", server_addr, links[lane * 2], links[lane * 2 + 1])
            await loop.create_datagram_endpoint(lambda p=proxy: p, local_addr=("127.0.0.1", 0))
            entrances.append(proxy)
        cert, key, token = [output / "identity" / name for name in ("cert.pem", "key.pem", "token")]
        server = await processes.launch("server", [
            binary, "server", "--listen", address(server_addr), "--cert", cert, "--key", key,
            "--token-file", token, "--target", address(target_addr), "--max-rate-bps", args.rate_bps,
            "--stats-file", output / "server.final.json", "--stats-jsonl", output / "server.stats.jsonl",
            "--stats-interval-ms", "200"])
        await ready(server, output / "server.stats.jsonl")
        client_args = [binary, "client", "--listen", address(client_addr), "--server-name", "localhost",
                       "--ca", cert, "--token-file", token, "--rate-bps", args.rate_bps,
                       "--fec", args.fec, "--queue-ms", args.queue_ms,
                       "--stats-file", output / "client.final.json",
                       "--stats-jsonl", output / "client.stats.jsonl", "--stats-interval-ms", "200"]
        for proxy in entrances:
            client_args += ["--entrance", address(proxy.transport.get_extra_info("sockname"))]
        if args.profile == "adaptive":
            client_args += ["--adaptive", "--latency-target-ms", "20"]
            for group in (range(args.paths) if args.topology == "independent" else [0] * args.paths):
                client_args += ["--path-group", str(group)]
        elif args.profile == "quality":
            client_args += ["--quality-schedule"]
        client_args += args.client_extra_arg
        client = await processes.launch("client", client_args)
        initial = await ready(client, output / "client.stats.jsonl", args.paths)
        save(output / "readiness.json", initial)
        start = time.monotonic() + .2
        start_ns = round(start * 1e9)
        receive_tasks = [asyncio.create_task(s.receive()) for s in streams.values()]

        async def change_phases():
            offset = 0
            for phase in phases:
                await asyncio.sleep(max(0, start + offset - time.monotonic()))
                condition = phase["condition"]
                for proxy_index, proxy in enumerate(entrances):
                    proxy.enabled = not (condition == "all_outage"
                                         or condition == "one_outage" and proxy_index == 0)
                for index, link in enumerate(links):
                    rate = clean.rate_bps
                    if condition == "congested" and (args.topology == "shared" or index < 2):
                        rate = round(args.congested_mbps * 1e6)
                    link.configure(Shape(rate, args.delay_ms, args.queue_bytes, args.network_queue_ms))
                snapshots.append({"window": phase["name"], "elapsed_seconds": time.monotonic() - start,
                                  "utc": utc(), "links": [l.snapshot() for l in links],
                                  "client_alive": client.returncode is None,
                                  "server_alive": server.returncode is None})
                save(output / "phase-events.json", snapshots)
                offset += phase["seconds"]

        async def inspect():
            for _ in range(math.ceil(sum(p["seconds"] for p in phases) + 2)):
                await asyncio.sleep(1)
                with (output / "shaper.jsonl").open("a") as handle:
                    handle.write(json.dumps({"elapsed_seconds": time.monotonic() - start,
                                             "links": [l.snapshot() for l in links],
                                             "client_returncode": client.returncode,
                                             "server_returncode": server.returncode}) + "\n")

        total = sum(p["seconds"] for p in phases)
        work_tasks = [asyncio.create_task(change_phases()), asyncio.create_task(inspect())]
        work_tasks += [asyncio.create_task(s.send(start, phases)) for s in streams.values()]
        await asyncio.wait_for(asyncio.gather(*work_tasks), total + 8)
        await asyncio.sleep(max(0, start + total + 2 - time.monotonic()))
        outcome = "completed" if client.returncode is None and server.returncode is None else "runtime_exited"
        save(output / "target-counters.json", dict(echo.counters))
    except BaseException as caught:
        error = f"{type(caught).__name__}: {caught}"
        if isinstance(caught, (KeyboardInterrupt, asyncio.CancelledError)):
            outcome = "interrupted"
    finally:
        for task in work_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*work_tasks, return_exceptions=True)
        for task in receive_tasks:
            task.cancel()
        await asyncio.gather(*receive_tasks, return_exceptions=True)
        exits = await processes.close()
        for proxy in entrances:
            await proxy.close()
        for link in links:
            await link.close()
        if echo_transport:
            echo_transport.close()
        for stream in streams.values():
            stream.close()
        save(output / "commands.json", processes.commands)
        save(output / "process-exits.json", exits)
        save(output / "shaper-final.json", [l.snapshot() for l in links])
        save(output / "entrances-final.json", [{"name": p.name, "counters": dict(p.counters)}
                                               for p in entrances])
        if streams:
            with (output / "samples.jsonl").open("w") as handle:
                for stream in streams.values():
                    for sample in stream.samples:
                        handle.write(json.dumps(sample) + "\n")
        result = {"schema_version": 1, "finished_utc": utc(), "outcome": outcome,
                  "error": error, "start_monotonic_ns": start_ns,
                  "windows": summarize(streams, phases, args.deadline_ms, start_ns),
                  "stream_counters": {str(k): dict(s.counters) for k, s in streams.items()},
                  "process_exits": exits, "shaper_counters": [l.snapshot() for l in links],
                  "caveat": "Finite local packet-shaping screen; no WAN or statistical superiority claim."}
        save(output / "result.json", result)
    return output


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", choices=("rr", "quality", "adaptive"), default="rr")
    parser.add_argument("--topology", choices=("independent", "shared"), default="independent")
    parser.add_argument("--paths", choices=(1, 2), type=int, default=2)
    parser.add_argument("--bulk-pps", type=int, default=900)
    parser.add_argument("--interactive-pps", type=int, default=20)
    parser.add_argument("--link-mbps", type=float, default=3.0)
    parser.add_argument("--congested-mbps", type=float, default=.35)
    parser.add_argument("--rate-bps", type=int, default=8_000_000)
    parser.add_argument("--queue-ms", type=int, default=40)
    parser.add_argument("--fec", type=int, default=0)
    parser.add_argument("--delay-ms", type=float, default=8)
    parser.add_argument("--queue-bytes", type=int, default=65536)
    parser.add_argument("--network-queue-ms", type=float, default=250)
    parser.add_argument("--phase-seconds", type=float, default=12)
    parser.add_argument("--deadline-ms", type=float, default=100)
    parser.add_argument("--seed", type=int, default=20261009)
    parser.add_argument("--outages", action="store_true")
    parser.add_argument("--client-extra-arg", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if not (1 <= args.bulk_pps <= 3000 and 1 <= args.interactive_pps <= 200
            and 3 <= args.phase_seconds <= 60 and 1 <= args.rate_bps <= 100_000_000
            and 1 <= args.queue_ms <= 1000 and args.fec in (0, 2, 3, 4, 8)
            and 1 <= args.deadline_ms <= 2000):
        parser.error("workload is outside bounded local-test limits")
    Shape(round(args.link_mbps * 1e6), args.delay_ms, args.queue_bytes, args.network_queue_ms).validate()
    Shape(round(args.congested_mbps * 1e6), args.delay_ms, args.queue_bytes, args.network_queue_ms).validate()
    if sum(p["seconds"] for p in phases_for(args)) * (args.bulk_pps + args.interactive_pps) > 100000:
        parser.error("at most 100000 planned application operations per run")
    return args


def main():
    args = parse_args()
    output = asyncio.run(experiment(args))
    result = json.loads((output / "result.json").read_text())
    print(json.dumps({"output": str(output), "outcome": result["outcome"], "error": result.get("error")}))
    return 0 if result["outcome"] in ("completed", "registered_only") else 1


if __name__ == "__main__":
    raise SystemExit(main())

