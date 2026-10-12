"""Finite real-binary diagnostic inside a dedicated Linux test container."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time
import uuid

from bench.readiness import ProcessSample, ReadinessRequirement, wait_for_ready


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def optional_raw_text(path):
    """Optional resource evidence must never become a benchmark validity gate."""
    try:
        return {"raw": path.read_text(), "error": None}
    except (OSError, UnicodeError) as error:
        return {"raw": None, "error": f"{type(error).__name__}: {error}"}


def parse_snmp(text):
    sections = {}
    lines = text.splitlines()
    for header, values in zip(lines[::2], lines[1::2]):
        keys, counts = header.split(), values.split()
        if not keys or not counts or keys[0] != counts[0] or len(keys) != len(counts):
            raise ValueError("invalid namespace SNMP counter snapshot")
        sections[keys[0].rstrip(":")] = dict(zip(keys[1:], map(int, counts[1:])))
    return sections


def latest_complete_snapshot(path, maximum_bytes=1024 * 1024):
    """Periodic JSONL is live; --stats-file is written only on shutdown."""
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            offset = max(0, size - maximum_bytes)
            stream.seek(offset)
            data = stream.read(maximum_bytes)
    except FileNotFoundError:
        return None
    lines = data.split(b"\n")[:-1]  # Never parse a line still being appended.
    if offset:
        lines = lines[1:]  # The initial chunk may begin in the middle of a record.
    for line in reversed(lines):
        if line:
            return json.loads(line)
    return None


def summarize(samples, source, count):
    """Use every planned slot and actual source span, never received-only tails."""
    if source.get("sent") != count or source.get("requested_count") != count:
        raise ValueError("source did not send the full registered population")
    if len(samples) != count or {s["seq"] for s in samples} != set(range(count)):
        raise ValueError("sample population missing or duplicated")
    span = source["send_span_seconds"]
    if not math.isfinite(span) or span <= 0:
        raise ValueError("invalid actual source span")
    delays = []
    for sample in samples:
        received = sample.get("receive_unix_us")
        sent = sample.get("send_unix_us")
        if received is None:
            delays.append(math.inf)
        elif sent is None or received < sent:
            raise ValueError("invalid same-kernel one-way timestamp")
        else:
            delays.append((received - sent) / 1000)
    ordered = sorted(delays)
    timely = sum(d <= 200 for d in delays)
    goodput = timely * 964 * 8 / span / 1e6
    def quantile(p):
        value = ordered[math.ceil(count * p) - 1]
        return value if math.isfinite(value) else "infinity"
    return {
        "planned": count, "received": sum(math.isfinite(d) for d in delays),
        "within_200ms": timely, "on_time_ratio": timely / count,
        "p95_ms": quantile(.95), "p99_ms": quantile(.99),
        "actual_source_span_seconds": span, "deadline_goodput_mbps": goodput,
        "joint_gate_passed": timely / count >= .95 and goodput >= 300,
        "scope": "single controlled diagnostic; not statistical performance acceptance",
    }


def path_commands(client, server, index, rtt_ms, rate_mbps, queue_packets):
    """Both egress directions get half the registered RTT and a finite queue."""
    left, right = f"p{index}c", f"p{index}s"
    subnet = f"10.203.{index + 1}"
    commands = [
        ["ip", "link", "add", left, "type", "veth", "peer", "name", right],
        ["ip", "link", "set", left, "netns", client],
        ["ip", "link", "set", right, "netns", server],
    ]
    for namespace, device, suffix in [(client, left, 1), (server, right, 2)]:
        commands += [
            ["ip", "-n", namespace, "addr", "add", f"{subnet}.{suffix}/24", "dev", device],
            ["ip", "-n", namespace, "link", "set", device, "up"],
            ["ip", "netns", "exec", namespace, "tc", "qdisc", "add", "dev", device,
             "root", "netem", "limit", str(queue_packets), "delay", f"{rtt_ms / 2:g}ms",
             "rate", f"{rate_mbps:g}mbit"],
        ]
    return commands


def client_path_arguments(args):
    shared = getattr(args, "topology", "independent") == "shared"
    arguments = []
    for index in range(4):
        arguments += ["--entrance", f"10.203.{index + 1}.2:9443",
                      "--path-bind", f"10.203.{index + 1}.1:{9500 + index}",
                      "--path-group", str(0 if shared else index)]
    if shared:
        group_bps = min(int(args.shared_rate_mbps * 1000000), 400000000)
        arguments += ["--group-rate-bps", f"0:{group_bps}"]
    return arguments


def shaping_errors(qdiscs, client, server, rtts, rate_mbps, queue_packets):
    errors = []
    for namespace, suffix in ((client, "c"), (server, "s")):
        shaped = [q for q in qdiscs.get(namespace, []) if q.get("kind") == "netem"]
        if len(shaped) != 4:
            errors.append(f"{namespace}: expected four netem queues")
        by_device = {q.get("dev"): q for q in shaped}
        for index, expected_rtt in enumerate(rtts):
            device = f"p{index}{suffix}"
            qdisc = by_device.get(device, {})
            options = qdisc.get("options", {})
            delay = options.get("delay", {}).get("delay")
            rate = options.get("rate", {}).get("rate")
            if delay is None or abs(delay - expected_rtt / 2000) > .000002:
                errors.append(f"{device}: half-RTT delay mismatch")
            if rate != rate_mbps * 1000000 / 8:
                errors.append(f"{device}: shaped byte rate mismatch")
            if options.get("limit") != queue_packets:
                errors.append(f"{device}: queue bound mismatch")
            if qdisc.get("drops", 0):
                errors.append(f"{device}: preflight drops")
    return errors


def timeseries(raw_path, csv_path):
    previous = {}
    complete_lines, incomplete_tail_bytes = 0, 0
    with raw_path.open() as source, csv_path.open("w") as target:
        fields = ["sample_unix_ms", "path_id", "cwnd_bytes", "rtt_ms", "pacing_rate_bps",
                  "datagram_send_buffer_space_bytes", "udp_tx_mbps", "udp_io_operations_tx_delta",
                  "full_attempts_delta", "sender_input_full_delta", "original_full_delta",
                  "original_expired_delta"]
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        for line in source:
            if not line.endswith("\n"):
                incomplete_tail_bytes = len(line.encode())
                continue
            snapshot = json.loads(line)
            complete_lines += 1
            now = snapshot["sample_unix_ms"]
            direction = snapshot["stats"]["directions"].get("client_to_server", {})
            records, symbols = direction.get("records", {}), direction.get("symbols", {})
            aggregate = [records.get("sender_queue_full_dropped", 0),
                         symbols.get("originals_queue_full_dropped", 0),
                         symbols.get("originals_expired_dropped", 0)]
            for path in snapshot["stats"]["paths"].values():
                identity = (path["path_id"], path.get("connection_id"))
                q = path["quinn"]
                current = [q["udp_bytes_tx"], q.get("udp_io_operations_tx", 0),
                           path["send_buffer_full_attempts"], *aggregate]
                prev = previous.get(identity)
                delta = [None] * 6
                rate = None
                if prev and now > prev[0]:
                    delta = [c - p for c, p in zip(current, prev[1])]
                    if min(delta) < 0:
                        raise ValueError("cumulative counters regressed within one connection")
                    rate = delta[0] * 8 / (now - prev[0]) / 1000
                writer.writerow(dict(zip(fields, [now, path["path_id"],
                    q["congestion_window_bytes"], q["smoothed_rtt_ms"], q.get("pacing_rate_bps"),
                    q.get("datagram_send_buffer_space_bytes"), rate, *delta[1:]])))
                previous[identity] = (now, current)
    return {"complete": incomplete_tail_bytes == 0, "complete_snapshots": complete_lines,
            "incomplete_tail_bytes": incomplete_tail_bytes,
            "scope": "complete-line diagnostic; incomplete raw evidence invalidates the attempt"}


class Testbed:
    def __init__(self, output):
        self.output = output
        self.client, self.server = (f"bp-{uuid.uuid4().hex[:8]}-{side}" for side in ("c", "s"))
        self.owned_namespaces = []
        self.owned_links = []
        self.jobs = []
        self.commands = []
        self.stop = threading.Event()
        self.sampler = None
        self.sample_errors = []
        self.business_started = False
        self.orderly_shutdown = False
        self.cleanup_confirmed = False

    def command(self, argv, *, timeout=10, check=True):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        self.commands.append({"argv": argv, "exit_code": result.returncode,
                              "stdout": result.stdout, "stderr": result.stderr})
        if check and result.returncode:
            raise RuntimeError(f"command failed: {argv}: {result.stderr}")
        return result

    def setup(self, args):
        if getattr(args, "topology", "independent") == "shared":
            from bench.netem_shared import setup_shared
            self.shared_plan = setup_shared(self, args)
            return
        for namespace in (self.client, self.server):
            self.command(["ip", "netns", "add", namespace])
            self.owned_namespaces.append(namespace)
            self.command(["ip", "-n", namespace, "link", "set", "lo", "up"])
        for index, rtt in enumerate(args.rtt_ms):
            commands = path_commands(self.client, self.server, index, rtt, args.rate_mbps, args.queue_packets)
            self.command(commands[0])
            self.owned_links += [f"p{index}c", f"p{index}s"]
            for command in commands[1:]:
                self.command(command)
        save(self.output / "topology.json", {
            "client_namespace": self.client, "server_namespace": self.server,
            "topology": "four independent bidirectional links",
            "rtt_ms": args.rtt_ms, "per_direction_delay_ms": [x / 2 for x in args.rtt_ms],
            "per_path_mbps": args.rate_mbps, "queue_packets_per_direction": args.queue_packets,
            "random_loss_percent": 0,
        })

    def qdiscs(self):
        result = {}
        for namespace in self.owned_namespaces:
            value = self.command(["ip", "netns", "exec", namespace, "tc", "-j", "-s", "qdisc", "show"])
            result[namespace] = json.loads(value.stdout)
        return result

    def network_snapshot(self, filename):
        value = {"sample_unix_ms": int(time.time() * 1000), "namespaces": {}}
        value.update(self.resource_snapshot())
        for namespace in self.owned_namespaces:
            prefix = ["ip", "netns", "exec", namespace]
            snmp = self.command([*prefix, "cat", "/proc/net/snmp"]).stdout
            value["namespaces"][namespace] = {
                "proc_net_snmp": snmp, "snmp_counters": parse_snmp(snmp),
                "link_stats": json.loads(self.command([*prefix, "ip", "-j", "-s", "link"]).stdout),
                "udp_sockets_with_memory": self.command([*prefix, "ss", "-u", "-a", "-m", "-n"]).stdout,
            }
        save(self.output / filename, value)

    def resource_snapshot(self):
        cpu = {name: optional_raw_text(Path("/sys/fs/cgroup") / name)
               for name in ("cpu.max", "cpu.stat")}
        source = {"scope": "owned_source_main_thread", "pid": None, "tid": None,
                  "raw": None, "error": "owned source process is not running"}
        for role, process in self.jobs:
            if role == "source" and process.poll() is None:
                source.update({"pid": process.pid, "tid": process.pid,
                    **optional_raw_text(Path(f"/proc/{process.pid}/task/{process.pid}/schedstat"))})
                # Do not attribute a re-used PID after the owned process exits.
                if process.poll() is not None:
                    source.update({"raw": None, "error": "owned source exited during sample"})
                break
        return {
            "container_cpu": {"scope": "container_cgroup",
                              **{name: result["raw"] for name, result in cpu.items()},
                              "read_errors": {name: result["error"] for name, result in cpu.items()
                                              if result["error"]}},
            "guest_pressure": {"scope": "linux_vm_guest_global",
                               **{name: optional_raw_text(Path("/proc/pressure") / name)
                                  for name in ("cpu", "memory", "io")}},
            "container_memory": {"scope": "container_cgroup",
                                 **{name: optional_raw_text(Path("/sys/fs/cgroup") / name)
                                    for name in ("memory.current", "memory.max", "memory.events")}},
            "source_main_thread_schedstat": source,
        }

    def validate(self, args):
        observed = []
        qdiscs = self.qdiscs()
        failure = None
        save(self.output / "validation.json", {"passed": False, "failure": "validation incomplete",
             "ping": observed, "qdiscs_before": qdiscs})
        for index, expected in enumerate(args.rtt_ms):
            # Resolve the neighbor before measuring link delay: the first echo
            # otherwise pays an extra shaped ARP exchange. QUIC startup resolves
            # this neighbor too; this does not warm the BBR connection.
            warmup = self.command(["ip", "netns", "exec", self.client, "ping", "-n", "-c", "1",
                                   "-W", "2", "-I", f"10.203.{index + 1}.1", f"10.203.{index + 1}.2"])
            result = self.command(["ip", "netns", "exec", self.client, "ping", "-n", "-c", "5", "-i", ".1",
                                   "-W", "2", "-I", f"10.203.{index + 1}.1", f"10.203.{index + 1}.2"])
            match = re.search(r"(?:rtt|round-trip)[^=]*= ([\d.]+)/([\d.]+)/([\d.]+)/", result.stdout)
            if not match:
                raise RuntimeError("ping RTT summary missing")
            minimum, average, maximum = map(float, match.groups())
            observed.append({"path_id": index, "expected_rtt_ms": expected,
                             "minimum_ms": minimum, "average_ms": average, "maximum_ms": maximum,
                             "neighbor_warmup_stdout": warmup.stdout})
            if not expected - 2 <= average <= expected + 10:
                failure = failure or f"path {index} RTT outside validation range: {average}"
            save(self.output / "validation.json", {"passed": False,
                 "failure": failure or "validation incomplete", "ping": observed, "qdiscs_before": qdiscs})
        qdiscs_after = self.qdiscs()
        if getattr(args, "topology", "independent") == "shared":
            from bench.netem_shared import shared_shaping_errors
            errors = shared_shaping_errors(qdiscs_after, self.shared_plan)
        else:
            errors = shaping_errors(qdiscs_after, self.client, self.server, args.rtt_ms,
                                    args.rate_mbps, args.queue_packets)
        failure = failure or ("; ".join(errors) if errors else None)
        save(self.output / "validation.json", {"passed": failure is None, "failure": failure,
             "ping": observed, "qdiscs_before": qdiscs, "qdiscs_after": qdiscs_after})
        if failure:
            raise RuntimeError(failure)
        if getattr(args, "topology", "independent") == "shared":
            from bench.netem_calibration import calibrate_shared
            calibrate_shared(self, self.shared_plan, args.rate_mbps)
        else:
            from bench.netem_calibration import calibrate_links
            calibrate_links(self, [f"10.203.{index + 1}.2" for index in range(4)], args.rate_mbps)

    def spawn(self, namespace, role, argv):
        with (self.output / f"{role}.log").open("w") as log:
            started = int(time.time() * 1000)
            actual = ["ip", "netns", "exec", namespace, *argv]
            process = subprocess.Popen(actual, stdout=log, stderr=log, start_new_session=True)
        self.jobs.append((role, process))
        self.commands.append({"argv": actual, "pid": process.pid, "started_unix_ms": started})
        return process, started

    def runtime_ready(self, process, started, role, ids=(), session=None):
        def poll(_remaining):
            path = self.output / f"{role}.jsonl"
            try:
                snapshot = latest_complete_snapshot(path)
            except json.JSONDecodeError:
                snapshot = None
            return ProcessSample(snapshot, process.poll() is None, process.pid)
        result = wait_for_ready(poll, ReadinessRequirement(role, process.pid, started,
            tuple(ids), session_id=session), 15)
        save(self.output / f"{role}-readiness.json", result.__dict__)
        if not result.ready:
            raise RuntimeError(f"{role} not ready: {result.reason} {result.detail}")
        return result.session_id

    def start_sampling(self):
        def sample():
            with (self.output / "qdisc-series.jsonl").open("w") as target:
                while not self.stop.is_set():
                    try:
                        target.write(json.dumps({"sample_unix_ms": int(time.time() * 1000),
                            "qdiscs": self.qdiscs(), **self.resource_snapshot()}) + "\n")
                        target.flush()
                    except Exception as error:
                        self.sample_errors.append(repr(error))
                        return
                    self.stop.wait(.25)
        self.sampler = threading.Thread(target=sample)
        self.sampler.start()

    def run(self, args):
        binary = str(args.binary)
        identity = self.output / "identity"
        self.command([binary, "init", "--dir", str(identity)])
        cert, key, token = (str(identity / name) for name in ("cert.pem", "key.pem", "token"))
        def stats(role):
            return ["--stats-file", str(self.output / f"{role}.json"), "--stats-jsonl",
                    str(self.output / f"{role}.jsonl"), "--stats-interval-ms", "250"]
        server, started = self.spawn(self.server, "server", [binary, "server", "--listen", "0.0.0.0:9443",
            "--target", "127.0.0.1:9200", "--cert", cert, "--key", key, "--token-file", token,
            "--max-rate-bps", "400000000", *stats("server")])
        self.runtime_ready(server, started, "server")
        client_args = [binary, "client", "--listen", "127.0.0.1:9100", "--server-name", "localhost",
            "--ca", cert, "--token-file", token, "--fec", "0", "--redundancy-percent", "0",
            "--rate-bps", "400000000", "--queue-ms", "100", "--latency-target-ms", "100",
            "--receiver-feedback", *stats("client")]
        client_args += client_path_arguments(args)
        if args.mode == "adaptive":
            client_args += ["--adaptive", "--capacity-probe-bps", "20000000", "--probe-guided-recovery"]
        if args.datagram_buffer_bytes is not None:
            client_args += ["--datagram-send-buffer-bytes", str(args.datagram_buffer_bytes)]
        client, client_started = self.spawn(self.client, "client", client_args)
        session = self.runtime_ready(client, client_started, "client", range(4))
        self.runtime_ready(server, started, "server", range(4), session)
        count = args.duration_seconds * args.pps
        run_id = uuid.uuid4().hex
        common = ["--run-id", run_id, "--count", str(count), "--pps", str(args.pps),
                  "--size", "1000", "--deadline-ms", "200", "--drain-ms", "3000", "--startup-timeout-ms", "15000"]
        sink, sink_started = self.spawn(self.server, "sink", [binary, "sink", "--listen", "127.0.0.1:9200",
            "--ready-file", str(self.output / "sink-ready.json"), *common,
            "--result-file", str(self.output / "sink-result.json"),
            "--samples-file", str(self.output / "sink-samples.json")])
        deadline = time.monotonic() + 5
        while True:
            try:
                ready = json.loads((self.output / "sink-ready.json").read_text())
                if (ready.get("pid") == sink.pid and ready.get("sample_unix_ms", 0) >= sink_started
                    and ready.get("run_id") == run_id and ready.get("ready") is True and sink.poll() is None):
                    break
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            if sink.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("sink JSON readiness failed")
            time.sleep(.05)
        self.network_snapshot("network-before-business.json")
        self.business_started = True
        self.start_sampling()
        source, _ = self.spawn(self.client, "source", [binary, "probe", "--mode", "send", "--target", "127.0.0.1:9100",
            *common, "--result-file", str(self.output / "source-result.json")])
        source.wait(timeout=args.duration_seconds + 20)
        sink.wait(timeout=10)
        if source.returncode or sink.returncode:
            raise RuntimeError("source/sink failed")
        self.network_snapshot("network-after-business.json")
        source_result = json.loads((self.output / "source-result.json").read_text())
        sink_result = json.loads((self.output / "sink-result.json").read_text())
        if source_result.get("corrupt", 0) or sink_result.get("corrupt", 0):
            raise RuntimeError("probe integrity failure")
        samples = json.loads((self.output / "sink-samples.json").read_text())["samples"]
        save(self.output / "summary.json", summarize(samples, source_result, count))

    def cleanup(self):
        errors, exits = [], {}
        self.orderly_shutdown = True
        self.stop.set()
        if self.sampler:
            self.sampler.join(timeout=25)
            if self.sampler.is_alive():
                errors.append("qdisc sampler did not stop")
        for role, process in reversed(self.jobs):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
        for role, process in reversed(self.jobs):
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.orderly_shutdown = False
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    errors.append(f"process still alive after forced stop: {role}")
                errors.append(f"forced stop: {role}")
            exits[role] = process.returncode
            if process.returncode:
                self.orderly_shutdown = False
                errors.append(f"nonzero exit: {role}: {process.returncode}")
        if self.business_started:
            try:
                self.network_snapshot("network-after-runtime-stop.json")
            except Exception as error:
                errors.append(f"final namespace counter snapshot failed: {error}")
        for namespace in reversed(self.owned_namespaces):
            try:
                result = self.command(["ip", "netns", "delete", namespace], check=False)
                if result.returncode:
                    errors.append(f"namespace cleanup failed: {namespace}")
            except Exception as error:
                errors.append(f"namespace cleanup failed: {namespace}: {error}")
        # Only orphaned root endpoints created by this attempt, never global qdiscs.
        for interface in self.owned_links:
            try:
                if self.command(["ip", "link", "show", "dev", interface], check=False).returncode == 0:
                    if self.command(["ip", "link", "delete", interface], check=False).returncode:
                        errors.append(f"interface cleanup failed: {interface}")
            except Exception as error:
                errors.append(f"interface cleanup failed: {interface}: {error}")
        try:
            namespace_names = {line.split()[0] for line in self.command(["ip", "netns", "list"]).stdout.splitlines() if line.strip()}
            interface_names = {link["ifname"] for link in json.loads(self.command(["ip", "-j", "link", "show"]).stdout)}
            remaining_namespaces = set(self.owned_namespaces) & namespace_names
            remaining_interfaces = set(self.owned_links) & interface_names
            live_processes = [role for role, process in self.jobs if process.poll() is None]
            for name in sorted(remaining_namespaces | remaining_interfaces):
                errors.append(f"owned resource still present: {name}")
            if live_processes:
                errors.append(f"owned processes still alive: {live_processes}")
            self.cleanup_confirmed = (not remaining_namespaces and not remaining_interfaces
                and not live_processes and not (self.sampler and self.sampler.is_alive()))
        except Exception as error:
            errors.append(f"cleanup verification failed: {error}")
        return errors, exits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["validate", "run"])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--duration-seconds", type=int, default=20)
    parser.add_argument("--pps", type=int, default=40000)
    parser.add_argument("--rtt-ms", type=float, nargs=4, default=[30, 45, 60, 80])
    parser.add_argument("--rate-mbps", type=float, default=100)
    parser.add_argument("--queue-packets", type=int, default=1024)
    parser.add_argument("--mode", choices=["fixed", "adaptive"], default="fixed")
    parser.add_argument("--topology", choices=["independent", "shared"], default="independent")
    parser.add_argument("--shared-rate-mbps", type=float, default=400)
    parser.add_argument("--datagram-buffer-bytes", type=int)
    args = parser.parse_args()
    if (not Path("/.dockerenv").exists() or os.environ.get("BRAIDPATH_NETEM_CONTAINER") != "1"
        or os.geteuid() != 0):
        parser.error("requires root inside a dedicated Docker test container with BRAIDPATH_NETEM_CONTAINER=1")
    args.output = args.output.resolve()
    if "local" not in args.output.parts:
        parser.error("all generated configuration and evidence must be under local/")
    if (not 1 <= args.duration_seconds <= 30 or not 1 <= args.pps <= 40000
        or args.duration_seconds * args.pps > 1000000):
        parser.error("finite workload must be <=30 s, <=40000 pps, <=1000000 records")
    if (any(not math.isfinite(x) or not 1 <= x <= 200 for x in args.rtt_ms)
        or not math.isfinite(args.rate_mbps) or not 1 <= args.rate_mbps <= 1000
        or not 32 <= args.queue_packets <= 4096):
        parser.error("invalid finite shaping settings")
    if not math.isfinite(args.shared_rate_mbps) or not 1 <= args.shared_rate_mbps <= 400:
        parser.error("shared physical rate must be 1..400 Mbps")
    if args.datagram_buffer_bytes is not None and not 1200 <= args.datagram_buffer_bytes <= 76800:
        parser.error("datagram buffer must be 1200..76800 bytes")
    if args.action == "run":
        if args.binary is None or not args.binary.is_file():
            parser.error("run needs an existing Linux binary")
        args.binary = args.binary.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    registration = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    registration.update({"registered_unix_ms": int(time.time() * 1000), "payload_bytes": 964,
                         "deadline_ms": 200, "outer_budget_bps": 400000000, "full_population": True})
    registration["harness_sha256"] = {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
        for name in ("netem.py", "readiness.py", "netem_calibration.py", "netem_shared.py")}
    if args.binary:
        registration["binary_sha256"] = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    save(args.output / "registration.json", registration)
    bed = Testbed(args.output)
    failure = None
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("testbed interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        bed.setup(args)
        bed.validate(args)
        if args.action == "run":
            bed.run(args)
    except BaseException as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup_errors, exits = bed.cleanup()
        if args.action == "run" and (args.output / "client.jsonl").exists():
            try:
                status = timeseries(args.output / "client.jsonl", args.output / "path-series.csv")
                save(args.output / "path-series-status.json", status)
                if not status["complete"]:
                    raise ValueError("partial final JSONL line; complete-line CSV is diagnostic only")
                for role in ("client", "server"):
                    snapshot = json.loads((args.output / f"{role}.json").read_text())
                    if (snapshot.get("final") is not True or snapshot.get("outcome") != "stopped"
                        or snapshot.get("stats", {}).get("shutdown_complete") is not True):
                        raise ValueError(f"{role} final shutdown not confirmed")
            except Exception as error:
                bed.orderly_shutdown = False
                failure = failure or f"time series invalid: {error}"
        valid = (not failure and not cleanup_errors and not bed.sample_errors
                 and bed.cleanup_confirmed and bed.orderly_shutdown)
        if (args.output / "summary.json").exists():
            summary = json.loads((args.output / "summary.json").read_text())
            summary["attempt_valid"] = valid
            save(args.output / "summary.json", summary)
        save(args.output / "commands.json", bed.commands)
        save(args.output / "completion.json", {"failure": failure, "cleanup_errors": cleanup_errors,
            "exit_codes": exits, "sample_errors": bed.sample_errors,
            "orderly_shutdown": bed.orderly_shutdown,
            "cleanup_confirmed": bed.cleanup_confirmed, "valid": valid})
    if failure or cleanup_errors or bed.sample_errors:
        raise SystemExit(f"diagnostic invalid: {failure}; cleanup={cleanup_errors}; samples={bed.sample_errors}")


if __name__ == "__main__":
    main()
