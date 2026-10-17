"""Finite real-binary diagnostic on loopback with the native Rust link emulator.

Runs on the development host without containers, namespaces or privileges. The
emulator (examples/link_lab.rs) shapes every path in both directions; business
loss and registered rate steps are applied through its stdin after readiness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time
import uuid

from bench.netem import latest_complete_snapshot, summarize, timeseries
from bench.readiness import ProcessSample, ReadinessRequirement, wait_for_ready

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_BYTES = 964


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def free_address():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{sock.getsockname()[1]}"


def parse_step(text):
    """AT_SECONDS:PATH:RATE_MBPS, relative to the source launch."""
    parts = text.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("step must be AT_SECONDS:PATH:RATE_MBPS")
    at, path, rate = float(parts[0]), int(parts[1]), float(parts[2])
    if not (math.isfinite(at) and at >= 0 and math.isfinite(rate) and 1 <= rate <= 1000 and path >= 0):
        raise argparse.ArgumentTypeError("step outside bounded limits")
    return {"at_seconds": at, "path": path, "rate_mbps": rate}


def path_rates(args):
    rates = args.rate_mbps if len(args.rate_mbps) > 1 else args.rate_mbps * len(args.rtt_ms)
    if len(rates) != len(args.rtt_ms):
        raise ValueError("rate list must have one value or one per path")
    return rates


def capacity_mbps(rates, steps, duration):
    """Time-averaged sum of forward path rates over the source window."""
    total = 0.0
    for index, rate in enumerate(rates):
        changes = sorted((s["at_seconds"], s["rate_mbps"]) for s in steps if s["path"] == index)
        current, last = rate, 0.0
        for at, value in changes:
            at = min(at, duration)
            total += current * (at - last)
            current, last = value, at
        total += current * (duration - last)
    return total / duration


def per_second_goodput(samples, start_us, seconds, deadline_ms=200):
    """On-time payload Mbps per one-second source cohort (by send time)."""
    buckets = [0] * seconds
    for sample in samples:
        sent, received = sample.get("send_unix_us"), sample.get("receive_unix_us")
        if sent is None or received is None or received - sent > deadline_ms * 1000:
            continue
        index = int((sent - start_us) // 1_000_000)
        if 0 <= index < seconds:
            buckets[index] += 1
    return [round(count * PAYLOAD_BYTES * 8 / 1e6, 3) for count in buckets]


def client_arguments(args, cert, token, listen, entrances, stats):
    arguments = ["client", "--listen", listen, "--server-name", "localhost", "--ca", cert,
                 "--token-file", token, "--fec", "0", "--redundancy-percent", "0",
                 "--rate-bps", args.rate_bps, "--queue-ms", "100", "--latency-target-ms", "100",
                 "--receiver-feedback", *stats]
    for index, entrance in enumerate(entrances):
        arguments += ["--entrance", entrance, "--path-group", str(index)]
    if args.mode == "adaptive":
        arguments += ["--adaptive", "--capacity-probe-bps", "20000000", "--probe-guided-recovery"]
    else:
        arguments += ["--adaptive", "--quality-schedule", "--small-fec-bytes", "0",
                      "--capacity-probe-bps", "0", "--datagram-send-buffer-bytes", "1200"]
    return arguments + endpoint_options(args) + args.client_extra_arg


def endpoint_options(args):
    options = []
    if args.legacy_recovery:
        options.append("--legacy-recovery")
    return options


class Lab:
    def __init__(self, output):
        self.output = output
        self.jobs = []
        self.commands = []
        self.emulator = None
        self.control_log = []
        self.lock = threading.Lock()

    def spawn(self, role, argv, **kwargs):
        with (self.output / f"{role}.log").open("w") as log:
            started = int(time.time() * 1000)
            process = subprocess.Popen([str(a) for a in argv], stdout=log, stderr=log,
                                       start_new_session=True, **kwargs)
        self.jobs.append((role, process))
        self.commands.append({"role": role, "argv": [str(a) for a in argv], "pid": process.pid,
                              "started_unix_ms": started})
        return process, started

    def control(self, change):
        with self.lock:
            line = json.dumps(change)
            self.emulator.stdin.write(line + "\n")
            self.emulator.stdin.flush()
            self.control_log.append({"sample_unix_ms": int(time.time() * 1000), "change": change})

    def wait_file(self, path, process, started, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = json.loads(path.read_text())
                if value.get("pid") == process.pid and value.get("sample_unix_ms", 0) >= started:
                    return value
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            if process.poll() is not None:
                break
            time.sleep(.05)
        raise RuntimeError(f"readiness file not produced: {path.name}")

    def runtime_ready(self, process, started, role, ids=(), session=None):
        def poll(_remaining):
            try:
                snapshot = latest_complete_snapshot(self.output / f"{role}.jsonl")
            except json.JSONDecodeError:
                snapshot = None
            return ProcessSample(snapshot, process.poll() is None, process.pid)
        result = wait_for_ready(poll, ReadinessRequirement(role, process.pid, started, tuple(ids),
                                                           session_id=session), 15)
        save(self.output / f"{role}-readiness.json", result.__dict__)
        if not result.ready:
            raise RuntimeError(f"{role} not ready: {result.reason} {result.detail}")
        return result.session_id

    def run(self, args):
        rates = path_rates(args)
        binary = args.binary
        identity = self.output / "identity"
        init = subprocess.run([str(binary), "init", "--dir", str(identity)], capture_output=True,
                              text=True, timeout=10)
        self.commands.append({"role": "init", "exit_code": init.returncode})
        if init.returncode:
            raise RuntimeError("identity initialization failed")
        cert, key, token = (str(identity / name) for name in ("cert.pem", "key.pem", "token"))
        server_addr, sink_addr, client_addr = free_address(), free_address(), free_address()
        lab_argv = [args.lab_binary, "--server", server_addr, "--queue-packets", args.queue_packets,
                    "--seed", args.seed, "--ready-file", self.output / "link-ready.json",
                    "--stats-jsonl", self.output / "link.jsonl", "--final-file", self.output / "link-final.json"]
        if args.policer_burst_bytes:
            lab_argv += ["--policer-burst-bytes", args.policer_burst_bytes]
        for rtt, rate in zip(args.rtt_ms, rates):
            lab_argv += ["--path", f"{rtt:g}:{rate:g}"]
        self.emulator, started = self.spawn("link", lab_argv, stdin=subprocess.PIPE, text=True)
        ready = self.wait_file(self.output / "link-ready.json", self.emulator, started)
        entrances = [path["entrance"] for path in ready["paths"]]

        def stats(role):
            return ["--stats-file", str(self.output / f"{role}.json"), "--stats-jsonl",
                    str(self.output / f"{role}.jsonl"), "--stats-interval-ms", "250"]
        server_argv = [binary, "server", "--listen", server_addr, "--target", sink_addr, "--cert", cert,
                       "--key", key, "--token-file", token, "--max-rate-bps", args.rate_bps,
                       *(["--datagram-send-buffer-bytes", "1200"] if args.mode == "native-service" else []),
                       *endpoint_options(args), *stats("server"), *args.server_extra_arg]
        server, server_started = self.spawn("server", server_argv)
        self.runtime_ready(server, server_started, "server")
        client, client_started = self.spawn("client", [binary, *client_arguments(
            args, cert, token, client_addr, entrances, stats("client"))])
        session = self.runtime_ready(client, client_started, "client", range(len(entrances)))
        self.runtime_ready(server, server_started, "server", range(len(entrances)), session)
        count = args.duration_seconds * args.pps
        common = ["--run-id", uuid.uuid4().hex, "--count", str(count), "--pps", str(args.pps),
                  "--size", "1000", "--deadline-ms", "200", "--drain-ms", "3000",
                  "--startup-timeout-ms", "15000"]
        sink, sink_started = self.spawn("sink", [binary, "sink", "--listen", sink_addr,
            "--ready-file", self.output / "sink-ready.json", *common,
            "--result-file", self.output / "sink-result.json",
            "--samples-file", self.output / "sink-samples.json"])
        sink_ready = self.wait_file(self.output / "sink-ready.json", sink, sink_started, 5)
        if sink_ready.get("ready") is not True:
            raise RuntimeError("sink JSON readiness failed")
        if args.loss_percent:
            for index in range(len(entrances)):
                self.control({"path": index, "loss_percent": args.loss_percent})
        timers = [threading.Timer(step["at_seconds"], self.control,
                                  [{"path": step["path"], "rate_mbps": step["rate_mbps"]}])
                  for step in args.step]
        source, _ = self.spawn("source", [binary, "probe", "--mode", "send", "--target", client_addr,
            *common, "--result-file", self.output / "source-result.json",
            "--samples-file", self.output / "source-samples.json"])
        for timer in timers:
            timer.start()
        try:
            source.wait(timeout=args.duration_seconds + 20)
            sink.wait(timeout=10)
        finally:
            for timer in timers:
                timer.cancel()
        if source.returncode or sink.returncode:
            raise RuntimeError("source/sink failed")
        source_result = json.loads((self.output / "source-result.json").read_text())
        sink_result = json.loads((self.output / "sink-result.json").read_text())
        if source_result.get("corrupt", 0) or sink_result.get("corrupt", 0):
            raise RuntimeError("probe integrity failure")
        samples = json.loads((self.output / "sink-samples.json").read_text())["samples"]
        source_samples = json.loads((self.output / "source-samples.json").read_text())["samples"]
        summary = summarize(samples, source_result, count, source_samples=source_samples, pps=args.pps)
        capacity = capacity_mbps(rates, args.step, args.duration_seconds)
        offered = args.pps * PAYLOAD_BYTES * 8 / 1e6
        summary.update({
            "path_rate_mbps": rates, "steps": args.step, "loss_percent_each_direction": args.loss_percent,
            "policer_burst_bytes": args.policer_burst_bytes,
            "link_model": "direct-drop policer" if args.policer_burst_bytes else "FIFO shaper",
            "time_average_forward_capacity_mbps": capacity, "offered_payload_mbps": offered,
            "goodput_to_capacity_ratio": summary["deadline_goodput_mbps"] / capacity,
            "per_second_on_time_goodput_mbps": per_second_goodput(
                samples, source_samples[0]["send_unix_us"], args.duration_seconds),
            "joint_gate_passed": None,
            "scope": "single native loopback diagnostic; capacity counts IPv4+UDP wire bytes",
        })
        save(self.output / "summary.json", summary)
        if not summary["source_qualified"]:
            raise RuntimeError("invalid source: " + "; ".join(summary["source_qualification"]["reasons"]))

    def cleanup(self):
        errors, exits = [], {}
        for role, process in reversed(self.jobs):
            if role != "link" and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
        for role, process in reversed(self.jobs):
            if role == "link":
                continue
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                errors.append(f"forced stop: {role}")
            exits[role] = process.returncode
            if process.returncode:
                errors.append(f"nonzero exit: {role}: {process.returncode}")
        if self.emulator:
            try:
                self.emulator.stdin.close()
                self.emulator.wait(timeout=5)
            except Exception as error:
                self.emulator.kill()
                errors.append(f"emulator stop failed: {error}")
            exits["link"] = self.emulator.returncode
            if self.emulator.returncode:
                errors.append(f"nonzero exit: link: {self.emulator.returncode}")
        return errors, exits


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--lab-binary", required=True, type=Path)
    parser.add_argument("--duration-seconds", type=int, default=20)
    parser.add_argument("--pps", type=int, default=40000)
    parser.add_argument("--rtt-ms", type=float, nargs="+", default=[30, 45, 60, 80])
    parser.add_argument("--rate-mbps", type=float, nargs="+", default=[100])
    parser.add_argument("--queue-packets", type=int, default=1024)
    parser.add_argument("--policer-burst-bytes", type=int, default=0,
                        help="direct-drop IPv4+UDP byte-token bucket; zero uses FIFO shaping")
    parser.add_argument("--rate-bps", default="400000000",
                        help="client and server cap in bits per second, or auto")
    parser.add_argument("--mode", choices=["adaptive", "native-service"], default="native-service")
    parser.add_argument("--loss-percent", type=float, default=0,
                        help="random loss per direction during business only")
    parser.add_argument("--step", type=parse_step, action="append", default=[],
                        help="AT_SECONDS:PATH:RATE_MBPS forward and return rate change")
    parser.add_argument("--seed", type=int, default=20261016)
    parser.add_argument("--legacy-recovery", action="store_true")
    parser.add_argument("--client-extra-arg", action="append", default=[])
    parser.add_argument("--server-extra-arg", action="append", default=[])
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    if ROOT / "local" not in args.output.parents:
        parser.error("all generated configuration and evidence must be under local/")
    if (not 1 <= args.duration_seconds <= 30 or not 1 <= args.pps <= 50000
            or args.duration_seconds * args.pps > 1000000):
        parser.error("finite workload must be <=30 s, <=50000 pps, <=1000000 records")
    if (not 1 <= len(args.rtt_ms) <= 8
            or any(not math.isfinite(x) or not 1 <= x <= 400 for x in args.rtt_ms)
            or any(not math.isfinite(x) or not 1 <= x <= 1000 for x in args.rate_mbps)
            or not 8 <= args.queue_packets <= 16384):
        parser.error("invalid finite shaping settings")
    if args.policer_burst_bytes != 0 and not 2048 <= args.policer_burst_bytes <= 1048576:
        parser.error("policer burst must be zero or 2048..1048576 IPv4+UDP bytes")
    try:
        path_rates(args)
    except ValueError as error:
        parser.error(str(error))
    if any(step["path"] >= len(args.rtt_ms) or step["at_seconds"] >= args.duration_seconds
           for step in args.step):
        parser.error("steps must name an existing path inside the source window")
    if not math.isfinite(args.loss_percent) or not 0 <= args.loss_percent <= 90:
        parser.error("business loss must be 0..90 percent")
    if args.rate_bps != "auto" and not args.rate_bps.isdigit():
        parser.error("rate must be bits per second or auto")
    for name in ("binary", "lab_binary"):
        path = getattr(args, name)
        if not path.is_file():
            parser.error(f"{name} must be an existing file")
        setattr(args, name, path.resolve())
    return args


def main(argv=None):
    args = parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)
    registration = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    registration.update({
        "registered_unix_ms": int(time.time() * 1000), "payload_bytes": PAYLOAD_BYTES, "deadline_ms": 200,
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "lab_binary_sha256": hashlib.sha256(args.lab_binary.read_bytes()).hexdigest(),
        "harness_sha256": {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                           for name in ("native_lab.py", "netem.py", "readiness.py")},
    })
    save(args.output / "registration.json", registration)
    lab = Lab(args.output)
    failure = None

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("native lab interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        lab.run(args)
    except BaseException as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        cleanup_errors, exits = lab.cleanup()
        if (args.output / "client.jsonl").exists():
            try:
                status = timeseries(args.output / "client.jsonl", args.output / "path-series.csv")
                save(args.output / "path-series-status.json", status)
            except Exception as error:
                failure = failure or f"time series invalid: {error}"
        for role in ("client", "server"):
            try:
                snapshot = json.loads((args.output / f"{role}.json").read_text())
                if snapshot.get("final") is not True or snapshot.get("outcome") != "stopped":
                    failure = failure or f"{role} final shutdown not confirmed"
            except Exception as error:
                failure = failure or f"{role} final snapshot missing: {error}"
    valid = not failure and not cleanup_errors
    save(args.output / "commands.json", lab.commands)
    save(args.output / "controls.json", lab.control_log)
    save(args.output / "result.json", {"valid": valid, "failure": failure,
                                       "cleanup_errors": cleanup_errors, "exits": exits})
    print(json.dumps({"output": str(args.output), "valid": valid, "failure": failure}))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
