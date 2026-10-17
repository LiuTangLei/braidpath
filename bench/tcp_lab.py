"""Finite single-TCP transfer through BraidPath over the native link emulator.

Runs on the development host without privileges. The emulator shapes every
path in both directions (FIFO serializer, propagation delay, optional loss).
One TCP connection carries a seeded payload; the target verifies integrity.
Selecting a subset of paths gives the matched single-path baseline on the same
emulated topology. Loopback shares one CPU and kernel: this is a controlled
diagnostic, not a WAN or independent-bandwidth acceptance result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
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


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "lab-binary", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--path", type=parse_path, action="append", required=True)
    parser.add_argument("--use-path", type=int, action="append",
                        help="client entrance subset by emulator path index; default all")
    parser.add_argument("--bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--direction", choices=("up", "down"), default="up")
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
    args.use_path = args.use_path or list(range(len(args.path)))
    if any(not 0 <= i < len(args.path) for i in args.use_path):
        parser.error("unknown path index")
    return args


def payload(size, seed):
    return random.Random(seed).randbytes(size)


class Target(threading.Thread):
    """One-connection TCP target: digest an upload or serve a download."""

    def __init__(self, direction, data):
        super().__init__(daemon=True)
        self.direction, self.data = direction, data
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.address = "127.0.0.1:%d" % self.listener.getsockname()[1]
        self.error = None

    def run(self):
        try:
            conn, _ = self.listener.accept()
            with conn:
                if self.direction == "up":
                    digest, count = hashlib.sha256(), 0
                    while chunk := conn.recv(1 << 16):
                        digest.update(chunk)
                        count += len(chunk)
                    conn.sendall(DIGEST.pack(digest.digest(), count))
                else:
                    conn.sendall(self.data)
                    conn.shutdown(socket.SHUT_WR)
                    conn.recv(1)
        except OSError as error:
            self.error = repr(error)


def transfer(address, direction, data, limit):
    host, port = address.rsplit(":", 1)
    conn = socket.create_connection((host, int(port)), timeout=limit)
    started = time.monotonic()
    with conn:
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
            digest, count, first = hashlib.sha256(), 0, None
            while chunk := conn.recv(1 << 16):
                first = first or time.monotonic() - started
                digest.update(chunk)
                count += len(chunk)
            elapsed = time.monotonic() - started
            exact = digest.digest() == hashlib.sha256(data).digest() and count == len(data)
    return {"elapsed_seconds": elapsed, "exact": exact, "received_bytes": count,
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
    args.output.mkdir(parents=True, exist_ok=True)
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
        target = Target(args.direction, data)
        target.start()
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
                                  "--key", key, "--token-file", token, "--tcp-target", target.address,
                                  "--stats-file", args.output / "server.json", *args.server_arg])
        wait_log(args.output / "server.log", "HTTP/3 server ready", server)
        entrances = [ready["paths"][i]["entrance"] for i in args.use_path]
        client = spawn("client", [args.binary, "client", "--listen", udp_listen, "--tcp-listen", tcp_listen,
                                  *sum((["--entrance", e] for e in entrances), []),
                                  "--server-name", "localhost", "--ca", cert, "--token-file", token,
                                  "--stats-file", args.output / "client.json", *args.client_arg])
        wait_log(args.output / "client.log", "UDP client ready", client)
        time.sleep(0.5)
        result = transfer(tcp_listen, args.direction, data, args.timeout_seconds)
        target.join(5)
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
        summary = {
            **result,
            "direction": args.direction, "bytes": args.bytes, "paths": args.path,
            "used_paths": args.use_path, "loss_percent_each_direction": args.loss_percent,
            "used_capacity_mbps": capacity,
            "goodput_to_used_capacity": result["goodput_mbps"] / capacity,
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
