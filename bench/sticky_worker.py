#!/usr/bin/env python3
"""Finite raw-UDP tuple diagnostic endpoint; configuration/results stay in local/."""
import argparse
import json
import select
import signal
import socket
import struct
import time
from pathlib import Path

HEADER = struct.Struct("!4s16sBBBBBIQq")
HELLO, HELLO_ACK, DATA, ACK = range(4)
COUNT, PPS, SIZE, FLOWS = 375, 25, 1000, 8


def packet(token, kind, path, round_id, direction, flow, seq=0, mono=0, unix=0):
    header = HEADER.pack(b"BPS1", token, kind, path, round_id, direction, flow, seq, mono, unix)
    return header + bytes([seq % 251]) * (SIZE - HEADER.size) if kind == DATA else header


def decode(data, token):
    if len(data) < HEADER.size:
        return None
    magic, secret, kind, path, round_id, direction, flow, seq, mono, unix = HEADER.unpack(data[:HEADER.size])
    if magic != b"BPS1" or secret != token or kind not in range(4) or path > 1 or round_id > 2 or direction > 1 or flow >= FLOWS or seq >= COUNT:
        return None
    if kind == DATA:
        if len(data) != SIZE or data[HEADER.size:] != bytes([seq % 251]) * (SIZE - HEADER.size):
            return None
    elif len(data) != HEADER.size:
        return None
    return kind, path, round_id, direction, flow, seq, mono, unix


def save(path, value):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, allow_nan=False) + "\n")
    tmp.replace(path)


def quantile(values, population, fraction):
    import math
    index = max(0, math.ceil(population * fraction) - 1)
    values = sorted(values)
    return values[index] if index < len(values) else "infinity"


def run(config, directory):
    token = bytes.fromhex(config["token"])
    client = config["role"] == "client"
    sockets, mapping, sock_ids = [], {}, {}
    for path in config["paths"] if client else [None]:
        for flow in range(FLOWS) if client else [0]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", path["ports"][flow]) if client else tuple(config["listen"]))
            if client:
                sock.connect(tuple(path["entrance"]))
                sock_ids[sock] = (path["id"], flow)
            sock.setblocking(False)
            sockets.append(sock)
    stopping = False
    def stop(signum, frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    start = time.monotonic()
    next_hello = 0
    active, seen_commands, mapping_changes = None, set(), []
    rejected = 0
    save(directory / "ready.json", {"ready": True, "pid": __import__("os").getpid(), "sockets": [s.getsockname() for s in sockets]})
    def emit():
        flows = []
        for flow in range(FLOWS):
            sent = active["sent"][flow]
            received = active["received"][flow]
            rtts = active["rtts"][flow]
            times = [s["send_mono_us"] for s in sent]
            span = (max(times) - min(times)) / 1e6 if len(times) > 1 else None
            flows.append({"flow": flow, "source_count": len(sent), "received": len(received), "duplicates": active["duplicates"][flow],
                "rtt_received": len(rtts), "rtt_p50_received_ms": quantile(rtts, len(rtts), .5) if rtts else None,
                "rtt_p95_unconditional_ms": quantile(rtts, COUNT, .95), "rtt_p99_unconditional_ms": quantile(rtts, COUNT, .99),
                "source_span_seconds": span, "actual_pps": (len(times)-1)/span if span else None,
                "sent_samples": sent, "received_samples": list(received.values()), "mapping_peer": mapping.get((active["path"], flow)),
                "client_socket": next((s.getsockname() for s, k in sock_ids.items() if k == (active["path"], flow)), None)})
        save(directory / (active["key"] + ".json"), {"key": active["key"], "role": active["role"], "flows": flows, "mapping_changes": mapping_changes,
            "round": active["round"], "path": active["path"], "direction": active["direction"], "completed_unix_us": time.time_ns()//1000})
    while not stopping and time.monotonic() - start < config.get("maximum_seconds", 2700):
        now = time.monotonic()
        if client and now >= next_hello:
            for sock, (path, flow) in sock_ids.items():
                sock.send(packet(token, HELLO, path, 0, 0, flow))
            next_hello = now + 10
        command_path = directory / "command.json"
        if command_path.exists():
            command = json.loads(command_path.read_text())
            if command["key"] not in seen_commands:
                if active is not None:
                    raise RuntimeError("overlapping diagnostic command")
                seen_commands.add(command["key"])
                active = {**command, "began": now, "until": now + 35, "next": now, "seq": 0,
                    "sent": [[] for _ in range(FLOWS)], "received": [{} for _ in range(FLOWS)], "rtts": [[] for _ in range(FLOWS)],
                    "ack_sequences": [set() for _ in range(FLOWS)], "duplicates": [0]*FLOWS}
                save(directory / (command["key"] + "-ready.json"), {"ready": True})
        if active and active["role"] == "send" and active["seq"] < COUNT and now >= active["next"]:
            seq = active["seq"]
            for flow in range(FLOWS):
                mono, unix = time.monotonic_ns()//1000, time.time_ns()//1000
                data = packet(token, DATA, active["path"], active["round"], active["direction"], flow, seq, mono, unix)
                if client:
                    sock = next(s for s, k in sock_ids.items() if k == (active["path"], flow))
                    sock.send(data)
                else:
                    sockets[0].sendto(data, mapping[(active["path"], flow)])
                active["sent"][flow].append({"seq": seq, "send_mono_us": mono, "send_unix_us": unix})
            active["seq"] += 1
            active["next"] = max(active["began"] + active["seq"] / PPS, now + 1/PPS)
            if active["seq"] == COUNT:
                active["until"] = time.monotonic() + 3
        if active and now >= active["until"]:
            emit()
            active = None
        readable, _, _ = select.select(sockets, [], [], .002)
        for sock in readable:
            data, peer = sock.recvfrom(SIZE+1)
            decoded = decode(data, token)
            if decoded is None:
                rejected += 1
                continue
            kind, path, round_id, direction, flow, seq, mono, unix = decoded
            if client and sock_ids[sock] != (path, flow):
                rejected += 1
                continue
            if not client and kind == HELLO:
                old = mapping.get((path, flow))
                if old is not None and old != peer:
                    mapping_changes.append({"path": path, "flow": flow, "before": old, "after": peer, "unix_us": time.time_ns()//1000})
                    if len(mapping_changes) > 128:
                        raise RuntimeError("mapping change bound exceeded")
                mapping[(path, flow)] = peer
                sock.sendto(packet(token, HELLO_ACK, path, 0, 0, flow), peer)
                save(directory / "mappings.json", {"peers": {f"{p}/{f}": v for (p,f),v in mapping.items()}, "changes": mapping_changes})
                continue
            if kind == HELLO_ACK:
                continue
            if not active or (path,round_id,direction) != (active["path"],active["round"],active["direction"]):
                rejected += 1
                continue
            if kind == DATA and active["role"] == "receive":
                if seq in active["received"][flow]:
                    active["duplicates"][flow] += 1
                else:
                    active["received"][flow][seq] = {"seq": seq, "send_unix_us": unix, "receive_unix_us": time.time_ns()//1000, "peer": peer}
                if client:
                    sock.send(packet(token, ACK, path, round_id, direction, flow, seq, mono, unix))
                else:
                    sock.sendto(packet(token, ACK, path, round_id, direction, flow, seq, mono, unix), peer)
                # Follow unique progress at the same bounded configured pace.
                if seq == COUNT-1:
                    active["until"] = min(active["until"], time.monotonic()+3)
            elif kind == ACK and active["role"] == "send" and seq < active["seq"]:
                if seq not in active["ack_sequences"][flow]:
                    expected = active["sent"][flow][seq]
                    if expected["send_mono_us"] != mono:
                        rejected += 1
                        continue
                    active["ack_sequences"][flow].add(seq)
                    active["rtts"][flow].append((time.monotonic_ns()//1000-mono)/1000)
    if active:
        emit()
    save(directory / "result.json", {"final": True, "rejected": rejected, "mapping_changes": mapping_changes, "commands": sorted(seen_commands)})
    for sock in sockets:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    directory = Path(args.directory)
    run(json.loads(Path(args.config).read_text()), directory)
