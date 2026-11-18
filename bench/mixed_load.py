"""Bounded SOCKS5 mixed traffic and message-level acceptance metrics."""

import hashlib
import math
import multiprocessing
import select
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack


def read_exact(sock, length):
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise RuntimeError("incomplete socket reply")
        result.extend(part)
    return bytes(result)


def split(address):
    host, port = address.rsplit(":", 1)
    return host, int(port)


def percentile(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1] if values else None


def datagram_metrics(sent, replies):
    """Use planned messages as the denominator and encode an infinite p99 as null."""
    delays, duplicate, malformed = {}, 0, 0
    for sequence, delay, valid in replies:
        if not valid or sequence not in sent:
            malformed += 1
        elif sequence in delays:
            duplicate += 1
        else:
            delays[sequence] = delay
    count = len(sent)
    missing = count - len(delays)
    tail = percentile(list(delays.values()) + [math.inf] * missing, .99)
    return {"sent": count, "missing": missing, "duplicates": duplicate, "malformed": malformed,
            "on_time": sum(delay <= 200 for delay in delays.values()),
            "p99_ms": tail if tail is not None and math.isfinite(tail) else None}


def compare(candidate, reference):
    if not candidate["reliable_exact"]:
        return "fail"
    if not candidate["generator_valid"] or not reference["generator_valid"] or not reference["reliable_exact"]:
        return "insufficient"
    actual, baseline = candidate["udp"], reference["udp"]
    if actual["duplicates"] or actual["malformed"] or actual["on_time"] * 100 < 99 * actual["sent"]:
        return "fail"
    if not actual["sent"] or not baseline["sent"]:
        return "insufficient"
    if (actual["missing"] / actual["sent"] - baseline["missing"] / baseline["sent"]
            > .005 + 1e-12):
        return "fail"
    if baseline["p99_ms"] is not None and (actual["p99_ms"] is None
                                           or actual["p99_ms"] > baseline["p99_ms"] + 10):
        return "fail"
    return "pass"


def evaluate(candidate, native, game, unified=False):
    """Evaluate one comparable fixed-load block against predeclared gates."""
    udp = compare(candidate, game)
    if udp == "fail":
        return {"status": "fail", "udp": udp}
    if udp == "insufficient" or (not unified and
                                 (not native["generator_valid"] or not native["reliable_exact"])):
        return {"status": "insufficient", "udp": udp}
    throughput_reference = game if unified else native

    def short_tail(window):
        sample = percentile([item["elapsed_seconds"] if item["outcome"] == "ok" else math.inf
                             for item in window["short_requests"]], .95)
        return sample if sample is not None and math.isfinite(sample) else None

    reference_tail = short_tail(throughput_reference)
    candidate_tail = short_tail(candidate)
    ratios = {}
    for direction, values in throughput_reference["directions"].items():
        available = values["goodput_mbps"]
        ratios[direction] = (candidate["directions"][direction]["goodput_mbps"] / available
                             if available else None)
    if reference_tail is None or any(ratio is None for ratio in ratios.values()):
        return {"status": "insufficient", "udp": udp, "goodput_ratios": ratios}
    short_ok = candidate_tail is not None and candidate_tail <= 1.15 * reference_tail
    throughput_ok = all(ratio >= .90 for ratio in ratios.values())
    return {"status": "pass" if short_ok and throughput_ok else "fail",
            "udp": udp, "goodput_ratios": ratios, "short_requests_pass": short_ok,
            "short_p95_ms": candidate_tail * 1000 if candidate_tail is not None else None,
            "reference_short_p95_ms": reference_tail * 1000}



def udp_echo(sock, stop):
    sock.settimeout(.1)
    while not stop.is_set():
        try:
            message, peer = sock.recvfrom(8192)
        except socket.timeout:
            continue
        sock.sendto(message, peer)


def associate(control, address):
    control.sendall(b"\x05\x01\x00")
    if read_exact(control, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 method refused")
    control.sendall(b"\x05\x03\x00\x01" + bytes(6))
    reply = read_exact(control, 10)
    if reply[:4] != b"\x05\x00\x00\x01":
        raise RuntimeError("SOCKS5 IPv4 UDP association refused")
    relay_address = socket.inet_ntoa(reply[4:8]) if any(reply[4:8]) else address
    return relay_address, int.from_bytes(reply[8:], "big")


def udp_window(sock, header, start, seconds):
    sent, messages, replies = {}, {}, []
    total = round(seconds * 50)
    sequence = 0
    finish = start + seconds + 10
    while time.monotonic() < finish:
        now = time.monotonic()
        if sequence < total and now >= start + sequence / 50:
            size = 128 if sequence % 2 == 0 else 1200
            body = struct.pack("!Q", sequence) + bytes(size - 8)
            messages[sequence] = header + body
            sent[sequence] = now
            sock.send(messages[sequence])
            sequence += 1
        next_send = start + sequence / 50 if sequence < total else finish
        readable, _, _ = select.select([sock], [], [], max(0, next_send - time.monotonic()))
        if readable:
            data = sock.recv(8192)
            seq = int.from_bytes(data[10:18], "big")
            replies.append((seq, (time.monotonic() - sent.get(seq, start)) * 1000,
                            messages.get(seq) == data))
    lateness = [max(0, at - (start + seq / 50)) for seq, at in sent.items()]
    valid = (len(sent) == total and max(lateness, default=0) <= .04
             and sum(delay > .02 for delay in lateness) * 100 <= total)
    return datagram_metrics(sent, replies), valid, sent, replies


def udp_worker(report, sock, header, start_wall, start_parent, seconds):
    # Python 3.9 on macOS uses a process-local monotonic origin. Convert
    # the common start instant once, then use only the worker's clock.
    start = time.monotonic() + (start_wall - time.time())
    with report, sock:
        metrics, valid, sent, replies = udp_window(sock, header, start, seconds)
        report.send((metrics, valid, {seq: start_parent + (at - start) for seq, at in sent.items()},
                     replies))


class Delivery:
    def __init__(self):
        self.condition = threading.Condition()
        self.received = 0


def send_until(sock, data, start, stop, delivery):
    time.sleep(max(0, start - time.monotonic()))
    end = 0
    sent = memoryview(data)
    while end < len(sent):
        with delivery.condition:
            # Bound load-generator socket/relay backlog so the registered
            # drain interval measures the tunnel rather than a 32 MiB preload.
            delivery.condition.wait_for(
                lambda: end - delivery.received < 2 * 1024 * 1024,
                timeout=max(0, stop - time.monotonic()),
            )
        left = stop - time.monotonic()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            end += sock.send(sent[end:end + 65536])
        except socket.timeout:
            break
    sock.shutdown(socket.SHUT_WR)
    return end, hashlib.sha256(sent[:end]).hexdigest(), end < len(sent)


def receive_until(sock, start, stop, deadline, cap, delivery):
    digest, received = hashlib.sha256(), 0
    progress = [0] * math.ceil(stop - start)
    exact = True
    try:
        while True:
            sock.settimeout(max(.001, deadline - time.monotonic()))
            if time.monotonic() >= deadline:
                raise TimeoutError("mixed drain deadline")
            data = sock.recv(65536)
            if not data:
                break
            received += len(data)
            if received > cap:
                raise RuntimeError("received beyond registered cap")
            digest.update(data)
            with delivery.condition:
                delivery.received = received
                delivery.condition.notify()
            now = time.monotonic()
            if now < stop:
                index = max(0, int(now - start))
                if index < len(progress):
                    progress[index] += len(data)
    except OSError:
        exact = False
    return received, digest.hexdigest(), exact, progress


def run(proxy, connect, seconds, data, probe, connections):
    """Run one fixed window against a ready SOCKS5 endpoint."""
    stop_echo = threading.Event()
    with ExitStack() as stack:
        udp_target = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp_target.bind(("127.0.0.1", 0))
        control = stack.enter_context(socket.create_connection(split(proxy), timeout=10))
        udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp.connect(associate(control, split(proxy)[0]))
        target_host, target_port = udp_target.getsockname()
        header = b"\x00\x00\x00\x01" + socket.inet_aton(target_host) + struct.pack("!H", target_port)
        pairs = []
        for _ in range(2 * connections):
            listener = stack.enter_context(socket.create_server(("127.0.0.1", 0)))
            listener.settimeout(10)
            target = "127.0.0.1:%d" % listener.getsockname()[1]
            local = stack.enter_context(socket.create_connection(split(proxy), timeout=10))
            connect(local, target, time.monotonic() + 10)
            peer = stack.enter_context(listener.accept()[0])
            pairs.append((local, peer))
        start = time.monotonic() + .75
        start_wall = time.time() + (start - time.monotonic())
        stop = start + seconds
        worker_context = multiprocessing.get_context("spawn")
        report, sender = worker_context.Pipe(duplex=False)
        datagrams = worker_context.Process(
            target=udp_worker, args=(sender, udp, header, start_wall, start, seconds), daemon=True)
        datagrams.start()
        sender.close()
        echo = threading.Thread(target=udp_echo, args=(udp_target, stop_echo), daemon=True)
        echo.start()
        probe.start()
        try:
            with ThreadPoolExecutor(max_workers=4 * connections) as workers:
                traffic = {"up": [], "down": []}
                for index, (local, peer) in enumerate(pairs):
                    direction = "up" if index < connections else "down"
                    give, take = (local, peer) if direction == "up" else (peer, local)
                    delivery = Delivery()
                    sending = workers.submit(send_until, give, data, start, stop, delivery)
                    receiving = workers.submit(receive_until, take, start, stop, stop + 10,
                                                len(data), delivery)
                    traffic[direction].append((sending, receiving))
                directions = {}
                complete, generators = True, True
                for direction, flows in traffic.items():
                    sent_total, received_total = 0, 0
                    progress_total = [0] * seconds
                    transfers = []
                    for sending, receiving in flows:
                        count, checksum, active = sending.result()
                        received, digest, drained, progress = receiving.result()
                        exact = drained and count > 0 and (count, checksum) == (received, digest)
                        complete &= exact
                        generators &= active
                        sent_total += count
                        received_total += received
                        progress_total = [a + b for a, b in zip(progress_total, progress)]
                        transfers.append({"sent": count, "received": received,
                                          "sha256": digest, "exact": exact})
                    directions[direction] = {
                        "sent": sent_total, "received": received_total,
                        "flows": transfers,
                        "bytes_per_second": progress_total,
                        "goodput_mbps": sum(progress_total) * 8 / seconds / 1e6,
                    }
                if not report.poll(max(0, stop + 12 - time.monotonic())):
                    raise RuntimeError("UDP worker missed its report deadline")
                udp_summary, on_schedule, sent, replies = report.recv()
        finally:
            report.close()
            if datagrams.is_alive():
                datagrams.join(1)
            if datagrams.is_alive():
                datagrams.terminate()
            datagrams.join()
            stop_echo.set()
            echo.join(1)
            probe.stop.set()
            probe.join(10)
    return {"reliable_exact": complete, "generator_valid": generators and on_schedule,
            "directions": directions, "udp": udp_summary, "udp_sent_monotonic": sent,
            "udp_replies": replies, "start_monotonic": start, "stop_monotonic": stop,
            "short_requests": [item for item in probe.attempts
                               if start <= item["started_monotonic"] < stop]}
