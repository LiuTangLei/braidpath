"""Bounded SOCKS5 mixed traffic and message-level acceptance metrics."""

import hashlib
import math
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


def run(proxy, connect, seconds, data, probe):
    """Run one fixed window against a ready SOCKS5 endpoint."""
    stop_echo = threading.Event()
    with ExitStack() as stack:
        listeners = [stack.enter_context(socket.create_server(("127.0.0.1", 0))) for _ in range(2)]
        udp_target = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp_target.bind(("127.0.0.1", 0))
        control = stack.enter_context(socket.create_connection(split(proxy), timeout=10))
        udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp.connect(associate(control, split(proxy)[0]))
        target_host, target_port = udp_target.getsockname()
        header = b"\x00\x00\x00\x01" + socket.inet_aton(target_host) + struct.pack("!H", target_port)
        pairs = []
        for listener in listeners:
            listener.settimeout(10)
            local = stack.enter_context(socket.create_connection(split(proxy), timeout=10))
            connect(local, "127.0.0.1:%d" % listener.getsockname()[1], time.monotonic() + 10)
            peer = stack.enter_context(listener.accept()[0])
            pairs.append((local, peer))
        start = time.monotonic() + .5
        stop = start + seconds
        echo = threading.Thread(target=udp_echo, args=(udp_target, stop_echo), daemon=True)
        echo.start()
        probe.start()
        try:
            with ThreadPoolExecutor(max_workers=5) as workers:
                udp_task = workers.submit(udp_window, udp, header, start, seconds)
                traffic = []
                for give, take in [pairs[0], pairs[1][::-1]]:
                    delivery = Delivery()
                    sender = workers.submit(send_until, give, data, start, stop, delivery)
                    receiver = workers.submit(receive_until, take, start, stop, stop + 10, len(data), delivery)
                    traffic.append((sender, receiver))
                directions = {}
                complete, generators = True, True
                for direction, (sender, receiver) in zip(("up", "down"), traffic):
                    count, checksum, active = sender.result()
                    received, digest, drained, progress = receiver.result()
                    complete &= drained and count > 0 and (count, checksum) == (received, digest)
                    generators &= active
                    directions[direction] = {"sent": count, "received": received, "sha256": digest,
                                             "bytes_per_second": progress,
                                             "goodput_mbps": sum(progress) * 8 / seconds / 1e6}
                udp_summary, on_schedule, sent, replies = udp_task.result()
        finally:
            stop_echo.set()
            echo.join(1)
            probe.stop.set()
            probe.join(10)
    return {"reliable_exact": complete, "generator_valid": generators and on_schedule,
            "directions": directions, "udp": udp_summary, "udp_sent_monotonic": sent,
            "udp_replies": replies, "start_monotonic": start, "stop_monotonic": stop,
            "short_requests": [item for item in probe.attempts
                               if start <= item["started_monotonic"] < stop]}
