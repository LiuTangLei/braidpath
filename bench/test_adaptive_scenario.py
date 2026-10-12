"""Meaningful bounds, serialization and measurement tests; no BraidPath build needed."""
import asyncio
from collections import Counter
from types import SimpleNamespace
import time
import unittest
import socket
import heapq
from pathlib import Path
import tempfile
from unittest.mock import patch
from bench import adaptive_scenario

from bench.adaptive_scenario import (SerializedLink, Shape, phases_for, quantile, summarize,
                                     window_at, udp_send, udp_receive, Traffic,
                                     LATE_ACCOUNTING_BATCH, HEADER)
from bench.adaptive_compare import evaluate_window


class PacketShaperTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.links = []

    async def asyncTearDown(self):
        for link in self.links:
            await link.close()
            self.assertEqual(link.queued_bytes, 0)

    def link(self, shape):
        link = SerializedLink.create("test", shape, 20261009)
        self.links.append(link)
        return link

    async def wait_count(self, items, count, seconds=3):
        until = time.monotonic() + seconds
        while len(items) < count and time.monotonic() < until:
            await asyncio.sleep(.002)
        self.assertGreaterEqual(len(items), count)

    async def test_fifo_serializes_real_ip_udp_bytes_instead_of_bursting(self):
        link = self.link(Shape(80_000, delay_ms=0, queue_ms=1000))
        received = []
        started = time.monotonic()
        for index in range(3):
            link.submit(bytes([index]) * 1000, lambda data: received.append((data[0], time.monotonic())))
        await self.wait_count(received, 3)
        self.assertEqual([item[0] for item in received], [0, 1, 2])
        # Three 1028-byte IP/UDP packets require >=308.4 ms at 80 kbit/s.
        self.assertGreaterEqual(received[-1][1] - started, .300)
        self.assertEqual(link.counters["forwarded_ip_udp_bytes"], 3 * 1028)

    async def test_python39_udp_helpers_preserve_datagrams_and_cancel_readiness(self):
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for sock in (sender, receiver):
                sock.setblocking(False)
                sock.bind(("127.0.0.1", 0))
            read = asyncio.create_task(udp_receive(receiver, 2048))
            await asyncio.sleep(.001)
            self.assertEqual(await udp_send(sender, b"x" * 1200, receiver.getsockname()), 1200)
            data, peer = await asyncio.wait_for(read, 1)
            self.assertEqual(data, b"x" * 1200)
            self.assertEqual(peer, sender.getsockname())
            cancelled = asyncio.create_task(udp_receive(receiver, 2048))
            await asyncio.sleep(.001)
            cancelled.cancel()
            await asyncio.gather(cancelled, return_exceptions=True)
            await udp_send(sender, b"next", receiver.getsockname())
            self.assertEqual((await asyncio.wait_for(udp_receive(receiver, 2048), 1))[0], b"next")
        finally:
            sender.close()
            receiver.close()

    async def test_capacity_reduction_applies_to_existing_backlog(self):
        link = self.link(Shape(800_000, delay_ms=0, queue_ms=2000))
        received = []
        for index in range(8):
            link.submit(bytes([index]) * 1000, lambda data: received.append(time.monotonic()))
        await self.wait_count(received, 1)
        reduced = time.monotonic()
        link.configure(Shape(80_000, delay_ms=0, queue_ms=2000))
        await self.wait_count(received, 8)
        self.assertGreaterEqual(received[-1] - reduced, .55)

    async def test_queue_memory_bound_includes_inflight_and_shutdown_is_conserved(self):
        link = self.link(Shape(80_000, delay_ms=100, queue_bytes=2056, queue_ms=1000))
        accepted = [link.submit(b"x" * 1000, lambda _: None) for _ in range(20)]
        self.assertEqual(sum(accepted), 2)
        self.assertLessEqual(link.counters["peak_queued_bytes"], 2056)
        await asyncio.sleep(.02)
        await link.close()
        self.links.remove(link)
        self.assertEqual(link.queued_bytes, 0)
        self.assertEqual(link.counters["queue_full_drops"], 18)
        self.assertEqual(link.counters["admitted_packets"],
                         link.counters["forwarded_packets"] + link.counters["shutdown_drops"])

    async def test_explicit_packet_loss_is_not_successful_delivery(self):
        link = self.link(Shape(1_000_000, delay_ms=0, loss=1))
        received = []
        for _ in range(3):
            link.submit(b"x" * 100, received.append)
        await asyncio.sleep(.04)
        self.assertEqual(received, [])
        self.assertEqual(link.counters["configured_loss_drops"], 3)
        self.assertEqual(link.queued_bytes, 0)

    async def test_shared_entrances_do_not_multiply_group_capacity(self):
        shared = self.link(Shape(80_000, delay_ms=0, queue_ms=1000))
        arrivals = []
        started = time.monotonic()
        for entrance in (0, 1):
            for _ in range(2):
                shared.submit(bytes([entrance]) * 1000, lambda _: arrivals.append(time.monotonic()))
        await self.wait_count(arrivals, 4)
        self.assertGreaterEqual(arrivals[-1] - started, .400)
        self.assertEqual(shared.counters["forwarded_ip_udp_bytes"], 4 * 1028)

    async def test_queue_age_expiry_prevents_delivering_unbounded_old_backlog(self):
        link = self.link(Shape(80_000, delay_ms=0, queue_ms=120))
        received = []
        for _ in range(5):
            link.submit(b"x" * 1000, received.append)
        await asyncio.sleep(.30)
        self.assertEqual(len(received), 1)
        self.assertEqual(link.counters["queue_age_drops"], 4)
        self.assertEqual(link.queued_bytes, 0)


class SourceSchedulingTests(unittest.TestCase):
    """Deterministic ready-callback cost, with no real sockets or wall-clock sleep."""

    def traffic(self, kind, pps, size):
        stream = Traffic.__new__(Traffic)
        stream.kind, stream.pps, stream.size = kind, pps, size
        stream.samples, stream.counters = [], Counter()
        stream.socket, stream.destination = None, None
        return stream

    def simulate(self, initial, cost, legacy=False, duration=3, bulk_pps=900):
        clock = SimpleNamespace(now=initial)
        bulk = self.traffic(1, bulk_pps, 1000)
        interactive = self.traffic(2, 20, 128)
        sent, turns, legacy_counts = [], [], Counter()
        phases = [{"name": "window_a", "seconds": min(1, duration), "condition": "clean"}]
        if duration > 1:
            phases.append({"name": "window_b", "seconds": duration - 1, "condition": "clean"})

        class Delay:
            def __init__(self, delay):
                self.delay = delay

            def __await__(self):
                yield self.delay

        async def send_packet(_socket, data, _peer):
            _, kind, seq, stamp = HEADER.unpack_from(data)
            sent.append((kind, seq, stamp / 1e9))
            return len(data)

        async def old_one_yield_per_missed_slot():
            # Counterexample: the v1 late-accounting pattern, under identical
            # simulated competing-callback cost. It performs no network I/O.
            for seq in range(round(duration * 900)):
                planned = seq / 900
                await Delay(max(0, planned - clock.now))
                legacy_counts["late" if clock.now - planned > .050 else "admitted"] += 1

        bulk_task = old_one_yield_per_missed_slot() if legacy else bulk.send(0, phases)
        interactive_task = interactive.send(initial, [{"name": "interactive", "seconds": 1, "condition": "clean"}])
        tasks = [bulk_task, interactive_task]
        pending = [(initial, index, index, task) for index, task in enumerate(tasks)]
        order = len(tasks)
        with patch("bench.adaptive_scenario.asyncio.sleep", new=lambda delay: Delay(delay)), \
             patch("bench.adaptive_scenario.time.monotonic", side_effect=lambda: clock.now), \
             patch("bench.adaptive_scenario.time.monotonic_ns", side_effect=lambda: round(clock.now * 1e9)), \
             patch("bench.adaptive_scenario.udp_send", side_effect=send_packet):
            try:
                while pending:
                    wake, _, index, task = heapq.heappop(pending)
                    clock.now = max(clock.now, wake) + cost
                    before = len(bulk.samples)
                    try:
                        delay = task.send(None)
                    except StopIteration:
                        turns.append((index, len(bulk.samples) - before))
                        continue
                    turns.append((index, len(bulk.samples) - before))
                    heapq.heappush(pending, (clock.now + delay, order, index, task))
                    order += 1
                    self.assertLess(order, 20_000, "simulated source failed to make bounded progress")
            finally:
                for task in tasks:
                    task.close()
        return bulk, interactive, sent, turns, legacy_counts

    def test_expired_backlog_is_batched_without_erasing_samples_or_starving_interactive(self):
        # A 1.2 ms competing ready-callback cost exceeds a 900 pps source slot.
        # Bulk starts with a 1.2 s accounting backlog while interactive is current.
        bulk, interactive, sent, turns, _ = self.simulate(1.2, .0012)
        self.assertEqual([s["seq"] for s in bulk.samples], list(range(2700)))
        self.assertEqual(Counter(s["window"] for s in bulk.samples), {"window_a": 900, "window_b": 1800})
        self.assertGreater(bulk.counters["generator_late"], 900)
        self.assertTrue(all(s["send_ns"] is None for s in bulk.samples if s["status"] == "generator_late"))
        bulk_sends = [(seq, at) for kind, seq, at in sent if kind == 1]
        self.assertTrue(bulk_sends)
        self.assertLess(bulk_sends[0][1], 1.225, "late accounting did not catch up within a few bounded batches")
        self.assertTrue(all(at - seq / 900 <= .050000001 for seq, at in bulk_sends))
        self.assertLessEqual(max(amount for _, amount in turns), LATE_ACCOUNTING_BATCH)
        self.assertGreater(sum(amount == LATE_ACCOUNTING_BATCH for _, amount in turns), 1)
        self.assertEqual(sum(s["status"] == "kernel_accepted" for s in interactive.samples), 20)
        self.assertTrue(any(index == 1 for index, _ in turns[:6]), "interactive task must run between accounting batches")
        _, old_interactive, _, _, old = self.simulate(1.2, .0012, legacy=True)
        self.assertEqual(old["late"], 2700)
        self.assertEqual(old["admitted"], 0)
        self.assertEqual(sum(s["status"] == "kernel_accepted" for s in old_interactive.samples), 20)

    def test_late_cutoff_remains_strictly_greater_than_fifty_milliseconds(self):
        at_boundary, _, sent, _, _ = self.simulate(.050, 0, duration=1 / 900)
        self.assertEqual(at_boundary.samples[0]["status"], "kernel_accepted")
        self.assertEqual(sum(kind == 1 for kind, _, _ in sent), 1)
        after_boundary, _, sent, _, _ = self.simulate(.050001, 0, duration=1 / 900)
        self.assertEqual(after_boundary.samples[0]["status"], "generator_late")
        self.assertEqual(sum(kind == 1 for kind, _, _ in sent), 0)

    def test_batch_does_not_send_a_future_low_rate_slot_early(self):
        bulk, _, sent, _, _ = self.simulate(.2, 0, duration=2, bulk_pps=1)
        self.assertEqual([s["status"] for s in bulk.samples], ["generator_late", "kernel_accepted"])
        self.assertEqual([(seq, at) for kind, seq, at in sent if kind == 1], [(1, 1.0)])


class MeasurementTests(unittest.TestCase):
    def test_loss_is_registered_and_kept_on_every_phase_and_direction(self):
        args = adaptive_scenario.parse_args([
            "--binary", "unused", "--output", "unused", "--loss", ".20",
            "--phase-seconds", "3", "--outages"])
        for topology in ["independent", "shared"]:
            args.topology = topology
            for phase in phases_for(args):
                self.assertEqual(phase["loss"], .20)
                for index in range(4 if topology == "independent" else 2):
                    shape = adaptive_scenario.phase_shape(args, phase["condition"], index)
                    self.assertEqual(shape.loss, .20)
                    expected = args.congested_mbps if phase["condition"] == "congested" \
                        and (topology == "shared" or index < 2) else args.link_mbps
                    self.assertEqual(shape.rate_bps, round(expected * 1e6))

    def test_loss_and_latency_parser_bounds_preserve_defaults(self):
        base = ["--binary", "unused", "--output", "unused"]
        default = adaptive_scenario.parse_args(base)
        self.assertEqual(default.loss, 0)
        self.assertEqual(default.latency_target_ms, 20)
        configured = adaptive_scenario.parse_args(base + ["--loss", ".2", "--latency-target-ms", "100"])
        self.assertEqual(configured.latency_target_ms, 100)
        for boundary in ["0", "1"]:
            self.assertEqual(adaptive_scenario.parse_args(base + ["--loss", boundary]).loss,
                             float(boundary))
        for option, value in [("--loss", "-.01"), ("--loss", "1.01"), ("--loss", "nan"),
                              ("--latency-target-ms", "0"), ("--latency-target-ms", "1001")]:
            with self.subTest(option=option, value=value), self.assertRaises(SystemExit):
                adaptive_scenario.parse_args(base + [option, value])

    def test_loss_and_latency_are_registered_without_running_a_workload(self):
        (adaptive_scenario.ROOT / "local").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=adaptive_scenario.ROOT / "local") as directory:
            binary = Path(directory) / "unused-binary"
            binary.write_bytes(b"manifest-only test")
            output = Path(directory) / "registered"
            args = adaptive_scenario.parse_args([
                "--binary", str(binary), "--output", str(output), "--dry-run",
                "--loss", ".20", "--latency-target-ms", "100"])
            asyncio.run(adaptive_scenario.experiment(args))
            import json
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["loss"], .20)
            self.assertEqual(manifest["latency_target_ms"], 100)
            self.assertTrue(all(p["loss"] == .20 for p in manifest["phases"]))
            self.assertEqual(manifest["profile"], "rr")
            self.assertEqual([p["seconds"] for p in manifest["phases"]], [4, 12, 12, 12])
            self.assertFalse((output / "commands.json").exists())

    def test_target_one_way_uses_absolute_local_clock_and_all_planned_operations(self):
        phases = [{"name": "window_a", "seconds": 1, "condition": "clean"}]
        stream = SimpleNamespace(pps=4, size=1000, samples=[
            {"window": "window_a", "status": "kernel_accepted", "send_ns": 1_000_000_000,
             "target_ns": 1_200_000_000, "echo_ns": 1_300_000_000},
            {"window": "window_a", "status": "kernel_accepted", "send_ns": 2_000_000_000,
             "target_ns": 2_250_000_000, "echo_ns": 2_350_000_000},
            {"window": "window_a", "status": "generator_late", "send_ns": None,
             "target_ns": None, "echo_ns": None}])
        result = summarize({1: stream}, phases, 200, 0)[0]["streams"]["bulk"]
        self.assertEqual(result["target_one_way_p50_ms"], 250)
        self.assertEqual(result["target_one_way_p95_ms"], "infinity")
        self.assertEqual(result["target_one_way_p99_ms"], "infinity")
        self.assertEqual(result["target_one_way_on_time_operations"], 1)
        self.assertEqual(result["target_one_way_deadline_miss_fraction"], .75)
        self.assertEqual(result["missing_target_operations"], 2)
        self.assertEqual(result["target_one_way_on_time_payload_bytes"], 1000 - HEADER.size)
        self.assertEqual(result["target_one_way_on_time_payload_goodput_bps"], (1000 - HEADER.size) * 8)
        self.assertEqual(result["target_payload_goodput_bps"], 2 * (1000 - HEADER.size) * 8)
        self.assertEqual(result["measurement_header_bytes_excluded_per_record"], HEADER.size)
        self.assertEqual(result["rtt_p50_ms"], 350)
        self.assertEqual(result["target_goodput_bps"], 16000)

    def comparison_window(self, target, on_time, miss):
        return {"name": "window_a", "condition": "clean",
                "streams": {"bulk": {"target_goodput_bps": target,
                                     "on_time_echo_goodput_bps": on_time},
                            "interactive": {"deadline_miss_fraction": miss}}}

    def test_clean_perfect_baseline_requires_no_impossible_positive_gain(self):
        baseline = self.comparison_window(100, 100, 0)
        candidate = self.comparison_window(95, 95, 0)
        self.assertTrue(all(evaluate_window(baseline, candidate)["screening_gates"].values()))

    def test_zero_ontime_baseline_cannot_make_dropping_all_payload_pass(self):
        baseline = self.comparison_window(100, 0, 1)
        candidate = self.comparison_window(0, 0, 1)
        self.assertFalse(evaluate_window(baseline, candidate)["screening_gates"]["target_goodput_retained"])

    def test_recovery_has_availability_gate_when_old_runtime_has_no_payload(self):
        baseline = self.comparison_window(0, 0, 1)
        candidate = self.comparison_window(50, 50, .1)
        result = evaluate_window(baseline, candidate)
        self.assertIsNone(result["target_goodput_ratio"])
        self.assertTrue(result["screening_gates"]["candidate_delivers_without_baseline_reference"])

    def test_absolute_monotonic_latency_and_missing_operations(self):
        phases = [{"name": "window_a", "seconds": 1, "condition": "clean"}]
        stream = SimpleNamespace(pps=2, size=1000, samples=[
            {"window": "window_a", "status": "kernel_accepted",
             "send_ns": 1_000_000_000, "echo_ns": 1_250_000_000, "target_ns": 1_100_000_000}])
        result = summarize({1: stream}, phases, 100, 0)[0]["streams"]["bulk"]
        self.assertEqual(result["planned_operations"], 2)
        self.assertEqual(result["generator_not_issued_operations"], 1)
        self.assertEqual(result["rtt_p50_ms"], 250)
        self.assertEqual(result["rtt_p99_ms"], "infinity")
        self.assertEqual(result["deadline_miss_fraction"], 1)
        self.assertEqual(result["target_goodput_bps"], 8000)
        self.assertEqual(result["on_time_echo_goodput_bps"], 0)

    def test_source_windows_do_not_include_drain_or_shift_at_arrival(self):
        phases = [{"name": "window_a", "seconds": 1, "condition": "clean"},
                  {"name": "window_b", "seconds": 1, "condition": "congested"}]
        self.assertEqual(window_at(phases, .999), "window_a")
        self.assertEqual(window_at(phases, 1), "window_b")
        stream = SimpleNamespace(pps=1, size=1000, samples=[
            {"window": "window_a", "status": "kernel_accepted",
             "send_ns": 1_000_000_000, "echo_ns": 1_050_000_000, "target_ns": 1_025_000_000},
            {"window": "window_b", "status": "kernel_accepted",
             "send_ns": 2_000_000_000, "echo_ns": None, "target_ns": None}])
        windows = summarize({1: stream}, phases, 100, 0)
        self.assertEqual(windows[0]["streams"]["bulk"]["on_time_echo_goodput_bps"], 8000)
        self.assertEqual(windows[1]["streams"]["bulk"]["deadline_miss_fraction"], 1)

    def test_lifecycle_schedule_blackouts_exceed_transport_idle_timeout(self):
        phases = phases_for(SimpleNamespace(phase_seconds=12, outages=True))
        self.assertEqual([p["name"] for p in phases],
                         ["warmup", "window_a", "window_b", "window_c",
                          "window_d", "window_e", "window_f", "window_g"])
        self.assertGreaterEqual(next(p["seconds"] for p in phases if p["condition"] == "all_outage"), 18)
        self.assertGreaterEqual(phases[-1]["seconds"], 15)

    def test_missing_latency_stays_in_quantile_population(self):
        self.assertEqual(quantile([2, 4, float("inf")], .99), "infinity")


if __name__ == "__main__":
    unittest.main()

