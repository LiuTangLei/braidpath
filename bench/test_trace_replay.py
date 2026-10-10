"""Exact synchronization, gaps and attribution tests using tiny native traces."""
import json
from pathlib import Path
import tempfile
import unittest

from bench.trace_replay import Replay, pack


class TraceTests(unittest.TestCase):
    def fixture(self, root, name, times, missing):
        for role in ["source", "receiver"]:
            folder = root / (role + "-" + name)
            folder.mkdir()
            samples = [dict(seq=seq, send_unix_us=stamp if role == "source" or not lost else None,
                            receive_unix_us=None if role == "source" or lost else stamp + 100,
                            missing=True if role == "source" else lost)
                       for seq, (stamp, lost) in enumerate(zip(times, missing))]
            (folder / "samples.json").write_text(json.dumps(dict(samples=samples)))
            (folder / "result.json").write_text(json.dumps(dict(outcome="ok", run_id=name,
                                                               sent=len(times), local_addr="fixture")))

    def test_shared_clock_preserves_correlated_bursts_and_empty_sender_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            raw = Path(temp)
            self.fixture(raw, "a", [1000, 1001, 9000, 9001], [False, True, True, False])
            self.fixture(raw, "b", [1003, 1004, 9000, 9005], [True, True, True, False])
            pack(raw, raw / "packed", ["a", "b"])
            with Replay(raw / "packed") as replay:
                events = list(replay.events())
                self.assertEqual([row[0] for row in events], [0, 1, 3, 4, 8000, 8000, 8001, 8005])
                self.assertEqual([row[:3] for row in events if row[3] is None],
                                 [(1, 0, 1), (3, 1, 0), (4, 1, 1), (8000, 0, 2), (8000, 1, 2)])
                self.assertEqual(len(events), 8)
                self.assertEqual(events[-1][3], 9105)
            with self.assertRaises(FileExistsError):
                pack(raw, raw / "packed", ["a", "b"])

    def test_local_drop_deltas_remain_separate_and_never_change_packet_masks(self):
        with tempfile.TemporaryDirectory() as temp:
            raw = Path(temp)
            self.fixture(raw, "a", [1000, 9000], [True, False])
            relay = raw / "relay-a"
            relay.mkdir()
            rows = [dict(sample_unix_ms=stamp, stats=dict(relay=dict(server_to_client=dict(
                    budget_dropped=lost, queue_full_dropped=0)))) for stamp, lost in [(0, 2), (100, 5), (200, 5)]]
            rows.insert(0, dict(sample_unix_ms=-100, stats=dict(relay={})))
            (relay / "stats.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            manifest = pack(raw, raw / "packed", ["a"])
            sideband = manifest["relay"]["a"]
            self.assertFalse(sideband["applied_to_replay"])
            self.assertFalse(sideband["clock_calibrated_to_sender"])
            self.assertIsNone(sideband["packet_id_attribution"])
            self.assertEqual([row["drops"]["budget_dropped"] for row in sideband["intervals"]], [2, 3])
            with Replay(raw / "packed") as replay:
                self.assertEqual(sum(row[3] is None for row in replay.events()), 1)

    def test_bad_sender_clock_and_binary_corruption_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            raw = Path(temp)
            self.fixture(raw, "a", [2000, 1000], [False, False])
            with self.assertRaisesRegex(ValueError, "source sequence/timestamp"):
                pack(raw, raw / "invalid", ["a"])
            self.fixture(raw, "b", [1000, 2000], [False, True])
            pack(raw, raw / "packed", ["b"])
            binary = raw / "packed" / "path-0.bin"
            content = bytearray(binary.read_bytes())
            content[-1] ^= 1
            binary.write_bytes(content)
            with self.assertRaisesRegex(ValueError, "digest"):
                Replay(raw / "packed")


if __name__ == "__main__":
    unittest.main()
