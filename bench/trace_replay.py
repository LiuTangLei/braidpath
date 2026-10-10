"""Pack and replay synchronized native UDP samples on a virtual clock.

The common sender clock and every packet outcome are retained. Relay counters
are sideband evidence: without packet IDs they cannot be subtracted from the
end-to-end loss mask or applied a second time. No network traffic is generated.
"""
import argparse
from array import array
import hashlib
import heapq
import json
import mmap
from pathlib import Path
import struct

RECORD = struct.Struct("<QQ")  # sender UNIX us, receiver UNIX us (zero = missing)
MAX_PACKETS = 1_000_000
MAX_JSON_BYTES = 192 * 1024 * 1024
MAX_PATHS = 4


def read_json(path):
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("sample file exceeds the bounded input size")
    return json.loads(path.read_text())


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def relay_intervals(path):
    """Keep cumulative deltas on the relay's own, uncalibrated clock."""
    previous = None
    rows = []
    with path.open() as stream:
        for line in stream:
            if len(line) > 1024 * 1024:
                raise ValueError("relay record exceeds bounded input size")
            row = json.loads(line)
            counters = row["stats"]["relay"].get("server_to_client", {})
            drops = {key: value for key, value in counters.items() if key.endswith("_dropped")}
            stamp = row["sample_unix_ms"]
            if previous:
                if stamp < previous[0] or any(value < previous[1].get(key, 0) for key, value in drops.items()):
                    raise ValueError("relay clock or cumulative counters regressed")
                if previous[1] and not drops:
                    raise ValueError("active relay counters disappeared")
            delta = {key: value - (previous[1].get(key, 0) if previous else 0) for key, value in drops.items()}
            if any(delta.values()):
                rows.append(dict(start_relay_unix_ms=previous[0] if previous else None,
                                 end_relay_unix_ms=stamp, drops=delta))
            previous = stamp, drops
            if len(rows) > 100_000:
                raise ValueError("relay intervals exceed the bounded input size")
    return {"clock_calibrated_to_sender": False, "packet_id_attribution": None,
            "includes_control_datagrams": True, "applied_to_replay": False,
            "totals": previous[1] if previous else {}, "intervals": rows}


def pack(raw, destination, paths):
    if not 1 <= len(paths) <= MAX_PATHS or len(set(paths)) != len(paths):
        raise ValueError("expected one to four distinct paths")
    destination.mkdir()  # refuse to overwrite any previous evidence
    manifest = {"schema_version": 1, "record_format": "<QQ", "paths": [],
                "loss_scope": "end_to_end_including_unattributed_local_loss",
                "delay_scope": "raw receiver clock; no absolute one-way delay inference",
                "relay": {}, "sources": {}}
    for index, name in enumerate(paths):
        source_file = raw / ("source-" + name) / "samples.json"
        receiver_file = raw / ("receiver-" + name) / "samples.json"
        source = read_json(source_file)["samples"]
        if not 0 < len(source) <= MAX_PACKETS:
            raise ValueError("packet population exceeds bound")
        times = array("Q")
        for seq, sample in enumerate(source):
            stamp = sample["send_unix_us"]
            if sample["seq"] != seq or stamp is None or (times and stamp < times[-1]):
                raise ValueError("source sequence/timestamp mismatch")
            times.append(stamp)
        del source
        receiver = read_json(receiver_file)["samples"]
        if len(receiver) != len(times):
            raise ValueError("source/receiver populations differ")
        source_result = read_json(source_file.with_name("result.json"))
        receiver_result = read_json(receiver_file.with_name("result.json"))
        if (source_result["outcome"] != "ok" or receiver_result["outcome"] != "ok"
                or source_result["run_id"] != receiver_result["run_id"]
                or source_result["sent"] != len(times)):
            raise ValueError("failed or mismatched native run")
        filename = f"path-{index}.bin"
        lost = 0
        with (destination / filename).open("xb") as output:
            for seq, sample in enumerate(receiver):
                received = sample["receive_unix_us"]
                if sample["seq"] != seq or sample["missing"] != (received is None):
                    raise ValueError("receiver sequence/outcome mismatch")
                if received is not None and sample["send_unix_us"] != times[seq]:
                    raise ValueError("native echoed sender timestamp mismatch")
                lost += received is None
                output.write(RECORD.pack(times[seq], received or 0))
        manifest["paths"].append(dict(name=name, file=filename, packets=len(times), lost=lost,
                                      first_unix_us=times[0], last_unix_us=times[-1],
                                      sha256=digest(destination / filename),
                                      run_id=source_result["run_id"],
                                      source_addr=source_result["local_addr"],
                                      receiver_addr=receiver_result["local_addr"]))
        del receiver
        manifest["sources"][name] = {"source_sha256": digest(source_file),
                                      "receiver_sha256": digest(receiver_file)}
        relay = raw / ("relay-" + name) / "stats.jsonl"
        if relay.exists():
            manifest["relay"][name] = relay_intervals(relay)
            manifest["sources"][name]["relay_sha256"] = digest(relay)
    manifest["origin_unix_us"] = min(path["first_unix_us"] for path in manifest["paths"])
    with (destination / "manifest.json").open("x") as output:
        json.dump(manifest, output, indent=2)
        output.write("\n")
    return manifest


class Replay:
    """At most four memory-mapped streams; no wall-clock sleeps or packet queues."""
    def __init__(self, directory):
        self.manifest = read_json(directory / "manifest.json")
        paths = self.manifest["paths"]
        if not 1 <= len(paths) <= MAX_PATHS:
            raise ValueError("invalid path bound")
        self.streams = []
        self.maps = []
        try:
            for path in paths:
                filename = directory / path["file"]
                if (not 0 < path["packets"] <= MAX_PACKETS
                        or filename.stat().st_size != path["packets"] * RECORD.size
                        or digest(filename) != path["sha256"]):
                    raise ValueError("invalid packed trace size or digest")
                stream = filename.open("rb")
                self.streams.append(stream)
                self.maps.append(mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ))
        except BaseException:
            self.close()
            raise

    def record(self, path, seq):
        return RECORD.unpack_from(self.maps[path], seq * RECORD.size)

    def events(self):
        heap = [(self.record(index, 0)[0], index, 0) for index in range(len(self.maps))]
        heapq.heapify(heap)
        previous = self.manifest["origin_unix_us"]
        while heap:
            stamp, path, seq = heapq.heappop(heap)
            if stamp < previous:
                raise ValueError("non-monotonic sender clock")
            previous = stamp
            received = self.record(path, seq)[1]
            yield stamp - self.manifest["origin_unix_us"], path, seq, received or None
            if seq + 1 < self.manifest["paths"][path]["packets"]:
                heapq.heappush(heap, (self.record(path, seq + 1)[0], path, seq + 1))

    def close(self):
        for mapping in self.maps:
            mapping.close()
        for stream in self.streams:
            stream.close()
        self.maps = []
        self.streams = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--paths", nargs="+", required=True)
    args = parser.parse_args()
    result = pack(args.raw, args.destination, args.paths)
    print(json.dumps({"origin_unix_us": result["origin_unix_us"],
                      "packets": sum(path["packets"] for path in result["paths"])}))


if __name__ == "__main__":
    main()
