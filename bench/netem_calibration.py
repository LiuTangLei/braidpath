"""Finite UDP rate calibration for the isolated netem testbed."""

import json
import time


def receiver_rate(result):
    """Use receiver-observed UDP delivery, never the configured sender rate."""
    if result.get("error"):
        raise ValueError(result["error"])
    received = result["end"].get("sum_received")
    if received is None:
        received = result["end"]["sum"]
    if received.get("sender") is True:
        raise ValueError("receiver rate unavailable")
    return received["bits_per_second"] / 1_000_000


def calibrate_links(bed, targets, rate_mbps):
    """Four simultaneous, three-second UDP tests, each over its own shaped link.

    Calibration deliberately offers more than the configured rate. Its drops
    remain in raw counters, separately from the subsequent business workload.
    The caller owns process cleanup and must snapshot workload counters anew.
    """
    from bench.netem import save

    before = bed.qdiscs()
    servers, sources = [], []
    for index, target in enumerate(targets):
        process, _ = bed.spawn(bed.server, f"calibration-server-{index}",
                              ["iperf3", "-s", "-1", "-J", "-B", target,
                               "-p", str(9300 + index)])
        servers.append(process)
    # Check actual listener sockets before launching clients; no traffic warmup.
    deadline = time.monotonic() + 5
    while True:
        listeners = bed.command(["ip", "netns", "exec", bed.server, "ss", "-H", "-ltn"]).stdout
        if all(f":{9300 + i}" in listeners for i in range(len(targets))):
            break
        if any(p.poll() is not None for p in servers) or time.monotonic() > deadline:
            raise RuntimeError("UDP calibration control listeners not ready")
        time.sleep(.05)
    for index, target in enumerate(targets):
        process, _ = bed.spawn(bed.client, f"calibration-source-{index}",
                              ["iperf3", "-c", target, "-p", str(9300 + index),
                               "-u", "-b", f"{rate_mbps * 1.4:g}M", "-l", "1000",
                               "-t", "3", "-J"])
        sources.append(process)
    for process in [*sources, *servers]:
        process.wait(timeout=12)
        if process.returncode:
            raise RuntimeError("UDP rate calibration process failed")
    observed = []
    for index in range(len(targets)):
        result = json.loads((bed.output / f"calibration-source-{index}.log").read_text())
        rate = receiver_rate(result)
        observed.append({"path_id": index, "configured_link_mbps": rate_mbps,
                         "receiver_udp_payload_mbps": rate,
                         "within_calibration_range": .85 * rate_mbps <= rate <= 1.05 * rate_mbps})
    passed = all(x["within_calibration_range"] for x in observed)
    save(bed.output / "rate-calibration.json", {
        "passed": passed, "duration_seconds": 3, "offered_per_path_mbps": rate_mbps * 1.4,
        "range": "85..105 percent of shaped rate; UDP payload excludes link headers",
        "scope": "testbed calibration, not application performance acceptance",
        "paths": observed, "before_qdiscs": before, "after_qdiscs": bed.qdiscs(),
    })
    if not passed:
        raise RuntimeError("actual UDP rate outside testbed calibration range")
