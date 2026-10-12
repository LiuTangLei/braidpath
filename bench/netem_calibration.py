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


def calibrate_shared(bed, plan, leaf_rate_mbps):
    """Measure each leaf alone, then the common link alone, without a fair-share assumption.

    A shared FIFO can distribute overloaded independent UDP senders unevenly.
    That is a topology behavior, not evidence that a leaf's configured rate is
    wrong. Each individual rate still has the same 85..105 percent check.
    """
    from bench.netem import save

    access = plan["access_calibration"]
    cases = [(f"leaf-{i}", bed.server, path["entrance"].split(":")[0],
              9300 + i, leaf_rate_mbps) for i, path in enumerate(plan["paths"])]
    cases.append(("access", access["server_namespace"], access["target"],
                  9310, plan["shared_access_mbps"]))
    result = {"passed": False, "method": "four individual leaf links, then isolated common access link",
              "duration_seconds_each": 3, "range": "85..105 percent of each configured rate",
              "scope": "testbed calibration, not application performance acceptance",
              "paths": [], "before_qdiscs": bed.qdiscs()}
    for label, namespace, target, port, rate in cases:
        server, _ = bed.spawn(namespace, f"calibration-{label}-server",
                              ["iperf3", "-s", "-1", "-J", "-B", target, "-p", str(port)])
        deadline = time.monotonic() + 5
        while True:
            listeners = bed.command(["ip", "netns", "exec", namespace, "ss", "-H", "-ltn"]).stdout
            if f":{port}" in listeners:
                break
            if server.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError(f"{label} calibration listener not ready")
            time.sleep(.05)
        source, _ = bed.spawn(bed.client, f"calibration-{label}-source",
                              ["iperf3", "-c", target, "-p", str(port), "-u",
                               "-b", f"{rate * 1.4:g}M", "-l", "1000", "-t", "3", "-J"])
        for process in (source, server):
            process.wait(timeout=12)
            if process.returncode:
                raise RuntimeError(f"{label} rate calibration process failed")
        observed = receiver_rate(json.loads((bed.output / f"calibration-{label}-source.log").read_text()))
        passed = .85 * rate <= observed <= 1.05 * rate
        result["paths"].append({"link": label, "configured_mbps": rate,
                                "receiver_udp_payload_mbps": observed,
                                "within_calibration_range": passed})
        result["after_qdiscs"] = bed.qdiscs()
        save(bed.output / "rate-calibration.json", result)
        if not passed:
            raise RuntimeError(f"{label} actual UDP rate outside testbed calibration range")
    result["passed"] = True
    save(bed.output / "rate-calibration.json", result)
