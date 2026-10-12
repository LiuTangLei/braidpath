"""Optional four-entry topology crossing one shared access link.

This module only builds/configures owned container namespaces. The caller uses
the existing finite run, readiness, evidence and cleanup lifecycle.
"""

from __future__ import annotations

import math


def shared_plan(client, server, router, rtt_ms, rate_mbps, shared_rate_mbps, queue_packets):
    if (len(rtt_ms) != 4 or any(not math.isfinite(x) or not 1 <= x <= 200 for x in rtt_ms)
        or any(not math.isfinite(x) or not 1 <= x <= 1000 for x in (rate_mbps, shared_rate_mbps))
        or not 32 <= queue_packets <= 4096):
        raise ValueError("invalid finite shared topology settings")
    commands, queues, paths = [], [], []
    for namespace in (client, router, server):
        commands += [["ip", "netns", "add", namespace],
                     ["ip", "-n", namespace, "link", "set", "lo", "up"]]
    bridge_mac = "02:42:00:00:00:03"
    commands += [["ip", "-n", router, "link", "add", "br0", "type", "bridge"],
                 ["ip", "-n", router, "link", "set", "br0", "address", bridge_mac],
                 ["ip", "-n", router, "addr", "add", "10.204.0.2/30", "dev", "br0"],
                 ["ip", "-n", router, "link", "set", "br0", "up"]]

    def link(left_ns, left_device, left_ip, left_mac, right_ns, right_device, right_ip, right_mac,
             rate, delay, purpose):
        commands.extend([
            ["ip", "link", "add", left_device, "type", "veth", "peer", "name", right_device],
            ["ip", "link", "set", left_device, "netns", left_ns],
            ["ip", "link", "set", right_device, "netns", right_ns],
        ])
        for namespace, device, address, mac in ((left_ns, left_device, left_ip, left_mac),
                                               (right_ns, right_device, right_ip, right_mac)):
            commands.append(["ip", "-n", namespace, "link", "set", device, "address", mac])
            if address:
                commands.append(["ip", "-n", namespace, "addr", "add", address, "dev", device])
            commands.extend([
                ["ip", "-n", namespace, "link", "set", device, "up"],
                ["ip", "netns", "exec", namespace, "tc", "qdisc", "add", "dev", device,
                 "root", "netem", "limit", str(queue_packets), "delay", f"{delay:g}ms", "rate", f"{rate:g}mbit"],
            ])
            queues.append({"namespace": namespace, "device": device, "delay_seconds": delay / 1000,
                           "rate_bytes_per_second": rate * 1000000 / 8, "queue_packets": queue_packets,
                           "purpose": purpose})

    client_mac = "02:42:00:00:00:01"
    link(client, "u0c", "10.204.0.1/30", client_mac, router, "u0r", None, "02:42:00:00:00:02",
         shared_rate_mbps, 0, "shared_access")
    commands += [["ip", "-n", router, "link", "set", "u0r", "master", "br0"],
                 ["ip", "-n", client, "neigh", "replace", "10.204.0.2", "lladdr", bridge_mac,
                  "nud", "permanent", "dev", "u0c"],
                 ["ip", "netns", "exec", router, "bridge", "fdb", "replace", client_mac,
                  "dev", "u0r", "master", "static"]]
    for index, rtt in enumerate(rtt_ms):
        source, target = (f"10.203.{index + 1}.{suffix}" for suffix in (1, 2))
        router_device, server_device = f"p{index}c", f"p{index}s"
        router_mac, server_mac = (f"02:42:00:01:{index + 1:02x}:{suffix:02x}" for suffix in (1, 2))
        link(router, router_device, None, router_mac, server, server_device, f"{target}/24", server_mac,
             rate_mbps, rtt / 2, "entry_link")
        commands.extend([
            ["ip", "-n", router, "link", "set", router_device, "master", "br0"],
            ["ip", "-n", client, "addr", "add", f"{source}/24", "dev", "u0c"],
            ["ip", "-n", client, "route", "add", f"{target}/32", "dev", "u0c", "src", source],
            ["ip", "-n", client, "neigh", "replace", target, "lladdr", server_mac,
             "nud", "permanent", "dev", "u0c"],
            ["ip", "-n", server, "neigh", "replace", source, "lladdr", client_mac,
             "nud", "permanent", "dev", server_device],
            ["ip", "netns", "exec", router, "bridge", "fdb", "replace", server_mac,
             "dev", router_device, "master", "static"],
        ])
        paths.append({"path_id": index, "client_bind": f"{source}:{9500 + index}",
                      "entrance": f"{target}:9443", "bottleneck_group": 0,
                      "client_access_device": "u0c", "router_access_device": "u0r",
                      "router_entry_device": router_device, "server_entry_device": server_device,
                      "client_mac": client_mac, "server_mac": server_mac})
    return {
        "topology": "four entrances behind one shared bidirectional access link",
        "client_namespace": client, "server_namespace": server, "router_namespace": router,
        "forwarding": "owned layer-2 bridge with static neighbors and per-entry static FDB",
        "shared_access_mbps": shared_rate_mbps, "entry_link_mbps": rate_mbps,
        "rtt_ms": list(rtt_ms), "random_loss_percent": 0,
        "group_rate_bps": {"0": int(shared_rate_mbps * 1000000)},
        "access_calibration": {"server_namespace": router, "target": "10.204.0.2",
                               "client_address": "10.204.0.1", "bridge_mac": bridge_mac,
                               "physical_rate_mbps": shared_rate_mbps},
        "queues": queues, "paths": paths, "commands": commands,
    }


def setup_shared(bed, args):
    """Integration seam: call instead of Testbed.setup's independent branch."""
    from bench.netem import save
    bed.router = f"{bed.client}-router"
    plan = shared_plan(bed.client, bed.server, bed.router, args.rtt_ms, args.rate_mbps,
                       args.shared_rate_mbps, args.queue_packets)
    save(bed.output / "topology.json", plan)
    for command in plan["commands"]:
        bed.command(command)
        if command[:3] == ["ip", "netns", "add"]:
            bed.owned_namespaces.append(command[3])
        elif command[:3] == ["ip", "link", "add"]:
            bed.owned_links += [command[3], command[-1]]
    return plan


def shared_shaping_errors(qdiscs, plan):
    """Check every actual shaping device, including the one common access link."""
    errors = []
    actual = {(namespace, qdisc.get("dev")): qdisc
              for namespace, entries in qdiscs.items() for qdisc in entries if qdisc.get("kind") == "netem"}
    expected = {(queue["namespace"], queue["device"]) for queue in plan["queues"]}
    if set(actual) != expected:
        errors.append("shared topology netem devices do not match the registered access and entry links")
    for queue in plan["queues"]:
        name = queue["device"]
        qdisc = actual.get((queue["namespace"], name), {})
        options = qdisc.get("options", {})
        delay = options.get("delay", {}).get("delay", 0)
        if abs(delay - queue["delay_seconds"]) > .000002:
            errors.append(f"{name}: propagation delay mismatch")
        if options.get("rate", {}).get("rate") != queue["rate_bytes_per_second"]:
            errors.append(f"{name}: shared/entry byte rate mismatch")
        if options.get("limit") != queue["queue_packets"]:
            errors.append(f"{name}: queue bound mismatch")
        if qdisc.get("drops", 0):
            errors.append(f"{name}: preflight drops")
    return errors
