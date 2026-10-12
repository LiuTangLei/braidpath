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
        if namespace == router:
            commands.append(["ip", "netns", "exec", namespace, "sysctl", "-w", "net.ipv4.ip_forward=1"])
        for key in ("all", "default"):
            commands.append(["ip", "netns", "exec", namespace, "sysctl", "-w",
                             f"net.ipv4.conf.{key}.rp_filter=0"])

    def link(left_ns, left_device, left_ip, right_ns, right_device, right_ip, rate, delay, purpose):
        commands.extend([
            ["ip", "link", "add", left_device, "type", "veth", "peer", "name", right_device],
            ["ip", "link", "set", left_device, "netns", left_ns],
            ["ip", "link", "set", right_device, "netns", right_ns],
        ])
        for namespace, device, address in ((left_ns, left_device, left_ip), (right_ns, right_device, right_ip)):
            commands.extend([
                ["ip", "-n", namespace, "addr", "add", address, "dev", device],
                ["ip", "-n", namespace, "link", "set", device, "up"],
                ["ip", "netns", "exec", namespace, "tc", "qdisc", "add", "dev", device,
                 "root", "netem", "limit", str(queue_packets), "delay", f"{delay:g}ms", "rate", f"{rate:g}mbit"],
            ])
            queues.append({"namespace": namespace, "device": device, "delay_seconds": delay / 1000,
                           "rate_bytes_per_second": rate * 1000000 / 8, "queue_packets": queue_packets,
                           "purpose": purpose})

    link(client, "u0c", "10.204.0.1/30", router, "u0r", "10.204.0.2/30",
         shared_rate_mbps, 0, "shared_access")
    for index, rtt in enumerate(rtt_ms):
        source, target, gateway = (f"10.203.{index + 1}.{suffix}" for suffix in (1, 2, 254))
        router_device, server_device = f"p{index}c", f"p{index}s"
        link(router, router_device, f"{gateway}/24", server, server_device, f"{target}/24",
             rate_mbps, rtt / 2, "entry_link")
        commands.extend([
            ["ip", "-n", client, "addr", "add", f"{source}/32", "dev", "lo"],
            ["ip", "-n", client, "route", "add", f"{target}/32", "via", "10.204.0.2", "dev", "u0c", "src", source],
            ["ip", "-n", router, "route", "add", f"{source}/32", "via", "10.204.0.1", "dev", "u0r"],
            ["ip", "-n", server, "route", "add", f"{source}/32", "via", gateway, "dev", server_device],
        ])
        paths.append({"path_id": index, "client_bind": f"{source}:{9500 + index}",
                      "entrance": f"{target}:9443", "bottleneck_group": 0,
                      "client_access_device": "u0c", "router_access_device": "u0r",
                      "router_entry_device": router_device, "server_entry_device": server_device})
    return {
        "topology": "four entrances behind one shared bidirectional access link",
        "client_namespace": client, "server_namespace": server, "router_namespace": router,
        "shared_access_mbps": shared_rate_mbps, "entry_link_mbps": rate_mbps,
        "rtt_ms": list(rtt_ms), "random_loss_percent": 0,
        "group_rate_bps": {"0": int(shared_rate_mbps * 1000000)},
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
