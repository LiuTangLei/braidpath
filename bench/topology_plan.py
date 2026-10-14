"""Pure finite topology-discovery registration; concrete routes stay local.

No networking, filesystem writes or inferred capacities. The first survey is
cold-start diagnosis, not proof of sustained or native-equivalent performance.
"""
from collections import Counter
from bench.delivery_frontier import EvidenceError, integer


def make_plan(routes, *, parallel_route, duration_seconds=10, bulk_pps=40_000):
    routes = list(routes)
    if not 2 <= len(routes) <= 4 or len(set(routes)) != len(routes):
        raise EvidenceError("this finite survey requires two to four distinct routes")
    if any(not isinstance(r, str) or not r or len(r) > 64 for r in routes):
        raise EvidenceError("route names must be short nonempty strings")
    if parallel_route not in routes:
        raise EvidenceError("parallel control must use a predeclared single route")
    if integer(duration_seconds, "duration_seconds") != 10:
        raise EvidenceError("the first cold survey is fixed at ten source seconds")
    if integer(bulk_pps, "bulk_pps") != 40_000:
        raise EvidenceError("the first survey retains 320Mbps nominal datagram input")
    modes = {"solo_" + str(i): {"kind": "single", "routes": [r],
                               "connections": 1, "entrances": [r]}
             for i, r in enumerate(routes)}
    modes["parallel"] = {"kind": "same_route_multi", "routes": [parallel_route],
                         "connections": len(routes), "entrances": [parallel_route] * len(routes)}
    modes["aggregate"] = {"kind": "multipath", "routes": routes,
                          "connections": len(routes), "entrances": routes}
    forward = list(modes)
    order = [{"window": "window_" + chr(97 + i), "mode": name}
             for i, name in enumerate(forward + forward[::-1])]
    assert len(order) <= 12 and all(n == 2 for n in Counter(r["mode"] for r in order).values())
    return {
        "schema_version": 1, "phase": "P1_cold_topology_discovery",
        "minimum_goodput_ratio": 1.5, "maximum_p95_ratio": 1.0,
        "minimum_on_time_fraction": .95, "required_single_routes": routes,
        "candidate_mode": "aggregate", "modes": modes, "order": order,
        "common": {"service": "unreliable_datagrams", "carrier": "http3_quic_datagram",
                   "native_cc": "bbr", "crypto": "same_frozen_binary_tls13",
                   "payload_bytes": 964, "total_rate_cap_bps": 500_000_000,
                   "offered_payload_bps": bulk_pps * 964 * 8,
                   "warmup_seconds": 0, "deadline_ms": 200,
                   "deadline_basis": "source_echo_rtt", "coding_profile": "uncoded_no_copies",
                   "host_fixture": "must_bind_before_freeze"},
        "source": {"duration_seconds": duration_seconds, "datagram_bytes": 1000,
                   "bulk_pps": bulk_pps, "bulk_count": bulk_pps * duration_seconds,
                   "echo_bytes": 128, "echo_pps": 20, "echo_count": 20 * duration_seconds,
                   "drain_ms": 3000},
        "limits": {"no_completed_workload_retries": True, "cold_session_each_window": True,
                   "inter_window_cooldown_seconds": 20,
                   "maximum_nominal_business_seconds": len(order) * duration_seconds,
                   "maximum_windows": len(order), "queue_ms": 100,
                   "group_rate_cap_bps": 500_000_000, "datagram_send_buffer_bytes": 9600,
                   "frontier_scheduler": False, "fec": 0, "small_fec_bytes": 0,
                   "redundancy_percent": 0, "adaptive": True},
        "acceptance_scope": "short cold-start engineering comparison, not release or sustained capacity",
        "native_reference_completed": False, "best_parallel_route_identified": False,
        "steady_state_confirmed": False,
    }
