import copy
import unittest
from types import SimpleNamespace

from bench.netem import client_path_arguments
from bench.netem_shared import shared_plan, shared_shaping_errors


class SharedPhysicalTopology(unittest.TestCase):
    def setUp(self):
        self.plan = shared_plan("client", "server", "router", [30, 45, 60, 80], 100, 400, 1024)

    def test_four_distinct_tuples_route_through_one_common_access_link(self):
        paths = self.plan["paths"]
        self.assertEqual(len({(p["client_bind"], p["entrance"]) for p in paths}), 4)
        self.assertEqual(len({p["client_bind"].split(":")[0] for p in paths}), 4)
        access = [q for q in self.plan["queues"] if q["purpose"] == "shared_access"]
        self.assertEqual({(q["namespace"], q["device"]) for q in access},
                         {("client", "u0c"), ("router", "u0r")})
        self.assertEqual(len(access), 2)  # Two directions of one physical veth link.
        routes = [argv for argv in self.plan["commands"] if argv[:4] == ["ip", "-n", "client", "route"]]
        self.assertEqual(len(routes), 4)
        self.assertTrue(all(argv[argv.index("via") + 1] == "10.204.0.2" for argv in routes))
        self.assertTrue(all(argv[argv.index("dev") + 1] == "u0c" for argv in routes))
        self.assertEqual({p["bottleneck_group"] for p in paths}, {0})
        self.assertEqual(self.plan["group_rate_bps"], {"0": 400000000})

    def test_runtime_uses_one_bounded_group_and_preserves_independent_default(self):
        shared = client_path_arguments(SimpleNamespace(topology="shared", shared_rate_mbps=400))
        groups = [shared[i + 1] for i, value in enumerate(shared) if value == "--path-group"]
        self.assertEqual(groups, ["0"] * 4)
        self.assertEqual(shared[-2:], ["--group-rate-bps", "0:400000000"])
        independent = client_path_arguments(SimpleNamespace())
        self.assertEqual([independent[i + 1] for i, value in enumerate(independent) if value == "--path-group"],
                         ["0", "1", "2", "3"])
        self.assertNotIn("--group-rate-bps", independent)
        for flag in ("--entrance", "--path-bind"):
            self.assertEqual([shared[i + 1] for i, value in enumerate(shared) if value == flag],
                             [independent[i + 1] for i, value in enumerate(independent) if value == flag])

    def test_return_host_routes_prevent_direct_arp_for_virtual_client_addresses(self):
        routes = [argv for argv in self.plan["commands"] if "route" in argv]
        for path in self.plan["paths"]:
            source = path["client_bind"].split(":")[0] + "/32"
            router_routes = [r for r in routes if r[2] == "router" and r[5] == source]
            server_routes = [r for r in routes if r[2] == "server" and r[5] == source]
            self.assertEqual(len(router_routes), 1)
            self.assertEqual(len(server_routes), 1)
            self.assertEqual(router_routes[0][router_routes[0].index("dev") + 1], "u0r")
            self.assertEqual(server_routes[0][server_routes[0].index("dev") + 1], path["server_entry_device"])
        changes = [argv for argv in self.plan["commands"] if "sysctl" in argv]
        self.assertTrue(all(argv[:3] == ["ip", "netns", "exec"] for argv in changes))
        self.assertEqual([argv[3] for argv in changes if argv[-1] == "net.ipv4.ip_forward=1"], ["router"])

    def test_shared_rate_and_leaf_delay_are_verified_separately(self):
        qdiscs = {name: [] for name in ("client", "server", "router")}
        for queue in self.plan["queues"]:
            qdiscs[queue["namespace"]].append({"kind": "netem", "dev": queue["device"], "drops": 0,
                "options": {"delay": {"delay": queue["delay_seconds"]},
                    "rate": {"rate": queue["rate_bytes_per_second"]}, "limit": queue["queue_packets"]}})
        self.assertEqual(shared_shaping_errors(qdiscs, self.plan), [])
        wrong = copy.deepcopy(qdiscs)
        wrong["client"][0]["options"]["rate"]["rate"] *= 4
        self.assertIn("u0c: shared/entry byte rate mismatch", shared_shaping_errors(wrong, self.plan))
        del wrong["router"][0]
        self.assertTrue(any("registered access" in error for error in shared_shaping_errors(wrong, self.plan)))


if __name__ == "__main__":
    unittest.main()
