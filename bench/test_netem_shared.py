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
        self.assertTrue(all("via" not in argv for argv in routes))
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

    def test_common_link_calibration_targets_bridge_without_crossing_a_leaf(self):
        calibration = self.plan["access_calibration"]
        self.assertEqual(calibration["server_namespace"], "router")
        self.assertEqual(calibration["physical_rate_mbps"], 400)
        self.assertNotIn(calibration["target"], {p["entrance"].split(":")[0] for p in self.plan["paths"]})
        self.assertNotIn(calibration["client_address"], {p["client_bind"].split(":")[0] for p in self.plan["paths"]})
        self.assertNotIn(calibration["bridge_mac"], {p["client_mac"] for p in self.plan["paths"]}
                         | {p["server_mac"] for p in self.plan["paths"]})
        commands = self.plan["commands"]
        addresses = [command for command in commands if "addr" in command and command[2] == "router"]
        self.assertEqual(addresses, [["ip", "-n", "router", "addr", "add", "10.204.0.2/30", "dev", "br0"]])
        neighbor = [command for command in commands if "neigh" in command and command[5] == calibration["target"]]
        self.assertEqual(len(neighbor), 1)
        self.assertEqual(neighbor[0][neighbor[0].index("lladdr") + 1], calibration["bridge_mac"])
        self.assertEqual(neighbor[0][neighbor[0].index("dev") + 1], "u0c")

    def test_static_neighbors_and_bridge_fdb_preserve_each_paths_leaf_affinity(self):
        self.assertFalse(any("sysctl" in command for command in self.plan["commands"]))
        bridge_ports = [command for command in self.plan["commands"] if "master" in command and "bridge" not in command]
        self.assertEqual({command[5] for command in bridge_ports}, {"u0r", "p0c", "p1c", "p2c", "p3c"})
        self.assertTrue(all(command[command.index("master") + 1] == "br0" for command in bridge_ports))
        neighbors = [command for command in self.plan["commands"] if "neigh" in command]
        forwarding = [command for command in self.plan["commands"] if "fdb" in command]
        for path in self.plan["paths"]:
            target = path["entrance"].split(":")[0]
            source = path["client_bind"].split(":")[0]
            client_neighbor = [command for command in neighbors if command[2] == "client" and command[5] == target]
            server_neighbor = [command for command in neighbors if command[2] == "server" and command[5] == source]
            self.assertEqual(len(client_neighbor), 1)
            self.assertEqual(len(server_neighbor), 1)
            self.assertEqual(client_neighbor[0][client_neighbor[0].index("lladdr") + 1], path["server_mac"])
            self.assertEqual(client_neighbor[0][client_neighbor[0].index("dev") + 1], "u0c")
            self.assertEqual(server_neighbor[0][server_neighbor[0].index("lladdr") + 1], path["client_mac"])
            self.assertEqual(server_neighbor[0][server_neighbor[0].index("dev") + 1], path["server_entry_device"])
            entry = [command for command in forwarding if command[7] == path["server_mac"]]
            self.assertEqual(len(entry), 1)
            self.assertEqual(entry[0][entry[0].index("dev") + 1], path["router_entry_device"])
            self.assertIn("static", entry[0])

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
