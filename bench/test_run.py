"""Offline benchmark contracts: no SSH, credentials, services, or WAN workload."""
import io
import json
import signal
import sys
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from bench.run import (AttemptFailure, Firewall, Job, REMOTE, WRAPPER, Remote, Runner,
                       aggregate_artifacts, last_snapshot, private_path,
                       schedule, split_load, summary, validate)


def configuration():
    # Deliberately non-routable symbolic strings; never a deployed topology.
    topology = {
        "hosts": {"source": {"ssh": "source-alias", "binary": "/fixture/binary", "workdir": "/fixture/runs", "interface": "fixture-interface"},
                  "destination": {"ssh": "destination-alias", "binary": "/fixture/binary", "workdir": "/fixture/runs"}},
        "client_host": "source", "server_host": "destination",
        "tls": {"server_name": "fixture-name", "ca": "/fixture/ca", "cert": "/fixture/cert", "key": "/fixture/key", "token_file": "/fixture/token"},
        "addresses": {"client_listen": "client-bind", "server_listen": "server-bind", "server_target": "target-bind", "raw_listen": "raw-bind", "raw_target": "raw-target"},
        "paths": {"direct": {"entrance": "server-entrance", "raw_entrance": "raw-entrance"}},
    }
    matrix = {"duration_seconds": 2, "repeats": 2, "order": "abba", "retry_startup": 0,
              "cases": [{"name": "paired", "path": "direct", "direction": "echo", "pps": 12, "profiles": ["bbr", "bbr_fec4"]}],
              "profiles": {"bbr": {"transport": "braidpath", "fec": 0, "congestion": "bbr"}, "bbr_fec4": {"transport": "braidpath", "fec": 4, "congestion": "bbr"}}}
    return topology, matrix


def report(mode="echo", pid=123, count=10, lost=1, run_id="fixture-run"):
    return {"command": "probe", "mode": mode, "final": True, "outcome": "ok", "pid": pid, "sample_unix_ms": 2000, "run_id": run_id,
            "received": count-lost, "lost": lost, "late": 1, "quantile_population": count, "requested_count": count,
            "expected_count": count, "sent": count, "p50_ms": 1, "p95_ms": "infinity", "p99_ms": "infinity",
            "useful_goodput_bps": 100, "local_addr": "socket-one", "peer_addr": "same-target"}


def artifact(value, samples=None, code=0):
    return {"files": {"result.json": json.dumps(value), "samples.json": json.dumps({"samples": samples or []}), "exit.json": json.dumps({"returncode": code})}, "alive": False, "pid": value["pid"]}


class ScheduleTests(unittest.TestCase):
    def test_abba_and_alternating_three_profiles(self):
        _, matrix = configuration()
        self.assertEqual([r["profile"] for r in schedule(matrix)], ["bbr", "bbr_fec4", "bbr_fec4", "bbr"])
        matrix["cases"][0]["profiles"] = ["single", "three0", "three4"]
        matrix.update(order="alternating", repeats=3)
        rows = schedule(matrix)
        self.assertEqual([r["profile"] for r in rows], ["single", "three0", "three4", "three4", "three0", "single", "single", "three0", "three4"])
        self.assertEqual(len(set(r["row_id"] for r in rows)), 9)

    def test_load_is_total_and_integer(self):
        self.assertEqual(split_load(25, 15, 4), [(7, 105), (6, 90), (6, 90), (6, 90)])
        self.assertEqual(sum(p for p, _ in split_load(25, 15, 4)), 25)
        self.assertEqual(sum(c for _, c in split_load(25, 15, 4)), 375)

    def test_source_port_pools_are_topology_only_and_bounded(self):
        topology, matrix = configuration()
        topology["path_bind_ports"] = {"direct": [40000, 40001]}
        validate(topology, matrix)
        for ports in [[], [40000,40000], [0], [65536]]:
            topology["path_bind_ports"]["direct"] = ports
            with self.assertRaises(ValueError):
                validate(topology, matrix)

    def test_validation_rejects_multiflow_direction_and_matrix_addresses(self):
        topology, matrix = configuration()
        validate(topology, matrix)
        matrix["profiles"]["bbr"] = {"transport": "raw-udp", "flows": 4}
        matrix["cases"][0]["direction"] = "client_to_server"
        with self.assertRaisesRegex(ValueError, "only for raw"):
            validate(topology, matrix)
        matrix["cases"][0]["direction"] = "echo"
        matrix["profiles"]["bbr"]["listen"] = "private-address"
        with self.assertRaisesRegex(ValueError, "topology only"):
            validate(topology, matrix)

    def test_output_cannot_escape_local(self):
        with self.assertRaises(ValueError):
            private_path("bench/evidence")
        self.assertTrue(str(private_path("local/fixture-run")).endswith("local/fixture-run"))

    def test_last_jsonl_sample_not_cumulative_sum(self):
        self.assertEqual(last_snapshot('{"n":1}\n{"n":2}\n{"n":'), {"n": 2})


class MetricTests(unittest.TestCase):
    def test_missing_infinity_and_final_counters_preserved(self):
        value = report()
        data = artifact(value)
        data["files"].update({"stats.json": json.dumps({"stats": {"handshake_failures": 2}}), "stats.jsonl": '{"stats":{"handshake_failures":1}}\n'})
        result = aggregate_artifacts({"probe-0": data}, "echo")
        self.assertEqual(result["delivery"]["lost"], 1)
        self.assertEqual(result["delivery"]["on_time"], 8)
        self.assertEqual(result["delivery"]["latency_by_flow"][0]["p99_ms"], "infinity")
        self.assertEqual(result["handshake"]["probe-0"]["handshake_failures"], 2)

    def test_nonzero_exit_not_overridden_by_json_success(self):
        result = aggregate_artifacts({"probe-0": artifact(report(), code=1)}, "echo")
        self.assertIn("probe-0: nonzero or missing exit status", result["errors"])

    def test_sender_receiver_reconciliation(self):
        sender, receiver = report(mode="send"), report(mode="receive")
        sender["sent"] = 9
        sender["actual_offered_load_bps"] = 99
        receiver["sent"] = None
        result = aggregate_artifacts({"probe-0": artifact(sender), "sink": artifact(receiver)}, "client_to_server")
        self.assertFalse(result["sender_receiver"]["source_complete"])
        self.assertEqual(result["sender_receiver"]["actual_offered_load_bps"], 99)
        self.assertTrue(any("not proven network loss" in e for e in result["errors"]))

    def test_multiflow_ports_and_overlap(self):
        a, b = report(), report(pid=124)
        b["local_addr"] = "socket-two"
        times_a = [{"send_unix_us": n} for n in (0, 1000)]
        times_b = [{"send_unix_us": n} for n in (50, 1050)]
        result = aggregate_artifacts({"probe-0": artifact(a, times_a), "probe-1": artifact(b, times_b)}, "echo")
        self.assertEqual(result["multiflow"]["sender_overlap_fraction_by_flow"], [.95, .95])
        self.assertFalse(result["errors"])
        b["local_addr"] = a["local_addr"]
        result = aggregate_artifacts({"probe-0": artifact(a, times_a), "probe-1": artifact(b, [{"send_unix_us": 900}, {"send_unix_us": 1900}])}, "echo")
        self.assertTrue(any("distinct local" in e for e in result["errors"]))
        self.assertTrue(any("less than 90%" in e for e in result["errors"]))

    def test_primary_and_retry_denominators_separate(self):
        results = [{"ordinal": 0, "outcome": "error", "stage": "startup", "workload_started": False}, {"ordinal": 1, "outcome": "ok", "stage": "workload", "workload_started": True}]
        result = summary(results)
        self.assertEqual(result["primary_availability"]["successful"], 0)
        self.assertEqual(result["primary_availability"]["attempts"], 1)
        self.assertEqual(result["retry_availability"]["successful"], 1)


class FakeRemote:
    def __init__(self):
        self.stopped = []
        self.launched = []
        self.commands = []
        self.create_error = False

    def launch(self, jobs):
        for i, job in enumerate(jobs):
            self.launched.append(job.role)
            job.pid, job.started_unix_ms = 123+i, 1000

    def stop(self, job):
        self.stopped.append(job.role)
        return {"returncode": 0}

    def collect(self, job):
        return {"files": {}, "alive": False, "unit_state": {}}

    def call(self, host, action, **kwargs):
        self.commands.append([action, kwargs.get("lease", "")])
        return {"errors": []}

    def command(self, host, argv):
        self.commands.append(argv)
        code = 1 if argv == ["check-absent"] else (2 if argv == ["create-rule"] and self.create_error else 0)
        return subprocess.CompletedProcess(argv, code, "", "")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.topology, self.matrix = configuration()
        self.remote = FakeRemote()
        self.runner = Runner(self.topology, self.matrix, Path(self.temp.name), self.remote)
        self.row = schedule(self.matrix)[0]

    def prepare_failure(self, case, profile):
        job = self.runner.job("source", "fixture-first", ["fixture-command"])
        self.runner.launch([job])
        raise AttemptFailure("startup failed")

    def prepare_success(self, case, profile):
        a = self.runner.job("destination", "fixture-first", ["fixture-command"])
        b = self.runner.job("source", "fixture-second", ["fixture-command"])
        self.runner.launch([a, b])

    def test_optional_runtime_switches_are_explicit_and_off_by_default(self):
        for enabled in (False, True):
            self.runner.attempt_id="switch-fixture";self.runner.directory=Path(self.temp.name);self.runner.record={"group":0};self.runner.jobs=[]
            profile={"transport":"braidpath","fec":4,"entrances":["direct"],"receiver_feedback":enabled,"quality_schedule":enabled,"rotate_source_port":enabled}
            with patch.object(self.runner,"runtime_ready",return_value=type("Ready",(),{"session_id":"session"})()):
                self.runner.prepare_runtime(self.matrix["cases"][0],profile)
            client=next(j for j in self.runner.jobs if j.role=="client")
            for option in ("--receiver-feedback","--quality-schedule","--rotate-source-port"):
                self.assertEqual(option in client.argv,enabled)

    def test_startup_failure_cleans_registered_process(self):
        with patch.object(self.runner, "prepare_runtime", side_effect=self.prepare_failure), patch.object(self.runner, "workload") as workload:
            result = self.runner.attempt(self.row, 0)
        workload.assert_not_called()
        self.assertEqual(self.remote.stopped, ["fixture-first"])
        self.assertEqual(result["outcome"], "error")
        self.assertFalse(result["workload_started"])
        self.assertEqual(result["status"], "finished")

    def test_workload_exception_and_ctrl_c_cleanup_reverse_order(self):
        for error in (RuntimeError("workload failed"), KeyboardInterrupt()):
            self.remote.stopped = []
            with patch.object(self.runner, "prepare_runtime", side_effect=self.prepare_success), patch.object(self.runner, "workload", side_effect=error):
                if isinstance(error, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        self.runner.attempt(self.row, 0)
                else:
                    self.runner.attempt(self.row, 0)
            self.assertEqual(self.remote.stopped, ["fixture-second", "fixture-first"])
            result = json.loads((self.runner.directory / "attempt.json").read_text())
            self.assertEqual(result["status"], "finished")
            self.assertEqual(result["outcome"], "interrupted" if isinstance(error, KeyboardInterrupt) else "error")

    def test_launch_uncertainty_still_registered_for_cleanup(self):
        def uncertain(jobs):
            raise RuntimeError("SSH disconnected after unit submission")
        with patch.object(self.runner, "prepare_runtime", side_effect=self.prepare_failure), patch.object(self.remote, "launch", side_effect=uncertain):
            self.runner.attempt(self.row, 0)
        self.assertEqual(self.remote.stopped, ["fixture-first"])

    def test_retry_keeps_first_failure_and_resume_skips_completed(self):
        self.matrix["retry_startup"] = 1
        with patch.object(self.runner, "prepare_runtime", side_effect=self.prepare_failure), patch.object(self.runner, "workload"):
            attempts = self.runner.run_rows([self.row])
        self.assertEqual([r["ordinal"] for r in attempts], [0, 1])
        self.assertEqual(len(list((Path(self.temp.name)/"attempts").iterdir())), 2)
        with patch.object(self.runner, "attempt") as attempt:
            resumed = self.runner.run_rows([self.row])
        attempt.assert_not_called()
        self.assertEqual(len(resumed), 2)
        self.assertEqual(summary(resumed)["primary_availability"]["attempts"], 1)
        self.assertEqual(summary(resumed)["retry_availability"]["attempts"], 1)

    def test_unconfirmed_cleanup_blocks_rows_and_retry_but_evidence_errors_do_not(self):
        self.matrix["retry_startup"] = 1
        rows = schedule(self.matrix)
        for scenario in ("still_alive", "unknown", "collection_error", "runtime_error", "stop_failed_but_gone"):
            with self.subTest(scenario=scenario):
                self.remote = FakeRemote()
                self.runner = Runner(self.topology, self.matrix, Path(self.temp.name) / scenario, self.remote)
                def stop(job):
                    self.remote.stopped.append(job.role)
                    if scenario in ("still_alive", "unknown", "stop_failed_but_gone"):
                        raise RuntimeError("SSH reset during stop")
                    return {"returncode": 0}
                def collect(job):
                    if scenario in ("unknown", "collection_error"):
                        raise RuntimeError("artifact transfer failed")
                    final = {"final": True, "process_id": job.pid, "sample_unix_ms": 2000, "outcome": "error", "stats": {"shutdown_complete": True}}
                    return {"files": {"stats.json": json.dumps(final)} if scenario == "runtime_error" else {}, "alive": scenario == "still_alive", "unit_state": {"ActiveState": "active" if scenario == "still_alive" else "inactive"}}
                def prepare(case, profile):
                    job = self.runner.job("destination", "server", ["fixture-command"], stats=scenario == "runtime_error")
                    self.runner.launch([job])
                    raise AttemptFailure("startup failed")
                with patch.object(self.runner, "prepare_runtime", side_effect=prepare), patch.object(self.remote, "stop", side_effect=stop), patch.object(self.remote, "collect", side_effect=collect), patch.object(self.runner, "workload") as workload:
                    if scenario in ("still_alive", "unknown"):
                        with self.assertRaisesRegex(AttemptFailure, "cleanup unconfirmed"):
                            self.runner.run_rows(rows)
                    else:
                        attempts = self.runner.run_rows(rows)
                        self.assertEqual(len(attempts), len(rows))
                        self.assertTrue(all(r["cleanup_confirmed"] for r in attempts))
                        self.assertTrue(all(r["outcome"] == "error" for r in attempts))
                workload.assert_not_called()
                saved = json.loads((self.runner.output / "summary.json").read_text())
                if scenario in ("still_alive", "unknown"):
                    self.assertEqual(self.remote.launched, ["server"])
                    self.assertEqual(len(saved["attempts"]), 1)
                    self.assertFalse(saved["attempts"][0]["cleanup_confirmed"])
                    self.assertEqual(saved["unexecuted_rows"], rows[1:])
                    with patch.object(self.runner, "attempt") as attempt:
                        with self.assertRaisesRegex(AttemptFailure, "cleanup unconfirmed"):
                            self.runner.run_rows(rows)
                    attempt.assert_not_called()
                else:
                    self.assertEqual(saved["unexecuted_rows"], [])

    def test_cleanup_cancellation_is_deferred_then_stops_before_next_row(self):
        rows = schedule(self.matrix)
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum):
                self.remote = FakeRemote()
                self.runner = Runner(self.topology, self.matrix, Path(self.temp.name) / signal.Signals(signum).name, self.remote)
                previous = signal.getsignal(signum)
                events = []
                original_stop = self.remote.stop
                def stop(job):
                    events.append("stop:" + job.role)
                    if job.role == "fixture-second":
                        signal.getsignal(signum)(signum, None)
                        events.append("cancel-received")
                    return original_stop(job)
                def collect(job):
                    events.append("collect:" + job.role)
                    return {"files": {}, "alive": False, "unit_state": {"ActiveState": "inactive"}}
                def complete(case, profile):
                    self.runner.record.update(stage="workload", workload_started=True)
                with patch.object(self.runner, "prepare_runtime", side_effect=self.prepare_success), patch.object(self.runner, "workload", side_effect=complete), patch.object(self.remote, "stop", side_effect=stop), patch.object(self.remote, "collect", side_effect=collect):
                    with self.assertRaisesRegex(KeyboardInterrupt, "deferred until cleanup completed"):
                        self.runner.run_rows(rows)
                self.assertEqual(events, ["stop:fixture-second", "cancel-received", "collect:fixture-second", "stop:fixture-first", "collect:fixture-first"])
                self.assertEqual(self.remote.launched, ["fixture-first", "fixture-second"])
                self.assertEqual(signal.getsignal(signum), previous)
                saved = json.loads((self.runner.output / "summary.json").read_text())
                self.assertEqual(saved["attempts"][0]["outcome"], "interrupted")
                self.assertEqual(saved["attempts"][0]["status"], "finished")
                self.assertTrue(saved["attempts"][0]["cleanup_confirmed"])
                self.assertEqual(saved["unexecuted_rows"], rows[1:])

    def test_firewall_lease_before_create_and_only_owned_removed(self):
        rule = {"host": "source", "check": ["check-absent"], "create": ["create-rule"], "remove": ["remove-rule"], "lease_seconds": 60}
        existing = {**rule, "check": ["check-existing"]}
        self.topology["firewall"] = [existing, rule]
        firewall = Firewall(self.remote, self.topology, Path(self.temp.name), 300)
        firewall.setup()
        self.assertEqual(len(firewall.owned), 1)
        commands = self.remote.commands
        lease_index = next(i for i, argv in enumerate(commands) if argv[0] == "systemd-run")
        self.assertLess(lease_index, commands.index(["create-rule"]))
        self.assertIn("--on-active=60s", commands[lease_index])
        self.assertFalse(firewall.cleanup())
        self.assertEqual(commands.count(["remove-rule"]), 1)

    def test_failed_firewall_create_and_removal_keep_lease(self):
        self.topology["firewall"] = [{"host": "source", "check": ["check-absent"], "create": ["create-rule"], "remove": ["remove-rule"]}]
        self.remote.create_error = True
        firewall = Firewall(self.remote, self.topology, Path(self.temp.name), 300)
        with self.assertRaisesRegex(RuntimeError, "create failed"):
            firewall.setup()
        self.assertFalse(firewall.cleanup())
        self.assertIn(["remove-rule"], self.remote.commands)

    def test_collected_finite_unit_and_unused_lease_service_are_clean(self):
        job = {"unit": "fixture-collected", "directory": self.temp.name}
        def systemctl(args, **kwargs):
            return subprocess.CompletedProcess(args, 1, "not-found\n" if args[1] == "show" else "", "unit absent")
        for payload in ({"action": "stop", "jobs": [job]}, {"action": "cancel_lease", "lease": "fixture-lease"}):
            output = io.StringIO()
            with patch.object(sys, "argv", ["fixture", json.dumps(payload)]), patch("subprocess.run", side_effect=systemctl), redirect_stdout(output):
                exec(REMOTE, {})
            result = json.loads(output.getvalue())
            self.assertEqual(result[0]["returncode"] if payload["action"] == "stop" else result["errors"], 0 if payload["action"] == "stop" else [])

    def test_current_profiles_use_bbr_and_reject_other_controllers_before_launch(self):
        self.runner.directory = Path(self.temp.name)
        self.runner.attempt_id = "fixture-attempt"
        self.runner.record = {}
        case = self.matrix["cases"][0]
        from types import SimpleNamespace
        for name in ("bbr", "bbr_fec4"):
            self.runner.jobs = []
            with patch.object(self.runner, "runtime_ready", return_value=SimpleNamespace(session_id="fixture-session")):
                self.runner.prepare_runtime(case, self.matrix["profiles"][name])
            for job in self.runner.jobs:
                self.assertNotIn("--congestion", job.argv)
        self.matrix["profiles"]["bbr"]["congestion"] = "cubic"
        with self.assertRaisesRegex(ValueError, "only BBR"):
            validate(self.topology, self.matrix)
        with patch.object(self.runner, "launch") as launch:
            with self.assertRaisesRegex(ValueError, "only BBR"):
                self.runner.prepare_runtime(case, self.matrix["profiles"]["bbr"])
            launch.assert_not_called()

    def test_paired_profiles_reuse_the_group_source_port(self):
        self.runner.directory = Path(self.temp.name)
        self.runner.attempt_id = "fixture-bound"
        self.runner.record = {"group": 1}
        self.topology["path_bind_ports"] = {"direct": [40000,40001]}
        from types import SimpleNamespace
        for profile in self.matrix["profiles"].values():
            self.runner.jobs = []
            with patch.object(self.runner, "runtime_ready", return_value=SimpleNamespace(session_id="fixture-session")):
                self.runner.prepare_runtime(self.matrix["cases"][0], profile)
            client = next(j for j in self.runner.jobs if j.role == "client")
            self.assertEqual(client.argv[client.argv.index("--path-bind")+1], "0.0.0.0:40001")

    def test_immediate_child_exit_still_records_launch_and_exit(self):
        child = unittest.mock.Mock(pid=123)
        child.wait.return_value = 2
        payload = {"directory": self.temp.name, "argv": ["fixture-immediate-error"]}
        with patch.object(sys, "argv", ["fixture", json.dumps(payload)]), patch("subprocess.Popen", return_value=child), patch("pathlib.Path.read_text", side_effect=FileNotFoundError), patch("signal.signal"):
            with self.assertRaises(SystemExit) as caught:
                exec(WRAPPER, {})
        self.assertEqual(caught.exception.code, 1)
        launch = json.loads((Path(self.temp.name) / "launch.json").read_text())
        result = json.loads((Path(self.temp.name) / "exit.json").read_text())
        self.assertEqual(launch["pid"], 123)
        self.assertIsNone(launch["proc_start_ticks"])
        self.assertEqual(result["returncode"], 2)

    def test_compressed_collect_roundtrip_limit_and_readiness_tail(self):
        folder = Path(self.temp.name)
        original = json.dumps({"repeated": "fixture-data" * 1000}) + "\n"
        (folder / "result.json").write_text(original)
        (folder / "stats.jsonl").write_text('{"n":1}\n{"n":2}\n{"n":')
        job = {"unit": "fixture-collected", "directory": self.temp.name}
        remote = Remote(self.topology)
        def helper(payload):
            output = io.StringIO()
            with patch.object(sys, "argv", ["fixture", json.dumps(payload)]), patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "LoadState=not-found\n", "")), redirect_stdout(output):
                exec(REMOTE, {})
            return output.getvalue()
        for limit, exceeds in ((20000, False), (64, True)):
            payload = {"action": "collect", "jobs": [job], "names": ["result.json", "stats.jsonl"], "artifact_limit_bytes": limit}
            encoded = helper(payload)
            with patch.object(remote, "command", return_value=subprocess.CompletedProcess([], 0, encoded, "")):
                result = remote.call("source", "collect", jobs=[job], artifact_limit_bytes=limit)[0]
            if exceeds:
                self.assertTrue(result["collection_errors"])
                self.assertFalse(result["files"])
            else:
                self.assertEqual(result["files"]["result.json"], original)
                self.assertLess(len(encoded), len(original))
        result = json.loads(helper({"action": "state", "jobs": [job]}))[0]
        self.assertEqual(result["files"]["stats.jsonl"], '{"n":2}\n')
        with patch.object(remote, "command", side_effect=subprocess.TimeoutExpired("large-helper-code", 3)):
            with self.assertRaisesRegex(RuntimeError, "remote_timeout") as caught:
                remote.call("source", "collect", timeout=3)
        self.assertNotIn("large-helper-code", str(caught.exception))

    def test_management_helper_uses_stdin_not_large_mux_command(self):
        with patch("bench.run.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "{}", "")) as run:
            Remote(self.topology).call("source", "fixture", large="x" * 100000)
        self.assertLess(len(run.call_args.args[0][-1]), 512)
        payload=json.loads(run.call_args.kwargs["input"])
        self.assertEqual(payload["request"]["large"], "x" * 100000)
        self.assertEqual(payload["script"], REMOTE)

    def test_ssh_options_are_explicit_and_preserved(self):
        self.topology["hosts"]["source"]["ssh_options"] = ["-J", "fixture-jump"]
        with patch("bench.run.subprocess.run") as run:
            Remote(self.topology).command("source", ["fixture-command", "literal;argument"])
        argv = run.call_args.args[0]
        self.assertIn("fixture-jump", argv)
        self.assertEqual(argv[-1], "fixture-command 'literal;argument'")


if __name__ == "__main__":
    unittest.main()
