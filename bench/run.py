#!/usr/bin/env python3
"""Parameterized finite benchmark runner. Private configuration/evidence: local/ only."""
from __future__ import annotations

import argparse
import base64
import gzip
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bench.readiness import ProcessSample, ReadinessRequirement, wait_for_ready

ROOT = Path(__file__).resolve().parents[1]
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
FILES = ("launch.json", "exit.json", "ready.json", "result.json", "samples.json", "stats.json", "stats.jsonl", "stdout.log", "stderr.log")


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


@contextmanager
def cleanup_signals():
    pending = []
    def defer(signum, frame):
        pending.append(signum)
    previous = {sig: signal.signal(sig, defer) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if pending:
            raise KeyboardInterrupt(f"{signal.Signals(pending[0]).name} deferred until cleanup completed")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def private_path(value):
    path = Path(value).resolve()
    if not path.is_relative_to((ROOT / "local").resolve()) or path == (ROOT / "local").resolve():
        raise ValueError("configuration and output must be below the repository's ignored local/ directory")
    return path


def integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def validate(topology, matrix):
    for host in (topology["client_host"], topology["server_host"]):
        if host not in topology["hosts"]:
            raise ValueError("unknown endpoint host")
    for host in topology["hosts"].values():
        for key in ("ssh", "binary", "workdir"):
            if not isinstance(host.get(key), str) or not host[key]:
                raise ValueError(f"host requires {key}")
        if not host["binary"].startswith("/") or not host["workdir"].startswith("/"):
            raise ValueError("remote binary/workdir must be absolute paths")
        options = host.get("ssh_options", [])
        if not isinstance(options, list) or not all(isinstance(x, str) for x in options):
            raise ValueError("ssh_options must be an argv list")
    integer(matrix.get("duration_seconds", 15), "duration_seconds", 1, 3600)
    integer(matrix.get("payload_bytes", 1000), "payload_bytes", 16, 1000)
    integer(matrix.get("deadline_ms", 250), "deadline_ms", 1, 10000)
    integer(matrix.get("drain_ms", 3000), "drain_ms", 0, 60000)
    integer(matrix.get("stats_interval_ms", 250), "stats_interval_ms", 10, 60000)
    integer(matrix.get("rate_bps", 5000000), "rate_bps", 1, 1000000000)
    integer(matrix.get("block_ms", 25), "block_ms", 1, 1000)
    integer(matrix.get("repeats", 1), "repeats", 1, 1000)
    integer(matrix.get("retry_startup", 0), "retry_startup", 0, 1)
    if matrix.get("order", "alternating") not in ("alternating", "abba"):
        raise ValueError("order must be alternating or abba")
    integer(matrix.get("readiness_timeout_seconds", 30), "readiness_timeout_seconds", 1, 60)
    names = set()
    if not matrix.get("cases"):
        raise ValueError("cases cannot be empty")
    for case in matrix["cases"]:
        name = case["name"]
        if not name or name in names or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in name):
            raise ValueError("case names must be unique simple identifiers")
        names.add(name)
        if case["path"] not in topology["paths"]:
            raise ValueError("unknown case path")
        if case["direction"] not in ("echo", "client_to_server", "server_to_client"):
            raise ValueError("invalid direction")
        pps = integer(case["pps"], "pps", 1, 20000)
        integer(pps * matrix.get("duration_seconds", 15), "count", 1, 100000)
        if case["direction"] != "echo" and matrix.get("payload_bytes", 1000) < 36:
            raise ValueError("one-way payload must be at least 36 bytes")
        profiles = case["profiles"]
        if not profiles or len(set(profiles)) != len(profiles):
            raise ValueError("profiles must be nonempty and unique")
        if matrix.get("order") == "abba" and (len(profiles) != 2 or matrix.get("repeats", 1) % 2):
            raise ValueError("abba requires two profiles and even repeats")
        for profile_name in profiles:
            if not isinstance(profile_name, str) or not profile_name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in profile_name):
                raise ValueError("profile names must be simple identifiers")
            profile = matrix["profiles"][profile_name]
            if profile["transport"] not in ("raw-udp", "braidpath"):
                raise ValueError("invalid transport")
            flows = integer(profile.get("flows", 1), "flows", 1, 64)
            if pps < flows:
                raise ValueError("total pps must be at least flow count")
            if flows > 1 and (profile["transport"] != "raw-udp" or case["direction"] != "echo"):
                raise ValueError("multiple flows are supported only for raw UDP echo")
            if profile["transport"] == "braidpath":
                if profile.get("congestion", "bbr") not in ("bbr", "cubic"):
                    raise ValueError("invalid congestion")
                integer(profile.get("fec", 0), "fec", 0, 32)
                entrances = profile.get("entrances", ["@path"])
                paths = [case["path"] if p == "@path" else p for p in entrances]
                if not paths or len(paths) != len(set(paths)) or len(paths) > 8:
                    raise ValueError("entrances must be unique topology path names, maximum eight")
                if any(p not in topology["paths"] for p in paths):
                    raise ValueError("entrances must reference topology paths, never addresses")
    for rule in topology.get("firewall", []):
        if rule["host"] not in topology["hosts"]:
            raise ValueError("unknown firewall host")
        for key in ("check", "create", "remove"):
            if not isinstance(rule[key], list) or not rule[key] or not all(isinstance(x, str) for x in rule[key]):
                raise ValueError("firewall commands must be nonempty argv lists")
    for path_name, ports in topology.get("path_bind_ports", {}).items():
        if path_name not in topology["paths"] or not isinstance(ports, list) or not ports or len(set(ports)) != len(ports):
            raise ValueError("path bind ports need a known path and a nonempty unique port list")
        for port in ports:
            integer(port, "path bind port", 1, 65535)
    # Infrastructure belongs exclusively in topology, including probe source binds.
    forbidden = {"ssh", "host", "hosts", "port", "listen", "target", "interface", "addresses", "firewall", "binary", "workdir", "path_bind_ports"}
    def inspect(value):
        if isinstance(value, dict):
            if forbidden.intersection(value):
                raise ValueError("infrastructure fields belong in topology only")
            for child in value.values():
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)
    inspect(matrix)


def schedule(matrix, case_filter=None):
    """Each group contains all profiles; adjacent groups reverse their order."""
    rows = []
    for case in matrix["cases"]:
        if case_filter and case["name"] != case_filter:
            continue
        for group in range(matrix.get("repeats", 1)):
            profiles = case["profiles"] if group % 2 == 0 else list(reversed(case["profiles"]))
            for position, profile in enumerate(profiles):
                rows.append({"row_id": f"{case['name']}-g{group:04d}-{profile}", "case": case["name"], "group": group, "position": position, "profile": profile})
    if not rows:
        raise ValueError("no matching cases")
    return rows


def split_load(pps, duration, flows):
    rates = [pps // flows + (i < pps % flows) for i in range(flows)]
    return [(int(rate), int(rate) * duration) for rate in rates]


@dataclass
class Job:
    host: str
    role: str
    unit: str
    directory: str
    argv: list[str]
    runtime_seconds: int
    pid: int | None = None
    started_unix_ms: int | None = None
    run_id: str | None = None
    runtime_stats: bool = False


# Runs inside a uniquely named, bounded systemd unit. JSON records real binary PID
# and exit status independently of journald; stdout/stderr are evidence only.
WRAPPER = r'''
import json, os, pathlib, signal, subprocess, sys, time
p=json.loads(sys.argv[1]); d=p["directory"]
def write(name, value):
    tmp=d+"/"+name+".tmp"
    with open(tmp,"w") as f: json.dump(value,f)
    os.replace(tmp,d+"/"+name)
started=time.time_ns()//1000000
with open(d+"/stdout.log","a") as out, open(d+"/stderr.log","a") as err:
    child=subprocess.Popen(p["argv"],stdout=out,stderr=err)
    def stop(signum,frame):
        try: child.send_signal(signal.SIGINT)
        except ProcessLookupError: pass
    signal.signal(signal.SIGINT,stop); signal.signal(signal.SIGTERM,stop)
    try:
        proc_start_ticks=pathlib.Path("/proc/"+str(child.pid)+"/stat").read_text().rsplit(")",1)[1].split()[19]
    except FileNotFoundError:
        proc_start_ticks=None
    write("launch.json",{"pid":child.pid,"started_unix_ms":started,"proc_start_ticks":proc_start_ticks})
    code=child.wait()
    write("exit.json",{"returncode":code,"finished_unix_ms":time.time_ns()//1000000})
sys.exit(0 if code==0 else 1)
'''

REMOTE = r'''
import base64, concurrent.futures, gzip, hashlib, json, os, pathlib, subprocess, sys, time
p=json.loads(sys.argv[1]); action=p["action"]
def last_complete_snapshot(f, limit):
    size=f.stat().st_size
    with f.open("rb") as stream:
        position=size; tail=b""
        while position>0 and len(tail)<limit:
            amount=min(65536,position,limit-len(tail)); position-=amount
            stream.seek(position); tail=stream.read(amount)+tail
            lines=tail.splitlines(keepends=True)
            # A first line beginning mid-file may be an incomplete prefix.
            candidates=lines if position==0 else lines[1:]
            for line in reversed(candidates):
                if not line.endswith(b"\n"): continue
                try:
                    text=line.decode("utf-8"); value=json.loads(text)
                    if isinstance(value,dict): return text,None
                except (ValueError,UnicodeDecodeError): pass
        return "",("no complete snapshot within bounded tail" if position>0 else None)
def state(j, files=False):
    d=pathlib.Path(j["directory"]); out={"files":{},"collection_errors":[]}
    names=p.get("names",["launch.json","exit.json","ready.json","stats.jsonl"])
    limit=p.get("artifact_limit_bytes",128*1024*1024)
    existing=[(name,d/name) for name in names if (d/name).exists()]
    if files:
        total=sum(f.stat().st_size for _,f in existing)
        out["artifact_bytes"]=total; out["artifact_limit_bytes"]=limit
        if total>limit:
            out["collection_errors"].append("artifact total exceeds byte limit")
            existing=[]
    consumed=0
    for name,f in existing:
        if not files and name=="stats.jsonl":
            text,error=last_complete_snapshot(f,p.get("snapshot_limit_bytes",16*1024*1024))
            if text: out["files"][name]=text
            if error: out["collection_errors"].append(error)
            continue
        with f.open("rb") as stream: content=stream.read(max(0,limit-consumed)+1)
        consumed+=len(content)
        if consumed>limit:
            out["files"]={}; out["collection_errors"].append("artifact grew beyond byte limit during collection")
            break
        out["files"][name]=content.decode("utf-8",errors="replace")
    launch=json.loads(out["files"].get("launch.json","null")); pid=launch["pid"] if launch else None
    alive=False
    if pid:
        try:
            os.kill(pid,0)
            # Reject zombies; the wrapper's exit file is authoritative when present.
            proc=pathlib.Path("/proc/"+str(pid)+"/stat").read_text().rsplit(")",1)[1].split()
            alive=proc[0]!="Z" and (not launch.get("proc_start_ticks") or proc[19]==launch["proc_start_ticks"])
        except (ProcessLookupError,FileNotFoundError): pass
    out.update(pid=pid,alive=alive and "exit.json" not in out["files"])
    return out
if action=="launch":
    def launch(j):
        pathlib.Path(j["directory"]).mkdir(parents=True,mode=0o700,exist_ok=False)
        args=["systemd-run","--quiet","--collect","--unit="+j["unit"],"--property=RuntimeMaxSec="+str(j["runtime_seconds"]),"--property=MemoryMax=512M","--property=KillSignal=SIGINT","--property=KillMode=mixed","--property=TimeoutStopSec=8","--property=StandardOutput=null","--property=StandardError=append:"+j["directory"]+"/stderr.log","python3","-c",p["wrapper"],json.dumps(j)]
        r=subprocess.run(args,capture_output=True,text=True,timeout=15)
        if r.returncode: raise RuntimeError(r.stderr)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            f=pathlib.Path(j["directory"])/"launch.json"
            if f.exists(): return json.loads(f.read_text())
            time.sleep(.05)
        raise RuntimeError("unit did not write launch identity")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(p["jobs"])) as pool:
        result=list(pool.map(launch,p["jobs"]))
elif action=="state": result=[state(j) for j in p["jobs"]]
elif action=="cancel_lease":
    result={"errors":[]}
    for unit in [p["lease"]+".timer",p["lease"]+".service"]:
        r=subprocess.run(["systemctl","stop",unit],capture_output=True,text=True,timeout=15)
        if r.returncode:
            q=subprocess.run(["systemctl","show",unit,"--property=LoadState","--value"],capture_output=True,text=True,timeout=10)
            if q.stdout.strip()!="not-found": result["errors"].append({"unit":unit,"returncode":r.returncode,"stderr":r.stderr})
elif action=="stop":
    result=[]
    for j in p["jobs"]:
        r=subprocess.run(["systemctl","stop",j["unit"]],capture_output=True,text=True,timeout=15)
        code=r.returncode
        if code:
            q=subprocess.run(["systemctl","show",j["unit"],"--property=LoadState","--value"],capture_output=True,text=True,timeout=10)
            if q.stdout.strip()=="not-found" and not state(j)["alive"]: code=0
        result.append({"returncode":code,"stderr":r.stderr if code else ""})
elif action=="collect":
    result=[]
    for j in p["jobs"]:
        s=state(j,True)
        r=subprocess.run(["systemctl","show",j["unit"],"--property=LoadState,Result,ExecMainCode,ExecMainStatus,ActiveState,SubState"],capture_output=True,text=True,timeout=10)
        s["unit_state"]={line.split("=",1)[0]:line.split("=",1)[1] for line in r.stdout.splitlines() if "=" in line}
        s["unit_query_returncode"]=r.returncode
        result.append(s)
elif action=="fingerprint":
    h=hashlib.sha256()
    with open(p["binary"],"rb") as f:
        for block in iter(lambda:f.read(1048576),b""): h.update(block)
    result={"sha256":h.hexdigest(),"version":subprocess.run([p["binary"],"--version"],capture_output=True,text=True,check=True,timeout=10).stdout.strip()}
elif action=="network":
    result={"sample_unix_ms":time.time_ns()//1000000,"snmp":{},"interfaces":{}}
    lines=pathlib.Path("/proc/net/snmp").read_text().splitlines()
    for keys,vals in zip(lines[::2],lines[1::2]):
        k=keys.split(); v=vals.split(); result["snmp"][k[0].rstrip(":")]=dict(zip(k[1:],map(int,v[1:])))
    names=["bytes","packets","errs","drop","fifo","frame","compressed","multicast"]
    for line in pathlib.Path("/proc/net/dev").read_text().splitlines()[2:]:
        name,values=line.split(":",1); values=list(map(int,values.split()))
        result["interfaces"][name.strip()]={"receive":dict(zip(names,values[:8])),"transmit":dict(zip(["bytes","packets","errs","drop","fifo","colls","carrier","compressed"],values[8:]))}
    try:
        tc=subprocess.run(["tc","-j","-s","qdisc","show"],capture_output=True,text=True,timeout=10)
        result["qdisc"]=json.loads(tc.stdout) if tc.returncode==0 else {"error":"tc failed","returncode":tc.returncode,"stderr":tc.stderr}
    except (FileNotFoundError,ValueError,subprocess.TimeoutExpired) as e: result["qdisc"]={"error":str(e)}
else: raise ValueError("unknown action")
if action=="collect":
    raw=json.dumps(result).encode("utf-8")
    print(json.dumps({"encoding":"gzip+base64","uncompressed_bytes":len(raw),"data":base64.b64encode(gzip.compress(raw)).decode("ascii")}))
else: print(json.dumps(result))
'''


class Remote:
    def __init__(self, topology):
        self.topology = topology

    def command(self, host, argv, timeout=30):
        return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", *self.topology["hosts"][host].get("ssh_options", []), self.topology["hosts"][host]["ssh"], shlex.join(argv)], capture_output=True, text=True, timeout=timeout)

    def call(self, host, action, timeout=30, **kwargs):
        try:
            result = self.command(host, ["python3", "-c", REMOTE, json.dumps({"action": action, **kwargs})], timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(json.dumps({"error": "remote_timeout", "host": host, "action": action, "timeout_seconds": timeout})) from None
        if result.returncode:
            raise RuntimeError(f"remote {action} failed: {result.stderr.strip()}")
        value = json.loads(result.stdout)
        if action == "collect":
            if value.get("encoding") != "gzip+base64":
                raise RuntimeError("unsupported artifact transfer encoding")
            # JSON escaping adds overhead to source files, but remains bounded.
            maximum = kwargs.get("artifact_limit_bytes", MAX_ARTIFACT_BYTES) * 6 * len(kwargs.get("jobs", [])) + 1048576
            declared = value["uncompressed_bytes"]
            if type(declared) is not int or not 0 <= declared <= maximum:
                raise RuntimeError("artifact transfer exceeds decoded byte limit")
            compressed = base64.b64decode(value["data"], validate=True)
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
                decoded = stream.read(declared + 1)
            if len(decoded) != declared:
                raise RuntimeError("artifact transfer decoded size mismatch")
            return json.loads(decoded)
        return value

    def launch(self, jobs):
        groups = {}
        for job in jobs:
            groups.setdefault(job.host, []).append(job)
        def launch_group(item):
            host, group = item
            values = self.call(host, "launch", timeout=35, jobs=[asdict(j) for j in group], wrapper=WRAPPER)
            for job, value in zip(group, values):
                job.pid, job.started_unix_ms = value["pid"], value["started_unix_ms"]
        with ThreadPoolExecutor(max_workers=len(groups)) as pool:
            list(pool.map(launch_group, groups.items()))

    def state(self, job, timeout=10):
        return self.call(job.host, "state", timeout=max(.1, min(timeout, 10)), jobs=[asdict(job)])[0]

    def stop(self, job):
        return self.call(job.host, "stop", jobs=[asdict(job)])[0]

    def collect(self, job):
        return self.call(job.host, "collect", jobs=[asdict(job)], names=FILES, artifact_limit_bytes=MAX_ARTIFACT_BYTES)[0]


def last_snapshot(text):
    for line in reversed(text.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


class AttemptFailure(RuntimeError):
    pass


class Firewall:
    """Only rules observed absent are owned. Arm a bounded removal lease first."""
    def __init__(self, remote, topology, output, lease_seconds):
        self.remote, self.topology, self.output = remote, topology, output
        self.lease_seconds = lease_seconds
        state = self.output / "firewall.json"
        self.owned = [r for r in json.loads(state.read_text()) if not r.get("cleaned")] if state.exists() else []

    def setup(self):
        if self.owned:
            if self.cleanup():
                raise RuntimeError("unfinished owned firewall cleanup failed")
            self.owned = []
        for rule in self.topology.get("firewall", []):
            result = self.remote.command(rule["host"], rule["check"])
            if result.returncode == 0:
                continue
            if result.returncode != 1:
                raise RuntimeError("firewall existence check failed")
            lease = "braidpath-bench-lease-" + uuid.uuid4().hex
            record = {"rule": rule, "lease": lease, "create_started": False}
            # If SSH/create is interrupted, removal is already owned and leased.
            self.owned.append(record)
            save(self.output / "firewall.json", self.owned)
            args = rule.get("lease_create") or ["systemd-run", "--quiet", "--collect", "--property=RuntimeMaxSec=30", "--property=MemoryMax=512M", "--property=KillSignal=SIGINT", "--property=TimeoutStopSec=8", "--unit=" + lease, "--on-active=" + str(rule.get("lease_seconds", self.lease_seconds)) + "s", "--timer-property=AccuracySec=1s", "--", *rule["remove"]]
            result = self.remote.command(rule["host"], args)
            if result.returncode:
                raise RuntimeError("firewall removal lease could not be armed")
            record["create_started"] = True
            save(self.output / "firewall.json", self.owned)
            result = self.remote.command(rule["host"], rule["create"])
            if result.returncode:
                raise RuntimeError("firewall create failed (owned cleanup remains armed)")

    def cleanup(self):
        errors = []
        for record in reversed(self.owned):
            rule = record["rule"]
            try:
                if record["create_started"]:
                    result = self.remote.command(rule["host"], rule["remove"])
                    if result.returncode:
                        raise RuntimeError("owned firewall removal failed; lease remains armed")
                if rule.get("lease_remove"):
                    result = self.remote.command(rule["host"], rule["lease_remove"])
                    failed = result.returncode != 0
                else:
                    failed = bool(self.remote.call(rule["host"], "cancel_lease", timeout=55, lease=record["lease"])["errors"])
                if failed:
                    raise RuntimeError("firewall lease cancellation failed")
                record["cleaned"] = True
            except Exception as error:
                errors.append(str(error))
        save(self.output / "firewall.json", self.owned)
        return errors


class Runner:
    def __init__(self, topology, matrix, output, remote=None):
        self.topology, self.matrix, self.output = topology, matrix, Path(output)
        self.remote = remote or Remote(topology)
        self.jobs = []
        self.directory = None
        self.attempt_id = None
        self.record = None

    def job(self, host, role, args, stats=False, run_id=None):
        remote_dir = self.topology["hosts"][host]["workdir"].rstrip("/") + "/" + self.attempt_id + "/" + role
        lifetime = self.matrix.get("duration_seconds", 15) + self.matrix.get("drain_ms", 3000) // 1000 + 90
        job = Job(host, role, "braidpath-bench-" + self.attempt_id + "-" + role, remote_dir, [], lifetime, run_id=run_id, runtime_stats=stats)
        job.argv = [self.topology["hosts"][host]["binary"], *map(str, args)]
        if stats:
            job.argv += ["--stats-file", remote_dir + "/stats.json", "--stats-jsonl", remote_dir + "/stats.jsonl", "--stats-interval-ms", str(self.matrix.get("stats_interval_ms", 250))]
        self.jobs.append(job)  # register before launch, including uncertain remote outcomes
        self.persist_jobs()
        return job

    def persist_jobs(self):
        save(self.directory / "jobs.json", [asdict(j) for j in self.jobs])

    def launch(self, jobs):
        try:
            self.remote.launch(jobs)
        finally:
            self.persist_jobs()

    def runtime_ready(self, job, ids=(), session=None):
        def poll(remaining):
            state = self.remote.state(job, remaining)
            if state.get("collection_errors"):
                raise AttemptFailure("; ".join(state["collection_errors"]))
            snapshot = last_snapshot(state["files"].get("stats.jsonl", ""))
            return ProcessSample(snapshot, state["alive"], state["pid"])
        result = wait_for_ready(poll, ReadinessRequirement(job.role.split("-")[0], job.pid, job.started_unix_ms, tuple(ids), session_id=session), self.matrix.get("readiness_timeout_seconds", 30))
        self.record.setdefault("readiness", {})[job.role] = asdict(result)
        save(self.directory / "attempt.json", self.record)
        if not result.ready:
            raise AttemptFailure(f"{job.role} readiness: {result.reason} ({result.detail})")
        return result

    def target_ready(self, job):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            state = self.remote.state(job, deadline - time.monotonic())
            if not state["alive"] or state["pid"] != job.pid:
                raise AttemptFailure("target exited or process identity changed")
            ready_text = state["files"].get("ready.json")
            if ready_text:
                ready = json.loads(ready_text)
                if ready.get("ready") is True and ready.get("pid") == job.pid and ready.get("sample_unix_ms", -1) >= job.started_unix_ms and ready.get("instance_id") and ready.get("run_id") == job.run_id:
                    self.record["target_readiness"] = ready
                    return
            time.sleep(.1)
        raise AttemptFailure("fresh target readiness timed out")

    def workload_args(self, rate, count, run_id, transport):
        return ["--count", count, "--size", self.matrix.get("payload_bytes", 1000), "--pps", rate, "--deadline-ms", self.matrix.get("deadline_ms", 250), "--drain-ms", self.matrix.get("drain_ms", 3000), "--startup-timeout-ms", 30000, "--run-id", run_id, "--transport", transport]

    def results_flags(self, job):
        job.argv += ["--result-file", job.directory + "/result.json", "--samples-file", job.directory + "/samples.json"]
        self.persist_jobs()

    def prepare_runtime(self, case, profile):
        t, m = self.topology, self.matrix
        path_names = [case["path"] if p == "@path" else p for p in profile.get("entrances", ["@path"])] if profile["transport"] == "braidpath" else [case["path"]]
        relay_jobs = []
        for index, name in enumerate(path_names):
            path = t["paths"][name]
            if "host" not in path:
                continue
            raw = profile["transport"] == "raw-udp"
            args = ["relay", "--listen", path["raw_listen"] if raw else path["listen"], "--target", path["raw_target"] if raw else path["target"], "--rate-bps", path.get("rate_bps", 15000000)]
            for source in path["allow_source"]:
                args += ["--allow-source", source]
            relay_jobs.append(self.job(path["host"], "relay-" + str(index), args, stats=True))
        if relay_jobs:
            self.launch(relay_jobs)
            for job in relay_jobs:
                self.runtime_ready(job)
        if profile["transport"] == "raw-udp":
            return
        a, tls = t["addresses"], t["tls"]
        # Omitting the controller explicitly exercises the shipping BBR default.
        cc = [] if profile.get("congestion", "bbr") == "bbr" else ["--congestion", "cubic"]
        server = self.job(t["server_host"], "server", ["server", "--listen", a["server_listen"], "--cert", tls["cert"], "--key", tls["key"], "--token-file", tls.get("server_token_file", tls["token_file"]), "--target", a["server_target"], "--max-rate-bps", m.get("rate_bps", 5000000), *cc], stats=True)
        self.launch([server])
        self.runtime_ready(server)
        args = ["client", "--listen", a["client_listen"], "--server-name", tls["server_name"], "--ca", tls["ca"], "--token-file", tls.get("client_token_file", tls["token_file"]), "--fec", profile.get("fec", 0), "--block-ms", m.get("block_ms", 25), "--rate-bps", m.get("rate_bps", 5000000), *cc]
        interface = t["hosts"][t["client_host"]].get("interface")
        if interface:
            args += ["--interface", interface]
        for name in path_names:
            args += ["--entrance", t["paths"][name]["entrance"]]
        if t.get("path_bind_ports"):
            for name in path_names:
                ports = t["path_bind_ports"][name]
                port = ports[self.record["group"] % len(ports)]
                entrance = t["paths"][name]["entrance"]
                args += ["--path-bind", ("[::]:" if entrance.startswith("[") else "0.0.0.0:") + str(port)]
        client = self.job(t["client_host"], "client", args, stats=True)
        self.launch([client])
        ready = self.runtime_ready(client, range(len(path_names)))
        self.runtime_ready(server, range(len(path_names)), ready.session_id)

    def workload(self, case, profile):
        t, m = self.topology, self.matrix
        transport, direction = profile["transport"], case["direction"]
        loads = split_load(case["pps"], m.get("duration_seconds", 15), profile.get("flows", 1))
        run_ids = [uuid.uuid4().hex for _ in loads]
        target_address = t["addresses"]["raw_listen"] if transport == "raw-udp" else t["addresses"]["server_target"]
        if direction == "echo":
            target = self.job(t["server_host"], "echo", ["echo", "--listen", target_address])
        else:
            rate, count = loads[0]
            target = self.job(t["server_host"], "sink", ["sink", "--role", "receive" if direction == "client_to_server" else "reverse-source", "--listen", target_address, *self.workload_args(rate, count, run_ids[0], transport)], run_id=run_ids[0])
            self.results_flags(target)
        target.argv += ["--ready-file", target.directory + "/ready.json"]
        self.persist_jobs()
        # The target startup timer starts only after all authenticated paths pass.
        self.launch([target])
        self.target_ready(target)
        mode = {"echo": "echo", "client_to_server": "send", "server_to_client": "receive"}[direction]
        entrance = t["paths"][case["path"]]["raw_entrance"] if transport == "raw-udp" else t["addresses"]["client_listen"]
        probes = []
        for flow, ((rate, count), run_id) in enumerate(zip(loads, run_ids)):
            job = self.job(t["client_host"], "probe-" + str(flow), ["probe", "--mode", mode, "--target", entrance, *self.workload_args(rate, count, run_id, transport)], run_id=run_id)
            # Ephemeral source ports are independently allocated by the kernel.
            self.results_flags(job)
            probes.append(job)
        self.record["stage"] = "workload"
        self.record["workload_started"] = True
        save(self.directory / "attempt.json", self.record)
        self.launch(probes)  # one SSH batch with concurrent unit submissions
        finite = probes + ([target] if direction != "echo" else [])
        deadline = time.monotonic() + m.get("duration_seconds", 15) + m.get("drain_ms", 3000) / 1000 + 45
        pending = list(finite)
        while pending and time.monotonic() < deadline:
            for job in list(pending):
                state = self.remote.state(job, deadline - time.monotonic())
                if "exit.json" in state["files"]:
                    pending.remove(job)
                elif not state["alive"]:
                    raise AttemptFailure(f"{job.role} exited without exit JSON")
            if pending:
                time.sleep(.2)
        if pending:
            raise AttemptFailure("workload exceeded finite deadline")

    def cleanup(self):
        errors, artifacts = [], {}
        self.cleanup_unconfirmed = []
        for job in reversed(self.jobs):
            confirmed = False
            try:
                result = self.remote.stop(job)
                confirmed = result["returncode"] == 0
                if result["returncode"]:
                    errors.append(f"{job.role}: unit stop failed: {result.get('stderr', '')}")
            except Exception as error:
                errors.append(f"{job.role}: stop: {error}")
            try:
                artifact = self.remote.collect(job)
                artifacts[job.role] = artifact
                unit_state = artifact.get("unit_state", {})
                if artifact.get("alive") is True:
                    confirmed = False
                elif artifact.get("alive") is False and (unit_state.get("LoadState") == "not-found" or unit_state.get("ActiveState") in ("inactive", "failed")):
                    confirmed = True
                errors.extend(f"{job.role}: {error}" for error in artifact.get("collection_errors", []))
                folder = self.directory / job.role
                folder.mkdir(exist_ok=True)
                for name, content in artifact["files"].items():
                    (folder / name).write_text(content)
                save(folder / "unit-state.json", artifact.get("unit_state", {}))
                save(folder / "collection.json", {key: artifact.get(key) for key in ("artifact_bytes", "artifact_limit_bytes", "collection_errors")})
                if artifact.get("alive"):
                    errors.append(f"{job.role}: process still alive after cleanup")
                if job.runtime_stats:
                    final = json.loads(artifact["files"].get("stats.json", "null"))
                    if not final or final.get("final") is not True or final.get("process_id") != job.pid or final.get("sample_unix_ms", -1) < (job.started_unix_ms or 0):
                        errors.append(f"{job.role}: missing or stale final runtime stats")
                    elif final.get("outcome") == "error":
                        errors.append(f"{job.role}: runtime final outcome is error")
                    elif final.get("stats", {}).get("drain_incomplete") or not final.get("stats", {}).get("shutdown_complete"):
                        errors.append(f"{job.role}: runtime cleanup incomplete")
            except Exception as error:
                errors.append(f"{job.role}: collect: {error}")
            if not confirmed:
                self.cleanup_unconfirmed.append({"host": job.host, "role": job.role, "unit": job.unit})
        return errors, artifacts

    def attempt(self, row, ordinal):
        self.attempt_id = uuid.uuid4().hex
        self.directory = self.output / "attempts" / (row["row_id"] + f"-try{ordinal}-" + self.attempt_id)
        self.directory.mkdir(parents=True)
        self.jobs = []
        self.record = {**row, "attempt_id": self.attempt_id, "ordinal": ordinal, "status": "running", "stage": "startup", "workload_started": False, "outcome": None}
        save(self.directory / "attempt.json", self.record)
        case = next(c for c in self.matrix["cases"] if c["name"] == row["case"])
        profile = self.matrix["profiles"][row["profile"]]
        interrupted = None
        try:
            if self.topology.get("capture_network", False):
                for host in self.topology["hosts"]:
                    save(self.directory / (host + "-network-before.json"), self.remote.call(host, "network"))
            self.prepare_runtime(case, profile)
            self.workload(case, profile)
            self.record["outcome"] = "ok"
        except BaseException as error:
            self.record["outcome"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "error"
            self.record["error"] = f"{type(error).__name__}: {error}"
            if not isinstance(error, Exception):
                interrupted = error
        finally:
            try:
                with cleanup_signals():
                    errors, artifacts = self.cleanup()
                    self.record["cleanup_errors"] = errors
                    self.record["cleanup_unconfirmed"] = self.cleanup_unconfirmed
                    self.record["cleanup_confirmed"] = not self.cleanup_unconfirmed
                    try:
                        self.record["metrics"] = aggregate_artifacts(artifacts, case["direction"], self.jobs)
                    except Exception as error:
                        self.record["metrics"] = {"errors": [f"malformed structured metrics: {error}"]}
                    if errors or self.record["metrics"]["errors"]:
                        if self.record["outcome"] == "ok":
                            self.record["outcome"] = "error"
                    if self.topology.get("capture_network", False):
                        for host in self.topology["hosts"]:
                            try:
                                save(self.directory / (host + "-network-after.json"), self.remote.call(host, "network"))
                            except Exception as error:
                                self.record.setdefault("evidence_errors", []).append(str(error))
                                self.record["outcome"] = "error"
                    self.record["status"] = "finished"
                    save(self.directory / "attempt.json", self.record)
            except KeyboardInterrupt as error:
                interrupted = error
                self.record.update(outcome="interrupted", error=str(error))
                save(self.directory / "attempt.json", self.record)
        if interrupted:
            raise interrupted
        return self.record

    def recover(self, path, record):
        """An unfinished record is cleaned and preserved, never silently rerun."""
        self.directory = path.parent
        job_file = self.directory / "jobs.json"
        self.jobs = [Job(**value) for value in json.loads(job_file.read_text())] if job_file.exists() else []
        with cleanup_signals():
            errors, artifacts = self.cleanup()
            case = next(c for c in self.matrix["cases"] if c["name"] == record["case"])
            record.update(status="finished", outcome="interrupted", error="recovered unfinished attempt", cleanup_errors=errors, cleanup_unconfirmed=self.cleanup_unconfirmed, cleanup_confirmed=not self.cleanup_unconfirmed, metrics=aggregate_artifacts(artifacts, case["direction"], self.jobs))
            save(path, record)
        return record

    def run_rows(self, rows):
        attempts = []
        try:
            for path in sorted((self.output / "attempts").glob("*/attempt.json")):
                record = json.loads(path.read_text())
                attempts.append(record if record.get("status") == "finished" else self.recover(path, record))
            if any(r.get("cleanup_confirmed") is False for r in attempts):
                raise AttemptFailure("remote process cleanup unconfirmed; refusing subsequent rows")
            for row in rows:
                existing = [r for r in attempts if r["row_id"] == row["row_id"]]
                if existing:
                    # A failed initial startup may have one separately counted retry.
                    first = min(existing, key=lambda r: r["ordinal"])
                    if len(existing) != 1 or first["ordinal"] != 0 or first["outcome"] == "ok" or first.get("cleanup_errors") or first.get("workload_started") or first["outcome"] == "interrupted" or not self.matrix.get("retry_startup", 0):
                        continue
                    ordinal = 1
                else:
                    ordinal = 0
                record = self.attempt(row, ordinal)
                attempts.append(record)
                save(self.output / "summary.json", summary(attempts, rows))
                if record["cleanup_confirmed"] is False:
                    raise AttemptFailure("remote process cleanup unconfirmed; refusing subsequent rows")
                if ordinal == 0 and record["outcome"] == "error" and not record.get("cleanup_errors") and not record["workload_started"] and self.matrix.get("retry_startup", 0):
                    retry = self.attempt(row, 1)
                    attempts.append(retry)
                    if retry["cleanup_confirmed"] is False:
                        raise AttemptFailure("remote process cleanup unconfirmed; refusing subsequent rows")
                    save(self.output / "summary.json", summary(attempts, rows))
            return attempts
        finally:
            records = [json.loads(p.read_text()) for p in sorted((self.output / "attempts").glob("*/attempt.json"))]
            save(self.output / "summary.json", summary(records, rows))


def aggregate_artifacts(artifacts, direction, jobs=()):
    """Keep reports/counters scoped. Never sum cumulative JSONL snapshots."""
    out = {"errors": [], "reports": {}, "runtime": {}, "handshake": {}, "probe_exits": {}, "process_exits": {}}
    identities = {j.role: j for j in jobs}
    for role, artifact in artifacts.items():
        files = artifact["files"]
        out["errors"].extend(f"{role}: {error}" for error in artifact.get("collection_errors", []))
        try:
            out["process_exits"][role] = json.loads(files.get("exit.json", "null"))["returncode"]
        except (ValueError, TypeError, KeyError):
            out["process_exits"][role] = None
        for name, bucket in (("result.json", "reports"), ("stats.json", "runtime")):
            if name not in files:
                continue
            try:
                value = json.loads(files[name])
                out[bucket][role] = value
                job = identities.get(role)
                if job and (value.get("pid", value.get("process_id")) != job.pid or value.get("sample_unix_ms", -1) < (job.started_unix_ms or 0)):
                    out["errors"].append(f"{role}: stale result identity")
                if bucket == "reports" and job and value.get("run_id") != job.run_id:
                    out["errors"].append(f"{role}: mismatched workload run ID")
            except (ValueError, TypeError) as error:
                out["errors"].append(f"{role}: malformed {name}: {error}")
        if role.startswith("probe") or role == "sink":
            try:
                code = json.loads(files.get("exit.json", "null"))["returncode"]
            except (ValueError, TypeError, KeyError):
                code = None
            out["probe_exits"][role] = code
            if code != 0:
                out["errors"].append(f"{role}: nonzero or missing exit status")
            report = out["reports"].get(role)
            if report is None or report.get("final") is not True or report.get("outcome") != "ok":
                out["errors"].append(f"{role}: missing or unsuccessful final probe report")
            if "samples.json" not in files:
                out["errors"].append(f"{role}: missing samples")
    keys = ("handshake_attempts", "handshake_successes", "handshake_failures", "handshake_cancelled", "path_admission_attempts", "path_admission_successes", "path_admission_failures", "path_admission_cancelled")
    for role, snapshot in out["runtime"].items():
        stats = snapshot.get("stats", {})
        out["handshake"][role] = {key: stats.get(key, 0) for key in keys}
    out["path_tuples"] = [{"role": role, "path_key": key, "path_id": path.get("path_id"),
        "local_socket": path.get("local_socket"), "peer_socket": path.get("peer_socket"),
        "sending_direction": path.get("sending_direction")}
        for role, snapshot in out["runtime"].items() for key, path in snapshot.get("stats", {}).get("paths", {}).items()]
    probes = [report for role, report in out["reports"].items() if role.startswith("probe")]
    if direction == "echo":
        delivered = probes
    elif direction == "client_to_server":
        delivered = [out["reports"]["sink"]] if "sink" in out["reports"] else []
    else:
        delivered = probes
    if delivered and all("received" in report for report in delivered):
        population = sum(r.get("quantile_population", 0) for r in delivered)
        received, lost, late = (sum(r[key] for r in delivered) for key in ("received", "lost", "late"))
        out["delivery"] = {"population": population, "received": received, "lost": lost, "late": late, "on_time": received - late, "loss_rate": lost / max(1, population), "deadline_miss_rate": (lost + late) / max(1, population), "sum_per_flow_observation_goodput_bps": sum(r["useful_goodput_bps"] for r in delivered), "approx_common_window_goodput_bps": sum(r.get("useful_bytes", 0) for r in delivered) * 8 / max(max(r.get("observation_seconds", 0) for r in delivered), 1e-300), "goodput_note": "Common-window estimate uses total useful bytes / maximum per-flow observation duration; slightly offset flow starts are not an exact common interval.", "latency_by_flow": [{key: r.get(key) for key in ("p50_ms", "p95_ms", "p99_ms")} for r in delivered]}
    if direction != "echo" and probes and "sink" in out["reports"]:
        sender = probes[0] if direction == "client_to_server" else out["reports"]["sink"]
        receiver = out["reports"]["sink"] if direction == "client_to_server" else probes[0]
        out["sender_receiver"] = {"actual_sent": sender.get("sent"), "receiver_expected": receiver.get("expected_count"), "receiver_received": receiver.get("received"), "source_complete": sender.get("sent") == receiver.get("expected_count"), "actual_offered_load_bps": sender.get("actual_offered_load_bps")}
        if not out["sender_receiver"]["source_complete"]:
            out["errors"].append("sender incomplete; configured receiver missing slots are not proven network loss")
    if len(probes) > 1:
        addresses = [r.get("local_addr") for r in probes]
        peers = {r.get("peer_addr") for r in probes}
        if None in addresses or len(set(addresses)) != len(addresses) or len(peers) != 1 or None in peers:
            out["errors"].append("multiflow requires distinct local addresses and one common target")
        spans = []
        for role in sorted(out["reports"]):
            if not role.startswith("probe"):
                continue
            try:
                samples = json.loads(artifacts[role]["files"]["samples.json"])["samples"]
                sent = [s["send_unix_us"] for s in samples if s.get("send_unix_us") is not None]
                spans.append((min(sent), max(sent)))
            except (ValueError, KeyError, TypeError):
                out["errors"].append(f"{role}: cannot verify sender overlap")
        if len(spans) == len(probes):
            overlap = max(0, min(s[1] for s in spans) - max(s[0] for s in spans))
            ratios = [overlap / max(1, end - start) for start, end in spans]
            out["multiflow"] = {"local_addresses": addresses, "same_target": len(peers) == 1, "sender_overlap_fraction_by_flow": ratios}
            if min(ratios) < .9:
                out["errors"].append("multiflow sender durations overlap less than 90%")
    return out


def summary(attempts, rows=()):
    def availability(values):
        return {"attempts": len(values), "successful": sum(r["outcome"] == "ok" for r in values), "workload_started": sum(bool(r.get("workload_started")) for r in values), "by_stage": {stage: sum(r.get("stage") == stage and r["outcome"] != "ok" for r in values) for stage in ("startup", "workload")}}
    executed = {r["row_id"] for r in attempts if "row_id" in r}
    return {"schema_version": 1, "unexecuted_rows": [row for row in rows if row["row_id"] not in executed], "primary_availability": availability([r for r in attempts if r["ordinal"] == 0]), "retry_availability": availability([r for r in attempts if r["ordinal"] > 0]), "attempts": attempts, "interpretation": "Retries do not replace failures. Runtime JSONL is cumulative; metrics keep final counters per process/direction/path. Latency infinity strings are preserved; no performance acceptance claim."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--case")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    def terminated(signum, frame):
        raise KeyboardInterrupt("SIGTERM")
    signal.signal(signal.SIGTERM, terminated)
    output = private_path(args.output)
    topology = json.loads(private_path(args.topology).read_text())
    matrix = json.loads(private_path(args.matrix).read_text())
    validate(topology, matrix)
    rows = schedule(matrix, args.case)
    output.mkdir(parents=True, exist_ok=True)
    config = {"topology_sha256": digest(topology), "matrix_sha256": digest(matrix), "case_filter": args.case}
    manifest_path = output / "manifest.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text())["configuration"] != config:
        raise ValueError("output already belongs to a different configuration; use a new output directory")
    save(output / "schedule.json", {"configuration": config, "rows": rows})
    if args.dry_run:
        print(json.dumps({"configuration": config, "rows": rows}))
        return 0
    remote = Remote(topology)
    fingerprints = {host: remote.call(host, "fingerprint", binary=entry["binary"]) for host, entry in topology["hosts"].items()}
    if manifest_path.exists():
        if json.loads(manifest_path.read_text())["binary_fingerprints"] != fingerprints:
            raise ValueError("remote binary fingerprints changed; use a new output directory")
    else:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        save(manifest_path, {"schema_version": 1, "configuration": config, "git_head": head, "binary_fingerprints": fingerprints, "created_unix_ms": time.time_ns() // 1000000})
    # Each attempt is bounded to duration+90 seconds; include the one optional retry.
    lease_seconds = len(rows) * (1 + matrix.get("retry_startup", 0)) * (matrix.get("duration_seconds", 15) + 180) + 300
    firewall = Firewall(remote, topology, output, lease_seconds)
    runner = Runner(topology, matrix, output, remote)
    error = None
    attempts = []
    try:
        firewall.setup()
        attempts = runner.run_rows(rows)
    except BaseException as caught:
        error = caught
    finally:
        with cleanup_signals():
            cleanup_errors = firewall.cleanup()
            records = [json.loads(p.read_text()) for p in sorted((output / "attempts").glob("*/attempt.json"))]
            save(output / "summary.json", summary(records, rows))
            save(output / "run-status.json", {"error": str(error) if error else None, "firewall_cleanup_errors": cleanup_errors})
    if error:
        raise error
    return 1 if cleanup_errors or any(r["outcome"] != "ok" for r in attempts) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as error:
        print(json.dumps({"outcome": "error", "error": str(error)}), file=sys.stderr)
        sys.exit(1)
