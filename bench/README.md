# Finite benchmark runner

`run.py` runs parameterized, paired comparisons with preinstalled binaries. It does
not deploy binaries, change congestion defaults, alter the scheduler/FEC, or make
performance acceptance claims. Python 3.9+, key-based SSH, remote Python 3,
Linux/systemd and permission to create transient units are required.

Keep **both configuration files and every result below ignored `local/`**. No
hostnames, IPs, ports, firewall rules, credentials or actual run records belong in
public files. Remote binaries, identity files and working directories are supplied
by the private topology. Remote working directories retain evidence for recovery.
Use dedicated test ports; the harness never stops an existing service. Do not run
concurrent harnesses against the same topology or concurrently mutate its rules.

```sh
python3 bench/run.py --topology local/topology.json --matrix local/matrix.json \
  --output local/benchmark --dry-run
python3 bench/run.py --topology local/topology.json --matrix local/matrix.json \
  --output local/benchmark
# Optional limited smoke; use a separate output directory.
python3 bench/run.py --topology local/topology.json --matrix local/matrix.json \
  --output local/smoke --case CASE_NAME
python3 -m unittest bench.test_run bench.test_readiness
```

Dry run writes `schedule.json` and prints JSON without SSH or firewall changes.
An existing output directory resumes only the same configuration and remote
binary hashes. Completed rows, including failed or interrupted rows, are not
silently rerun. A previously unfinished attempt is stopped, collected and retained
as interrupted. Use a new output directory for a new comparison or changed
configuration/binaries. The manifest records local Git HEAD and remote binary
SHA-256/version; binaries are rechecked on resume. SSH management failures remain
errors; there is no automatic route change.

## Private topology schema

The following field descriptions are intentionally address-free. All command
fields contain argv lists, not shell strings.

- `hosts`: map of symbolic host names to `ssh`, absolute `binary`, absolute
  `workdir`; optional `ssh_options` argv (for an explicit jump host), optional
  client `interface` (one interface; omission uses the default route).
- `client_host`, `server_host`: names in `hosts`.
- `tls`: `server_name`, client `ca`, server `cert`/`key`, and `token_file`.
  Optional `client_token_file`/`server_token_file` override the common path.
  The runner references existing files and never reads or copies their secrets.
- `addresses`: `client_listen` for the tunnel ingress, `server_listen` for QUIC,
  `server_target` for the echo/sink bind behind the tunnel, and `raw_listen` for
  the directly reachable raw echo/sink bind. Select matching test destination
  ports for a fair comparison; these cases run serially.
- `paths`: map of names to `entrance` and `raw_entrance`, both reachable from the
  client. A relay path additionally has `host`, `listen`, `target`, `raw_listen`,
  `raw_target`, `allow_source` list and optional `rate_bps` (default 15000000).
  The raw relay forwards directly to the ordinary UDP echo/sink destination.
- Optional `capture_network: true`: read-only before/after JSON snapshots of
  `/proc/net/snmp`, `/proc/net/dev` and `tc -j -s qdisc show`. Missing/failed `tc`
  is recorded under `qdisc.error`; no qdisc is installed or changed. These are
  host-wide counters and may include unrelated traffic.
- Optional `firewall`: list of `{host, check, create, remove}`. `check` returns 0
  for an existing exact rule, 1 for absent, and other values for an error. Existing
  rules are neither owned nor removed. `remove` must remove only the exact test
  rule, including its dedicated comment/identity, never an unrelated broad rule.
  Optional positive `lease_seconds` overrides the computed whole-run allowance;
  size it to exceed the entire planned run and cleanup. Optional `lease_create`
  and `lease_remove` argv replace the generic systemd timer operations; the
  create command must arm a bounded, independent removal lease before rule creation.

The harness records rule ownership before invoking creation and arms a removal
lease first. It removes only owned rules on success, failure, Ctrl-C or SIGTERM.
If rule removal fails, the lease remains armed and the run reports a cleanup
error. Recovery attempts cleanup of unfinished ownership before starting work.
A SIGKILL, lost management connection or machine crash cannot run local `finally`;
remote finite unit lifetimes and the removal timer bound the remaining effects.

## Matrix schema

This example contains only symbolic path names and workload parameters. Save and
adapt it in `local/matrix.json`; topology addresses never go in the matrix.

```json
{
  "duration_seconds": 15,
  "payload_bytes": 1000,
  "deadline_ms": 250,
  "drain_ms": 3000,
  "stats_interval_ms": 250,
  "rate_bps": 5000000,
  "block_ms": 25,
  "repeats": 2,
  "order": "alternating",
  "retry_startup": 0,
  "cases": [
    {
      "name": "echo-comparison",
      "path": "direct",
      "direction": "echo",
      "pps": 200,
      "profiles": ["raw1", "bbr", "cubic"]
    }
  ],
  "profiles": {
    "raw1": {"transport": "raw-udp", "flows": 1},
    "raw2": {"transport": "raw-udp", "flows": 2},
    "raw4": {"transport": "raw-udp", "flows": 4},
    "bbr": {"transport": "braidpath", "congestion": "bbr", "fec": 0, "entrances": ["@path"]},
    "cubic": {"transport": "braidpath", "congestion": "cubic", "fec": 0, "entrances": ["@path"]},
    "three0": {"transport": "braidpath", "congestion": "bbr", "fec": 0, "entrances": ["direct", "relay_a", "relay_b"]},
    "three4": {"transport": "braidpath", "congestion": "bbr", "fec": 4, "entrances": ["direct", "relay_a", "relay_b"]}
  }
}
```

Each repetition is a paired group containing all selected profiles. Adjacent
groups alternate forward/reverse order: two profiles with two groups produce
`A B B A`; three profiles produce `A B C C B A`, and the next group reverses again.
`order: "abba"` explicitly requires two profiles and an even number of groups.
`repeats` counts groups, so every profile runs exactly that many primary attempts.
`@path` uses the current case path. Named entrances support best-single versus
three-entrance FEC0/FEC4 echo comparisons at the same application rate/budget.
BBR profiles omit `--congestion` on both endpoints to exercise the shipping
default; CUBIC profiles explicitly pass `--congestion cubic` on both endpoints.

Directions are `echo`, `client_to_server`, and `server_to_client`. Count is
`pps * duration_seconds`; `pps` is the **total** across flows. Raw echo supports
multiple source sockets against the exact same target IP/port. Integer rate and
count are split across flows, with remainders assigned deterministically. Probe
units launch concurrently in one SSH batch; actual local addresses must be
distinct and the actual sample send spans must overlap by at least 90% for every
flow. Multiflow one-way and multiflow tunnel profiles are rejected. One-way runs
use one finite sink and a shared random run ID. Payload/count/rate/drain bounds
follow [the finite probe contract](../docs/probe.md); optional
`readiness_timeout_seconds` is 1–60 (default 30).

## Lifecycle and evidence

Every process has an attempt UUID, unique transient systemd unit, `MemoryMax=512M`,
finite `RuntimeMaxSec`, SIGINT stop and `TimeoutStopSec=8`. The wrapper records
actual binary PID, remote start wall time, `/proc` start identity and exit status
as JSON. Finite successful/failed units are collected automatically; a missing
unit is considered cleaned only after checking it is absent and its recorded
process is not alive. Stop happens in reverse launch order in `finally`; errors
and missing/stale final stats remain explicit.

For a tunnel profile, the runner first checks each relay and the server listener,
then all unique authenticated client paths and the server's matching client
session. Only then does it launch the echo/sink target, so a sink startup timer
cannot expire during QUIC handshakes. Target readiness checks live PID, fresh
JSON timestamp/instance and the sink's run ID. It then starts finite probes. No
runtime or probe readiness is inferred from human logs.

Each `attempts/…/attempt.json` retains stage, readiness result, outcome, cleanup
errors and metrics. Per-process folders retain full final JSON, cumulative JSONL,
packet samples, readiness/launch/exit JSON, stdout/stderr and systemd properties.
Artifact collection uses gzip/base64 in transit and preserves the original local
file contents. Each process has a 128 MiB total artifact limit; overflow or file
growth beyond it records `collection_errors` and refuses a valid conclusion.
Readiness transfers only the latest complete stats JSON line from a bounded
16 MiB tail, rather than repeatedly copying the entire cumulative file.
A nonzero process exit is retained even when result JSON exists. Runtime counters
remain scoped by process/direction/path; cumulative periodic snapshots are never
summed as independent observations. Handshake negotiation and authenticated path
admission failures are reported separately.

`summary.json` contains every attempt and separate **primary** and **retry**
availability denominators. `retry_startup: 1` permits one new startup attempt
only after a failed, fully cleaned startup; it never replaces the failure. A
started workload, interrupted attempt or cleanup failure is not retried. Ordinary
packet loss/lateness is measured rather than treated as an acceptance failure;
missing data, integrity errors and operational failures remain unsuccessful.

Delivery retains on-time counts, loss/lateness, per-flow unconditional latency
quantiles (including the literal `"infinity"`) and full endpoint reports. One-way
results reconcile actual source sends with receiver configured counts before
claiming loss. Multiflow goodput explicitly distinguishes the sum of per-flow
observation goodputs from an approximate common-window value (total useful bytes
divided by maximum observation duration); slight start offsets prevent treating
that approximation as exact simultaneous throughput. Host/QUIC datagram counters,
logical record counts and probe losses are distinct measurement layers.
