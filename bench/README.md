# Finite benchmark runner

`python3 -m bench.netem validate --output local/NEW_PREFLIGHT` checks an isolated
Linux four-path testbed. `python3 -m bench.netem run --binary LINUX_BINARY
--output local/NEW_RUN` validates it before one finite fixed-mode FEC0 diagnostic.
Run only as root **inside a dedicated disposable Docker container**, with
`BRAIDPATH_NETEM_CONTAINER=1`, namespace administration capabilities and Linux
`ip`, `tc`, `ping`, and `iperf3` installed. Never use host networking or production hosts.
The default 20-second workload has four independent 100 Mbps paths and RTTs
30/45/60/80 ms; each direction gets half that delay, a 1024-packet queue and
zero random loss.
`validate` checks actual RTT using finite pings after a separately recorded ARP
warmup, then calibrates independent-path rates concurrently with three-second raw
UDP streams. Calibration deliberately offers 140 percent of each link rate and
retains its drops separately from the business workload. Both actions remove their own namespaces and
interfaces in `finally`; the enclosing disposable container bounds crash cleanup.
No existing output is overwritten or resumed. All generated identities, topology,
commands, raw JSONL, packet samples, readiness and completion evidence stay under
ignored `local/`. Native stats and qdisc series are sampled every 250 ms. CSV rates
use counter deltas; aggregate drop deltas repeated beside paths must not be summed
across paths. One-way tails retain missing slots as infinity; deadline-useful
goodput divides by actual source span. A single diagnostic is not acceptance.
Boundary snapshots before/after business traffic and after runtime shutdown retain
namespace UDP/kernel counters, interface counters and socket memory. These counters
keep their native scopes and must not be added to application drops without
reconciliation. Registration binds the binary and four harness source hashes.
Boundary snapshots and the existing 250 ms qdisc series also retain optional
raw Linux VM guest-wide CPU/memory/I/O pressure, container cgroup memory limits
and events, and the owned source main thread's scheduler counters while it is
alive. Scope labels keep guest pressure separate from container and thread
evidence. Missing or unreadable resource telemetry is recorded without changing
network validation or acceptance; these observations do not retroactively prove
the cause of earlier source stalls. CPU remains diagnostic.
Completion distinguishes orderly shutdown from verified absence of owned
processes, namespaces and interfaces. A forced stop or partial JSONL tail makes
the attempt invalid even when cleanup is confirmed. Complete-line CSV from an
incomplete stream remains diagnostic and is explicitly marked in its status file;
the original raw evidence is preserved.
`--topology shared --shared-rate-mbps 400` routes the same four distinct client
source addresses through one physical access link and an owned bridge namespace,
then four entry links with the registered half-RTT delays. All four runtime paths
use group zero with an explicit group budget capped by the 400 Mbps aggregate
budget. Shared qdiscs and namespace network counters are included in the same
evidence; configuration validation checks the common link and every entry link.
Static neighbors and bridge forwarding entries bind each entrance to its own
delayed leaf link. Setup uses namespace-scoped link administration and requires
no writable sysctl mount or host network settings.
Independent topology remains the default. Shared calibration measures each leaf
sequentially for three seconds, then measures only the common access link against
a bridge-local calibration address for three seconds. The same 85–105 percent
receiver-rate check applies to each physical link; shared FIFO does not imply
equal per-path shares. These setup calibrations are separate from the unchanged
20-second business workload.
The CSV BBR pacing rate is the controller's exported internal target; Quinn's
packet pacer uses cwnd/RTT. UDP I/O operations are transmit batches: their ratio
to datagrams does not by itself prove system calls or GSO usage.
`--mode adaptive` is explicit; congestion remains BBR. An optional
`--datagram-buffer-bytes` forwards the runtime buffer flag for separately registered
experiments to both endpoints and does not change the runtime default.
`--mode native-service` selects adaptive original-only traffic without capacity
probes or probe-guided recovery. Its optional `--native-service-guard` enables
the local experiment on both endpoints. `--paths 0`, `--paths 0 0 0 0`, and
`--paths 0 1 2 3` select a single connection, four connections sharing one physical
link, and four independent links respectively; repeated indices retain distinct
source ports and share the same physical queue and rate limit. Total budgets,
deadlines, BBR and the other physical links' calibration remain unchanged.
The source sample file and summary retain actual source timestamps, the overall
offered rate, and each nominal one-second cohort's rate. Any cohort below the
existing 95 percent source floor invalidates the measurement; its raw data and
delivery summary remain available. Source qualification does not replace the
300 Mbps and 95-percent-within-200-ms joint delivery gate.
The runtime `--datagram-send-buffer-bytes` option is available independently on
client and server. Reverse-direction experiments must configure the server's
outgoing buffer; the client option only configures that client's outgoing bytes.
Both endpoints default to 1200 bytes and accept bounded overrides up to 76800.
`python3 -m unittest bench.test_netem bench.test_readiness` checks accounting,
bidirectional delay and the authenticated-path readiness gate.

`python3 -m bench.native_lab --binary HOST_BINARY --lab-binary LINK_LAB
--output local/NEW_RUN` runs the same finite source/sink workload on the
development host without containers, namespaces or privileges. Build the
emulator with `cargo build --release --example link_lab`. Freeze compared
endpoint binaries with identical target selections and build flags; build each
with `cargo build --release --locked --bin braidpath` in its own checkout and
use a separate target directory for each checkout. Build the emulator
separately: combining `--bin braidpath` with `--example link_lab` enables the
example's dev-dependency features and produces a different endpoint binary in
this repository. Do not treat a fast cached build in a shared target directory
as proof that an archived source copy was rebuilt. Record source and binary
hashes before measurements. The emulator binds only loopback sockets and shapes every path in both directions: a virtual-clock
serializer over IPv4+UDP bytes, half the registered RTT as one-way delay, a
packet limit that counts queued and propagating packets like netem, and seeded
random loss. `--rtt-ms` takes one to eight paths and `--rate-mbps` one value
or one per path. `--loss-percent` accepts 0–90 and applies after readiness.
Random erasures occur before rate accounting, so erased packets consume no
serializer or policer credit. `--policer-burst-bytes` selects a direct-drop
byte-token bucket (2048–1048576 IPv4+UDP bytes) in each direction; its default
of zero preserves FIFO shaping. Accepted packets incur propagation and their
own serialization time, without waiting behind earlier accepted packets.
The existing packet limit still counts propagating packets: check separate
`policer_drops` and `queue_full_drops` before interpreting a run as a policer
case. Rate steps settle token credit at the old rate before applying the new
rate. `--step AT_SECONDS:PATH:RATE_MBPS` changes both directions of a path relative
to the source launch. `--mode` selects `native-service` (default) or `adaptive`;
`--rate-bps` defaults to 400000000 and accepts `auto`. The summary adds the
time-averaged forward capacity and per-second on-time goodput. Timer jitter
and other host load can stall the source; source qualification then marks the
run invalid instead of retrying it. This is a loopback diagnostic, not a WAN or
kernel-qdisc equivalent. `python3 -m unittest bench.test_native_lab` checks its
argument limits and accounting.

`python3 -m bench.trace_replay RAW DEST --paths PATH_A PATH_B PATH_C PATH_D`
packs native sender/receiver samples for synchronized virtual-time replay.
`Replay.events()` retains every source timestamp, gap and end-to-end missing
packet on a common sender clock. It generates no traffic and refuses to
overwrite evidence. Relay drop counters stay separate, with unknown packet
attribution and uncalibrated relay clocks; they are neither subtracted from nor
added to the recorded loss mask. Captured receiver timestamps do not establish
absolute one-way delay. Keep input, bundles and results in ignored `local/`.

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

`sticky_worker.py` is a finite raw-UDP diagnostic endpoint for a private
coordinator. It uses eight fixed client sockets, 375 records per flow at 25 pps,
and 1,000-byte DATA with 49-byte same-socket receipts. Receiver counts measure
directional delivery; source monotonic receipts measure RTT. The coordinator
must preserve or verify both relay legs' tuples, register finite rounds and
timing before sending, retain management failures, and stop all owned units.
Small ten-second keepalives preserve idle mappings and are separate from DATA.
Keep its bearer configuration, commands, samples and result tables private.
`python3 -m unittest bench.test_sticky` checks framing and missing RTT semantics.

The following field descriptions are intentionally address-free. All command
fields contain argv lists, not shell strings.

- `hosts`: map of symbolic host names to `ssh`, absolute `binary`, absolute
  `workdir`; optional `ssh_options` argv (for an explicit jump host), optional
  client `interface` (one interface; omission uses the default route).
- `client_host`, `server_host`: names in `hosts`.
- Optional `path_bind_ports`: path-name map of unique source-port pools. The
  runner uses `group % pool_length` for each path, keeping the same client port
  across profiles in a paired group. Supply all paths used by the comparison.
  Actual client sockets and server-observed relay peers remain in `path_tuples`.
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
      "profiles": ["raw1", "bbr"]
    }
  ],
  "profiles": {
    "raw1": {"transport": "raw-udp", "flows": 1},
    "raw2": {"transport": "raw-udp", "flows": 2},
    "raw4": {"transport": "raw-udp", "flows": 4},
    "bbr": {"transport": "braidpath", "congestion": "bbr", "fec": 0, "entrances": ["@path"]},
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
Current profiles use BBR and omit the controller argument on both endpoints.
The current harness rejects other controller values before starting services.
Historical records remain unchanged and are not input profiles for new runs.

For bounded local packet-shaping experiments with persistent sessions and a
small RTT probe alongside bulk traffic, use `adaptive_scenario.py` and
[the adaptive validation procedure](../docs/adaptive-validation.md).

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
and missing/stale final stats remain explicit. `cleanup_confirmed` records whether
remote process shutdown was confirmed, independently of workload/collection
errors. If any process is alive or its cleanup cannot be confirmed, the runner
aborts subsequent rows and retries, and retains `cleanup_unconfirmed` plus
`summary.json`'s `unexecuted_rows`. A failed collection after confirmed shutdown
still invalidates that attempt but does not imply a leftover process. An output
containing unconfirmed cleanup also refuses to resume. SIGINT/SIGTERM received
during cleanup is deferred until cleanup and record saving finish, then interrupts
the run before the next row; cancellation is never discarded.

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
