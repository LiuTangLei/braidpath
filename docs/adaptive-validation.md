# Adaptive runtime validation

The product goal has two separate acceptance conditions: aggregate useful capacity
when genuinely independent links have spare capacity, and keep application delay
bounded when capacity falls. A low delay number accompanied by mostly missing
application operations does not satisfy the second condition.

## Bounded local packet experiment

`bench/adaptive_scenario.py` runs the real BraidPath executable on loopback.
It creates a dedicated identity, one server, one client and one ordinary UDP echo
target. All entrances use separate local sockets. The client process and logical
application sockets remain in place through the whole scenario.

Python 3.9 or newer and the previously built executable are sufficient. No sudo,
firewall change, namespace, external host or package installation is required.
The UDP sender uses selector readiness compatible with Python 3.9; its successful
send count means kernel acceptance, not remote delivery.

The shapers operate on actual encrypted UDP packets in each direction, including
QUIC handshakes, control packets and ACKs. Each FIFO serializes the IPv4+UDP byte
cost at its configured rate. Delay is applied after serialization. Queue byte and
age limits, configured packet loss, path outages and all-path outages are explicit.
A capacity change affects packets already waiting. Bytes reserved by queued,
serializing and delayed packets remain bounded and are released on cleanup.

`--topology independent` gives each entrance a distinct serializer in each
direction. `--topology shared` makes every entrance share one serializer per
direction, so adding entrances cannot multiply the physical bottleneck capacity.
These are controlled models of those relationships; loopback cannot establish
which physical paths a real deployment shares. The adaptive client receives
matching explicit path-group IDs.

The default source offers 900 bulk records/s of 1000 bytes and 20 independent
interactive requests/s of 128 bytes. Bulk is echoed too, so upload and download
are simultaneously loaded. The aggregate sender ceiling is 8 Mbit/s; two clean
independent links each have a 3 Mbit/s IP/UDP serializer. Offered application
traffic therefore exceeds the finite emulated capacity. Both profiles use the
same source schedule, ceiling, queue configuration, FEC setting and shaper seed.

The first 4 seconds are a separate warmup. Subsequent neutral windows are:

| Window | Duration | Configured condition |
| --- | ---: | --- |
| `window_a` | 12 s | Clean links under the offered bulk load |
| `window_b` | 12 s | First independent link drops to 0.35 Mbit/s; for shared topology the common group drops to that rate |
| `window_c` | 12 s | Clean capacities restored |
| `window_d` | 8 s | Optional first-entrance outage |
| `window_e` | 8 s | Optional first-entrance recovery |
| `window_f` | 18 s | Optional all-entrance outage, exceeding the 15 s transport idle timeout |
| `window_g` | 15 s | Optional recovery without restarting the client or application |

The optional lifecycle windows require `--outages`. The complete default
scenario is 89 seconds of source traffic plus 2 seconds of receive drain, with
bounded startup and owned-process cleanup. At most 100,000 application operations
are allowed. Parameter limits and a fresh output-directory requirement prevent
accidental unbounded campaigns or replacement of failed records.

## Measurement contract

Every scheduled operation belongs to its source window. The receiver records
the exact sequence and integrity-checked payload; RTT uses the harness process's
single monotonic clock. No minimum is subtracted. A uniformly slower route stays
slower in the reported latency distribution.

Reports distinguish:

- Planned operations, late generator slots and successful kernel submissions.
- Target receipt of unique application records.
- Returned unique echoes and echoes meeting the predeclared RTT deadline.
- Application goodput over the fixed active source window.
- Runtime application admission, queue rejection/expiry and transport counters in
  the client/server JSON snapshots.
- Outer IP/UDP bytes, classified shaper drops, current/peak queue bytes and
  serialization age at the shaper boundary.

Missing operations, generator slots that were not issued and censored echoes are
infinity in the unconditional RTT quantiles. If the source or runtime stops,
remaining planned operations stay in the denominator. Original samples,
phase events, every process exit and logs are retained. A failed source generator
is not accepted as a lower-delay experiment.

The receive drain lets in-flight observations finish; it is not included in the
active-window goodput denominator. A record arriving in a later window remains
attributed to its original source window. Both complete-window metrics and raw
samples are available so adaptation transient periods are not silently removed.

## Running a registered comparison

Freeze the baseline executable before runtime changes. Use separate fresh output
directories; never restart a completed row or overwrite its evidence.

```sh
python3 bench/adaptive_scenario.py \
  --binary local/adaptive-20261009/braidpath-BASELINE \
  --profile rr --topology independent --outages \
  --output local/adaptive-20261009/baseline-independent-RUN_ID

python3 bench/adaptive_scenario.py \
  --binary local/adaptive-20261009/braidpath-CANDIDATE \
  --profile adaptive --topology independent --outages \
  --output local/adaptive-20261009/candidate-independent-RUN_ID

python3 -m unittest bench.test_adaptive_scenario
```

Compare already completed runs without sending more traffic:

```sh
python3 bench/adaptive_compare.py \
  --baseline local/adaptive-20261009/baseline-independent-RUN_ID \
  --candidate local/adaptive-20261009/candidate-independent-RUN_ID \
  --output local/adaptive-20261009/independent-comparison-RUN_ID.json
```

The comparison refuses mismatched registered settings or incomplete generator/
startup experiments. It exposes differing harness hashes instead of hiding them.
Clean-window target goodput must also retain at least 90% of the baseline; this
guard is necessary when the baseline itself has zero on-time payload. When the
old runtime delivers no payload after an outage, recovery is assessed as
availability rather than a division by a zero throughput reference.

A `manifest.json` is written before processes start and records executable
and harness hashes, every workload/shaper setting, source phases and screening
gates. `--dry-run` writes only that registration. It still reserves the output
directory; choose a separate new directory for an actual run.

`--profile rr` can also run the candidate binary's simple-policy control;
`--profile quality` provides the previous quality-only ablation when available.
Optional current flags can be passed as repeated `--client-extra-arg=VALUE`
arguments. Do not change settings after inspecting a candidate result and then
present the new workload as the original paired comparison.

## Acceptance must match the condition

The manifest declares a finite engineering screen, not statistical proof.

- Require at least 95% of planned source submissions and no integrity errors.
- In clean windows, require non-inferiority: at least 90% of baseline on-time
  useful goodput and no more than one percentage point added interactive deadline
  misses. A baseline already at 100% does not need an impossible positive gain.
- In the impaired window, seek fewer interactive deadline misses while retaining
  useful payload delivery. Report payload delivered before the RTT deadline so
  dropping everything cannot appear successful.
- In recovery windows, report the time to the first new successful application
  exchange, restored useful throughput, current controller state and path shares.
- For lifecycle, require the adaptive client process and application sockets to
  survive the full outage and deliver in the recovery window. Report expected
  old-runtime exit as an availability failure, not an absent performance sample.
- Verify queue limits, release on cleanup and explicit outcome/counter conservation.

Use one-entrance clean controls at the same offered traffic to determine actual
useful single-path capacity before claiming the two-link capacity target from the
main validation plan. Shared-bottleneck scenarios must not be pooled with
independent-link scenarios.

One bounded run can reveal a defect or justify the next implementation decision.
It cannot establish a P99 superiority claim: 20 interactive operations/s yields
only 240 observations in each default 12-second window. Promotion of a default
still requires paired repetitions, the declared tail-sample caveat, native
platform behavior and longer resource/lifecycle observations.

CPU efficiency remains a later optimization target. Correctness, usable delivery,
real application latency and bounded resources are current gates. The local
shaper's own timer/CPU limits must be checked from offered-load and queue
measurements before interpreting a runtime result; nominal serializer capacity
is not an observed WAN throughput measurement.

