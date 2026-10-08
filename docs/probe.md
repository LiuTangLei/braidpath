# Finite UDP measurements

`probe` emits one compact JSON result to stdout and optionally `--result-file`.
`sink` handles one finite run and pins one UDP peer. `--ready-file` records the
bound address, PID, random instance identifier, shared run identifier and UNIX
sample time; `--result-file` records the final result. Match readiness to the
current PID and run identifier rather than trusting an old file. Both commands
emit error JSON for workload validation, startup and runtime failures when the
output destination remains usable. CLI parsing errors still come from Clap.

## Echo and raw baseline

The echo endpoint returns ordinary UDP payloads unchanged. It has no probe
protocol or remote control interface:

Create `local/probe/` before running these examples. Keep all run artifacts there.

```sh
braidpath echo --listen 127.0.0.1:9000 --ready-file local/probe/echo-ready.json
braidpath probe --mode echo --transport raw-udp --target 127.0.0.1:9000 \
  --count 3000 --size 1000 --pps 200 --deadline-ms 250 \
  --result-file local/probe/echo-result.json --samples-file local/probe/echo-samples.json
```

`--transport raw-udp|braidpath` labels the result; it does not change routing.
For a raw baseline, select the ordinary echo or finite sink address directly.
For BraidPath, select the local client UDP entrance and configure the server's
UDP target as that echo or sink address. RTT uses a monotonic clock, including
when wall clocks change. Echo probes support payloads from 16 to 1000 bytes.

## Forward one-way stream

Generate one unpredictable 128-bit run identifier and share it through a trusted
channel. For example, `openssl rand -hex 16`. The identifier authorizes one finite
run; reuse is discouraged. Supply the same count, size and rate at both ends.
Launch the sink first, then the sender within its startup timeout:

```sh
braidpath sink --role receive --listen 127.0.0.1:9001 --run-id "$PROBE_RUN_ID" \
  --count 3000 --size 1000 --pps 200 --startup-timeout-ms 60000 \
  --ready-file local/probe/sink-ready.json --result-file local/probe/sink-result.json \
  --samples-file local/probe/sink-samples.json
braidpath probe --mode send --target 127.0.0.1:9001 --run-id "$PROBE_RUN_ID" \
  --transport raw-udp --count 3000 --size 1000 --pps 200 \
  --result-file local/probe/sender-result.json --samples-file local/probe/sender-samples.json
```

The sender records actual successful socket sends. It reports delivery as
unavailable and omits received/loss/delay/goodput metrics. The receiver's
`expected_count` is configured locally; its `sent` and actual offered load are
null because it cannot observe successful sends. Reconcile the sender's actual
`sent` and samples with the receiver before treating all expected-but-missing
slots as network loss, particularly if the sender failed or was interrupted.
Control registration, ACK and end datagrams are counted separately from data.

## Reverse one-way stream over the same mapping

Use `sink --role reverse-source` with the same finite, locally configured
workload and shared run identifier, and `probe --mode receive` at the client.
The receiver first sends a fixed-size registration to create the tunnel or relay
UDP mapping. The source sends its stream back through that same source socket.
A valid first data packet can establish availability if the ACK was lost.
Registration uses at most three attempts within `--startup-timeout-ms`; attempts
and control datagrams are included in JSON. No available source or mapping
produces an explicit startup error.

Count, payload size and rate are never requested remotely. A wrong run identifier
receives no response and cannot start a stream; a source sends its configured
count exactly once and never restarts for duplicate registrations. A sink pins
the first authenticated registration peer for the entire finite run. One-way
payloads include a 36-byte measurement header with sequence number and signed
UNIX send time. They range from 36 to 1000 bytes. The run identifier is a bearer
capability, not a substitute for transport authentication or anti-spoofing.

## Interpretation and bounds

- One-way delay is **relative**, not absolute: compute each signed arrival UNIX
  microsecond timestamp minus send timestamp, then subtract the minimum transit
  delta of this run. Constant clock offsets cancel. Clock drift or wall-clock
  steps during the run remain measurement limitations. Inspect packet samples
  when those effects matter.
- `late` counts received packets whose relative one-way delay exceeds
  `deadline_ms`; echo uses monotonic RTT instead. `late_rate` and `loss_rate` use
  the full count denominator, not only received packets. `deadline_misses`
  includes missing plus late packets.
- P50/P95/P99 are unconditional nearest-rank quantiles of the full population.
  Missing packets occupy positive-infinity slots, encoded as the explicit JSON
  string `"infinity"`. A loss-heavy P99 must never silently become a received-only
  P99 or ambiguous null. Sender-only reports omit quantiles entirely.
- `requested_send_span_seconds` is `(count - 1) / pps`.
  `send_span_seconds` is the source's measured monotonic first-to-last send span,
  carried to the receiver by a separate end marker; it is unavailable if the
  marker is lost. `observed_send_span_seconds` spans timestamps of received
  packets and may understate the actual source span after loss.
- Nominal `requested_offered_load_bps` is `pps * size * 8`.
  `actual_offered_load_bps` is `(sent - 1) * size * 8 / send_span_seconds`,
  measuring the intervals between successful sends; a single packet has no nonzero span and yields null.
  `useful_goodput_bps` is received bytes meeting the deadline times eight divided
  by `observation_seconds`. Observation includes configured drain time, but
  excludes startup registration. These byte counts include the measurement
  header and exclude UDP/IP/QUIC wire overhead.
- `--drain-ms` defaults to 3000 and is bounded to 60000. Receive observation starts with
  the configured send span plus drain; receipt of the source end marker permits
  a fixed drain after its actual completion. Before that marker, each unique
  valid packet advancing the highest sequence may extend observation according
  to actual progress plus the remaining nominal send span and drain; duplicates,
  invalid packets and later out-of-order packets cannot renew it. Missing end
  markers cannot extend a run indefinitely. Startup timeout is 1–60000 ms. Count is 1–100000, rate is
  1–20000 pps, deadline is 1–10000 ms; allocations are bounded by count.
- `--samples-file` stores exactly one bounded slot per configured sequence with
  `seq`, `send_unix_us` and `receive_unix_us`. A receiver has null timestamps for
  missing packets; join with source samples by sequence to recover send times
  and correlate loss with runtime queue samples. Sender samples have null
  receive times because delivery is unknown. Samples are also saved after
  runtime errors where possible; partial evidence is not a complete measurement.
- `--listen` selects the probe source address. Distinct ports support parallel
  flows through a shared BraidPath client. Ordinary raw echo supports concurrent
  source ports against the same target port. Finite one-way sinks each pin one
  peer and therefore need separate sink ports/processes. No CPU-based pass/fail gate is applied.

A run exits unsuccessfully for unavailable data, integrity failures (corrupt or
duplicate data), interruption or operational errors. Ordinary packet loss and
late delivery remain measured outcomes; they do not by themselves fail the
command. Do not interpret a zero exit status as a performance acceptance gate.
