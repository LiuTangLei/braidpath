# Source-specific RTT baselines

Since v0.2.1, client/server senders use source-specific RTT baselines by default.
`--legacy-recovery` restores the mixed baseline; the retained
`--rtt-source-baselines` compatibility flag re-enables just this correction
with that legacy mode. Each sender keeps separate minimum observations for Quinn RTT and authenticated RTT probes
within each path generation. The existing selector still chooses an absolute
RTT; its queue excess is compared to the minimum from that same source instead
of the shared minimum. Stable offsets between estimators no longer create
queue growth merely because an old probe ages out of the selector.

This addresses the reproducible mixed-baseline negative control in the tests,
not a proven explanation of every public-network slowdown. The minimum is a
local observation, not a calibrated propagation delay. A path already queued
at its first sample cannot establish its true empty-path baseline.

Absolute RTT samples, generation identity, feedback freshness, selected-source
policy, native BBR, sender memory bounds, deadlines and loss/transport brakes
remain. Real increases from either selected estimator's own minimum still
exercise the existing queue brake. The correction cannot issue tokens or raise
a configured rate cap. The ordinary bandwidth-recovery logic remains in place;
this is not the independent `--native-service-guard` feature.

Both modes collect the same bounded shadow minima. Duplicate or regressing
probe identifiers cannot lower a learned probe baseline. Generation changes
reset all minima and counters while preserving the local setting. Peers cannot
change that setting through negotiation.

Minima do not age upward within a generation. A lasting increase in propagation
delay can therefore remain classified as queue pressure. Sustained RTT and
delivery samples alone cannot distinguish that change from a standing queue
elsewhere on the path; periodically replacing the minimum would hide both.
Changing this behavior requires an independent requalification signal and a
comparison that also preserves real-queue braking. No timer-based reset or
automatic decay of remembered service is enabled in v0.2.2 or v0.3.0.

The long-lived regression fixtures keep one generation through a sustained RTT
step and through a prolonged capacity reduction followed by recovery. They
record allowances, fixed-window simulated delivery, queue percentiles, drops
and recovery intervals while checking memory, packet-age and admission bounds.
The FIFO model omits Quinn congestion control, flow scheduling and application
ingress deadlines. Its results can expose controller behavior, but cannot
establish an end-to-end performance improvement or justify weakening those
safeguards. Run-specific measurements and decisions remain in ignored `local/`.

Control snapshots expose `rtt_source_baselines_enabled`, the two `source_*`
minima, `mixed_rtt_excess_ms`, and `rtt_source_baseline_corrections`. The last is
an observation count, not saved requests, prevented brakes or bandwidth gain.
Existing absolute RTTs, mixed minimum and diagnostic minima remain visible.

The controlled regression replays the same observations through both modes: a
100 ms Quinn estimate and 80 ms probe retain a 256,000 bit/s allowance with
source-specific baselines; the old mixed baseline invents 20 ms of queue and
reduces the allowance to 236,800 bit/s. Separate regressions retain real-delay,
loss, socket-pressure and deadline safeguards. These are controller allowances,
not measured network throughput. Runtime checks exercise the default in both
directions over four local paths.

For performance comparisons, keep workload and limits identical, require
complete request populations and source qualification, and verify cleanup. Keep run-specific topology and results in ignored `local/`. Local
regressions do not establish public-network speed or latency improvement.
