# Experimental source-specific RTT baselines

`--rtt-source-baselines` is a default-off, local client/server experiment. It
keeps separate minimum observations for Quinn RTT and authenticated RTT probes
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
exercise the existing queue brake. The experiment cannot issue tokens or raise
a configured rate cap. The ordinary bandwidth-recovery logic remains in place;
this is not the independent `--native-service-guard` feature.

Both modes collect the same bounded shadow minima. Duplicate or regressing
probe identifiers cannot lower a learned probe baseline. Generation changes
reset all minima and counters while preserving the local opt-in. Peers cannot
enable the option through negotiation.

Control snapshots expose `rtt_source_baselines_enabled`, the two `source_*`
minima, `mixed_rtt_excess_ms`, and `rtt_source_baseline_corrections`. The last is
an observation count, not saved requests, prevented brakes or bandwidth gain.
Existing absolute RTTs, mixed minimum and diagnostic minima remain visible.

Validate identical binaries with the option off/on, unchanged workload and
limits, complete request populations, source qualification and independent
cleanup. Keep run-specific topology and results in ignored `local/`. Local
regressions do not establish public-network speed or latency improvement.
