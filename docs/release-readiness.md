# Release readiness

Correctness checks and field performance gates are separate. A release candidate
must identify the exact tested source, complete the CI matrix, and retain failed
or incomplete measurements. One successful paired measurement does not establish
capacity, fairness or latency across networks.

The forward shared-bottleneck guard waits for post-cut finalized sequence ranges,
not just a timer. It probes slowly at and above its last overrun rate. Its
send-rate/loss estimate is a heuristic; feedback gaps, rate changes and competition
still require measured validation. `forward_guard.settling` exposes the wait.

Known limits to carry into prerelease notes until separately verified:

- Aggregate throughput depends on usable path capacity and endpoint processing.
  More paths do not guarantee proportional gains. CPU profiling is required to
  distinguish endpoint limits from path scheduling or pacing.
- Unequal RTT and independent delay variation can leave relay paths underused.
  The severe independent-jitter regression remains an acceptance gate until a
  bounded comparison passes; ordinary low-loss results do not close that gate.
- An endpoint or relay requests an 8 MiB UDP receive buffer. Linux can cap this
  at `net.core.rmem_max`; the runtime warns on a reduced grant. Operators should
  inspect the granted socket buffer and UDP `RcvbufErrors` before choosing an
  approved host-level change. This software does not change system-wide limits.
- Sparse samples and short downloads make tail quantiles unstable. Report sample
  counts, unconditional failures, maximum latency and complete-file goodput.

Private host details, run records, measurements and analyses belong in ignored
`local/`. Publishing a tag or merging a candidate is a separate release action.
