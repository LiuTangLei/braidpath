# Release readiness

Freeze the source revision, artifact hashes and operating configurations before
a release run. Keep precursor results attached to their original revisions and
record release acceptance against the combined build.

## Required integration gates

1. **Source and contract:** build both endpoint roles from the same candidate;
   update version metadata, current CLI guidance and feedback-format contracts.
   Removed recovery modes and compatibility aliases must have no runtime callers.
2. **Correctness:** pass the existing CI jobs for Rust on Linux, macOS and
   Windows, Rust 1.88 MSRV, benchmark helpers and platform installers. Preserve
   byte integrity, bounded resource use, half-close, cancellation and path
   generation isolation.
3. **Selected operating policy:** perform one bounded fixed-endpoint acceptance
   for the final configuration. Download requires complete-file goodput and
   responsive DATAGRAM/control service during native receive pressure. Game
   requires full-population delivery and tail latency with competing TCP,
   short-upload completion and idle restart. Missing or incomplete transfers are
   failures, not omitted samples. Compare explicit limits with automatic settings
   separately from code changes.
4. **Artifacts:** build and smoke-check all 11 release targets through the
   existing release workflow. Validate binary identity and the complete
   `SHA256SUMS` bundle; the tag must match the Cargo package version.
5. **Promotion:** review the exact candidate results and remaining limitations.
   The existing tag workflow creates a draft release. A draft or successful build
   is not a published release or deployment receipt.

The scope is integration and release acceptance. Do not rerun completed precursor
workloads to seek a better result or introduce unrelated optimization work.

## Operating boundaries

- Aggregate goodput depends on usable path capacity, shared bottlenecks and
  endpoint processing. Entrance count does not demonstrate independent capacity.
- Short transfers and sparse UDP samples cannot establish steady-state
  throughput or rare-tail behavior. Report population size, unconditional
  failures, completion time and complete-file goodput.
- Game's local UDP deadline is checked through writer and Quinn admission.
  It cannot recall data already accepted by Quinn or the kernel, and does not
  bound propagation or application round-trip time.
- Measure Game idle restart and short uploads separately from mixed traffic.
  Keep the fixed-cap and automatic-policy results with their tested settings.
- Unequal RTT, independent jitter, partial path replacement and shared-bottleneck
  competition remain material operating conditions. Retain unresolved
  regressions and avoid claims beyond the exercised conditions.
- Native return and DATAGRAM carry different byte populations. Distinguish
  writer handoff, native transport acceptance, peer receipt and application
  delivery when interpreting counters.
- Socket buffer requests remain subject to operating-system limits. The runtime
  reports reduced grants; it does not change host-wide network configuration.

Private hosts, credentials, run records and result analyses belong in ignored
`local/`. Keep timestamp instants and negative results intact. Public notes
describe mechanisms, supported contracts and verified release status.
