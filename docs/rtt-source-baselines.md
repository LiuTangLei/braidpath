# Source-specific RTT baselines

Client/server senders keep separate RTT baselines for native Quinn estimates and
authenticated probes within each path generation. The selector chooses an
absolute RTT; queue excess is measured against the baseline from that same
source. A stable difference between the estimators does not become queue growth
merely because the selected source changes.

A minimum observation is not calibrated propagation delay. A path already
queued at its first sample cannot establish its true empty-path baseline.
Freshness, generation identity, native congestion control, sender memory limits,
local deadlines and loss/transport brakes remain active. This policy neither
creates pacing tokens nor raises configured rate ceilings.

Duplicate or regressing probe identifiers do not lower a learned probe baseline.
A new path generation resets its evidence. Continuous qualified light service
can retire a stable offset; local backlog or blocked transport prevents that
refresh. A lasting capacity change and a standing network queue can still be
difficult to distinguish, so long-running behavior remains a validation concern.

Control snapshots expose the selected RTT source, source-specific minima,
resulting excess and transport wait. Additional observed minima and any mixed
baseline comparison are diagnostics; they do not establish absolute one-way
delay or a queue-free physical path. Keep the associated observation timestamp
when interpreting a later rate-change event.

Tests should preserve real-delay, loss, socket-pressure and deadline responses
while checking source changes and path replacement. Controller allowances and
synthetic FIFO results are not end-to-end throughput measurements. Keep
workloads and budgets matched, retain complete populations and store private
run records in ignored `local/`.
