# Quinn protocol dependency

Source: `quinn-proto` 0.11.19 from crates.io, upstream commit
`8192ed399a26a6e8f0aba43d10ec8badaa5b905e`.
Crate SHA-256: `0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe`.
Upstream: <https://github.com/quinn-rs/quinn>.

Local change: before rejecting a stream with too many retained buffers, coalesce
all contiguous data into actual byte spans. Normal compaction retains large
buffers to avoid copying, which can leave more than 1,024 buffers for contiguous
data with mixed frame sizes. A deterministic 5,100,672-byte backlog reproduced
the failure without packet loss. The extra coalescing runs only when normal
compaction would otherwise close the connection. The original fragment count
limit, flow-control memory budgets and duplicate/gap flood tests remain in place.

The added regression covers mixed-size backlogs and a missing prefix restored
after the backlog arrives. Existing upstream security regression tests are
retained. This extends the coalescing work described in
<https://github.com/quinn-rs/quinn/issues/2809> and
<https://github.com/quinn-rs/quinn/pull/2814>; it is a local correction, not an
upstream release claim. Remove this patch when a verified upstream release
passes these regressions.

The source and dual MIT/Apache-2.0 licenses are preserved. Registry bookkeeping,
the upstream development lockfile and the redundant original manifest are omitted.
