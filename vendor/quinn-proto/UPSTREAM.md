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
compaction would otherwise close the connection.

Second local change: a local regression shows the fixed 1,024-span bound can
also reject genuine loss holes. Alternating lost and received 1,200-byte frames
leave one span per 2.4 KB; a large flight can exceed 1,024 real spans. This is an
illustrative pattern, not a bound on all legitimate traffic or proof of the exact
WAN failure pattern. The live captures did not record span distributions. The bound is now the larger of 1,024 and one span per KiB of unread
extent (`end - bytes_read`), which flow control limits to the receive window.
The compaction trigger stays at twice the current bound. Span metadata therefore
remains a small fraction of window-bounded memory, and denser gap floods are
still rejected. A rejection logs span count, bound and extent under the
`braidpath::quinn` tracing target. Flow-control memory budgets and the upstream
duplicate/gap flood tests remain in place.

The added regressions cover mixed-size backlogs, a missing prefix restored
after the backlog arrives, a 16 MiB window with every other frame lost, and a
gap flood twice as dense as the scaled bound across the same extent, preseeded
with a high-offset frame in both ordered and unordered modes. Existing upstream security regression tests are
retained. This extends the coalescing work described in
<https://github.com/quinn-rs/quinn/issues/2809> and
<https://github.com/quinn-rs/quinn/pull/2814>; it is a local correction, not an
upstream release claim. Remove this patch when a verified upstream release
passes these regressions.

The source and dual MIT/Apache-2.0 licenses are preserved. Registry bookkeeping,
the upstream development lockfile and the redundant original manifest are omitted.

The local assembler also clips already-consumed ordered prefixes during
compaction. Overlapping retransmissions could otherwise reappear when an
application switched from ordered reads to unordered `read_to_end`, falsely
reporting trailing stream bytes. A regression covers duplicate-only and partially
unread overlaps. Aggregate TCP framing additionally checks EOF in ordered mode.

The packet pacer consumes BBR's modeled bytes-per-second pacing rate when it is
available, rather than deriving its rate from BBR's separately inflated in-flight
window. Controllers without an explicit rate retain window/RTT pacing. The burst
budget is recomputed and clamped when the modeled rate changes. A deterministic
regression covers rate-based refilling, reductions and return to window pacing.
This does not change the application bandwidth ceiling or synthesize ACKs.

The BBR bandwidth estimator now feeds every non-application-limited delivery
sample into its ten-round maximum filter. Previously it updated only for a new
maximum, so lower samples could never expire a stale high estimate. Samples
marked application-limited may raise the estimate but cannot lower it. Two
deterministic regressions cover peak expiry and the application-limited rule.
This corrects filter aging; it does not establish that all WAN loss is caused
by the estimator or change the configured application bandwidth ceiling.

The delivery estimator now captures delivered-byte and send/ACK clock state for
individual ACK-eliciting packets, using the flight-sampling model described in
<https://datatracker.ietf.org/doc/html/draft-cheng-iccrg-delivery-rate-estimation-02>.
It measures the entire acknowledged delivery interval divided by the larger of
its send and ACK spans, and retains the send-time application-limited marker.
This is an independently written local sampling correction, not a BBRv3 upgrade
or an assertion that the expired experimental draft is a published standard.
An inline snapshot uses at most 32 bytes, with no per-packet heap allocation or
separate map; recovery drops it on ACK, loss or packet-space disposal. The native
sent-packet size budget grows from 128 to 160 bytes and remains checked. Packets
from another path generation cannot contaminate the sampler after migration.

The first RTT sample establishes the probe clock instead of triggering an
immediate startup probe. A busy drain phase no longer advances its cycle index
while retaining the previous gain. Ordinary delivery also ages the extra ACK
aggregation window; its elapsed-byte arithmetic uses a wide intermediate so a
long-idle connection cannot overflow. Regressions cover ACK compression after
an unrelated send burst, stretched and reordered ACKs, idle restart, startup,
drain-phase retention and ACK-aggregation expiry. Startup window growth also
compares the current window against its target, correcting a comparison of the
unitless gain against a byte count that otherwise allowed continued growth
after the target was reached; a bounded-growth regression covers this.

The controller interface also exposes whether BBR is currently in its native
RTT-probe phase. Other controllers return false. This is phase telemetry only;
it does not change BBR's probe timing, pacing, loss response or flight window.
Quinn publishes the flag with its existing lock-free connection hints.
