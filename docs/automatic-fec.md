# Automatic sender FEC

Automatic FEC is the normal client behavior; no enable switch or `--fec` argument
is needed. `--fec auto` names that existing default. Both directions adapt independently using
authenticated receiver reports of symbol loss **before** FEC reconstruction.
Feedback is enabled automatically; adaptive path pacing still requires
`--adaptive`. Explicit `--fec 0` disables ordinary FEC, and numeric `--fec K`
preserves fixed K+1 coding. Both endpoints must support the `auto` session
policy; older servers reject it. Use a numeric value for older peers.

| Finalized loss rate | Full-block target | Repair/source symbol ratio |
| --- | --- | --- |
| < 0.2% | No FEC | 0 |
| 0.2% to < 1% | 32+1 | 3.125% |
| 1% to < 3% | 16+1 | 6.25% |
| 3% to < 8% | 8+1 | 12.5% |
| >= 8% | 4+1 | 25% |

Repair stays near four to twelve times the loss rate. Reliable streams
retransmit the residual loss that one repair per block cannot recover, and
short records and ACKs keep their own copies, so bulk protection does not try
to remove every loss at the cost of goodput.

Bulk traffic starts with no repair; short records and stream ACKs have independent protection from the first packet. Every 500 ms the sender takes deltas
of finalized cumulative counts, weighting active paths by symbol exposure.
Closed, silent (when another path is usable), or stale (>3 seconds) path
feedback is excluded. A full observation needs at least 64 newly finalized
symbols; sparser feedback accumulates for up to two seconds. A window still
below 64 symbols can raise protection, with its losses counted against at
least 32 symbols, so one sparse loss selects at most 8+1.
It cannot lower protection. Duplicate, byte-only, empty, and sparse reports
cannot trigger a downgrade. A connection generation starts a new counter
baseline and discards pending sparse samples, unconfirmed counts, and any pending downgrade.

If any symbols are sent on eligible paths and no qualified feedback
arrives for three seconds, the sender returns bulk protection to 4+1 and forgets
its loss estimate. An idle session keeps its strength.

Loss is smoothed with a 0.5 EWMA weight. Upgrades use the higher of the newest
raw sample and the EWMA, and happen on that observation. Loss is finalized
before it is reported, so protection follows the onset of loss by roughly
one to two seconds; a short burst during a no-FEC interval is repaired by
retransmission. Each weaker level has its own three-second qualification hold,
requiring both rates to stay 20% below the entry threshold of the next stronger
level. Changing between safe weaker targets does not restart every hold;
a loss sample cancels only the levels it no longer supports. The weakest
qualified level is selected, and an upgrade clears all pending holds. Empty
ticks cannot complete a hold; gaps longer than one second cancel all holds.
This is an engineering policy, not a calibrated optimum
or an independent physical packet-loss estimator.

Switching closes any partial old block and preserves monotonically increasing
block IDs, including across no-FEC intervals. Originals remain immediate.
The existing `--block-ms` deadline and `--redundancy-percent` admission budget
still apply: partial blocks can have a higher nominal ratio, but actual repairs
cannot exceed available budget. Lower budgets may prevent the chosen target
from being admitted. Auto requires a positive repair budget and one repair;
explicit small-record, mixed, dual-repair, and capacity-probe experiments retain
their numeric FEC configuration.

This policy does not recover arbitrary burst loss or a whole failed path, and
it does not guarantee a throughput gain. See [statistics](statistics.md) for
the current target, loss denominator, and transition counters. Private run
records and topology-specific results belong in ignored `local/`.

## Independent short-record and ACK protection

Auto negotiates `braidpath-auto-small: 1` with an explicit response echo. Both
endpoints must support it; fixed numeric FEC remains compatible with older peers.
Records of at most 128 application bytes and all reliable-stream ACKs (including
large selective ACKs) use a separate protection lane. A cold,
unknown target permits one repair copy; qualified clean target 0 permits none
for UDP records and ACKs, while short reliable-stream data retains one copy,
32+1 permits one, 16+1 and 8+1 permit two, and
4+1 permits three. From 1% loss interactive records keep two copies although
bulk repair stays at 16+1: copies are cheap, and an acknowledgement direction
paced near its own demand may not have budget for a retransmission. Stream
ACKs take at most one copy at any level: each is superseded by the next, and on
an asymmetric uplink their extra copies add to the reverse load that causes loss. The copies carry identical authenticated repair bytes and one
block ID; the receiver delivers once. Delayed originals remain duplicates.

Only an actually admitted original authorizes its own generated/queued copies.
They cannot borrow bulk credit or fund bulk repair. Auto additionally caps repair
admission for this class at min(aggregate rate / 4, 1 Mbit/s), a 2400-byte maximum
idle burst, and charges the datagram frame plus the existing 80-byte pacing cost.
A continuous download acknowledges continuously, and each ACK is superseded by
the next, so ACK copies may spend only credit above 1200 bytes. That remainder
stays available for the first records of new and interactive streams.
All originals, copies, feedback and probes still share aggregate/group caps and
native congestion control. Budget or queue pressure can discard a repair.

The existing small-record delivery policy ranks timely paths and separates
same-path copies until the previous datagram has left Quinn's outgoing queue.
This avoids relying on multiple copies packed into the same native datagram.
Independent packet loss remains an approximation; shared failures can lose every
copy. These bounds prioritize interaction without promising a latency deadline.

Qualified clean feedback removes proactive UDP/ACK copies even when the
bulk k stays zero. Short reliable-stream data keeps one immediate copy within
the same independent budget: waiting for its next packet would add a full RTT
to an isolated request. Short reliable retries carry local transmission identity:
second attempts authorize one copy, third/later attempts authorize three, within
the same rate/credit/queue limits. This protects recovery before a finalized loss
report arrives. With zero selected copies the control record is plain, keeps
normal latency scheduling, and does not earn bulk repair credit.
