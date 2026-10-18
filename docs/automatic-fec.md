# Automatic sender FEC

The client defaults to `--fec auto`. Both directions adapt independently using
authenticated receiver reports of symbol loss **before** FEC reconstruction.
Feedback is enabled automatically; adaptive path pacing still requires
`--adaptive`. Explicit `--fec 0` disables ordinary FEC, and numeric `--fec K`
preserves fixed K+1 coding. Both endpoints must support the `auto` session
policy; older servers reject it. Use a numeric value for older peers.

| Finalized loss rate | Full-block target | Repair/source symbol ratio |
| --- | --- | --- |
| < 0.1% | No FEC | 0 |
| 0.1% to < 0.5% | 32+1 | 3.125% |
| 0.5% to < 1% | 16+1 | 6.25% |
| 1% to < 3% | 8+1 | 12.5% |
| >= 3% | 4+1 | 25% |

The sender starts at 4+1 until feedback qualifies. Every 500 ms it takes deltas
of finalized cumulative counts, weighting active paths by symbol exposure.
Closed, silent (when another path is usable), or stale (>3 seconds) path
feedback is excluded. A full observation needs at least 64 newly finalized
symbols; sparser feedback accumulates for up to two seconds. A window still
below 64 symbols can raise protection, with its losses counted against 64
symbols, so it never selects more than full evidence of the same losses would.
It cannot lower protection. Duplicate, byte-only, empty, and sparse reports
cannot trigger a downgrade. A connection generation starts a new counter
baseline and discards pending sparse samples, unconfirmed counts, and any pending downgrade.

If any symbols are sent on eligible paths and no qualified feedback
arrives for three seconds, the sender returns to the starting 4+1 and forgets
its loss estimate. An idle session keeps its strength.

Loss is smoothed with a 0.5 EWMA weight. Upgrades use the higher of the newest
raw sample and the EWMA, and happen on that observation. Loss is finalized
before it is reported, so protection follows the onset of loss by roughly
one to two seconds; a short burst during a no-FEC interval is repaired by
retransmission. Downgrades
require both rates to stay 20% below the current entry threshold with a stable
lower target for three seconds of qualified observations. Empty ticks cannot
complete the hold; gaps longer than one second cancel it. This is an engineering policy, not a calibrated optimum
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
