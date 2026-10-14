# Receiver state and sender pressure accounting

With `--adaptive-fec-retention`, the receiver now adapts both the reconstruction
time horizon and the block-count budget. The fixed receiver still uses its
original 256-block policy.

The adaptive receiver measures advancement of the dense authenticated block-ID
space against its own monotonic clock. After a bounded measurement interval,
it budgets approximately 1.25 times the recent peak block rate times the longest
current retention promise, plus 32 blocks for interleaved small records. The
window grows promptly and contracts gradually with fresh lower-rate evidence.
It remains between 256 and 2048 block IDs. Duplicate and reordered old IDs do
not manufacture rate samples. Large authenticated jumps are still hard-capped.

Growing the window cannot lower the retired-ID floor or resurrect discarded
decoder state. The existing first-arrival deadlines and record-ID deduplication
remain independent. This is retention for opportunistic repair, not a playout
queue or an additional waiting period before original delivery.

An additional 8 MiB budget covers the decoder structures and their owned vector
capacities. If accepting a symbol crosses it, oldest retained decoder payloads
are retired before the receiver call completes. BTree bookkeeping, allocator
overhead and transient output records are not included in this capacity gauge;
they remain bounded separately by the 2048-block and existing record limits.
The gauge is not a promise that process RSS stays below 8 MiB. Timer expiry and
session close release the accounted state as well.

Expiry wakeups use a conservative cached earliest deadline. A stale early hint
can cause an extra sweep, but cannot extend a block's eligibility. Advancing the
block floor removes only the obsolete BTree prefix rather than scanning every
retained block for every packet.

Diagnostics live under each receiving session's `fec_retention.receive_budget`,
including current/peak block budget, recent block rate, decoder bytes and
byte-budget retirements. A retired block count is not the number of application
records lost; completed blocks can also be retired.

The sender's adaptive pressure observation also uses the connection's actual
empty-buffer allowance instead of assuming a 1200-byte buffer. With an explicit
larger buffer, occupied bytes are no longer accidentally reported as zero.
Transport-blocked classification includes feedback and HTTP DATAGRAM framing,
not just the inner record length. These observations do not raise rate caps,
disable congestion control or extend the sender queue deadline.

These changes have deterministic regression coverage for high block rates,
monotonic retirement, low-rate behavior, memory bounds, idle expiry and framed
queue pressure. Public-network throughput/latency claims require separately
recorded comparisons against the exact prior executable.
