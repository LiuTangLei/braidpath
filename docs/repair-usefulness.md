# Local repair usefulness guard

`--repair-usefulness-guard` is an opt-in local sender filter, off by default.
It applies only to explicitly negotiated mixed two-repair bulk blocks. It does
not change coding bytes, receiver behavior, clocks, pacing, memory/queue limits,
repair credit, small-copy traffic, BBR or any other transport setting.

The sender records a bit only when its own bounded original-symbol queue
permanently rejects that source index. When P or Q is generated for a completed
block, three or more such indices prove that this implementation cannot recover
any missing original from its two equations. The existing decoder requires at
most two missing members. This is not a prediction of remote loss or queue state.
The optional filter drops only those generated bulk repairs, before queueing or
spending any transmission credit. It does not reimburse tokens or count repairs
as useful delivered bytes. Other blocks and all surviving originals are unchanged.

Pending and in-flight originals are never counted as permanent erasures. Loss
after admission and later expiration are deliberately not inferred by this
minimal filter. One or two local rejections retain both repairs; unknown or
evicted metadata conservatively retains them. Each index contributes one bit,
so duplicated bookkeeping cannot manufacture three distinct missing originals.
The bitmap fits existing structure padding on the tested 64-bit targets;
the existing 512 metadata entries and 64/256 queue bounds do not change.

Both modes count `repairs_locally_unrecoverable` and its encoded bytes as a
shadow diagnostic. Enabled mode also counts `repairs_locally_unrecoverable_skipped`
and bytes, and records trace reason `locally_unrecoverable`. These repairs were
generated but never queued. Old counter consumers must include this optional
pre-queue terminal count in conservation. None of these counters means physical
NIC bytes saved: the unfiltered repair might instead have expired or lacked credit.

This is a proved local-delivery-preserving filter in the deterministic fixtures,
not a WAN bandwidth or latency guarantee. Runtime admission and changed path
feedback can change later scheduling. Public comparisons must retain complete
source/request populations and all original limits; no automatic promotion.
