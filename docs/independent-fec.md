# Independent bulk repair equations

The throughput branch has an opt-in two-repair codec. Existing sessions keep
the original single-XOR codec, wire bytes and defaults. No deployment or WAN
performance claim follows from enabling the new mode.

For a client session, append:

```text
--mixed-fec --small-fec-bytes 128 --fec 16 --fec-repairs 2 --redundancy-percent 13
```

Both endpoints must support the extension. The authenticated request and response
must agree on `braidpath-fec-repairs: 2`; a missing, unknown, duplicate or mismatched
response does not silently downgrade. The absent header means the legacy
single-repair format. The new flag defaults to `1`, and `2` requires explicit
mixed FEC with a bulk block size of at least two. Small records retain their
existing immediate original-plus-one-repair encoding, not two repair copies.
In adaptive mixed mode, that one small copy is admitted to Quinn at least 10 ms
after its original's actual admission, without extending the ingress deadline.

## Coding and delivery

Each bulk original is emitted immediately. A full block or the existing timer
emits two length-prefixed, zero-padded parity symbols. P is the original XOR
equation. Q weights source index `i` by the distinct nonzero field element `i+1`
over GF(256), with primitive polynomial `0x11d`. For two missing symbols `x,y`
with coefficients `a,b`, the decoder solves `x+y=P` and `a*x+b*y=Q` after
subtracting the known symbols. `a XOR b` is nonzero, so either two missing
originals, or one missing original and one missing repair, can be reconstructed.
The decoder validates both reconstructed length/padding fields before committing
either record. Identical repeats are idempotent; conflicting metadata is rejected.

This is a private two-equation codec, not an RFC 5510 wire implementation.
Systematic MDS erasure coding and its finite-field background are described in
RFC 5510, sections 8.1–8.3. This implementation has no new dependency and does
not claim interoperability with that RFC or with the separate TCP relay.

## Budget and boundaries

The nominal full-block redundancy is `2/16 = 12.5%` of source symbol count.
Thirteen percent allows limited framing headroom but does not guarantee that
every generated repair is admitted. Short blocks still produce two full repair
symbols. **Actual admitted HTTP DATAGRAM bytes**, including both P and Q, debit
the existing bulk repair budget and the ordinary total/group rate budget.
They cannot spend the separately reserved small-record allowance. Merely
generating a symbol or losing an original creates no repair credit.

The original sender age, short queues, record-ID deduplication and receiver-local
retention remain in force. Fixed reception uses 256 block IDs; adaptive retention
also uses the bounded [rate-derived block and byte budget](receiver-budgets.md).
Retention is not a playout delay. Both hard bounds can still retire state before
the time limit when demand exceeds their capacity. More than two missing source symbols, or
insufficient independent received equations, remain unrecoverable without later
original arrival. No reliable-stream or retransmission layer is introduced.

## Wire and observation

Existing kinds `0` (original), `1` (P), and `2` (plain) are unchanged. Kind `3`
is Q, with the same block/count/body layout as P. A receiver rejects Q unless
the session negotiated two repairs. Q does not enlarge the maximum datagram.

P and Q use distinct receiver observation tokens 32 and 33. Packet traces use
`symbol.kind = repair_q` for Q and do not invent a record ID from parity bytes.
Consumers of the old strict trace schema must explicitly support or reject this
new kind; the old single-parity replay corpus remains a legacy reference.
Generated/admitted/dropped repair counters count both equations. Their totals
are not the number of uniquely saved application messages.

## Verification

The repository tests exercise all two-erasure combinations for blocks of
1, 2, 4, 8, 16 and 32 source symbols, including unequal lengths, opposite receive
orders, duplicate symbols, either parity alone, invalid/conflicting metadata,
short timer flushes and block-ID exhaustion. A same-erasure fixture compares
two 8+1 blocks with one 16+2 block at equal nominal repair count; it is a codec
mechanism test, not a throughput benchmark. Runtime tests exercise authenticated
bidirectional HTTP/3 paths, policy negotiation, mixed small-record coding,
repair accounting and distinct Q trace events.

Run the relevant suites with:

```sh
cargo test --offline --locked --test dual_fec
cargo test --offline --locked dual_
cargo test --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
```

Public-network comparison with the single-repair candidate, latency tails,
actual wire traffic and high-load retention still requires separate measured
evidence. Keep the mode opt-in until those tradeoffs are verified.
