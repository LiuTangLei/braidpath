# Research direction: identifiable, deadline-constrained multipath service

## Decision and implementation status

The next research question is **which additional transmission produces additional
unique application delivery before its deadline, and which shared resource pays
for it?** It is not whether a higher configured send rate, more paths, or more
repair bytes makes a throughput counter larger.

The implementation in this branch consists of an offline stage-accounting audit
(`bench/delivery_frontier.py`) and a shadow-only rate-pulse interpreter
(`bench/frontier_response.py`). The second consumes a proposed evidence contract;
its collector and live control integration are **not implemented**. Neither tool
changes transport behavior, opens sockets, performs SSH, alters congestion
control, discovers physical bottlenecks, or promotes a runtime candidate. Unit
fixtures are synthetic counterexamples, not public-network performance results.

This investigation preserves the distinction between the experimental datagram
runtime and a reliable HTTP/TCP service. Existing low-latency production services
are not an experimental transport component to replace during diagnosis.

## 1. Start from resources and information, not protocol branding

UDP specifies message delivery without reliable ordering or congestion control.
It does not grant capacity or bypass a router, a policer, a socket queue, a CPU,
or a shared access link. QUIC DATAGRAM adds security and QUIC congestion control
without automatic retransmission of the application datagram. A transport ACK
does not establish successful application processing. See RFC 8085 and RFC 9221.

An operational queue model is:

```
backlog_next = max(0, backlog + admitted_work - completed_work)
queue_wait approximately backlog / sustainable_service_rate
```

These are planning approximations, not identities for a bursty stochastic queue.
Long-run admitted work above service must accumulate or be disposed of. Bounded
queues protect latency by disposing of work; those disposals do not locate the
underlying bottleneck. Enlarging the queue changes the trade-off, not capacity.

Record at least three kinds of limitation separately:

| Limitation | Needed evidence | Wrong conclusion to avoid |
| --- | --- | --- |
| Source/application supply | Original backlog, source pacing, actual emitted work | Low demand means low path capacity |
| Host/overlay admission | First rejecting gate, actor service time, queue residence, aggregate/group budget | Every full local queue proves slow CPU |
| Carrier/network/receiver | Actual socket transmission, in-flight allowance, ECN/loss, receiver service and delivery | API acceptance proves a packet was transmitted |

Quinn's congestion control and the overlay's per-path adaptive controller both
affect supply. Investigate their interaction; do not infer that their combination
is wrong merely because both exist. A smaller overlay budget can censor the
delivery-rate observation. BBR's handling of application-limited samples is an
important analogy, not proof that a particular estimator is faulty here.

## 2. Use two different graphs

**Resource graph:** paths can share access bandwidth, relay/backhaul capacity,
server uplink, aggregate policers and endpoint service. One path can consume
several overlapping resources; a single mutually exclusive group ID cannot
represent every possible bottleneck topology. Configured caps are ceilings, not
measured capacities.

For a conceptual resource incidence matrix `A`, all original, repair, retry and
probe traffic must satisfy `A * wire_rate <= resource_capacity`. Independent
capacities can add; duplicated use of one capacity cannot. Different entrances
can improve effective delivery through route diversity even when they cannot
multiply the common access-link capacity.

**Failure graph:** two routes can have correlated losses without sharing the
currently limiting capacity, and share capacity without perfectly correlated
loss. Estimate paired deadline failures only from properly matched trials. Do
not infer `P(A and B fail) = P(A fail)*P(B fail)` from marginal loss rates.

For two copies, the deadline failure event is a joint event. Temporal spacing
changes both correlation and the remaining deadline. The second copy is useful
only if it improves first-useful delivery enough to pay for its resource cost.
RFC 8382 describes statistical shared-bottleneck inference and its limitations;
RFC 6356 motivates coupling resource use, not blindly adding independent senders.

## 3. Optimize useful delivery and preserve reliable semantics

The research objective is a measured frontier, not one magic operating point:

```
G_D = unique application bytes delivered within deadline D / actual source span
```

Report unconditional completion/latency, total unique goodput, outer wire bytes,
CPU and drops alongside it. Unsent/missing observations remain in the population.
The denominator for a mixed process ledger is not the bulk-only test population.

Interactive work should be evaluated by its completion deadline, not merely its
packet size. Small bulk packets are not automatically urgent; a large interactive
response is not automatically expendable. Bulk transfers can use a slower path
when its incremental service outweighs reordering and completion cost. Maintain
per-flow ordering and receiver credit for reliable work, not one global ordered
queue across unrelated flows. A reliable adapter must backpressure/recover or
explicitly fail; it cannot silently adopt datagram expiry as successful delivery.

A future scheduler should compare predicted **finish time**, including local
wait, transport allowance, serialization, path delay uncertainty and per-flow
dependencies. Lowest RTT alone ignores queued work and capacity. RTT/2 is not a
certified one-way delay. A stale or unknown estimate must remain uncertain.

## 4. Repair is a downstream decision, not the first control signal

Systematic originals should not wait for a coding block. The repair strategy
should follow observed burst lengths, deadline slack, matched loss diversity and
available shared-resource budget. Sliding-window FEC or selective cross-path
repair is a promising later candidate because it can decouple repair emission
from a fixed block closure (RFC 8680/8681); its rank, overhead, CPU and deadline
behavior must still be tested.

FEC cannot reconstruct an application record that was dropped before encoding.
An encoded original dropped locally may still be reconstructed from a surviving
repair; counting both the local disposal and recovered delivery as final loss
would be wrong. FEC may not hide actual congestion signals (RFC 9265).

For an idealized erasure channel with independent loss `p`, ignoring framing,
finite block effects and deadlines, a necessary average condition is
`(1 + repair/source)*(1-p) >= 1`. This is not a sufficient finite-deadline
guarantee, especially for burst or whole-path loss. More redundancy consumes
capacity; it does not create it.

## 5. Stage ledger: the first implemented gate

The offline auditor requires final clean endpoint snapshots, the same single
session at both endpoints, complete aggregate/session censuses, and closure of
each server-return record equation:

```
application_received = ingress_enqueued + pre_ingress_dispositions
ingress_enqueued = sender_enqueued + pre_sender_dispositions
sender_enqueued = sender_consumed + unconsumed_shutdown
sender_consumed = originals_generated + ingress_expiry
originals_generated = originals_enqueued + encoded_original_queue_disposals
originals_enqueued = originals_api_admitted + encoded_expiry + encoded_shutdown
```

Encoding errors have both record and timer-flush origins, so nonzero ambiguous
encoding-error counts are rejected rather than assigned fictitious records.
Repair symbols remain a separate population. Input hashes identify exactly what
was read; the audit does not claim to revalidate the entire historical binary,
collector and source-archive chain. A protection-failed campaign remains failed,
even when some closed windows can be audited.

Optional timeline analysis counts distinct sampled controller states. It does
not convert snapshots into durations. Backlog plus a non-full API buffer does
not prove that a congestion window or pacer offered an immediate transmission
opportunity. Exact limiter ownership is deliberately returned as unknown.

## 6. New identification experiments, not more fixed-overload version trials

Do not alter or repeat an already completed campaign to improve its result.
Register new experiments independently, retaining previous failures and keeping
production protection, rate ceilings and exact-owned cleanup intact.

| Stage | Question | Treatment and required evidence |
| --- | --- | --- |
| Host reference | Can the endpoints serve the required packet rate? | Isolated loopback/private reference; same sizes/codec/queues; source, actor, socket and sink census; no claim of WAN capacity |
| Single-path frontier | Which service is available under each offered rate? | Fixed bounded rate levels, warm connections, actual wire supply, backlog and on-time outcomes; both directions separately |
| Paired-path intervention | Does extra use of one route add useful service or displace another? | Hold other offered rates/settings fixed, one small additive pulse, reference before/after, same cohorts and deadlines |
| Fixed-total redistribution | Does moving the same total load improve completion? | Change the path allocation, not total demand or repair allowance; distinct experiment from an additive pulse |
| Control ownership | Is an overlay gate limiting otherwise usable carrier service? | Instrument actual rejecting gates first; then separately test a precise overlay-only treatment with native CC/caps retained |
| Recovery frontier | When does repair beat another original or retry? | Only after capacity/queue evidence; matched loss and timing, uncoded control, separate useful-byte and wire-byte populations |

Use measurements to choose operating regions, not to lower the original
acceptance requirement. A lower-load survey is calibration; it is not passing a
higher-load throughput/SLA test. Warm steady state and cold-start behavior need
separate registered evaluations.

### Shadow pulse interpreter

`interpret_pulse` is an offline evidence contract, not an active controller. It
requires uncoded, disjoint original IDs, complete cohorts, valid deadline clocks,
protection, no local original disposals and one declared offered-rate treatment.
It normalizes byte counts by actual source spans and returns, among others:

- Requested increase not realized at the socket: limiter remains unidentified.
- Reference changed too much: drift, not a capacity decision.
- Extra useful bytes without extra queue cost or displacement: observed positive
  marginal yield, **not** an estimate of maximum capacity or path independence.
- Other paths lost useful delivery: observed interference, **not** proof of the
  physical location of a shared bottleneck.
- Extra total bytes miss deadlines or queueing rises: do not call it low-latency
  capacity gain.

The defaults (5% reference drift, 50% pulse realization, 10% minimum marginal
yield and 5 ms queue growth) are explicit engineering screening thresholds, not
physical constants. Freeze them before collection. Synthetic model clocks are
forbidden as measured deadline proof. The real pulse collector still needs
actual socket/cohort attribution; existing cumulative API counters alone cannot
supply the contract. No synthetic outcome is promoted to a measured result.

## 7. Subsequent control architecture, conditional on evidence

The candidate architecture is a hierarchy with explicit owners: native transport
controls per-path in-flight congestion exposure; the session allocates shared
resource budgets and schedules useful work against deadlines; recovery consumes
the same resource accounting. A supervisor tracks estimator uncertainty and
permits finite identification probes only within safety budgets. Unknown
capacity must neither be treated as zero forever nor as permission to flood.

This could require changing the current controller structure rather than
micro-optimizing it. That decision is contingent on identifying the binding
constraints, not on assuming raw UDP, an alternative congestion algorithm, or a
new codec will necessarily outperform the existing carrier.

## Primary sources

- RFC 8085, UDP Usage Guidelines: https://www.rfc-editor.org/rfc/rfc8085
- RFC 9221, QUIC DATAGRAM sections 5.2–5.4: https://www.rfc-editor.org/rfc/rfc9221
- RFC 8382, Shared Bottleneck Detection: https://www.rfc-editor.org/rfc/rfc8382
- RFC 6356, Coupled Congestion Control: https://www.rfc-editor.org/rfc/rfc6356
- RFC 9265, FEC Coding and Congestion Control: https://www.rfc-editor.org/rfc/rfc9265
- RFC 8680/8681, Sliding Window FEC: https://www.rfc-editor.org/rfc/rfc8680 and https://www.rfc-editor.org/rfc/rfc8681
- BBR draft-ietf-ccwg-bbr-06, section 5.5.4 (draft, not an RFC): https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr-06#section-5.5.4
