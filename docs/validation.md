# Validation plan

Validate in dependency order: codec → secure datagrams → paths/relays → scheduling → reliable streams → deployment. Automated tests and reusable harness code belong in the repository. Run records, captures, benchmark outputs and feasibility notes remain local in ignored directories.

## 1. Protocol and resource invariants

These are pass/fail gates, independent of speed:

- No corrupted or duplicate application delivery within an active flow; stable identity across original, repair and retransmission paths.
- No application data before connection authentication and authorized session admission; reject cross-client joins, stale epochs and invalid metadata.
- Recovered-data reports never create QUIC ACKs or count as original arrivals on a lost path.
- Valid originals do not wait for a full coding block. Block timers run without new input; distinguish encoder emission from actual transmission.
- All queues, decoder maps, report ranges and deduplication/reorder windows obey configured byte/count/time limits, including hostile authenticated inputs.
- Datagram overload/expiry is observable. Reliable overload applies backpressure; acknowledged bytes cannot be silently evicted.
- No oversized datagram is silently truncated, no unsupported path silently falls back to another interface, and no sequence or offset wraps into an active identity.
- Authentication failure, all-path loss, end-of-stream and server restart produce explicit outcomes within documented timeouts.

Exercise all erasure positions and arrival orders for small blocks, repeated/recovered originals, multi-erasure failures, repair loss and expiry. Add parser/property tests and fuzzing with length/allocation limits when the network format exists. Model checkable finite cases first; random tests complement them.

## 2. Secure single-path gate

Test the selected Quinn version and configuration before expanding the runtime:

| Area | Required check |
| --- | --- |
| Datagram negotiation | Unsupported peers and send-size errors are handled explicitly |
| TLS and session join | Trusted client succeeds; wrong client/server identity and foreign session join fail; no 0-RTT data |
| Encryption/FEC | Recover canonical records from authenticated originals/repair; invalid records cannot allocate unbounded state |
| Transport buffering | Saturate send/receive buffers; distinguish queue admission, local drop, wire loss and application acceptance |
| ACK semantics | Lose/delay reports; cumulative reports converge without crediting repaired bytes to the failed path |
| Timers | Sparse traffic, no new input, graceful stop, cancellation and deadline expiry |
| Packet packing | Several small symbols in one UDP packet; erasure injection at the socket boundary as well as at the symbol boundary |
| MTU | Negotiated small limit, PMTU decrease, different original/repair sizes and an unusable sub-minimum path |

Use bounded loopback impairment first, then Linux network namespaces/netem for actual queueing, delay, rate and UDP-packet loss. Verify the configured impairment with counters. Application-level omissions are useful codec checks, not proof of on-wire loss handling.

## 3. Topology and platform gate

Test `1×1`, `1×3`, `2×1`, then `2×3` (interfaces × entrances), in upload, download and simultaneous bidirectional traffic. Include direct and relay paths, relay-only operation and path removal/rejoin.

For relays, verify authenticated TURN/UDP allocations, main-server destination restrictions, channel/allocation refresh, return routing, idle expiry, port/source changes, quotas and forbidden destinations. A transparent loopback forwarder does not satisfy TURN integration or public relay authorization.

Capture on the selected physical interfaces and on both sides of each relay to prove the path actually used. Traffic counters from the main server alone cannot establish the client's interface. Test with competing default routes, IPv4/IPv6, NAT rebinding and interface address changes. Linux/macOS/Windows must each pass their native network cases; builds alone are insufficient.

Inject full path failure, relay restart and shared backhaul failure. Verify that surviving paths continue, stale generations are rejected and all-path failure is bounded. For unreliable service, report the resulting losses; claim lossless failover only after the reliable-stream gate passes.

## 4. A staged impairment matrix

Avoid starting with a huge Cartesian product. Run each mechanism alone, then selected interactions, then randomized stress.

| Dimension | Reference cases |
| --- | --- |
| Symbol/packet loss | 0%, 1%, 3%, 5%, 10%; distinguish injection boundaries |
| Loss shape | Independent Bernoulli, burst loss with stated burst lengths, simultaneous cross-path outage |
| RTT/jitter | Equal paths, asymmetric paths, time-varying jitter and delayed ACK direction |
| Capacity | Equal links, unequal links, changing capacity, server/backhaul bottleneck |
| Correlation | Independent access links; same access link with several entrances; common bottleneck beyond different interfaces |
| Workload | Isolated short messages, request/response, sustained bulk, small flows alongside bulk |
| Budget | FEC off; full-block XOR baseline; strict redundancy cap; budget exhausted during a loss burst |
| Receiver | Slow reader, CPU pressure, small receive credit/buffer and decoder eviction |
| Lifecycle | Path addition, disconnection, relay expiry, reconnect, flow close and shutdown |

Control cases include a good path plus a nearly unusable path, correlated loss that defeats XOR, and sparse arrivals slower than the block deadline. A scheduler must be able to leave a path mostly unused when using it harms delivery.

## 5. Fair comparisons

Use both **best single path** and **multipath without active redundancy**, with identical encryption, authentication, MTU limits, congestion controllers and offered load. Enable FEC as the single changed factor first. Add multi-erasure coding or hedges only in separate comparisons.

For datagrams, compare useful bytes delivered before a predeclared deadline and deadline-miss rate first. Reporting P99 only for the surviving packets can make a dropping implementation look faster. For reliable streams, compare full completion latency, goodput and failure/timeout rate; do not compare unreliable completion with reliable completion as if they were the same service.

Measure byte cost at named boundaries: application payload, encoded records, outer UDP/IP on client access links, relay backhaul and main-server links. Keep per-segment totals; summing both hops of a relayed packet is a resource-cost metric, not client-access overhead. Include headers, padding, retransmission, ACKs, probes and relay framing.

Measure CPU per endpoint and per delivered useful byte, plus peak memory and queue age. Pin hardware, build profile, crypto backend, batching/GSO settings and logging level. Account for the QUIC and relay adapter overhead before choosing a more expensive codec.

## 6. Statistical method and engineering targets

For controlled comparisons, use at least 10 paired seeds/runs, alternate baseline/candidate order, separate warmup and predeclare a stopping rule. Tail-latency cases should aim for at least 10,000 application observations per run; when that is impractical, report the smaller sample and avoid a precise P99 claim. Summarize paired run-level differences with confidence intervals; correlated packets are not independent trial repetitions.

Record every issued operation, including deadline misses, failures and right-censored timeouts. Show completion and deadline-miss rates beside latency. Use request/response latency on one monotonic clock unless synchronized clocks and their error bound support one-way measurement. Store all evidence locally.

Initial engineering targets for the designated reference scenarios below are **acceptance goals, not current results or universal promises**. Freeze scenario settings and any target revisions before measuring a candidate:

| Gate | Reference setup | Acceptance target |
| --- | --- | --- |
| Correctness | All deterministic protocol cases | No corruption, duplicate delivery or silent successful truncation |
| Capacity | Two equal independent links, no loss, no server/CPU bottleneck, FEC off | At least 90% of the sum of individually measured goodputs under the same framing and load |
| Datagram usefulness | 3% independent packet loss, matched traffic and total rate cap, predeclared deadline | Lower deadline-miss rate with FEC, no reduction in useful delivered byte rate; paired interval supports the claim |
| Reliable latency | 3% independent packet loss after stream recovery exists | At least 20% lower P99 completion time than the no-FEC reliable baseline, with no added failures and at least 90% of baseline goodput |
| Clean-path cost | Same single path, no loss, optional FEC disabled | No more than 10% goodput regression versus the minimal equivalent QUIC DATAGRAM adapter |
| Fairness | Several entrances share a bottleneck with one competing QUIC flow | Competitor goodput at least 90% of the one-entrance reference; bounded queue growth; no multiplication of configured group rate |
| Resource use | Sustained overload and churn | Stay within declared limits; resource state returns to the configured idle bound after expiration |

If a gain misses its gate, retain the simpler baseline or leave that optimization opt-in. A static rate cap does not establish fairness: the competing-flow test is still required. If shared-bottleneck behavior fails, default that group to one active data path plus bounded probes until a controller change passes; do not claim unrestricted bandwidth aggregation.

## 7. Reliable-stream and release gate

Reliable streams additionally require selective ACK recovery under report loss, per-flow credit, reordering bounds, final-offset acknowledgment, half-close/reset, exact byte/hash comparison and explicit failure on unrecoverable session loss. Run a short interactive flow alongside a bulk flow to check cross-flow isolation. FIN cannot overtake missing data into a false success.

A release needs the relevant native-platform topology cases, sustained lifecycle/resource tests, stable wire-version negotiation and operator documentation. Pin the chosen dependency versions and verify their Rust/platform requirements; the current core's Rust 1.85 minimum is not yet a promise for future network dependencies.

No performance claim is promoted from a codec test, a single local probe, or successful builds alone.
