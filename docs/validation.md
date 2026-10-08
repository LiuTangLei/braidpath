# Validation plan

Initial priority: latency and useful throughput. CPU consumption may be recorded for diagnosis but is not a current acceptance gate or an optimization target; optimize CPU efficiency later. Correctness, bounded memory/queues and explicit traffic limits remain required.

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

### Carrier semantics and cost gate

Apply this gate to the native Rust HTTP/3 candidate described in [carrier design](transports.md), before committing the multipath runtime to it. Xray is a source reference, not a required test service or product dependency. Start with a plain-QUIC control and the HTTP/3 candidate; add an HTTPS stream profile only when needed.

| Area | Required evidence |
| --- | --- |
| Real HTTP behavior | Independent HTTP/3 client can retrieve the configured website; wrong/absent proxy credentials cannot obtain aggregate service; normal errors contain no private configuration or custom diagnostic banner |
| Datagram negotiation | Both QUIC DATAGRAM and HTTP Datagram settings are supported; authenticated request/context mapping is enforced; unsupported peers fail explicitly |
| Delivery semantics | After actual UDP packet loss, a later independent source/repair record can reach the decoder without waiting for the missing record's retransmission; separately demonstrate any ordering delay of stream profiles |
| Authentication | Server verification, application credentials, cross-client session rejection, invalid contexts, replay/stale epochs and no early application data; normal website access does not require mTLS |
| Queue ownership | Saturation, cancellation and deadline expiry are observable and bounded at every layer; successful writes and deadline setters are not assumed to prove transmission or cancellation |
| Path ownership | Distinct interfaces/entrances really use distinct sockets/connections; pooling cannot merge the supposed paths; connection replacement updates its generation |
| Framing | Account for HTTP Datagram context/request identifiers, QUIC/IP, control messages and padding; detect PMTU changes and avoid automatic proxy fragmentation |
| Website consistency | Verify the configured domain, certificates, ALPN, H3 settings and normal requests over the advertised protocols; if TCP HTTPS is advertised, verify its behavior too |
| Fingerprint limits | Capture cold/repeated handshakes, QUIC parameters and Initial packet sizes/packing, plus steady-state sizes/cadence with FEC and scheduling enabled; compare with the selected reference client and record remaining differences instead of claiming a browser match from ALPN alone |

Keep application authorization, cryptographic verification and resource bounds intact while changing the wire appearance. Probe behavior from clients without credentials on authorized endpoints. A successful website retrieval establishes HTTP behavior, not unobservability or GFW reachability. Packet randomization and TLS-terminating intermediaries are separate profiles, with separate trust and reachability checks.

Measure the incremental HTTP/3 cost with FEC off first, then enable identical FEC settings as the single changed factor. Match transport congestion control, physical paths, offered load, total access-link rate, crypto, MTU and batching. Count padding, website/probe responses and all control traffic. Report cold establishment separately from steady-state payload delivery. At the reference clean-path gate, require at least 90% of the minimal plain-QUIC adapter's goodput, no additional deadline misses, and bounded memory/queue state; CPU-efficiency acceptance is deferred. Do not hide a slower adapter behind additional connections or a more aggressive controller.

After that, repeat the single/multipath, packet-loss, useful-delivery, fairness and resource gates below using the complete selected carrier. The preferred HTTP/3 profile is rejected or revised if it consumes the recovery gain. A stream profile gets its own baseline and claims; it cannot pass by inheriting datagram results. Actual deployment selection still requires the reachability gate.

## 3. Topology and platform gate

Test `1×1`, `1×3`, `2×1`, then `2×3` (interfaces × entrances), in upload, download and simultaneous bidirectional traffic. Include direct and relay paths, relay-only operation and path removal/rejoin.

Test the chosen relay profile. For TURN/UDP, verify authenticated allocations, main-server destination restrictions, channel/allocation refresh, return routing, idle expiry, port/source changes, quotas and forbidden destinations. For web-facing fixed L4 entrances, verify that only the configured main service address/port is reachable, ciphertext remains end-to-end, both directions preserve the entrance, mapping/rate/state limits hold, and proxy authorization is enforced at the main server. Ordinary website requests may pass without proxy credentials. A simple loopback forwarder proves neither production profile.

Capture on the selected physical interfaces and on both sides of each relay to prove the path actually used. Traffic counters from the main server alone cannot establish the client's interface. Test with competing default routes, IPv4/IPv6, NAT rebinding and interface address changes. Linux/macOS/Windows must each pass their native network cases; builds alone are insufficient.

Inject full path failure, relay restart and shared backhaul failure. Verify that surviving paths continue, stale generations are rejected and all-path failure is bounded. For unreliable service, report the resulting losses; claim lossless failover only after the reliable-stream gate passes.

### Deployment reachability gate

For GFW-affected or otherwise filtered deployments, validate the complete on-wire profile separately from loss recovery. Laboratory impairment and localhost tests cannot establish censorship resistance.

- Compare plain QUIC and the native HTTP/3 candidate on the intended access networks, with authorized endpoints; include another profile only when proposed for deployment. Low-volume UDP reachability probes are a diagnostic baseline, not a deployable protocol.
- Record ISP/access type, direction, endpoint profile, packet-size range, time window, handshake success/time, sustained useful traffic, idle/reconnect behavior and repeatability. Use multiple time windows and relevant access networks before making a deployment-specific claim.
- Distinguish failure to establish, failure after establishment, partial throughput, ordinary queue loss and persistent unreachability. Collect evidence at both endpoints. A failed probe alone is not proof that the GFW caused it; check routing, NAT, host firewall and provider policy too.
- Count unsuccessful connections and full-route outages in availability results. FEC recovery rates among surviving sessions cannot hide establishment failures.
- Test direct and relayed profiles independently. Include encapsulation overhead, handshake/control traffic and return-path behavior. A TURN allocation's success is not evidence that subsequent end-to-end traffic remains usable.
- Preserve endpoint authentication and configured rate/resource bounds. State the observation scope and date; do not extrapolate a temporary success into durable censorship resistance or probe resistance.

For a claimed deployment profile, the operator must specify required establishment success, sustained availability and reconnect time before comparison. Select no cross-border default until repeated observations meet those requirements. Keep all measurements and infrastructure details local.

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

Record CPU per endpoint and per delivered useful byte for later optimization, plus peak memory and queue age. CPU cost does not reject an otherwise useful initial implementation. Pin hardware, build profile, crypto backend, batching/GSO settings and logging level. Account for the QUIC and relay adapter overhead before choosing a more expensive codec.

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

A release needs the relevant native-platform topology cases, sustained lifecycle/resource tests, stable wire-version negotiation and operator documentation. Pin the chosen dependency versions and verify their Rust/platform requirements; the current runtime requires Rust 1.88 or newer.

No performance claim is promoted from a codec test, a single local probe, or successful builds alone.
