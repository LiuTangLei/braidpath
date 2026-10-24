# Architecture and feasibility

This document defines the implementation direction and its acceptance gates. The experimental implementations are described in the [runtime guide](runtime.md) and [proxy operation guide](mesh.md); the broader design below still includes future work. See the [README](../README.md) for current capabilities and the [roadmap](roadmap.md) for dependencies.

Distributed mode implements a leaderless server directory and leased opaque
entrances. Every server can be an exit; session state lives only at the client
and its selected exit. See [distributed servers](mesh.md) for implemented
behavior, trust boundaries and limits.

## Implemented v0.5.0 TCP profile

The TCP proxy combines the existing leaderless mesh control plane with the
aggregate DATAGRAM data plane. One SOCKS5 listener selects one exit; one
application TCP connection opens one target TCP socket there. Multiple encrypted
paths carry that byte stream under one aggregate session, without creating
parallel target connections. Mesh membership, certificate/token authentication,
destination authorization and UDP association handling remain control boundaries.

The reliable stream engine uses byte-offset SACK, cumulative acknowledgments,
receiver credit and explicit FIN/reset. Fine-grained repair can move to a healthy
path, and automatic FEC shares the aggregate scheduler and rate budget with
original records. QUIC handles security and per-path congestion control; it does
not retransmit DATAGRAM payload. Ordered delivery and repair remain above the
paths rather than inside reliable per-path QUIC payload streams.

TCP uses ALPN `braidpath-stream/2` and capability `proxy-stream-v2`, requiring a
coordinated client/server upgrade. Native SOCKS UDP retains `braidpath-proxy/1`
without FEC; the existing fixed-target UDP tunnel remains a distinct service.
The former TCP record-RPC profile is replaced, with no transport-selection knob.
Implementation correctness, WAN stability and single-connection multipath gain
are independent acceptance gates. The profile remains experimental.

## 1. Feasibility boundary

The topology is implementable: independently reachable client–entrance paths can carry symbols belonging to one endpoint session, and nearby relays can forward those paths to one client-selected exit. The expected latency and capacity gains remain workload- and network-dependent.

| Constraint | Consequence |
| --- | --- |
| Several entrances share the client's access link | No capacity multiplication at that bottleneck |
| Relay backhauls converge on one server uplink | Server/backhaul capacity bounds aggregate goodput |
| Correlated loss removes several symbols in a block | One XOR parity symbol is insufficient |
| Repair arrives after the application's deadline | Recovery may succeed without improving useful delivery |
| Redundancy competes with originals on a congested link | More FEC can increase delay and reduce goodput |
| Different path RTTs create reordered arrivals | A byte stream still waits for missing earlier bytes |

For independent original/repair symbol erasures with probability `p`, a full XOR `k+1` block leaves a particular original unrecovered with probability `p × [1 − (1 − p)^k]`. This is an analytical model, not a performance result. Correlated loss, packet packing, variable sizes, and deadlines invalidate its simplifying assumptions.

## 2. Engineering baseline: encrypted unreliable paths

For the first engineering baseline, use **one end-to-end QUIC connection per active interface–entrance pair**, carrying application data and repair symbols in DATAGRAM frames. Quinn is the candidate Rust runtime. This requires neither kernel multipath support nor a Multipath QUIC extension. The QUIC-specific choices below describe this baseline, not mandatory internals of the aggregate core or a finalized deployment profile.

QUIC DATAGRAM preserves unreliable delivery while sharing QUIC's security and congestion control. Its data is not automatically retransmitted. Small reliable streams carry session setup and infrequent control operations; bulk payload and time-sensitive receipt reports remain datagrams. These are protocol capabilities, not a claim that FEC defeats congestion. [RFC 9221, sections 5–6](https://www.rfc-editor.org/rfc/rfc9221.html#section-5)

Responsibilities are explicit:

| Layer | Owns |
| --- | --- |
| QUIC implementation | TLS keys, transport packet numbers/ACKs, transport loss detection, connection congestion control, pacing, PMTU discovery |
| BraidPath path adapter | Interface/socket binding, bounded queues, datagram size checks, measured path observations |
| BraidPath session | Membership, logical data IDs, FEC, application receipt reports, optional reliable recovery, deduplication and flow limits |
| Application adapter | Datagram deadlines or ordered byte-stream semantics, authorized destination mapping |
| Relay | Profile-specific forwarding restrictions and return mapping; no application decryption |

A custom carrier over UDP would also need a secure handshake, congestion controller, pacing and loss feedback. Retain it as a candidate when deployment reachability or measured runtime limitations justify that engineering cost; do not assume it is more reachable merely because it is not QUIC. In the low-latency baseline, do not replace DATAGRAM payloads with reliable per-path streams: that would add an independent retransmission/ordering layer beneath aggregate recovery.

### Reachability under filtering and censorship

QUIC DATAGRAM is carried over UDP and still establishes a QUIC connection. Choosing DATAGRAM changes payload delivery semantics; it does not disguise the handshake or turn a custom application into ordinary HTTP/3 traffic. QUIC Initial protection is observable by on-path parties; it does not provide the secrecy of established traffic keys. [RFC 9001, sections 5 and 7](https://www.rfc-editor.org/rfc/rfc9001.html#section-5)

Keep three decisions separate: aggregate recovery/scheduling, secure congestion-controlled datagram transport, and the externally visible carrier/encapsulation. The aggregate core consumes authenticated records and bounded path observations; it must not depend on Quinn types, TLS certificate APIs or QUIC packet numbers. A different carrier must provide equivalent authentication, resource and congestion guarantees. Do not disable identity verification to improve handshake success.

The preferred deployment candidate is an independently implemented Rust HTTP/3 service with authenticated HTTP Datagrams. It uses the same QUIC connection for security, congestion control and data delivery; it does not tunnel one QUIC stack through another. Xray is a design reference only, with no runtime dependency or wire-compatibility requirement. The [carrier design](transports.md) explains the applicable lessons from REALITY, Vision, XHTTP, Hysteria and MASQUE, including why an H3 HTTP body is not a DATAGRAM path.

Plain QUIC remains the engineering control. A future HTTPS stream profile and any datagram-preserving packet mask require separate acceptance. Raw UDP probes diagnose basic reachability only. TURN allocation/authentication does not prove censorship resistance either. Any wrapper changes MTU, wire cost, queueing and possibly delivery semantics. Reliable carriers cannot inherit the datagram baseline's latency claims or silently join its coding groups.

FEC helps when enough symbols arrive. It cannot recover a consistently blocked handshake or a route that drops every usable symbol. Co-located entrances may also share filtering policies, so route count is not censorship independence.

Before selecting a deployment default, pass the [deployment reachability gate](validation.md#deployment-reachability-gate) on the intended networks. No current BraidPath test establishes reachability on filtered networks or resistance to active probing. This gate precedes deployment selection; performance-only success cannot waive it.

## 3. Session, path and data identity

Current mesh and proxy profiles verify the selected exit's pinned server
certificate and authenticate client credentials inside the encrypted application
exchange before admitting destinations or data. Session joins verify the same
authorized identity. Profile-specific handshake and resumption policies do not
replace these checks. Ordinary website requests remain separate from authorized
proxy use; credential trust, rotation and revocation are deployment requirements.

The first authenticated connection creates a session. Additional connections request a join over a control stream. The server checks the same authorized client identity, session identifier, current session epoch, protocol version and negotiated limits before accepting their data. Knowing a session ID alone grants no access.

A path is a logical interface–entrance pair with a **generation**, not merely a remote IP. Replacing a socket/connection creates a new generation; stale reports must not update the replacement. NAT rebinding requires transport address validation. Interface changes must not silently turn an explicitly bound path into the default-route path.

Use separate identity spaces:

- QUIC packet numbers remain private to each connection and direction.
- A session epoch and direction scope all BraidPath data/block IDs.
- Logical data IDs survive FEC recovery and resending on another path.
- Flow IDs and message IDs / byte offsets describe application delivery.
- FEC block ID, symbol index, codec profile and actual source count describe coding.

Do not use the current `(block, index)` alone as a session-wide delivery identity. The session must work when FEC is disabled or a repair packet is lost. Reliable flow termination declares the final byte offset so a lost tail cannot look like successful completion.

Control operations need request IDs and idempotent responses so they can be retried through another surviving path. A primary control connection must not become a permanent single point of failure. All-path loss permits bounded reconnection; expiry or selected-exit restart produces an explicit session failure, not silent byte-stream continuation.

## 4. FEC and encryption order

The initial design is **canonical application record → FEC → QUIC encryption on the selected path**. Decode only authenticated records obtained from connections admitted to the session. Relays see ciphertext. Do not XOR different connections' QUIC ciphertext or reuse their keys/nonces.

A source symbol must include enough coded information to recover delivery identity: flow/message ID or byte offset, flags, payload length and bytes. Block metadata is carried inside the authenticated DATAGRAM. Validate counts, lengths, codec profile, direction and block window before allocating decoder state. Recovery derives an application record from authenticated symbols; it does not reconstruct a QUIC packet or generate a transport ACK.

The current codec accepts arbitrary byte payloads, emits originals immediately, and closes a block at `k` or a caller-driven deadline. A network adapter can encode a canonical record into that payload. Its 1200-byte bound is an **in-memory limit**, not a safe network payload size. The decoder is block-scoped, emits unordered deliveries, and should be discarded after an error; error returns do not promise rollback.

FEC capacity and timing are distinct. With one repair symbol, two missing originals remain missing; a failed path often removes several. Multi-erasure codes, retransmission for reliable flows, or expiration for deadline traffic must handle the remainder. Never wait indefinitely for a block to fill or for FEC before considering reliable recovery.

Small symbols can share a QUIC/UDP packet. Losing that packet can therefore erase multiple symbols from one block. The validation harness must model the actual packing boundary instead of treating every codec symbol as an independent network loss. Interleaving or larger codes are later choices, with their delay/CPU cost measured. Sliding-window coding is a candidate, not an assumed improvement. [RFC 8681](https://www.rfc-editor.org/rfc/rfc8681.html)

## 5. Two delivery services, two kinds of acknowledgment

The UDP tunnel provides **unreliable datagrams with optional FEC**. Deliver originals/recovered data once within a bounded deduplication window, drop late messages by policy, and report losses. An expired or unrecoverable datagram is not a reliable-transport failure. Sender queue deadlines use its local monotonic clock; receiver expiry uses a negotiated lifetime/playout policy. Never compare raw monotonic timestamps from different machines. End-to-end deadline success is measured by the requesting application or synchronized instrumentation.

The v0.5.0 TCP proxy implements **reliable ordered streams** with selective
application ACKs, bounded retransmission, receiver credit, byte offsets,
FIN/reset semantics and explicit failure. Selective ACKs suppress redundant
repair; cumulative ACK progress releases retained source bytes. Receiver credit
includes accepted but undelivered data, which cannot be evicted after
acknowledgment. Reordering is per flow, not across unrelated streams.

Host-wide admission permits bound TCP to 256 flows across sessions. TX and RX
each share 32 MiB of retained-data credit, with a 128 KiB progress reserve per
flow and direction. Idle streams do not preallocate shared data. TX credit is
acquired before reading a socket, and retries reuse it. RX charges only new
bytes and retains credit until local delivery or header consumption. Under
pressure, a cumulative-point repair may use its flow's reserve; other data is
dropped before SACK state changes. ACK/FIN/RESET processing is independent of
data credit, and live ACKs precede bounded replay-control responses.

Flow ownership spans the mux and its socket tasks. Cancellation works even when
the open/attach command channel is full. Explicit session termination closes
its flows and releases I/O, while half-close preserves the other direction.
A new session generation cannot inherit old Flow handles or recreate an exit's
lost external TCP socket. Host-wide TCP payload pacing reuses the proxy's
combined TCP/UDP rate bucket; the default operational ceiling remains 10 Gbit/s.

| Signal | Meaning | May stop reliable resending? | May erase QUIC loss? |
| --- | --- | --- | --- |
| QUIC ACK | A transport packet reached the peer's QUIC stack | No, by itself | QUIC handles its own state |
| BraidPath accepted-data report | Peer retained an original or recovered record for delivery | Yes | No |
| BraidPath original-arrival observation | An original arrived on a specific path generation | Used for path statistics | No |

Recovered data must not be credited as original delivery on the failed path. Otherwise FEC hides loss and misleads scheduling. QUIC's actual loss/ECN signals remain intact. [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html)

Receipt reports are authenticated, cumulative/selective, bounded and periodically refreshed so a lost report does not cause endless retransmission. Feedback may travel over another active path; same-path probes provide attributable RTT samples. RTT/2 is only a heuristic, not a measured one-way delay.

## 6. Scheduling, queues and budgets

Begin with a bounded, observable scheduler; introduce adaptation after baselines exist. Prefer eligible paths with low estimated completion cost, using application queue age/bytes, transport-buffer availability, delivered original byte rate, RTT/jitter and recent health. Upstream and downstream maintain separate observations. Do not infer precise bandwidth or transmission times from undocumented runtime internals.

Use one sender owner per connection and bounded queues by bytes and age. A full path must not stall all other senders. Quinn exposes datagram limits and queue space; `send_datagram` may replace older queued datagrams, while `send_datagram_wait` waits for capacity. Deliberate cancellation/drop policies and deadlines belong in the adapter. Enqueue success is not wire transmission or application delivery. Do not assume an already-enqueued datagram can be recalled: keep the runtime queue small and enforce receiver expiry too. [Quinn Connection API](https://docs.rs/quinn/0.11.12/quinn/struct.Connection.html)

Maintain bounded probes on suspect paths; probe traffic counts toward the same limits. FEC, retransmissions and probes cannot bypass the transport's congestion control. Repair generation and on-wire transmission are separate timestamps.

Before enabling multiple entrances, implement an aggregate pacer/rate cap plus explicitly configured bottleneck groups. All paths through one client access interface share its initial group; operators can merge other known shared routes and cap server/backhaul use. Rate caps are necessary operational bounds, **not proof of fairness**. Independent QUIC connections can still compete unfairly against one competing flow. Automatic shared-bottleneck detection and coupled congestion control are later research, informed by [RFC 6356](https://www.rfc-editor.org/rfc/rfc6356.html); its TCP algorithm cannot simply be copied into QUIC.

Active redundancy uses a bounded token bucket: credit from original encoded bytes admitted for sending, debit for repair/hedge bytes with the same framing basis, fixed maximum credit and no unbounded idle accumulation. Queue drops and actual wire totals remain separate counters. No silent startup debt. Reliable retransmissions use a separate recovery allowance but still obey the overall pacer and receiver credit.

Sparse traffic exposes a real trade-off: closing every one-packet block with parity costs roughly one extra symbol. A strict 10% budget cannot protect every isolated packet that way. Budget exhaustion must skip repair and report reduced coverage, or the user must explicitly select a higher-overhead policy. FEC overhead must be measured in bytes, including padding, not just `m/k`.

## 7. Relay and interface integration

For the QUIC engineering baseline, the reference authenticated relay route is **TURN over UDP** using an existing TURN server, with one allocation per client path and peer permission for the selected exit. A client adapter exposes the relayed datagrams to Quinn; QUIC still terminates at the selected exit. Allocation/channel refresh, idle timeouts and return mapping are mandatory. TURN over TCP/TLS is outside the initial low-latency baseline because a reliable outer stream can introduce ordering delays. [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html)

Restrict TURN relay destinations to the configured selected exit, with host firewall enforcement for the intended UDP port. TURN permissions alone are per IP, not a port allowlist. Bound allocations, per-client bandwidth and idle lifetime. Test wrong credentials, forbidden destinations, expiry and rebinding. An unrestricted transparent UDP forwarder is not a public deployment design.

For the web-facing HTTP/3 candidate, public TURN framing would change the visible protocol. Evaluate a **fixed-destination L4 entrance** that forwards only the configured selected exit service address/port and preserves its encrypted handshake in both directions. Authentication of proxy use remains on the selected exit; normal website requests are permitted without proxy credentials. Bound relay state, traffic and idle lifetime, preserve return mapping, and expose no client-selected destination. This profile has different admission and abuse controls from TURN and requires its own acceptance. TURN integration is not a prerequisite for selecting fixed L4 entrances.

For direct and fixed-L4-entrance paths, supply an explicitly configured UDP socket to Quinn. For TURN paths, use its abstract socket adapter and account for TURN framing, batching and PMTU behavior. Integration must demonstrate correct per-datagram metadata and segmentation rather than assuming default GSO behavior survives a wrapper. [Quinn Endpoint API](https://docs.rs/quinn/0.11.12/quinn/struct.Endpoint.html)

| Platform | Planned binding | Required evidence |
| --- | --- | --- |
| Linux | Interface binding, source address and policy route where needed | Traffic on requested device, including competing default routes |
| macOS | `IP_BOUND_IF` / IPv6 equivalent with an interface index | Capture on the actual interface and reconnection after address change |
| Windows | `IP_UNICAST_IF` / IPv6 equivalent plus source binding | Actual egress and return delivery; not merely the selected local address |

Use the supported OS APIs and fail clearly when explicit binding cannot be honored. A one-interface mode can use normal routing. See [socket2](https://docs.rs/socket2/0.6.5/socket2/struct.Socket.html#method.bind_device_by_index_v4) and [Microsoft socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options). Cross-platform codec CI does not establish any of these network behaviors.

## 8. MTU and bounded state

For each coding group, choose a symbol size fitting all selected data/repair paths. Deduct BraidPath headers and coding length fields from the runtime's current maximum DATAGRAM payload; the relay adapter must also limit the underlying UDP size for its own outer encapsulation. QUIC needs a path capable of 1200-byte UDP payloads; a relay wrapper needs additional space. [RFC 9000, section 14](https://www.rfc-editor.org/rfc/rfc9000.html#section-14)

On a smaller-path join or MTU decrease, close the current block, start a new size/profile generation, and stop sending oversized records on that path. Pending reliable records require explicit resegmentation with stable byte offsets. The v0.3.0 UDP runtime implements bounded message fragmentation/reassembly up to a negotiated 4,096 bytes above the existing 1,000-byte record format (see runtime.md). Larger local messages are rejected with an oversize counter. Never silently truncate or rely on IP fragmentation.

Negotiate and enforce limits for paths, flows, active blocks, symbols, pending bytes, report ranges, retransmit state, reordering and idle time. Expired block IDs stay outside a bounded acceptance window so replaying a retired block cannot allocate it again. Full queues apply backpressure to reliable flows and explicit drop/expiry to datagrams. Authenticated peers still need size and resource checks.

## 9. What still has to be demonstrated

The architecture has a practical implementation route, but runtime selection is gated on bounded queue behavior, profile-specific relay feasibility and real interface binding. The HTTP/3 candidate additionally needs correct HTTP behavior, authenticated datagram mapping and measured fingerprint limitations. Deployment selection requires deployment reachability evidence. Performance acceptance additionally requires shared-bottleneck competition, correlated loss, sparse traffic and both directions. CPU-efficiency optimization is deferred until the latency/throughput behavior is established. Neither a successful codec test nor a local encrypted-path probe proves those properties.

The [validation plan](validation.md) defines those gates. Test records and feasibility-probe outputs stay local; this document contains design decisions and methods only.

The [delivery-frontier research plan](delivery-frontier.md) separates resource
constraints, failure correlation and deadline utility. Its current tools audit
historical stage accounting and interpret a proposed rate-pulse contract offline;
they are not a live scheduler or a claim of measured capacity.
