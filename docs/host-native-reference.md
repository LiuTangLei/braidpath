# Loopback host and native-carrier reference

`examples/native_host_reference.rs` is a finite, IPv4-loopback-only measurement
adapter. It does not replace a production transport. Client/server TLS roots,
native BBR, 9600-byte Quinn send buffer, 256-slot input, existing 64-record
per-flow queue, 100 ms queue age and 500 Mbps ceiling are retained. A separate
ALPN and constant-time token authentication prevent accidental use as HTTP/3.
No flow or datagram is accepted before authentication. All endpoints have finite
lifetimes, at most 16 local flows, and explicit cleanup/record ledgers.

Two reference frame profiles exist: a 12-byte routing/sequence header and a
55-byte header matching the **length** of an uncoded BraidPath record plus path
quality and HTTP DATAGRAM headers on stream zero. Padding is checked, not billed
as useful application data. Length equivalence is not semantic, authentication
message, feedback, statistics, fairness or scheduler equivalence. The reference
does not implement H3, adaptive scheduling, repair or path quality feedback.

`bench.host_reference` registers a mirrored comparison of raw loopback UDP,
thin/native-length-matched QUIC, complete overlay with native CC, and complete
overlay with adaptive CC. The same native source, raw measurement format,
Python routing adapter and echo generator are used. Every window has a 3-second
continuous source prefix followed immediately by a 10-second business suffix.
The prefix is costed separately, all missing slots remain, and the pooled P95
uses the raw population. This profile is host-local only: no delay/loss injection,
WAN-capacity estimate, automatically selected best path or production promotion.

Each stage is measured. In particular, source records not received by the local
test adapter are **not Internet loss**. API acceptance is not delivery proof.
The native reference has a simpler telemetry/actor path, so a difference cannot
be attributed solely to byte overhead or a particular algorithm. Full raw source,
receiver, echo, native/overlay statistics, identities and hashes stay in the
owned experiment directory. Child CPU is for the whole fixture, not endpoint
CPU alone. Loopback co-location puts source and receiver on one machine; it does
not establish the processing capacity of a split-host WAN topology.

Use host results to locate the next experiment, not to rewrite old WAN results.
Any network-native reference requires a separately reviewed explicit topology,
authentication, resource/protection envelope and corresponding same-load control.
No public address is accepted by the current native host reference.

The native API still obeys congestion control. RFC 9221 sections 5.2–5.4 also
distinguish transport ACKs from successful application processing and exclude
DATAGRAM frames from stream flow-control limits. Thus changing the reliable
stream receive window alone is not a datagram-capacity fix.

Reference: https://www.rfc-editor.org/rfc/rfc9221.html
