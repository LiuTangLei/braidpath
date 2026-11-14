# BraidPath changes to Quinn 0.11.12

The connection driver and UDP dependency integration differ from the crates.io
release (benches, tests and examples are omitted).

## UDP dependency

The UDP backend uses [`quinn-udp` 0.6.3](https://github.com/quinn-rs/quinn/releases/tag/quinn-udp-0.6.3)
rather than upstream Quinn 0.11's 0.5 dependency. Both manifest forms are updated, including forwarding Quinn's `log`
feature to the renamed `udp/tracing-log` bridge. The application lockfile at the
repository root selects the dependency used by BraidPath.

The UDP dependency itself also enables `tracing-log`: keeping only its old
`tracing` feature would compile but select the new backend's no-op log macros,
hiding refused-send diagnostics. A regression captures an OS-refused send via
the native adapter and verifies the diagnostic reaches a tracing subscriber.

The native runtime adapters deliberately retain `UdpSocketState::send` with a
narrow deprecation expectation. In Quinn 0.11, forwarding every error from the
new `try_send` API would terminate a connection, including on an oversized PMTU
probe. Keeping `send` preserves the existing behavior: readiness backpressure is
returned while an OS-refused datagram is dropped for QUIC recovery. The new
transport-error queue is not enabled. `tests/udp_backend.rs` exercises the real
Tokio adapter's error policy and IPv4/IPv6 receive boundaries, including GSO when
the socket advertises it.

The new receive interface index and kernel timestamp fields remain available in
`RecvMeta`; the protocol driver continues to use its existing receive clock and
address metadata. This dependency change does not claim timestamp-driven RTT
sampling or modify the patched BBR controller. Apple's private fast datapath
remains opt-in and is not enabled by this integration.

## Connection hints

The connection driver holds the connection lock for its whole poll, including
the UDP send. A task that reads connection state from another thread waits for
that poll to finish. The patch publishes, at the end of each driver poll and on
every accepted datagram, a few values that can be read without the lock:

- `Connection::is_closed`
- `Connection::datagram_send_buffer_space_hint`
- `Connection::max_datagram_size_hint`
- `Connection::rtt_hint`, `min_rtt_hint`, `cwnd_hint`
- `Connection::probing_rtt_hint` reports the native BBR RTT-probe phase, without changing congestion control.
- `Connection::liveness_hint` (received ACK and transmitted eliciting-frame counts)

`Connection::datagrams_drained` resolves when the published send buffer space
grows or the connection closes. Published space never exceeds the actual
space, because transmissions in progress are published when their poll ends.

Liveness counters use the same publication points. The sender's 5 ms reachability
check reads these counters and `rtt_hint` without waiting for a UDP send in the
driver. Sent frames are published before the release-store of received ACKs;
the reader loads ACKs first. These are monotonic advisory values, not a new
synchronized connection-statistics API. The existing silence bound and new
connection reset remain unchanged.
