# BraidPath changes to Quinn 0.11.12

Only `src/connection.rs` differs from the crates.io release (benches, tests and
examples are omitted).

The connection driver holds the connection lock for its whole poll, including
the UDP send. A task that reads connection state from another thread waits for
that poll to finish. The patch publishes, at the end of each driver poll and on
every accepted datagram, a few values that can be read without the lock:

- `Connection::is_closed`
- `Connection::datagram_send_buffer_space_hint`
- `Connection::max_datagram_size_hint`
- `Connection::rtt_hint`, `min_rtt_hint`, `cwnd_hint`

`Connection::datagrams_drained` resolves when the published send buffer space
grows or the connection closes. Published space never exceeds the actual
space, because transmissions in progress are published when their poll ends.
