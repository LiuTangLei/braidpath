# Calibrating the directional ACK laboratory

The laboratory is a measurement instrument, not the production transport. A
change in its receive service, socket storage or scheduling requires new
calibration; it cannot be presented as a production throughput optimization.
Historical experiment artifacts and unsuccessful calibration attempts remain
unchanged in the local evidence directory.

## Native receipt is not application receipt

The instrument records three different layers in each direction: application
API admission, QUIC DATAGRAM frames transmitted/received, and application reads.
It also records endpoint UDP counters and modeled-link receipt/forwarding.

An application-read gap after native receipt indicates an instrument/consumer
boundary problem; do not relabel it as loss on the modeled link. UDP count gaps
are only cumulative observation differences. Control traffic and snapshots taken
at slightly different moments can affect them; they are not precise physical
loss-location or per-request packet assignments.

The receiving task now drains a bounded ready batch before reevaluating send
queues. The batch adds no new application queue and no intentional delay. It
continues to validate every message's run, sequence, kind, timestamp and body,
and retains all missing/late request slots. The send path also subscribes to
Quinn's actual datagram-space readiness instead of relying only on the next
receive event or periodic tick. Expiry is checked before polling the sending
operation, so a late wake does not extend the record's deadline.

## Instrument resources are explicit

`--socket-receive-bytes` and `--socket-send-bytes` affect only the four freshly
created loopback sockets. Both default to zero, retaining OS defaults; explicit
requests must be between 64 KiB and 4 MiB. Each socket reports its initial and
actual buffer sizes. An unsuccessful or clamped request is not assumed to have
been applied. No system-wide socket setting is changed.

The bounded relay drains packet batches using Quinn's native UDP runtime adapter,
including the adapter's received-segmentation metadata. Sixteen 64 KiB receive
slots limit the workspace to one MiB per direction. The existing modeled FIFO,
service rate, propagation time and maximum queue size are unchanged. Due packets
advance before another timer is armed. The relay uses two finite dedicated
IO/timer workers in one shared runtime, separate from the four workers serving the test connections.
This is additional instrument resource use, not evidence of lower production CPU.

Each relay socket is registered once and shared through the native async socket
adapter. A blocked send retains the exact FIFO head and waits for native write
readiness while permitting receive progress. The existing memory, queue-time and
propagation bounds remain. This removes overlapping registrations; it does not
by itself prove why any historical host dropped packets.

Sample files use a bounded 64 KiB buffered writer, flushed explicitly. Token-by-token
JSON writes must not turn a finite post-load artifact save into an unbounded
mounted-filesystem operation. Serialization/flush failure remains a failed run.

Socket headroom does not guarantee bounded residence time, establish network
capacity, or permit accepting a misleading benchmark. Timer lateness and source
lateness remain visible. A larger socket queue is not a substitute for prompt
receive/forward service.

## Health gates

`bench.lab_health.classify` is a pure evidence checker. It cannot run workloads
or reclassify a historical failure. A clean reference requires complete business
originals and request deadlines, closed API/native and native/application
accounting, no leftover application queue, the registered source supply,
complete owned-socket evidence, no intentional model loss, and measured model
timer lateness no greater than five milliseconds. The five-millisecond value is
an explicit calibration criterion, not a property guaranteed by the OS.

ACK-study acceptance additionally requires all four no-artificial-loss control
windows to pass clean calibration and no receive-consumer/timer contamination in
the remaining windows. Older files without boundary measurements remain
uncalibrated; absence of a counter is not evidence of zero loss. Lower ACK counts
or better throughput cannot override these prerequisites.

## Regression versus capacity qualification

Portable functional tests verify integrity, expiry, cleanup and both matched ACK
profiles at a modest fixed load. They are not throughput results.

The high-load `calibrated_clean_link_preserves_both_request_and_bulk_cohorts`
qualification retains the fixed 10,000 datagrams/second, 1,000-byte data,
20-millisecond modeled one-way delay and full business population. A separate
`plaintext_relay_reference_preserves_sustained_datagrams` qualification removes
QUIC, ACKs and encryption to distinguish instrument service from protocol work.
Both are explicit release-profile diagnostics rather than default CI speed
requirements, since CI hosts cannot guarantee the required service. A failed
qualification remains a failed qualification; a passing low-load regression
cannot substitute for it.

Neither these checks nor the native UDP adapter establish real Linux-host,
public-network, multi-path or reliable HTTP/TCP gains. Those remain separately
registered experiments after the applicable instrument calibration passes.

## Primary API references

- Quinn 0.11.12 TransportConfig: incoming DATAGRAM overflow discards old unread
  data; outgoing overflow and buffering are distinct from stream flow control.
  https://docs.rs/quinn/0.11.12/quinn/struct.TransportConfig.html
- Quinn 0.11.12 AsyncUdpSocket: bounded native receive batches, segmentation
  metadata and explicit write-readiness notification.
  https://docs.rs/quinn/0.11.12/quinn/trait.AsyncUdpSocket.html
- Quinn 0.11.12 Runtime: converting owned sockets to the native runtime adapter.
  https://docs.rs/quinn/0.11.12/quinn/trait.Runtime.html
