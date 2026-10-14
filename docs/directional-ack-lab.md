# Directional ACK-frequency laboratory

## Implemented scope

`examples/directional_ack_lab.rs` is a finite, native, single-process QUIC
experiment. All sockets bind to ephemeral IPv4 loopback addresses; there are no
configurable external targets. It authenticates the TLS certificate and a random
test token, uses the project's pinned BBR and bounded datagram buffer, and never
changes the production transport configuration. The protocol is a laboratory
protocol, not HTTP/3 or a wire-compatible BraidPath endpoint.

One downstream sender requests either `every-two` (threshold 1) or `every-eight`
(threshold 7). Both profiles request a maximum ACK delay of 10ms and reordering
threshold 2. The upstream/client endpoint requests no policy change. Actual
ACK_FREQUENCY send/receive counters are checked in both directions. These are
peer requests, not promises of exactly one ACK per N packets. The shared profile
module also preserves `unchanged` as the reference-example default.

## Removing the earlier measurement bottleneck

The bulk source, request source, original sink and echo responder are written in
Rust and live inside the experiment. They do not pass through the former Python
UDP application adapter. Every configured source record has an original slot:
issue time, API admission, application reception or explicit missing/disposition.
Requests additionally record service observation and response admission. Full
completion latency starts at application issue, not API admission; local wait
is not hidden. The reference still has bounded native queues and can legitimately
dispose of work when the native transport cannot serve the offered workload.

This improves identification but is not identical to a two-host deployment.
Both endpoints, sources and the link model share one process and four Tokio
workers. Process CPU is explicitly combined, not per-endpoint CPU. The model
container/Mac host is not a proxy for the actual Linux servers' capacity.

## Fixed resource scenarios

`python3 -m bench.directional_ack_study --binary <built-example> --output <new-dir>`
pre-registers eight windows: two/eight/eight/two with an unlimited reverse packet
resource, followed by the same order with a synthetic 2,000-packet/s resource.
Both directions have 20ms modeled propagation. The reverse resource has at most
20ms of scheduled additional service wait and bounded memory; overflow is
explicitly counted. The forward direction has no configured packet-rate limit.
No kernel qdisc, sysctl, firewall or service is modified.

All windows offer 10,000 original 1,000-byte payloads per second (80Mbps before
the 55-byte laboratory record overhead) and 50 requests/s. Two seconds of source
warmup are accounted separately from eight business seconds; two seconds of
drain follow. This is mechanism identification, not a reduced-load substitute
for the best-single-connection aggregation target. Completed workloads are not
retried for a preferred result.

The proxy forwards real encrypted UDP packets without looking at whether they
contain ACKs or requests. It reports offered, forwarded, discarded and shutdown
counts, actual timer lateness and maximum modeled wait. Real task scheduling can
add jitter beyond the requested propagation; that limitation must remain in the
report. This is not a claim to reproduce any specific public-network policer.

## Measurement and acceptance

Original business bytes are counted once, after application validation. Warmup
bytes do not earn business credit. All request slots, including locally unsent
and missing requests, remain in the completion/tail population. Phase-aligned
native counter differences use recorded snapshot times; in-flight packets that
cross boundaries prevent exact per-source-cohort wire attribution.

The predeclared engineering screen requires two windows per profile, at least
95% of control goodput, no worse on-time fraction, at least 95% on-time requests,
finite pooled P95 no more than 1.05 times control, and at least 15% fewer native
reverse UDP packets. Lower ACK counts alone are not success. Missing or invalid
generator, negotiation, lifecycle, source identity or accounting evidence stops
the study rather than silently changing denominators.

Raw source/request slots, timeline counters, model queue dispositions, exact
configuration, binary/source hashes and process completion records are retained
in ignored local output. Public documentation must not substitute controlled
laboratory performance for Linux/WAN, multipath or reliable HTTP/TCP validation.

## Standards status

The pinned Quinn 0.11.12 documentation states support for ACK-Frequency draft-04.
The working-group draft-14 page retrieved on 2026-10-15 is marked expired, with
an expiry date of 2026-08-09. Neither is a final standardized-protocol claim.
This experiment verifies the pinned implementation pair and does not guess
interoperability with other versions.

- https://docs.rs/quinn/0.11.12/quinn/struct.AckFrequencyConfig.html
- https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-14
