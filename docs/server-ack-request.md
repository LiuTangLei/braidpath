# Server-only ACK-frequency requests

The server exposes `--ack-request unchanged|every-two|every-eight`. The runtime
default is `every-eight`, and the client makes the same request of the server
unless `--legacy-recovery` is set (see "Reverse load on an asymmetric uplink" in
[runtime](runtime.md)). The library entry points keep `unchanged`. No policy is
activated by traffic, a remembered path score, or a benchmark result.

The two experimental modes ask a supporting peer to acknowledge by the second
or eighth ack-eliciting packet. They use the same requested maximum delay of
10 ms and the same reordering threshold of two. The only difference in their
request tuple is the ack-eliciting threshold (one versus seven).

The server flag configures the server transport; the client's request follows
its own `--legacy-recovery` choice. Real authenticated HTTP/3 regressions check
received payloads, extension negotiation, and the unchanged mode's absence of
negotiation.

These are negotiated peer requests, not a command to discard ACKs or to ignore
loss. Pinned Quinn can clamp requests; its wire implementation follows the draft
version documented by that dependency. Native BBR, TLS, recovery, token admission,
queue deadlines, configured rate ceilings, FEC settings and path allocation are
not changed by this flag. The original `serve` and transport constructors remain
available and call the unchanged policy.

The reusable example profile uses this same request implementation to prevent
laboratory and runtime tuples from drifting. Sharing the policy code does not
make the example an equivalent public-network benchmark.

## Pilot discipline

A new field comparison must freeze an identical binary in both arms and verify
the actual server flag plus native negotiation counters at both peers. Requests,
unique payload delivery, full-population latency and reverse packets/bytes must
remain separate metrics. A single preselected route is not the contemporaneous
best route, and a request-policy ratio is not a multipath-over-single-path ratio.

Low-rate pilots are functionality and operating-envelope checks, not a substitute
for a failed high-rate calibration. Their offered load, aggregate/group ceilings,
path count and total duration must be declared before running. Incomplete health
verification, protection failure, changed identities, missing source cohorts or
unconfirmed cleanup prevents acceptance. Preparing or building a candidate does
not authorize deployment or promotion.

The existing production observation timeout, heartbeat policy and exact-owned
cleanup remain required for any protected public-network campaign. A blocked or
unknown qualification is left unresolved rather than bypassed. No rate-reducing
pilot reclassifies an earlier failed capacity or timer-fidelity test.

## Primary documentation

- Quinn 0.11.12 ACK frequency request semantics:
  https://docs.rs/quinn/0.11.12/quinn/struct.AckFrequencyConfig.html
- RFC 9221 on DATAGRAM congestion control, acknowledgements and application delivery:
  https://www.rfc-editor.org/rfc/rfc9221.html
