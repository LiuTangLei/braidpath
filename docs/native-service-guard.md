# Experimental native service recovery

`--native-service-guard` is a **default-off**, local sender experiment. Enable it
explicitly on each endpoint being evaluated. It is active only with adaptive,
original-only traffic: FEC, small-record FEC, redundancy and independent capacity
probes must all be zero/off. Other configurations retain the existing controller.
The peer cannot enable this local option through session negotiation.

The experiment lets a new, positive receiver report renew a cautious application
admission allowance toward the connection's current native congestion window
divided by its RTT. This is a sending allowance, **not measured path capacity**.
Each renewal is bounded by the configured maximum and one doubling per native
RTT (with a 10ms minimum interval). It creates no burst tokens.

Recovery requires active demand, fresh positive delivery and finalized feedback,
low queue delay, no current transport blockage, no ordinary or fast-loss pressure,
and no active reprobe. A new reduction takes precedence. Existing post-brake
holds and at least two native RTTs after the last brake cannot be bypassed.
Repeated reports, idle traffic and first reports from a new generation cannot
renew service. Native startup remains separate.

Native BBR, authentication, packet mapping, scheduler weights, deadlines, total
and group limits, health checks and loss/delay brakes are unchanged. This option
does not implement reliable datagram retransmission or make a multipath speed
or latency guarantee. QUIC DATAGRAM already uses native congestion control; see
RFC 9221, section 5.4.

Diagnostics retain the live opt-in and native hint in each control sample,
record `native_service_recovery` rate changes, and count successful renewals in
`native_service_recoveries`. A zero count is not evidence of a speed improvement.

`python3 -m bench.native_service_readiness` performs a finite off/on actual-HTTP/3
loopback qualification with no synthetic link. Complete payload and interaction
populations are required. This test is not WAN capacity, best-single-route,
independent-path aggregation or reliable HTTP/TCP acceptance. Run-specific
conditions, artifacts and decisions belong in ignored `local/`.
