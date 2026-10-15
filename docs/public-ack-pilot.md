# Readiness for a bounded public-network ACK pilot

The real-network pilot and the synthetic delayed-link experiment have different
instruments. The former runs the actual HTTP/3 client and server, native sources,
the existing application adapter, and a fixed relay. It does not run the
laboratory delay queue. A failure of the laboratory's five-millisecond timer
criterion remains a failure; it must not be relabelled as passed or used to
authorize claims about a calibrated artificial link.

Before a new low-load public functional pilot, `bench.http3_pilot_readiness`
instead exercises the actual HTTP/3 path on loopback without a delay simulator.
Both server-only ACK request profiles use the same source population, adapter,
total/group budget, queues, native BBR and authentication. It requires all 20,000
originals and all 200 requests, including their 200ms deadline, to be delivered;
source/adapter accounting, actual ACK direction, final endpoint identity and
owned-process cleanup must also pass. This is functional readiness, not a new
capacity qualification or a replacement for high-load calibration.

The old host-reference default remains the original high-load profile. The new
explicit readiness profile is 2,000 datagrams/second at 1,000 bytes for ten
seconds, no warmup, 20 requests/second, a 3s drain and 50Mbps aggregate/group caps.
Only the server requests ACK changes; the two profiles share the same 10ms
requested delay and reordering threshold. All buffers and the 100ms application
queue deadline remain explicit. Actual source spans and full missing cohorts
are retained, and the original timing-failed evidence is not modified.

Public runs still require the existing fresh production identity reference,
read-only observer pilot, frozen binary/source/collector identities, 8s
observation deadline, 15s heartbeat, finite workloads and exact-owned cleanup.
No qualification removes or weakens those protections. Missing calibration or
an incomplete public run does not permit default promotion. A single preselected
route is not proof of gain over the current best single connection, multiple
paths, or a high-load/real reliable HTTP/TCP workload.
