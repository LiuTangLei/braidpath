# Roadmap

## 0.7.0 release scope

The 0.7.0 line combines the native download return and Game policies and removes
retired recovery interfaces. See the [release notes](releases/v0.7.0.md) and
[release readiness checklist](release-readiness.md).

Current commands and policy boundaries are documented in [runtime](runtime.md),
[mesh](mesh.md), and [reliable streams](reliable-streams.md).

| Area | Implemented in the candidate |
| --- | --- |
| Application entry | Fixed UDP/TCP forwarding, per-exit SOCKS5/HTTP CONNECT, and bounded UDP associations |
| Reliable TCP | Byte-offset ACK/SACK, receiver credit, half-close, failure recovery and shared memory limits |
| Download policy | Negotiated native HTTP/3 return bodies for bulk DATA/FIN, QUIC-owned carrier recovery, bounded storage, and DATAGRAM receive arbitration |
| Game policy | Separate UDP service, original and copy priority, spaced protection, local deadlines through Quinn admission, and local-drop-aware network feedback |
| Multipath control | Path generations, current-source RTT baselines, receiver delivery qualification, explicit group limits and bounded reconnection |
| Operations | Platform installers, lifecycle events, structured transfer evidence and bounded diagnostic output |

The ordinary UDP policy retains its existing defaults. Native return and Game
are mutually exclusive session choices; use separate sessions/listeners. Their implementations are not a claim that every
network gains throughput, that logical paths have independent capacity, or that
a local deadline bounds end-to-end latency.

## Work after this release

These are research questions, not extra requirements to add to this release:

- Native-return scheduling based on path-attributed completed delivery and
  continuous application progress.
- Whole-message UDP scheduling and the marginal benefit of individual copies
  under correlated loss and delayed local service.
- Long-running qualification across capacity changes, idle restart and partial
  path replacement.
- Shared-bottleneck fairness and independent physical-interface validation.
- CPU or allocation changes only after profiling identifies a limiting stage.

TUN integration, automatic carrier fallback, browser fingerprint shaping and
additional coding families remain separate proposals. They do not justify
keeping retired runtime implementations in the current tree.

## History and evidence

Published changes belong in [release notes](releases/); earlier source designs
remain available through Git history. Current documentation describes supported
behavior rather than maintaining a second historical implementation guide.
Private topology, run records and measurement analyses stay in ignored
`local/`. Preserve failed measurements and do not repeat completed workloads
merely to obtain a better score.
