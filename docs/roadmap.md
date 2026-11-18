# Roadmap

## 0.7.0 release scope

The current development version is **0.7.0-rc.1**. It is not a published release.
This increment freezes the implemented download and Game policies, removes
retired compatibility paths, and validates one combined source revision. Results
from precursor branches remain evidence about those branches.

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

## Work required to close 0.7.0

- Finish removal of retired recovery modes, obsolete feedback decoding and
  ineffective CLI aliases, including their callers, tests and current guidance.
- Verify the combined source with the existing cross-platform CI and complete
  release artifact matrix.
- Validate the final selected policies in a bounded, fixed-endpoint comparison:
  complete-file transfer and control responsiveness for download; complete UDP
  populations, competing traffic and short uploads for Game.
- Record the exact source and configuration, including failures and unresolved
  regressions, before promotion. Follow [release readiness](release-readiness.md).

A full-size download and a latency-only UDP window answer different questions.
Game automatic startup can affect short-upload completion. That boundary remains
part of acceptance even when isolated UDP latency improves.

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
