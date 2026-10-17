# Reliable TCP streams

`client --tcp-listen ADDRESS` accepts local TCP connections. `server --tcp-target
ADDRESS` connects each one to a fixed TCP destination. The client requests the
`braidpath-streams: 1` session header; a server without `--tcp-target` refuses the
session. `--target` (UDP) becomes optional when `--tcp-target` is configured, and
both may be used in one session.

```bash
./target/release/braidpath server --listen 127.0.0.1:7443 \
  --cert local/identity/cert.pem --key local/identity/key.pem \
  --token-file local/identity/token --tcp-target 127.0.0.1:8080
./target/release/braidpath client --tcp-listen 127.0.0.1:7001 \
  --entrance 127.0.0.1:7443 --entrance 127.0.0.1:7444 --adaptive \
  --server-name localhost --ca local/identity/cert.pem --token-file local/identity/token
```

This is a fixed-target port forward, not a SOCKS or HTTP proxy. The local listener
should stay on loopback: every local caller uses the tunnel credential.

## Design

Each TCP connection is one stream. Its bytes travel as ordinary aggregate records,
so one connection is scheduled across every eligible path, FEC protects it like any
other record, and relays see nothing new. The stream layer runs only at the client
and the main server; the server reassembles one ordered byte stream and holds one
TCP connection to the target, so a relay or path change does not change what the
target sees.

| Element | Behavior |
| --- | --- |
| Flows | Data on flow `2^30 | id`, acknowledgments on `2^30 | 2^29 | id`, so acknowledgments take their own per-flow queue turn. UDP flows stay below `2^30`. |
| Sequence space | Byte offsets, plus one virtual byte at the final size for FIN. Segments carry at most 990 bytes and keep their boundaries across retransmission. |
| Acknowledgment | Cumulative point, receive limit, total duplicate bytes, and up to 64 selective ranges. Sent after 16 segments or 2 ms, and immediately for gaps, duplicates, FIN, zero-length probes, or a window opening by a quarter. |
| Loss | A segment is lost when older than the reorder threshold and a later transmission was delivered, or older than 1.5 thresholds without that evidence. The threshold is the windowed maximum RTT (or `srtt + 4·rttvar`, whichever is larger) times a reorder factor of 1.25–2; for the first 250 ms of sampling it is at least 250 ms, since a slower path is unobserved until its first acknowledgment. |
| Backoff | Only a retransmission with no acknowledgment progress since its previous attempt backs off (1.5× per stall, bounded). Random loss with live acknowledgments is repaired at the threshold pace. |
| Spurious repair | A rise in the peer's duplicate count raises the reorder factor by 25%, up to 2; progress decays it toward 1.25. |
| Local drop | Each stream original carries a hold through the sender queue. If it leaves without Quinn admission (expiry, queue rejection, API error) the stream retransmits it at once instead of waiting for loss detection. |
| Local backlog | Stream bytes waiting for admission are capped at half the admission lifetime of the measured admission rate, between 8 and 56 records, so stream data does not age out of the adaptive 20 ms sender lifetime. |
| Windows | 256 KiB initial, then the receiver advertises its share of a 64 MiB session budget, between 256 KiB and 8 MiB per stream. The sender reads from its local socket only up to the peer limit plus 256 KiB. |
| Probes | An empty client stream announces itself with a zero-length segment, repeated until acknowledged, so server-first protocols work. A closed window is probed with zero-length segments. |
| End | FIN after local EOF, and write shutdown after the peer FIN and all data are written, for full half-close. A stream retires when both directions finish. |
| Reset | Socket errors, violations, connect failure (10 s), or 30 s without acknowledgment progress send RESET (twice) and close the local socket with RST, never FIN. Frames for a closed stream are answered with RESET. A new session epoch resets all streams. |
| Limits | 256 concurrent streams per session; 120 s tombstones prevent late frames from reopening a closed stream. |

Congestion control remains below this layer: Quinn's per-connection BBR and, with
`--adaptive`, the per-path pacing controllers. The stream layer adds no rate
controller; it only keeps a short, admitted backlog and repairs loss. Retransmissions
are new records, so the record-ID window still deduplicates paths and FEC.

## Statistics

The sending direction's JSON contains `tcp_streams`: opened, completed, local and
peer resets, rejected streams, bytes from and to the application, segments sent,
retransmitted segments and bytes, local-drop retransmissions, probe timeouts,
spurious-repair reports, duplicate bytes received, and acknowledgments sent and
received.

## Controlled measurement

`bench/tcp_lab.py` runs one TCP transfer through the native link emulator
(`examples/link_lab.rs`) and verifies its SHA-256. `--use-path` selects a subset of
emulated paths, giving a matched single-path baseline on the same topology:

```bash
cargo build --release --locked --bin braidpath --example link_lab
python3 -m bench.tcp_lab --binary target/release/braidpath \
  --lab-binary target/release/examples/link_lab --output local/tcp-lab/all \
  --path 20:20 --path 20:20 --path 20:20 --bytes 16777216 --client-arg=--adaptive
python3 -m bench.tcp_lab ... --output local/tcp-lab/single --use-path 0
```

Results stay under `local/`. Loopback shares one host, CPU and kernel; an emulated
result is not a WAN, independent-capacity or deployment acceptance result.

## Not yet implemented

- SOCKS5 and HTTP CONNECT entrances with per-stream destinations. The first stream
  bytes can carry a destination header without a new frame type.
- Path-aware loss detection: the stream layer does not know which path carried a
  segment, so a loss on a fast path waits for the slowest observed RTT.
- Priority classes between interactive and bulk streams beyond the existing
  per-flow round robin.
- Coordinated FEC strength for streams, and cross-host WAN acceptance.
