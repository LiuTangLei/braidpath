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

The local listener should stay on loopback: every local caller uses the tunnel
credential.

## Proxy entrances

`client --proxy-listen ADDRESS` accepts SOCKS5 and HTTP CONNECT on one port; the first
byte selects the protocol (`0x05` is SOCKS5). `server --proxy` connects each such
stream to the destination it names. The client requests `braidpath-proxy: 1`; a
server without `--proxy` refuses the session. Fixed-target and proxy streams can be
used in the same session.

```bash
./target/release/braidpath server ... --proxy
./target/release/braidpath client --proxy-listen 127.0.0.1:1080 --entrance ... --adaptive ...
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
curl -p -x http://127.0.0.1:1080 https://example.com/
```

| Element | Behavior |
| --- | --- |
| SOCKS5 | RFC 1928 without authentication. CONNECT and [UDP ASSOCIATE](#udp-associate) with IPv4, IPv6 or domain addresses. BIND is answered with `07` (command not supported). A CONNECT reply's bound address is `0.0.0.0:0`. |
| HTTP CONNECT | `CONNECT host:port` (bracketed IPv6 accepted); headers up to 8 KiB; other methods get `405`. Bytes sent after the request header are carried as early data. |
| Destination | The first stream bytes are a SOCKS-style address header (type, address or name, port). Stream identifiers with bit 28 set carry one. Names resolve on the server. |
| Zero round trip | The client answers success (`00`, or `200 Connection established`) as soon as the local handshake completes, so the application's first bytes follow the destination header in the same flight instead of one tunnel round trip later. |
| Status | The server's first stream byte is a status: success, or a SOCKS5 reply code. Because success was already answered, a failure status resets the local connection (RST), never a clean end, so a truncated exchange cannot look complete. Specific SOCKS reply codes and HTTP error statuses are therefore not reported for remote failures; local handshake errors still are. |
| Authorization | Only globally routable unicast addresses are permitted: loopback, private, link-local, shared (100.64/10), benchmarking, reserved, multicast, unspecified, IPv6 unique-local, link-local and IPv4-mapped forms of these are denied, after name resolution. `--proxy-allow-private` permits all but unspecified and multicast. A denial is status `02`. |
| Failure | Resolution or connection failure, or 10 s without connection, returns a status, then FIN; both sides then retire the stream. Application bytes sent before the failure are discarded. |

The proxy listener has no authentication, so it should stay on loopback; the
client warns at startup when either local listener is bound elsewhere. A caller
that reaches it can use the tunnel for TCP and, through UDP ASSOCIATE, as a UDP
relay.

### Client interoperability

`bench/proxy_interop.py` chains a third-party client to the entrance: the tool's
own SOCKS5 inbound forwards through one BraidPath outbound (SOCKS5 or HTTP
CONNECT), over one loopback path, to loopback targets. It verifies a 1 MiB HTTP
body by address and by name (`localhost`) and, with the SOCKS5 outbound, 20 UDP
ASSOCIATE echoes, byte for byte; client and server stream statistics confirm the
traffic crossed the tunnel. The tool runs from its own directory under `local/`.

```bash
python3 -m bench.proxy_interop --binary target/release/braidpath \
  --tool sing-box --tool-binary PATH/sing-box --outbound socks5 --output local/interop/sing-box
```

| Client | SOCKS5 outbound (TCP, name, UDP) | HTTP CONNECT outbound (TCP, name) |
| --- | --- | --- |
| mihomo 1.19.31 | passed | passed |
| sing-box 1.14.3 | passed | passed |
| Xray 26.3.27 | passed | passed |

The tested outbounds, for a BraidPath client with `--proxy-listen 127.0.0.1:1080`
(names are examples; route the traffic you intend with each tool's own rules):

```yaml
# mihomo
proxies:
  - {name: braidpath, type: socks5, server: 127.0.0.1, port: 1080, udp: true}
rules:
  - MATCH,braidpath
```

```json
{"type": "socks", "tag": "braidpath", "server": "127.0.0.1", "server_port": 1080, "version": "5"}
```

```json
{"protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]}}
```

The second is a sing-box outbound, the third an Xray outbound; for HTTP CONNECT use
`type: http` (mihomo, sing-box) or `"protocol": "http"` (Xray), which carries TCP
only. These are local protocol checks on macOS arm64, not performance or
reachability results. Xray's fetches take about one second longer with either outbound: its
default one-second half-close policy, also seen with its direct outbound.

### UDP ASSOCIATE

UDP ASSOCIATE is part of `braidpath-proxy: 1`; it uses no stream. The client binds
a UDP relay socket on the address the SOCKS client connected to and returns it in
the reply. Datagrams travel as unreliable records, with the same scheduling and FEC
as fixed UDP forwarding.

| Element | Behavior |
| --- | --- |
| Flow | One flow per association, `2^31 | n`. A client record is the SOCKS UDP request without its reserved and fragment fields, `[type][address][port][data]`; a server record names the reply's source in the same form. An empty client record ends the association. |
| Relay socket | Accepts datagrams only from the IP address of the control connection's peer; replies go to that host's most recent source port. The association ends when the control connection closes. |
| Server | One socket per association, dual-stack where the host allows it. Names resolve on the server, IPv4 addresses first, cached for 60 s. The CONNECT destination rule applies, including `--proxy-allow-private`. Replies are accepted only from addresses this association has sent to (at most 256). |
| Limits | 64 associations per session; a server association idle for 120 s is retired and recreated when the client sends again. Fragmented datagrams (`FRAG` ≠ 0) and datagrams over the record payload (about 1000 bytes including the address) are dropped and counted; nothing is fragmented or reassembled. QUIC and other protocols that need 1200-byte datagrams therefore do not fit. |
| Delivery | Unreliable: a datagram lost on every path and not repaired by FEC is lost, as with fixed UDP forwarding. |

Path handshakes are separate from proxy replies: a session is long-lived, so QUIC
handshakes (with [0-RTT](runtime.md#0-rtt) for resumed paths) occur at startup and
reconnection, not per TCP connection.

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
| Acknowledgment | Cumulative point, receive limit, total duplicate bytes, and up to 64 selective ranges. Sent after 16 segments or 2 ms, with count-driven ACKs spaced at least 4 ms. The first duplicate report is immediate; further duplicate reports coalesce for 4 ms while preserving the full duplicate count. FIN, zero-length probes, and a window opening by a quarter remain immediate. When the window holds more ranges, as under sustained loss, the frame describes the ranges holding the most recently stored data first (a repair that filled an old hole, then the newest data), as TCP SACK does; describing only the lowest ranges let data above them reach its loss deadline although it had arrived. |
| Loss | A segment is lost when older than the reorder threshold and a later transmission was delivered, or older than 1.5 thresholds without that evidence. The threshold uses the larger of the actual admitting path's QUIC RTT and the largest of that path's recent stream RTT samples (including acknowledgment return delay), times a reorder factor of 1.25–2. QUIC's estimate already carries the path's variance; the stream's own first-sample variance bound (three RTTs) is not applied per path, so a new stream does not wait three RTTs to repair its first loss. Only acknowledgments of a newer original on each path can update that path's RTT; a later SACK of older, previously omitted data releases bytes without replacing a newer sample. Timing starts at admission, excluding the local queue. Before admission is known, the conservative aggregate RTT estimate remains in use. |
| Backoff | Only a retransmission with no acknowledgment progress since its previous attempt backs off (1.5× per stall, bounded). Random loss with live acknowledgments is repaired at the threshold pace. |
| Head-of-line repair | The repair of the segment at the cumulative point is followed by one extra copy once the repair is admitted (see below), so one further loss does not hold every later byte for another loss threshold. |
| Spurious repair | A rise in the peer's duplicate count raises the reorder factor by 25%, up to 2; progress decays it toward 1.25. Duplicates explained by the sender's own extra copies (tail probes and head-of-line copies, at most two segments' worth outstanding) do not count. |
| Local drop | Each stream original carries a hold through the sender queue. If it leaves without Quinn admission (expiry, queue rejection, API error) the stream retransmits it at once instead of waiting for loss detection. |
| Local backlog | Stream bytes waiting for admission are capped at half the admission lifetime of the measured admission rate, between 8 and 56 records, so stream data does not age out of the adaptive 20 ms sender lifetime. |
| Windows | 256 KiB initial, then the receiver advertises its share of a 32 MiB host receive budget among streams retaining bytes, between 256 KiB and 32 MiB per stream. Idle streams do not dilute that window. Out-of-order data that continues a held range extends it, so an acknowledgment walks the holes rather than every segment. The sender reads from its local socket only up to the peer limit plus 256 KiB. |
| Probes | An empty client stream announces itself with a zero-length segment, repeated until acknowledged, so server-first protocols work. A closed window is probed with zero-length segments. |
| End | FIN after local EOF, and write shutdown after the peer FIN and all data are written, for full half-close. A stream retires when both directions finish, after acknowledging the peer's FIN; its tombstone answers a repeated FIN with that final acknowledgment rather than RESET, so the peer completes instead of resetting a finished exchange. |
| Reset | Socket errors, violations, connect failure (10 s), or 30 s without acknowledgment progress send RESET (twice) and close the local socket with RST, never FIN. Frames for a closed stream are answered with RESET. A new session epoch resets all streams. |
| Limits | 256 concurrent streams per host, shared across sessions; 120 s tombstones prevent late frames from reopening a closed stream. |

Each direction shares a 32 MiB retained-byte allowance and 65,536 retained-credit
slots per host. A flow also keeps 128 KiB and 128 private credit slots for forward
progress, so other stalled flows cannot prevent its cumulative-hole repair.
The receiver separately bounds out-of-order range nodes to 65,536 across all
sessions: FIFO byte credits alone cannot account for those nodes after unrelated
prefix writes. At that bound new ranges remain unacknowledged; duplicates,
extensions of existing ranges and cumulative-hole repairs still proceed. Reset
and cancellation return all slots. Oversized credit and range-slot caches shrink
as they drain.

Congestion control remains below this layer: Quinn's per-connection BBR and, with
`--adaptive`, the per-path pacing controllers. The stream layer adds no rate
controller; it only keeps a short, admitted backlog and repairs loss. Retransmissions
are new records, so the record-ID window still deduplicates paths and FEC.

Reliable aggregate sessions can renew their application sending allowance toward
the actual native congestion window divided by RTT, including with automatic FEC.
Renewal requires a new, fresh positive receiver report, active demand, low delay,
no current loss pressure and no transport blockage; it cannot override a brake or
mint burst tokens. Growth is capped at one doubling per native RTT and by the
configured total/group limits. This allowance is not a capacity measurement.

Reliable server sessions use the same bounded 4096-datagram receive queue as
clients. Four ready path readers can therefore hand off a short burst without
turning local actor scheduling into packet loss. Raw UDP server sessions retain
their existing 256-event latency budget; sender admission queues are unchanged.
Normal status ticks identify sessions and report application bytes, stream
retransmitted bytes, pending local I/O and queued sender bytes while active.
Server path ticks include the application pacing allowance alongside native
QUIC counters. Idle stream diagnostics remain silent after their final totals.

After at least one second without queued business demand, a reliable path can
restart from its original native window at the current RTT when demand returns.
This uses neither a retained BBR peak nor new burst tokens. Current delay, loss,
transport blockage, loss trials and learned loss ceilings still apply. Idle RTT
brakes therefore do not require a tiny sending allowance to build a new bulk
delivery sample before the path can participate again.
ACKs and small status records do not consume that bulk reactivation opportunity.

A bulk stream with later SACKed data can send one extra copy of its persistent
head hole after a quarter of its path RTT (10–50 ms). A newer cumulative ACK
cancels the copy, and each stream allows at most one such probe per RTT. This
does not declare loss or move the original loss timer; a dropped probe leaves
ordinary recovery live. Existing admission and memory budgets also cover it.

Shared forward-loss trials count paths with qualified finalized data intervals.
Idle connected paths do not vote against congestion on active routes. At least
two measured routes are required when multiple routes are connected, and two
thirds of the measured routes must corroborate the loss.
If a binding trial lowers both loss and throughput after a startup burst, it can
make one further trial from the measured post-cut baseline while residual loss
remains. The follow-up must settle and collect two new qualified cohorts; it
cannot learn a loss floor or refine again when still inconclusive.

For reliable aggregate sessions, application pacing observations pause briefly
while native BBR drains its flight for an RTT probe, then allow two RTTs
(200–500 ms) for in-flight probe replies and receiver reports to settle. One
episode can pause observations for at most 750 ms. A native RTT rise of at least
half the configured queue-delay target overrides this pause. Native congestion
control, liveness, packet deadlines, FEC and byte-stream recovery continue during
the pause. UDP-only sessions and `--legacy-recovery` keep their existing behavior.
This avoids treating the native controller's deliberate service dip as a new
application capacity ceiling; WAN performance acceptance remains pending.

## Statistics

The sending direction's JSON contains `tcp_streams`: opened, completed, local and
peer resets, rejected streams, bytes from and to the application, segments sent,
retransmitted segments and bytes, local-drop retransmissions, probe timeouts,
spurious-repair reports, duplicate bytes received, and acknowledgments sent and
received. `udp_associations`, `udp_datagrams_to_tunnel`, `udp_datagrams_from_tunnel`
and `udp_datagrams_dropped` count UDP ASSOCIATE traffic.

## Scheduling

Two scheduler rules serve TCP streams and fixed UDP alike:

| Rule | Behavior |
| --- | --- |
| Path liveness | A path whose ack-eliciting QUIC frames (datagrams, stream data, pings) have gone unanswered by any ACK for `max(2·RTT + 25 ms, 100 ms)` is withheld from data scheduling until an ACK arrives; the controller's and Quinn's probes still elicit one. If every open path is silent, none is withheld. A queue delays ACKs without stopping them, so this is reachability evidence, not a congestion signal; it acts before the adaptive controller's receiver-report exclusion, which takes seconds. |
| Latency class | A record of at most 320 encoded bytes, or a stream segment while that stream has at most 64 KiB outstanding, is offered to paths in order of expected delivery delay (half the base RTT plus network and local queueing) instead of the throughput order. For TCP records of at most 320 encoded bytes, adaptive senders first retain healthy routes within 20 ms (or the smaller remaining admission budget) of the best delay, then check pacing credit; an unready head yields to other flows instead of entering a much slower route. Bulk transfers keep the throughput order. Where the opt-in small-record FEC policy (`--small-fec-bytes`) applies, its delay and loss ranking decides instead. |

The adaptive controller's queue brake cuts to a delivery sample only if that
sample measured the bottleneck: most of its admission interval lies inside the
current backlog, or the queue was observed within one base RTT of the interval's
end. A sample from an application-limited period before a burst meets neither and
gets the ordinary 20% brake; it could otherwise cut a newly busy path to the
minimum rate. At startup the transport window limits sends before a local backlog
forms, so the queue condition keeps the immediate cut there. If the retained
interval predates the backlog and measured sparse traffic, a fresh paired busy
interval of at least 100 ms may size the queue reduction. The 500 ms capacity
observation horizon is unchanged. This busy interval can size the reduction even
when startup's native sending allowance was too large to be fully exercised.
Before such a busy interval exists, a rising native RTT reaching the queue target
can trigger the startup brake. Its fallback allowance uses the initial native
window divided by the current RTT, so an expanded BBR startup window cannot keep
all paths overfilled while receiver feedback catches up. This is a sending
allowance, not a capacity estimate; legacy recovery retains its original behavior.

## Controlled measurement

Each session actor services one queued local socket completion before selecting
its next input and flushes stream state once per turn. Continuous incoming wire
traffic therefore cannot indefinitely postpone local reads, writes, or EOF.

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

`--connections N` runs N concurrent transfers. With `--entrance socks5`,
`--probe-interval-ms` sends 64-byte echo probes on a separate connection, reported as
idle and during-transfer RTT percentiles; `--tail-seconds S` keeps probing for S
seconds after the transfer and reports those separately, so an event can impair
interactive-only traffic. `--fresh-probe-interval-ms` (50–5000) opens a new SOCKS5
connection per attempt and times connect, CONNECT and one 64-byte echo, as a new
request beside the load would; failures stay in its outcome population. `--event SECONDS:JSON` sends a control line
to the emulator, for example `--event '2:{"path":0,"down":true}'` to take a path down
(both queued and new packets are dropped). Each result reports the largest gap
between received bytes.

`--direction both --entrance socks5` starts N uploads and N downloads in the same
session (at most 16 per direction), each against its own target. `--bytes` applies
to each connection. `by_direction` verifies each direction separately and reports
its goodput over the same complete workload wall interval; total goodput is their
sum. `capacity_mbps_per_direction` is the emulated path sum, and
`used_capacity_mbps` is twice that sum for duplex. Each direction still has its
own runtime rate cap. Duplex totals must not be compared with a single-direction
capacity denominator. Every requested path must authenticate in one session before
the workload starts; `path-ready.json` retains that evidence.

Probes are closed-loop, with one request outstanding and a minimum interval;
they do not maintain a fixed offered request rate under delay. Each attempt's
start, completion and outcome are retained in `probe-attempts.json`. A request
belongs to the phase where it started, even when it completes after the bulk
transfer or tail observation ends. `p99_ms` describes successful requests;
`attempts`, `failed`, `timeouts` and `p99_all_outcomes_ms_lower_bound` also retain
failed requests. `p99_is_censored` marks failures whose eventual successful
completion time is unknown. A setup failure is retained as `probe.error` even
when no echo request started. A failed stream remains a failed connection in the
summary instead of disappearing as a worker-thread exception. Transfer progress
cannot extend its configured deadline. The summary is diagnostic evidence, not
full-population deadline or statistical performance acceptance.

```bash
python3 -m bench.tcp_lab --binary target/release/braidpath \
  --lab-binary target/release/examples/link_lab --output local/tcp-lab/duplex \
  --path 50:15 --path 50:15 --entrance socks5 --direction both \
  --connections 1 --bytes 33554432 --probe-interval-ms 20 \
  --client-arg=--adaptive --client-arg=--rate-bps --client-arg=30000000
```

Results stay under `local/`. Loopback shares one host, CPU and kernel; an emulated
result is not a WAN, independent-capacity or deployment acceptance result.

## Not yet implemented

- SOCKS5 user/password authentication, and destination allow-lists beyond the
  public-address rule.
- UDP ASSOCIATE datagrams above the record payload, and SOCKS UDP fragmentation.
- Priority classes between interactive and bulk streams beyond the latency class
  and the existing per-flow round robin.
- Coordinated FEC strength for streams, and cross-host WAN acceptance.

### Bounded short-tail probe

A sender with exactly one admitted, never-retransmitted segment of at most 128
sequence bytes, and no unsent application bytes, can queue one additional copy.
Its timer uses the actual route's native RTT and smoothed stream ACK RTT on that
route, a 12.5% timing margin and the 2 ms ACK delay (capped at 2 s). A single old
delayed ACK does not pin this one-copy timer to the recent maximum; full loss
recovery still keeps the conservative maximum. Unknown/local-queue routes cannot
probe. This copy is not a loss declaration: it preserves the original loss
clock, route, stall backoff and failure timer. A local drop of the probe does not
mark the original lost. There is at most one probe per retained segment; a new
acknowledged flight starts independently. Full loss recovery remains available
at its original deadline, even if the probe is queued or lost. Large/multi-segment
flights retain their existing recovery policy. Probes obey normal queue, pacing,
receiver-window and native congestion constraints. `tcp_streams.tail_probes_queued`
counts successful local queue entries, also included in retransmission totals;
it does not claim native admission or prove which copy caused acknowledgment.

### Head-of-line repair copy

Every byte the receiver holds above a hole waits for that hole's repair. Under
random loss the repair itself can be lost, and the hole then lasts a further loss
threshold (with stall backoff), during which the receiver releases nothing. When
the sender retransmits the segment at the cumulative acknowledgment point, it
therefore queues one additional copy of it, after the repair's own admission has
timed it. Like the tail probe, the copy is not a loss declaration: it keeps the
repair's loss clock, route and backoff evidence, its local drop does not mark the
segment lost, and it counts toward the one-probe limit of the retained segment.
A segment receives at most one such copy; repairs behind the cumulative point are
not copied. Before queueing, the copy waits for the repair's admission and is
abandoned if the repair is superseded or the segment is acknowledged. `tcp_streams.head_copies_queued`
counts successful local queue entries, also included in retransmission totals.
The duplicate allowance is credited only when Quinn admits the copy, once per
transmission. A copy discarded locally grants no allowance. Admission or discard
can follow the original's acknowledgment without changing the repair's timer.
