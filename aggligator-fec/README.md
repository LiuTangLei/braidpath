# Latency-first HTTP and multi-port TCP forwarding

The active branch is `experiment/http-ultralow-latency-20261010`, version
`0.2.0-latency.1`. New `init` configurations default to immediate path replication
and eight unused pre-handshaken sessions shared across all TCP ports. Used
connections never return to the pool; a request is delivered to one target socket.

See [the latency guide](../docs/http-ultralow-latency.md) for setup, comparisons,
the actual wire budget, and validation. Existing configuration files retain their
explicit settings. Create fresh state files to evaluate the latency profile.

Current measurements and their limits are in the
[2026-10-10 latency validation record](../docs/http-ultralow-latency-validation-20261010.md).

## Historical bandwidth-focused RC evidence

The records below describe earlier commits and their own test environments.
They are not performance measurements of the latency branch.

## RC1 peak-hour verification

The `fec-v0.1.0-rc.1` release adds a five-minute notBefore allowance at control-certificate
creation without bypassing normal TLS validation. Final verification passed 91 Rust tests,
strict Clippy, the single-WAN six-port CLI acceptance suite, and eight public IPv4 scenarios
on six confirmed hosts (72 bulk downloads, 2016 MiB verified). Japanese and mixed relays
remain subject to variable throughput and tail latency; this is not a universal 200 Mbps
promise. Full evidence and known limits: [`RC1 peak validation`](../docs/rc1-peak-validation-20260906.md)
and [`release notes`](../docs/release-notes-fec-v0.1.0-rc.1.md).


**Status (2026-09-06): 0.1.0-rc.1, single-WAN multi-port TCP release candidate.**
Build with `--features managed` for `init`, `invite`, `join`, `run`, `check`, `status`, `rotate`,
and `revoke`. A master issues one `agg1://...` invitation usable by relays and a client,
stores enrolled identities, and pushes live relay changes to active TCP sessions.
One active client identity per instance, up to 16 named TCP services and 32 concurrent TCP
connections. The client can use up to four separately bound access links; each connection
has independent FEC, ordered delivery and ARQ, sharing physical sockets and bandwidth budgets.
This is NOT a production multi-user proxy and not the upstream `agg-tunnel --fec` option.
The control plane uses pinned TLS 1.3. The experimental UDP DATA plane remains unencrypted
and has no cryptographic admission: control TLS is neither data protection nor camouflage.
Dynamic path quality, bounded ARQ, pacing and interleaving are implemented;
full adaptive congestion control is not. The upstream aggregate delivery algorithm is unchanged.
The live-test work also fixes macOS TCP interface/source-address binding and adds an
optional `agg-speed --interface` filter; these do not change the aggregation algorithm.

## RC1 quick start and acceptance

Start with `agg-fec-tunnel --help`, then `init --help`, `join --help`, and `run --help`.
Help is command-specific with Chinese examples; terminal output is readable, and `--json`
or redirected output preserves JSON for scripts. Default state is `./agg-fec.json`.
`check --state FILE` validates configuration offline without printing secrets, connecting
or binding ports. Invitations may be pasted on stdin or read from an owner-only file.

[中文快速开始](../docs/rc1-quickstart.zh-CN.md) ·
[RC 验收记录](../docs/rc1-validation-20260906.md)

The RC acceptance run used one uplink and six local TCP ports: three rounds of ten
simultaneous flows, 211,026,752 checked application bytes, a 22-second idle connection,
a deliberately slow reader, unavailable/recovered targets and forty abrupt TCP resets.
The resets exposed a real leaked-peer-flow-slot issue; bounded repeated cancellation
now releases the peer's flow without waiting for its old idle timeout. Normal FIN
completion does not send cancellation. Tests also lose the first two cancel datagrams.

Public IPv4 tests used j2 with j/jx2 relays, three distinct HTTP targets and three concurrent
64MiB downloads per round. All nine files (576MiB), target identities and both session
closures passed. Aggregate request-to-tail goodput was 195.69 / 193.87 / 198.21 Mbps,
shared across the ports, not per port. Read gaps still reached about 195ms; neither a
constant 200Mbps nor long-duration production stability is claimed.

90 Rust tests, strict Clippy, the CLI contract suite and macOS arm64/Linux amd64 builds
passed. Multi-WAN remains simulation-only and UDP/WireGuard is outside RC1 performance
acceptance. `scripts/package-fec-rc.py` prepares local checksummed binary/source archives;
it does not publish a GitHub release, install a service, or create a Git tag.

## Multiple TCP ports and client broadband links

The managed data envelope is now `AFM3` (flow ID + stable access/entrance lane), containing
the existing FEC packet format. Upgrade managed master, relays and client together; the
previous single-stream managed data protocol is not wire-compatible. Existing owner-only
JSON files using one `target`/`listen` remain readable; they map to the `default` service.
The static/raw CLI modes keep their legacy protocol.

```sh
# Documentation addresses; replace with owned, reachable endpoints and real services.
agg-fec-tunnel init --state master.json --control 198.51.100.10:5706 \
  --advertise 198.51.100.10:5702 \
  --forward web=127.0.0.1:8080 --forward ssh=127.0.0.1:22 \
  --wire-mbps 500 --upload-wire-mbps 160
agg-fec-tunnel run --state master.json

# Paste the same agg1:// invitation into stdin after join; do not publish it.
agg-fec-tunnel join --state client.json --as client --name my-client \
  --forward web=127.0.0.1:18080 --forward ssh=127.0.0.1:10022 \
  --uplink en0=80/260 --uplink en1=80/260
agg-fec-tunnel run --state client.json
```

`--uplink INTERFACE=UPLOAD/DOWNLOAD` takes Mbps **wire limits**, not guaranteed application
throughput. Each is the budget of a physical broadband connection, not of each TCP stream
or remote relay. Master `--wire-mbps` and `--upload-wire-mbps` are shared download/upload
ceilings. Source, parity and retry packets share these budgets; small bounded control
traffic is separate to avoid ACK deadlock. Set ceilings deliberately for the actual WANs.
Two adapters into the same bottleneck are not two independent ISP connections.

Each WAN opens its own bound data/control socket. The master observes and admits each WAN
source IP through TLS under the same client identity. The relay return table distinguishes
flow AND access lane, including two NAT source ports from the same public IP. Only fixed
configured services are addressable; service names cannot select arbitrary remote targets.

Within a WAN, path quality chooses the better entrance. Between viable independent WANs,
weighted scheduling uses their configured capacities; parity is balanced across WAN budgets
as well. A severely degraded WAN is excluded until it becomes viable again. This is not
automatic ISP capacity estimation or a complete adaptive congestion controller.

macOS uses per-socket interface indices; Linux managed modes use SO_BINDTODEVICE (may need
privilege). No host route, interface, qdisc or system-wide socket settings are changed.
The server remains single-access; server multihoming is intentionally deferred.

Actual loopback UDP tests cover concurrent flows, same-relay/two-WAN association, a 1.3s
single-WAN blackout and recovery, same-stream relay add/remove, bandwidth aggregation,
backpressured applications, packet admission and bounded state. A local CLI integration
run validated four local ports, nine simultaneous connections and two independently bound
access sockets. This is **not** two-ISP Internet validation and does not establish that the
new multiplexed binary preserves the older public 200Mbps measurements. See
`../docs/multiport-multiwan-20260906.md` for exact evidence and limitations.

## Earlier single-service setup and hot topology

```sh
cargo +1.97.0 build -p aggligator-fec --features managed --bin agg-fec-tunnel --release
# Example documentation addresses only; replace with owned, reachable endpoints.
agg-fec-tunnel init --state master.json --control 198.51.100.10:5706 \
  --advertise 198.51.100.10:5702 --target 127.0.0.1:10000
agg-fec-tunnel run --state master.json

# Elsewhere: paste the invitation into stdin after running join, then press Enter.
agg-fec-tunnel join --state relay.json --as relay --name relay-1 \
  --advertise 198.51.100.11:5702
agg-fec-tunnel run --state relay.json
agg-fec-tunnel join --state client.json --as client --name client-1 --listen 127.0.0.1:10000
agg-fec-tunnel run --state client.json
```

`init` uses OpenSSL once to generate a local certificate. Runtime uses rustls and pins
that certificate from the invitation. Configuration files are sensitive and owner-only;
no master private key is shared. Prefer stdin over `--invite` to avoid shell-history leaks.
`join --interface en0` remains the single-access shortcut. In managed mode macOS/Linux
bind this application's data/control sockets without changing system routing. Other roles remain available with
`--features cli` alone.

Membership is persisted atomically, heartbeats have a bounded lease, and enrolled nodes
reconnect with their own identity after invitation rotation or master restart. Control
loss retains last-known data paths while reconnecting. `revoke` updates active sessions;
it does not install kernel firewall rules. At most seven registered relays and eight distinct
entrance addresses per client process are supported (combined with up to four WANs for 32
lanes). Historical entrance slots are not reused; excessive address churn requires a client
restart. Codec, service mappings and local uplink configuration changes require a restart;
relay membership updates continue to apply to existing streams.

Two public IPv4 validation batches each transferred three verified 256 MiB HTTP files.
In each first download, j joined, jx2 joined, then j was revoked with the SAME live session
ID; all three paths carried originals. First-batch cold goodput was 201.72/202.50/202.30Mbps;
final-code repeat was 199.17/201.93/185.77Mbps. All bytes and closes passed, but the slower
final samples remain reported: this is not a constant-200Mbps or low-tail-latency guarantee.
All owned server resources were removed and pre-existing services/firewall checked.

See `../docs/managed-tcp-and-udp-direction-20260906.md` and
`../analysis/managed-tcp-live-20260906.json` for exact scope, deployment commands, all
samples, limitations, and reasoning about split TCP versus TCP inside WireGuard.
Local reproducible CLI coverage is `tests/managed_cli.py`; `tests/live_managed.py`
is explicitly opt-in on the previously authorized hosts and never runs with Cargo.

## UDP/WireGuard prototype

`udp-client`/`udp-server` preserve datagram boundaries with FEC, bounded fragments,
deduplication and expiry. There is no outer ARQ. Default delivery is immediate/unordered;
`--udp-reorder-ms` offers a finite waiting window, never infinite global reliability.
Tests use real wireguard-go with a userspace TCP/IP stack and no OS network interfaces.
Measured WG throughput remains much lower than the split-TCP mode; do not advertise it
as a proven 200Mbps WG accelerator. `tests/wg-lab` is a separate Go test module, not a
production dependency. It must not be mistaken for kernel-WireGuard performance.

## Earlier higher-loss IPv4 follow-up

The later 512 MiB HTTP retest exposed 4.64–7.48% overall original-datagram deficits
with RTT-only selection, concentrated on the faster j entrance. New bounded passive
`delivery` telemetry records original arrivals separately from FEC reconstruction.
`SessionConfig.delivery_aware` defaults to true; CLI `--rtt-only` disables only this
quality score for same-binary comparisons. It is a direction-specific estimate,
not an application ACK, authenticated control protocol, or bandwidth estimator.

Three full confirmation downloads achieved 201.33 / 201.32 / 202.29 Mbps including
cold setup, with all payloads and session closure verified. HTTP read-gap P99 was
9.80–10.06 ms versus 18.82–20.21 ms in the initial baseline. Maximum gaps remained
130.51–153.94 ms: this is not a zero-stall or universal 200 Mbps guarantee. An RTT-only
recheck again showed 5.30% original deficit and 19.98 ms read-gap P99.

Read `../docs/multipath-fec-high-loss-retest-20260905.md` and
`../analysis/multipath-fec-high-loss-retest-20260905.json` for all eight completed
samples, one SSH-observation interruption, metric caveats and cleanup audits.
All data legs remained public IPv4; the original 260 Mbps cap and 64+8 FEC were unchanged.

## Earlier real TCP business and dynamic selection update

`session::connect` / `session::accept` take an exclusively owned receiving UDP socket,
explicit peers and `SessionConfig`, and return a full-duplex byte stream plus a task.
**Await the session task to distinguish clean completion from failure; stream EOF alone
is not proof of end-to-end success.** Hard cancellation uses task.abort. An IP with port
zero may learn one NAT source port from that preconfigured IP; this is not authentication
and does not implement arbitrary NAT rebinding or multi-client admission.

The `path` scheduler continuously uses correlated probe RTT, smoothing, jitter, timeout
penalties and age, instead of a lifetime minimum. Near-fast paths share source traffic;
substantially slower/dead paths do not. The `probe_loss` metric is not payload loss.

Three final 512 MiB HTTP downloads passed complete SHA-256 AND both session close checks.
Payload goodput was 210.389 / 204.134 / 208.493 Mbps; including cold setup it was
206.842 / 200.857 / 205.077 Mbps. Maximum HTTP read gaps were 74.990 / 65.093 / 95.113 ms.
These gaps are NOT ping or the former synthetic ordered-echo P99, and not every individual
one-second bucket exceeded 200 Mbps. A real delayed-relay test shifted original traffic
away from a path whose smoothed RTT rose to about 346 ms and completed the download.

Read `../docs/multipath-fec-business-20260905.md` and
`../analysis/multipath-fec-business-20260905.json` for full scope, failed runs, repaired
queue/close bugs, test conditions and cleanup. Raw wire-profile and cover-transport
reasoning is in `../docs/traffic-profile-and-cover-transport-20260905.md`.

```sh
cargo +1.97.0 build -p aggligator-fec --features cli --bin agg-fec-tunnel --release
target/release/agg-fec-tunnel --help
```

The CLI has `client`, `server`, and fixed-target `relay` roles. The bounded `http-test`
role only binds loopback and serves generated bytes, not filesystem content. Live Python
scripts require explicit server-owner authorization and are never run by Cargo tests.
No service was left installed on the test hosts.

## Earlier 200 Mbps optimization update

All-public-IPv4 final validation repeated complete delivery at 209.21 / 208.93 / 209.07 Mbps
in three 30-second samples. Sources used 1300-byte payloads, 64+8 FEC with eight time-interleave
lanes, a 260 Mbps aggregate wire cap, and bounded selective ARQ. All 1,817,304 original
payloads were verified and acknowledged. The primary source path was j; direct j2 and jx2
carried repair symbols. This is low-latency-primary scheduling, not equal traffic striping.

P99 ordered echo RTT was 276.785 / 197.881 / 278.365 ms and maximum delivery stalls were
169.409 / 114.880 / 121.644 ms. Throughput is repeatable; strict low-tail-latency stability
is NOT fully established. Read `../docs/multipath-fec-200m-optimization-20260905.md` and
`../analysis/multipath-fec-200m-final-20260905.json`, including failed candidates and
per-second delivery measurements. No production service was installed.

## Earlier real network follow-up

The `live_lab` example and the explicitly invoked Python scripts under `tests/` exercised
j2 as main server and j/jx2 as transparent relays. They are bounded measurement programs,
not a deployed service or general tunnel. See
[`docs/multipath-fec-live-20260905.md`](../docs/multipath-fec-live-20260905.md) for all
three-round results, higher-rate failures, CPU diagnostics, TCP setup correction and
cleanup checks. They must not be run against arbitrary hosts: addresses, access permission
and free ports must be checked again. No live test is automatically invoked by Cargo.

At 100 Mbps offered downstream load, three-path 8+4 and 8+8 both recovered every source
in the three main short samples. Higher-rate measurements exposed a sender CPU bottleneck
and residual losses. These results do not establish a production reliable throughput ceiling
or a general speed/latency win over TCP.

This experiment targets one main server A, several nearby transparent forwarding servers,
and a client with lossy paths to those entrances. A and the client each run ONE shared FEC
encoder/decoder per direction; the forwarding servers do not perform independent decoding.
It tests spending redundant bandwidth to fill missing bytes sooner, without abandoning bytes
from a reliable application stream.

## Implemented

- Systematic Reed-Solomon erasure coding with immediately emitted original sources.
- Optional time-interleaved blocks with explicit application-sequence mapping (`interleave`).
- Bounded cumulative/selective receipt state and packet retry history (`recovery`).
- A byte-accounted pacing clock covering original, repair and retry data (`pacing`).
- Linux sendmmsg with partial-prefix tracking and portable fallback (`datagram`, runtime feature).
- Owned/cancellable live-test sending thread, ACK loss and tail recovery, and delivery-stall metrics.
- Full-block repairs, or a configurable short deadline (default 2 ms) for partial blocks.
- Shortened blocks: with configured 8+4, three sources use 3+2; one source uses 1+1.
- Variable payload sizes; originals are unpadded on the wire. Repairs protect a two-byte
  original-length field plus payload and zero padding.
- Shared decoding of frames arriving on different paths, bounded block retention, duplicate
  handling, versioned wire framing, dimensional/length checks, and checked sequence arithmetic.
- No-FEC mode (`repair_shards = 0`) for a comparable ARQ-only experimental baseline.
- Real loopback UDP transparent-relay tests in both directions.
- A test-only adapter proving handshake, data echo, fragmentation/reassembly, and graceful
  close against unmodified upstream Aggligator 0.12.1.

## API and runtime contract

`Config` defaults to `data_shards=8`, `repair_shards=4`, `max_payload=1100`,
`max_block_delay=2ms`, and `max_decode_blocks=256`.

`Encoder::push(payload, now)` returns an original source immediately and any repairs due.
The caller MUST also call `Encoder::poll(now)` from a timer while idle. `flush()` seals a
partial block. A deadline limits block formation, not network queueing or total delivery time.

`Decoder::input(frame)` emits originals/reconstructed sources as soon as they are available,
UNORDERED. The caller owns reliable delivery ordering and runtime flow control. The separate
`recovery::SendWindow` provides bounded sender state, not a complete receiver or connection API.
Original duplicates can be emitted again, including after codec-cache eviction, so a reliable
transport can repeat lost acknowledgements. Deduplicate by the session-global `seq`.

Eviction from the bounded FEC cache is NOT an acknowledgement and MUST NOT cause a reliable
transport to discard missing application bytes. Reliable replay/reorder state must be bounded
and tracked separately. The standalone codec does not negotiate parameters; the optional
session layer checks the agreed codec dimensions during its initial exchange.

## Wire and security boundary

Frames have a 26-byte experimental `AF01` header and either an unpadded original or a repair
symbol. Without interleaving a source sequence is `base + index`; with L agreed lanes it is
`base + index * L`, and callers must use the `interleave` helpers rather than raw decoder sequences. Repairs describe the ACTUAL shortened block
size and repair count. The parser rejects invalid versions/kinds, sizes, indices, inconsistent
cached metadata, truncated bodies, and trailing bytes.

This is NOT the RFC FECFRAME wire protocol. The codec has **no cryptographic authentication,
confidentiality, replay admission, session identifiers, or integrity checking**. The session
wrapper adds a random session ID and fixed-peer admission, NOT cryptographic protection.
Inner application authentication cannot protect outer ACK/FEC metadata. Reed-Solomon
here repairs erasures, not arbitrary corrupted or malicious symbols. The production transport
must authenticate the header and body BEFORE admitting a frame to the decoder. Bounds checks
are not a replacement for authentication. Even well-formed forged source bytes are unsafe.

The configured payload bound is NOT a path-MTU guarantee: account for this header, IP/UDP,
cryptographic overhead and any relay encapsulation. The test adapter uses 1100-byte chunks
and bounds the original opaque Aggligator packet size to 1 MiB. That adapter is test-only.

## Reproduce

Use Rust 1.97.0 (the upstream workspace MSRV), without changing the machine-wide default:

```sh
cargo +1.97.0 test -p aggligator-fec --all-features --all-targets -- --nocapture
cargo +1.97.0 clippy -p aggligator-fec --all-features --all-targets -- -D warnings
cargo +1.97.0 run --release -p aggligator-fec --example codec_bench
cargo +1.97.0 run --release -p aggligator-fec --example multipath_lab -- --packets 4096 --seed 1
```

`multipath_lab` also accepts `--seed`, `--app-mbps`, `--wire-mbps`, and `--scenario`.
Its default is 40 Mbps offered application traffic over ONE shared 100 Mbps bottleneck,
three paths with 50/52/55 ms one-way base delay, 2 ms maximum block formation time,
and a common packet-level ARQ policy with a fixed 180 ms retry timeout.

It is a deterministic VIRTUAL-TIME MODEL using real codec operations. It is NOT a TCP,
KCP or QUIC implementation/benchmark, does not include CPU work in its virtual clock, and
has no adaptive congestion controller. A configured-rate pacer and 1024-packet reliable
window bound the experiment. The baseline is the SAME prototype ARQ path without FEC,
not the operating system TCP stack. ACK snapshots cover the full receive window, are
coalesced to 1 ms, and are duplicated over two paths. Wire byte accounting includes IPv4,
UDP, codec framing, repairs and source retransmissions; reverse ACK traffic is separate.

Reported latency is generation-to-IN-ORDER-delivery one-way time, NOT ping RTT. The
`fec_recovered` count includes originals reconstructed before their delayed primary arrives,
even without actual packet loss. Failed samples are retained and cause a nonzero exit.

The CPU microbenchmark measures source-bit processing rate, not tunnel throughput. It
excludes sockets, encryption, session management, packet scheduling and congestion control.

## Tests and results

The current version passes 90 tests, including multi-flow/multi-WAN isolation, bounded
named-service negotiation, bandwidth aggregation, blackout recovery, and sampled original-arrival telemetry,
quality-aware path selection, dynamic path changes, real byte-stream
sessions, upstream add_io integration, slow-reader backpressure, burst retransmission,
long receive-only then close, pacing, interleaving, selective recovery, batch partial
completion, full-window blackout and combined ARQ/ACK-loss coverage. Run with
`--all-features --all-targets` to include the runtime tests and live-harness unit tests. The 8+8 real-UDP test loses a whole relay path plus extra source
packets, then recovers 128/128 payloads in each direction with 56 FEC reconstructions and
no source retransmissions. The over-budget UDP test explicitly retries one original;
it is an integration-point test, not a complete live ARQ implementation.

See `../docs/multipath-fec-experiment.md` for the topology, exact three-seed model results,
CPU measurements, limitations, and the remaining engineering boundary.

## IPv4-only follow-up

`tests/live_ipv4.py` explicitly binds the Mac's physical en0 interface and uses public
IPv4 for BOTH the client-to-entrance and relay-to-main data legs. It learns one UDP
NAT port from each allowlisted client IP, never accepts arbitrary forwarding targets,
and owns narrowly scoped temporary main-host firewall rules through an SSH shell
cleanup trap plus controller audit. Do not run these scripts without server-owner
permission. This is measurement scaffolding, not authentication or a production relay.

The 2026-09-05 follow-up completed 34 UDP/FEC and 12 TCP data samples. Three 100Mbps
8+8 downlink samples and a 20-second/250,000-packet two-entrance sample reconstructed
all originals, but other FEC runs retained holes and high-load limitations persisted.
IPv4 was not universally lower-latency than the earlier IPv6 runs. See
`../docs/multipath-fec-live-ipv4-20260905.md` for all key samples, topology caveats,
failed-delivery accounting, and verified cleanup. Earlier IPv6 results remain separate.
