# Experimental runtime

BraidPath currently forwards unreliable UDP messages to one operator-configured destination. Each path uses real HTTP/3 over Quinn/rustls, with authenticated HTTP Datagrams. There is no Xray runtime, TCP adapter, TUN device or transparent IP tunnel.

## Local quick start

Build with `cargo build --release --locked` (Rust 1.88+). The following commands run from the repository root. Keep the long-running commands in separate terminals.

```bash
# Run once. Refuses to replace an existing identity directory.
./target/release/braidpath init --dir local/identity --name localhost

# Terminal 1: test destination (or use your own UDP service).
./target/release/braidpath echo --listen 127.0.0.1:9000

# Terminal 2: main server.
./target/release/braidpath server --listen 127.0.0.1:7443 \
  --cert local/identity/cert.pem --key local/identity/key.pem \
  --token-file local/identity/token --target 127.0.0.1:9000

# Terminal 3: client. Applications send UDP to this local port.
./target/release/braidpath client --listen 127.0.0.1:7000 \
  --entrance 127.0.0.1:7443 --server-name localhost \
  --ca local/identity/cert.pem --token-file local/identity/token

# Terminal 4: ordinary HTTP/3 and end-to-end datagram checks.
./target/release/braidpath get --entrance 127.0.0.1:7443 \
  --server-name localhost --ca local/identity/cert.pem
./target/release/braidpath probe --target 127.0.0.1:7000 \
  --count 1000 --size 1000 --pps 200 --deadline-ms 250
```

For separate hosts, bind the server to its intended address, use a certificate matching `--server-name`, and securely copy the public certificate and token to the client. Keep the private key only on the main server. `init` creates a self-signed test certificate; production identity provisioning and rotation are not automated. One server token defines one authorization domain. Unix identity permissions are restricted; operators must restrict credential ACLs on Windows.

The local client listener should stay on loopback unless other local-network callers are deliberately authorized. Its callers share the tunnel credential. The main server permits only its configured UDP target; it is not an arbitrary destination proxy.

## Multiple entrances and interfaces

A loopback relay can be added in another terminal:

```bash
./target/release/braidpath relay --listen 127.0.0.1:7444 \
  --target 127.0.0.1:7443 --allow-source 127.0.0.1
```

Restart the client with both `--entrance 127.0.0.1:7443` and `--entrance 127.0.0.1:7444`. For remote relays, configure the main server's reachable address and allow the client's actual public source IP. No credentials or TLS keys are installed on relays. Each client socket gets a separate return mapping; relay backhaul traffic goes directly to the main server.

On Linux, repeat `--interface eth0 --interface wlan0` to create the interface–entrance Cartesian product, up to eight connections. Binding requires appropriate socket permissions and routes; it does not create policy routes. Non-Linux explicit interface binding returns an error. Without the option, all platforms use the default route. Creating several connections on one interface does not demonstrate multiple access links.

## Policy and limits

| Option or bound | Meaning |
| --- | --- |
| `--fec 4` (default), `--fec 0` | One XOR repair per block of at most four originals, or FEC off; maximum block size 32 |
| `--block-ms 3` | Maximum encoder block age, driven by a 1 ms timer; originals are emitted immediately |
| `--redundancy-percent 30` | Repair HTTP-datagram byte budget credited only by successfully admitted originals; saved credit is bounded |
| `--congestion bbr` (client/server) | BBR is the only runtime congestion controller; each QUIC connection still controls its own congestion window |
| `--rate-bps 10000000` | Per-session, per-direction aggregate pacing cap, including an estimated header allowance; independent QUIC congestion control remains active |
| `--adaptive` | Opt-in per-path pacing, sender-age admission, fresh-health eligibility, independent probes and automatic startup/outage recovery |
| `--latency-target-ms 20` | Local sender-age limit and added-delay control objective; does not bound propagation RTT or end-to-end delivery |
| `--path-group GROUP` | One group ID per interface–entrance pair; omitted assignments default to the interface index |
| `--group-rate-bps GROUP:BITS_PER_SECOND` | Shared per-direction cap for every path in that group; repeat for different groups; each cap is 64,000..aggregate bits/s |
| Server `--max-rate-bps` | Caps the session's server-side sender; not a server-wide or inbound traffic policer |
| `--queue-ms 100` | Sender lifetime starts at original application ingress; adaptive mode uses the smaller of this and `--latency-target-ms` |
| Message size | 1,000 application bytes; no fragmentation; larger local UDP messages drop |
| State | 16 sessions, 8 paths/session, 64 flows/session, 256 queued events/records, 256 decode-block slots, 8,192-ID dedup window |
| Sender symbol queue | At most 256 total symbols, 64 originals per flow and 64 repairs; admitted flows receive turns |
| Lifetimes | Receiver repair waiting uses `--queue-ms`; UDP flows expire after 60 s idle; adaptive sessions retain an empty-path epoch for approximately 120 s |
| Relay | Fixed destination, explicit source allowlist, 64 mappings, 32 queued packets/mapping, 30 s idle; shared bidirectional byte-rate cap |

Originals are never delayed merely to fill a block. At 200 messages/s, the default 3 ms block often contains only one original: the repair budget can skip many singleton repairs. Use a deliberate larger block deadline (for example 25 ms) when comparing full four-record blocks, and count the additional recovery wait. The existing FEC defaults are unchanged; the adaptive mode does not select a new FEC configuration.

Repair credit is now created only after an original HTTP datagram is accepted by Quinn. Originals dropped before admission, including expired input, do not create credit. Repair credit is spent only on actual repair admission, with a bounded balance; insufficient credit cannot block original service. Repairs prefer an eligible path not used by their block's admitted originals, but this is a best-effort preference. The budget counts admitted HTTP-datagram bytes, not exact NIC wire bytes or confirmed delivery. Aggregate and group pacing also charge feedback, probes and an estimated header allowance. Handshake, ACK, transport retransmission and relay backhaul costs require separate measurement.

The QUIC datagram send buffer is limited to 1,200 bytes including internal allocation overhead. It can hold one maximum-size BraidPath record or several small ones. The application cannot expire or recall a record after Quinn accepts it: this is a byte bound, not an end-to-end deadline guarantee.

The baseline scheduler round-robins open connections with datagram buffer space. The optional quality scheduler preserves its simpler weighted policy; byte service is charged only to the path that actually accepts a symbol. Failed attempts spend no service credit. Adaptive mode additionally checks local ingress age, path-health freshness and per-path pacing. Neither mode automatically detects shared bottlenecks or couples congestion windows.

Original expiration uses application ingress time across input and symbol queues. Adaptive mode drops originals after `min(queue-ms, latency-target-ms)` of sender age. Admission checks that local age alone; estimated network queue delay separately affects pacing and scheduling weights. A nonexpired original still needs an eligible path, pacing budget and Quinn buffer space. Repair lifetime begins with the earliest original in its block. At the receiver, `queue-ms` bounds repair waiting; retiring a repair block does not itself invalidate a previously unseen original. These local policies cannot recall an original already in Quinn, a kernel queue or the network, and do not establish an absolute end-to-end deadline guarantee.

The per-flow and repair queue caps prevent one bulk flow and its repairs from filling every sender symbol slot. They do not reserve kernel or ingress-channel capacity for an interactive caller, and do not establish complete end-to-end traffic-class isolation under overload.

Queues and decode windows are bounded, but this is not hostile-load acceptance. The server accepts up to 128 active connections and bounds handshake/request resolution time. Authenticated clients share the server token's resource domain. Process supervision and deployment quotas remain operator responsibilities.

## Wire profile v1

- TLS verifies the main server's certificate and name; ALPN is `h3`; 0-RTT is disabled. Both peers must advertise QUIC DATAGRAM capacity and HTTP/3 `H3_DATAGRAM` support.
- `GET /` serves a small ordinary HTML page. Unknown requests and unauthenticated `POST /session` return the same 404 response. This is a functional HTTP/3 endpoint, not browser impersonation or a complete production website.
- A long-lived `POST /session` carries the bearer token and version, random 128-bit session ID, path ID and policy headers. Joining another path requires the same credential and session policy. A request FIN or connection closure removes that path. An adaptive session retains an empty-path epoch for approximately 120 s; a baseline session ends when its last path leaves.
- This is a BraidPath application mapping using RFC 9297 HTTP Datagrams, **not CONNECT-UDP, MASQUE, WebTransport or Xray compatibility**. It has no Capsule or reliable HTTP-body fallback.
- Each QUIC DATAGRAM contains the request's Quarter Stream ID, context ID zero and one BraidPath record. Variable-width Quarter Stream IDs are encoded and checked; contexts, versions, lengths and bounds are validated.
- BraidPath envelope: `BP`, version byte `1`, kind byte (data `0`, XOR repair `1`, plain `2`), big-endian 64-bit block ID and 8-bit shard index (or source count for repair records). The payload is the codec shard (length-protected XOR bytes for repair), or a plain record. Canonical application records contain a big-endian 32-bit flow ID, 64-bit delivery ID and UDP payload. Maximum encoded envelope: 1,027 bytes.
- Flow/delivery IDs are scoped to the authenticated session and sending direction. Delivery IDs survive FEC reconstruction; late originals and duplicates are suppressed within the bounded window. Expired blocks cannot be reallocated by delayed shards.

BBR is the only runtime controller in this latency- and throughput-focused implementation. Quinn labels its BBR implementation experimental; the choice is not a universal performance or fairness guarantee. CPU-efficiency optimization is deferred and is not a promotion gate for this increment; correctness, bounded queues and memory limits still apply. Each endpoint owns its sending controller and pacing budget, so configure both endpoints' caps for a symmetric comparison.

The wire profile is experimental and may change before release. The aggregate runtime currently depends directly on the Quinn carrier; a general carrier trait is still future work.

## Verification and interpretation

`cargo test --all-targets --locked` includes deterministic codec/record tests and real-socket three-entrance subprocess tests covering website access, wrong credentials, impaired relay traffic, integrity and relay removal. Deterministic adaptive tests cover repeated clean/congested/recovery transitions, idle/stale feedback, clock-drift diagnostics, transient buffer occupancy, byte-accounting units and application-limited traffic. These tests validate mechanisms, not WAN performance. CI runs on Linux, macOS and Windows; explicit interface binding is Linux-only.

`probe` supports echo and finite forward/reverse one-way measurements with `sink`. JSON reports loss, lateness, useful bytes, actual send span and unconditional P50/P95/P99; missing packets count as positive infinity, encoded as `"infinity"`. Echo uses monotonic RTT; one-way delay subtracts the minimum signed transit delta and is relative, not absolute. Select the ordinary UDP target directly for a raw baseline. Goodput includes the final observation allowance; measured rate and sender/receiver counts must be reconciled. Integrity failures, unavailable data and operational failures remain explicit. See [probe commands and interpretation](probe.md).

Relay `--drop-every N` deterministically drops every Nth permitted incoming UDP packet, including handshake/control traffic. It is a diagnostic packet-loss injector, not an independent random-loss model or a symmetric impairment model. Do not infer FEC benefit from a single run. Compare FEC-off/on, best single entrance and aggregation at the same application load and total budget, count both directions and backhaul cost, and include unequal RTTs, shared bottlenecks and outages. Follow the broader [validation gates](validation.md).

Test settings, credentials, private topology, raw captures and run results stay in ignored local directories. This runtime does not establish a default validated for filtered networks: stock Quinn fingerprints, TCP website parity/fallback, independent-peer interoperability and sustained deployment acceptance remain open.

## Machine-readable counters

For fixed-tuple comparisons, the client accepts one `--path-bind ADDRESS:PORT`
per interface–entrance pair, in the same path order as its interfaces and
entrances. Omit it for kernel-assigned ports. Binding failures are explicit; a
requested source port is used for the initial attempt. An adaptive retry or
explicit source-port rotation preserves the configured source IP and interface
but requests a new kernel-assigned port. Client path statistics record
`local_socket`; both endpoints record `peer_socket`, exposing the relay's
upstream mapping at the server. A repeated client port does not by itself prove
an unchanged relay-side tuple.

Client, server and relay support `--stats-file` for final JSON and optional `--stats-jsonl` / `--stats-interval-ms` for cumulative periodic samples. Readiness and failures are included so benchmarks can stop parsing logs. [Statistics schema and conservation boundaries](statistics.md) distinguish logical records, aggregate symbols, QUIC packets and relay datagrams. Run records belong under ignored `local/`.

`client --receiver-feedback` negotiates feedback version 2 with the authenticated peer. Sequence gaps, unique measured symbol bytes and delay variation are reported through bounded control datagrams, independently of FEC delivery. Delivery-rate samples use the receiver's report interval, not synchronized clocks or the spacing of feedback arrivals. This opt-in mode does not change data scheduling. Both endpoints must support the negotiated version; rejected negotiation is an explicit path admission failure. See [statistics](statistics.md) for counters, bounds and clock limitations.

`client --quality-schedule` enables receiver feedback and smooth weighted round robin in both directions. An estimate needs 16 finalized symbols and a report younger than 3 seconds; unknown/stale paths have weight 2. Healthy weight is `round(32 * (1-loss)^4 / (1 + (delay_variation_ms + quinn_rtt_ms)/50))`, clamped to 1..32. Every open path therefore retains an original-symbol probe share within the existing offered traffic and pacer. RTT includes both legs, so this heuristic does not claim absolute forward delay. Buffer-full paths are skipped using the existing admission behavior.

## Adaptive mode

`--adaptive` enables feedback, byte-weighted scheduling, per-path admission pacing and independent authenticated request/reply probes in both directions. It remains opt-in. Each new path generation starts with an allowance of at most 256 kbit/s and a bounded 2,400-byte burst. Exploration requires backlog and at least 90% actual use of the allowance. Allowed bytes are integrated using the rate active during each part of the control window, so a later rate reduction cannot make earlier admissions appear more fully utilized. The initial search also checks receiver delivery against admission. A low application-limited delivery sample does not establish a capacity ceiling.

Ordinary congestion changes pacing while fresh health keeps a path eligible. The controller uses the latest authenticated probe RTT alongside current Quinn RTT, and finalized interval loss separately from diagnostic RTT/loss EWMAs. Persistent rising delay, a new loss interval or a demonstrated delivery shortfall can reduce the allowance. Repeated old evidence or a constant RTT offset does not repeatedly multiply the pace downward. Recently observed drainage and retained delivery support recovery: a pending drain recovery survives intermediate RTT observations until the next rate-control tick, which may restore up to 90% of a recent service hint. A short low-delivery report without exercised allowance does not establish a new capacity ceiling. Bounded 25% steps every 200 ms revisit a previously exercised range, switching to at most 3% every 500 ms once within 90% of retained delivery. Initial supported growth is capped at 50% every 400 ms. Aggregate/group caps and actual admissions constrain every step.

Immediate safety braking is separate from entering persistent cautious exploration. At the first observation of a pressure episode, the controller records whether actual admission used at least 90% of the integrated allowance. An effective brake enters persistent caution only when that original episode was exercised; filling a smaller allowance after a brake cannot retrospectively qualify the episode. Loss-only pressure uses the same rule. Episode retirement requires both clear current pressure and a genuinely new finalized loss interval that does not trigger loss pressure. A clear RTT on an old report alone does not retire it. This lets cold exploration resume after the tested unexercised pause without changing the growth gains or immediate safety brakes.

Reachability evidence is positive received-byte progress on the path or a valid authenticated probe reply. Finalizing missing symbols refreshes loss information but cannot extend the positive-delivery timestamp, even when a healthy alternate path carries the report. After the startup grace period, positive evidence older than 3 seconds makes a path probe-only. An earlier exclusion applies when a fresh finalized interval contains at least 8 symbols, all are lost, received-byte rate is zero, and neither positive delivery nor a valid probe has occurred within 500 ms. That exclusion persists until new positive evidence arrives; its timing also depends on loss finalization and feedback delivery. Positive delivery or a valid probe reply can restore business eligibility immediately. Same-generation recovery retains learned pace and delivery history; a new path generation resets that controller and starts a new search.

The controller observes approximately every 100 ms. Ordinary delay needs at least 100 ms of persistence before a delay brake; a large increase can be acted on immediately at an observation. Rate reductions occur no more often than every 100 ms; growth uses the intervals above. RTT probes are due no more often than every 500 ms per path, including while business traffic is idle, and require aggregate/group budget and Quinn buffer space. Probe requests and replies do not enter FEC or application delivery; unmatched, replayed, expired or wrong-generation replies cannot refresh health. A healthy feedback route is preferred over silent paths. Deferred feedback reserves aggregate budget and budget in one usable group. Both business traffic and probes respect that reservation, preventing continuous small records from consuming every feedback opportunity.

The measured cross-clock transit minimum remains diagnostic. Adaptive congestion decisions use local-clock RTT evidence and buffer pressure; a rising cross-clock value alone cannot cause downshift or elective rotation. Observed delivery counts measured symbols before application processing, and the pacing allowance is an operational budget. The bounded Quinn buffer contributes a sustained-blocking signal. Its current size falls below the controller's transient-burst allowance, so it does not contribute an occupancy-derived waiting-time estimate.

The per-generation minimum RTT currently has no aging: a permanent propagation change can remain classified as excess delay. Retained delivery can also cause bounded upward trials after a permanent capacity reduction. Pressure-episode retirement has a separate limitation: a new clear finalized interval does not prove that every loss from before or during the episode has been finalized, because no sequence watermark ties that interval to episode onset. A later loss report can therefore start another episode. The cold-pause regression does not establish a universal startup cure; delayed feedback, baseline refresh and long-running behavior require further validation.

The default 20 ms target applies to local sender age and the added-delay control objective; admission uses local age alone. The separate prospective mixed bulk/interactive comparison uses a 100 ms application round-trip deadline: at least 95% on-time delivery in clean/recovered windows and 90% in the impaired window including its transition, while retaining at least 90% of matched-baseline target goodput in clean/recovered windows. These are objectives for a defined validation workload, not a hard cross-host SLA or a claim that the current candidate passes. Application deadline misses and unconditional tail latency remain the acceptance metrics.

Example with the local main server and relay above:

```bash
./target/release/braidpath client --listen 127.0.0.1:7000 \
  --entrance 127.0.0.1:7443 --entrance 127.0.0.1:7444 \
  --server-name localhost --ca local/identity/cert.pem \
  --token-file local/identity/token --adaptive --latency-target-ms 20 \
  --rate-bps 10000000 --path-group 0 --path-group 0 \
  --group-rate-bps 0:8000000
```

This assigns both entrances to one explicitly capped group. By default, all entrances on the same configured interface share a group; default-route paths all belong to group 0. With two interfaces and two entrances, path order is interface 0/entrance 0, interface 0/entrance 1, interface 1/entrance 0, interface 1/entrance 1. Repeated `--path-group` values override that mapping. Group caps constrain combined admitted traffic; they do not discover physical independence or prove congestion-control fairness against other traffic.

## Path and session recovery

Adaptive mode retries initially unavailable and disconnected paths, including an all-path outage. There is at most one attempt per path and two attempts across the client at once. Attempts have an 8-second deadline; consecutive failures back off from 2 s to at most 60 s. A newly disconnected path remains recoverable after a successful connection; a lifetime attempt counter cannot permanently disable it. Each retry preserves interface, entrance and explicit source IP, while selecting a new source port.

`--rotate-source-port` additionally permits elective replacement of an open degraded path and requires quality scheduling or adaptive mode. The legacy quality criterion uses at least 32 finalized symbols, fresh forward feedback and 4 continuous seconds with loss above 5% or transit variation above 100 ms. Adaptive mode corroborates the delay criterion with local RTT-probe evidence. Return-only degradation does not independently trigger this client-side elective policy. An initial connection does not spend the elective cooldown; a successful elective rotation starts a 30-second cooldown. Replacement can discard in-flight old-generation datagrams, which remain losses.

Generation numbers increase within the authenticated session. The server keeps one highest admitted generation per path, rejecting replay or regression without an expanding history. Old-handler cleanup cannot remove its replacement. During a short all-path outage, session and record identity remain intact. If the server has expired its empty session or restarted, it rejects rejoin explicitly; the client then creates a fresh session ID and resets that epoch's flow/record state while retaining the local UDP listener. This is an explicit new epoch, not replay of already delivered records or reliable delivery across the outage.

Paired fixed-load observations, availability failures, port histories and unconditional latency must be reported before considering a default change. Multi-interface capacity, shared-bottleneck competition, long-running field behavior and deployment reachability remain separate acceptance gates. Automatic bottleneck detection, coupled congestion control, adaptive FEC and multi-erasure coding remain deferred.
