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
| `--redundancy-percent 30` | Repair-record byte budget relative to original-record bytes, with bounded saved credit; insufficient credit skips repair |
| `--congestion bbr` (client/server) | Default per-endpoint controller; `cubic` remains available for comparison, with the same application cap |
| `--rate-bps 10000000` | Per-session, per-direction aggregate pacing cap, including an estimated header allowance; independent QUIC congestion control remains active |
| Server `--max-rate-bps` | Caps the session's server-side sender; not a server-wide or inbound traffic policer |
| `--queue-ms 100` | Maximum age in the aggregate outgoing queue; expired records drop |
| Message size | 1,000 application bytes; no fragmentation; larger local UDP messages drop |
| State | 16 sessions, 8 paths/session, 64 flows/session, 256 queued events/records, 256 decode-block slots, 8,192-ID dedup window |
| Lifetimes | Decode blocks expire after 2 s; UDP flows after 60 s idle; all-path failure terminates the client |
| Relay | Fixed destination, explicit source allowlist, 64 mappings, 32 queued packets/mapping, 30 s idle; shared bidirectional byte-rate cap |

Originals are never delayed merely to fill a block. At 200 messages/s, the default 3 ms block often contains only one original: the repair budget will skip many singleton repairs. Use a deliberate larger block deadline (for example 25 ms) when comparing full four-record blocks, and count the additional recovery wait. The repair budget credits generated original records, including ones that can later expire; it is not yet a ratio enforced on actual wire transmissions. Exact sent-byte redundancy accounting remains future work. It accounts encoded records, not exact NIC wire cost. Pacing uses an estimate; handshake, ACK, transport retransmission and relay backhaul costs require separate measurement.

The QUIC datagram send buffer is limited to 1,200 bytes including internal allocation overhead. It can hold one maximum-size BraidPath record or several small ones. The application cannot expire or recall a record after Quinn accepts it: this is a byte bound, not an end-to-end deadline guarantee.

The current scheduler round-robins connections that have datagram buffer space and remain open. It does not estimate delivery time, detect shared bottlenecks or couple congestion windows. A blackholed path can still receive records until QUIC declares it closed; loss during this interval is expected. Surviving paths remain usable. There is no path rejoin or all-path reconnect; restart establishes a fresh session epoch.

Queues and decode windows are bounded, but this is not hostile-load acceptance. The server accepts up to 128 active connections and bounds handshake/request resolution time. Authenticated clients share the server token's resource domain. Process supervision and deployment quotas remain operator responsibilities.

## Wire profile v1

- TLS verifies the main server's certificate and name; ALPN is `h3`; 0-RTT is disabled. Both peers must advertise QUIC DATAGRAM capacity and HTTP/3 `H3_DATAGRAM` support.
- `GET /` serves a small ordinary HTML page. Unknown requests and unauthenticated `POST /session` return the same 404 response. This is a functional HTTP/3 endpoint, not browser impersonation or a complete production website.
- A long-lived `POST /session` carries the bearer token and version, random 128-bit session ID, path ID and policy headers. Joining another path requires the same credential and session policy. A request FIN or connection closure removes that path; removing the last path destroys the session.
- This is a BraidPath application mapping using RFC 9297 HTTP Datagrams, **not CONNECT-UDP, MASQUE, WebTransport or Xray compatibility**. It has no Capsule or reliable HTTP-body fallback.
- Each QUIC DATAGRAM contains the request's Quarter Stream ID, context ID zero and one BraidPath record. Variable-width Quarter Stream IDs are encoded and checked; contexts, versions, lengths and bounds are validated.
- BraidPath envelope: `BP`, version byte `1`, kind byte (data `0`, XOR repair `1`, plain `2`), big-endian 64-bit block ID and 8-bit shard index (or source count for repair records). The payload is the codec shard (length-protected XOR bytes for repair), or a plain record. Canonical application records contain a big-endian 32-bit flow ID, 64-bit delivery ID and UDP payload. Maximum encoded envelope: 1,027 bytes.
- Flow/delivery IDs are scoped to the authenticated session and sending direction. Delivery IDs survive FEC reconstruction; late originals and duplicates are suppressed within the bounded window. Expired blocks cannot be reallocated by delayed shards.

BBR is the default for this initial latency- and throughput-focused implementation. Quinn labels its BBR implementation experimental; the choice is not a universal performance or fairness guarantee. CUBIC remains an explicit comparison option. CPU-efficiency optimization is deferred; correctness, bounded queues and memory limits still apply. Controller selection is local to each sending endpoint, so configure the client and main server separately for a symmetric comparison.

The wire profile is experimental and may change before release. The aggregate runtime currently depends directly on the Quinn carrier; a general carrier trait is still future work.

## Verification and interpretation

`cargo test --all-targets --locked` includes deterministic codec/record tests and a real-socket three-entrance subprocess test covering website access, wrong credentials, impaired relay traffic, integrity and relay removal. CI runs on Linux, macOS and Windows; explicit interface binding is Linux-only.

`probe` supports echo and finite forward/reverse one-way measurements with `sink`. JSON reports loss, lateness, useful bytes, actual send span and unconditional P50/P95/P99; missing packets count as positive infinity, encoded as `"infinity"`. Echo uses monotonic RTT; one-way delay subtracts the minimum signed transit delta and is relative, not absolute. Select the ordinary UDP target directly for a raw baseline. Goodput includes the final observation allowance; measured rate and sender/receiver counts must be reconciled. Integrity failures, unavailable data and operational failures remain explicit. See [probe commands and interpretation](probe.md).

Relay `--drop-every N` deterministically drops every Nth permitted incoming UDP packet, including handshake/control traffic. It is a diagnostic packet-loss injector, not an independent random-loss model or a symmetric impairment model. Do not infer FEC benefit from a single run. Compare FEC-off/on, best single entrance and aggregation at the same application load and total budget, count both directions and backhaul cost, and include unequal RTTs, shared bottlenecks and outages. Follow the broader [validation gates](validation.md).

Test settings, credentials, private topology, raw captures and run results stay in ignored local directories. This runtime does not establish a default validated for filtered networks: stock Quinn fingerprints, TCP website parity/fallback, independent-peer interoperability and sustained deployment acceptance remain open.

## Machine-readable counters

For fixed-tuple comparisons, the client accepts one `--path-bind ADDRESS:PORT`
per interface–entrance pair, in the same path order as its interfaces and
entrances. Omit it for kernel-assigned ports. Binding failures are explicit; a
requested source port is never silently replaced. Client path statistics record
`local_socket`; both endpoints record `peer_socket`, exposing the relay's
upstream mapping at the server. A repeated client port does not by itself prove
an unchanged relay-side tuple.

Client, server and relay support `--stats-file` for final JSON and optional `--stats-jsonl` / `--stats-interval-ms` for cumulative periodic samples. Readiness and failures are included so benchmarks can stop parsing logs. [Statistics schema and conservation boundaries](statistics.md) distinguish logical records, aggregate symbols, QUIC packets and relay datagrams. Run records belong under ignored `local/`.
