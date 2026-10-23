# Distributed servers

`mesh-server` runs equal peers. Any server can admit another server, answer
client discovery, become a selected exit, or forward encrypted traffic toward
another exit. The first server only initializes credentials; it has no permanent
coordination role. Membership converges through authenticated peer exchanges.

## TCP/UDP proxy and multiple exits (v0.3.2)

Enable proxy egress with `--proxy`. A fixed `--target` is optional in this mode;
provide both options to serve the existing UDP tunnel and the proxy together.
Existing state directories and client/server keys can be reused.

```sh
braidpath mesh-server --dir local/node-a --id node-a \
  --listen 0.0.0.0:4433 --advertise 192.0.2.10:4433 --proxy

braidpath mesh-server --dir local/node-b --id node-b \
  --listen 0.0.0.0:4433 --advertise 192.0.2.20:4433 --proxy \
  --join 192.0.2.10:4433 --join-key local/server-key.json

# One SOCKS5 endpoint distributes new connections across the selected exits.
# Additional endpoints let applications select an exit explicitly.
braidpath proxy-client --connect 192.0.2.10:4433 \
  --connection-key local/client-key.json --dir local/proxy-client \
  --exit node-a --exit node-b --listen 127.0.0.1:1080 \
  --socks5 node-a=127.0.0.1:1081 --socks5 node-b=127.0.0.1:1082
```

Repeat `--exit` for up to eight nodes, or specify just one for a fixed exit.
The main listener assigns new TCP connections and UDP associations round robin.
Each connection/association retains its exit for its entire lifetime, including
all destinations within one UDP association. If connecting to an exit fails,
the pool can try another selected exit before sending the application request.
A pinned `--socks5 EXIT=ADDRESS` listener uses only that exit. A destination
rejection is returned to the application; requests are never replayed elsewhere.
Existing streams fail if their exit fails; other exits continue serving their
own streams. Clients discover address updates in the background every 15 seconds;
new connections use updated addresses while existing connections retain their
original peer. This is concurrent use of exits by separate flows; one TCP stream
uses one reliable QUIC stream to one exit.

All local listeners must bind loopback. Their SOCKS5 interface supports CONNECT,
UDP ASSOCIATE and the no-authentication method; BIND returns command unsupported.
The remote link requires the existing pinned certificate and client token, and
authenticates the requested exit ID before accepting destinations. There is no
public unauthenticated SOCKS port. Domains are sent to the selected exit for
resolution; both IPv4 and IPv6 destinations are supported. UDP prefers IPv4 when
DNS provides both families; an explicit IPv6 destination uses IPv6.

For [Clash/Mihomo SOCKS5 nodes](https://wiki.metacubex.one/en/config/proxies/socks/),
merge these entries into the application's existing configuration:

```yaml
proxies:
  - {name: BP-Pool, type: socks5, server: 127.0.0.1, port: 1080, udp: true}
  - {name: BP-A, type: socks5, server: 127.0.0.1, port: 1081, udp: true}
  - {name: BP-B, type: socks5, server: 127.0.0.1, port: 1082, udp: true}
proxy-groups:
  - name: BraidPath
    type: select
    proxies: [BP-Pool, BP-A, BP-B]
```

Choose BP-A/B for a fixed exit, or BP-Pool for concurrent use by new connections.
Route the desired application rules to the BraidPath group. BraidPath must run on
the same machine as these loopback SOCKS endpoints. This supplies the proxy
service model requested for v0.3.2; its wire protocol is not Hysteria 2, so a
Clash `hysteria2` entry cannot connect to it directly.

The proxy uses ALPN `braidpath-proxy/1` on the existing server UDP port. TCP uses
QUIC reliability and backpressure, including half-close. UDP uses QUIC DATAGRAM
with bounded fragmentation (up to 65,507 payload bytes), no retransmission and
no FEC. SOCKS UDP headers also consume the local operating system's datagram
limit. SOCKS-level fragments (`FRAG != 0`) are dropped as permitted by
[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.txt). The existing HTTP/3 FEC
tunnel and its cooperating relay entrances retain their separate behavior.

Proxy limits and lifecycle:

- Each server admits 64 proxy connections, 256 streams, 64 UDP associations and
  1,024 UDP destinations in total; each association allows 32 destinations.
  Each authenticated QUIC connection permits 64 concurrent streams. The client
  admits 256 local sessions. Up to 32 OS DNS lookups may be in flight; a timed-out
  lookup retains its slot until the resolver actually returns. Pending connections retain the shared server
  admission budget and must authenticate within eight seconds.
- `--max-rate-bps` caps the combined TCP/UDP proxy payload in both directions,
  across all proxy clients, with a 128 KiB burst. TCP waits for credit; excess
  UDP is dropped. This is the proxy budget; existing relay/tunnel budgets are
  separate. `auto` uses the existing 1 Gbit/s maximum.
- UDP associations close when their SOCKS TCP owner closes, after 60 seconds
  without traffic, or when their QUIC connection closes. UDP destination sockets
  expire after 60 seconds idle. TCP streams expire after 300 seconds idle across
  both directions. An empty proxy connection closes after 60 seconds.
- Datagram assembly allows four incomplete packets per association, a two-second
  lifetime and a 64-packet history. Expired/completed packet IDs cannot be revived
  by late fragments. Queues, socket buffers and per-send waits are bounded.
- Public destinations are allowed by default. Private, loopback, link-local,
  shared-address and local IPv6 destinations are blocked after DNS resolution;
  the checked IP is the actual connection target. `--proxy-allow-private` opts
  into access to those networks for trusted client-key holders. Unspecified and
  multicast addresses remain blocked. Proxy access must be explicitly enabled
  on each desired exit.

`mesh-status` advertises `proxy-tcp-v1` / `proxy-udp-v1` only when enabled, and
includes live proxy connection, stream, association, destination and rejection
counts. Local tests cover real QUIC/SOCKS sockets, selected and simultaneous
exits, domain resolution, half-close, fragmented UDP, authentication, destination
policy, exit failure and resource cleanup. Public-network performance and
application-specific Clash acceptance remain separate validation work.

## Credentials and startup

Keep state and copied credentials under ignored `local/`. A new or empty dedicated
state directory creates a cluster identity automatically. On another server, import its
`server-key.json` and join **any reachable member**:

```sh
# First server (replace public address and UDP target).
braidpath mesh-server --dir local/node-a --id node-a \
  --listen 0.0.0.0:4433 --advertise 192.0.2.10:4433 \
  --target 127.0.0.1:9000 --relay-ports 44400-44463

# Another server, with the server key copied through a secure channel.
braidpath mesh-server --dir local/node-b --id node-b \
  --listen 0.0.0.0:4433 --advertise 192.0.2.20:4433 \
  --target 127.0.0.1:9000 --relay-ports 44400-44463 \
  --join 192.0.2.10:4433 --join-key local/server-key.json
```

Restart with the same arguments. Saved identity is reused, and an unavailable
`--join` entry does not block a server that has persisted peers. Enrollment keys
may be removed after a successful import; an existing `--join-key` file must
still match the saved cluster. Both join options may also be omitted on restart.
From v0.2.2, stop a node and restart it with the same `--dir` and `--id`, but
the new `--listen` / `--advertise` address, to move it. Its keys remain unchanged.
The authoritative identity atomically increments an address incarnation; normal
restarts at the same address retain it. Newer incarnations replace older records
for that ID, and stale gossip cannot roll the address back. A migration cannot
displace a different live node at the new address. Upgrade all mesh participants
before using this operation. Existing UDP target flow state is not migrated.
Incarnation ordering is retained in membership and unexpired reconnect hints;
the seven-day hint limit is not a permanent identity revocation registry.

IDs and advertised addresses must be unique among running servers. The
directory holds up to 32 members. Membership maintenance is automatic:

- A persisted address migration supersedes the same ID's older incarnation.
  Conflicting legacy records with incarnation zero, or a different ID reusing
  a departed member's address, replace the old record once no member has
  reported it running for 20 seconds. Other running claims never displace each
  other; the conflicting record is ignored and logged at debug level. Retaining
  a versioned node ID requires its saved state; a fresh directory cannot reset
  an existing member's incarnation.
- Records that no member has reported running for 10 minutes are forgotten,
  freeing their slot. A server with no live peer forgets nothing, so its own
  isolation cannot erase the cluster. If the table is full, an authenticated new
  sender may replace the oldest record unheard for at least 10 minutes; that
  record is first saved as a reconnect hint. Recent members cannot be displaced
  for capacity. A forgotten server that returns is
  admitted again through its saved peers or `--join`. Before forgetting,
  each server persists up to 32 separate reconnect hints with the UTC time
  they were recorded. Once per minute it probes up to four forgotten addresses
  in rotation, concurrently and without advertising them as live, so a full
  hint set is tried within eight minutes. Thus two groups that both remained
  internally connected can discover each other after a long partition,
  including after restart. A hint is removed once its ID or address is a member
  again, and expires after seven days, so a retired server is not probed
  forever; a partition lasting longer needs `--join`. An unreadable hint file
  is logged and ignored rather than blocking startup. These hints are
  reconnection candidates, not trusted liveness or revoked identities.

Credential rotation is not automated.

Back up the whole state directory, including private `identity.json`. Interrupted
initialization can finish on the next start with the same keys; missing derived
key files are restored from that identity. Conflicting files are rejected rather
than overwritten. Only one server can own a state directory; its operating-system
lock is released even after a crash. Peer caches are atomically replaced before
new membership is committed. Writes are serialized on blocking workers, outside
the runtime and membership read locks; reads, lease renewals and forwarding do
not wait for disk sync. Cancelling a request cannot reorder its pending write.
A worker retains the directory lock until its disk and memory publication ends.
Reconnect hints are saved before removing members, and returning-member hints
are deleted only after membership is durable. Complete older state directories
are adopted with their existing identity.

Export **only `client-key.json`** to clients. It contains the pinned certificate
and client access token, but no TLS private key or membership token. The server
join key grants full cluster trust, including the shared server TLS identity;
all servers are in one administrative trust domain. Client credentials cannot
register members. Imported keys are not logged or printed. Unix directories and
secret files are restricted to the owner; apply equivalent directory ACLs on
Windows.

## Discovery and exit selection

```sh
braidpath nodes --connect 192.0.2.20:4433 \
  --connection-key local/client-key.json --dir local/client

braidpath mesh-client --connect 192.0.2.20:4433 \
  --connect 192.0.2.30:4433 \
  --connection-key local/client-key.json --dir local/client \
  --exit node-a --listen 127.0.0.1:7000 --adaptive
```

Discovery returns live node IDs and addresses. `--connect` is only the discovery
entry and may be repeated. Explicit entries are queried concurrently. A mesh
client waits for a response containing its selected exit; a fast partial view
does not cancel the other requests. If no entry supplies that exit, the client
tries previously authenticated members saved in its local
directory. Those cached addresses are hints, and every response still needs
certificate and token authentication. Reusing that directory allows client
restart after the original entry disappears. `--exit` decides which server delivers traffic to **its configured UDP
target**. Each client may choose a different exit. A session has exactly one
exit responsible for deduplication, FEC and UDP flows; this is not a cluster
leader. Selecting a different exit starts a new session. There is no TCP, TUN,
system-wide default route, or transparent migration of existing UDP flow state.

The client starts with its direct exit path immediately and allocates cooperating
entrances in the background, up to eight paths. Each successful allocation is
published without waiting for slower optional nodes. Leases renew every 11 seconds on their own
timer; discovery runs every 15 seconds in the background, so unavailable
members cannot delay a renewal. After discovery the client adds newly
discovered nodes when a path slot is available. A lease the server explicitly
rejects is recreated, or released at once if no replacement can be allocated.
Renewal completions are consumed individually alongside discovery and allocation;
a stalled renewal does not prevent a newly allocated entrance being published.
Unchanged paths keep their connections; replacements keep the local UDP
listener and selected exit. Each recovered entrance is published immediately,
without waiting for other renewals to finish.
Discovery rotates among known members and falls back to other members on
failure. A partial live directory does not erase previously known candidates.
The saved member cache is bounded to 32 entries. A fresh authenticated
response replaces cached records with the same ID or address, subject to the
incarnation ordering above, and evicts older hints first when the cache is full.
Cache writes are serialized on a blocking worker with coalesced pending state;
maintenance and network lease cleanup do not wait for disk sync. Runtime teardown
can still wait for an outstanding filesystem operation.
When no data path is connected, the client attempts all configured entrances
concurrently (at most eight), so unavailable earlier entries cannot delay a
working later entry. Background reconnections retain a two-attempt limit.

From v0.3.0, `mesh-client` accepts repeated `--interface` (Linux) and/or
`--source-ip` options. When both are present, counts must match. Interface and
source binding apply to bootstrap discovery, allocation, renewal, release and
the matching data paths. Each uplink gets a distinct group in option order;
`--group-rate-bps` applies to that group's data, feedback, probes and repairs.
The eight-path session budget is divided across uplinks, including one direct
path per uplink. Reordering discovery does not change an unchanged route's ID.
Source-IP binding is portable, but alone does not override the OS routing table
or prove independent physical networks. Mesh path
reconnection and generation feedback are enabled even without `--adaptive`;
that flag additionally enables adaptive pacing. Reconnect to change the exit.
If the selected exit restarts and loses its session, the client creates a new
session epoch; existing UDP target flow state cannot be preserved. It never
silently selects a different exit. From v0.2.1, every mesh session request and
response must name the selected exit ID, including the response that authorizes
a new epoch. A reused address belonging to another node is rejected before
any application traffic. When discovery learns a new address for the same exit,
the direct path is replaced and leases targeting the old address are discarded
and reacquired. Existing UDP flows may need to restart.

Upgrade the mesh client and its selected exit together to v0.2.1 or newer.
Older mesh clients omit this binding, and older exits cannot acknowledge it;
both cases fail explicitly. The cluster key format remains unchanged. v0.2.2
adds allocation request identities, explicit release, and nonzero address
incarnations; upgrade mesh clients and servers together before using these
features. Older parsers reject the added fields. Ordinary `client`/`server`
sessions still work without a mesh
exit header.

Each v0.2.2 allocation has a stable random request identity. Repeating it from
the same source IP for the same exit returns the existing lease, including when
the response was lost or the lease quota is full. Deduplication state is bounded
by the live lease table and expires with the lease. It does not preserve a lease
across a relay restart. Changing the exit under the same request identity is
rejected. Normal client exit and address migration explicitly release old
allocations; release can select a lease or its allocation request identity, so
an allocation whose response was lost can still be reclaimed. Release is
authenticated and source/exit bound. A successful release waits for its relay
task and UDP socket to close; repeating a release is harmless.

Graceful client cleanup is bounded to five seconds. A killed client, unreachable
control endpoint still relies on the existing idle lease timeout. A bounded
history of 512 released request identities rejects late allocations for 45
seconds, including release arriving before allocation. Oldest entries are
evicted at capacity; requests arriving beyond this history still rely on idle
expiration. Control-plane failure alone does not release a working data path.

## Coordination and resource bounds

- Every server probes known peers every five seconds, concurrently, and
  advertises only the members it currently sees live. Only a successful direct
  authenticated exchange makes a peer live locally. It expires after 20 seconds
  without such evidence; repeated gossip cannot revive it. Offline peers remain
  in the restart cache and are probed until forgotten. Records are judged one
  at a time, so one conflicting record cannot block the rest of an exchange or
  the sender's liveness. Initial discovery can take a sync interval.
- Control uses authenticated HTTP/3 with normal certificate validation and no
  early application data. Each process reuses one connection per destination,
  with at most 32 cached client destinations or 36 server destinations (including
  four reconnect probes), and a four-second request deadline.
  Complete HTTP rejections reuse the connection; transport/protocol failure or
  cancellation closes it. Requests are not blindly
  replayed. Control bodies are limited to 32 KiB. Cached connections that are
  idle (unused for 20 seconds on servers, 33 seconds on clients) are
  closed, leaving lease holders as the client's long-lived control peers. An
  authenticated mesh request takes a slot from a separate budget of 256
  control connections. Pending handshakes and unclassified connections have a
  separate 64-connection budget and must authenticate within 10 seconds of
  the handshake; this absolute deadline also covers blocked response writes.
  Authenticated data connections have 128 slots.
  Full data capacity therefore does not block a new control handshake. A full
  control budget rejects the connection before executing an operation, without
  borrowing data slots. The server closes a control connection after 60 seconds
  without an authenticated request, including when an unrelated response is
  blocked by the peer. Connections cannot switch between control
  and data roles.
- A relay allocation accepts UDP only from the authenticated control client's
  observed source IP. New allocations require a live registered exit. Allocations
  are limited to 64 per server and 16 per client source IP, with the existing
  64 source mappings and bounded queues per allocation. All allocations share
  one server-wide `--max-rate-bps` relay budget, charging both directions
  together with the existing 48-byte per-datagram overhead estimate and a
  32 KiB burst. This relay budget is separate from the selected exit's session
  cap. Leases with recent demand share the refill rate; idle shares are reclaimed
  after one second, checked every 100 ms or when activity changes. A busy lease
  cannot spend other active leases' ongoing shares. Releasing a lease returns
  its share without granting extra total tokens.
- Leases expire after 45 seconds without renewal *or forwarded client traffic*,
  reaped on the five-second maintenance interval, so a working data path
  survives a control-plane outage. An idle orphaned allocation still expires.
  Disconnecting a client stops renewal; task cancellation closes its control
  connections. An explicitly rejected renewal triggers a new allocation and
  updates the running tunnel. On the client, brief control failures retain the
  previous entrance while its authenticated QUIC data connection remains open,
  even after 45 seconds without renewal. The tunnel reports connection health
  every 200 milliseconds, outside the packet path. A closed path, or a health
  reporter silent for 45 seconds, cannot indefinitely retain an expired lease.
  An explicit server rejection still removes or replaces the old allocation.
  Per-allocation relay lifecycle and statistics logs are at debug level.
  An existing owned lease can renew while its exit's membership heartbeat is
  unavailable, preserving a working UDP path without permitting target changes.
- Intermediate servers forward opaque QUIC packets. There is no second QUIC
  encapsulation and no per-packet membership lookup or filesystem access. FEC
  and scheduling remain in the existing client/exit data plane. Relay map
  cleanup runs on maintenance rather than scanning every mapping per packet.
  Full relay queues reject packets before copying their payloads; steady-state
  counter updates do not allocate direction labels. A failed source mapping
  does not terminate other mappings in the relay allocation.

Servers need reachable UDP at their advertised service address **and relay
ports**. `--relay-ports 44400-44463` confines allocation to that inclusive range;
a single port is also accepted. Open/map that range and the service port in the
firewall/NAT. The installer example uses this 64-port range. A busy range rejects
new allocations instead of silently opening another port. At most 64 allocations
remain active, even if a larger range (up to 1,024 ports) is configured. Omitting
the option retains OS-assigned ports for existing configurations.

Relay ports bind to the service bind IP and use the advertised IP. NAT must
preserve their port numbers. A single exposed service port alone cannot carry
cooperating relays. Differing source routes between control and data, and
automatic NAT traversal, remain unsupported.

On Unix, SIGTERM and SIGINT follow the same bounded cleanup path: endpoints,
relay mappings and background tasks stop before final statistics and trace
output are finalized.

## Validation boundary

Local socket tests exercise authenticated membership, all three nodes acting
as exits through relay-only paths, bootstrap-server loss, joining a surviving
member, and restart from persisted peers. A live client test excludes the direct
exit, restarts its relay while reserving the old lease port, verifies recovery
on the same session, and then adds another server without restarting the client.
Control tests verify connection reuse, timeout/cancellation cleanup and bounds.
A stalled discovery entry and an unrelated stalled renewal are checked while an
expired relay entrance is replaced and delivered to the tunnel. Another test
keeps two entrance handshakes unanswered and verifies UDP delivery through a
third entrance before those handshakes time out.
Tests also cover original-argument restart with a dead join entry, cached client
discovery, fixed relay-port exhaustion/reuse, interrupted identity setup,
invalid-key rejection, process-exit lock release and failed cache-write recovery.
Tests also model a four-node partition beyond the forgetting deadline, reload
persisted reconnect hints and restore membership through real authenticated
exchanges. A real UDP relay carries traffic while its control port blackholes
renewal and the client's lease timestamp is older than 45 seconds. Admission
tests exhaust independent budgets and verify role separation over HTTP/3.
Unit tests cover merge atomicity, stale gossip, member limits and credential separation. These are functional
checks, not evidence of WAN reachability, higher throughput, or lower CPU use.
The original `server`, `client` and fixed-target `relay` commands remain usable.

The v0.2.1 regressions additionally cover a full isolated directory admitting a
new authenticated member, stalled/cancelled/failed persistence, exit-address
reuse through direct and relay paths, incomplete discovery, optional allocation
blackholes, blocked unauthenticated responses, aggregate relay budgets, and
SIGTERM against the local executable. These are local correctness checks, not
public-network throughput or service-manager deployment acceptance.

The v0.2.2 checks cut a real HTTP/3 allocation response after server commit,
retry without consuming another lease, reject unauthorized release, and cycle
allocation/release 64 times through one relay port. They also cover bounded
release-before-allocation cancellation, slow and failed cache writes, stale
cache incarnations, and allocation publication during an unrelated blocked
renewal. A process test keeps a client running while its selected server moves
using the original state directory and keys, then reuses the old address for a
different node; recovery must deliver to the selected exit and never to the
address successor. These checks do not establish a WAN recovery-time guarantee.


## v0.3.0 multi-network operation and diagnostics

For example, on Linux with two configured uplinks:

```sh
braidpath mesh-client --connect 192.0.2.20:4433 \
  --connection-key ./client-key.json --dir ./client-state --exit node_a \
  --interface eth0 --interface eth1 --adaptive \
  --group-rate-bps 0:10000000 --group-rate-bps 1:5000000
```

Use `--source-ip` once per uplink to bind an explicitly configured local address.
Only address families supported by that source address can be used. In v0.3.1,
at least one uplink must initialize; a missing local interface/address on another
uplink does not fail the whole client. Unavailable uplinks retry initialization
every two seconds. A control owner with no usable path for 30 seconds is retired
and recreated, including its bound sockets. The local UDP listener remains.
Each initialized uplink retains one reconnect slot. Remaining slots are shared
among usable uplinks (or all starting uplinks for a ten-second grace period),
within the same eight-path total and the unchanged per-group rate limits.
Shrinking an allocation releases excess leases and rejects late allocations.
All paths continue to authenticate the same selected exit.

A mesh path that has admitted at least eight symbols without positive delivery
feedback for three seconds is closed and retried. Successful QUIC keepalives
alone do not clear this condition; idle paths without outstanding evidence are
not failed. Generation changes reset the evidence. A failed relay can be replaced
by an available candidate without waiting for an elective quality score. That
failed member has a 30-second selection cooldown. The chosen exit never changes.

When every usable data path disappears, a health notification starts one
coalesced directory refresh, with at least two seconds between starts. The
normal 15-second refresh and independent lease renewal remain active. The
connection event stream identifies QUIC, HTTP/3 and session admission stages;
refresh/lease failures also have diagnostic logs. These timers are not measured
outage-to-business-packet guarantees.

A full uplink path allocation with at least two connected paths can use one
slot to assess another known entrance. The direct exit stays configured. Trials
have a 30-second cooldown and an eight-second evaluation period. An incumbent
requires fresh positive delivery (at least eight symbols, evidence younger than
two seconds); a candidate must improve RTT weighted by observed loss by more
than 20%. RTT alone cannot promote a candidate. A failed or unproven candidate
returns its slot to the incumbent when another usable path remains. The last
connected path is retained. These are bounded entrance-selection heuristics,
not a claim of optimal routes or higher application goodput. A small allocation
with fewer than three slots does not run elective trials.

Read-only status uses the existing authenticated HTTP/3 port:

```sh
braidpath mesh-status --connect 192.0.2.20:4433 \
  --connection-key ./client-key.json --dir ./client-state
```

The JSON separates known peers, directly live peers and reconnect hints; reports
lease and control-connection occupancy and limits; and counts persistence
failures since process start. Recovery is `standalone`, `reconnecting` or
`connected`. Occupancy includes the diagnostic control connection itself and
leases awaiting periodic cleanup. Inspection does not renew leases or alter
membership. Tokens, private keys, lease selectors and filesystem error details
are excluded. An unauthenticated request still gets an empty 404.

`GET /mesh/info` advertises control protocol 1 and named features. New lease
allocations require exit binding, node incarnation, allocation request identity
and explicit release support. Unknown optional features are ignored; a missing
required feature rejects that entrance without weakening ownership rules.
Upgrade servers before v0.3.0 clients. Typed authenticated errors distinguish
expired leases, owner mismatch, released requests, unavailable exits, node/source
lease limits and persistence failures. Old generic error responses remain
errors, not successful fallback responses.

Larger UDP messages use a separately echoed session limit (see
[runtime message contract](runtime.md#udp-message-boundaries)). Old sessions
without that extension remain limited to 1,000 bytes. Use
`--max-message-bytes 1000` for a data session with an older peer; this does not
bypass mesh capability or exit-identity requirements.

Client statistics include bounded `mesh_uplinks` entries: group, bound source,
initialization attempts, controlled failure code, path allowance and current
usable/configured counts. States distinguish waiting, connecting, connected,
unavailable and stopped. These are local path observations, not application
reachability or independent-WAN certification.

Native tests cover missing-uplink startup/reinitialization, bounded slot sharing,
failed-relay replacement, resize/release/reallocation and separate bound control sockets and lease ownership, four
routes in one tunnel, larger-message echo, cleanup and bounded candidate
selection. Portable loopback tests do not certify two independent WANs. A
physical multi-network acceptance run must record actual source routes, network
removal/recovery and the time to the first valid application response, with
run details kept in ignored `local/`.
