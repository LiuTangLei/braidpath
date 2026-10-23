# Distributed servers

`mesh-server` runs equal peers. Any server can admit another server, answer
client discovery, become a selected exit, or forward encrypted traffic toward
another exit. The first server only initializes credentials; it has no permanent
coordination role. Membership converges through authenticated peer exchanges.

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
IDs and advertised addresses must be unique among running servers. The
directory holds up to 32 members. Membership maintenance is automatic:

- A server that moved to a new address, or a new server that reuses a departed
  member's ID or address, replaces the old record once no member has reported
  the old record running for 20 seconds. Two running claims never displace
  each other; the conflicting record is ignored and logged at debug level.
- Records that no member has reported running for 10 minutes are forgotten,
  freeing their slot. A server with no live peer forgets nothing, so its own
  isolation cannot erase the cluster. A forgotten server that returns is
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
new membership is committed. Complete older state directories are adopted with
their existing identity.

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
entry and may be repeated. Explicit entries are queried concurrently; if all
fail, the client tries previously authenticated members saved in its local
directory. Those cached addresses are hints, and every response still needs
certificate and token authentication. Reusing that directory allows client
restart after the original entry disappears. `--exit` decides which server delivers traffic to **its configured UDP
target**. Each client may choose a different exit. A session has exactly one
exit responsible for deduplication, FEC and UDP flows; this is not a cluster
leader. Selecting a different exit starts a new session. There is no TCP, TUN,
system-wide default route, or transparent migration of existing UDP flow state.

The client uses a direct exit path and allocates cooperating entrances from
other live nodes, up to eight paths. Leases renew every 11 seconds on their own
timer; discovery runs every 15 seconds in the background, so unavailable
members cannot delay a renewal. After discovery the client adds newly
discovered nodes when a path slot is available. A lease the server explicitly
rejects is recreated, or released at once if no replacement can be allocated.
Unchanged paths keep their connections; replacements keep the local UDP
listener and selected exit. Each recovered entrance is published immediately,
without waiting for other renewals to finish.
Discovery rotates among known members and falls back to other members on
failure. A partial live directory does not erase previously known candidates.
The saved member cache is bounded to 32 entries. A fresh authenticated
response replaces cached records with the same ID or address, and evicts older
hints first when the cache is full.
When no data path is connected, the client attempts all configured entrances
concurrently (at most eight), so unavailable earlier entries cannot delay a
working later entry. Background reconnections retain a two-attempt limit.

The current mesh client uses the default local route; explicit multi-interface
binding remains available through the original `client` command. Mesh path
reconnection and generation feedback are enabled even without `--adaptive`;
that flag additionally enables adaptive pacing. Reconnect to change the exit.
If the selected exit restarts and loses its session, the client creates a new
session epoch; existing UDP target flow state cannot be preserved. It never
silently selects a different exit.

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
  the handshake; authenticated data connections have 128 slots.
  Full data capacity therefore does not block a new control handshake. A full
  control budget rejects the connection before executing an operation, without
  borrowing data slots. The server closes a control connection after 60 seconds
  without an authenticated request. Connections cannot switch between control
  and data roles.
- A relay allocation accepts UDP only from the authenticated control client's
  observed source IP. New allocations require a live registered exit. Allocations
  are limited to 64 per server and 16 per client source IP, with the existing
  64 source mappings, bounded
  queues and rate budget per allocation. The selected exit's aggregate session
  cap still applies; allocation rate caps are not a host-wide bandwidth cap.
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
