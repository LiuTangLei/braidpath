//! Leaderless discovery and leased, opaque UDP entrances. FEC remains at the
//! client-selected exit; membership changes never replicate live session state.
use super::{MAX_PATHS, relay, stats, transport, tunnel};
use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, Bytes};
use http::{Method, Request, Response};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};

mod discovery;
mod hints;
mod ports;
mod status;
mod storage;
pub use ports::RelayPorts;
use status::Failure;
pub use status::{Capabilities, Status};
mod control;
use control::Control;

mod networks;
mod selection;
pub(crate) use networks::Route;
pub use networks::{Networks, Uplink};
mod entrances;
pub use entrances::Entrances;
pub(crate) use entrances::{PathHealth, PathSample};

const NAME: &str = "braidpath.mesh";
const MAX_NODES: usize = 32;
const MAX_BODY: usize = 32 * 1024;
const LIVE_FOR: Duration = Duration::from_secs(20);
const LEASE_FOR: Duration = Duration::from_secs(45);
const SYNC_EVERY: Duration = Duration::from_secs(5);
// Records nobody has reported running for this long are dropped. A returning
// server re-announces itself through its saved peers or `--join`.
const FORGET_AFTER: Duration = Duration::from_secs(10 * 60);
const RECONNECT_EVERY: Duration = Duration::from_secs(60);
const MAX_SOURCE_LEASES: usize = 16;
const MAX_RELEASED_REQUESTS: usize = MAX_NODES * MAX_SOURCE_LEASES;
// Control connections have their own budget, separate from data paths.
const CONTROL_CONNECTIONS: usize = 256;
pub(crate) const CONTROL_IDLE: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub address: SocketAddr,
    // Persisted locally and advanced only when the advertised address changes.
    // Zero is the legacy wire format; unchanged nodes can still be discovered
    // by older peers while a cluster is upgraded.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub incarnation: u64,
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}
impl Node {
    pub(super) fn supersedes(&self, previous: &Node) -> bool {
        self.id == previous.id
            && (self.incarnation > previous.incarnation
                || (self.incarnation == previous.incarnation
                    && (self.address == previous.address || self.incarnation == 0)))
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 64
                && self
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid node id"
        );
        ensure!(
            self.address.port() != 0
                && !self.address.ip().is_unspecified()
                && !self.address.ip().is_multicast(),
            "node requires a reachable unicast address"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClientKey {
    version: u8,
    certificate: String,
    token: String,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ServerKey {
    client: ClientKey,
    private_key: String,
    member_token: String,
}
fn valid_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    ensure!(
        fs::metadata(path)?.len() <= MAX_BODY as u64,
        "mesh file too large"
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn private_write(path: &Path, data: &[u8]) -> Result<()> {
    storage::atomic_write(path, data, false)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let data = serde_json::to_vec_pretty(value)?;
    ensure!(data.len() <= MAX_BODY, "mesh state exceeds size limit");
    private_write(path, &data)
}
fn install_client(dir: &Path, key: &ClientKey) -> Result<()> {
    ensure!(
        key.version == 1 && valid_token(&key.token),
        "invalid client key"
    );
    let certificates = rustls_pemfile::certs(&mut key.certificate.as_bytes())
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(!certificates.is_empty(), "empty cluster certificate");
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate)?;
    }
    // Validate before publishing either file: an invalid import must not leave
    // a half-installed client identity that prevents retry with the right key.
    for (name, bytes) in [
        ("cert.pem", key.certificate.as_bytes()),
        ("token", key.token.as_bytes()),
    ] {
        let path = dir.join(name);
        if path.exists() {
            ensure!(
                fs::read(&path)? == bytes,
                "state directory belongs to a different cluster"
            );
        } else {
            private_write(&path, bytes)?;
        }
    }
    transport::certificates(&dir.join("cert.pem"))?;
    Ok(())
}

#[derive(Clone)]
struct Peer {
    node: Node,
    // Only a direct authenticated exchange establishes local liveness.
    seen: Option<Instant>,
    // Any authenticated report that the node runs: its own exchange, or a
    // member listing it as live. Unheard records can be replaced or forgotten.
    heard: Instant,
}
enum Admission {
    Unchanged,
    Add { replaces: Vec<String> },
    Reject(&'static str),
}
struct Lease {
    source: IpAddr,
    exit: String,
    request: Option<String>,
    address: SocketAddr,
    touched: Instant,
    metrics: stats::Metrics,
    forwarded: u64,
    task: AbortTask,
}
#[derive(Default)]
struct ReleasedRequests(BTreeMap<(IpAddr, String), (String, Instant)>);
impl ReleasedRequests {
    fn prune(&mut self) {
        self.0.retain(|_, (_, at)| at.elapsed() < LEASE_FOR);
    }
    fn insert(&mut self, source: IpAddr, request: String, exit: String) {
        self.prune();
        self.0.insert((source, request), (exit, Instant::now()));
        if self.0.len() > MAX_RELEASED_REQUESTS {
            let oldest = self
                .0
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(key, _)| key.clone())
                .expect("nonempty cancellations");
            self.0.remove(&oldest);
        }
    }
}
impl Lease {
    fn forwarded(&self) -> u64 {
        let mut forwarded = 0;
        self.metrics
            .state(|s| forwarded = s.relay.get(stats::FORWARD).map_or(0, |d| d.forwarded));
        forwarded
    }
}
fn reap(leases: &mut BTreeMap<String, Lease>) {
    leases.retain(|_, lease| {
        // Admitted owner traffic proves the path is in use even while its
        // control renewals are delayed; idle orphaned allocations still expire.
        let forwarded = lease.forwarded();
        if forwarded != lease.forwarded {
            lease.forwarded = forwarded;
            lease.touched = Instant::now();
        }
        lease.touched.elapsed() < LEASE_FOR && !lease.task.0.is_finished()
    });
}
pub(crate) struct AbortTask(tokio::task::JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub struct State {
    proxy: Option<Arc<super::proxy::Server>>,
    own: Node,
    _directory_lock: Option<Arc<fs::File>>,
    bind: SocketAddr,
    relay_ports: Option<RelayPorts>,
    dir: PathBuf,
    client_auth: String,
    member_auth: String,
    peers: Arc<Mutex<BTreeMap<String, Peer>>>,
    // Forgotten membership is not a revocation of cluster trust. Keep a bounded
    // restart-safe set of addresses to heal partitions without manual joins.
    reconnect: Arc<Mutex<Vec<hints::Hint>>>,
    membership_write: Arc<tokio::sync::Mutex<()>>,
    persistence: Arc<status::Persistence>,
    leases: Mutex<BTreeMap<String, Lease>>,
    // Always locked after leases. Bounded cancellation history prevents a
    // delayed allocation from recreating a just-released path.
    released_requests: Mutex<ReleasedRequests>,
    control_connections: Arc<Semaphore>,
    rate: u64,
    relay_budget: Arc<relay::HostBudget>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    sender: Node,
    nodes: Vec<Node>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayRequest {
    exit: String,
    lease: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRequest {
    exit: String,
    lease: Option<String>,
    request: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseReply {
    released: bool,
}
fn valid_lease_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayReply {
    lease: String,
    address: SocketAddr,
}

impl State {
    pub(crate) fn node_id(&self) -> &str {
        &self.own.id
    }
    fn known(&self) -> Vec<Node> {
        let mut nodes = vec![self.own.clone()];
        nodes.extend(
            self.peers
                .lock()
                .expect("peers")
                .values()
                .map(|p| p.node.clone()),
        );
        nodes
    }
    fn active(&self) -> Vec<Node> {
        let mut nodes = vec![self.own.clone()];
        nodes.extend(
            self.peers
                .lock()
                .expect("peers")
                .values()
                .filter(|p| p.seen.is_some_and(|at| at.elapsed() < LIVE_FOR))
                .map(|p| p.node.clone()),
        );
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        nodes
    }
    fn exchange(&self) -> Exchange {
        // Only advertise members this server has seen live. Departed records
        // then age out everywhere instead of being revived by gossip.
        Exchange {
            sender: self.own.clone(),
            nodes: self.active(),
        }
    }
    fn admit(own: &Node, peers: &BTreeMap<String, Peer>, node: &Node) -> Admission {
        if node.validate().is_err() {
            return Admission::Reject("invalid node");
        }
        if node.id == own.id {
            return if node == own {
                Admission::Unchanged
            } else {
                Admission::Reject("record conflicts with the local node")
            };
        }
        if node.address == own.address {
            return Admission::Reject("record reuses the local address");
        }
        if peers.get(&node.id).is_some_and(|p| p.node == *node) {
            return Admission::Unchanged;
        }
        if peers
            .get(&node.id)
            .is_some_and(|p| !node.supersedes(&p.node))
        {
            return Admission::Reject("stale or inconsistent node incarnation");
        }
        let conflicts: Vec<_> = peers
            .values()
            .filter(|p| p.node.id == node.id || p.node.address == node.address)
            .collect();
        // A persisted address update supersedes the same node immediately.
        // Other IDs still cannot take an address a live member currently owns.
        if conflicts.iter().any(|p| {
            p.heard.elapsed() < LIVE_FOR
                && !(p.node.id == node.id && node.incarnation > p.node.incarnation)
        }) {
            return Admission::Reject("conflicts with a current member");
        }
        Admission::Add {
            replaces: conflicts.into_iter().map(|p| p.node.id.clone()).collect(),
        }
    }
    // Serialize mutations independently of the read locks. The blocking task
    // owns the sequence guard and completes both disk and memory publication
    // even if its request is cancelled; a later write cannot overtake it.
    async fn update_members(
        &self,
        update: impl FnOnce(&Node, &mut BTreeMap<String, Peer>, &mut Vec<hints::Hint>) -> Result<()>
        + Send
        + 'static,
    ) -> Result<()> {
        let write = self.membership_write.clone().lock_owned().await;
        let own = self.own.clone();
        let dir = self.dir.clone();
        let peers = self.peers.clone();
        let reconnect = self.reconnect.clone();
        let directory_lock = self._directory_lock.clone();
        let persistence = self.persistence.clone();
        tokio::task::spawn_blocking(move || {
            let _write = write;
            // A cancelled server may drop State while this write finishes.
            // Keep the directory exclusively owned until publication ends.
            let _directory_lock = directory_lock;
            let previous = peers.lock().expect("peers").clone();
            let previous_hints = reconnect.lock().expect("reconnect hints").clone();
            let mut next = previous.clone();
            let mut next_hints = previous_hints.clone();
            update(&own, &mut next, &mut next_hints)?;
            // Publish hints before removing membership: interruption must not
            // erase the only saved route back across a long partition.
            if next_hints != previous_hints {
                persistence.record(hints::save(&dir, &next_hints))?;
                *reconnect.lock().expect("reconnect hints") = next_hints.clone();
            }
            if !previous
                .values()
                .map(|p| &p.node)
                .eq(next.values().map(|p| &p.node))
            {
                let nodes: Vec<_> = next.values().map(|p| &p.node).collect();
                persistence.record(storage::atomic_write(
                    &dir.join("peers.json"),
                    &serde_json::to_vec(&nodes)?,
                    true,
                ))?;
            }
            let nodes: Vec<_> = next.values().map(|p| &p.node).collect();
            let useful = hints::useful(&next_hints, &own, &nodes, hints::now_unix());
            *peers.lock().expect("peers") = next;
            // Removing a returning node's hint is safe only after its member
            // record is durable. Failed cleanup leaves harmless extra hints
            // and is retried on the next membership operation.
            if useful != next_hints {
                match persistence.record(hints::save(&dir, &useful)) {
                    Ok(()) => *reconnect.lock().expect("reconnect hints") = useful,
                    Err(error) => {
                        tracing::warn!(%error, "could not prune persisted reconnect hints")
                    }
                }
            }
            Ok(())
        })
        .await
        .map_err(|error| {
            self.persistence
                .record::<()>(Err(error.into()))
                .unwrap_err()
        })
        .context("membership persistence worker failed")?
    }
    async fn merge(&self, exchange: Exchange, direct: bool) -> Result<()> {
        ensure!(exchange.nodes.len() <= MAX_NODES, "too many members");
        let now = Instant::now();
        let now_unix = hints::now_unix();
        self.update_members(move |own, next, reconnect| {
            let records = std::iter::once(&exchange.sender).chain(&exchange.nodes);
            for (index, node) in records.enumerate() {
                let sender = index == 0;
                if reconnect
                    .iter()
                    .any(|hint| {
                        now_unix.saturating_sub(hint.forgotten_unix)
                            < hints::HINT_TTL.as_secs()
                            && hint.node.id == node.id
                            && !node.supersedes(&hint.node)
                    })
                {
                    ensure!(!sender, "stale or inconsistent forgotten node incarnation");
                    tracing::debug!(node=%node.id, "stale membership hint ignored");
                    continue;
                }
                match Self::admit(own, next, node) {
                    Admission::Unchanged => {}
                    Admission::Add { mut replaces } => {
                        if next.len() + 1 - replaces.len() >= MAX_NODES {
                            // A valid new sender can heal a full isolated table.
                            // Hints alone may not evict members, and recently
                            // heard records are never displaced for capacity.
                            let stale = sender.then(|| {
                                next.values()
                                    .filter(|p| p.heard.elapsed() >= FORGET_AFTER)
                                    .min_by_key(|p| p.heard)
                                    .map(|p| p.node.clone())
                            }).flatten();
                            if let Some(stale) = stale {
                                *reconnect = hints::add(reconnect, std::slice::from_ref(&stale), hints::now_unix());
                                replaces.push(stale.id);
                            } else {
                                ensure!(!sender, "cluster member limit reached");
                                tracing::debug!(node=%node.id, "membership hint ignored: member limit");
                                continue;
                            }
                        }
                        for id in replaces {
                            next.remove(&id);
                            tracing::debug!(node=%id, "replaced stale member record");
                        }
                        next.insert(node.id.clone(), Peer { node: node.clone(), seen: None, heard: now });
                    }
                    Admission::Reject(reason) => {
                        ensure!(!sender, "{reason}");
                        tracing::debug!(node=%node.id, reason, "membership hint ignored");
                        continue;
                    }
                }
                if let Some(peer) = next.get_mut(&node.id) {
                    peer.heard = now;
                    if sender && direct {
                        peer.seen = Some(now);
                    }
                }
            }
            Ok(())
        }).await
    }
    async fn forget_departed(&self) -> Result<()> {
        self.update_members(|_, peers, reconnect| {
            // Isolation alone must not erase the directory. An authenticated
            // new sender can still reclaim an old slot through merge().
            if !peers
                .values()
                .any(|p| p.seen.is_some_and(|at| at.elapsed() < LIVE_FOR))
            {
                return Ok(());
            }
            let departed: Vec<_> = peers
                .values()
                .filter(|p| p.heard.elapsed() >= FORGET_AFTER)
                .map(|p| p.node.clone())
                .collect();
            if !departed.is_empty() {
                *reconnect = hints::add(reconnect, &departed, hints::now_unix());
                for node in departed {
                    peers.remove(&node.id);
                }
            }
            Ok(())
        })
        .await
    }
    /// Drop hints for members that returned or expired, then pick the next
    /// rotating batch to probe. A failed save is retried on the next round.
    async fn reconnect_candidates(&self, cursor: &mut usize) -> Vec<Node> {
        if let Err(error) = self.update_members(|_, _, _| Ok(())).await {
            tracing::warn!(%error, "could not persist reconnect hints");
        }
        let useful = {
            let peers = self.peers.lock().expect("peers");
            let hints = self.reconnect.lock().expect("reconnect hints");
            let members: Vec<_> = peers.values().map(|p| &p.node).collect();
            hints::useful(&hints, &self.own, &members, hints::now_unix())
        };
        if useful.is_empty() {
            return vec![];
        }
        let batch = hints::RECONNECT_BATCH.min(useful.len());
        let start = *cursor % useful.len();
        *cursor = start + batch;
        (0..batch)
            .map(|i| useful[(start + i) % useful.len()].node.clone())
            .collect()
    }
    async fn sync_peer(&self, control: &Control, peer: Node, body: Vec<u8>) {
        let result: Result<Exchange> = control
            .request(peer.address, &self.member_auth, "/mesh/sync", Some(body))
            .await;
        match result {
            Ok(reply) if reply.sender == peer => {
                if let Err(error) = self.merge(reply, true).await {
                    tracing::warn!(%error, "membership rejected");
                }
            }
            _ => tracing::debug!(node=%peer.id, "peer sync unavailable"),
        }
    }
    pub(crate) fn control_permit(&self) -> Option<OwnedSemaphorePermit> {
        self.control_connections.clone().try_acquire_owned().ok()
    }
    async fn relay(&self, source: IpAddr, request: RelayRequest) -> Result<RelayReply> {
        ensure!(
            request.request.as_deref().is_none_or(valid_lease_id)
                && !(request.lease.is_some() && request.request.is_some()),
            "invalid allocation request"
        );
        let mut leases = self.leases.lock().expect("leases");
        reap(&mut leases);
        if let Some(key) = &request.request {
            let mut released = self.released_requests.lock().expect("released requests");
            released.prune();
            ensure!(
                !released.0.contains_key(&(source, key.clone())),
                Failure::RequestReleased
            );
        }
        if let Some(id) = request.lease {
            let lease = leases.get_mut(&id).context(Failure::LeaseExpired)?;
            ensure!(
                lease.source == source && lease.exit == request.exit,
                Failure::OwnerMismatch
            );
            lease.touched = Instant::now();
            return Ok(RelayReply {
                lease: id,
                address: lease.address,
            });
        }
        // A reply can be lost after the socket was allocated. Replaying that
        // allocation returns the same owned path, even at the resource cap or
        // during a membership outage. The key lives only as long as its lease.
        if let Some(key) = &request.request
            && let Some((id, lease)) = leases
                .iter_mut()
                .find(|(_, lease)| lease.source == source && lease.request.as_ref() == Some(key))
        {
            ensure!(lease.exit == request.exit, Failure::OwnerMismatch);
            lease.touched = Instant::now();
            return Ok(RelayReply {
                lease: id.clone(),
                address: lease.address,
            });
        }
        // The immutable target was authenticated when the lease was allocated.
        // A missed membership heartbeat must not expire a working UDP path.
        // Only new allocations require current control-plane liveness.
        let target = self
            .active()
            .into_iter()
            .find(|n| n.id == request.exit)
            .context(Failure::ExitUnavailable)?;
        ensure!(leases.len() < 64, Failure::LeaseLimit);
        ensure!(
            leases.values().filter(|l| l.source == source).count() < MAX_SOURCE_LEASES,
            Failure::SourceLimit
        );
        // Bind synchronously so allocation is atomic with respect to the lease
        // limit without holding a lock across an await.
        let socket = match self.relay_ports {
            Some(ports) => ports.bind(self.bind.ip())?,
            None => std::net::UdpSocket::bind(SocketAddr::new(self.bind.ip(), 0))?,
        };
        socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        let address = SocketAddr::new(self.own.address.ip(), socket.local_addr()?.port());
        let id = transport::hex(&rand::random::<[u8; 16]>());
        let metrics = stats::Metrics::new("mesh-relay");
        let options = relay::Options {
            listen: socket.local_addr()?,
            target: target.address,
            allow: vec![source],
            rate: self.rate,
            drop_every: 0,
            stats: metrics.clone(),
        };
        let host = self.relay_budget.clone();
        let task = AbortTask(tokio::spawn(async move {
            if let Err(error) = relay::run_on_socket_with_budget(options, socket, false, host).await
            {
                tracing::warn!(%error, "mesh relay ended");
            }
        }));
        leases.insert(
            id.clone(),
            Lease {
                source,
                exit: request.exit,
                request: request.request,
                address,
                touched: Instant::now(),
                metrics,
                forwarded: 0,
                task,
            },
        );
        Ok(RelayReply { lease: id, address })
    }
    async fn release(&self, source: IpAddr, request: ReleaseRequest) -> Result<ReleaseReply> {
        ensure!(
            request.lease.is_some() != request.request.is_some(),
            "release requires exactly one lease or allocation request"
        );
        ensure!(
            request
                .lease
                .as_deref()
                .or(request.request.as_deref())
                .is_some_and(valid_lease_id),
            "invalid release selector"
        );
        let removed = {
            let mut leases = self.leases.lock().expect("leases");
            if let Some(key) = &request.request {
                let mut released = self.released_requests.lock().expect("released requests");
                released.prune();
                if let Some((exit, _)) = released.0.get(&(source, key.clone())) {
                    ensure!(*exit == request.exit, Failure::OwnerMismatch);
                }
            }
            let id = request.lease.clone().or_else(|| {
                leases
                    .iter()
                    .find(|(_, lease)| lease.source == source && lease.request == request.request)
                    .map(|(id, _)| id.clone())
            });
            let removed = if let Some(id) = id {
                if let Some(lease) = leases.get(&id) {
                    ensure!(
                        lease.source == source && lease.exit == request.exit,
                        Failure::OwnerMismatch
                    );
                }
                leases.remove(&id)
            } else {
                None
            };
            let key = request
                .request
                .or_else(|| removed.as_ref().and_then(|lease| lease.request.clone()));
            if let Some(key) = key {
                self.released_requests
                    .lock()
                    .expect("released requests")
                    .insert(source, key, request.exit);
            }
            removed
        };
        if let Some(mut lease) = removed {
            // Wait outside the map lock: success means the relay task and its
            // UDP socket have actually gone away, not merely left the table.
            lease.task.0.abort();
            let _ = (&mut lease.task.0).await;
            Ok(ReleaseReply { released: true })
        } else {
            Ok(ReleaseReply { released: false })
        }
    }
    pub(crate) fn authorized(&self, request: &Request<()>) -> bool {
        let expected = if request.uri().path() == "/mesh/sync" {
            &self.member_auth
        } else {
            &self.client_auth
        };
        let auth = request
            .headers()
            .get("authorization")
            .map(|h| h.as_bytes())
            .unwrap_or_default();
        bool::from(auth.ct_eq(expected.as_bytes()))
    }
    pub(crate) async fn handle(
        &self,
        request: &Request<()>,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        source: IpAddr,
    ) -> Result<bool> {
        let path = request.uri().path();
        if !self.authorized(request) {
            stream
                .send_response(Response::builder().status(404).body(())?)
                .await?;
            stream.finish().await?;
            return Ok(false);
        }
        let result: Result<Vec<u8>> = async {
            match (request.method(), path) {
                (&Method::GET, "/mesh/info") => Ok(serde_json::to_vec(&self.capabilities())?),
                (&Method::GET, "/mesh/status") => Ok(serde_json::to_vec(&self.status())?),
                (&Method::GET, "/mesh/nodes") => Ok(serde_json::to_vec(&self.active())?),
                (&Method::POST, "/mesh/sync") => {
                    let exchange: Exchange = serde_json::from_slice(&read_body(stream).await?)?;
                    // Incoming announcements are hints, never proof that the
                    // advertised service is reachable. Our next probe checks it.
                    self.merge(exchange, false).await?;
                    Ok(serde_json::to_vec(&self.exchange())?)
                }
                (&Method::POST, "/mesh/relay") => {
                    let request = serde_json::from_slice(&read_body(stream).await?)?;
                    Ok(serde_json::to_vec(&self.relay(source, request).await?)?)
                }
                (&Method::POST, "/mesh/release") => {
                    let request = serde_json::from_slice(&read_body(stream).await?)?;
                    Ok(serde_json::to_vec(&self.release(source, request).await?)?)
                }
                _ => bail!(Failure::UnsupportedOperation),
            }
        }
        .await;
        let (status, body) = match result {
            Ok(body) => (200, body),
            Err(error) => {
                tracing::debug!(%error, "mesh request rejected");
                (
                    400,
                    serde_json::to_vec(&status::ErrorReply {
                        code: error
                            .downcast_ref::<Failure>()
                            .copied()
                            .unwrap_or(Failure::InvalidRequest),
                    })?,
                )
            }
        };
        stream
            .send_response(
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(())?,
            )
            .await?;
        stream.send_data(Bytes::from(body)).await?;
        stream.finish().await?;
        Ok(true)
    }
}
async fn read_body(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    while let Some(mut part) = stream.recv_data().await? {
        ensure!(
            result.len() + part.remaining() <= MAX_BODY,
            "mesh request too large"
        );
        result.extend(part.copy_to_bytes(part.remaining()));
    }
    Ok(result)
}

pub struct ServerOptions {
    pub dir: PathBuf,
    pub id: String,
    pub listen: SocketAddr,
    pub advertise: SocketAddr,
    pub relay_ports: Option<RelayPorts>,
    pub join: Option<SocketAddr>,
    pub join_key: Option<PathBuf>,
    pub target: Option<SocketAddr>,
    pub proxy: Option<super::proxy::ServerConfig>,
    pub rate: u64,
    pub stats: stats::Metrics,
}
pub async fn serve(options: ServerOptions) -> Result<()> {
    ensure!(
        options.target.is_some() || options.proxy.is_some(),
        "enable a UDP tunnel target or proxy service"
    );
    ensure!(
        (64_000..=super::MAX_RATE_BPS).contains(&options.rate),
        "invalid server rate"
    );
    let own = Node {
        id: options.id,
        address: options.advertise,
        incarnation: 0,
    };
    own.validate()?;
    ensure!(
        options.listen.is_ipv4() == options.advertise.is_ipv4(),
        "listen and advertise address families differ"
    );
    let (key, own, directory_lock) = storage::open_server(
        &options.dir,
        &own,
        options.join_key.as_deref(),
        options.join.is_some(),
    )?;
    let proxy = options
        .proxy
        .map(|config| {
            super::proxy::Server::new(
                config,
                key.client.token.clone(),
                own.id.clone(),
                options.rate,
            )
        })
        .transpose()?;
    let state = Arc::new(State {
        proxy: proxy.clone(),
        own,
        _directory_lock: Some(Arc::new(directory_lock)),
        bind: options.listen,
        relay_ports: options.relay_ports,
        dir: options.dir.clone(),
        rate: options.rate,
        client_auth: format!("Bearer {}", key.client.token),
        member_auth: format!("Bearer {}", key.member_token),
        peers: Arc::new(Mutex::new(BTreeMap::new())),
        reconnect: Arc::new(Mutex::new(hints::load(&options.dir))),
        membership_write: Arc::new(tokio::sync::Mutex::new(())),
        persistence: Arc::default(),
        relay_budget: Arc::new(relay::HostBudget::new(options.rate)),
        leases: Mutex::new(BTreeMap::new()),
        released_requests: Mutex::new(ReleasedRequests::default()),
        control_connections: Arc::new(Semaphore::new(CONTROL_CONNECTIONS)),
    });
    if options.dir.join("peers.json").exists() {
        let nodes = read_json(&options.dir.join("peers.json"))?;
        state
            .merge(
                Exchange {
                    sender: state.own.clone(),
                    nodes,
                },
                false,
            )
            .await?;
    }
    let control = Arc::new(Control::server(
        &options.dir.join("cert.pem"),
        options.listen.is_ipv6()
            || options.join.is_some_and(|a| a.is_ipv6())
            || state.known().iter().any(|n| n.address.is_ipv6()),
    )?);
    if let Some(seed) = options.join {
        let joined = async {
            let exchange: Exchange = control
                .request(
                    seed,
                    &state.member_auth,
                    "/mesh/sync",
                    Some(serde_json::to_vec(&state.exchange())?),
                )
                .await?;
            ensure!(
                exchange.sender.address == seed,
                "join endpoint differs from advertised address"
            );
            state.merge(exchange, true).await
        }
        .await;
        if let Err(error) = joined {
            if state.known().len() == 1 {
                return Err(error).context("join cluster");
            }
            tracing::warn!(%error, "join entry unavailable; restarting through persisted peers");
        }
    }

    let background = state.clone();
    let _maintenance = AbortTask(tokio::spawn(async move {
        let mut tick = tokio::time::interval(SYNC_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut next_reconnect = Instant::now();
        let mut reconnect_cursor = 0;
        loop {
            tick.tick().await;
            reap(&mut background.leases.lock().expect("leases"));
            if let Err(error) = background.forget_departed().await {
                tracing::warn!(%error, "could not persist departed members");
            }
            // Release connections to forgotten or replaced addresses.
            control.prune(LIVE_FOR);
            let mut peers: Vec<_> = background
                .known()
                .into_iter()
                .filter(|n| n.id != background.own.id)
                .collect();
            if Instant::now() >= next_reconnect {
                peers.extend(background.reconnect_candidates(&mut reconnect_cursor).await);
                next_reconnect = Instant::now() + RECONNECT_EVERY;
            }
            let body = serde_json::to_vec(&background.exchange()).expect("exchange serialization");
            let mut pending = JoinSet::new();
            for peer in peers {
                let control = control.clone();
                let state = background.clone();
                let body = body.clone();
                pending.spawn(async move {
                    state.sync_peer(&control, peer, body).await;
                });
            }
            while pending.join_next().await.is_some() {}
        }
    }));
    tracing::info!(node=%state.own.id, "leaderless mesh enabled; client-key.json and server-key.json are in the state directory");
    tunnel::serve_with_mesh(
        tunnel::ServerOptions {
            bind: options.listen,
            cert: options.dir.join("cert.pem"),
            key: options.dir.join("key.pem"),
            token: options.dir.join("token"),
            target: options.target,
            proxy,
            max_rate: options.rate,
            congestion: transport::Congestion::default(),
            datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            adaptive_fec_retention: false,
            stats: options.stats,
        },
        transport::AckRequest::Unchanged,
        Some(state),
    )
    .await
}

#[derive(Clone)]
pub struct ClientIdentity {
    pub dir: PathBuf,
    auth: String,
    cache: discovery::Cache,
}
impl ClientIdentity {
    pub fn open(dir: PathBuf, key_path: &Path) -> Result<Self> {
        let key: ClientKey = read_json(key_path)?;
        private_dir(&dir)?;
        install_client(&dir, &key)?;
        Ok(Self {
            cache: discovery::Cache::open(dir.clone()),
            dir,
            auth: format!("Bearer {}", key.token),
        })
    }
    pub fn name(&self) -> String {
        NAME.into()
    }
    /// Keep the guard alive while using its entrance updates. Discovery and
    /// lease recovery run outside the packet path and keep the selected exit.
    pub async fn entrances(
        &self,
        nodes: Vec<Node>,
        exit: &str,
        limit: usize,
    ) -> Result<(Vec<SocketAddr>, Entrances)> {
        Entrances::start(self, nodes, exit, limit, Duration::from_secs(15)).await
    }
}

#[cfg(test)]
mod lease_tests;
#[cfg(test)]
mod migration_tests;
#[cfg(test)]
pub(crate) mod tests;
