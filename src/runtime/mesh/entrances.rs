use super::*;
use tokio::sync::watch;

// Renew several times per lease lifetime, independently of discovery.
const RENEW_EVERY: Duration = Duration::from_secs(LEASE_FOR.as_secs() / 4);

/// Periodic data-plane evidence; an abandoned reporter expires with the lease.
#[derive(Clone)]
pub(crate) struct PathHealth {
    pub checked: Instant,
    pub addresses: Vec<SocketAddr>,
    pub samples: Vec<PathSample>,
}
impl Default for PathHealth {
    fn default() -> Self {
        Self {
            checked: Instant::now(),
            addresses: Vec::new(),
            samples: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct PathSample {
    pub address: SocketAddr,
    pub group: u8,
    pub delivered: bool,
    pub failed: bool,
    pub rtt_ms: f64,
    pub loss: f64,
}
impl PathSample {
    pub(super) fn score(&self) -> Option<f64> {
        (!self.failed && self.delivered && self.rtt_ms.is_finite() && self.loss.is_finite())
            .then_some(self.rtt_ms.max(1.0) * (1.0 + 4.0 * self.loss.clamp(0.0, 1.0)))
    }
}

/// Owns maintenance and its bounded, best-effort remote lease cleanup.
pub struct Entrances {
    limit: watch::Sender<usize>,
    health: watch::Sender<PathHealth>,
    updates: watch::Receiver<Vec<SocketAddr>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    maintenance: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Entrances {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
impl Entrances {
    pub(super) fn resize(&self, limit: usize) {
        self.limit.send_if_modified(|old| {
            if *old == limit {
                false
            } else {
                *old = limit;
                true
            }
        });
    }
    pub(crate) fn health(&self) -> watch::Sender<PathHealth> {
        self.health.clone()
    }

    pub fn updates(&self) -> watch::Receiver<Vec<SocketAddr>> {
        self.updates.clone()
    }

    /// Normal CLI exit waits for remote cleanup; dropping the guard requests
    /// the same cleanup without blocking its caller. An unreachable server or
    /// a request completed after cancellation still has its idle lease TTL.
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(maintenance) = self.maintenance.take() {
            let _ = maintenance.await;
        }
    }

    pub(super) async fn start(
        identity: &ClientIdentity,
        nodes: Vec<Node>,
        exit: &str,
        limit: usize,
        interval: Duration,
    ) -> Result<(Vec<SocketAddr>, Self)> {
        Self::start_bound(identity, nodes, exit, limit, interval, &Uplink::default()).await
    }

    pub(super) async fn start_bound(
        identity: &ClientIdentity,
        nodes: Vec<Node>,
        exit: &str,
        limit: usize,
        interval: Duration,
        uplink: &Uplink,
    ) -> Result<(Vec<SocketAddr>, Self)> {
        ensure!((1..=MAX_PATHS).contains(&limit), "invalid entrance limit");
        validate_nodes(&nodes)?;
        let known = identity.cache.remember(&nodes)?;
        let nodes = discovery::current_nodes(&known, &nodes)?;
        let selected = nodes
            .iter()
            .find(|n| n.id == exit)
            .context("selected exit not found")?
            .clone();
        let (health, observed) = watch::channel(PathHealth::default());
        let directory = Directory {
            health: observed,
            control: Arc::new(Control::bound(
                &identity.dir.join("cert.pem"),
                nodes.iter().any(|n| n.address.is_ipv6()),
                uplink,
            )?),
            auth: identity.auth.clone(),
            selected,
            cache: identity.cache.clone(),
            known,
            nodes,
            leases: BTreeMap::new(),
            requests: BTreeMap::new(),
            limit,
            discovery_cursor: 0,
            allocation_cursor: 0,
            explorer: selection::Explorer::default(),
        };
        let initial = directory.addresses();
        let (tx, updates) = watch::channel(initial.clone());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (limit_tx, limit_rx) = watch::channel(limit);
        let maintenance = tokio::spawn(directory.run(tx, interval, Some(limit_rx), async {
            let _ = stopped.await;
        }));
        Ok((
            initial,
            Self {
                limit: limit_tx,
                health,
                updates,
                stop: Some(stop),
                maintenance: Some(maintenance),
            },
        ))
    }
}

pub(super) struct ClientLease {
    pub(super) node: Node,
    pub(super) reply: RelayReply,
    pub(super) renewed: Instant,
}
#[derive(Clone)]
struct Allocation {
    node: Node,
    exit: Node,
    request: String,
}
struct Renewal {
    allocation: Allocation,
    previous: RelayReply,
    result: Result<Option<RelayReply>>,
}
struct Directory {
    health: watch::Receiver<PathHealth>,
    control: Arc<Control>,
    auth: String,
    selected: Node,
    cache: discovery::Cache,
    nodes: Vec<Node>,
    known: Vec<Node>,
    leases: BTreeMap<String, ClientLease>,
    requests: BTreeMap<String, Allocation>,
    limit: usize,
    discovery_cursor: usize,
    allocation_cursor: usize,
    explorer: selection::Explorer,
}

pub(super) fn validate_nodes(nodes: &[Node]) -> Result<()> {
    ensure!(
        !nodes.is_empty() && nodes.len() <= MAX_NODES,
        "invalid node count"
    );
    let mut ids = std::collections::HashSet::new();
    let mut addresses = std::collections::HashSet::new();
    for node in nodes {
        node.validate()?;
        ensure!(
            ids.insert(&node.id) && addresses.insert(node.address),
            "duplicate member"
        );
    }
    Ok(())
}

impl Directory {
    fn addresses(&self) -> Vec<SocketAddr> {
        std::iter::once(self.selected.address)
            .chain(self.leases.values().map(|lease| lease.reply.address))
            .collect()
    }

    fn publish(&self, tx: &watch::Sender<Vec<SocketAddr>>) {
        let addresses = self.addresses();
        // Unchanged leases must not wake the tunnel or disturb connections.
        tx.send_if_modified(|current| {
            if *current == addresses {
                false
            } else {
                *current = addresses;
                true
            }
        });
    }

    #[cfg(test)]
    async fn maintain(self, tx: watch::Sender<Vec<SocketAddr>>, interval: Duration) {
        self.run(tx, interval, None, std::future::pending()).await;
    }

    async fn run(
        mut self,
        tx: watch::Sender<Vec<SocketAddr>>,
        interval: Duration,
        mut limits: Option<watch::Receiver<usize>>,
        stop: impl Future<Output = ()>,
    ) {
        let renew_every = interval.min(RENEW_EVERY);
        let mut renew = tokio::time::interval(renew_every);
        let mut discover = tokio::time::interval(interval);
        for tick in [&mut renew, &mut discover] {
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.reset();
        }
        // Adopt already-held leases too (used by restored/test directories).
        for node in self
            .leases
            .values()
            .map(|lease| lease.node.clone())
            .collect::<Vec<_>>()
        {
            self.request_for(&node);
        }
        let mut discovery = JoinSet::new();
        let mut recovery_after = Instant::now();
        let mut health_open = true;
        let mut allocations = self.allocations();
        let mut renewals = JoinSet::new();
        let mut renewing = std::collections::BTreeSet::new();
        let mut releases = JoinSet::new();
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = &mut stop => break,
                result = async { limits.as_mut().expect("enabled limits").changed().await }, if limits.is_some() => {
                    if result.is_err() { limits = None; continue; }
                    self.limit = (*limits.as_mut().expect("limits").borrow_and_update()).clamp(1, MAX_PATHS);
                    self.explorer.reset();
                    allocations.abort_all();
                    for allocation in self.resize() {
                        self.start_release(&mut releases, allocation);
                    }
                    allocations = self.allocations();
                    self.publish(&tx);
                }
                result = self.health.changed(), if health_open => {
                    if result.is_err() { health_open = false; continue; }
                    let health = self.health.borrow_and_update().clone();
                    let now = Instant::now();
                    if health.addresses.is_empty() && now >= recovery_after && discovery.is_empty() {
                        recovery_after = now + Duration::from_secs(2);
                        tracing::debug!(stage="discovery", "mesh has no usable paths; refreshing directory");
                        discovery.spawn(self.discovery());
                    }
                    if allocations.is_empty()
                        && let Some(retired) = self.explorer.advance(&self.nodes, &self.selected, &self.leases, &health, self.limit, now) {
                        self.leases.remove(&retired);
                        if let Some(allocation) = self.requests.remove(&retired) { self.start_release(&mut releases, allocation); }
                        self.publish(&tx);
                        allocations = self.allocations();
                    }
                }
                _ = renew.tick() => {
                    self.expire_leases();
                    self.start_renewals(&mut renewals, &mut renewing);
                    self.publish(&tx);
                }
                _ = discover.tick(), if discovery.is_empty() => {
                    discovery.spawn(self.discovery());
                }
                Some(result) = discovery.join_next() => {
                    match result {
                        Ok(Some(nodes)) => {
                            let previous_exit = self.selected.clone();
                            for allocation in self.apply_nodes(nodes) {
                                self.start_release(&mut releases, allocation);
                            }
                            if self.selected != previous_exit {
                                self.explorer.reset();
                                allocations.abort_all();
                                allocations = JoinSet::new();
                                renewals.abort_all();
                                renewals = JoinSet::new();
                                renewing.clear();
                            }
                        }
                        _ => tracing::debug!("mesh directory refresh unavailable; retaining known peers"),
                    }
                    // In-flight requests keep their captured node and exit.
                    // Their completions are checked before publishing, so a
                    // changed directory never reintroduces a stale route.
                    self.control.prune(renew_every * 3);
                    if allocations.is_empty() {
                        allocations = self.allocations();
                    }
                    self.publish(&tx);
                }
                Some(result) = allocations.join_next() => {
                    match result {
                        Ok((allocation, Ok(reply))) => {
                            if self.current(&allocation) && self.leases.len() < self.limit - 1 {
                                let node = allocation.node;
                                self.leases.insert(node.id.clone(), ClientLease {
                                    node, reply, renewed: Instant::now(),
                                });
                                self.publish(&tx);
                            } else {
                                // This also handles a response that completed
                                // after a migration's earlier release attempt.
                                self.start_release(&mut releases, allocation);
                            }
                        }
                        Ok((allocation, Err(error))) => tracing::debug!(node=%allocation.node.id, %error, "optional entrance unavailable"),
                        Err(error) => tracing::warn!(%error, "entrance allocation task failed"),
                    }
                }
                Some(result) = renewals.join_next() => {
                    match result {
                        Ok(renewal) => {
                            renewing.remove(&renewal.allocation.node.id);
                            if self.current(&renewal.allocation) {
                                self.apply_renewal(renewal, &tx);
                            } else {
                                self.start_release(&mut releases, renewal.allocation);
                            }
                        }
                        Err(error) => tracing::warn!(%error, "entrance renewal task failed"),
                    }
                }
                Some(_) = releases.join_next() => {}
            }
        }
        discovery.abort_all();
        // Give already-sent requests one second to settle before releasing by
        // request identity. Cancelled/late server work still has its idle TTL.
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            while allocations.join_next().await.is_some() {}
            while renewals.join_next().await.is_some() {}
        })
        .await;
        allocations.abort_all();
        renewals.abort_all();
        while allocations.join_next().await.is_some() {}
        while renewals.join_next().await.is_some() {}
        let _ = tokio::time::timeout(Duration::from_secs(4), async {
            // Queue current allocations alongside retired ones: an unreachable
            // old member must not delay release at a healthy current member.
            for (_, allocation) in std::mem::take(&mut self.requests) {
                self.start_release(&mut releases, allocation);
            }
            while releases.join_next().await.is_some() {}
        })
        .await;
    }

    fn current(&self, allocation: &Allocation) -> bool {
        self.selected == allocation.exit
            && self
                .requests
                .get(&allocation.node.id)
                .is_some_and(|current| {
                    current.node == allocation.node && current.request == allocation.request
                })
    }

    fn resize(&mut self) -> Vec<Allocation> {
        let health = self.health.borrow();
        let mut retained: Vec<_> = self.leases.keys().cloned().collect();
        retained.sort_by(|a, b| {
            let score = |id: &String| {
                let address = self.leases[id].reply.address;
                health
                    .samples
                    .iter()
                    .find(|s| s.address == address)
                    .and_then(PathSample::score)
                    .unwrap_or(f64::INFINITY)
            };
            score(a).total_cmp(&score(b)).then_with(|| a.cmp(b))
        });
        retained.truncate(self.limit - 1);
        self.leases.retain(|id, _| retained.contains(id));
        let mut retired = Vec::new();
        self.requests.retain(|id, allocation| {
            if retained.contains(id) {
                true
            } else {
                retired.push(allocation.clone());
                false
            }
        });
        retired
    }

    fn start_release(&self, pending: &mut JoinSet<()>, allocation: Allocation) {
        // Changing membership cannot accumulate unbounded cleanup tasks. TTL
        // remains the fallback when previous releases fill this bounded set.
        if pending.len() >= MAX_NODES + MAX_PATHS {
            return;
        }
        let control = self.control.clone();
        let auth = self.auth.clone();
        pending.spawn(async move {
            let body = serde_json::to_vec(&ReleaseRequest {
                exit: allocation.exit.id,
                lease: None,
                request: Some(allocation.request),
            }).expect("release request");
            if let Err(error) = control.request::<ReleaseReply>(
                allocation.node.address, &auth, "/mesh/release", Some(body),
            ).await {
                tracing::debug!(node=%allocation.node.id, %error, "lease release unavailable; retaining idle expiry");
            }
        });
    }

    fn apply_nodes(&mut self, incoming: Vec<Node>) -> Vec<Allocation> {
        let Ok(known) = self.cache.remember(&incoming) else {
            return vec![];
        };
        // A slower authenticated response must not roll back an already-known
        // address incarnation, either in the cache or in the active directory.
        let Ok(nodes) = discovery::current_nodes(&known, &incoming) else {
            return vec![];
        };
        self.known = known;
        if let Some(selected) = nodes.iter().find(|node| node.id == self.selected.id) {
            self.selected = selected.clone();
        }
        let mut retired = Vec::new();
        self.requests.retain(|id, allocation| {
            let current = allocation.exit == self.selected
                && nodes.iter().find(|node| node.id == *id).map_or_else(
                    || self.leases.contains_key(id),
                    |node| *node == allocation.node,
                );
            if !current {
                retired.push(allocation.clone());
            }
            current
        });
        self.leases.retain(|id, lease| {
            self.requests
                .get(id)
                .is_some_and(|request| request.node == lease.node)
        });
        self.nodes = nodes;
        retired
    }

    fn discovery(&mut self) -> impl Future<Output = Option<Vec<Node>>> + Send + 'static {
        // Rotate the discovery entry so the original bootstrap is never a
        // dependency. Only a failed request triggers bounded parallel fallback.
        let mut candidates = self.known.clone();
        self.discovery_cursor %= candidates.len();
        let preferred = candidates.remove(self.discovery_cursor);
        self.discovery_cursor += 1;
        let control = self.control.clone();
        let auth = self.auth.clone();
        let exit = self.selected.id.clone();
        async move {
            let query = |address: SocketAddr| {
                let control = control.clone();
                let auth = auth.clone();
                let exit = exit.clone();
                async move {
                    let nodes: Vec<Node> =
                        control.request(address, &auth, "/mesh/nodes", None).await?;
                    validate_nodes(&nodes)?;
                    ensure!(
                        nodes.iter().any(|node| node.id == exit),
                        "selected exit absent from directory"
                    );
                    Ok::<_, anyhow::Error>(nodes)
                }
            };
            if let Ok(nodes) = query(preferred.address).await {
                return Some(nodes);
            }
            let mut pending = JoinSet::new();
            for node in candidates {
                pending.spawn(query(node.address));
            }
            while let Some(result) = pending.join_next().await {
                if let Ok(Ok(nodes)) = result {
                    return Some(nodes);
                }
            }
            None
        }
    }

    fn request_for(&mut self, node: &Node) -> Allocation {
        self.requests
            .entry(node.id.clone())
            .or_insert_with(|| Allocation {
                node: node.clone(),
                exit: self.selected.clone(),
                request: format!("{:032x}", rand::random::<u128>()),
            })
            .clone()
    }

    fn start_renewals(
        &mut self,
        pending: &mut JoinSet<Renewal>,
        renewing: &mut std::collections::BTreeSet<String>,
    ) {
        let leases: Vec<_> = self
            .leases
            .values()
            .map(|lease| (lease.node.clone(), lease.reply.clone()))
            .collect();
        for (node, previous) in leases {
            if !renewing.insert(node.id.clone()) {
                continue;
            }
            let allocation = self.request_for(&node);
            let control = self.control.clone();
            let auth = self.auth.clone();
            pending.spawn(async move {
                let result = renew(&control, &auth, &allocation, previous.clone()).await;
                Renewal {
                    allocation,
                    previous,
                    result,
                }
            });
        }
    }

    fn apply_renewal(&mut self, renewal: Renewal, tx: &watch::Sender<Vec<SocketAddr>>) {
        let id = &renewal.allocation.node.id;
        let Some(lease) = self.leases.get_mut(id) else {
            return;
        };
        if lease.node != renewal.allocation.node || lease.reply.lease != renewal.previous.lease {
            return;
        }
        match renewal.result {
            Ok(None) => {
                self.leases.remove(id);
                self.publish(tx);
            }
            Ok(Some(reply)) => {
                lease.reply = reply;
                lease.renewed = Instant::now();
                self.publish(tx);
            }
            Err(error) => tracing::debug!(node=%id, %error, "entrance renewal unavailable"),
        }
    }

    fn expire_leases(&mut self) {
        let health = self.health.borrow();
        self.leases.retain(|_, lease| {
            lease.renewed.elapsed() < LEASE_FOR
                || (health.checked.elapsed() < LEASE_FOR
                    && health.addresses.contains(&lease.reply.address))
        });
    }

    fn allocations(&mut self) -> JoinSet<(Allocation, Result<RelayReply>)> {
        let mut pending = JoinSet::new();
        let mut candidates = self
            .nodes
            .iter()
            .filter(|n| n.id != self.selected.id && !self.leases.contains_key(&n.id))
            .filter(|n| self.explorer.available(&n.id, Instant::now()))
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return pending;
        }
        self.allocation_cursor %= candidates.len();
        candidates.rotate_left(self.allocation_cursor);
        if let Some(preferred) = &self.explorer.preferred {
            candidates.sort_by_key(|n| n.id != *preferred);
        }
        let available = self.limit - 1 - self.leases.len();
        self.allocation_cursor += available;
        // Each completion is consumed by maintenance independently of slower
        // optional peers. Renewal and discovery remain independently scheduled.
        for node in candidates.into_iter().take(available) {
            let control = self.control.clone();
            let auth = self.auth.clone();
            let allocation = self.request_for(&node);
            pending.spawn(async move {
                let reply = allocate_request(&control, &auth, &allocation).await;
                (allocation, reply)
            });
        }
        pending
    }
}

fn validate_reply(node: &Node, reply: &RelayReply) -> Result<()> {
    ensure!(
        reply.address.ip() == node.address.ip()
            && reply.address.port() != 0
            && reply.lease.len() == 32
            && reply.lease.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid relay lease"
    );
    Ok(())
}
#[cfg(test)]
async fn allocate(control: &Control, auth: &str, node: &Node, exit: &str) -> Result<RelayReply> {
    allocate_request(
        control,
        auth,
        &Allocation {
            node: node.clone(),
            exit: Node {
                id: exit.into(),
                address: node.address,
                incarnation: 0,
            },
            request: format!("{:032x}", rand::random::<u128>()),
        },
    )
    .await
}

async fn allocate_request(
    control: &Control,
    auth: &str,
    allocation: &Allocation,
) -> Result<RelayReply> {
    control.capabilities(allocation.node.address, auth).await?;
    let body = serde_json::to_vec(&RelayRequest {
        exit: allocation.exit.id.clone(),
        lease: None,
        request: Some(allocation.request.clone()),
    })?;
    let reply = control
        .request(allocation.node.address, auth, "/mesh/relay", Some(body))
        .await?;
    validate_reply(&allocation.node, &reply)?;
    Ok(reply)
}
/// `Ok(None)`: the server rejected the lease and no replacement was allocated.
async fn renew(
    control: &Control,
    auth: &str,
    allocation: &Allocation,
    old: RelayReply,
) -> Result<Option<RelayReply>> {
    let node = &allocation.node;
    let body = serde_json::to_vec(&RelayRequest {
        exit: allocation.exit.id.clone(),
        lease: Some(old.lease.clone()),
        request: None,
    })?;
    let result = control
        .request::<RelayReply>(node.address, auth, "/mesh/relay", Some(body))
        .await;
    match result {
        Ok(reply) => {
            validate_reply(node, &reply)?;
            ensure!(
                reply.lease == old.lease && reply.address == old.address,
                "renewal changed lease identity"
            );
            Ok(Some(reply))
        }
        Err(error)
            if error
                .downcast_ref::<super::control::Rejected>()
                .is_some_and(|e| e.0 == http::StatusCode::BAD_REQUEST) =>
        {
            // The replacement reuses a stable request identity, including when
            // its first response is lost. A timeout alone does not replace a
            // potentially healthy lease.
            match allocate_request(control, auth, allocation).await {
                Ok(reply) => Ok(Some(reply)),
                Err(error) => {
                    tracing::debug!(node=%node.id, %error, "entrance replacement unavailable");
                    Ok(None)
                }
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn all_paths_lost_triggers_discovery_before_periodic_refresh() {
        use super::super::tests::{address, server, wait_nodes};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let exit = address();
        let entry = address();
        let _exit = server(temp.path(), "exit", exit, address(), None).await;
        let identity = ClientIdentity::open(
            temp.path().join("client"),
            &temp.path().join("exit/client-key.json"),
        )
        .unwrap();
        let nodes = wait_nodes(&identity, exit, &["exit"]).await;
        let (_, guard) = Entrances::start(&identity, nodes, "exit", 2, Duration::from_secs(3600))
            .await
            .unwrap();
        let _entry = server(
            temp.path(),
            "entry",
            entry,
            address(),
            Some((exit, temp.path().join("exit/server-key.json"))),
        )
        .await;
        wait_nodes(&identity, exit, &["entry", "exit"]).await;
        let mut updates = guard.updates();
        guard.health().send_replace(PathHealth::default());
        tokio::time::timeout(Duration::from_secs(2), async {
            while updates.borrow_and_update().len() != 2 {
                updates.changed().await.unwrap();
            }
        })
        .await
        .expect("lost paths waited for periodic discovery");
        guard.shutdown().await;
    }

    #[tokio::test]
    async fn allocation_completion_is_consumed_while_other_lease_renewal_is_blocked() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("identity");
        transport::initialize(&dir, NAME).unwrap();
        let endpoint = transport::server(
            "127.0.0.1:0".parse().unwrap(),
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
            transport::Congestion::default(),
        )
        .unwrap();
        let available = Node {
            id: "available".into(),
            address: endpoint.local_addr().unwrap(),
            incarnation: 0,
        };
        let silent_exit = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let unavailable = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let selected = Node {
            id: "exit".into(),
            address: silent_exit.local_addr().unwrap(),
            incarnation: 0,
        };
        let unavailable_node = Node {
            id: "unavailable".into(),
            address: unavailable.local_addr().unwrap(),
            incarnation: 0,
        };
        let reply_address = SocketAddr::from(([127, 0, 0, 1], 21001));
        let (ready, accepted) = tokio::sync::oneshot::channel();
        let (reply_now, reply_allowed) = tokio::sync::oneshot::channel();
        let _server = AbortTask(tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut h3 = h3::server::builder()
                .enable_datagram(true)
                .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            let (request, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.uri().path(), "/mesh/info");
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream
                .send_data(Bytes::from(
                    serde_json::to_vec(&Capabilities::default()).unwrap(),
                ))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            let (request, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.uri().path(), "/mesh/relay");
            while stream.recv_data().await.unwrap().is_some() {}
            ready.send(()).unwrap();
            reply_allowed.await.unwrap();
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream
                .send_data(Bytes::from(
                    serde_json::to_vec(&RelayReply {
                        lease: "2".repeat(32),
                        address: reply_address,
                    })
                    .unwrap(),
                ))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            let _ = connection.closed().await;
        }));
        let directory = Directory {
            health: watch::channel(PathHealth::default()).1,
            control: Arc::new(Control::new(&dir.join("cert.pem"), false).unwrap()),
            auth: format!("Bearer {}", transport::token(&dir.join("token")).unwrap()),
            selected: selected.clone(),
            cache: discovery::Cache::open(dir),
            nodes: vec![selected.clone(), available],
            known: vec![selected],
            leases: BTreeMap::from([(
                unavailable_node.id.clone(),
                ClientLease {
                    node: unavailable_node,
                    reply: RelayReply {
                        lease: "1".repeat(32),
                        address: unavailable.local_addr().unwrap(),
                    },
                    renewed: Instant::now(),
                },
            )]),
            requests: BTreeMap::new(),
            limit: 3,
            discovery_cursor: 0,
            allocation_cursor: 0,
            explorer: selection::Explorer::default(),
        };
        let (tx, mut updates) = watch::channel(directory.addresses());
        let _maintenance = AbortTask(tokio::spawn(
            directory.maintain(tx, Duration::from_millis(50)),
        ));
        tokio::time::timeout(Duration::from_secs(2), accepted)
            .await
            .unwrap()
            .unwrap();
        // Only renewal can contact this address: discovery uses silent_exit.
        // Receipt of the QUIC handshake proves renewal is now in flight.
        let mut packet = [0; 1500];
        tokio::time::timeout(Duration::from_secs(1), unavailable.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        reply_now.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !updates.borrow_and_update().contains(&reply_address) {
                updates.changed().await.unwrap();
            }
        })
        .await
        .expect("ready allocation waited for unrelated renewal timeout");
    }

    #[tokio::test]
    async fn direct_start_and_first_optional_lease_do_not_wait_for_blackholed_allocation() {
        use super::super::tests::{
            Task, address, echo, policy, server, wait_for_response, wait_nodes,
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let (target, _echo) = echo(b'E').await;
        let exit = address();
        let relay = address();
        let _exit = server(root, "exit", exit, target, None).await;
        let identity =
            ClientIdentity::open(root.join("client"), &root.join("exit/client-key.json")).unwrap();
        wait_nodes(&identity, exit, &["exit"]).await;
        let _relay = server(
            root,
            "relay",
            relay,
            address(),
            Some((exit, root.join("exit/server-key.json"))),
        )
        .await;
        let mut nodes = wait_nodes(&identity, relay, &["exit", "relay"]).await;
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        nodes.insert(
            0,
            Node {
                id: "blackhole".into(),
                incarnation: 0,
                address: blackhole.local_addr().unwrap(),
            },
        );
        let (initial, guard) = tokio::time::timeout(
            Duration::from_secs(1),
            Entrances::start(&identity, nodes, "exit", 3, Duration::from_secs(60)),
        )
        .await
        .expect("direct path waited for optional allocation")
        .unwrap();
        assert_eq!(initial, vec![exit]);
        let mut updates = guard.updates();
        let listen = address();
        let _client = Task(tokio::spawn(tunnel::client_with_mesh_exit(
            tunnel::ClientOptions {
                tcp_listen: None,
                proxy_listen: None,
                listen,
                entrances: initial,
                interfaces: vec![],
                path_binds: vec![],
                path_groups: vec![],
                ca: identity.dir.join("cert.pem"),
                token: identity.dir.join("token"),
                name: identity.name(),
                adaptive_fec_retention: false,
                rotate_source_port: false,
                policy: policy(),
                datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
                congestion: transport::Congestion::default(),
                stats: stats::Metrics::new("direct-start"),
            },
            Some(guard.updates()),
            Some(guard.health()),
            "exit".into(),
        )));
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.connect(listen).await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_response(&app, b"E-direct-start"),
        )
        .await
        .expect("working direct path waited four seconds for blackhole");
        tokio::time::timeout(Duration::from_secs(1), async {
            while updates.borrow_and_update().len() < 2 {
                updates.changed().await.unwrap();
            }
        })
        .await
        .expect("successful optional allocation waited for blackhole");
        assert_eq!(updates.borrow().len(), 2);
        let released_address = updates.borrow()[1];
        drop(_client);
        guard.shutdown().await;
        let _rebound = UdpSocket::bind(released_address)
            .await
            .expect("graceful shutdown did not release relay socket");
    }

    #[tokio::test]
    async fn reused_exit_address_and_relay_cannot_forward_to_another_cluster_target() {
        use super::super::tests::{
            Task, address, echo, policy, server, wait_for_response, wait_nodes,
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let (target, _echo) = echo(b'A').await;
        let wrong_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exit = address();
        let replacement = address();
        let _exit = server(root, "exit", exit, target, None).await;
        let identity =
            ClientIdentity::open(root.join("client"), &root.join("exit/client-key.json")).unwrap();
        wait_nodes(&identity, exit, &["exit"]).await;
        let _replacement = server(
            root,
            "replacement",
            replacement,
            wrong_target.local_addr().unwrap(),
            Some((exit, root.join("exit/server-key.json"))),
        )
        .await;
        let nodes = wait_nodes(&identity, replacement, &["exit", "replacement"]).await;
        let node = nodes.iter().find(|node| node.id == "replacement").unwrap();
        let control = Control::new(&identity.dir.join("cert.pem"), false).unwrap();
        let relay = allocate(&control, &identity.auth, node, "replacement")
            .await
            .unwrap();
        // Both stale paths now terminate at another authenticated cluster node:
        // a reused direct address and a lease whose old target was replaced.
        let stale = vec![replacement, relay.address];
        let (updates, observed) = watch::channel(stale.clone());
        let metrics = stats::Metrics::new("bound-exit-client");
        let listen = address();
        let _client = Task(tokio::spawn(tunnel::client_with_mesh_exit(
            tunnel::ClientOptions {
                tcp_listen: None,
                proxy_listen: None,
                listen,
                entrances: stale,
                interfaces: vec![],
                path_binds: vec![],
                path_groups: vec![],
                ca: identity.dir.join("cert.pem"),
                token: identity.dir.join("token"),
                name: identity.name(),
                adaptive_fec_retention: false,
                rotate_source_port: false,
                policy: policy(),
                datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
                congestion: transport::Congestion::default(),
                stats: metrics.clone(),
            },
            Some(observed),
            None,
            "exit".into(),
        )));
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.connect(listen).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                app.send(b"A-never-to-replacement").await.unwrap();
                if metrics.snapshot(false, "test", None).unwrap()["stats"]["path_admission_failures"].as_u64().unwrap() >= 2 { break; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.expect("both wrong exit paths must reject");
        let mut buffer = [0; 128];
        assert!(
            matches!(wrong_target.try_recv_from(&mut buffer), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        updates.send_replace(vec![exit]);
        wait_for_response(&app, b"A-after-exit-moved").await;
        assert!(
            matches!(wrong_target.try_recv_from(&mut buffer), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[tokio::test]
    async fn healthy_data_path_survives_expired_control_renewal_and_stale_health_expires() {
        use super::super::tests::{
            Task, address, echo, policy, server, state, wait_for_response, wait_nodes,
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let (target, _echo) = echo(b'E').await;
        let exit = address();
        let _exit = server(root, "exit", exit, target, None).await;
        let identity =
            ClientIdentity::open(root.join("client"), &root.join("exit/client-key.json")).unwrap();
        let nodes = wait_nodes(&identity, exit, &["exit"]).await;
        let selected = nodes[0].clone();
        // The control port silently blackholes requests, while the separately
        // allocated UDP relay still reaches the authenticated exit.
        let unavailable = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_node = Node {
            id: "relay".into(),
            incarnation: 0,
            address: unavailable.local_addr().unwrap(),
        };
        let mut relay = state(root);
        relay.own = relay_node.clone();
        relay.bind = "127.0.0.1:0".parse().unwrap();
        relay
            .merge(
                Exchange {
                    sender: selected.clone(),
                    nodes: vec![],
                },
                true,
            )
            .await
            .unwrap();
        let reply = relay
            .relay(
                "127.0.0.1".parse().unwrap(),
                RelayRequest {
                    exit: selected.id.clone(),
                    lease: None,
                    request: None,
                },
            )
            .await
            .unwrap();
        let relay_address = reply.address;
        let (health, observed) = watch::channel(PathHealth::default());
        let mut directory = Directory {
            health: observed.clone(),
            control: Arc::new(Control::new(&identity.dir.join("cert.pem"), false).unwrap()),
            auth: identity.auth.clone(),
            selected,
            cache: identity.cache.clone(),
            nodes: nodes.clone(),
            known: nodes,
            leases: BTreeMap::from([(
                relay_node.id.clone(),
                ClientLease {
                    node: relay_node,
                    reply,
                    renewed: Instant::now() - LEASE_FOR * 2,
                },
            )]),
            requests: BTreeMap::new(),
            limit: 2,
            discovery_cursor: 0,
            allocation_cursor: 0,
            explorer: selection::Explorer::default(),
        };
        let (tx, mut updates) = watch::channel(directory.addresses());
        let (paths, rx) = watch::channel(vec![relay_address]);
        let _bridge = Task(tokio::spawn(async move {
            while updates.changed().await.is_ok() {
                paths.send_replace(updates.borrow_and_update()[1..].to_vec());
            }
        }));
        let metrics = stats::Metrics::new("control-outage-client");
        let listen = address();
        let mut fixed = policy();
        fixed.adaptive = false;
        fixed.quality_schedule = false;
        let client = Task(tokio::spawn(tunnel::client_with_mesh_exit(
            tunnel::ClientOptions {
                tcp_listen: None,
                proxy_listen: None,
                listen,
                entrances: vec![relay_address],
                interfaces: vec![],
                path_binds: vec![],
                path_groups: vec![],
                ca: identity.dir.join("cert.pem"),
                token: identity.dir.join("token"),
                name: identity.name(),
                adaptive_fec_retention: false,
                rotate_source_port: false,
                policy: fixed,
                datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
                congestion: transport::Congestion::default(),
                stats: metrics.clone(),
            },
            Some(rx),
            Some(health.clone()),
            "exit".into(),
        )));
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.connect(listen).await.unwrap();
        wait_for_response(&app, b"E-before-control-outage").await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !observed.borrow().addresses.contains(&relay_address) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let before = metrics.snapshot(false, "test", None).unwrap();
        let mut renewals = JoinSet::new();
        directory.start_renewals(&mut renewals, &mut Default::default());
        // Real four-second control timeout, without blocking maintenance.
        while let Some(Ok(renewal)) = renewals.join_next().await {
            directory.apply_renewal(renewal, &tx);
        }
        directory.expire_leases();
        directory.publish(&tx);
        assert!(directory.addresses().contains(&relay_address));
        relay
            .leases
            .lock()
            .unwrap()
            .values_mut()
            .for_each(|lease| lease.touched = Instant::now() - LEASE_FOR * 2);
        reap(&mut relay.leases.lock().unwrap());
        assert_eq!(relay.leases.lock().unwrap().len(), 1);
        wait_for_response(&app, b"E-after-control-outage").await;
        let after = metrics.snapshot(false, "test", None).unwrap();
        assert_eq!(
            before["stats"]["sessions"]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            after["stats"]["sessions"]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>()
        );
        assert!(!client.0.is_finished());
        drop(client);
        // A stopped reporter's old healthy observation cannot pin the path.
        health.send_replace(PathHealth {
            checked: Instant::now() - LEASE_FOR,
            addresses: vec![relay_address],
            samples: vec![],
        });
        directory.expire_leases();
        assert!(directory.leases.is_empty());
    }

    #[tokio::test]
    async fn expired_entrance_recovers_before_unavailable_discovery_finishes() {
        replacement_precedes_unavailable_control(false).await;
    }

    #[tokio::test]
    async fn expired_entrance_recovers_before_unresponsive_lease_times_out() {
        replacement_precedes_unavailable_control(true).await;
    }

    async fn replacement_precedes_unavailable_control(with_unavailable_lease: bool) {
        use super::super::tests::{address, server, wait_nodes};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let exit_address = address();
        let relay_address = address();
        let _exit = server(root, "exit", exit_address, address(), None).await;
        let identity =
            ClientIdentity::open(root.join("client"), &root.join("exit/client-key.json")).unwrap();
        wait_nodes(&identity, exit_address, &["exit"]).await;
        let _relay = server(
            root,
            "relay",
            relay_address,
            address(),
            Some((exit_address, root.join("exit/server-key.json"))),
        )
        .await;
        let nodes = wait_nodes(&identity, relay_address, &["exit", "relay"]).await;
        // Bound UDP sockets silently discard probes and keep their ports from
        // being reused: no ICMP refusal or accidental replacement can pass this.
        let unavailable = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_entrance = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let selected = nodes.iter().find(|node| node.id == "exit").unwrap().clone();
        let relay = nodes
            .iter()
            .find(|node| node.id == "relay")
            .unwrap()
            .clone();
        let unavailable_node = Node {
            id: "unavailable".into(),
            incarnation: 0,
            address: unavailable.local_addr().unwrap(),
        };
        let mut known = vec![unavailable_node.clone()];
        known.extend(nodes.iter().cloned());
        let mut directory = Directory {
            health: watch::channel(PathHealth::default()).1,
            control: Arc::new(Control::new(&identity.dir.join("cert.pem"), false).unwrap()),
            auth: identity.auth.clone(),
            selected,
            cache: identity.cache.clone(),
            nodes,
            known,
            // Model the client's old lease after a relay restart. The live
            // server explicitly rejects it, allowing one replacement request.
            leases: BTreeMap::from([(
                relay.id.clone(),
                ClientLease {
                    node: relay,
                    reply: RelayReply {
                        lease: "0".repeat(32),
                        address: old_entrance.local_addr().unwrap(),
                    },
                    renewed: Instant::now(),
                },
            )]),
            requests: BTreeMap::new(),
            limit: if with_unavailable_lease { 3 } else { 2 },
            discovery_cursor: 0,
            allocation_cursor: 0,
            explorer: selection::Explorer::default(),
        };
        if with_unavailable_lease {
            directory.leases.insert(
                unavailable_node.id.clone(),
                ClientLease {
                    node: unavailable_node,
                    reply: RelayReply {
                        lease: "1".repeat(32),
                        address: unavailable.local_addr().unwrap(),
                    },
                    renewed: Instant::now(),
                },
            );
        }
        let (tx, mut updates) = watch::channel(directory.addresses());
        // Discovery prefers the unavailable member first. Both unresponsive
        // requests have a four-second deadline; a recovered path must reach
        // the tunnel without waiting for either unrelated peer.
        let maintenance = AbortTask(tokio::spawn(
            directory.maintain(tx, Duration::from_millis(50)),
        ));
        tokio::time::timeout(Duration::from_secs(2), updates.changed())
            .await
            .expect("relay recovery waited for unavailable control")
            .unwrap();
        let addresses = updates.borrow_and_update().clone();
        assert_eq!(addresses.len(), if with_unavailable_lease { 3 } else { 2 });
        assert_eq!(addresses[0], exit_address);
        assert_ne!(addresses[1], old_entrance.local_addr().unwrap());
        if with_unavailable_lease {
            assert_eq!(addresses[2], unavailable.local_addr().unwrap());
        }
        assert!(!maintenance.0.is_finished());
    }

    #[tokio::test]
    async fn partial_discovery_keeps_known_candidates_and_fresh_records_replace_stale_hints() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("identity");
        transport::initialize(&dir, NAME).unwrap();
        let nodes: Vec<_> = (0..MAX_NODES)
            .map(|i| Node {
                id: format!("node_{i:02}"),
                incarnation: 0,
                address: SocketAddr::from(([127, 0, 0, 1], 10000 + i as u16)),
            })
            .collect();
        let mut directory = Directory {
            health: watch::channel(PathHealth::default()).1,
            control: Arc::new(Control::new(&dir.join("cert.pem"), false).unwrap()),
            auth: String::new(),
            selected: nodes[0].clone(),
            cache: discovery::Cache::open(dir.clone()),
            nodes: nodes.clone(),
            known: nodes.clone(),
            leases: BTreeMap::new(),
            requests: BTreeMap::new(),
            limit: MAX_PATHS,
            discovery_cursor: 0,
            allocation_cursor: 0,
            explorer: selection::Explorer::default(),
        };
        directory.cache.remember(&nodes).unwrap();
        let partial = vec![nodes[1].clone()];
        directory.apply_nodes(partial.clone());
        assert_eq!(directory.known, nodes);
        assert_eq!(directory.nodes, partial);
        // A moved member and a new member on a reused address replace the
        // cached records instead of blocking discovery.
        let mut moved = nodes[2].clone();
        moved.address.set_port(20000);
        let mut renamed = nodes[3].clone();
        renamed.id = "replacement".into();
        directory.apply_nodes(vec![moved.clone(), renamed.clone()]);
        assert_eq!(directory.nodes, vec![moved.clone(), renamed.clone()]);
        assert!(directory.known.contains(&moved) && directory.known.contains(&renamed));
        assert!(!directory.known.contains(&nodes[2]) && !directory.known.contains(&nodes[3]));
        assert_eq!(directory.known.len(), MAX_NODES);
        // A full cache evicts an old hint for a current member.
        let extra = Node {
            id: "extra".into(),
            incarnation: 0,
            address: "127.0.0.1:20001".parse().unwrap(),
        };
        directory.apply_nodes(vec![extra.clone()]);
        assert_eq!(directory.known.len(), MAX_NODES);
        assert!(directory.known.contains(&extra));
        directory.cache.flush().await;
        assert_eq!(discovery::cached(&dir), directory.known);
        directory.leases.insert(
            extra.id.clone(),
            ClientLease {
                node: extra,
                reply: RelayReply {
                    lease: "1".repeat(32),
                    address: "127.0.0.1:21000".parse().unwrap(),
                },
                renewed: Instant::now(),
            },
        );
        let mut moved_exit = directory.selected.clone();
        moved_exit.address.set_port(22000);
        directory.apply_nodes(vec![moved_exit.clone()]);
        assert_eq!(directory.addresses(), vec![moved_exit.address]);
        assert!(
            directory.leases.is_empty(),
            "old immutable relay targets survived exit migration"
        );
    }
}
