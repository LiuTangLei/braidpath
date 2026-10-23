use super::*;
use tokio::sync::watch;

// Renew several times per lease lifetime, independently of discovery.
const RENEW_EVERY: Duration = Duration::from_secs(LEASE_FOR.as_secs() / 4);

/// Periodic data-plane evidence; an abandoned reporter expires with the lease.
#[derive(Clone)]
pub(crate) struct PathHealth {
    pub checked: Instant,
    pub addresses: Vec<SocketAddr>,
}
impl Default for PathHealth {
    fn default() -> Self {
        Self {
            checked: Instant::now(),
            addresses: Vec::new(),
        }
    }
}

/// Owns the maintenance task; dropping it stops discovery and lease renewal.
pub struct Entrances {
    health: watch::Sender<PathHealth>,
    updates: watch::Receiver<Vec<SocketAddr>>,
    _maintenance: AbortTask,
}
impl Entrances {
    pub(crate) fn health(&self) -> watch::Sender<PathHealth> {
        self.health.clone()
    }

    pub fn updates(&self) -> watch::Receiver<Vec<SocketAddr>> {
        self.updates.clone()
    }

    pub(super) async fn start(
        identity: &ClientIdentity,
        nodes: Vec<Node>,
        exit: &str,
        limit: usize,
        interval: Duration,
    ) -> Result<(Vec<SocketAddr>, Self)> {
        ensure!((1..=MAX_PATHS).contains(&limit), "invalid entrance limit");
        validate_nodes(&nodes)?;
        let selected = nodes
            .iter()
            .find(|n| n.id == exit)
            .context("selected exit not found")?
            .clone();
        let (health, observed) = watch::channel(PathHealth::default());
        let directory = Directory {
            health: observed,
            control: Arc::new(Control::new(
                &identity.dir.join("cert.pem"),
                nodes.iter().any(|n| n.address.is_ipv6()),
            )?),
            auth: identity.auth.clone(),
            selected,
            cache_dir: identity.dir.clone(),
            known: discovery::merge_known(&discovery::cached(&identity.dir), &nodes)?,
            nodes,
            leases: BTreeMap::new(),
            limit,
            discovery_cursor: 0,
            allocation_cursor: 0,
        };
        let initial = directory.addresses();
        let (tx, updates) = watch::channel(initial.clone());
        let maintenance = AbortTask(tokio::spawn(directory.maintain(tx, interval)));
        Ok((
            initial,
            Self {
                health,
                updates,
                _maintenance: maintenance,
            },
        ))
    }
}

struct ClientLease {
    node: Node,
    reply: RelayReply,
    renewed: Instant,
}
struct Directory {
    health: watch::Receiver<PathHealth>,
    control: Arc<Control>,
    auth: String,
    selected: Node,
    cache_dir: PathBuf,
    nodes: Vec<Node>,
    known: Vec<Node>,
    leases: BTreeMap<String, ClientLease>,
    limit: usize,
    discovery_cursor: usize,
    allocation_cursor: usize,
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

    async fn maintain(mut self, tx: watch::Sender<Vec<SocketAddr>>, interval: Duration) {
        // Renewal has its own cadence and discovery runs in the background, so
        // unavailable members never delay a working entrance's lease renewal.
        let renew_every = interval.min(RENEW_EVERY);
        let mut renew = tokio::time::interval(renew_every);
        let mut discover = tokio::time::interval(interval);
        for tick in [&mut renew, &mut discover] {
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.reset();
        }
        let mut discovery = JoinSet::new();
        let mut allocations = self.allocations();
        loop {
            tokio::select! {
                _ = renew.tick() => {
                    self.renew_leases(&tx).await;
                    self.publish(&tx);
                }
                _ = discover.tick(), if discovery.is_empty() => {
                    discovery.spawn(self.discovery());
                }
                Some(result) = discovery.join_next() => {
                    let previous_exit = self.selected.address;
                    match result {
                        Ok(Some(nodes)) => self.apply_nodes(nodes),
                        _ => tracing::debug!("mesh directory refresh unavailable; retaining known peers"),
                    }
                    if self.selected.address != previous_exit {
                        // These requests selected an immutable relay target
                        // before the exit moved; their results are now stale.
                        allocations.abort_all();
                        allocations = JoinSet::new();
                    }
                    // Keep connections to lease holders; close rotated ones.
                    self.control.prune(renew_every * 3);
                    if allocations.is_empty() {
                        allocations = self.allocations();
                    }
                    self.publish(&tx);
                }
                Some(result) = allocations.join_next() => {
                    match result {
                        Ok((node, Ok(reply))) => {
                            // An allocation made for an old member address is
                            // never published after that member moves.
                            if self.nodes.contains(&node) {
                                self.leases.insert(node.id.clone(), ClientLease {
                                    node, reply, renewed: Instant::now(),
                                });
                                self.publish(&tx);
                            }
                        }
                        Ok((node, Err(error))) => tracing::debug!(node=%node.id, %error, "optional entrance unavailable"),
                        Err(error) => tracing::warn!(%error, "entrance allocation task failed"),
                    }
                }
            }
        }
    }

    fn apply_nodes(&mut self, nodes: Vec<Node>) {
        let Ok(known) = discovery::merge_known(&self.known, &nodes) else {
            return;
        };
        if known != self.known {
            if let Err(error) = discovery::remember(&self.cache_dir, &known) {
                tracing::warn!(%error, "could not persist updated discovery hints");
            }
            self.known = known;
        }
        if let Some(selected) = nodes.iter().find(|node| node.id == self.selected.id) {
            if selected.address != self.selected.address {
                // Renewal preserves a lease's original UDP target. Allocate
                // fresh leases after migration instead of renewing old routes.
                self.leases.clear();
            }
            self.selected = selected.clone();
        }
        self.nodes = nodes;
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

    async fn renew_leases(&mut self, tx: &watch::Sender<Vec<SocketAddr>>) {
        let mut pending = JoinSet::new();
        for lease in self.leases.values() {
            let control = self.control.clone();
            let auth = self.auth.clone();
            let exit = self.selected.id.clone();
            let node = lease.node.clone();
            let old = lease.reply.clone();
            pending.spawn(async move {
                let result = renew(&control, &auth, &node, &exit, old).await;
                (node.id, result)
            });
        }
        while let Some(result) = pending.join_next().await {
            if let Ok((id, result)) = result {
                let lease = self.leases.get_mut(&id).expect("existing lease");
                match result {
                    Ok(None) => {
                        // The server no longer has this allocation, so its path
                        // cannot work; free the slot for another member now.
                        self.leases.remove(&id);
                        self.publish(tx);
                    }
                    Ok(Some(reply)) => {
                        let changed = lease.reply.address != reply.address;
                        lease.reply = reply;
                        lease.renewed = Instant::now();
                        // One failed peer must not hold a recovered entrance
                        // behind the rest of this concurrent renewal batch.
                        if changed {
                            self.publish(tx);
                        }
                    }
                    Err(error) => tracing::debug!(node=%id, %error, "entrance renewal unavailable"),
                }
            }
        }
        // A live authenticated data connection can outlast failed control
        // renewals. Stale observations cannot pin a slot after its client stops.
        self.expire_leases();
    }

    fn expire_leases(&mut self) {
        let health = self.health.borrow();
        self.leases.retain(|_, lease| {
            lease.renewed.elapsed() < LEASE_FOR
                || (health.checked.elapsed() < LEASE_FOR
                    && health.addresses.contains(&lease.reply.address))
        });
    }

    fn allocations(&mut self) -> JoinSet<(Node, Result<RelayReply>)> {
        let mut pending = JoinSet::new();
        let mut candidates = self
            .nodes
            .iter()
            .filter(|n| n.id != self.selected.id && !self.leases.contains_key(&n.id))
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return pending;
        }
        self.allocation_cursor %= candidates.len();
        candidates.rotate_left(self.allocation_cursor);
        let available = self.limit - 1 - self.leases.len();
        self.allocation_cursor += available;
        // Each completion is consumed by maintenance independently of slower
        // optional peers. Renewal and discovery remain independently scheduled.
        for node in candidates.into_iter().take(available) {
            let control = self.control.clone();
            let auth = self.auth.clone();
            let exit = self.selected.id.clone();
            pending.spawn(async move {
                let reply = allocate(&control, &auth, &node, &exit).await;
                (node, reply)
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
async fn allocate(control: &Control, auth: &str, node: &Node, exit: &str) -> Result<RelayReply> {
    let body = serde_json::to_vec(&RelayRequest {
        exit: exit.into(),
        lease: None,
    })?;
    let reply = control
        .request(node.address, auth, "/mesh/relay", Some(body))
        .await?;
    validate_reply(node, &reply)?;
    Ok(reply)
}
/// `Ok(None)`: the server rejected the lease and no replacement was allocated.
async fn renew(
    control: &Control,
    auth: &str,
    node: &Node,
    exit: &str,
    old: RelayReply,
) -> Result<Option<RelayReply>> {
    let body = serde_json::to_vec(&RelayRequest {
        exit: exit.into(),
        lease: Some(old.lease.clone()),
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
            // Explicit rejection means the old allocation is gone (e.g. a
            // restarted server). A transport timeout alone is not retried here.
            match allocate(control, auth, node, exit).await {
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
            cache_dir: identity.dir.clone(),
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
            limit: 2,
            discovery_cursor: 0,
            allocation_cursor: 0,
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
        directory.renew_leases(&tx).await; // Real four-second control timeout.
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
            address: unavailable.local_addr().unwrap(),
        };
        let mut known = vec![unavailable_node.clone()];
        known.extend(nodes.iter().cloned());
        let mut directory = Directory {
            health: watch::channel(PathHealth::default()).1,
            control: Arc::new(Control::new(&identity.dir.join("cert.pem"), false).unwrap()),
            auth: identity.auth.clone(),
            selected,
            cache_dir: identity.dir.clone(),
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
            limit: if with_unavailable_lease { 3 } else { 2 },
            discovery_cursor: 0,
            allocation_cursor: 0,
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
                address: SocketAddr::from(([127, 0, 0, 1], 10000 + i as u16)),
            })
            .collect();
        let mut directory = Directory {
            health: watch::channel(PathHealth::default()).1,
            control: Arc::new(Control::new(&dir.join("cert.pem"), false).unwrap()),
            auth: String::new(),
            selected: nodes[0].clone(),
            cache_dir: dir.clone(),
            nodes: nodes.clone(),
            known: nodes.clone(),
            leases: BTreeMap::new(),
            limit: MAX_PATHS,
            discovery_cursor: 0,
            allocation_cursor: 0,
        };
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
            address: "127.0.0.1:20001".parse().unwrap(),
        };
        directory.apply_nodes(vec![extra.clone()]);
        assert_eq!(directory.known.len(), MAX_NODES);
        assert!(directory.known.contains(&extra));
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
