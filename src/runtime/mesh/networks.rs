//! One control owner per uplink; all routes share the tunnel's eight-path budget.
use super::*;
use tokio::sync::watch;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Uplink {
    pub interface: Option<String>,
    pub bind: Option<IpAddr>,
    pub group: u8,
}
impl Uplink {
    pub(super) fn supports(&self, address: SocketAddr) -> bool {
        self.bind.is_none_or(|ip| ip.is_ipv4() == address.is_ipv4())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    pub address: SocketAddr,
    pub uplink: Uplink,
}
impl From<SocketAddr> for Route {
    fn from(address: SocketAddr) -> Self {
        Self {
            address,
            uplink: Uplink::default(),
        }
    }
}
pub struct Networks {
    routes: watch::Receiver<Vec<Route>>,
    health: watch::Sender<PathHealth>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    maintenance: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Networks {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
impl Networks {
    pub(crate) fn routes(&self) -> watch::Receiver<Vec<Route>> {
        self.routes.clone()
    }
    pub(crate) fn health(&self) -> watch::Sender<PathHealth> {
        self.health.clone()
    }
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.maintenance.take() {
            let _ = task.await;
        }
    }
}

struct NetworkSlot {
    uplink: Uplink,
    guard: Option<Entrances>,
    retry_at: Instant,
    started: Instant,
    last_usable: Instant,
    attempts: u64,
    failure: Option<&'static str>,
}
impl NetworkSlot {
    fn new(uplink: Uplink) -> Self {
        let now = Instant::now();
        Self {
            uplink,
            guard: None,
            retry_at: now,
            started: now,
            last_usable: now,
            attempts: 0,
            failure: None,
        }
    }
    async fn start(&mut self, identity: &ClientIdentity, nodes: &[Node], exit: &str) {
        self.attempts += 1;
        self.retry_at = Instant::now() + Duration::from_secs(2);
        let nodes: Vec<_> = nodes
            .iter()
            .filter(|n| self.uplink.supports(n.address))
            .cloned()
            .collect();
        if !nodes.iter().any(|n| n.id == exit) {
            self.failure = Some("exit_address_family");
            return;
        }
        match Entrances::start_bound(
            identity,
            nodes,
            exit,
            1,
            Duration::from_secs(15),
            &self.uplink,
        )
        .await
        {
            Ok((_, guard)) => {
                self.guard = Some(guard);
                self.started = Instant::now();
                self.last_usable = self.started;
                self.failure = None;
            }
            Err(error) => {
                self.failure = Some("uplink_initialization");
                tracing::debug!(group=self.uplink.group, %error, "uplink unavailable; bounded retry scheduled");
            }
        }
    }
}

// Reserve one reconnect path for each initialized uplink. Only the remaining
// slots are borrowed; discovery and the total eight-path envelope stay bounded.
fn allocate_limits(capacities: &[usize], preferred: &[bool]) -> Vec<usize> {
    let mut limits: Vec<_> = capacities.iter().map(|n| usize::from(*n > 0)).collect();
    let prefer = capacities.iter().zip(preferred).any(|(n, p)| *n > 0 && *p);
    let mut remaining = MAX_PATHS - limits.iter().sum::<usize>();
    while remaining > 0 {
        let mut changed = false;
        for i in 0..limits.len() {
            if remaining > 0 && limits[i] < capacities[i] && (!prefer || preferred[i]) {
                limits[i] += 1;
                remaining -= 1;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    limits
}

fn publish_routes(slots: &[NetworkSlot], limits: &[usize], tx: &watch::Sender<Vec<Route>>) {
    let next = slots
        .iter()
        .zip(limits)
        .flat_map(|(slot, limit)| {
            slot.guard
                .as_ref()
                .map(|guard| {
                    guard
                        .updates()
                        .borrow()
                        .iter()
                        .take(*limit)
                        .map(|address| Route {
                            address: *address,
                            uplink: slot.uplink.clone(),
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    tx.send_if_modified(|old| {
        if *old == next {
            false
        } else {
            *old = next;
            true
        }
    });
}
impl ClientIdentity {
    pub async fn discover_on(
        &self,
        entries: &[SocketAddr],
        exit: &str,
        uplinks: &[Uplink],
    ) -> Result<Vec<Node>> {
        ensure!(
            !entries.is_empty() && entries.len() <= MAX_NODES,
            "provide 1..32 discovery entries"
        );
        ensure!(
            !uplinks.is_empty() && uplinks.len() <= MAX_PATHS,
            "uplink count must be 1..8"
        );
        let mut pending = JoinSet::new();
        for uplink in uplinks {
            let identity = self.clone();
            let uplink = uplink.clone();
            let entries = entries.to_vec();
            let exit = exit.to_owned();
            pending.spawn(async move {
                let control = Arc::new(Control::bound(
                    &identity.dir.join("cert.pem"),
                    entries.iter().any(|a| a.is_ipv6()),
                    &uplink,
                )?);
                let entries: Vec<_> = entries
                    .into_iter()
                    .filter(|a| uplink.supports(*a))
                    .collect();
                match identity
                    .query_with(control.clone(), &entries, Some(&exit))
                    .await
                {
                    Ok(nodes) => Ok(nodes),
                    Err(error) => {
                        let cached: Vec<_> = identity
                            .cache
                            .known()
                            .iter()
                            .map(|n| n.address)
                            .filter(|a| uplink.supports(*a) && !entries.contains(a))
                            .collect();
                        if cached.is_empty() {
                            return Err(error);
                        }
                        identity.query_with(control, &cached, Some(&exit)).await
                    }
                }
            });
        }
        let mut last = anyhow::anyhow!("no usable mesh uplink");
        while let Some(result) = pending.join_next().await {
            match result {
                Ok(Ok(nodes)) => return Ok(nodes),
                Ok(Err(error)) => last = error,
                Err(error) => last = error.into(),
            }
        }
        Err(last)
    }
    pub async fn networks(
        &self,
        nodes: Vec<Node>,
        exit: &str,
        uplinks: Vec<Uplink>,
    ) -> Result<Networks> {
        self.networks_with_metrics(nodes, exit, uplinks, stats::Metrics::new("mesh-networks"))
            .await
    }

    pub(crate) async fn networks_with_metrics(
        &self,
        nodes: Vec<Node>,
        exit: &str,
        uplinks: Vec<Uplink>,
        metrics: stats::Metrics,
    ) -> Result<Networks> {
        ensure!(
            !uplinks.is_empty() && uplinks.len() <= MAX_PATHS,
            "uplink count must be 1..8"
        );
        entrances::validate_nodes(&nodes)?;
        ensure!(
            nodes.iter().any(|n| n.id == exit),
            "selected exit not found"
        );
        let mut groups = std::collections::BTreeSet::new();
        for uplink in &uplinks {
            ensure!(
                usize::from(uplink.group) < MAX_PATHS && groups.insert(uplink.group),
                "uplink groups must be distinct and below eight"
            );
        }
        let mut slots: Vec<_> = uplinks.into_iter().map(NetworkSlot::new).collect();
        for slot in &mut slots {
            slot.start(self, &nodes, exit).await;
        }
        ensure!(
            slots.iter().any(|s| s.guard.is_some()),
            "no usable mesh uplink: local bind or exit address family unavailable"
        );
        let (tx, routes) = watch::channel(Vec::new());
        let (health, mut observed) = watch::channel(PathHealth::default());
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        publish_routes(&slots, &vec![1; slots.len()], &tx);
        let identity = self.clone();
        let exit = exit.to_owned();
        let maintenance = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(200));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut cleanups = JoinSet::new();
            let mut health_open = true;
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    Some(_) = cleanups.join_next() => {},
                    result = observed.changed(), if health_open => {
                        if result.is_err() { health_open = false; continue; }
                        let all = observed.borrow_and_update();
                        for slot in &slots {
                            if let Some(guard) = &slot.guard {
                                let samples: Vec<_> = all.samples.iter().filter(|s| s.group == slot.uplink.group).cloned().collect();
                                guard.health().send_replace(PathHealth { checked: all.checked, addresses: samples.iter().filter(|s| !s.failed).map(|s| s.address).collect(), samples });
                            }
                        }
                    }
                    _ = tick.tick() => {
                        let now = Instant::now();
                        let known = identity.cache.known();
                        let all = observed.borrow().clone();
                        let fresh = now.saturating_duration_since(all.checked) < Duration::from_secs(2);
                        let mut capacities = Vec::new();
                        let mut preferred = Vec::new();
                        let mut diagnostics = Vec::new();
                        for slot in &mut slots {
                            let usable = if fresh { all.samples.iter().filter(|s| s.group == slot.uplink.group && !s.failed).count() } else { 0 };
                            if usable > 0 { slot.last_usable = now; }
                            // Recreate the bound control socket after prolonged failure,
                            // including interfaces removed and recreated with a new index.
                            if slot.guard.is_some() && now.saturating_duration_since(slot.last_usable) >= Duration::from_secs(30) {
                                if let Some(guard) = slot.guard.take() { cleanups.spawn(guard.shutdown()); }
                                slot.retry_at = now + Duration::from_secs(2);
                                slot.failure = Some("no_usable_path");
                            }
                            if slot.guard.is_none() && now >= slot.retry_at {
                                slot.start(&identity, &known, &exit).await;
                            }
                            let capacity = if slot.guard.is_some() { known.iter().filter(|n| slot.uplink.supports(n.address)).count().clamp(1, MAX_PATHS) } else { 0 };
                            capacities.push(capacity);
                            let starting = now.saturating_duration_since(slot.started) < Duration::from_secs(10);
                            preferred.push(usable > 0 || starting);
                            diagnostics.push(stats::MeshUplink {
                                group: slot.uplink.group, interface: slot.uplink.interface.clone(), source_ip: slot.uplink.bind.map(|ip| ip.to_string()),
                                state: if slot.guard.is_none() { "waiting" } else if usable > 0 { "connected" } else if starting { "connecting" } else { "unavailable" },
                                usable_paths: usable, path_limit: 0, configured_paths: 0, control_starts: slot.attempts, failure: slot.failure,
                            });
                        }
                        let limits = allocate_limits(&capacities, &preferred);
                        for ((slot, limit), diagnostic) in slots.iter().zip(&limits).zip(&mut diagnostics) {
                            if let Some(guard) = &slot.guard {
                                guard.resize(*limit);
                                diagnostic.configured_paths = guard.updates().borrow().len().min(*limit);
                            }
                            diagnostic.path_limit = *limit;
                        }
                        publish_routes(&slots, &limits, &tx);
                        metrics.state(|s| s.mesh_uplinks = diagnostics);
                    }
                }
            }
            for slot in &mut slots {
                if let Some(guard) = slot.guard.take() {
                    cleanups.spawn(guard.shutdown());
                }
            }
            while cleanups.join_next().await.is_some() {}
            metrics.state(|s| {
                for uplink in &mut s.mesh_uplinks {
                    uplink.state = "stopped";
                    uplink.configured_paths = 0;
                    uplink.usable_paths = 0;
                }
            });
        });
        Ok(Networks {
            routes,
            health,
            stop: Some(stop),
            maintenance: Some(maintenance),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Task, address, policy, server, wait_nodes};
    use super::*;

    #[test]
    fn shared_path_slots_follow_available_networks_without_exceeding_eight() {
        assert_eq!(allocate_limits(&[8, 8], &[true, true]), [4, 4]);
        assert_eq!(allocate_limits(&[8, 8], &[true, false]), [7, 1]);
        assert_eq!(allocate_limits(&[8, 0], &[true, false]), [8, 0]);
        assert_eq!(allocate_limits(&[2, 8], &[true, true]), [2, 6]);
        assert_eq!(allocate_limits(&[8; 8], &[false; 8]), [1; 8]);
        for healthy in 0..256u16 {
            let preferred: Vec<_> = (0..8).map(|i| healthy & (1 << i) != 0).collect();
            assert_eq!(
                allocate_limits(&[8; 8], &preferred).iter().sum::<usize>(),
                8
            );
        }
    }

    #[tokio::test]
    async fn missing_local_uplink_does_not_block_other_network_and_can_reinitialize() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().unwrap();
        let exit = address();
        let _exit = server(root.path(), "exit", exit, address(), None).await;
        let identity = ClientIdentity::open(
            root.path().join("client"),
            &root.path().join("exit/client-key.json"),
        )
        .unwrap();
        let nodes = wait_nodes(&identity, exit, &["exit"]).await;
        let missing = Uplink {
            bind: Some("192.0.2.123".parse().unwrap()),
            group: 0,
            interface: None,
        };
        let available = Uplink {
            bind: Some("127.0.0.1".parse().unwrap()),
            group: 1,
            interface: None,
        };
        let metrics = stats::Metrics::new("missing-uplink");
        let networks = identity
            .networks_with_metrics(
                nodes.clone(),
                "exit",
                vec![missing.clone(), available.clone()],
                metrics.clone(),
            )
            .await
            .unwrap();
        assert!(networks.routes.borrow().iter().all(|r| r.uplink.group == 1));
        assert_eq!(networks.routes.borrow().len(), 1);
        // Exercise the exact retry initialization with availability restored.
        let mut slot = NetworkSlot::new(missing);
        slot.start(&identity, &nodes, "exit").await;
        assert!(slot.guard.is_none());
        assert_eq!(slot.failure, Some("uplink_initialization"));
        slot.uplink = available;
        slot.start(&identity, &nodes, "exit").await;
        assert!(slot.guard.is_some());
        assert_eq!(slot.attempts, 2);
        slot.guard.take().unwrap().shutdown().await;
        networks.shutdown().await;
    }

    #[tokio::test]
    async fn resizing_and_failed_data_paths_release_leases_and_preserve_the_exit() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().unwrap();
        let exit = address();
        let _exit = server(root.path(), "exit", exit, address(), None).await;
        let mut servers = Vec::new();
        for id in ["entry_a", "entry_b", "entry_c"] {
            servers.push(
                server(
                    root.path(),
                    id,
                    address(),
                    address(),
                    Some((exit, root.path().join("exit/server-key.json"))),
                )
                .await,
            );
        }
        let identity = ClientIdentity::open(
            root.path().join("client"),
            &root.path().join("exit/client-key.json"),
        )
        .unwrap();
        let nodes = wait_nodes(&identity, exit, &["entry_a", "entry_b", "entry_c", "exit"]).await;
        let (_, guard) = Entrances::start_bound(
            &identity,
            nodes,
            "exit",
            3,
            Duration::from_secs(1),
            &Uplink::default(),
        )
        .await
        .unwrap();
        let mut updates = guard.updates();
        async fn count(updates: &mut watch::Receiver<Vec<SocketAddr>>, expected: usize) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while updates.borrow_and_update().len() != expected {
                    updates.changed().await.unwrap();
                }
            })
            .await
            .unwrap();
        }
        count(&mut updates, 3).await;
        let original = updates.borrow().clone();
        let bad = original[1];
        guard.health().send_replace(PathHealth {
            checked: Instant::now(),
            addresses: vec![exit, original[2]],
            samples: vec![PathSample {
                address: bad,
                group: 0,
                delivered: false,
                failed: true,
                rtt_ms: 0.0,
                loss: 0.0,
            }],
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let routes = updates.borrow_and_update().clone();
                if routes.len() == 3 && !routes.contains(&bad) {
                    break;
                }
                updates.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let replaced = updates.borrow().clone();
        assert!(replaced.contains(&exit));
        assert!(replaced.contains(&original[2]));
        guard.resize(1);
        count(&mut updates, 1).await;
        assert_eq!(*updates.borrow(), vec![exit]);
        // Release completion is asynchronous; check the actual remote lease
        // table rather than merely the watch publication.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let free = original
                    .iter()
                    .chain(replaced.iter())
                    .filter(|a| **a != exit)
                    .all(|a| std::net::UdpSocket::bind(a).is_ok());
                if free {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        guard.resize(3);
        count(&mut updates, 3).await;
        let final_routes = updates.borrow().clone();
        guard.shutdown().await;
        assert!(
            final_routes
                .iter()
                .filter(|a| **a != exit)
                .all(|a| std::net::UdpSocket::bind(a).is_ok())
        );
    }

    #[tokio::test]
    async fn bound_uplinks_share_one_tunnel_and_preserve_large_udp_messages() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().unwrap();
        let target = address();
        let _echo = Task(tokio::spawn(crate::runtime::probe::echo(target, None)));
        let exit = address();
        let entry = address();
        let server_metrics = stats::Metrics::new("message-server");
        let _exit = super::super::tests::server_with_metrics(
            root.path(),
            "exit",
            exit,
            target,
            None,
            server_metrics.clone(),
        )
        .await;
        let identity = ClientIdentity::open(
            root.path().join("client"),
            &root.path().join("exit/client-key.json"),
        )
        .unwrap();
        wait_nodes(&identity, exit, &["exit"]).await;
        let _entry = server(
            root.path(),
            "entry",
            entry,
            target,
            Some((exit, root.path().join("exit/server-key.json"))),
        )
        .await;
        let nodes = wait_nodes(&identity, entry, &["entry", "exit"]).await;
        // Portable ownership/route-identity fixture. These are two bound local
        // sockets on the same source network, not evidence of independent WANs.
        let uplinks: Vec<_> = (0..2)
            .map(|group| Uplink {
                interface: None,
                bind: Some("127.0.0.1".parse().unwrap()),
                group,
            })
            .collect();
        let discovered = identity
            .discover_on(&[entry], "exit", &uplinks)
            .await
            .unwrap();
        assert_eq!(discovered, nodes);
        let guard = identity
            .networks_with_metrics(discovered, "exit", uplinks, stats::Metrics::new("uplinks"))
            .await
            .unwrap();
        let mut routes = guard.routes();
        tokio::time::timeout(Duration::from_secs(3), async {
            while routes.borrow_and_update().len() < 4 {
                routes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let relay_addresses: Vec<_> = routes
            .borrow()
            .iter()
            .filter(|r| r.address != exit)
            .map(|r| r.address)
            .collect();
        assert_eq!(relay_addresses.len(), 2);
        assert_ne!(relay_addresses[0], relay_addresses[1]);
        assert!(routes.borrow().len() <= MAX_PATHS);
        let mut session_policy = policy();
        session_policy.max_message_bytes = super::super::super::MAX_MESSAGE;
        session_policy.adaptive = false;
        session_policy.quality_schedule = false;
        let listen = address();
        let metrics = stats::Metrics::new("bound-message-client");
        let client = Task(tokio::spawn(tunnel::client_with_routes(
            tunnel::ClientOptions {
                stream_connector: None,
                tcp_listen: None,
                proxy_listen: None,
                listen,
                entrances: routes.borrow().iter().map(|r| r.address).collect(),
                interfaces: vec![],
                path_binds: vec![],
                path_groups: vec![],
                ca: identity.dir.join("cert.pem"),
                token: identity.dir.join("token"),
                name: identity.name(),
                policy: session_policy,
                adaptive_fec_retention: false,
                rotate_source_port: false,
                datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
                congestion: transport::Congestion::default(),
                stats: metrics.clone(),
            },
            guard.routes(),
            guard.health(),
            "exit".into(),
        )));
        // This fixture tests steady-state message integrity, not startup loss
        // on a newly admitted UDP route. Wait for every configured data path.
        let mut ready = guard.health().subscribe();
        tokio::time::timeout(Duration::from_secs(4), async {
            while ready.borrow_and_update().addresses.len() != 4 {
                ready.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.connect(listen).await.unwrap();
        let mut b = [0; 8192];
        // Readiness only, not a throughput workload.
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                app.send(b"ready").await.unwrap();
                if tokio::time::timeout(Duration::from_millis(100), app.recv(&mut b))
                    .await
                    .is_ok()
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
        for size in [1200, 1472, 4096] {
            let data: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            app.send(&data).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(2), app.recv(&mut b))
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "large message {size}: {error}; {}",
                        serde_json::json!({"client":metrics.snapshot(false, "diagnostic", None).unwrap(), "server":server_metrics.snapshot(false, "diagnostic", None).unwrap()})
                    )
                })
                .unwrap();
            assert_eq!(&b[..n], data);
        }
        app.send(&vec![0; 4097]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), app.recv(&mut b))
                .await
                .is_err()
        );
        drop(client);
        guard.shutdown().await;
        for addr in relay_addresses {
            let _socket = UdpSocket::bind(addr)
                .await
                .expect("uplink cleanup retained relay socket");
        }
    }
}
