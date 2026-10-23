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
    guards: Vec<Entrances>,
    routes: watch::Receiver<Vec<Route>>,
    health: watch::Sender<PathHealth>,
    bridge: AbortTask,
}
impl Networks {
    pub(crate) fn routes(&self) -> watch::Receiver<Vec<Route>> {
        self.routes.clone()
    }
    pub(crate) fn health(&self) -> watch::Sender<PathHealth> {
        self.health.clone()
    }
    pub async fn shutdown(self) {
        self.bridge.0.abort();
        let mut cleanup = JoinSet::new();
        for guard in self.guards {
            cleanup.spawn(guard.shutdown());
        }
        while cleanup.join_next().await.is_some() {}
    }
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
        ensure!(
            !uplinks.is_empty() && uplinks.len() <= MAX_PATHS,
            "uplink count must be 1..8"
        );
        let mut groups = std::collections::BTreeSet::new();
        for uplink in &uplinks {
            ensure!(
                usize::from(uplink.group) < MAX_PATHS && groups.insert(uplink.group),
                "uplink groups must be distinct and below eight"
            );
        }
        let mut guards = Vec::new();
        for (index, uplink) in uplinks.iter().enumerate() {
            let limit = MAX_PATHS / uplinks.len() + usize::from(index < MAX_PATHS % uplinks.len());
            let nodes: Vec<_> = nodes
                .iter()
                .filter(|n| uplink.supports(n.address))
                .cloned()
                .collect();
            let (_, guard) =
                Entrances::start_bound(self, nodes, exit, limit, Duration::from_secs(15), uplink)
                    .await?;
            guards.push(guard);
        }
        let mut updates: Vec<_> = guards.iter().map(Entrances::updates).collect();
        let reporters: Vec<_> = guards.iter().map(Entrances::health).collect();
        let collect = |updates: &mut [watch::Receiver<Vec<SocketAddr>>]| {
            updates
                .iter_mut()
                .zip(&uplinks)
                .flat_map(|(rx, uplink)| {
                    rx.borrow_and_update()
                        .iter()
                        .map(|address| Route {
                            address: *address,
                            uplink: uplink.clone(),
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        let (tx, routes) = watch::channel(collect(&mut updates));
        let (health, mut observed) = watch::channel(PathHealth::default());
        // One bounded bridge, no per-packet task. The 200 ms tick also coalesces
        // simultaneous membership updates across interfaces.
        let bridge = AbortTask(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(200));
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let next: Vec<_> = updates.iter_mut().zip(&uplinks).flat_map(|(rx, uplink)| rx.borrow_and_update().iter().map(|address| Route { address: *address, uplink: uplink.clone() }).collect::<Vec<_>>()).collect();
                        tx.send_if_modified(|old| if *old == next {false} else {*old = next; true});
                    }
                    result = observed.changed() => {
                        if result.is_err() { break; }
                        let all = observed.borrow_and_update();
                        for (reporter, uplink) in reporters.iter().zip(&uplinks) {
                            let samples: Vec<_> = all.samples.iter().filter(|s| s.group == uplink.group).cloned().collect();
                            reporter.send_replace(PathHealth { checked: all.checked, addresses: samples.iter().map(|s| s.address).collect(), samples });
                        }
                    }
                }
            }
        }));
        Ok(Networks {
            guards,
            routes,
            health,
            bridge,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Task, address, policy, server, wait_nodes};
    use super::*;

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
            .networks(discovered, "exit", uplinks)
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
