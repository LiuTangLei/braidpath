use super::{protocol::*, *};
use crate::runtime::{mesh, shutdown::Shutdown, stats, transport, tunnel};
use anyhow::{Context, bail};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    str::FromStr,
    sync::RwLock,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex as AsyncMutex, Semaphore},
    task::JoinSet,
    time::timeout,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub exit: String,
    pub address: SocketAddr,
}
impl FromStr for Listener {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let (exit, address) = s.split_once('=').context("use EXIT=127.0.0.1:PORT")?;
        ensure!(!exit.is_empty(), "missing exit id");
        let address: SocketAddr = address.parse()?;
        ensure!(
            address.ip().is_loopback(),
            "SOCKS5 listeners must use loopback addresses"
        );
        Ok(Self {
            exit: exit.into(),
            address,
        })
    }
}
pub struct ClientOptions {
    pub identity: mesh::ClientIdentity,
    pub connect: Vec<SocketAddr>,
    pub exits: Vec<String>,
    pub listen: SocketAddr,
    pub socks5: Vec<Listener>,
    pub game_exits: Vec<String>,
    pub game_listen: SocketAddr,
    pub game_socks5: Vec<Listener>,
    pub tcp_forward: Vec<Listener>,
    pub paths: usize,
    pub interface: Option<String>,
    pub socks5_early_reply: bool,
    pub game_socks5_early_reply: bool,
    pub status_socket: Option<std::path::PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SessionMode {
    Normal,
    Game,
}

impl SessionMode {
    fn label(self) -> &'static str {
        match self {
            Self::Normal => "socks",
            Self::Game => "game",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SessionKey {
    pub(super) exit: String,
    pub(super) mode: SessionMode,
}

impl SessionKey {
    pub(super) fn new(exit: impl Into<String>, mode: SessionMode) -> Self {
        Self {
            exit: exit.into(),
            mode,
        }
    }
}

impl std::fmt::Display for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.mode.label(), self.exit)
    }
}

pub(super) fn listener_plan(
    exits: &[String],
    base: SocketAddr,
    overrides: &[Listener],
) -> Result<Vec<Listener>> {
    ensure!(
        exits.len() <= crate::runtime::MAX_PATHS,
        "select at most eight exits per mode"
    );
    ensure!(
        base.ip().is_loopback(),
        "SOCKS5 listeners must use loopback addresses"
    );
    let mut by_exit = BTreeMap::new();
    for listener in overrides {
        ensure!(!listener.exit.is_empty(), "missing SOCKS5 exit");
        ensure!(
            listener.address.ip().is_loopback(),
            "SOCKS5 listeners must use loopback addresses"
        );
        ensure!(
            by_exit.insert(&listener.exit, listener.address).is_none(),
            "duplicate SOCKS5 listener for exit: {}",
            listener.exit
        );
    }
    let mut seen_exits = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut planned = exits
        .iter()
        .enumerate()
        .map(|(index, exit)| {
            ensure!(!exit.is_empty(), "missing SOCKS5 exit");
            ensure!(seen_exits.insert(exit), "duplicate proxy exit: {exit}");
            let address = match by_exit.remove(exit) {
                Some(address) => address,
                None => {
                    // Port zero requests a separate OS-assigned port for each exit.
                    let port = if base.port() == 0 {
                        0
                    } else {
                        base.port().checked_add(index as u16).context(
                            "SOCKS5 port range exceeds 65535; specify listener addresses",
                        )?
                    };
                    SocketAddr::new(base.ip(), port)
                }
            };
            ensure!(
                address.port() == 0 || addresses.insert(address),
                "duplicate SOCKS5 listener address: {address}"
            );
            Ok(Listener {
                exit: exit.clone(),
                address,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for (exit, address) in by_exit {
        ensure!(
            address.port() == 0 || addresses.insert(address),
            "duplicate SOCKS5 listener address: {address}"
        );
        planned.push(Listener {
            exit: exit.clone(),
            address,
        });
    }
    Ok(planned)
}
struct Routes {
    _guard: mesh::Entrances,
    updates: tokio::sync::watch::Receiver<Vec<SocketAddr>>,
}

struct Aggregate {
    connector: tunnel::tcp::Connector,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl Aggregate {
    fn running(&self) -> bool {
        self.task.as_ref().is_some_and(|task| !task.is_finished())
    }
    async fn shutdown(mut self) {
        self.connector.close();
        if let Some(mut task) = self.task.take()
            && timeout(CONNECT_TIMEOUT + Duration::from_secs(2), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for Aggregate {
    fn drop(&mut self) {
        self.connector.close();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn stop_slot(aggregate: Option<Aggregate>, routes: Option<Routes>) {
    if let Some(aggregate) = aggregate {
        aggregate.shutdown().await;
    }
    if let Some(routes) = routes {
        routes._guard.shutdown().await;
    }
}

struct Slot {
    routes: AsyncMutex<Option<Routes>>,
    route_nodes: Mutex<Option<tokio::sync::watch::Sender<Option<Vec<mesh::Node>>>>>,
    aggregate: AsyncMutex<Option<Aggregate>>,
    stream_metrics: stats::Metrics,
    #[cfg(test)]
    stream_health: Mutex<Option<tokio::sync::watch::Sender<mesh::PathHealth>>>,
    #[cfg(test)]
    test_stream_updates: Mutex<Option<tokio::sync::watch::Sender<Vec<SocketAddr>>>>,
    #[cfg(test)]
    test_routes: Mutex<Option<Vec<SocketAddr>>>,
}
pub(super) struct Pool {
    identity: mesh::ClientIdentity,
    interface: Option<String>,
    slots: BTreeMap<SessionKey, Slot>,
    nodes: RwLock<Vec<mesh::Node>>,
    nodes_changed: tokio::sync::Notify,
    path_limit: std::sync::atomic::AtomicUsize,
    pub(super) stream_budget: Arc<tunnel::tcp::Budget>,
    closed: std::sync::atomic::AtomicBool,
    shutdown_done: std::sync::atomic::AtomicBool,
    shutdown_complete: tokio::sync::Notify,
}
impl Pool {
    fn uplink(&self) -> mesh::Uplink {
        mesh::Uplink {
            interface: self.interface.clone(),
            ..mesh::Uplink::default()
        }
    }

    fn status_json(
        &self,
        socks_addresses: &BTreeMap<SessionKey, SocketAddr>,
        forwards: &Mutex<BTreeMap<String, (SocketAddr, stats::Metrics)>>,
    ) -> serde_json::Value {
        let (tcp_flows, buffered_bytes) = self.stream_budget.snapshot();
        let udp_flows = self.stream_budget.udp_flows();
        let mut node_ids: Vec<String> = self
            .nodes
            .read()
            .expect("mesh nodes")
            .iter()
            .map(|n| n.id.clone())
            .collect();
        node_ids.sort();
        let mut exits = serde_json::Map::new();
        for (key, slot) in &self.slots {
            let mut summary = crate::runtime::status_socket::metrics_summary(&slot.stream_metrics);
            summary["address"] = serde_json::json!(socks_addresses[key].to_string());
            summary["exit"] = serde_json::json!(key.exit);
            summary["mode"] = serde_json::json!(match key.mode {
                SessionMode::Normal => "normal",
                SessionMode::Game => "game",
            });
            exits.insert(key.to_string(), summary);
        }
        let mut tcp_forwards = serde_json::Map::new();
        for (exit, (addr, metrics)) in forwards.lock().expect("forward status").iter() {
            let mut summary = crate::runtime::status_socket::metrics_summary(metrics);
            if let Some(obj) = summary.as_object_mut() {
                obj.insert("address".into(), serde_json::json!(addr.to_string()));
            }
            tcp_forwards.insert(exit.clone(), summary);
        }
        let interface_index = self
            .interface
            .as_deref()
            .and_then(transport::interface_index);
        serde_json::json!({
            "schema_version": 2,
            "role": "proxy-client",
            "pid": std::process::id(),
            "path_limit": self.path_limit.load(std::sync::atomic::Ordering::Relaxed),
            "interface": self.interface,
            "interface_index": interface_index,
            "discovered_nodes": {
                "count": node_ids.len(),
                "ids": node_ids,
            },
            "budget": {
                "tcp_flows": tcp_flows,
                "udp_flows": udp_flows,
                "buffered_bytes": buffered_bytes,
                "max_tcp_flows": tunnel::tcp::MAX_TCP_FLOWS,
                "max_udp_flows": tunnel::tcp::MAX_UDP_FLOWS,
            },
            "exits": exits,
            "tcp_forwards": tcp_forwards,
        })
    }

    pub(super) fn new(
        identity: mesh::ClientIdentity,
        nodes: Vec<mesh::Node>,
        sessions: Vec<SessionKey>,
        interface: Option<String>,
    ) -> Result<Arc<Self>> {
        let mut slots = BTreeMap::new();
        for key in sessions {
            ensure!(!slots.contains_key(&key), "duplicate proxy session: {key}");
            let label = key.to_string();
            slots.insert(
                key,
                Slot {
                    routes: AsyncMutex::new(None),
                    route_nodes: Mutex::new(None),
                    aggregate: AsyncMutex::new(None),
                    stream_metrics: stats::Metrics::new("client").with_summary_label(label),
                    #[cfg(test)]
                    stream_health: Mutex::new(None),
                    #[cfg(test)]
                    test_stream_updates: Mutex::new(None),
                    #[cfg(test)]
                    test_routes: Mutex::new(None),
                },
            );
        }
        let _ = transport::token(&identity.dir.join("token"))?;
        Ok(Arc::new(Self {
            identity,
            interface,
            slots,
            nodes: RwLock::new(nodes),
            nodes_changed: tokio::sync::Notify::new(),
            path_limit: std::sync::atomic::AtomicUsize::new(4),
            stream_budget: Arc::new(tunnel::tcp::Budget::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
            shutdown_done: std::sync::atomic::AtomicBool::new(false),
            shutdown_complete: tokio::sync::Notify::new(),
        }))
    }
    fn has_exit(&self, id: &str) -> bool {
        self.nodes
            .read()
            .expect("proxy nodes")
            .iter()
            .any(|node| node.id == id)
    }
    fn stream_running(&self, key: &SessionKey) -> bool {
        self.slots
            .get(key)
            .and_then(|slot| slot.aggregate.try_lock().ok())
            .is_some_and(|guard| guard.as_ref().is_some_and(Aggregate::running))
    }
    async fn wait_for_exit_nodes(&self, id: &str) -> Result<Vec<mesh::Node>> {
        loop {
            ensure!(
                !self.closed.load(std::sync::atomic::Ordering::Acquire),
                "proxy client stopped"
            );
            let notified = self.nodes_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let nodes = self.nodes.read().expect("proxy nodes");
                if nodes.iter().any(|node| node.id == id) {
                    return Ok(nodes.clone());
                }
            }
            notified.await;
        }
    }
    async fn route_watch(
        &self,
        key: &SessionKey,
    ) -> Result<(
        tokio::sync::watch::Receiver<Vec<SocketAddr>>,
        tokio::sync::watch::Sender<mesh::PathHealth>,
    )> {
        ensure!(
            !self.closed.load(std::sync::atomic::Ordering::Acquire),
            "proxy client stopped"
        );
        let slot = self.slots.get(key).context("proxy session not selected")?;
        let mut routes = slot.routes.lock().await;
        if routes.is_none() {
            let nodes = self.wait_for_exit_nodes(&key.exit).await?;
            let limit = self.path_limit.load(std::sync::atomic::Ordering::Relaxed);
            let (_, guard) = self
                .identity
                .entrances_on(nodes, &key.exit, limit, &self.uplink())
                .await?;
            ensure!(
                !self.closed.load(std::sync::atomic::Ordering::Acquire),
                "proxy client stopped"
            );
            let nodes_tx = guard.nodes_sender();
            let latest = self.nodes.read().expect("proxy nodes").clone();
            let _ = nodes_tx.send(Some(latest));
            *slot.route_nodes.lock().expect("route nodes") = Some(nodes_tx);
            *routes = Some(Routes {
                updates: guard.updates(),
                _guard: guard,
            });
        }
        let routes = routes.as_ref().expect("proxy routes");
        Ok((routes.updates.clone(), routes._guard.health()))
    }
    /// Prepare one aggregate session without opening a destination.
    pub(super) async fn prepare_stream(&self, key: &SessionKey) -> Result<tunnel::tcp::Connector> {
        ensure!(
            !self.closed.load(std::sync::atomic::Ordering::Acquire),
            "proxy client stopped"
        );
        let slot = self.slots.get(key).context("proxy session not selected")?;
        {
            let aggregate = slot.aggregate.lock().await;
            if let Some(current) = aggregate
                .as_ref()
                .filter(|current| current.running() && !current.connector.is_closed())
            {
                let connector = current.connector.clone();
                drop(aggregate);
                connector.wait_ready().await?;
                return Ok(connector);
            }
        }
        // Each session owns its entrance leases and reports its own path health.
        let (updates, health) = self.route_watch(key).await?;
        let connector = {
            let mut aggregate = slot.aggregate.lock().await;
            if let Some(current) = aggregate
                .as_ref()
                .filter(|current| current.running() && !current.connector.is_closed())
            {
                current.connector.clone()
            } else {
                if let Some(old) = aggregate.take() {
                    old.shutdown().await;
                }
                #[cfg(test)]
                let updates = {
                    *slot.stream_health.lock().expect("stream health") = Some(health.clone());
                    if let Some(addresses) = slot.test_routes.lock().expect("test routes").clone() {
                        let (sender, receiver) = tokio::sync::watch::channel(addresses);
                        *slot.test_stream_updates.lock().expect("test stream routes") =
                            Some(sender);
                        receiver
                    } else {
                        updates
                    }
                };
                let connector = tunnel::tcp::Connector::new(self.stream_budget.clone());
                let options = tunnel::ClientOptions {
                    adaptive_fec_retention: false,
                    rotate_source_port: false,
                    listen: "127.0.0.1:0".parse().expect("loopback address"),
                    tcp_listen: None,
                    proxy_listen: None,
                    stream_connector: Some(connector.clone()),
                    entrances: updates.borrow().clone(),
                    interfaces: self.interface.iter().cloned().collect(),
                    path_binds: vec![],
                    datagram_send_buffer_bytes: transport::MAX_DATAGRAM_SEND_BUFFER_BYTES,
                    path_groups: vec![],
                    name: self.identity.name(),
                    ca: self.identity.dir.join("cert.pem"),
                    token: self.identity.dir.join("token"),
                    policy: reliable_policy(key.mode),
                    congestion: transport::Congestion::Bbr,
                    stats: slot.stream_metrics.clone(),
                };
                ensure!(
                    !self.closed.load(std::sync::atomic::Ordering::Acquire),
                    "proxy client stopped"
                );
                let key = key.clone();
                let closer = connector.clone();
                let task = tokio::spawn(async move {
                    let result = tunnel::client_with_mesh_exit(
                        options,
                        Some(updates),
                        Some(health),
                        key.exit.clone(),
                    )
                    .await;
                    closer.close();
                    if let Err(error) = &result {
                        tracing::warn!(session = %key, %error, "aggregate proxy session stopped");
                    }
                    result
                });
                *aggregate = Some(Aggregate {
                    connector: connector.clone(),
                    task: Some(task),
                });
                connector
            }
        };
        connector.wait_ready().await?;
        Ok(connector)
    }
    pub(super) async fn open_stream(
        &self,
        key: &SessionKey,
        target: Address,
        early_reply: bool,
    ) -> Result<tunnel::tcp::Flow> {
        let connector = self.prepare_stream(key).await?;
        connector.open(target.into(), early_reply).await
    }
    #[cfg(test)]
    pub(super) fn test_stream_metrics(&self, key: &SessionKey) -> stats::Metrics {
        self.slots[key].stream_metrics.clone()
    }

    #[cfg(test)]
    pub(super) fn transport_snapshot(
        &self,
        key: &SessionKey,
    ) -> BTreeMap<SocketAddr, (u64, u64, u64, u64)> {
        let slot = &self.slots[key];
        let _ = slot.stream_metrics.snapshot(false, "observed", None);
        let mut paths = BTreeMap::new();
        slot.stream_metrics.state(|state| {
            for path in state.paths.values().filter(|path| {
                path.authenticated
                    && !path.quinn.closed
                    && !state.retired_sessions.contains(&path.session_id)
            }) {
                if let Ok(address) = path.peer_socket.parse() {
                    paths.insert(
                        address,
                        (
                            (path.quinn.smoothed_rtt_ms * 1000.0) as u64,
                            path.quinn.congestion_window_bytes,
                            path.quinn.sent_packets,
                            path.quinn.lost_packets,
                        ),
                    );
                }
            }
        });
        paths
    }
    #[cfg(test)]
    pub(super) fn test_path_failed(&self, key: &SessionKey, address: SocketAddr) -> bool {
        let health = self.slots[key].stream_health.lock().unwrap();
        let Some(health) = health.as_ref() else {
            return true;
        };
        // Missing evidence during startup or reconnect is not a healthy path.
        health
            .borrow()
            .samples
            .iter()
            .find(|sample| sample.address == address)
            .is_none_or(|sample| sample.failed)
    }
    #[cfg(test)]
    pub(super) fn set_path_limit(&self, limit: usize) {
        self.path_limit
            .store(limit, std::sync::atomic::Ordering::Relaxed);
    }
    pub(super) async fn shutdown(self: &Arc<Self>) {
        if !self.closed.swap(true, std::sync::atomic::Ordering::AcqRel) {
            self.nodes_changed.notify_waiters();
            // This task owns the complete traversal, including async Slot locks.
            // No handle is kept in Pool, so there is no owner/handle reference cycle.
            let owner = self.clone();
            tokio::spawn(async move {
                owner.shutdown_inner().await;
                owner
                    .shutdown_done
                    .store(true, std::sync::atomic::Ordering::Release);
                owner.shutdown_complete.notify_waiters();
            });
        }
        loop {
            let complete = self.shutdown_complete.notified();
            tokio::pin!(complete);
            complete.as_mut().enable();
            if self
                .shutdown_done
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            complete.await;
        }
    }
    async fn shutdown_inner(&self) {
        let mut releases = Vec::with_capacity(self.slots.len());
        for slot in self.slots.values() {
            let mut aggregate = slot.aggregate.lock().await;
            let mut routes = slot.routes.lock().await;
            slot.route_nodes.lock().expect("route nodes").take();
            // Dropping a waiter detaches this task; it must not abort cleanup
            // and release the guard while its aggregate runtime still runs.
            releases.push(tokio::spawn(stop_slot(aggregate.take(), routes.take())));
        }
        for release in releases {
            let _ = release.await;
        }
    }
    #[cfg(test)]
    pub(super) fn test_set_routes(&self, key: &SessionKey, routes: Vec<SocketAddr>) {
        if let Some(updates) = self.slots[key].test_stream_updates.lock().unwrap().as_ref() {
            updates.send_replace(routes.clone());
        }
        *self.slots[key].test_routes.lock().unwrap() = Some(routes);
    }
    #[cfg(test)]
    pub(super) async fn test_addresses(&self, key: &SessionKey) -> Vec<SocketAddr> {
        if let Some(routes) = self.slots[key].test_routes.lock().unwrap().clone() {
            return routes;
        }
        let (updates, _) = self.route_watch(key).await.unwrap();
        updates.borrow().clone()
    }
    fn refresh(&self, nodes: &[mesh::Node]) -> Option<Vec<mesh::Node>> {
        let mut current = self.nodes.write().expect("proxy nodes");
        // Merge incoming nodes by ID so a partial view of one exit never drops
        // another selected exit learned from a different peer or cache.
        let mut by_id: BTreeMap<String, mesh::Node> = current
            .iter()
            .cloned()
            .map(|node| (node.id.clone(), node))
            .collect();
        for node in nodes.iter().cloned() {
            by_id.insert(node.id.clone(), node);
        }
        let merged: Vec<mesh::Node> = by_id.into_values().collect();
        if *current == merged {
            return None;
        }
        *current = merged.clone();
        drop(current);
        for slot in self.slots.values() {
            if let Some(tx) = slot.route_nodes.lock().expect("route nodes").as_ref() {
                let _ = tx.send(Some(merged.clone()));
            }
        }
        self.nodes_changed.notify_waiters();
        Some(merged)
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        let mut owned = Vec::new();
        for slot in self.slots.values_mut() {
            let aggregate = slot.aggregate.get_mut().take();
            let routes = slot.routes.get_mut().take();
            if let Some(current) = &aggregate {
                current.connector.close();
            }
            if aggregate.is_some() || routes.is_some() {
                owned.push((aggregate, routes));
            }
        }
        if owned.is_empty() {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let stopping: Vec<_> = owned
                .into_iter()
                .map(|(aggregate, routes)| runtime.spawn(stop_slot(aggregate, routes)))
                .collect();
            runtime.spawn(async move {
                for task in stopping {
                    let _ = task.await;
                }
            });
        }
    }
}

fn reliable_policy(mode: SessionMode) -> tunnel::Policy {
    let game_mode = mode == SessionMode::Game;
    let mut policy = tunnel::Policy {
        game_mode: false,
        native_return: true,
        max_message_bytes: if game_mode {
            crate::runtime::MAX_MESSAGE
        } else {
            crate::runtime::MAX_PAYLOAD
        },
        streams: false,
        proxy: true,
        adaptive: true,
        capacity_probe_bps: 0,
        probe_guided_recovery: false,
        latency_target_ms: 20,
        group_rates: [crate::runtime::MAX_RATE_BPS; crate::runtime::MAX_PATHS],
        receiver_feedback: true,
        quality_schedule: true,
        fec: crate::runtime::automatic_fec::AUTO,
        fec_repairs: 1,
        small_fec_bytes: 0,
        mixed_fec: false,
        redundancy: 30,
        rate: crate::runtime::MAX_RATE_BPS,
        block_ms: 3,
        queue_ms: 100,
    };
    if game_mode {
        policy.enable_game();
    }
    policy
}

pub(super) fn validate_listeners(
    normal: &[Listener],
    game: &[Listener],
    forwards: &[Listener],
) -> Result<BTreeSet<String>> {
    let total = normal.len() + game.len() + forwards.len();
    ensure!(
        total > 0,
        "configure at least one SOCKS5 or fixed TCP listener"
    );
    ensure!(
        total <= mesh::MAX_SOURCE_LEASES,
        "at most {} proxy sessions per process",
        mesh::MAX_SOURCE_LEASES
    );
    ensure!(
        forwards.len() <= crate::runtime::MAX_PATHS,
        "at most eight fixed TCP forwards"
    );
    let mut fixed_exits = BTreeSet::new();
    for listener in forwards {
        ensure!(!listener.exit.is_empty(), "missing fixed TCP exit");
        ensure!(
            listener.address.ip().is_loopback(),
            "fixed TCP listeners must use loopback addresses"
        );
        ensure!(
            fixed_exits.insert(&listener.exit),
            "duplicate fixed TCP exit: {}",
            listener.exit
        );
    }
    let mut addresses = BTreeSet::new();
    let mut wanted = BTreeSet::new();
    for listener in normal.iter().chain(game).chain(forwards) {
        ensure!(
            listener.address.port() == 0 || addresses.insert(listener.address),
            "duplicate local listener address: {}",
            listener.address
        );
        wanted.insert(listener.exit.clone());
    }
    ensure!(
        wanted.len() <= crate::runtime::MAX_PATHS,
        "select at most eight mesh exits"
    );
    Ok(wanted)
}

struct FixedForwardConfig {
    identity: mesh::ClientIdentity,
    mapping: Listener,
    listener: Arc<TcpListener>,
    paths: usize,
    interface: Option<String>,
    metrics: stats::Metrics,
}

async fn fixed_forward_once(
    config: &FixedForwardConfig,
    nodes: Vec<mesh::Node>,
    mut nodes_rx: tokio::sync::watch::Receiver<Vec<mesh::Node>>,
) -> Result<()> {
    let uplink = mesh::Uplink {
        interface: config.interface.clone(),
        ..Default::default()
    };
    let (entrances, leases) = config
        .identity
        .entrances_on(nodes, &config.mapping.exit, config.paths, &uplink)
        .await?;
    let lease_nodes = leases.nodes_sender();
    let latest = nodes_rx.borrow_and_update().clone();
    let _ = lease_nodes.send(Some(latest));
    let mut policy = reliable_policy(SessionMode::Normal);
    policy.proxy = false;
    policy.streams = true;
    let options = tunnel::ClientOptions {
        adaptive_fec_retention: false,
        rotate_source_port: false,
        listen: "127.0.0.1:0".parse().expect("loopback address"),
        tcp_listen: None,
        proxy_listen: None,
        stream_connector: None,
        entrances,
        interfaces: config.interface.iter().cloned().collect(),
        path_binds: vec![],
        path_groups: vec![],
        name: config.identity.name(),
        ca: config.identity.dir.join("cert.pem"),
        token: config.identity.dir.join("token"),
        datagram_send_buffer_bytes: transport::MAX_DATAGRAM_SEND_BUFFER_BYTES,
        congestion: transport::Congestion::Bbr,
        policy,
        stats: config.metrics.clone(),
    };
    let push_nodes = async move {
        while nodes_rx.changed().await.is_ok() {
            let _ = lease_nodes.send(Some(nodes_rx.borrow_and_update().clone()));
        }
        std::future::pending::<()>().await
    };
    let result = tokio::select! {
        res = tunnel::client_with_fixed_listener(
            options,
            leases.updates(),
            leases.health(),
            config.mapping.exit.clone(),
            config.listener.clone(),
        ) => res,
        _ = push_nodes => unreachable!(),
    };
    leases.shutdown().await;
    result
}

async fn fixed_forward_supervisor(
    config: FixedForwardConfig,
    mut nodes_rx: tokio::sync::watch::Receiver<Vec<mesh::Node>>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if *stop_rx.borrow() {
            return;
        }
        let nodes = loop {
            if *stop_rx.borrow() {
                return;
            }
            let current = nodes_rx.borrow_and_update().clone();
            if current.iter().any(|n| n.id == config.mapping.exit) {
                break current;
            }
            tokio::select! {
                _ = stop_rx.changed() => return,
                changed = nodes_rx.changed() => {
                    if changed.is_err() { return; }
                }
            }
        };
        let started = Instant::now();
        let result = tokio::select! {
            _ = stop_rx.changed() => return,
            result = fixed_forward_once(&config, nodes, nodes_rx.clone()) => result,
        };
        if *stop_rx.borrow() {
            return;
        }
        if started.elapsed() >= Duration::from_secs(30) {
            backoff = Duration::from_secs(1);
        }
        match result {
            Ok(()) => return,
            Err(error) => {
                tracing::warn!(
                    exit = %config.mapping.exit,
                    retry_secs = backoff.as_secs(),
                    %error,
                    "fixed TCP forward unavailable; retaining listener and retrying"
                );
            }
        }
        tokio::select! {
            _ = stop_rx.changed() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(15));
    }
}

pub async fn client(options: ClientOptions) -> Result<()> {
    ensure!(
        !options.connect.is_empty() && options.connect.len() <= 32,
        "provide 1..32 discovery entries"
    );
    ensure!(
        (1..=crate::runtime::MAX_PATHS).contains(&options.paths),
        "invalid proxy path limit"
    );
    let normal = listener_plan(&options.exits, options.listen, &options.socks5)?;
    let game = listener_plan(
        &options.game_exits,
        options.game_listen,
        &options.game_socks5,
    )?;
    let wanted = validate_listeners(&normal, &game, &options.tcp_forward)?;
    let initial_nodes = options.identity.cached_nodes();
    let fixed_identity = options.identity.clone();
    let fixed_interface = options.interface.clone();
    // Bind every requested port before touching the network so cold boots and
    // transient WAN outages keep local listeners bound and never crash-loop.
    let mut listeners = Vec::with_capacity(normal.len() + game.len());
    let mut socks_addresses = BTreeMap::new();
    for (mode, planned) in [(SessionMode::Normal, normal), (SessionMode::Game, game)] {
        for listener in planned {
            let key = SessionKey::new(listener.exit, mode);
            let socket = TcpListener::bind(listener.address)
                .await
                .with_context(|| format!("bind {key} at {}", listener.address))?;
            socks_addresses.insert(key.clone(), socket.local_addr()?);
            listeners.push((socket, key));
        }
    }
    let mut forwards = Vec::with_capacity(options.tcp_forward.len());
    for mapping in options.tcp_forward {
        let listener = Arc::new(TcpListener::bind(mapping.address).await.with_context(|| {
            format!("bind fixed TCP for {} at {}", mapping.exit, mapping.address)
        })?);
        forwards.push((mapping, listener));
    }
    let pool = Pool::new(
        options.identity,
        initial_nodes.clone(),
        socks_addresses.keys().cloned().collect(),
        options.interface,
    )?;
    pool.path_limit
        .store(options.paths, std::sync::atomic::Ordering::Relaxed);
    let (nodes_tx, nodes_rx) = tokio::sync::watch::channel(initial_nodes);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let normal_permits = Arc::new(Semaphore::new(tunnel::tcp::MAX_TCP_FLOWS));
    let game_permits = Arc::new(Semaphore::new(tunnel::tcp::MAX_TCP_FLOWS));
    let forward_status = Arc::new(Mutex::new(BTreeMap::new()));
    let mut tasks = JoinSet::new();
    let mut forward_tasks = JoinSet::new();
    for (mapping, listener) in forwards {
        let local_addr = listener.local_addr()?;
        tracing::info!(address=%local_addr, exit=%mapping.exit, "fixed TCP forward bound");
        let metrics = stats::Metrics::new("fixed-forward")
            .with_summary_label(format!("fixed:{}", mapping.exit));
        forward_status
            .lock()
            .expect("forward status")
            .insert(mapping.exit.clone(), (local_addr, metrics.clone()));
        forward_tasks.spawn(fixed_forward_supervisor(
            FixedForwardConfig {
                identity: fixed_identity.clone(),
                mapping,
                listener,
                paths: options.paths,
                interface: fixed_interface.clone(),
                metrics,
            },
            nodes_rx.clone(),
            stop_rx.clone(),
        ));
    }
    let _status_guard = if let Some(path) = options.status_socket {
        let status_pool = pool.clone();
        let status_forwards = forward_status.clone();
        Some(crate::runtime::status_socket::spawn(
            path,
            Arc::new(move || status_pool.status_json(&socks_addresses, &status_forwards)),
        )?)
    } else {
        None
    };
    for (listener, key) in listeners {
        tracing::info!(address=%listener.local_addr()?, session=%key, "SOCKS5 proxy ready");
        let (permits, early_reply) = match key.mode {
            SessionMode::Normal => (&normal_permits, options.socks5_early_reply),
            SessionMode::Game => (&game_permits, options.game_socks5_early_reply),
        };
        tasks.spawn(listen(
            listener,
            pool.clone(),
            key,
            permits.clone(),
            early_reply,
        ));
    }
    let mut discovery: JoinSet<Result<()>> = JoinSet::new();
    let mut stream_nodes = nodes_rx;
    let mut warmups: JoinSet<()> = JoinSet::new();
    let spawn_discovery = |discovery: &mut JoinSet<Result<()>>, pool: &Arc<Pool>| {
        let pool = pool.clone();
        let entries = options.connect.clone();
        let wanted = wanted.clone();
        let nodes_tx = nodes_tx.clone();
        discovery.spawn(async move {
            let uplink = pool.uplink();
            pool.identity
                .discover_progressively_on(&entries, &uplink, &wanted, |nodes| {
                    if let Some(merged) = pool.refresh(nodes) {
                        nodes_tx.send_replace(merged);
                    }
                })
                .await
        });
    };
    let spawn_warmups = |warmups: &mut JoinSet<()>, pool: &Arc<Pool>| {
        for key in pool.slots.keys() {
            if pool.has_exit(&key.exit) && !pool.stream_running(key) {
                let pool = pool.clone();
                let key = key.clone();
                warmups.spawn(async move {
                    if let Err(error) = pool.prepare_stream(&key).await {
                        tracing::warn!(session=%key, %error, "aggregate proxy session unavailable");
                    }
                });
            }
        }
    };
    // Warm up exits already known from the persistent node cache immediately
    // while fresh discovery runs in parallel.
    spawn_warmups(&mut warmups, &pool);
    spawn_discovery(&mut discovery, &pool);
    let mut bootstrap_backoff = Duration::from_secs(1);
    let mut next_discovery = tokio::time::Instant::now() + Duration::from_secs(15);
    // The aggregate runtime publishes path health; only native UDP caches
    // need this periodic retirement check after discovered exit address changes.
    let mut maintenance = tokio::time::interval(Duration::from_secs(1));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut diagnostics: Option<tokio::task::JoinHandle<()>> = None;
    let mut shutdown = Shutdown::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait() => break,
            _ = maintenance.tick() => {
                if tracing::enabled!(tracing::Level::DEBUG)
                    && diagnostics.as_ref().is_none_or(|task| task.is_finished())
                {
                    let metrics: Vec<_> = pool.slots.iter()
                        .map(|(key, slot)| (key.clone(), slot.stream_metrics.clone()))
                        .collect();
                    // JSON encoding and debug output must not occupy a network
                    // worker. One bounded job serves every selected exit; a slow
                    // sink skips ticks instead of queuing diagnostic work.
                    diagnostics = Some(tokio::task::spawn_blocking(move || {
                        for (key, metrics) in metrics {
                            if let Ok(snapshot) = metrics.snapshot(false, "observed", None) {
                                tracing::debug!(session=%key, %snapshot, "proxy aggregate statistics");
                            }
                        }
                    }));
                }
            },
            result = tasks.join_next(), if !tasks.is_empty() => {
                result.context("proxy listeners stopped")???;
                bail!("proxy listener stopped");
            }
            _ = forward_tasks.join_next(), if !forward_tasks.is_empty() => {}
            _ = warmups.join_next(), if !warmups.is_empty() => {}
            _ = tokio::time::sleep_until(next_discovery), if discovery.is_empty() => {
                spawn_discovery(&mut discovery, &pool);
            }
            _ = stream_nodes.changed() => {
                spawn_warmups(&mut warmups, &pool);
            }
            Some(result) = discovery.join_next(), if !discovery.is_empty() => {
                let missing: Vec<_> = wanted.iter().filter(|exit| !pool.has_exit(exit)).collect();
                if missing.is_empty() {
                    bootstrap_backoff = Duration::from_secs(1);
                    next_discovery = tokio::time::Instant::now() + Duration::from_secs(15);
                    if !matches!(result, Ok(Ok(()))) {
                        tracing::debug!(?result, "periodic mesh discovery unavailable");
                    }
                    spawn_warmups(&mut warmups, &pool);
                } else {
                    tracing::warn!(
                        ?missing, ?result, retry_secs = bootstrap_backoff.as_secs(),
                        "some proxy exits not yet discovered; retaining local listeners and retrying"
                    );
                    next_discovery = tokio::time::Instant::now() + bootstrap_backoff;
                    bootstrap_backoff = (bootstrap_backoff * 2).min(Duration::from_secs(15));
                }
            }
        }
    }
    let _ = stop_tx.send(true);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    forward_tasks.abort_all();
    while forward_tasks.join_next().await.is_some() {}
    warmups.abort_all();
    while warmups.join_next().await.is_some() {}
    discovery.abort_all();
    while discovery.join_next().await.is_some() {}
    pool.shutdown().await;
    if let Some(diagnostics) = diagnostics {
        let _ = diagnostics.await;
    }
    Ok(())
}
pub(super) async fn listen(
    listener: TcpListener,
    pool: Arc<Pool>,
    key: SessionKey,
    permits: Arc<Semaphore>,
    early_reply: bool,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                tcp.set_nodelay(true)?;
                let pool = pool.clone();
                let key = key.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = super::socks::serve(tcp, pool, &key, early_reply).await { tracing::debug!(%error, session=%key, "SOCKS5 client closed"); }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::path::Path as FsPath;

    fn normal(exit: &str) -> SessionKey {
        SessionKey::new(exit, SessionMode::Normal)
    }

    fn pool(root: &FsPath) -> Arc<Pool> {
        let server = root.join("server");
        transport::initialize(&server, "localhost").unwrap();
        let key = root.join("client-key.json");
        std::fs::write(
            &key,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "certificate": std::fs::read_to_string(server.join("cert.pem")).unwrap(),
                "token": std::fs::read_to_string(server.join("token")).unwrap(),
            }))
            .unwrap(),
        )
        .unwrap();
        let identity = mesh::ClientIdentity::open(root.join("client"), &key).unwrap();
        Pool::new(
            identity,
            vec![mesh::Node {
                id: "exit".into(),
                address: "127.0.0.1:1".parse().unwrap(),
                alternate: None,
                incarnation: 0,
            }],
            vec![normal("exit")],
            None,
        )
        .unwrap()
    }

    async fn mesh_server(
        root: &FsPath,
        id: &str,
        join: Option<SocketAddr>,
    ) -> (SocketAddr, AbortTask) {
        let address = mesh::tests::address();
        let metrics = stats::Metrics::new("test-proxy-cleanup");
        let options = mesh::ServerOptions {
            dir: root.join(id),
            id: id.into(),
            listen: address,
            advertise: address,
            advertise_alternate: None,
            relay_ports: None,
            target: None,
            tcp_target: None,
            proxy: Some(ServerConfig {
                allow_private: true,
            }),
            join,
            join_key: join.map(|_| root.join("a/server-key.json")),
            rate: crate::runtime::MAX_RATE_BPS,
            stats: metrics.clone(),
        };
        let task = AbortTask(tokio::spawn(async move {
            mesh::serve(options)
                .await
                .expect("cleanup test mesh server failed");
        }));
        timeout(Duration::from_secs(3), async {
            while !metrics.is_ready() {
                assert!(
                    !task.0.is_finished(),
                    "cleanup test mesh exited before readiness"
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        (address, task)
    }

    #[tokio::test]
    async fn aggregate_snapshot_excludes_cold_and_closed_connections() {
        let root = tempfile::tempdir().unwrap();
        let pool = pool(root.path());
        let server = transport::server_with_proxy(
            "127.0.0.1:0".parse().unwrap(),
            &root.path().join("server/cert.pem"),
            &root.path().join("server/key.pem"),
            transport::Congestion::Bbr,
            transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            transport::AckRequest::Unchanged,
            true,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let client = transport::client_bound_with_session_alpn(
            address,
            &pool.identity.dir.join("cert.pem"),
            None,
            transport::Congestion::Bbr,
            None,
            transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            transport::AckRequest::Unchanged,
            true,
            false,
        )
        .unwrap();
        let (outgoing, incoming) = timeout(Duration::from_secs(3), async {
            tokio::join!(client.connect(address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await
            })
        })
        .await
        .unwrap();
        let outgoing = outgoing.unwrap();
        let _incoming = incoming.unwrap();
        let slot = &pool.slots[&normal("exit")];
        slot.stream_metrics
            .register("active", 0, 0, stats::FORWARD, &outgoing);
        slot.stream_metrics
            .scope("active", stats::FORWARD)
            .path(1, |path| {
                path.peer_socket = "127.0.0.1:9".into();
            });
        assert_eq!(
            pool.transport_snapshot(&normal("exit"))
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [address]
        );
        outgoing.close(0u32.into(), b"test closed path");
        assert!(pool.transport_snapshot(&normal("exit")).is_empty());
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn cancelling_shutdown_waiter_keeps_runtime_cleanup_owned() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let root = tempfile::tempdir().unwrap();
        let pool = pool(root.path());
        let connector = tunnel::tcp::Connector::new(pool.stream_budget.clone());
        let stopped = connector.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let observed = finished.clone();
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let runtime = tokio::spawn(async move {
            stopped.closed().await;
            entered.send(()).unwrap();
            released.await.unwrap();
            observed.store(true, Ordering::Release);
            Ok(())
        });
        let slot = &pool.slots[&normal("exit")];
        *slot.aggregate.lock().await = Some(Aggregate {
            connector,
            task: Some(runtime),
        });
        let shutting_down = pool.clone();
        let waiter = tokio::spawn(async move { shutting_down.shutdown().await });
        timeout(Duration::from_secs(3), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(!finished.load(Ordering::Acquire));
        waiter.abort();
        let _ = waiter.await;
        assert!(!finished.load(Ordering::Acquire));
        release.send(()).unwrap();
        timeout(Duration::from_secs(3), async {
            while !finished.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelling the shutdown waiter cancelled owned cleanup");
        assert_eq!(pool.stream_budget.snapshot(), (0, 0));
    }

    #[tokio::test]
    async fn cancelled_shutdown_waiter_still_cleans_all_exits_after_a_slot_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let root = tempfile::tempdir().unwrap();
        let (a, _server_a) = mesh_server(root.path(), "a", None).await;
        let (b, _server_b) = mesh_server(root.path(), "b", Some(a)).await;
        // A newly joining relay immediately probes its known endpoints. The
        // first server otherwise verifies a later join only on its 5 s tick.
        let (c, _server_c) = mesh_server(root.path(), "c", Some(b)).await;
        let identity = mesh::ClientIdentity::open(
            root.path().join("client"),
            &root.path().join("a/client-key.json"),
        )
        .unwrap();
        // Listener readiness is not member liveness. Observe the relay's real
        // authenticated directory before allocating either exit's owned lease.
        let nodes = timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(nodes) = identity.discover(c).await
                    && [("a", a), ("b", b), ("c", c)].iter().all(|(id, address)| {
                        nodes
                            .iter()
                            .any(|node| node.id == *id && node.address == *address)
                    })
                {
                    break nodes;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("cleanup relay did not verify both live exits");
        let pool = Pool::new(
            identity.clone(),
            nodes.clone(),
            vec![normal("a"), normal("b")],
            None,
        )
        .unwrap();
        let mut finished = Vec::new();
        let (first_closed, closed) = tokio::sync::oneshot::channel();
        let mut first_closed = Some(first_closed);
        for exit in ["a", "b"] {
            let candidates = nodes
                .iter()
                .filter(|node| node.id == exit || node.id == "c")
                .cloned()
                .collect();
            let (_, guard) = identity.entrances(candidates, exit, 2).await.unwrap();
            let mut updates = guard.updates();
            // The guard publishes only allocations it actually owns. Wait for
            // that event before adding a synthetic runtime to this lifecycle test.
            timeout(Duration::from_secs(3), async {
                loop {
                    if updates.borrow_and_update().len() == 2 {
                        break;
                    }
                    updates
                        .changed()
                        .await
                        .expect("cleanup guard stopped before allocation");
                }
            })
            .await
            .unwrap_or_else(|_| panic!("cleanup guard for {exit} did not publish its relay lease"));
            let slot = &pool.slots[&normal(exit)];
            *slot.routes.lock().await = Some(Routes {
                updates,
                _guard: guard,
            });
            let connector = tunnel::tcp::Connector::new(pool.stream_budget.clone());
            let stopped = connector.clone();
            let completed = Arc::new(AtomicBool::new(false));
            let observed = completed.clone();
            let entered = if exit == "a" {
                first_closed.take()
            } else {
                None
            };
            let task = tokio::spawn(async move {
                stopped.closed().await;
                if let Some(entered) = entered {
                    entered.send(()).unwrap();
                }
                observed.store(true, Ordering::Release);
                Ok(())
            });
            *slot.aggregate.lock().await = Some(Aggregate {
                connector,
                task: Some(task),
            });
            finished.push(completed);
        }
        assert_eq!(identity.status(c).await.unwrap().leases, 2);

        // The shutdown owner must suspend on the second exit after starting
        // cleanup for the first. Keep an external Pool Arc throughout.
        let second = pool.slots[&normal("b")].aggregate.lock().await;
        let waiting_pool = pool.clone();
        let waiter = tokio::spawn(async move { waiting_pool.shutdown().await });
        timeout(Duration::from_secs(3), closed)
            .await
            .unwrap()
            .unwrap();
        waiter.abort();
        let _ = waiter.await;
        assert!(!finished[1].load(Ordering::Acquire));
        drop(second);
        timeout(Duration::from_secs(3), pool.shutdown())
            .await
            .expect("cancelled waiter stranded another exit");
        assert!(finished.iter().all(|done| done.load(Ordering::Acquire)));
        assert_eq!(identity.status(a).await.unwrap().leases, 0);
        assert_eq!(identity.status(b).await.unwrap().leases, 0);
        assert_eq!(identity.status(c).await.unwrap().leases, 0);
        assert_eq!(pool.stream_budget.snapshot(), (0, 0));
        assert_eq!(
            Arc::strong_count(&pool),
            1,
            "shutdown owner retained Pool after completion"
        );
    }
}
