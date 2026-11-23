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
    pub tcp_forward: Vec<Listener>,
    pub paths: usize,
    pub interface: Option<String>,
    pub socks5_early_reply: bool,
    pub game_mode: bool,
}

pub(super) fn listener_plan(
    exits: &[String],
    base: SocketAddr,
    overrides: &[Listener],
) -> Result<Vec<Listener>> {
    ensure!(
        !exits.is_empty() && exits.len() <= 8,
        "select 1..8 proxy exits"
    );
    ensure!(
        base.ip().is_loopback(),
        "SOCKS5 listeners must use loopback addresses"
    );
    let mut by_exit = BTreeMap::new();
    for listener in overrides {
        ensure!(
            exits.contains(&listener.exit),
            "SOCKS5 listener exit not selected: {}",
            listener.exit
        );
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
    exits
        .iter()
        .enumerate()
        .map(|(index, exit)| {
            ensure!(seen_exits.insert(exit), "duplicate proxy exit: {exit}");
            let address = match by_exit.get(exit) {
                Some(address) => *address,
                None => {
                    // Port zero requests a separate OS-assigned port for each exit.
                    let port = if base.port() == 0 {
                        0
                    } else {
                        base.port()
                            .checked_add(index as u16)
                            .context("SOCKS5 port range exceeds 65535; use --socks5 EXIT=ADDRESS")?
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
        .collect()
}
struct Routes {
    _guard: mesh::Entrances,
    updates: tokio::sync::watch::Receiver<Vec<SocketAddr>>,
}

// Relay leases arrive asynchronously. A failed direct probe must not prevent
// the same SOCKS request from using a lease that becomes available.
async fn first_route<T, F>(
    mut updates: tokio::sync::watch::Receiver<Vec<SocketAddr>>,
    dial: impl Fn(SocketAddr) -> F,
) -> Result<T>
where
    T: Send + 'static,
    F: Future<Output = Result<T>> + Send + 'static,
{
    // Leave time in the SOCKS handshake budget for opening the target stream.
    timeout(Duration::from_secs(5), async {
        let mut attempted = BTreeSet::new();
        let mut pending = JoinSet::new();
        loop {
            {
                let current = updates.borrow_and_update();
                attempted.retain(|address| current.contains(address));
                for &address in current.iter() {
                    if attempted.insert(address) {
                        let attempt = dial(address);
                        pending.spawn(async move { (address, attempt.await) });
                    }
                }
            }
            tokio::select! {
                change = updates.changed() => change.context("SOCKS routes stopped")?,
                Some(attempt) = pending.join_next() => {
                    let (address, result) = attempt?;
                    match result {
                        Ok(value) if updates.borrow().contains(&address) => return Ok(value),
                        Ok(_) => {}
                        Err(error) => tracing::debug!(%address, %error, "SOCKS route unavailable"),
                    }
                }
            }
        }
    })
    .await
    .context("no reachable SOCKS route")?
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
    pub(super) game_mode: bool,
    slots: BTreeMap<String, Slot>,
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

    pub(super) fn new(
        identity: mesh::ClientIdentity,
        nodes: Vec<mesh::Node>,
        exits: Vec<String>,
        interface: Option<String>,
        game_mode: bool,
    ) -> Result<Arc<Self>> {
        ensure!(
            !exits.is_empty() && exits.len() <= 8,
            "select 1..8 proxy exits"
        );
        let mut slots = BTreeMap::new();
        for exit in &exits {
            ensure!(!slots.contains_key(exit), "duplicate proxy exit: {exit}");
            slots.insert(
                exit.clone(),
                Slot {
                    routes: AsyncMutex::new(None),
                    aggregate: AsyncMutex::new(None),
                    stream_metrics: stats::Metrics::new("client")
                        .with_summary_label(format!("socks:{exit}")),
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
            game_mode,
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
    fn stream_running(&self, id: &str) -> bool {
        self.slots
            .get(id)
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
        id: &str,
    ) -> Result<(
        tokio::sync::watch::Receiver<Vec<SocketAddr>>,
        tokio::sync::watch::Sender<mesh::PathHealth>,
    )> {
        ensure!(
            !self.closed.load(std::sync::atomic::Ordering::Acquire),
            "proxy client stopped"
        );
        let slot = self.slots.get(id).context("exit not selected")?;
        let mut routes = slot.routes.lock().await;
        if routes.is_none() {
            let nodes = self.wait_for_exit_nodes(id).await?;
            let limit = self.path_limit.load(std::sync::atomic::Ordering::Relaxed);
            let (_, guard) = self
                .identity
                .entrances_on(nodes, id, limit, &self.uplink())
                .await?;
            ensure!(
                !self.closed.load(std::sync::atomic::Ordering::Acquire),
                "proxy client stopped"
            );
            *routes = Some(Routes {
                updates: guard.updates(),
                _guard: guard,
            });
        }
        let routes = routes.as_ref().expect("proxy routes");
        Ok((routes.updates.clone(), routes._guard.health()))
    }
    /// Prepare one aggregate session for an exit without opening a destination.
    pub(super) async fn prepare_stream(&self, id: &str) -> Result<tunnel::tcp::Connector> {
        ensure!(
            !self.closed.load(std::sync::atomic::Ordering::Acquire),
            "proxy client stopped"
        );
        let slot = self.slots.get(id).context("exit not selected")?;
        let mut aggregate = slot.aggregate.lock().await;
        if let Some(current) = aggregate.as_ref().filter(|current| current.running()) {
            return Ok(current.connector.clone());
        }
        if let Some(old) = aggregate.take() {
            old.shutdown().await;
        }
        // This reporter owns the entrance health channel for this exit. Native
        // UDP remains lazy and must not overwrite aggregate-path evidence.
        let (updates, health) = self.route_watch(id).await?;
        let status = first_route(updates.clone(), |address| {
            let identity = self.identity.clone();
            let uplink = self.uplink();
            let exit = id.to_owned();
            async move {
                let status = identity.status_on(address, &uplink).await?;
                ensure!(status.node.id == exit, "proxy exit identity changed");
                Ok(status)
            }
        })
        .await?;
        status.capabilities.require_proxy_stream()?;
        #[cfg(test)]
        let updates = {
            *slot.stream_health.lock().expect("stream health") = Some(health.clone());
            if let Some(addresses) = slot.test_routes.lock().expect("test routes").clone() {
                let (sender, receiver) = tokio::sync::watch::channel(addresses);
                *slot.test_stream_updates.lock().expect("test stream routes") = Some(sender);
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
            policy: reliable_policy(self.game_mode),
            congestion: transport::Congestion::Bbr,
            stats: slot.stream_metrics.clone(),
        };
        ensure!(
            !self.closed.load(std::sync::atomic::Ordering::Acquire),
            "proxy client stopped"
        );
        let exit = id.to_owned();
        let closer = connector.clone();
        let task = tokio::spawn(async move {
            let result =
                tunnel::client_with_mesh_exit(options, Some(updates), Some(health), exit.clone())
                    .await;
            closer.close();
            if let Err(error) = &result {
                tracing::warn!(%exit, %error, "aggregate proxy session stopped");
            }
            result
        });
        *aggregate = Some(Aggregate {
            connector: connector.clone(),
            task: Some(task),
        });
        Ok(connector)
    }
    pub(super) async fn open_stream(
        &self,
        id: &str,
        target: Address,
        early_reply: bool,
    ) -> Result<tunnel::tcp::Flow> {
        let connector = self.prepare_stream(id).await?;
        connector.open(target.into(), early_reply).await
    }
    #[cfg(test)]
    pub(super) fn test_stream_metrics(&self, id: &str) -> stats::Metrics {
        self.slots[id].stream_metrics.clone()
    }

    #[cfg(test)]
    pub(super) fn transport_snapshot(
        &self,
        id: &str,
    ) -> BTreeMap<SocketAddr, (u64, u64, u64, u64)> {
        let slot = &self.slots[id];
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
    pub(super) fn test_path_failed(&self, id: &str, address: SocketAddr) -> bool {
        let health = self.slots[id].stream_health.lock().unwrap();
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
            // Dropping a waiter detaches this task; it must not abort cleanup
            // and release the guard while its aggregate runtime still runs.
            releases.push(tokio::spawn(stop_slot(aggregate.take(), routes.take())));
        }
        for release in releases {
            let _ = release.await;
        }
    }
    #[cfg(test)]
    pub(super) fn test_set_routes(&self, id: &str, routes: Vec<SocketAddr>) {
        if let Some(updates) = self.slots[id].test_stream_updates.lock().unwrap().as_ref() {
            updates.send_replace(routes.clone());
        }
        *self.slots[id].test_routes.lock().unwrap() = Some(routes);
    }
    #[cfg(test)]
    pub(super) async fn test_addresses(&self, id: &str) -> Vec<SocketAddr> {
        if let Some(routes) = self.slots[id].test_routes.lock().unwrap().clone() {
            return routes;
        }
        let (updates, _) = self.route_watch(id).await.unwrap();
        updates.borrow().clone()
    }
    fn refresh(&self, nodes: Vec<mesh::Node>) {
        let mut current = self.nodes.write().expect("proxy nodes");
        // Merge incoming nodes by ID so a partial view of one exit never drops
        // another selected exit learned from a different peer or cache.
        let mut by_id: BTreeMap<String, mesh::Node> = current
            .iter()
            .cloned()
            .map(|node| (node.id.clone(), node))
            .collect();
        for node in nodes {
            by_id.insert(node.id.clone(), node);
        }
        *current = by_id.into_values().collect();
        drop(current);
        self.nodes_changed.notify_waiters();
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

fn reliable_policy(game_mode: bool) -> tunnel::Policy {
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

pub(super) fn validate_tcp_forwards(forwards: &[Listener], socks: &[Listener]) -> Result<()> {
    ensure!(
        forwards.len() <= crate::runtime::MAX_PATHS,
        "at most eight fixed TCP forwards"
    );
    let mut addresses: BTreeSet<_> = socks.iter().map(|listener| listener.address).collect();
    let mut exits = BTreeSet::new();
    for listener in forwards {
        ensure!(!listener.exit.is_empty(), "missing fixed TCP exit");
        ensure!(
            listener.address.ip().is_loopback(),
            "fixed TCP listeners must use loopback addresses"
        );
        ensure!(
            exits.insert(&listener.exit),
            "duplicate fixed TCP exit: {}",
            listener.exit
        );
        ensure!(
            listener.address.port() == 0 || addresses.insert(listener.address),
            "duplicate local listener address: {}",
            listener.address
        );
    }
    Ok(())
}

async fn discover_wanted(
    identity: &mesh::ClientIdentity,
    entries: &[SocketAddr],
    wanted: &BTreeSet<String>,
    uplink: &mesh::Uplink,
) -> Result<(Vec<mesh::Node>, Vec<String>)> {
    let mut nodes = identity.discover_any_on(entries, uplink).await?;
    let mut missing_exits = Vec::new();
    let mut missing = JoinSet::new();
    for exit in wanted {
        if !nodes.iter().any(|node| node.id == *exit) {
            let identity = identity.clone();
            let entries = entries.to_vec();
            let exit = exit.clone();
            let uplink = uplink.clone();
            missing.spawn(async move {
                let res = identity.discover_exit_on(&entries, &exit, &uplink).await;
                (exit, res)
            });
        }
    }
    while let Some(result) = missing.join_next().await {
        match result {
            Ok((exit, Ok(found))) => {
                if let Some(node) = found.into_iter().find(|n| n.id == exit) {
                    nodes.push(node);
                } else {
                    missing_exits.push(exit);
                }
            }
            Ok((exit, Err(error))) => {
                tracing::debug!(%exit, %error, "selected exit not yet discovered");
                missing_exits.push(exit);
            }
            Err(_) => {}
        }
    }
    Ok((nodes, missing_exits))
}

struct FixedForwardConfig {
    identity: mesh::ClientIdentity,
    mapping: Listener,
    listener: Arc<TcpListener>,
    paths: usize,
    interface: Option<String>,
    game_mode: bool,
}

async fn fixed_forward_once(config: &FixedForwardConfig, nodes: Vec<mesh::Node>) -> Result<()> {
    let uplink = mesh::Uplink {
        interface: config.interface.clone(),
        ..Default::default()
    };
    let (entrances, leases) = config
        .identity
        .entrances_on(nodes, &config.mapping.exit, config.paths, &uplink)
        .await?;
    let mut policy = reliable_policy(config.game_mode);
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
        stats: stats::Metrics::new("fixed-forward")
            .with_summary_label(format!("fixed:{}", config.mapping.exit)),
    };
    let result = tunnel::client_with_fixed_listener(
        options,
        leases.updates(),
        leases.health(),
        config.mapping.exit.clone(),
        config.listener.clone(),
    )
    .await;
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
            result = fixed_forward_once(&config, nodes) => result,
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
    let planned = listener_plan(&options.exits, options.listen, &options.socks5)?;
    validate_tcp_forwards(&options.tcp_forward, &planned)?;
    let wanted: BTreeSet<_> = options
        .exits
        .iter()
        .chain(options.tcp_forward.iter().map(|listener| &listener.exit))
        .cloned()
        .collect();
    ensure!(
        wanted.len() <= crate::runtime::MAX_PATHS,
        "select at most eight mesh exits"
    );
    let initial_nodes = options.identity.cached_nodes();
    let selected_exits = options.exits.clone();
    let fixed_identity = options.identity.clone();
    let fixed_interface = options.interface.clone();
    let pool = Pool::new(
        options.identity,
        initial_nodes.clone(),
        options.exits,
        options.interface,
        options.game_mode,
    )?;
    pool.path_limit
        .store(options.paths, std::sync::atomic::Ordering::Relaxed);
    // Bind every requested port before touching the network so cold boots and
    // transient WAN outages keep local listeners bound and never crash-loop.
    let mut listeners = Vec::with_capacity(planned.len());
    for listener in planned {
        listeners.push((
            TcpListener::bind(listener.address).await.with_context(|| {
                format!("bind SOCKS5 for {} at {}", listener.exit, listener.address)
            })?,
            listener.exit,
        ));
    }
    let mut forwards = Vec::with_capacity(options.tcp_forward.len());
    for mapping in options.tcp_forward {
        let listener = Arc::new(TcpListener::bind(mapping.address).await.with_context(|| {
            format!("bind fixed TCP for {} at {}", mapping.exit, mapping.address)
        })?);
        forwards.push((mapping, listener));
    }
    let (nodes_tx, nodes_rx) = tokio::sync::watch::channel(initial_nodes);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let permits = Arc::new(Semaphore::new(crate::runtime::tunnel::tcp::MAX_TCP_FLOWS));
    let mut tasks = JoinSet::new();
    let mut forward_tasks = JoinSet::new();
    for (mapping, listener) in forwards {
        tracing::info!(address=%listener.local_addr()?, exit=%mapping.exit, "fixed TCP forward bound");
        forward_tasks.spawn(fixed_forward_supervisor(
            FixedForwardConfig {
                identity: fixed_identity.clone(),
                mapping,
                listener,
                paths: options.paths,
                interface: fixed_interface.clone(),
                game_mode: options.game_mode,
            },
            nodes_rx.clone(),
            stop_rx.clone(),
        ));
    }
    for (listener, exit) in listeners {
        tracing::info!(address=%listener.local_addr()?, %exit, "SOCKS5 proxy ready");
        tasks.spawn(listen(
            listener,
            pool.clone(),
            exit,
            permits.clone(),
            options.socks5_early_reply,
        ));
    }
    let mut discovery: JoinSet<Result<(Vec<mesh::Node>, Vec<String>)>> = JoinSet::new();
    let mut warmups: JoinSet<()> = JoinSet::new();
    let spawn_discovery = |discovery: &mut JoinSet<Result<(Vec<mesh::Node>, Vec<String>)>>,
                           pool: &Arc<Pool>,
                           entries: &[SocketAddr],
                           wanted: &BTreeSet<String>| {
        let identity = pool.identity.clone();
        let uplink = pool.uplink();
        let entries = entries.to_vec();
        let wanted = wanted.clone();
        discovery
            .spawn(async move { discover_wanted(&identity, &entries, &wanted, &uplink).await });
    };
    let spawn_warmups = |warmups: &mut JoinSet<()>, pool: &Arc<Pool>, exits: &[String]| {
        for exit in exits {
            if pool.has_exit(exit) && !pool.stream_running(exit) {
                let pool = pool.clone();
                let exit = exit.clone();
                warmups.spawn(async move {
                    if let Err(error) = pool.prepare_stream(&exit).await {
                        tracing::warn!(%exit, %error, "aggregate proxy exit unavailable");
                    }
                });
            }
        }
    };
    spawn_discovery(&mut discovery, &pool, &options.connect, &wanted);
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
                        .map(|(exit, slot)| (exit.clone(), slot.stream_metrics.clone()))
                        .collect();
                    // JSON encoding and debug output must not occupy a network
                    // worker. One bounded job serves every selected exit; a slow
                    // sink skips ticks instead of queuing diagnostic work.
                    diagnostics = Some(tokio::task::spawn_blocking(move || {
                        for (exit, metrics) in metrics {
                            if let Ok(snapshot) = metrics.snapshot(false, "observed", None) {
                                tracing::debug!(%exit, %snapshot, "proxy aggregate statistics");
                            }
                        }
                    }));
                }
            },
            result = tasks.join_next() => { result.context("proxy listeners stopped")???; bail!("proxy listener stopped"); }
            _ = forward_tasks.join_next(), if !forward_tasks.is_empty() => {}
            _ = warmups.join_next(), if !warmups.is_empty() => {}
            _ = tokio::time::sleep_until(next_discovery), if discovery.is_empty() => {
                spawn_discovery(&mut discovery, &pool, &options.connect, &wanted);
            }
            Some(result) = discovery.join_next(), if !discovery.is_empty() => {
                match result {
                    Ok(Ok((nodes, missing_exits))) => {
                        pool.refresh(nodes);
                        let merged = pool.nodes.read().expect("proxy nodes").clone();
                        nodes_tx.send_replace(merged);
                        spawn_warmups(&mut warmups, &pool, &selected_exits);
                        let all_present = missing_exits.is_empty()
                            && wanted.iter().all(|exit| pool.has_exit(exit));
                        if all_present {
                            bootstrap_backoff = Duration::from_secs(1);
                            next_discovery = tokio::time::Instant::now() + Duration::from_secs(15);
                        } else {
                            tracing::warn!(
                                missing = ?missing_exits,
                                retry_secs = bootstrap_backoff.as_secs(),
                                "some proxy exits not yet discovered; retrying"
                            );
                            next_discovery = tokio::time::Instant::now() + bootstrap_backoff;
                            bootstrap_backoff = (bootstrap_backoff * 2).min(Duration::from_secs(15));
                        }
                    }
                    Ok(Err(error)) => {
                        let any_missing = wanted.iter().any(|exit| !pool.has_exit(exit));
                        if any_missing {
                            tracing::warn!(
                                retry_secs = bootstrap_backoff.as_secs(),
                                %error,
                                "mesh discovery unavailable; retaining local listeners and retrying"
                            );
                            next_discovery = tokio::time::Instant::now() + bootstrap_backoff;
                            bootstrap_backoff = (bootstrap_backoff * 2).min(Duration::from_secs(15));
                        } else {
                            tracing::debug!(%error, "periodic mesh discovery unavailable");
                            spawn_warmups(&mut warmups, &pool, &selected_exits);
                            next_discovery = tokio::time::Instant::now() + Duration::from_secs(15);
                        }
                    }
                    Err(_) => {
                        next_discovery = tokio::time::Instant::now() + bootstrap_backoff;
                        bootstrap_backoff = (bootstrap_backoff * 2).min(Duration::from_secs(15));
                    }
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
    exit: String,
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
                let pool = pool.clone(); let exit = exit.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = super::socks::serve(tcp, pool, &exit, early_reply).await { tracing::debug!(%error, %exit, "SOCKS5 client closed"); }
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
            vec!["exit".into()],
            None,
            false,
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
        let slot = &pool.slots["exit"];
        slot.stream_metrics
            .register("active", 0, 0, stats::FORWARD, &outgoing);
        slot.stream_metrics
            .scope("active", stats::FORWARD)
            .path(1, |path| {
                path.peer_socket = "127.0.0.1:9".into();
            });
        assert_eq!(
            pool.transport_snapshot("exit")
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [address]
        );
        outgoing.close(0u32.into(), b"test closed path");
        assert!(pool.transport_snapshot("exit").is_empty());
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
        let slot = &pool.slots["exit"];
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
            vec!["a".into(), "b".into()],
            None,
            false,
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
            let slot = &pool.slots[exit];
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
        let second = pool.slots["b"].aggregate.lock().await;
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
