use super::{protocol::*, *};
use crate::runtime::{mesh, shutdown::Shutdown, transport};
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
    pub paths: usize,
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
pub(super) struct Connection {
    pub(super) raw: quinn::Connection,
    pub(super) router: Arc<Router>,
    _reader: AbortTask,
    _close: CloseConnection,
    _endpoint: quinn::Endpoint,
}
const DOWNLOAD_PERMITS: usize = 512;
// Records this small are latency-bound; send them on the lowest-RTT path.
const SMALL_RECORD: usize = 16 * 1024;
struct Path {
    address: SocketAddr,
    connection: Mutex<Option<Arc<Connection>>>,
    connecting: AsyncMutex<()>,
    retired: std::sync::atomic::AtomicBool,
    upload: Arc<Semaphore>,
    download: Arc<Semaphore>,
    control: Arc<Semaphore>,
    progress: Arc<Semaphore>,
    rtt_us: std::sync::atomic::AtomicU64,
    service: Arc<super::bond::PathService>,
    retry_after: Mutex<Option<Instant>>,
    failed: std::sync::atomic::AtomicBool,
    probe: Mutex<Option<AbortTask>>,
    // Health evidence for entrance selection: last completed RPC, and the
    // native sent/lost packet counters at the previous report.
    last_ok: Mutex<Option<Instant>>,
    reported: Mutex<(u64, u64)>,
    telemetry: Mutex<transport::ProxyTelemetry>,
}
impl Path {
    fn new(address: SocketAddr) -> Self {
        Self {
            address,
            connection: Mutex::new(None),
            connecting: AsyncMutex::new(()),
            retired: std::sync::atomic::AtomicBool::new(false),
            upload: Arc::new(Semaphore::new(128)),
            download: Arc::new(Semaphore::new(DOWNLOAD_PERMITS)),
            control: Arc::new(Semaphore::new(16)),
            progress: Arc::new(Semaphore::new(128)),
            rtt_us: std::sync::atomic::AtomicU64::new(200_000),
            service: Arc::new(super::bond::PathService::default()),
            retry_after: Mutex::new(None),
            failed: std::sync::atomic::AtomicBool::new(false),
            probe: Mutex::new(None),
            last_ok: Mutex::new(None),
            reported: Mutex::new((0, 0)),
            telemetry: Mutex::new(transport::ProxyTelemetry::default()),
        }
    }
    fn permits(&self, op: &super::bond::Operation) -> &Arc<Semaphore> {
        match op {
            super::bond::Operation::Put { .. } => &self.upload,
            super::bond::Operation::Pull { .. } => &self.download,
            super::bond::Operation::UploadStatus { .. } => &self.progress,
            _ => &self.control,
        }
    }
    fn connected(&self) -> bool {
        self.connection
            .lock()
            .expect("proxy connection")
            .as_ref()
            .is_some_and(|conn| conn.raw.close_reason().is_none())
    }
    fn retire(&self) {
        self.retired
            .store(true, std::sync::atomic::Ordering::Release);
        self.probe.lock().expect("path probe").take();
        if let Some(conn) = self.connection.lock().expect("proxy connection").take() {
            conn.raw.close(0u32.into(), b"aggregate path retired");
        }
    }
}
struct RpcPermit {
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ready: Arc<tokio::sync::Notify>,
}
impl Drop for RpcPermit {
    fn drop(&mut self) {
        self._permit.take();
        self.ready.notify_waiters();
    }
}
struct Routes {
    _guard: mesh::Entrances,
    updates: tokio::sync::watch::Receiver<Vec<SocketAddr>>,
}
struct Slot {
    node: RwLock<mesh::Node>,
    paths: Mutex<BTreeMap<SocketAddr, Arc<Path>>>,
    routes: AsyncMutex<Option<Routes>>,
    #[cfg(test)]
    test_routes: Mutex<Option<Vec<SocketAddr>>>,
}
pub(super) struct Pool {
    identity: mesh::ClientIdentity,
    token: String,
    slots: BTreeMap<String, Slot>,
    nodes: RwLock<Vec<mesh::Node>>,
    path_limit: std::sync::atomic::AtomicUsize,
    cursor: std::sync::atomic::AtomicUsize,
    ready: Arc<tokio::sync::Notify>,
    pub(super) flow_credit: Arc<Semaphore>,
    cleanups: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
impl Pool {
    pub(super) fn new(
        identity: mesh::ClientIdentity,
        nodes: Vec<mesh::Node>,
        exits: Vec<String>,
    ) -> Result<Arc<Self>> {
        ensure!(
            !exits.is_empty() && exits.len() <= 8,
            "select 1..8 proxy exits"
        );
        let mut slots = BTreeMap::new();
        for exit in &exits {
            ensure!(!slots.contains_key(exit), "duplicate proxy exit: {exit}");
            let node = nodes
                .iter()
                .find(|n| n.id == *exit)
                .with_context(|| format!("proxy exit not discovered: {exit}"))?
                .clone();
            slots.insert(
                exit.clone(),
                Slot {
                    node: RwLock::new(node),
                    paths: Mutex::new(BTreeMap::new()),
                    routes: AsyncMutex::new(None),
                    #[cfg(test)]
                    test_routes: Mutex::new(None),
                },
            );
        }
        let token = transport::token(&identity.dir.join("token"))?;
        Ok(Arc::new(Self {
            identity,
            token,
            slots,
            nodes: RwLock::new(nodes),
            path_limit: std::sync::atomic::AtomicUsize::new(4),
            cursor: std::sync::atomic::AtomicUsize::new(0),
            ready: Arc::new(tokio::sync::Notify::new()),
            flow_credit: Arc::new(Semaphore::new(MAX_STREAMS)),
            cleanups: Mutex::new(Vec::new()),
        }))
    }
    async fn paths(&self, id: &str) -> Result<Vec<Arc<Path>>> {
        let slot = self.slots.get(id).context("exit not selected")?;
        #[cfg(test)]
        if let Some(addresses) = slot.test_routes.lock().expect("test routes").clone() {
            return Ok(Self::cache_paths(slot, addresses));
        }
        let mut routes = slot.routes.lock().await;
        if routes.is_none() {
            let nodes = self.nodes.read().expect("proxy nodes").clone();
            let limit = self.path_limit.load(std::sync::atomic::Ordering::Relaxed);
            let (_, guard) = self.identity.entrances(nodes, id, limit).await?;
            *routes = Some(Routes {
                updates: guard.updates(),
                _guard: guard,
            });
        }
        let addresses = routes
            .as_ref()
            .expect("proxy routes")
            .updates
            .borrow()
            .clone();
        Ok(Self::cache_paths(slot, addresses))
    }
    fn cache_paths(slot: &Slot, addresses: Vec<SocketAddr>) -> Vec<Arc<Path>> {
        let mut paths = slot.paths.lock().expect("proxy paths");
        paths.retain(|address, path| {
            let keep = addresses.contains(address);
            // A retired entrance stops forwarding once its lease is released.
            // Close it now so in-flight records replay without a stall timeout.
            if !keep {
                path.retire();
            }
            keep
        });
        addresses
            .into_iter()
            .map(|address| {
                paths
                    .entry(address)
                    .or_insert_with(|| Arc::new(Path::new(address)))
                    .clone()
            })
            .collect()
    }
    async fn authenticate(
        identity: &mesh::ClientIdentity,
        token: &str,
        address: SocketAddr,
        id: &str,
    ) -> Result<Arc<Connection>> {
        let endpoint = transport::proxy_client(address, &identity.dir.join("cert.pem"))?;
        let connection = timeout(CONNECT_TIMEOUT, async {
            let raw = endpoint.connect(address, &identity.name())?.await?;
            let close = CloseConnection(raw.clone());
            let (mut send, mut recv) = raw.open_bi().await?;
            let mut auth = vec![1];
            auth.extend(token.as_bytes());
            auth.push(id.len() as u8);
            auth.extend(id.as_bytes());
            send.write_all(&auth).await?;
            send.finish()?;
            ensure!(
                recv.read_to_end(1).await? == [0],
                "proxy authentication rejected"
            );
            let router = Arc::new(Router::default());
            let dispatch = router.clone();
            let read = raw.clone();
            let reader = AbortTask(tokio::spawn(async move {
                while let Ok(data) = read.read_datagram().await {
                    dispatch.dispatch(data);
                }
            }));
            Ok::<_, anyhow::Error>(Arc::new(Connection {
                raw,
                router,
                _reader: reader,
                _close: close,
                _endpoint: endpoint,
            }))
        })
        .await??;
        Ok(connection)
    }
    async fn connect(&self, id: &str, path: &Path) -> Result<Arc<Connection>> {
        let _connecting = path.connecting.lock().await;
        {
            let mut cached = path.connection.lock().expect("proxy connection");
            ensure!(
                !path.retired.load(std::sync::atomic::Ordering::Acquire),
                "aggregate path retired"
            );
            if let Some(conn) = &*cached
                && conn.raw.close_reason().is_none()
            {
                return Ok(conn.clone());
            }
            *cached = None;
        }
        let connection = Self::authenticate(&self.identity, &self.token, path.address, id).await?;
        let mut cached = path.connection.lock().expect("proxy connection");
        // Retirement can race with the handshake. Never install a connection
        // after its entrance lease has been released.
        ensure!(
            !path.retired.load(std::sync::atomic::Ordering::Acquire),
            "aggregate path retired"
        );
        *cached = Some(connection.clone());
        Ok(connection)
    }
    /// Authenticate optional paths before giving them download records. This
    /// opens no destination socket and never delays SOCKS listener startup.
    fn prepare_path(&self, id: &str, path: &Arc<Path>) {
        if path.connected()
            || path.failed.load(std::sync::atomic::Ordering::Acquire)
            || path.retired.load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        let mut task = path.probe.lock().expect("path probe");
        if task.as_ref().is_some_and(|task| !task.0.is_finished()) {
            return;
        }
        let (identity, token, id, weak, ready) = (
            self.identity.clone(),
            self.token.clone(),
            id.to_owned(),
            Arc::downgrade(path),
            self.ready.clone(),
        );
        *task = Some(AbortTask(tokio::spawn(async move {
            let Some(path) = weak.upgrade() else {
                return;
            };
            let _connecting = path.connecting.lock().await;
            if path.connected() || path.retired.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            match Self::authenticate(&identity, &token, path.address, &id).await {
                Ok(conn) => {
                    let mut cached = path.connection.lock().expect("proxy connection");
                    if path.retired.load(std::sync::atomic::Ordering::Acquire) {
                        return;
                    }
                    path.rtt_us.store(
                        conn.raw.rtt().as_micros() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    *path.last_ok.lock().expect("path health") = Some(Instant::now());
                    *cached = Some(conn);
                    tracing::debug!(exit=%id, address=%path.address, "aggregate path prepared");
                }
                Err(error) => {
                    path.failed
                        .store(true, std::sync::atomic::Ordering::Release);
                    *path.retry_after.lock().expect("path retry") =
                        Some(Instant::now() + Duration::from_secs(1));
                    tracing::debug!(exit=%id, address=%path.address, %error, "aggregate path preparation failed");
                }
            }
            ready.notify_waiters();
        })));
    }
    pub(super) async fn prepare_paths(&self, id: &str) -> Result<()> {
        for path in self.paths(id).await? {
            self.prepare_path(id, &path);
        }
        Ok(())
    }
    fn probe(&self, id: &str, path: &Arc<Path>) {
        if path.retired.load(std::sync::atomic::Ordering::Acquire)
            || !path.failed.load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        let mut task = path.probe.lock().expect("path probe");
        if task.as_ref().is_some_and(|task| !task.0.is_finished()) {
            return;
        }
        let (identity, token, address, exit, weak, ready) = (
            self.identity.clone(),
            self.token.clone(),
            path.address,
            id.to_owned(),
            Arc::downgrade(path),
            self.ready.clone(),
        );
        *task = Some(AbortTask(tokio::spawn(async move {
            loop {
                let retry = {
                    let Some(path) = weak.upgrade() else {
                        break;
                    };
                    *path.retry_after.lock().expect("path retry")
                };
                if let Some(at) = retry {
                    tokio::time::sleep_until(at).await;
                }
                let result = Self::authenticate(&identity, &token, address, &exit).await;
                let Some(path) = weak.upgrade() else {
                    break;
                };
                match result {
                    Ok(conn) => {
                        let mut cached = path.connection.lock().expect("proxy connection");
                        if path.retired.load(std::sync::atomic::Ordering::Acquire) {
                            break;
                        }
                        path.service.reset();
                        *cached = Some(conn);
                        path.failed
                            .store(false, std::sync::atomic::Ordering::Release);
                        *path.retry_after.lock().expect("path retry") = None;
                        ready.notify_waiters();
                        tracing::debug!(%exit, %address, "aggregate path probe recovered");
                        break;
                    }
                    Err(error) => {
                        tracing::debug!(%exit, %address, %error, "aggregate path probe failed");
                        *path.retry_after.lock().expect("path retry") =
                            Some(Instant::now() + Duration::from_secs(5));
                    }
                }
            }
        })));
    }
    pub(super) async fn get(&self, id: &str) -> Result<Arc<Connection>> {
        let slot = self.slots.get(id).context("exit not selected")?;
        let address = slot.node.read().expect("proxy node").address;
        let path = slot
            .paths
            .lock()
            .expect("proxy paths")
            .entry(address)
            .or_insert_with(|| Arc::new(Path::new(address)))
            .clone();
        self.connect(id, &path).await
    }
    pub(super) async fn call(
        &self,
        id: &str,
        key: super::bond::Key,
        op: super::bond::Operation,
        usage: &Mutex<BTreeMap<SocketAddr, (u64, u64)>>,
    ) -> Result<super::bond::Reply> {
        self.call_inner(id, key, op, usage, None).await
    }
    pub(super) async fn call_stream(
        &self,
        id: &str,
        key: super::bond::Key,
        op: super::bond::Operation,
        usage: &Mutex<BTreeMap<SocketAddr, (u64, u64)>>,
        sink: &mut super::bond::StreamSink,
    ) -> Result<super::bond::Reply> {
        self.call_inner(id, key, op, usage, Some(sink)).await
    }
    async fn call_inner(
        &self,
        id: &str,
        key: super::bond::Key,
        mut op: super::bond::Operation,
        usage: &Mutex<BTreeMap<SocketAddr, (u64, u64)>>,
        mut stream: Option<&mut super::bond::StreamSink>,
    ) -> Result<super::bond::Reply> {
        let mut failures = 0;
        let mut busy = 0u32;
        let mut started = Instant::now();
        loop {
            ensure!(
                !stream.as_ref().is_some_and(|sink| sink.events.is_closed()),
                "download consumer closed"
            );
            ensure!(
                started.elapsed() < IDLE_TIMEOUT,
                "aggregate RPC resource wait expired"
            );
            let changed = self.ready.notified();
            let mut paths = self.paths(id).await?;
            if !paths.is_empty() {
                let len = paths.len();
                paths.rotate_left(
                    self.cursor
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        % len,
                );
            }
            for path in &paths {
                self.probe(id, path);
                self.prepare_path(id, path);
            }
            let rtt = |p: &Arc<Path>| p.rtt_us.load(std::sync::atomic::Ordering::Relaxed);
            let (interactive, avoid) = stream
                .as_ref()
                .map_or((false, None), |sink| (sink.interactive, sink.avoid));
            if let super::bond::Operation::Pull { count, .. } = op {
                if interactive {
                    // A wait for future bytes carries the next interactive reply.
                    paths.sort_by_key(rtt);
                } else {
                    let cost = |path: &Path| {
                        path.service.cost(
                            count as usize * super::bond::CHUNK,
                            Duration::from_micros(
                                path.rtt_us.load(std::sync::atomic::Ordering::Relaxed),
                            ),
                            path.download.available_permits() < DOWNLOAD_PERMITS,
                        )
                    };
                    paths.sort_by(|a, b| {
                        cost(a).total_cmp(&cost(b)).then_with(|| {
                            b.download
                                .available_permits()
                                .cmp(&a.download.available_permits())
                        })
                    });
                }
                paths.sort_by_key(|p| avoid == Some(p.address));
            } else if let super::bond::Operation::Put { data, .. } = &op {
                if data.len() <= SMALL_RECORD {
                    paths.sort_by_key(rtt);
                } else {
                    paths.sort_by_key(|p| std::cmp::Reverse(p.permits(&op).available_permits()));
                }
            } else {
                // Progress gates every data path: do not distribute these small
                // messages to a slow relay just because its bulk queue is empty.
                paths.sort_by_key(|p| p.rtt_us.load(std::sync::atomic::Ordering::Relaxed));
            }
            let ready_download = matches!(op, super::bond::Operation::Pull { .. })
                && paths.iter().any(|path| {
                    path.connected() && !path.failed.load(std::sync::atomic::Ordering::Acquire)
                });
            let chosen = paths.into_iter().find_map(|path| {
                // A cold relay must not hold the next records behind its
                // handshake while an authenticated path can deliver them now.
                if ready_download && !path.connected() {
                    return None;
                }
                if path.failed.load(std::sync::atomic::Ordering::Acquire)
                    || path
                        .retry_after
                        .lock()
                        .expect("path retry")
                        .is_some_and(|at| at > Instant::now())
                {
                    return None;
                }
                let permit = path.permits(&op).clone().try_acquire_owned().ok()?;
                Some((
                    path,
                    RpcPermit {
                        _permit: Some(permit),
                        ready: self.ready.clone(),
                    },
                ))
            });
            let Some((path, _permit)) = chosen else {
                tokio::select! { _ = changed => {}, _ = tokio::time::sleep(Duration::from_millis(20)) => {} }
                continue;
            };
            if let Some(sink) = stream.as_deref_mut() {
                *sink.route.lock().expect("download route") = path.address;
                let records = match op {
                    super::bond::Operation::Pull { count, .. } if !sink.interactive => {
                        count as usize
                    }
                    _ => 0,
                };
                sink.delivery = Some(path.service.start(records));
            }
            let mut used_connection = None;
            let result = async {
                let conn = self.connect(id, &path).await?;
                path.rtt_us.store(
                    conn.raw.rtt().as_micros().min(u64::MAX as u128) as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                used_connection = Some(conn.clone());
                super::bond::rpc(&conn.raw, key, &mut op, stream.as_deref_mut()).await
            }
            .await;
            // Authentication can fail before rpc() takes the reservation.
            if let Some(sink) = stream.as_deref_mut() {
                sink.delivery.take();
            }
            started = Instant::now();
            match result {
                Ok(super::bond::Reply::Failed(super::bond::BUSY)) => {
                    // Exit memory or handler admission is full. The path is
                    // healthy: release its permit and retry after a backoff.
                    busy = busy.saturating_add(1);
                    drop(_permit);
                    tokio::time::sleep(Duration::from_millis(10 << busy.min(4))).await;
                }
                Ok(reply) => {
                    *path.last_ok.lock().expect("path health") = Some(Instant::now());
                    let mut used = usage.lock().expect("flow usage");
                    let counter = used.entry(path.address).or_default();
                    if let super::bond::Operation::Put { data, .. } = &op
                        && matches!(reply, super::bond::Reply::Uploaded { .. })
                    {
                        counter.0 += data.len() as u64;
                    }
                    return Ok(reply);
                }
                Err(error) => {
                    if stream.as_ref().is_some_and(|sink| sink.events.is_closed()) {
                        return Err(error);
                    }
                    let delivered_batch = stream.is_some()
                        && matches!(op, super::bond::Operation::Pull { count: 0, .. });
                    let terminal = used_connection.as_ref().and_then(|c| c.raw.close_reason()).is_some_and(|reason| {
                        matches!(reason, quinn::ConnectionError::ApplicationClosed(ref close) if close.reason.as_ref() == b"server stopped" || close.reason.as_ref() == b"shutdown" || close.reason.as_ref() == b"proxy owner stopped")
                    });
                    if terminal {
                        if delivered_batch {
                            return Ok(super::bond::Reply::Accepted);
                        }
                        return Err(error.context("selected proxy exit shut down"));
                    }
                    let mut cached = path.connection.lock().expect("proxy connection");
                    if let (Some(used), Some(current)) = (&used_connection, &*cached)
                        && !Arc::ptr_eq(used, current)
                    {
                        // An error from the old connection cannot retire a recovered path.
                        if delivered_batch {
                            return Ok(super::bond::Reply::Accepted);
                        }
                        continue;
                    }
                    path.failed
                        .store(true, std::sync::atomic::Ordering::Release);
                    *path.retry_after.lock().expect("path retry") =
                        Some(Instant::now() + Duration::from_secs(1));
                    if let Some(conn) = cached.take() {
                        conn.raw.close(0u32.into(), b"aggregate path stalled");
                    }
                    drop(cached);
                    self.probe(id, &path);
                    if delivered_batch {
                        return Ok(super::bond::Reply::Accepted);
                    }
                    failures += 1;
                    tracing::debug!(%id, address=%path.address, %error, "aggregate record moving to another path");
                    if failures >= 8 {
                        return Err(error.context("all aggregate TCP paths failed"));
                    }
                }
            }
        }
    }
    /// A path stalled behind later arrivals takes no new work for a while,
    /// unless it is the only usable path. Native failure still needs a timeout.
    pub(super) fn suspect(&self, id: &str, address: SocketAddr, duration: Duration) {
        let now = Instant::now();
        let paths = self.slots[id].paths.lock().expect("proxy paths");
        let usable = |p: &Path| {
            !p.failed.load(std::sync::atomic::Ordering::Acquire)
                && p.retry_after
                    .lock()
                    .expect("path retry")
                    .is_none_or(|at| at <= now)
        };
        if !paths.values().any(|p| p.address != address && usable(p)) {
            return;
        }
        if let Some(path) = paths.get(&address).filter(|p| usable(p)) {
            *path.retry_after.lock().expect("path retry") = Some(now + duration);
        }
    }
    /// Head-of-line re-request delay: several fast-path RTTs, bounded.
    pub(super) fn hedge_delay(&self, id: &str) -> Duration {
        let rtt = self.slots[id]
            .paths
            .lock()
            .expect("proxy paths")
            .values()
            .filter(|p| !p.failed.load(std::sync::atomic::Ordering::Acquire))
            .map(|p| p.rtt_us.load(std::sync::atomic::Ordering::Relaxed))
            .min()
            .unwrap_or(200_000);
        (Duration::from_micros(rtt) * 3).clamp(Duration::from_millis(100), Duration::from_secs(1))
    }
    /// Feed proxy path evidence to entrance selection, as the tunnel does, so
    /// a failed or persistently poor relay can be replaced by another server.
    pub(super) fn report_health(&self) {
        let now = Instant::now();
        for (id, slot) in &self.slots {
            let Ok(routes) = slot.routes.try_lock() else {
                continue;
            };
            let Some(routes) = routes.as_ref() else {
                continue;
            };
            // Apply entrance changes even when all live RPCs are waiting for
            // target data. No new application request is needed to retire a path.
            let paths = Self::cache_paths(slot, routes.updates.borrow().clone());
            for path in &paths {
                self.prepare_path(id, path);
            }
            let samples: Vec<_> = paths
                .iter()
                .map(|path| {
                    let failed = path.failed.load(std::sync::atomic::Ordering::Acquire);
                    let stats = path
                        .connection
                        .lock()
                        .expect("proxy connection")
                        .as_ref()
                        .map(|c| {
                            path.telemetry
                                .lock()
                                .expect("path telemetry")
                                .report(&c.raw, "client", id);
                            c.raw.stats().path
                        });
                    let mut reported = path.reported.lock().expect("path health");
                    let loss = stats.map_or(0.0, |stats| {
                        let sent = stats.sent_packets.saturating_sub(reported.0);
                        let lost = stats.lost_packets.saturating_sub(reported.1);
                        *reported = (stats.sent_packets, stats.lost_packets);
                        if sent == 0 {
                            0.0
                        } else {
                            lost as f64 / sent as f64
                        }
                    });
                    mesh::PathSample {
                        address: path.address,
                        group: 0,
                        delivered: !failed
                            && path.last_ok.lock().expect("path health").is_some_and(|at| {
                                now.saturating_duration_since(at) < Duration::from_secs(10)
                            }),
                        failed,
                        rtt_ms: path.rtt_us.load(std::sync::atomic::Ordering::Relaxed) as f64
                            / 1000.0,
                        loss,
                    }
                })
                .collect();
            routes._guard.health().send_replace(mesh::PathHealth {
                checked: now.into_std(),
                addresses: samples
                    .iter()
                    .filter(|s| !s.failed)
                    .map(|s| s.address)
                    .collect(),
                samples,
            });
        }
    }
    pub(super) fn service_snapshot(&self, id: &str) -> BTreeMap<SocketAddr, (u64, usize)> {
        self.slots[id]
            .paths
            .lock()
            .expect("proxy paths")
            .iter()
            .map(|(address, path)| (*address, path.service.snapshot()))
            .collect()
    }
    pub(super) fn transport_snapshot(
        &self,
        id: &str,
    ) -> BTreeMap<SocketAddr, (u64, u64, u64, u64)> {
        self.slots[id]
            .paths
            .lock()
            .expect("proxy paths")
            .iter()
            .filter_map(|(address, path)| {
                let cached = path.connection.try_lock().ok()?;
                let stats = cached.as_ref()?.raw.stats().path;
                Some((
                    *address,
                    (
                        stats.rtt.as_micros().min(u64::MAX as u128) as u64,
                        stats.cwnd,
                        stats.sent_packets,
                        stats.lost_packets,
                    ),
                ))
            })
            .collect()
    }
    #[cfg(test)]
    pub(super) fn test_path_failed(&self, id: &str, address: SocketAddr) -> bool {
        self.slots[id]
            .paths
            .lock()
            .unwrap()
            .get(&address)
            .is_some_and(|p| p.failed.load(std::sync::atomic::Ordering::Acquire))
    }
    #[cfg(test)]
    pub(super) fn set_path_limit(&self, limit: usize) {
        self.path_limit
            .store(limit, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(test)]
    pub(super) fn test_fail_path(&self, id: &str, address: SocketAddr) {
        if let Some(path) = self.slots[id].paths.lock().unwrap().get(&address) {
            path.failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
    #[cfg(test)]
    pub(super) async fn test_connect_path(
        &self,
        id: &str,
        address: SocketAddr,
    ) -> quinn::Connection {
        let path = self
            .paths(id)
            .await
            .unwrap()
            .into_iter()
            .find(|p| p.address == address)
            .unwrap();
        self.connect(id, &path).await.unwrap().raw.clone()
    }
    pub(super) fn track_cleanup(&self, task: tokio::task::JoinHandle<()>) {
        let mut tasks = self.cleanups.lock().expect("flow cleanup");
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }
    pub(super) async fn shutdown(&self) {
        // Listener cancellation schedules cancellation of its child flow tasks.
        // Wait for their owners and close RPCs before tearing down leased paths.
        let _owners = timeout(
            CONNECT_TIMEOUT + Duration::from_secs(2),
            self.flow_credit
                .clone()
                .acquire_many_owned(MAX_STREAMS as u32),
        )
        .await
        .ok();
        let cleanups = std::mem::take(&mut *self.cleanups.lock().expect("flow cleanup"));
        for mut task in cleanups {
            if timeout(CONNECT_TIMEOUT + Duration::from_secs(1), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
        let mut releases = JoinSet::new();
        for slot in self.slots.values() {
            if let Some(routes) = slot.routes.lock().await.take() {
                releases.spawn(routes._guard.shutdown());
            }
            let paths: Vec<_> = slot
                .paths
                .lock()
                .expect("proxy paths")
                .values()
                .cloned()
                .collect();
            for path in paths {
                path.probe.lock().expect("path probe").take();
                if let Some(conn) = path.connection.lock().expect("proxy connection").take() {
                    conn.raw.close(0u32.into(), b"proxy client shutdown");
                }
            }
        }
        while releases.join_next().await.is_some() {}
    }
    #[cfg(test)]
    pub(super) fn test_set_routes(&self, id: &str, routes: Vec<SocketAddr>) {
        *self.slots[id].test_routes.lock().unwrap() = Some(routes);
    }
    #[cfg(test)]
    pub(super) async fn test_addresses(&self, id: &str) -> Vec<SocketAddr> {
        self.paths(id)
            .await
            .unwrap()
            .iter()
            .map(|p| p.address)
            .collect()
    }
    fn refresh(&self, nodes: Vec<mesh::Node>) {
        for node in &nodes {
            if let Some(slot) = self.slots.get(&node.id) {
                let mut current = slot.node.write().expect("proxy node");
                if node.incarnation >= current.incarnation {
                    *current = node.clone();
                }
            }
        }
        *self.nodes.write().expect("proxy nodes") = nodes;
    }
}

pub async fn client(options: ClientOptions) -> Result<()> {
    let planned = listener_plan(&options.exits, options.listen, &options.socks5)?;
    let mut nodes = options.identity.discover_any(&options.connect).await?;
    let mut missing = JoinSet::new();
    for exit in &options.exits {
        if !nodes.iter().any(|node| node.id == *exit) {
            let identity = options.identity.clone();
            let entries = options.connect.clone();
            let exit = exit.clone();
            missing.spawn(async move {
                let nodes = identity.discover_exit(&entries, &exit).await?;
                Ok::<_, anyhow::Error>(
                    nodes
                        .into_iter()
                        .find(|n| n.id == exit)
                        .expect("discovery requires selected exit"),
                )
            });
        }
    }
    while let Some(result) = missing.join_next().await {
        nodes.push(result??);
    }
    let selected_exits = options.exits.clone();
    let pool = Pool::new(options.identity, nodes, options.exits)?;
    ensure!(
        (1..=crate::runtime::MAX_PATHS).contains(&options.paths),
        "invalid proxy path limit"
    );
    pool.path_limit
        .store(options.paths, std::sync::atomic::Ordering::Relaxed);
    // Bind every requested port before publishing readiness or accepting clients.
    let mut listeners = Vec::with_capacity(planned.len());
    for listener in planned {
        listeners.push((
            TcpListener::bind(listener.address).await.with_context(|| {
                format!("bind SOCKS5 for {} at {}", listener.exit, listener.address)
            })?,
            listener.exit,
        ));
    }
    let permits = Arc::new(Semaphore::new(MAX_STREAMS));
    let mut tasks = JoinSet::new();
    for (listener, exit) in listeners {
        tracing::info!(address=%listener.local_addr()?, %exit, "SOCKS5 proxy ready");
        tasks.spawn(listen(listener, pool.clone(), exit, permits.clone()));
    }
    let mut discovery = JoinSet::new();
    // Prepare optional entrances without delaying the direct SOCKS listener or
    // opening any target TCP connection. Every logical flow can then use them.
    for exit in selected_exits {
        let pool = pool.clone();
        discovery.spawn(async move {
            let _ = pool.prepare_paths(&exit).await;
        });
    }
    let mut refresh = tokio::time::interval(Duration::from_secs(15));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Entrance selection only acts on evidence younger than two seconds.
    let mut health = tokio::time::interval(Duration::from_secs(1));
    health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut shutdown = Shutdown::new();
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            _ = health.tick() => pool.report_health(),
            result = tasks.join_next() => { result.context("proxy listeners stopped")???; bail!("proxy listener stopped"); }
            _ = refresh.tick(), if discovery.is_empty() => {
                let pool = pool.clone(); let entries = options.connect.clone();
                discovery.spawn(async move { if let Ok(nodes) = pool.identity.discover_any(&entries).await { pool.refresh(nodes); } });
            }
            _ = discovery.join_next(), if !discovery.is_empty() => {}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    discovery.abort_all();
    while discovery.join_next().await.is_some() {}
    pool.shutdown().await;
    Ok(())
}
pub(super) async fn listen(
    listener: TcpListener,
    pool: Arc<Pool>,
    exit: String,
    permits: Arc<Semaphore>,
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
                    if let Err(error) = super::socks::serve(tcp, pool, &exit).await { tracing::debug!(%error, %exit, "SOCKS5 client closed"); }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}
