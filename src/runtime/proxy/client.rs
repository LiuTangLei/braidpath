use super::{protocol::*, *};
use crate::runtime::{mesh, shutdown::Shutdown, transport};
use anyhow::{Context, bail};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    str::FromStr,
    sync::{
        RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    net::TcpListener,
    sync::{Mutex as AsyncMutex, Semaphore},
    task::JoinSet,
    time::timeout,
};

#[derive(Clone, Debug)]
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
}
pub(super) struct Connection {
    pub(super) raw: quinn::Connection,
    pub(super) router: Arc<Router>,
    _reader: AbortTask,
    _close: CloseConnection,
    _endpoint: quinn::Endpoint,
}
struct Slot {
    node: RwLock<mesh::Node>,
    connection: AsyncMutex<Option<(SocketAddr, Arc<Connection>)>>,
}
pub(super) struct Pool {
    identity: mesh::ClientIdentity,
    token: String,
    slots: BTreeMap<String, Slot>,
    exits: Vec<String>,
    next: AtomicUsize,
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
                    connection: AsyncMutex::new(None),
                },
            );
        }
        let token = transport::token(&identity.dir.join("token"))?;
        Ok(Arc::new(Self {
            identity,
            token,
            slots,
            exits,
            next: AtomicUsize::new(0),
        }))
    }
    pub(super) async fn select(&self, pinned: Option<&str>) -> Result<(String, Arc<Connection>)> {
        let choices = match pinned {
            Some(id) => vec![id.to_owned()],
            None => {
                let start = self.next.fetch_add(1, Ordering::Relaxed) % self.exits.len();
                (0..self.exits.len())
                    .map(|i| self.exits[(start + i) % self.exits.len()].clone())
                    .collect()
            }
        };
        let mut last = None;
        for id in choices {
            match timeout(Duration::from_secs(2), self.get(&id)).await {
                Ok(Ok(conn)) => return Ok((id, conn)),
                Ok(Err(e)) => last = Some(e),
                Err(e) => last = Some(e.into()),
            }
        }
        Err(last.context("no selected proxy exit")?).context("selected proxy exits unavailable")
    }
    async fn get(&self, id: &str) -> Result<Arc<Connection>> {
        let slot = self.slots.get(id).context("exit not selected")?;
        let address = slot.node.read().expect("proxy node").address;
        let mut cached = slot.connection.lock().await;
        if let Some((at, conn)) = &*cached
            && *at == address
            && conn.raw.close_reason().is_none()
        {
            return Ok(conn.clone());
        }
        *cached = None;
        let endpoint = transport::proxy_client(address, &self.identity.dir.join("cert.pem"))?;
        let connection = timeout(CONNECT_TIMEOUT, async {
            let raw = endpoint.connect(address, &self.identity.name())?.await?;
            let close = CloseConnection(raw.clone());
            let (mut send, mut recv) = raw.open_bi().await?;
            let mut auth = vec![1];
            auth.extend(self.token.as_bytes());
            auth.push(id.len() as u8);
            auth.extend(id.as_bytes());
            send.write_all(&auth).await?;
            send.finish()?;
            let response = recv.read_to_end(1).await?;
            ensure!(response == [0], "proxy authentication rejected");
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
        *cached = Some((address, connection.clone()));
        Ok(connection)
    }
    fn refresh(&self, nodes: Vec<mesh::Node>) {
        for node in nodes {
            if let Some(slot) = self.slots.get(&node.id) {
                let mut current = slot.node.write().expect("proxy node");
                if node.incarnation >= current.incarnation {
                    *current = node;
                }
            }
        }
    }
}

pub async fn client(options: ClientOptions) -> Result<()> {
    ensure!(
        options.listen.ip().is_loopback(),
        "SOCKS5 listeners must use loopback addresses"
    );
    ensure!(
        options.socks5.len() <= 8,
        "at most eight pinned SOCKS5 listeners"
    );
    ensure!(
        !options.exits.is_empty() && options.exits.len() <= 8,
        "select 1..8 proxy exits"
    );
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
    let pool = Pool::new(options.identity, nodes, options.exits)?;
    // Bind every requested port before publishing readiness or accepting clients.
    let mut listeners = vec![(TcpListener::bind(options.listen).await?, None)];
    for listener in options.socks5 {
        ensure!(
            listener.address.ip().is_loopback() && pool.slots.contains_key(&listener.exit),
            "pinned listener must reference a selected exit and a loopback address"
        );
        listeners.push((
            TcpListener::bind(listener.address).await?,
            Some(listener.exit),
        ));
    }
    let permits = Arc::new(Semaphore::new(MAX_STREAMS));
    let mut tasks = JoinSet::new();
    for (listener, exit) in listeners {
        tracing::info!(address=%listener.local_addr()?, exit=exit.as_deref().unwrap_or("selected-exit-pool"), "SOCKS5 proxy ready");
        tasks.spawn(listen(listener, pool.clone(), exit, permits.clone()));
    }
    let mut discovery = JoinSet::new();
    let mut refresh = tokio::time::interval(Duration::from_secs(15));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut shutdown = Shutdown::new();
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
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
    Ok(())
}
pub(super) async fn listen(
    listener: TcpListener,
    pool: Arc<Pool>,
    pinned: Option<String>,
    permits: Arc<Semaphore>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                tcp.set_nodelay(true)?;
                let pool = pool.clone(); let pinned = pinned.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = super::socks::serve(tcp, pool, pinned.as_deref()).await { tracing::debug!(%error, "SOCKS5 client closed"); }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}
