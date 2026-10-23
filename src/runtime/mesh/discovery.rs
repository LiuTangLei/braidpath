use super::*;

const CACHE: &str = "client-peers.json";

/// A fresh authenticated response replaces cached hints with the same ID or
/// address, so a moved or replaced member cannot block discovery. The cache
/// stays bounded and keeps current members before older hints.
pub(super) fn merge_known(previous: &[Node], incoming: &[Node]) -> Result<Vec<Node>> {
    entrances::validate_nodes(incoming)?;
    let mut merged: BTreeMap<_, _> = incoming.iter().map(|n| (n.id.clone(), n.clone())).collect();
    // Resolve all same-ID incarnations before the capacity pass. A full
    // incoming directory must not skip a newer record near the end of a cache.
    for node in previous {
        if merged
            .get(&node.id)
            .is_some_and(|incoming| !incoming.supersedes(node))
        {
            // Prefer the already-authenticated newer incarnation over another
            // stale record claiming its address; keep the result unambiguous.
            merged.retain(|id, other| *id == node.id || other.address != node.address);
            merged.insert(node.id.clone(), node.clone());
        }
    }
    for node in previous {
        if merged.len() >= MAX_NODES {
            break;
        }
        if !merged.contains_key(&node.id) && !merged.values().any(|n| n.address == node.address) {
            merged.insert(node.id.clone(), node.clone());
        }
    }
    Ok(merged.into_values().collect())
}

/// Keep the freshly reported set of IDs while using the newest authenticated
/// incarnation known for each. Cached-only members are still just hints.
pub(super) fn current_nodes(known: &[Node], incoming: &[Node]) -> Result<Vec<Node>> {
    let nodes = incoming
        .iter()
        .filter_map(|node| known.iter().find(|current| current.id == node.id).cloned())
        .collect::<Vec<_>>();
    entrances::validate_nodes(&nodes)?;
    Ok(nodes)
}

pub(super) fn cached(dir: &Path) -> Vec<Node> {
    let path = dir.join(CACHE);
    if !path.exists() {
        return vec![];
    }
    match read_json::<Vec<Node>>(&path).and_then(|nodes| {
        entrances::validate_nodes(&nodes)?;
        Ok(nodes)
    }) {
        Ok(nodes) => nodes,
        Err(error) => {
            tracing::warn!(%error, "ignoring invalid client discovery cache");
            vec![]
        }
    }
}

/// One ordered, coalescing writer shared by bootstrap and maintenance. The
/// blocking worker owns its buffers until the newest snapshot is durable even
/// if the async caller is cancelled. At most one write and one bounded pending
/// snapshot exist; no filesystem work runs in the maintenance select loop.
#[derive(Clone)]
pub(super) struct Cache(Arc<CacheInner>);
struct CacheInner {
    dir: PathBuf,
    state: Mutex<CacheState>,
    drained: tokio::sync::Notify,
    #[cfg(test)]
    before_write: Option<Arc<dyn Fn() + Send + Sync>>,
}
struct CacheState {
    known: Vec<Node>,
    pending: Option<Vec<Node>>,
    running: bool,
    dirty: bool,
}
impl Cache {
    pub(super) fn open(dir: PathBuf) -> Self {
        let known = cached(&dir);
        Self(Arc::new(CacheInner {
            dir,
            state: Mutex::new(CacheState {
                known,
                pending: None,
                running: false,
                dirty: false,
            }),
            drained: tokio::sync::Notify::new(),
            #[cfg(test)]
            before_write: None,
        }))
    }

    #[cfg(test)]
    pub(super) fn with_before_write(dir: PathBuf, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        let mut cache = Self::open(dir);
        Arc::get_mut(&mut cache.0).unwrap().before_write = Some(hook);
        cache
    }

    pub(super) fn known(&self) -> Vec<Node> {
        self.0.state.lock().expect("client cache").known.clone()
    }

    pub(super) fn remember(&self, nodes: &[Node]) -> Result<Vec<Node>> {
        let mut state = self.0.state.lock().expect("client cache");
        let known = merge_known(&state.known, nodes)?;
        let changed = known != state.known;
        if changed {
            state.known = known.clone();
            state.dirty = true;
        }
        // A failed write stays dirty, but only a later authenticated update
        // retries it; a disk outage cannot create an unbounded retry loop.
        if changed || (state.dirty && !state.running) {
            state.pending = Some(known.clone());
            if !state.running {
                state.running = true;
                let cache = self.clone();
                tokio::task::spawn_blocking(move || cache.write_pending());
            }
        }
        Ok(known)
    }

    fn write_pending(&self) {
        loop {
            let nodes = {
                let mut state = self.0.state.lock().expect("client cache");
                match state.pending.take() {
                    Some(nodes) => nodes,
                    None => {
                        state.running = false;
                        self.0.drained.notify_waiters();
                        return;
                    }
                }
            };
            #[cfg(test)]
            if let Some(before_write) = &self.0.before_write {
                before_write();
            }
            let result = serde_json::to_vec(&nodes)
                .map_err(anyhow::Error::from)
                .and_then(|bytes| storage::atomic_write(&self.0.dir.join(CACHE), &bytes, true));
            match result {
                Ok(()) => {
                    let mut state = self.0.state.lock().expect("client cache");
                    if state.known == nodes {
                        state.dirty = false;
                    }
                }
                Err(error) => tracing::warn!(%error, "could not persist client discovery hints"),
            }
        }
    }

    #[cfg(test)]
    pub(super) async fn flush(&self) {
        loop {
            let drained = self.0.drained.notified();
            tokio::pin!(drained);
            drained.as_mut().enable();
            if !self.0.state.lock().expect("client cache").running {
                return;
            }
            drained.await;
        }
    }
}

impl ClientIdentity {
    pub async fn discover(&self, address: SocketAddr) -> Result<Vec<Node>> {
        self.query_entries(&[address], None).await
    }

    /// Explicit entries take precedence. Cached authenticated members provide
    /// a second bounded attempt when every requested bootstrap is unavailable.
    pub async fn discover_any(&self, entries: &[SocketAddr]) -> Result<Vec<Node>> {
        self.discover_for(entries, None).await
    }

    /// A partial member view is useful for listing, but cannot complete a
    /// client bootstrap until it contains the selected exit.
    pub async fn discover_exit(&self, entries: &[SocketAddr], exit: &str) -> Result<Vec<Node>> {
        self.discover_for(entries, Some(exit)).await
    }

    async fn discover_for(&self, entries: &[SocketAddr], exit: Option<&str>) -> Result<Vec<Node>> {
        ensure!(
            !entries.is_empty() && entries.len() <= MAX_NODES,
            "provide 1..32 discovery entries"
        );
        let failure = match self.query_entries(entries, exit).await {
            Ok(nodes) => return Ok(nodes),
            Err(error) => error,
        };
        let alternatives: Vec<_> = self
            .cache
            .known()
            .into_iter()
            .map(|node| node.address)
            .filter(|address| !entries.contains(address))
            .collect();
        if alternatives.is_empty() {
            return Err(failure).context("no discovery entry available");
        }
        tracing::info!("discovery entries unavailable; trying previously authenticated members");
        self.query_entries(&alternatives, exit)
            .await
            .context("cached discovery entries unavailable")
    }

    async fn query_entries(&self, entries: &[SocketAddr], exit: Option<&str>) -> Result<Vec<Node>> {
        let control = Arc::new(Control::new(
            &self.dir.join("cert.pem"),
            entries.iter().any(|a| a.is_ipv6()),
        )?);
        self.query_with(control, entries, exit).await
    }

    pub(super) async fn query_with(
        &self,
        control: Arc<Control>,
        entries: &[SocketAddr],
        exit: Option<&str>,
    ) -> Result<Vec<Node>> {
        let mut pending = JoinSet::new();
        for address in entries
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
        {
            let control = control.clone();
            let auth = self.auth.clone();
            pending.spawn(async move {
                let nodes: Vec<Node> = control.request(address, &auth, "/mesh/nodes", None).await?;
                entrances::validate_nodes(&nodes)?;
                Ok::<_, anyhow::Error>(nodes)
            });
        }
        let mut last = anyhow::anyhow!("no discovery entries");
        while let Some(result) = pending.join_next().await {
            match result {
                Ok(Ok(nodes)) => {
                    // The response establishes the current ID set, while an
                    // older response cannot regress a known address revision.
                    let nodes = match self
                        .cache
                        .remember(&nodes)
                        .and_then(|known| current_nodes(&known, &nodes))
                    {
                        Ok(nodes) => nodes,
                        Err(error) => {
                            last = error;
                            continue;
                        }
                    };
                    if exit.is_none_or(|exit| nodes.iter().any(|node| node.id == exit)) {
                        return Ok(nodes);
                    }
                    last = anyhow::anyhow!(
                        "discovery response does not contain selected exit {}",
                        exit.unwrap()
                    );
                }
                Ok(Err(error)) => last = error,
                Err(error) => last = error.into(),
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_cache_preserves_late_newer_incarnations_and_unique_addresses() {
        let previous: Vec<_> = (0..MAX_NODES)
            .map(|i| Node {
                id: format!("node_{i:02}"),
                address: SocketAddr::from(([127, 0, 0, 1], 10000 + i as u16)),
                incarnation: 2,
            })
            .collect();
        let mut incoming = previous.clone();
        let newest = previous.last().unwrap();
        incoming.last_mut().unwrap().incarnation = 1;
        incoming.last_mut().unwrap().address.set_port(20000);
        incoming[0].address = newest.address;
        incoming[0].id = "reused".into();
        let merged = merge_known(&previous, &incoming).unwrap();
        entrances::validate_nodes(&merged).unwrap();
        assert!(merged.contains(newest));
        assert!(!merged.iter().any(|node| node.id == "reused"));
        assert!(merged.len() <= MAX_NODES);
        assert_eq!(
            current_nodes(&merged, &[incoming.last().unwrap().clone()]).unwrap(),
            vec![newest.clone()]
        );
    }

    #[tokio::test]
    async fn unchanged_discovery_retries_a_previous_cache_write_failure() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("temporarily-unavailable");
        let cache = Cache::open(dir.clone());
        let node = Node {
            id: "exit".into(),
            address: "127.0.0.1:10000".parse().unwrap(),
            incarnation: 1,
        };
        cache.remember(std::slice::from_ref(&node)).unwrap();
        cache.flush().await;
        assert!(cache.0.state.lock().unwrap().dirty);
        assert!(!dir.join(CACHE).exists());
        fs::create_dir(&dir).unwrap();
        cache.remember(std::slice::from_ref(&node)).unwrap();
        cache.flush().await;
        assert_eq!(cached(&dir), vec![node]);
        assert!(!cache.0.state.lock().unwrap().dirty);
    }

    #[tokio::test]
    async fn blocked_cache_write_coalesces_updates_and_survives_producer_cancellation() {
        use std::sync::{
            Condvar,
            atomic::{AtomicUsize, Ordering},
        };
        let temp = tempfile::tempdir().unwrap();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let entered = Arc::new(tokio::sync::Notify::new());
        let writes = Arc::new(AtomicUsize::new(0));
        let cache = Cache::with_before_write(temp.path().to_path_buf(), {
            let gate = gate.clone();
            let entered = entered.clone();
            let writes = writes.clone();
            Arc::new(move || {
                if writes.fetch_add(1, Ordering::SeqCst) == 0 {
                    entered.notify_one();
                    // Bound the fixture even if an assertion fails.
                    let _ = gate
                        .1
                        .wait_timeout_while(
                            gate.0.lock().unwrap(),
                            Duration::from_secs(3),
                            |open| !*open,
                        )
                        .unwrap();
                }
            })
        });
        let initial = Node {
            id: "exit".into(),
            address: "127.0.0.1:10000".parse().unwrap(),
            incarnation: 0,
        };
        cache.remember(std::slice::from_ref(&initial)).unwrap();
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        let (sent, received) = tokio::sync::oneshot::channel();
        let producer = tokio::spawn({
            let cache = cache.clone();
            async move {
                for incarnation in 1..=128 {
                    let mut node = initial.clone();
                    node.incarnation = incarnation;
                    node.address.set_port(10000 + incarnation as u16);
                    cache.remember(&[node]).unwrap();
                }
                sent.send(()).unwrap();
                std::future::pending::<()>().await;
            }
        });
        tokio::time::timeout(Duration::from_secs(1), received)
            .await
            .unwrap()
            .unwrap();
        producer.abort();
        let _ = producer.await;
        // This runs on the same single Tokio thread while the disk worker is
        // blocked; only the newest <=32-member snapshot is pending.
        let expected = cache.known();
        assert_eq!(expected[0].incarnation, 128);
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            cache.0.state.lock().unwrap().pending.as_ref().unwrap(),
            &expected
        );
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        tokio::time::timeout(Duration::from_secs(1), cache.flush())
            .await
            .unwrap();
        assert_eq!(cached(temp.path()), expected);
        assert_eq!(writes.load(Ordering::SeqCst), 2);
    }

    async fn reply_once(identity: &ClientIdentity, id: &str, delay: Duration) -> (Node, AbortTask) {
        let endpoint = transport::server(
            "127.0.0.1:0".parse().unwrap(),
            &identity.dir.join("cert.pem"),
            &identity.dir.join("key.pem"),
            transport::Congestion::default(),
        )
        .unwrap();
        let node = Node {
            id: id.into(),
            incarnation: 0,
            address: endpoint.local_addr().unwrap(),
        };
        let body = serde_json::to_vec(&vec![node.clone()]).unwrap();
        let auth = identity.auth.clone();
        let task = AbortTask(tokio::spawn(async move {
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
            assert_eq!(request.headers()["authorization"], auth);
            tokio::time::sleep(delay).await;
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream.send_data(Bytes::from(body)).await.unwrap();
            stream.finish().await.unwrap();
            let _ = connection.closed().await;
        }));
        (node, task)
    }

    #[tokio::test]
    async fn selected_exit_waits_for_complete_entry_and_tries_cached_entries_after_partial_success()
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for use_cache in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let dir = temp.path().join("identity");
            transport::initialize(&dir, NAME).unwrap();
            let auth = format!("Bearer {}", transport::token(&dir.join("token")).unwrap());
            let cache = Cache::open(dir.clone());
            let identity = ClientIdentity { dir, auth, cache };
            let (partial, _partial) = reply_once(&identity, "partial", Duration::ZERO).await;
            let (complete, _complete) =
                reply_once(&identity, "exit", Duration::from_millis(100)).await;
            let entries = if use_cache {
                identity
                    .cache
                    .remember(std::slice::from_ref(&complete))
                    .unwrap();
                vec![partial.address]
            } else {
                vec![partial.address, complete.address]
            };
            let nodes = tokio::time::timeout(
                Duration::from_secs(2),
                identity.discover_exit(&entries, "exit"),
            )
            .await
            .expect("complete entry was not considered")
            .unwrap();
            assert_eq!(nodes, vec![complete]);
        }
    }
    #[tokio::test]
    async fn bootstrap_does_not_regress_a_newer_authenticated_exit_incarnation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("identity");
        transport::initialize(&dir, NAME).unwrap();
        let auth = format!("Bearer {}", transport::token(&dir.join("token")).unwrap());
        let cache = Cache::open(dir.clone());
        let identity = ClientIdentity { dir, auth, cache };
        let (stale, _server) = reply_once(&identity, "exit", Duration::ZERO).await;
        let mut newer = stale.clone();
        newer.address.set_port(if stale.address.port() == 20000 {
            20001
        } else {
            20000
        });
        newer.incarnation = 1;
        identity
            .cache
            .remember(std::slice::from_ref(&newer))
            .unwrap();
        let discovered = identity
            .discover_exit(&[stale.address], "exit")
            .await
            .unwrap();
        assert_eq!(discovered, vec![newer]);
        identity.cache.flush().await;
    }
}
