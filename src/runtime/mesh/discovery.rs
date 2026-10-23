use super::*;

const CACHE: &str = "client-peers.json";

/// A fresh authenticated response replaces cached hints with the same ID or
/// address, so a moved or replaced member cannot block discovery. The cache
/// stays bounded and keeps current members before older hints.
pub(super) fn merge_known(previous: &[Node], incoming: &[Node]) -> Result<Vec<Node>> {
    entrances::validate_nodes(incoming)?;
    let mut merged: BTreeMap<_, _> = incoming.iter().map(|n| (n.id.clone(), n.clone())).collect();
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

pub(super) fn remember(dir: &Path, nodes: &[Node]) -> Result<()> {
    let previous = cached(dir);
    let known = merge_known(&previous, nodes)?;
    if known != previous {
        storage::atomic_write(&dir.join(CACHE), &serde_json::to_vec(&known)?, true)?;
    }
    Ok(())
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
        let alternatives: Vec<_> = cached(&self.dir)
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
                    // Liveness always comes from this new authenticated response.
                    if let Err(error) = remember(&self.dir, &nodes) {
                        tracing::warn!(%error, "could not persist client discovery hints");
                    }
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
            let identity = ClientIdentity { dir, auth };
            let (partial, _partial) = reply_once(&identity, "partial", Duration::ZERO).await;
            let (complete, _complete) =
                reply_once(&identity, "exit", Duration::from_millis(100)).await;
            let entries = if use_cache {
                remember(&identity.dir, std::slice::from_ref(&complete)).unwrap();
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
}
