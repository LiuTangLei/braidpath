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
        self.query_entries(&[address]).await
    }

    /// Explicit entries take precedence. Cached authenticated members provide
    /// a second bounded attempt when every requested bootstrap is unavailable.
    pub async fn discover_any(&self, entries: &[SocketAddr]) -> Result<Vec<Node>> {
        ensure!(
            !entries.is_empty() && entries.len() <= MAX_NODES,
            "provide 1..32 discovery entries"
        );
        let failure = match self.query_entries(entries).await {
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
        self.query_entries(&alternatives)
            .await
            .context("cached discovery entries unavailable")
    }

    async fn query_entries(&self, entries: &[SocketAddr]) -> Result<Vec<Node>> {
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
                    return Ok(nodes);
                }
                Ok(Err(error)) => last = error,
                Err(error) => last = error.into(),
            }
        }
        Err(last)
    }
}
