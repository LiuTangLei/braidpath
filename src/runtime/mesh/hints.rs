//! Bounded, restart-safe addresses of forgotten members. They heal a long
//! partition without manual joins; they are never trusted liveness.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

const FILE: &str = "reconnect-peers.json";
// A retired server stops being probed after this long. A partition that lasts
// longer needs a manual `--join`.
pub(super) const HINT_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
// Probed concurrently per reconnect round: a full set is tried in eight rounds.
pub(super) const RECONNECT_BATCH: usize = 4;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Hint {
    pub node: Node,
    /// UTC seconds since the Unix epoch when this server forgot the member.
    pub forgotten_unix: u64,
}
impl Hint {
    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.forgotten_unix) >= HINT_TTL.as_secs()
    }
}

pub(super) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Hints are optional: an unreadable file is reported and ignored, never a
/// reason to refuse startup.
pub(super) fn load(dir: &Path) -> Vec<Hint> {
    let path = dir.join(FILE);
    if !path.exists() {
        return vec![];
    }
    match read_json::<Vec<Hint>>(&path).and_then(|hints| {
        ensure!(hints.len() <= MAX_NODES, "too many reconnect hints");
        let nodes: Vec<_> = hints.iter().map(|h| h.node.clone()).collect();
        if !nodes.is_empty() {
            entrances::validate_nodes(&nodes)?;
        }
        Ok(hints)
    }) {
        Ok(hints) => hints,
        Err(error) => {
            tracing::warn!(%error, "ignoring invalid reconnect hints");
            vec![]
        }
    }
}

pub(super) fn save(dir: &Path, hints: &[Hint]) -> Result<()> {
    storage::atomic_write(&dir.join(FILE), &serde_json::to_vec(hints)?, true)
}

/// Newly forgotten members replace older hints with the same ID or address.
/// Expired hints are dropped and the most recently forgotten are kept.
pub(super) fn add(hints: &[Hint], departed: &[Node], now: u64) -> Vec<Hint> {
    let mut next: Vec<_> = departed
        .iter()
        .map(|node| Hint {
            node: node.clone(),
            forgotten_unix: now,
        })
        .collect();
    for hint in hints {
        if !hint.expired(now)
            && !next
                .iter()
                .any(|h| h.node.id == hint.node.id || h.node.address == hint.node.address)
        {
            next.push(hint.clone());
        }
    }
    // Stable: newly departed members stay ahead of equally recent hints.
    next.sort_by_key(|hint| std::cmp::Reverse(hint.forgotten_unix));
    next.truncate(MAX_NODES);
    next
}

/// Hints worth probing: unexpired, and not the local node or a current
/// member's ID or address. A member that is forgotten again gets a new hint.
pub(super) fn useful(hints: &[Hint], own: &Node, members: &[&Node], now: u64) -> Vec<Hint> {
    hints
        .iter()
        .filter(|hint| {
            !hint.expired(now)
                && std::iter::once(own)
                    .chain(members.iter().copied())
                    .all(|n| n.id != hint.node.id && n.address != hint.node.address)
        })
        .cloned()
        .collect()
}
