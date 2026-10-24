//! Authenticated, bounded diagnostics on the existing control connection.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

const REQUIRED: &[&str] = &[
    "exit-binding",
    "node-incarnation",
    "lease-requests",
    "lease-release",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub protocol: u8,
    pub features: Vec<String>,
    pub max_message_bytes: usize,
}
impl Default for Capabilities {
    fn default() -> Self {
        Self {
            protocol: 1,
            features: REQUIRED
                .iter()
                .chain(["udp-fragments-v1"].iter())
                .map(|s| (*s).into())
                .collect(),
            max_message_bytes: super::super::MAX_MESSAGE,
        }
    }
}
impl Capabilities {
    pub(super) fn check(&self) -> Result<()> {
        ensure!(self.protocol == 1, "unsupported mesh control protocol");
        for required in REQUIRED {
            ensure!(
                self.features.iter().any(|f| f == required),
                "missing required mesh capability: {required}"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Failure {
    InvalidRequest,
    LeaseExpired,
    OwnerMismatch,
    RequestReleased,
    ExitUnavailable,
    LeaseLimit,
    SourceLimit,
    Persistence,
    UnsupportedOperation,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Failure {}
#[derive(Serialize, Deserialize)]
pub(super) struct ErrorReply {
    pub code: Failure,
}

#[derive(Default)]
pub(super) struct Persistence {
    failures: AtomicU64,
}
impl Persistence {
    pub(super) fn record<T>(&self, result: Result<T>) -> Result<T> {
        result
            .inspect_err(|_| {
                self.failures.fetch_add(1, Ordering::Relaxed);
            })
            .context(Failure::Persistence)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Status {
    pub node: Node,
    pub capabilities: Capabilities,
    pub known_peers: usize,
    pub directly_live_peers: usize,
    pub reconnect_hints: usize,
    pub leases: usize,
    #[serde(default)]
    pub active_relay_forward_bytes: u64,
    #[serde(default)]
    pub active_relay_return_bytes: u64,
    #[serde(default)]
    pub active_relay_budget_dropped: u64,
    #[serde(default)]
    pub active_relay_queue_dropped: u64,
    #[serde(default)]
    pub active_relay_socket_send_dropped: u64,
    pub lease_limit: usize,
    pub source_lease_limit: usize,
    pub control_connections: usize,
    pub control_connection_limit: usize,
    pub persistence_failures: u64,
    pub recovery: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<super::super::proxy::Snapshot>,
}
impl State {
    pub(super) fn capabilities(&self) -> Capabilities {
        let mut capabilities = Capabilities::default();
        if self.proxy.is_some() {
            capabilities.features.extend([
                "proxy-tcp-v1".into(),
                "proxy-udp-v1".into(),
                "proxy-bond-v2".into(),
            ]);
        }
        capabilities
    }
    pub(super) fn status(&self) -> Status {
        let peers = self.peers.lock().expect("peers");
        let known = peers.len();
        let live = peers
            .values()
            .filter(|p| p.seen.is_some_and(|at| at.elapsed() < LIVE_FOR))
            .count();
        drop(peers);
        let hints = self.reconnect.lock().expect("hints").len();
        let (leases, relay) = {
            let leases = self.leases.lock().expect("leases");
            let mut totals = [0u64; 5];
            for lease in leases.values() {
                lease.metrics.state(|s| {
                    totals[0] += s.relay.get(stats::FORWARD).map_or(0, |r| r.forwarded_bytes);
                    totals[1] += s.relay.get(stats::RETURN).map_or(0, |r| r.forwarded_bytes);
                    for direction in s.relay.values() {
                        totals[2] += direction.budget_dropped;
                        totals[3] += direction.queue_full_dropped;
                        totals[4] += direction.socket_send_dropped;
                    }
                });
            }
            (leases.len(), totals)
        };
        Status {
            node: self.own.clone(),
            capabilities: self.capabilities(),
            proxy: self.proxy.as_ref().map(|p| p.snapshot()),
            known_peers: known,
            directly_live_peers: live,
            reconnect_hints: hints,
            // Read-only: inspection does not renew or remove leases.
            leases,
            active_relay_forward_bytes: relay[0],
            active_relay_return_bytes: relay[1],
            active_relay_budget_dropped: relay[2],
            active_relay_queue_dropped: relay[3],
            active_relay_socket_send_dropped: relay[4],
            lease_limit: 64,
            source_lease_limit: MAX_SOURCE_LEASES,
            control_connections: CONTROL_CONNECTIONS - self.control_connections.available_permits(),
            control_connection_limit: CONTROL_CONNECTIONS,
            persistence_failures: self.persistence.failures.load(Ordering::Relaxed),
            recovery: if live > 0 {
                "connected"
            } else if known > 0 || hints > 0 {
                "reconnecting"
            } else {
                "standalone"
            }
            .into(),
        }
    }
}
impl ClientIdentity {
    pub async fn status(&self, address: SocketAddr) -> Result<Status> {
        Control::new(&self.dir.join("cert.pem"), address.is_ipv6())?
            .request(address, &self.auth, "/mesh/status", None)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn authenticated_status_and_typed_errors_use_existing_control_endpoint() {
        use super::super::tests::{address, server, wait_nodes};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().unwrap();
        let at = address();
        let _server = server(root.path(), "exit", at, address(), None).await;
        let identity = ClientIdentity::open(
            root.path().join("client"),
            &root.path().join("exit/client-key.json"),
        )
        .unwrap();
        wait_nodes(&identity, at, &["exit"]).await;
        let control = Control::new(&identity.dir.join("cert.pem"), false).unwrap();
        control.capabilities(at, &identity.auth).await.unwrap();
        assert_eq!(identity.status(at).await.unwrap().node.id, "exit");
        let denied = control
            .request::<Status>(at, "invalid", "/mesh/status", None)
            .await
            .err()
            .unwrap();
        assert_eq!(
            denied.downcast_ref::<control::Rejected>().unwrap().0,
            http::StatusCode::NOT_FOUND
        );
        let body = serde_json::to_vec(&RelayRequest {
            exit: "exit".into(),
            lease: Some("0".repeat(32)),
            request: None,
        })
        .unwrap();
        let expired = control
            .request::<RelayReply>(at, &identity.auth, "/mesh/relay", Some(body))
            .await
            .err()
            .unwrap();
        assert_eq!(
            expired.downcast_ref::<control::Rejected>().unwrap().1,
            Some(Failure::LeaseExpired)
        );
    }
    #[test]
    fn capability_contract_accepts_optional_but_rejects_missing_required() {
        let mut caps = Capabilities::default();
        caps.features.push("future-optional-feature".into());
        caps.check().unwrap();
        caps.features.retain(|f| f != "exit-binding");
        assert!(
            caps.check()
                .unwrap_err()
                .to_string()
                .contains("exit-binding")
        );
    }
    #[tokio::test]
    async fn status_is_bounded_read_only_and_excludes_secrets() {
        let temp = tempfile::tempdir().unwrap();
        let state = super::super::tests::state(temp.path());
        state
            .persistence
            .record::<()>(Err(anyhow::anyhow!("secret path")))
            .unwrap_err();
        let permit = state.control_permit().unwrap();
        let before = state.status();
        assert_eq!(before.control_connections, 1);
        assert_eq!(before.persistence_failures, 1);
        assert_eq!(before.recovery, "standalone");
        let json = serde_json::to_string(&before).unwrap();
        for secret in [
            "secret path",
            "Bearer",
            "private_key",
            "client_auth",
            "member_auth",
        ] {
            assert!(!json.contains(secret));
        }
        assert_eq!(state.status().leases, before.leases);
        drop(permit);
        assert_eq!(state.status().control_connections, 0);
    }
}
