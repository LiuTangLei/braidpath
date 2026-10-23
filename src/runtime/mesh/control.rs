//! Small, bounded HTTP/3 pool for mesh synchronization and lease maintenance.
use super::{AbortTask, MAX_BODY, MAX_NODES, NAME, transport};
use anyhow::{Context, Result, ensure};
use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode};
use serde::de::DeserializeOwned;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, time::timeout_at};

type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type Slot = Arc<Mutex<Option<Connection>>>;

#[derive(Debug)]
pub(super) struct Rejected(pub StatusCode, pub Option<super::status::Failure>);
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mesh request rejected ({}, {:?})", self.0, self.1)
    }
}
impl std::error::Error for Rejected {}

// The guard also covers cancellation during HTTP/3 setup, before the driver is
// spawned. Merely dropping a Quinn handle does not necessarily close its peer.
struct CloseConnection(quinn::Connection);
impl Drop for CloseConnection {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"mesh control released");
    }
}
struct Connection {
    raw: CloseConnection,
    sender: Sender,
    driver: AbortTask,
    used: Instant,
}
impl Connection {
    fn closed(&self) -> bool {
        self.raw.0.close_reason().is_some() || self.driver.0.is_finished()
    }

    async fn request<T: DeserializeOwned>(
        &mut self,
        auth: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<T> {
        let req = Request::builder()
            .method(if body.is_some() {
                Method::POST
            } else {
                Method::GET
            })
            .uri(format!("https://{NAME}{path}"))
            .header("authorization", auth)
            .body(())?;
        let mut request = self.sender.send_request(req).await?;
        if let Some(body) = body {
            request.send_data(Bytes::from(body)).await?;
        }
        request.finish().await?;
        let response = request.recv_response().await?;
        let mut data = Vec::new();
        while let Some(mut part) = request.recv_data().await? {
            ensure!(
                data.len() + part.remaining() <= MAX_BODY,
                "mesh response too large"
            );
            data.extend(part.copy_to_bytes(part.remaining()));
        }
        if response.status() != StatusCode::OK {
            return Err(Rejected(
                response.status(),
                serde_json::from_slice::<super::status::ErrorReply>(&data)
                    .ok()
                    .map(|r| r.code),
            )
            .into());
        }
        Ok(serde_json::from_slice(&data)?)
    }
}

pub(super) struct Control {
    v4: Option<quinn::Endpoint>,
    v6: Option<quinn::Endpoint>,
    peers: std::sync::Mutex<BTreeMap<SocketAddr, Slot>>,
    capacity: usize,
}
impl Control {
    pub(super) fn new(ca: &Path, ipv6: bool) -> Result<Self> {
        Self::bound(ca, ipv6, &super::Uplink::default())
    }

    pub(super) fn bound(ca: &Path, ipv6: bool, uplink: &super::Uplink) -> Result<Self> {
        let endpoint = |remote| {
            transport::client_bound(
                remote,
                ca,
                uplink.interface.as_deref(),
                transport::Congestion::default(),
                uplink.bind.map(|ip| SocketAddr::new(ip, 0)),
            )
        };
        let v4 = if uplink.bind.is_none_or(|ip| ip.is_ipv4()) {
            Some(endpoint("127.0.0.1:1".parse()?)?)
        } else {
            None
        };
        let v6 = if uplink.bind.is_none_or(|ip| ip.is_ipv6()) {
            match endpoint("[::1]:1".parse()?) {
                Ok(e) => Some(e),
                Err(e) if ipv6 => return Err(e),
                Err(_) => None,
            }
        } else {
            None
        };
        Ok(Self {
            v4,
            v6,
            peers: std::sync::Mutex::new(BTreeMap::new()),
            capacity: MAX_NODES,
        })
    }

    pub(super) async fn capabilities(
        &self,
        address: SocketAddr,
        auth: &str,
    ) -> Result<super::Capabilities> {
        let caps: super::Capabilities = self
            .request(address, auth, "/mesh/info", None)
            .await
            .context("server must support v0.3 mesh capability negotiation")?;
        caps.check()?;
        Ok(caps)
    }

    pub(super) fn server(ca: &Path, ipv6: bool) -> Result<Self> {
        let mut control = Self::new(ca, ipv6)?;
        control.capacity += super::hints::RECONNECT_BATCH;
        Ok(control)
    }

    fn slot(&self, address: SocketAddr) -> Result<Slot> {
        let mut peers = self.peers.lock().expect("control peers");
        if let Some(slot) = peers.get(&address) {
            return Ok(slot.clone());
        }
        ensure!(
            peers.len() < self.capacity,
            "mesh control destination limit reached"
        );
        let slot = Arc::new(Mutex::new(None));
        peers.insert(address, slot.clone());
        Ok(slot)
    }

    async fn connect(&self, address: SocketAddr) -> Result<Connection> {
        let endpoint = if address.is_ipv4() {
            self.v4
                .as_ref()
                .context("IPv4 control endpoint unavailable for uplink")?
        } else {
            self.v6
                .as_ref()
                .context("IPv6 control endpoint unavailable")?
        };
        let raw = CloseConnection(endpoint.connect(address, NAME)?.await?);
        let (mut driver, sender) =
            h3::client::new(h3_quinn::Connection::new(raw.0.clone())).await?;
        let driver = AbortTask(tokio::spawn(async move {
            let error = driver.wait_idle().await;
            tracing::debug!(%address, %error, "mesh control connection ended");
        }));
        Ok(Connection {
            raw,
            sender,
            driver,
            used: Instant::now(),
        })
    }

    /// Close cached connections unused for `idle` and forget their slots, so
    /// keepalives do not pin connections to rotated or departed members.
    pub(super) fn prune(&self, idle: Duration) {
        self.peers.lock().expect("control peers").retain(|_, slot| {
            // Another request holds or is waiting for this slot.
            if Arc::strong_count(slot) > 1 {
                return true;
            }
            let Ok(mut cached) = slot.try_lock() else {
                return true;
            };
            if cached
                .as_ref()
                .is_some_and(|conn| conn.closed() || conn.used.elapsed() >= idle)
            {
                *cached = None;
            }
            cached.is_some()
        });
    }

    pub(super) async fn request<T: DeserializeOwned>(
        &self,
        address: SocketAddr,
        auth: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<T> {
        ensure!(
            body.as_ref().is_none_or(|data| data.len() <= MAX_BODY),
            "mesh request too large"
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        let slot = self.slot(address)?;
        // Serializing one destination avoids duplicate handshakes and matches
        // the server's bounded control processing. Other peers remain parallel.
        let mut cached = timeout_at(deadline, slot.lock()).await?;
        let mut connection = cached.take().filter(|conn| !conn.closed());
        let result = timeout_at(deadline, async {
            if connection.is_none() {
                connection = Some(self.connect(address).await?);
            }
            connection
                .as_mut()
                .expect("connected control peer")
                .request(auth, path, body)
                .await
        })
        .await?;
        // A complete, bounded HTTP rejection is still a healthy connection.
        // Reuse it for e.g. allocating a replacement after an expired lease.
        // Transport/protocol errors, timeout and cancellation discard it;
        // no request is replayed, including allocations with an unknown result.
        if result.is_ok() || result.as_ref().is_err_and(|error| error.is::<Rejected>()) {
            if let Some(connection) = connection.as_mut() {
                connection.used = Instant::now();
            }
            *cached = connection;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{sync::mpsc, task::JoinSet, time::timeout};

    struct Server {
        _dir: tempfile::TempDir,
        endpoint: quinn::Endpoint,
        _task: AbortTask,
        accepts: Arc<AtomicUsize>,
        requests: Arc<AtomicUsize>,
        received: mpsc::UnboundedReceiver<quinn::Connection>,
    }
    impl Server {
        fn new(first_status: Option<StatusCode>) -> Self {
            Self::with_body(first_status, Bytes::from_static(b"1"))
        }
        fn with_body(first_status: Option<StatusCode>, first_body: Bytes) -> Self {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let dir = tempfile::tempdir().unwrap();
            let identity = dir.path().join("identity");
            transport::initialize(&identity, NAME).unwrap();
            let endpoint = transport::server(
                "127.0.0.1:0".parse().unwrap(),
                &identity.join("cert.pem"),
                &identity.join("key.pem"),
                transport::Congestion::default(),
            )
            .unwrap();
            let accepts = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(AtomicUsize::new(0));
            let (sent, received) = mpsc::unbounded_channel();
            let listener = endpoint.clone();
            let accepts_count = accepts.clone();
            let requests_count = requests.clone();
            let task = AbortTask(tokio::spawn(async move {
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        incoming = listener.accept() => {
                            let Some(incoming) = incoming else { break };
                            let requests = requests_count.clone();
                            let sent = sent.clone();
                            let accepts = accepts_count.clone();
                            let first_body = first_body.clone();
                            connections.spawn(async move {
                                let conn = incoming.await.unwrap();
                                accepts.fetch_add(1, Ordering::SeqCst);
                                let mut h3 = h3::server::Connection::<_, Bytes>::new(
                                    h3_quinn::Connection::new(conn.clone())
                                ).await.unwrap();
                                while let Ok(Some(resolver)) = h3.accept().await {
                                    let (_, mut stream) = resolver.resolve_request().await.unwrap();
                                    let index = requests.fetch_add(1, Ordering::SeqCst);
                                    let _ = sent.send(conn.clone());
                                    if index == 0 && first_status.is_none() {
                                        conn.closed().await;
                                        break;
                                    }
                                    let status = if index == 0 { first_status.unwrap() } else { StatusCode::OK };
                                    if stream.send_response(http::Response::builder().status(status).body(()).unwrap()).await.is_err() { break; }
                                    let body = if index == 0 { first_body.clone() } else { Bytes::from_static(b"1") };
                                    if stream.send_data(body).await.is_err() { break; }
                                    if stream.finish().await.is_err() { break; }
                                }
                            });
                        }
                        _ = connections.join_next(), if !connections.is_empty() => {}
                    }
                }
            }));
            Self {
                _dir: dir,
                endpoint,
                _task: task,
                accepts,
                requests,
                received,
            }
        }
        fn control(&self) -> Control {
            Control::new(&self._dir.path().join("identity/cert.pem"), false).unwrap()
        }
        fn address(&self) -> SocketAddr {
            self.endpoint.local_addr().unwrap()
        }
        async fn received(&mut self) -> quinn::Connection {
            timeout(Duration::from_secs(2), self.received.recv())
                .await
                .unwrap()
                .unwrap()
        }
    }

    #[tokio::test]
    async fn concurrent_requests_reuse_one_connection_and_drop_closes_it() {
        let mut server = Server::new(Some(StatusCode::OK));
        let control = Arc::new(server.control());
        let address = server.address();
        let mut requests = JoinSet::new();
        for _ in 0..8 {
            let control = control.clone();
            requests.spawn(async move {
                control
                    .request::<u32>(address, "Bearer test", "/mesh/nodes", None)
                    .await
                    .unwrap()
            });
        }
        while let Some(result) = requests.join_next().await {
            assert_eq!(result.unwrap(), 1);
        }
        assert_eq!(server.accepts.load(Ordering::SeqCst), 1);
        assert_eq!(server.requests.load(Ordering::SeqCst), 8);
        let peer = server.received().await;
        drop(control);
        timeout(Duration::from_secs(2), peer.closed())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn complete_rejection_is_typed_not_replayed_and_connection_is_reused() {
        let mut server = Server::new(Some(StatusCode::BAD_REQUEST));
        let control = server.control();
        let error = control
            .request::<u32>(
                server.address(),
                "Bearer test",
                "/mesh/relay",
                Some(b"{}".to_vec()),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Rejected>().unwrap().0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
        let peer = server.received().await;
        assert!(peer.close_reason().is_none());
        assert_eq!(
            control
                .request::<u32>(server.address(), "Bearer test", "/mesh/nodes", None)
                .await
                .unwrap(),
            1
        );
        assert_eq!(server.accepts.load(Ordering::SeqCst), 1);
        assert_eq!(server.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn oversized_rejection_discards_connection_without_replaying() {
        let mut server = Server::with_body(
            Some(StatusCode::BAD_REQUEST),
            Bytes::from(vec![b'x'; MAX_BODY + 1]),
        );
        let control = server.control();
        let error = control
            .request::<u32>(
                server.address(),
                "Bearer test",
                "/mesh/relay",
                Some(b"{}".to_vec()),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("response too large"));
        assert!(!error.is::<Rejected>());
        assert!(
            control
                .slot(server.address())
                .unwrap()
                .lock()
                .await
                .is_none()
        );
        timeout(Duration::from_secs(2), server.received().await.closed())
            .await
            .unwrap();
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn timeout_and_cancellation_release_connection_and_driver() {
        for cancel in [false, true] {
            let mut server = Server::new(None);
            let control = Arc::new(server.control());
            let address = server.address();
            let active = control.clone();
            let request = tokio::spawn(async move {
                active
                    .request::<u32>(address, "Bearer test", "/mesh/relay", Some(b"{}".to_vec()))
                    .await
            });
            let peer = server.received().await;
            if cancel {
                request.abort();
                assert!(request.await.unwrap_err().is_cancelled());
            } else {
                assert!(
                    request
                        .await
                        .unwrap()
                        .unwrap_err()
                        .is::<tokio::time::error::Elapsed>()
                );
            }
            timeout(Duration::from_secs(2), peer.closed())
                .await
                .unwrap();
            assert_eq!(server.requests.load(Ordering::SeqCst), 1);
            assert!(control.slot(address).unwrap().lock().await.is_none());
            assert_eq!(
                control
                    .request::<u32>(address, "Bearer test", "/mesh/nodes", None)
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(server.accepts.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn idle_connections_are_pruned_and_closed() {
        let mut server = Server::new(Some(StatusCode::OK));
        let control = server.control();
        let address = server.address();
        assert_eq!(
            control
                .request::<u32>(address, "Bearer test", "/mesh/nodes", None)
                .await
                .unwrap(),
            1
        );
        let peer = server.received().await;
        control.prune(Duration::from_secs(60));
        assert!(control.slot(address).unwrap().lock().await.is_some());
        control.prune(Duration::ZERO);
        assert!(control.peers.lock().unwrap().is_empty());
        timeout(Duration::from_secs(2), peer.closed())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn server_pool_has_room_for_all_members_and_a_full_reconnect_batch() {
        let server = Server::new(Some(StatusCode::OK));
        let control =
            Control::server(&server._dir.path().join("identity/cert.pem"), false).unwrap();
        for port in 1..=MAX_NODES + super::super::hints::RECONNECT_BATCH {
            control
                .slot(SocketAddr::from(([127, 0, 0, 1], port as u16)))
                .unwrap();
        }
        assert!(control.slot("127.0.0.1:10000".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn destination_cache_is_bounded() {
        let server = Server::new(Some(StatusCode::OK));
        let control = server.control();
        for port in 1..=MAX_NODES {
            control
                .slot(SocketAddr::from(([127, 0, 0, 1], port as u16)))
                .unwrap();
        }
        assert!(
            control
                .slot(SocketAddr::from(([127, 0, 0, 1], MAX_NODES as u16 + 1)))
                .is_err()
        );
        assert!(control.slot(SocketAddr::from(([127, 0, 0, 1], 1))).is_ok());
    }
}
