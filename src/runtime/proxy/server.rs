use super::{protocol::*, *};
use anyhow::Context;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};
use subtle::ConstantTimeEq;
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct ServerConfig {
    pub allow_private: bool,
}
pub struct Server {
    config: ServerConfig,
    token: String,
    exit: String,
    rate: Arc<Rate>,
    stream_budget: Arc<crate::runtime::tunnel::tcp::Budget>,
    connections: Arc<Semaphore>,
    streams: Arc<Semaphore>,
    associations: Arc<Semaphore>,
    destinations: Arc<Semaphore>,
    rejected: AtomicU64,
}
#[derive(Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub connections: usize,
    pub streams: usize,
    pub udp_associations: usize,
    pub udp_destinations: usize,
    pub rejected: u64,
    #[serde(default)]
    pub tcp_flows: usize,
    #[serde(default)]
    pub buffered_bytes: usize,
    #[serde(default)]
    pub control_streams: usize,
}
impl Server {
    pub fn new(
        config: ServerConfig,
        token: String,
        exit: String,
        rate_bps: u64,
    ) -> Result<Arc<Self>> {
        ensure!(
            (64_000..=crate::runtime::MAX_RATE_BPS).contains(&rate_bps),
            "invalid proxy rate"
        );
        ensure!(
            token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid proxy token"
        );
        let rate = Arc::new(Rate::new(rate_bps));
        let stream_budget = Arc::new(crate::runtime::tunnel::tcp::Budget::with_rate(rate.clone()));
        Ok(Arc::new(Self {
            config,
            token,
            exit,
            rate,
            stream_budget,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            streams: Arc::new(Semaphore::new(MAX_STREAMS)),
            associations: Arc::new(Semaphore::new(MAX_ASSOCIATIONS)),
            destinations: Arc::new(Semaphore::new(1024)),
            rejected: AtomicU64::new(0),
        }))
    }
    pub(crate) fn stream_budget(&self) -> Arc<crate::runtime::tunnel::tcp::Budget> {
        self.stream_budget.clone()
    }
    pub fn snapshot(&self) -> Snapshot {
        let (tcp_flows, buffered_bytes) = self.stream_budget.snapshot();
        Snapshot {
            tcp_flows,
            buffered_bytes,
            connections: MAX_CONNECTIONS - self.connections.available_permits(),
            streams: MAX_STREAMS - self.streams.available_permits() + tcp_flows,
            control_streams: MAX_STREAMS - self.streams.available_permits(),
            udp_associations: MAX_ASSOCIATIONS - self.associations.available_permits(),
            udp_destinations: 1024 - self.destinations.available_permits(),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
    pub(crate) async fn connection(
        self: Arc<Self>,
        conn: quinn::Connection,
        pending: OwnedSemaphorePermit,
    ) -> Result<()> {
        let _close = CloseConnection(conn.clone());
        let _permit = self
            .connections
            .clone()
            .try_acquire_owned()
            .context("proxy connection limit")?;
        timeout(CONNECT_TIMEOUT, async {
            let (mut send, mut recv) = conn.accept_bi().await?;
            ensure!(
                recv.id().index() == 0,
                "authentication must be the first stream"
            );
            let auth = recv.read_to_end(130).await?;
            ensure!(
                auth.len() >= 66 && auth[0] == 1,
                "invalid proxy authentication"
            );
            let valid = bool::from(auth[1..65].ct_eq(self.token.as_bytes()))
                && auth[65] as usize == auth.len() - 66
                && auth[66..] == *self.exit.as_bytes();
            ensure!(valid, "proxy authentication or exit mismatch");
            send.write_all(&[0]).await?;
            send.finish()?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        drop(pending);
        conn.set_max_concurrent_bi_streams(((MAX_ASSOCIATIONS + 8) as u32).into());
        let router = Arc::new(Router::default());
        let mut tasks = JoinSet::new();
        let mut maintenance = tokio::time::interval(Duration::from_secs(5));
        let mut telemetry = crate::runtime::transport::ProxyTelemetry::default();
        let mut last = Instant::now();
        loop {
            tokio::select! {
                accepted = conn.accept_bi() => {
                    let (mut send, mut recv) = accepted?;
                    let Ok(permit) = self.streams.clone().try_acquire_owned() else {
                        self.rejected.fetch_add(1, Ordering::Relaxed);
                        // Bound handlers before spawning; refuse only this
                        // request so a healthy native UDP connection survives.
                        let _ = recv.stop(0u32.into());
                        let _ = timeout(CONNECT_TIMEOUT, async {
                            send.write_all(&[1]).await?;
                            send.finish()?;
                            Ok::<_, anyhow::Error>(())
                        }).await;
                        continue;
                    };
                    last = Instant::now();
                    let state = self.clone(); let conn = conn.clone(); let router = router.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = state.clone().stream(conn, send, recv, router).await {
                            state.rejected.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(%error, "proxy stream closed");
                        }
                    });
                }
                data = conn.read_datagram() => router.dispatch(data?),
                _ = tasks.join_next(), if !tasks.is_empty() => { last = Instant::now(); }
                _ = maintenance.tick() => {
                    telemetry.report(&conn, "server", &self.exit);
                    if tasks.is_empty() && last.elapsed() >= UDP_IDLE { return Ok(()); }
                }
            }
        }
    }
    async fn stream(
        self: Arc<Self>,
        conn: quinn::Connection,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        router: Arc<Router>,
    ) -> Result<()> {
        let command = timeout(CONNECT_TIMEOUT, recv.read_u8()).await??;
        match command {
            UDP => {
                let _permit = self
                    .associations
                    .clone()
                    .try_acquire_owned()
                    .context("proxy UDP association limit")?;
                let id = send.id().index();
                let registration = router.register(id)?;
                timeout(CONNECT_TIMEOUT, send.write_all(&[0])).await??;
                // Keep both halves until the local SOCKS TCP association closes.
                self.udp(conn, recv, registration, id).await?;
                send.finish()?;
                Ok(())
            }
            _ => {
                timeout(CONNECT_TIMEOUT, send.write_all(&[7])).await??;
                send.finish()?;
                Ok(())
            }
        }
    }
    async fn udp(
        self: Arc<Self>,
        conn: quinn::Connection,
        mut control: quinn::RecvStream,
        mut registration: Registration,
        id: u64,
    ) -> Result<()> {
        struct Destination {
            socket: Arc<UdpSocket>,
            active: Arc<Mutex<Instant>>,
            _reader: AbortTask,
        }
        let mut flows: HashMap<Address, Destination> = HashMap::new();
        let mut reassembly = Reassembly::default();
        let counter = Arc::new(AtomicU64::new(0));
        let active = Arc::new(Mutex::new(Instant::now()));
        let mut maintenance = tokio::time::interval(Duration::from_secs(5));
        let mut close = [0; 1];
        loop {
            tokio::select! {
                _ = control.read(&mut close) => return Ok(()),
                _ = maintenance.tick() => {
                    flows.retain(|_, f| !f._reader.0.is_finished() && f.active.lock().expect("UDP activity").elapsed() < UDP_IDLE);
                    if active.lock().expect("UDP activity").elapsed() >= UDP_IDLE { return Ok(()); }
                }
                frame = registration.recv.recv() => {
                    let Some(frame) = frame else { return Ok(()); };
                    let Some(packet) = reassembly.receive(frame, Instant::now()) else { continue; };
                    let Ok((address, data)) = packet_parts(&packet).await else { continue; };
                    if self.rate.delay(packet.len()).is_some() { continue; }
                    if flows.get(&address).is_some_and(|f| f._reader.0.is_finished()) { flows.remove(&address); }
                    if !flows.contains_key(&address) {
                        if flows.len() >= MAX_DESTINATIONS { continue; }
                        let Ok(permit) = self.destinations.clone().try_acquire_owned() else { continue; };
                        let opened = timeout(CONNECT_TIMEOUT, async {
                            let mut targets = address.resolve(self.config.allow_private).await?;
                            // UDP connect cannot detect an unreachable dual-stack peer.
                            // Prefer A records; an explicit IPv6 address stays IPv6.
                            targets.sort_by_key(|target| target.is_ipv6());
                            let mut error = None;
                            for target in targets {
                                let socket = udp_socket(if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?).await?;
                                match socket.connect(target).await { Ok(()) => return Ok::<_, anyhow::Error>(socket), Err(e) => error = Some(e) }
                            }
                            Err(error.context("no UDP destination")?.into())
                        }).await;
                        let Ok(Ok(socket)) = opened else { continue; };
                        let socket = Arc::new(socket); let read_socket = socket.clone();
                        let remote = socket.peer_addr()?;
                        let flow_active = Arc::new(Mutex::new(Instant::now())); let touch = flow_active.clone();
                        let state = self.clone(); let conn = conn.clone(); let counter = counter.clone(); let active = active.clone();
                        let reader = AbortTask(tokio::spawn(async move {
                            let _permit = permit;
                            let mut data = vec![0; MAX_UDP + 1];
                            while let Ok(n) = read_socket.recv(&mut data).await {
                                if n > MAX_UDP || state.rate.delay(n).is_some() { continue; }
                                let mut out = Vec::with_capacity(n + 19); Address::Ip(remote).encode(&mut out); out.extend(&data[..n]);
                                if send_packet(&conn, id, counter.fetch_add(1, Ordering::Relaxed), &out).await.is_err() {
                                    if conn.close_reason().is_some() { break; }
                                    continue;
                                }
                                *touch.lock().expect("UDP activity") = Instant::now();
                                *active.lock().expect("UDP activity") = Instant::now();
                            }
                        }));
                        flows.insert(address.clone(), Destination { socket, active: flow_active, _reader: reader });
                    }
                    let flow = flows.get(&address).expect("UDP destination");
                    if flow.socket.send(data).await.is_ok() {
                        *flow.active.lock().expect("UDP activity") = Instant::now();
                        *active.lock().expect("UDP activity") = Instant::now();
                    }
                }
            }
        }
    }
}
// Keep the packet function distinct from the owned buffer in the receive loop.
async fn packet_parts(data: &[u8]) -> Result<(Address, &[u8])> {
    packet(data).await
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use crate::runtime::transport::{self, AckRequest, Congestion};

    struct Fixture {
        server: Arc<Server>,
        connection: quinn::Connection,
        _server: quinn::Endpoint,
        _client: quinn::Endpoint,
        _worker: AbortTask,
    }

    async fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let identity = temp.path().join("identity");
        transport::initialize(&identity, "localhost").unwrap();
        let endpoint = transport::server_with_proxy(
            "127.0.0.1:0".parse().unwrap(),
            &identity.join("cert.pem"),
            &identity.join("key.pem"),
            Congestion::Bbr,
            transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            AckRequest::Unchanged,
            true,
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let client = transport::proxy_client(address, &identity.join("cert.pem"), None).unwrap();
        let (outgoing, incoming) =
            tokio::join!(client.connect(address, "localhost").unwrap(), async {
                endpoint.accept().await.unwrap().await
            });
        let connection = outgoing.unwrap();
        let server = Server::new(
            ServerConfig {
                allow_private: true,
            },
            "a".repeat(64),
            "exit".into(),
            crate::runtime::MAX_RATE_BPS,
        )
        .unwrap();
        let pending = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
        let worker = AbortTask(tokio::spawn({
            let server = server.clone();
            async move {
                let _ = server.connection(incoming.unwrap(), pending).await;
            }
        }));
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let mut auth = vec![1];
        auth.extend("a".repeat(64).bytes());
        auth.extend(b"\x04exit");
        send.write_all(&auth).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(1).await.unwrap(), [0]);
        Fixture {
            server,
            connection,
            _server: endpoint,
            _client: client,
            _worker: worker,
        }
    }

    async fn udp_control(connection: &quinn::Connection) {
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&[UDP]).await.unwrap();
        let mut status = [1];
        recv.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [0]);
        send.finish().unwrap();
        assert!(recv.read_to_end(0).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn exhausted_native_handlers_refuse_one_request_and_recover_the_same_connection() {
        let fixture = fixture().await;
        let held = fixture
            .server
            .streams
            .clone()
            .try_acquire_many_owned(MAX_STREAMS as u32)
            .unwrap();
        let (mut send, mut recv) = fixture.connection.open_bi().await.unwrap();
        send.write_all(&[UDP]).await.unwrap();
        let _ = send.finish();
        let response = timeout(Duration::from_secs(2), recv.read_to_end(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, [1]);
        assert!(fixture.connection.close_reason().is_none());
        assert_eq!(fixture.server.snapshot().rejected, 1);
        drop(held);
        timeout(Duration::from_secs(2), udp_control(&fixture.connection))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), async {
            while fixture.server.snapshot().control_streams != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(fixture.server.snapshot().udp_associations, 0);
        assert_eq!(fixture.server.snapshot().buffered_bytes, 0);
    }

    #[tokio::test]
    async fn removed_tcp_and_bond_commands_cannot_open_targets_or_disable_udp() {
        let fixture = fixture().await;
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        for command in [TCP, 16, 17, 25] {
            let (mut send, mut recv) = fixture.connection.open_bi().await.unwrap();
            let mut request = vec![command];
            if command == TCP {
                Address::Ip(target.local_addr().unwrap()).encode(&mut request);
            }
            send.write_all(&request).await.unwrap();
            let _ = send.finish();
            assert_eq!(
                timeout(Duration::from_secs(2), recv.read_to_end(1))
                    .await
                    .unwrap()
                    .unwrap(),
                [7]
            );
            assert!(fixture.connection.close_reason().is_none());
        }
        assert!(
            timeout(Duration::from_millis(30), target.accept())
                .await
                .is_err()
        );
        timeout(Duration::from_secs(2), udp_control(&fixture.connection))
            .await
            .unwrap();
        assert_eq!(fixture.server.snapshot().tcp_flows, 0);
    }
}
