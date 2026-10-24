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

const DATA_RPCS: usize = 512;
// Download ranges are short, and each flow keeps at most two future waiters.
const DOWNLOAD_RPCS: usize = 1024;
// Each aggregate flow can hold an upload progress wait and a control operation.
const CONTROL_RPCS: usize = super::bond::MAX_FLOWS * 2 + 128;
const RPCS: usize = DATA_RPCS + DOWNLOAD_RPCS + CONTROL_RPCS;

#[derive(Clone, Copy, Debug, Default)]
pub struct ServerConfig {
    pub allow_private: bool,
}
pub struct Server {
    config: ServerConfig,
    token: String,
    exit: String,
    rate: Arc<Rate>,
    bonds: Arc<super::bond::Registry>,
    connections: Arc<Semaphore>,
    streams: Arc<Semaphore>,
    rpcs: Arc<Semaphore>,
    data_rpcs: Arc<Semaphore>,
    downloads: Arc<Semaphore>,
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
    pub rpc_streams: usize,
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
        Ok(Arc::new(Self {
            config,
            token,
            exit,
            rate: Arc::new(Rate::new(rate_bps)),
            bonds: super::bond::Registry::new(),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            streams: Arc::new(Semaphore::new(MAX_STREAMS)),
            rpcs: Arc::new(Semaphore::new(RPCS)),
            data_rpcs: Arc::new(Semaphore::new(DATA_RPCS)),
            downloads: Arc::new(Semaphore::new(DOWNLOAD_RPCS)),
            associations: Arc::new(Semaphore::new(MAX_ASSOCIATIONS)),
            destinations: Arc::new(Semaphore::new(1024)),
            rejected: AtomicU64::new(0),
        }))
    }
    pub fn snapshot(&self) -> Snapshot {
        let (tcp_flows, buffered_bytes) = self.bonds.snapshot();
        Snapshot {
            tcp_flows,
            buffered_bytes,
            connections: MAX_CONNECTIONS - self.connections.available_permits(),
            streams: MAX_STREAMS - self.streams.available_permits() + tcp_flows,
            rpc_streams: RPCS - self.rpcs.available_permits(),
            udp_associations: MAX_ASSOCIATIONS - self.associations.available_permits(),
            udp_destinations: 1024 - self.destinations.available_permits(),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
    fn data_admission(&self, command: u8) -> Result<Option<OwnedSemaphorePermit>> {
        if command == super::bond::PULL {
            return Ok(Some(
                self.downloads
                    .clone()
                    .try_acquire_owned()
                    .context("proxy download RPC limit")?,
            ));
        }
        if matches!(command, TCP | UDP | super::bond::PUT) {
            Ok(Some(
                self.data_rpcs
                    .clone()
                    .try_acquire_owned()
                    .context("proxy data RPC limit")?,
            ))
        } else {
            Ok(None)
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
        crate::runtime::transport::authenticated_proxy(&conn);
        conn.set_max_concurrent_bi_streams(1024u32.into());
        let router = Arc::new(Router::default());
        let mut tasks = JoinSet::new();
        let mut maintenance = tokio::time::interval(Duration::from_secs(5));
        let mut last = Instant::now();
        loop {
            tokio::select! {
                accepted = conn.accept_bi() => {
                    let (mut send, mut recv) = accepted?;
                    let Ok(permit) = self.rpcs.clone().try_acquire_owned() else {
                        self.rejected.fetch_add(1, Ordering::Relaxed);
                        // The outer handler budget can fill before the command
                        // is read. A bounded refusal keeps aggregate clients from
                        // mistaking overload for a broken transport. Older scalar
                        // commands also see a nonzero failure status.
                        let _ = recv.stop(0u32.into());
                        let _ = timeout(CONNECT_TIMEOUT, super::bond::respond(
                            &mut send, super::bond::Reply::Failed(super::bond::BUSY),
                        )).await;
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
                _ = maintenance.tick() => { if tasks.is_empty() && last.elapsed() >= UDP_IDLE && !self.bonds.owns_connection(conn.stable_id()) { return Ok(()); } }
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
        let bond = (super::bond::OPEN..=super::bond::PULL).contains(&command);
        let _data_permit = match self.data_admission(command) {
            Ok(permit) => permit,
            // Aggregate clients retry a busy reply; dropping the stream would
            // instead look like a failed path and move all of its records.
            Err(_) if bond => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                let _ = recv.stop(0u32.into());
                return super::bond::respond(
                    &mut send,
                    super::bond::Reply::Failed(super::bond::BUSY),
                )
                .await;
            }
            Err(error) => return Err(error),
        };
        let _logical_permit = if command == TCP || command == UDP {
            Some(
                self.streams
                    .clone()
                    .try_acquire_owned()
                    .context("proxy stream limit")?,
            )
        } else {
            None
        };
        match command {
            _ if bond => {
                self.bonds
                    .serve(
                        command,
                        &conn,
                        &mut send,
                        &mut recv,
                        self.config.allow_private,
                        self.rate.clone(),
                    )
                    .await
            }
            TCP => {
                let target = timeout(CONNECT_TIMEOUT, Address::read(&mut recv)).await??;
                let connected = timeout(CONNECT_TIMEOUT, async {
                    let addresses = target.resolve(self.config.allow_private).await?;
                    Ok::<_, anyhow::Error>(TcpStream::connect(addresses.as_slice()).await?)
                })
                .await;
                let tcp = match connected {
                    Ok(Ok(tcp)) => tcp,
                    result => {
                        let code = match &result {
                            Ok(Err(error)) => error
                                .downcast_ref::<ReplyError>()
                                .map(|e| e.0)
                                .unwrap_or_else(|| {
                                    if error.downcast_ref::<std::io::Error>().is_some_and(|e| {
                                        e.kind() == std::io::ErrorKind::ConnectionRefused
                                    }) {
                                        5
                                    } else {
                                        4
                                    }
                                }),
                            _ => 4,
                        };
                        timeout(CONNECT_TIMEOUT, send.write_all(&[code])).await??;
                        send.finish()?;
                        return Err(ReplyError(code).into());
                    }
                };
                tcp.set_nodelay(true)?;
                let mut response = vec![0];
                Address::Ip(tcp.local_addr()?).encode(&mut response);
                timeout(CONNECT_TIMEOUT, send.write_all(&response)).await??;
                super::legacy::bridge(tcp, send, recv, Some(&self.rate)).await
            }
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
    #[tokio::test]
    async fn exhausted_handler_budgets_reply_busy_and_recover_on_the_same_connection() {
        use crate::runtime::transport::{self, AckRequest, Congestion};
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
        let at = endpoint.local_addr().unwrap();
        let client = transport::proxy_client(at, &identity.join("cert.pem")).unwrap();
        let (outgoing, incoming) = tokio::join!(client.connect(at, "localhost").unwrap(), async {
            endpoint.accept().await.unwrap().await
        });
        let conn = outgoing.unwrap();
        let server = Server::new(
            ServerConfig::default(),
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
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut auth = vec![1];
        auth.extend("a".repeat(64).bytes());
        auth.extend(b"\x04exit");
        send.write_all(&auth).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(1).await.unwrap(), [0]);

        // Both levels used to reset the RPC, which retired an otherwise good
        // path. Hold the real admission permits and exercise the wire reply.
        for budget in [&server.rpcs, &server.data_rpcs] {
            let held = budget
                .clone()
                .try_acquire_many_owned(budget.available_permits() as u32)
                .unwrap();
            let mut op = super::super::bond::Operation::Put {
                sequence: 0,
                offset: 0,
                data: bytes::Bytes::from_static(b"body"),
            };
            let reply = timeout(
                Duration::from_secs(2),
                super::super::bond::rpc(&conn, [7; 32], &mut op, None),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(matches!(
                reply,
                super::super::bond::Reply::Failed(super::super::bond::BUSY)
            ));
            assert!(conn.close_reason().is_none());
            drop(held);
            let mut close = super::super::bond::Operation::Close;
            let reply = timeout(
                Duration::from_secs(2),
                super::super::bond::rpc(&conn, [7; 32], &mut close, None),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(matches!(reply, super::super::bond::Reply::Accepted));
        }
        timeout(Duration::from_secs(2), async {
            while server.snapshot().rpc_streams != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(server.snapshot().tcp_flows, 0);
        assert_eq!(server.snapshot().buffered_bytes, 0);
        drop(worker);
    }
    #[test]
    fn pending_data_leaves_control_capacity_for_progress_and_reclamation() {
        let server = Server::new(
            ServerConfig::default(),
            "a".repeat(64),
            "exit".into(),
            crate::runtime::MAX_RATE_BPS,
        )
        .unwrap();
        let _data = server
            .data_rpcs
            .clone()
            .try_acquire_many_owned(DATA_RPCS as u32)
            .unwrap();
        let _downloads = server
            .downloads
            .clone()
            .try_acquire_many_owned(DOWNLOAD_RPCS as u32)
            .unwrap();
        let _headers = server
            .rpcs
            .clone()
            .try_acquire_many_owned((DATA_RPCS + DOWNLOAD_RPCS) as u32)
            .unwrap();
        assert_eq!(server.rpcs.available_permits(), CONTROL_RPCS);
        for command in [TCP, UDP, super::bond::PUT, super::bond::PULL] {
            assert!(server.data_admission(command).is_err());
        }
        for command in [
            super::bond::OPEN,
            super::bond::CLOSE,
            super::bond::FIN,
            super::bond::ACK_FIN,
            super::bond::DOWNLOAD_ACK,
            super::bond::UPLOAD_STATUS,
        ] {
            let _header = server.rpcs.clone().try_acquire_owned().unwrap();
            assert!(server.data_admission(command).unwrap().is_none());
        }
    }
}
