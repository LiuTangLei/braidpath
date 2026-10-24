use anyhow::{Context, Result, ensure};
use quinn::{
    ClientConfig, Endpoint, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use socket2::{Domain, Protocol, Socket, Type};
use std::{fs, io::BufReader, net::SocketAddr, path::Path, sync::Arc, time::Duration};

pub const DEFAULT_DATAGRAM_SEND_BUFFER_BYTES: usize = 1200;
pub const MAX_DATAGRAM_SEND_BUFFER_BYTES: usize = 76_800;
const PROXY_STREAM_WINDOW: u32 = 16 * 1024 * 1024;
const PROXY_CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
const PROXY_SOCKET_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// Low-frequency native counters for active proxy transports. Payload and
/// retransmission bytes are deliberately separate from application goodput.
pub(crate) struct ProxyTelemetry {
    at: std::time::Instant,
    connection: Option<usize>,
    sent: u64,
    received: u64,
}
impl Default for ProxyTelemetry {
    fn default() -> Self {
        Self {
            at: std::time::Instant::now(),
            connection: None,
            sent: 0,
            received: 0,
        }
    }
}
impl ProxyTelemetry {
    pub(crate) fn report(&mut self, conn: &quinn::Connection, side: &'static str, exit: &str) {
        let id = conn.stable_id();
        let now = std::time::Instant::now();
        if self.connection == Some(id) && now.duration_since(self.at) < Duration::from_secs(5) {
            return;
        }
        let stats = conn.stats();
        if self.connection != Some(id) {
            self.sent = 0;
            self.received = 0;
        }
        let traffic = stats
            .udp_tx
            .bytes
            .saturating_sub(self.sent)
            .saturating_add(stats.udp_rx.bytes.saturating_sub(self.received));
        self.at = now;
        self.connection = Some(id);
        self.sent = stats.udp_tx.bytes;
        self.received = stats.udp_rx.bytes;
        if traffic < 64 * 1024 {
            return;
        }
        tracing::info!(
            side, exit, connection = id, peer = %conn.remote_address(),
            rtt_us = stats.path.rtt.as_micros() as u64, cwnd = stats.path.cwnd,
            sent_packets = stats.path.sent_packets, lost_packets = stats.path.lost_packets,
            lost_bytes = stats.path.lost_bytes, congestion_events = stats.path.congestion_events,
            udp_tx_bytes = stats.udp_tx.bytes, udp_rx_bytes = stats.udp_rx.bytes,
            "proxy transport counters"
        );
    }
}

pub(crate) fn datagram_socket_buffers(socket: socket2::SockRef<'_>, scope: &'static str) {
    // Some platforms reject oversized requests; others accept and clamp them.
    // Leave the platform's buffer intact if even a 1 MiB request is refused.
    let request = |set: &dyn Fn(usize) -> std::io::Result<()>| {
        let mut requested = PROXY_SOCKET_BUFFER_BYTES;
        while set(requested).is_err() && requested > 1024 * 1024 {
            requested /= 2;
        }
    };
    request(&|bytes| socket.set_recv_buffer_size(bytes));
    request(&|bytes| socket.set_send_buffer_size(bytes));
    // Record what the OS granted so host-wide UDP drop counters can be
    // compared with this socket's actual limits.
    tracing::info!(
        scope,
        receive = ?socket.recv_buffer_size().ok(),
        send = ?socket.send_buffer_size().ok(),
        "UDP socket buffers"
    );
}

/// Expand shared stream credit only after the proxy token and exit are verified.
pub(crate) fn authenticated_proxy(connection: &quinn::Connection) {
    connection.set_receive_window(PROXY_CONNECTION_WINDOW.into());
    connection.set_send_window(u64::from(PROXY_CONNECTION_WINDOW));
}

pub fn token(path: &Path) -> Result<String> {
    let s = fs::read_to_string(path).context("read token file")?;
    let s = s.trim();
    ensure!(
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "token must contain 64 hexadecimal characters"
    );
    Ok(s.to_owned())
}
pub fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut r = BufReader::new(fs::File::open(path)?);
    let certs = rustls_pemfile::certs(&mut r).collect::<std::io::Result<Vec<_>>>()?;
    ensure!(!certs.is_empty(), "empty certificate file");
    Ok(certs)
}
fn key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(path)?))?
        .context("missing private key")
}
/// BBR is an experimental implementation in the pinned Quinn release.
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum Congestion {
    #[default]
    Bbr,
    Cubic,
}

/// Explicit peer ACK-frequency requests for controlled directional comparisons.
/// The default preserves Quinn's existing behavior. Native recovery and BBR are
/// unchanged, and the peer can clamp or decline an extension request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum AckRequest {
    #[default]
    Unchanged,
    EveryTwo,
    EveryEight,
}
impl AckRequest {
    /// (ack-eliciting threshold, maximum requested delay ms, reordering threshold).
    pub fn request(self) -> Option<(u32, u64, u32)> {
        match self {
            Self::Unchanged => None,
            Self::EveryTwo => Some((1, 10, 2)),
            Self::EveryEight => Some((7, 10, 2)),
        }
    }

    pub fn apply(self, transport: &mut TransportConfig) {
        if let Some((threshold, delay, reorder)) = self.request() {
            let mut request = quinn::AckFrequencyConfig::default();
            request.ack_eliciting_threshold(threshold.into());
            request.max_ack_delay(Some(Duration::from_millis(delay)));
            request.reordering_threshold(reorder.into());
            transport.ack_frequency_config(Some(request));
        }
    }
}
pub fn config(congestion: Congestion) -> TransportConfig {
    let mut t = TransportConfig::default();
    match congestion {
        Congestion::Bbr => {
            t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        Congestion::Cubic => {
            t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
    }
    t.max_concurrent_bidi_streams(16u32.into());
    t.max_concurrent_uni_streams(8u32.into());
    t.datagram_receive_buffer_size(Some(256 * 1200));
    // Quinn cannot expire individual queued datagrams. Keep at most one maximum-
    // size BraidPath record (or a few small ones) beyond the application deadline
    // queue. This bounds hidden bytes, not residence time on a stalled path.
    t.datagram_send_buffer_size(DEFAULT_DATAGRAM_SEND_BUFFER_BYTES);
    t.max_idle_timeout(Some(
        Duration::from_secs(15)
            .try_into()
            .expect("constant timeout"),
    ));
    t.keep_alive_interval(Some(Duration::from_secs(3)));
    t.send_window(256 * 1024);
    t.receive_window((256u32 * 1024).into());
    t.stream_receive_window((16u32 * 1024).into());
    t
}
pub fn server(
    bind: SocketAddr,
    cert: &Path,
    key_path: &Path,
    congestion: Congestion,
) -> Result<Endpoint> {
    server_with_datagram_buffer(
        bind,
        cert,
        key_path,
        congestion,
        DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
    )
}

/// Server-side outgoing buffer for bounded reverse-direction measurements.
/// Bytes include Quinn metadata and do not bound datagram residence time.
pub fn server_with_datagram_buffer(
    bind: SocketAddr,
    cert: &Path,
    key_path: &Path,
    congestion: Congestion,
    datagram_send_buffer_bytes: usize,
) -> Result<Endpoint> {
    server_with_ack_request(
        bind,
        cert,
        key_path,
        congestion,
        datagram_send_buffer_bytes,
        AckRequest::Unchanged,
    )
}

pub fn server_with_ack_request(
    bind: SocketAddr,
    cert: &Path,
    key_path: &Path,
    congestion: Congestion,
    datagram_send_buffer_bytes: usize,
    ack_request: AckRequest,
) -> Result<Endpoint> {
    server_with_proxy(
        bind,
        cert,
        key_path,
        congestion,
        datagram_send_buffer_bytes,
        ack_request,
        false,
    )
}

pub(crate) fn server_with_proxy(
    bind: SocketAddr,
    cert: &Path,
    key_path: &Path,
    congestion: Congestion,
    datagram_send_buffer_bytes: usize,
    ack_request: AckRequest,
    proxy: bool,
) -> Result<Endpoint> {
    ensure!(
        (DEFAULT_DATAGRAM_SEND_BUFFER_BYTES..=MAX_DATAGRAM_SEND_BUFFER_BYTES)
            .contains(&datagram_send_buffer_bytes),
        "datagram send buffer must be 1200..76800 bytes"
    );
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates(cert)?, key(key_path)?)?;
    tls.alpn_protocols = vec![b"h3".to_vec(), super::proxy::ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let mut conf = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let mut transport = config(congestion);
    if proxy {
        // The per-stream window cannot be changed after QUIC negotiation.
        // Keep the aggregate receive/send windows at 256 KiB until proxy auth.
        transport.stream_receive_window(PROXY_STREAM_WINDOW.into());
    }
    transport.datagram_send_buffer_size(datagram_send_buffer_bytes);
    ack_request.apply(&mut transport);
    conf.transport_config(Arc::new(transport));
    if proxy {
        let socket = std::net::UdpSocket::bind(bind)?;
        datagram_socket_buffers(socket2::SockRef::from(&socket), "proxy");
        return Ok(Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(conf),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?);
    }
    Ok(Endpoint::server(conf, bind)?)
}
pub fn client(
    remote: SocketAddr,
    ca: &Path,
    interface: Option<&str>,
    congestion: Congestion,
) -> Result<Endpoint> {
    client_bound(remote, ca, interface, congestion, None)
}

pub fn client_bound(
    remote: SocketAddr,
    ca: &Path,
    interface: Option<&str>,
    congestion: Congestion,
    bind: Option<SocketAddr>,
) -> Result<Endpoint> {
    client_bound_with_datagram_buffer(
        remote,
        ca,
        interface,
        congestion,
        bind,
        DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
    )
}

/// Bounded outgoing datagram memory for controlled measurements. This includes
/// Quinn metadata and does not guarantee a maximum datagram residence time.
pub fn client_bound_with_datagram_buffer(
    remote: SocketAddr,
    ca: &Path,
    interface: Option<&str>,
    congestion: Congestion,
    bind: Option<SocketAddr>,
    datagram_send_buffer_bytes: usize,
) -> Result<Endpoint> {
    client_with_alpn(
        remote,
        ca,
        interface,
        congestion,
        bind,
        datagram_send_buffer_bytes,
        b"h3",
    )
}

pub(crate) fn proxy_client(remote: SocketAddr, ca: &Path) -> Result<Endpoint> {
    client_with_alpn(
        remote,
        ca,
        None,
        // Proxy uploads need loss-responsive pacing on the shared uplink.
        // This choice does not change the server's download controller.
        Congestion::Cubic,
        None,
        DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
        super::proxy::ALPN,
    )
}

fn client_with_alpn(
    remote: SocketAddr,
    ca: &Path,
    interface: Option<&str>,
    congestion: Congestion,
    bind: Option<SocketAddr>,
    datagram_send_buffer_bytes: usize,
    alpn: &[u8],
) -> Result<Endpoint> {
    ensure!(
        (DEFAULT_DATAGRAM_SEND_BUFFER_BYTES..=MAX_DATAGRAM_SEND_BUFFER_BYTES)
            .contains(&datagram_send_buffer_bytes),
        "datagram send buffer must be 1200..76800 bytes"
    );
    let mut roots = rustls::RootCertStore::empty();
    for cert in certificates(ca)? {
        roots.add(cert)?;
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];
    tls.enable_early_data = false;
    let mut conf = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    let mut transport = config(congestion);
    if alpn == super::proxy::ALPN {
        transport.stream_receive_window(PROXY_STREAM_WINDOW.into());
        transport.receive_window(PROXY_CONNECTION_WINDOW.into());
        transport.send_window(u64::from(PROXY_CONNECTION_WINDOW));
    }
    transport.datagram_send_buffer_size(datagram_send_buffer_bytes);
    conf.transport_config(Arc::new(transport));
    let s = Socket::new(
        if remote.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if let Some(name) = interface {
        #[cfg(target_os = "linux")]
        s.bind_device(Some(name.as_bytes()))
            .with_context(|| format!("bind interface {name}"))?;
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("explicit interface binding is currently supported only on Linux: {name}");
    }
    let bind: SocketAddr = bind.unwrap_or(
        if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?,
    );
    ensure!(
        bind.is_ipv4() == remote.is_ipv4(),
        "path bind address family differs from entrance"
    );
    s.bind(&bind.into())?;
    s.set_nonblocking(true)?;
    if alpn == super::proxy::ALPN {
        datagram_socket_buffers(socket2::SockRef::from(&s), "proxy");
    }
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        s.into(),
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(conf);
    Ok(endpoint)
}

pub fn initialize(dir: &Path, name: &str) -> Result<()> {
    ensure!(
        !dir.exists(),
        "identity directory already exists; refusing to replace credentials"
    );
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let cert = rcgen::generate_simple_self_signed(vec![name.to_owned()])?;
    fs::write(dir.join("cert.pem"), cert.cert.pem())?;
    fs::write(dir.join("key.pem"), cert.signing_key.serialize_pem())?;
    let secret: [u8; 32] = rand::random();
    fs::write(dir.join("token"), hex(&secret))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in ["key.pem", "token"] {
            fs::set_permissions(dir.join(p), fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proxy_streams_acknowledge_large_flight_before_application_reads() {
        let temp = tempfile::tempdir().unwrap();
        let identity = temp.path().join("identity");
        initialize(&identity, "localhost").unwrap();
        let server = server_with_proxy(
            "127.0.0.1:0".parse().unwrap(),
            &identity.join("cert.pem"),
            &identity.join("key.pem"),
            Congestion::Bbr,
            DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            AckRequest::Unchanged,
            true,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let client = proxy_client(address, &identity.join("cert.pem")).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            let (outgoing, incoming) =
                tokio::join!(client.connect(address, "localhost").unwrap(), async {
                    server.accept().await.unwrap().await
                });
            let outgoing = outgoing.unwrap();
            let incoming = incoming.unwrap();
            assert!(outgoing.congestion_state().metrics().ssthresh.is_some());
            assert!(incoming.congestion_state().metrics().ssthresh.is_none());
            authenticated_proxy(&incoming);
            let (mut upload, mut download) = outgoing.open_bi().await.unwrap();
            // Make the stream visible to accept_bi without reading its payload.
            upload.write_all(&[1]).await.unwrap();
            let (response, mut request) = incoming.accept_bi().await.unwrap();
            // Hold a backlog above the 5.1 MB mixed-frame failure reproduced
            // in the assembler regression, in both directions before reads.
            let payload = vec![7; 6 * 1024 * 1024];
            // Completion requires peer ACKs, not just local write buffering.
            // The old 16 KiB stream / 256 KiB connection windows would stall
            // here in both directions until the application consumed data.
            let send = |mut stream: quinn::SendStream, data: Vec<u8>| async move {
                stream.write_all(&data).await.unwrap();
                stream.finish().unwrap();
                assert_eq!(stream.stopped().await.unwrap(), None);
            };
            tokio::join!(
                send(upload, payload.clone()),
                send(response, payload.clone())
            );
            let received = request.read_to_end(payload.len() + 1).await.unwrap();
            assert_eq!(received[0], 1);
            assert_eq!(&received[1..], payload);
            assert_eq!(download.read_to_end(payload.len()).await.unwrap(), payload);
        })
        .await
        .expect("proxy flow-control windows blocked outstanding data");
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
    }

    /// Delay both directions by `delay` and drop roughly `loss_per_mille` of
    /// client datagrams once the handshake has had room to complete. The loss
    /// pattern is a fixed hash of the datagram index, so runs are repeatable.
    async fn lossy_relay(
        server: SocketAddr,
        delay: Duration,
        loss_per_mille: u64,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicU64>) {
        use std::collections::VecDeque;
        use tokio::{net::UdpSocket, sync::mpsc, time::Instant};
        // Forward each queued datagram once its delay has elapsed.
        async fn forward(
            mut queue: mpsc::UnboundedReceiver<(Instant, Vec<u8>)>,
            send: impl Fn(&[u8]),
        ) {
            let mut held = VecDeque::new();
            loop {
                if held.is_empty() {
                    match queue.recv().await {
                        Some(item) => held.push_back(item),
                        None => return,
                    }
                }
                while let Ok(item) = queue.try_recv() {
                    held.push_back(item);
                }
                tokio::time::sleep_until(held.front().unwrap().0).await;
                while held.front().is_some_and(|(due, _)| *due <= Instant::now()) {
                    send(&held.pop_front().unwrap().1);
                }
            }
        }
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        back.connect(server).await.unwrap();
        let address = front.local_addr().unwrap();
        let (to_server, server_queue) = mpsc::unbounded_channel();
        let (to_client, client_queue) = mpsc::unbounded_channel();
        let peer = Arc::new(std::sync::Mutex::new(None));
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
        {
            let (front, peer, dropped) = (front.clone(), peer.clone(), dropped.clone());
            tokio::spawn(async move {
                let mut buf = vec![0; 65_536];
                for index in 0u64.. {
                    let Ok((n, from)) = front.recv_from(&mut buf).await else {
                        return;
                    };
                    *peer.lock().unwrap() = Some(from);
                    let hash = index.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(29);
                    if index >= 64 && hash % 1000 < loss_per_mille {
                        dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                    let _ = to_server.send((Instant::now() + delay, buf[..n].to_vec()));
                }
            });
        }
        {
            let back = back.clone();
            tokio::spawn(async move {
                let mut buf = vec![0; 65_536];
                while let Ok(n) = back.recv(&mut buf).await {
                    let _ = to_client.send((Instant::now() + delay, buf[..n].to_vec()));
                }
            });
        }
        tokio::spawn(forward(server_queue, move |data| {
            let _ = back.try_send(data);
        }));
        tokio::spawn(forward(client_queue, move |data| {
            if let Some(to) = *peer.lock().unwrap() {
                let _ = front.try_send_to(data, to);
            }
        }));
        (address, dropped)
    }

    // Single-threaded and modest in size so parallel timing tests keep their CPU.
    #[tokio::test]
    async fn proxy_upload_recovers_from_loss_across_a_large_stream_window() {
        let temp = tempfile::tempdir().unwrap();
        let identity = temp.path().join("identity");
        initialize(&identity, "localhost").unwrap();
        let server = server_with_proxy(
            "127.0.0.1:0".parse().unwrap(),
            &identity.join("cert.pem"),
            &identity.join("key.pem"),
            Congestion::Bbr,
            DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            AckRequest::Unchanged,
            true,
        )
        .unwrap();
        // Non-congestive loss on a long flight keeps many holes open in one
        // stream while retransmissions catch up. The dense-hole bound itself
        // is covered by the assembler regressions; this checks the whole
        // proxy transport still delivers every byte in order.
        let (relay, dropped) =
            lossy_relay(server.local_addr().unwrap(), Duration::from_millis(50), 100).await;
        // Keep this assembler regression on a large BBR flight under imposed
        // non-congestive loss; the proxy default's CUBIC policy is checked above.
        let client = client_with_alpn(
            relay,
            &identity.join("cert.pem"),
            None,
            Congestion::Bbr,
            None,
            DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            super::super::proxy::ALPN,
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(60), async {
            let (outgoing, incoming) =
                tokio::join!(client.connect(relay, "localhost").unwrap(), async {
                    server.accept().await.unwrap().await
                });
            let outgoing = outgoing.unwrap();
            let incoming = incoming.unwrap();
            authenticated_proxy(&incoming);
            let (mut upload, _download) = outgoing.open_bi().await.unwrap();
            upload.write_all(&[1]).await.unwrap();
            let (_response, mut request) = incoming.accept_bi().await.unwrap();
            let payload: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
            let expected = payload.clone();
            let send = tokio::spawn(async move {
                upload.write_all(&payload).await.unwrap();
                upload.finish().unwrap();
                upload.stopped().await
            });
            let received = request.read_to_end(expected.len() + 1).await.unwrap();
            assert_eq!(received[0], 1);
            assert!(received[1..] == expected[..]);
            assert_eq!(send.await.unwrap().unwrap(), None);
        })
        .await
        .expect("lossy upload did not complete");
        assert!(
            dropped.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "relay did not inject packet loss"
        );
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
    }
}
