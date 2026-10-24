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
const PROXY_SOCKET_RECEIVE_BYTES: usize = 8 * 1024 * 1024;

fn proxy_socket_receive_buffer(socket: socket2::SockRef<'_>) {
    let mut requested = PROXY_SOCKET_RECEIVE_BYTES;
    // Some platforms reject oversized requests; others accept and clamp them.
    // Leave the platform's buffer intact if even a 1 MiB request is refused.
    while socket.set_recv_buffer_size(requested).is_err() && requested > 1024 * 1024 {
        requested /= 2;
    }
    tracing::debug!(requested, granted = ?socket.recv_buffer_size().ok(), "proxy UDP receive buffer");
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
pub fn config(_congestion: Congestion) -> TransportConfig {
    let mut t = TransportConfig::default();
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
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
        proxy_socket_receive_buffer(socket2::SockRef::from(&socket));
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
        Congestion::default(),
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
        proxy_socket_receive_buffer(socket2::SockRef::from(&s));
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
}
