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
/// Server resumption tickets held for 0-RTT; each is single use.
const SERVER_TICKETS: usize = 4096;
/// Tickets per handshake. Every attempt spends one, including attempts that
/// fail during an outage, and a client keeps at most eight per server.
const TICKETS_PER_HANDSHAKE: usize = 4;

/// One TLS client configuration per trusted CA set. rustls binds resumption
/// tickets to the verifier that checked the original handshake, so every
/// endpoint for the same CA must share it to send 0-RTT data; a reconnecting
/// path binds a new endpoint.
fn client_crypto(ca: &Path) -> Result<Arc<QuicClientConfig>> {
    type Configs = Vec<(Vec<CertificateDer<'static>>, Arc<QuicClientConfig>)>;
    static CONFIGS: std::sync::Mutex<Configs> = std::sync::Mutex::new(Vec::new());
    let certificates = certificates(ca)?;
    let mut configs = CONFIGS.lock().expect("client TLS configurations");
    if let Some((_, config)) = configs.iter().find(|(c, _)| *c == certificates) {
        return Ok(config.clone());
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in certificates.iter().cloned() {
        roots.add(cert)?;
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = true;
    let config = Arc::new(QuicClientConfig::try_from(tls)?);
    configs.push((certificates, config.clone()));
    Ok(config)
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

/// The server's TLS configuration, including 0-RTT acceptance.
pub fn server_tls(cert: &Path, key_path: &Path) -> Result<rustls::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates(cert)?, key(key_path)?)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // 0-RTT. rustls accepts early data only with stateful resumption and takes
    // each ticket out of this store on use, so a replayed first flight cannot
    // have its early data accepted again. A restart forgets every ticket.
    tls.max_early_data_size = u32::MAX;
    tls.session_storage = rustls::server::ServerSessionMemoryCache::new(SERVER_TICKETS);
    tls.send_tls13_tickets = TICKETS_PER_HANDSHAKE;
    Ok(tls)
}

pub fn server_with_ack_request(
    bind: SocketAddr,
    cert: &Path,
    key_path: &Path,
    congestion: Congestion,
    datagram_send_buffer_bytes: usize,
    ack_request: AckRequest,
) -> Result<Endpoint> {
    ensure!(
        (DEFAULT_DATAGRAM_SEND_BUFFER_BYTES..=MAX_DATAGRAM_SEND_BUFFER_BYTES)
            .contains(&datagram_send_buffer_bytes),
        "datagram send buffer must be 1200..76800 bytes"
    );
    let tls = server_tls(cert, key_path)?;
    let mut conf = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let mut transport = config(congestion);
    transport.datagram_send_buffer_size(datagram_send_buffer_bytes);
    ack_request.apply(&mut transport);
    conf.transport_config(Arc::new(transport));
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
    ensure!(
        (DEFAULT_DATAGRAM_SEND_BUFFER_BYTES..=MAX_DATAGRAM_SEND_BUFFER_BYTES)
            .contains(&datagram_send_buffer_bytes),
        "datagram send buffer must be 1200..76800 bytes"
    );
    let mut conf = ClientConfig::new(client_crypto(ca)?);
    let mut transport = config(congestion);
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
