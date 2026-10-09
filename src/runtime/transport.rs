use anyhow::{Context, Result, ensure};
use quinn::{
    ClientConfig, Endpoint, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use socket2::{Domain, Protocol, Socket, Type};
use std::{fs, io::BufReader, net::SocketAddr, path::Path, sync::Arc, time::Duration};

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
    Cubic,
    #[default]
    Bbr,
}
pub fn config(congestion: Congestion) -> TransportConfig {
    let mut t = TransportConfig::default();
    if matches!(congestion, Congestion::Bbr) {
        t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    t.max_concurrent_bidi_streams(16u32.into());
    t.max_concurrent_uni_streams(8u32.into());
    t.datagram_receive_buffer_size(Some(256 * 1200));
    // Quinn cannot expire individual queued datagrams. Keep at most one maximum-
    // size BraidPath record (or a few small ones) beyond the application deadline
    // queue. This bounds hidden bytes, not residence time on a stalled path.
    t.datagram_send_buffer_size(1200);
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
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates(cert)?, key(key_path)?)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    let mut conf = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    conf.transport_config(Arc::new(config(congestion)));
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
    let mut roots = rustls::RootCertStore::empty();
    for cert in certificates(ca)? {
        roots.add(cert)?;
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = false;
    let mut conf = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    conf.transport_config(Arc::new(config(congestion)));
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
