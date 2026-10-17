//! Reliable TCP streams over real HTTP/3 paths, relays and loopback sockets:
//! fixed-target forwarding and SOCKS5 / HTTP CONNECT entrances.
use std::{
    fs,
    io::{ErrorKind, Read, Write},
    net::{Shutdown, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
const BIN: &str = env!("CARGO_BIN_EXE_braidpath");

struct Process {
    child: Child,
    log: PathBuf,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn launch(args: &[&str], dir: &Path, name: &str) -> Process {
    let log = dir.join(format!("{name}.log"));
    let child = Command::new(BIN)
        .env("RUST_LOG", "braidpath=info")
        .args(args)
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    Process { child, log }
}
fn ready(p: &mut Process, text: &str) {
    let start = Instant::now();
    loop {
        let log = fs::read_to_string(&p.log).unwrap();
        if log.contains(text) {
            return;
        }
        assert!(
            p.child.try_wait().unwrap().is_none(),
            "process exited: {log}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(12),
            "not ready: {log}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}
fn port() -> String {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}
fn tcp_port() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

/// Echo every connection; connections whose first byte is `b'B'` get a banner first.
fn echo_target() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            thread::spawn(move || {
                conn.write_all(b"banner\n").unwrap();
                let mut buffer = vec![0; 65536];
                loop {
                    match conn.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buffer[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
                let _ = conn.shutdown(Shutdown::Write);
            });
        }
    });
    address
}

struct Topology {
    dir: tempfile::TempDir,
    _processes: Vec<Process>,
    tcp_listen: String,
}
impl Topology {
    /// The latest `tcp_streams` snapshot that `role` wrote.
    fn streams(&self, role: &str) -> Option<serde_json::Value> {
        let text = std::fs::read_to_string(self.dir.path().join(format!("{role}.jsonl"))).ok()?;
        let line = text
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())?;
        line["stats"]["directions"]
            .as_object()?
            .values()
            .find_map(|direction| direction.get("tcp_streams").cloned())
    }
}

/// `server` selects the stream kind on the server; `local` is the client flag
/// for the matching local listener.
fn topology(server: &[&str], relays: &[&str], local: &str) -> Topology {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    assert!(
        Command::new(BIN)
            .args(["init", "--dir", identity.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
    let cert = identity.join("cert.pem");
    let key = identity.join("key.pem");
    let token = identity.join("token");
    let main = port();
    let mut processes = Vec::new();
    let server_stats = dir.path().join("server.jsonl");
    let client_stats = dir.path().join("client.jsonl");
    let mut server = launch(
        &[
            "server",
            "--listen",
            &main,
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--token-file",
            token.to_str().unwrap(),
            "--stats-jsonl",
            server_stats.to_str().unwrap(),
            "--stats-interval-ms",
            "100",
        ]
        .into_iter()
        .chain(server.iter().copied())
        .collect::<Vec<_>>(),
        dir.path(),
        "server",
    );
    ready(&mut server, "HTTP/3 server ready");
    processes.push(server);
    let mut entrances = vec![main.clone()];
    for (i, drop_every) in relays.iter().enumerate() {
        let address = port();
        let mut relay = launch(
            &[
                "relay",
                "--listen",
                &address,
                "--target",
                &main,
                "--allow-source",
                "127.0.0.1",
                "--rate-bps",
                "200000000",
                "--drop-every",
                drop_every,
            ],
            dir.path(),
            &format!("relay{i}"),
        );
        ready(&mut relay, "fixed-target relay ready");
        processes.push(relay);
        entrances.push(address);
    }
    let tcp_listen = tcp_port();
    let udp_listen = port();
    let mut args = vec![
        "client",
        "--listen",
        &udp_listen,
        local,
        &tcp_listen,
        "--server-name",
        "localhost",
        "--ca",
        cert.to_str().unwrap(),
        "--token-file",
        token.to_str().unwrap(),
        "--rate-bps",
        "200000000",
        "--stats-jsonl",
        client_stats.to_str().unwrap(),
        "--stats-interval-ms",
        "100",
    ];
    for entrance in &entrances {
        args.extend(["--entrance", entrance]);
    }
    let mut client = launch(&args, dir.path(), "client");
    ready(&mut client, "UDP client ready");
    processes.push(client);
    Topology {
        dir,
        _processes: processes,
        tcp_listen,
    }
}

fn read_exact_or_eof(conn: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut out = vec![0; n];
    conn.read_exact(&mut out).unwrap();
    out
}

#[test]
fn single_connections_survive_lossy_multipath_with_half_close_and_isolation() {
    let target = echo_target();
    let topology = topology(&["--tcp-target", &target], &["0", "13"], "--tcp-listen");
    // A server-first protocol: nothing is written before the banner arrives.
    let mut idle = TcpStream::connect(&topology.tcp_listen).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert_eq!(read_exact_or_eof(&mut idle, 7), b"banner\n");
    // Bulk transfers on several connections, each verified byte for byte.
    let workers: Vec<_> = (0..4u8)
        .map(|seed| {
            let address = topology.tcp_listen.clone();
            thread::spawn(move || {
                let size = if seed == 0 { 6 << 20 } else { 512 << 10 };
                let data: Vec<u8> = (0..size)
                    .map(|i| (i as u32).wrapping_mul(2654435761).to_be_bytes()[seed as usize % 4])
                    .collect();
                let mut conn = TcpStream::connect(&address).unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                let mut reader = conn.try_clone().unwrap();
                let expected = data.clone();
                let read = thread::spawn(move || {
                    let mut got = Vec::new();
                    reader.read_to_end(&mut got).unwrap();
                    got
                });
                conn.write_all(&data).unwrap();
                conn.shutdown(Shutdown::Write).unwrap();
                let got = read.join().unwrap();
                assert_eq!(&got[..7], b"banner\n");
                assert!(
                    got[7..] == expected[..],
                    "connection {seed} corrupted: {} bytes",
                    got.len()
                );
            })
        })
        .collect();
    // The idle connection stays responsive while bulk transfers run.
    let started = Instant::now();
    idle.write_all(b"ping").unwrap();
    assert_eq!(read_exact_or_eof(&mut idle, 4), b"ping");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "interactive echo took {:?}",
        started.elapsed()
    );
    for worker in workers {
        worker.join().unwrap();
    }
    idle.shutdown(Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    idle.read_to_end(&mut rest).unwrap();
    assert!(
        rest.is_empty(),
        "half-close returns end of stream after the echo"
    );
}

#[test]
fn unreachable_target_resets_the_local_connection() {
    let closed = tcp_port();
    let topology = topology(&["--tcp-target", &closed], &[], "--tcp-listen");
    let mut conn = TcpStream::connect(&topology.tcp_listen).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let _ = conn.write_all(b"hello");
    let started = Instant::now();
    let mut buffer = [0; 16];
    match conn.read(&mut buffer) {
        Err(error) => assert!(
            matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
            ),
            "{error}"
        ),
        Ok(n) => panic!("expected a reset, got {n} bytes"),
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn server_without_the_stream_kind_rejects_the_session() {
    for (server, local, message) in [
        (
            "--target",
            "--tcp-listen",
            "TCP streams are not enabled on this server",
        ),
        (
            "--tcp-target",
            "--proxy-listen",
            "proxy streams are not enabled on this server",
        ),
    ] {
        rejected(server, local, message);
    }
}

fn rejected(server_flag: &str, local: &str, message: &str) {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    Command::new(BIN)
        .args(["init", "--dir", identity.to_str().unwrap()])
        .output()
        .unwrap();
    let cert = identity.join("cert.pem");
    let main = port();
    let mut server = launch(
        &[
            "server",
            "--listen",
            &main,
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            identity.join("key.pem").to_str().unwrap(),
            "--token-file",
            identity.join("token").to_str().unwrap(),
            server_flag,
            &port(),
        ],
        dir.path(),
        "server",
    );
    ready(&mut server, "HTTP/3 server ready");
    let output = Command::new(BIN)
        .args([
            "client",
            "--listen",
            &port(),
            local,
            &tcp_port(),
            "--entrance",
            &main,
            "--server-name",
            "localhost",
            "--ca",
            cert.to_str().unwrap(),
            "--token-file",
            identity.join("token").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "stream session must not be admitted"
    );
    let server_log = fs::read_to_string(&server.log).unwrap();
    assert!(server_log.contains(message), "{server_log}");
}

/// SOCKS5 CONNECT; returns the reply code and the connection.
fn socks(proxy: &str, request: &[u8]) -> (u8, TcpStream) {
    let mut conn = TcpStream::connect(proxy).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    conn.write_all(&[5, 1, 0]).unwrap();
    assert_eq!(read_exact_or_eof(&mut conn, 2), [5, 0]);
    conn.write_all(request).unwrap();
    let reply = read_exact_or_eof(&mut conn, 10);
    assert_eq!((reply[0], reply[2], reply[3]), (5, 0, 1), "{reply:?}");
    (reply[1], conn)
}
fn socks_ipv4(address: &str) -> Vec<u8> {
    let address: std::net::SocketAddrV4 = address.parse().unwrap();
    let mut request = vec![5, 1, 0, 1];
    request.extend(address.ip().octets());
    request.extend(address.port().to_be_bytes());
    request
}
fn socks_domain(host: &str, port: u16) -> Vec<u8> {
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend(host.as_bytes());
    request.extend(port.to_be_bytes());
    request
}
/// HTTP CONNECT; returns the status line and the connection after the header.
fn http_connect(proxy: &str, authority: &str, early: &[u8]) -> (String, TcpStream) {
    let mut conn = TcpStream::connect(proxy).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut request =
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes();
    request.extend(early);
    conn.write_all(&request).unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.extend(read_exact_or_eof(&mut conn, 1));
    }
    let head = String::from_utf8(head).unwrap();
    (head.lines().next().unwrap().to_owned(), conn)
}
/// A refused destination resets the already-answered local connection.
fn assert_reset(conn: &mut TcpStream) {
    let mut buffer = [0; 16];
    match conn.read(&mut buffer) {
        Err(error) => assert!(
            matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
            ),
            "{error}"
        ),
        Ok(n) => panic!("expected a reset, got {n} bytes"),
    }
}

/// Each side retires a finished stream only after acknowledging the peer's FIN,
/// and a retired stream answers a repeated FIN with that acknowledgment, so
/// neither side waits for one that never comes or resets a complete exchange.
#[test]
fn finished_streams_complete_on_both_sides_without_reset() {
    let target = echo_target();
    let topology = topology(
        &["--proxy", "--proxy-allow-private"],
        &["5"],
        "--proxy-listen",
    );
    const EXCHANGES: u64 = 24;
    for i in 0..EXCHANGES {
        let (status, mut conn) = socks(&topology.tcp_listen, &socks_ipv4(&target));
        assert_eq!(status, 0);
        let request = format!("request {i}");
        conn.write_all(request.as_bytes()).unwrap();
        conn.shutdown(Shutdown::Write).unwrap();
        let mut got = Vec::new();
        conn.read_to_end(&mut got).unwrap();
        assert_eq!(got, [b"banner\n", request.as_bytes()].concat());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let settled = loop {
        let both = ["client", "server"].map(|role| topology.streams(role));
        if let [Some(client), Some(server)] = &both
            && [client, server].iter().all(|s| s["completed"] == EXCHANGES)
        {
            break both;
        }
        assert!(
            Instant::now() < deadline,
            "streams did not complete: {both:?}"
        );
        thread::sleep(Duration::from_millis(100));
    };
    for streams in settled.iter().flatten() {
        assert_eq!(streams["reset_local"], 0, "{streams}");
        assert_eq!(streams["reset_peer"], 0, "{streams}");
        assert_eq!(streams["active"], 0, "{streams}");
    }
}

#[test]
fn proxy_entrances_reach_named_destinations_over_lossy_multipath() {
    let target = echo_target();
    let port: u16 = target.rsplit_once(':').unwrap().1.parse().unwrap();
    let closed = tcp_port();
    let topology = topology(
        &["--proxy", "--proxy-allow-private"],
        &["13"],
        "--proxy-listen",
    );
    let proxy = topology.tcp_listen.as_str();
    // SOCKS5 to an address, carrying a verified bulk transfer with half-close.
    let (status, mut conn) = socks(proxy, &socks_ipv4(&target));
    assert_eq!(status, 0);
    let data: Vec<u8> = (0..2u32 << 20)
        .map(|i| i.wrapping_mul(2654435761) as u8)
        .collect();
    let mut reader = conn.try_clone().unwrap();
    let read = thread::spawn(move || {
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        got
    });
    conn.write_all(&data).unwrap();
    conn.shutdown(Shutdown::Write).unwrap();
    let got = read.join().unwrap();
    assert_eq!(&got[..7], b"banner\n");
    assert!(
        got[7..] == data[..],
        "SOCKS stream corrupted: {} bytes",
        got.len()
    );
    // A name resolved by the server; IPv6 candidates refuse, IPv4 succeeds.
    let (status, mut conn) = socks(proxy, &socks_domain("localhost", port));
    assert_eq!(status, 0);
    assert_eq!(read_exact_or_eof(&mut conn, 7), b"banner\n");
    // HTTP CONNECT with bytes sent before the response.
    let (line, mut conn) = http_connect(proxy, &target, b"early");
    assert!(line.starts_with("HTTP/1.1 200 "), "{line}");
    assert_eq!(read_exact_or_eof(&mut conn, 12), b"banner\nearly");
    // Success is answered before the server connects (no tunnel round trip),
    // so a refused destination resets the connection, never a clean end.
    let (status, mut conn) = socks(proxy, &socks_ipv4(&closed));
    assert_eq!(status, 0);
    assert_reset(&mut conn);
    let (line, mut conn) = http_connect(proxy, &closed, b"request");
    assert!(line.starts_with("HTTP/1.1 200 "), "{line}");
    assert_reset(&mut conn);
    // Commands other than CONNECT are answered locally.
    let mut associate = socks_ipv4(&target);
    associate[1] = 3;
    let (status, _) = socks(proxy, &associate);
    assert_eq!(status, 7);
}

#[test]
fn proxy_server_denies_private_destinations_by_default() {
    let target = echo_target();
    let port: u16 = target.rsplit_once(':').unwrap().1.parse().unwrap();
    let topology = topology(&["--proxy"], &[], "--proxy-listen");
    let proxy = topology.tcp_listen.as_str();
    for request in [socks_ipv4(&target), socks_domain("localhost", port)] {
        let (status, mut conn) = socks(proxy, &request);
        assert_eq!(status, 0);
        assert_reset(&mut conn);
    }
    let (line, mut conn) = http_connect(proxy, &target, b"");
    assert!(line.starts_with("HTTP/1.1 200 "), "{line}");
    assert_reset(&mut conn);
}
