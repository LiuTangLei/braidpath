//! Reliable TCP streams over real HTTP/3 paths, relays and loopback sockets.
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
    _dir: tempfile::TempDir,
    _processes: Vec<Process>,
    tcp_listen: String,
}

fn topology(tcp_target: &str, relays: &[&str]) -> Topology {
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
            "--tcp-target",
            tcp_target,
        ],
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
        "--tcp-listen",
        &tcp_listen,
        "--server-name",
        "localhost",
        "--ca",
        cert.to_str().unwrap(),
        "--token-file",
        token.to_str().unwrap(),
        "--rate-bps",
        "200000000",
    ];
    for entrance in &entrances {
        args.extend(["--entrance", entrance]);
    }
    let mut client = launch(&args, dir.path(), "client");
    ready(&mut client, "UDP client ready");
    processes.push(client);
    Topology {
        _dir: dir,
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
    let topology = topology(&target, &["0", "13"]);
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
    let topology = topology(&closed, &[]);
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
fn server_without_tcp_target_rejects_stream_sessions() {
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
            "--target",
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
            "--tcp-listen",
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
    assert!(
        server_log.contains("TCP streams are not enabled on this server"),
        "{server_log}"
    );
}
