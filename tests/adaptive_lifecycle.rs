//! Real local runtime lifecycle: server restart, session epochs and bounded cancellation.
#![cfg(unix)]
use anyhow::{Context, Result};
use braidpath::runtime::transport::{self, Congestion};
use bytes::Bytes;
use h3::ConnectionState;
use http::{Request, StatusCode};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::time::timeout;

const BIN: &str = env!("CARGO_BIN_EXE_braidpath");

struct Process {
    child: Child,
    json: PathBuf,
    jsonl: PathBuf,
    log: PathBuf,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Process {
    fn launch(args: &[&str], dir: &Path, name: &str) -> Self {
        let json = dir.join(format!("{name}.json"));
        let jsonl = dir.join(format!("{name}.jsonl"));
        let log = dir.join(format!("{name}.log"));
        let child = Command::new(BIN)
            .env("RUST_LOG", "braidpath=info")
            .args(args)
            .args([
                "--stats-file",
                json.to_str().unwrap(),
                "--stats-jsonl",
                jsonl.to_str().unwrap(),
                "--stats-interval-ms",
                "25",
            ])
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        Self {
            child,
            json,
            jsonl,
            log,
        }
    }
    fn logs(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
    fn alive(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "runtime exited: {}",
            self.logs()
        );
    }
    fn latest(&self) -> Option<Value> {
        fs::read_to_string(&self.jsonl)
            .ok()?
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str(line).ok())
    }
    fn wait_snapshot(&mut self, limit: Duration, predicate: impl Fn(&Value) -> bool) -> Value {
        let until = Instant::now() + limit;
        loop {
            self.alive();
            if let Some(value) = self.latest()
                && predicate(&value)
            {
                return value;
            }
            assert!(
                Instant::now() < until,
                "snapshot deadline: {:?}\n{}",
                self.latest(),
                self.logs()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn finish(&mut self) -> Value {
        assert!(
            Command::new("kill")
                .args(["-INT", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let until = Instant::now() + Duration::from_secs(6);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "runtime failed on stop: {}", self.logs());
                break;
            }
            assert!(Instant::now() < until, "shutdown deadline: {}", self.logs());
            thread::sleep(Duration::from_millis(10));
        }
        let result: Value = serde_json::from_str(&fs::read_to_string(&self.json).unwrap()).unwrap();
        assert_eq!(result["final"], true);
        assert_eq!(
            result["stats"]["shutdown_complete"],
            true,
            "{}",
            self.logs()
        );
        assert_eq!(
            result["stats"]["drain_incomplete"],
            false,
            "{}",
            self.logs()
        );
        assert_eq!(self.latest().unwrap(), result);
        result
    }
}

struct Echo {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Echo {
    fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let quit = stop.clone();
        let thread = thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            while !quit.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buffer) {
                    Ok((n, peer)) => {
                        socket.send_to(&buffer[..n], peer).unwrap();
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => panic!("echo socket: {error}"),
                }
            }
        });
        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.thread.take().unwrap().join();
    }
}

fn unused_address() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn server(
    identity: &Path,
    listen: SocketAddr,
    target: SocketAddr,
    dir: &Path,
    name: &str,
) -> Process {
    let mut process = Process::launch(
        &[
            "server",
            "--listen",
            &listen.to_string(),
            "--cert",
            identity.join("cert.pem").to_str().unwrap(),
            "--key",
            identity.join("key.pem").to_str().unwrap(),
            "--token-file",
            identity.join("token").to_str().unwrap(),
            "--target",
            &target.to_string(),
            "--congestion",
            "bbr",
        ],
        dir,
        name,
    );
    process.wait_snapshot(Duration::from_secs(8), |v| v["stats"]["ready"] == true);
    process
}
fn expect_echo(socket: &UdpSocket, value: &[u8], process: &mut Process) {
    let until = Instant::now() + Duration::from_secs(4);
    let mut buffer = [0u8; 2048];
    while Instant::now() < until {
        process.alive();
        socket.send(value).unwrap();
        match socket.recv(&mut buffer) {
            Ok(n) if &buffer[..n] == value => return,
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("application socket: {error}"),
        }
    }
    panic!("echo did not resume: {}", process.logs());
}
fn active_session(value: &Value, exclude: Option<&str>) -> Option<String> {
    value["stats"]["paths"]
        .as_object()?
        .values()
        .find_map(|path| {
            let sid = path["session_id"].as_str()?;
            (path["authenticated"] == true
                && path["quinn"]["closed"] == false
                && exclude != Some(sid))
            .then(|| sid.to_owned())
        })
}

#[test]
fn adaptive_restart_preserves_listener_replaces_session_and_cancels_failed_reconnect() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    transport::initialize(&identity, "localhost").unwrap();
    let echo = Echo::start();
    let server_address = unused_address();
    let mut first_server = server(
        &identity,
        server_address,
        echo.address,
        dir.path(),
        "server-first",
    );
    let client_address = unused_address();
    let mut client = Process::launch(
        &[
            "client",
            "--listen",
            &client_address.to_string(),
            "--entrance",
            &server_address.to_string(),
            "--server-name",
            "localhost",
            "--ca",
            identity.join("cert.pem").to_str().unwrap(),
            "--token-file",
            identity.join("token").to_str().unwrap(),
            "--adaptive",
            "--fec",
            "0",
            "--queue-ms",
            "50",
            "--rate-bps",
            "2000000",
            "--congestion",
            "bbr",
        ],
        dir.path(),
        "client",
    );
    let pid = client.child.id();
    let first = client.wait_snapshot(Duration::from_secs(12), |v| {
        active_session(v, None).is_some()
    });
    let old_session = active_session(&first, None).unwrap();
    let application = UdpSocket::bind("127.0.0.1:0").unwrap();
    application.connect(client_address).unwrap();
    application
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    expect_echo(&application, b"before server restart", &mut client);

    first_server.finish();
    client.alive();
    assert!(
        UdpSocket::bind(client_address).is_err(),
        "application listener disappeared during outage"
    );
    let mut second_server = server(
        &identity,
        server_address,
        echo.address,
        dir.path(),
        "server-second",
    );
    let recovered = client.wait_snapshot(Duration::from_secs(20), |v| {
        active_session(v, Some(&old_session)).is_some()
    });
    let new_session = active_session(&recovered, Some(&old_session)).unwrap();
    assert_ne!(new_session, old_session);
    assert!(
        client
            .logs()
            .contains("server session expired; creating a fresh authenticated epoch")
    );
    assert_eq!(client.child.id(), pid);
    assert!(UdpSocket::bind(client_address).is_err());
    expect_echo(
        &application,
        b"after fresh authenticated session",
        &mut client,
    );

    // Keep the destination UDP port open without responding so this is a pending
    // reconnect handshake, not immediate ICMP refusal or an idle ready client.
    second_server.finish();
    let blackhole = UdpSocket::bind(server_address).unwrap();
    blackhole
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    let mut packet = [0u8; 2048];
    loop {
        client.alive();
        match blackhole.recv_from(&mut packet) {
            Ok((n, _)) if n >= 1200 && packet[0] & 0x80 != 0 => break,
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("blackhole socket: {error}"),
        }
        assert!(
            Instant::now() < until,
            "no actual reconnect Initial observed: {}",
            client.logs()
        );
    }
    let final_client = client.finish();
    assert!(
        final_client["stats"]["handshake_cancelled"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(
        final_client["stats"]["retired_session_total"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert!(
        UdpSocket::bind(client_address).is_ok(),
        "listener retained after process shutdown"
    );
}

async fn admit_generation(
    identity: &Path,
    remote: SocketAddr,
    session: &str,
    generation: u64,
    rejoin: bool,
) -> Result<StatusCode> {
    timeout(Duration::from_secs(4), async {
        let endpoint = transport::client(remote, &identity.join("cert.pem"), None, Congestion::Bbr)?;
        let conn = endpoint.connect(remote, "localhost")?.await?;
        let (mut driver, mut send) = h3::client::builder().enable_datagram(true)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone())).await?;
        tokio::select! {
            error = driver.wait_idle() => anyhow::bail!("HTTP/3 ended before SETTINGS: {error}"),
            _ = async { while !send.settings().enable_datagram() { tokio::time::sleep(Duration::from_millis(1)).await; } } => {}
        }
        let token = fs::read_to_string(identity.join("token"))?;
        let mut request = Request::builder().method("POST").uri("https://localhost/session")
            .header("authorization", format!("Bearer {}", token.trim()))
            .header("braidpath-version", "1").header("braidpath-session", session)
            .header("braidpath-path", "0").header("braidpath-generation", generation)
            .header("braidpath-feedback", "2").header("braidpath-scheduler", "adaptive")
            .header("braidpath-fec", "0").header("braidpath-redundancy", "0")
            .header("braidpath-rate", "10000000").header("braidpath-block-ms", "3")
            .header("braidpath-queue-ms", "50");
        if rejoin { request = request.header("braidpath-rejoin", "1"); }
        let mut request = send.send_request(request.body(())?).await?;
        let response = tokio::select! {
            error = driver.wait_idle() => anyhow::bail!("HTTP/3 ended during admission: {error}"),
            response = request.recv_response() => response?
        };
        let status = response.status();
        request.finish().await?;
        conn.close(0u32.into(), b"test generation complete");
        endpoint.close(0u32.into(), b"test generation complete");
        let _ = timeout(Duration::from_millis(500), endpoint.wait_idle()).await;
        Ok(status)
    }).await.context("bounded generation admission")?
}

#[tokio::test]
async fn live_session_accepts_more_than_three_rejoins_and_rejects_stale_generation() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    transport::initialize(&identity, "localhost").unwrap();
    let echo = Echo::start();
    let address = unused_address();
    let mut server = server(
        &identity,
        address,
        echo.address,
        dir.path(),
        "generation-server",
    );
    let session = "0123456789abcdef0123456789abcdef";
    for generation in 1..=6 {
        assert_eq!(
            admit_generation(&identity, address, session, generation, generation > 1)
                .await
                .unwrap(),
            StatusCode::OK
        );
    }
    let snapshot = server.wait_snapshot(Duration::from_secs(4), |v| {
        v["stats"]["paths"][format!("{session}/0")]["total_generations"] == 6
    });
    let path = &snapshot["stats"]["paths"][format!("{session}/0")];
    assert_eq!(path["retired_generations"], 5);
    assert_eq!(path["previous_generations"].as_array().unwrap().len(), 3);
    assert!(
        admit_generation(&identity, address, session, 5, true)
            .await
            .is_err()
    );
    let until = Instant::now() + Duration::from_secs(2);
    while !server.logs().contains("generation replay or regression") {
        server.alive();
        assert!(
            Instant::now() < until,
            "stale generation was not explicitly rejected: {}",
            server.logs()
        );
        thread::sleep(Duration::from_millis(10));
    }
    let final_server = server.finish();
    assert_eq!(
        final_server["stats"]["paths"][format!("{session}/0")]["total_generations"],
        6
    );
}

#[test]
fn shared_group_small_packets_preserve_feedback_and_independent_probes() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    transport::initialize(&identity, "localhost").unwrap();
    let echo = Echo::start();
    let address = unused_address();
    let mut server = server(
        &identity,
        address,
        echo.address,
        dir.path(),
        "shared-group-server",
    );
    let client_address = unused_address();
    let mut client = Process::launch(
        &[
            "client",
            "--listen",
            &client_address.to_string(),
            "--entrance",
            &address.to_string(),
            "--entrance",
            &address.to_string(),
            "--entrance",
            &address.to_string(),
            "--path-group",
            "0",
            "--path-group",
            "0",
            "--path-group",
            "0",
            "--group-rate-bps",
            "0:64000",
            "--server-name",
            "localhost",
            "--ca",
            identity.join("cert.pem").to_str().unwrap(),
            "--token-file",
            identity.join("token").to_str().unwrap(),
            "--adaptive",
            "--fec",
            "0",
            "--rate-bps",
            "3000000",
            "--congestion",
            "bbr",
        ],
        dir.path(),
        "shared-group-client",
    );
    let initial = client.wait_snapshot(Duration::from_secs(12), |v| {
        v["stats"]["paths"].as_object().is_some_and(|paths| {
            paths.len() == 3
                && paths
                    .values()
                    .all(|path| path["authenticated"] == true && path["quinn"]["closed"] == false)
        })
    });
    let session = active_session(&initial, None).unwrap();
    let application = UdpSocket::bind("127.0.0.1:0").unwrap();
    application.connect(client_address).unwrap();
    application.set_nonblocking(true).unwrap();

    // Each 64-byte business datagram costs 199 admitted-budget bytes, while a
    // three-path report costs 282. The group refills only 8 bytes/ms. Without
    // reserving group tokens, continuously offered small originals can consume
    // every refill before feedback fits, even with ample aggregate tokens.
    // Three separate QUIC connections use one explicitly shared local group;
    // this checks admission progress, not independent path capacity.
    let started = Instant::now();
    let until = started + Duration::from_millis(5500);
    let midpoint = started + Duration::from_millis(2750);
    let mut middle = None;
    let mut middle_echoes = 0;
    let mut offered = 0u64;
    let mut echoed = BTreeSet::new();
    let mut payload = [0x5au8; 64];
    let mut received = [0u8; 2048];
    while Instant::now() < until {
        payload[..8].copy_from_slice(&offered.to_be_bytes());
        assert_eq!(application.send(&payload).unwrap(), payload.len());
        offered += 1;
        loop {
            match application.recv(&mut received) {
                Ok(n) => {
                    assert_eq!(n, payload.len());
                    assert_eq!(&received[8..n], &[0x5a; 56]);
                    let id = u64::from_be_bytes(received[..8].try_into().unwrap());
                    assert!(id < offered, "echo of an unoffered record");
                    echoed.insert(id);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("shared-group application socket: {error}"),
            }
        }
        if middle.is_none() && Instant::now() >= midpoint {
            client.alive();
            server.alive();
            middle = client.latest();
            middle_echoes = echoed.len();
        }
        thread::sleep(Duration::from_millis(1));
    }
    client.alive();
    server.alive();
    let middle = middle.expect("periodic midpoint snapshot");
    let end = client.latest().expect("periodic loaded snapshot");
    let final_client = client.finish();
    let final_server = server.finish();
    let feedback = |value: &Value| {
        value["stats"]["directions"]["client_to_server"]["symbols"]["feedback_admitted"]
            .as_u64()
            .unwrap_or(0)
    };
    let first_controls = feedback(&initial);
    let middle_controls = feedback(&middle);
    let last_controls = feedback(&end);
    eprintln!(
        "shared-group progress: offered={offered}, echoes={middle_echoes}/{}, feedback={first_controls}/{middle_controls}/{last_controls}",
        echoed.len()
    );
    // Both windows are sampled while the small-packet producer is still active;
    // startup reports or feedback sent after stopping cannot satisfy this check.
    assert!(
        middle_controls >= first_controls + 2 && last_controls >= middle_controls + 2,
        "feedback stopped under shared-group contention: {first_controls}/{middle_controls}/{last_controls}\n{}",
        client.logs()
    );
    assert!(
        middle_echoes > 0 && echoed.len() > middle_echoes,
        "business delivery did not coexist with feedback: echoes={middle_echoes}/{}\n{}",
        echoed.len(),
        client.logs()
    );
    for id in 0..3 {
        let key = format!("{session}/{id}");
        let before = &initial["stats"]["paths"][&key]["receiver_feedback"];
        let after = &end["stats"]["paths"][&key]["receiver_feedback"];
        for counter in ["probes_sent", "replies_received"] {
            assert!(
                after[counter].as_u64().unwrap() > before[counter].as_u64().unwrap_or(0),
                "independent path {id} {counter} did not advance\n{}",
                client.logs()
            );
        }
    }
    let symbols = &end["stats"]["directions"]["client_to_server"]["symbols"];
    assert!(
        [
            "originals_expired_dropped",
            "originals_ingress_expired_dropped",
            "originals_queue_full_dropped"
        ]
        .iter()
        .any(|name| symbols[*name].as_u64().unwrap() > 0),
        "test never created admission backlog"
    );
    assert!(
        final_server["stats"]["directions"]["client_to_server"]["records"]["udp_target_delivered"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(final_client["stats"]["configured_paths"], 3);
}
