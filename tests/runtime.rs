//! Real loopback sockets and subprocess lifecycle. Run records stay in TempDir.
use serde_json::Value;
use std::{
    fs,
    net::UdpSocket,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
const BIN: &str = env!("CARGO_BIN_EXE_braidpath");
// Real-time UDP admission ages are part of the runtime contract. Concurrent
// multi-process fixtures on a two-core runner can exhaust those ages before
// the sender runs; isolate these socket fixtures without changing production
// queue limits, source rates, or assertions.
static SOCKET_FIXTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn socket_fixture() -> std::sync::MutexGuard<'static, ()> {
    SOCKET_FIXTURE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}
// Negotiation/integrity fixture: retain 2000 pps, but provision the encoded cost.
const DUAL_FEC_TEST_RATE_BPS: u64 = 20_000_000;
// This fixture proves parity negotiation/integrity and the 13% repair budget,
// not a 20 ms latency SLO. Coarse host scheduling must still allow a full
// 16-record block before flushing and enough time to admit its second repair.
const DUAL_FEC_TEST_WINDOW_MS: u64 = 100;

#[test]
fn dual_fec_fixture_budget_covers_its_unchanged_source_and_encoded_frames() {
    use braidpath::{
        fec::DualEncoder,
        runtime::{
            quality,
            wire::{self, Record},
        },
    };
    let created = Instant::now();
    let mut encoder = DualEncoder::new(16, Duration::from_millis(DUAL_FEC_TEST_WINDOW_MS)).unwrap();
    let mut symbols = Vec::new();
    for id in 0..200 {
        let record = Record {
            flow: 1,
            id,
            payload: vec![7; 700],
        };
        symbols.extend(
            encoder
                .push(
                    &record.encode().unwrap(),
                    created + Duration::from_micros(id * 500),
                )
                .unwrap(),
        );
    }
    symbols.extend(encoder.flush());
    let quality = quality::State::new(1);
    let cost: usize = symbols
        .into_iter()
        .map(|shard| {
            // Largest stream mapping in the actual three-path fixture is two bytes.
            wire::http_datagram(0, &quality.wrap(&wire::shard(shard), 0))
                .unwrap()
                .len()
                + 80
        })
        .sum();
    let supplied_bytes = DUAL_FEC_TEST_RATE_BPS / 8 / 10; // 200 records at 2000 pps, 100 ms.
    assert!(
        cost as u64 <= supplied_bytes,
        "integrity fixture overloads its own sender budget: {cost} bytes demand, {supplied_bytes} supplied; source/count/codec are unchanged"
    );
}
/// Preserve the complete fixture when a socket/timing assertion fails.
struct FailureEvidence(PathBuf);
impl Drop for FailureEvidence {
    fn drop(&mut self) {
        if thread::panicking() {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("local/test-failures");
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let destination = root.join(format!("runtime-{}-{stamp}", std::process::id()));
            let _ = fs::create_dir_all(&root);
            match fs::rename(&self.0, &destination) {
                Ok(()) => eprintln!("fixture evidence retained at {}", destination.display()),
                Err(error) => eprintln!("could not retain fixture evidence: {error}"),
            }
        }
    }
}

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
fn launch(args: &[String], dir: &Path, name: &str) -> Process {
    let log = dir.join(format!("{name}.log"));
    let file = fs::File::create(&log).unwrap();
    let child = Command::new(BIN)
        .env("RUST_LOG", "braidpath=info")
        // Each fixture has several independent async runtimes. Giving every
        // subprocess all runner cores oversubscribes the host and can fill the
        // bounded UDP queue before QUIC gets CPU time. Keep the same packets,
        // pacing, queue limits and assertions. Two workers also let QUIC's
        // driver progress while the sender handles a ready ingress burst.
        .env("TOKIO_WORKER_THREADS", "2")
        .args(args)
        .stdout(Stdio::null())
        .stderr(file)
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
fn run(args: &[String]) -> Output {
    run_bounded(args, Duration::from_secs(15))
}
fn run_bounded(args: &[String], maximum: Duration) -> Output {
    let mut child = Command::new(BIN)
        .env("RUST_LOG", "braidpath=info")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > maximum {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "command timeout: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
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

#[test]
fn proxy_cli_creates_one_socks_endpoint_per_exit_with_remote_half_close() {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    let _serial = socket_fixture();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let state = root.join("server");
    let server_addr = port();
    let mut server = launch(
        &args(&[
            "mesh-server",
            "--dir",
            state.to_str().unwrap(),
            "--id",
            "node-a",
            "--listen",
            &server_addr,
            "--advertise",
            &server_addr,
            "--proxy",
            "--proxy-allow-private",
        ]),
        root,
        "proxy-server",
    );
    ready(&mut server, "HTTP/3 server ready");
    let server_b_addr = port();
    let mut server_b = launch(
        &args(&[
            "mesh-server",
            "--dir",
            root.join("server-b").to_str().unwrap(),
            "--id",
            "node-b",
            "--listen",
            &server_b_addr,
            "--advertise",
            &server_b_addr,
            "--proxy",
            "--proxy-allow-private",
            "--join",
            &server_addr,
            "--join-key",
            state.join("server-key.json").to_str().unwrap(),
        ]),
        root,
        "proxy-server-b",
    );
    ready(&mut server_b, "HTTP/3 server ready");
    let key = state.join("client-key.json");
    // Listening is not membership readiness: the bootstrap advertises b only
    // after its own reachability probe succeeds, not on the incoming join hint.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let identity =
                braidpath::runtime::mesh::ClientIdentity::open(root.join("readiness"), &key)
                    .unwrap();
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let nodes = identity
                        .discover(server_addr.parse().unwrap())
                        .await
                        .unwrap();
                    if nodes.iter().any(|node| node.id == "node-b") {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("bootstrap did not discover node-b");
        });
    let client_state = root.join("client");
    let mut client = launch(
        &args(&[
            "proxy-client",
            "--connect",
            &server_addr,
            "--connection-key",
            key.to_str().unwrap(),
            "--dir",
            client_state.to_str().unwrap(),
            "--exit",
            "node-b",
            "--exit",
            "node-a",
            "--listen",
            "127.0.0.1:0",
        ]),
        root,
        "proxy-client",
    );
    ready(&mut client, "exit=node-a");
    let log = fs::read_to_string(&client.log).unwrap();
    let listeners: Vec<_> = log
        .lines()
        .filter(|l| l.contains("SOCKS5 proxy ready"))
        .map(|line| {
            (
                line.split_whitespace()
                    .find_map(|p| p.strip_prefix("exit="))
                    .unwrap(),
                line.split_whitespace()
                    .find_map(|p| p.strip_prefix("address="))
                    .unwrap(),
            )
        })
        .collect();
    assert_eq!(listeners.len(), 2, "exactly one listener per exit: {log}");
    assert_eq!((listeners[0].0, listeners[1].0), ("node-b", "node-a"));
    assert_ne!(listeners[0].1, listeners[1].1);
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = target.local_addr().unwrap();
    let target = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = target.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"proxy process acceptance");
            stream.write_all(b"response after request FIN").unwrap();
        }
    });
    for (_, listener) in listeners {
        let mut socket = TcpStream::connect(listener).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.write_all(&[5, 1, 0]).unwrap();
        let mut method = [0; 2];
        socket.read_exact(&mut method).unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(address.port().to_be_bytes());
        socket.write_all(&request).unwrap();
        let mut reply = [0; 10];
        socket.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        socket.write_all(b"proxy process acceptance").unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        let mut body = Vec::new();
        socket.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"response after request FIN");
    }
    target.join().unwrap();
    for server_addr in [&server_addr, &server_b_addr] {
        let status = run(&args(&[
            "mesh-status",
            "--connect",
            server_addr,
            "--connection-key",
            key.to_str().unwrap(),
            "--dir",
            root.join("inspect").to_str().unwrap(),
        ]));
        assert!(status.status.success());
        let status: Value = serde_json::from_slice(&status.stdout).unwrap();
        assert_eq!(status["proxy"]["streams"], 0);
        // TCP owns aggregate DATAGRAM sessions; this TCP-only client must not
        // also prepare a second set of native UDP proxy connections.
        assert_eq!(status["proxy"]["connections"], 0);
        assert_eq!(status["proxy"]["tcp_flows"], 0);
        assert_eq!(status["proxy"]["buffered_bytes"], 0);
        assert_eq!(status["proxy"]["rpc_streams"], 0);
    }
    #[cfg(unix)]
    {
        assert!(
            Command::new("kill")
                .args(["-INT", &client.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if let Some(status) = client.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "proxy client failed to stop");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn latest_stats(file: &Path) -> Value {
    fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<Value>(line).ok())
        .map(|snapshot| snapshot["stats"].clone())
        .unwrap_or(Value::Null)
}

fn latest_directions(file: &Path) -> Value {
    latest_stats(file)["directions"].clone()
}
// Quality scheduling may leave a joined path unused in one direction. Check
// that every exercised direction was reported and every path authenticated.
// Feedback can be piggybacked on another route, so standalone control counts
// do not establish whether this path's data was reported.
fn path_feedback_covers_exercised_directions(path: &Value, require_all: bool) -> bool {
    let feedback = &path["receiver_feedback"];
    let sent = feedback["sent_symbols"].as_u64().unwrap();
    let received = path["original_packets_received"].as_u64().unwrap()
        + path["repair_symbols_received"].as_u64().unwrap();
    path["authenticated"] == true
        && (!require_all || (sent > 0 && received > 0))
        && (sent == 0 || feedback["sender_estimate"]["expected"].as_u64().unwrap() > 0)
        && (received == 0 || feedback["received"]["expected"].as_u64().unwrap() > 0)
}

#[test]
fn path_feedback_requires_reports_for_data_and_authentication_for_idle_paths() {
    let mut path = serde_json::json!({
        "authenticated": true,
        "original_packets_received": 0,
        "repair_symbols_received": 0,
        "receiver_feedback": {
            "sent_symbols": 0,
            "sender_estimate": {"expected": 0}, "received": {"expected": 0}
        }
    });
    assert!(path_feedback_covers_exercised_directions(&path, false));
    assert!(!path_feedback_covers_exercised_directions(&path, true));
    path["receiver_feedback"]["sent_symbols"] = 1.into();
    assert!(!path_feedback_covers_exercised_directions(&path, false));
    path["receiver_feedback"]["sender_estimate"]["expected"] = 1.into();
    path["repair_symbols_received"] = 1.into();
    assert!(!path_feedback_covers_exercised_directions(&path, false));
    path["receiver_feedback"]["received"]["expected"] = 1.into();
    assert!(path_feedback_covers_exercised_directions(&path, false));
    path["authenticated"] = false.into();
    assert!(!path_feedback_covers_exercised_directions(&path, false));
}

#[test]
fn authenticated_http3_three_paths_and_udp_integrity() {
    three_paths(0);
}

#[test]
fn ack_requests_are_directional_on_real_http3() {
    let _fixture = socket_fixture();
    let directory = tempfile::tempdir().unwrap();
    let identity = directory.path().join("identity");
    assert!(
        run(&args(&[
            "init",
            "--dir",
            identity.to_str().unwrap(),
            "--name",
            "localhost"
        ]))
        .status
        .success()
    );
    for profile in ["unchanged", "every-two", "every-eight"] {
        let folder = directory.path().join(profile);
        fs::create_dir(&folder).unwrap();
        let echo_addr = port();
        let server_addr = port();
        let client_addr = port();
        let cert = identity.join("cert.pem");
        let key = identity.join("key.pem");
        let token = identity.join("token");
        let server_stats = folder.join("server.jsonl");
        let client_stats = folder.join("client.jsonl");
        let mut echo = launch(&args(&["echo", "--listen", &echo_addr]), &folder, "echo");
        ready(&mut echo, "test echo ready");
        let mut server = launch(
            &args(&[
                "server",
                "--listen",
                &server_addr,
                "--cert",
                cert.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
                "--token-file",
                token.to_str().unwrap(),
                "--target",
                &echo_addr,
                "--ack-request",
                profile,
                "--stats-jsonl",
                server_stats.to_str().unwrap(),
                "--stats-interval-ms",
                "50",
            ]),
            &folder,
            "server",
        );
        ready(&mut server, "HTTP/3 server ready");
        let mut client = launch(
            &args(&[
                "client",
                "--listen",
                &client_addr,
                "--entrance",
                &server_addr,
                "--server-name",
                "localhost",
                "--ca",
                cert.to_str().unwrap(),
                "--token-file",
                token.to_str().unwrap(),
                "--fec",
                "0",
                "--small-fec-bytes",
                "0",
                "--stats-jsonl",
                client_stats.to_str().unwrap(),
                "--stats-interval-ms",
                "50",
            ]),
            &folder,
            "client",
        );
        ready(&mut client, "UDP client ready");
        let out = run(&args(&[
            "probe",
            "--target",
            &client_addr,
            "--count",
            "100",
            "--pps",
            "100",
            "--size",
            "128",
            "--deadline-ms",
            "1000",
        ]));
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let probe: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(probe["received"], 100, "{profile}: {probe}");
        assert_eq!(probe["corrupt"], 0);
        let read = |path: &Path| -> Value {
            fs::read_to_string(path)
                .unwrap()
                .lines()
                .rev()
                .find_map(|s| serde_json::from_str(s).ok())
                .unwrap()
        };
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            let s = read(&server_stats);
            let c = read(&client_stats);
            let s = &s["stats"]["paths"]
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap()["quinn"];
            let c = &c["stats"]["paths"]
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap()["quinn"];
            // The client asks for every-eight by default, whatever the server asks.
            let upstream = c["ack_frequency_frames_tx"].as_u64().unwrap() > 0
                && s["ack_frequency_frames_rx"].as_u64().unwrap() > 0;
            if profile == "unchanged" {
                assert_eq!(s["ack_frequency_frames_tx"], 0);
                assert_eq!(c["ack_frequency_frames_rx"], 0);
                if upstream {
                    break;
                }
            } else if upstream
                && s["ack_frequency_frames_tx"].as_u64().unwrap() > 0
                && c["ack_frequency_frames_rx"].as_u64().unwrap() > 0
            {
                break;
            }
            assert!(
                Instant::now() < end,
                "{profile}: no actual directional negotiation"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn same_entrance_four_connections_have_distinct_sockets_and_preserve_uncoded_integrity() {
    four_connection_integrity(false);
}

#[test]
fn native_service_guard_preserves_four_connection_uncoded_integrity() {
    four_connection_integrity(true);
}

fn four_connection_integrity(native_service_guard: bool) {
    four_connection_profile(native_service_guard, false);
}

#[test]
fn rtt_source_baselines_compatibility_flag_preserves_default_integrity() {
    four_connection_profile(false, true);
}

fn four_connection_profile(native_service_guard: bool, rtt_source_baselines: bool) {
    let _fixture = socket_fixture();
    use std::collections::BTreeSet;
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    assert!(
        run(&args(&[
            "init",
            "--dir",
            identity.to_str().unwrap(),
            "--name",
            "localhost"
        ]))
        .status
        .success()
    );
    let cert = identity.join("cert.pem");
    let key = identity.join("key.pem");
    let token = identity.join("token");
    let echo_addr = port();
    let server_addr = port();
    let client_addr = port();
    let stats_file = dir.path().join("client.jsonl");
    let server_stats = dir.path().join("server.jsonl");
    let mut echo = launch(&args(&["echo", "--listen", &echo_addr]), dir.path(), "echo");
    ready(&mut echo, "test echo ready");
    let mut server = launch(
        &args(&[
            "server",
            "--listen",
            &server_addr,
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--token-file",
            token.to_str().unwrap(),
            "--target",
            &echo_addr,
            "--max-rate-bps",
            "10000000",
            "--stats-jsonl",
            server_stats.to_str().unwrap(),
            "--stats-interval-ms",
            "50",
        ])
        .into_iter()
        .chain(native_service_guard.then(|| "--native-service-guard".to_owned()))
        .chain(rtt_source_baselines.then(|| "--rtt-source-baselines".to_owned()))
        .collect::<Vec<_>>(),
        dir.path(),
        "server",
    );
    ready(&mut server, "HTTP/3 server ready");
    let mut client_args = args(&[
        "client",
        "--listen",
        &client_addr,
        "--server-name",
        "localhost",
        "--ca",
        cert.to_str().unwrap(),
        "--token-file",
        token.to_str().unwrap(),
        "--adaptive",
        "--fec",
        "0",
        "--small-fec-bytes",
        "0",
        "--redundancy-percent",
        "0",
        "--rate-bps",
        "10000000",
        "--group-rate-bps",
        "0:10000000",
        "--stats-jsonl",
        stats_file.to_str().unwrap(),
        "--stats-interval-ms",
        "50",
    ]);
    for _ in 0..4 {
        client_args.extend(args(&["--entrance", &server_addr, "--path-group", "0"]));
    }
    if native_service_guard {
        client_args.push("--native-service-guard".into());
    }
    if rtt_source_baselines {
        client_args.push("--rtt-source-baselines".into());
    }
    let mut client = launch(&client_args, dir.path(), "client");
    let until = Instant::now() + Duration::from_secs(12);
    loop {
        let last = fs::read_to_string(&stats_file)
            .unwrap_or_default()
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str::<Value>(line).ok());
        if let Some(v) = last
            && let Some(paths) = v["stats"]["paths"].as_object()
            && paths.len() == 4
        {
            assert!(paths.values().all(|p| p["authenticated"] == true));
            let ids: BTreeSet<_> = paths
                .values()
                .map(|p| p["connection_id"].as_u64().unwrap())
                .collect();
            let sockets: BTreeSet<_> = paths
                .values()
                .map(|p| p["local_socket"].as_str().unwrap())
                .collect();
            assert_eq!(ids.len(), 4);
            assert_eq!(sockets.len(), 4);
            assert!(paths.values().all(|p| p["peer_socket"] == server_addr));
            break;
        }
        assert!(client.child.try_wait().unwrap().is_none());
        assert!(
            Instant::now() < until,
            "four distinct connections not ready: {}",
            fs::read_to_string(&client.log).unwrap()
        );
        thread::sleep(Duration::from_millis(20));
    }
    let result = run(&args(&[
        "probe",
        "--target",
        &client_addr,
        "--count",
        "40",
        "--size",
        "100",
        "--pps",
        "20",
        "--deadline-ms",
        "1000",
    ]));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let values: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(values["received"], 40);
    assert_eq!(values["corrupt"], 0);
    assert_eq!(values["duplicate"], 0);
    let d = latest_directions(&stats_file);
    assert_eq!(d["client_to_server"]["symbols"]["repairs_generated"], 0);
    for (file, direction) in [
        (&stats_file, "client_to_server"),
        (&server_stats, "server_to_client"),
    ] {
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let d = latest_stats(file);
            let observed = d["paths"].as_object().is_some_and(|paths| {
                paths.len() == 4
                    && paths.values().all(|path| {
                        path["sending_direction"] == direction
                            && path["adaptive"]["last_control"]["native_service_guard_enabled"]
                                == native_service_guard
                            // Source baselines are the default; the old
                            // flag remains accepted and changes nothing.
                            && path["adaptive"]["last_control"]["rtt_source_baselines_enabled"]
                                == true
                    })
            });
            if observed {
                break;
            }
            assert!(
                Instant::now() < until,
                "missing live native-service mode on all four paths: {d}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}
#[test]
fn authenticated_receiver_feedback_both_directions() {
    three_paths(1);
}
#[test]
fn quality_scheduler_retains_bidirectional_integrity() {
    three_paths(2);
}
#[test]
fn small_record_fec_negotiates_and_sends_bounded_repairs_in_both_directions() {
    three_paths(4);
}
#[test]
fn adaptive_fec_retention_works_on_authenticated_bidirectional_sockets() {
    three_paths(5);
}
#[test]
fn dual_fec_negotiates_on_three_real_http3_paths_in_both_directions() {
    three_paths(6);
}
#[test]
fn frontier_scheduler_preserves_real_three_path_integrity_and_publishes_gates() {
    three_paths(7);
}
#[test]
fn frontier_with_dual_recovery_keeps_both_authenticated_lanes_and_budgets() {
    three_paths(8);
}
#[test]
fn repair_usefulness_guard_preserves_real_dual_and_small_lane_delivery() {
    three_paths(9);
}
#[test]
fn persistent_bad_path_rejoins_with_new_udp_port() {
    three_paths(3);
}
fn three_paths(mode: u8) {
    let _fixture = socket_fixture();
    let feedback = mode > 0;
    let dual = matches!(mode, 6 | 8 | 9);
    let frontier_enabled = matches!(mode, 7 | 8);
    let repair_guard = mode == 9;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("local/test-fixtures");
    fs::create_dir_all(&root).unwrap();
    let dir = tempfile::tempdir_in(root).unwrap();
    let _evidence = FailureEvidence(dir.path().to_owned());
    let identity = dir.path().join("identity");
    let ident = identity.to_str().unwrap();
    assert!(
        run(&args(&["init", "--dir", ident, "--name", "localhost"]))
            .status
            .success()
    );
    let cert = identity.join("cert.pem");
    let key = identity.join("key.pem");
    let token = identity.join("token");
    let echo_addr = port();
    let main_addr = port();
    let relay_addr = port();
    let relay2_addr = port();
    let client_addr = port();
    let mut echo = launch(&args(&["echo", "--listen", &echo_addr]), dir.path(), "echo");
    ready(&mut echo, "test echo ready");
    let server_stats = dir.path().join("server-stats.jsonl");
    let client_stats = dir.path().join("client-stats.jsonl");
    let mut server = launch(
        &args(&[
            "server",
            "--stats-jsonl",
            server_stats.to_str().unwrap(),
            "--stats-interval-ms",
            "100",
            "--listen",
            &main_addr,
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--token-file",
            token.to_str().unwrap(),
            "--target",
            &echo_addr,
        ])
        .into_iter()
        .chain((mode >= 5).then(|| "--adaptive-fec-retention".to_owned()))
        .chain(frontier_enabled.then(|| "--frontier-scheduler".to_owned()))
        .chain(repair_guard.then(|| "--repair-usefulness-guard".to_owned()))
        .chain(dual.then(|| "--packet-trace".to_owned()))
        .chain(dual.then(|| {
            dir.path()
                .join("server-trace.jsonl")
                .to_str()
                .unwrap()
                .to_owned()
        }))
        .chain(dual.then(|| "--max-rate-bps".to_owned()))
        .chain(dual.then(|| DUAL_FEC_TEST_RATE_BPS.to_string()))
        .collect::<Vec<_>>(),
        dir.path(),
        "server",
    );
    ready(&mut server, "HTTP/3 server ready");
    let site = run(&args(&[
        "get",
        "--entrance",
        &main_addr,
        "--server-name",
        "localhost",
        "--ca",
        cert.to_str().unwrap(),
    ]));
    assert!(
        site.status.success(),
        "{}",
        String::from_utf8_lossy(&site.stderr)
    );
    assert!(String::from_utf8_lossy(&site.stdout).contains("Welcome"));
    let wrong_name = run(&args(&[
        "get",
        "--entrance",
        &main_addr,
        "--server-name",
        "wrong.example",
        "--ca",
        cert.to_str().unwrap(),
    ]));
    assert!(
        !wrong_name.status.success(),
        "server identity must be verified"
    );
    let wrong = dir.path().join("wrong-token");
    fs::write(&wrong, "0".repeat(64)).unwrap();
    let bad = run(&args(&[
        "client",
        "--listen",
        &client_addr,
        "--entrance",
        &main_addr,
        "--server-name",
        "localhost",
        "--ca",
        cert.to_str().unwrap(),
        "--token-file",
        wrong.to_str().unwrap(),
    ]));
    assert!(!bad.status.success());
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("admission rejected"),
        "wrong-token client failed for a different reason: {}\nserver: {}",
        String::from_utf8_lossy(&bad.stderr),
        fs::read_to_string(&server.log).unwrap()
    );
    let mut relay = launch(
        &args(&[
            "relay",
            "--listen",
            &relay_addr,
            "--target",
            &main_addr,
            "--allow-source",
            "127.0.0.1",
        ]),
        dir.path(),
        "relay",
    );
    ready(&mut relay, "fixed-target relay ready");
    let mut relay2 = launch(
        &args(&[
            "relay",
            "--listen",
            &relay2_addr,
            "--target",
            &main_addr,
            "--allow-source",
            "127.0.0.1",
            "--drop-every",
            if mode == 3 { "5" } else { "17" },
        ]),
        dir.path(),
        "relay2",
    );
    ready(&mut relay2, "fixed-target relay ready");
    let mut client_args = args(&[
        "client",
        "--stats-jsonl",
        client_stats.to_str().unwrap(),
        "--stats-interval-ms",
        "100",
        "--listen",
        &client_addr,
        "--entrance",
        &main_addr,
        "--entrance",
        &relay_addr,
        "--entrance",
        &relay2_addr,
        "--server-name",
        "localhost",
        "--ca",
        cert.to_str().unwrap(),
        "--token-file",
        token.to_str().unwrap(),
        "--block-ms",
        "25",
        "--redundancy-percent",
        "50",
    ]);
    if feedback {
        client_args.push("--receiver-feedback".into());
    }
    if mode >= 2 {
        client_args.push("--quality-schedule".into());
    }
    if mode == 3 {
        client_args.push("--rotate-source-port".into());
    }
    if mode == 4 {
        client_args.extend(args(&["--fec", "0", "--small-fec-bytes", "128"]));
        let index = client_args
            .iter()
            .position(|arg| arg == "--redundancy-percent")
            .unwrap();
        client_args[index + 1] = "0".into();
    }
    if mode >= 5 {
        if !dual {
            client_args.extend(args(&["--fec", "4"]));
        }
        client_args.extend(args(&[
            "--mixed-fec",
            "--small-fec-bytes",
            "128",
            "--adaptive-fec-retention",
        ]));
    }
    if dual {
        let block = client_args
            .iter()
            .position(|arg| arg == "--block-ms")
            .unwrap();
        client_args[block + 1] = DUAL_FEC_TEST_WINDOW_MS.to_string();
        client_args.extend([
            "--latency-target-ms".into(),
            DUAL_FEC_TEST_WINDOW_MS.to_string(),
        ]);
        client_args.extend(args(&[
            "--fec",
            "16",
            "--fec-repairs",
            "2",
            "--packet-trace",
            dir.path().join("client-trace.jsonl").to_str().unwrap(),
        ]));
        client_args.extend(["--rate-bps".into(), DUAL_FEC_TEST_RATE_BPS.to_string()]);
        let index = client_args
            .iter()
            .position(|a| a == "--redundancy-percent")
            .unwrap();
        client_args[index + 1] = "13".into();
    }
    // These are negotiation/integrity fixtures, not 20 ms latency benchmarks.
    // Match the existing 100 ms non-adaptive queue age on debug CI runners;
    // retain the same source, payloads, count, rate cap, queue slots and asserts.
    if (frontier_enabled || repair_guard) && !dual {
        client_args.extend(args(&["--latency-target-ms", "100"]));
    }
    if frontier_enabled {
        client_args.extend(args(&["--frontier-scheduler", "--adaptive"]));
    }
    if repair_guard {
        client_args.extend(args(&["--repair-usefulness-guard", "--adaptive"]));
    }
    let mut client = launch(&client_args, dir.path(), "client");
    ready(&mut client, "UDP client ready");
    if frontier_enabled || repair_guard {
        // Adaptive mode announces its first usable path, not completion of all
        // joins. This three-path fixture must await the actual third join.
        let until = Instant::now() + Duration::from_secs(12);
        loop {
            let log = fs::read_to_string(&client.log).unwrap();
            if log.matches("client path ready").count() >= 3 {
                break;
            }
            assert!(client.child.try_wait().unwrap().is_none(), "{log}");
            assert!(
                Instant::now() < until,
                "three adaptive paths not ready: {log}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
    let logs = fs::read_to_string(&client.log).unwrap();
    assert_eq!(logs.matches("client path ready").count(), 3, "{logs}");
    let result = run_bounded(
        &args(&[
            "probe",
            "--target",
            &client_addr,
            "--count",
            if mode == 3 { "1200" } else { "200" },
            "--size",
            if mode == 4 { "128" } else { "700" },
            "--pps",
            if dual { "2000" } else { "200" },
            "--deadline-ms",
            "1000",
        ]),
        Duration::from_secs(if mode == 3 { 45 } else { 15 }),
    );
    assert!(
        result.status.success(),
        "{}\nclient:{}\nserver:{}",
        String::from_utf8_lossy(&result.stderr),
        fs::read_to_string(&client.log).unwrap(),
        fs::read_to_string(&server.log).unwrap()
    );
    let stats: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(stats["corrupt"], 0);
    assert_eq!(stats["duplicate"], 0);
    assert!(
        stats["received"].as_u64().unwrap() > if mode == 3 { 900 } else { 150 },
        "{stats}\nclient counters:{}\nserver counters:{}",
        latest_directions(&client_stats),
        latest_directions(&server_stats),
    );
    if feedback && mode != 3 {
        let until = Instant::now() + Duration::from_secs(4);
        loop {
            let enough = [&client_stats, &server_stats].iter().all(|file| {
                let text = fs::read_to_string(file).unwrap();
                let snapshot = text
                    .lines()
                    .rev()
                    .find_map(|line| serde_json::from_str::<Value>(line).ok())
                    .unwrap();
                let paths = snapshot["stats"]["paths"].as_object().unwrap();
                paths.len() == 3
                    && (mode != 4
                        || snapshot["stats"]["directions"][if file == &&client_stats {
                            "client_to_server"
                        } else {
                            "server_to_client"
                        }]["symbols"]["repairs_quinn_admitted"]
                            .as_u64()
                            .unwrap_or(0)
                            > 0)
                    && paths
                        .values()
                        .all(|p| path_feedback_covers_exercised_directions(p, mode < 2))
            });
            if enough {
                break;
            }
            assert!(
                Instant::now() < until,
                "feedback did not reach both senders"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
    if mode >= 5 {
        for (file, direction) in [
            (&client_stats, "server_to_client"),
            (&server_stats, "client_to_server"),
        ] {
            let text = fs::read_to_string(file).unwrap();
            let snapshot = text
                .lines()
                .rev()
                .find_map(|l| serde_json::from_str::<Value>(l).ok())
                .unwrap();
            let sessions = snapshot["stats"]["sessions"].as_object().unwrap();
            let gauges: Vec<_> = sessions
                .values()
                .filter_map(|s| s.get(direction).and_then(|d| d.get("fec_retention")))
                .collect();
            assert_eq!(
                gauges.len(),
                1,
                "retention must be a receiving-session gauge: {snapshot}"
            );
            assert_eq!(gauges[0]["enabled"], true);
            assert!((50..=250).contains(&gauges[0]["current_ms"].as_u64().unwrap()));
            assert!(gauges[0]["metadata_blocks"].as_u64().unwrap() <= 256);
            assert!(
                snapshot["stats"]["directions"][direction]
                    .get("fec_retention")
                    .is_none()
            );
        }
    }
    if dual {
        let until = Instant::now() + Duration::from_secs(4);
        loop {
            let both = ["client-trace.jsonl", "server-trace.jsonl"]
                .iter()
                .all(|name| {
                    let text = fs::read_to_string(dir.path().join(name)).unwrap();
                    let rows: Vec<Value> = text
                        .lines()
                        .filter_map(|line| serde_json::from_str(line).ok())
                        .collect();
                    let q: Vec<_> = rows
                        .iter()
                        .filter(|r| r["symbol"]["kind"] == "repair_q")
                        .collect();
                    assert!(
                        q.iter().all(|r| {
                            if r["stage"] == "record_decoded" || r["stage"] == "record_duplicate" {
                                r["recovered"] == true && r["record"]["record_id"].is_u64()
                            } else {
                                r["record"].is_null()
                            }
                        }),
                        "Q has no wire record identity; only validated reconstruction may attach a recovered record"
                    );
                    q.iter().any(|r| r["stage"] == "symbol_generated")
                        && q.iter().any(|r| r["stage"] == "peer_http_received")
                });
            if both {
                break;
            }
            assert!(
                Instant::now() < until,
                "both authenticated directions must actually transmit and receive Q parity\nclient counters:{}\nserver counters:{}",
                latest_directions(&client_stats),
                latest_directions(&server_stats)
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
    if mode == 3 {
        let until = Instant::now() + Duration::from_secs(12);
        loop {
            let text = fs::read_to_string(&client_stats).unwrap();
            let snapshot = text
                .lines()
                .rev()
                .find_map(|l| serde_json::from_str::<Value>(l).ok())
                .unwrap();
            let paths = snapshot["stats"]["paths"].as_object().unwrap();
            if let Some(path) = paths
                .values()
                .find(|p| p["rotation_successes"].as_u64().unwrap_or(0) > 0)
            {
                let old = path["previous_generations"].as_array().unwrap();
                assert!(!old.is_empty());
                assert_ne!(old[0]["local_socket"], path["local_socket"]);
                let pid = path["path_id"].as_u64().unwrap();
                let fresh = run(&args(&[
                    "probe",
                    "--target",
                    &client_addr,
                    "--count",
                    "200",
                    "--size",
                    "700",
                    "--pps",
                    "200",
                    "--deadline-ms",
                    "1000",
                ]));
                assert!(
                    fresh.status.success(),
                    "{}",
                    String::from_utf8_lossy(&fresh.stderr)
                );
                let verified_until = Instant::now() + Duration::from_secs(4);
                loop {
                    let text = fs::read_to_string(&client_stats).unwrap();
                    let current = text
                        .lines()
                        .rev()
                        .find_map(|l| serde_json::from_str::<Value>(l).ok())
                        .unwrap();
                    let current = current["stats"]["paths"]
                        .as_object()
                        .unwrap()
                        .values()
                        .find(|p| p["path_id"].as_u64() == Some(pid))
                        .unwrap();
                    if current["receiver_feedback"]["sender_estimate"]["expected"]
                        .as_u64()
                        .unwrap_or(0)
                        > 0
                    {
                        break;
                    }
                    assert!(
                        Instant::now() < verified_until,
                        "new generation was removed by old path cleanup"
                    );
                    thread::sleep(Duration::from_millis(50));
                }
                break;
            }
            assert!(
                Instant::now() < until,
                "persistent bad path never rejoined: {snapshot}"
            );
            thread::sleep(Duration::from_millis(100));
        }
    }
    if matches!(mode, 8 | 9) {
        // Exercise the configured small lane too; bulk-only traffic cannot
        // prove that finish preference and small-copy accounting coexist.
        let result = run(&args(&[
            "probe",
            "--target",
            &client_addr,
            "--count",
            "40",
            "--size",
            "128",
            "--pps",
            "20",
            "--deadline-ms",
            "200",
        ]));
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let small: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(small["corrupt"], 0);
        assert_eq!(small["duplicate"], 0);
        assert!(small["received"].as_u64().unwrap() >= 38, "{small}");
        for (file, direction) in [
            (&client_stats, "client_to_server"),
            (&server_stats, "server_to_client"),
        ] {
            let d = latest_directions(file);
            let s = &d[direction]["symbols"];
            assert!(s["mixed_small_originals_generated"].as_u64().unwrap() > 0);
            assert!(s["mixed_small_repairs_quinn_admitted"].as_u64().unwrap() > 0);
            assert!(s["mixed_bulk_repairs_quinn_admitted"].as_u64().unwrap() > 0);
            assert!(
                s["mixed_bulk_repair_admitted_bytes"].as_u64().unwrap()
                    <= s["mixed_bulk_original_admitted_bytes"].as_u64().unwrap() * 13 / 100
            );
        }
    }
    if repair_guard {
        for file in [&client_stats, &server_stats] {
            let snapshot = fs::read_to_string(file)
                .unwrap()
                .lines()
                .rev()
                .find_map(|line| serde_json::from_str::<Value>(line).ok())
                .unwrap();
            assert_eq!(snapshot["repair_usefulness_guard"], true);
        }
    }
    if frontier_enabled {
        for (file, direction) in [
            (&client_stats, "client_to_server"),
            (&server_stats, "server_to_client"),
        ] {
            let snapshot = fs::read_to_string(file)
                .unwrap()
                .lines()
                .rev()
                .find_map(|line| serde_json::from_str::<Value>(line).ok())
                .unwrap();
            let sessions = snapshot["stats"]["sessions"].as_object().unwrap();
            assert_eq!(sessions.len(), 1);
            let frontier = &sessions.values().next().unwrap()[direction]["sender_frontier"];
            assert_eq!(frontier["enabled"], true, "{snapshot}");
            assert!(frontier["head_previews"].as_u64().unwrap() > 0);
            assert_eq!(frontier["paths"].as_array().unwrap().len(), 8);
        }
    }
    // Losing a relay must not terminate the surviving independent paths.
    drop(relay2);
    let result = run(&args(&[
        "probe",
        "--target",
        &client_addr,
        "--count",
        "100",
        "--size",
        "100",
        "--pps",
        "100",
        "--deadline-ms",
        "1000",
    ]));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn independent_probe_negotiates_and_measures_without_application_records() {
    independent_probe_session(false);
}

#[test]
fn guided_recovery_negotiates_without_promoting_idle_probe_bytes_to_business() {
    independent_probe_session(true);
}

fn independent_probe_session(guided: bool) {
    let _fixture = socket_fixture();
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    assert!(
        run(&args(&[
            "init",
            "--dir",
            identity.to_str().unwrap(),
            "--name",
            "localhost"
        ]))
        .status
        .success()
    );
    let cert = identity.join("cert.pem");
    let key = identity.join("key.pem");
    let token = identity.join("token");
    let target = UdpSocket::bind("127.0.0.1:0").unwrap();
    target
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let target_addr = target.local_addr().unwrap().to_string();
    let main_addr = port();
    let client_addr = port();
    let client_stats = dir.path().join("client.jsonl");
    let server_stats = dir.path().join("server.jsonl");
    let mut server = launch(
        &args(&[
            "server",
            "--listen",
            &main_addr,
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--token-file",
            token.to_str().unwrap(),
            "--target",
            &target_addr,
            "--max-rate-bps",
            "2000000",
            "--stats-jsonl",
            server_stats.to_str().unwrap(),
            "--stats-interval-ms",
            "100",
        ]),
        dir.path(),
        "server",
    );
    ready(&mut server, "HTTP/3 server ready");
    let mut client_args = args(&[
        "client",
        "--listen",
        &client_addr,
        "--entrance",
        &main_addr,
        "--server-name",
        "localhost",
        "--ca",
        cert.to_str().unwrap(),
        "--token-file",
        token.to_str().unwrap(),
        "--adaptive",
        "--fec",
        "0",
        "--redundancy-percent",
        "0",
        "--rate-bps",
        "2000000",
        "--capacity-probe-bps",
        "64000",
        "--stats-jsonl",
        client_stats.to_str().unwrap(),
        "--stats-interval-ms",
        "100",
    ]);
    if guided {
        client_args.push("--probe-guided-recovery".into());
    }
    let mut client = launch(&client_args, dir.path(), "client");
    ready(&mut client, "UDP client ready");
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let mut measured = 0;
        for file in [&client_stats, &server_stats] {
            let text = fs::read_to_string(file).unwrap_or_default();
            if let Some(snapshot) = text
                .lines()
                .rev()
                .find_map(|l| serde_json::from_str::<Value>(l).ok())
                && let Some(paths) = snapshot["stats"]["paths"].as_object()
            {
                for path in paths.values() {
                    let probe = &path["capacity_probe"];
                    if probe["sender_estimate"]["received_bytes"]
                        .as_u64()
                        .unwrap_or(0)
                        > 0
                        && probe["sender_estimate"]["delivered_bps"]
                            .as_f64()
                            .unwrap_or(0.0)
                            > 0.0
                    {
                        assert_eq!(path["receiver_feedback"]["sent_symbols"], 0);
                        assert_eq!(path["receiver_feedback"]["received"]["received_bytes"], 0);
                        assert_eq!(
                            path["receiver_feedback"]["sender_estimate"]["received_bytes"],
                            0
                        );
                        assert_eq!(path["quinn_admitted_originals"], 0);
                        assert!(probe["sent_symbols"].as_u64().unwrap() > 0);
                        measured += 1;
                    }
                }
            }
        }
        if measured == 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "probe feedback failed: client={} server={}",
            fs::read_to_string(&client.log).unwrap(),
            fs::read_to_string(&server.log).unwrap()
        );
        assert!(client.child.try_wait().unwrap().is_none());
        assert!(server.child.try_wait().unwrap().is_none());
        thread::sleep(Duration::from_millis(30));
    }
    assert!(
        target.recv_from(&mut [0; 2048]).is_err(),
        "probe reached the application target"
    );
}
