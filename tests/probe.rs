//! Focused finite local UDP workloads; transient run files remain in TempDir.
use serde_json::{Value, json};
use std::{
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
const BIN: &str = env!("CARGO_BIN_EXE_braidpath");
struct Process {
    child: Child,
    ready: PathBuf,
    result: PathBuf,
    stderr: PathBuf,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn launch(args: &[&str], dir: &Path, name: &str) -> Process {
    let ready = dir.join(format!("{name}-ready.json"));
    let result = dir.join(format!("{name}-result.json"));
    let stderr = dir.join(format!("{name}-stderr.log"));
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .args(["--ready-file", ready.to_str().unwrap()]);
    if args[0] == "sink" {
        cmd.args(["--result-file", result.to_str().unwrap()]);
    }
    Process {
        child: cmd
            .stdout(Stdio::null())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap(),
        ready,
        result,
        stderr,
    }
}
fn ready(p: &mut Process) -> Value {
    let start = Instant::now();
    loop {
        if let Ok(text) = fs::read_to_string(&p.ready)
            && let Ok(value) = serde_json::from_str::<Value>(&text)
        {
            assert_eq!(value["ready"], true);
            assert_eq!(value["pid"], p.child.id());
            assert!(value["sample_unix_ms"].as_i64().unwrap() > 0);
            assert_eq!(value["instance_id"].as_str().unwrap().len(), 32);
            let listen: SocketAddr = value["listen"].as_str().unwrap().parse().unwrap();
            assert_eq!(listen.ip().to_string(), "127.0.0.1");
            assert_ne!(listen.port(), 0);
            return value;
        }
        assert!(
            p.child.try_wait().unwrap().is_none(),
            "early process exit: result={}; stderr={}",
            fs::read_to_string(&p.result).unwrap_or_default(),
            fs::read_to_string(&p.stderr).unwrap_or_default()
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "readiness timeout"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
fn run(args: &[&str]) -> (bool, Value) {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            return (
                output.status.success(),
                serde_json::from_slice(&output.stdout).unwrap(),
            );
        }
        if start.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            panic!("probe timeout");
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn finish(p: &mut Process) -> Value {
    let start = Instant::now();
    loop {
        if let Some(status) = p.child.try_wait().unwrap() {
            assert!(status.success());
            return serde_json::from_str(&fs::read_to_string(&p.result).unwrap()).unwrap();
        }
        assert!(start.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(5));
    }
}
fn run_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}
#[test]
fn ordinary_echo_raw_metadata_and_monotonic_rtt() {
    let dir = tempfile::tempdir().unwrap();
    // Let the process own its ephemeral bind; dropping a temporary reservation
    // before spawn lets concurrent tests claim that same port.
    let mut echo = launch(&["echo", "--listen", "127.0.0.1:0"], dir.path(), "echo");
    let target = ready(&mut echo)["listen"].as_str().unwrap().to_owned();
    let (ok, v) = run(&[
        "probe",
        "--target",
        &target,
        "--listen",
        "127.0.0.1:0",
        "--transport",
        "raw-udp",
        "--count",
        "12",
        "--pps",
        "200",
        "--size",
        "16",
        "--drain-ms",
        "100",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["transport"], "raw-udp");
    assert_eq!(v["listen"], v["local_addr"]);
    let local: SocketAddr = v["local_addr"].as_str().unwrap().parse().unwrap();
    assert_eq!(local.ip().to_string(), "127.0.0.1");
    assert_ne!(local.port(), 0);
    assert_eq!(v["peer_addr"], target);
    assert_eq!(v["sent"], 12);
    assert_eq!(v["received"], 12);
    assert_eq!(v["lost"], 0);
    assert!(v["p50_ms"].as_f64().unwrap() >= 0.);
    assert_eq!(v["control_datagrams_sent"], 0);
    assert_eq!(v["control_datagrams_received"], 0);
}
#[test]
fn forward_one_way_sink_is_authoritative_and_samples_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let id = run_id();
    let samples = dir.path().join("samples.json");
    let mut sink = launch(
        &[
            "sink",
            "--listen",
            "127.0.0.1:0",
            "--run-id",
            &id,
            "--count",
            "12",
            "--pps",
            "200",
            "--size",
            "100",
            "--drain-ms",
            "100",
            "--samples-file",
            samples.to_str().unwrap(),
        ],
        dir.path(),
        "forward",
    );
    let listening = ready(&mut sink);
    assert_eq!(listening["run_id"], id);
    let target = listening["listen"].as_str().unwrap().to_owned();
    let (ok, sender) = run(&[
        "probe",
        "--mode",
        "send",
        "--target",
        &target,
        "--run-id",
        &id,
        "--count",
        "12",
        "--pps",
        "200",
        "--size",
        "100",
        "--drain-ms",
        "100",
    ]);
    assert!(ok, "{sender}");
    assert_eq!(sender["sent"], 12);
    assert!(sender.get("received").is_none());
    assert!(sender.get("loss_rate").is_none());
    assert_eq!(sender["control_datagrams_sent"], 2);
    assert_eq!(sender["registration_attempts"], 1);
    let receiver = finish(&mut sink);
    assert_eq!(receiver["sent"], Value::Null);
    assert_eq!(receiver["received"], 12);
    assert_eq!(receiver["expected_count"], 12);
    assert_eq!(receiver["lost"], 0);
    assert_eq!(receiver["direction"], "client_to_server");
    assert_eq!(receiver["control_datagrams_received"], 2);
    assert_eq!(receiver["control_datagrams_sent"], 1);
    assert!(receiver["send_span_seconds"].as_f64().unwrap() > 0.);
    assert!(receiver["useful_goodput_bps"].as_f64().unwrap() > 0.);
    let sample: Value = serde_json::from_str(&fs::read_to_string(samples).unwrap()).unwrap();
    assert_eq!(sample["samples"].as_array().unwrap().len(), 12);
    assert!(
        sample["samples"].as_array().unwrap().iter().all(
            |s| s["send_unix_us"].as_i64().is_some() && s["receive_unix_us"].as_i64().is_some()
        )
    );
}
#[test]
fn reverse_stream_uses_the_registration_socket_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let id = run_id();
    let mut sink = launch(
        &[
            "sink",
            "--role",
            "reverse-source",
            "--listen",
            "127.0.0.1:0",
            "--run-id",
            &id,
            "--count",
            "12",
            "--pps",
            "200",
            "--size",
            "100",
            "--drain-ms",
            "1000",
        ],
        dir.path(),
        "reverse",
    );
    let target = ready(&mut sink)["listen"].as_str().unwrap().to_owned();
    // Opaque UDP mapping: the upstream source socket is created once and reused.
    let downstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream.connect(&target).unwrap();
    downstream.set_nonblocking(true).unwrap();
    upstream.set_nonblocking(true).unwrap();
    let relay_addr = downstream.local_addr().unwrap().to_string();
    let mapped_peer = upstream.local_addr().unwrap().to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let relay = thread::spawn(move || {
        let mut peer = None;
        let mut b = [0u8; 1001];
        let mut forwarded = (0, 0);
        while !stopped.load(Ordering::Relaxed) {
            if let Ok((n, from)) = downstream.recv_from(&mut b) {
                peer = Some(from);
                upstream.send(&b[..n]).unwrap();
                forwarded.0 += 1;
            }
            if let Ok(n) = upstream.recv(&mut b) {
                downstream.send_to(&b[..n], peer.unwrap()).unwrap();
                forwarded.1 += 1;
            }
            // Mapping is exercised over real UDP. Controlled-time unit tests
            // independently cover slow progress without host scheduling assumptions.
            thread::sleep(Duration::from_millis(1));
        }
        forwarded
    });
    let (ok, receiver) = run(&[
        "probe",
        "--mode",
        "receive",
        "--target",
        &relay_addr,
        "--run-id",
        &id,
        "--count",
        "12",
        "--pps",
        "200",
        "--size",
        "100",
        "--drain-ms",
        "1000",
    ]);
    stop.store(true, Ordering::Relaxed);
    let forwarded = relay.join().unwrap();
    let source = finish(&mut sink);
    let diagnostic = format!("receiver={receiver}; source={source}; relay={forwarded:?}");
    assert!(ok, "{diagnostic}");
    assert_eq!(receiver["received"], 12, "{diagnostic}");
    assert_eq!(receiver["direction"], "server_to_client");
    assert_eq!(receiver["control_datagrams_sent"], 1);
    assert_eq!(source["sent"], 12);
    assert_eq!(source["peer"], mapped_peer);
    assert!(source.get("loss_rate").is_none());
}
#[test]
fn missing_echo_operations_have_explicit_infinite_quantiles() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let target = socket.local_addr().unwrap().to_string();
    let echo = thread::spawn(move || {
        let mut b = [0u8; 1001];
        for i in 0..10 {
            let (n, peer) = socket.recv_from(&mut b).unwrap();
            if i < 5 {
                socket.send_to(&b[..n], peer).unwrap();
            }
        }
    });
    let (ok, v) = run(&[
        "probe",
        "--target",
        &target,
        "--transport",
        "raw-udp",
        "--count",
        "10",
        "--pps",
        "200",
        "--size",
        "100",
        "--drain-ms",
        "100",
    ]);
    echo.join().unwrap();
    assert!(ok, "{v}");
    assert_eq!(v["received"], 5);
    assert_eq!(v["lost"], 5);
    assert_eq!(v["loss_rate"], json!(0.5));
    assert!(v["p50_ms"].is_number());
    assert_eq!(v["p95_ms"], "infinity");
    assert_eq!(v["p99_ms"], "infinity");
}
#[test]
fn wrong_run_id_does_not_amplify_and_timeout_is_machine_readable() {
    let dir = tempfile::tempdir().unwrap();
    let id = run_id();
    let wrong = run_id();
    let mut sink = launch(
        &[
            "sink",
            "--role",
            "reverse-source",
            "--listen",
            "127.0.0.1:0",
            "--run-id",
            &id,
            "--count",
            "12",
            "--pps",
            "200",
            "--size",
            "100",
            "--startup-timeout-ms",
            "1500",
        ],
        dir.path(),
        "reject",
    );
    let target = ready(&mut sink)["listen"].as_str().unwrap().to_owned();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(&target).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut registration = vec![0u8; 36];
    registration[..4].copy_from_slice(b"BPP2");
    registration[4] = 1;
    for i in 0..16 {
        registration[8 + i] = u8::from_str_radix(&wrong[i * 2..i * 2 + 2], 16).unwrap();
    }
    socket.send(&registration).unwrap();
    let mut b = [0u8; 1001];
    assert!(socket.recv(&mut b).is_err());
    let start = Instant::now();
    while sink.child.try_wait().unwrap().is_none() {
        assert!(start.elapsed() < Duration::from_secs(3));
        thread::sleep(Duration::from_millis(5));
    }
    let v: Value = serde_json::from_str(&fs::read_to_string(&sink.result).unwrap()).unwrap();
    assert_eq!(v["outcome"], "error");
    assert_eq!(v["sent"], 0);
    assert_eq!(v["control_datagrams_sent"], 0);
    assert_eq!(v["rejected_datagrams"], 1);
    let (ok, v) = run(&[
        "probe",
        "--mode",
        "receive",
        "--target",
        &target,
        "--run-id",
        &id,
        "--startup-timeout-ms",
        "150",
    ]);
    assert!(!ok);
    assert_eq!(v["outcome"], "error");
    assert!(v["registration_attempts"].as_u64().unwrap() <= 3);
}
#[test]
fn invalid_count_does_not_allocate_and_emits_error_json() {
    let (ok, v) = run(&["probe", "--target", "127.0.0.1:1", "--count", "4294967295"]);
    assert!(!ok);
    assert_eq!(v["outcome"], "error");
    assert_eq!(v["sent"], 0);
}

#[test]
fn unavailable_registration_retries_are_bounded_and_counted() {
    let quiet = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = quiet.local_addr().unwrap().to_string();
    let id = run_id();
    let (ok, v) = run(&[
        "probe",
        "--mode",
        "receive",
        "--target",
        &target,
        "--run-id",
        &id,
        "--startup-timeout-ms",
        "150",
        "--count",
        "1",
    ]);
    assert!(!ok);
    assert_eq!(v["outcome"], "error");
    assert_eq!(v["registration_attempts"], 3);
    assert_eq!(v["control_datagrams_sent"], 3);
    assert_eq!(v["sent"], 0);
    assert!(
        v["local_addr"]
            .as_str()
            .unwrap()
            .split(':')
            .next_back()
            .unwrap()
            .parse::<u16>()
            .unwrap()
            > 0
    );
    assert_eq!(v["peer_addr"], target);
    quiet
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let mut b = [0u8; 1001];
    for _ in 0..3 {
        assert_eq!(quiet.recv_from(&mut b).unwrap().0, 36);
    }
    assert!(quiet.recv_from(&mut b).is_err());
}
