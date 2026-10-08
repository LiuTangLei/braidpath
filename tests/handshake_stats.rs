//! Local diagnostic contracts; no WAN or transport policy changes.
#![cfg(unix)]
use braidpath::runtime::{
    stats::{ConnectionTrace, Metrics},
    transport,
};
use serde_json::Value;
use std::{
    fs,
    net::UdpSocket,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
const BIN: &str = env!("CARGO_BIN_EXE_braidpath");

#[test]
fn bounded_connection_events_preserve_stages_and_cumulative_failures() {
    let metrics = Metrics::new("server");
    for _ in 0..200 {
        let mut trace = ConnectionTrace::new(
            metrics.clone(),
            "127.0.0.1:1234".parse().unwrap(),
            None,
            "incoming",
        );
        trace.failed("deadline_elapsed");
    }
    let snapshot = metrics.snapshot(false, "running", None).unwrap();
    assert_eq!(snapshot["bounds"]["connection_events"], 128);
    assert_eq!(snapshot["stats"]["handshake_attempts"], 200);
    assert_eq!(snapshot["stats"]["handshake_failures"], 200);
    assert_eq!(snapshot["stats"]["path_admission_attempts"], 0);
    assert_eq!(snapshot["stats"]["omitted_connection_events"], 272);
    let events = snapshot["stats"]["connection_events"].as_array().unwrap();
    assert_eq!(events.len(), 128);
    let last = events.last().unwrap();
    assert_eq!(last["connection_id"], 200);
    assert_eq!(last["stage"], "incoming");
    assert_eq!(last["phase"], "quic_handshake");
    assert_eq!(last["remote"], "127.0.0.1:1234");
    assert_eq!(last["timeout_ms"], 5000);
    assert_eq!(last["error"], "deadline_elapsed");
    assert!(
        last["process_elapsed_ms"].as_f64().unwrap() >= last["total_elapsed_ms"].as_f64().unwrap()
    );
}

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
fn launch(args: &[&str], dir: &Path, name: &str) -> Process {
    let json = dir.join(format!("{name}.json"));
    let jsonl = dir.join(format!("{name}.jsonl"));
    let log = dir.join(format!("{name}.log"));
    let child = Command::new(BIN)
        .args(args)
        .args([
            "--stats-file",
            json.to_str().unwrap(),
            "--stats-jsonl",
            jsonl.to_str().unwrap(),
            "--stats-interval-ms",
            "50",
        ])
        .env("RUST_LOG", "braidpath=info")
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    Process {
        child,
        json,
        jsonl,
        log,
    }
}
fn await_sample(p: &mut Process, predicate: impl Fn(&Value) -> bool) -> Value {
    let start = Instant::now();
    loop {
        if let Ok(text) = fs::read_to_string(&p.jsonl)
            && let Some(v) = text
                .lines()
                .filter_map(|s| serde_json::from_str::<Value>(s).ok())
                .next_back()
            && predicate(&v)
        {
            return v;
        }
        assert!(
            p.child.try_wait().unwrap().is_none(),
            "{}",
            fs::read_to_string(&p.log).unwrap()
        );
        assert!(
            start.elapsed() < Duration::from_secs(12),
            "readiness timeout"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn completed(p: &mut Process, success: bool) -> Value {
    let start = Instant::now();
    loop {
        if let Some(status) = p.child.try_wait().unwrap() {
            assert_eq!(
                status.success(),
                success,
                "{}",
                fs::read_to_string(&p.log).unwrap()
            );
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(12), "process timeout");
        thread::sleep(Duration::from_millis(10));
    }
    serde_json::from_str(&fs::read_to_string(&p.json).unwrap()).unwrap()
}
fn stop(p: &mut Process) -> Value {
    assert!(
        Command::new("kill")
            .args(["-INT", &p.child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    completed(p, true)
}

#[test]
fn loopback_auth_rejection_and_normal_shutdown_are_not_handshake_failures() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    transport::initialize(&identity, "localhost").unwrap();
    let cert = identity.join("cert.pem");
    let key = identity.join("key.pem");
    let token = identity.join("token");
    let target = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string();
    let target_address = target.local_addr().unwrap().to_string();
    let mut server = launch(
        &[
            "server",
            "--listen",
            &address,
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--token-file",
            token.to_str().unwrap(),
            "--target",
            &target_address,
        ],
        dir.path(),
        "server",
    );
    await_sample(&mut server, |v| v["stats"]["ready"] == true);
    let site = Command::new(BIN)
        .args([
            "get",
            "--entrance",
            &address,
            "--server-name",
            "localhost",
            "--ca",
            cert.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(site.status.success());
    assert!(String::from_utf8_lossy(&site.stdout).contains("Welcome"));

    let wrong_token = dir.path().join("wrong-token");
    fs::write(&wrong_token, "0".repeat(64)).unwrap();
    let mut denied = launch(
        &[
            "client",
            "--listen",
            "127.0.0.1:0",
            "--entrance",
            &address,
            "--server-name",
            "localhost",
            "--ca",
            cert.to_str().unwrap(),
            "--token-file",
            wrong_token.to_str().unwrap(),
        ],
        dir.path(),
        "denied",
    );
    let denied_stats = completed(&mut denied, false);
    assert_eq!(denied_stats["stats"]["handshake_successes"], 1);
    assert_eq!(denied_stats["stats"]["handshake_failures"], 0);
    assert_eq!(denied_stats["stats"]["path_admission_attempts"], 1);
    assert_eq!(denied_stats["stats"]["path_admission_failures"], 1);
    let failure = denied_stats["stats"]["connection_events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["outcome"] == "failed")
        .unwrap();
    assert_eq!(failure["phase"], "path_admission");
    assert_eq!(failure["stage"], "admission");
    assert_eq!(failure["path_id"], 0);
    assert_eq!(failure["remote"], address);
    assert_eq!(failure["timeout_ms"], 8000);
    assert_eq!(failure["timeout_scope"], "whole_path");

    let mut client = launch(
        &[
            "client",
            "--listen",
            "127.0.0.1:0",
            "--entrance",
            &address,
            "--server-name",
            "localhost",
            "--ca",
            cert.to_str().unwrap(),
            "--token-file",
            token.to_str().unwrap(),
        ],
        dir.path(),
        "client",
    );
    let ready = await_sample(&mut client, |v| v["stats"]["ready"] == true);
    assert_eq!(ready["stats"]["path_admission_successes"], 1);
    let c = stop(&mut client);
    assert_eq!(c["stats"]["handshake_failures"], 0);
    assert_eq!(c["stats"]["path_admission_failures"], 0);
    assert!(
        c["stats"]["connection_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["phase"] == "established"
                && (e["outcome"] == "closed" || e["outcome"] == "cancelled"))
    );
    await_sample(&mut server, |v| {
        v["stats"]["connection_events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["phase"] == "established" && e["outcome"] == "closed")
    });
    let s = stop(&mut server);
    assert_eq!(s["stats"]["handshake_successes"], 3);
    assert_eq!(s["stats"]["handshake_failures"], 0);
    assert_eq!(s["stats"]["path_admission_attempts"], 2);
    assert_eq!(s["stats"]["path_admission_successes"], 1);
    assert_eq!(s["stats"]["path_admission_failures"], 1);
    let events = &s["stats"]["connection_events"];
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["error"] == "authorization_rejected")
    );
    let serialized = events.to_string();
    assert!(!serialized.contains(&fs::read_to_string(token).unwrap()));
    assert!(!serialized.contains(&"0".repeat(64)));
    assert!(!serialized.contains("session_id"));
}
