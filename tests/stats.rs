//! Live UDP/HTTP3 counters, graceful stop, JSON readiness and injected-loss accounting.
#![cfg(unix)]
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    net::UdpSocket,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
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
fn launch(args: &[&str], dir: &Path, name: &str) -> Process {
    let json = dir.join(format!("{name}.json"));
    let jsonl = dir.join(format!("{name}.jsonl"));
    let log = dir.join(format!("{name}.log"));
    let mut command = Command::new(BIN);
    command.env("RUST_LOG", "braidpath=info").args(args);
    if args[0] != "echo" {
        command.args([
            "--stats-file",
            json.to_str().unwrap(),
            "--stats-jsonl",
            jsonl.to_str().unwrap(),
            "--stats-interval-ms",
            "50",
        ]);
    }
    let child = command
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
fn ready(process: &mut Process) {
    let start = Instant::now();
    loop {
        if process.jsonl.exists()
            && fs::read_to_string(&process.jsonl)
                .unwrap()
                .lines()
                .filter_map(|s| serde_json::from_str::<Value>(s).ok())
                .any(|v| v["stats"]["ready"] == true)
        {
            return;
        }
        assert!(
            process.child.try_wait().unwrap().is_none(),
            "{}",
            fs::read_to_string(&process.log).unwrap()
        );
        assert!(
            start.elapsed() < Duration::from_secs(12),
            "readiness timeout: {}",
            fs::read_to_string(&process.log).unwrap()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn finish(process: &mut Process) -> Value {
    assert!(
        Command::new("kill")
            .args(["-INT", &process.child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let start = Instant::now();
    loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            assert!(
                status.success(),
                "{}",
                fs::read_to_string(&process.log).unwrap()
            );
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(6), "stop timeout");
        thread::sleep(Duration::from_millis(10));
    }
    let result: Value = serde_json::from_str(&fs::read_to_string(&process.json).unwrap()).unwrap();
    assert_eq!(result["final"], true);
    assert_eq!(result["stats"]["shutdown_complete"], true);
    assert_eq!(result["stats"]["drain_incomplete"], false);
    let last: Value = serde_json::from_str(
        fs::read_to_string(&process.jsonl)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(last, result);
    result
}
fn port() -> String {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}
fn num(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap()
}
fn ids(v: &Value, name: &str) -> BTreeSet<u64> {
    v[name]["recent"]
        .as_array()
        .map(|a| a.iter().map(|v| v.as_u64().unwrap()).collect())
        .unwrap_or_default()
}
fn drops(v: &Value) -> u64 {
    [
        "unauthorized_dropped",
        "oversize_dropped",
        "impairment_dropped",
        "budget_dropped",
        "mapping_limit_dropped",
        "mapping_error_dropped",
        "queue_full_dropped",
        "mapping_closed_dropped",
        "socket_send_dropped",
        "shutdown_dropped",
        "mapping_expired_queue_dropped",
        "socket_send_cancelled_dropped",
    ]
    .iter()
    .map(|k| num(v, k))
    .sum()
}
fn check_symbols(v: &Value) {
    assert_eq!(
        num(v, "originals_generated"),
        num(v, "originals_enqueued") + num(v, "originals_queue_full_dropped")
    );
    assert_eq!(
        num(v, "repairs_generated"),
        num(v, "repairs_enqueued")
            + num(v, "repairs_queue_full_dropped")
            + num(v, "repairs_budget_skipped")
    );
    assert_eq!(
        num(v, "originals_enqueued"),
        num(v, "originals_quinn_admitted")
            + num(v, "originals_expired_dropped")
            + num(v, "originals_shutdown_dropped")
    );
    assert_eq!(
        num(v, "repairs_enqueued"),
        num(v, "repairs_quinn_admitted")
            + num(v, "repairs_expired_dropped")
            + num(v, "repairs_shutdown_dropped")
    );
}
#[test]
fn raw_udp_relay_injected_loss_has_exact_conservation() {
    let dir = tempfile::tempdir().unwrap();
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = port();
    sink.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut relay = launch(
        &[
            "relay",
            "--listen",
            &addr,
            "--target",
            &sink.local_addr().unwrap().to_string(),
            "--allow-source",
            "127.0.0.1",
            "--drop-every",
            "4",
        ],
        dir.path(),
        "relay",
    );
    ready(&mut relay);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.connect(&addr).unwrap();
    let mut received = BTreeSet::new();
    let mut b = [0; 100];
    for id in 1u64..=40 {
        client.send(&id.to_be_bytes()).unwrap();
        if !id.is_multiple_of(4) {
            let (n, _) = sink.recv_from(&mut b).unwrap();
            assert_eq!(n, 8);
            received.insert(u64::from_be_bytes(b[..8].try_into().unwrap()));
        }
    }
    assert!(sink.recv_from(&mut b).is_err());
    let stats = finish(&mut relay);
    let forward = &stats["stats"]["relay"]["client_to_server"];
    assert_eq!(num(forward, "received"), 40);
    assert_eq!(num(forward, "forwarded"), 30);
    assert_eq!(num(forward, "impairment_dropped"), 10);
    assert_eq!(
        num(forward, "received"),
        num(forward, "forwarded") + drops(forward)
    );
    println!(
        "raw relay conservation: received=40 forwarded=30 impairment_dropped=10 unexplained=0"
    );
    let missing = (1u64..=40)
        .filter(|id| !received.contains(id))
        .collect::<Vec<_>>();
    assert_eq!(
        missing,
        (1u64..=40)
            .filter(|id| id.is_multiple_of(4))
            .collect::<Vec<_>>()
    );
}
#[test]
fn http3_impairment_reconciles_queues_symbols_and_observed_logical_ids() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    assert!(
        Command::new(BIN)
            .args(["init", "--dir", identity.to_str().unwrap()])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let cert = identity.join("cert.pem");
    let key = identity.join("key.pem");
    let token = identity.join("token");
    let main = port();
    let relayaddr = port();
    let clientaddr = port();
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    sink.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
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
            "--target",
            &sink.local_addr().unwrap().to_string(),
        ],
        dir.path(),
        "server",
    );
    ready(&mut server);
    let mut relay = launch(
        &[
            "relay",
            "--listen",
            &relayaddr,
            "--target",
            &main,
            "--allow-source",
            "127.0.0.1",
            "--drop-every",
            "7",
        ],
        dir.path(),
        "relay",
    );
    ready(&mut relay);
    let mut client = launch(
        &[
            "client",
            "--listen",
            &clientaddr,
            "--entrance",
            &relayaddr,
            "--server-name",
            "localhost",
            "--ca",
            cert.to_str().unwrap(),
            "--token-file",
            token.to_str().unwrap(),
            "--fec",
            "0",
            "--rate-bps",
            "64000",
        ],
        dir.path(),
        "client",
    );
    ready(&mut client);
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.connect(&clientaddr).unwrap();
    for id in 1u64..=160 {
        let mut payload = vec![0; 1000];
        payload[..8].copy_from_slice(&id.to_be_bytes());
        app.send(&payload).unwrap();
        thread::sleep(Duration::from_millis(5));
    }
    let mut delivered = BTreeSet::new();
    let mut b = [0; 1001];
    while let Ok((n, _)) = sink.recv_from(&mut b) {
        assert_eq!(n, 1000);
        delivered.insert(u64::from_be_bytes(b[..8].try_into().unwrap()));
    }
    thread::sleep(Duration::from_millis(200));
    let c = finish(&mut client);
    let s = finish(&mut server);
    let r = finish(&mut relay);
    let send = &c["stats"]["directions"]["client_to_server"];
    let recv = &s["stats"]["directions"]["client_to_server"];
    assert_eq!(num(&send["records"], "application_received"), 160);
    check_symbols(&send["symbols"]);
    assert_eq!(
        num(&send["records"], "sender_queue_enqueued"),
        num(&send["records"], "sender_input_consumed")
            + num(&send["records"], "input_shutdown_dropped")
    );
    assert_eq!(
        num(&recv["records"], "udp_target_delivered"),
        delivered.len() as u64
    );
    let session = c["stats"]["sessions"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap();
    let admitted = ids(
        &c["stats"]["sessions"][session]["client_to_server"],
        "quinn_admitted_record_ids",
    );
    let accepted = ids(
        &s["stats"]["sessions"][session]["client_to_server"],
        "udp_delivered_record_ids",
    );
    assert_eq!(
        admitted.len() as u64,
        num(&send["symbols"], "originals_quinn_admitted")
    );
    assert_eq!(accepted, delivered);
    assert!(accepted.is_subset(&admitted));
    let not_received_after_drain = admitted.difference(&accepted).count();
    assert_eq!(admitted.len(), accepted.len() + not_received_after_drain);
    println!(
        "HTTP3 FEC0 logical reconciliation: admitted={} delivered={} observed_not_received_after_drain={} (unattributed)",
        admitted.len(),
        accepted.len(),
        not_received_after_drain
    );
    let symbols = &send["symbols"];
    let records = &send["records"];
    assert!(
        num(symbols, "originals_expired_dropped") > 0,
        "controlled queue overload must expire originals"
    );
    let expiry = &symbols["expiry_wait"];
    assert_eq!(
        num(expiry, "count"),
        num(symbols, "originals_expired_dropped") + num(symbols, "repairs_expired_dropped")
    );
    assert!(expiry["sum_ms"].as_f64().unwrap() > 0.);
    assert!(expiry["max_ms"].as_f64().unwrap() >= 100.);
    assert_eq!(
        expiry["histogram"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .sum::<u64>(),
        num(expiry, "count")
    );
    assert_eq!(
        num(records, "application_received"),
        num(records, "sender_queue_full_dropped")
            + num(records, "sender_queue_closed_dropped")
            + num(records, "input_shutdown_dropped")
            + num(records, "encoding_dropped")
            + num(symbols, "originals_quinn_admitted")
            + num(symbols, "originals_queue_full_dropped")
            + num(symbols, "originals_expired_dropped")
            + num(symbols, "originals_shutdown_dropped")
    );
    println!(
        "queue expiry conservation: application={} quinn_admitted={} expired={} shutdown={} expiry_wait_count={} expiry_wait_max_ms={}",
        num(records, "application_received"),
        num(symbols, "originals_quinn_admitted"),
        num(symbols, "originals_expired_dropped"),
        num(symbols, "originals_shutdown_dropped"),
        num(expiry, "count"),
        expiry["max_ms"]
    );

    for forward in r["stats"]["relay"].as_object().unwrap().values() {
        assert_eq!(
            num(forward, "received"),
            num(forward, "forwarded") + drops(forward)
        );
    }
    let path = c["stats"]["paths"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(
        num(path, "quinn_admitted_originals"),
        num(&send["symbols"], "originals_quinn_admitted")
    );
    assert!(path["quinn"]["min_rtt_ms"].as_f64().is_some());
    assert!(path["quinn"]["congestion_events"].as_u64().is_some());
}
#[test]
fn error_returns_final_json_without_log_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let stats = dir.path().join("error.json");
    let stream = dir.path().join("error.jsonl");
    let result = Command::new(BIN)
        .args([
            "client",
            "--entrance",
            "127.0.0.1:1",
            "--server-name",
            "localhost",
            "--ca",
            "missing-cert",
            "--token-file",
            "missing-token",
            "--stats-file",
            stats.to_str().unwrap(),
            "--stats-jsonl",
            stream.to_str().unwrap(),
        ])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!result.success());
    let final_stats: Value = serde_json::from_str(&fs::read_to_string(stats).unwrap()).unwrap();
    assert_eq!(final_stats["outcome"], "error");
    assert_eq!(final_stats["final"], true);
    assert!(final_stats["error"].as_str().unwrap().contains("token"));
}
