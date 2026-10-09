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
        if start.elapsed() > Duration::from_secs(15) {
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
fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}
#[test]
fn authenticated_http3_three_paths_and_udp_integrity() {
    three_paths(0);
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
fn persistent_bad_path_rejoins_with_new_udp_port() {
    three_paths(3);
}
fn three_paths(mode: u8) {
    let feedback = mode > 0;
    let dir = tempfile::tempdir().unwrap();
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
        ]),
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
    assert!(String::from_utf8_lossy(&bad.stderr).contains("admission rejected"));
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
    let mut client = launch(&client_args, dir.path(), "client");
    ready(&mut client, "UDP client ready");
    let logs = fs::read_to_string(&client.log).unwrap();
    assert_eq!(logs.matches("client path ready").count(), 3, "{logs}");
    let result = run(&args(&[
        "probe",
        "--target",
        &client_addr,
        "--count",
        if mode == 3 { "1200" } else { "200" },
        "--size",
        "700",
        "--pps",
        "200",
        "--deadline-ms",
        "1000",
    ]));
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
        "{stats}"
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
                    && paths.values().all(|p| {
                        p["receiver_feedback"]["sender_estimate"]["expected"]
                            .as_u64()
                            .unwrap_or(0)
                            > 0
                            && p["receiver_feedback"]["received"]["expected"]
                                .as_u64()
                                .unwrap_or(0)
                                > 0
                    })
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
