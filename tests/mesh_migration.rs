//! Real process restart using the original state directory, with an address
//! successor and an already-running client. All process data stays in TempDir.
use braidpath::runtime::mesh::{ClientIdentity, Node};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, time::timeout};

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
impl Process {
    async fn start(root: &Path, name: &str, args: &[String], ready: &str) -> Self {
        let log = root.join(format!("{name}.log"));
        let mut process = Self {
            child: Command::new(env!("CARGO_BIN_EXE_braidpath"))
                .args(args)
                .env("RUST_LOG", "braidpath=info")
                .env("TOKIO_WORKER_THREADS", "2")
                .stdout(Stdio::null())
                .stderr(fs::File::create(&log).unwrap())
                .spawn()
                .unwrap(),
            log,
        };
        timeout(Duration::from_secs(10), async {
            loop {
                let log = fs::read_to_string(&process.log).unwrap();
                assert!(
                    process.child.try_wait().unwrap().is_none(),
                    "process exited: {log}"
                );
                if log.contains(ready) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "process not ready: {}",
                fs::read_to_string(&process.log).unwrap()
            )
        });
        process
    }
}

async fn server(
    root: &Path,
    id: &str,
    address: SocketAddr,
    target: SocketAddr,
    join: Option<SocketAddr>,
) -> Process {
    let mut args = vec![
        "mesh-server".into(),
        "--dir".into(),
        root.join(id).display().to_string(),
        "--id".into(),
        id.into(),
        "--listen".into(),
        address.to_string(),
        "--advertise".into(),
        address.to_string(),
        "--target".into(),
        target.to_string(),
        "--max-rate-bps".into(),
        "10000000".into(),
    ];
    if let Some(join) = join {
        args.extend([
            "--join".into(),
            join.to_string(),
            "--join-key".into(),
            root.join("node_a/server-key.json").display().to_string(),
        ]);
    }
    Process::start(
        root,
        &format!("{id}-{}", address.port()),
        &args,
        "HTTP/3 server ready",
    )
    .await
}

struct Echo {
    address: SocketAddr,
    received: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Echo {
    async fn start(label: u8) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let received = Arc::new(AtomicU64::new(0));
        let counter = received.clone();
        let task = tokio::spawn(async move {
            let mut data = [0; 64];
            loop {
                let (n, source) = socket.recv_from(&mut data).await.unwrap();
                counter.fetch_add(1, Ordering::Relaxed);
                data[0] = label;
                socket.send_to(&data[..n], source).await.unwrap();
            }
        });
        Self {
            address,
            received,
            task,
        }
    }
}

async fn wait_members(
    identity: &ClientIdentity,
    at: SocketAddr,
    expected: &[(&str, SocketAddr, u64)],
) {
    timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(nodes) = identity.discover(at).await
                && expected.iter().all(|(id, address, incarnation)| {
                    nodes.iter().any(|node: &Node| {
                        node.id == *id
                            && node.address == *address
                            && node.incarnation == *incarnation
                    })
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("real mesh processes did not converge");
}

async fn delivered(app: &UdpSocket, sequence: &mut u64, maximum: Duration) {
    timeout(maximum, async {
        loop {
            *sequence += 1;
            let mut packet = [0; 9];
            packet[1..].copy_from_slice(&sequence.to_le_bytes());
            app.send(&packet).await.unwrap();
            let accepted = timeout(Duration::from_millis(100), async {
                let mut response = [0; 64];
                loop {
                    let n = app.recv(&mut response).await.unwrap();
                    assert_eq!(response[0], b'A', "business traffic reached the wrong exit");
                    if n == packet.len() && response[1..n] == packet[1..] {
                        break;
                    }
                }
            })
            .await;
            if accepted.is_ok() {
                break;
            }
        }
    })
    .await
    .expect("existing client did not recover selected exit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_client_recovers_moved_server_and_never_delivers_to_address_successor() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    // Reserve all endpoints together so the allocator cannot reuse one.
    let reservations: Vec<_> = (0..5)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<_> = reservations
        .iter()
        .map(|s| s.local_addr().unwrap())
        .collect();
    let (old_a, moved_a, b, c, client_at) = (
        addresses[0],
        addresses[1],
        addresses[2],
        addresses[3],
        addresses[4],
    );
    drop(reservations);
    let target_a = Echo::start(b'A').await;
    let other_target = Echo::start(b'X').await;
    let initial = server(root, "node_a", old_a, target_a.address, None).await;
    let _b = server(root, "node_b", b, other_target.address, Some(old_a)).await;
    let _c = server(root, "node_c", c, other_target.address, Some(b)).await;
    let key_path = root.join("node_a/client-key.json");
    let identity = ClientIdentity::open(root.join("observer"), &key_path).unwrap();
    wait_members(
        &identity,
        b,
        &[("node_a", old_a, 0), ("node_b", b, 0), ("node_c", c, 0)],
    )
    .await;
    let key_before = fs::read(root.join("node_a/server-key.json")).unwrap();
    let _client = Process::start(
        root,
        "client",
        &[
            "mesh-client".into(),
            "--connect".into(),
            b.to_string(),
            "--connection-key".into(),
            key_path.display().to_string(),
            "--dir".into(),
            root.join("client").display().to_string(),
            "--exit".into(),
            "node_a".into(),
            "--listen".into(),
            client_at.to_string(),
            "--adaptive".into(),
        ],
        "UDP client ready",
    )
    .await;
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.connect(client_at).await.unwrap();
    let mut sequence = 0;
    delivered(&app, &mut sequence, Duration::from_secs(5)).await;

    let started_utc_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let started = Instant::now();
    drop(initial);
    // Same ID, keys and state directory; no enrollment arguments are required.
    let _moved = server(root, "node_a", moved_a, target_a.address, None).await;
    wait_members(&identity, b, &[("node_a", moved_a, 1)]).await;
    let _successor = server(root, "successor", old_a, other_target.address, Some(b)).await;
    wait_members(
        &identity,
        c,
        &[("node_a", moved_a, 1), ("successor", old_a, 0)],
    )
    .await;
    assert_eq!(
        fs::read(root.join("node_a/server-key.json")).unwrap(),
        key_before
    );
    delivered(&app, &mut sequence, Duration::from_secs(30)).await;
    let recovered_after_ms = started.elapsed().as_millis();
    for _ in 0..5 {
        delivered(&app, &mut sequence, Duration::from_secs(3)).await;
    }
    assert_eq!(other_target.received.load(Ordering::Relaxed), 0);
    eprintln!(
        "{}",
        serde_json::json!({
            "scenario": "original_state_address_migration", "started_utc_seconds": started_utc_seconds,
            "first_verified_post_restart_delivery_ms": recovered_after_ms,
            "wrong_exit_deliveries": 0,
            "note": "Includes process startup and convergence observations; bounded acceptance, not a network latency benchmark"
        })
    );
}
