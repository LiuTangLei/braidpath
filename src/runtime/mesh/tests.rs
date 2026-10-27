use super::super::tunnel::Policy;
use super::*;
use tokio::time::timeout;

pub(super) struct Task<T>(pub(super) tokio::task::JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(crate) fn address() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
pub(super) async fn wait_nodes(
    identity: &ClientIdentity,
    at: SocketAddr,
    expected: &[&str],
) -> Vec<Node> {
    eprintln!("waiting for {expected:?} at {at}");
    let mut last = String::from("no response");
    timeout(Duration::from_secs(30), async {
        loop {
            match identity.discover(at).await {
                Ok(nodes)
                    if nodes.iter().map(|n| n.id.as_str()).collect::<Vec<_>>() == expected =>
                {
                    return nodes;
                }
                Ok(nodes) => last = format!("authenticated nodes: {nodes:?}"),
                Err(error) => last = format!("{error:#}"),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("membership at {at} expected {expected:?}: {last}"))
}
pub(super) async fn server(
    root: &Path,
    id: &str,
    listen: SocketAddr,
    target: SocketAddr,
    join: Option<(SocketAddr, PathBuf)>,
) -> Task<Result<()>> {
    server_with_metrics(
        root,
        id,
        listen,
        target,
        join,
        stats::Metrics::new("test-server"),
    )
    .await
}
pub(super) async fn server_with_metrics(
    root: &Path,
    id: &str,
    listen: SocketAddr,
    target: SocketAddr,
    join: Option<(SocketAddr, PathBuf)>,
    metrics: stats::Metrics,
) -> Task<Result<()>> {
    let dir = root.join(id);
    let options = ServerOptions {
        dir: dir.clone(),
        id: id.into(),
        listen,
        advertise: listen,
        relay_ports: None,
        target: Some(target),
        tcp_target: None,
        proxy: None,
        rate: 10_000_000,
        join: join.as_ref().map(|(a, _)| *a),
        join_key: join.map(|(_, p)| p),
        stats: metrics.clone(),
    };
    let mut task = Task(tokio::spawn(serve(options)));
    timeout(Duration::from_secs(8), async {
        while !metrics.is_ready() && !task.0.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    if task.0.is_finished() {
        panic!(
            "mesh server {id} at {listen} exited before readiness: {:?}",
            (&mut task.0).await
        );
    }
    assert!(
        metrics.is_ready(),
        "mesh fixture returned before socket readiness"
    );
    task
}
pub(crate) fn policy() -> Policy {
    Policy {
        streams: false,
        proxy: false,
        max_message_bytes: 1000,
        adaptive: true,
        capacity_probe_bps: 0,
        probe_guided_recovery: false,
        latency_target_ms: 100,
        group_rates: [10_000_000; MAX_PATHS],
        receiver_feedback: true,
        quality_schedule: true,
        fec: 0,
        fec_repairs: 1,
        small_fec_bytes: 0,
        mixed_fec: false,
        redundancy: 0,
        rate: 10_000_000,
        block_ms: 3,
        queue_ms: 100,
    }
}
pub(super) async fn echo(label: u8) -> (SocketAddr, Task<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    (
        address,
        Task(tokio::spawn(async move {
            let mut bytes = [0; 1024];
            loop {
                let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
                bytes[0] = label;
                socket.send_to(&bytes[..n], peer).await.unwrap();
            }
        })),
    )
}
async fn wait_entrances(guard: &Entrances, count: usize) -> Vec<SocketAddr> {
    let mut updates = guard.updates();
    timeout(Duration::from_secs(8), async {
        loop {
            let addresses = updates.borrow_and_update().clone();
            if addresses.len() >= count {
                return addresses;
            }
            updates.changed().await.unwrap();
        }
    })
    .await
    .expect("optional entrances were not allocated")
}

async fn delivery(identity: &ClientIdentity, entrances: Vec<SocketAddr>, label: u8, exit: &str) {
    let listen = address();
    let client = Task(tokio::spawn(tunnel::client_with_mesh_exit(
        tunnel::ClientOptions {
            stream_connector: None,
            tcp_listen: None,
            proxy_listen: None,
            adaptive_fec_retention: false,
            rotate_source_port: false,
            listen,
            entrances,
            interfaces: vec![],
            path_binds: vec![],
            path_groups: vec![],
            datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            name: identity.name(),
            ca: identity.dir.join("cert.pem"),
            token: identity.dir.join("token"),
            policy: policy(),
            congestion: transport::Congestion::default(),
            stats: stats::Metrics::new("test-client"),
        },
        None,
        None,
        exit.into(),
    )));
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.connect(listen).await.unwrap();
    timeout(Duration::from_secs(8), async {
        let mut result = [0; 64];
        loop {
            assert!(!client.0.is_finished(), "client exited");
            app.send(b"_mesh-exit-proof").await.unwrap();
            if let Ok(Ok(n)) = timeout(Duration::from_millis(100), app.recv(&mut result)).await {
                assert_eq!(n, 16);
                assert_eq!(result[0], label);
                assert_eq!(&result[1..n], b"mesh-exit-proof");
                break;
            }
        }
    })
    .await
    .expect("no delivered UDP response");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_survives_bootstrap_loss_and_selects_any_exit_through_peers() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("braidpath=warn")
        .try_init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let (target_a, _echo_a) = echo(b'A').await;
    let (target_b, _echo_b) = echo(b'B').await;
    let (target_c, _echo_c) = echo(b'C').await;
    let a = address();
    let b = address();
    let c = address();
    let first = server(root, "node_a", a, target_a, None).await;
    let identity =
        ClientIdentity::open(root.join("client"), &root.join("node_a/client-key.json")).unwrap();
    wait_nodes(&identity, a, &["node_a"]).await;
    let second = server(
        root,
        "node_b",
        b,
        target_b,
        Some((a, root.join("node_a/server-key.json"))),
    )
    .await;
    wait_nodes(&identity, b, &["node_a", "node_b"]).await;
    let third = server(
        root,
        "node_c",
        c,
        target_c,
        Some((b, root.join("node_b/server-key.json"))),
    )
    .await;
    let nodes = wait_nodes(&identity, a, &["node_a", "node_b", "node_c"]).await;
    wait_nodes(&identity, b, &["node_a", "node_b", "node_c"]).await;
    wait_nodes(&identity, c, &["node_a", "node_b", "node_c"]).await;

    // Each node can be the exit. Force relay-only traffic, excluding the direct
    // address, so an echo cannot accidentally pass without server cooperation.
    for (id, label) in [("node_a", b'A'), ("node_b", b'B'), ("node_c", b'C')] {
        let (_, leases) = identity
            .entrances(nodes.clone(), id, MAX_PATHS)
            .await
            .unwrap();
        let entrances = wait_entrances(&leases, 3).await;
        assert_eq!(entrances.len(), 3);
        delivery(&identity, entrances[1..].to_vec(), label, id).await;
    }
    let control = Control::new(&identity.dir.join("cert.pem"), false).unwrap();
    let attempt = Exchange {
        sender: Node {
            id: "intruder".into(),
            address: address(),
            incarnation: 0,
        },
        nodes: vec![],
    };
    assert!(
        control
            .request::<Exchange>(
                b,
                &identity.auth,
                "/mesh/sync",
                Some(serde_json::to_vec(&attempt).unwrap())
            )
            .await
            .is_err()
    );
    assert!(
        control
            .request::<Vec<Node>>(b, "Bearer wrong", "/mesh/nodes", None)
            .await
            .is_err()
    );
    assert!(
        control
            .request::<RelayReply>(
                b,
                &identity.auth,
                "/mesh/relay",
                Some(
                    serde_json::to_vec(&RelayRequest {
                        request: None,
                        exit: "intruder".into(),
                        lease: None
                    })
                    .unwrap()
                )
            )
            .await
            .is_err()
    );

    drop(first);
    let remaining = wait_nodes(&identity, b, &["node_b", "node_c"]).await;
    // The local client cache survives process restart. A dead original entry
    // must not prevent a new client from discovering a surviving member.
    let reopened =
        ClientIdentity::open(root.join("client"), &root.join("node_a/client-key.json")).unwrap();
    assert_eq!(reopened.discover_any(&[a]).await.unwrap(), remaining);
    assert_eq!(reopened.discover_any(&[a, c]).await.unwrap(), remaining);
    let (_, leases) = identity
        .entrances(remaining, "node_c", MAX_PATHS)
        .await
        .unwrap();
    let entrances = wait_entrances(&leases, 2).await;
    assert_eq!(entrances.len(), 2);
    delivery(&identity, entrances[1..].to_vec(), b'C', "node_c").await;

    // A new server joins a surviving member; it never contacts the first server.
    let d = address();
    let fourth = server(
        root,
        "node_d",
        d,
        target_b,
        Some((c, root.join("node_c/server-key.json"))),
    )
    .await;
    wait_nodes(&identity, d, &["node_b", "node_c", "node_d"]).await;
    wait_nodes(&identity, b, &["node_b", "node_c", "node_d"]).await;
    drop(second);
    // Restart with the original enrollment arguments, even though the original
    // seed is down; saved identity and peers must take precedence.
    timeout(Duration::from_secs(8), async {
        loop {
            if std::net::UdpSocket::bind(b).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("cancelled server retained listening socket");
    let restarted = server(
        root,
        "node_b",
        b,
        target_b,
        Some((a, root.join("node_a/server-key.json"))),
    )
    .await;
    wait_nodes(&identity, b, &["node_b", "node_c", "node_d"]).await;
    drop((restarted, third, fourth));
}

pub(crate) fn state(root: &Path) -> State {
    State {
        proxy: None,
        fixed_tcp: false,
        _directory_lock: None,
        own: Node {
            id: "own".into(),
            address: "127.0.0.1:10000".parse().unwrap(),
            incarnation: 0,
        },
        bind: "127.0.0.1:10000".parse().unwrap(),
        relay_ports: None,
        dir: root.into(),
        client_auth: "client".into(),
        member_auth: "member".into(),
        peers: Arc::new(Mutex::new(BTreeMap::new())),
        reconnect: Arc::new(Mutex::new(Vec::new())),
        membership_write: Arc::new(tokio::sync::Mutex::new(())),
        persistence: Arc::default(),
        relay_budget: Arc::new(relay::HostBudget::new(10_000_000)),
        leases: Mutex::new(BTreeMap::new()),
        released_requests: Mutex::new(ReleasedRequests::default()),
        control_connections: Arc::new(tokio::sync::Semaphore::new(CONTROL_CONNECTIONS)),
        rate: 10_000_000,
    }
}
fn node(id: &str, port: u16) -> Node {
    Node {
        id: id.into(),
        address: SocketAddr::from(([127, 0, 0, 1], port)),
        incarnation: 0,
    }
}
fn age(state: &State, id: &str, by: Duration) {
    let mut peers = state.peers.lock().unwrap();
    let peer = peers.get_mut(id).unwrap();
    peer.heard = Instant::now() - by;
    peer.seen = peer.seen.map(|_| Instant::now() - by);
}
#[tokio::test]
async fn gossip_does_not_extend_liveness_and_conflicting_hints_are_isolated() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(temp.path());
    let peer = node("peer", 10001);
    state
        .merge(
            Exchange {
                sender: peer.clone(),
                nodes: vec![],
            },
            true,
        )
        .await
        .unwrap();
    state.peers.lock().unwrap().get_mut("peer").unwrap().seen = Some(Instant::now() - LIVE_FOR);
    state
        .merge(
            Exchange {
                sender: peer.clone(),
                nodes: vec![],
            },
            false,
        )
        .await
        .unwrap();
    assert_eq!(state.active(), vec![state.own.clone()]);
    // A hint conflicting with a current member is skipped; the sender and
    // unrelated hints are still accepted, and the sender becomes live.
    let good = node("good", 10002);
    let other = node("other", 10004);
    let mut conflict = peer.clone();
    conflict.address.set_port(10003);
    let mut stale_own = state.own.clone();
    stale_own.address.set_port(10005);
    state
        .merge(
            Exchange {
                sender: good.clone(),
                nodes: vec![good.clone(), conflict.clone(), other.clone(), stale_own],
            },
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        state.known(),
        vec![state.own.clone(), good.clone(), other, peer.clone()]
    );
    assert_eq!(state.active(), vec![good.clone(), state.own.clone()]);
    // An inconsistent sender is still rejected as a whole.
    assert!(
        state
            .merge(
                Exchange {
                    sender: conflict,
                    nodes: vec![],
                },
                true,
            )
            .await
            .is_err()
    );
    // New records beyond the member limit are skipped, not fatal.
    let too_many = (0..MAX_NODES as u16)
        .map(|i| node(&format!("n{i:02}"), 11000 + i))
        .collect();
    state
        .merge(
            Exchange {
                sender: peer,
                nodes: too_many,
            },
            false,
        )
        .await
        .unwrap();
    assert_eq!(state.known().len(), MAX_NODES);
    // Only live members are advertised to peers.
    assert_eq!(state.exchange().nodes, state.active());
}

#[tokio::test]
async fn moved_members_replace_unheard_records_and_departed_members_are_forgotten() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(temp.path());
    let live = node("live", 10001);
    let moving = node("moving", 10002);
    for sender in [&live, &moving] {
        state
            .merge(
                Exchange {
                    sender: sender.clone(),
                    nodes: vec![],
                },
                true,
            )
            .await
            .unwrap();
    }
    let mut moved = moving.clone();
    moved.address.set_port(10003);
    let reused = node("successor", 10001);
    let exchange = |sender: &Node| Exchange {
        sender: sender.clone(),
        nodes: vec![],
    };
    // Records heard recently are never displaced.
    assert!(state.merge(exchange(&moved), false).await.is_err());
    assert!(state.merge(exchange(&reused), false).await.is_err());
    age(&state, "moving", LIVE_FOR);
    state.merge(exchange(&moved), false).await.unwrap();
    assert_eq!(
        state.known(),
        vec![state.own.clone(), live.clone(), moved.clone()]
    );
    let saved: Vec<Node> = read_json(&temp.path().join("peers.json")).unwrap();
    assert_eq!(saved, vec![live.clone(), moved.clone()]);

    // An isolated server keeps every record, however old.
    age(&state, "live", FORGET_AFTER);
    age(&state, "moving", FORGET_AFTER);
    state.forget_departed().await.unwrap();
    assert_eq!(state.known().len(), 3);
    // Once a peer is live again, records nobody reported running are dropped.
    state.merge(exchange(&live), true).await.unwrap();
    state.forget_departed().await.unwrap();
    assert_eq!(state.known(), vec![state.own.clone(), live.clone()]);
    let saved: Vec<Node> = read_json(&temp.path().join("peers.json")).unwrap();
    assert_eq!(saved, vec![live]);
    // A departed member that returns is admitted again by its own exchange.
    state.merge(exchange(&moved), false).await.unwrap();
    assert_eq!(state.known().len(), 3);
}

#[tokio::test]
async fn failed_restart_cache_write_does_not_commit_membership_and_can_retry() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(temp.path());
    let peer = Node {
        id: "peer".into(),
        address: "127.0.0.1:10001".parse().unwrap(),
        incarnation: 0,
    };
    fs::create_dir(temp.path().join("peers.json")).unwrap();
    let exchange = || Exchange {
        sender: peer.clone(),
        nodes: vec![],
    };
    assert!(state.merge(exchange(), true).await.is_err());
    assert_eq!(state.known(), vec![state.own.clone()]);
    fs::remove_dir(temp.path().join("peers.json")).unwrap();
    state.merge(exchange(), true).await.unwrap();
    let saved: Vec<Node> = read_json(&temp.path().join("peers.json")).unwrap();
    assert_eq!(saved, vec![peer]);
    assert_eq!(state.known().len(), 2);
}
#[tokio::test]
async fn full_isolated_directory_admits_sender_and_preserves_displaced_peer() {
    let temp = tempfile::tempdir().unwrap();
    let server = state(temp.path());
    let old: Vec<_> = (0..MAX_NODES as u16 - 1)
        .map(|i| node(&format!("old_{i:02}"), 11000 + i))
        .collect();
    server
        .merge(
            Exchange {
                sender: server.own.clone(),
                nodes: old.clone(),
            },
            false,
        )
        .await
        .unwrap();
    let newcomer = node("newcomer", 12000);
    let exchange = || Exchange {
        sender: newcomer.clone(),
        nodes: vec![],
    };
    assert!(
        server.merge(exchange(), false).await.is_err(),
        "live records were evicted"
    );
    for peer in &old {
        age(&server, &peer.id, FORGET_AFTER);
    }
    age(&server, &old[0].id, FORGET_AFTER + LIVE_FOR);
    server.forget_departed().await.unwrap();
    assert_eq!(
        server.known().len(),
        MAX_NODES,
        "isolation erased the directory"
    );
    server
        .merge(
            Exchange {
                sender: server.own.clone(),
                nodes: vec![newcomer.clone()],
            },
            false,
        )
        .await
        .unwrap();
    assert!(
        !server.known().contains(&newcomer),
        "gossip evicted a member"
    );
    server.merge(exchange(), false).await.unwrap();
    assert_eq!(server.known().len(), MAX_NODES);
    assert!(server.known().contains(&newcomer));
    assert!(!server.known().contains(&old[0]));
    assert_eq!(
        hints::load(temp.path())
            .iter()
            .map(|h| &h.node)
            .collect::<Vec<_>>(),
        vec![&old[0]]
    );
    let saved: Vec<Node> = read_json(&temp.path().join("peers.json")).unwrap();
    assert_eq!(saved, server.known()[1..]);
}

#[tokio::test]
async fn failed_capacity_recovery_keeps_old_members_and_returning_hint_until_durable() {
    let temp = tempfile::tempdir().unwrap();
    let server = state(temp.path());
    let old: Vec<_> = (0..MAX_NODES as u16 - 1)
        .map(|i| node(&format!("old_{i:02}"), 11000 + i))
        .collect();
    server
        .merge(
            Exchange {
                sender: server.own.clone(),
                nodes: old.clone(),
            },
            false,
        )
        .await
        .unwrap();
    for peer in &old {
        age(&server, &peer.id, FORGET_AFTER);
    }
    age(&server, &old[0].id, FORGET_AFTER + LIVE_FOR);
    let newcomer = node("newcomer", 12000);
    let exchange = || Exchange {
        sender: newcomer.clone(),
        nodes: vec![],
    };
    fs::create_dir(temp.path().join("reconnect-peers.json")).unwrap();
    assert!(server.merge(exchange(), true).await.is_err());
    assert_eq!(server.known()[1..], old);
    fs::remove_dir(temp.path().join("reconnect-peers.json")).unwrap();
    fs::rename(
        temp.path().join("peers.json"),
        temp.path().join("prior-peers.json"),
    )
    .unwrap();
    fs::create_dir(temp.path().join("peers.json")).unwrap();
    assert!(server.merge(exchange(), true).await.is_err());
    assert_eq!(server.known()[1..], old);
    assert_eq!(hints::load(temp.path())[0].node, old[0]);
    fs::remove_dir(temp.path().join("peers.json")).unwrap();
    fs::rename(
        temp.path().join("prior-peers.json"),
        temp.path().join("peers.json"),
    )
    .unwrap();
    server.merge(exchange(), true).await.unwrap();
    // A returning hinted member must remain recoverable if its member-file
    // write fails. Pruning this hint before that write would lose both routes.
    fs::rename(
        temp.path().join("peers.json"),
        temp.path().join("prior-peers.json"),
    )
    .unwrap();
    fs::create_dir(temp.path().join("peers.json")).unwrap();
    let returning = || Exchange {
        sender: old[0].clone(),
        nodes: vec![],
    };
    assert!(server.merge(returning(), true).await.is_err());
    assert!(hints::load(temp.path()).iter().any(|h| h.node == old[0]));
    fs::remove_dir(temp.path().join("peers.json")).unwrap();
    fs::rename(
        temp.path().join("prior-peers.json"),
        temp.path().join("peers.json"),
    )
    .unwrap();
    server.merge(returning(), true).await.unwrap();
    assert!(server.known().contains(&old[0]));
    assert!(!hints::load(temp.path()).iter().any(|h| h.node == old[0]));
}

#[tokio::test]
async fn stalled_membership_write_keeps_reads_and_relay_live_and_cancellation_preserves_order() {
    let temp = tempfile::tempdir().unwrap();
    let (target, _echo) = echo(b'E').await;
    let mut server = state(temp.path());
    server.own.address = target;
    server.bind = "127.0.0.1:0".parse().unwrap();
    let server = Arc::new(server);
    let source = "127.0.0.1".parse().unwrap();
    let lease = server
        .relay(
            source,
            RelayRequest {
                request: None,
                exit: "own".into(),
                lease: None,
            },
        )
        .await
        .unwrap();
    let first = node("first", 11000);
    let second = node("second", 11001);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writing = {
        let server = server.clone();
        let first = first.clone();
        tokio::spawn(async move {
            server
                .update_members(move |_, peers, _| {
                    peers.insert(
                        first.id.clone(),
                        Peer {
                            node: first,
                            seen: None,
                            heard: Instant::now(),
                        },
                    );
                    started_tx.send(()).unwrap();
                    // Controlled blocking persistence boundary; the current-thread
                    // runtime must still service reads, traffic, renewals and timers.
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(())
                })
                .await
        })
    };
    timeout(Duration::from_secs(2), started_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server.known(), vec![server.own.clone()]);
    assert_eq!(server.active(), vec![server.own.clone()]);
    let renewed = timeout(
        Duration::from_millis(250),
        server.relay(
            source,
            RelayRequest {
                request: None,
                exit: "own".into(),
                lease: Some(lease.lease.clone()),
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(renewed.address, lease.address);
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.connect(lease.address).await.unwrap();
    app.send(b"_persisting").await.unwrap();
    let mut received = [0; 32];
    let n = timeout(Duration::from_secs(1), app.recv(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..n], b"Epersisting");
    let next_write = {
        let server = server.clone();
        let second = second.clone();
        tokio::spawn(async move {
            server
                .merge(
                    Exchange {
                        sender: second,
                        nodes: vec![],
                    },
                    true,
                )
                .await
        })
    };
    writing.abort();
    assert!(writing.await.unwrap_err().is_cancelled());
    tokio::task::yield_now().await;
    assert!(
        !next_write.is_finished(),
        "cancelled request released its unfinished write"
    );
    release_tx.send(()).unwrap();
    timeout(Duration::from_secs(2), next_write)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let saved: Vec<Node> = read_json(&temp.path().join("peers.json")).unwrap();
    assert_eq!(saved, vec![first, second]);
    assert_eq!(server.known()[1..], saved);
}

#[tokio::test]
async fn failed_persistence_worker_releases_writer_without_publishing_state() {
    let temp = tempfile::tempdir().unwrap();
    let server = state(temp.path());
    let result = server
        .update_members(|_, _, _| panic!("injected persistence worker failure"))
        .await;
    assert!(result.is_err());
    assert_eq!(server.known(), vec![server.own.clone()]);
    let peer = node("peer", 11000);
    server
        .merge(
            Exchange {
                sender: peer.clone(),
                nodes: vec![],
            },
            true,
        )
        .await
        .unwrap();
    let saved: Vec<Node> = read_json(&temp.path().join("peers.json")).unwrap();
    assert_eq!(saved, vec![peer]);
}

#[tokio::test]
async fn cancelled_server_keeps_directory_exclusive_until_pending_write_finishes() {
    let temp = tempfile::tempdir().unwrap();
    let mut server = state(temp.path());
    let lock = fs::File::create(temp.path().join("server.lock")).unwrap();
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    server._directory_lock = Some(Arc::new(lock));
    let server = Arc::new(server);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writing = {
        let server = server.clone();
        tokio::spawn(async move {
            server
                .update_members(move |_, _, _| {
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(())
                })
                .await
        })
    };
    timeout(Duration::from_secs(2), started_rx)
        .await
        .unwrap()
        .unwrap();
    writing.abort();
    assert!(writing.await.unwrap_err().is_cancelled());
    drop(server);
    let next_owner = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(temp.path().join("server.lock"))
        .unwrap();
    assert!(fs2::FileExt::try_lock_exclusive(&next_owner).is_err());
    release_tx.send(()).unwrap();
    timeout(Duration::from_secs(2), async {
        while fs2::FileExt::try_lock_exclusive(&next_owner).is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn client_export_has_no_server_secrets_and_cannot_overwrite_another_identity() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("client");
    private_dir(&dir).unwrap();
    let cert = rcgen::generate_simple_self_signed(vec![NAME.into()]).unwrap();
    let mut client = ClientKey {
        version: 1,
        certificate: cert.cert.pem(),
        token: "a".repeat(64),
    };
    let certificate = client.certificate.clone();
    client.certificate = "not a certificate".into();
    assert!(install_client(&dir, &client).is_err());
    assert!(!dir.join("cert.pem").exists());
    assert!(!dir.join("token").exists());
    client.certificate = certificate;
    install_client(&dir, &client).unwrap();
    install_client(&dir, &client).unwrap();
    client.token = "b".repeat(64);
    assert!(install_client(&dir, &client).is_err());
    let json = serde_json::to_value(&client).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 3);
    assert!(serde_json::from_value::<ServerKey>(json).is_err());
}

#[tokio::test]
async fn relay_leases_are_source_bound_and_expire() {
    let temp = tempfile::tempdir().unwrap();
    let mut state = state(temp.path());
    state.bind = "127.0.0.1:0".parse().unwrap();
    let source = "127.0.0.1".parse().unwrap();
    let created = state
        .relay(
            source,
            RelayRequest {
                request: None,
                exit: "own".into(),
                lease: None,
            },
        )
        .await
        .unwrap();
    let request = || RelayRequest {
        request: None,
        exit: "own".into(),
        lease: Some(created.lease.clone()),
    };
    assert!(
        state
            .relay("127.0.0.2".parse().unwrap(), request())
            .await
            .is_err()
    );
    let renewed = state.relay(source, request()).await.unwrap();
    assert_eq!(renewed.address, created.address);
    state
        .leases
        .lock()
        .unwrap()
        .get_mut(&created.lease)
        .unwrap()
        .touched = Instant::now() - LEASE_FOR;
    assert!(state.relay(source, request()).await.is_err());
    assert!(state.leases.lock().unwrap().is_empty());
}

#[tokio::test]
async fn relay_traffic_keeps_a_lease_and_sources_are_capped() {
    let temp = tempfile::tempdir().unwrap();
    let mut state = state(temp.path());
    state.bind = "127.0.0.1:0".parse().unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    state.own.address = target.local_addr().unwrap();
    let source = "127.0.0.1".parse().unwrap();
    let request = || RelayRequest {
        request: None,
        exit: "own".into(),
        lease: None,
    };
    let created = state.relay(source, request()).await.unwrap();
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.send_to(b"in-use", created.address).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while state.leases.lock().unwrap()[&created.lease].forwarded() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("relay did not forward");
    state
        .leases
        .lock()
        .unwrap()
        .get_mut(&created.lease)
        .unwrap()
        .touched = Instant::now() - LEASE_FOR;
    reap(&mut state.leases.lock().unwrap());
    assert!(state.leases.lock().unwrap().contains_key(&created.lease));
    // The next packet takes the direct-send path. Lease liveness must count
    // successful forwards, rather than depending on queue admissions.
    app.send_to(b"still-in-use", created.address).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while state.leases.lock().unwrap()[&created.lease].forwarded() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("direct relay did not forward");
    state
        .leases
        .lock()
        .unwrap()
        .get_mut(&created.lease)
        .unwrap()
        .touched = Instant::now() - LEASE_FOR;
    reap(&mut state.leases.lock().unwrap());
    assert!(state.leases.lock().unwrap().contains_key(&created.lease));
    // Without new traffic or renewal the lease then expires normally.
    state
        .leases
        .lock()
        .unwrap()
        .get_mut(&created.lease)
        .unwrap()
        .touched = Instant::now() - LEASE_FOR;
    reap(&mut state.leases.lock().unwrap());
    assert!(state.leases.lock().unwrap().is_empty());

    for _ in 0..MAX_SOURCE_LEASES {
        state.relay(source, request()).await.unwrap();
    }
    assert!(state.relay(source, request()).await.is_err());
    state
        .relay("127.0.0.2".parse().unwrap(), request())
        .await
        .unwrap();
}

#[tokio::test]
async fn membership_outage_preserves_owned_lease_and_udp_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let mut state = state(temp.path());
    state.bind = "127.0.0.1:0".parse().unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let exit = Node {
        id: "exit".into(),
        address: target.local_addr().unwrap(),
        incarnation: 0,
    };
    state
        .merge(
            Exchange {
                sender: exit,
                nodes: vec![],
            },
            true,
        )
        .await
        .unwrap();
    let source = "127.0.0.1".parse().unwrap();
    let created = state
        .relay(
            source,
            RelayRequest {
                request: None,
                exit: "exit".into(),
                lease: None,
            },
        )
        .await
        .unwrap();
    state.peers.lock().unwrap().get_mut("exit").unwrap().seen = Some(Instant::now() - LIVE_FOR);
    assert_eq!(state.active(), vec![state.own.clone()]);
    assert!(
        state
            .relay(
                source,
                RelayRequest {
                    request: None,
                    exit: "exit".into(),
                    lease: None,
                }
            )
            .await
            .is_err(),
        "offline exits must not get new allocations"
    );
    let request = || RelayRequest {
        request: None,
        exit: "exit".into(),
        lease: Some(created.lease.clone()),
    };
    assert!(
        state
            .relay("127.0.0.2".parse().unwrap(), request())
            .await
            .is_err()
    );
    assert!(
        state
            .relay(
                source,
                RelayRequest {
                    request: None,
                    exit: "own".into(),
                    lease: Some(created.lease.clone()),
                }
            )
            .await
            .is_err(),
        "renewal must not redirect the target"
    );
    let renewed = state.relay(source, request()).await.unwrap();
    assert_eq!(renewed.address, created.address);
    assert_eq!(renewed.lease, created.lease);
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    timeout(Duration::from_secs(3), async {
        app.send_to(b"control-outage", renewed.address)
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let (n, peer) = target.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..n], b"control-outage");
        target.send_to(&buffer[..n], peer).await.unwrap();
        let (n, peer) = app.recv_from(&mut buffer).await.unwrap();
        assert_eq!(peer, renewed.address);
        assert_eq!(&buffer[..n], b"control-outage");
    })
    .await
    .expect("working UDP path was lost with membership liveness");
}

#[tokio::test]
async fn relay_port_exhaustion_and_reclamation_stay_within_configured_range() {
    let temp = tempfile::tempdir().unwrap();
    let mut state = state(temp.path());
    state.bind = "127.0.0.1:0".parse().unwrap();
    let port = address().port();
    state.relay_ports = Some(port.to_string().parse().unwrap());
    let source = "127.0.0.1".parse().unwrap();
    let request = || RelayRequest {
        request: None,
        exit: "own".into(),
        lease: None,
    };
    let allocated = state.relay(source, request()).await.unwrap();
    assert_eq!(allocated.address.port(), port);
    assert!(state.relay(source, request()).await.is_err());
    state.leases.lock().unwrap().clear();
    tokio::task::yield_now().await;
    let allocated = state.relay(source, request()).await.unwrap();
    assert_eq!(allocated.address.port(), port);
}

pub(super) async fn wait_for_response(app: &UdpSocket, marker: &[u8]) {
    timeout(Duration::from_secs(15), async {
        let mut bytes = [0; 128];
        loop {
            app.send(marker).await.unwrap();
            if let Ok(Ok(n)) = timeout(Duration::from_millis(100), app.recv(&mut bytes)).await
                && bytes[..n] == *marker
            {
                break;
            }
        }
    })
    .await
    .expect("UDP did not recover on the existing client socket");
}

#[tokio::test]
async fn unresponsive_entrances_do_not_delay_a_healthy_path() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let (target, _echo) = echo(b'E').await;
    let exit = address();
    let _server = server(root, "exit", exit, target, None).await;
    let identity =
        ClientIdentity::open(root.join("client"), &root.join("exit/client-key.json")).unwrap();
    wait_nodes(&identity, exit, &["exit"]).await;
    // Reserve both ports without replying, so the first two handshakes remain
    // pending until their eight-second deadline rather than failing with ICMP.
    let unavailable_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let unavailable_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let entrances = vec![
        unavailable_a.local_addr().unwrap(),
        unavailable_b.local_addr().unwrap(),
        exit,
    ];
    let (_tx, updates) = tokio::sync::watch::channel(entrances.clone());
    let listen = address();
    let mut fixed = policy();
    fixed.adaptive = false;
    fixed.quality_schedule = false;
    fixed.receiver_feedback = false;
    let client = Task(tokio::spawn(tunnel::client_with_mesh_exit(
        tunnel::ClientOptions {
            stream_connector: None,
            tcp_listen: None,
            proxy_listen: None,
            adaptive_fec_retention: false,
            rotate_source_port: false,
            listen,
            entrances,
            interfaces: vec![],
            path_binds: vec![],
            path_groups: vec![],
            datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            name: identity.name(),
            ca: identity.dir.join("cert.pem"),
            token: identity.dir.join("token"),
            policy: fixed,
            congestion: transport::Congestion::default(),
            stats: stats::Metrics::new("unresponsive-entrance-client"),
        },
        Some(updates),
        None,
        "exit".into(),
    )));
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.connect(listen).await.unwrap();
    timeout(
        Duration::from_secs(2),
        wait_for_response(&app, b"E-healthy-third-path"),
    )
    .await
    .expect("healthy path waited behind unresponsive handshakes");
    assert!(!client.0.is_finished());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn running_client_discovers_new_members_and_recovers_restarted_relay() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let (target, _echo) = echo(b'E').await;
    let a = address();
    let b = address();
    let _first = server(root, "exit", a, target, None).await;
    let identity =
        ClientIdentity::open(root.join("client"), &root.join("exit/client-key.json")).unwrap();
    wait_nodes(&identity, a, &["exit"]).await;
    let relay = server(
        root,
        "relay_b",
        b,
        target,
        Some((a, root.join("exit/server-key.json"))),
    )
    .await;
    let nodes = wait_nodes(&identity, b, &["exit", "relay_b"]).await;
    // Shorter maintenance cadence only in this bounded local correctness test.
    let (_, guard) = Entrances::start(&identity, nodes, "exit", 3, Duration::from_millis(100))
        .await
        .unwrap();
    let initial = wait_entrances(&guard, 2).await;
    assert_eq!(initial.len(), 2);
    let old_relay = initial[1];
    let mut updates = guard.updates();
    // Exclude the direct exit throughout, proving delivery uses a mesh relay.
    let (tx, rx) = tokio::sync::watch::channel(initial[1..].to_vec());
    let _bridge = Task(tokio::spawn(async move {
        while updates.changed().await.is_ok() {
            let relay_only = updates.borrow_and_update()[1..].to_vec();
            if !relay_only.is_empty() {
                tx.send_replace(relay_only);
            }
        }
    }));
    let metrics = stats::Metrics::new("recovering-client");
    let listen = address();
    let mut fixed = policy();
    fixed.adaptive = false;
    fixed.quality_schedule = false;
    fixed.receiver_feedback = false;
    let client = Task(tokio::spawn(tunnel::client_with_mesh_exit(
        tunnel::ClientOptions {
            stream_connector: None,
            tcp_listen: None,
            proxy_listen: None,
            adaptive_fec_retention: false,
            rotate_source_port: false,
            listen,
            entrances: initial[1..].to_vec(),
            interfaces: vec![],
            path_binds: vec![],
            path_groups: vec![],
            datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            name: identity.name(),
            ca: identity.dir.join("cert.pem"),
            token: identity.dir.join("token"),
            policy: fixed,
            congestion: transport::Congestion::default(),
            stats: metrics.clone(),
        },
        Some(rx),
        None,
        "exit".into(),
    )));
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.connect(listen).await.unwrap();
    wait_for_response(&app, b"E-before-restart").await;
    let before = metrics.snapshot(false, "test", None).unwrap();
    let session = before["stats"]["sessions"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();

    drop(relay);
    timeout(Duration::from_secs(8), async {
        while std::net::UdpSocket::bind(b).is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Keep the old port reserved so a new allocation cannot accidentally appear
    // to work by reusing the lost lease's socket address.
    let reserved = timeout(Duration::from_secs(8), async {
        loop {
            if let Ok(socket) = std::net::UdpSocket::bind(old_relay) {
                break socket;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("cancelled relay retained lease socket");
    let _restarted = server(root, "relay_b", b, target, None).await;
    let mut changed = guard.updates();
    timeout(Duration::from_secs(15), async {
        while changed.borrow_and_update().contains(&old_relay) {
            changed.changed().await.unwrap();
        }
    })
    .await
    .expect("client did not reallocate its relay lease");
    wait_for_response(&app, b"E-after-restart").await;
    assert!(!client.0.is_finished());

    // A running client includes a newly joined member without restarting.
    let c = address();
    let _third = server(
        root,
        "relay_c",
        c,
        target,
        Some((b, root.join("relay_b/server-key.json"))),
    )
    .await;
    timeout(Duration::from_secs(15), async {
        while changed.borrow_and_update().len() != 3 {
            changed.changed().await.unwrap();
        }
    })
    .await
    .expect("client did not discover the new cooperating member");
    timeout(Duration::from_secs(8), async {
        loop {
            let state = metrics.snapshot(false, "test", None).unwrap();
            let live = state["stats"]["paths"]
                .as_object()
                .unwrap()
                .values()
                .filter(|p| p["quinn"]["closed"] == false && p["authenticated"] == true)
                .count();
            if live == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("new entrance did not join the existing client session");
    wait_for_response(&app, b"E-new-peer").await;
    let after = metrics.snapshot(false, "test", None).unwrap();
    assert_eq!(
        after["stats"]["sessions"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        vec![&session]
    );
    assert_eq!(
        after["stats"]["paths"]
            .as_object()
            .unwrap()
            .values()
            .map(|p| p["total_generations"].as_u64().unwrap())
            .sum::<u64>(),
        3
    );
    drop(reserved);
}

// Shared only by local connection-admission tests.
pub(crate) fn connection_state(root: &Path, address: SocketAddr, capacity: usize) -> Arc<State> {
    let mut server = state(root);
    server.own.address = address;
    server.bind = address;
    server.client_auth = format!("Bearer {}", transport::token(&root.join("token")).unwrap());
    server.control_connections = Arc::new(Semaphore::new(capacity));
    Arc::new(server)
}

#[tokio::test]
async fn partition_heals_after_both_groups_forget_and_reload_hints() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    transport::initialize(&identity, NAME).unwrap();
    let nodes: Vec<_> = (0..4)
        .map(|i| Node {
            id: format!("node_{i}"),
            address: address(),
            incarnation: 0,
        })
        .collect();
    let mut states = Vec::new();
    for (i, own) in nodes.iter().enumerate() {
        let dir = temp.path().join(&own.id);
        fs::create_dir_all(&dir).unwrap();
        let mut server = state(&dir);
        server.own = own.clone();
        server.bind = own.address;
        for other in nodes.iter().filter(|n| n.id != own.id) {
            server
                .merge(
                    Exchange {
                        sender: other.clone(),
                        nodes: vec![],
                    },
                    true,
                )
                .await
                .unwrap();
        }
        // Model the elapsed partition without a ten-minute wall-clock sleep.
        for (j, other) in nodes.iter().enumerate() {
            if i / 2 != j / 2 {
                age(&server, &other.id, FORGET_AFTER + LIVE_FOR);
            }
        }
        server.forget_departed().await.unwrap();
        assert_eq!(server.known().len(), 2);
        let saved: Vec<Node> = read_json(&dir.join("peers.json")).unwrap();
        assert_eq!(saved.len(), 1);
        let saved_hints = hints::load(&dir);
        assert_eq!(saved_hints.len(), 2);
        // Reload from disk: recovery may not depend on leftover in-memory peers.
        *server.reconnect.lock().unwrap() = saved_hints;
        states.push(Arc::new(server));
    }
    let mut servers = Vec::new();
    for server in &states {
        let metrics = stats::Metrics::new("partition-server");
        let task = Task(tokio::spawn(tunnel::serve_with_mesh(
            tunnel::ServerOptions {
                tcp_target: None,
                stream_proxy: None,
                bind: server.own.address,
                cert: identity.join("cert.pem"),
                key: identity.join("key.pem"),
                token: identity.join("token"),
                target: Some(address()),
                proxy: None,
                max_rate: 10_000_000,
                congestion: transport::Congestion::default(),
                datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
                adaptive_fec_retention: false,
                stats: metrics.clone(),
            },
            transport::AckRequest::Unchanged,
            Some(server.clone()),
        )));
        timeout(Duration::from_secs(2), async {
            while !metrics.is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        servers.push(task);
    }
    let control = Control::new(&identity.join("cert.pem"), false).unwrap();
    let mut cursor = 0;
    let candidates = states[0].reconnect_candidates(&mut cursor).await;
    assert_eq!(
        candidates,
        nodes[2..].to_vec(),
        "partition lost reconnect hints"
    );
    let candidate = candidates[0].clone();
    states[0]
        .sync_peer(
            &control,
            candidate,
            serde_json::to_vec(&states[0].exchange()).unwrap(),
        )
        .await;
    // Only normal authenticated sync exchanges propagate the recovered bridge.
    for _ in 0..3 {
        for server in &states {
            for peer in server.known().into_iter().filter(|n| *n != server.own) {
                server
                    .sync_peer(
                        &control,
                        peer,
                        serde_json::to_vec(&server.exchange()).unwrap(),
                    )
                    .await;
            }
        }
    }
    for server in &states {
        assert_eq!(server.active(), nodes);
    }
}

#[tokio::test]
async fn reconnect_hints_are_bounded_deduplicated_and_saved_before_forgetting() {
    let temp = tempfile::tempdir().unwrap();
    let server = state(temp.path());
    let live = node("live", 10001);
    server
        .merge(
            Exchange {
                sender: live,
                nodes: vec![],
            },
            true,
        )
        .await
        .unwrap();
    for i in 0..MAX_NODES as u16 {
        let old = node(&format!("old_{i:02}"), 11000 + i);
        server
            .merge(
                Exchange {
                    sender: old.clone(),
                    nodes: vec![],
                },
                true,
            )
            .await
            .unwrap();
        age(&server, &old.id, FORGET_AFTER);
        server.forget_departed().await.unwrap();
    }
    assert_eq!(hints::load(temp.path()).len(), MAX_NODES);
    let departed = node("last", 12000);
    server
        .merge(
            Exchange {
                sender: departed.clone(),
                nodes: vec![],
            },
            true,
        )
        .await
        .unwrap();
    age(&server, &departed.id, FORGET_AFTER);
    fs::remove_file(temp.path().join("reconnect-peers.json")).unwrap();
    fs::create_dir(temp.path().join("reconnect-peers.json")).unwrap();
    assert!(server.forget_departed().await.is_err());
    assert!(
        server.known().contains(&departed),
        "failed hint persistence erased membership"
    );
}

#[tokio::test]
async fn reconnect_hints_rotate_in_batches_expire_and_leave_when_members_return() {
    let temp = tempfile::tempdir().unwrap();
    let server = state(temp.path());
    let now = hints::now_unix();
    let departed: Vec<_> = (0..6)
        .map(|i| node(&format!("gone_{i}"), 11000 + i))
        .collect();
    let expired = hints::Hint {
        node: node("retired", 12000),
        forgotten_unix: now - hints::HINT_TTL.as_secs(),
    };
    let saved = hints::add(&[expired], &departed, now);
    assert_eq!(saved.len(), departed.len(), "expired hint was kept");
    hints::save(temp.path(), &saved).unwrap();
    *server.reconnect.lock().unwrap() = hints::load(temp.path());

    // Each round probes a bounded batch and the rotation covers every hint.
    let mut cursor = 0;
    let first = server.reconnect_candidates(&mut cursor).await;
    let second = server.reconnect_candidates(&mut cursor).await;
    assert_eq!(first.len(), hints::RECONNECT_BATCH);
    let mut probed: Vec<_> = first.iter().chain(&second).map(|n| n.id.clone()).collect();
    probed.sort();
    probed.dedup();
    assert_eq!(probed.len(), departed.len());

    // A returning member's hint is removed on disk, and a newer address for
    // the same ID replaces the old hint.
    server
        .merge(
            Exchange {
                sender: departed[0].clone(),
                nodes: vec![],
            },
            true,
        )
        .await
        .unwrap();
    let remaining = server.reconnect_candidates(&mut cursor).await;
    assert!(!remaining.contains(&departed[0]));
    assert_eq!(hints::load(temp.path()).len(), departed.len() - 1);
    let mut moved = departed[1].clone();
    moved.address.set_port(13000);
    let replaced = hints::add(&hints::load(temp.path()), std::slice::from_ref(&moved), now);
    assert_eq!(replaced.len(), departed.len() - 1);
    assert_eq!(replaced[0].node, moved);
    assert!(!replaced.iter().any(|h| h.node == departed[1]));

    // Hints are optional: an unreadable file never blocks startup.
    fs::write(temp.path().join("reconnect-peers.json"), b"not json").unwrap();
    assert!(hints::load(temp.path()).is_empty());
    let old_format = serde_json::to_vec(&departed).unwrap();
    fs::write(temp.path().join("reconnect-peers.json"), old_format).unwrap();
    assert!(hints::load(temp.path()).is_empty());
}
