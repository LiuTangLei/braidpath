use super::protocol::*;
use super::*;
use crate::runtime::{mesh, stats, transport};
use bytes::Bytes;
use std::{net::SocketAddr, path::Path};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    time::timeout,
};

struct Task<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn address() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
async fn start_metered(
    root: &Path,
    id: &str,
    join: Option<SocketAddr>,
    allow_private: bool,
) -> (SocketAddr, Task<Result<()>>, stats::Metrics) {
    let at = address();
    let metrics = stats::Metrics::new("test-proxy");
    let task = Task(tokio::spawn(mesh::serve(mesh::ServerOptions {
        dir: root.join(id),
        id: id.into(),
        listen: at,
        advertise: at,
        relay_ports: None,
        target: None,
        proxy: Some(ServerConfig { allow_private }),
        join,
        join_key: join.map(|_| root.join("a/server-key.json")),
        rate: crate::runtime::MAX_RATE_BPS,
        stats: metrics.clone(),
    })));
    timeout(Duration::from_secs(5), async {
        while !metrics.is_ready() {
            assert!(!task.0.is_finished(), "mesh {id} exited before readiness");
            // A readiness probe must not busy-poll alongside the socket workers.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("mesh {id} did not become ready at {at}"));
    (at, task, metrics)
}
async fn start(
    root: &Path,
    id: &str,
    join: Option<SocketAddr>,
    allow_private: bool,
) -> (SocketAddr, Task<Result<()>>) {
    let (at, task, _) = start_metered(root, id, join, allow_private).await;
    (at, task)
}
fn identity(root: &Path, dir: &str) -> mesh::ClientIdentity {
    mesh::ClientIdentity::open(root.join(dir), &root.join("a/client-key.json")).unwrap()
}
async fn local_listener(pool: Arc<client::Pool>, exit: &str) -> (SocketAddr, Task<Result<()>>) {
    local_listener_capacity(pool, exit, 16).await
}
async fn local_listener_capacity(
    pool: Arc<client::Pool>,
    exit: &str,
    capacity: usize,
) -> (SocketAddr, Task<Result<()>>) {
    let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listen.local_addr().unwrap();
    let task = Task(tokio::spawn(client::listen(
        listen,
        pool,
        exit.to_owned(),
        Arc::new(Semaphore::new(capacity)),
    )));
    (at, task)
}
async fn socks(at: SocketAddr, command: u8, target: Address) -> (TcpStream, u8, Address) {
    let mut tcp = TcpStream::connect(at).await.unwrap();
    tcp.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    tcp.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, command, 0];
    target.encode(&mut request);
    tcp.write_all(&request).await.unwrap();
    let mut response = [0; 3];
    timeout(Duration::from_secs(10), tcp.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((response[0], response[2]), (5, 0));
    let bound = Address::read(&mut tcp).await.unwrap();
    (tcp, response[1], bound)
}
async fn echo() -> (SocketAddr, Task<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    let task = Task(tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut tcp,_) = accepted.unwrap();
                    tasks.spawn(async move {
                        let mut buffer = [0;8192];
                        loop {
                            match tcp.read(&mut buffer).await {
                                Ok(0) => { let _ = tcp.write_all(b"FIN").await; break; }
                                Ok(n) => { if tcp.write_all(&buffer[..n]).await.is_err() { break; } }
                                Err(_) => break,
                            }
                        }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }));
    (at, task)
}
fn node(id: &str, address: SocketAddr) -> mesh::Node {
    mesh::Node {
        id: id.into(),
        address,
        incarnation: 0,
    }
}

#[test]
fn proxy_accepts_ten_gigabit_ceiling_and_rejects_out_of_range_rates() {
    for (rate, accepted) in [
        (63_999, false),
        (64_000, true),
        (10_000_000_000, true),
        (10_000_000_001, false),
    ] {
        assert_eq!(
            Server::new(ServerConfig::default(), "a".repeat(64), "exit".into(), rate).is_ok(),
            accepted,
            "rate {rate}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn ten_gigabit_budget_retains_credit_between_millisecond_timer_ticks() {
    let rate = Rate::new(10_000_000_000);
    // Exhaust the bounded startup burst; idle time must not grow it further.
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(rate.delay(12_500_000).is_none());
    assert!(rate.delay(1).is_some());
    for _ in 0..10 {
        tokio::time::advance(Duration::from_millis(1)).await;
        // 10 Gbit/s supplies 1.25 MB per millisecond, including after the
        // initial burst. A fixed 128 KiB bucket silently loses this credit.
        assert!(rate.delay(1_250_000).is_none());
        assert!(rate.delay(1).is_some());
    }
}
async fn empty(identity: &mesh::ClientIdentity, at: SocketAddr) {
    timeout(Duration::from_secs(4), async {
        loop {
            let s = identity.status(at).await.unwrap().proxy.unwrap();
            if s.streams == 0
                && s.tcp_flows == 0
                && s.buffered_bytes == 0
                && s.rpc_streams == 0
                && s.udp_associations == 0
                && s.udp_destinations == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn each_exit_gets_one_port_in_selection_order_with_explicit_overrides() {
    let exits = ["b".into(), "a".into(), "c".into()];
    let base = "127.0.0.1:1080".parse().unwrap();
    let expected: Vec<Listener> = ["b=127.0.0.1:1080", "a=127.0.0.1:1081", "c=127.0.0.1:1082"]
        .into_iter()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(client::listener_plan(&exits, base, &[]).unwrap(), expected);
    let custom = "a=127.0.0.1:2080".parse().unwrap();
    let mut expected_custom = expected.clone();
    expected_custom[1] = custom;
    assert_eq!(
        client::listener_plan(&exits, base, &expected_custom[1..2]).unwrap(),
        expected_custom,
    );
    // Explicit mappings stay attached to IDs even when --exit order changes.
    let reversed = ["c".into(), "a".into(), "b".into()];
    assert_eq!(
        client::listener_plan(&reversed, base, &expected).unwrap(),
        expected.into_iter().rev().collect::<Vec<_>>(),
    );
    assert!(
        client::listener_plan(&exits, "127.0.0.1:0".parse().unwrap(), &[])
            .unwrap()
            .iter()
            .all(|listener| listener.address.port() == 0)
    );
    assert_eq!(
        client::listener_plan(&["a".into()], "[::1]:65535".parse().unwrap(), &[]).unwrap()[0]
            .address
            .to_string(),
        "[::1]:65535",
    );
}

#[test]
fn ambiguous_or_unusable_socks_listener_plans_are_rejected() {
    let exits = ["a".into(), "b".into()];
    let base = "127.0.0.1:1080".parse().unwrap();
    for overrides in [
        vec!["missing=127.0.0.1:2080"],
        vec!["a=127.0.0.1:2080", "a=127.0.0.1:2081"],
        vec!["a=127.0.0.1:1081"],
        vec!["a=127.0.0.1:2080", "b=127.0.0.1:2080"],
    ] {
        let overrides: Vec<Listener> = overrides.into_iter().map(|s| s.parse().unwrap()).collect();
        assert!(client::listener_plan(&exits, base, &overrides).is_err());
    }
    assert!(client::listener_plan(&[], base, &[]).is_err());
    assert!(client::listener_plan(&["a".into(), "a".into()], base, &[]).is_err());
    assert!(client::listener_plan(&exits, "0.0.0.0:1080".parse().unwrap(), &[]).is_err());
    assert!(client::listener_plan(&exits, "127.0.0.1:65535".parse().unwrap(), &[]).is_err());
}

#[tokio::test]
async fn separate_tcp_listeners_pin_exits_half_close_and_share_connections() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (a, _a, metrics_a) = start_metered(root, "a", None, true).await;
    let (b, _b) = start(root, "b", Some(a), true).await;
    let identity = identity(root, "client");
    let pool = client::Pool::new(
        identity.clone(),
        vec![node("a", a), node("b", b)],
        vec!["a".into(), "b".into()],
    )
    .unwrap();
    let (listen_a, _listen_a) = local_listener(pool.clone(), "a").await;
    let (listen_b, _listen_b) = local_listener(pool.clone(), "b").await;
    let (target, _echo) = echo().await;
    let (mut first, status, _) = socks(
        listen_a,
        TCP,
        Address::Domain("localhost".into(), target.port()),
    )
    .await;
    assert_eq!(status, 0);
    let (mut second, status, _) = socks(listen_b, TCP, Address::Ip(target)).await;
    assert_eq!(status, 0);
    for at in [a, b] {
        let s = identity.status(at).await.unwrap();
        assert!(
            s.capabilities
                .features
                .iter()
                .any(|f| f == "proxy-stream-v2")
        );
        assert_eq!(s.proxy.unwrap().streams, 1);
    }
    let (mut third, status, _) = socks(listen_a, TCP, Address::Ip(target)).await;
    assert_eq!(status, 0);
    assert_eq!(identity.status(a).await.unwrap().proxy.unwrap().streams, 2);
    // All TCP streams to this exit share one aggregate session across its paths.
    let snapshot = identity.status(a).await.unwrap().proxy.unwrap();
    assert!(snapshot.connections <= 2);
    let mut sessions = 0;
    metrics_a.state(|state| sessions = state.sessions.len());
    assert_eq!(sessions, 1);
    assert_eq!(snapshot.tcp_flows, 2);
    let payload: Vec<_> = (0..131_072).map(|i| (i % 251) as u8).collect();
    for tcp in [&mut first, &mut second, &mut third] {
        let (mut r, mut w) = tcp.split();
        let write = async {
            w.write_all(&payload).await.unwrap();
            w.shutdown().await.unwrap();
        };
        let read = async {
            let mut out = Vec::new();
            r.read_to_end(&mut out).await.unwrap();
            out
        };
        let (_, out) = timeout(Duration::from_secs(5), async { tokio::join!(write, read) })
            .await
            .unwrap();
        assert_eq!(&out[..payload.len()], payload.as_slice());
        assert_eq!(&out[payload.len()..], b"FIN");
    }
    empty(&identity, a).await;
    empty(&identity, b).await;
}

#[tokio::test]
async fn separate_udp_listeners_pin_exits_fragment_and_release_independently() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (at, _server) = start(root, "a", None, true).await;
    let (b, _server_b) = start(root, "b", Some(at), true).await;
    let identity = identity(root, "client");
    let pool = client::Pool::new(
        identity.clone(),
        vec![node("a", at), node("b", b)],
        vec!["a".into(), "b".into()],
    )
    .unwrap();
    let (listen, _listen) = local_listener(pool.clone(), "a").await;
    let (listen_b, _listen_b) = local_listener(pool, "b").await;
    let echo = udp_socket("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let target = echo.local_addr().unwrap();
    let _echo = Task(tokio::spawn(async move {
        let mut b = vec![0; 65_536];
        loop {
            let (n, p) = echo.recv_from(&mut b).await.unwrap();
            echo.send_to(&b[..n], p).await.unwrap();
        }
    }));
    let udp = udp_socket("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (tcp, status, bound) = socks(listen, UDP, Address::Ip(udp.local_addr().unwrap())).await;
    assert_eq!(status, 0);
    let Address::Ip(bound) = bound else { panic!() };
    let mut reply = vec![0; 65_536];
    for size in [0, 1472, 4096, 60_000] {
        let data: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
        let mut packet = vec![0, 0, 0];
        Address::Domain("localhost".into(), target.port()).encode(&mut packet);
        packet.extend(&data);
        udp.send_to(&packet, bound).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(4), udp.recv_from(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..3], &[0, 0, 0]);
        let (address, body) = protocol::packet(&reply[3..n]).await.unwrap();
        assert_eq!(address, Address::Ip(target));
        assert_eq!(body, data);
    }
    let rogue = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut p = vec![0, 0, 0];
    Address::Ip(target).encode(&mut p);
    p.extend(b"must not forward");
    rogue.send_to(&p, bound).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), rogue.recv_from(&mut reply))
            .await
            .is_err()
    );
    p[2] = 1;
    udp.send_to(&p, bound).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), udp.recv_from(&mut reply))
            .await
            .is_err()
    );
    let s = identity.status(at).await.unwrap().proxy.unwrap();
    assert_eq!(s.udp_associations, 1);
    assert_eq!(s.udp_destinations, 1);
    assert_eq!(
        identity.status(b).await.unwrap().proxy.unwrap().connections,
        0
    );
    let udp_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (tcp_b, status, bound_b) =
        socks(listen_b, UDP, Address::Ip(udp_b.local_addr().unwrap())).await;
    assert_eq!(status, 0);
    let Address::Ip(bound_b) = bound_b else {
        panic!()
    };
    assert_eq!(
        identity
            .status(b)
            .await
            .unwrap()
            .proxy
            .unwrap()
            .udp_associations,
        1
    );
    drop(tcp);
    empty(&identity, at).await;
    // Closing a's association must leave b's socket and exit usable.
    p[2] = 0;
    udp_b.send_to(&p, bound_b).await.unwrap();
    let (n, _) = timeout(Duration::from_secs(4), udp_b.recv_from(&mut reply))
        .await
        .unwrap()
        .unwrap();
    let (address, body) = protocol::packet(&reply[3..n]).await.unwrap();
    assert_eq!(address, Address::Ip(target));
    assert_eq!(body, b"must not forward");
    assert_eq!(
        identity
            .status(b)
            .await
            .unwrap()
            .proxy
            .unwrap()
            .udp_destinations,
        1
    );
    drop(tcp_b);
    empty(&identity, b).await;
}

#[tokio::test]
async fn wrong_token_wrong_exit_private_destination_and_unsupported_command_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (at, _server) = start(root, "a", None, false).await;
    let identity = identity(root, "client");
    let endpoint = transport::proxy_client(at, &identity.dir.join("cert.pem")).unwrap();
    for (token, exit) in [
        ("0".repeat(64), "a".to_owned()),
        (
            transport::token(&identity.dir.join("token")).unwrap(),
            "wrong".into(),
        ),
    ] {
        let conn = endpoint
            .connect(at, &identity.name())
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut auth = vec![1];
        auth.extend(token.as_bytes());
        auth.push(exit.len() as u8);
        auth.extend(exit.as_bytes());
        send.write_all(&auth).await.unwrap();
        send.finish().unwrap();
        assert!(
            timeout(Duration::from_secs(2), recv.read_to_end(1))
                .await
                .unwrap()
                .is_err()
        );
    }
    let pool = client::Pool::new(identity.clone(), vec![node("a", at)], vec!["a".into()]).unwrap();
    let (listen, _listen) = local_listener(pool, "a").await;
    let (target, _echo) = echo().await;
    for address in [
        Address::Ip(target),
        Address::Domain("localhost".into(), target.port()),
    ] {
        let (_, status, _) = socks(listen, TCP, address).await;
        assert_eq!(status, 2);
    }
    let (_, status, _) = socks(listen, 2, Address::Ip(target)).await;
    assert_eq!(status, 7);
    empty(&identity, at).await;
}

#[tokio::test]
async fn tcp_connect_failure_is_reported_before_socks_success() {
    let root = tempfile::tempdir().unwrap();
    let (at, _server) = start(root.path(), "a", None, true).await;
    let identity = identity(root.path(), "connect-failure-client");
    let pool = client::Pool::new(identity.clone(), vec![node("a", at)], vec!["a".into()]).unwrap();
    let (listen, _listener) = local_listener(pool.clone(), "a").await;
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = unused.local_addr().unwrap();
    drop(unused);
    let (mut tcp, status, bound) = timeout(
        Duration::from_secs(8),
        socks(listen, TCP, Address::Ip(target)),
    )
    .await
    .unwrap();
    assert_eq!(
        status, 5,
        "a refused target must not produce a successful SOCKS reply"
    );
    assert_eq!(bound.port(), 0);
    assert_eq!(
        timeout(Duration::from_secs(1), tcp.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    empty(&identity, at).await;
    pool.shutdown().await;
    assert_eq!(pool.stream_budget.snapshot(), (0, 0));
}

#[tokio::test]
async fn aggregate_proxy_rejects_bad_credentials_and_wrong_exit_before_target_connect() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (at, _server) = start(root, "a", None, true).await;
    let valid = identity(root, "valid-client");
    let mut key: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("a/client-key.json")).unwrap()).unwrap();
    key["token"] = serde_json::Value::String("0".repeat(64));
    let bad_key = root.join("bad-client-key.json");
    std::fs::write(&bad_key, serde_json::to_vec(&key).unwrap()).unwrap();
    let bad = mesh::ClientIdentity::open(root.join("bad-client"), &bad_key).unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    for (client_identity, exit) in [(bad, "a"), (valid.clone(), "wrong")] {
        let pool =
            client::Pool::new(client_identity, vec![node(exit, at)], vec![exit.into()]).unwrap();
        let (listen, listener) = local_listener(pool.clone(), exit).await;
        let (_, status, _) = timeout(
            Duration::from_secs(8),
            socks(listen, TCP, Address::Ip(target_address)),
        )
        .await
        .unwrap();
        assert_ne!(status, 0);
        assert!(
            timeout(Duration::from_millis(50), target.accept())
                .await
                .is_err()
        );
        drop(listener);
        pool.shutdown().await;
        assert_eq!(pool.stream_budget.snapshot(), (0, 0));
    }
    empty(&valid, at).await;
}

#[tokio::test]
async fn aggregate_proxy_requires_the_advertised_stream_capability() {
    let root = tempfile::tempdir().unwrap();
    let at = address();
    let metrics = stats::Metrics::new("no-proxy-capability");
    let _server = Task(tokio::spawn(mesh::serve(mesh::ServerOptions {
        dir: root.path().join("a"),
        id: "a".into(),
        listen: at,
        advertise: at,
        relay_ports: None,
        target: Some(address()),
        proxy: None,
        join: None,
        join_key: None,
        rate: crate::runtime::MAX_RATE_BPS,
        stats: metrics.clone(),
    })));
    timeout(Duration::from_secs(5), async {
        while !metrics.is_ready() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    let identity = identity(root.path(), "capability-client");
    let status = identity.status(at).await.unwrap();
    assert!(
        !status
            .capabilities
            .features
            .iter()
            .any(|f| f == "proxy-stream-v2")
    );
    let pool = client::Pool::new(identity, vec![node("a", at)], vec!["a".into()]).unwrap();
    let (listen, _listener) = local_listener(pool.clone(), "a").await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_, code, _) = timeout(
        Duration::from_secs(8),
        socks(listen, TCP, Address::Ip(target.local_addr().unwrap())),
    )
    .await
    .unwrap();
    assert_ne!(code, 0);
    assert!(
        timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
    pool.shutdown().await;
    assert_eq!(pool.stream_budget.snapshot(), (0, 0));
}

#[test]
fn address_policy_checks_mapped_and_private_ranges() {
    for ip in [
        "127.0.0.1",
        "10.1.1.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.1.1",
        "198.18.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "fe80::1",
        "fd00::1",
    ] {
        assert!(!permitted(ip.parse().unwrap(), false), "{ip}");
    }
    for ip in ["1.1.1.1", "2606:4700:4700::1111"] {
        assert!(permitted(ip.parse().unwrap(), false));
    }
    for ip in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "ff02::1"] {
        assert!(!permitted(ip.parse().unwrap(), true));
    }
}

#[test]
fn udp_reassembly_is_bounded_out_of_order_and_does_not_extend_deadlines() {
    fn frame(id: u64, total: u32, offset: u32, data: &[u8]) -> Bytes {
        let mut b = Vec::new();
        b.extend(id.to_be_bytes());
        b.extend(total.to_be_bytes());
        b.extend(offset.to_be_bytes());
        b.extend(data);
        b.into()
    }
    let now = Instant::now();
    let mut r = Reassembly::default();
    assert!(r.receive(frame(1, 1002, 1000, &[8, 9]), now).is_none());
    let out = r.receive(frame(1, 1002, 0, &[7; 1000]), now).unwrap();
    assert_eq!(&out[1000..], &[8, 9]);
    assert!(r.receive(frame(1, 1002, 0, &[7; 1000]), now).is_none());
    assert!(r.receive(frame(1, 1002, 1000, &[8, 9]), now).is_none());
    for id in 10..14 {
        assert!(r.receive(frame(id, 1001, 0, &[1; 1000]), now).is_none());
    }
    assert!(r.receive(frame(14, 1001, 0, &[1; 1000]), now).is_none());
    assert!(r.receive(frame(14, 1001, 1000, &[2]), now).is_none());
    assert!(
        r.receive(frame(10, 1001, 0, &[1; 1000]), now + Duration::from_secs(1))
            .is_none()
    );
    assert!(
        r.receive(frame(10, 1001, 1000, &[2]), now + Duration::from_secs(3))
            .is_none()
    );
    assert!(
        r.receive(
            frame(20, u32::MAX, 0, &[1; 1000]),
            now + Duration::from_secs(3)
        )
        .is_none()
    );
    assert!(
        r.receive(frame(10, 1001, 0, &[1; 1000]), now + Duration::from_secs(3))
            .is_none()
    );
}

#[tokio::test]
async fn failed_exit_never_falls_back_and_other_listener_keeps_serving() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (a, server_a) = start(root, "a", None, true).await;
    let (b, _server_b) = start(root, "b", Some(a), true).await;
    let identity = identity(root, "client");
    let pool = client::Pool::new(
        identity.clone(),
        vec![node("a", a), node("b", b)],
        vec!["a".into(), "b".into()],
    )
    .unwrap();
    let (listen_a, _listener_a) = local_listener(pool.clone(), "a").await;
    let (listen_b, _listener_b) = local_listener(pool, "b").await;
    let (target, _echo) = echo().await;
    let (mut first, status, _) = socks(listen_a, TCP, Address::Ip(target)).await;
    assert_eq!(status, 0);
    let (mut second, status, _) = socks(listen_b, TCP, Address::Ip(target)).await;
    assert_eq!(status, 0);
    drop(server_a);
    timeout(Duration::from_secs(3), async {
        let mut b = [0];
        let result = first.read(&mut b).await;
        assert!(result.is_err() || result.unwrap() == 0);
    })
    .await
    .unwrap();
    // Both TCP and UDP on a must fail, even though b is still healthy.
    for command in [TCP, UDP] {
        let (_, status, _) = socks(listen_a, command, Address::Ip(target)).await;
        assert_ne!(status, 0);
    }
    assert_eq!(identity.status(b).await.unwrap().proxy.unwrap().streams, 1);
    let (mut third, status, _) = socks(listen_b, TCP, Address::Ip(target)).await;
    assert_eq!(status, 0);
    for tcp in [&mut second, &mut third] {
        tcp.write_all(b"alive").await.unwrap();
        let mut out = [0; 5];
        timeout(Duration::from_secs(2), tcp.read_exact(&mut out))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&out, b"alive");
        tcp.shutdown().await.unwrap();
        let mut fin = Vec::new();
        tcp.read_to_end(&mut fin).await.unwrap();
        assert_eq!(fin, b"FIN");
    }
    empty(&identity, b).await;
}

#[tokio::test(start_paused = true)]
async fn host_rate_budget_is_shared_and_cancellation_does_not_reserve_future_bytes() {
    let rate = Arc::new(Rate::new(64_000));
    assert!(rate.delay(131_072).is_none());
    let copy = rate.clone();
    let task = tokio::spawn(async move {
        copy.acquire(8_000).await;
    });
    tokio::task::yield_now().await;
    task.abort();
    let _ = task.await;
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(rate.delay(8_000).is_none());
    assert!(rate.delay(1).is_some());
}

#[tokio::test]
async fn association_dispatch_is_bounded_and_released_with_its_owner() {
    let router = Arc::new(Router::default());
    let mut registrations = Vec::new();
    for id in 0..MAX_ASSOCIATIONS as u64 {
        registrations.push(router.register(id).unwrap());
    }
    assert!(router.register(MAX_ASSOCIATIONS as u64).is_err());
    assert!(router.register(0).is_err());
    let mut data = 1u64.to_be_bytes().to_vec();
    data.extend(b"only association one");
    router.dispatch(data.into());
    assert_eq!(
        registrations[1].recv.recv().await.unwrap(),
        &b"only association one"[..]
    );
    assert!(registrations[0].recv.try_recv().is_err());
    drop(registrations);
    assert!(router.register(0).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_tcp_connection_uses_multiple_servers_and_survives_a_relay_stopping() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (a, _a, _) = start_metered(root, "a", None, true).await;
    let (b, relay_b, _mb) = start_metered(root, "b", Some(a), true).await;
    let (c, _c, _mc) = start_metered(root, "c", Some(a), true).await;
    let identity = identity(root, "bond-client");
    let pool = client::Pool::new(
        identity.clone(),
        vec![node("a", a), node("b", b), node("c", c)],
        vec!["a".into()],
    )
    .unwrap();
    timeout(Duration::from_secs(5), async {
        while pool.test_addresses("a").await.len() < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (listen, _listener) = local_listener(pool.clone(), "a").await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = target.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let payload: Vec<u8> = (0..32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let (go, wait) = tokio::sync::oneshot::channel();
    let target_task = Task(tokio::spawn(async move {
        let (mut tcp, _) = target.accept().await.unwrap();
        count.fetch_add(1, Ordering::Relaxed);
        // Send the second half only after a relay has stopped. Both halves
        // belong to the same target TCP socket and must survive path repair.
        let (head, tail) = payload.split_at(payload.len() / 2);
        tcp.write_all(head).await.unwrap();
        wait.await.unwrap();
        tcp.write_all(tail).await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut upload = Vec::new();
        tcp.read_to_end(&mut upload).await.unwrap();
        assert_eq!(upload, b"single-flow-upload");
        // Repair and path replacement must keep the original target socket.
        assert!(
            timeout(Duration::from_millis(10), target.accept())
                .await
                .is_err()
        );
    }));
    let (mut tcp, status, _) = socks(listen, TCP, Address::Ip(at)).await;
    assert_eq!(status, 0);
    let transfer = tokio::spawn(async move {
        tcp.write_all(b"single-flow-upload").await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut received = Vec::new();
        tcp.read_to_end(&mut received).await.unwrap();
        received
    });
    timeout(Duration::from_secs(5), async {
        loop {
            let bs = identity.status(b).await.unwrap();
            let cs = identity.status(c).await.unwrap();
            if bs.active_relay_return_bytes > 65536 && cs.active_relay_return_bytes > 65536 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(relay_b);
    go.send(()).unwrap();
    let received = timeout(Duration::from_secs(12), transfer)
        .await
        .expect("relay outage reset the logical TCP flow")
        .unwrap();
    assert!(
        received == expected,
        "payload differs: {} vs {} bytes",
        received.len(),
        expected.len()
    );
    assert_eq!(accepted.load(Ordering::Relaxed), 1);
    let relayed = identity.status(c).await.unwrap();
    assert!(relayed.active_relay_return_bytes > 65536);
    assert!(relayed.active_relay_forward_bytes > 0);
    empty(&identity, a).await;
    drop(target_task);
    drop(pool);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aggregate_client_reset_reclaims_tcp_and_payload_resources() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (a, _server) = start(root, "a", None, true).await;
    let identity = identity(root, "reset-client");
    let pool = client::Pool::new(identity.clone(), vec![node("a", a)], vec!["a".into()]).unwrap();
    let (listen, _listener) = local_listener(pool, "a").await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = target.local_addr().unwrap();
    let closed = Arc::new(AtomicBool::new(false));
    let observed = closed.clone();
    let _target = Task(tokio::spawn(async move {
        let (mut tcp, _) = target.accept().await.unwrap();
        let data = vec![42; 65536];
        loop {
            if tcp.write_all(&data).await.is_err() {
                break;
            }
        }
        observed.store(true, Ordering::Release);
    }));
    let (tcp, status, _) = socks(listen, TCP, Address::Ip(at)).await;
    assert_eq!(status, 0);
    timeout(Duration::from_secs(3), async {
        loop {
            let s = identity.status(a).await.unwrap().proxy.unwrap();
            if s.buffered_bytes > 0 {
                assert!(s.buffered_bytes <= 64 * 1024 * 1024);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    socket2::SockRef::from(&tcp)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(tcp);
    empty(&identity, a).await;
    timeout(Duration::from_secs(3), async {
        while !closed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_blackhole_is_quarantined_and_rejoins_the_same_tcp_flow_after_recovery() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (a, _server, server_metrics) = start_metered(root, "a", None, true).await;
    let identity = identity(root, "blackhole-client");
    let pool = client::Pool::new(identity.clone(), vec![node("a", a)], vec!["a".into()]).unwrap();
    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let via = front.local_addr().unwrap();
    let back = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    back.connect(a).await.unwrap();
    let blocked = Arc::new(AtomicBool::new(false));
    let packets = Arc::new(AtomicU64::new(0));
    let (fault, count) = (blocked.clone(), packets.clone());
    let _relay = Task(tokio::spawn(async move {
        let (mut upstream, mut downstream) = (vec![0; 65536], vec![0; 65536]);
        let mut peer = None;
        loop {
            tokio::select! {
                r=front.recv_from(&mut upstream)=>{let(n,from)=r.unwrap();peer=Some(from);if !fault.load(Ordering::Acquire){back.send(&upstream[..n]).await.unwrap();count.fetch_add(n as u64,Ordering::Relaxed);}},
                r=back.recv(&mut downstream)=>{let n=r.unwrap();if !fault.load(Ordering::Acquire)&&let Some(peer)=peer{front.send_to(&downstream[..n],peer).await.unwrap();count.fetch_add(n as u64,Ordering::Relaxed);}}
            }
        }
    }));
    pool.test_set_routes("a", vec![a, via]);
    assert!(
        pool.test_path_failed("a", via),
        "an unpublished path is not ready"
    );
    pool.prepare_stream("a").await.unwrap();
    timeout(Duration::from_secs(3), async {
        while pool.test_path_failed("a", via) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both paths must be authenticated before the fault");

    let (listen, _listener) = local_listener(pool.clone(), "a").await;
    let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = source.local_addr().unwrap();
    let (go, wait) = tokio::sync::oneshot::channel();
    let _source = Task(tokio::spawn(async move {
        let (mut tcp, _) = source.accept().await.unwrap();
        // A backlog larger than the record window spreads ranges over both
        // paths, so the blackholed one holds outstanding work when it fails.
        let backlog = vec![71; 32 * 1024 * 1024];
        tcp.write_all(&backlog).await.unwrap();
        wait.await.unwrap();
        // After probe recovery, a fresh backlog must use the restored path.
        tcp.write_all(&backlog).await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut upload = Vec::new();
        tcp.read_to_end(&mut upload).await.unwrap();
        assert_eq!(upload, b"one-connection");
    }));
    let (mut tcp, status, _) = socks(listen, TCP, Address::Ip(at)).await;
    assert_eq!(status, 0);
    let transfer = tokio::spawn(async move {
        tcp.write_all(b"one-connection").await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut received = Vec::new();
        tcp.read_to_end(&mut received).await.unwrap();
        received
    });
    timeout(Duration::from_secs(3), async {
        while packets.load(Ordering::Relaxed) < 65536 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    blocked.store(true, Ordering::Release);
    timeout(Duration::from_secs(6), async {
        while !pool.test_path_failed("a", via) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("blackholed route continued receiving new data work");
    blocked.store(false, Ordering::Release);
    timeout(Duration::from_secs(10), async {
        while pool.test_path_failed("a", via) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("recovered path did not pass its isolated liveness probe");
    let before = packets.load(Ordering::Relaxed);
    go.send(()).unwrap();
    let received = timeout(Duration::from_secs(8), transfer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.len(), 64 * 1024 * 1024);
    assert!(received.iter().all(|b| *b == 71));
    assert!(
        packets.load(Ordering::Relaxed) > before + 65536,
        "restored path never resumed carrying payload; server paths={}",
        server_metrics
            .snapshot(false, "recovery-diagnostic", None)
            .unwrap()["stats"]["paths"]
    );
    empty(&identity, a).await;
}

#[tokio::test]
async fn aggregate_shutdown_releases_optional_leases_and_flow_admission_credit() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (a, _a) = start(root, "a", None, true).await;
    let (b, _b) = start(root, "b", Some(a), true).await;
    let identity = identity(root, "shutdown-client");
    let pool = client::Pool::new(
        identity.clone(),
        vec![node("a", a), node("b", b)],
        vec!["a".into()],
    )
    .unwrap();
    timeout(Duration::from_secs(3), async {
        while pool.test_addresses("a").await.len() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(identity.status(b).await.unwrap().leases, 1);
    let (listen, listener) = local_listener(pool.clone(), "a").await;
    let (target, _echo) = echo().await;
    let (_tcp, status, _) = socks(listen, TCP, Address::Ip(target)).await;
    assert_eq!(status, 0);
    drop(listener);
    timeout(Duration::from_secs(4), pool.shutdown())
        .await
        .expect("normal shutdown left flow owners or leases pending");
    empty(&identity, a).await;
    assert_eq!(identity.status(b).await.unwrap().leases, 0);
    assert_eq!(pool.stream_budget.snapshot(), (0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_stream_bytes_are_charged_and_reset_reclaims_them_with_downlink_blocked() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let root = tempfile::tempdir().unwrap();
    let (at, _server) = start(root.path(), "a", None, true).await;
    let identity = identity(root.path(), "queued-client");
    let pool = client::Pool::new(identity.clone(), vec![node("a", at)], vec!["a".into()]).unwrap();
    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let via = front.local_addr().unwrap();
    let back = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    back.connect(at).await.unwrap();
    let blocked = Arc::new(AtomicBool::new(false));
    let gate = blocked.clone();
    let _relay = Task(tokio::spawn(async move {
        let (mut up, mut down) = (vec![0; 65536], vec![0; 65536]);
        let mut peer = None;
        loop {
            tokio::select! {
                r = front.recv_from(&mut up) => {
                    let (n, from) = r.unwrap(); peer = Some(from);
                    back.send(&up[..n]).await.unwrap();
                }
                r = back.recv(&mut down) => {
                    let n = r.unwrap();
                    if !gate.load(Ordering::Acquire) && let Some(peer) = peer {
                        front.send_to(&down[..n], peer).await.unwrap();
                    }
                }
            }
        }
    }));
    pool.test_set_routes("a", vec![via]);
    let (listen, _listener) = local_listener(pool.clone(), "a").await;
    let (target, _echo) = echo().await;
    let (mut tcp, status, _) = socks(listen, TCP, Address::Ip(target)).await;
    assert_eq!(status, 0);
    // Keep the upstream usable so cancellation can reach the exit. No received
    // data or ACK can get back: retained bytes must remain charged throughout.
    blocked.store(true, Ordering::Release);
    timeout(Duration::from_secs(2), tcp.write_all(&vec![83; 128 * 1024]))
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = identity.status(at).await.unwrap().proxy.unwrap();
            if snapshot.buffered_bytes > 0 {
                assert_eq!(snapshot.tcp_flows, 1);
                assert!(snapshot.buffered_bytes <= 64 * 1024 * 1024);
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("stream bytes were retained without appearing in the host budget");
    socket2::SockRef::from(&tcp)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(tcp);
    // Local ownership must be reclaimed even with no ACK path. An exhausted
    // QUIC congestion window cannot promise delivery of RESET until that
    // path recovers, so assert peer reclamation after restoring delivery.
    timeout(Duration::from_secs(4), async {
        while pool.stream_budget.snapshot() != (0, 0) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancelled local flow kept its stream or payload credit");
    blocked.store(false, Ordering::Release);
    empty(&identity, at).await;
    pool.shutdown().await;
    empty(&identity, at).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_paths_do_not_open_targets_and_cold_relays_do_not_hold_downloads() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (at, _server) = start(root, "a", None, true).await;
    let identity = identity(root, "prepare-client");
    let pool = client::Pool::new(identity.clone(), vec![node("a", at)], vec!["a".into()]).unwrap();
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cold = blackhole.local_addr().unwrap();
    pool.test_set_routes("a", vec![at, cold]);
    pool.prepare_paths("a").await.unwrap();
    timeout(Duration::from_secs(2), async {
        while pool.transport_snapshot("a").len() != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    empty(&identity, at).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let bytes = 4 * 1024 * 1024;
    let send = Task(tokio::spawn(async move {
        let (mut tcp, _) = target.accept().await.unwrap();
        tcp.write_all(&vec![37; bytes]).await.unwrap();
        tcp.shutdown().await.unwrap();
    }));
    let (listen, listener) = local_listener(pool.clone(), "a").await;
    // A cold path's four-second connect timeout must not become a data stall.
    timeout(Duration::from_secs(2), async {
        let (mut tcp, status, _) = socks(listen, TCP, Address::Ip(address)).await;
        assert_eq!(status, 0);
        let mut received = Vec::new();
        tcp.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, vec![37; bytes]);
        tcp.shutdown().await.unwrap();
    })
    .await
    .expect("download waited for an unready optional path");
    pool.test_set_routes("a", vec![at]);
    assert_eq!(pool.test_addresses("a").await, [at]);
    drop(listener);
    drop(send);
    pool.shutdown().await;
    empty(&identity, at).await;
    assert!(pool.transport_snapshot("a").is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_proxy_relay_is_reported_and_replaced_by_another_server() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (a, _a) = start(root, "a", None, true).await;
    let (b, relay_b) = start(root, "b", Some(a), true).await;
    let (c, relay_c) = start(root, "c", Some(a), true).await;
    let (d, relay_d) = start(root, "d", Some(a), true).await;
    let identity = identity(root, "health-client");
    let pool = client::Pool::new(
        identity.clone(),
        vec![node("a", a), node("b", b), node("c", c), node("d", d)],
        vec!["a".into()],
    )
    .unwrap();
    pool.set_path_limit(3);
    let original = timeout(Duration::from_secs(5), async {
        loop {
            let routes = pool.test_addresses("a").await;
            if routes.len() == 3 {
                break routes;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    pool.prepare_stream("a").await.unwrap();
    timeout(Duration::from_secs(3), async {
        while pool.transport_snapshot("a").len() != 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("aggregate paths did not authenticate");
    let (listen, _listener) = local_listener(pool.clone(), "a").await;
    let (target, _echo) = echo().await;
    let (mut tcp, status, _) = socks(listen, TCP, Address::Ip(target)).await;
    assert_eq!(status, 0);
    let mut relays = [(b, Some(relay_b)), (c, Some(relay_c)), (d, Some(relay_d))];
    let mut stopped = false;
    for (address, task) in &mut relays {
        if identity.status(*address).await.unwrap().leases > 0 {
            drop(task.take());
            stopped = true;
            break;
        }
    }
    assert!(stopped, "fault injection did not stop an allocated relay");
    timeout(Duration::from_secs(5), async {
        loop {
            // Exercise the same TCP socket while the runtime observes a real
            // relay shutdown and the selector replaces its lease.
            tcp.write_all(&[71; 1024]).await.unwrap();
            let mut reply = [0; 1024];
            tcp.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [71; 1024]);
            pool.report_health();
            let routes = pool.test_addresses("a").await;
            if routes.len() == 3
                && routes.iter().any(|p| !original.contains(p))
                && pool
                    .transport_snapshot("a")
                    .keys()
                    .all(|p| routes.contains(p))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("failed aggregate relay was never replaced");
    tcp.shutdown().await.unwrap();
    let mut end = Vec::new();
    tcp.read_to_end(&mut end).await.unwrap();
    assert_eq!(end, b"FIN");
    empty(&identity, a).await;
    pool.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_tcp_upload_repairs_loss_without_duplicating_target_bytes() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (a, _a) = start(root, "a", None, true).await;
    let (b, relay_b) = start(root, "b", Some(a), true).await;
    let (c, _c) = start(root, "c", Some(a), true).await;
    let identity = identity(root, "upload-replay");
    let pool = client::Pool::new(
        identity.clone(),
        vec![node("a", a), node("b", b), node("c", c)],
        vec!["a".into()],
    )
    .unwrap();
    timeout(Duration::from_secs(4), async {
        while pool.test_addresses("a").await.len() < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    pool.prepare_stream("a").await.unwrap();
    timeout(Duration::from_secs(3), async {
        while pool.transport_snapshot("a").len() != 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("upload paths did not authenticate before fault injection");
    let (listen, listener) = local_listener(pool.clone(), "a").await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = target.local_addr().unwrap();
    let payload: Vec<_> = (0..16 * 1024 * 1024).map(|i| (i % 239) as u8).collect();
    let expected = payload.clone();
    let target_task = tokio::spawn(async move {
        let (mut tcp, _) = target.accept().await.unwrap();
        let mut received = Vec::new();
        tcp.read_to_end(&mut received).await.unwrap();
        assert!(
            received == expected,
            "payload differs: {} vs {} bytes",
            received.len(),
            expected.len()
        );
        tcp.write_all(b"complete").await.unwrap();
        tcp.shutdown().await.unwrap();
    });
    let (mut tcp, status, _) = socks(listen, TCP, Address::Ip(at)).await;
    assert_eq!(status, 0);
    let transfer = tokio::spawn(async move {
        tcp.write_all(&payload).await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut response = Vec::new();
        tcp.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"complete");
    });
    timeout(Duration::from_secs(4), async {
        while identity.status(b).await.unwrap().active_relay_forward_bytes < 65536 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    drop(relay_b);
    timeout(Duration::from_secs(12), transfer)
        .await
        .expect("upload did not move unacknowledged records to surviving paths")
        .unwrap();
    target_task.await.unwrap();
    empty(&identity, a).await;
    drop(listener);
    pool.shutdown().await;
    assert_eq!(identity.status(c).await.unwrap().leases, 0);
}

/// Manual WAN diagnosis only. Private topology/keys and the byte budget are
/// supplied in an ignored case file; ordinary tests never generate WAN traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an explicit bounded external fixture case"]
async fn single_tcp_external_route_diagnostic() {
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Case {
        label: String,
        connection_key: std::path::PathBuf,
        bootstrap: SocketAddr,
        exit: String,
        routes: Vec<SocketAddr>,
        target: SocketAddr,
        token: String,
        direction: String,
        bytes: usize,
        sha256: String,
    }
    let file = std::env::var("BRAIDPATH_WAN_CASE").expect("explicit case file required");
    let case: Case = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
    assert!(!case.routes.is_empty() && case.routes.len() <= 8);
    assert!(case.bytes > 0 && case.bytes <= 128 * 1024 * 1024);
    assert!(["upload", "download"].contains(&case.direction.as_str()));
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,braidpath::runtime::proxy=debug")
        .try_init();
    timeout(Duration::from_secs(45), async {
        let root = tempfile::tempdir().unwrap();
        let identity = mesh::ClientIdentity::open(root.path().join("client"), &case.connection_key).unwrap();
        let nodes = identity.discover(case.bootstrap).await.unwrap();
        let pool = client::Pool::new(identity.clone(), nodes, vec![case.exit.clone()]).unwrap();
        pool.test_set_routes(&case.exit, case.routes);
        let (listen, listener) = local_listener(pool.clone(), &case.exit).await;
        let (mut tcp, status, _) = socks(listen, TCP, Address::Ip(case.target)).await;
        assert_eq!(status, 0);
        let request = serde_json::json!({"token":case.token,"direction":case.direction,"bytes":case.bytes});
        tcp.write_all(format!("{request}\n").as_bytes()).await.unwrap();
        let mut ready = [0;3]; tcp.read_exact(&mut ready).await.unwrap(); assert_eq!(&ready,b"OK\n");
        let start = std::time::Instant::now();
        let mut transferred = 0;
        let mut buffer = vec![b'Z';65536];
        while transferred < case.bytes {
            let n = buffer.len().min(case.bytes-transferred);
            if case.direction=="upload" { tcp.write_all(&buffer[..n]).await.unwrap(); transferred+=n; }
            else {
                let received=tcp.read(&mut buffer[..n]).await.unwrap(); assert!(received>0,"short download at {transferred}");
                assert!(buffer[..received].iter().all(|&byte|byte==b'Z'),"payload corruption"); transferred+=received;
            }
        }
        if case.direction=="upload" {tcp.shutdown().await.unwrap();}
        let mut response=Vec::new(); tcp.read_to_end(&mut response).await.unwrap();
        let seconds=start.elapsed().as_secs_f64();
        let result:serde_json::Value=serde_json::from_slice(&response).unwrap();
        assert_eq!(result["bytes"].as_u64(),Some(case.bytes as u64)); assert_eq!(result["sha256"].as_str(),Some(case.sha256.as_str()));
        drop(tcp); drop(listener); pool.shutdown().await;
        println!("WAN_CASE={}",serde_json::json!({"label":case.label,"direction":case.direction,"bytes":transferred,"seconds":seconds,"mbps":transferred as f64*8.0/seconds/1e6,"local_tcp_connections":1,"target_tcp_connections":1,"verified":true,"fixture":result}));
    }).await.expect("bounded WAN case exceeded its deadline");
}

#[tokio::test]
async fn live_lanes_deliver_interactive_turns_before_batch_completion_or_tcp_eof() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (a, _server) = start(root, "a", None, true).await;
    let identity = identity(root, "interactive-lane");
    let pool = client::Pool::new(identity.clone(), vec![node("a", a)], vec!["a".into()]).unwrap();
    let (listen, listener) = local_listener(pool.clone(), "a").await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = target.local_addr().unwrap();
    let peer = Task(tokio::spawn(async move {
        let (mut tcp, _) = target.accept().await.unwrap();
        let mut request = [0; 3];
        tcp.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"one");
        tcp.write_all(b"first").await.unwrap();
        tcp.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"two");
        tcp.write_all(b"second").await.unwrap();
        let mut rest = Vec::new();
        tcp.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        tcp.shutdown().await.unwrap();
    }));
    let (mut tcp, status, _) = socks(listen, TCP, Address::Ip(at)).await;
    assert_eq!(status, 0);
    tcp.write_all(b"one").await.unwrap();
    let mut first = [0; 5];
    timeout(Duration::from_secs(3), tcp.read_exact(&mut first))
        .await
        .expect("first turn waited for an entire lane")
        .unwrap();
    assert_eq!(&first, b"first");
    tcp.write_all(b"two").await.unwrap();
    let mut second = [0; 6];
    timeout(Duration::from_secs(3), tcp.read_exact(&mut second))
        .await
        .expect("second turn waited for TCP EOF")
        .unwrap();
    assert_eq!(&second, b"second");
    tcp.shutdown().await.unwrap();
    let mut tail = Vec::new();
    tcp.read_to_end(&mut tail).await.unwrap();
    assert!(tail.is_empty());
    empty(&identity, a).await;
    drop(listener);
    pool.shutdown().await;
    drop(peer);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_streaming_flows_do_not_starve_an_active_flow_and_all_release() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (a, _server) = start(root, "a", None, true).await;
    let identity = identity(root, "idle-lanes");
    let pool = client::Pool::new(identity.clone(), vec![node("a", a)], vec!["a".into()]).unwrap();
    let (listen, listener) = local_listener_capacity(pool.clone(), "a", MAX_STREAMS).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = target.local_addr().unwrap();
    let peer = Task(tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted=target.accept()=>{let(mut tcp,_)=accepted.unwrap();tasks.spawn(async move {let mut input=[0;4];let n=tcp.read(&mut input).await.unwrap();if n>0 {tcp.write_all(b"PONG").await.unwrap();let mut tail=Vec::new();tcp.read_to_end(&mut tail).await.unwrap();}tcp.shutdown().await.unwrap();});},
                _=tasks.join_next(),if !tasks.is_empty()=>{},
            }
        }
    }));
    // Above the former 64-flow exit limit. An idle flow keeps one future-data
    // waiter (two while a reply streams), not one per logical lane.
    let flows = 96;
    let mut idle = Vec::new();
    for _ in 0..flows {
        let (tcp, status, _) = socks(listen, TCP, Address::Ip(at)).await;
        assert_eq!(status, 0);
        idle.push(tcp);
    }
    let held = identity.status(a).await.unwrap().proxy.unwrap();
    assert_eq!(held.tcp_flows, flows);
    assert!(
        held.rpc_streams <= flows * 2,
        "idle flows hold {} exit handlers",
        held.rpc_streams
    );
    let (mut active, status, _) = socks(listen, TCP, Address::Ip(at)).await;
    assert_eq!(status, 0);
    active.write_all(b"PING").await.unwrap();
    let mut reply = [0; 4];
    timeout(Duration::from_secs(5), active.read_exact(&mut reply))
        .await
        .expect("idle lane requests starved active data")
        .unwrap();
    assert_eq!(&reply, b"PONG");
    drop(active);
    drop(idle);
    empty(&identity, a).await;
    drop(listener);
    pool.shutdown().await;
    drop(peer);
}
