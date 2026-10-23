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
async fn start(
    root: &Path,
    id: &str,
    join: Option<SocketAddr>,
    allow_private: bool,
) -> (SocketAddr, Task<Result<()>>) {
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
        rate: 100_000_000,
        stats: metrics.clone(),
    })));
    timeout(Duration::from_secs(5), async {
        while !metrics.is_ready() {
            assert!(!task.0.is_finished());
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    (at, task)
}
fn identity(root: &Path, dir: &str) -> mesh::ClientIdentity {
    mesh::ClientIdentity::open(root.join(dir), &root.join("a/client-key.json")).unwrap()
}
async fn local_listener(pool: Arc<client::Pool>, exit: &str) -> (SocketAddr, Task<Result<()>>) {
    let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listen.local_addr().unwrap();
    let task = Task(tokio::spawn(client::listen(
        listen,
        pool,
        exit.to_owned(),
        Arc::new(Semaphore::new(16)),
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
                        loop { let n = tcp.read(&mut buffer).await.unwrap(); if n == 0 { tcp.write_all(b"FIN").await.unwrap(); break; } tcp.write_all(&buffer[..n]).await.unwrap(); }
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
async fn empty(identity: &mesh::ClientIdentity, at: SocketAddr) {
    timeout(Duration::from_secs(4), async {
        loop {
            let s = identity.status(at).await.unwrap().proxy.unwrap();
            if s.streams == 0 && s.udp_associations == 0 && s.udp_destinations == 0 {
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
    let (a, _a) = start(root, "a", None, true).await;
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
        assert!(s.capabilities.features.iter().any(|f| f == "proxy-tcp-v1"));
        assert_eq!(s.proxy.unwrap().streams, 1);
    }
    let (mut third, status, _) = socks(listen_a, TCP, Address::Ip(target)).await;
    assert_eq!(status, 0);
    assert_eq!(identity.status(a).await.unwrap().proxy.unwrap().streams, 2);
    assert_eq!(
        identity.status(a).await.unwrap().proxy.unwrap().connections,
        1
    );
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
