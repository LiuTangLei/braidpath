//! Allocation/release fault contracts, including a real lost HTTP/3 response.
use super::*;
use tokio::time::timeout;

fn allocation(key: &str) -> RelayRequest {
    RelayRequest {
        exit: "own".into(),
        lease: None,
        request: Some(key.into()),
    }
}
fn release_request(key: &str) -> ReleaseRequest {
    ReleaseRequest {
        exit: "own".into(),
        lease: None,
        request: Some(key.into()),
    }
}
fn fixture(root: &Path) -> State {
    let mut state = tests::state(root);
    state.bind = "127.0.0.1:0".parse().unwrap();
    state
}

#[tokio::test]
async fn allocation_retry_recovers_a_lost_http3_response_without_an_extra_lease() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir().unwrap();
    let identity = root.path().join("identity");
    transport::initialize(&identity, NAME).unwrap();
    let endpoint = transport::server(
        "127.0.0.1:0".parse().unwrap(),
        &identity.join("cert.pem"),
        &identity.join("key.pem"),
        transport::Congestion::default(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    let state = Arc::new(fixture(root.path()));
    let listener = endpoint.clone();
    let server = state.clone();
    let _task = AbortTask(tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let lost = Arc::new(AtomicBool::new(false));
        loop {
            tokio::select! {
                Some(incoming) = listener.accept() => {
                    let server = server.clone();
                    let lost = lost.clone();
                    connections.spawn(async move {
                        let conn = incoming.await.unwrap();
                        let source = conn.remote_address().ip();
                        let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn.clone())).await.unwrap();
                        while let Ok(Some(resolver)) = h3.accept().await {
                            let (request, mut stream) = resolver.resolve_request().await.unwrap();
                            if request.uri().path() == "/mesh/relay" && !lost.swap(true, Ordering::SeqCst) {
                                assert!(server.authorized(&request));
                                let request = serde_json::from_slice(&read_body(&mut stream).await.unwrap()).unwrap();
                                server.relay(source, request).await.unwrap();
                                // Commit the allocation, then cut the connection before any reply.
                                conn.close(0u32.into(), b"injected lost allocation response");
                                break;
                            }
                            let _ = server.handle(&request, &mut stream, source).await;
                        }
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }));
    let control = Control::new(&identity.join("cert.pem"), false).unwrap();
    let key = "a".repeat(32);
    let body = serde_json::to_vec(&allocation(&key)).unwrap();
    assert!(
        control
            .request::<RelayReply>(address, "client", "/mesh/relay", Some(body.clone()))
            .await
            .is_err()
    );
    assert_eq!(state.leases.lock().unwrap().len(), 1);
    let committed = {
        let leases = state.leases.lock().unwrap();
        let (id, lease) = leases.first_key_value().unwrap();
        (id.clone(), lease.address)
    };
    let reply: RelayReply = control
        .request(address, "client", "/mesh/relay", Some(body))
        .await
        .unwrap();
    assert_eq!((reply.lease, reply.address), committed);
    assert_eq!(state.leases.lock().unwrap().len(), 1);
    let release = serde_json::to_vec(&release_request(&key)).unwrap();
    assert!(
        control
            .request::<ReleaseReply>(address, "wrong", "/mesh/release", Some(release.clone()))
            .await
            .is_err()
    );
    assert_eq!(state.leases.lock().unwrap().len(), 1);
    let released: ReleaseReply = control
        .request(address, "client", "/mesh/release", Some(release))
        .await
        .unwrap();
    assert!(released.released);
    assert!(state.leases.lock().unwrap().is_empty());
    let _reclaimed = UdpSocket::bind(committed.1).await.unwrap();
}

#[tokio::test]
async fn concurrent_allocation_retries_do_not_spend_quota_twice() {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(fixture(root.path()));
    let source = "127.0.0.1".parse().unwrap();
    let key = "b".repeat(32);
    let mut calls = JoinSet::new();
    for _ in 0..32 {
        let state = state.clone();
        let key = key.clone();
        calls.spawn(async move { state.relay(source, allocation(&key)).await.unwrap() });
    }
    let first = calls.join_next().await.unwrap().unwrap();
    while let Some(result) = calls.join_next().await {
        let reply = result.unwrap();
        assert_eq!(reply.lease, first.lease);
        assert_eq!(reply.address, first.address);
    }
    for i in 1..MAX_SOURCE_LEASES {
        state
            .relay(source, allocation(&format!("{i:032x}")))
            .await
            .unwrap();
    }
    assert_eq!(state.leases.lock().unwrap().len(), MAX_SOURCE_LEASES);
    assert!(
        state
            .relay(source, allocation(&"c".repeat(32)))
            .await
            .is_err()
    );
    assert_eq!(
        state.relay(source, allocation(&key)).await.unwrap().lease,
        first.lease
    );
    let mut conflict = allocation(&key);
    conflict.exit = "other".into();
    assert!(state.relay(source, conflict).await.is_err());
    // Source IP remains part of ownership even when a request key is copied.
    let other = state
        .relay("127.0.0.2".parse().unwrap(), allocation(&key))
        .await
        .unwrap();
    assert_ne!(other.lease, first.lease);
}

#[tokio::test]
async fn release_enforces_owner_and_is_idempotent_for_both_selectors() {
    let root = tempfile::tempdir().unwrap();
    let state = fixture(root.path());
    let source = "127.0.0.1".parse().unwrap();
    let key = "d".repeat(32);
    let reply = state.relay(source, allocation(&key)).await.unwrap();
    let by_id = || ReleaseRequest {
        exit: "own".into(),
        lease: Some(reply.lease.clone()),
        request: None,
    };
    assert!(
        state
            .release("127.0.0.2".parse().unwrap(), by_id())
            .await
            .is_err()
    );
    assert!(
        !state
            .release("127.0.0.2".parse().unwrap(), release_request(&key))
            .await
            .unwrap()
            .released
    );
    let mut wrong_exit = by_id();
    wrong_exit.exit = "other".into();
    assert!(state.release(source, wrong_exit).await.is_err());
    assert_eq!(state.leases.lock().unwrap().len(), 1);
    assert!(state.release(source, by_id()).await.unwrap().released);
    assert!(!state.release(source, by_id()).await.unwrap().released);
    assert!(
        !state
            .release(source, release_request(&key))
            .await
            .unwrap()
            .released
    );
    let _reclaimed = UdpSocket::bind(reply.address).await.unwrap();
    assert!(
        state
            .relay(source, allocation("not-a-request-key"))
            .await
            .is_err()
    );
    assert!(
        state
            .release(
                source,
                ReleaseRequest {
                    exit: "own".into(),
                    lease: None,
                    request: None
                }
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn repeated_release_reclaims_the_only_relay_port_and_task() {
    let root = tempfile::tempdir().unwrap();
    let mut state = fixture(root.path());
    let port = tests::address().port();
    state.relay_ports = Some(port.to_string().parse().unwrap());
    let source = "127.0.0.1".parse().unwrap();
    timeout(Duration::from_secs(5), async {
        for i in 0..64 {
            let key = format!("{i:032x}");
            let reply = state.relay(source, allocation(&key)).await.unwrap();
            assert_eq!(reply.address.port(), port);
            assert!(
                state
                    .release(source, release_request(&key))
                    .await
                    .unwrap()
                    .released
            );
            assert!(state.leases.lock().unwrap().is_empty());
            // No sleep/yield/retry: a successful release has joined the old task.
            let _reclaimed = std::net::UdpSocket::bind(reply.address).unwrap();
        }
    })
    .await
    .expect("bounded lease churn did not finish");
}

#[tokio::test]
async fn cancellation_precedes_allocation_and_blocks_late_duplicates_with_bounded_history() {
    let root = tempfile::tempdir().unwrap();
    let state = fixture(root.path());
    let source = "127.0.0.1".parse().unwrap();
    let key = "e".repeat(32);
    assert!(
        !state
            .release(source, release_request(&key))
            .await
            .unwrap()
            .released
    );
    assert!(state.relay(source, allocation(&key)).await.is_err());
    let fresh = "f".repeat(32);
    state.relay(source, allocation(&fresh)).await.unwrap();
    assert!(
        state
            .release(source, release_request(&fresh))
            .await
            .unwrap()
            .released
    );
    assert!(state.relay(source, allocation(&fresh)).await.is_err());
    let mut wrong = release_request(&fresh);
    wrong.exit = "other".into();
    assert!(state.release(source, wrong).await.is_err());
    assert!(state.leases.lock().unwrap().is_empty());
    for i in 0..MAX_RELEASED_REQUESTS + 1 {
        state
            .release(source, release_request(&format!("{i:032x}")))
            .await
            .unwrap();
    }
    assert_eq!(
        state.released_requests.lock().unwrap().0.len(),
        MAX_RELEASED_REQUESTS
    );
    assert!(
        state
            .relay(
                source,
                allocation(&format!("{:032x}", MAX_RELEASED_REQUESTS))
            )
            .await
            .is_err()
    );
    // This bounded protection is not an unbounded revocation registry.
    for (_, at) in state.released_requests.lock().unwrap().0.values_mut() {
        *at = Instant::now() - LEASE_FOR;
    }
    let resumed = state
        .relay(
            source,
            allocation(&format!("{:032x}", MAX_RELEASED_REQUESTS)),
        )
        .await
        .unwrap();
    assert!(!resumed.lease.is_empty());
    assert!(state.released_requests.lock().unwrap().0.is_empty());
}
