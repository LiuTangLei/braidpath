use super::*;

#[test]
fn entrance_changes_preserve_ids_and_wait_for_inflight_slots() {
    let mut configs: Vec<_> = (0..MAX_PATHS)
        .map(|id| PathConfig {
            remote: SocketAddr::from(([127, 0, 0, 1], 10000 + id as u16)),
            interface: None,
            bind: None,
            group: 0,
            generation: 100 + id as u64,
            attempted: true,
            enabled: true,
        })
        .collect();
    let mut endpoints = std::array::from_fn(|_| None);
    let paths = Arc::new(Mutex::new(vec![]));
    let mut rotations = std::array::from_fn(|_| scheduler::Rotation::default());
    let mut inflight = [false; MAX_PATHS];
    let mut desired: Vec<_> = configs.iter().rev().map(|c| c.remote).collect();
    reconcile_entrances(
        &desired,
        &mut configs,
        &inflight,
        &mut endpoints,
        &paths,
        &mut rotations,
    );
    assert_eq!(configs[0].remote.port(), 10000);
    assert!(configs.iter().all(|c| c.attempted && c.enabled));

    let new = "127.0.0.1:20000".parse().unwrap();
    desired.pop();
    desired.push(new);
    inflight[0] = true;
    reconcile_entrances(
        &desired,
        &mut configs,
        &inflight,
        &mut endpoints,
        &paths,
        &mut rotations,
    );
    assert_eq!(configs.len(), MAX_PATHS);
    assert_eq!(configs[0].remote.port(), 10000, "inflight slot was reused");
    inflight[0] = false;
    reconcile_entrances(
        &desired,
        &mut configs,
        &inflight,
        &mut endpoints,
        &paths,
        &mut rotations,
    );
    assert_eq!(configs[0].remote, new);
    assert_eq!(configs[0].generation, 100);
    assert!(!configs[0].attempted);
    assert_eq!(configs[1].remote.port(), 10001);
    assert_eq!(configs[1].generation, 101);
    assert!(configs[1].attempted);

    reconcile_entrances(
        &[new],
        &mut configs,
        &inflight,
        &mut endpoints,
        &paths,
        &mut rotations,
    );
    assert_eq!(configs.iter().filter(|c| c.enabled).count(), 1);
    assert_eq!(
        configs.len(),
        MAX_PATHS,
        "retired IDs must retain their generations"
    );
}

struct Task<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn control_connection(
    endpoint: &quinn::Endpoint,
    address: SocketAddr,
) -> (quinn::Connection, H3Send, Task<()>) {
    let raw = endpoint
        .connect(address, "braidpath.mesh")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, sender) = h3::client::builder()
        .enable_datagram(true)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(raw.clone()))
        .await
        .unwrap();
    let task = Task(tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    }));
    (raw, sender, task)
}

async fn mesh_request(
    sender: &mut H3Send,
    token: &str,
    path: &str,
    body: Option<&str>,
) -> Result<StatusCode> {
    let request = Request::builder()
        .uri(format!("https://braidpath.mesh{path}"))
        .method(if body.is_some() {
            Method::POST
        } else {
            Method::GET
        })
        .header("authorization", format!("Bearer {token}"))
        .body(())?;
    let mut stream = sender.send_request(request).await?;
    if let Some(body) = body {
        stream
            .send_data(Bytes::copy_from_slice(body.as_bytes()))
            .await?;
    }
    stream.finish().await?;
    let status = stream.recv_response().await?.status();
    while stream.recv_data().await?.is_some() {}
    Ok(status)
}

#[tokio::test]
async fn connection_budgets_isolate_control_data_and_pending_admission() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    transport::initialize(&identity, "braidpath.mesh").unwrap();
    let address = mesh::tests::address();
    let mesh = mesh::tests::connection_state(&identity, address, 1);
    let metrics = stats::Metrics::new("budget-server");
    // Small budgets exercise exactly the same admission code without hundreds
    // of handshakes. Holding the data permit models full established capacity.
    let data = Arc::new(Semaphore::new(1));
    let pending = Arc::new(Semaphore::new(2));
    let saturated_data = data.clone().acquire_owned().await.unwrap();
    let _server = Task(tokio::spawn(serve_with_budgets(
        ServerOptions {
            bind: address,
            cert: identity.join("cert.pem"),
            key: identity.join("key.pem"),
            token: identity.join("token"),
            target: mesh::tests::address(),
            max_rate: 10_000_000,
            congestion: transport::Congestion::default(),
            datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            adaptive_fec_retention: false,
            stats: metrics.clone(),
        },
        transport::AckRequest::Unchanged,
        Some(mesh.clone()),
        pending.clone(),
        data.clone(),
    )));
    timeout(Duration::from_secs(2), async {
        while !metrics.is_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let endpoint = transport::client(
        address,
        &identity.join("cert.pem"),
        None,
        transport::Congestion::default(),
    )
    .unwrap();
    let token = transport::token(&identity.join("token")).unwrap();
    let (first, mut first_send, _first_driver) = control_connection(&endpoint, address).await;
    assert_eq!(
        mesh_request(&mut first_send, &token, "/mesh/nodes", None)
            .await
            .unwrap(),
        StatusCode::OK
    );
    assert_eq!(
        data.available_permits(),
        0,
        "full data capacity blocked control"
    );
    assert_eq!(pending.available_permits(), 2);
    drop(saturated_data);
    let (overflow, mut overflow_send, _overflow_driver) =
        control_connection(&endpoint, address).await;
    assert!(
        mesh_request(
            &mut overflow_send,
            &token,
            "/mesh/relay",
            Some(r#"{"exit":"own","lease":null}"#)
        )
        .await
        .is_err(),
        "full control budget admitted an operation"
    );
    timeout(Duration::from_secs(2), overflow.closed())
        .await
        .unwrap();
    assert_eq!(
        data.available_permits(),
        1,
        "control overflow borrowed data capacity"
    );
    let mut policy = mesh::tests::policy();
    policy.adaptive = false;
    let mut diagnostic = stats::ConnectionTrace::new(
        stats::Metrics::new("budget-client"),
        address,
        Some(0),
        "test",
    );
    let (joined, _, mut driver, _request, mut send) = connect_path(
        &endpoint,
        address,
        "braidpath.mesh",
        &token,
        &transport::hex(&rand::random::<[u8; 16]>()),
        0,
        0,
        1,
        false,
        &policy,
        &mut diagnostic,
    )
    .await
    .unwrap();
    let _data_driver = Task(tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    }));
    assert_eq!(data.available_permits(), 0);
    // An established data connection cannot also perform mesh operations.
    assert!(
        mesh_request(&mut send, &token, "/mesh/nodes", None)
            .await
            .is_err()
    );
    timeout(Duration::from_secs(2), joined.closed())
        .await
        .unwrap();
    // Control role remains fixed even when there is free data capacity.
    assert!(
        mesh_request(&mut first_send, &token, SESSION_PATH, Some(""))
            .await
            .is_err()
    );
    timeout(Duration::from_secs(2), first.closed())
        .await
        .unwrap();
    timeout(Duration::from_secs(2), async {
        while data.available_permits() != 1 || pending.available_permits() != 2 {
            tokio::task::yield_now().await;
        }
        while mesh.control_permit().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Even pending handshakes are bounded independently.
    let held = pending.clone().acquire_many_owned(2).await.unwrap();
    assert!(
        timeout(
            Duration::from_secs(2),
            endpoint.connect(address, "braidpath.mesh").unwrap()
        )
        .await
        .unwrap()
        .is_err()
    );
    drop(held);
    let (_last, mut last_send, _last_driver) = control_connection(&endpoint, address).await;
    assert_eq!(
        mesh_request(&mut last_send, &token, "/mesh/nodes", None)
            .await
            .unwrap(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn ordinary_server_releases_unauthenticated_connection_at_ten_seconds() {
    admission_deadline(false, false).await;
}

#[tokio::test]
async fn mesh_server_deadline_also_bounds_incomplete_request_headers() {
    admission_deadline(true, true).await;
}

async fn admission_deadline(mesh_enabled: bool, incomplete_headers: bool) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    transport::initialize(&identity, "braidpath.mesh").unwrap();
    let address = mesh::tests::address();
    let mesh = mesh_enabled.then(|| mesh::tests::connection_state(&identity, address, 1));
    let metrics = stats::Metrics::new("server");
    let pending = Arc::new(Semaphore::new(1));
    let data = Arc::new(Semaphore::new(1));
    let _server = Task(tokio::spawn(serve_with_budgets(
        ServerOptions {
            bind: address,
            cert: identity.join("cert.pem"),
            key: identity.join("key.pem"),
            token: identity.join("token"),
            target: mesh::tests::address(),
            max_rate: 10_000_000,
            congestion: transport::Congestion::default(),
            datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            adaptive_fec_retention: false,
            stats: metrics.clone(),
        },
        transport::AckRequest::Unchanged,
        mesh,
        pending.clone(),
        data.clone(),
    )));
    timeout(Duration::from_secs(2), async {
        while !metrics.is_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let endpoint = transport::client(
        address,
        &identity.join("cert.pem"),
        None,
        transport::Congestion::default(),
    )
    .unwrap();
    let (raw, mut send, _driver) = control_connection(&endpoint, address).await;
    // A complete, rejected request proves the handshake/HTTP3 setup is done;
    // rejection must not extend the absolute unauthenticated deadline.
    assert_eq!(
        mesh_request(&mut send, "wrong", SESSION_PATH, Some(""))
            .await
            .unwrap(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(pending.available_permits(), 0);
    metrics.state(|s| {
        assert!(
            s.connection_events
                .iter()
                .any(|event| event.stage == "admission_wait" && event.timeout_ms == Some(10_000))
        )
    });
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(9)).await;
    for _ in 0..128 {
        tokio::task::yield_now().await;
    }
    assert!(raw.close_reason().is_none());
    let mut partial = if incomplete_headers {
        let (mut tx, _rx) = raw.open_bi().await.unwrap();
        // HTTP/3 HEADERS, declared length 100, no header payload or FIN.
        tx.write_all(&[1, 0x40, 100]).await.unwrap();
        Some(tx)
    } else {
        None
    };
    tokio::time::advance(Duration::from_millis(50)).await;
    for _ in 0..128 {
        tokio::task::yield_now().await;
    }
    assert_eq!(pending.available_permits(), 0);
    // Eleven seconds exceeds admission but is below a five-second request
    // timeout started at second nine. No wall-clock ten-second sleep is used.
    tokio::time::advance(Duration::from_millis(1950)).await;
    for _ in 0..1024 {
        if pending.available_permits() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        pending.available_permits(),
        1,
        "unauthenticated connection outlived its admission deadline"
    );
    assert_eq!(data.available_permits(), 1);
    if let Some(tx) = partial.as_mut() {
        let _ = tx.reset(0u32.into());
    }
    tokio::time::resume();
}
