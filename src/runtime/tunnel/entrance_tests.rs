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

#[tokio::test]
async fn mesh_session_rejects_wrong_or_missing_exit_before_epoch_recovery() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    transport::initialize(&identity, "braidpath.mesh").unwrap();
    let address = mesh::tests::address();
    let state = mesh::tests::connection_state(&identity, address, 1);
    let metrics = stats::Metrics::new("identity-server");
    let pending = Arc::new(Semaphore::new(1));
    let data = Arc::new(Semaphore::new(1));
    let _server = Task(tokio::spawn(serve_with_budgets(
        ServerOptions {
            bind: address,
            cert: identity.join("cert.pem"),
            key: identity.join("key.pem"),
            token: identity.join("token"),
            target: Some(mesh::tests::address()),
            tcp_target: None,
            stream_proxy: None,
            proxy: None,
            max_rate: 10_000_000,
            congestion: transport::Congestion::default(),
            datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            adaptive_fec_retention: false,
            stats: metrics.clone(),
        },
        transport::AckRequest::Unchanged,
        Some(state),
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
    for exit in [None, Some("previous-address-owner")] {
        for rejoin in [false, true] {
            let mut diagnostic = stats::ConnectionTrace::new(
                stats::Metrics::new("identity-client"),
                address,
                Some(0),
                "test",
            );
            let result = connect_path(
                &endpoint,
                address,
                "braidpath.mesh",
                &token,
                &transport::hex(&rand::random::<[u8; 16]>()),
                0,
                0,
                1,
                rejoin,
                &mesh::tests::policy(),
                exit,
                &mut diagnostic,
            )
            .await;
            let error = match result {
                Ok(_) => panic!("wrong exit admitted"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("identity mismatch"), "{error}");
            assert!(
                !error.is::<SessionExpired>(),
                "mismatch requested a fresh epoch"
            );
            assert_eq!(
                data.available_permits(),
                1,
                "wrong exit consumed data capacity"
            );
            // The client's rejection closes H3 asynchronously. Wait for that
            // exact pending permit before the next case uses our one-slot
            // fixture, rather than accidentally testing handshake saturation.
            timeout(Duration::from_secs(2), async {
                while pending.available_permits() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("rejected connection retained pending capacity");
        }
    }
}

#[tokio::test]
async fn legacy_session_response_cannot_silently_remove_mesh_exit_binding() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    transport::initialize(&identity, "braidpath.mesh").unwrap();
    for status in [StatusCode::OK, StatusCode::GONE] {
        let server = transport::server(
            "127.0.0.1:0".parse().unwrap(),
            &identity.join("cert.pem"),
            &identity.join("key.pem"),
            transport::Congestion::default(),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let _server = Task(tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let mut h3 = h3::server::builder()
                .enable_datagram(true)
                .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            let (_request, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            stream
                .send_response(
                    Response::builder()
                        .status(status)
                        .header("braidpath-version", "1")
                        .header("braidpath-max-payload", MAX_PAYLOAD)
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            stream.finish().await.unwrap();
            let _ = connection.closed().await;
        }));
        let endpoint = transport::client(
            address,
            &identity.join("cert.pem"),
            None,
            transport::Congestion::default(),
        )
        .unwrap();
        let mut diagnostic = stats::ConnectionTrace::new(
            stats::Metrics::new("legacy-client"),
            address,
            Some(0),
            "test",
        );
        let result = timeout(
            Duration::from_secs(2),
            connect_path(
                &endpoint,
                address,
                "braidpath.mesh",
                &transport::token(&identity.join("token")).unwrap(),
                &transport::hex(&rand::random::<[u8; 16]>()),
                0,
                0,
                1,
                status == StatusCode::GONE,
                &mesh::tests::policy(),
                Some("own"),
                &mut diagnostic,
            ),
        )
        .await
        .unwrap();
        let error = match result {
            Ok(_) => panic!("legacy peer accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unsupported peer"), "{error}");
        assert!(!error.is::<SessionExpired>());
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
            target: Some(mesh::tests::address()),
            tcp_target: None,
            stream_proxy: None,
            proxy: None,
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
        Some("own"),
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
    admission_deadline(AdmissionScenario::Idle).await;
}

#[tokio::test]
async fn mesh_server_deadline_also_bounds_incomplete_request_headers() {
    admission_deadline(AdmissionScenario::IncompleteHeaders).await;
}

#[tokio::test]
async fn unauthenticated_response_without_stream_credit_cannot_pin_pending_permit() {
    admission_deadline(AdmissionScenario::StalledResponse).await;
}

#[tokio::test]
async fn authenticated_control_response_without_stream_credit_cannot_pin_control_permit() {
    admission_deadline(AdmissionScenario::StalledControlResponse).await;
}

enum AdmissionScenario {
    Idle,
    IncompleteHeaders,
    StalledResponse,
    StalledControlResponse,
}

async fn admission_deadline(scenario: AdmissionScenario) {
    let incomplete_headers = matches!(scenario, AdmissionScenario::IncompleteHeaders);
    let authenticated_control = matches!(scenario, AdmissionScenario::StalledControlResponse);
    let stalled_response = matches!(
        scenario,
        AdmissionScenario::StalledResponse | AdmissionScenario::StalledControlResponse
    );
    let mesh_enabled = incomplete_headers || authenticated_control;
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
            target: Some(mesh::tests::address()),
            tcp_target: None,
            stream_proxy: None,
            proxy: None,
            max_rate: 10_000_000,
            congestion: transport::Congestion::default(),
            datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            adaptive_fec_retention: false,
            stats: metrics.clone(),
        },
        transport::AckRequest::Unchanged,
        mesh.clone(),
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
    let endpoint = if stalled_response {
        // 64 bytes carry H3 settings/headers but cannot carry the website body.
        // Keepalive stays enabled, so transport idle timeout cannot mask the
        // application's absolute admission deadline.
        let mut roots = rustls::RootCertStore::empty();
        for cert in transport::certificates(&identity.join("cert.pem")).unwrap() {
            roots.add(cert).unwrap();
        }
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        ));
        let mut transport = transport::config(transport::Congestion::default());
        transport.stream_receive_window(64u32.into());
        config.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(config);
        endpoint
    } else {
        transport::client(
            address,
            &identity.join("cert.pem"),
            None,
            transport::Congestion::default(),
        )
        .unwrap()
    };
    let (raw, mut send, _driver) = control_connection(&endpoint, address).await;
    // A complete, rejected request proves the handshake/HTTP3 setup is done;
    // rejection must not extend the absolute unauthenticated deadline.
    assert_eq!(
        mesh_request(&mut send, "wrong", SESSION_PATH, Some(""))
            .await
            .unwrap(),
        StatusCode::NOT_FOUND
    );
    if authenticated_control {
        let token = transport::token(&identity.join("token")).unwrap();
        assert_eq!(
            mesh_request(&mut send, &token, "/mesh/nodes", None)
                .await
                .unwrap(),
            StatusCode::OK
        );
        assert!(mesh.as_ref().unwrap().control_permit().is_none());
    }
    let _blocked_response = if stalled_response {
        let mut request = send
            .send_request(
                Request::builder()
                    .uri("https://braidpath.mesh/")
                    .method(Method::GET)
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        request.finish().await.unwrap();
        assert_eq!(
            request.recv_response().await.unwrap().status(),
            StatusCode::OK
        );
        // Deliberately do not consume the body, withholding stream credit.
        Some(request)
    } else {
        None
    };
    assert_eq!(
        pending.available_permits(),
        usize::from(authenticated_control)
    );
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
    assert_eq!(
        pending.available_permits(),
        usize::from(authenticated_control)
    );
    // Eleven seconds exceeds admission but is below a five-second request
    // timeout started at second nine. No wall-clock ten-second sleep is used.
    if authenticated_control {
        // Advance in small steps so actual QUIC keepalives are serviced. The
        // connection must remain open beyond the 15-second transport idle
        // timeout and until just before its 60-second control deadline.
        for _ in 0..50 {
            tokio::time::advance(Duration::from_secs(1)).await;
            for _ in 0..128 {
                tokio::task::yield_now().await;
            }
            assert!(raw.close_reason().is_none());
            assert!(mesh.as_ref().unwrap().control_permit().is_none());
        }
    }
    tokio::time::advance(Duration::from_millis(1950)).await;
    for _ in 0..1024 {
        if pending.available_permits() == 1
            && (!authenticated_control || mesh.as_ref().unwrap().control_permit().is_some())
        {
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
    if authenticated_control {
        assert!(
            mesh.as_ref().unwrap().control_permit().is_some(),
            "stalled response retained the control permit after 60 seconds"
        );
    }
    if let Some(tx) = partial.as_mut() {
        let _ = tx.reset(0u32.into());
    }
    tokio::time::resume();
}

#[test]
fn route_identity_includes_uplink_and_retains_other_network_during_removal() {
    let address = "127.0.0.1:12345".parse().unwrap();
    let mut routes: Vec<_> = (0..2)
        .map(|group| mesh::Route {
            address,
            uplink: mesh::Uplink {
                interface: Some(format!("test{group}")),
                bind: Some(format!("127.0.0.{}", group + 1).parse().unwrap()),
                group,
            },
        })
        .collect();
    let mut configs = Vec::new();
    let mut endpoints = std::array::from_fn(|_| None);
    let paths = Arc::new(Mutex::new(vec![]));
    let mut rotations = std::array::from_fn(|_| scheduler::Rotation::default());
    let inflight = [false; MAX_PATHS];
    reconcile_routes(
        &routes,
        &mut configs,
        &inflight,
        &mut endpoints,
        &paths,
        &mut rotations,
    );
    assert_eq!(configs.len(), 2);
    let generations: Vec<_> = configs.iter().map(|c| c.generation).collect();
    routes.reverse();
    reconcile_routes(
        &routes,
        &mut configs,
        &inflight,
        &mut endpoints,
        &paths,
        &mut rotations,
    );
    assert_eq!(configs[0].group, 0);
    assert_eq!(configs[1].group, 1);
    routes.retain(|r| r.uplink.group == 1);
    reconcile_routes(
        &routes,
        &mut configs,
        &inflight,
        &mut endpoints,
        &paths,
        &mut rotations,
    );
    assert!(!configs[0].enabled && configs[1].enabled);
    assert_eq!(configs[1].generation, generations[1]);
    routes.push(mesh::Route {
        address,
        uplink: mesh::Uplink {
            interface: Some("restored".into()),
            bind: Some("127.0.0.3".parse().unwrap()),
            group: 0,
        },
    });
    reconcile_routes(
        &routes,
        &mut configs,
        &inflight,
        &mut endpoints,
        &paths,
        &mut rotations,
    );
    assert_eq!(configs.len(), 2);
    assert_eq!(configs[0].generation, generations[0]);
    assert_eq!(configs[0].bind, Some("127.0.0.3:0".parse().unwrap()));
}

#[test]
fn fragmentation_requires_exact_capability_echo_and_legacy_is_explicit() {
    let mut headers = http::HeaderMap::new();
    validate_message_echo(&headers, 1000).unwrap();
    assert!(validate_message_echo(&headers, 4096).is_err());
    headers.insert("braidpath-message-bytes", "4096".parse().unwrap());
    validate_message_echo(&headers, 4096).unwrap();
    assert!(validate_message_echo(&headers, 1000).is_err());
    headers.insert("braidpath-message-bytes", "65535".parse().unwrap());
    assert!(validate_message_echo(&headers, 4096).is_err());
}
