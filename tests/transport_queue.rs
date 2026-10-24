use braidpath::{
    fec::Encoder,
    runtime::{
        MAX_PAYLOAD,
        transport::{self, Congestion},
        wire::{self, Receiver, Record},
    },
};
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[tokio::test(flavor = "current_thread")]
async fn explicit_datagram_buffer_holds_eight_records_without_eviction() {
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    transport::initialize(&identity, "localhost").unwrap();
    let server = transport::server(
        "127.0.0.1:0".parse().unwrap(),
        &identity.join("cert.pem"),
        &identity.join("key.pem"),
        Congestion::Bbr,
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    for invalid in [1199, 76_801, usize::MAX] {
        assert!(
            transport::client_bound_with_datagram_buffer(
                address,
                &identity.join("cert.pem"),
                None,
                Congestion::Bbr,
                None,
                invalid,
            )
            .is_err()
        );
    }
    // Darwin loopback is interface index1. Exercise the real bound endpoint
    // handshake and datagram path, rather than only parsing an interface name.
    let interface = cfg!(target_os = "macos").then_some("ifindex:1");
    let client = transport::client_bound_with_datagram_buffer(
        address,
        &identity.join("cert.pem"),
        interface,
        Congestion::Bbr,
        Some("127.0.0.1:0".parse().unwrap()),
        8 * 1200,
    )
    .unwrap();
    assert_eq!(client.local_addr().unwrap().ip(), address.ip());
    let (outgoing, incoming) = timeout(Duration::from_secs(3), async {
        tokio::join!(client.connect(address, "localhost").unwrap(), async {
            server.accept().await.unwrap().await
        })
    })
    .await
    .unwrap();
    let outgoing = outgoing.unwrap();
    let incoming = incoming.unwrap();
    let records: Vec<_> = (0..16)
        .map(|id| {
            let original = Record {
                flow: 1,
                id,
                payload: vec![id as u8; MAX_PAYLOAD],
            };
            wire::http_datagram(0, &wire::plain(&original).unwrap()).unwrap()
        })
        .collect();
    // Synchronous current-thread admissions cannot be drained by the driver.
    let mut admitted = 0;
    for record in &records {
        if outgoing.datagram_send_buffer_space() < record.len() {
            break;
        }
        outgoing.send_datagram(record.clone()).unwrap();
        admitted += 1;
    }
    // Bytes include metadata, so 9600 bytes can hold more than eight small records.
    assert!(admitted >= 8);
    assert!(admitted < records.len());
    assert!(outgoing.datagram_send_buffer_space() < records[0].len());
    for expected in records.into_iter().take(admitted) {
        assert_eq!(
            timeout(Duration::from_secs(3), incoming.read_datagram())
                .await
                .unwrap()
                .unwrap(),
            expected
        );
    }
    client.close(0u32.into(), b"test complete");
    server.close(0u32.into(), b"test complete");
}

#[tokio::test(flavor = "current_thread")]
async fn bounded_transport_queue_preserves_maximum_plain_and_repair_frames() {
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    transport::initialize(&identity, "localhost").unwrap();
    let congestion = Congestion::Bbr;
    let server = transport::server(
        "127.0.0.1:0".parse().unwrap(),
        &identity.join("cert.pem"),
        &identity.join("key.pem"),
        congestion,
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let bound = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = bound.local_addr().unwrap();
    drop(bound);
    let client = transport::client_bound(
        address,
        &identity.join("cert.pem"),
        None,
        congestion,
        Some(bind),
    )
    .unwrap();
    assert_eq!(client.local_addr().unwrap(), bind);
    let (outgoing, incoming) = timeout(Duration::from_secs(3), async {
        tokio::join!(client.connect(address, "localhost").unwrap(), async {
            server.accept().await.unwrap().await
        })
    })
    .await
    .unwrap();
    let outgoing = outgoing.unwrap();
    let incoming = incoming.unwrap();
    assert_eq!(incoming.remote_address(), bind);
    let original = Record {
        flow: 1,
        id: 0,
        payload: vec![0xab; MAX_PAYLOAD],
    };
    let plain = wire::http_datagram(0, &wire::plain(&original).unwrap()).unwrap();

    // No await here: the current-thread transport driver cannot drain the queue
    // between admission and the capacity check. The default buffer is only a
    // ceiling (each path's writer bounds what it holds there), and the
    // published hint follows the accepted frame.
    let empty = outgoing.datagram_send_buffer_space();
    assert!(empty <= transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES && empty >= 8 * plain.len());
    assert_eq!(outgoing.datagram_send_buffer_space_hint(), empty);
    outgoing.send_datagram(plain.clone()).unwrap();
    let space = outgoing.datagram_send_buffer_space();
    assert!(space <= empty - plain.len());
    assert_eq!(outgoing.datagram_send_buffer_space_hint(), space);

    let received = timeout(Duration::from_secs(3), incoming.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, plain);
    let mut receiver = Receiver::default();
    assert_eq!(
        receiver
            .receive(wire::http_payload(&received, 0).unwrap(), Instant::now())
            .unwrap(),
        vec![original]
    );

    let repaired = Record {
        flow: 1,
        id: 1,
        payload: vec![0xcd; MAX_PAYLOAD],
    };
    let mut encoder = Encoder::new(1, Duration::from_millis(25)).unwrap();
    let repair = encoder
        .push(&repaired.encode().unwrap(), Instant::now())
        .unwrap()
        .pop()
        .unwrap();
    let repair = wire::http_datagram(0, &wire::shard(repair)).unwrap();
    assert!(outgoing.datagram_send_buffer_space() >= repair.len());
    outgoing.send_datagram(repair.clone()).unwrap();
    let received = timeout(Duration::from_secs(3), incoming.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, repair);
    assert_eq!(
        receiver
            .receive(wire::http_payload(&received, 0).unwrap(), Instant::now())
            .unwrap(),
        vec![repaired]
    );
    assert_eq!(receiver.recovered, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn server_datagram_send_buffer_override_reaches_reverse_connection_without_eviction() {
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    transport::initialize(&identity, "localhost").unwrap();
    for invalid in [1199, 76_801, usize::MAX] {
        assert!(
            transport::server_with_datagram_buffer(
                "127.0.0.1:0".parse().unwrap(),
                &identity.join("cert.pem"),
                &identity.join("key.pem"),
                Congestion::Bbr,
                invalid,
            )
            .is_err()
        );
    }
    // Zero is the default ceiling.
    for bytes in [0, 1200, 9600] {
        let server = if bytes == 0 {
            transport::server(
                "127.0.0.1:0".parse().unwrap(),
                &identity.join("cert.pem"),
                &identity.join("key.pem"),
                Congestion::Bbr,
            )
        } else {
            transport::server_with_datagram_buffer(
                "127.0.0.1:0".parse().unwrap(),
                &identity.join("cert.pem"),
                &identity.join("key.pem"),
                Congestion::Bbr,
                bytes,
            )
        }
        .unwrap();
        let address = server.local_addr().unwrap();
        let client =
            transport::client(address, &identity.join("cert.pem"), None, Congestion::Bbr).unwrap();
        let (client_conn, server_conn) = timeout(Duration::from_secs(3), async {
            tokio::join!(client.connect(address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await
            })
        })
        .await
        .unwrap();
        let client_conn = client_conn.unwrap();
        let server_conn = server_conn.unwrap();
        let records: Vec<_> = (0..16)
            .map(|id| {
                let record = Record {
                    flow: 1,
                    id,
                    payload: vec![id as u8; MAX_PAYLOAD],
                };
                wire::http_datagram(0, &wire::plain(&record).unwrap()).unwrap()
            })
            .collect();
        let mut admitted = 0;
        // No await: the current-thread driver cannot drain or mask the bound.
        for record in &records {
            if server_conn.datagram_send_buffer_space() < record.len() {
                break;
            }
            server_conn.send_datagram(record.clone()).unwrap();
            admitted += 1;
        }
        if bytes == 0 {
            assert_eq!(admitted, records.len());
        } else if bytes == 1200 {
            assert_eq!(admitted, 1);
        } else {
            assert!(admitted >= 8 && admitted < records.len());
        }
        for record in records.into_iter().take(admitted) {
            assert_eq!(
                timeout(Duration::from_secs(3), client_conn.read_datagram())
                    .await
                    .unwrap()
                    .unwrap(),
                record
            );
        }
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
    }
}
