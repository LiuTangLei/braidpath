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
async fn bounded_transport_queue_preserves_maximum_plain_and_repair_frames() {
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("identity");
    transport::initialize(&identity, "localhost").unwrap();
    for congestion in [Congestion::Cubic, Congestion::Bbr] {
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
        // between admission and the same capacity check used by the aggregate sender.
        assert!(outgoing.datagram_send_buffer_space() >= plain.len());
        outgoing.send_datagram(plain.clone()).unwrap();
        assert!(outgoing.datagram_send_buffer_space() < plain.len());

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
}
