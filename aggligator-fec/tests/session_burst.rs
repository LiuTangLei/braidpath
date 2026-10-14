#![cfg(feature = "runtime")]
use aggligator_fec::{
    Config, Frame,
    interleave::source_sequence,
    session::{self, SessionConfig},
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hundreds_of_simultaneous_missing_sources_backpressure_repair_queue() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ap = a.local_addr().unwrap();
        let bp = b.local_addr().unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rp = relay.local_addr().unwrap();
        let forward = tokio::spawn(async move {
            let mut buf = [0; 1600];
            loop {
                let (n, from) = relay.recv_from(&mut buf).await.unwrap();
                let to = if from == ap { bp } else { ap };
                if n > 13 && buf[4] == 1 {
                    let frame = Frame::decode(&buf[13..n], 1300).unwrap();
                    if source_sequence(&frame, 1).unwrap().is_some_and(|seq| (20..620).contains(&seq)) {
                        continue;
                    }
                }
                relay.send_to(&buf[..n], to).await.unwrap();
            }
        });
        let cfg = SessionConfig {
            fec: Config { data_shards: 8, repair_shards: 0, max_payload: 1300, ..Config::default() },
            lanes: 1,
            wire_mbps: 80,
            nack_delay: Duration::from_millis(10),
            idle_timeout: Duration::from_secs(3),
            delivery_aware: true,
            adaptive_retries: false,
            low_latency: false,
        };
        let (server, client) =
            tokio::join!(session::accept(b, vec![rp], cfg.clone()), session::connect(a, vec![rp], cfg));
        let mut c = client.unwrap();
        let mut s = server.unwrap();
        let sending = tokio::spawn(async move {
            let w = c.stream.write_all(&vec![0x3d; 1_500_000]).await;
            let _ = c.stream.shutdown().await;
            let mut eof = Vec::new();
            let _ = c.stream.read_to_end(&mut eof).await;
            (w, c.task.await.unwrap())
        });
        let mut got = Vec::new();
        s.stream.read_to_end(&mut got).await.unwrap();
        let _ = s.stream.shutdown().await;
        let server_result = s.task.await.unwrap();
        let (client_write, client_result) = sending.await.unwrap();
        forward.abort();
        assert!(client_result.is_ok(), "sender error: {client_result:?}; receiver: {server_result:?}");
        assert!(client_write.is_ok());
        assert!(server_result.is_ok(), "{server_result:?}");
        assert_eq!(got, vec![0x3d; 1_500_000]);
    })
    .await
    .expect("burst recovery timed out");
}
