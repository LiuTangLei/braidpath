#![cfg(feature = "runtime")]
use aggligator_fec::session::{self, SessionConfig};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fin_must_not_discard_bytes_waiting_for_a_slow_application_reader() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ap = a.local_addr().unwrap();
        let bp = b.local_addr().unwrap();
        let cfg = SessionConfig::default();
        let (s, c) = tokio::join!(session::accept(b, vec![ap], cfg.clone()), session::connect(a, vec![bp], cfg));
        let mut c = c.unwrap();
        let mut s = s.unwrap();
        let send = tokio::spawn(async move {
            c.stream.write_all(&vec![23; 200_000]).await.unwrap();
            c.stream.shutdown().await.unwrap();
            let mut empty = Vec::new();
            c.stream.read_to_end(&mut empty).await.unwrap();
            c.task.await.unwrap().unwrap()
        });
        s.stream.shutdown().await.unwrap();
        // Exceeds the FIN-ACK linger, but not the configured idle timeout.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let mut got = Vec::new();
        s.stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got.len(), 200_000, "clean FIN must wait for the bounded application write pump");
        assert!(got.iter().all(|b| *b == 23));
        s.task.await.unwrap().unwrap();
        send.await.unwrap();
    })
    .await
    .unwrap();
}
