#![cfg(feature = "runtime")]
use aggligator_fec::session::{self, SessionConfig};
use std::{sync::Arc, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UdpSocket, time::timeout};

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn missing_old_probes_do_not_kill_an_active_stream() {
    timeout(Duration::from_secs(12), async {
        let a=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay=UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (aa,bb,rr)=(a.local_addr().unwrap(),b.local_addr().unwrap(),relay.local_addr().unwrap());
        let forwarding=tokio::spawn(async move {
            let mut buf=[0;1600];let mut pongs=0usize;
            loop {
                let (n,from)=relay.recv_from(&mut buf).await.unwrap();
                if n>=13 && buf[4]==3 {
                    pongs+=1;
                    // Lose old probes in both directions, while newer probes and
                    // payload continue to arrive. No packet loss is injected into data.
                    if pongs%6<2 {continue;}
                }
                let dest=if from==aa {bb} else if from==bb {aa} else {continue;};
                relay.send_to(&buf[..n],dest).await.unwrap();
            }
        });
        let cfg=SessionConfig{wire_mbps:20,idle_timeout:Duration::from_secs(4),..SessionConfig::default()};
        let (s,c)=tokio::join!(session::accept(b,vec![rr],cfg.clone()),session::connect(a,vec![rr],cfg));
        let (mut s,mut c)=(s.unwrap(),c.unwrap());
        let sending=tokio::spawn(async move {
            c.stream.write_all(&vec![0x5d;3_000_000]).await.unwrap();
            c.stream.shutdown().await.unwrap();let mut eof=Vec::new();c.stream.read_to_end(&mut eof).await.unwrap();
            c.task.await.unwrap()
        });
        let mut bytes=Vec::new();s.stream.read_to_end(&mut bytes).await.unwrap();
        s.stream.shutdown().await.unwrap();let result=s.task.await.unwrap();
        assert_eq!(bytes,vec![0x5d;3_000_000]);assert!(result.is_ok(),"{result:?}");
        let result=sending.await.unwrap();assert!(result.is_ok(),"{result:?}");
        forwarding.abort();
    }).await.unwrap();
}
