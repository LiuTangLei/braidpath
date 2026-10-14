#![cfg(feature="runtime")]
use aggligator_fec::session::{self,SessionConfig};
use std::{sync::Arc,time::Duration};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::UdpSocket};
#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn close_after_long_receive_only_phase_gets_a_fresh_fin_deadline() {
    tokio::time::timeout(Duration::from_secs(8),async {
        let a=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());let b=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ap=a.local_addr().unwrap();let bp=b.local_addr().unwrap();
        let cfg=SessionConfig {idle_timeout:Duration::from_secs(2),..SessionConfig::default()};
        let(s,c)=tokio::join!(session::accept(b,vec![ap],cfg.clone()),session::connect(a,vec![bp],cfg));
        let mut c=c.unwrap();let mut s=s.unwrap();
        let server=tokio::spawn(async move {
            let mut request=[0;1];s.stream.read_exact(&mut request).await.unwrap();assert_eq!(request,[1]);
            tokio::time::sleep(Duration::from_millis(2400)).await;
            s.stream.write_all(b"OK").await.unwrap();s.stream.shutdown().await.unwrap();
            let mut rest=Vec::new();s.stream.read_to_end(&mut rest).await.unwrap();s.task.await.unwrap()
        });
        c.stream.write_all(&[1]).await.unwrap();let mut response=Vec::new();c.stream.read_to_end(&mut response).await.unwrap();assert_eq!(response,b"OK");
        c.stream.shutdown().await.unwrap();
        let client_result=c.task.await.unwrap();let server_result=server.await.unwrap();
        assert!(client_result.is_ok(),"{client_result:?}; {server_result:?}");assert!(server_result.is_ok());
    }).await.unwrap();
}
