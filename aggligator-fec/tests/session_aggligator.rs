#![cfg(feature="runtime")]
//! Actual reliable UDP session handed to unmodified upstream stream-link API.
use aggligator::{cfg::Cfg,connect::{connect,Server}};
use aggligator_fec::session::{self,SessionConfig};
use bytes::Bytes;
use std::{future::IntoFuture,sync::Arc,time::Duration};
use tokio::net::UdpSocket;
#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn original_aggregation_handshake_payload_and_close_over_real_session() {
    tokio::time::timeout(Duration::from_secs(10),async {
        let a=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());let b=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ap=a.local_addr().unwrap();let bp=b.local_addr().unwrap();let cfg=SessionConfig::default();
        let(s,c)=tokio::join!(session::accept(b,vec![ap],cfg.clone()),session::connect(a,vec![bp],cfg));
        let s=s.unwrap();let c=c.unwrap();
        let server=async move {
            let(read,write)=tokio::io::split(s.stream);
            let server=Server::new(Cfg::default());let mut listener=server.listen().unwrap();
            let _link=server.add_incoming_io(read,write,"udp-fec",&[],None).await.unwrap();
            let incoming=listener.next().await.unwrap();let(task,ch,control)=incoming.accept();
            let running=tokio::spawn(task.into_future());let(tx,mut rx)=ch.into_tx_rx();
            for _ in 0..32 {let p=rx.recv().await.unwrap().unwrap();tx.send(p).await.unwrap();}
            drop(tx);assert!(rx.recv().await.unwrap().is_none());control.terminated().await.unwrap();running.await.unwrap().unwrap();
            s.task.await.unwrap().unwrap()
        };
        let client=async move {
            let(read,write)=tokio::io::split(c.stream);let(task,outgoing,control)=connect(Cfg::default());let running=tokio::spawn(task.into_future());
            control.add_io(read,write,"udp-fec",&[],None).await.unwrap();
            let ch=outgoing.connect().await.unwrap();let(tx,mut rx)=ch.into_tx_rx();
            for i in 0..32u8 {let bytes=Bytes::from(vec![i;32000]);tx.send(bytes.clone()).await.unwrap();assert_eq!(rx.recv().await.unwrap().unwrap(),bytes);}
            drop(tx);assert!(rx.recv().await.unwrap().is_none());control.terminated().await.unwrap();running.await.unwrap().unwrap();
            c.task.await.unwrap().unwrap()
        };
        let(sr,cr)=tokio::join!(server,client);assert!(sr.rx_payload_bytes>1024000&&cr.rx_payload_bytes>1024000);
    }).await.expect("upstream real-session adapter stalled");
}
