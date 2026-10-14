#![cfg(feature="runtime")]
use aggligator_fec::session::{self,SessionConfig};
use std::{sync::Arc,time::Duration};
use tokio::{net::UdpSocket,io::{AsyncReadExt,AsyncWriteExt},time::{sleep,timeout}};
#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn alive_but_backpressured_reader_can_pause_longer_than_idle_timeout(){
    timeout(Duration::from_secs(10),async{
        let a=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());let b=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let aa=a.local_addr().unwrap();let bb=b.local_addr().unwrap();let cfg=SessionConfig{idle_timeout:Duration::from_secs(2),..Default::default()};
        let(s,c)=tokio::join!(session::accept(b,vec![aa],cfg.clone()),session::connect(a,vec![bb],cfg));let(mut s,mut c)=(s.unwrap(),c.unwrap());
        let sending=tokio::spawn(async move{
            c.stream.write_all(&vec![8;3_000_000]).await.unwrap();c.stream.shutdown().await.unwrap();
            let mut eof=Vec::new();c.stream.read_to_end(&mut eof).await.unwrap();c.task.await.unwrap().unwrap()
        });
        sleep(Duration::from_millis(3300)).await;
        let mut got=Vec::new();s.stream.read_to_end(&mut got).await.unwrap();assert_eq!(got,vec![8;3_000_000]);
        s.stream.shutdown().await.unwrap();s.task.await.unwrap().unwrap();sending.await.unwrap();
    }).await.unwrap();
}
