#![cfg(feature = "runtime")]
use aggligator_fec::{Config,session::{self,SessionConfig}};
use std::{sync::Arc,time::Duration};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::UdpSocket,time::timeout};

async fn pair(cfg:SessionConfig)->(session::Session,session::Session) {
    let a=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let b=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let ap=a.local_addr().unwrap();let bp=b.local_addr().unwrap();
    let (server,client)=tokio::join!(session::accept(b,vec![ap],cfg.clone()),session::connect(a,vec![bp],cfg));
    (client.unwrap(),server.unwrap())
}
fn cfg()->SessionConfig {
    SessionConfig {fec:Config {data_shards:8,repair_shards:4,max_payload:1300,
        max_block_delay:Duration::from_millis(2),..Config::default()},lanes:4,
        wire_mbps:100,nack_delay:Duration::from_millis(10),idle_timeout:Duration::from_secs(5),delivery_aware:true,adaptive_retries:false,low_latency:false}
}
#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn arbitrary_bytes_half_close_and_response_are_exact() {
    timeout(Duration::from_secs(12),async {
        let (mut client,mut server)=pair(cfg()).await;
        let request:Vec<_>=(0..2_000_000).map(|n|(n*17%251) as u8).collect();
        let expected=request.clone();
        let server_task=tokio::spawn(async move {
            let mut bytes=Vec::new();server.stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes,expected);bytes.reverse();
            server.stream.write_all(&bytes).await.unwrap();server.stream.shutdown().await.unwrap();
            server.task.await.unwrap().unwrap()
        });
        client.stream.write_all(&request).await.unwrap();client.stream.shutdown().await.unwrap();
        let mut reply=Vec::new();client.stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply,request.into_iter().rev().collect::<Vec<_>>());
        let client_report=client.task.await.unwrap().unwrap();let server_report=server_task.await.unwrap();
        assert_eq!(client_report.tx_payload_bytes,2_000_000);assert_eq!(client_report.rx_payload_bytes,2_000_000);
        assert_eq!(server_report.rx_payload_bytes,2_000_000);
        assert!(client_report.max_send_history<=8192&&server_report.max_receive_buffer<=8192);
    }).await.expect("byte stream or half-close stalled");
}
#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn loss_reordering_and_a_failed_relay_do_not_corrupt_stream() {
    timeout(Duration::from_secs(12),async {
        let a=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ap=a.local_addr().unwrap();let bp=b.local_addr().unwrap();
        let mut relays=Vec::new();let mut jobs=Vec::new();
        for path in 0..3 {
            let socket=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());relays.push(socket.local_addr().unwrap());
            jobs.push(tokio::spawn(async move {
                let mut buffer=[0;1600];let mut ndata=0;
                loop {
                    let Ok((n,from))=socket.recv_from(&mut buffer).await else{break;};
                    if path==2{continue;}
                    let to=if from==ap{bp}else if from==bp{ap}else{continue;};
                    if matches!(buffer.get(4),Some(1|8)){ndata+=1;if ndata%47==0{continue;}}
                    // Delay one packet at a time via independent timers, allowing reordering.
                    let data=buffer[..n].to_vec();let s=socket.clone();
                    tokio::spawn(async move {tokio::time::sleep(Duration::from_millis(if path==0{2}else{5})).await;let _=s.send_to(&data,to).await;});
                }
            }));
        }
        let c=cfg();let (server,client)=tokio::join!(session::accept(b,relays.clone(),c.clone()),session::connect(a,relays,c));
        let mut client=client.unwrap();let mut server=server.unwrap();
        let data:Vec<u8>=(0..500_000).map(|n|(n*19%253)as u8).collect();let expected=data.clone();
        let rx=tokio::spawn(async move {
            let mut got=Vec::new();server.stream.read_to_end(&mut got).await.unwrap();assert_eq!(got,expected);
            server.stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK").await.unwrap();
            server.stream.shutdown().await.unwrap();server.task.await.unwrap().unwrap()
        });
        client.stream.write_all(&data).await.unwrap();client.stream.shutdown().await.unwrap();
        let mut reply=Vec::new();client.stream.read_to_end(&mut reply).await.unwrap();assert!(reply.ends_with(b"\r\n\r\nOK"));
        let cr=client.task.await.unwrap().unwrap();let sr=rx.await.unwrap();
        assert_eq!(cr.path_source_packets[2],0);assert!(sr.rx_fec_recovered>0||cr.tx_retries>0);
        for job in jobs{job.abort();}
    }).await.expect("loss recovery failed to finish");
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn repeated_sessions_on_same_addresses_do_not_accept_old_stream_data() {
    timeout(Duration::from_secs(10),async {
        let a=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());let ap=a.local_addr().unwrap();let bp=b.local_addr().unwrap();
        let mut old=0;
        for round in 0..2u8 {
            let (server,client)=tokio::join!(session::accept(b.clone(),vec![ap],cfg()),session::connect(a.clone(),vec![bp],cfg()));
            let mut c=client.unwrap();let mut s=server.unwrap();
            let rx=tokio::spawn(async move {let mut v=Vec::new();s.stream.read_to_end(&mut v).await.unwrap();assert_eq!(v,vec![round;333]);s.stream.shutdown().await.unwrap();s.task.await.unwrap().unwrap()});
            c.stream.write_all(&vec![round;333]).await.unwrap();c.stream.shutdown().await.unwrap();
            let mut eof=Vec::new();c.stream.read_to_end(&mut eof).await.unwrap();let r=c.task.await.unwrap().unwrap();rx.await.unwrap();
            assert_ne!(r.session_id,old);old=r.session_id;
        }
    }).await.unwrap();
}
