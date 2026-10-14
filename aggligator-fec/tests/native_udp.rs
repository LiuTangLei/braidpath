#![cfg(feature="runtime")]
use aggligator_fec::{Frame, session::SessionConfig, udp_tunnel};
use std::{sync::Arc,time::Duration};
use tokio::{net::UdpSocket,task::JoinHandle,time::{sleep,timeout}};

struct Owned(Vec<JoinHandle<()>>);
impl Drop for Owned {fn drop(&mut self){for task in &self.0{task.abort();}}}

async fn sockets()->(Arc<UdpSocket>,Arc<UdpSocket>,Arc<UdpSocket>,Arc<UdpSocket>,Arc<UdpSocket>,Arc<UdpSocket>){
    let mut out=Vec::new();for _ in 0..6{out.push(Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()));}
    (out[0].clone(),out[1].clone(),out[2].clone(),out[3].clone(),out[4].clone(),out[5].clone())
}
fn spawn_run(net:Arc<UdpSocket>,peer:std::net::SocketAddr,app:Arc<UdpSocket>,target:Option<std::net::SocketAddr>,cfg:SessionConfig,client:bool)->JoinHandle<()> {
    tokio::spawn(async move{let r=udp_tunnel::run(net,vec![peer],app,target,cfg,client).await;panic!("UDP runtime exited unexpectedly: {r:?}");})
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn exact_bidirectional_udp_including_empty_and_fragmented_datagrams(){
    timeout(Duration::from_secs(8),async{
        let(a,b,la,lb,user,service)=sockets().await;
        let cfg=SessionConfig::default();
        let jobs=Owned(vec![spawn_run(a.clone(),b.local_addr().unwrap(),la.clone(),None,cfg.clone(),true),
            spawn_run(b,a.local_addr().unwrap(),lb,Some(service.local_addr().unwrap()),cfg,false)]);
        sleep(Duration::from_millis(120)).await;
        // Keep loopback writes below macOS's per-datagram socket ceiling;
        // the protocol's 65507-byte reassembly bound is unit-tested separately.
        for size in [0,1,148,92,32,1200,1420,4096,8192]{
            let payload:Vec<_>=(0..size).map(|i|(i*17%251)as u8).collect();
            user.send_to(&payload,la.local_addr().unwrap()).await.unwrap();
            let mut buf=vec![0;65536];let(n,reply)=timeout(Duration::from_secs(1),service.recv_from(&mut buf)).await.unwrap().unwrap();
            assert_eq!(&buf[..n],payload);
            service.send_to(&buf[..n],reply).await.unwrap();
            let n=timeout(Duration::from_secs(1),user.recv(&mut buf)).await.unwrap().unwrap();assert_eq!(&buf[..n],payload);
        }
        drop(jobs);
    }).await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn irrecoverable_missing_datagram_does_not_hold_next_datagram(){
    timeout(Duration::from_secs(6),async{
        let(a,b,la,lb,user,service)=sockets().await;
        let relay=UdpSocket::bind("127.0.0.1:0").await.unwrap();let relay_addr=relay.local_addr().unwrap();
        let aa=a.local_addr().unwrap();let bb=b.local_addr().unwrap();
        let mut cfg=SessionConfig::default();cfg.fec.data_shards=1;cfg.fec.repair_shards=0;cfg.lanes=1;
        let forward=tokio::spawn(async move{let mut buf=[0;1600];loop{
            let(n,from)=relay.recv_from(&mut buf).await.unwrap();let to=if from==aa{bb}else{aa};
            if from==aa&&n>=13&&buf[4]==22&&let Ok(Frame::Source{payload,..})=Frame::decode(&buf[13..n],1300)
                &&payload.len()>=16&&payload[..8]==0u64.to_be_bytes(){continue;}
            relay.send_to(&buf[..n],to).await.unwrap();
            if n>=13&&buf[4]==22{relay.send_to(&buf[..n],to).await.unwrap();} // Duplicate every forwarded symbol.
        }});
        let jobs=Owned(vec![forward,spawn_run(a,relay_addr,la.clone(),None,cfg.clone(),true),
            spawn_run(b,relay_addr,lb,Some(service.local_addr().unwrap()),cfg,false)]);
        sleep(Duration::from_millis(120)).await;
        user.send_to(b"lost",la.local_addr().unwrap()).await.unwrap();
        user.send_to(b"later",la.local_addr().unwrap()).await.unwrap();
        let mut buf=[0;100];let n=timeout(Duration::from_millis(150),service.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n],b"later");assert!(timeout(Duration::from_millis(100),service.recv(&mut buf)).await.is_err());
        drop(jobs);
    }).await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn parity_recovers_missing_original_without_a_retransmission(){
    timeout(Duration::from_secs(6),async{
        let(a,b,la,lb,user,service)=sockets().await;
        let relay=UdpSocket::bind("127.0.0.1:0").await.unwrap();let relay_addr=relay.local_addr().unwrap();
        let aa=a.local_addr().unwrap();let bb=b.local_addr().unwrap();
        let mut cfg=SessionConfig::default();cfg.fec.data_shards=1;cfg.fec.repair_shards=1;cfg.lanes=1;
        let forward=tokio::spawn(async move{let mut buf=[0;1600];loop{
            let(n,from)=relay.recv_from(&mut buf).await.unwrap();let to=if from==aa{bb}else{aa};
            if from==aa&&n>=13&&buf[4]==22&&matches!(Frame::decode(&buf[13..n],1300),Ok(Frame::Source{..})){continue;}
            relay.send_to(&buf[..n],to).await.unwrap();
        }});
        let jobs=Owned(vec![forward,spawn_run(a,relay_addr,la.clone(),None,cfg.clone(),true),
            spawn_run(b,relay_addr,lb,Some(service.local_addr().unwrap()),cfg,false)]);
        sleep(Duration::from_millis(120)).await;
        user.send_to(b"parity only",la.local_addr().unwrap()).await.unwrap();
        let mut buf=[0;100];let n=timeout(Duration::from_millis(150),service.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n],b"parity only");drop(jobs);
    }).await.unwrap();
}
