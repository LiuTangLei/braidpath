#![cfg(feature="runtime")]
//! Actual loopback UDP with enforced sender budgets, not Internet bandwidth.
use aggligator_fec::{Config,multiplex::{Hub,LinkSocket,Route,LANES},session::{self,SessionConfig}};
use std::{sync::Arc,time::{Duration,Instant}};
use tokio::{net::UdpSocket,io::{AsyncReadExt,AsyncWriteExt},time::timeout};
async fn socket()->Arc<UdpSocket>{Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())}
async fn measure(count:usize)->f64{
    let main=socket().await;let addr=main.local_addr().unwrap();
    let(server,mut incoming)=Hub::server(main,20,vec![10;count]).unwrap();
    server.set_admission(vec!["127.0.0.1".parse().unwrap()],vec![]).unwrap();
    let mut sockets=Vec::new();for _ in 0..count{sockets.push(LinkSocket{socket:socket().await,wire_mbps:10});}
    let client=Hub::client(sockets,20).unwrap();let mut routes=vec![None;LANES];
    for i in 0..count{routes[i*8]=Some(Route{socket:i,destination:addr});}client.set_routes(routes).unwrap();
    let cfg=SessionConfig{fec:Config{data_shards:8,repair_shards:1,max_block_delay:Duration::from_millis(2),..Config::default()},lanes:1,wire_mbps:20,..Default::default()};
    let server_cfg=cfg.clone();let receiving=tokio::spawn(async move{
        let mut s=session::multiplexed(incoming.recv().await.unwrap(),server_cfg,false).await.unwrap();
        let mut bytes=Vec::new();s.stream.read_to_end(&mut bytes).await.unwrap();let end=Instant::now();
        assert_eq!(bytes,vec![0x1c;4*1024*1024]);s.stream.shutdown().await.unwrap();s.task.await.unwrap().unwrap();end
    });
    let mut s=session::multiplexed(client.open().unwrap(),cfg,true).await.unwrap();let start=Instant::now();
    s.stream.write_all(&vec![0x1c;4*1024*1024]).await.unwrap();s.stream.shutdown().await.unwrap();
    let mut eof=Vec::new();s.stream.read_to_end(&mut eof).await.unwrap();s.task.await.unwrap().unwrap();
    let elapsed=receiving.await.unwrap().duration_since(start).as_secs_f64();
    assert_eq!(server.flow_count(),0);4.0*1024.0*1024.0*8.0/elapsed/1e6
}
#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn two_independent_ten_megabit_accesses_exceed_one_without_multiplying_each_budget(){
    timeout(Duration::from_secs(25),async{
        let single=measure(1).await;let dual=measure(2).await;
        println!("actual loopback FEC throughput: one 10Mbps access={single:.3}Mbps, two 10Mbps accesses={dual:.3}Mbps");
        assert!(single<10.5&&dual<20.5,"wire caps exceeded");
        assert!(dual>single*1.35,"second independent WAN did not aggregate capacity");
    }).await.unwrap();
}
