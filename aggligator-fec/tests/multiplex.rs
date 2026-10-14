#![cfg(feature="runtime")]
use aggligator_fec::{multiplex::{Hub,Route,LinkSocket,LANES},session::{self,SessionConfig}};
use std::{sync::Arc,time::Duration};
use tokio::{net::UdpSocket,io::{AsyncReadExt,AsyncWriteExt},time::timeout};

async fn socket()->Arc<UdpSocket>{Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())}
#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn concurrent_independent_streams_share_two_real_udp_sockets(){
    timeout(Duration::from_secs(15),async{
        let main=socket().await;let a=socket().await;let b=socket().await;
        let(server,mut incoming)=Hub::server(main.clone(),80,vec![40,40]).unwrap();
        server.set_admission(vec!["127.0.0.1".parse().unwrap()],vec![]).unwrap();
        let client=Hub::client(vec![LinkSocket{socket:a,wire_mbps:40},LinkSocket{socket:b,wire_mbps:40}],80).unwrap();
        let mut routes=vec![None;LANES];routes[0]=Some(Route{socket:0,destination:main.local_addr().unwrap()});routes[8]=Some(Route{socket:1,destination:main.local_addr().unwrap()});client.set_routes(routes).unwrap();
        let cfg=SessionConfig{wire_mbps:80,..Default::default()};
        let expected=4;
        let server_cfg=cfg.clone();
        let acceptor=tokio::spawn(async move{
            let mut tasks=Vec::new();
            for _ in 0..expected{
                let flow=incoming.recv().await.unwrap();let cfg=server_cfg.clone();
                tasks.push(tokio::spawn(async move{
                    let mut s=session::multiplexed(flow,cfg,false).await.unwrap();
                    let mut bytes=Vec::new();s.stream.read_to_end(&mut bytes).await.unwrap();
                    assert_eq!(bytes.len(),300_000);let value=bytes[0];assert!(bytes.iter().all(|b|*b==value));
                    s.stream.write_all(&[value]).await.unwrap();s.stream.shutdown().await.unwrap();
                    s.task.await.unwrap().unwrap()
                }));
            }
            for task in tasks{task.await.unwrap();}
        });
        let mut tasks=Vec::new();
        for value in 1..=expected as u8{
            let c=client.clone();let cfg=cfg.clone();tasks.push(tokio::spawn(async move{
                let mut s=session::multiplexed(c.open().unwrap(),cfg,true).await.unwrap();
                s.stream.write_all(&vec![value;300_000]).await.unwrap();s.stream.shutdown().await.unwrap();
                let mut reply=Vec::new();s.stream.read_to_end(&mut reply).await.unwrap();assert_eq!(reply,[value]);
                let report=s.task.await.unwrap().unwrap();
                assert!(report.path_source_packets[0]>0);assert!(report.path_source_packets[8]>0);
            }));
        }
        for task in tasks{task.await.unwrap();}acceptor.await.unwrap();
        assert_eq!(client.flow_count(),0);assert_eq!(server.flow_count(),0);
    }).await.unwrap();
}
