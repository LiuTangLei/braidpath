#![cfg(feature="runtime")]
use aggligator_fec::{multiplex::{Hub,Route,LinkSocket,LANES},session::{self,SessionConfig}};
use std::{sync::Arc,time::Duration};
use tokio::{net::UdpSocket,io::{AsyncReadExt,AsyncWriteExt},time::timeout};

async fn socket()->Arc<UdpSocket>{Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn abort_releases_both_flow_slots_even_when_first_cancel_packets_are_lost(){
    timeout(Duration::from_secs(8),async{
        let main=socket().await;let access=socket().await;let relay=socket().await;
        let ma=main.local_addr().unwrap();let ca=access.local_addr().unwrap();let ra=relay.local_addr().unwrap();
        let forward=tokio::spawn(async move{
            let mut lost=0;let mut bytes=[0;1600];
            loop{
                let(n,from)=relay.recv_from(&mut bytes).await.unwrap();
                if from==ca&&n>=26&&bytes[17]==13&&lost<2{lost+=1;continue;}
                relay.send_to(&bytes[..n],if from==ca{ma}else{ca}).await.unwrap();
            }
        });
        let(server,mut incoming)=Hub::server(main,80,vec![80]).unwrap();
        server.set_admission(vec!["127.0.0.1".parse().unwrap()],vec![]).unwrap();
        let client=Hub::client(vec![LinkSocket{socket:access,wire_mbps:80}],80).unwrap();
        let mut routes=vec![None;LANES];routes[0]=Some(Route{socket:0,destination:ra});client.set_routes(routes).unwrap();
        let cf=client.open().unwrap();
        let c=tokio::spawn(session::multiplexed(cf,SessionConfig::default(),true));
        let mut s=session::multiplexed(incoming.recv().await.unwrap(),SessionConfig::default(),false).await.unwrap();
        let mut c=c.await.unwrap().unwrap();
        c.stream.write_all(b"hello").await.unwrap();let mut got=[0;5];s.stream.read_exact(&mut got).await.unwrap();assert_eq!(&got,b"hello");
        c.task.abort();let _=c.task.await;drop(c.stream);
        let result=timeout(Duration::from_secs(2),s.task).await.expect("remote kept aborted flow until the old 20-second timeout").unwrap();
        assert!(result.is_err());drop(s.stream);
        assert_eq!(client.flow_count(),0);assert_eq!(server.flow_count(),0);
        forward.abort();
    }).await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn cancel_cannot_allocate_a_new_flow(){
    let main=socket().await;let other=socket().await;
    let(server,_incoming)=Hub::server(main.clone(),80,vec![80]).unwrap();
    server.set_admission(vec!["127.0.0.1".parse().unwrap()],vec![]).unwrap();
    let mut bytes=b"AFM3".to_vec();bytes.extend(7u64.to_be_bytes());bytes.push(0);
    bytes.extend(b"AFL1");bytes.push(13);bytes.extend(9u64.to_be_bytes());
    other.send_to(&bytes,main.local_addr().unwrap()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(server.flow_count(),0);
}
