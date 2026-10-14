#![cfg(feature="runtime")]
use aggligator_fec::{multiplex::{self,Hub,Route,LinkSocket,RelayTable,LANES},session::{self,SessionConfig}};
use std::{sync::{Arc,atomic::{AtomicBool,Ordering}},time::{Duration,Instant}};
use tokio::{net::UdpSocket,io::{AsyncReadExt,AsyncWriteExt},time::{timeout,sleep},task::JoinHandle};
struct Tasks(Vec<JoinHandle<()>>);impl Drop for Tasks{fn drop(&mut self){for task in &self.0{task.abort();}}}
async fn socket()->Arc<UdpSocket>{Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn same_relay_distinguishes_two_wans_and_recovers_after_one_blackout(){
    timeout(Duration::from_secs(15),async{
        let main=socket().await;let relay=socket().await;let a=socket().await;let b=socket().await;
        let main_addr=main.local_addr().unwrap();let relay_addr=relay.local_addr().unwrap();
        let failed=Arc::new(AtomicBool::new(false));let fault=failed.clone();
        let forward=tokio::spawn(async move{
            let mut table=RelayTable::default();let mut buf=[0u8;1600];
            loop{let(n,from)=relay.recv_from(&mut buf).await.unwrap();
                if let Some((_,lane,_))=multiplex::decode(&buf[..n])&&lane<8&&fault.load(Ordering::Relaxed){continue;}
                if let Some(to)=table.route(&buf[..n],from,main_addr,&["127.0.0.1".parse().unwrap()],Instant::now()){
                    relay.send_to(&buf[..n],to).await.unwrap();
                }
            }
        });
        let(server,mut incoming)=Hub::server(main,8,vec![4,4]).unwrap();server.set_admission(vec![],vec![relay_addr]).unwrap();
        let client=Hub::client(vec![LinkSocket{socket:a,wire_mbps:4},LinkSocket{socket:b,wire_mbps:4}],8).unwrap();
        let mut routes=vec![None;LANES];routes[0]=Some(Route{socket:0,destination:relay_addr});routes[8]=Some(Route{socket:1,destination:relay_addr});client.set_routes(routes).unwrap();
        let cfg=SessionConfig{wire_mbps:8,idle_timeout:Duration::from_secs(8),..Default::default()};
        let server_cfg=cfg.clone();let receiving=tokio::spawn(async move{
            let mut s=session::multiplexed(incoming.recv().await.unwrap(),server_cfg,false).await.unwrap();
            let mut bytes=Vec::new();s.stream.read_to_end(&mut bytes).await.unwrap();assert_eq!(bytes,vec![0x7b;3_000_000]);
            s.stream.shutdown().await.unwrap();s.task.await.unwrap().unwrap()
        });
        let changing=tokio::spawn(async move{
            sleep(Duration::from_millis(500)).await;failed.store(true,Ordering::Relaxed);
            sleep(Duration::from_millis(1300)).await;failed.store(false,Ordering::Relaxed);
        });
        let _owned=Tasks(vec![forward,changing]);
        let mut s=session::multiplexed(client.open().unwrap(),cfg,true).await.unwrap();
        s.stream.write_all(&vec![0x7b;3_000_000]).await.unwrap();s.stream.shutdown().await.unwrap();
        let mut eof=Vec::new();s.stream.read_to_end(&mut eof).await.unwrap();
        let report=s.task.await.unwrap().unwrap();let receive_report=receiving.await.unwrap();
        assert!(report.path_source_packets[0]>0&&report.path_source_packets[8]>0);
        assert!(report.tx_retries>0);assert_eq!(receive_report.rx_payload_bytes,3_000_000);
        let last=report.path_samples.last().unwrap();
        let during=report.path_samples.iter().find(|p|p.at_s>=1.7).unwrap();
        assert!(last.source_packets[0]>during.source_packets[0],"first WAN did not recover");
        println!("two-WAN shared relay: 3000000 exact bytes, retries={}, lanes={:?}",report.tx_retries,[report.path_source_packets[0],report.path_source_packets[8]]);
        assert_eq!(client.flow_count(),0);assert_eq!(server.flow_count(),0);
    }).await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn mux_hot_relay_change_preserves_the_same_stream(){
    timeout(Duration::from_secs(12),async{
        let main=socket().await;let old=socket().await;let new=socket().await;let client_socket=socket().await;
        let main_addr=main.local_addr().unwrap();let old_addr=old.local_addr().unwrap();let new_addr=new.local_addr().unwrap();
        let mut jobs=Tasks(Vec::new());
        for relay in [old,new]{jobs.0.push(tokio::spawn(async move{
            let mut table=RelayTable::default();let mut buf=[0;1600];loop{
                let(n,from)=relay.recv_from(&mut buf).await.unwrap();
                if let Some(to)=table.route(&buf[..n],from,main_addr,&["127.0.0.1".parse().unwrap()],Instant::now()){
                    relay.send_to(&buf[..n],to).await.unwrap();
                }
            }
        }));}
        let(server,mut incoming)=Hub::server(main,12,vec![12]).unwrap();server.set_admission(vec![],vec![old_addr,new_addr]).unwrap();
        let client=Hub::client(vec![LinkSocket{socket:client_socket,wire_mbps:12}],12).unwrap();
        let mut routes=vec![None;LANES];routes[0]=Some(Route{socket:0,destination:old_addr});client.set_routes(routes.clone()).unwrap();
        let cfg=SessionConfig{wire_mbps:12,..Default::default()};let server_cfg=cfg.clone();
        let receiving=tokio::spawn(async move{
            let mut s=session::multiplexed(incoming.recv().await.unwrap(),server_cfg,false).await.unwrap();
            let mut bytes=Vec::new();s.stream.read_to_end(&mut bytes).await.unwrap();assert_eq!(bytes,vec![31;3_000_000]);
            s.stream.shutdown().await.unwrap();s.task.await.unwrap().unwrap()
        });
        let c=client.clone();let server2=server.clone();jobs.0.push(tokio::spawn(async move{
            sleep(Duration::from_millis(400)).await;routes[1]=Some(Route{socket:0,destination:new_addr});c.set_routes(routes.clone()).unwrap();
            sleep(Duration::from_millis(350)).await;routes[0]=None;c.set_routes(routes).unwrap();server2.set_admission(vec![],vec![new_addr]).unwrap();
        }));
        let mut s=session::multiplexed(client.open().unwrap(),cfg,true).await.unwrap();s.stream.write_all(&vec![31;3_000_000]).await.unwrap();
        s.stream.shutdown().await.unwrap();let mut eof=Vec::new();s.stream.read_to_end(&mut eof).await.unwrap();
        let tx=s.task.await.unwrap().unwrap();let rx=receiving.await.unwrap();
        assert_eq!(tx.session_id,rx.session_id);assert!(tx.path_source_packets[0]>0&&tx.path_source_packets[1]>0);
        assert!(tx.topology_updates>=2);assert_eq!(client.flow_count(),0);assert_eq!(server.flow_count(),0);
    }).await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn unknown_ids_sources_and_flow_limit_are_bounded(){
    let main=socket().await;let(server,mut incoming)=Hub::server(main.clone(),20,vec![20]).unwrap();
    server.set_admission(vec![],vec![]).unwrap();let attacker=socket().await;
    let mut body=b"AFL1".to_vec();body.push(9);body.extend(1u64.to_be_bytes());body.extend(b"FECSTREAM2");
    let mut wire=b"AFM3".to_vec();wire.extend(7u64.to_be_bytes());wire.push(0);wire.extend(body);
    attacker.send_to(&wire,main.local_addr().unwrap()).await.unwrap();
    assert!(timeout(Duration::from_millis(50),incoming.recv()).await.is_err());assert_eq!(server.flow_count(),0);
    let c=Hub::client(vec![LinkSocket{socket:socket().await,wire_mbps:20}],20).unwrap();let mut flows=Vec::new();
    for _ in 0..multiplex::MAX_FLOWS{flows.push(c.open().unwrap());}
    assert!(c.open().is_err());drop(flows);assert_eq!(c.flow_count(),0);
}
