#![cfg(feature="runtime")]
use aggligator_fec::session::{self,SessionConfig};
use std::{sync::Arc,time::Duration};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::UdpSocket,sync::watch,task::JoinHandle,time::{sleep,timeout}};
struct Owned(Vec<JoinHandle<()>>);
impl Drop for Owned{fn drop(&mut self){for task in &self.0{task.abort();}}}
#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn add_then_remove_a_relay_during_the_same_stream_without_losing_bytes(){
    timeout(Duration::from_secs(12),async{
        let a=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let aa=a.local_addr().unwrap();let bb=b.local_addr().unwrap();
        let mut relays=Vec::new();let mut jobs=Owned(Vec::new());
        for _ in 0..2 {
            let socket=UdpSocket::bind("127.0.0.1:0").await.unwrap();relays.push(socket.local_addr().unwrap());
            jobs.0.push(tokio::spawn(async move{let mut buf=[0;1600];loop{
                let(n,from)=socket.recv_from(&mut buf).await.unwrap();
                let to=if from==aa{bb}else if from==bb{aa}else{continue;};socket.send_to(&buf[..n],to).await.unwrap();
            }}));
        }
        let(tx_a,rx_a)=watch::channel(vec![relays[0]]);let(tx_b,rx_b)=watch::channel(vec![relays[0]]);
        let cfg=SessionConfig{wire_mbps:20,..Default::default()};
        let(s,c)=tokio::join!(session::accept_dynamic(b,rx_b,cfg.clone()),session::connect_dynamic(a,rx_a,cfg));
        let(mut c,mut s)=(c.unwrap(),s.unwrap());
        jobs.0.push(tokio::spawn(async move{
            sleep(Duration::from_millis(250)).await;tx_a.send(vec![relays[0],relays[1]]).unwrap();tx_b.send(vec![relays[0],relays[1]]).unwrap();
            sleep(Duration::from_millis(250)).await;tx_a.send(vec![relays[1]]).unwrap();tx_b.send(vec![relays[1]]).unwrap();
            sleep(Duration::from_secs(6)).await;
        }));
        let send=tokio::spawn(async move{
            c.stream.write_all(&vec![0x73;4_000_000]).await.unwrap();c.stream.shutdown().await.unwrap();
            let mut reply=Vec::new();c.stream.read_to_end(&mut reply).await.unwrap();assert_eq!(reply,b"complete");
            c.task.await.unwrap().unwrap()
        });
        let mut received=Vec::new();s.stream.read_to_end(&mut received).await.unwrap();assert_eq!(received,vec![0x73;4_000_000]);
        s.stream.write_all(b"complete").await.unwrap();s.stream.shutdown().await.unwrap();
        let receiver=s.task.await.unwrap().unwrap();let sender=send.await.unwrap();
        assert_eq!(receiver.session_id,sender.session_id);
        assert!(sender.topology_updates>=2);assert!(receiver.topology_updates>=2);
        assert!(sender.path_source_packets[0]>0&&sender.path_source_packets[1]>0);
        assert!(!sender.path_state[0].live);assert!(sender.path_addresses[1].port()!=0);
        println!("same session {}, 4,000,000 exact bytes, hot changes {}, source slots {:?}",sender.session_id,sender.topology_updates,sender.path_source_packets);
        drop(jobs);
    }).await.unwrap();
}
