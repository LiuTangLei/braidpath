//! Real loopback UDP sockets: client <-> three transparent relays <-> A.
//! Fault injection inspects the frame solely to choose repeatable losses; bytes
//! forwarded by the relay are otherwise unchanged. No public listeners are used.
use aggligator_fec::{Config,Decoder,Encoder,Frame};
use std::{collections::BTreeMap,net::SocketAddr,sync::{Arc,atomic::{AtomicBool,Ordering}},time::Duration};
use tokio::{net::UdpSocket,task::JoinHandle,time::{sleep,timeout}};

struct AbortTasks(Vec<JoinHandle<()>>);
impl Drop for AbortTasks {
    fn drop(&mut self) {for task in &self.0 {task.abort();}}
}
struct Topology {
    client:Arc<UdpSocket>,main:Arc<UdpSocket>,relays:Vec<SocketAddr>,
    loss_active:Arc<AtomicBool>,_tasks:AbortTasks,
}
impl Topology {
    async fn new(excessive_loss:bool)->Self {
        let client=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let main=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr=client.local_addr().unwrap();
        let main_addr=main.local_addr().unwrap();
        let loss_active=Arc::new(AtomicBool::new(true));
        let mut tasks=Vec::new();
        let mut relays=Vec::new();
        for path in 0..3usize {
            let socket=UdpSocket::bind("127.0.0.1:0").await.unwrap();
            relays.push(socket.local_addr().unwrap());
            let active=loss_active.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf=[0u8;1500];
                loop {
                    let (n,from)=socket.recv_from(&mut buf).await.unwrap();
                    let target=if from==client_addr {main_addr} else if from==main_addr {client_addr} else {continue;};
                    if active.load(Ordering::Acquire) {
                        if excessive_loss {
                            if matches!(Frame::decode(&buf[..n],1100),Ok(Frame::Source {index:0..=2,..})) {continue;}
                        } else {
                            // Erase an ENTIRE path, including its parity. On the other
                            // two, also erase occasional original data packets.
                            if path==1 {continue;}
                            if let Ok(Frame::Source {base,index,..})=Frame::decode(&buf[..n],1100)
                                && (base+u64::from(index))%7==0 {continue;}
                        }
                    }
                    socket.send_to(&buf[..n],target).await.unwrap();
                }
            }));
        }
        Self {client,main,relays,loss_active,_tasks:AbortTasks(tasks)}
    }
    async fn send(&self,socket:&UdpSocket,frame:&Frame,alternate:bool) {
        let path=match frame {
            Frame::Source {base,index,..} => ((*base+u64::from(*index)+u64::from(alternate))%3) as usize,
            Frame::Repair {base,data,index,..} => ((*base+u64::from(*data)+u64::from(*index))%3) as usize,
        };
        socket.send_to(&frame.encode().unwrap(),self.relays[path]).await.unwrap();
    }
}

fn contents(seq:u64)->Vec<u8> {
    let mut out=vec![(seq%251) as u8;250+(seq%17) as usize];
    out[..8].copy_from_slice(&seq.to_be_bytes());
    out
}
async fn receive(socket:Arc<UdpSocket>,cfg:Config,count:usize)->(BTreeMap<u64,Vec<u8>>,usize) {
    let mut dec=Decoder::new(cfg).unwrap();
    let mut values=BTreeMap::new();
    let mut recovered=0;
    let mut buf=[0u8;1500];
    while values.len()<count {
        let n=socket.recv(&mut buf).await.unwrap();
        let frame=Frame::decode(&buf[..n],1100).unwrap();
        for item in dec.input(&frame).unwrap() {
            assert!(item.seq<count as u64);
            assert_eq!(item.payload,contents(item.seq));
            if !values.contains_key(&item.seq) && item.recovered {recovered+=1;}
            if let Some(old)=values.insert(item.seq,item.payload.clone()) {assert_eq!(old,item.payload);}
        }
    }
    (values,recovered)
}

async fn direction(reverse:bool) {
    let network=Topology::new(false).await;
    let cfg=Config {data_shards:8,repair_shards:8,..Config::default()};
    let (sender,receiver)=if reverse {(&network.main,network.client.clone())} else {(&network.client,network.main.clone())};
    let mut enc=Encoder::new(cfg.clone()).unwrap();
    let recv=tokio::spawn(receive(receiver,cfg,128));
    for seq in 0..128 {
        for frame in enc.push(contents(seq),Duration::ZERO).unwrap() {network.send(sender,&frame,false).await;}
        // Bound instantaneous socket pressure; this is not a throughput test.
        if seq%8==7 {sleep(Duration::from_millis(1)).await;}
    }
    let (values,recovered)=timeout(Duration::from_secs(3),recv).await.expect("FEC did not repair a path erasure").unwrap();
    assert_eq!(values.len(),128);
    assert!(recovered>40);
    for seq in 0..128 {assert_eq!(values[&seq],contents(seq));}
    println!("real UDP {}: 128/128 exact payloads, {recovered} FEC repairs, 0 source retransmits, one whole relay erased",
        if reverse {"A -> client"} else {"client -> A"});
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn three_transparent_udp_relays_recover_both_directions() {
    direction(false).await;
    direction(true).await;
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn beyond_fec_capacity_needs_a_source_retransmit_not_path_reset() {
    let network=Topology::new(true).await;
    let cfg=Config {data_shards:4,repair_shards:2,..Config::default()};
    let mut enc=Encoder::new(cfg.clone()).unwrap();
    let mut frames=Vec::new();
    for seq in 0..4 {frames.extend(enc.push(contents(seq),Duration::ZERO).unwrap());}
    let mut decoder=Decoder::new(cfg).unwrap();
    let mut received=BTreeMap::new();
    for frame in &frames {network.send(&network.client,frame,false).await;}
    let mut buf=[0u8;1500];
    // Exactly three codeword shards arrive: one data + two repair, below k=4.
    for _ in 0..3 {
        let n=timeout(Duration::from_secs(2),network.main.recv(&mut buf)).await.unwrap().unwrap();
        for item in decoder.input(&Frame::decode(&buf[..n],1100).unwrap()).unwrap() {
            received.insert(item.seq,item.payload);
        }
    }
    assert_eq!(received.len(),1,"must not claim complete delivery beyond the erasure budget");
    assert!(received.contains_key(&3));
    // A bounded, explicit packet retry supplies the missing degree of freedom.
    // This tests the integration point; it is NOT a production ACK/ARQ runtime.
    network.loss_active.store(false,Ordering::Release);
    network.send(&network.client,&frames[0],true).await;
    let n=timeout(Duration::from_secs(2),network.main.recv(&mut buf)).await.unwrap().unwrap();
    for item in decoder.input(&Frame::decode(&buf[..n],1100).unwrap()).unwrap() {
        received.insert(item.seq,item.payload);
    }
    for seq in 0..4 {assert_eq!(received[&seq],contents(seq));}
    println!("real UDP over-budget loss: 4/4 exact payloads after one cross-path source retry; no relay/path reset");
}
