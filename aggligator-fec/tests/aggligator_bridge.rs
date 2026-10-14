//! Proof of the adapter boundary against unmodified upstream Aggligator 0.12.1.
//! Three lossy packet lanes form ONE logical reliable packet link. This test
//! guarantees loss stays within FEC capacity; production ARQ, authenticated path
//! admission, MTU negotiation and congestion control are deliberately not implied.
use aggligator::{cfg::Cfg,connect::{connect,Server},io::TxRxBox};
use aggligator_fec::{Config,Decoder,Encoder,Frame};
use bytes::{Buf,Bytes,BytesMut};
use futures::{channel::mpsc,SinkExt,StreamExt};
use std::{collections::BTreeMap,future::IntoFuture,io,time::Duration};
use tokio::{task::JoinHandle,time::{interval,timeout,Instant,MissedTickBehavior}};

struct AbortTasks(Vec<JoinHandle<()>>);
impl Drop for AbortTasks {fn drop(&mut self) {for task in &self.0 {task.abort();}}}

const MAX_PACKET:usize=1024*1024;

async fn deliver(frames:Vec<Frame>,decoder:&mut Decoder,pending:&mut BTreeMap<u64,Bytes>,
                 next:&mut u64,assembly:&mut BytesMut,out:&mut mpsc::Sender<Bytes>)->bool {
    for frame in frames {
        let lane=match &frame {
            Frame::Source {base,index,..}=>(*base+u64::from(*index))%3,
            Frame::Repair {base,data,index,..}=>(*base+u64::from(*data)+u64::from(*index))%3,
        };
        if lane==1 {continue;} // Erase both data and repairs on one complete lane.
        let frame=Frame::decode(&frame.encode().unwrap(),1400).unwrap();
        for packet in decoder.input(&frame).unwrap() {
            if packet.seq>=*next {pending.entry(packet.seq).or_insert(Bytes::from(packet.payload));}
        }
        while let Some(chunk)=pending.remove(next) {
            *next+=1;
            assembly.extend_from_slice(&chunk);
            assert!(assembly.len()<=MAX_PACKET+1404);
            while assembly.len()>=4 {
                let len=u32::from_be_bytes(assembly[..4].try_into().unwrap()) as usize;
                assert!(len<=MAX_PACKET);
                if assembly.len()<4+len {break;}
                assembly.advance(4);
                let packet=assembly.split_to(len).freeze();
                if out.send(packet).await.is_err() {return false;}
            }
        }
        assert!(pending.len()<=64);
    }
    true
}

fn fec_direction()->(TxRxBox,JoinHandle<()>) {
    let (input,mut rx)=mpsc::channel::<Bytes>(32);
    let (mut output,received)=mpsc::channel::<Bytes>(32);
    let task=tokio::spawn(async move {
        let cfg=Config {data_shards:8,repair_shards:8,max_payload:1400,..Config::default()};
        let mut enc=Encoder::new(cfg.clone()).unwrap();
        let mut dec=Decoder::new(cfg).unwrap();
        let mut pending=BTreeMap::new();
        let mut assembly=BytesMut::new();
        let mut next=0;
        let start=Instant::now();
        let mut tick=interval(Duration::from_millis(1));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            let frames=tokio::select! {
                packet=rx.next()=>match packet {
                    Some(packet)=>{
                        // Upstream link tests alone can produce ~64KiB packets.
                        // Preserve packet boundaries but NEVER put a jumbo on UDP.
                        assert!(packet.len()<=MAX_PACKET);
                        let mut framed=Vec::with_capacity(packet.len()+4);
                        framed.extend_from_slice(&(packet.len() as u32).to_be_bytes());
                        framed.extend_from_slice(&packet);
                        let now=start.elapsed();
                        let mut frames=Vec::new();
                        for chunk in framed.chunks(1100) {frames.extend(enc.push(chunk.to_vec(),now).unwrap());}
                        frames
                    },
                    None=>{
                        let frames=enc.flush().unwrap();
                        deliver(frames,&mut dec,&mut pending,&mut next,&mut assembly,&mut output).await;
                        break;
                    }
                },
                _=tick.tick()=>enc.poll(start.elapsed()).unwrap(),
            };
            if !deliver(frames,&mut dec,&mut pending,&mut next,&mut assembly,&mut output).await {break;}
        }
    });
    let tx=input.sink_map_err(|_|io::Error::new(io::ErrorKind::BrokenPipe,"FEC test pipe closed"));
    let rx=received.map(Ok::<_,io::Error>);
    (TxRxBox::new(tx,rx),task)
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn upstream_handshake_data_echo_and_graceful_close_over_cross_path_fec() {
    let (ab,task_ab)=fec_direction();
    let (ba,task_ba)=fec_direction();
    let _tasks=AbortTasks(vec![task_ab,task_ba]);
    let server=async move {
        let server=Server::new(Cfg::default());
        let mut listener=server.listen().unwrap();
        let _link=server.add_incoming(ba.tx,ab.rx,"fec-incoming",&[],None).await.unwrap();
        let incoming=listener.next().await.unwrap();
        let (task,ch,control)=incoming.accept();
        let task=tokio::spawn(task.into_future());
        let (tx,mut rx)=ch.into_tx_rx();
        for i in 0..128u8 {
            let payload=rx.recv().await.unwrap().unwrap();
            assert_eq!(payload,Bytes::from(vec![i;300]));
            tx.send(payload).await.unwrap();
        }
        drop(tx);
        assert!(rx.recv().await.unwrap().is_none());
        control.terminated().await.unwrap();
        task.await.unwrap().unwrap();
    };
    let client=async move {
        let (task,outgoing,control)=connect(Cfg::default());
        let task=tokio::spawn(task.into_future());
        control.add(ab.tx,ba.rx,"fec-outgoing",&[],None).await.unwrap();
        let ch=outgoing.connect().await.unwrap();
        let (tx,mut rx)=ch.into_tx_rx();
        for i in 0..128u8 {
            let payload=Bytes::from(vec![i;300]);
            tx.send(payload.clone()).await.unwrap();
            assert_eq!(rx.recv().await.unwrap().unwrap(),payload);
        }
        drop(tx);
        assert!(rx.recv().await.unwrap().is_none());
        control.terminated().await.unwrap();
        task.await.unwrap().unwrap();
    };
    timeout(Duration::from_secs(10),async {tokio::join!(server,client);}).await
        .expect("upstream Aggligator handshake/data/close did not finish over the FEC bridge");
    println!("unmodified upstream 0.12.1: handshake + 128 exact bidirectional echoes + graceful close; one of three lanes erased");
}
