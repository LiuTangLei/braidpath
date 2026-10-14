//! Experimental unordered, fixed-peer UDP/FEC forwarding.
//!
//! This is NOT UDP through the reliable byte-stream adapter: every complete
//! datagram is delivered independently. There is no ARQ or global ordered wait.
//! Incomplete fragments expire; queues and replay state are bounded. No outer
//! authentication/encryption is provided. Only provisioned peers and one local
//! application endpoint are admitted. A random session ID is not authentication.
use crate::{
    Decoder, Frame,
    datagram::{Datagram, try_send_batch},
    delivery::{DeliveryReceiver, DeliverySender, RawReceipt},
    interleave::{InterleavedEncoder, decode, source_sequence},
    pacing::PacingClock,
    path::PathScheduler,
    session::SessionConfig,
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}, mpsc},
    thread,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

const HEADER: usize = 13;
const FRAGMENT: usize = 16;
const MAX_DATAGRAM: usize = 65_507;
const MAX_QUEUE: usize = 512;
const MAX_ASSEMBLIES: usize = 256;
const MAX_ASSEMBLY_BYTES: usize = 8 * 1024 * 1024;
const MAX_AGE: Duration = Duration::from_millis(200);
const HELLO: u8 = 20;
const ACCEPT: u8 = 21;
const DATA: u8 = 22;
const PING: u8 = 23;
const PONG: u8 = 24;
const RECEIPT: u8 = 25;

fn error(value: impl std::fmt::Display) -> io::Error { io::Error::other(value.to_string()) }
fn envelope(kind: u8, id: u64, payload: &[u8]) -> Vec<u8> {
    let mut out=Vec::with_capacity(HEADER+payload.len());
    out.extend_from_slice(b"AFL1");out.push(kind);out.extend_from_slice(&id.to_be_bytes());out.extend_from_slice(payload);out
}
fn parse(bytes: &[u8]) -> Option<(u8,u64,&[u8])> {
    if bytes.len()<HEADER || &bytes[..4]!=b"AFL1" { return None; }
    Some((bytes[4],u64::from_be_bytes(bytes[5..13].try_into().ok()?),&bytes[13..]))
}
fn admit(peers: &mut [SocketAddr], from: SocketAddr, learn: bool) -> Option<usize> {
    if let Some(path)=peers.iter().position(|p| *p==from) { return Some(path); }
    if !learn { return None; }
    let path=peers.iter().position(|p|p.port()==0 && p.ip()==from.ip())?;
    peers[path]=from;Some(path)
}
fn hello(cfg: &SessionConfig) -> Vec<u8> {
    let mut bytes=b"FECUDP1".to_vec();
    bytes.extend_from_slice(&[cfg.fec.data_shards as u8,cfg.fec.repair_shards as u8,cfg.lanes as u8]);
    bytes.extend_from_slice(&(cfg.fec.max_payload as u16).to_be_bytes());bytes
}
async fn handshake(socket: &UdpSocket, peers: &mut [SocketAddr], cfg: &SessionConfig, initiator: bool) -> io::Result<u64> {
    let id=rand::random::<u64>().max(1);let expected=hello(cfg);
    let deadline=tokio::time::Instant::now()+Duration::from_secs(10);
    let mut timer=tokio::time::interval(Duration::from_millis(100));
    let mut buf=[0u8;1600];
    loop {
        tokio::select! {
            _=tokio::time::sleep_until(deadline)=>return Err(io::Error::new(io::ErrorKind::TimedOut,"UDP FEC handshake timeout")),
            _=timer.tick()=>{
                for peer in peers.iter().filter(|p|p.port()!=0) {
                    socket.send_to(&envelope(0,0,&[]),peer).await?;
                    if initiator {socket.send_to(&envelope(HELLO,id,&expected),peer).await?;}
                }
            },
            received=socket.recv_from(&mut buf)=>{
                let(n,from)=received?;let Some((kind,sid,body))=parse(&buf[..n]) else{continue;};
                let learn=(kind==0&&sid==0&&body.is_empty())||(kind==HELLO&&sid!=0&&body==expected);
                if admit(peers,from,learn).is_none(){continue;}
                if !initiator&&kind==HELLO&&sid!=0&&body==expected {
                    socket.send_to(&envelope(ACCEPT,sid,&expected),from).await?;return Ok(sid);
                }
                if initiator&&kind==ACCEPT&&sid==id&&body==expected {return Ok(id);}
            }
        }
    }
}

/// Bounded sliding replay gate, independent of FEC retention and application delivery.
struct Replay { high: Option<u64>, tags: Vec<Option<u64>> }
impl Replay {
    fn new(size: usize) -> Self {Self{high:None,tags:vec![None;size]}}
    fn accepts(&self,seq:u64)->bool {
        if self.high.is_some_and(|h|h.saturating_sub(seq)>=self.tags.len() as u64){return false;}
        self.tags[seq as usize%self.tags.len()]!=Some(seq)
    }
    fn mark(&mut self,seq:u64)->bool {
        if !self.accepts(seq){return false;}
        self.high=Some(self.high.map_or(seq,|h|h.max(seq)));
        let slot=seq as usize%self.tags.len();self.tags[slot]=Some(seq);true
    }
}
struct Assembly { started:Instant,total:usize,bytes:Vec<u8>,seen:Vec<bool>,remaining:usize }
struct Reassembly {chunk:usize,pending:BTreeMap<u64,Assembly>,bytes:usize,delivered:Replay}
impl Reassembly {
    fn new(chunk:usize)->Self {Self{chunk,pending:BTreeMap::new(),bytes:0,delivered:Replay::new(8192)}}
    fn expire(&mut self,now:Instant) {
        let mut released=0;
        self.pending.retain(|_,p|{
            if now.saturating_duration_since(p.started)>=MAX_AGE {released+=p.total;false}else{true}
        });
        self.bytes-=released;
    }
    fn input(&mut self,payload:&[u8],now:Instant)->Option<Vec<u8>> {
        if payload.len()<FRAGMENT{return None;}
        let id=u64::from_be_bytes(payload[..8].try_into().ok()?);
        let total=u32::from_be_bytes(payload[8..12].try_into().ok()?) as usize;
        let offset=u32::from_be_bytes(payload[12..16].try_into().ok()?) as usize;
        let body=&payload[FRAGMENT..];
        if total>MAX_DATAGRAM||offset>total||!offset.is_multiple_of(self.chunk)
            ||body.len()!=self.chunk.min(total-offset)||!self.delivered.accepts(id){return None;}
        if total==0 {
            if offset!=0||!body.is_empty(){return None;}
            self.delivered.mark(id);return Some(Vec::new());
        }
        if offset==total{return None;}
        if !self.pending.contains_key(&id) {
            self.expire(now);
            if self.pending.len()>=MAX_ASSEMBLIES||self.bytes+total>MAX_ASSEMBLY_BYTES{return None;}
            let count=total.div_ceil(self.chunk);
            self.pending.insert(id,Assembly{started:now,total,bytes:vec![0;total],seen:vec![false;count],remaining:count});
            self.bytes+=total;
        }
        let entry=self.pending.get_mut(&id)?;
        if entry.total!=total{return None;}
        let index=offset/self.chunk;
        if !entry.seen[index] {
            entry.bytes[offset..offset+body.len()].copy_from_slice(body);
            entry.seen[index]=true;entry.remaining-=1;
        }
        if entry.remaining!=0{return None;}
        let entry=self.pending.remove(&id)?;self.bytes-=entry.total;
        self.delivered.mark(id);Some(entry.bytes)
    }
}
#[derive(Default)]
pub struct UdpCounters {
    pub app_rx:AtomicU64,pub app_tx:AtomicU64,pub app_rx_bytes:AtomicU64,pub app_tx_bytes:AtomicU64,
    pub net_tx:AtomicU64,pub net_rx:AtomicU64,pub queue_drops:AtomicU64,pub expired:AtomicU64,
    pub local_send_drops:AtomicU64,pub recovered:AtomicU64,
}
pub struct UdpEndpoint {
    pub network:Arc<UdpSocket>,pub peers:Vec<SocketAddr>,pub application:Arc<UdpSocket>,
    pub target:Option<SocketAddr>,pub config:SessionConfig,pub initiator:bool,
    /// Optional finite reordering window for TCP carried inside WG. Zero keeps
    /// immediate unordered delivery. Gaps are skipped at the deadline, never ARQed.
    pub reorder_delay:Duration,
}
struct Shared {paths:PathScheduler,peers:Vec<SocketAddr>,delivery:DeliverySender,counters:Arc<UdpCounters>}
struct SendItem {created:Instant,frame:Frame}
struct Stop {flag:Arc<AtomicBool>,worker:Option<thread::JoinHandle<()>>}
impl Drop for Stop {
    fn drop(&mut self){self.flag.store(true,Ordering::Release);if let Some(worker)=self.worker.take(){let _=worker.join();}}
}
fn sender(socket:std::net::UdpSocket,id:u64,shared:Arc<Mutex<Shared>>,cfg:SessionConfig,
          rx:mpsc::Receiver<SendItem>,stop:Arc<AtomicBool>,start:Instant)->io::Result<()> {
    let mut queue=VecDeque::new();
    let mut pacer=PacingClock::new(u64::from(cfg.wire_mbps)*125000,Duration::from_micros(150)).ok_or_else(||error("invalid pacing"))?;
    while !stop.load(Ordering::Acquire) {
        while queue.len()<MAX_QUEUE {
            match rx.try_recv(){Ok(item)=>queue.push_back(item),Err(_)=>break,}
        }
        while queue.front().is_some_and(|item:&SendItem|item.created.elapsed()>MAX_AGE){
            queue.pop_front();shared.lock().map_err(error)?.counters.expired.fetch_add(1,Ordering::Relaxed);
        }
        let mut packets=Vec::with_capacity(16);let mut sources=Vec::with_capacity(16);
        {
            let mut s=shared.lock().map_err(error)?;let now=start.elapsed();
            if let Some(best)=s.paths.best(now) {
                for _ in 0..16 {
                    let Some(item)=queue.pop_front()else{break;};
                    let seq=source_sequence(&item.frame,cfg.lanes).map_err(error)?;
                    // WG may contain TCP: spraying its successive encrypted
                    // packets across even slightly different RTTs creates duplicate
                    // ACK bursts in the inner TCP stack. Keep originals on the
                    // current best path, use other eligible paths for repair, and
                    // re-evaluate the primary as observations change.
                    let path=if seq.is_some(){best}else{s.paths.repair(now,best).unwrap_or(best)};
                    let mut payload=envelope(DATA,id,&[]);item.frame.encode_into(&mut payload).map_err(error)?;
                    packets.push(Datagram{destination:s.peers[path],payload});sources.push((seq,path));
                }
            }
        }
        if packets.is_empty(){thread::sleep(Duration::from_micros(100));continue;}
        let bytes=packets.iter().map(|p|p.payload.len()+if p.destination.is_ipv6(){48}else{28}).sum();
        let due=start+pacer.reserve(start.elapsed(),bytes);
        while let Some(left)=due.checked_duration_since(Instant::now()) {
            if stop.load(Ordering::Acquire){return Ok(());}
            thread::sleep(left.min(Duration::from_millis(1)));
        }
        let mut sent=0;let deadline=Instant::now()+Duration::from_millis(2);
        while sent<packets.len() && !stop.load(Ordering::Acquire) {
            match try_send_batch(&socket,&packets[sent..]) {
                Ok(0)=>break,
                Ok(n)=>{
                    let mut s=shared.lock().map_err(error)?;
                    for &(seq,path) in &sources[sent..sent+n]{if let Some(seq)=seq{s.delivery.sent(seq,path);}}
                    s.counters.net_tx.fetch_add(n as u64,Ordering::Relaxed);sent+=n;
                },
                Err(e) if matches!(e.kind(),io::ErrorKind::Interrupted|io::ErrorKind::WouldBlock)=>{
                    if Instant::now()>=deadline{break;}thread::sleep(Duration::from_micros(50));
                },
                Err(e)=>return Err(e),
            }
        }
    }
    Ok(())
}
fn queue_frames(tx:&mpsc::SyncSender<SendItem>,frames:Vec<Frame>,counters:&UdpCounters)->io::Result<()> {
    let created=Instant::now();
    for frame in frames {
        match tx.try_send(SendItem{created,frame}) {
            Ok(())=>{},
            Err(mpsc::TrySendError::Full(_))=>{counters.queue_drops.fetch_add(1,Ordering::Relaxed);},
            Err(mpsc::TrySendError::Disconnected(_))=>return Err(error("UDP sender stopped")),
        }
    }
    Ok(())
}

/// Exclusive network socket, one fixed loopback UDP application peer, no OS interfaces.
/// The two sides must use compatible codec parameters. Dropping/aborting this future
/// stops its owned sender thread. Run a separate instance for each WG peer.
pub async fn run(network:Arc<UdpSocket>,peers:Vec<SocketAddr>,application:Arc<UdpSocket>,
                 target:Option<SocketAddr>,cfg:SessionConfig,initiator:bool)->io::Result<()> {
    run_observed(UdpEndpoint{network,peers,application,target,config:cfg,initiator,reorder_delay:Duration::ZERO},Arc::default()).await
}

pub async fn run_observed(endpoint:UdpEndpoint,counters:Arc<UdpCounters>)->io::Result<()> {
    let UdpEndpoint{network,mut peers,application,target,config:cfg,initiator,reorder_delay}=endpoint;
    cfg.validate()?;
    if peers.is_empty()||peers.len()>8||cfg.fec.max_payload<=FRAGMENT||reorder_delay>Duration::from_millis(100)
        ||peers.iter().any(|p|p.ip().is_unspecified()||p.ip().is_multicast())
        ||!application.local_addr()?.ip().is_loopback()
        ||target.is_some_and(|t|!t.ip().is_loopback()||t.port()==0) {
        return Err(error("explicit peers, loopback application endpoint and valid fragment size required"));
    }
    let id=handshake(&network,&mut peers,&cfg,initiator).await?;
    let shared=Arc::new(Mutex::new(Shared{paths:PathScheduler::new(peers.len())?,peers:peers.clone(),delivery:DeliverySender::default(),counters:counters.clone()}));
    let start=Instant::now();let raw:std::net::UdpSocket=socket2::SockRef::from(&*network).try_clone()?.into();
    let (tx,rx)=mpsc::sync_channel(MAX_QUEUE);
    let (done_tx,mut done_rx)=tokio::sync::oneshot::channel();
    let flag=Arc::new(AtomicBool::new(false));let f=flag.clone();let s=shared.clone();let c=cfg.clone();
    let worker=thread::Builder::new().name("fec-udp-send".into()).spawn(move||{let _=done_tx.send(sender(raw,id,s,c,rx,f,start));})?;
    let _stop=Stop{flag,worker:Some(worker)};
    let mut encoder=InterleavedEncoder::new(cfg.fec.clone(),cfg.lanes).map_err(error)?;
    let mut decoder=Decoder::new(cfg.fec.clone()).map_err(error)?;
    let mut reassembly=Reassembly::new(cfg.fec.max_payload-FRAGMENT);
    let mut ordering=DeadlineOrder::new(reorder_delay);
    let mut replay=Replay::new(16_384);let mut message=0u64;
    let mut delivery=DeliveryReceiver::default();let mut highest=0;
    let mut app_peer=target;let mut last_packet=Instant::now();
    let mut outstanding=vec![VecDeque::<(u64,Instant)>::new();peers.len()];
    let mut tick=tokio::time::interval(Duration::from_millis(1));tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut probes=tokio::time::interval(Duration::from_millis(100));probes.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut net_buf=[0u8;1600];let mut app_buf=vec![0u8;65_536];
    loop {
        tokio::select! {
            result=&mut done_rx=>return result.map_err(error)?,
            _=tick.tick()=>{
                queue_frames(&tx,encoder.poll(start.elapsed()).map_err(error)?,&counters)?;reassembly.expire(Instant::now());
                deliver_local(&application,app_peer,ordering.poll(Instant::now()),&counters);
            },
            _=probes.tick()=>{
                if last_packet.elapsed()>cfg.idle_timeout{return Err(io::Error::new(io::ErrorKind::TimedOut,"UDP peer idle timeout"));}
                for path in 0..peers.len() {
                    while outstanding[path].front().is_some_and(|(_,at)|at.elapsed()>Duration::from_millis(750)) {
                        outstanding[path].pop_front();shared.lock().map_err(error)?.paths.timeout(path,start.elapsed());
                    }
                    if peers[path].port()==0{continue;}
                    let nonce=start.elapsed().as_nanos() as u64;
                    network.send_to(&envelope(PING,id,&nonce.to_be_bytes()),peers[path]).await?;
                    outstanding[path].push_back((nonce,Instant::now()));
                }
                let best=shared.lock().map_err(error)?.paths.best(start.elapsed());
                if let Some(best)=best {
                    // Highest observed source is not an ACK; quality samples wait
                    // their own settling interval and can never release payload state.
                    for receipt in delivery.ready(highest,start.elapsed()) {
                        network.send_to(&envelope(RECEIPT,id,&receipt.encode().unwrap()),peers[best]).await?;
                    }
                }
            },
            packet=application.recv_from(&mut app_buf)=>{
                let(n,from)=packet?;
                if !from.ip().is_loopback()||n>MAX_DATAGRAM{continue;}
                if app_peer.is_none(){app_peer=Some(from);}
                if app_peer!=Some(from){continue;}
                counters.app_rx.fetch_add(1,Ordering::Relaxed);counters.app_rx_bytes.fetch_add(n as u64,Ordering::Relaxed);
                let chunk=cfg.fec.max_payload-FRAGMENT;
                let pieces=n.div_ceil(chunk).max(1);
                for part in 0..pieces {
                    let offset=part*chunk;let end=(offset+chunk).min(n);
                    let mut payload=Vec::with_capacity(FRAGMENT+end-offset);
                    payload.extend_from_slice(&message.to_be_bytes());payload.extend_from_slice(&(n as u32).to_be_bytes());
                    payload.extend_from_slice(&(offset as u32).to_be_bytes());payload.extend_from_slice(&app_buf[offset..end]);
                    queue_frames(&tx,encoder.push(payload,start.elapsed()).map_err(error)?,&counters)?;
                }
                message=message.checked_add(1).ok_or_else(||error("UDP message sequence exhausted"))?;
            },
            packet=network.recv_from(&mut net_buf)=>{
                let(n,from)=packet?;let Some((kind,sid,body))=parse(&net_buf[..n])else{continue;};
                let learn=kind==0&&sid==0&&body.is_empty();
                let Some(path)=admit(&mut peers,from,learn)else{continue;};
                if learn{shared.lock().map_err(error)?.peers.clone_from(&peers);}
                if sid!=id{continue;}last_packet=Instant::now();
                match kind {
                    HELLO if body==hello(&cfg)=>{network.send_to(&envelope(ACCEPT,id,body),from).await?;},
                    PING if body.len()==8=>{network.send_to(&envelope(PONG,id,body),from).await?;},
                    PONG if body.len()==8=>{
                        let nonce=u64::from_be_bytes(body.try_into().unwrap());
                        if let Some(index)=outstanding[path].iter().position(|(n,_)|*n==nonce) {
                            let(_,at)=outstanding[path].remove(index).unwrap();shared.lock().map_err(error)?.paths.observe(path,at.elapsed(),start.elapsed());
                        }
                    },
                    RECEIPT if cfg.delivery_aware=>{
                        if let Some(receipt)=RawReceipt::decode(body) {
                            let mut s=shared.lock().map_err(error)?;
                            for(path,(samples,missing))in s.delivery.apply(receipt).into_iter().enumerate() {
                                if samples>0{s.paths.observe_delivery(path,samples,missing,start.elapsed());}
                            }
                        }
                    },
                    DATA=>{
                        counters.net_rx.fetch_add(1,Ordering::Relaxed);
                        let Ok(frame)=Frame::decode(body,cfg.fec.max_payload)else{continue;};
                        if let Ok(Some(seq))=source_sequence(&frame,cfg.lanes){delivery.original(seq);highest=highest.max(seq.saturating_add(1));}
                        let Ok(decoded)=decode(&mut decoder,&frame,cfg.lanes)else{continue;};
                        for packet in decoded {
                            highest=highest.max(packet.seq.saturating_add(1));
                            if !replay.mark(packet.seq){continue;}
                            if packet.recovered{counters.recovered.fetch_add(1,Ordering::Relaxed);}
                            if let Some(bytes)=reassembly.input(&packet.payload,Instant::now()) {
                                let msg=u64::from_be_bytes(packet.payload[..8].try_into().unwrap());
                                deliver_local(&application,app_peer,ordering.input(msg,bytes,Instant::now()),&counters);
                            }
                        }
                    },
                    _=>{},
                }
            }
        }
    }
}

fn deliver_local(application:&UdpSocket,peer:Option<SocketAddr>,packets:Vec<Vec<u8>>,counters:&UdpCounters) {
    if let Some(peer)=peer {for bytes in packets {
        if application.try_send_to(&bytes,peer).is_ok(){
            counters.app_tx.fetch_add(1,Ordering::Relaxed);counters.app_tx_bytes.fetch_add(bytes.len()as u64,Ordering::Relaxed);
        }else{counters.local_send_drops.fetch_add(1,Ordering::Relaxed);}
    }}
}

struct DeadlineOrder {next:u64,delay:Duration,pending:BTreeMap<u64,(Instant,Vec<u8>)>,bytes:usize}
impl DeadlineOrder {
    fn new(delay:Duration)->Self {Self{next:0,delay,pending:BTreeMap::new(),bytes:0}}
    fn input(&mut self,id:u64,payload:Vec<u8>,now:Instant)->Vec<Vec<u8>> {
        if self.delay.is_zero()||id<self.next {return vec![payload];}
        if self.pending.len()>=4096||self.bytes+payload.len()>MAX_ASSEMBLY_BYTES {
            // UDP backpressure never creates an unbounded reliable queue.
            return Vec::new();
        }
        if let std::collections::btree_map::Entry::Vacant(entry)=self.pending.entry(id) {
            self.bytes+=payload.len();entry.insert((now,payload));
        }
        self.poll(now)
    }
    fn poll(&mut self,now:Instant)->Vec<Vec<u8>> {
        let mut out=Vec::new();
        loop {
            if let Some((_,payload))=self.pending.remove(&self.next) {
                self.next=self.next.saturating_add(1);self.bytes-=payload.len();out.push(payload);
            } else if let Some((&id,_))=self.pending.first_key_value() {
                let oldest=self.pending.values().map(|(at,_)|*at).min().unwrap();
                if now.saturating_duration_since(oldest)<self.delay {break;}
                self.next=id; // Give up only this timed-out gap, not the later messages.
            } else {break;}
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fragment(id:u64,total:u32,offset:u32,body:&[u8])->Vec<u8>{
        let mut p=id.to_be_bytes().to_vec();p.extend(total.to_be_bytes());p.extend(offset.to_be_bytes());p.extend(body);p
    }
    #[test]
    fn missing_message_never_blocks_later_complete_message_and_duplicates() {
        let now=Instant::now();let mut r=Reassembly::new(4);
        assert!(r.input(&fragment(0,8,0,b"abcd"),now).is_none());
        assert_eq!(r.input(&fragment(1,3,0,b"new"),now),Some(b"new".to_vec()));
        assert!(r.input(&fragment(1,3,0,b"new"),now).is_none());
        assert_eq!(r.input(&fragment(0,8,4,b"efgh"),now),Some(b"abcdefgh".to_vec()));
    }
    #[test]
    fn fragment_dimensions_expiry_and_memory_are_bounded() {
        let now=Instant::now();let mut r=Reassembly::new(4);
        assert!(r.input(&fragment(0,99_999,0,b"abcd"),now).is_none());
        assert!(r.input(&fragment(0,8,1,b"abcd"),now).is_none());
        for id in 0..300 {r.input(&fragment(id,8,0,b"abcd"),now);}
        assert_eq!(r.pending.len(),MAX_ASSEMBLIES);assert!(r.bytes<=MAX_ASSEMBLY_BYTES);
        r.expire(now+MAX_AGE);assert_eq!(r.bytes,0);assert!(r.pending.is_empty());
        assert_eq!(r.input(&fragment(301,0,0,b""),now),Some(vec![]));
    }
    #[test]
    fn finite_reorder_waits_for_a_repair_but_never_beyond_its_deadline() {
        let now=Instant::now();let mut q=DeadlineOrder::new(Duration::from_millis(20));
        assert_eq!(q.input(0,vec![0],now),vec![vec![0]]);
        assert!(q.input(2,vec![2],now).is_empty());
        assert_eq!(q.input(1,vec![1],now+Duration::from_millis(5)),vec![vec![1],vec![2]]);
        assert!(q.input(5,vec![5],now+Duration::from_millis(6)).is_empty());
        assert!(q.input(4,vec![4],now+Duration::from_millis(25)).is_empty());
        assert_eq!(q.poll(now+Duration::from_millis(26)),vec![vec![4],vec![5]]);
        assert_eq!(q.input(3,vec![3],now+Duration::from_millis(30)),vec![vec![3]]);
        assert_eq!(q.bytes,0);
    }
    #[test]
    fn maximum_payload_reassembles_in_reverse_order() {
        let now=Instant::now();let chunk=1284;let mut r=Reassembly::new(chunk);
        let bytes:Vec<_>=(0..MAX_DATAGRAM).map(|i|(i%251)as u8).collect();
        let mut got=None;
        for offset in (0..bytes.len()).step_by(chunk).collect::<Vec<_>>().into_iter().rev(){
            got=r.input(&fragment(1,bytes.len()as u32,offset as u32,&bytes[offset..(offset+chunk).min(bytes.len())]),now).or(got);
        }
        assert_eq!(got,Some(bytes));assert_eq!(r.bytes,0);
    }
    #[test]
    fn replay_window_accepts_reordering_but_not_duplicates_or_ancient_data() {
        let mut r=Replay::new(4);assert!(r.mark(4));assert!(r.mark(2));assert!(!r.mark(2));assert!(!r.mark(0));assert!(r.mark(6));assert!(!r.mark(2));
    }
}
