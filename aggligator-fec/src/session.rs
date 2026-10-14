//! Experimental, bounded full-duplex reliable byte-stream over shared FEC paths.
//!
//! One session owns receive access to its UDP socket. Peers and forwarding targets
//! must be provisioned out of band; the random session ID is NOT authentication.
//! No outer secrecy or anti-censorship claim is made. Deploy only between trusted
//! endpoints/allowlisted peers, with inner application authentication as required.
//! This adapter does not change Aggligator's global delivery algorithm.
use crate::{
    Config, Decoder, Frame,
    delivery::{DeliveryReceiver, DeliverySender, RawReceipt},
    datagram::Datagram,
    packet::{PacketSocket,PacketSender},
    interleave::{InterleavedEncoder, source_sequence, decode as decode_interleaved},
    pacing::PacingClock,
    path::{PathScheduler, PathSnapshot},
    recovery::{Feedback, SendWindow},
};
use std::{
    collections::{BTreeMap, VecDeque},
    io, net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, Ordering}, mpsc as sync_mpsc},
    thread, time::{Duration, Instant},
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt, DuplexStream}, net::UdpSocket, sync::mpsc, task::JoinHandle};

const MAGIC: &[u8;4] = b"AFL1";
const HEADER: usize = 13;
const DATA: u8 = 1;
const PING: u8 = 2;
const PONG: u8 = 3;
const ACK: u8 = 6;
const EXTENT: u8 = 7;
const RETRY: u8 = 8;
const HELLO: u8 = 9;
const ACCEPT: u8 = 10;
const FIN_ACK: u8 = 11;
// Optional quality telemetry. Legacy peers ignore it; never changes delivery ACKs.
const RAW_RECEIPT: u8 = 12;
const WINDOW: usize = 8192;
const QUEUE: usize = 256;

fn err(e: impl std::fmt::Display) -> io::Error { io::Error::other(e.to_string()) }
fn wire(kind:u8,id:u64,body:&[u8])->Vec<u8> {
    let mut bytes=Vec::with_capacity(HEADER+body.len());
    bytes.extend_from_slice(MAGIC);bytes.push(kind);bytes.extend_from_slice(&id.to_be_bytes());bytes.extend_from_slice(body);bytes
}
fn parse(bytes:&[u8])->Option<(u8,u64,&[u8])> {
    if bytes.len()<HEADER || &bytes[..4]!=MAGIC {return None;}
    Some((bytes[4],u64::from_be_bytes(bytes[5..13].try_into().ok()?),&bytes[13..]))
}
fn peer_index(from:SocketAddr,peers:&mut [SocketAddr],learn:bool)->Option<usize> {
    if let Some(i)=peers.iter().position(|p|*p==from){return Some(i);}
    if learn {
        let i=peers.iter().position(|p|p.port()==0&&p.ip()==from.ip())?;
        peers[i]=from;return Some(i);
    }
    None
}

#[derive(Clone,Debug)]
pub struct SessionConfig {
    pub fec:Config,
    pub lanes:usize,
    /// All source, repair, retry and extent bytes share this per-session ceiling.
    /// Includes IPv4/IPv6+UDP; excludes Ethernet. Not adaptive congestion control.
    pub wire_mbps:u32,
    pub nack_delay:Duration,
    pub idle_timeout:Duration,
    /// Include observed original-arrival deficits in the path score.
    pub delivery_aware:bool,
    /// Optional conservative retry suppression for long-RTT paths; benchmark
    /// before enabling, since speculative copies can help on heavy loss.
    pub adaptive_retries:bool,
    /// Race original and retry datagrams on every enabled route, deliver on
    /// arrival and wake idle senders on demand. Trades wire capacity for latency.
    pub low_latency:bool,
}
impl Default for SessionConfig {
    fn default()->Self { Self {fec:Config {data_shards:64,repair_shards:8,max_payload:1300,
        max_decode_blocks:256,max_block_delay:Duration::from_millis(40)},lanes:8,
        wire_mbps:260,nack_delay:Duration::from_millis(30),idle_timeout:Duration::from_secs(20),delivery_aware:true,adaptive_retries:false,low_latency:false} }
}
impl SessionConfig {
    pub fn validate(&self)->io::Result<()> {
        self.fec.validate().map_err(err)?;
        if !(1..=16).contains(&self.lanes)||self.fec.repair_shards.saturating_mul(self.lanes)>128||!(1..=1000).contains(&self.wire_mbps)
            ||self.nack_delay<Duration::from_millis(5)||self.nack_delay>Duration::from_millis(500)
            ||self.idle_timeout<Duration::from_secs(2)||self.idle_timeout>Duration::from_secs(300) {
            return Err(err("invalid session configuration"));
        }
        Ok(())
    }
    fn hello(&self)->Vec<u8> {
        // Only wire-compatible dimensions are negotiated; each direction has its own cap.
        let mut b=b"FECSTREAM2".to_vec();
        b.extend_from_slice(&[self.fec.data_shards as u8,self.fec.repair_shards as u8,self.lanes as u8]);
        b.extend_from_slice(&(self.fec.max_payload as u16).to_be_bytes());b
    }
}
#[derive(Clone,Debug)]
pub struct PathSample {pub at_s:f64,pub source_packets:Vec<u64>}
#[derive(Clone,Debug,Default)]
pub struct SessionReport {
    pub session_id:u64,
    pub tx_payload_bytes:u64,
    pub rx_payload_bytes:u64,
    pub tx_wire_bytes:u64,
    pub tx_retries:u64,
    /// Low-latency copies dropped on local socket pressure; reliable history
    /// remains until peer acknowledgement, so these never drop stream bytes.
    pub tx_local_send_drops:u64,
    pub rx_fec_recovered:u64,
    /// Valid source/repair/retry datagrams observed, including late arrivals.
    /// Not a unique-source loss counter: network duplicates can affect these counts.
    pub path_rx_source_datagrams:Vec<u64>,
    pub path_rx_repair_datagrams:Vec<u64>,
    pub path_rx_retry_datagrams:Vec<u64>,
    pub max_send_history:usize,
    pub max_receive_buffer:usize,
    pub max_ordered_stall_ms:f64,
    pub path_source_packets:Vec<u64>,
    pub path_repair_packets:Vec<u64>,
    pub path_retry_packets:Vec<u64>,
    pub path_state:Vec<PathSnapshot>,
    /// Bounded last 100 seconds of cumulative source counts, sampled every 500ms.
    pub path_samples:Vec<PathSample>,
    pub path_addresses:Vec<SocketAddr>,
    pub topology_updates:u64,
    pub elapsed_s:f64,
}
/// Dropping the stream alone closes application IO. Abort `task` for hard cancellation.
/// A clean task result means both FINs were delivered and outgoing data acknowledged.
pub struct Session {pub stream:DuplexStream,pub task:JoinHandle<io::Result<SessionReport>>}

pub async fn connect(socket:Arc<UdpSocket>,mut peers:Vec<SocketAddr>,cfg:SessionConfig)->io::Result<Session> {
    cfg.validate()?;check_peers(&peers)?;
    let socket=PacketSocket::from(socket);
    let id=rand::random::<u64>().max(1);
    handshake(&socket,&mut peers,&cfg,Some(id)).await?;
    Ok(start(socket,peers,cfg,id,None))
}
pub async fn accept(socket:Arc<UdpSocket>,mut peers:Vec<SocketAddr>,cfg:SessionConfig)->io::Result<Session> {
    cfg.validate()?;check_peers(&peers)?;
    let socket=PacketSocket::from(socket);
    let id=handshake(&socket,&mut peers,&cfg,None).await?;
    Ok(start(socket,peers,cfg,id,None))
}

/// Watch-based peer changes apply to this SAME session/sequence space. Slot
/// identities remain stable, so queued ACKs and loss samples cannot refer to a
/// different path after deletion. At most eight distinct endpoints per session.
pub async fn connect_dynamic(socket:Arc<UdpSocket>,updates:tokio::sync::watch::Receiver<Vec<SocketAddr>>,cfg:SessionConfig)->io::Result<Session> {
    dynamic_handshake(socket,updates,cfg,true).await
}
pub async fn accept_dynamic(socket:Arc<UdpSocket>,updates:tokio::sync::watch::Receiver<Vec<SocketAddr>>,cfg:SessionConfig)->io::Result<Session> {
    dynamic_handshake(socket,updates,cfg,false).await
}
fn padded(mut peers:Vec<SocketAddr>)->io::Result<Vec<SocketAddr>> {
    check_peers(&peers)?;
    peers.resize(8,SocketAddr::from(([0,0,0,0],0)));Ok(peers)
}
async fn dynamic_handshake(socket:Arc<UdpSocket>,mut updates:tokio::sync::watch::Receiver<Vec<SocketAddr>>,cfg:SessionConfig,client:bool)->io::Result<Session> {
    cfg.validate()?;let socket=PacketSocket::from(socket);let ours=client.then(||rand::random::<u64>().max(1));
    loop {
        let current=updates.borrow_and_update().clone();
        if current.is_empty(){updates.changed().await.map_err(err)?;continue;}
        let mut peers=padded(current)?;
        tokio::select! {
            result=handshake(&socket,&mut peers,&cfg,ours)=>{
                let id=result?;return Ok(start(socket,peers,cfg,id,Some(updates)));
            },
            changed=updates.changed()=>{changed.map_err(err)?;},
        }
    }
}

fn check_peers(peers:&[SocketAddr])->io::Result<()> {
    if peers.is_empty()||peers.len()>8||peers.iter().any(|p|p.ip().is_unspecified()||p.ip().is_multicast()) {
        return Err(err("provide 1..8 explicit unicast peers"));
    }
    Ok(())
}
/// Independent reliable flow on shared physical sockets. Virtual lane numbers
/// remain stable across relay changes and distinguish each client access link.
pub async fn multiplexed(flow:Arc<crate::multiplex::FlowIo>,cfg:SessionConfig,client:bool)->io::Result<Session>{
    cfg.validate()?;let updates=flow.updates();let socket=PacketSocket::Flow(flow);
    let mut peers=(0..crate::multiplex::LANES).map(crate::multiplex::virtual_peer).collect::<Vec<_>>();
    let ours=client.then(||rand::random::<u64>().max(1));
    let id=handshake(&socket,&mut peers,&cfg,ours).await?;
    Ok(start(socket,peers,cfg,id,Some(updates)))
}
async fn handshake(socket:&PacketSocket,peers:&mut [SocketAddr],cfg:&SessionConfig,initiator:Option<u64>)->io::Result<u64> {
    let mut tick=tokio::time::interval(Duration::from_millis(100));
    let deadline=tokio::time::Instant::now()+Duration::from_secs(10);
    let mut buffer=[0;1600];let hello=cfg.hello();
    loop {
        tokio::select! {
            _=tokio::time::sleep_until(deadline)=>return Err(io::Error::new(io::ErrorKind::TimedOut,"FEC session handshake timeout")),
            _=tick.tick()=>{
                for peer in peers.iter().filter(|p|p.port()!=0) {
                    socket.send_to(&wire(0,0,&[]),*peer).await?;
                    if let Some(id)=initiator {socket.send_to(&wire(HELLO,id,&hello),*peer).await?;}
                }
            },
            result=socket.recv_from(&mut buffer)=>{
                let(n,from)=result?;let Some((kind,id,body))=parse(&buffer[..n])else{continue;};
                let learn=(kind==0&&id==0&&body.is_empty())||(kind==HELLO&&id!=0&&body==hello);
                if peer_index(from,peers,learn).is_none(){continue;}
                match (initiator,kind) {
                    (None,HELLO) if id!=0&&body==hello=>{
                        socket.send_to(&wire(ACCEPT,id,&hello),from).await?;return Ok(id);
                    },
                    (Some(ours),ACCEPT) if id==ours&&body==hello=>return Ok(id),
                    _=>{},
                }
            },
        }
    }
}

enum Input {Data(Vec<u8>),Fin}
enum Command {Feedback(Feedback),FinAck(u64),RawReceipt(RawReceipt)}
struct WorkerGuard {stop:Arc<AtomicBool>,join:Option<thread::JoinHandle<()>>}
impl Drop for WorkerGuard {
    fn drop(&mut self){self.stop.store(true,Ordering::Release);if let Some(join)=self.join.take(){join.thread().unpark();let _=join.join();}}
}
fn wake_sender(wake:&OnceLock<thread::Thread>){if let Some(worker)=wake.get(){worker.unpark();}}
#[derive(Default)]
struct TxReport {bytes:u64,wire:u64,retries:u64,local_drops:u64,max_history:usize,sources:Vec<u64>,repairs:Vec<u64>,retry_paths:Vec<u64>,samples:VecDeque<PathSample>}
struct Queued {packet:Datagram,kind:u8,path:usize,seq:Option<u64>}
fn enqueue(frames:Vec<Frame>,header:(u8,u64),peers:&[SocketAddr],scheduler:&mut PathScheduler,
           now:Duration,lanes:usize,queue:&mut VecDeque<Queued>)->io::Result<()> {
    let (kind,id)=header;
    for frame in frames {
        // The receive task may change path state between generation and enqueue.
        // Keep the frame in the bounded queue even when every probe is stale;
        // sender gates network submission until a path becomes live again.
        let best=scheduler.best(now).or_else(||peers.iter().position(|p|p.port()!=0))
            .ok_or_else(||err("no provisioned peer"))?;
        // This is only a staging hint. Weighted selection happens once, when
        // the actual batch is submitted, so queued traffic cannot skew weights.
        let path=best;
        let seq=source_sequence(&frame,lanes).map_err(err)?;
        if seq.is_none()&&!matches!(frame,Frame::Repair {..}){return Err(err("invalid source"));}
        let mut payload=wire(kind,id,&[]);frame.encode_into(&mut payload).map_err(err)?;
        queue.push_back(Queued {packet:Datagram {destination:peers[path],payload},kind,path,seq});
    }
    if queue.len()>QUEUE {return Err(err("bounded send queue exceeded"));}Ok(())
}
fn wait(deadline:Instant,stop:&AtomicBool)->io::Result<()> {
    while let Some(left)=deadline.checked_duration_since(Instant::now()) {
        if stop.load(Ordering::Acquire){return Err(err("session cancelled"));}
        thread::park_timeout(left);
    }Ok(())
}
struct SendContext {
    socket:PacketSender,
    id:u64,
    peer_state:Arc<Mutex<Vec<SocketAddr>>>,
    cfg:SessionConfig,
    shared:Arc<Mutex<PathScheduler>>,
    start:Instant,
    stop:Arc<AtomicBool>,
}
fn sender(context:SendContext,mut input:mpsc::Receiver<Input>,
          commands:sync_mpsc::Receiver<Command>)->io::Result<TxReport> {
    let SendContext {socket,id,peer_state,cfg,shared,start,stop}=context;
    let mut peers=peer_state.lock().map_err(err)?.clone();
    let mut encoder=InterleavedEncoder::new(cfg.fec.clone(),cfg.lanes).map_err(err)?;
    // Keep a WAN-sized reliable history. Bound unsent work independently; a
    // small HTTP request must not wait behind a throughput-sized submission batch.
    let retry_delay=if cfg.low_latency {cfg.nack_delay.max(Duration::from_millis(10))}else{Duration::from_millis(120)};
    let mut history=SendWindow::new(WINDOW,WINDOW*cfg.fec.max_payload,retry_delay,if cfg.low_latency{255}else{30}).map_err(err)?;
    let mut pacer=PacingClock::new(u64::from(cfg.wire_mbps)*125000,Duration::from_micros(150)).ok_or_else(||err("pacer"))?;
    let batch=if cfg.low_latency{1}else{16};
    let extent_interval=if cfg.low_latency{Duration::from_millis(10)}else{Duration::from_millis(40)};
    let mut queue=VecDeque::new();let mut fin=false;let mut fin_ack=false;
    let mut delivery=DeliverySender::default();
    let mut last_extent=Instant::now()-Duration::from_secs(1);let mut advertised=None;
    let mut last_ack=Instant::now();let mut sampled=Instant::now();
    let mut report=TxReport {sources:vec![0;peers.len()],repairs:vec![0;peers.len()],retry_paths:vec![0;peers.len()],..Default::default()};
    while !fin||!history.is_empty()||!queue.is_empty()||!fin_ack {
        if stop.load(Ordering::Acquire){return Err(err("session cancelled"));}
        if sampled.elapsed()>=Duration::from_millis(500) {
            if report.samples.len()==200{report.samples.pop_front();}
            report.samples.push_back(PathSample {at_s:start.elapsed().as_secs_f64(),source_packets:report.sources.clone()});sampled=Instant::now();
        }
        if last_ack.elapsed()>cfg.idle_timeout&&(!history.is_empty()||(fin&&!fin_ack)){return Err(err("reliable delivery made no acknowledgement progress"));}
        // Reserve space for one 64-source repair request, a FEC flush and controls.
        for _ in 0..128 {
            if queue.len()>QUEUE-64-cfg.fec.repair_shards*cfg.lanes-peers.len(){break;}
            let Ok(cmd)=commands.try_recv() else{break;};
            match cmd {
                Command::Feedback(feedback)=>{
                    let cooldown=if cfg.low_latency{retry_delay}
                        else if cfg.adaptive_retries {shared.lock().map_err(err)?.retry_delay(start.elapsed())}
                        else {Duration::from_millis(120)};
                    history.set_retry_cooldown(cooldown).map_err(err)?;
                    let frames=match history.feedback(feedback,start.elapsed()) {
                        Ok(frames)=>frames,
                        Err(crate::recovery::RecoveryError::InvalidFeedback)=>continue,
                        Err(error)=>return Err(err(error)),
                    };
                    // Repeated valid ACKs also establish liveness during reader backpressure.
                    last_ack=Instant::now();
                    if !frames.is_empty() {
                        let mut paths=shared.lock().map_err(err)?;
                        enqueue(frames,(RETRY,id),&peers,&mut paths,start.elapsed(),cfg.lanes,&mut queue)?;
                    }
                },
                Command::RawReceipt(receipt) if cfg.delivery_aware&&!cfg.low_latency=>{
                    let observations=delivery.apply(receipt);
                    let mut scheduler=shared.lock().map_err(err)?;
                    for (path,(samples,missing)) in observations.into_iter().enumerate() {
                        if samples>0 {scheduler.observe_delivery(path,samples,missing,start.elapsed());}
                    }
                },
                Command::FinAck(extent) if fin&&extent==history.next()=>fin_ack=true,
                _=>{},
            }
        }
        if fin&&history.is_empty()&&queue.is_empty()&&fin_ack{break;}
        peers.clone_from(&*peer_state.lock().map_err(err)?);
        let live={
            let mut scheduler=shared.lock().map_err(err)?;
            if cfg.low_latency {peers.iter().enumerate().any(|(i,p)|p.port()!=0&&scheduler.is_enabled(i))}
            else {scheduler.best(start.elapsed()).is_some()}
        };
        if live {
            while !fin&&queue.len()<batch&&history.has_space(cfg.fec.max_payload) {
                match input.try_recv() {
                    Ok(Input::Data(payload))=>{
                        if history.is_empty(){last_ack=Instant::now();}
                        report.bytes+=payload.len() as u64;
                        let frames=encoder.push(payload,start.elapsed()).map_err(err)?;
                        for frame in &frames {if let Some(seq)=source_sequence(frame,cfg.lanes).map_err(err)? {history.retain_at(seq,frame).map_err(err)?;}}
                        report.max_history=report.max_history.max(history.len());
                        enqueue(frames,(DATA,id),&peers,&mut *shared.lock().map_err(err)?,start.elapsed(),cfg.lanes,&mut queue)?;
                    },
                    Ok(Input::Fin)|Err(mpsc::error::TryRecvError::Disconnected)=>{
                        fin=true;last_ack=Instant::now();
                    },
                    Err(mpsc::error::TryRecvError::Empty)=>break,
                }
            }
            let frames=if fin {encoder.flush()}else{encoder.poll(start.elapsed())}.map_err(err)?;
            enqueue(frames,(DATA,id),&peers,&mut *shared.lock().map_err(err)?,start.elapsed(),cfg.lanes,&mut queue)?;
        }
        let new_extent=advertised!=Some((history.next(),fin));
        // DATA is never held for a control timer. Advertise the drained burst
        // tail immediately; continuous bulk traffic needs only the bounded
        // periodic extent, otherwise each 1100-byte source amplifies into an
        // EXTENT and an ACK on every physical route.
        let fin_changed=fin&&advertised.is_none_or(|(_,was_fin)|!was_fin);
        let immediate_extent=cfg.low_latency&&new_extent&&(input.is_empty()||fin_changed);
        let needs_extent=!cfg.low_latency||!history.is_empty()||(fin&&!fin_ack);
        if live && needs_extent && queue.len()+peers.len()<=QUEUE
            &&(immediate_extent||last_extent.elapsed()>=extent_interval) {
            let mut body=history.next().to_be_bytes().to_vec();body.push(u8::from(fin));
            let scheduler=shared.lock().map_err(err)?;
            for(path,peer)in peers.iter().enumerate().filter(|(i,p)|p.port()!=0&&scheduler.is_enabled(*i)) {
                queue.push_back(Queued {packet:Datagram {destination:*peer,payload:wire(EXTENT,id,&body)},kind:EXTENT,path,seq:None});
                // One logical control; copies are made at submission with the current topology.
                if cfg.low_latency{break;}
            }
            advertised=Some((history.next(),fin));last_extent=Instant::now();
        }
        if !live || queue.is_empty(){
            // Notifications have a sticky park token: data/ACK arriving between
            // the last try_recv and park cannot be lost. No idle 100us polling.
            let mut deadline=sampled+Duration::from_millis(500);
            if live&&needs_extent{deadline=deadline.min(last_extent+extent_interval);}
            // Conventional FEC blocks retain their short flush deadline.
            if live&&cfg.fec.repair_shards>0{deadline=deadline.min(Instant::now()+cfg.fec.max_block_delay.min(Duration::from_millis(1)));}
            thread::park_timeout(deadline.saturating_duration_since(Instant::now()));continue;
        }
        let mut packets=Vec::new();let mut meta=Vec::new();
        {
            let mut scheduler=shared.lock().map_err(err)?;
            let now=start.elapsed();let best=scheduler.best(now);
            queue.retain(|q|(q.kind!=EXTENT||cfg.low_latency||scheduler.is_enabled(q.path))
                &&!(q.kind==RETRY&&q.seq.is_some_and(|seq|seq<history.acknowledged())));
            if cfg.low_latency {
                let mut targets=peers.iter().enumerate().filter(|(i,p)|p.port()!=0&&scheduler.is_enabled(*i)).map(|(i,_)|i).collect::<Vec<_>>();
                if targets.is_empty(){continue;}
                // Probe estimates only affect submission order, never admission.
                if let Some(best)=best&&let Some(at)=targets.iter().position(|p|*p==best){targets.swap(0,at);}
                if let Some(q)=queue.pop_front(){
                    let replicate=q.kind==EXTENT||q.seq.is_some();
                    for &path in &targets {
                        let mut packet=q.packet.clone();packet.destination=peers[path];
                        packets.push(packet);meta.push((q.kind,path,q.seq));
                        if !replicate{break;}
                    }
                }
            } else {
                let Some(best)=best else {continue;};
                for queued in queue.iter_mut().take(batch) {
                    if matches!(queued.kind,DATA|RETRY) {
                        let path=if queued.packet.payload.get(HEADER+4)==Some(&1) {
                            scheduler.repair(now,best).unwrap_or(best)
                        } else {scheduler.select(now).unwrap_or(best)};
                        queued.path=path;queued.packet.destination=peers[path];
                    }
                }
                for _ in 0..queue.len().min(batch) {let q=queue.pop_front().unwrap();meta.push((q.kind,q.path,q.seq));packets.push(q.packet);}
            }
        }
        if packets.is_empty(){continue;}
        // The per-session cap and the shared physical cap both charge every
        // replica, including the multiplex header and the actual IP family.
        let bytes=packets.iter().try_fold(0usize,|sum,p|socket.wire_size(p).map(|n|sum+n))?;
        let deadline=start+pacer.reserve(start.elapsed(),bytes);
        wait(socket.reserve(&packets,deadline)?,&stop)?;
        let mut offset=0;let blocked=Instant::now();
        while offset<packets.len() {
            if stop.load(Ordering::Acquire){return Err(err("session cancelled"));}
            let end=if cfg.low_latency{offset+1}else{packets.len()};
            match socket.send_batch(&packets[offset..end]) {
                Ok(0) if !cfg.low_latency=>return Err(err("UDP batch stalled")),
                Ok(0)=>{report.local_drops+=1;offset+=1;},
                Ok(n)=>{
                    for i in offset..offset+n {
                        let(kind,path,seq)=meta[i];let packet=&packets[i];
                        report.wire+=socket.wire_size(packet)? as u64;
                        if kind==RETRY {report.retries+=1;report.retry_paths[path]+=1;}
                        else if kind==DATA&&packet.payload.get(HEADER+4)==Some(&0){
                            report.sources[path]+=1;
                            if !cfg.low_latency&&let Some(seq)=seq{delivery.sent(seq,path);}
                        }
                        else if kind==DATA {report.repairs[path]+=1;}
                    }offset+=n;
                },
                Err(e) if cfg.low_latency&&matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted
                    |io::ErrorKind::NetworkUnreachable|io::ErrorKind::HostUnreachable|io::ErrorKind::AddrNotAvailable)=>{
                    // A congested/dead local access must not hold a healthy
                    // replica for 100ms. ARQ still owns the undelivered source.
                    report.local_drops+=1;offset+=1;
                },
                Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>{
                    if blocked.elapsed()>Duration::from_millis(100){return Err(err("UDP enqueue deadline"));}
                    thread::park_timeout(Duration::from_micros(50));
                },
                Err(e)=>return Err(e),
            }
        }
    }
    Ok(report)
}
fn start(socket:PacketSocket,peers:Vec<SocketAddr>,cfg:SessionConfig,id:u64,updates:Option<tokio::sync::watch::Receiver<Vec<SocketAddr>>>)->Session {
    let (stream,internal)=tokio::io::duplex(if cfg.low_latency{16*1024}else{64*1024});
    let task=tokio::spawn(drive(socket,peers,cfg,id,internal,updates));Session {stream,task}
}
struct Pumps(Vec<JoinHandle<io::Result<()>>>);
impl Drop for Pumps {fn drop(&mut self){for pump in &self.0{pump.abort();}}}
async fn drive(socket:PacketSocket,mut peers:Vec<SocketAddr>,cfg:SessionConfig,id:u64,internal:DuplexStream,mut updates:Option<tokio::sync::watch::Receiver<Vec<SocketAddr>>>)->io::Result<SessionReport> {
    let start=Instant::now();let (mut app_read,mut app_write)=tokio::io::split(internal);
    let depth=if cfg.low_latency{16}else{128};
    let (app_tx,app_rx)=mpsc::channel(depth);let (out_tx,mut out_rx)=mpsc::channel::<Vec<u8>>(depth);
    let sender_wake=Arc::new(OnceLock::<thread::Thread>::new());let input_wake=sender_wake.clone();
    let delivery_wake=Arc::new(tokio::sync::Notify::new());let output_wake=delivery_wake.clone();
    let (app_done_tx,mut app_done_rx)=tokio::sync::oneshot::channel::<io::Result<()>>();
    let mut app_write_finished=false;
    let size=cfg.fec.max_payload;
    let _pumps=Pumps(vec![tokio::spawn(async move {
        loop {let mut b=vec![0;size];let n=app_read.read(&mut b).await?;
            if n==0 {app_tx.send(Input::Fin).await.map_err(err)?;wake_sender(&input_wake);return Ok(());}
            b.truncate(n);app_tx.send(Input::Data(b)).await.map_err(err)?;wake_sender(&input_wake);
        }
    }),tokio::spawn(async move {
        let result=async {
            while let Some(bytes)=out_rx.recv().await {app_write.write_all(&bytes).await?;output_wake.notify_one();}
            app_write.shutdown().await
        }.await;
        let _=app_done_tx.send(result);Ok(())
    })]);
    let paths=Arc::new(Mutex::new(PathScheduler::new(peers.len())?));
    let initial_routes=updates.as_ref().map(|u|u.borrow().clone());
    for(index,peer)in peers.iter().enumerate(){
        let enabled=!peer.ip().is_unspecified()&&initial_routes.as_ref().is_none_or(|r|r.contains(peer)||r.iter().any(|p|p.port()==0&&p.ip()==peer.ip()));
        paths.lock().map_err(err)?.set_enabled(index,enabled);
    }
    // The handshake path has proved bidirectional reachability; RTT comes from correlated probes.
    let raw=socket.sender()?;
    if let Some(weights)=socket.access_weights(){paths.lock().map_err(err)?.set_access_weights(weights)?;}
    let stop=Arc::new(AtomicBool::new(false));let s=stop.clone();let p=paths.clone();let c=cfg.clone();let peer_state=Arc::new(Mutex::new(peers.clone()));let ps=peer_state.clone();
    let (command_tx,commands)=sync_mpsc::sync_channel(128);let(done_tx,mut done_rx)=tokio::sync::oneshot::channel();
    let worker_wake=sender_wake.clone();
    let join=thread::Builder::new().name("fec-session-send".into()).spawn(move||{
        let _=worker_wake.set(thread::current());
        let _=done_tx.send(sender(SendContext {socket:raw,id,peer_state:ps,cfg:c,shared:p,start,stop:s},app_rx,commands));
    })?;
    let _guard=WorkerGuard {stop,join:Some(join)};
    let mut decoder=Decoder::new(cfg.fec.clone()).map_err(err)?;
    let mut pending=BTreeMap::<u64,Vec<u8>>::new();let mut gaps=BTreeMap::<u64,Instant>::new();
    let mut next=0u64;let mut highest=0u64;let mut remote_fin=None;let mut out=Some(out_tx);let mut tx_report=None;
    let mut quiet_since=None::<Instant>;let mut last_packet=Instant::now();
    let mut outstanding:Vec<VecDeque<(u64,Instant)>>=vec![VecDeque::new();peers.len()];
    let mut report=SessionReport {session_id:id,
        path_rx_source_datagrams:vec![0;peers.len()],path_rx_repair_datagrams:vec![0;peers.len()],
        path_rx_retry_datagrams:vec![0;peers.len()],..Default::default()};
    let mut feedback_tick=tokio::time::interval(Duration::from_millis(5));
    let probe_interval=if cfg.low_latency{Duration::from_millis(500)}else{Duration::from_millis(100)};
    let mut probe_tick=tokio::time::interval(probe_interval);
    probe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut feedback_at=tokio::time::Instant::now();
    let ack_interval=Duration::from_millis(1);
    let mut last_ack_sent=Instant::now()-ack_interval;
    let mut ack_cursor=None;
    let mut ack_requested=false;
    let mut nack_sent=BTreeMap::<u64,Instant>::new();
    let mut delivery=DeliveryReceiver::default();
    let mut buf=[0u8;1600];let mut last_progress=None::<Instant>;
    loop {
        tokio::select! {
            change=async {
                match &mut updates {
                    Some(watch)=>watch.changed().await.map(|()|watch.borrow_and_update().clone()),
                    None=>std::future::pending().await,
                }
            }=>{
                match change {
                    Err(_)=>updates=None, // Keep last-known paths if the watcher is stopped.
                    Ok(wanted)=>{
                        if wanted.len()>peers.len()||wanted.iter().any(|p|p.ip().is_unspecified()||p.ip().is_multicast()){continue;}
                        let mut enabled=vec![false;peers.len()];
                        let mut scheduler=paths.lock().map_err(err)?;
                        for desired in wanted {
                            let index=peers.iter().position(|p|*p==desired||(desired.port()==0&&p.ip()==desired.ip()))
                                .or_else(||peers.iter().position(|p|p.ip().is_unspecified()));
                            // Do not repurpose historical slots during a live stream.
                            // Further churn is picked up by the next connection.
                            if let Some(index)=index {
                                if peers[index].ip().is_unspecified(){peers[index]=desired;outstanding[index].clear();}
                                enabled[index]=true;
                            }
                        }
                        for(index,enabled)in enabled.into_iter().enumerate().take(peers.len()){
                            scheduler.set_enabled(index,enabled);
                            if !enabled{outstanding[index].clear();}
                        }
                        peer_state.lock().map_err(err)?.clone_from(&peers);
                        wake_sender(&sender_wake);
                        report.topology_updates+=1;
                    },
                }
            },
            result=&mut done_rx,if tx_report.is_none()=>{tx_report=Some(result.map_err(err)??);if cfg.low_latency{feedback_at=tokio::time::Instant::now();}},
            result=&mut app_done_rx,if !app_write_finished=>{result.map_err(err)??;app_write_finished=true;if cfg.low_latency{feedback_at=tokio::time::Instant::now();}},
            _=delivery_wake.notified(),if cfg.low_latency&&!pending.is_empty()=>{feedback_at=tokio::time::Instant::now();},
            _=probe_tick.tick()=>{
                if let Some(weights)=socket.access_weights(){paths.lock().map_err(err)?.set_access_weights(weights)?;}
                let now=Instant::now();
                for path in 0..peers.len() {
                    if !paths.lock().map_err(err)?.is_enabled(path){continue;}
                    while outstanding[path].front().is_some_and(|(_,at)|now.duration_since(*at)>Duration::from_millis(500)) {
                        outstanding[path].pop_front();paths.lock().map_err(err)?.timeout(path,start.elapsed());
                    }
                    if peers[path].port()==0 {continue;}
                    let nonce=start.elapsed().as_nanos() as u64;
                    let body=nonce.to_be_bytes();
                    // Newly discovered relays learn the client's NAT tuple from
                    // an envelope primer before forwarding correlated probes.
                    if updates.is_some(){socket.send_to(&wire(0,0,&[]),peers[path]).await?;}
                    socket.send_to(&wire(PING,id,&body),peers[path]).await?;
                    outstanding[path].push_back((nonce,Instant::now()));
                }
            },
            _=async {
                if cfg.low_latency{if feedback_at>tokio::time::Instant::now(){tokio::time::sleep_until(feedback_at).await;}}
                else{feedback_tick.tick().await;}
            }=>{
                if last_packet.elapsed()>cfg.idle_timeout{return Err(err("session peer idle timeout"));}
                // ACK only after bounded delivery-channel admission, not after FEC cache insertion.
                while let Some(bytes)=pending.remove(&next) {
                    let len=bytes.len();let Some(tx)=&out else{return Err(err("data after peer FIN"));};
                    match tx.try_send(bytes) {
                        Ok(())=>{
                            report.rx_payload_bytes+=len as u64;gaps.remove(&next);next+=1;
                            if let Some(last)=last_progress {report.max_ordered_stall_ms=report.max_ordered_stall_ms.max(last.elapsed().as_secs_f64()*1000.0);}
                            last_progress=Some(Instant::now());
                        },
                        Err(mpsc::error::TrySendError::Full(bytes))=>{pending.insert(next,bytes);break;},
                        Err(mpsc::error::TrySendError::Closed(_))=>return Err(err("application receive side closed")),
                    }
                }
                gaps.retain(|seq,_|*seq>=next&&!pending.contains_key(seq));
                nack_sent.retain(|base,_|base.saturating_add(64)>next);
                let now=Instant::now();let limit=highest.min(next+WINDOW as u64);
                for seq in next..limit {if !pending.contains_key(&seq){gaps.entry(seq).or_insert(now);}}
                let mut next_feedback=now+Duration::from_secs(1);
                if !pending.is_empty()||highest>next{next_feedback=next_feedback.min(now+Duration::from_millis(100));}
                let targets:Vec<usize>={
                    let mut s=paths.lock().map_err(err)?;
                    if cfg.low_latency {
                        peers.iter().enumerate().filter(|(i,p)|p.port()!=0&&s.is_enabled(*i)).map(|(i,_)|i).collect()
                    } else {
                        let best=s.best(start.elapsed());let second=best.and_then(|b|s.repair(start.elapsed(),b));
                        best.into_iter().chain(second.filter(|i|Some(*i)!=best)).collect()
                    }
                };
                if !targets.is_empty() {
                    if !cfg.low_latency {
                        for receipt in delivery.ready(next,start.elapsed()) {
                            if let Some(body)=receipt.encode() {
                                let packet=wire(RAW_RECEIPT,id,&body);
                                for &path in &targets {socket.send_to(&packet,peers[path]).await?;}
                            }
                        }
                    }
                    // Application admission above remains immediate. Only a
                    // cumulative ACK may coalesce for at most 1ms under load;
                    // the first data ACK and both closing ACKs remain immediate.
                    let closing=remote_fin==Some(next);
                    if !cfg.low_latency||closing||ack_requested||ack_cursor!=Some(next) {
                        let due=last_ack_sent+ack_interval;
                        let first_data=ack_cursor==Some(0)&&next>0;
                        if !cfg.low_latency||closing||first_data||now>=due {
                            let ack=Feedback {next,base:next,limit:next,missing:0};
                            let packet=wire(ACK,id,&ack.encode().unwrap());
                            for &path in &targets {
                                socket.send_to(&packet,peers[path]).await?;
                                if !cfg.low_latency{break;}
                            }
                            last_ack_sent=Instant::now();ack_cursor=Some(next);ack_requested=false;
                        } else {next_feedback=next_feedback.min(due);}
                    }
                    let repeat=if cfg.low_latency{Duration::from_millis(10)}else{Duration::from_millis(50)};
                    let mut count=0;
                    for base in (next..limit).step_by(64) {
                        let end=(base+64).min(limit);let mut mask=0u64;let mut due=now;
                        for seq in base..end {
                            if let Some(at)=gaps.get(&seq) {
                                due=due.max(*at+cfg.nack_delay);mask|=1<<(seq-base);
                            }
                        }
                        if mask==0{continue;}
                        if let Some(at)=nack_sent.get(&base){due=due.max(*at+repeat);}
                        // Zero bits mean received: wait until every missing bit in
                        // this window is old enough, never falsely SACK a young gap.
                        if due>now{next_feedback=next_feedback.min(due);continue;}
                        let fb=Feedback {next,base,limit:end,missing:mask};let packet=wire(ACK,id,&fb.encode().unwrap());
                        for &path in &targets {socket.send_to(&packet,peers[path]).await?;}
                        nack_sent.insert(base,now);next_feedback=next_feedback.min(now+repeat);
                        count+=1;if count==8{break;}
                    }
                    if remote_fin==Some(next) {
                        drop(out.take());
                        for &path in &targets{socket.send_to(&wire(FIN_ACK,id,&next.to_be_bytes()),peers[path]).await?;}
                        next_feedback=next_feedback.min(now+Duration::from_millis(20));
                    }
                }
                feedback_at=tokio::time::Instant::from_std(next_feedback);
                report.max_receive_buffer=report.max_receive_buffer.max(pending.len());
                if tx_report.is_some()&&remote_fin==Some(next)&&app_write_finished {
                    // Shared sockets can retain a small final-ACK record after
                    // every byte/FIN is proved complete, freeing the active flow
                    // slot immediately. Raw sessions and a full close cache keep
                    // the original receive grace instead.
                    if cfg.low_latency&&socket.finish_clean(id,next)?{break;}
                    let at=quiet_since.get_or_insert(now);
                    // Continue repeating FIN_ACK so lost final control cannot hang the peer.
                    if at.elapsed()>Duration::from_millis(600){break;}
                }
            },
            recv=socket.recv_from(&mut buf)=>{
                let(n,from)=recv?;let Some((kind,sid,body))=parse(&buf[..n])else{continue;};
                let learn=kind==0&&sid==0&&body.is_empty();
                let Some(path)=peer_index(from,&mut peers,learn)else{continue;};
                if !paths.lock().map_err(err)?.is_enabled(path){continue;}
                if learn{peer_state.lock().map_err(err)?.clone_from(&peers);wake_sender(&sender_wake);}
                if sid!=id {continue;}last_packet=Instant::now();
                match kind {
                    HELLO if body==cfg.hello()=>{socket.send_to(&wire(ACCEPT,id,body),from).await?;},
                    PING if body.len()==8=>{socket.send_to(&wire(PONG,id,body),from).await?;},
                    PONG if body.len()==8=>{
                        let nonce=u64::from_be_bytes(body.try_into().unwrap());
                        if let Some(i)=outstanding[path].iter().position(|(n,_)|*n==nonce) {
                            let(_,sent)=outstanding[path].remove(i).unwrap();paths.lock().map_err(err)?.observe(path,sent.elapsed(),start.elapsed());wake_sender(&sender_wake);
                        }
                    },
                    RAW_RECEIPT=>{if !cfg.low_latency&&let Some(receipt)=RawReceipt::decode(body){let _=command_tx.try_send(Command::RawReceipt(receipt));wake_sender(&sender_wake);}},
                    ACK=>{if let Some(fb)=Feedback::decode(body){let _=command_tx.try_send(Command::Feedback(fb));wake_sender(&sender_wake);}},
                    FIN_ACK if body.len()==8=>{let _=command_tx.try_send(Command::FinAck(u64::from_be_bytes(body.try_into().unwrap())));wake_sender(&sender_wake);},
                    EXTENT if body.len()==9&&body[8]<=1=>{
                        let extent=u64::from_be_bytes(body[..8].try_into().unwrap());
                        if extent>next+WINDOW as u64 {continue;}
                        highest=highest.max(extent);
                        if body[8]==1 {
                            if extent<next||remote_fin.is_some_and(|old|old!=extent){return Err(err("conflicting peer FIN"));}
                            remote_fin=Some(extent);
                        }
                        if cfg.low_latency{ack_requested=true;feedback_at=tokio::time::Instant::now();}
                    },
                    DATA|RETRY=>{
                        let Ok(frame)=Frame::decode(body,cfg.fec.max_payload)else{continue;};
                        let(base,last)=match &frame {
                            Frame::Source {..}=>{let Ok(Some(seq))=source_sequence(&frame,cfg.lanes)else{continue;};(seq,seq)},
                            Frame::Repair {base,data,..}=>{
                                let Some(last)=base.checked_add((u64::from(*data)-1)*cfg.lanes as u64)else{continue;};(*base,last)
                            },
                        };
                        // Observe wire arrivals before the delivery/replay-window rejection:
                        // a source may legitimately arrive after an earlier FEC reconstruction.
                        if kind==RETRY {report.path_rx_retry_datagrams[path]+=1;}
                        else if matches!(&frame,Frame::Source {..}) {
                            report.path_rx_source_datagrams[path]+=1;
                            if !cfg.low_latency&&base<next+WINDOW as u64 {delivery.original(base);}
                        }
                        else {report.path_rx_repair_datagrams[path]+=1;}
                        if last<next||base>=next+WINDOW as u64||last>=next+WINDOW as u64{continue;}
                        if remote_fin.is_some_and(|extent|last>=extent){return Err(err("data past peer FIN"));}
                        let Ok(values)=decode_interleaved(&mut decoder,&frame,cfg.lanes)else{continue;};
                        highest=highest.max(last.saturating_add(1));
                        for d in values {
                            if d.seq<next||d.seq>=next+WINDOW as u64{continue;}
                            if let std::collections::btree_map::Entry::Vacant(entry)=pending.entry(d.seq) {
                                if d.recovered{report.rx_fec_recovered+=1;}
                                gaps.remove(&d.seq);entry.insert(d.payload);
                            }
                        }
                        if cfg.low_latency{feedback_at=tokio::time::Instant::now();}
                    },
                    _=>{},
                }
            },
        }
    }
    let tx=tx_report.ok_or_else(||err("sender incomplete"))?;
    report.tx_payload_bytes=tx.bytes;report.tx_wire_bytes=tx.wire;report.tx_retries=tx.retries;report.tx_local_send_drops=tx.local_drops;
    report.max_send_history=tx.max_history;report.path_source_packets=tx.sources;
    report.path_repair_packets=tx.repairs;report.path_retry_packets=tx.retry_paths;report.path_samples=tx.samples.into_iter().collect();
    report.path_state=paths.lock().map_err(err)?.snapshots(start.elapsed());report.path_addresses=socket.physical_peers(&peers);report.elapsed_s=start.elapsed().as_secs_f64();
    socket.mark_clean();
    Ok(report)
}
