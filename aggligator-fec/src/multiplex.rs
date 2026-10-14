//! Socket-sharing multiplexer for independent FEC TCP sessions.
//!
//! One receiver owns each physical socket. AFM3 identifies a flow and a stable
//! (client access link, server entrance) lane; the payload remains the existing
//! FEC protocol. Data is not encrypted/authenticated by this envelope. Admission
//! still relies on the TLS-provisioned source/relay allowlist. No arbitrary target
//! is accepted from UDP: the application negotiates a configured service ID.
use crate::{datagram::{Datagram,try_send_batch},pacing::PacingClock};
use std::{collections::{BTreeMap,VecDeque},io,net::{IpAddr,SocketAddr},sync::{Arc,Mutex,atomic::{AtomicBool,AtomicU64,Ordering}},time::{Duration,Instant}};
use tokio::{net::UdpSocket,sync::{mpsc,watch},task::AbortHandle};

pub const ACCESSES:usize=4;
pub const ENTRANCES:usize=8;
pub const LANES:usize=ACCESSES*ENTRANCES;
pub const HEADER:usize=13;
pub const MAX_FLOWS:usize=32;
const INBOX:usize=1024;
const RETIRED:usize=4096;
const CANCEL:u8=13;
const CANCEL_LIFETIME:Duration=Duration::from_secs(2);
const CLOSED_LIFETIME:Duration=Duration::from_secs(2);
const MAX_CLOSED:usize=1024;
const CLOSE_REPLY_INTERVAL:Duration=Duration::from_millis(5);
fn error(e:impl std::fmt::Display)->io::Error{io::Error::other(e.to_string())}
pub fn virtual_peer(lane:usize)->SocketAddr{SocketAddr::from(([127,0,0,1],lane as u16+1))}
fn lane_of(peer:SocketAddr)->io::Result<usize>{
    let n=usize::from(peer.port());if peer.ip()!=IpAddr::from([127,0,0,1])||!(1..=LANES).contains(&n){return Err(error("invalid virtual lane"));}Ok(n-1)
}
pub fn decode(bytes:&[u8])->Option<(u64,usize,&[u8])>{
    if bytes.len()<HEADER+13||bytes.len()>1600||&bytes[..4]!=b"AFM3"{return None;}
    let flow=u64::from_be_bytes(bytes[4..12].try_into().ok()?);let lane=bytes[12]as usize;
    if flow==0||lane>=LANES||&bytes[HEADER..HEADER+4]!=b"AFL1"{return None;}
    Some((flow,lane,&bytes[HEADER..]))
}
fn encode(flow:u64,lane:usize,body:&[u8])->Vec<u8>{
    let mut bytes=Vec::with_capacity(HEADER+body.len());bytes.extend_from_slice(b"AFM3");bytes.extend_from_slice(&flow.to_be_bytes());bytes.push(lane as u8);bytes.extend_from_slice(body);bytes
}
fn hello(body:&[u8])->bool{body.len()>=23&&body[4]==9&&body[5..13]!=[0;8]&&body[13..].starts_with(b"FECSTREAM2")}
fn association(body:&[u8])->bool{hello(body)||(body.len()==21&&body[4]==2)}
fn local_path_fault(e:&io::Error)->bool{
    #[cfg(unix)]{matches!(e.raw_os_error(),Some(libc::ENETDOWN|libc::ENETUNREACH|libc::EHOSTUNREACH|libc::EHOSTDOWN|libc::EADDRNOTAVAIL|libc::ENXIO))}
    #[cfg(not(unix))]{matches!(e.kind(),io::ErrorKind::NetworkUnreachable|io::ErrorKind::HostUnreachable|io::ErrorKind::AddrNotAvailable)}
}

#[derive(Clone,Debug)]
pub struct Route {pub socket:usize,pub destination:SocketAddr}
pub struct LinkSocket {pub socket:Arc<UdpSocket>,pub wire_mbps:u32}
struct Physical {async_socket:Arc<UdpSocket>,raw:std::net::UdpSocket}
struct Budget {start:Instant,total:PacingClock,links:Vec<PacingClock>}
impl Budget {
    fn new(total:u32,rates:&[u32])->io::Result<Self>{
        if total==0||rates.is_empty()||rates.contains(&0){return Err(error("positive link rates required"));}
        let clock=|rate|PacingClock::new(u64::from(rate)*125000,Duration::from_micros(150)).unwrap();
        Ok(Self{start:Instant::now(),total:clock(total),links:rates.iter().map(|r|clock(*r)).collect()})
    }
    fn reserve(&mut self,base:Instant,costs:&[(usize,usize)])->Instant{
        let mut due=base.saturating_duration_since(self.start);
        let total=costs.iter().map(|(_,n)|*n).sum();due=due.max(self.total.reserve(due,total));
        let mut per=[0usize;ACCESSES];for &(link,n)in costs{per[link]+=n;}
        for(index,n)in per.into_iter().enumerate().take(self.links.len()){if n>0{due=due.max(self.links[index].reserve(due,n));}}
        self.start+due
    }
}
struct Entry {tx:mpsc::Sender<(Vec<u8>,SocketAddr)>,routes:Arc<Mutex<Vec<Option<Route>>>>,updates:watch::Sender<Vec<SocketAddr>>,session:Arc<AtomicU64>,finished:Arc<AtomicBool>}
struct Cancellation {session:u64,routes:Vec<(usize,Route)>,until:Instant,next:Instant}
// Closed flows have no receive inbox, worker or admission slot. Only an exact
// repeated peer FIN can elicit its final cumulative ACK and FIN_ACK; no DATA or
// HELLO can revive one. The fixed expiry never extends on incoming traffic.
struct Closed {session:u64,extent:u64,routes:Vec<(usize,Route)>,until:Instant,next:Instant}
struct Inner {flows:BTreeMap<u64,Entry>,retired:VecDeque<u64>,cancellations:BTreeMap<u64,Cancellation>,closed:BTreeMap<u64,Closed>,client_routes:Vec<Option<Route>>,allowed:Vec<IpAddr>,relays:Vec<SocketAddr>}
#[derive(Default)]
pub struct Counters {pub tx_packets:AtomicU64,pub rx_packets:AtomicU64,pub demux_drops:AtomicU64,pub rejected:AtomicU64,pub local_path_errors:AtomicU64}
pub struct Hub {
    physical:Vec<Physical>,inner:Mutex<Inner>,budget:Mutex<Budget>,weights:Mutex<Vec<u32>>,
    incoming:Option<mpsc::Sender<Arc<FlowIo>>>,tasks:Mutex<Vec<AbortHandle>>,pub counters:Counters,
}
impl Drop for Hub{fn drop(&mut self){if let Ok(tasks)=self.tasks.get_mut(){for task in tasks{task.abort();}}}}
pub struct FlowIo {
    pub id:u64,hub:Arc<Hub>,routes:Arc<Mutex<Vec<Option<Route>>>>,session:Arc<AtomicU64>,finished:Arc<AtomicBool>,
    rx:tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>,SocketAddr)>>,updates:watch::Receiver<Vec<SocketAddr>>,
}
impl Drop for FlowIo {fn drop(&mut self){self.hub.remove(self.id,&self.finished);}}
impl Hub {
    fn create(sockets:Vec<LinkSocket>,total:u32,weights:Vec<u32>,incoming:Option<mpsc::Sender<Arc<FlowIo>>>)->io::Result<Arc<Self>>{
        if sockets.is_empty()||sockets.len()>ACCESSES||weights.is_empty()||weights.len()>ACCESSES{return Err(error("one to four access sockets/weights required"));}
        let physical=sockets.into_iter().map(|s|{
            let raw:std::net::UdpSocket=socket2::SockRef::from(&*s.socket).try_clone()?.into();
            Ok(Physical{raw,async_socket:s.socket})
        }).collect::<io::Result<Vec<_>>>()?;
        let this=Arc::new(Self{physical,inner:Mutex::new(Inner{flows:BTreeMap::new(),retired:VecDeque::new(),cancellations:BTreeMap::new(),closed:BTreeMap::new(),client_routes:vec![None;LANES],allowed:Vec::new(),relays:Vec::new()}),
            budget:Mutex::new(Budget::new(total,&weights)?),weights:Mutex::new(weights),incoming,tasks:Mutex::new(Vec::new()),counters:Counters::default()});
        for index in 0..this.physical.len(){
            let weak=Arc::downgrade(&this);let socket=this.physical[index].async_socket.clone();
            let task=tokio::spawn(async move{
                let mut buf=[0u8;1600];loop{
                    let Ok((n,from))=socket.recv_from(&mut buf).await else{break;};
                    let Some(hub)=weak.upgrade()else{break;};hub.receive(index,from,&buf[..n]);
                }
            });this.tasks.lock().map_err(error)?.push(task.abort_handle());
        }
        // Retransmit an abort notification briefly on up to two known routes.
        // Lost aborts still have the existing peer-idle timeout as a final bound.
        let weak=Arc::downgrade(&this);
        let task=tokio::spawn(async move{
            let mut timer=tokio::time::interval(Duration::from_millis(100));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop{timer.tick().await;let Some(hub)=weak.upgrade()else{break;};hub.send_cancellations();}
        });this.tasks.lock().map_err(error)?.push(task.abort_handle());
        Ok(this)
    }
    pub fn client(sockets:Vec<LinkSocket>,total:u32)->io::Result<Arc<Self>>{
        let weights=sockets.iter().map(|s|s.wire_mbps).collect();Self::create(sockets,total,weights,None)
    }
    pub fn server(socket:Arc<UdpSocket>,total:u32,access_rates:Vec<u32>)->io::Result<(Arc<Self>,mpsc::Receiver<Arc<FlowIo>>)>{
        let(tx,rx)=mpsc::channel(MAX_FLOWS);
        Ok((Self::create(vec![LinkSocket{socket,wire_mbps:total}],total,access_rates,Some(tx))?,rx))
    }
    pub fn set_admission(&self,allowed:Vec<IpAddr>,relays:Vec<SocketAddr>)->io::Result<()> {
        let mut inner=self.inner.lock().map_err(error)?;inner.allowed=allowed;inner.relays=relays;
        // Removed relays stop receiving new traffic. Historical lane identity is
        // preserved; an admitted new association can fill it without mixing flows.
        for entry in inner.flows.values(){
            let mut routes=entry.routes.lock().map_err(error)?;
            for route in routes.iter_mut(){if route.as_ref().is_some_and(|r|!inner.allowed.contains(&r.destination.ip())&&!inner.relays.contains(&r.destination)){*route=None;}}
            Self::publish(entry,&routes);
        }
        let allowed=inner.allowed.clone();let relays=inner.relays.clone();
        for closed in inner.closed.values_mut(){closed.routes.retain(|(_,r)|allowed.contains(&r.destination.ip())||relays.contains(&r.destination));}
        Ok(())
    }
    pub fn set_access_rates(&self,rates:Vec<u32>,total:u32)->io::Result<()> {
        if rates.is_empty()||rates.len()>ACCESSES||rates.contains(&0){return Err(error("invalid access rates"));}
        let mut weights=self.weights.lock().map_err(error)?;
        if *weights!=rates{*self.budget.lock().map_err(error)?=Budget::new(total,&rates)?;*weights=rates;}Ok(())
    }
    pub fn set_routes(&self,routes:Vec<Option<Route>>)->io::Result<()> {
        if routes.len()!=LANES||routes.iter().flatten().any(|r|r.socket>=self.physical.len()||r.destination.port()==0){return Err(error("invalid route map"));}
        let mut inner=self.inner.lock().map_err(error)?;inner.client_routes=routes.clone();
        for entry in inner.flows.values(){entry.routes.lock().map_err(error)?.clone_from(&routes);Self::publish(entry,&routes);}
        for closed in inner.closed.values_mut(){closed.routes.retain(|(lane,old)|routes[*lane].as_ref().is_some_and(|r|r.socket==old.socket&&r.destination==old.destination));}
        Ok(())
    }
    fn publish(entry:&Entry,routes:&[Option<Route>]){
        let peers=routes.iter().enumerate().filter(|(_,r)|r.is_some()).map(|(lane,_)|virtual_peer(lane)).collect::<Vec<_>>();
        entry.updates.send_if_modified(|old|if *old!=peers{*old=peers.clone();true}else{false});
    }
    fn flow(self:&Arc<Self>,id:u64,inner:&mut Inner)->io::Result<Arc<FlowIo>>{
        if inner.flows.len()>=MAX_FLOWS||inner.flows.contains_key(&id)||inner.retired.contains(&id)||inner.closed.contains_key(&id){return Err(error("flow limit/duplicate/retired identifier"));}
        let routes=Arc::new(Mutex::new(if self.incoming.is_none(){inner.client_routes.clone()}else{vec![None;LANES]}));
        let peers=routes.lock().map_err(error)?.iter().enumerate().filter(|(_,r)|r.is_some()).map(|(i,_)|virtual_peer(i)).collect();
        let(tx,rx)=mpsc::channel(INBOX);let(updates,watch)=watch::channel(peers);let session=Arc::new(AtomicU64::new(0));let finished=Arc::new(AtomicBool::new(false));
        inner.flows.insert(id,Entry{tx,routes:routes.clone(),updates,session:session.clone(),finished:finished.clone()});
        Ok(Arc::new(FlowIo{id,hub:self.clone(),routes,session,finished,rx:tokio::sync::Mutex::new(rx),updates:watch}))
    }
    pub fn open(self:&Arc<Self>)->io::Result<Arc<FlowIo>>{
        let id=rand::random::<u64>().max(1);let mut inner=self.inner.lock().map_err(error)?;self.flow(id,&mut inner)
    }
    /// Background prewarming may not take the final foreground admission slot.
    #[cfg(feature="managed")]
    pub(crate) fn open_spare(self:&Arc<Self>)->io::Result<Arc<FlowIo>>{
        let id=rand::random::<u64>().max(1);let mut inner=self.inner.lock().map_err(error)?;
        if inner.flows.len()>=MAX_FLOWS-1{return Err(error("last flow slot reserved for a foreground connection"));}
        self.flow(id,&mut inner)
    }
    pub fn flow_count(&self)->usize{self.inner.lock().map_or(0,|i|i.flows.len())}
    fn retire(inner:&mut Inner,id:u64){
        if !inner.retired.contains(&id){if inner.retired.len()==RETIRED{inner.retired.pop_front();}inner.retired.push_back(id);}
    }
    fn finish_clean(&self,id:u64,session:u64,extent:u64,finished:&Arc<AtomicBool>)->io::Result<bool>{
        let now=Instant::now();let mut inner=self.inner.lock().map_err(error)?;
        inner.closed.retain(|_,c|c.until>now);
        let Some(entry)=inner.flows.get(&id)else{return Err(error("flow disappeared before clean completion"));};
        if session==0||entry.session.load(Ordering::Acquire)!=session||!Arc::ptr_eq(&entry.finished,finished){
            return Err(error("clean completion does not match the live session"));
        }
        // Never evict a still-live close record to make room. The caller keeps
        // its existing 600ms receive grace if bounded retirement is unavailable.
        if inner.closed.len()>=MAX_CLOSED{return Ok(false);}
        let routes=entry.routes.lock().map_err(error)?.iter().enumerate()
            .filter_map(|(lane,route)|route.clone().map(|r|(lane,r))).collect::<Vec<_>>();
        if routes.is_empty(){return Ok(false);}
        finished.store(true,Ordering::Release);
        inner.flows.remove(&id);
        inner.closed.insert(id,Closed{session,extent,routes,until:now+CLOSED_LIFETIME,next:now});
        Self::retire(&mut inner,id);Ok(true)
    }
    fn send_close_reply(&self,id:u64,session:u64,extent:u64,routes:&[(usize,Route)]){
        let feedback=crate::recovery::Feedback{next:extent,base:extent,limit:extent,missing:0}.encode().unwrap();
        let mut ack=b"AFL1".to_vec();ack.push(6);ack.extend(session.to_be_bytes());ack.extend(feedback);
        let mut fin_ack=b"AFL1".to_vec();fin_ack.push(11);fin_ack.extend(session.to_be_bytes());fin_ack.extend(extent.to_be_bytes());
        for (lane,route)in routes{
            // Return copies on every still-authorized route: the usable upload
            // path need not be the usable download path during asymmetric loss.
            for body in [&ack,&fin_ack]{
                let bytes=encode(id,*lane,body);
                match self.physical[route.socket].async_socket.try_send_to(&bytes,route.destination){
                    Ok(_)=>{self.counters.tx_packets.fetch_add(1,Ordering::Relaxed);},
                    Err(e)if local_path_fault(&e)=>{self.counters.local_path_errors.fetch_add(1,Ordering::Relaxed);},
                    Err(_)=>{}, // The peer retries its FIN; never queue unbounded controls.
                }
            }
        }
    }
    fn remove(&self,id:u64,finished:&Arc<AtomicBool>){
        if let Ok(mut inner)=self.inner.lock()
            &&inner.flows.get(&id).is_some_and(|entry|Arc::ptr_eq(&entry.finished,finished))
            &&let Some(entry)=inner.flows.remove(&id){
                let session=entry.session.load(Ordering::Relaxed);
                if session!=0&&!entry.finished.swap(true,Ordering::AcqRel){
                    let routes=entry.routes.lock().map_or_else(|_|Vec::new(),|r|r.iter().enumerate()
                        .filter_map(|(lane,route)|route.clone().map(|r|(lane,r))).take(2).collect());
                    let now=Instant::now();inner.cancellations.retain(|_,c|c.until>now);
                    if inner.cancellations.len()<MAX_FLOWS*4 {
                        inner.cancellations.insert(id,Cancellation{session,routes,until:now+CANCEL_LIFETIME,next:now});
                    }
                }
                Self::retire(&mut inner,id);
        }
        self.send_cancellations();
    }
    fn send_cancellations(&self){
        let mut packets=Vec::new();
        if let Ok(mut inner)=self.inner.lock(){
            let now=Instant::now();inner.cancellations.retain(|_,c|c.until>now);inner.closed.retain(|_,c|c.until>now);
            for (&id,c) in &mut inner.cancellations{
                if c.next>now{continue;}c.next=now+Duration::from_millis(100);
                let mut body=b"AFL1".to_vec();body.push(CANCEL);body.extend(c.session.to_be_bytes());
                for (lane,route)in &c.routes{packets.push((route.clone(),encode(id,*lane,&body)));}
            }
        }
        for (route,bytes)in packets{if self.physical[route.socket].async_socket.try_send_to(&bytes,route.destination).is_ok(){
            self.counters.tx_packets.fetch_add(1,Ordering::Relaxed);
        }}
    }
    fn receive(self:&Arc<Self>,socket:usize,from:SocketAddr,bytes:&[u8]){
        let Some((id,lane,body))=decode(bytes)else{self.counters.rejected.fetch_add(1,Ordering::Relaxed);return;};
        let Ok(mut inner)=self.inner.lock()else{return;};
        if self.incoming.is_some()&&!inner.allowed.contains(&from.ip())&&!inner.relays.contains(&from){self.counters.rejected.fetch_add(1,Ordering::Relaxed);return;}
        let now=Instant::now();
        if inner.closed.get(&id).is_some_and(|c|c.until<=now){inner.closed.remove(&id);}
        if let Some(closed)=inner.closed.get_mut(&id){
            let sid=u64::from_be_bytes(body[5..13].try_into().unwrap());
            let valid=body.len()==22&&body[4]==7&&body[21]==1&&sid==closed.session
                &&u64::from_be_bytes(body[13..21].try_into().unwrap())==closed.extent
                &&closed.routes.iter().any(|(l,r)|*l==lane&&r.socket==socket&&r.destination==from);
            let reply=if valid&&now>=closed.next{
                closed.next=now+CLOSE_REPLY_INTERVAL;
                Some((closed.session,closed.extent,closed.routes.clone()))
            }else{None};
            drop(inner);
            if let Some((session,extent,routes))=reply{self.send_close_reply(id,session,extent,&routes);}
            return;
        }
        // Cancellation cannot allocate a flow or establish/rebind a path. Require
        // the existing session ID AND its exact receiving socket/source tuple.
        if body.len()==13&&body[4]==CANCEL {
            let sid=u64::from_be_bytes(body[5..13].try_into().unwrap());
            let valid=inner.flows.get(&id).is_some_and(|entry|sid!=0&&entry.session.load(Ordering::Relaxed)==sid
                &&entry.routes.lock().is_ok_and(|r|r[lane].as_ref().is_some_and(|p|p.socket==socket&&p.destination==from)));
            if valid{
                if let Some(entry)=inner.flows.remove(&id){entry.finished.store(true,Ordering::Release);}
                Self::retire(&mut inner,id);
            }else{self.counters.rejected.fetch_add(1,Ordering::Relaxed);}
            return;
        }
        let mut accepted=None;
        if !inner.flows.contains_key(&id){
            if self.incoming.is_none()||!hello(body){return;}
            let Ok(flow)=self.flow(id,&mut inner)else{return;};accepted=Some(flow);
        }
        let Some(entry)=inner.flows.get(&id)else{return;};
        let sid=u64::from_be_bytes(body[5..13].try_into().unwrap());
        if hello(body){let _=entry.session.compare_exchange(0,sid,Ordering::Relaxed,Ordering::Relaxed);}
        if sid!=0&&sid!=entry.session.load(Ordering::Relaxed){return;}
        let Ok(mut routes)=entry.routes.lock()else{return;};
        if self.incoming.is_some(){
            let route=&mut routes[lane];
            if route.as_ref().is_none_or(|r|r.socket!=socket||r.destination!=from){
                if !association(body){return;}
                *route=Some(Route{socket,destination:from});Self::publish(entry,&routes);
            }
        }else if routes[lane].as_ref().is_none_or(|r|r.socket!=socket||r.destination!=from){return;}
        self.counters.rx_packets.fetch_add(1,Ordering::Relaxed);
        if entry.tx.try_send((body.to_vec(),virtual_peer(lane))).is_err(){self.counters.demux_drops.fetch_add(1,Ordering::Relaxed);}
        drop(routes);drop(inner);
        if let Some(flow)=accepted&&let Some(accept)=&self.incoming{let _=accept.try_send(flow);}
    }
}
impl FlowIo {
    /// Called only after both FIN exchanges and all application delivery completed.
    pub fn mark_clean(&self){self.finished.store(true,Ordering::Release);}
    /// The session has proved both FINs, outgoing cumulative ACKs and complete
    /// application output. Transfer only final ACK repetition to the hub.
    pub(crate) fn finish_clean(&self,session:u64,extent:u64)->io::Result<bool>{
        self.hub.finish_clean(self.id,session,extent,&self.finished)
    }
    pub fn updates(&self)->watch::Receiver<Vec<SocketAddr>>{self.updates.clone()}
    pub fn weights(&self)->Vec<u32>{self.hub.weights.lock().map_or_else(|_|vec![1],|w|w.clone())}
    pub fn physical_peers(&self)->Vec<SocketAddr>{
        self.routes.lock().map_or_else(|_|Vec::new(),|routes|routes.iter().map(|r|r.as_ref().map_or(SocketAddr::from(([0,0,0,0],0)),|r|r.destination)).collect())
    }
    pub fn wire_size(&self,packet:&Datagram)->io::Result<usize>{
        let lane=lane_of(packet.destination)?;let routes=self.routes.lock().map_err(error)?;
        Ok(packet.payload.len()+HEADER+if routes[lane].as_ref().is_some_and(|r|r.destination.is_ipv6()){48}else{28})
    }
    pub async fn recv_from(&self,buf:&mut[u8])->io::Result<(usize,SocketAddr)>{
        if self.finished.load(Ordering::Acquire){return Err(io::Error::new(io::ErrorKind::ConnectionReset,"remote flow cancelled"));}
        let mut rx=self.rx.lock().await;let(body,from)=rx.recv().await.ok_or_else(||io::Error::new(io::ErrorKind::ConnectionReset,"multiplexed flow closed by peer"))?;
        if body.len()>buf.len(){return Err(error("flow packet too large"));}buf[..body.len()].copy_from_slice(&body);Ok((body.len(),from))
    }
    pub async fn send_to(&self,body:&[u8],to:SocketAddr)->io::Result<usize>{
        if self.finished.load(Ordering::Acquire){return Err(error("flow is closed"));}
        if hello(body){let sid=u64::from_be_bytes(body[5..13].try_into().unwrap());let _=self.session.compare_exchange(0,sid,Ordering::Relaxed,Ordering::Relaxed);}
        let lane=lane_of(to)?;let route=self.routes.lock().map_err(error)?[lane].clone();
        let Some(route)=route else{return Ok(body.len());};
        // Small control packets bypass data queues so a saturated upload cannot
        // deadlock download ACKs. They are accounted separately from data budgets.
        let packet=encode(self.id,lane,body);
        match self.hub.physical[route.socket].async_socket.try_send_to(&packet,route.destination){
            Ok(_)=>{self.hub.counters.tx_packets.fetch_add(1,Ordering::Relaxed);},
            Err(e)if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>{},
            Err(e)if local_path_fault(&e)=>{self.hub.counters.local_path_errors.fetch_add(1,Ordering::Relaxed);},
            Err(e)=>return Err(e),
        }Ok(body.len())
    }
    pub fn reserve(&self,packets:&[Datagram],base:Instant)->io::Result<Instant>{
        if self.finished.load(Ordering::Acquire){return Err(error("flow is closed"));}
        let routes=self.routes.lock().map_err(error)?;
        let mut costs=Vec::with_capacity(packets.len());
        for packet in packets{
            let lane=lane_of(packet.destination)?;
            if let Some(route)=&routes[lane]{let link=lane/ENTRANCES;costs.push((link,packet.payload.len()+HEADER+if route.destination.is_ipv4(){28}else{48}));}
        }
        self.hub.budget.lock().map_err(error).map(|mut b|b.reserve(base,&costs))
    }
    pub fn send_batch(&self,packets:&[Datagram])->io::Result<usize>{
        if self.finished.load(Ordering::Acquire){return Err(error("flow is closed"));}
        let routes=self.routes.lock().map_err(error)?;let mut submitted=0;
        while submitted<packets.len(){
            let lane=lane_of(packets[submitted].destination)?;
            let Some(route)=routes[lane].clone()else{submitted+=1;continue;};
            let socket=route.socket;let mut batch=Vec::with_capacity(packets.len()-submitted);
            for packet in &packets[submitted..]{
                let lane=lane_of(packet.destination)?;
                let Some(route)=&routes[lane]else{break;};if route.socket!=socket{break;}
                batch.push(Datagram{destination:route.destination,payload:encode(self.id,lane,&packet.payload)});
            }
            match try_send_batch(&self.hub.physical[socket].raw,&batch){
                Ok(n)=>{self.hub.counters.tx_packets.fetch_add(n as u64,Ordering::Relaxed);submitted+=n;if n<batch.len(){break;}},
                Err(e)if local_path_fault(&e)=>{
                    // Treat this access link as temporarily lossy, not the entire
                    // TCP connection as broken. Reliable history remains intact.
                    self.hub.counters.local_path_errors.fetch_add(batch.len()as u64,Ordering::Relaxed);submitted+=batch.len();
                },
                Err(_)if submitted>0=>break,
                Err(e)=>return Err(e),
            }
        }Ok(submitted)
    }
}

/// Relay return table distinguishes simultaneous streams AND broadband lanes.
/// An old or different source tuple cannot hijack an established association.
pub struct RelayTable {entries:BTreeMap<(u64,usize),RelayEntry>,max:usize,ttl:Duration,low_latency:bool}
struct RelayEntry {source:SocketAddr,last_seen:Instant,session:u64,fin_acks:u8,closed_until:Option<Instant>}
impl RelayEntry {
    fn expired(&self,now:Instant,ttl:Duration)->bool{
        self.closed_until.is_some_and(|until|now>=until)||now.saturating_duration_since(self.last_seen)>=ttl
    }
    fn observe(&mut self,body:&[u8],from_master:bool,now:Instant,low_latency:bool){
        self.last_seen=now;
        if low_latency&&body.len()==21&&body[4]==11 {
            self.fin_acks|=if from_master{1}else{2};
            // A one-way FIN_ACK is normal for a half-closed TCP stream. Only
            // both directions prove that both peers have seen the other's EOF.
            if self.fin_acks==3&&self.closed_until.is_none(){self.closed_until=Some(now+CLOSED_LIFETIME);}
        }
    }
}
impl Default for RelayTable{fn default()->Self{Self{entries:BTreeMap::new(),max:MAX_FLOWS*LANES,ttl:Duration::from_secs(60),low_latency:false}}}
impl RelayTable {
    pub fn set_low_latency(&mut self,enabled:bool){
        self.low_latency=enabled;
        if !enabled{for entry in self.entries.values_mut(){entry.fin_acks=0;entry.closed_until=None;}}
    }
    pub fn prune(&mut self,now:Instant,allowed:&[IpAddr]){self.entries.retain(|_,entry|allowed.contains(&entry.source.ip())&&!entry.expired(now,self.ttl));}
    pub fn route(&mut self,bytes:&[u8],from:SocketAddr,master:SocketAddr,allowed:&[IpAddr],now:Instant)->Option<SocketAddr>{
        let(flow,lane,body)=decode(bytes)?;
        let sid=u64::from_be_bytes(body[5..13].try_into().ok()?);
        let key=(flow,lane);
        if self.entries.get(&key).is_some_and(|entry|entry.expired(now,self.ttl)){self.entries.remove(&key);}
        if from==master{
            let entry=self.entries.get_mut(&key)?;if sid!=entry.session{return None;}
            entry.observe(body,true,now,self.low_latency);return Some(entry.source);
        }
        if !allowed.contains(&from.ip()){return None;}
        if !self.entries.contains_key(&key){
            if !association(body){return None;}
            if self.low_latency{
                self.prune(now,allowed);
                if self.entries.len()>=self.max {
                    // A relay can miss one side's final ACK on a multipath flow.
                    // Under pressure reclaim only a stale route; live and warm
                    // sessions refresh these entries with their 500ms PINGs.
                    // A recovered path can re-associate on its next PING. DATA
                    // racing that PING remains recoverable by ARQ/other copies.
                    let stale=self.entries.iter().filter(|(_,entry)|now.saturating_duration_since(entry.last_seen)>Duration::from_secs(3))
                        .min_by_key(|(_,entry)|entry.last_seen).map(|(key,_)|*key);
                    if let Some(stale)=stale{self.entries.remove(&stale);}
                }
            }
            if self.entries.len()>=self.max{return None;}
            self.entries.insert(key,RelayEntry{source:from,last_seen:now,session:sid,fin_acks:0,closed_until:None});
        }
        let entry=self.entries.get_mut(&key)?;
        if sid!=entry.session{return None;}
        if entry.source!=from{
            // A recovered WAN may get a new NAT port. Only a matching session's
            // association from an already control-admitted IP can update it.
            if !association(body){return None;}entry.source=from;
        }
        entry.observe(body,false,now,self.low_latency);Some(master)
    }
    pub fn len(&self)->usize{self.entries.len()}
    pub fn is_empty(&self)->bool{self.entries.is_empty()}
}

#[cfg(test)]
mod close_tests {
    use super::*;

    #[tokio::test]
    async fn full_close_cache_preserves_active_fallback_and_old_drop_cannot_remove_a_new_generation() {
        let socket=Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let hub=Hub::client(vec![LinkSocket{socket,wire_mbps:80}],80).unwrap();
        let route=Route{socket:0,destination:"127.0.0.1:9999".parse().unwrap()};
        let mut routes=vec![None;LANES];routes[0]=Some(route.clone());hub.set_routes(routes).unwrap();
        let old={let mut inner=hub.inner.lock().unwrap();hub.flow(10_000,&mut inner).unwrap()};
        old.session.store(71,Ordering::Release);
        let now=Instant::now();
        {
            let mut inner=hub.inner.lock().unwrap();
            for id in 1..=MAX_CLOSED as u64{
                inner.closed.insert(id,Closed{session:1,extent:0,routes:vec![(0,route.clone())],
                    until:now+CLOSED_LIFETIME,next:now});
            }
        }
        assert!(!old.finish_clean(71,1).unwrap(),"a full close cache must keep the existing receive grace");
        assert_eq!(hub.flow_count(),1);assert!(!old.finished.load(Ordering::Acquire));
        hub.inner.lock().unwrap().closed.get_mut(&1).unwrap().until=now-Duration::from_secs(1);
        assert!(old.finish_clean(71,1).unwrap());
        assert_eq!(hub.flow_count(),0);
        assert_eq!(hub.inner.lock().unwrap().closed.len(),MAX_CLOSED);

        // Simulate expiry plus retirement-ring turnover while an old FlowIo is
        // still held externally. Its eventual Drop must not remove a later flow
        // that happens to reuse the identifier.
        let replacement={
            let mut inner=hub.inner.lock().unwrap();
            inner.closed.remove(&old.id);inner.retired.retain(|id|*id!=old.id);
            hub.flow(old.id,&mut inner).unwrap()
        };
        replacement.session.store(72,Ordering::Release);
        drop(old);
        assert_eq!(hub.flow_count(),1);
        assert!(!replacement.finished.load(Ordering::Acquire));
        assert_eq!(hub.inner.lock().unwrap().flows[&replacement.id].session.load(Ordering::Acquire),72);
    }
}
