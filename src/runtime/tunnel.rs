use super::{
    MAX_PATHS, MAX_PAYLOAD, QUEUE, transport,
    wire::{self, Receiver, Record},
};
use crate::fec::Encoder;
use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, Bytes};
use h3::ConnectionState;
use http::{Method, Request, Response, StatusCode};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    net::UdpSocket,
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
    time::{MissedTickBehavior, interval, timeout},
};
use tracing::{info, warn};

const MAX_FLOWS: usize = 64;
const SESSION_PATH: &str = "/session";
const WEBSITE: &str = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Welcome</title><h1>Welcome</h1><p>This service is online.</p></html>\n";

#[derive(Clone, Debug)]
pub struct Policy {
    pub fec: u8,
    pub redundancy: u8,
    pub rate: u64,
    pub block_ms: u64,
    pub queue_ms: u64,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.fec <= 32 && self.redundancy <= 100,
            "invalid FEC configuration"
        );
        ensure!(
            (64_000..=1_000_000_000).contains(&self.rate),
            "rate must be 64000..1000000000 bits/s"
        );
        ensure!(
            (1..=100).contains(&self.block_ms) && (1..=1000).contains(&self.queue_ms),
            "invalid deadline"
        );
        Ok(())
    }
}
#[derive(Clone)]
struct OutPath {
    id: u8,
    conn: quinn::Connection,
    stream: u64,
}
type Paths = Arc<Mutex<Vec<OutPath>>>;
struct Pending {
    data: Bytes,
    created: Instant,
}

/// One owner for the aggregate encoder, budget, pacer and all datagram queues.
async fn sender(
    mut input: mpsc::Receiver<Record>,
    paths: Paths,
    policy: Policy,
    mut stop: watch::Receiver<bool>,
) {
    let mut encoder = Encoder::new(policy.fec.max(1), Duration::from_millis(policy.block_ms))
        .expect("validated policy");
    let mut queue = VecDeque::<Pending>::new();
    let mut credit = 0usize;
    let mut cursor = 0usize;
    let mut sent = 0u64;
    let mut drops = 0u64;
    let mut repairs = 0u64;
    let mut skipped = 0u64;
    let mut tokens = 0f64;
    let mut last = Instant::now();
    let mut tick = interval(Duration::from_millis(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let enqueue = |data: Bytes, queue: &mut VecDeque<Pending>, drops: &mut u64| {
        if queue.len() < QUEUE {
            queue.push_back(Pending {
                data,
                created: Instant::now(),
            });
        } else {
            *drops += 1;
        }
    };
    let mut add = |s: crate::fec::Shard,
                   queue: &mut VecDeque<Pending>,
                   drops: &mut u64,
                   credit: &mut usize| {
        let repair = matches!(s, crate::fec::Shard::Repair { .. });
        let data = wire::shard(s);
        if repair {
            if *credit < data.len() * 100 {
                skipped += 1;
                return;
            }
            *credit -= data.len() * 100;
            repairs += 1;
        } else {
            *credit = (*credit + data.len() * usize::from(policy.redundancy))
                .min(2 * wire::MAX_WIRE * 100);
        }
        enqueue(data, queue, drops);
    };
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _=stop.changed()=>break,
            _=tick.tick()=>{
                if policy.fec>0&& let Some(s)=encoder.flush_due(Instant::now()){add(s,&mut queue,&mut drops,&mut credit);}
            },
            record=input.recv()=>{
                let Some(record)=record else{break};
                if policy.fec==0 {
                    match wire::plain(&record) {Ok(data)=>enqueue(data,&mut queue,&mut drops),Err(_)=>drops+=1}
                }else if let Ok(data)=record.encode() {
                    match encoder.push(&data,Instant::now()) {Ok(shards)=>for s in shards {add(s,&mut queue,&mut drops,&mut credit)},Err(_)=>drops+=1}
                }else{drops+=1;}
            }
        }
        let now = Instant::now();
        tokens = (tokens + now.duration_since(last).as_secs_f64() * policy.rate as f64 / 8.0)
            .min(8.0 * 1200.0);
        last = now;
        while let Some(front) = queue.front() {
            if now.duration_since(front.created) > Duration::from_millis(policy.queue_ms) {
                queue.pop_front();
                drops += 1;
                continue;
            }
            // Includes an allowance for QUIC, UDP and IP headers; capture actual cost separately.
            let cost = (front.data.len() + 80) as f64;
            if tokens < cost {
                break;
            }
            let mut admitted = false;
            {
                let p = paths.lock().expect("paths lock");
                for n in 0..p.len() {
                    let i = (cursor + n) % p.len();
                    let path = &p[i];
                    if path.conn.close_reason().is_some() {
                        continue;
                    }
                    let Ok(data) = wire::http_datagram(path.stream, &front.data) else {
                        continue;
                    };
                    if path
                        .conn
                        .max_datagram_size()
                        .is_none_or(|max| data.len() > max)
                    {
                        continue;
                    }
                    if path.conn.datagram_send_buffer_space() < data.len() {
                        continue;
                    }
                    if path.conn.send_datagram(data).is_ok() {
                        cursor = (i + 1) % p.len();
                        admitted = true;
                        break;
                    }
                }
            }
            if !admitted {
                break;
            }
            tokens -= cost;
            sent += 1;
            queue.pop_front();
        }
    }
    info!(sent, drops, repairs, skipped, "aggregate sender stopped");
}

enum Event {
    Wire(Bytes),
    Reply(u32, Vec<u8>),
}
struct Session {
    events: mpsc::Sender<Event>,
    paths: Paths,
    stop: watch::Sender<bool>,
    policy: Policy,
    ingress_drops: Arc<AtomicU64>,
}
type Sessions = Arc<Mutex<HashMap<String, Arc<Session>>>>;

async fn session_loop(
    session: Arc<Session>,
    mut events: mpsc::Receiver<Event>,
    target: SocketAddr,
) {
    let (tx, rx) = mpsc::channel(QUEUE);
    let mut tasks = JoinSet::new();
    tasks.spawn(sender(
        rx,
        session.paths.clone(),
        session.policy.clone(),
        session.stop.subscribe(),
    ));
    let mut stop = session.stop.subscribe();
    let mut decoder = Receiver::default();
    let mut flows: HashMap<u32, (Arc<UdpSocket>, Instant)> = HashMap::new();
    let mut next_id = 0u64;
    let mut tick = interval(Duration::from_secs(5));
    let mut dropped = 0u64;
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _=stop.changed()=>break,
            _=tick.tick()=>{
                flows.retain(|_,(_,t)|t.elapsed()<Duration::from_secs(60));
                let p=session.paths.lock().expect("paths lock");
                for path in p.iter(){let stats=path.conn.stats();info!(path=path.id,rtt_ms=path.conn.rtt().as_secs_f64()*1000.0,tx_packets=stats.udp_tx.datagrams,rx_packets=stats.udp_rx.datagrams,tx_bytes=stats.udp_tx.bytes,rx_bytes=stats.udp_rx.bytes,lost=stats.path.lost_packets,cwnd=stats.path.cwnd,"server path statistics");}
                info!(paths=p.len(),flows=flows.len(),originals=decoder.originals,recovered=decoder.recovered,duplicates=decoder.duplicates,invalid=decoder.invalid,dropped,ingress_drops=session.ingress_drops.load(Ordering::Relaxed),"server session");
            },
            e=events.recv()=>match e {
                Some(Event::Wire(data))=>{
                    let records=match decoder.receive(&data,Instant::now()){Ok(v)=>v,Err(_)=>{decoder.invalid+=1;continue}};
                    for r in records {
                        if !flows.contains_key(&r.flow) {
                            if flows.len()>=MAX_FLOWS{dropped+=1;continue}
                            let bind=if target.is_ipv4(){"0.0.0.0:0"}else{"[::]:0"};
                            let Ok(socket)=UdpSocket::bind(bind).await else{dropped+=1;continue};
                            if socket.connect(target).await.is_err() || socket.writable().await.is_err(){dropped+=1;continue}
                            let socket=Arc::new(socket); let weak=Arc::downgrade(&socket); let events=session.events.clone(); let flow=r.flow; let mut quit=session.stop.subscribe(); let ingress_drops=session.ingress_drops.clone();
                            tasks.spawn(async move {
                                let mut b=vec![0;65536];
                                loop {
                                    let Some(socket)=weak.upgrade() else{break};
                                    tokio::select! {
                                        _=quit.changed()=>break,
                                        value=timeout(Duration::from_secs(5),socket.recv(&mut b))=>match value {
                                            Ok(Ok(n)) if n<=MAX_PAYLOAD=>{if events.try_send(Event::Reply(flow,b[..n].to_vec())).is_err(){ingress_drops.fetch_add(1,Ordering::Relaxed);}},
                                            Ok(Err(_))=>break,
                                            _=>{}
                                        }
                                    }
                                }
                            });
                            flows.insert(r.flow,(socket,Instant::now()));
                        }
                        if let Some((socket,last))=flows.get_mut(&r.flow) {
                            *last=Instant::now(); if socket.try_send(&r.payload).is_err(){dropped+=1;}
                        }
                    }
                },
                Some(Event::Reply(flow,payload))=>{
                    let Some((_,last))=flows.get_mut(&flow) else{continue}; *last=Instant::now();
                    let Some(id)=next_id.checked_add(1) else{break}; next_id=id;
                    if tx.try_send(Record{flow,id,payload}).is_err(){dropped+=1;}
                },
                None=>break,
            }
        }
        while tasks.try_join_next().is_some() {}
    }
    info!(
        originals = decoder.originals,
        recovered = decoder.recovered,
        dropped,
        "server session stopped"
    );
}

pub struct ServerOptions {
    pub bind: SocketAddr,
    pub cert: std::path::PathBuf,
    pub key: std::path::PathBuf,
    pub token: std::path::PathBuf,
    pub target: SocketAddr,
    pub max_rate: u64,
    pub congestion: transport::Congestion,
}
pub async fn serve(options: ServerOptions) -> Result<()> {
    let endpoint = transport::server(
        options.bind,
        &options.cert,
        &options.key,
        options.congestion,
    )?;
    let secret = Arc::new(format!("Bearer {}", transport::token(&options.token)?));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let limit = Arc::new(Semaphore::new(128));
    let mut tasks = JoinSet::new();
    info!(address=%endpoint.local_addr()?,target=%options.target,"HTTP/3 server ready");
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            incoming=endpoint.accept()=>{
                let Some(incoming)=incoming else{break};
                let Ok(permit)=limit.clone().try_acquire_owned() else{incoming.refuse();continue};
                let sessions=sessions.clone(); let secret=secret.clone(); let target=options.target; let max_rate=options.max_rate;
                tasks.spawn(async move {
                    let _permit=permit;
                    if let Err(e)=server_connection(incoming,sessions,secret,target,max_rate).await {warn!(error=%e,"HTTP/3 connection ended");}
                });
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{}
        }
    }
    endpoint.close(0u32.into(), b"shutdown");
    for session in sessions.lock().expect("sessions lock").values() {
        let _ = session.stop.send(true);
    }
    Ok(())
}

async fn server_connection(
    incoming: quinn::Incoming,
    sessions: Sessions,
    secret: Arc<String>,
    target: SocketAddr,
    max_rate: u64,
) -> Result<()> {
    let conn = timeout(Duration::from_secs(5), incoming).await??;
    let mut h3 = h3::server::builder()
        .enable_datagram(true)
        .max_field_section_size(8192)
        .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
        .await?;
    let mut joined: Option<(String, Arc<Session>, u8, u64)> = None;
    let mut request: Option<h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>> = None;
    let admission_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let result:Result<()>=async {
        loop {
            tokio::select! {
                _=tokio::time::sleep_until(admission_deadline),if joined.is_none()=>bail!("session admission timed out"),
                accepted=h3.accept()=>{
                    let Some(resolver)=accepted? else{break};
                    let (req,mut stream)=timeout(Duration::from_secs(5),resolver.resolve_request()).await??;
                    if req.method()!=Method::POST || req.uri().path()!=SESSION_PATH {
                        let ok=req.method()==Method::GET && req.uri().path()=="/";
                        stream.send_response(Response::builder().status(if ok{StatusCode::OK}else{StatusCode::NOT_FOUND}).header("content-type","text/html; charset=utf-8").body(())?).await?;
                        stream.send_data(Bytes::from_static(if ok{WEBSITE.as_bytes()}else{b"Not found\n"})).await?; stream.finish().await?;continue
                    }
                    let auth=req.headers().get("authorization").map(|h|h.as_bytes()).unwrap_or_default();
                    if !bool::from(auth.ct_eq(secret.as_bytes())) {
                        stream.send_response(Response::builder().status(404).header("content-type","text/html; charset=utf-8").body(())?).await?;stream.send_data(Bytes::from_static(b"Not found\n")).await?;stream.finish().await?;continue
                    }
                    ensure!(joined.is_none(),"only one aggregate request per connection");
                    // Request and control streams can arrive in either order. Drive
                    // control processing before deciding whether the peer supports DATAGRAM.
                    if !h3.settings().enable_datagram() {
                        timeout(Duration::from_secs(5), std::future::poll_fn(|cx| {
                            match h3.poll_accept_request_stream(cx) {
                                Poll::Ready(Ok(_)) => Poll::Ready(Err(anyhow::anyhow!("connection ended or extra request before SETTINGS"))),
                                Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                                Poll::Pending if h3.settings().enable_datagram() => Poll::Ready(Ok(())),
                                Poll::Pending => Poll::Pending,
                            }
                        })).await??;
                    }
                    ensure!(conn.max_datagram_size().is_some_and(|n|n>=wire::MAX_WIRE+9),"peer lacks required datagram capacity");
                    let header=|name:&str|->Result<&str>{req.headers().get(name).context("missing session header")?.to_str().context("invalid session header")};
                    ensure!(header("braidpath-version")?=="1","unsupported version");
                    let sid=header("braidpath-session")?.to_owned(); ensure!(sid.len()==32 && sid.bytes().all(|b|b.is_ascii_hexdigit()),"invalid session id");
                    let pid:u8=header("braidpath-path")?.parse()?; ensure!(usize::from(pid)<MAX_PATHS,"path limit");
                    let policy=Policy{fec:header("braidpath-fec")?.parse()?,redundancy:header("braidpath-redundancy")?.parse()?,rate:header("braidpath-rate")?.parse::<u64>()?.min(max_rate),block_ms:header("braidpath-block-ms")?.parse()?,queue_ms:header("braidpath-queue-ms")?.parse()?};policy.validate()?;
                    let session={
                        let mut map=sessions.lock().expect("sessions lock");
                        if let Some(session)=map.get(&sid){
                            ensure!(session.policy.fec==policy.fec && session.policy.redundancy==policy.redundancy && session.policy.rate==policy.rate && session.policy.block_ms==policy.block_ms && session.policy.queue_ms==policy.queue_ms,"session policy mismatch"); session.clone()
                        }else{
                            ensure!(map.len()<16,"session limit");
                            let (tx,rx)=mpsc::channel(QUEUE);let (stop,_)=watch::channel(false);
                            let s=Arc::new(Session{events:tx,paths:Arc::new(Mutex::new(Vec::new())),stop,policy,ingress_drops:Arc::new(AtomicU64::new(0))});
                            map.insert(sid.clone(),s.clone());tokio::spawn(session_loop(s.clone(),rx,target));s
                        }
                    };
                    let stream_id=stream.id().into_inner();
                    {
                        let mut paths=session.paths.lock().expect("paths lock");
                        ensure!(paths.len()<MAX_PATHS && !paths.iter().any(|p|p.id==pid),"duplicate/path limit");
                        paths.push(OutPath{id:pid,conn:conn.clone(),stream:stream_id});
                    }
                    joined=Some((sid,session,pid,stream_id));
                    stream.send_response(Response::builder().status(200).header("braidpath-version","1").header("braidpath-max-payload",MAX_PAYLOAD).body(())?).await?;
                    request=Some(stream);
                    info!(path=pid,remote=%conn.remote_address(),"authenticated path joined");
                },
                data=conn.read_datagram()=>{
                    let data=data?;
                    if let Some((_,session,_,stream))=&joined
                        && let Ok(payload)=wire::http_payload(&data,*stream)
                            && payload.len()<=wire::MAX_WIRE && session.events.try_send(Event::Wire(Bytes::copy_from_slice(payload))).is_err(){session.ingress_drops.fetch_add(1,Ordering::Relaxed);}
                },
                body=async {request.as_mut().expect("guarded request").recv_data().await},if request.is_some()=>{
                    let _=body?; break; // No reliable data is defined for this request; FIN ends membership.
                }
            }
        }
        Ok(())
    }.await;
    conn.close(0u32.into(), b"request closed");
    if let Some((sid, session, pid, _)) = joined {
        let mut map = sessions.lock().expect("sessions lock");
        let mut paths = session.paths.lock().expect("paths lock");
        paths.retain(|p| p.id != pid);
        if paths.is_empty() {
            let _ = session.stop.send(true);
            map.remove(&sid);
        }
        info!(path = pid, "path left");
    }
    result
}

pub struct ClientOptions {
    pub listen: SocketAddr,
    pub entrances: Vec<SocketAddr>,
    pub interfaces: Vec<String>,
    pub name: String,
    pub ca: std::path::PathBuf,
    pub token: std::path::PathBuf,
    pub policy: Policy,
    pub congestion: transport::Congestion,
}
pub async fn client(options: ClientOptions) -> Result<()> {
    options.policy.validate()?;
    ensure!(
        !options.entrances.is_empty()
            && options.entrances.len() * options.interfaces.len().max(1) <= MAX_PATHS,
        "need 1..8 interface/entrance pairs"
    );
    let token = transport::token(&options.token)?;
    let sid = transport::hex(&rand::random::<[u8; 16]>());
    let paths: Paths = Arc::new(Mutex::new(Vec::new()));
    let (wire_tx, mut wire_rx) = mpsc::channel::<Bytes>(QUEUE);
    let mut tasks = JoinSet::new();
    let mut endpoints = Vec::new();
    let ingress_drops = Arc::new(AtomicU64::new(0));
    let interfaces: Vec<Option<&str>> = if options.interfaces.is_empty() {
        vec![None]
    } else {
        options
            .interfaces
            .iter()
            .map(|s| Some(s.as_str()))
            .collect()
    };
    for interface in interfaces {
        for entrance in &options.entrances {
            let pid = endpoints.len() as u8;
            let endpoint =
                transport::client(*entrance, &options.ca, interface, options.congestion)?;
            endpoints.push(endpoint.clone());
            let connection = timeout(
                Duration::from_secs(8),
                connect_path(
                    &endpoint,
                    *entrance,
                    &options.name,
                    &token,
                    &sid,
                    pid,
                    &options.policy,
                ),
            )
            .await;
            match connection {
                Ok(Ok((conn, stream, mut driver, mut request, send))) => {
                    paths.lock().expect("paths lock").push(OutPath {
                        id: pid,
                        conn: conn.clone(),
                        stream,
                    });
                    let tx = wire_tx.clone();
                    let ingress_drops = ingress_drops.clone();
                    tasks.spawn(async move {
                    // Dropping the last SendRequest closes the HTTP/3 connection.
                    let _send = send;
                    loop {tokio::select! {
                        _=driver.wait_idle()=>break,
                        body=request.recv_data()=>{let _=body;break},
                        d=conn.read_datagram()=>match d {
                            Ok(d)=>if let Ok(p)=wire::http_payload(&d,stream)&& p.len()<=wire::MAX_WIRE && tx.try_send(Bytes::copy_from_slice(p)).is_err(){ingress_drops.fetch_add(1,Ordering::Relaxed);},
                            Err(_)=>break,
                        }
                    }}
                    conn.close(0u32.into(),b"path ended");warn!(path=pid,"client path ended");
                });
                    info!(path=pid,remote=%entrance,interface=interface.unwrap_or("default"),"client path ready");
                }
                Ok(Err(error)) => warn!(path=pid,remote=%entrance,error=%error,"path unavailable"),
                Err(error) => {
                    warn!(path=pid,remote=%entrance,error=%error,"path connection timed out")
                }
            }
        }
    }
    ensure!(
        !paths.lock().expect("paths lock").is_empty(),
        "no authenticated paths available"
    );
    let socket = UdpSocket::bind(options.listen).await?;
    let (tx, rx) = mpsc::channel(QUEUE);
    let (stop, stop_rx) = watch::channel(false);
    tasks.spawn(sender(rx, paths.clone(), options.policy, stop_rx));
    let mut input = vec![0; 65536];
    let mut peers: HashMap<SocketAddr, (u32, Instant)> = HashMap::new();
    let mut reverse = HashMap::new();
    let mut next_flow = 0u32;
    let mut next_id = 0u64;
    let mut decoder = Receiver::default();
    let mut tick = interval(Duration::from_secs(2));
    let mut drops = 0u64;
    info!(listen=%socket.local_addr()?,paths=paths.lock().expect("paths lock").len(),"UDP client ready");
    let result:Result<()>=async {loop {tokio::select! {
        _=tokio::signal::ctrl_c()=>break,
        _=tick.tick()=>{
            peers.retain(|_,(id,last)|{if last.elapsed()<Duration::from_secs(60){true}else{reverse.remove(id);false}});
            let p=paths.lock().expect("paths lock");let live=p.iter().filter(|p|p.conn.close_reason().is_none()).count();
            for path in p.iter(){let stats=path.conn.stats();info!(path=path.id,alive=path.conn.close_reason().is_none(),rtt_ms=path.conn.rtt().as_secs_f64()*1000.0,tx_packets=stats.udp_tx.datagrams,rx_packets=stats.udp_rx.datagrams,tx_bytes=stats.udp_tx.bytes,rx_bytes=stats.udp_rx.bytes,lost=stats.path.lost_packets,cwnd=stats.path.cwnd,"path statistics");}
            info!(live,originals=decoder.originals,recovered=decoder.recovered,duplicates=decoder.duplicates,invalid=decoder.invalid,drops,ingress_drops=ingress_drops.load(Ordering::Relaxed),"client statistics");
            ensure!(live>0,"all paths failed; restart creates a fresh session epoch");
        },
        received=socket.recv_from(&mut input)=>{
            let (n,peer)=received?;
            if n>MAX_PAYLOAD{drops+=1;continue}
            if !peers.contains_key(&peer){
                if peers.len()>=MAX_FLOWS {drops+=1;continue}
                next_flow=next_flow.checked_add(1).context("flow id exhausted")?;peers.insert(peer,(next_flow,Instant::now()));reverse.insert(next_flow,peer);
            }
            let (flow,last)=peers.get_mut(&peer).expect("inserted peer");*last=Instant::now();
            next_id=next_id.checked_add(1).context("message id exhausted")?;
            if tx.try_send(Record{flow:*flow,id:next_id,payload:input[..n].to_vec()}).is_err(){drops+=1;}
        },
        data=wire_rx.recv()=>{
            let Some(data)=data else{bail!("all receivers ended")};
            match decoder.receive(&data,Instant::now()) {
                Ok(records)=>for r in records {
                    if let Some(peer)=reverse.get(&r.flow) {
                        if let Some((_,last))=peers.get_mut(peer) { *last=Instant::now(); }
                        if socket.try_send_to(&r.payload,*peer).is_err(){drops+=1;}
                    }
                },
                Err(_)=>decoder.invalid+=1,
            }
        }
    }}Ok(())}.await;
    info!(
        originals = decoder.originals,
        recovered = decoder.recovered,
        duplicates = decoder.duplicates,
        invalid = decoder.invalid,
        drops,
        ingress_drops = ingress_drops.load(Ordering::Relaxed),
        "client stopped"
    );
    let _ = stop.send(true);
    for endpoint in &endpoints {
        endpoint.close(0u32.into(), b"client stopped");
    }
    // Give close packets a bounded opportunity to leave before dropping endpoints.
    let _ = timeout(Duration::from_secs(2), async {
        for endpoint in &endpoints {
            endpoint.wait_idle().await;
        }
    })
    .await;
    result
}

type H3Client = h3::client::Connection<h3_quinn::Connection, Bytes>;
type H3Send = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3Request = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
#[allow(clippy::too_many_arguments)]
async fn connect_path(
    endpoint: &quinn::Endpoint,
    remote: SocketAddr,
    name: &str,
    token: &str,
    sid: &str,
    pid: u8,
    policy: &Policy,
) -> Result<(quinn::Connection, u64, H3Client, H3Request, H3Send)> {
    let conn = endpoint.connect(remote, name)?.await?;
    ensure!(
        conn.max_datagram_size()
            .is_some_and(|n| n >= wire::MAX_WIRE + 9),
        "insufficient datagram size"
    );
    let (mut driver, mut send) = h3::client::builder()
        .enable_datagram(true)
        .max_field_section_size(8192)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
        .await?;
    // Poll the driver concurrently so peer SETTINGS are processed before admission.
    tokio::select! {
        e=driver.wait_idle()=>bail!("HTTP/3 closed before settings: {e}"),
        _=async {while !send.settings().enable_datagram(){tokio::time::sleep(Duration::from_millis(1)).await;}}=>{}
    }
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("https://{name}{SESSION_PATH}"))
        .header("authorization", format!("Bearer {token}"))
        .header("braidpath-version", "1")
        .header("braidpath-session", sid)
        .header("braidpath-path", u16::from(pid))
        .header("braidpath-fec", u16::from(policy.fec))
        .header("braidpath-redundancy", u16::from(policy.redundancy))
        .header("braidpath-rate", policy.rate)
        .header("braidpath-block-ms", policy.block_ms)
        .header("braidpath-queue-ms", policy.queue_ms)
        .body(())?;
    let mut stream = send.send_request(req).await?;
    let response = tokio::select! {e=driver.wait_idle()=>bail!("HTTP/3 closed during admission: {e}"),r=stream.recv_response()=>r?};
    ensure!(
        response.status() == StatusCode::OK
            && response
                .headers()
                .get("braidpath-version")
                .is_some_and(|v| v == "1"),
        "session admission rejected: {}",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get("braidpath-max-payload")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            == Some(MAX_PAYLOAD),
        "payload size mismatch"
    );
    Ok((conn, stream.id().into_inner(), driver, stream, send))
}

pub async fn get(remote: SocketAddr, name: &str, ca: &std::path::Path) -> Result<String> {
    let endpoint = transport::client(remote, ca, None, transport::Congestion::Cubic)?;
    timeout(Duration::from_secs(8), async {
        let conn = endpoint.connect(remote, name)?.await?;
        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
        let mut request = send
            .send_request(Request::get(format!("https://{name}/")).body(())?)
            .await?;
        let response = async {
            let response = request.recv_response().await?;
            ensure!(
                response.status() == 200,
                "website status {}",
                response.status()
            );
            let mut result = Vec::new();
            while let Some(mut part) = request.recv_data().await? {
                ensure!(
                    result.len() + part.remaining() <= 65536,
                    "website response too large"
                );
                result.extend(part.copy_to_bytes(part.remaining()));
            }
            Ok::<_, anyhow::Error>(String::from_utf8(result)?)
        };
        tokio::select! {r=response=>r,e=driver.wait_idle()=>bail!("HTTP/3 closed: {e}")}
    })
    .await?
}
