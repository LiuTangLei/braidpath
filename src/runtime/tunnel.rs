use super::{
    MAX_PATHS, MAX_PAYLOAD, QUEUE, quality, scheduler,
    stats::{self, Scope},
    transport,
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
    pub receiver_feedback: bool,
    pub quality_schedule: bool,
    pub fec: u8,
    pub redundancy: u8,
    pub rate: u64,
    pub block_ms: u64,
    pub queue_ms: u64,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.quality_schedule || self.receiver_feedback,
            "quality scheduler requires receiver feedback"
        );
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
    quality: Arc<Mutex<quality::State>>,
    epoch: Instant,
}
type Paths = Arc<Mutex<Vec<OutPath>>>;

fn quality_time(path: &OutPath) -> u64 {
    path.epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}
fn measured_payload(
    paths: &Paths,
    pid: u8,
    payload: &[u8],
    enabled: bool,
    scope: &Scope,
) -> Result<Option<Bytes>> {
    if !enabled {
        return Ok(Some(Bytes::copy_from_slice(payload)));
    }
    let paths = paths.lock().expect("paths lock");
    if payload.starts_with(b"BQ1C") {
        for report in quality::parse_control(payload)? {
            if let Some(path) = paths.iter().find(|p| p.id == report.id) {
                let mut q = path.quality.lock().expect("quality lock");
                if q.apply(&report, quality_time(path)).is_err() {
                    q.snapshot.invalid_controls += 1;
                }
                scope.path(path.id, |p| p.receiver_feedback = Some(q.snapshot.clone()));
            }
        }
        return Ok(None);
    }
    let path = paths
        .iter()
        .find(|p| p.id == pid)
        .context("missing measurement path")?;
    let mut q = path.quality.lock().expect("quality lock");
    let inner = q.receive(payload, quality_time(path))?;
    scope.path(pid, |p| p.receiver_feedback = Some(q.snapshot.clone()));
    Ok(Some(Bytes::copy_from_slice(inner)))
}

struct Pending {
    data: Bytes,
    created: Instant,
    ingress_created: Instant,
    record_id: Option<u64>,
}
struct QueuedRecord {
    record: Record,
    created: Instant,
}

/// One owner for the aggregate encoder, budget, pacer and all datagram queues.
async fn sender(
    mut input: mpsc::Receiver<QueuedRecord>,
    paths: Paths,
    policy: Policy,
    mut stop: watch::Receiver<bool>,
    metrics: Scope,
) {
    let mut encoder = Encoder::new(policy.fec.max(1), Duration::from_millis(policy.block_ms))
        .expect("validated policy");
    let mut queue = VecDeque::<Pending>::new();
    let mut credit = 0usize;
    let mut scheduler = scheduler::Scheduler::default();
    let mut cursor = 0usize;
    let mut control_cursor = 0usize;
    let mut next_feedback = Instant::now();
    let mut tokens = 0f64;
    let mut last = Instant::now();
    let mut tick = interval(Duration::from_millis(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let enqueue = |data: Bytes, ingress_created: Instant, queue: &mut VecDeque<Pending>| {
        let id = if data[3] != 1 {
            wire::Record::decode(&data[wire::HEADER..])
                .ok()
                .map(|r| r.id)
        } else {
            None
        };
        metrics.update(|d| {
            if let Some(id) = id {
                d.generated_record_ids.add(id);
            }
            if queue.len() < QUEUE {
                if id.is_some() {
                    d.symbols.originals_enqueued += 1;
                } else {
                    d.symbols.repairs_enqueued += 1;
                }
            } else if id.is_some() {
                d.symbols.originals_queue_full_dropped += 1;
                d.locally_dropped_original_ids.add(id.expect("original id"));
            } else {
                d.symbols.repairs_queue_full_dropped += 1;
            }
        });
        if queue.len() < QUEUE {
            queue.push_back(Pending {
                data,
                created: Instant::now(),
                ingress_created,
                record_id: id,
            });
        }
    };
    let add = |s: crate::fec::Shard,
               ingress_created: Instant,
               queue: &mut VecDeque<Pending>,
               credit: &mut usize| {
        let repair = matches!(s, crate::fec::Shard::Repair { .. });
        let data = wire::shard(s);
        if repair {
            metrics.update(|d| d.symbols.repairs_generated += 1);
            if *credit < data.len() * 100 {
                metrics.update(|d| d.symbols.repairs_budget_skipped += 1);
                return;
            }
            *credit -= data.len() * 100;
        } else {
            metrics.update(|d| d.symbols.originals_generated += 1);
            *credit = (*credit + data.len() * usize::from(policy.redundancy))
                .min(2 * wire::MAX_WIRE * 100);
        }
        enqueue(data, ingress_created, queue);
    };
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _=stop.changed()=>break,
            _=tick.tick()=>{ if policy.fec>0 && let Some(s)=encoder.flush_due(Instant::now()){add(s,Instant::now(),&mut queue,&mut credit);} },
            queued=input.recv()=>{
                let Some(QueuedRecord{record,created})=queued else{break};
                metrics.update(|d| d.records.sender_input_consumed+=1);
                if policy.fec==0 {
                    match wire::plain(&record) {Ok(data)=>{metrics.update(|d|d.symbols.originals_generated+=1);enqueue(data,created,&mut queue)},Err(_)=>metrics.update(|d|d.records.encoding_dropped+=1)}
                } else if let Ok(data)=record.encode() {
                    match encoder.push(&data,Instant::now()){Ok(shards)=>for s in shards{add(s,created,&mut queue,&mut credit)},Err(_)=>metrics.update(|d|d.records.encoding_dropped+=1)}
                } else {metrics.update(|d|d.records.encoding_dropped+=1);}
            }
        }
        let now = Instant::now();
        tokens = (tokens + now.duration_since(last).as_secs_f64() * policy.rate as f64 / 8.0)
            .min(8.0 * 1200.0);
        last = now;
        if policy.receiver_feedback && now >= next_feedback {
            let p = paths.lock().expect("paths lock");
            let reports: Vec<_> = p
                .iter()
                .map(|path| {
                    path.quality
                        .lock()
                        .expect("quality lock")
                        .report(path.id, quality_time(path))
                })
                .collect();
            let frame = quality::control(&reports);
            let cost = (frame.len() + 80) as f64;
            if !p.is_empty() && tokens >= cost {
                for n in 0..p.len() {
                    let i = (control_cursor + n) % p.len();
                    let path = &p[i];
                    let data = wire::http_datagram(path.stream, &frame).expect("admitted stream");
                    if path.conn.close_reason().is_none()
                        && path
                            .conn
                            .max_datagram_size()
                            .is_some_and(|m| m >= data.len())
                        && path.conn.datagram_send_buffer_space() >= data.len()
                        && path.conn.send_datagram(data).is_ok()
                    {
                        tokens -= cost;
                        control_cursor = (i + 1) % p.len();
                        path.quality
                            .lock()
                            .expect("quality lock")
                            .snapshot
                            .controls_sent += 1;
                        break;
                    }
                }
            }
            for path in p.iter() {
                let snapshot = path.quality.lock().expect("quality lock").snapshot.clone();
                metrics.path(path.id, |s| s.receiver_feedback = Some(snapshot));
            }
            next_feedback = now + Duration::from_micros(quality::INTERVAL_US);
        }
        while let Some(front) = queue.front() {
            if now.duration_since(front.created) > Duration::from_millis(policy.queue_ms) {
                let expired = queue.pop_front().expect("front");
                metrics.update(|d| {
                    if let Some(id) = expired.record_id {
                        d.symbols.originals_expired_dropped += 1;
                        d.locally_dropped_original_ids.add(id);
                    } else {
                        d.symbols.repairs_expired_dropped += 1;
                    }
                    d.symbols
                        .expiry_wait
                        .add(now.duration_since(expired.ingress_created));
                });
                continue;
            }
            let cost = (front.data.len()
                + 80
                + if policy.receiver_feedback {
                    quality::HEADER
                } else {
                    0
                }) as f64;
            if tokens < cost {
                break;
            }
            let mut admitted = false;
            {
                let p = paths.lock().expect("paths lock");
                let order = if policy.quality_schedule {
                    let candidates: Vec<_> = p
                        .iter()
                        .filter(|path| path.conn.close_reason().is_none())
                        .map(|path| {
                            (
                                path.id,
                                scheduler::weight(
                                    &path
                                        .quality
                                        .lock()
                                        .expect("quality lock")
                                        .snapshot
                                        .sender_estimate,
                                    quality_time(path),
                                    path.conn.rtt().as_secs_f64() * 1000.0,
                                ),
                            )
                        })
                        .collect();
                    scheduler
                        .order(&candidates)
                        .into_iter()
                        .filter_map(|id| p.iter().position(|path| path.id == id))
                        .collect::<Vec<_>>()
                } else {
                    (0..p.len()).map(|n| (cursor + n) % p.len()).collect()
                };
                for i in order {
                    let path = &p[i];
                    if path.conn.close_reason().is_some() {
                        continue;
                    }
                    let payload = if policy.receiver_feedback {
                        path.quality
                            .lock()
                            .expect("quality lock")
                            .wrap(&front.data, quality_time(path))
                    } else {
                        front.data.clone()
                    };
                    let Ok(data) = wire::http_datagram(path.stream, &payload) else {
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
                        metrics.path(path.id, |p| p.send_buffer_full_attempts += 1);
                        continue;
                    }
                    match path.conn.send_datagram(data) {
                        Ok(()) => {
                            if policy.receiver_feedback {
                                path.quality
                                    .lock()
                                    .expect("quality lock")
                                    .snapshot
                                    .sent_symbols += 1;
                            }
                            metrics.path(path.id, |p| {
                                if front.record_id.is_some() {
                                    p.quinn_admitted_originals += 1;
                                } else {
                                    p.quinn_admitted_repairs += 1;
                                }
                            });
                            cursor = (i + 1) % p.len();
                            admitted = true;
                            break;
                        }
                        Err(_) => metrics.path(path.id, |p| p.quinn_send_error_attempts += 1),
                    }
                }
            }
            if !admitted {
                break;
            }
            tokens -= cost;
            let sent = queue.pop_front().expect("front");
            metrics.update(|d| {
                if let Some(id) = sent.record_id {
                    d.symbols.originals_quinn_admitted += 1;
                    d.quinn_admitted_record_ids.add(id);
                } else {
                    d.symbols.repairs_quinn_admitted += 1;
                }
                d.symbols
                    .admitted_wait
                    .add(now.duration_since(sent.ingress_created));
            });
        }
    }
    for pending in queue {
        metrics.update(|d| {
            if let Some(id) = pending.record_id {
                d.symbols.originals_shutdown_dropped += 1;
                d.locally_dropped_original_ids.add(id);
            } else {
                d.symbols.repairs_shutdown_dropped += 1;
            }
        });
    }
    input.close();
    while input.try_recv().is_ok() {
        metrics.update(|d| d.records.input_shutdown_dropped += 1);
    }
    info!("aggregate sender stopped");
}

#[derive(Clone, Copy)]
enum QueueLayer {
    Ingress,
    Sender,
    Receiver,
}
fn queue_error<T>(
    scope: &Scope,
    layer: QueueLayer,
    error: &mpsc::error::TrySendError<T>,
    pid: Option<u8>,
) {
    let closed = matches!(error, mpsc::error::TrySendError::Closed(_));
    scope.update(|d| match (layer, closed) {
        (QueueLayer::Ingress, false) => d.records.ingress_queue_full_dropped += 1,
        (QueueLayer::Ingress, true) => d.records.ingress_queue_closed_dropped += 1,
        (QueueLayer::Sender, false) => d.records.sender_queue_full_dropped += 1,
        (QueueLayer::Sender, true) => d.records.sender_queue_closed_dropped += 1,
        (QueueLayer::Receiver, false) => d.records.receiver_queue_full_dropped += 1,
        (QueueLayer::Receiver, true) => d.records.receiver_queue_closed_dropped += 1,
    });
    if let Some(pid) = pid {
        scope.path(pid, |p| {
            if closed {
                p.receiver_queue_closed_dropped += 1;
            } else {
                p.receiver_queue_full_dropped += 1;
            }
        });
    }
}

fn receive_records(decoder: &mut Receiver, metrics: &Scope, pid: u8, data: &[u8]) -> Vec<Record> {
    let before = (
        decoder.original_packets,
        decoder.originals,
        decoder.recovered,
        decoder.duplicates,
        decoder.stale,
    );
    let repairs_before = decoder.repair_packets;
    let result = decoder.receive(data, Instant::now());
    let invalid = u64::from(result.is_err());
    if invalid > 0 {
        decoder.invalid += 1;
    }
    let delta = (
        decoder.original_packets - before.0,
        decoder.originals - before.1,
        decoder.recovered - before.2,
        decoder.duplicates - before.3,
        decoder.stale - before.4,
    );
    metrics.update(|d| {
        d.records.repair_symbols_received += decoder.repair_packets - repairs_before;
        d.records.original_packets_received += delta.0;
        d.records.original_records_delivered += delta.1;
        d.records.fec_records_recovered += delta.2;
        d.records.deduplicated += delta.3;
        d.records.stale_symbols_dropped += delta.4;
        d.records.invalid_symbols_dropped += invalid;
    });
    metrics.path(pid, |p| {
        p.repair_symbols_received += decoder.repair_packets - repairs_before;
        p.original_packets_received += delta.0;
        p.original_records_delivered += delta.1;
        p.fec_records_recovered += delta.2;
        p.deduplicated += delta.3;
        p.stale_symbols_dropped += delta.4;
        p.invalid_symbols_dropped += invalid;
    });
    result.unwrap_or_default()
}

enum Event {
    Wire(u8, Bytes),
    Reply(u32, Vec<u8>, Instant),
}
struct Session {
    generations: Mutex<[Vec<u64>; MAX_PATHS]>,
    events: mpsc::Sender<Event>,
    paths: Paths,
    stop: watch::Sender<bool>,
    policy: Policy,
    ingress_drops: Arc<AtomicU64>,
    forward: Scope,
    returning: Scope,
    finished: tokio::sync::Notify,
    done: std::sync::atomic::AtomicBool,
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
        session.returning.clone(),
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
                Some(Event::Wire(pid,data))=>{
                    let records=receive_records(&mut decoder,&session.forward,pid,&data);
                    for r in records {
                        if !flows.contains_key(&r.flow) {
                            if flows.len()>=MAX_FLOWS{dropped+=1;session.forward.update(|d|d.records.udp_target_flow_dropped+=1);session.forward.path(pid,|p|p.udp_target_flow_dropped+=1);continue}
                            let bind=if target.is_ipv4(){"0.0.0.0:0"}else{"[::]:0"};
                            let Ok(socket)=UdpSocket::bind(bind).await else{dropped+=1;session.forward.update(|d|d.records.udp_target_send_dropped+=1);session.forward.path(pid,|p|p.udp_target_send_dropped+=1);continue};
                            if socket.connect(target).await.is_err() || socket.writable().await.is_err(){dropped+=1;session.forward.update(|d|d.records.udp_target_send_dropped+=1);session.forward.path(pid,|p|p.udp_target_send_dropped+=1);continue}
                            let socket=Arc::new(socket); let weak=Arc::downgrade(&socket); let events=session.events.clone(); let flow=r.flow; let mut quit=session.stop.subscribe(); let ingress_drops=session.ingress_drops.clone();let returning=session.returning.clone();
                            tasks.spawn(async move {
                                let mut b=vec![0;65536];
                                loop {
                                    let Some(socket)=weak.upgrade() else{break};
                                    tokio::select! {
                                        _=quit.changed()=>break,
                                        value=timeout(Duration::from_secs(5),socket.recv(&mut b))=>match value {
                                            Ok(Ok(n))=>{
                                                returning.update(|d|d.records.application_received+=1);
                                                if n>MAX_PAYLOAD{returning.update(|d|d.records.application_oversize_dropped+=1);continue;}
                                                let now=Instant::now();
                                                if let Err(error)=events.try_send(Event::Reply(flow,b[..n].to_vec(),now)){ingress_drops.fetch_add(1,Ordering::Relaxed);queue_error(&returning,QueueLayer::Ingress,&error,None);}else{returning.update(|d|d.records.ingress_queue_enqueued+=1);}
                                            },
                                            Ok(Err(_))=>break,
                                            _=>{}
                                        }
                                    }
                                }
                            });
                            flows.insert(r.flow,(socket,Instant::now()));
                        }
                        if let Some((socket,last))=flows.get_mut(&r.flow) {
                            *last=Instant::now(); if socket.try_send(&r.payload).is_err(){dropped+=1;session.forward.update(|d|d.records.udp_target_send_dropped+=1);session.forward.path(pid,|p|p.udp_target_send_dropped+=1);}else{session.forward.path(pid,|p|p.udp_target_delivered+=1);session.forward.update(|d|{d.records.udp_target_delivered+=1;d.records.udp_target_bytes+=r.payload.len() as u64;d.udp_delivered_record_ids.add(r.id);});}
                        }
                    }
                },
                Some(Event::Reply(flow,payload,created))=>{
                    let Some((_,last))=flows.get_mut(&flow) else{session.returning.update(|d|d.records.application_unavailable_dropped+=1);continue}; *last=Instant::now();
                    let Some(id)=next_id.checked_add(1) else{break}; next_id=id;
                    if let Err(error)=tx.try_send(QueuedRecord{record:Record{flow,id,payload},created}){dropped+=1;queue_error(&session.returning,QueueLayer::Sender,&error,None);}else{session.returning.update(|d|d.records.sender_queue_enqueued+=1);}
                },
                None=>break,
            }
        }
        while tasks.try_join_next().is_some() {}
    }
    let _ = session.stop.send(true);
    events.close();
    while let Ok(event) = events.try_recv() {
        match event {
            Event::Wire(_, _) => session
                .forward
                .update(|d| d.records.receiver_shutdown_dropped += 1),
            Event::Reply(..) => session
                .returning
                .update(|d| d.records.ingress_shutdown_dropped += 1),
        }
    }
    let joined = timeout(Duration::from_secs(2), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    if !joined {
        session.forward.metrics.state(|s| s.drain_incomplete = true);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    session.done.store(true, Ordering::Release);
    session.finished.notify_waiters();
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
    pub stats: stats::Metrics,
}
pub async fn serve(options: ServerOptions) -> Result<()> {
    ensure!(
        (64_000..=1_000_000_000).contains(&options.max_rate),
        "invalid server rate"
    );
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
    options.stats.readiness(true, 0);
    info!(address=%endpoint.local_addr()?,target=%options.target,congestion=?options.congestion,"HTTP/3 server ready");
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            incoming=endpoint.accept()=>{
                let Some(incoming)=incoming else{break};
                let Ok(permit)=limit.clone().try_acquire_owned() else{incoming.refuse();continue};
                let sessions=sessions.clone(); let secret=secret.clone(); let target=options.target; let max_rate=options.max_rate; let metrics=options.stats.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let mut diagnostic=stats::ConnectionTrace::new(metrics.clone(),incoming.remote_address(),None,"incoming");
                    let result=server_connection(incoming,sessions,secret,target,max_rate,metrics,&mut diagnostic).await;
                    let normal=diagnostic.finish(result.as_ref().err());
                    if let Err(e)=result {
                        if normal {info!(context=%diagnostic.context(),"HTTP/3 connection closed");}
                        else {warn!(context=%diagnostic.context(),error=%e,"HTTP/3 connection ended");}
                    }
                });
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{}
        }
    }
    options.stats.readiness(false, 0);
    let active = sessions
        .lock()
        .expect("sessions lock")
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for session in &active {
        let _ = session.stop.send(true);
    }
    endpoint.close(0u32.into(), b"shutdown");
    let joined = timeout(Duration::from_secs(3), async {
        while tasks.join_next().await.is_some() {}
        for session in active {
            while !session.done.load(Ordering::Acquire) {
                let notified = session.finished.notified();
                if !session.done.load(Ordering::Acquire) {
                    notified.await;
                }
            }
        }
    })
    .await
    .is_ok();
    if !joined {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    options.stats.state(|s| {
        s.shutdown_complete = joined;
        s.drain_incomplete |= !joined;
    });
    Ok(())
}

async fn server_connection(
    incoming: quinn::Incoming,
    sessions: Sessions,
    secret: Arc<String>,
    target: SocketAddr,
    max_rate: u64,
    metrics: stats::Metrics,
    diagnostic: &mut stats::ConnectionTrace,
) -> Result<()> {
    let conn = timeout(Duration::from_secs(5), incoming).await??;
    diagnostic.handshake_succeeded(&conn);
    diagnostic.enter("http3", "http3_setup");
    let mut h3 = h3::server::builder()
        .enable_datagram(true)
        .max_field_section_size(8192)
        .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
        .await?;
    diagnostic.succeeded();
    let mut joined: Option<(String, Arc<Session>, u8, u64)> = None;
    let mut request: Option<h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>> = None;
    let admission_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let admission_started = Instant::now();
    diagnostic.enter_since("path_admission", "admission_wait", admission_started);
    let result:Result<()>=async {
        loop {
            tokio::select! {
                _=tokio::time::sleep_until(admission_deadline),if joined.is_none()=>{
                    diagnostic.enter_since("path_admission","admission_wait",admission_started);
                    diagnostic.failed("admission_deadline_elapsed");
                    bail!("session admission timed out")
                },
                accepted=h3.accept()=>{
                    let Some(resolver)=accepted? else{break};
                    diagnostic.enter("http3_request","request_resolve");
                    let (req,mut stream)=timeout(Duration::from_secs(5),resolver.resolve_request()).await??;
                    diagnostic.succeeded();
                    if req.method()!=Method::POST || req.uri().path()!=SESSION_PATH {
                        let ok=req.method()==Method::GET && req.uri().path()=="/";
                        stream.send_response(Response::builder().status(if ok{StatusCode::OK}else{StatusCode::NOT_FOUND}).header("content-type","text/html; charset=utf-8").body(())?).await?;
                        stream.send_data(Bytes::from_static(if ok{WEBSITE.as_bytes()}else{b"Not found\n"})).await?; stream.finish().await?;
                        if joined.is_some(){diagnostic.enter("established","connected");}
                        else{diagnostic.enter_since("path_admission","admission_wait",admission_started);}
                        continue
                    }
                    diagnostic.begin_admission();
                    let auth=req.headers().get("authorization").map(|h|h.as_bytes()).unwrap_or_default();
                    if !bool::from(auth.ct_eq(secret.as_bytes())) {
                        diagnostic.rejected("authorization_rejected");
                        stream.send_response(Response::builder().status(404).header("content-type","text/html; charset=utf-8").body(())?).await?;stream.send_data(Bytes::from_static(b"Not found\n")).await?;stream.finish().await?;
                        if joined.is_some(){diagnostic.enter("established","connected");}
                        else{diagnostic.enter_since("path_admission","admission_wait",admission_started);}
                        continue
                    }
                    ensure!(joined.is_none(),"only one aggregate request per connection");
                    // Request and control streams can arrive in either order. Drive
                    // control processing before deciding whether the peer supports DATAGRAM.
                    diagnostic.enter("path_admission","peer_settings");
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
                    diagnostic.succeeded();
                    diagnostic.enter("path_admission","admission");
                    ensure!(conn.max_datagram_size().is_some_and(|n|n>=wire::MAX_WIRE+9),"peer lacks required datagram capacity");
                    let header=|name:&str|->Result<&str>{req.headers().get(name).context("missing session header")?.to_str().context("invalid session header")};
                    ensure!(header("braidpath-version")?=="1","unsupported version");
                    let sid=header("braidpath-session")?.to_owned(); ensure!(sid.len()==32 && sid.bytes().all(|b|b.is_ascii_hexdigit()),"invalid session id");
                    let pid:u8=header("braidpath-path")?.parse()?; ensure!(usize::from(pid)<MAX_PATHS,"path limit");
                    diagnostic.path_id(pid);
                    let feedback=req.headers().get("braidpath-feedback").map(|v|v.to_str()).transpose()?;ensure!(feedback.is_none() || feedback==Some("1"),"unsupported feedback version");
                    let generation=if feedback.is_some(){header("braidpath-generation")?.parse::<u64>()?}else{0};
                    ensure!(feedback.is_none() || conn.max_datagram_size().is_some_and(|n|n>=quality::MAX_FRAME+9),"peer lacks feedback datagram capacity");
                    let quality_schedule=req.headers().get("braidpath-scheduler").map(|v|v.to_str()).transpose()?;ensure!(quality_schedule.is_none() || quality_schedule==Some("quality"),"unknown scheduler");ensure!(quality_schedule.is_none() || feedback.is_some(),"quality scheduler requires feedback");
                    let policy=Policy{quality_schedule:quality_schedule.is_some(),receiver_feedback:feedback.is_some(),fec:header("braidpath-fec")?.parse()?,redundancy:header("braidpath-redundancy")?.parse()?,rate:header("braidpath-rate")?.parse::<u64>()?.min(max_rate),block_ms:header("braidpath-block-ms")?.parse()?,queue_ms:header("braidpath-queue-ms")?.parse()?};policy.validate()?;
                    let session={
                        let mut map=sessions.lock().expect("sessions lock");
                        if let Some(session)=map.get(&sid){
                            ensure!(session.policy.quality_schedule==policy.quality_schedule && session.policy.receiver_feedback==policy.receiver_feedback && session.policy.fec==policy.fec && session.policy.redundancy==policy.redundancy && session.policy.rate==policy.rate && session.policy.block_ms==policy.block_ms && session.policy.queue_ms==policy.queue_ms,"session policy mismatch"); session.clone()
                        }else{
                            ensure!(map.len()<16,"session limit");
                            let (tx,rx)=mpsc::channel(QUEUE);let (stop,_)=watch::channel(false);
                            let s=Arc::new(Session{generations:Mutex::new(std::array::from_fn(|_|Vec::new())),events:tx,paths:Arc::new(Mutex::new(Vec::new())),stop,policy,ingress_drops:Arc::new(AtomicU64::new(0)),forward:metrics.scope(&sid,stats::FORWARD),returning:metrics.scope(&sid,stats::RETURN),finished:tokio::sync::Notify::new(),done:std::sync::atomic::AtomicBool::new(false)});
                            map.insert(sid.clone(),s.clone());tokio::spawn(session_loop(s.clone(),rx,target));s
                        }
                    };
                    let stream_id=stream.id().into_inner();
                    {
                        let mut paths=session.paths.lock().expect("paths lock");
                        let rejoin=req.headers().get("braidpath-rejoin").is_some_and(|v|v=="1");
                        let existing=paths.iter().position(|p|p.id==pid);
                        ensure!(existing.is_none() || (rejoin && feedback.is_some()),"duplicate path");
                        let mut generations=session.generations.lock().expect("generation lock");
                        let history=&mut generations[usize::from(pid)];

                        ensure!(existing.is_some() || paths.len()<MAX_PATHS,"path limit");scheduler::admit_generation(history,generation)?;
                        if let Some(i)=existing {let old=paths.remove(i);old.conn.close(0u32.into(),b"path rejoined");}
                        paths.push(OutPath{id:pid,conn:conn.clone(),stream:stream_id,quality:Arc::new(Mutex::new(quality::State::new(generation))),epoch:Instant::now()});
                    }
                    metrics.register(&sid,pid,stream_id,stats::RETURN,&conn);
                    joined=Some((sid,session,pid,stream_id));
                    let mut response=Response::builder().status(200).header("braidpath-version","1").header("braidpath-max-payload",MAX_PAYLOAD);if feedback.is_some(){response=response.header("braidpath-feedback","1");}
                    if quality_schedule.is_some(){response=response.header("braidpath-scheduler","quality");}stream.send_response(response.body(())?).await?;
                    request=Some(stream);
                    diagnostic.admitted();
                    info!(path=pid,remote=%conn.remote_address(),"authenticated path joined");
                },
                data=conn.read_datagram()=>{
                    let data=data?;
                    if let Some((_,session,pid,stream))=&joined {
                        session.forward.path(*pid,|p|p.http_datagrams_received+=1);
                        if let Ok(payload)=wire::http_payload(&data,*stream) && payload.len()<=(if session.policy.receiver_feedback{quality::MAX_FRAME}else{wire::MAX_WIRE}) {
                            match measured_payload(&session.paths,*pid,payload,session.policy.receiver_feedback,&session.returning) {
                            Ok(Some(payload))=>{if let Err(error)=session.events.try_send(Event::Wire(*pid,payload)){session.ingress_drops.fetch_add(1,Ordering::Relaxed);queue_error(&session.forward,QueueLayer::Receiver,&error,Some(*pid));}},Ok(None)=>{},Err(_)=>session.forward.path(*pid,|p|p.invalid_http_datagrams_dropped+=1)}
                        } else {session.forward.path(*pid,|p|p.invalid_http_datagrams_dropped+=1);session.forward.update(|d|d.records.invalid_symbols_dropped+=1);}
                    }
                },
                body=async {request.as_mut().expect("guarded request").recv_data().await},if request.is_some()=>{
                    let _=body?; break; // No reliable data is defined for this request; FIN ends membership.
                }
            }
        }
        Ok(())
    }.await;
    // Classify the original close/error before our cleanup closes the connection.
    diagnostic.finish(result.as_ref().err());
    conn.close(0u32.into(), b"request closed");
    if let Some((sid, session, pid, _)) = joined {
        let last = {
            let mut map = sessions.lock().expect("sessions lock");
            let mut paths = session.paths.lock().expect("paths lock");
            paths.retain(|p| p.id != pid || p.conn.stable_id() != conn.stable_id());
            let last = paths.is_empty();
            if last {
                let _ = session.stop.send(true);
                map.remove(&sid);
            }
            last
        };
        if last
            && timeout(Duration::from_secs(3), async {
                while !session.done.load(Ordering::Acquire) {
                    let notified = session.finished.notified();
                    if !session.done.load(Ordering::Acquire) {
                        notified.await;
                    }
                }
            })
            .await
            .is_err()
        {
            metrics.state(|s| s.drain_incomplete = true);
        }
        info!(path = pid, "path left");
    }
    result
}

struct Rejoined {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    stream: u64,
    driver: H3Client,
    request: H3Request,
    send: H3Send,
}

pub struct ClientOptions {
    pub rotate_source_port: bool,
    pub listen: SocketAddr,
    pub entrances: Vec<SocketAddr>,
    pub interfaces: Vec<String>,
    pub path_binds: Vec<SocketAddr>,
    pub name: String,
    pub ca: std::path::PathBuf,
    pub token: std::path::PathBuf,
    pub policy: Policy,
    pub congestion: transport::Congestion,
    pub stats: stats::Metrics,
}
pub async fn client(options: ClientOptions) -> Result<()> {
    options.policy.validate()?;
    ensure!(
        !options.entrances.is_empty()
            && options.entrances.len() * options.interfaces.len().max(1) <= MAX_PATHS,
        "need 1..8 interface/entrance pairs"
    );
    let token = transport::token(&options.token)?;
    ensure!(
        options.path_binds.is_empty()
            || options.path_binds.len()
                == options.entrances.len() * options.interfaces.len().max(1),
        "path binds must match interface–entrance pair count"
    );
    let sid = transport::hex(&rand::random::<[u8; 16]>());
    let paths: Paths = Arc::new(Mutex::new(Vec::new()));
    let forward = options.stats.scope(&sid, stats::FORWARD);
    let returning = options.stats.scope(&sid, stats::RETURN);
    let (wire_tx, mut wire_rx) = mpsc::channel::<(u8, Bytes)>(QUEUE);
    let mut tasks = JoinSet::new();
    let mut endpoints = Vec::new();
    let mut configs: Vec<(SocketAddr, Option<String>)> = Vec::new();
    let mut rotations: [scheduler::Rotation; MAX_PATHS] =
        std::array::from_fn(|_| Default::default());
    let rotation_epoch = Instant::now();
    let (rejoin_tx, mut rejoin_rx) =
        mpsc::channel::<(u8, u64, Result<(Rejoined, stats::ConnectionTrace)>)>(MAX_PATHS);
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
            configs.push((*entrance, interface.map(str::to_owned)));
            let generation = rand::random::<u64>();
            let endpoint = transport::client_bound(
                *entrance,
                &options.ca,
                interface,
                options.congestion,
                options.path_binds.get(usize::from(pid)).copied(),
            )?;
            endpoints.push(endpoint.clone());
            let mut diagnostic = stats::ConnectionTrace::new(
                options.stats.clone(),
                *entrance,
                Some(pid),
                "quic_connect",
            );
            let connection = timeout(
                Duration::from_secs(8),
                connect_path(
                    &endpoint,
                    *entrance,
                    &options.name,
                    &token,
                    &sid,
                    pid,
                    generation,
                    false,
                    &options.policy,
                    &mut diagnostic,
                ),
            )
            .await;
            match connection {
                Ok(Ok((conn, stream, driver, request, send))) => {
                    options
                        .stats
                        .register(&sid, pid, stream, stats::FORWARD, &conn);
                    forward.path(pid, |p| {
                        p.local_socket = endpoint.local_addr().ok().map(|a| a.to_string())
                    });
                    paths.lock().expect("paths lock").push(OutPath {
                        id: pid,
                        conn: conn.clone(),
                        stream,
                        quality: Arc::new(Mutex::new(quality::State::new(generation))),
                        epoch: Instant::now(),
                    });
                    tasks.spawn(drive_client_path(
                        conn,
                        stream,
                        driver,
                        request,
                        send,
                        diagnostic,
                        pid,
                        wire_tx.clone(),
                        ingress_drops.clone(),
                        returning.clone(),
                        forward.clone(),
                        paths.clone(),
                        options.policy.receiver_feedback,
                    ));
                    info!(path=pid,remote=%entrance,interface=interface.unwrap_or("default"),"client path ready");
                }
                Ok(Err(error)) => {
                    diagnostic.finish(Some(&error));
                    warn!(path=pid,remote=%entrance,context=%diagnostic.context(),error=%error,"path unavailable");
                }
                Err(error) => {
                    diagnostic.failed("whole_path_deadline_elapsed");
                    warn!(path=pid,remote=%entrance,context=%diagnostic.context(),error=%error,"path connection timed out")
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
    tasks.spawn(sender(
        rx,
        paths.clone(),
        options.policy.clone(),
        stop_rx,
        forward.clone(),
    ));
    let mut input = vec![0; 65536];
    let mut peers: HashMap<SocketAddr, (u32, Instant)> = HashMap::new();
    let mut reverse = HashMap::new();
    let mut next_flow = 0u32;
    let mut next_id = 0u64;
    let mut decoder = Receiver::default();
    let mut tick = interval(Duration::from_secs(2));
    let mut drops = 0u64;
    options.stats.readiness(
        true,
        options.entrances.len() * options.interfaces.len().max(1),
    );
    info!(listen=%socket.local_addr()?,paths=paths.lock().expect("paths lock").len(),congestion=?options.congestion,"UDP client ready");
    let result:Result<()>=async {loop {tokio::select! {
        _=tokio::signal::ctrl_c()=>break,
        _=tick.tick()=>{
            peers.retain(|_,(id,last)|{if last.elapsed()<Duration::from_secs(60){true}else{reverse.remove(id);false}});
            let p=paths.lock().expect("paths lock");let live=p.iter().filter(|p|p.conn.close_reason().is_none()).count();
            for path in p.iter(){let stats=path.conn.stats();info!(path=path.id,alive=path.conn.close_reason().is_none(),rtt_ms=path.conn.rtt().as_secs_f64()*1000.0,tx_packets=stats.udp_tx.datagrams,rx_packets=stats.udp_rx.datagrams,tx_bytes=stats.udp_tx.bytes,rx_bytes=stats.udp_rx.bytes,lost=stats.path.lost_packets,cwnd=stats.path.cwnd,"path statistics");}

            drop(p);
            if options.rotate_source_port {
                let candidates=paths.lock().expect("paths lock").clone();
                for path in candidates {
                    let id=usize::from(path.id);let estimate=path.quality.lock().expect("quality lock").snapshot.sender_estimate.clone();
                    if !rotations[id].consider(&estimate,quality_time(&path),rotation_epoch.elapsed().as_micros() as u64) {continue;}
                    forward.path(path.id,|p|p.rotation_attempts+=1);
                    let (remote,interface)=configs[id].clone();let ca=options.ca.clone();let congestion=options.congestion;let name=options.name.clone();let token=token.clone();let sid=sid.clone();let policy=options.policy.clone();let metrics=options.stats.clone();let tx=rejoin_tx.clone();let generation=rand::random::<u64>();
                    tasks.spawn(async move {
                        let mut diagnostic=stats::ConnectionTrace::new(metrics,remote,Some(path.id),"quic_connect");
                        let result:Result<Rejoined>=async {
                            let endpoint=transport::client(remote,&ca,interface.as_deref(),congestion)?;
                            info!(path=path.id,generation,local=%endpoint.local_addr()?,remote=%remote,"path rejoin source socket");
                            let (conn,stream,driver,request,send)=timeout(Duration::from_secs(8),connect_path(&endpoint,remote,&name,&token,&sid,path.id,generation,true,&policy,&mut diagnostic)).await??;
                            Ok(Rejoined{endpoint,conn,stream,driver,request,send})
                        }.await;
                        if let Err(error)=&result {diagnostic.finish(Some(error));}
                        let _=tx.try_send((path.id,generation,result.map(|value|(value,diagnostic))));
                    });
                }
            }

            info!(live,originals=decoder.originals,recovered=decoder.recovered,duplicates=decoder.duplicates,invalid=decoder.invalid,drops,ingress_drops=ingress_drops.load(Ordering::Relaxed),"client statistics");
            ensure!(live>0,"all paths failed; restart creates a fresh session epoch");
        },

        rebuilt=rejoin_rx.recv()=>{
            if let Some((pid,generation,result))=rebuilt {
                rotations[usize::from(pid)].finished();
                match result {
                    Ok((value,diagnostic))=>{
                        options.stats.register(&sid,pid,value.stream,stats::FORWARD,&value.conn);
                        forward.path(pid,|p|{p.local_socket=value.endpoint.local_addr().ok().map(|a|a.to_string());p.rotation_successes+=1;});
                        {let mut p=paths.lock().expect("paths lock");p.retain(|path|path.id!=pid);p.push(OutPath{id:pid,conn:value.conn.clone(),stream:value.stream,quality:Arc::new(Mutex::new(quality::State::new(generation))),epoch:Instant::now()});}
                        endpoints.push(value.endpoint);
                        tasks.spawn(drive_client_path(value.conn,value.stream,value.driver,value.request,value.send,diagnostic,pid,wire_tx.clone(),ingress_drops.clone(),returning.clone(),forward.clone(),paths.clone(),options.policy.receiver_feedback));
                    },
                    Err(error)=>{forward.path(pid,|p|p.rotation_failures+=1);warn!(path=pid,error=%error,"path rejoin failed");}
                }
            }
        },

        received=socket.recv_from(&mut input)=>{
            let (n,peer)=received?;
            forward.update(|d|d.records.application_received+=1);
            if n>MAX_PAYLOAD{drops+=1;forward.update(|d|d.records.application_oversize_dropped+=1);continue}
            if !peers.contains_key(&peer){
                if peers.len()>=MAX_FLOWS {drops+=1;forward.update(|d|d.records.application_flow_limit_dropped+=1);continue}
                next_flow=next_flow.checked_add(1).context("flow id exhausted")?;peers.insert(peer,(next_flow,Instant::now()));reverse.insert(next_flow,peer);
            }
            let (flow,last)=peers.get_mut(&peer).expect("inserted peer");*last=Instant::now();
            next_id=next_id.checked_add(1).context("message id exhausted")?;
            if let Err(error)=tx.try_send(QueuedRecord{record:Record{flow:*flow,id:next_id,payload:input[..n].to_vec()},created:Instant::now()}){drops+=1;queue_error(&forward,QueueLayer::Sender,&error,None);}else{forward.update(|d|{d.records.ingress_queue_enqueued+=1;d.records.sender_queue_enqueued+=1;});}
        },
        data=wire_rx.recv()=>{
            let Some((pid,data))=data else{bail!("all receivers ended")};
            for r in receive_records(&mut decoder,&returning,pid,&data) {
                if let Some(peer)=reverse.get(&r.flow) {
                    if let Some((_,last))=peers.get_mut(peer){*last=Instant::now();}
                    if socket.try_send_to(&r.payload,*peer).is_err(){drops+=1;returning.update(|d|d.records.udp_target_send_dropped+=1);returning.path(pid,|p|p.udp_target_send_dropped+=1);}else{returning.path(pid,|p|p.udp_target_delivered+=1);returning.update(|d|{d.records.udp_target_delivered+=1;d.records.udp_target_bytes+=r.payload.len() as u64;d.udp_delivered_record_ids.add(r.id);});}
                }else{returning.update(|d|d.records.udp_target_flow_dropped+=1);returning.path(pid,|p|p.udp_target_flow_dropped+=1);}
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
    options.stats.readiness(
        false,
        options.entrances.len() * options.interfaces.len().max(1),
    );
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
    // Await the aggregate sender's explicit queued-record/symbol cancellation accounting.
    let joined = timeout(Duration::from_secs(2), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    if !joined {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    wire_rx.close();
    while wire_rx.try_recv().is_ok() {
        returning.update(|d| d.records.receiver_shutdown_dropped += 1);
    }
    options.stats.state(|s| {
        s.shutdown_complete = joined;
        s.drain_incomplete = !joined;
    });
    result
}

#[allow(clippy::too_many_arguments)]
async fn drive_client_path(
    conn: quinn::Connection,
    stream: u64,
    mut driver: H3Client,
    mut request: H3Request,
    send: H3Send,
    mut diagnostic: stats::ConnectionTrace,
    pid: u8,
    tx: mpsc::Sender<(u8, Bytes)>,
    ingress_drops: Arc<AtomicU64>,
    returning: Scope,
    measurement_scope: Scope,
    path_view: Paths,
    feedback: bool,
) {
    // Dropping the last SendRequest closes the HTTP/3 connection.
    let _send = send;
    let result:Result<()>=async {loop {tokio::select! {
                        e=driver.wait_idle()=>return Err(e.into()),
                        body=request.recv_data()=>{let _=body?;return Ok(())},
                        d=conn.read_datagram()=>match d {
                            Ok(d)=>{
                                returning.path(pid,|p|p.http_datagrams_received+=1);
                                if let Ok(p)=wire::http_payload(&d,stream) && p.len()<=(if feedback{quality::MAX_FRAME}else{wire::MAX_WIRE}) {
                                    match measured_payload(&path_view,pid,p,feedback,&measurement_scope) {Ok(Some(p))=>{if let Err(error)=tx.try_send((pid,p)){ingress_drops.fetch_add(1,Ordering::Relaxed);queue_error(&returning,QueueLayer::Receiver,&error,Some(pid));}},Ok(None)=>{},Err(_)=>returning.path(pid,|p|p.invalid_http_datagrams_dropped+=1)}
                                }else{returning.path(pid,|p|p.invalid_http_datagrams_dropped+=1);returning.update(|d|d.records.invalid_symbols_dropped+=1);}
                            },
                            Err(e)=>return Err(e.into()),
                        }
                    }}}.await;
    let normal = diagnostic.finish(result.as_ref().err());
    if normal {
        info!(context=%diagnostic.context(),"client path closed");
    } else {
        warn!(context=%diagnostic.context(),error=?result.err(),"client path ended");
    }
    conn.close(0u32.into(), b"path ended");
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
    generation: u64,
    rejoin: bool,
    policy: &Policy,
    diagnostic: &mut stats::ConnectionTrace,
) -> Result<(quinn::Connection, u64, H3Client, H3Request, H3Send)> {
    let conn = endpoint.connect(remote, name)?.await?;
    diagnostic.handshake_succeeded(&conn);
    diagnostic.enter("http3", "datagram_capacity");
    ensure!(
        conn.max_datagram_size().is_some_and(|n| n
            >= (if policy.receiver_feedback {
                quality::MAX_FRAME
            } else {
                wire::MAX_WIRE
            }) + 9),
        "insufficient datagram size"
    );
    diagnostic.succeeded();
    diagnostic.enter("http3", "http3_setup");
    let (mut driver, mut send) = h3::client::builder()
        .enable_datagram(true)
        .max_field_section_size(8192)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
        .await?;
    diagnostic.succeeded();
    diagnostic.enter("http3", "peer_settings");
    // Poll the driver concurrently so peer SETTINGS are processed before admission.
    tokio::select! {
        e=driver.wait_idle()=>bail!("HTTP/3 closed before settings: {e}"),
        _=async {while !send.settings().enable_datagram(){tokio::time::sleep(Duration::from_millis(1)).await;}}=>{}
    }
    diagnostic.succeeded();
    diagnostic.begin_admission();
    diagnostic.enter("path_admission", "admission");
    let mut req = Request::builder()
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
        .header("braidpath-queue-ms", policy.queue_ms);
    if policy.receiver_feedback {
        req = req
            .header("braidpath-feedback", "1")
            .header("braidpath-generation", generation);
    }
    if rejoin {
        req = req.header("braidpath-rejoin", "1");
    }
    if policy.quality_schedule {
        req = req.header("braidpath-scheduler", "quality");
    }
    let req = req.body(())?;
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
    ensure!(
        !policy.receiver_feedback
            || response
                .headers()
                .get("braidpath-feedback")
                .is_some_and(|v| v == "1"),
        "receiver feedback not negotiated"
    );
    ensure!(
        !policy.quality_schedule
            || response
                .headers()
                .get("braidpath-scheduler")
                .is_some_and(|v| v == "quality"),
        "quality scheduling not negotiated"
    );
    diagnostic.admitted();
    Ok((conn, stream.id().into_inner(), driver, stream, send))
}

pub async fn get(remote: SocketAddr, name: &str, ca: &std::path::Path) -> Result<String> {
    let endpoint = transport::client(remote, ca, None, transport::Congestion::default())?;
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
