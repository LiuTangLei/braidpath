use super::{
    MAX_PATHS, MAX_PAYLOAD, QUEUE, adaptive, outbound, quality, scheduler,
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
    collections::{BTreeMap, HashMap},
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
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
const SESSION_IDLE_GRACE: Duration = Duration::from_secs(120);
const SESSION_PATH: &str = "/session";
const WEBSITE: &str = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Welcome</title><h1>Welcome</h1><p>This service is online.</p></html>\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub adaptive: bool,
    pub latency_target_ms: u64,
    pub group_rates: [u64; MAX_PATHS],
    pub receiver_feedback: bool,
    pub quality_schedule: bool,
    pub fec: u8,
    pub redundancy: u8,
    pub rate: u64,
    pub block_ms: u64,
    pub queue_ms: u64,
}
impl Policy {
    fn admission_lifetime(&self) -> Duration {
        Duration::from_millis(if self.adaptive {
            self.queue_ms.min(self.latency_target_ms)
        } else {
            self.queue_ms
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.adaptive || (self.quality_schedule && self.receiver_feedback),
            "adaptive policy requires feedback and scheduling"
        );
        ensure!(
            (1..=1000).contains(&self.latency_target_ms),
            "latency target must be 1..1000 ms of additional queuing"
        );
        ensure!(
            self.group_rates
                .iter()
                .all(|r| (64_000..=self.rate).contains(r)),
            "group rate must be 64000..aggregate rate"
        );
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
    group: u8,
    conn: quinn::Connection,
    stream: u64,
    quality: Arc<Mutex<quality::State>>,
    epoch: Instant,
    probe_reply: Arc<Mutex<Option<quality::Probe>>>,
}
type Paths = Arc<Mutex<Vec<OutPath>>>;

fn quality_time(path: &OutPath) -> u64 {
    path.epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Copy)]
struct ReprobePath {
    id: u8,
    group: u8,
}

/// Coordinate experiments after every live controller has observed the same
/// sender tick. Closed/retired paths are absent, so they cannot retain a lease.
/// Existing aggregate/group pacers still enforce every actual admission.
fn grant_reprobes(
    paths: &[ReprobePath],
    controllers: &mut [adaptive::PathController; MAX_PATHS],
    aggregate_rate: u64,
    group_rates: &[u64; MAX_PATHS],
    next_path: &mut usize,
    now_us: u64,
) {
    let mut rates = [0u64; MAX_PATHS];
    let mut usable = [false; MAX_PATHS];
    let mut occupied = [false; MAX_PATHS];
    let mut grouped = [0u64; MAX_PATHS];
    let mut total = 0u64;
    for path in paths {
        let id = usize::from(path.id);
        let group = usize::from(path.group);
        let decision = controllers[id].decision(now_us);
        if decision.eligible {
            usable[id] = true;
            rates[id] = decision.pacing_bps;
            grouped[group] = grouped[group].saturating_add(rates[id]);
            total = total.saturating_add(rates[id]);
            occupied[group] |= controllers[id].reprobe_active();
        }
    }
    let first = *next_path;
    for offset in 0..MAX_PATHS {
        let id = (first + offset) % MAX_PATHS;
        let Some(path) = paths.iter().find(|path| usize::from(path.id) == id) else {
            continue;
        };
        let group = usize::from(path.group);
        if !usable[id] || occupied[group] {
            continue;
        }
        let Some(request) = controllers[id].reprobe_candidate(now_us) else {
            continue;
        };
        let headroom = aggregate_rate
            .saturating_sub(total)
            .min(group_rates[group].saturating_sub(grouped[group]));
        let ceiling = request.trial_bps.min(rates[id].saturating_add(headroom));
        if ceiling <= rates[id] || !controllers[id].start_reprobe(now_us, ceiling) {
            continue;
        }
        let admitted_rate = controllers[id].decision(now_us).pacing_bps;
        let increase = admitted_rate.saturating_sub(rates[id]);
        total = total.saturating_add(increase);
        grouped[group] = grouped[group].saturating_add(increase);
        rates[id] = admitted_rate;
        occupied[group] = true;
        *next_path = (id + 1) % MAX_PATHS;
    }
}

fn control_priority(path: &OutPath) -> (bool, u64) {
    let q = path.quality.lock().expect("quality lock");
    let fresh = q
        .snapshot
        .probe_updated_us
        .is_some_and(|at| quality_time(path).saturating_sub(at) < 3_000_000);
    (!fresh, (q.snapshot.probe_rtt_ms.max(0.0) * 1000.0) as u64)
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
    if payload.starts_with(b"BQ1C") || payload.starts_with(b"BQ2C") {
        for report in quality::parse_control(payload)? {
            if let Some(path) = paths.iter().find(|p| p.id == report.id) {
                let mut q = path.quality.lock().expect("quality lock");
                if q.apply(&report, quality_time(path)).is_err() {
                    q.snapshot.invalid_controls += 1;
                }
                let feedback = q.snapshot_at(quality_time(path));
                drop(q);
                scope.path(path.id, |p| p.receiver_feedback = Some(feedback));
            }
        }
        return Ok(None);
    }
    let path = paths
        .iter()
        .find(|p| p.id == pid)
        .context("missing measurement path")?;
    let mut q = path.quality.lock().expect("quality lock");
    if payload.starts_with(b"BQ2P") || payload.starts_with(b"BQ2R") {
        let probe = quality::parse_probe(payload)?;
        ensure!(
            probe.generation == q.snapshot.generation,
            "stale probe generation"
        );
        if probe.response {
            q.apply_probe(&probe, quality_time(path))?;
        } else {
            *path.probe_reply.lock().expect("probe reply lock") = Some(quality::Probe {
                response: true,
                ..probe
            });
        }
        let feedback = q.snapshot_at(quality_time(path));
        drop(q);
        scope.path(pid, |p| p.receiver_feedback = Some(feedback));
        return Ok(None);
    }
    let inner = q.receive(payload, quality_time(path))?;
    let feedback = q.snapshot_at(quality_time(path));
    drop(q);
    scope.path(pid, |p| p.receiver_feedback = Some(feedback));
    Ok(Some(Bytes::copy_from_slice(inner)))
}

struct QueuedRecord {
    record: Record,
    created: Instant,
}

#[derive(Clone)]
struct BlockSend {
    created: Instant,
    paths: u8,
}

fn enqueue_symbol(
    data: Bytes,
    created: Instant,
    queue: &mut outbound::Queue,
    blocks: &mut BTreeMap<u64, BlockSend>,
    metrics: &Scope,
) {
    let record = if data[3] != 1 {
        Record::decode(&data[wire::HEADER..]).ok()
    } else {
        None
    };
    let block = if data[3] != 2 {
        Some(u64::from_be_bytes(
            data[4..12].try_into().expect("wire header"),
        ))
    } else {
        None
    };
    let block_created = if let Some(block) = block {
        blocks
            .entry(block)
            .or_insert(BlockSend { created, paths: 0 })
            .created
            .min(created)
    } else {
        created
    };
    if let Some(block) = block {
        blocks.get_mut(&block).expect("block inserted").created = block_created;
    }
    let record_id = record.as_ref().map(|r| r.id);
    // An original keeps its own ingress clock; a repair expires with the oldest
    // original it could help, so encoder waiting never grants extra repair time.
    let created = if record_id.is_some() {
        created
    } else {
        block_created
    };
    let flow = record.map(|r| r.flow);
    metrics.update(|d| {
        if let Some(id) = record_id {
            d.symbols.originals_generated += 1;
            d.generated_record_ids.add(id);
        } else {
            d.symbols.repairs_generated += 1;
        }
    });
    let pending = outbound::Pending {
        data,
        created,
        record_id,
        flow,
        block,
    };
    let accepted = queue.push(pending).is_ok();
    metrics.update(|d| match (record_id, accepted) {
        (Some(_), true) => d.symbols.originals_enqueued += 1,
        (None, true) => d.symbols.repairs_enqueued += 1,
        (Some(id), false) => {
            d.symbols.originals_queue_full_dropped += 1;
            d.locally_dropped_original_ids.add(id);
        }
        (None, false) => d.symbols.repairs_queue_full_dropped += 1,
    });
    while blocks.len() > QUEUE * 2 {
        blocks.pop_first();
    }
}

fn account_expired(pending: &outbound::Pending, now: Instant, metrics: &Scope) {
    metrics.update(|d| {
        if let Some(id) = pending.record_id {
            d.symbols.originals_expired_dropped += 1;
            d.locally_dropped_original_ids.add(id);
        } else {
            d.symbols.repairs_expired_dropped += 1;
        }
        d.symbols
            .expiry_wait
            .add(now.saturating_duration_since(pending.created));
    });
}

/// This item remains at the application queue head until Quinn accepts it. The
/// sender cancels the wait before handling any other event that could move it.
struct PreparedSend {
    path: OutPath,
    generation: u64,
    front: outbound::Pending,
    candidates: Vec<(u8, i32)>,
    repair: bool,
    used: u8,
    data: Bytes,
    feedback_reserve: usize,
    group_reserve: usize,
}

struct WaitingSend {
    prepared: PreparedSend,
    send: Pin<Box<dyn Future<Output = Result<(), quinn::SendDatagramError>> + Send>>,
}

#[derive(Debug)]
enum SendReadiness {
    Admitted { at: Instant, next_cursor: usize },
    Expired,
    PathChanged,
    GateChanged,
    Failed,
}

impl WaitingSend {
    fn new(prepared: PreparedSend) -> Self {
        let conn = prepared.path.conn.clone();
        let data = prepared.data.clone();
        Self {
            prepared,
            // A pending Quinn future has not queued this datagram. Dropping it
            // before a successful poll cancels the attempt without any debit.
            send: Box::pin(async move { conn.send_datagram_wait(data).await }),
        }
    }

    fn poll(
        &mut self,
        cx: &mut TaskContext<'_>,
        shared_paths: &Paths,
        lifetime: Duration,
        mut allowed: impl FnMut(&PreparedSend, Instant) -> bool,
    ) -> Poll<SendReadiness> {
        let paths = shared_paths.lock().expect("paths lock");
        let Some(index) = paths.iter().position(|path| {
            path.id == self.prepared.path.id
                && path.group == self.prepared.path.group
                && path.stream == self.prepared.path.stream
                && path.conn.stable_id() == self.prepared.path.conn.stable_id()
                && path
                    .quality
                    .lock()
                    .expect("quality lock")
                    .snapshot
                    .generation
                    == self.prepared.generation
        }) else {
            return Poll::Ready(SendReadiness::PathChanged);
        };
        if paths[index].conn.close_reason().is_some() {
            return Poll::Ready(SendReadiness::PathChanged);
        }
        // Take the clock after acquiring the membership locks, immediately
        // before polling Quinn. A ready buffer must never revive an old record.
        let now = Instant::now();
        if now.saturating_duration_since(self.prepared.front.created) >= lifetime {
            return Poll::Ready(SendReadiness::Expired);
        }
        if !allowed(&self.prepared, now) {
            return Poll::Ready(SendReadiness::GateChanged);
        }
        match self.send.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(SendReadiness::Admitted {
                at: Instant::now(),
                next_cursor: (index + 1) % paths.len(),
            }),
            Poll::Ready(Err(_)) => Poll::Ready(SendReadiness::Failed),
        }
        // The membership guard is local to this synchronous poll. No mutex
        // guard survives Pending or is held while the sender awaits a wakeup.
    }

    fn cancel(self) -> PreparedSend {
        let Self { prepared, send } = self;
        drop(send);
        prepared
    }
}

enum SenderEvent {
    Stop,
    Tick,
    Input(Option<QueuedRecord>),
    Ready(SendReadiness),
}

struct Admission<'a> {
    path: &'a OutPath,
    front: &'a outbound::Pending,
    candidates: &'a [(u8, i32)],
    repair: bool,
    used: u8,
    frame_bytes: usize,
    next_cursor: usize,
    at: Instant,
}

/// The immediate path and the readiness path share the exact same successful
/// admission transaction. Pending, cancellation and expiry never call this.
struct SendAccounting<'a> {
    policy: &'a Policy,
    metrics: &'a Scope,
    queue: &'a mut outbound::Queue,
    blocks: &'a mut BTreeMap<u64, BlockSend>,
    budget: &'a mut outbound::RepairBudget,
    scheduler: &'a mut scheduler::Scheduler,
    controllers: &'a mut [adaptive::PathController; MAX_PATHS],
    pacer: &'a mut outbound::Pacer,
    groups: &'a mut [outbound::Pacer; MAX_PATHS],
    cursor: &'a mut usize,
    repair_turn: &'a mut bool,
    epoch: Instant,
}

impl SendAccounting<'_> {
    fn commit(&mut self, admission: Admission<'_>) {
        let Admission {
            path,
            front,
            candidates,
            repair,
            used,
            frame_bytes,
            next_cursor,
            at,
        } = admission;
        let sent = self.queue.pop(repair).expect("admitted front");
        debug_assert_eq!(sent.created, front.created);
        debug_assert_eq!(sent.record_id, front.record_id);
        debug_assert_eq!(sent.block, front.block);
        debug_assert_eq!(sent.data, front.data);
        let cost = frame_bytes + 80;
        self.pacer.spend(cost);
        self.groups[usize::from(path.group)].spend(cost);
        if self.policy.quality_schedule {
            self.scheduler.commit(candidates, path.id, frame_bytes);
        }
        if self.policy.adaptive {
            let now_us = at
                .saturating_duration_since(self.epoch)
                .as_micros()
                .min(u128::from(u64::MAX)) as u64;
            self.controllers[usize::from(path.id)].admitted_symbol(now_us, cost, sent.data.len());
        }
        if self.policy.receiver_feedback {
            path.quality
                .lock()
                .expect("quality lock")
                .admitted(sent.data.len());
        }
        if repair {
            self.budget.repair_admitted(frame_bytes);
            self.metrics
                .path(path.id, |p| p.quinn_admitted_repairs += 1);
            if used & (1 << path.id) != 0 {
                self.metrics
                    .update(|d| d.symbols.repair_no_diverse_path += 1);
            }
            if let Some(block) = sent.block {
                self.blocks.remove(&block);
            }
        } else {
            self.budget.original_admitted(frame_bytes);
            self.metrics
                .path(path.id, |p| p.quinn_admitted_originals += 1);
            if let Some(block) = sent.block
                && let Some(meta) = self.blocks.get_mut(&block)
            {
                meta.paths |= 1 << path.id;
            }
        }
        *self.cursor = next_cursor;
        *self.repair_turn = !repair;
        self.metrics.update(|d| {
            if let Some(id) = sent.record_id {
                d.symbols.originals_quinn_admitted += 1;
                d.symbols.originals_quinn_admitted_bytes += frame_bytes as u64;
                d.quinn_admitted_record_ids.add(id);
            } else {
                d.symbols.repairs_quinn_admitted += 1;
                d.symbols.repairs_quinn_admitted_bytes += frame_bytes as u64;
            }
            d.symbols
                .admitted_wait
                .add(at.saturating_duration_since(sent.created));
        });
    }
}

/// A single owner admits every business, repair, feedback and probe datagram.
/// Each local flow gets a turn; all classes obey the aggregate and group caps.
async fn sender(
    mut input: mpsc::Receiver<QueuedRecord>,
    shared_paths: Paths,
    policy: Policy,
    mut stop: watch::Receiver<bool>,
    metrics: Scope,
) {
    let mut encoder = Encoder::new(policy.fec.max(1), Duration::from_millis(policy.block_ms))
        .expect("validated policy");
    let mut queue = outbound::Queue::default();
    let mut blocks = BTreeMap::<u64, BlockSend>::new();
    let mut budget = outbound::RepairBudget::new(policy.redundancy);
    let mut scheduler = scheduler::Scheduler::default();
    let mut controllers: [adaptive::PathController; MAX_PATHS] = std::array::from_fn(|_| {
        adaptive::PathController::new(policy.rate, policy.latency_target_ms)
    });
    let burst = if policy.adaptive { 2400 } else { 9600 };
    let mut pacer = outbound::Pacer::new(policy.rate, burst);
    let mut groups: [outbound::Pacer; MAX_PATHS] =
        std::array::from_fn(|i| outbound::Pacer::new(policy.group_rates[i], burst));
    let epoch = Instant::now();
    let mut cursor = 0usize;
    let mut control_cursor = 0usize;
    let mut reprobe_cursor = 0usize;
    let mut feedback_schedule = quality::FeedbackSchedule::default();
    let mut pending_feedback: Option<(Bytes, quality::ReportKind)> = None;
    let mut observe_at = 0u64;
    let mut repair_turn = false;
    let mut tick = interval(Duration::from_millis(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let lifetime = policy.admission_lifetime();
    let mut waiting: Option<WaitingSend> = None;
    loop {
        if *stop.borrow() {
            break;
        }
        let event = tokio::select! {
            biased;
            _=stop.changed()=>SenderEvent::Stop,
            _=tick.tick()=>SenderEvent::Tick,
            ready=poll_fn(|cx| {
                let Some(wait) = waiting.as_mut() else {
                    return Poll::Pending;
                };
                wait.poll(cx, &shared_paths, lifetime, |attempt, now| {
                    let cost = attempt.data.len() + 80;
                    let now_us = now.saturating_duration_since(epoch).as_micros()
                        .min(u128::from(u64::MAX)) as u64;
                    let age = now.saturating_duration_since(attempt.front.created);
                    pacer.available(cost + attempt.feedback_reserve)
                        && groups[usize::from(attempt.path.group)]
                            .available(cost + attempt.group_reserve)
                        && (!attempt.repair || budget.can_repair(attempt.data.len()))
                        && (!policy.adaptive
                            || controllers[usize::from(attempt.path.id)]
                                .allow(now_us, cost, age.as_secs_f64() * 1000.0))
                })
            }), if waiting.is_some()=>SenderEvent::Ready(ready),
            item=input.recv()=>SenderEvent::Input(item),
        };
        // A different actor event invalidates this prepared queue head and its
        // budget checks. Cancel the future before touching any actor state.
        let prepared = waiting.take().map(WaitingSend::cancel);
        match event {
            SenderEvent::Stop => break,
            SenderEvent::Tick => {
                if policy.fec > 0
                    && let Some(shard) = encoder.flush_due(Instant::now())
                {
                    enqueue_symbol(
                        wire::shard(shard),
                        Instant::now(),
                        &mut queue,
                        &mut blocks,
                        &metrics,
                    );
                }
            }
            SenderEvent::Ready(SendReadiness::Admitted { at, next_cursor }) => {
                let attempt = prepared.expect("selected readiness attempt");
                SendAccounting {
                    policy: &policy,
                    metrics: &metrics,
                    queue: &mut queue,
                    blocks: &mut blocks,
                    budget: &mut budget,
                    scheduler: &mut scheduler,
                    controllers: &mut controllers,
                    pacer: &mut pacer,
                    groups: &mut groups,
                    cursor: &mut cursor,
                    repair_turn: &mut repair_turn,
                    epoch,
                }
                .commit(Admission {
                    path: &attempt.path,
                    front: &attempt.front,
                    candidates: &attempt.candidates,
                    repair: attempt.repair,
                    used: attempt.used,
                    frame_bytes: attempt.data.len(),
                    next_cursor,
                    at,
                });
            }
            SenderEvent::Ready(SendReadiness::Failed) => {
                let attempt = prepared.expect("selected readiness attempt");
                metrics.path(attempt.path.id, |p| p.quinn_send_error_attempts += 1);
            }
            SenderEvent::Ready(_) => {}
            SenderEvent::Input(item) => {
                let Some(QueuedRecord { record, created }) = item else {
                    break;
                };
                metrics.update(|d| d.records.sender_input_consumed += 1);
                if created.elapsed() >= lifetime {
                    metrics.update(|d| {
                        d.symbols.originals_ingress_expired_dropped += 1;
                        d.locally_dropped_original_ids.add(record.id);
                        d.symbols.expiry_wait.add(created.elapsed());
                    });
                    continue;
                }
                if policy.fec == 0 {
                    match wire::plain(&record) {
                        Ok(data) => {
                            enqueue_symbol(data, created, &mut queue, &mut blocks, &metrics)
                        }
                        Err(_) => metrics.update(|d| d.records.encoding_dropped += 1),
                    }
                } else if let Ok(data) = record.encode() {
                    match encoder.push(&data, Instant::now()) {
                        Ok(shards) => {
                            for shard in shards {
                                enqueue_symbol(
                                    wire::shard(shard),
                                    created,
                                    &mut queue,
                                    &mut blocks,
                                    &metrics,
                                );
                            }
                        }
                        Err(_) => metrics.update(|d| d.records.encoding_dropped += 1),
                    }
                } else {
                    metrics.update(|d| d.records.encoding_dropped += 1);
                }
            }
        }
        let now = Instant::now();
        let now_us = epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        pacer.refill(now_us);
        for group in &mut groups {
            group.refill(now_us);
        }
        for expired in queue.expire(now, lifetime) {
            account_expired(&expired, now, &metrics);
        }
        let paths = shared_paths.lock().expect("paths lock");
        if policy.adaptive && now_us >= observe_at {
            for path in paths.iter() {
                let q = path.quality.lock().expect("quality lock");
                let snapshot = &q.snapshot;
                let estimate = &snapshot.sender_estimate;
                let at = quality_time(path);
                controllers[usize::from(path.id)].observe(&adaptive::Observation {
                    now_us,
                    generation: snapshot.generation,
                    report_number: estimate.report_number,
                    feedback_age_us: estimate.updated_us.map(|t| at.saturating_sub(t)),
                    positive_delivery_age_us: estimate
                        .delivered_updated_us
                        .map(|t| at.saturating_sub(t)),
                    delivered_bytes: estimate.received_bytes,
                    delivered_bps: estimate.delivered_bps,
                    delivery_sample_span_us: estimate.sample_span_us,
                    delivery_report_time_us: estimate.report_time_us,
                    reprobe_enabled: policy.fec == 0
                        && policy.redundancy == 0
                        && path.conn.close_reason().is_none(),
                    feedback_sample_symbols: estimate.sample_symbols,
                    finalized_expected: Some(estimate.expected),
                    finalized_lost: Some(estimate.lost),
                    loss_sample_rate: (estimate.sample_symbols > 0)
                        .then_some(estimate.sample_loss_rate),
                    loss_rate: estimate.loss_rate,
                    rtt_ms: path.conn.rtt().as_secs_f64() * 1000.0,
                    probe_rtt_ms: snapshot.probe_updated_us.map(|_| snapshot.probe_rtt_ms),
                    probe_latest_rtt_ms: snapshot
                        .probe_updated_us
                        .map(|_| snapshot.probe_rtt_latest_ms),
                    probe_sample_id: snapshot.replies_received,
                    probe_age_us: snapshot.probe_updated_us.map(|t| at.saturating_sub(t)),
                    transit_excess_ms: estimate.delay_variation_ms,
                    send_queue_bytes: 1200usize
                        .saturating_sub(path.conn.datagram_send_buffer_space()),
                    offered_backlog: !queue.is_empty(),
                    transport_blocked: path.conn.datagram_send_buffer_space() < wire::MAX_WIRE,
                });
            }
            let live: Vec<_> = paths
                .iter()
                .filter(|path| path.conn.close_reason().is_none())
                .map(|path| ReprobePath {
                    id: path.id,
                    group: path.group,
                })
                .collect();
            grant_reprobes(
                &live,
                &mut controllers,
                policy.rate,
                &policy.group_rates,
                &mut reprobe_cursor,
                now_us,
            );
            for path in paths.iter() {
                let snapshot = controllers[usize::from(path.id)].snapshot(now_us);
                metrics.path(path.id, |p| p.adaptive = Some(snapshot));
            }
            observe_at = now_us.saturating_add(100_000);
        }
        if policy.receiver_feedback
            && pending_feedback.is_none()
            && feedback_schedule.should_check(now_us, policy.adaptive)
        {
            let unreported_bytes = paths
                .iter()
                .map(|path| {
                    path.quality
                        .lock()
                        .expect("quality lock")
                        .unreported_received_bytes()
                })
                .fold(0u64, u64::saturating_add);
            if let Some(kind) = feedback_schedule.due(now_us, policy.adaptive, unreported_bytes) {
                let reports: Vec<_> = paths
                    .iter()
                    .map(|path| {
                        let mut state = path.quality.lock().expect("quality lock");
                        let at = quality_time(path);
                        match kind {
                            quality::ReportKind::Full => state.report(path.id, at),
                            quality::ReportKind::Delivery => state.delivery_report(path.id, at),
                        }
                    })
                    .collect();
                if !reports.is_empty() {
                    pending_feedback = Some((quality::control_v2(&reports), kind));
                }
            }
        }
        if let Some((frame, kind)) = &pending_feedback {
            let mut admitted = false;
            let mut control_order: Vec<_> = (0..paths.len())
                .map(|n| (control_cursor + n) % paths.len())
                .collect();
            if policy.adaptive {
                // A healthy feedback route must not wait behind silent connections.
                control_order.sort_by_key(|i| control_priority(&paths[*i]));
            }
            for i in control_order {
                let path = &paths[i];
                let data = wire::http_datagram(path.stream, frame).expect("admitted stream");
                let cost = data.len() + 80;
                let group = &mut groups[usize::from(path.group)];
                if path.conn.close_reason().is_none()
                    && pacer.available(cost)
                    && group.available(cost)
                    && path
                        .conn
                        .max_datagram_size()
                        .is_some_and(|m| m >= data.len())
                    && path.conn.datagram_send_buffer_space() >= data.len()
                    && path.conn.send_datagram(data).is_ok()
                {
                    pacer.spend(cost);
                    group.spend(cost);
                    path.quality
                        .lock()
                        .expect("quality lock")
                        .snapshot
                        .controls_sent += 1;
                    metrics.update(|d| d.symbols.feedback_admitted += 1);
                    control_cursor = (i + 1) % paths.len();
                    admitted = true;
                    break;
                }
            }
            if admitted {
                feedback_schedule.admitted(*kind, now_us);
                pending_feedback = None;
            } else {
                metrics.update(|d| d.symbols.feedback_deferred += 1);
            }
        }
        // Preserve one feedback route's group allowance as well as global credit.
        // Small business/probe datagrams otherwise can starve a larger report forever.
        let feedback_reserve = pending_feedback
            .as_ref()
            .map_or(0, |(frame, _)| frame.len() + 89);
        let reserved_group = if feedback_reserve > 0 {
            paths
                .iter()
                .filter(|p| p.conn.close_reason().is_none())
                .min_by_key(|p| control_priority(p))
                .map(|p| p.group)
        } else {
            None
        };
        if policy.adaptive {
            for path in paths.iter().filter(|p| p.conn.close_reason().is_none()) {
                let id = usize::from(path.id);
                let reply = path.probe_reply.lock().expect("probe reply lock").clone();
                let frame = if let Some(reply) = reply {
                    Some(reply)
                } else if controllers[id].decision(now_us).probe_due {
                    Some(quality::Probe {
                        generation: path
                            .quality
                            .lock()
                            .expect("quality lock")
                            .snapshot
                            .generation,
                        nonce: quality_time(path),
                        response: false,
                    })
                } else {
                    None
                };
                let Some(probe) = frame else { continue };
                let data = wire::http_datagram(path.stream, &quality::probe(&probe))
                    .expect("probe mapping");
                let cost = data.len() + 80;
                let group = &mut groups[usize::from(path.group)];
                let group_reserve = if Some(path.group) == reserved_group {
                    feedback_reserve
                } else {
                    0
                };
                if pacer.available(cost + feedback_reserve)
                    && group.available(cost + group_reserve)
                    && path.conn.datagram_send_buffer_space() >= data.len()
                    && path
                        .conn
                        .max_datagram_size()
                        .is_some_and(|m| m >= data.len())
                    && path.conn.send_datagram(data).is_ok()
                {
                    pacer.spend(cost);
                    group.spend(cost);
                    if probe.response {
                        *path.probe_reply.lock().expect("probe reply lock") = None;
                    } else {
                        path.quality
                            .lock()
                            .expect("quality lock")
                            .probe_admitted(probe.nonce, quality_time(path));
                        controllers[id].probe_admitted(now_us);
                    }
                    metrics.update(|d| d.symbols.probes_admitted += 1);
                }
            }
        }
        let mut stalled_originals = 0usize;
        let mut blocked_repair = false;
        let mut next_wait = None;
        while !queue.is_empty() {
            let now = Instant::now();
            let now_us = epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
            let repair_ready = queue.front(true).is_some_and(|p| {
                !p.block.is_some_and(|b| queue.block_pending(b))
                    && budget.can_repair(
                        p.data.len()
                            + if policy.receiver_feedback {
                                quality::HEADER + 2
                            } else {
                                2
                            },
                    )
            });
            let repair =
                repair_ready && !blocked_repair && (repair_turn || queue.front(false).is_none());
            let Some(front) = queue.front(repair).cloned() else {
                if blocked_repair {
                    break;
                }
                // A repair with no admitted-original credit cannot hold the queue.
                if let Some(skipped) = queue.pop(true) {
                    if now.saturating_duration_since(skipped.created) >= lifetime {
                        account_expired(&skipped, now, &metrics);
                    } else {
                        metrics.update(|d| d.symbols.repairs_budget_skipped += 1);
                    }
                    if let Some(block) = skipped.block {
                        blocks.remove(&block);
                    }
                    continue;
                }
                break;
            };
            let age = now.saturating_duration_since(front.created);
            if age >= lifetime {
                account_expired(&queue.pop(repair).expect("front"), now, &metrics);
                stalled_originals = 0;
                continue;
            }
            let candidates: Vec<_> = paths
                .iter()
                .filter(|p| {
                    p.conn.close_reason().is_none()
                        && (!policy.adaptive
                            || controllers[usize::from(p.id)].decision(now_us).eligible)
                })
                .map(|path| {
                    let weight = if policy.adaptive {
                        controllers[usize::from(path.id)].decision(now_us).weight
                    } else {
                        scheduler::weight(
                            &path
                                .quality
                                .lock()
                                .expect("quality lock")
                                .snapshot
                                .sender_estimate,
                            quality_time(path),
                            path.conn.rtt().as_secs_f64() * 1000.0,
                        )
                    };
                    (path.id, weight)
                })
                .collect();
            let mut order: Vec<usize> = if policy.quality_schedule {
                scheduler
                    .order(
                        &candidates,
                        front.data.len()
                            + if policy.receiver_feedback {
                                quality::HEADER + 2
                            } else {
                                2
                            },
                    )
                    .into_iter()
                    .filter_map(|id| paths.iter().position(|p| p.id == id))
                    .collect()
            } else {
                (0..paths.len())
                    .map(|n| (cursor + n) % paths.len())
                    .collect()
            };
            let used = front
                .block
                .and_then(|b| blocks.get(&b))
                .map_or(0, |b| b.paths);
            if repair {
                order.sort_by_key(|i| u8::from(used & (1 << paths[*i].id) != 0));
            }
            let mut accepted = None;
            let mut wait_candidate = None;
            for i in order {
                let path = &paths[i];
                let id = usize::from(path.id);
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
                let frame_bytes = data.len();
                let cost = frame_bytes + 80;
                let group_reserve = if Some(path.group) == reserved_group {
                    feedback_reserve
                } else {
                    0
                };
                if !pacer.available(cost + feedback_reserve)
                    || !groups[usize::from(path.group)].available(cost + group_reserve)
                {
                    continue;
                }
                if repair && !budget.can_repair(frame_bytes) {
                    continue;
                }
                if policy.adaptive
                    && !controllers[id].allow(now_us, cost, age.as_secs_f64() * 1000.0)
                {
                    continue;
                }
                if path.conn.max_datagram_size().is_none_or(|m| data.len() > m) {
                    continue;
                }
                if path.conn.datagram_send_buffer_space() < data.len() {
                    metrics.path(path.id, |p| p.send_buffer_full_attempts += 1);
                    if wait_candidate.is_none() {
                        wait_candidate = Some(PreparedSend {
                            path: path.clone(),
                            generation: path
                                .quality
                                .lock()
                                .expect("quality lock")
                                .snapshot
                                .generation,
                            front: front.clone(),
                            candidates: candidates.clone(),
                            repair,
                            used,
                            data,
                            feedback_reserve,
                            group_reserve,
                        });
                    }
                    continue;
                }
                match path.conn.send_datagram(data) {
                    Ok(()) => {
                        accepted = Some((i, frame_bytes, Instant::now()));
                        break;
                    }
                    Err(_) => metrics.path(path.id, |p| p.quinn_send_error_attempts += 1),
                }
            }
            let Some((index, frame_bytes, at)) = accepted else {
                if repair {
                    blocked_repair = true;
                    if queue.front(false).is_some() {
                        continue;
                    }
                } else {
                    stalled_originals += 1;
                    if stalled_originals < queue.original_flows() {
                        queue.rotate_original();
                        continue;
                    }
                    if repair_ready && !blocked_repair {
                        repair_turn = true;
                        continue;
                    }
                }
                // Every immediate path (and other flow/repair head) had its
                // chance. Only this unchanged queue head may now wait on Quinn.
                next_wait = wait_candidate;
                break;
            };
            SendAccounting {
                policy: &policy,
                metrics: &metrics,
                queue: &mut queue,
                blocks: &mut blocks,
                budget: &mut budget,
                scheduler: &mut scheduler,
                controllers: &mut controllers,
                pacer: &mut pacer,
                groups: &mut groups,
                cursor: &mut cursor,
                repair_turn: &mut repair_turn,
                epoch,
            }
            .commit(Admission {
                path: &paths[index],
                front: &front,
                candidates: &candidates,
                repair,
                used,
                frame_bytes,
                next_cursor: (index + 1) % paths.len(),
                at,
            });
            stalled_originals = 0;
            blocked_repair = false;
        }
        for path in paths.iter() {
            let feedback = path
                .quality
                .lock()
                .expect("quality lock")
                .snapshot_at(quality_time(path));
            metrics.path(path.id, |p| p.receiver_feedback = Some(feedback));
        }
        drop(paths);
        waiting = next_wait.map(WaitingSend::new);
    }
    drop(waiting);
    for repair in [false, true] {
        while let Some(pending) = queue.pop(repair) {
            metrics.update(|d| {
                if let Some(id) = pending.record_id {
                    d.symbols.originals_shutdown_dropped += 1;
                    d.locally_dropped_original_ids.add(id);
                } else {
                    d.symbols.repairs_shutdown_dropped += 1;
                }
            });
        }
    }
    input.close();
    while input.try_recv().is_ok() {
        metrics.update(|d| d.records.input_shutdown_dropped += 1);
    }
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
    generations: Mutex<[Option<u64>; MAX_PATHS]>,
    empty_since: Mutex<Option<Instant>>,
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
    let mut decoder = Receiver::with_repair_wait(Duration::from_millis(session.policy.queue_ms));
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
    let mut maintenance = interval(Duration::from_secs(1));
    options.stats.readiness(true, 0);
    info!(address=%endpoint.local_addr()?,target=%options.target,congestion=?options.congestion,"HTTP/3 server ready");
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=maintenance.tick()=>{
                let mut map=sessions.lock().expect("sessions lock");
                map.retain(|sid,session| {
                    let expired=session.paths.lock().expect("paths lock").is_empty()
                        && session.empty_since.lock().expect("empty time lock").is_some_and(|at|at.elapsed()>=SESSION_IDLE_GRACE);
                    if expired {let _=session.stop.send(true);}
                    let retain=!expired && !session.done.load(Ordering::Acquire);
                    if !retain {options.stats.retire_session(sid);}
                    retain
                });
            },
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
    let active_ids = sessions
        .lock()
        .expect("sessions lock")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
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
    for sid in active_ids {
        options.stats.retire_session(&sid);
    }
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
                    let feedback=req.headers().get("braidpath-feedback").map(|v|v.to_str()).transpose()?;ensure!(feedback.is_none() || feedback==Some("2"),"unsupported feedback version");
                    let generation=if feedback.is_some(){header("braidpath-generation")?.parse::<u64>()?}else{0};
                    ensure!(feedback.is_none() || conn.max_datagram_size().is_some_and(|n|n>=quality::MAX_FRAME+9),"peer lacks feedback datagram capacity");
                    let quality_schedule=req.headers().get("braidpath-scheduler").map(|v|v.to_str()).transpose()?;
                    ensure!(matches!(quality_schedule,None|Some("quality")|Some("adaptive")),"unknown scheduler");ensure!(quality_schedule.is_none() || feedback.is_some(),"quality scheduler requires feedback");
                    let rate=header("braidpath-rate")?.parse::<u64>()?.min(max_rate);
                    let mut group_rates=[rate;MAX_PATHS];
                    if let Some(value)=req.headers().get("braidpath-group-rates") {
                        let values=value.to_str()?.split(',').map(str::parse::<u64>).collect::<std::result::Result<Vec<_>,_>>()?;
                        ensure!(values.len()==MAX_PATHS,"invalid group caps");
                        for (slot,value) in group_rates.iter_mut().zip(values) {*slot=value.min(rate);}
                    }
                    let group=req.headers().get("braidpath-group").map(|v|v.to_str()).transpose()?.unwrap_or("0").parse::<u8>()?;
                    ensure!(usize::from(group)<MAX_PATHS,"invalid path group");
                    let latency_target_ms=req.headers().get("braidpath-latency-ms").map(|v|v.to_str()).transpose()?.unwrap_or("20").parse::<u64>()?;
                    let policy=Policy{adaptive:quality_schedule==Some("adaptive"),latency_target_ms,group_rates,quality_schedule:quality_schedule.is_some(),receiver_feedback:feedback.is_some(),fec:header("braidpath-fec")?.parse()?,redundancy:header("braidpath-redundancy")?.parse()?,rate,block_ms:header("braidpath-block-ms")?.parse()?,queue_ms:header("braidpath-queue-ms")?.parse()?};policy.validate()?;
                    let rejoin=req.headers().get("braidpath-rejoin").is_some_and(|v|v=="1");
                    let stream_id=stream.id().into_inner();
                    // Membership and idle expiry share one map -> paths -> generation lock order.
                    // A reconnect never creates a fresh server session under an old identifier.
                    let admitted={
                        let mut map=sessions.lock().expect("sessions lock");
                        if rejoin && !map.contains_key(&sid) {None}
                        else {
                            let session=if let Some(session)=map.get(&sid) {
                                ensure!(session.policy==policy,"session policy mismatch");
                                ensure!(!session.done.load(Ordering::Acquire) && !*session.stop.borrow(),"session stopped");
                                session.clone()
                            } else {
                                ensure!(map.len()<16,"session limit");
                                let (tx,rx)=mpsc::channel(QUEUE);let (stop,_)=watch::channel(false);
                                let session=Arc::new(Session{generations:Mutex::new([None;MAX_PATHS]),empty_since:Mutex::new(Some(Instant::now())),events:tx,paths:Arc::new(Mutex::new(Vec::new())),stop,policy,ingress_drops:Arc::new(AtomicU64::new(0)),forward:metrics.scope(&sid,stats::FORWARD),returning:metrics.scope(&sid,stats::RETURN),finished:tokio::sync::Notify::new(),done:std::sync::atomic::AtomicBool::new(false)});
                                map.insert(sid.clone(),session.clone());
                                tokio::spawn(session_loop(session.clone(),rx,target));
                                session
                            };
                            {
                                let mut paths=session.paths.lock().expect("paths lock");
                                let existing=paths.iter().position(|p|p.id==pid);
                                ensure!(existing.is_none() || (rejoin && feedback.is_some()),"duplicate path");
                                ensure!(existing.is_some() || paths.len()<MAX_PATHS,"path limit");
                                let mut generations=session.generations.lock().expect("generation lock");
                                scheduler::admit_generation(&mut generations[usize::from(pid)],generation)?;
                                if let Some(i)=existing {paths.remove(i).conn.close(0u32.into(),b"path rejoined");}
                                paths.push(OutPath{id:pid,group,conn:conn.clone(),stream:stream_id,quality:Arc::new(Mutex::new(quality::State::new(generation))),epoch:Instant::now(),probe_reply:Arc::new(Mutex::new(None))});
                                *session.empty_since.lock().expect("empty time lock")=None;
                            }
                            Some(session)
                        }
                    };
                    let Some(session)=admitted else {
                        diagnostic.rejected("session_expired");
                        stream.send_response(Response::builder().status(StatusCode::GONE).body(())?).await?;
                        stream.finish().await?;
                        // FIN only queues the response. Keep the connection alive long
                        // enough for the client to receive 410 and select a fresh epoch.
                        let _=timeout(Duration::from_secs(2),conn.closed()).await;
                        bail!("session expired; a fresh session epoch is required");
                    };
                    metrics.register(&sid,pid,stream_id,stats::RETURN,&conn);
                    joined=Some((sid,session,pid,stream_id));
                    let mut response=Response::builder().status(200).header("braidpath-version","1").header("braidpath-max-payload",MAX_PAYLOAD);if feedback.is_some(){response=response.header("braidpath-feedback","2");}
                    if let Some(scheduler)=quality_schedule {response=response.header("braidpath-scheduler",scheduler);}stream.send_response(response.body(())?).await?;
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
                if session.policy.adaptive {
                    *session.empty_since.lock().expect("empty time lock") = Some(Instant::now());
                } else {
                    let _ = session.stop.send(true);
                    map.remove(&sid);
                }
            }
            last && !session.policy.adaptive
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
        if last {
            metrics.retire_session(&sid);
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
    pub path_groups: Vec<u8>,
    pub name: String,
    pub ca: std::path::PathBuf,
    pub token: std::path::PathBuf,
    pub policy: Policy,
    pub congestion: transport::Congestion,
    pub stats: stats::Metrics,
}
#[derive(Debug)]
struct SessionExpired;
impl std::fmt::Display for SessionExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server session expired; starting a fresh epoch")
    }
}
impl std::error::Error for SessionExpired {}

#[derive(Clone)]
struct PathConfig {
    remote: SocketAddr,
    interface: Option<String>,
    bind: Option<SocketAddr>,
    group: u8,
    generation: u64,
    attempted: bool,
}

/// Keep the local application socket while explicitly replacing an expired session epoch.
pub async fn client(options: ClientOptions) -> Result<()> {
    options.policy.validate()?;
    ensure!(
        !options.rotate_source_port || options.policy.quality_schedule,
        "source-port rotation requires quality scheduling or adaptive mode"
    );
    ensure!(
        !options.entrances.is_empty()
            && options.entrances.len() * options.interfaces.len().max(1) <= MAX_PATHS,
        "path count must be 1..8"
    );
    let count = options.entrances.len() * options.interfaces.len().max(1);
    ensure!(
        options.path_binds.is_empty() || options.path_binds.len() == count,
        "path binds must match interface–entrance pair count"
    );
    ensure!(
        options.path_groups.is_empty() || options.path_groups.len() == count,
        "path groups must match interface–entrance pair count"
    );
    ensure!(
        options
            .path_groups
            .iter()
            .all(|id| usize::from(*id) < MAX_PATHS),
        "invalid bottleneck group"
    );
    let socket = Arc::new(UdpSocket::bind(options.listen).await?);
    loop {
        let result = client_session(&options, socket.clone()).await;
        if options.policy.adaptive
            && result
                .as_ref()
                .err()
                .is_some_and(|error| error.is::<SessionExpired>())
        {
            info!(
                "server session expired; creating a fresh authenticated epoch on the existing local listener"
            );
            tokio::select! {
                _=tokio::signal::ctrl_c()=>return Ok(()),
                _=tokio::time::sleep(Duration::from_secs(1))=>{}
            }
            continue;
        }
        return result;
    }
}

async fn client_session(options: &ClientOptions, socket: Arc<UdpSocket>) -> Result<()> {
    let token = transport::token(&options.token)?;
    let sid = transport::hex(&rand::random::<[u8; 16]>());
    let paths: Paths = Arc::new(Mutex::new(Vec::new()));
    let forward = options.stats.scope(&sid, stats::FORWARD);
    let returning = options.stats.scope(&sid, stats::RETURN);
    let (wire_tx, mut wire_rx) = mpsc::channel::<(u8, Bytes)>(QUEUE);
    let mut tasks = JoinSet::new();
    let mut endpoints: [Option<quinn::Endpoint>; MAX_PATHS] = std::array::from_fn(|_| None);
    let mut configs = Vec::<PathConfig>::new();
    let mut rotations: [scheduler::Rotation; MAX_PATHS] =
        std::array::from_fn(|_| Default::default());
    let mut inflight = [false; MAX_PATHS];
    let mut elective_inflight = [false; MAX_PATHS];
    options.stats.state(|s| s.shutdown_complete = false);
    let epoch = Instant::now();
    let (rejoin_tx, mut rejoin_rx) =
        mpsc::channel::<(u8, u64, Result<(Rejoined, stats::ConnectionTrace)>)>(MAX_PATHS);
    let ingress_drops = Arc::new(AtomicU64::new(0));
    let interfaces: Vec<Option<String>> = if options.interfaces.is_empty() {
        vec![None]
    } else {
        options.interfaces.iter().cloned().map(Some).collect()
    };
    for (interface_index, interface) in interfaces.into_iter().enumerate() {
        for remote in &options.entrances {
            let id = configs.len();
            configs.push(PathConfig {
                remote: *remote,
                interface: interface.clone(),
                bind: options.path_binds.get(id).copied(),
                group: options
                    .path_groups
                    .get(id)
                    .copied()
                    .unwrap_or(interface_index as u8),
                generation: rand::random::<u64>() >> 1,
                attempted: false,
            });
        }
    }
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
    let mut decoder = Receiver::with_repair_wait(Duration::from_millis(options.policy.queue_ms));
    let mut tick = interval(Duration::from_millis(200));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut drops = 0u64;
    let mut has_session = false;
    let mut announced = false;
    let mut last_stats = 0u64;
    let result:Result<()>=async {loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=tick.tick()=>{
                let now_us=epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                peers.retain(|_,(id,last)|{if last.elapsed()<Duration::from_secs(60){true}else{reverse.remove(id);false}});
                let current=paths.lock().expect("paths lock").clone();
                let live=current.iter().filter(|p|p.conn.close_reason().is_none()).count();
                if announced && !options.policy.adaptive && live==0 {bail!("all paths failed");}
                for (id,config) in configs.iter_mut().enumerate() {
                    if inflight.iter().filter(|busy|**busy).count()>=2 {break;}
                    if inflight[id] {continue;}
                    let path=current.iter().find(|p|usize::from(p.id)==id);
                    let open=path.is_some_and(|p|p.conn.close_reason().is_none());
                    let elective=if options.rotate_source_port && open {
                        let path=path.expect("open path");
                        let q=path.quality.lock().expect("quality lock");
                        let mut estimate=q.snapshot.sender_estimate.clone();
                        // Cross-clock transit drift alone never requests an adaptive rejoin.
                        if options.policy.adaptive {
                            estimate.delay_variation_ms=if q.snapshot.probe_updated_us.is_some_and(|at|quality_time(path).saturating_sub(at)<3_000_000) {
                                (q.snapshot.probe_rtt_ms-path.conn.stats().path.min_rtt.as_secs_f64()*1000.0).max(0.0)
                            } else {0.0};
                        }
                        rotations[id].consider(&estimate,quality_time(path),now_us)
                    } else {false};
                    let recovery=(!config.attempted || options.policy.adaptive)
                        && rotations[id].should_retry(now_us,open);
                    if !elective && !recovery {continue;}
                    let previously_attempted=config.attempted;
                    config.attempted=true;
                    config.generation=config.generation.checked_add(1).context("path generation exhausted")?;
                    let generation=config.generation;
                    let bind=if previously_attempted {config.bind.map(|a|SocketAddr::new(a.ip(),0))}else{config.bind};
                    let config=config.clone();
                    let ca=options.ca.clone();let name=options.name.clone();let token=token.clone();let sid=sid.clone();
                    let policy=options.policy.clone();let metrics=options.stats.clone();let tx=rejoin_tx.clone();
                    let congestion=options.congestion;let rejoin=has_session;
                    let mut cancelled=stop.subscribe();
                    inflight[id]=true;
                    elective_inflight[id]=elective;
                    forward.path(id as u8,|p|{p.reconnect_attempts+=1;if elective{p.rotation_attempts+=1;}});
                    tasks.spawn(async move {
                        let mut diagnostic=stats::ConnectionTrace::new(metrics,config.remote,Some(id as u8),"quic_connect");
                        let attempt:Result<Option<Rejoined>>=async {
                            let endpoint=transport::client_bound(config.remote,&ca,config.interface.as_deref(),congestion,bind)?;
                            info!(path=id,generation,local=%endpoint.local_addr()?,remote=%config.remote,"path attempt source socket");
                            let connected=tokio::select! {
                                biased;
                                _=cancelled.changed()=>{
                                    endpoint.close(0u32.into(),b"connection attempt cancelled");
                                    diagnostic.cancelled();
                                    return Ok(None);
                                },
                                connected=timeout(Duration::from_secs(8),
                                    connect_path(&endpoint,config.remote,&name,&token,&sid,id as u8,config.group,generation,rejoin,&policy,&mut diagnostic))=>connected??
                            };
                            let (conn,stream,driver,request,send)=connected;
                            Ok(Some(Rejoined{endpoint,conn,stream,driver,request,send}))
                        }.await;
                        let attempt=match attempt {
                            Ok(None)=>return,
                            Ok(Some(value))=>Ok((value,diagnostic)),
                            Err(error)=>{diagnostic.finish(Some(&error));Err(error)}
                        };
                        let _=tx.send((id as u8,generation,attempt)).await;
                    });
                }
                if !announced && !options.policy.adaptive && configs.iter().all(|c|c.attempted) && !inflight.iter().any(|v|*v) {
                    ensure!(live>0,"no authenticated paths available");
                    announced=true;
                    options.stats.readiness(true,configs.len());
                    info!(listen=%socket.local_addr()?,paths=live,congestion=?options.congestion,"UDP client ready");
                }
                if now_us.saturating_sub(last_stats)>=2_000_000 {
                    last_stats=now_us;
                    info!(live,configured=configs.len(),originals=decoder.originals,recovered=decoder.recovered,duplicates=decoder.duplicates,invalid=decoder.invalid,drops,"client path status");
                }
            },
            rebuilt=rejoin_rx.recv()=>{
                let Some((pid,generation,rebuild))=rebuilt else {bail!("path supervisor ended")};
                let id=usize::from(pid);inflight[id]=false;
                let now_us=epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                match rebuild {
                    Ok((value,diagnostic))=>{
                        if elective_inflight[id] {rotations[id].rotation_succeeded(now_us);}
                        else {rotations[id].connection_succeeded(now_us);}
                        let replacing=endpoints[id].is_some();
                        options.stats.register(&sid,pid,value.stream,stats::FORWARD,&value.conn);
                        forward.path(pid,|p|{
                            p.local_socket=value.endpoint.local_addr().ok().map(|a|a.to_string());
                            p.reconnect_successes+=1;
                            if elective_inflight[id] {p.rotation_successes+=1;}
                        });
                        {
                            let mut active=paths.lock().expect("paths lock");
                            for old in active.iter().filter(|p|p.id==pid) {old.conn.close(0u32.into(),b"path replaced");}
                            active.retain(|p|p.id!=pid);
                            active.push(OutPath{id:pid,group:configs[id].group,conn:value.conn.clone(),stream:value.stream,
                                quality:Arc::new(Mutex::new(quality::State::new(generation))),epoch:Instant::now(),
                                probe_reply:Arc::new(Mutex::new(None))});
                        }
                        if let Some(old)=endpoints[id].replace(value.endpoint) {old.close(0u32.into(),b"path replaced");}
                        tasks.spawn(drive_client_path(value.conn,value.stream,value.driver,value.request,value.send,diagnostic,pid,
                            wire_tx.clone(),ingress_drops.clone(),returning.clone(),forward.clone(),paths.clone(),options.policy.receiver_feedback));
                        has_session=true;
                        if options.policy.adaptive && !announced {
                            options.stats.readiness(true,configs.len());
                            announced=true;
                            info!(listen=%socket.local_addr()?,paths=paths.lock().expect("paths lock").len(),congestion=?options.congestion,"UDP client ready");
                        }
                        info!(path=pid,generation,replacing,"client path ready");
                    },
                    Err(error)=>{
                        rotations[id].connection_failed(now_us);
                        forward.path(pid,|p|{p.reconnect_failures+=1;if elective_inflight[id]{p.rotation_failures+=1;}});
                        if error.is::<SessionExpired>() {return Err(error);}
                        warn!(path=pid,error=%error,"path attempt failed; bounded retry policy applies");
                    }
                }
            },
            received=socket.recv_from(&mut input)=>{
                let (n,peer)=received?;let created=Instant::now();
                forward.update(|d|d.records.application_received+=1);
                if n>MAX_PAYLOAD {drops+=1;forward.update(|d|d.records.application_oversize_dropped+=1);continue;}
                if !peers.contains_key(&peer) {
                    if peers.len()>=MAX_FLOWS {drops+=1;forward.update(|d|d.records.application_flow_limit_dropped+=1);continue;}
                    next_flow=next_flow.checked_add(1).context("flow id exhausted")?;
                    peers.insert(peer,(next_flow,created));reverse.insert(next_flow,peer);
                }
                let (flow,last)=peers.get_mut(&peer).expect("inserted peer");*last=created;
                next_id=next_id.checked_add(1).context("message id exhausted")?;
                if let Err(error)=tx.try_send(QueuedRecord{record:Record{flow:*flow,id:next_id,payload:input[..n].to_vec()},created}) {
                    drops+=1;queue_error(&forward,QueueLayer::Sender,&error,None);
                } else {forward.update(|d|{d.records.ingress_queue_enqueued+=1;d.records.sender_queue_enqueued+=1;});}
            },
            data=wire_rx.recv()=>{
                let Some((pid,data))=data else {bail!("all receivers ended")};
                for record in receive_records(&mut decoder,&returning,pid,&data) {
                    if let Some(peer)=reverse.get(&record.flow) {
                        if let Some((_,last))=peers.get_mut(peer) {*last=Instant::now();}
                        if socket.try_send_to(&record.payload,*peer).is_err() {
                            drops+=1;returning.update(|d|d.records.udp_target_send_dropped+=1);
                            returning.path(pid,|p|p.udp_target_send_dropped+=1);
                        } else {
                            returning.path(pid,|p|p.udp_target_delivered+=1);
                            returning.update(|d|{d.records.udp_target_delivered+=1;d.records.udp_target_bytes+=record.payload.len() as u64;d.udp_delivered_record_ids.add(record.id);});
                        }
                    } else {returning.update(|d|d.records.udp_target_flow_dropped+=1);returning.path(pid,|p|p.udp_target_flow_dropped+=1);}
                }
            }
        }
        while let Some(completion)=tasks.try_join_next() {completion.context("path task failed")?;}
    }Ok(())}.await;
    let _ = stop.send(true);
    options.stats.readiness(false, configs.len());
    for endpoint in endpoints.iter().flatten() {
        endpoint.close(0u32.into(), b"client session stopped");
    }
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
        s.drain_incomplete |= !joined;
    });
    options.stats.retire_session(&sid);
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
    group: u8,
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
        .header("braidpath-group", u16::from(group))
        .header(
            "braidpath-group-rates",
            policy
                .group_rates
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
        .header("braidpath-latency-ms", policy.latency_target_ms)
        .header("braidpath-fec", u16::from(policy.fec))
        .header("braidpath-redundancy", u16::from(policy.redundancy))
        .header("braidpath-rate", policy.rate)
        .header("braidpath-block-ms", policy.block_ms)
        .header("braidpath-queue-ms", policy.queue_ms);
    if policy.receiver_feedback {
        req = req
            .header("braidpath-feedback", "2")
            .header("braidpath-generation", generation);
    }
    if rejoin {
        req = req.header("braidpath-rejoin", "1");
    }
    if policy.quality_schedule {
        req = req.header(
            "braidpath-scheduler",
            if policy.adaptive {
                "adaptive"
            } else {
                "quality"
            },
        );
    }
    let req = req.body(())?;
    let mut stream = send.send_request(req).await?;
    let response = tokio::select! {e=driver.wait_idle()=>bail!("HTTP/3 closed during admission: {e}"),r=stream.recv_response()=>r?};
    if response.status() == StatusCode::GONE {
        diagnostic.rejected("session_expired");
        conn.close(0u32.into(), b"session epoch expired");
        return Err(SessionExpired.into());
    }
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
                .is_some_and(|v| v == "2"),
        "receiver feedback not negotiated"
    );
    ensure!(
        !policy.quality_schedule
            || response
                .headers()
                .get("braidpath-scheduler")
                .is_some_and(|v| v
                    == if policy.adaptive {
                        "adaptive"
                    } else {
                        "quality"
                    }),
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

#[cfg(test)]
mod sender_ready_tests;

#[cfg(test)]
mod reprobe_tests;

#[cfg(test)]
mod sender_clock_tests {
    use super::*;
    #[test]
    fn originals_keep_individual_ingress_times_and_repair_inherits_oldest() {
        let first = Instant::now();
        let second = first + Duration::from_millis(5);
        let mut encoder = Encoder::new(2, Duration::from_millis(100)).unwrap();
        let mut queue = outbound::Queue::default();
        let mut blocks = BTreeMap::new();
        let metrics = stats::Metrics::new("client").scope("clock-test", stats::FORWARD);
        for (id, created) in [(1, first), (2, second)] {
            let record = Record {
                flow: 1,
                id,
                payload: vec![42],
            };
            for shard in encoder.push(&record.encode().unwrap(), created).unwrap() {
                enqueue_symbol(
                    wire::shard(shard),
                    created,
                    &mut queue,
                    &mut blocks,
                    &metrics,
                );
            }
        }
        let expired = queue.expire(first + Duration::from_millis(20), Duration::from_millis(20));
        assert_eq!(expired.len(), 2);
        assert!(expired.iter().any(|p| p.record_id == Some(1)));
        assert!(expired.iter().any(|p| p.record_id.is_none()));
        let remaining = queue.pop(false).unwrap();
        assert_eq!(remaining.record_id, Some(2));
        assert_eq!(remaining.created, second);
        assert!(queue.is_empty());
    }
}
