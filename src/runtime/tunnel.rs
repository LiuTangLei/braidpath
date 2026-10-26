use super::{
    MAX_PATHS, MAX_PAYLOAD, QUEUE, adaptive, automatic_fec, capacity_probe, forward_guard, mesh,
    outbound, quality, reverse_guard, scheduler,
    sender_frontier::{self, Gate},
    shutdown::Shutdown,
    stats::{self, Scope},
    stream, trace, transport,
    wire::{self, Receiver, Record},
};
#[cfg(test)]
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
    net::{TcpListener, UdpSocket},
    sync::{Notify, Semaphore, mpsc, watch},
    task::JoinSet,
    time::{MissedTickBehavior, interval, timeout},
};
use tracing::{info, warn};

const MAX_FLOWS: usize = 64;
/// Datagrams reliable paths may hand their session before it reads them:
/// about 50 ms of a bulk download. One session task decodes every path, and a
/// shallower queue overflows during a brief stall of that task, turning a
/// local delay into stream retransmissions an RTT later.
const WIRE_QUEUE: usize = 4096;
const SESSION_IDLE_GRACE: Duration = Duration::from_secs(120);
const SESSION_PATH: &str = "/session";
pub(crate) const STREAM_ALPN: &[u8] = b"braidpath-stream/2";
// An authenticated stream/2 owner is discarding this epoch, rather than
// temporarily replacing a transport path. Its remote stream budget can end now.
const STREAM_SESSION_STOP: u32 = 0x4250;
pub(crate) const ADMISSION_TIMEOUT_MS: u64 = 10_000;
mod associate;
mod coding;
#[cfg(test)]
mod dual_tests;
mod ingress;
mod liveness;
mod local_delivery;
pub(crate) mod messages;
#[cfg(test)]
mod mixed_fec_tests;
mod native_probe;
mod path_health;
mod proxy;
#[cfg(test)]
mod repair_usefulness_tests;
mod small_delivery;
pub(crate) mod tcp;
mod writer;
pub use proxy::Access as ProxyAccess;
pub(crate) use proxy::Destination as StreamTarget;
#[doc(hidden)]
pub use tcp::Connector as StreamConnector;

/// Encoded symbols up to this size are latency traffic: stream
/// acknowledgments, keystrokes, DNS and similar small datagrams.
const LATENCY_RECORD_BYTES: usize = 320;
const WEBSITE: &str = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Welcome</title><h1>Welcome</h1><p>This service is online.</p></html>\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub max_message_bytes: usize,
    /// Reliable TCP streams to the server's fixed TCP target.
    pub streams: bool,
    /// Addressed streams from proxy entrances to client-named destinations.
    pub proxy: bool,
    pub adaptive: bool,
    pub capacity_probe_bps: u64,
    pub probe_guided_recovery: bool,
    pub latency_target_ms: u64,
    pub group_rates: [u64; MAX_PATHS],
    pub receiver_feedback: bool,
    pub quality_schedule: bool,
    pub fec: u8,
    pub fec_repairs: u8,
    pub small_fec_bytes: u16,
    pub mixed_fec: bool,
    pub redundancy: u8,
    pub rate: u64,
    pub block_ms: u64,
    pub queue_ms: u64,
}
impl Policy {
    fn flow(&self, flow: u32) -> u32 {
        if self.max_message_bytes > MAX_PAYLOAD {
            flow & !messages::FLAG
        } else {
            flow
        }
    }
    fn split_fec(&self) -> bool {
        self.mixed_fec || self.fec == automatic_fec::AUTO
    }
    fn admission_lifetime(&self) -> Duration {
        Duration::from_millis(if self.adaptive {
            self.queue_ms.min(self.latency_target_ms)
        } else {
            self.queue_ms
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (MAX_PAYLOAD..=super::MAX_MESSAGE).contains(&self.max_message_bytes),
            "max-message-bytes must be 1000..4096"
        );
        ensure!(
            (1..=2).contains(&self.fec_repairs),
            "fec-repairs must be 1 or 2"
        );
        ensure!(
            self.fec_repairs == 1 || (self.mixed_fec && self.fec >= 2),
            "two independent repairs require explicit mixed FEC and at least two bulk records"
        );
        ensure!(
            !self.probe_guided_recovery
                || (self.capacity_probe_bps > 0
                    && self.adaptive
                    && self.fec == 0
                    && self.redundancy == 0),
            "probe-guided recovery requires independent probes and adaptive original-only traffic"
        );
        ensure!(
            self.capacity_probe_bps == 0
                || (self.adaptive && self.fec == 0 && self.capacity_probe_bps <= self.rate / 20),
            "capacity probes require adaptive FEC0 and at most 5% aggregate budget"
        );
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
            (self.fec <= 32 || self.fec == automatic_fec::AUTO) && self.redundancy <= 100,
            "invalid FEC configuration"
        );
        ensure!(
            usize::from(self.small_fec_bytes) <= MAX_PAYLOAD,
            "small-record threshold must be at most 1000 bytes"
        );
        ensure!(
            self.fec != automatic_fec::AUTO
                || (self.receiver_feedback
                    && !self.mixed_fec
                    && self.small_fec_bytes == 0
                    && self.fec_repairs == 1
                    && self.redundancy > 0),
            "automatic FEC requires feedback, positive redundancy budget, one repair, and no small/mixed FEC"
        );
        if self.mixed_fec {
            ensure!(
                self.fec > 0
                    && self.small_fec_bytes > 0
                    && self.redundancy > 0
                    && self.capacity_probe_bps == 0,
                "mixed FEC requires a bulk FEC block, positive bulk redundancy, a small-record threshold, and no capacity probes"
            );
        } else {
            ensure!(
                self.small_fec_bytes == 0
                    || (self.fec == 0 && self.capacity_probe_bps == 0 && self.redundancy == 0),
                "small-record FEC requires FEC0 and redundancy-percent 0 without explicit mixed FEC"
            );
        }
        ensure!(
            (64_000..=super::MAX_RATE_BPS).contains(&self.rate),
            "rate must be 64000..10000000000 bits/s"
        );
        ensure!(
            (1..=100).contains(&self.block_ms) && (1..=1000).contains(&self.queue_ms),
            "invalid deadline"
        );
        Ok(())
    }
}

pub(super) fn parse_fec(value: &str) -> std::result::Result<u8, String> {
    if value == "auto" {
        return Ok(automatic_fec::AUTO);
    }
    value
        .parse::<u8>()
        .ok()
        .filter(|n| *n <= 32)
        .ok_or_else(|| "FEC must be auto or 0..32".to_owned())
}

fn mixed_fec_header(headers: &http::HeaderMap) -> Result<bool> {
    let value = headers
        .get("braidpath-mixed-fec")
        .map(|value| value.to_str())
        .transpose()?;
    ensure!(
        value.is_none_or(|value| value == "1"),
        "unsupported mixed FEC format"
    );
    Ok(value.is_some())
}

fn fec_repairs_header(headers: &http::HeaderMap) -> Result<u8> {
    ensure!(
        headers.get_all("braidpath-fec-repairs").iter().count() <= 1,
        "duplicate independent repair header"
    );
    let value = headers
        .get("braidpath-fec-repairs")
        .map(|v| v.to_str())
        .transpose()?;
    match value {
        None => Ok(1),
        Some("2") => Ok(2),
        _ => anyhow::bail!("unsupported independent repair format"),
    }
}

fn validate_fec_repairs_echo(headers: &http::HeaderMap, expected: u8) -> Result<()> {
    ensure!(
        fec_repairs_header(headers)? == expected,
        "independent FEC repairs not negotiated"
    );
    Ok(())
}

#[derive(Clone)]
struct OutPath {
    id: u8,
    group: u8,
    conn: quinn::Connection,
    /// Moves this path's datagrams into Quinn; the sender never takes the
    /// connection lock itself.
    writer: Arc<writer::Writer>,
    stream: u64,
    quality: Arc<Mutex<quality::State>>,
    capacity_probe: Arc<Mutex<capacity_probe::State>>,
    capacity_probe_enabled: bool,
    epoch: Instant,
    probe_reply: Arc<Mutex<Option<quality::Probe>>>,
}

impl OutPath {
    fn open(&self) -> bool {
        !self.conn.is_closed()
    }
}
type Paths = Arc<Mutex<Vec<OutPath>>>;

fn trace_path(scope: &Scope, stage: trace::Stage, path: trace::PathKey) {
    scope.trace_with(|context, _| {
        let mut event = trace::Event::new(context, stage);
        event.path = Some(path);
        event
    });
}

/// The UDP payload may arrive before a record ID is assigned. Never invent an ID.
fn trace_payload(
    scope: &Scope,
    stage: trace::Stage,
    payload: &[u8],
    reason: Option<trace::Reason>,
) {
    scope.trace_with(|context, capture| {
        let mut event = trace::Event::new(context, stage);
        event.bytes.payload = u32::try_from(payload.len()).ok();
        event.probe = capture.probe_identity(payload);
        event.reason = reason;
        event
    });
}

fn trace_outgoing(
    scope: &Scope,
    stage: trace::Stage,
    pending: &outbound::Pending,
    path: &OutPath,
    http_bytes: usize,
    reason: Option<trace::Reason>,
) {
    scope.trace_with(|context, capture| {
        let mut event = trace::Event::new(context, stage);
        stats::trace_symbol_fields(&mut event, &pending.data, capture);
        event.coding = Some(if pending.data[3] == 2 {
            trace::Coding::Plain
        } else if pending.small {
            trace::Coding::Small
        } else {
            trace::Coding::Ordinary
        });
        event.path = Some(trace::PathKey {
            path_id: path.id,
            generation: path
                .quality
                .lock()
                .expect("quality lock")
                .snapshot
                .generation,
            connection_id: path.conn.stable_id() as u64,
        });
        event.bytes.http_datagram = u32::try_from(http_bytes).ok();
        event.reason = reason;
        event
    });
}

/// Observe the authenticated HTTP DATAGRAM before quality/queue/decoder gates.
/// Control frames retain HTTP byte counts without being called business symbols.
fn trace_http(
    scope: &Scope,
    stage: trace::Stage,
    data: &[u8],
    stream: u64,
    feedback: bool,
    path: trace::PathKey,
    reason: Option<trace::Reason>,
) {
    scope.trace_with(|context, capture| {
        let mut event = trace::Event::new(context, stage);
        if let Ok(payload) = wire::http_payload(data, stream) {
            if !feedback {
                stats::trace_symbol_fields(&mut event, payload, capture);
            } else if (quality::HEADER + wire::HEADER..=quality::MAX_FRAME).contains(&payload.len())
                && payload.starts_with(b"BQ1D")
            {
                stats::trace_symbol_fields(&mut event, &payload[quality::HEADER..], capture);
            }
        }
        event.path = Some(path);
        event.bytes.http_datagram = u32::try_from(data.len()).ok();
        event.reason = reason;
        event
    });
}

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
        let admitted_rate = controllers[id].pacing_bps();
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
    observation_notify: Option<&Notify>,
) -> Result<Option<Bytes>> {
    if !enabled {
        return Ok(Some(Bytes::copy_from_slice(payload)));
    }
    let paths = paths.lock().expect("paths lock");
    if payload.starts_with(b"BQ1C") || payload.starts_with(b"BQ2C") || payload.starts_with(b"BQ3C")
    {
        let (reports, capacity_reports) = if payload.starts_with(b"BQ3C") {
            ensure!(
                paths.iter().all(|p| p.capacity_probe_enabled),
                "capacity probes not negotiated"
            );
            let (business, probes) = capacity_probe::parse_control(payload)?;
            (business, Some(probes))
        } else {
            (quality::parse_control(payload)?, None)
        };
        let mut accepted = false;
        for report in reports {
            if let Some(path) = paths.iter().find(|p| p.id == report.id) {
                let mut q = path.quality.lock().expect("quality lock");
                if q.apply(&report, quality_time(path)).is_err() {
                    q.snapshot.invalid_controls += 1;
                } else {
                    accepted = true;
                }
                let feedback = q.snapshot_at(quality_time(path));
                drop(q);
                scope.path(path.id, |p| p.receiver_feedback = Some(feedback));
                if let Some(probes) = &capacity_reports {
                    let report = probes
                        .iter()
                        .find(|probe| probe.id == path.id)
                        .expect("validated probe membership");
                    let mut state = path.capacity_probe.lock().expect("capacity probe lock");
                    let _ = state.apply(report, quality_time(path));
                    let snapshot = state.snapshot(quality_time(path));
                    scope.path(path.id, |p| p.capacity_probe = Some(snapshot));
                }
            }
        }
        drop(paths);
        if accepted && let Some(notify) = observation_notify {
            notify.notify_one();
        }
        return Ok(None);
    }
    let path = paths
        .iter()
        .find(|p| p.id == pid)
        .context("missing measurement path")?;
    if payload.starts_with(b"BQ3D") {
        ensure!(
            path.capacity_probe_enabled,
            "capacity probes not negotiated"
        );
        let mut state = path.capacity_probe.lock().expect("capacity probe lock");
        state.receive(payload, quality_time(path))?;
        let snapshot = state.snapshot(quality_time(path));
        scope.path(pid, |p| p.capacity_probe = Some(snapshot));
        return Ok(None);
    }
    let mut q = path.quality.lock().expect("quality lock");
    if payload.starts_with(b"BQ2P") || payload.starts_with(b"BQ2R") {
        let probe = quality::parse_probe(payload)?;
        let accepted_reply = probe.response;
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
        drop(paths);
        if accepted_reply && let Some(notify) = observation_notify {
            notify.notify_one();
        }
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
    /// Reliable-stream backpressure; released with the queued original.
    hold: Option<Arc<outbound::Hold>>,
}

#[derive(Clone)]
struct BlockSend {
    created: Instant,
    paths: u8,
    /// Only permanent original queue rejections, never pending/in-flight loss.
    /// Forgetting metadata loses evidence conservatively; it cannot add bits.
    locally_rejected_originals: u32,
    small_repair_limit: usize,
    small_repair_reserved: usize,
    /// The block's original is a reliable-stream acknowledgment.
    acknowledgment: bool,
}

fn repair_locally_unrecoverable(
    policy: Option<&Policy>,
    data: &[u8],
    small: bool,
    meta: Option<&BlockSend>,
) -> bool {
    if small
        || !policy.is_some_and(|p| p.mixed_fec && p.fec_repairs == 2)
        || data.len() < wire::HEADER
        || !matches!(data[3], 1 | 3)
        || !(1..=32).contains(&data[12])
    {
        return false;
    }
    let count = u32::from(data[12]);
    let mask = u32::MAX >> (32 - count);
    meta.is_some_and(|m| (m.locally_rejected_originals & mask).count_ones() > 2)
}

#[cfg(test)]
fn enqueue_symbol(
    data: Bytes,
    created: Instant,
    queue: &mut outbound::Queue,
    blocks: &mut BTreeMap<u64, BlockSend>,
    metrics: &Scope,
) {
    enqueue_coded_symbol(
        coding::EncodedSymbol {
            data,
            small: false,
            oldest_ingress: None,
        },
        created,
        queue,
        blocks,
        None,
        metrics,
        &mut None,
    );
}

fn enqueue_encoded(
    symbol: coding::EncodedSymbol,
    created: Instant,
    queue: &mut outbound::Queue,
    blocks: &mut BTreeMap<u64, BlockSend>,
    policy: &Policy,
    metrics: &Scope,
) {
    enqueue_coded_symbol(
        symbol,
        created,
        queue,
        blocks,
        Some(policy),
        metrics,
        &mut None,
    );
}

fn encode_input(
    input: QueuedRecord,
    encoder: &mut coding::RecordEncoder,
    policy: &Policy,
    queue: &mut outbound::Queue,
    blocks: &mut BTreeMap<u64, BlockSend>,
    metrics: &Scope,
) {
    let QueuedRecord {
        record,
        created,
        mut hold,
    } = input;
    if created.elapsed() >= policy.admission_lifetime() {
        metrics.trace_record(
            trace::Stage::RecordDropped,
            &record,
            None,
            Some(trace::Reason::Expired),
        );
        metrics.update(|d| {
            d.symbols.originals_ingress_expired_dropped += 1;
            d.locally_dropped_original_ids.add(record.id);
            d.symbols.expiry_wait.add(created.elapsed());
        });
        return;
    }
    let attempt = hold.as_ref().map_or(1, |h| h.transmission());
    match encoder.encode_attempt_ingress(&record, Instant::now(), attempt, created) {
        Ok(symbols) => {
            for symbol in symbols {
                enqueue_coded_symbol(
                    symbol,
                    created,
                    queue,
                    blocks,
                    Some(policy),
                    metrics,
                    &mut hold,
                );
            }
        }
        Err(_) => {
            metrics.trace_record(
                trace::Stage::RecordDropped,
                &record,
                None,
                Some(trace::Reason::Encoding),
            );
            metrics.update(|d| d.records.encoding_dropped += 1);
        }
    }
}

fn enqueue_coded_symbol(
    symbol: coding::EncodedSymbol,
    created: Instant,
    queue: &mut outbound::Queue,
    blocks: &mut BTreeMap<u64, BlockSend>,
    policy: Option<&Policy>,
    metrics: &Scope,
    hold: &mut Option<Arc<outbound::Hold>>,
) {
    let coding::EncodedSymbol {
        data,
        small,
        oldest_ingress,
    } = symbol;
    let mixed = policy.is_some_and(Policy::split_fec);
    let small_repair_limit = if mixed && small && data[3] == 1 {
        // The repair can use another HTTP request stream. Reserve against the
        // largest legal mapping, not the original's actual stream-id width.
        data.len()
            + if policy.is_some_and(|p| p.receiver_feedback) {
                quality::HEADER
            } else {
                0
            }
            + 9
    } else {
        0
    };
    let record = if matches!(data[3], 0 | 2) {
        Record::decode_identity(&data[wire::HEADER..]).ok()
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
    let oldest = oldest_ingress.map_or(created, |ingress| ingress.min(created));
    let block_created = if let Some(block) = block {
        blocks
            .entry(block)
            .or_insert(BlockSend {
                created: oldest,
                paths: 0,
                locally_rejected_originals: 0,
                small_repair_limit: 0,
                small_repair_reserved: 0,
                acknowledgment: false,
            })
            .created
            .min(oldest)
    } else {
        created
    };
    if let Some(block) = block {
        blocks.get_mut(&block).expect("block inserted").created = block_created;
    }
    let record_id = record.map(|(_, id)| id);
    // An original keeps its own ingress clock; a repair expires with the oldest
    // original it could help, so encoder waiting never grants extra repair time.
    let created = if record_id.is_some() {
        created
    } else {
        block_created
    };
    let flow = record.map(|(flow, _)| policy.map_or(flow, |p| p.flow(flow)));
    if let Some(block) = block
        && flow.is_some_and(stream::is_ack_flow)
    {
        blocks
            .get_mut(&block)
            .expect("block inserted")
            .acknowledgment = true;
    }
    metrics.update(|d| {
        if let Some(id) = record_id {
            d.symbols.originals_generated += 1;
            d.generated_record_ids.add(id);
        } else {
            d.symbols.repairs_generated += 1;
        }
        if mixed {
            match (small, record_id.is_some()) {
                (true, true) => d.symbols.mixed_small_originals_generated += 1,
                (true, false) => d.symbols.mixed_small_repairs_generated += 1,
                (false, true) => d.symbols.mixed_bulk_originals_generated += 1,
                (false, false) => d.symbols.mixed_bulk_repairs_generated += 1,
            }
        }
    });
    let mut generated_event = None;
    metrics.trace_with(|context, capture| {
        let mut event = trace::Event::new(context, trace::Stage::SymbolGenerated);
        stats::trace_symbol_fields(&mut event, &data, capture);
        event.coding = Some(if data[3] == 2 {
            trace::Coding::Plain
        } else if small {
            trace::Coding::Small
        } else {
            trace::Coding::Ordinary
        });
        generated_event = Some(event);
        event
    });
    let locally_unrecoverable =
        repair_locally_unrecoverable(policy, &data, small, block.and_then(|b| blocks.get(&b)));
    let skipped = locally_unrecoverable && metrics.metrics.repair_usefulness_guard();
    let encoded_bytes = data.len() as u64;
    let original_index = (data[3] == 0 && !small && mixed).then_some(u32::from(data[12]));
    if locally_unrecoverable {
        metrics.update(|d| {
            d.symbols.repairs_locally_unrecoverable += 1;
            d.symbols.repairs_locally_unrecoverable_bytes += encoded_bytes;
        });
    }
    let pending = outbound::Pending {
        data,
        created,
        record_id,
        flow,
        block,
        small,
        hold: if record_id.is_some() {
            hold.take()
        } else {
            None
        },
    };
    let accepted = !skipped && queue.push(pending).is_ok();
    if !accepted
        && !skipped
        && let Some(bit) = original_index.and_then(|index| 1u32.checked_shl(index))
        && let Some(meta) = block.and_then(|b| blocks.get_mut(&b))
    {
        meta.locally_rejected_originals |= bit;
    }
    if let Some(mut event) = generated_event {
        event.stage = if accepted {
            trace::Stage::SymbolQueued
        } else {
            trace::Stage::SymbolDropped
        };
        event.reason = if skipped {
            Some(trace::Reason::LocallyUnrecoverable)
        } else {
            (!accepted).then_some(trace::Reason::QueueFull)
        };
        metrics.metrics.trace().emit(event);
    }
    if accepted
        && small_repair_limit > 0
        && let Some(meta) = block.and_then(|block| blocks.get_mut(&block))
    {
        meta.small_repair_limit += small_repair_limit;
    }
    metrics.update(|d| {
        if skipped {
            d.symbols.repairs_locally_unrecoverable_skipped += 1;
            d.symbols.repairs_locally_unrecoverable_skipped_bytes += encoded_bytes;
        } else {
            match (record_id, accepted) {
                (Some(_), true) => d.symbols.originals_enqueued += 1,
                (None, true) => d.symbols.repairs_enqueued += 1,
                (Some(id), false) => {
                    d.symbols.originals_queue_full_dropped += 1;
                    d.locally_dropped_original_ids.add(id);
                }
                (None, false) => d.symbols.repairs_queue_full_dropped += 1,
            }
        }
    });
    while blocks.len() > QUEUE * 2 {
        blocks.pop_first();
    }
}

// The pre-mixed encoder remains an independent byte-compatibility reference.
#[cfg(test)]
fn encode_record(
    record: &Record,
    encoder: &mut Encoder,
    policy: &Policy,
    now: Instant,
) -> Result<Vec<Bytes>> {
    if policy.fec == 0
        && (policy.small_fec_bytes == 0
            || record.payload.len() > usize::from(policy.small_fec_bytes))
    {
        Ok(vec![wire::plain(record)?])
    } else {
        Ok(encoder
            .push(&record.encode()?, now)?
            .into_iter()
            .map(wire::shard)
            .collect())
    }
}

fn account_expired(pending: &outbound::Pending, now: Instant, metrics: &Scope) {
    metrics.trace_symbol(
        trace::Stage::SymbolDropped,
        &pending.data,
        None,
        None,
        Some(trace::Reason::Expired),
    );
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

fn repair_allowed(
    policy: &Policy,
    budget: &outbound::RepairBudget,
    blocks: &BTreeMap<u64, BlockSend>,
    pending: &outbound::Pending,
    frame_bytes: usize,
) -> bool {
    if small_delivery::applies(policy, pending) {
        // Independent k=1 blocks create exactly one queued copy. Its original
        // must have actually entered Quinn; expiry/generation grants no credit.
        pending
            .block
            .and_then(|block| blocks.get(&block))
            .is_some_and(|meta| {
                meta.paths != 0
                    && (!policy.split_fec() || meta.small_repair_reserved >= frame_bytes)
                    && budget.small_can_repair(frame_bytes + small_copy_reserve(meta))
            })
    } else {
        budget.can_repair(frame_bytes)
    }
}

/// A bulk download acknowledges continuously: its acknowledgment copies alone
/// can exhaust the small-copy rate, and each is superseded by the next one.
/// They spend only credit above one datagram, which stays available for the
/// first records of new and interactive streams.
fn small_copy_reserve(meta: &BlockSend) -> usize {
    if meta.acknowledgment { 1200 } else { 0 }
}

fn repair_frame_floor(policy: &Policy, pending: &outbound::Pending) -> usize {
    pending.data.len()
        + if policy.receiver_feedback {
            quality::HEADER
        } else {
            0
        }
        + 2
}

fn account_budget_skipped(policy: &Policy, pending: &outbound::Pending, metrics: &Scope) {
    metrics.trace_symbol(
        trace::Stage::SymbolDropped,
        &pending.data,
        None,
        None,
        Some(trace::Reason::Budget),
    );
    metrics.update(|d| {
        d.symbols.repairs_budget_skipped += 1;
        if policy.split_fec() && !pending.small {
            d.symbols.mixed_bulk_repairs_budget_skipped += 1;
            // No path/HTTP stream was selected. This is encoded wire length,
            // not hypothetical HTTP framing or admitted traffic.
            d.symbols.mixed_bulk_repair_budget_skipped_bytes += pending.data.len() as u64;
        }
    });
}

/// Charge only actual Quinn admissions. The mixed small allowance belongs to
/// one admitted k=1 original; bulk credit never borrows that allowance.
fn budget_admitted(
    policy: &Policy,
    budget: &mut outbound::RepairBudget,
    blocks: &mut BTreeMap<u64, BlockSend>,
    pending: &outbound::Pending,
    frame_bytes: usize,
    metrics: &Scope,
) {
    let repair = pending.record_id.is_none();
    if !policy.split_fec() {
        if repair {
            if policy.small_fec_bytes == 0 {
                budget.repair_admitted(frame_bytes);
            }
        } else {
            budget.original_admitted(frame_bytes);
        }
        return;
    }
    if pending.small {
        let meta = pending.block.and_then(|block| blocks.get_mut(&block));
        if repair {
            let meta = meta.expect("admitted small repair block");
            assert!(meta.paths != 0 && meta.small_repair_reserved >= frame_bytes);
            meta.small_repair_reserved -= frame_bytes;
            budget.small_repair_admitted(frame_bytes);
            metrics.update(|d| {
                d.symbols.mixed_small_repair_admitted_bytes += frame_bytes as u64;
                d.symbols.mixed_small_repairs_quinn_admitted += 1;
            });
        } else if let Some(meta) = meta {
            // The repair is generated and queued in the same encoder event.
            // Queue rejection creates no authorization, nor does mere ingress.
            debug_assert_eq!(meta.small_repair_reserved, 0);
            meta.small_repair_reserved = meta.small_repair_limit;
            metrics.update(|d| {
                d.symbols.mixed_small_repair_reserved_bytes += meta.small_repair_limit as u64;
            });
        }
    } else if repair {
        budget.repair_admitted(frame_bytes);
        metrics.update(|d| {
            d.symbols.mixed_bulk_repair_admitted_bytes += frame_bytes as u64;
            d.symbols.mixed_bulk_repairs_quinn_admitted += 1;
        });
    } else {
        budget.original_admitted(frame_bytes);
        metrics.update(|d| d.symbols.mixed_bulk_original_admitted_bytes += frame_bytes as u64);
    }
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

impl PreparedSend {
    fn small_delivery_allowed(
        &self,
        policy: &Policy,
        paths: &[OutPath],
        controllers: &mut [adaptive::PathController; MAX_PATHS],
        now_us: u64,
        age: Duration,
    ) -> bool {
        if !small_delivery::applies(policy, &self.front) {
            return true;
        }
        let candidates: Vec<_> = paths
            .iter()
            .filter(|path| {
                path.open()
                    && (!policy.adaptive || controllers[usize::from(path.id)].eligible(now_us))
            })
            .map(|path| (path.id, 1))
            .collect();
        // Match the main drain's current packet cost and age. An eligible fast
        // peer without business credit must not invalidate a writable peer.
        let candidates = if policy.adaptive {
            business_ready_candidates(
                &candidates,
                paths,
                controllers,
                now_us,
                self.front.data.len()
                    + if policy.receiver_feedback {
                        quality::HEADER
                    } else {
                        0
                    },
                age.as_secs_f64() * 1000.0,
                None,
            )
        } else {
            candidates
        };
        let eligible = candidates.iter().fold(0, |mask, (id, _)| mask | (1 << id));
        let timely = small_delivery::mask(
            paths,
            eligible,
            policy.admission_lifetime().saturating_sub(age),
            policy.latency_target_ms,
            if self.repair && policy.fec == automatic_fec::AUTO {
                self.used
            } else {
                0
            },
        );
        timely & (1 << self.path.id) != 0
            && (!self.repair || small_delivery::copy_ready(&self.path, self.used))
    }
}

struct WaitingSend {
    prepared: PreparedSend,
    admitted: Pin<Box<dyn Future<Output = ()> + Send>>,
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
        let writer = prepared.path.writer.clone();
        let bytes = prepared.data.len();
        Self {
            prepared,
            // Waiting queues nothing: dropping it cancels without any debit.
            admitted: Box::pin(async move { writer.admitted(bytes).await }),
        }
    }

    fn poll(
        &mut self,
        cx: &mut TaskContext<'_>,
        shared_paths: &Paths,
        lifetime: Duration,
        mut allowed: impl FnMut(&PreparedSend, Instant, &[OutPath]) -> bool,
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
        if !paths[index].open() {
            return Poll::Ready(SendReadiness::PathChanged);
        }
        // Take the clock after acquiring the membership locks, immediately
        // before polling Quinn. A ready buffer must never revive an old record.
        let now = Instant::now();
        if now.saturating_duration_since(self.prepared.front.created) >= lifetime {
            return Poll::Ready(SendReadiness::Expired);
        }
        if !allowed(&self.prepared, now, &paths) {
            return Poll::Ready(SendReadiness::GateChanged);
        }
        // Control checks can take time. Refresh after them, immediately
        // before the path's writer gets ownership of this datagram.
        if admission_now().saturating_duration_since(self.prepared.front.created) >= lifetime {
            return Poll::Ready(SendReadiness::Expired);
        }
        if self.admitted.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        if self.prepared.path.writer.send(self.prepared.data.clone()) {
            Poll::Ready(SendReadiness::Admitted {
                at: Instant::now(),
                next_cursor: (index + 1) % paths.len(),
            })
        } else {
            Poll::Ready(SendReadiness::Failed)
        }
        // The membership guard is local to this synchronous poll. No mutex
        // guard survives Pending or is held while the sender awaits a wakeup.
    }

    fn cancel(self) -> PreparedSend {
        let Self { prepared, admitted } = self;
        drop(admitted);
        prepared
    }
}

enum SenderEvent {
    Stop,
    Evidence,
    Tick,
    Input(Option<QueuedRecord>),
    Ready(SendReadiness),
}

fn send_datagram_before_deadline(
    path: &OutPath,
    data: Bytes,
    created: Instant,
    lifetime: Duration,
) -> Option<std::result::Result<Instant, ()>> {
    // Preparation can outlive the queue-head preflight.
    if admission_now().saturating_duration_since(created) >= lifetime {
        return None;
    }
    Some(path.writer.send(data).then(Instant::now).ok_or(()))
}

fn admission_now() -> Instant {
    #[cfg(test)]
    if let Some(now) = ADMISSION_CLOCK_FIXED.with(|clock| clock.get()) {
        return now;
    }
    #[cfg(test)]
    if let Some(now) = ADMISSION_CLOCK_OVERRIDE.with(|clock| clock.take()) {
        return now;
    }
    Instant::now()
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

fn update_business_pacer(
    business: &mut Option<outbound::BusinessPacer>,
    paths: &[OutPath],
    controllers: &[adaptive::PathController; MAX_PATHS],
    now_us: u64,
) {
    if let Some(business) = business {
        business.update(
            now_us,
            paths.iter().filter_map(|path| {
                if !path.open() {
                    return None;
                }
                let controller = &controllers[usize::from(path.id)];
                controller
                    .eligible(now_us)
                    .then_some((path.group, controller.pacing_bps()))
            }),
        );
    }
}

fn latency_candidates(
    mut candidates: Vec<(u8, i32)>,
    paths: &[OutPath],
    front: &outbound::Pending,
    repair: bool,
    policy: &Policy,
    age: Duration,
) -> Vec<(u8, i32)> {
    if !policy.adaptive
        || repair
        || small_delivery::applies(policy, front)
        || front
            .flow
            .is_none_or(|flow| stream::stream_id(flow).is_none())
        || front.data.len() > LATENCY_RECORD_BYTES
    {
        return candidates;
    }
    // Rank healthy paths before checking transient packet credit. A token gap
    // on an idle route must not send an interactive record into a long queue.
    // An unready head rotates normally, so other flows keep making progress.
    let eligible = candidates.iter().fold(0, |mask, (id, _)| mask | (1 << id));
    let timely = small_delivery::latency_mask(
        paths,
        eligible,
        policy.admission_lifetime().saturating_sub(age),
        policy.latency_target_ms,
    );
    candidates.retain(|(id, _)| timely & (1 << id) != 0);
    candidates
}

fn business_ready_candidates(
    candidates: &[(u8, i32)],
    paths: &[OutPath],
    controllers: &mut [adaptive::PathController; MAX_PATHS],
    now_us: u64,
    measured_payload_bytes: usize,
    queue_age_ms: f64,
    admitted: Option<u8>,
) -> Vec<(u8, i32)> {
    scheduler::ready_candidates(candidates, |id| {
        // The accepted path is charged even if a gate changes after admission.
        if admitted == Some(id) {
            return true;
        }
        let Some(path) = paths.iter().find(|path| path.id == id) else {
            return false;
        };
        // Mapping size depends on the actual stream ID, not on the payload.
        let Ok(mapping_bytes) = wire::http_datagram_overhead(path.stream) else {
            return false;
        };
        controllers[usize::from(id)].allow(
            now_us,
            measured_payload_bytes + mapping_bytes + 80,
            queue_age_ms,
        )
    })
}

fn transport_ready_candidates(
    candidates: &[(u8, i32)],
    paths: &[OutPath],
    measured_payload_bytes: usize,
    admitted: u8,
) -> Vec<(u8, i32)> {
    scheduler::ready_candidates(candidates, |id| {
        // Admission itself may have filled this path's buffer. It still pays.
        if id == admitted {
            return true;
        }
        let Some(path) = paths.iter().find(|path| path.id == id) else {
            return false;
        };
        let Ok(mapping_bytes) = wire::http_datagram_overhead(path.stream) else {
            return false;
        };
        let bytes = measured_payload_bytes + mapping_bytes;
        path.open()
            && path
                .conn
                .max_datagram_size_hint()
                .is_some_and(|max| bytes <= max)
            && path.writer.admits(bytes)
    })
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
    business: &'a mut Option<outbound::BusinessPacer>,
    paths: &'a [OutPath],
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
        if let Some(hold) = &sent.hold {
            hold.admitted(path.id, path.conn.rtt_hint(), at);
        }
        debug_assert_eq!(sent.created, front.created);
        debug_assert_eq!(sent.record_id, front.record_id);
        debug_assert_eq!(sent.block, front.block);
        debug_assert_eq!(sent.data, front.data);
        debug_assert_eq!(sent.small, front.small);
        trace_outgoing(
            self.metrics,
            trace::Stage::QuinnApiAdmitted,
            &sent,
            path,
            frame_bytes,
            None,
        );
        let cost = frame_bytes + 80;
        let now_us = at
            .saturating_duration_since(self.epoch)
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        // Recheck at actual admission, including Quinn's readiness-wait path.
        let measured_payload_bytes = front.data.len()
            + if self.policy.receiver_feedback {
                quality::HEADER
            } else {
                0
            };
        let ready_candidates = if self.policy.adaptive {
            let business_candidates = business_ready_candidates(
                candidates,
                self.paths,
                self.controllers,
                now_us,
                measured_payload_bytes,
                at.saturating_duration_since(front.created).as_secs_f64() * 1000.0,
                Some(path.id),
            );
            // Business credit does not make a full Quinn buffer ready. Filter
            // only settled service debt; send order still retains blocked paths
            // for readiness waits, and both filters preserve actual admission.
            Some(transport_ready_candidates(
                &business_candidates,
                self.paths,
                measured_payload_bytes,
                path.id,
            ))
        } else if self.policy.quality_schedule {
            Some(transport_ready_candidates(
                candidates,
                self.paths,
                measured_payload_bytes,
                path.id,
            ))
        } else {
            None
        };
        self.pacer.spend(cost);
        self.groups[usize::from(path.group)].spend(cost);
        if let Some(business) = self.business.as_mut() {
            business.spend(path.group, cost);
        }
        if self.policy.quality_schedule {
            self.scheduler.commit(
                ready_candidates.as_deref().unwrap_or(candidates),
                path.id,
                frame_bytes,
            );
        }
        if self.policy.adaptive {
            self.controllers[usize::from(path.id)].admitted_symbol(now_us, cost, sent.data.len());
            update_business_pacer(self.business, self.paths, self.controllers, now_us);
        }
        if self.policy.receiver_feedback {
            path.quality
                .lock()
                .expect("quality lock")
                .admitted(sent.data.len());
        }
        budget_admitted(
            self.policy,
            self.budget,
            self.blocks,
            &sent,
            frame_bytes,
            self.metrics,
        );
        if repair {
            self.metrics.path(path.id, |p| {
                p.quinn_admitted_repairs += 1;
                if small_delivery::applies(self.policy, front) {
                    p.quinn_admitted_small_repairs += 1;
                }
            });
            if used & (1 << path.id) != 0 {
                self.metrics
                    .update(|d| d.symbols.repair_no_diverse_path += 1);
            }
            if let Some(block) = sent.block {
                if self.queue.repair_pending(block) {
                    if let Some(meta) = self.blocks.get_mut(&block) {
                        meta.paths |= 1 << path.id;
                    }
                } else {
                    self.blocks.remove(&block);
                }
            }
        } else {
            self.metrics.path(path.id, |p| {
                p.quinn_admitted_originals += 1;
                if small_delivery::applies(self.policy, front) {
                    p.quinn_admitted_small_originals += 1;
                }
            });
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

#[cfg(test)]
thread_local! {
    static QUALITY_STATS_PUBLICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static ADMISSION_CLOCK_OVERRIDE: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
    static ADMISSION_CLOCK_FIXED: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

fn publish_receiver_feedback(paths: &[OutPath], metrics: &Scope) {
    for path in paths {
        let feedback = path
            .quality
            .lock()
            .expect("quality lock")
            .snapshot_at(quality_time(path));
        metrics.path(path.id, |p| p.receiver_feedback = Some(feedback));
        #[cfg(test)]
        QUALITY_STATS_PUBLICATIONS.with(|count| count.set(count.get() + 1));
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
    observation_notify: Option<Arc<Notify>>,
) {
    let mut encoder = coding::RecordEncoder::new(&policy).expect("validated policy");
    let mut fec_control =
        (policy.fec == automatic_fec::AUTO).then(automatic_fec::Controller::default);
    let mut frontier = sender_frontier::Snapshot {
        enabled: metrics.metrics.frontier_scheduler()
            && policy.adaptive
            && policy.small_fec_bytes > 0,
        ..Default::default()
    };
    let mut queue = outbound::Queue::default();
    let mut blocks = BTreeMap::<u64, BlockSend>::new();
    let mut budget = outbound::RepairBudget::new(policy.redundancy);
    if policy.fec == automatic_fec::AUTO {
        budget.enable_small_rate((policy.rate / 4).min(1_000_000));
    }
    let mut scheduler = scheduler::Scheduler::default();
    let mut controllers: [adaptive::PathController; MAX_PATHS] = std::array::from_fn(|_| {
        adaptive::PathController::new(policy.rate, policy.latency_target_ms)
            .with_rtt_source_baselines(metrics.metrics.rtt_source_baselines())
            .with_random_loss_service(metrics.metrics.random_loss_service())
            .with_queue_gated_loss(metrics.metrics.queue_gated_loss())
            .with_legacy_recovery(metrics.metrics.legacy_recovery())
    });
    let mut native_probes: [native_probe::Pause; MAX_PATHS] = Default::default();
    let mut logged_rate_changes = [0u64; MAX_PATHS];
    let reliable_native_service =
        (policy.streams || policy.proxy) && !metrics.metrics.legacy_recovery();
    let burst = if policy.adaptive { 2400 } else { 9600 };
    let mut pacer = outbound::Pacer::for_sender(policy.rate, burst);
    let mut groups: [outbound::Pacer; MAX_PATHS] =
        std::array::from_fn(|i| outbound::Pacer::for_sender(policy.group_rates[i], burst));
    let mut business = policy
        .adaptive
        .then(|| outbound::BusinessPacer::new(policy.rate, policy.group_rates, burst));
    let epoch = Instant::now();
    let mut cursor = 0usize;
    let mut control_cursor = 0usize;
    let mut reprobe_cursor = 0usize;
    let mut capacity_cursor = 0usize;
    let mut capacity_pacing: [capacity_probe::Controller; MAX_PATHS] =
        std::array::from_fn(|_| capacity_probe::Controller::new(0));
    let mut capacity_budget =
        capacity_probe::Budget::new(policy.capacity_probe_bps, policy.group_rates);
    let mut feedback_schedule = quality::FeedbackSchedule::default();
    let mut pending_feedback: Option<(Bytes, quality::ReportKind)> = None;
    let mut observation_schedule = policy.adaptive.then(outbound::ObservationSchedule::default);
    let mut reverse_guard =
        (policy.adaptive && !metrics.metrics.legacy_recovery()).then(reverse_guard::Guard::default);
    let mut forward_guard =
        (policy.adaptive && !metrics.metrics.legacy_recovery()).then(forward_guard::Guard::default);
    let mut repair_turn = false;
    let mut tick = interval(Duration::from_millis(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let lifetime = policy.admission_lifetime();
    let mut waiting: Option<WaitingSend> = None;
    let mut liveness: [liveness::Liveness; MAX_PATHS] = Default::default();
    loop {
        #[cfg(test)]
        sender_ready_tests::hold_deferred_expiry(
            waiting
                .as_ref()
                .is_some_and(|wait| wait.prepared.front.record_id == Some(64)),
        )
        .await;
        if *stop.borrow() {
            break;
        }
        let event = tokio::select! {
            biased;
            _=stop.changed()=>SenderEvent::Stop,
            _=async { observation_notify.as_ref().expect("adaptive observation notify").notified().await },
                if policy.adaptive && observation_notify.is_some()=>SenderEvent::Evidence,
            _=tick.tick()=>SenderEvent::Tick,
            ready=poll_fn(|cx| {
                let Some(wait) = waiting.as_mut() else {
                    return Poll::Pending;
                };
                wait.poll(cx, &shared_paths, lifetime, |attempt, now, paths| {
                    let cost = attempt.data.len() + 80;
                    let now_us = now.saturating_duration_since(epoch).as_micros()
                        .min(u128::from(u64::MAX)) as u64;
                    let age = now.saturating_duration_since(attempt.front.created);
                    if !pacer.available(cost + attempt.feedback_reserve)
                        || !groups[usize::from(attempt.path.group)]
                            .available(cost + attempt.group_reserve)
                        || (attempt.repair && !repair_allowed(&policy, &budget, &blocks, &attempt.front, attempt.data.len()))
                    {
                        return false;
                    }
                    if !attempt.small_delivery_allowed(&policy, paths, &mut controllers, now_us, age) {
                        return false;
                    }
                    if !policy.adaptive {
                        return true;
                    }
                    let allowed = controllers[usize::from(attempt.path.id)]
                        .allow(now_us, cost, age.as_secs_f64() * 1000.0);
                    update_business_pacer(&mut business, paths, &controllers, now_us);
                    allowed && business.as_ref().expect("adaptive business pacer")
                        .available(attempt.path.group, cost)
                })
            }), if waiting.is_some()=>SenderEvent::Ready(ready),
            item=input.recv()=>SenderEvent::Input(item),
        };
        // A different actor event invalidates this prepared queue head and its
        // budget checks. Cancel the future before touching any actor state.
        let prepared = waiting.take().map(WaitingSend::cancel);
        // Only this already-owned Input may defer until existing service has a
        // chance to free its slot. It never survives the current actor turn.
        let mut deferred_input = None;
        // Counters live in path.quality; these clones are only JSON observability.
        // Publish on the existing timer/evidence events, not every packet event.
        let publish_feedback_stats = matches!(&event, SenderEvent::Tick | SenderEvent::Evidence);
        match event {
            SenderEvent::Stop => break,
            SenderEvent::Evidence => {
                observation_schedule
                    .as_mut()
                    .expect("adaptive observation schedule")
                    .evidence_received();
            }
            SenderEvent::Tick => {
                let now = Instant::now();
                if policy.fec > 0 {
                    match encoder.flush_due(now) {
                        Ok(symbols) => {
                            for symbol in symbols {
                                enqueue_encoded(
                                    symbol,
                                    now,
                                    &mut queue,
                                    &mut blocks,
                                    &policy,
                                    &metrics,
                                );
                            }
                        }
                        Err(_) => metrics.update(|d| d.records.encoding_dropped += 1),
                    }
                }
            }
            SenderEvent::Ready(SendReadiness::Admitted { at, next_cursor }) => {
                frontier.readiness_admitted += 1;
                let attempt = prepared.expect("selected readiness attempt");
                let paths = shared_paths.lock().expect("paths lock");
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
                    business: &mut business,
                    paths: &paths,
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
                frontier.readiness_failed += 1;
                let attempt = prepared.expect("selected readiness attempt");
                trace_outgoing(
                    &metrics,
                    trace::Stage::QuinnApiRejected,
                    &attempt.front,
                    &attempt.path,
                    attempt.data.len(),
                    Some(trace::Reason::QuinnError),
                );
                metrics.path(attempt.path.id, |p| p.quinn_send_error_attempts += 1);
            }
            SenderEvent::Ready(_) => {
                frontier.readiness_gate_changed += 1;
            }
            SenderEvent::Input(item) => {
                #[cfg(test)]
                sender_ready_tests::prime_full_input_turn(
                    &mut queue,
                    &mut blocks,
                    &metrics,
                    &mut pacer,
                    &mut groups,
                );
                let Some(QueuedRecord {
                    record,
                    created,
                    hold,
                }) = item
                else {
                    break;
                };
                metrics.update(|d| d.records.sender_input_consumed += 1);
                metrics.trace_record(trace::Stage::SenderInput, &record, None, None);
                if created.elapsed() < lifetime && queue.would_be_full(policy.flow(record.flow)) {
                    deferred_input = Some(QueuedRecord {
                        record,
                        created,
                        hold,
                    });
                } else {
                    encode_input(
                        QueuedRecord {
                            record,
                            created,
                            hold,
                        },
                        &mut encoder,
                        &policy,
                        &mut queue,
                        &mut blocks,
                        &metrics,
                    );
                }
            }
        }
        let now = Instant::now();
        let now_us = epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        pacer.refill(now_us);
        budget.refill_small(now_us);
        for group in &mut groups {
            group.refill(now_us);
        }
        for expired in queue.expire(now, lifetime) {
            account_expired(&expired, now, &metrics);
        }
        let paths = shared_paths.lock().expect("paths lock");
        // Paths that stopped acknowledging carry no data, unless every open
        // path has: then nothing is gained by withholding it.
        let silent = {
            let (mut open, mut silent) = (0u8, 0u8);
            for path in paths.iter().filter(|p| p.open()) {
                let id = usize::from(path.id);
                liveness[id].observe(&path.conn, now);
                open |= 1 << id;
                silent |= u8::from(liveness[id].silent()) << id;
            }
            if silent == open { 0 } else { silent }
        };
        for path in paths.iter() {
            path.writer.set_pace(if policy.adaptive {
                controllers[usize::from(path.id)].pacing_bps()
            } else {
                policy.rate
            });
        }
        if observation_schedule
            .as_mut()
            .and_then(|schedule| schedule.take_due(now_us))
            .is_some()
        {
            let bulk_backlog = queue.has_bulk_stream_data();
            for path in paths.iter() {
                let q = path.quality.lock().expect("quality lock");
                let snapshot = &q.snapshot;
                let estimate = &snapshot.sender_estimate;
                let at = quality_time(path);
                let native_rtt = path.conn.rtt_hint();
                let native_probe = path.conn.probing_rtt_hint();
                let network_queue = native_rtt.saturating_sub(path.conn.min_rtt_hint())
                    >= Duration::from_micros(policy.latency_target_ms.max(2) * 500);
                if reliable_native_service
                    && native_probes[usize::from(path.id)].holds(
                        now_us,
                        snapshot.generation,
                        native_probe,
                        native_rtt,
                        network_queue,
                    )
                {
                    // The native controller still limits every packet. Its own
                    // flight drain is not evidence of a new network capacity.
                    // Keep safety decisions for a real native RTT rise, and
                    // never pause for more than 750 ms in one probe episode.
                    tracing::debug!(
                        path = path.id,
                        native_probe,
                        pacing_bps = controllers[usize::from(path.id)].pacing_bps(),
                        cwnd = path.conn.cwnd_hint(),
                        "native RTT probe holds application observation"
                    );
                    continue;
                }
                let frame_bytes = wire::MAX_WIRE
                    + if policy.receiver_feedback {
                        quality::HEADER
                    } else {
                        0
                    }
                    + wire::http_datagram_overhead(path.stream).expect("admitted stream");
                let send_queue_bytes = path.writer.backlog();
                let transport_blocked = !path.writer.admits(frame_bytes);
                let observation = adaptive::Observation {
                    bulk_backlog,
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
                    reprobe_enabled: !policy.probe_guided_recovery
                        && policy.fec == 0
                        && policy.redundancy == 0
                        && path.open(),
                    feedback_sample_symbols: estimate.sample_symbols,
                    finalized_expected: Some(estimate.expected),
                    finalized_lost: Some(estimate.lost),
                    admitted_symbols: Some(snapshot.sent_symbols),
                    admitted_symbol_bytes: Some(snapshot.sent_bytes),
                    loss_sample_rate: (estimate.sample_symbols > 0)
                        .then_some(estimate.sample_loss_rate),
                    loss_rate: estimate.loss_rate,
                    rtt_ms: native_rtt.as_secs_f64() * 1000.0,
                    probe_rtt_ms: snapshot.probe_updated_us.map(|_| snapshot.probe_rtt_ms),
                    probe_latest_rtt_ms: snapshot
                        .probe_updated_us
                        .map(|_| snapshot.probe_rtt_latest_ms),
                    probe_sample_id: snapshot.replies_received,
                    probe_age_us: snapshot.probe_updated_us.map(|t| at.saturating_sub(t)),
                    transit_excess_ms: (estimate.report_number > 0)
                        .then_some(estimate.delay_variation_ms),
                    send_queue_bytes,
                    offered_backlog: !queue.is_empty(),
                    transport_blocked,
                };
                let probe_snapshot = path
                    .capacity_probe
                    .lock()
                    .expect("capacity probe lock")
                    .snapshot(at);
                let cwnd = path.conn.cwnd_hint();
                let rtt_us = native_rtt.as_micros().min(u128::from(u64::MAX)) as u64;
                if reliable_native_service
                    || (metrics.metrics.native_service_guard()
                        && policy.fec == 0
                        && policy.small_fec_bytes == 0
                        && policy.redundancy == 0
                        && policy.capacity_probe_bps == 0
                        && !policy.probe_guided_recovery)
                {
                    controllers[usize::from(path.id)].observe_native_service(
                        &observation,
                        cwnd,
                        rtt_us,
                    );
                } else {
                    controllers[usize::from(path.id)].observe_native(
                        &observation,
                        policy.probe_guided_recovery.then_some(&probe_snapshot),
                        cwnd,
                        rtt_us,
                    );
                }
                if policy.capacity_probe_bps > 0 {
                    let group_paths = paths
                        .iter()
                        .filter(|p| p.group == path.group)
                        .count()
                        .max(1) as u64;
                    let ceiling = (policy.capacity_probe_bps / paths.len().max(1) as u64)
                        .min(policy.group_rates[usize::from(path.group)] / 20 / group_paths);
                    let ceiling = if policy.probe_guided_recovery {
                        controllers[usize::from(path.id)].independent_probe_ceiling(
                            now_us,
                            ceiling,
                            group_paths as usize,
                        )
                    } else {
                        ceiling
                    };
                    let queue_ms = controllers[usize::from(path.id)]
                        .decision(now_us)
                        .queue_delay_ms;
                    capacity_pacing[usize::from(path.id)].observe(
                        &capacity_probe::Demand {
                            now_us,
                            generation: snapshot.generation,
                            backlog: observation.offered_backlog,
                            blocked: observation.transport_blocked,
                            queue_ms,
                            target_ms: policy.latency_target_ms as f64,
                            rtt_ms: observation.probe_latest_rtt_ms,
                            rtt_age_us: observation.probe_age_us,
                            rtt_sample_id: observation.probe_sample_id,
                            received_probe_bytes: probe_snapshot.sender_estimate.received_bytes,
                            positive_probe_age_us: probe_snapshot
                                .sender_estimate
                                .delivered_updated_us
                                .and_then(|t| at.checked_sub(t)),
                            measurement_sufficient: policy.probe_guided_recovery
                                && controllers[usize::from(path.id)]
                                    .independent_probe_measurement_sufficient(now_us),
                        },
                        ceiling,
                    );
                    let rate = capacity_pacing[usize::from(path.id)].snapshot();
                    metrics.path(path.id, |p| p.capacity_probe_rate = Some(rate));
                }
            }
            let live: Vec<_> = paths
                .iter()
                .filter(|path| path.open())
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
            let mut cap_changed = false;
            if let Some(guard) = reverse_guard.as_mut() {
                let mut sent_bytes = 0u64;
                let counts: Vec<_> = paths
                    .iter()
                    .map(|path| {
                        let q = path.quality.lock().expect("quality lock");
                        sent_bytes = sent_bytes.saturating_add(q.snapshot.sent_bytes);
                        (
                            usize::from(path.id),
                            reverse_guard::Counts {
                                generation: q.snapshot.generation,
                                expected: q.snapshot.received.expected,
                                received: q.snapshot.received.received,
                            },
                        )
                    })
                    .collect();
                if guard.observe(now_us, &counts, sent_bytes) {
                    cap_changed = true;
                    metrics.publish_reverse_guard(guard.snapshot());
                }
            }
            if let Some(guard) = forward_guard.as_mut() {
                let mut sent_bytes = 0u64;
                let counts: Vec<_> = paths
                    .iter()
                    .map(|path| {
                        let q = path.quality.lock().expect("quality lock");
                        sent_bytes = sent_bytes.saturating_add(q.snapshot.sent_bytes);
                        let estimate = &q.snapshot.sender_estimate;
                        (
                            usize::from(path.id),
                            forward_guard::Counts {
                                generation: q.snapshot.generation,
                                sent_symbols: q.snapshot.sent_symbols,
                                expected: estimate.expected,
                                lost: estimate.lost,
                                received_bytes: estimate.received_bytes,
                                report_time_us: estimate.report_time_us,
                            },
                        )
                    })
                    .collect();
                cap_changed |= guard.observe(now_us, &counts, sent_bytes);
                metrics.publish_forward_guard(guard.snapshot());
                let learned = guard.take_random_loss();
                for (id, controller) in controllers.iter_mut().enumerate() {
                    controller.set_shared_loss(guard.shared_loss());
                    if let Some(loss) = learned[id] {
                        controller.inherit_random_loss(loss.generation, loss.fraction, now_us);
                    }
                }
            }
            if cap_changed {
                let cap = [
                    reverse_guard
                        .as_ref()
                        .and_then(reverse_guard::Guard::cap_bps),
                    forward_guard
                        .as_ref()
                        .and_then(forward_guard::Guard::cap_bps),
                ]
                .into_iter()
                .flatten()
                .fold(policy.rate, u64::min);
                pacer.set_rate(now_us, cap);
                tracing::debug!(
                    session = %metrics.session,
                    direction = metrics.direction,
                    cap_bps = cap,
                    forward = ?forward_guard.as_ref().map(forward_guard::Guard::snapshot),
                    reverse = ?reverse_guard.as_ref().map(reverse_guard::Guard::snapshot),
                    "application shared pacing changed"
                );
            }
            for path in paths.iter() {
                let snapshot = controllers[usize::from(path.id)].snapshot(now_us);
                if tracing::enabled!(tracing::Level::DEBUG)
                    && logged_rate_changes[usize::from(path.id)] != snapshot.rate_changes_total
                {
                    logged_rate_changes[usize::from(path.id)] = snapshot.rate_changes_total;
                    tracing::debug!(
                        session = %metrics.session,
                        direction = metrics.direction,
                        path = path.id,
                        change = ?snapshot.rate_changes.back(),
                        native_cwnd = path.conn.cwnd_hint(),
                        sender_backlog = !queue.is_empty(),
                        transport_queue_bytes = path.writer.backlog(),
                        "application path pacing changed"
                    );
                }
                metrics.path(path.id, |p| p.adaptive = Some(snapshot));
            }
        }
        if publish_feedback_stats
            && let Some(control) = fec_control.as_mut()
            && control.due(now_us)
        {
            let feedback: Vec<_> = paths
                .iter()
                .map(|path| {
                    (
                        path.id,
                        path.open() && silent & (1 << path.id) == 0,
                        path.quality
                            .lock()
                            .expect("quality lock")
                            .snapshot_at(quality_time(path)),
                    )
                })
                .collect();
            let changed = control.observe(
                now_us,
                feedback.iter().map(|(id, active, s)| (*id, *active, s)),
            );
            let snapshot = control.snapshot();
            if let Some(k) = changed.or_else(|| snapshot.loss_rate.map(|_| snapshot.data_shards)) {
                match encoder.set_fec(k) {
                    Ok(symbols) => {
                        for symbol in symbols {
                            enqueue_encoded(
                                symbol,
                                now,
                                &mut queue,
                                &mut blocks,
                                &policy,
                                &metrics,
                            );
                        }
                    }
                    Err(_) => {
                        metrics.update(|d| d.records.encoding_dropped += 1);
                        break;
                    }
                }
            }
            metrics.publish_automatic_fec(snapshot);
        }
        update_business_pacer(&mut business, &paths, &controllers, now_us);
        if policy.capacity_probe_bps > 0 {
            for path in paths.iter() {
                let snapshot = path
                    .capacity_probe
                    .lock()
                    .expect("capacity probe lock")
                    .snapshot(quality_time(path));
                metrics.path(path.id, |p| p.capacity_probe = Some(snapshot));
            }
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
                        .saturating_add(if policy.capacity_probe_bps > 0 {
                            let state = path.capacity_probe.lock().expect("capacity probe lock");
                            if state
                                .include_feedback(quality::ReportKind::Delivery, quality_time(path))
                            {
                                state.unreported_received_bytes()
                            } else {
                                0
                            }
                        } else {
                            0
                        })
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
                    let include_probes = policy.capacity_probe_bps > 0
                        && paths.iter().any(|path| {
                            path.capacity_probe
                                .lock()
                                .expect("capacity probe lock")
                                .include_feedback(kind, quality_time(path))
                        });
                    let frame = if include_probes {
                        let probes: Vec<_> = paths
                            .iter()
                            .map(|path| {
                                path.capacity_probe
                                    .lock()
                                    .expect("capacity probe lock")
                                    .report(path.id, kind, quality_time(path))
                            })
                            .collect();
                        capacity_probe::control(&reports, &probes)
                    } else {
                        quality::control_v2(&reports)
                    };
                    pending_feedback = Some((frame, kind));
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
                if path.open()
                    && pacer.available(cost)
                    && group.available(cost)
                    && path
                        .conn
                        .max_datagram_size_hint()
                        .is_some_and(|m| m >= data.len())
                    && path.writer.admits(data.len())
                    && path.writer.send_first(data)
                {
                    pacer.spend(cost);
                    group.spend(cost);
                    path.quality
                        .lock()
                        .expect("quality lock")
                        .snapshot
                        .controls_sent += 1;
                    if frame.starts_with(b"BQ3C") {
                        path.capacity_probe
                            .lock()
                            .expect("capacity probe lock")
                            .control_admitted();
                    }
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
                .filter(|p| p.open())
                .min_by_key(|p| control_priority(p))
                .map(|p| p.group)
        } else {
            None
        };
        if policy.adaptive {
            for path in paths.iter().filter(|p| p.open()) {
                let id = usize::from(path.id);
                let reply = path.probe_reply.lock().expect("probe reply lock").clone();
                let frame = if let Some(reply) = reply {
                    Some(reply)
                } else if controllers[id].decision(now_us).probe_due
                    || (policy.capacity_probe_bps > 0
                        && capacity_pacing[id].rtt_request_due(now_us))
                {
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
                    && path.writer.admits(data.len())
                    && path
                        .conn
                        .max_datagram_size_hint()
                        .is_some_and(|m| m >= data.len())
                    && path.writer.send_first(data)
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
                        if policy.capacity_probe_bps > 0 {
                            capacity_pacing[id].rtt_request_admitted(now_us);
                        }
                    }
                    metrics.update(|d| d.symbols.probes_admitted += 1);
                }
            }
        }
        if policy.capacity_probe_bps > 0 && !paths.is_empty() {
            let mut probe_rates = [0u64; MAX_PATHS];
            for path in paths.iter() {
                if path.open() {
                    let rate = capacity_pacing[usize::from(path.id)].snapshot().pacing_bps;
                    probe_rates[usize::from(path.group)] =
                        probe_rates[usize::from(path.group)].saturating_add(rate);
                }
            }
            capacity_budget.set_rates(now_us, probe_rates);
            let first = capacity_cursor;
            for offset in 0..paths.len() {
                let index = (first + offset) % paths.len();
                let path = &paths[index];
                if !path.open() {
                    continue;
                }
                if !capacity_pacing[usize::from(path.id)]
                    .available(now_us, capacity_probe::FRAME_BYTES + 82)
                {
                    continue;
                }
                let frame = path
                    .capacity_probe
                    .lock()
                    .expect("capacity probe lock")
                    .prepare_with_feedback(
                        quality_time(path),
                        !policy.probe_guided_recovery
                            || controllers[usize::from(path.id)]
                                .independent_probe_fast_feedback(now_us),
                    );
                let data =
                    wire::http_datagram(path.stream, &frame).expect("capacity probe mapping");
                let cost = data.len() + 80;
                let reserve = if Some(path.group) == reserved_group {
                    feedback_reserve
                } else {
                    0
                };
                let group = &mut groups[usize::from(path.group)];
                if capacity_pacing[usize::from(path.id)].available(now_us, cost)
                    && capacity_budget.available(now_us, path.group, cost)
                    && pacer.available(cost + feedback_reserve)
                    && group.available(cost + reserve)
                    && path.writer.admits(data.len())
                    && path
                        .conn
                        .max_datagram_size_hint()
                        .is_some_and(|size| size >= data.len())
                    && path.writer.send(data)
                {
                    pacer.spend(cost);
                    group.spend(cost);
                    capacity_budget.admitted(path.group, cost);
                    capacity_pacing[usize::from(path.id)].admitted(cost);
                    path.capacity_probe
                        .lock()
                        .expect("capacity probe lock")
                        .admitted();
                    capacity_cursor = (index + 1) % paths.len();
                }
            }
        }
        let mut stalled_originals = 0usize;
        let mut blocked_repair = false;
        let mut stalled_repairs = Vec::new();
        let mut repair_wait: Option<PreparedSend> = None;
        let mut next_wait = None;
        'drain: loop {
            if deferred_input
                .as_ref()
                .is_some_and(|input| !queue.would_be_full(policy.flow(input.record.flow)))
            {
                encode_input(
                    deferred_input.take().expect("current input"),
                    &mut encoder,
                    &policy,
                    &mut queue,
                    &mut blocks,
                    &metrics,
                );
            }
            if queue.is_empty() {
                break;
            }
            let now = Instant::now();
            let now_us = epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
            let affordable_repair = |p: &outbound::Pending| {
                repair_allowed(&policy, &budget, &blocks, p, repair_frame_floor(&policy, p))
            };
            let repair_ready = if policy.split_fec() {
                // At most REPAIR_LIMIT distinct heads are tried without an
                // admission. A budget- or path-blocked lane cannot hide a
                // separately authorized repair from the other coding lane.
                let ready = queue.promote_ready_repair(|p| {
                    !p.block
                        .is_some_and(|block| stalled_repairs.contains(&block))
                        && affordable_repair(p)
                });
                blocked_repair = !ready && !stalled_repairs.is_empty();
                ready
            } else {
                queue.front(true).is_some_and(|p| {
                    !p.block.is_some_and(|b| queue.block_pending(b)) && affordable_repair(p)
                })
            };
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
                        account_budget_skipped(&policy, &skipped, &metrics);
                    }
                    if let Some(block) = skipped.block
                        && !queue.repair_pending(block)
                    {
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
            frontier.head_previews += 1;
            let is_small = small_delivery::applies(&policy, &front);
            let candidates: Vec<_> = if policy.quality_schedule || policy.adaptive {
                paths
                    .iter()
                    .filter(|p| {
                        let eligible = p.open()
                            && silent & (1 << p.id) == 0
                            && (!policy.adaptive
                                || controllers[usize::from(p.id)].eligible(now_us));
                        if !eligible {
                            frontier.add(p.id, is_small, Gate::PathIneligible);
                        }
                        eligible
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
                                path.conn.rtt_hint().as_secs_f64() * 1000.0,
                            )
                        };
                        (path.id, weight)
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let candidates = latency_candidates(candidates, &paths, &front, repair, &policy, age);
            let before_allowance = candidates
                .iter()
                .fold(0u8, |mask, (id, _)| mask | (1 << id));
            let mut candidates = if policy.adaptive {
                business_ready_candidates(
                    &candidates,
                    &paths,
                    &mut controllers,
                    now_us,
                    front.data.len()
                        + if policy.receiver_feedback {
                            quality::HEADER
                        } else {
                            0
                        },
                    age.as_secs_f64() * 1000.0,
                    None,
                )
            } else {
                candidates
            };
            if policy.adaptive {
                let after = candidates
                    .iter()
                    .fold(0u8, |mask, (id, _)| mask | (1 << id));
                for id in 0..MAX_PATHS as u8 {
                    if before_allowance & !after & (1 << id) != 0 {
                        frontier.add(id, is_small, Gate::PathAllowance);
                    }
                }
                if after == 0 {
                    frontier.no_eligible_path_previews += 1;
                }
            }
            let used = front
                .block
                .and_then(|b| blocks.get(&b))
                .map_or(0, |b| b.paths);
            let small_mask = if is_small {
                let eligible = if policy.quality_schedule {
                    candidates.iter().fold(0, |mask, (id, _)| mask | (1 << id))
                } else {
                    paths.iter().fold(0, |mask, path| mask | (1 << path.id))
                };
                small_delivery::mask(
                    &paths,
                    eligible,
                    lifetime.saturating_sub(age),
                    policy.latency_target_ms,
                    if repair && policy.fec == automatic_fec::AUTO {
                        used
                    } else {
                        0
                    },
                )
            } else {
                u8::MAX
            };
            if is_small {
                candidates.retain(|(id, _)| small_mask & (1 << id) != 0);
            }
            if policy.adaptive {
                update_business_pacer(&mut business, &paths, &controllers, now_us);
            }
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
            if is_small {
                order.retain(|i| small_mask & (1 << paths[*i].id) != 0);
            }
            if repair {
                order.sort_by_key(|i| u8::from(used & (1 << paths[*i].id) != 0));
            } else if order.len() > 1
                && !is_small
                && (front.data.len() <= LATENCY_RECORD_BYTES
                    || front.hold.as_ref().is_some_and(|hold| hold.interactive()))
            {
                // Small records (acknowledgments, interactive and control
                // traffic) and latency-bound streams take the earliest ready
                // path; bulk keeps the weighted spread across paths. Where the
                // small-delivery policy applies, its delay and loss ranking
                // decides instead.
                let mut ranked: Vec<_> = order
                    .iter()
                    .map(|&i| (small_delivery::delay_ms(&paths[i]), i))
                    .collect();
                ranked.sort_by(|a, b| a.0.total_cmp(&b.0));
                order = ranked.into_iter().map(|(_, i)| i).collect();
            }
            // AUTO originals prefer a ready faster route in the same protection
            // tier. Repairs/fixed policies retain the opt-in frontier treatment.
            // Reordering never removes a fallback or bypasses any gate below.
            if is_small && policy.adaptive && order.len() > 1 {
                frontier.small_rank_evaluations += 1;
                let ids: Vec<_> = order.iter().map(|i| paths[*i].id).collect();
                let samples: Vec<_> = order
                    .iter()
                    .filter_map(|i| {
                        let path = &paths[*i];
                        let frame = front.data.len()
                            + quality::HEADER
                            + wire::http_datagram_overhead(path.stream).ok()?;
                        let mut sample = small_delivery::frontier_sample(
                            path,
                            frame,
                            if repair { used } else { 0 },
                        )?;
                        let reserve = if Some(path.group) == reserved_group {
                            feedback_reserve
                        } else {
                            0
                        };
                        sample.immediately_ready &= pacer.available(frame + 80 + feedback_reserve)
                            && groups[usize::from(path.group)].available(frame + 80 + reserve)
                            && business
                                .as_ref()
                                .expect("adaptive business pacer")
                                .available(path.group, frame + 80)
                            && (!repair
                                || (repair_allowed(&policy, &budget, &blocks, &front, frame)
                                    && small_delivery::copy_ready(path, used)));
                        Some(sample)
                    })
                    .collect();
                let auto_original = !repair && policy.fec == automatic_fec::AUTO;
                let preferred = if auto_original {
                    sender_frontier::preferred_original(&ids, &samples)
                } else {
                    sender_frontier::preferred(&ids, &samples)
                };
                if let Some(id) = preferred {
                    frontier.small_rank_opportunities += 1;
                    if frontier.enabled || auto_original {
                        let at = order
                            .iter()
                            .position(|i| paths[*i].id == id)
                            .expect("existing ranked path");
                        let selected = order.remove(at);
                        order.insert(0, selected);
                        if auto_original {
                            frontier.automatic_original_rank_changes += 1;
                        } else {
                            frontier.small_rank_changes += 1;
                        }
                    }
                }
            }
            let mut accepted = None;
            let mut wait_candidate = None;
            for i in order {
                let path = &paths[i];
                let id = usize::from(path.id);
                if !path.open() || silent & (1 << path.id) != 0 {
                    frontier.add(path.id, is_small, Gate::PathIneligible);
                    continue;
                }
                if is_small && repair && !small_delivery::copy_ready(path, used) {
                    frontier.add(path.id, is_small, Gate::CopySpacing);
                    continue;
                }
                let Ok(mapping_bytes) = wire::http_datagram_overhead(path.stream) else {
                    frontier.add(path.id, is_small, Gate::DatagramSize);
                    continue;
                };
                let frame_bytes = mapping_bytes
                    + front.data.len()
                    + if policy.receiver_feedback {
                        quality::HEADER
                    } else {
                        0
                    };
                let cost = frame_bytes + 80;
                let group_reserve = if Some(path.group) == reserved_group {
                    feedback_reserve
                } else {
                    0
                };
                if !pacer.available(cost + feedback_reserve) {
                    frontier.add(path.id, is_small, Gate::Aggregate);
                    continue;
                }
                if !groups[usize::from(path.group)].available(cost + group_reserve) {
                    frontier.add(path.id, is_small, Gate::Group);
                    continue;
                }
                if repair && !repair_allowed(&policy, &budget, &blocks, &front, frame_bytes) {
                    frontier.add(path.id, is_small, Gate::RepairCredit);
                    continue;
                }
                if policy.adaptive {
                    let allowed = controllers[id].allow(now_us, cost, age.as_secs_f64() * 1000.0);
                    update_business_pacer(&mut business, &paths, &controllers, now_us);
                    if !allowed {
                        frontier.add(path.id, is_small, Gate::PathAllowance);
                        continue;
                    }
                    if let Some(gate) = business
                        .as_ref()
                        .expect("adaptive business pacer")
                        .blocked_gate(path.group, cost)
                    {
                        frontier.add(path.id, is_small, gate);
                        continue;
                    }
                }
                if path
                    .conn
                    .max_datagram_size_hint()
                    .is_none_or(|m| frame_bytes > m)
                {
                    frontier.add(path.id, is_small, Gate::DatagramSize);
                    continue;
                }
                let blocked = !path.writer.admits(frame_bytes);
                #[cfg(test)]
                let blocked =
                    blocked || sender_ready_tests::defer_expiry_candidate(front.record_id);
                if blocked {
                    frontier.add(path.id, is_small, Gate::ApiBuffer);
                    metrics.path(path.id, |p| p.send_buffer_full_attempts += 1);
                    if wait_candidate.is_some() {
                        continue;
                    }
                }
                // Only a viable immediate send or the first readiness candidate
                // needs an owned frame. Failed previews consume no quality sequence.
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
                debug_assert_eq!(data.len(), frame_bytes);
                if blocked {
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
                    continue;
                }
                match send_datagram_before_deadline(path, data, front.created, lifetime) {
                    None => {
                        frontier.add(path.id, is_small, Gate::ExpiredBeforeApi);
                        let expired = queue.pop(repair).expect("expired front");
                        account_expired(&expired, Instant::now(), &metrics);
                        stalled_originals = 0;
                        continue 'drain;
                    }
                    Some(Ok(at)) => {
                        frontier.add(path.id, is_small, Gate::ApiAdmitted);
                        accepted = Some((i, frame_bytes, at));
                        break;
                    }
                    Some(Err(_)) => {
                        frontier.add(path.id, is_small, Gate::ApiError);
                        trace_outgoing(
                            &metrics,
                            trace::Stage::QuinnApiRejected,
                            &front,
                            path,
                            frame_bytes,
                            Some(trace::Reason::QuinnError),
                        );
                        metrics.path(path.id, |p| p.quinn_send_error_attempts += 1);
                    }
                }
            }
            let Some((index, frame_bytes, at)) = accepted else {
                if repair {
                    // Split lanes recompute the blocked flag from this list on
                    // every pass; without it the same unsendable repair would
                    // be retried until it expired, starving every original.
                    if policy.split_fec() {
                        stalled_repairs.push(front.block.expect("encoded repair block"));
                        if repair_wait.is_none() {
                            repair_wait = wait_candidate;
                        }
                        continue;
                    }
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
                business: &mut business,
                paths: &paths,
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
            stalled_repairs.clear();
            repair_wait = None;
        }
        if let Some(input) = deferred_input {
            // No immediate service freed the original slot. Keep the existing
            // bounded rejection, without changing a prepared wait's queue head.
            debug_assert!(queue.would_be_full(policy.flow(input.record.flow)));
            encode_input(
                input,
                &mut encoder,
                &policy,
                &mut queue,
                &mut blocks,
                &metrics,
            );
        }
        if next_wait.is_none()
            && let Some(attempt) = repair_wait
        {
            // A rotated candidate may wait only after restoring its exact
            // queue head. No admission occurred since this frame was prepared.
            if queue.promote_ready_repair(|p| {
                p.block == attempt.front.block
                    && p.created == attempt.front.created
                    && p.data == attempt.front.data
            }) {
                next_wait = Some(attempt);
            }
        }
        if publish_feedback_stats {
            publish_receiver_feedback(&paths, &metrics);
            metrics.publish_sender_frontier(frontier.clone());
        }
        drop(paths);
        waiting = next_wait.map(WaitingSend::new);
    }
    drop(waiting);
    for repair in [false, true] {
        while let Some(pending) = queue.pop(repair) {
            metrics.trace_symbol(
                trace::Stage::SymbolDropped,
                &pending.data,
                None,
                None,
                Some(trace::Reason::Shutdown),
            );
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
    while let Ok(pending) = input.try_recv() {
        metrics.trace_record(
            trace::Stage::RecordDropped,
            &pending.record,
            None,
            Some(trace::Reason::Shutdown),
        );
        metrics.update(|d| d.records.input_shutdown_dropped += 1);
    }
    publish_receiver_feedback(&shared_paths.lock().expect("paths lock"), &metrics);
    metrics.publish_sender_frontier(frontier);
}

#[derive(Clone, Copy)]
enum QueueLayer {
    Ingress,
    Sender,
    Receiver,
}
fn rejected_item<T>(error: &mpsc::error::TrySendError<T>) -> &T {
    match error {
        mpsc::error::TrySendError::Full(value) | mpsc::error::TrySendError::Closed(value) => value,
    }
}
fn queue_trace_reason<T>(layer: QueueLayer, error: &mpsc::error::TrySendError<T>) -> trace::Reason {
    match (layer, matches!(error, mpsc::error::TrySendError::Closed(_))) {
        (QueueLayer::Ingress, false) => trace::Reason::IngressFull,
        (QueueLayer::Ingress, true) => trace::Reason::IngressClosed,
        (QueueLayer::Sender, false) => trace::Reason::SenderFull,
        (QueueLayer::Sender, true) => trace::Reason::SenderClosed,
        (QueueLayer::Receiver, false) => trace::Reason::ReceiverFull,
        (QueueLayer::Receiver, true) => trace::Reason::ReceiverClosed,
    }
}

fn publish_messages(messages: &mut messages::Reassembly, scope: &Scope) {
    let (completed, dropped, failures) = messages.take_counters();
    if completed > 0 || dropped > 0 {
        scope.update(|d| {
            d.records.messages_reassembled += completed;
            d.records.message_reassembly_dropped += dropped;
            d.records.message_reassembly_failures.add(failures);
        });
    }
}

fn enqueue_message(
    tx: &mpsc::Sender<QueuedRecord>,
    records: messages::Fragments,
    created: Instant,
    scope: &Scope,
    small_threshold: usize,
) -> bool {
    let count = records.len() as u64;
    records.trace(scope, trace::Stage::MessageAssigned, None);
    let permits = ingress::reserve(
        tx,
        records.len(),
        small_threshold > 0 && !records.is_small(small_threshold),
    );
    match permits {
        Ok(permits) => {
            for (record, permit) in records.zip(permits) {
                // Small single messages keep the ordinary FIFO semantics.
                admit_record(record, created, scope, None, |queued| {
                    permit.send(queued);
                    Ok(())
                });
            }
            scope.update(|d| d.records.sender_queue_enqueued += count);
            true
        }
        Err(error) => {
            records.trace(
                scope,
                trace::Stage::MessageDropped,
                Some(queue_trace_reason(QueueLayer::Sender, &error)),
            );
            let closed = matches!(error, mpsc::error::TrySendError::Closed(()));
            if count == 1 {
                for record in records {
                    admit_record(record, created, scope, None, |queued| {
                        Err(if closed {
                            mpsc::error::TrySendError::Closed(queued)
                        } else {
                            mpsc::error::TrySendError::Full(queued)
                        })
                    });
                }
            } else {
                // No fragment buffers or per-fragment metrics locks are needed
                // for a message that never obtained input capacity.
                scope.update(|d| {
                    if closed {
                        d.records.sender_queue_closed_dropped += count;
                    } else {
                        d.records.sender_queue_full_dropped += count;
                    }
                });
            }
            scope.update(|d| d.records.messages_admission_dropped += 1);
            false
        }
    }
}

fn enqueue_record(
    tx: &mpsc::Sender<QueuedRecord>,
    record: Record,
    created: Instant,
    scope: &Scope,
    small_threshold: usize,
    hold: Option<Arc<outbound::Hold>>,
) -> bool {
    let payload_bytes = if record.flow & messages::FLAG != 0 {
        super::MAX_MESSAGE
    } else {
        record.payload.len()
    };
    admit_record(record, created, scope, hold, |queued| {
        ingress::try_send(tx, queued, payload_bytes, small_threshold)
    })
}

fn admit_record(
    record: Record,
    created: Instant,
    scope: &Scope,
    hold: Option<Arc<outbound::Hold>>,
    send: impl FnOnce(QueuedRecord) -> Result<(), mpsc::error::TrySendError<QueuedRecord>>,
) -> bool {
    let mut assigned_event = None;
    scope.trace_with(|context, capture| {
        let mut event = trace::Event::new(context, trace::Stage::RecordAssigned);
        event.record = Some(trace::RecordKey {
            flow: record.flow,
            record_id: record.id,
        });
        event.message = messages::metadata(&record);
        event.bytes.payload = u32::try_from(record.payload.len()).ok();
        event.probe = capture.probe_identity(&record.payload);
        assigned_event = Some(event);
        event
    });
    let result = send(QueuedRecord {
        record,
        created,
        hold,
    });
    if let Some(mut event) = assigned_event {
        event.stage = if result.is_ok() {
            trace::Stage::IngressQueued
        } else {
            trace::Stage::RecordDropped
        };
        event.reason = result
            .as_ref()
            .err()
            .map(|error| queue_trace_reason(QueueLayer::Sender, error));
        scope.metrics.trace().emit(event);
    }
    if let Err(error) = result {
        queue_error(scope, QueueLayer::Sender, &error, None);
        false
    } else {
        true
    }
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

fn publish_retention(decoder: &Receiver, metrics: &Scope) {
    if let Some(snapshot) = decoder.retention_snapshot() {
        metrics.publish_fec_retention(snapshot);
    }
}

async fn retention_deadline(decoder: &Receiver) {
    if let Some(at) = decoder.next_retention_deadline() {
        tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
#[tokio::test]
async fn adaptive_retention_timer_expires_without_another_packet() {
    let at = Instant::now();
    let mut decoder = Receiver::configured(Duration::from_millis(900), true);
    let record = Record {
        flow: 1,
        id: 1,
        payload: vec![7; 32],
    };
    let packet = wire::shard(crate::fec::Shard::Data {
        block: 0,
        index: 0,
        payload: record.encode().unwrap(),
    });
    decoder.receive(&packet, at).unwrap();
    timeout(Duration::from_secs(1), retention_deadline(&decoder))
        .await
        .unwrap();
    decoder.expire_adaptive(Instant::now());
    assert_eq!(decoder.retention_snapshot().unwrap().live_blocks, 0);
    assert!(decoder.next_retention_deadline().is_none());
}

fn receive_records(
    decoder: &mut Receiver,
    metrics: &Scope,
    pid: u8,
    data: &[u8],
    streams: Option<&tcp::Mux>,
) -> Vec<Record> {
    let before = (
        decoder.original_packets,
        decoder.originals,
        decoder.recovered,
        decoder.duplicates,
        decoder.stale,
    );
    let repairs_before = decoder.repair_packets;
    let late_before = decoder.late_stream_records;
    metrics.trace_symbol(trace::Stage::PeerSymbolReceived, data, None, None, None);
    let result = decoder.receive_with_late(
        data,
        Instant::now(),
        |flow| streams.is_some_and(|mux| mux.accepts_late(flow)),
        |record, repaired, disposition| {
            let duplicate = disposition == wire::RecordDisposition::Duplicate;
            metrics.trace_with(|context, capture| {
                let mut event = trace::Event::new(
                    context,
                    if duplicate {
                        trace::Stage::RecordDuplicate
                    } else {
                        trace::Stage::RecordDecoded
                    },
                );
                stats::trace_symbol_fields(&mut event, data, capture);
                // The triggering repair's block is real, but its decoded record is
                // known only after successful reconstruction/record validation.
                event.record = Some(trace::RecordKey {
                    flow: record.flow,
                    record_id: record.id,
                });
                event.bytes.payload = u32::try_from(record.payload.len()).ok();
                event.probe = capture.probe_identity(&record.payload);
                event.recovered = Some(repaired);
                event.reason = match disposition {
                    wire::RecordDisposition::Duplicate => Some(trace::Reason::Duplicate),
                    wire::RecordDisposition::LateStream => Some(trace::Reason::LateStream),
                    wire::RecordDisposition::New => None,
                };
                event
            });
        },
    );
    let invalid = u64::from(result.is_err());
    if invalid > 0 {
        decoder.invalid += 1;
        metrics.trace_symbol(
            trace::Stage::SymbolDropped,
            data,
            None,
            None,
            Some(trace::Reason::InvalidSymbol),
        );
    }
    let delta = (
        decoder.original_packets - before.0,
        decoder.originals - before.1,
        decoder.recovered - before.2,
        decoder.duplicates - before.3,
        decoder.stale - before.4,
    );
    if delta.4 > 0 {
        metrics.trace_symbol(
            trace::Stage::SymbolDropped,
            data,
            None,
            None,
            Some(trace::Reason::Stale),
        );
    }
    metrics.update(|d| {
        d.records.repair_symbols_received += decoder.repair_packets - repairs_before;
        d.records.late_stream_records_received += decoder.late_stream_records - late_before;
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
    publish_retention(decoder, metrics);
    result.unwrap_or_default()
}

enum Event {
    Wire(u8, Bytes),
    Reply(u32, Vec<u8>, Instant),
}
struct Session {
    adaptive_fec_retention: bool,
    generations: Mutex<[Option<u64>; MAX_PATHS]>,
    empty_since: Mutex<Option<Instant>>,
    events: mpsc::Sender<Event>,
    paths: Paths,
    stop: watch::Sender<bool>,
    policy: Policy,
    observation_notify: Option<Arc<Notify>>,
    ingress_drops: Arc<AtomicU64>,
    forward: Scope,
    returning: Scope,
    finished: tokio::sync::Notify,
    done: std::sync::atomic::AtomicBool,
}
type Sessions = Arc<Mutex<HashMap<String, Arc<Session>>>>;

fn session_events(streams: bool, proxy: bool) -> (mpsc::Sender<Event>, mpsc::Receiver<Event>) {
    // Reliable uploads have the same burst and repair behavior as downloads.
    // Keep their receive budget symmetric; raw latency UDP retains its queue.
    mpsc::channel(if streams || proxy { WIRE_QUEUE } else { QUEUE })
}

// Session loops are detached from connection handlers. Stop them even if the
// owning server future is cancelled before its normal shutdown path runs.
struct ServerLifetime {
    endpoint: quinn::Endpoint,
    sessions: Sessions,
}
impl Drop for ServerLifetime {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"server stopped");
        for session in self.sessions.lock().expect("sessions lock").values() {
            let _ = session.stop.send(true);
        }
    }
}

async fn stream_wake(streams: &mut Option<tcp::Mux>) -> tcp::Wake {
    match streams {
        Some(streams) => streams.wake().await,
        None => std::future::pending().await,
    }
}

async fn session_loop(
    session: Arc<Session>,
    mut events: mpsc::Receiver<Event>,
    target: Option<SocketAddr>,
    tcp: tcp::Targets,
    tcp_budget: Arc<tcp::Budget>,
) {
    if *session.stop.borrow() {
        session.done.store(true, Ordering::Release);
        session.finished.notify_waiters();
        return;
    }
    let (tx, rx) = mpsc::channel(QUEUE);
    let mut tasks = JoinSet::new();
    tasks.spawn(sender(
        rx,
        session.paths.clone(),
        session.policy.clone(),
        session.stop.subscribe(),
        session.returning.clone(),
        session.observation_notify.clone(),
    ));
    let mut stop = session.stop.subscribe();
    let mut decoder = Receiver::configured(
        Duration::from_millis(session.policy.queue_ms),
        session.adaptive_fec_retention,
    )
    .with_dual_repairs(session.policy.fec_repairs == 2);
    let mut messages = messages::Reassembly::new(
        session.policy.max_message_bytes,
        session.policy.admission_lifetime(),
    )
    .with_scope(session.forward.clone());
    publish_retention(&decoder, &session.forward);
    let mut delivery = local_delivery::Queue::new(
        session.forward.clone(),
        Duration::from_millis(
            session
                .policy
                .queue_ms
                .min(session.policy.latency_target_ms),
        ),
    );
    let mut flows: HashMap<u32, (Arc<UdpSocket>, Instant)> = HashMap::new();
    let mut streams = tcp::Mux::server(tcp, &session.policy, session.returning.clone(), tcp_budget);
    let small_threshold = ingress::small_threshold(&session.policy);
    let mut next_id = 0u64;
    let mut tick = interval(Duration::from_secs(5));
    let mut telemetry: [transport::ProxyTelemetry; MAX_PATHS] =
        std::array::from_fn(|_| Default::default());
    let mut dropped = 0u64;
    loop {
        if *stop.borrow() {
            break;
        }
        if let Some(mux) = streams.as_mut() {
            mux.service_io();
            mux.flush(&mut tcp::Out {
                tx: &tx,
                next_id: &mut next_id,
                scope: &session.returning,
                small_threshold,
            });
        }
        tokio::select! {
            biased;
            _=stop.changed()=>break,
            _=tick.tick()=>{
                flows.retain(|_,(_,t)|t.elapsed()<Duration::from_secs(60));
                let p=session.paths.lock().expect("paths lock");
                if session.policy.streams || session.policy.proxy {
                    for path in p.iter() { telemetry[usize::from(path.id)].report(&path.conn,"server","local"); }
                }
                for path in p.iter(){let stats=path.conn.stats();let mut app_pacing_bps=None;session.returning.path(path.id,|p|app_pacing_bps=p.adaptive.as_ref().map(|a|a.decision.pacing_bps));info!(session=%session.forward.session,path=path.id,?app_pacing_bps,rtt_ms=path.conn.rtt_hint().as_secs_f64()*1000.0,tx_packets=stats.udp_tx.datagrams,rx_packets=stats.udp_rx.datagrams,tx_bytes=stats.udp_tx.bytes,rx_bytes=stats.udp_rx.bytes,lost=stats.path.lost_packets,cwnd=stats.path.cwnd,"server path statistics");}
                info!(session=%session.forward.session,paths=p.len(),flows=flows.len(),originals=decoder.originals,recovered=decoder.recovered,duplicates=decoder.duplicates,late_stream_records=decoder.late_stream_records,invalid=decoder.invalid,dropped,ingress_drops=session.ingress_drops.load(Ordering::Relaxed),"server session");
                if let Some(mux)=streams.as_mut(){mux.report_progress();}
            },
            _=retention_deadline(&decoder)=>{decoder.expire_adaptive(Instant::now());publish_retention(&decoder,&session.forward);},
            _=messages::deadline(&messages)=>{messages.expire(Instant::now()); publish_messages(&mut messages, &session.forward);},
            completed=delivery.ready()=>dropped+=completed,
            e=events.recv()=>match e {
                Some(Event::Wire(pid,data))=>{
                    let records=receive_records(&mut decoder,&session.forward,pid,&data,streams.as_ref());
                    let decoded=Instant::now();
                    for r in records {
                        if let Some(mux)=streams.as_mut() && (stream::stream_id(r.flow).is_some() || associate::is_flow(r.flow)) {mux.receive(r);continue}
                        if stream::stream_id(r.flow).is_some() || associate::is_flow(r.flow) {dropped+=1;continue}
                        let Some((r, decoded)) = messages.receive(r, decoded) else { publish_messages(&mut messages, &session.forward); continue; };
                        publish_messages(&mut messages, &session.forward);
                        if !flows.contains_key(&r.flow) {
                            let Some(target)=target else{dropped+=delivery.socket_error(pid,&r);continue};
                            if flows.len()>=MAX_FLOWS{dropped+=1;session.forward.trace_record(trace::Stage::RecordDropped,&r,None,Some(trace::Reason::FlowLimit));session.forward.update(|d|d.records.udp_target_flow_dropped+=1);session.forward.path(pid,|p|p.udp_target_flow_dropped+=1);continue}
                            let bind=if target.is_ipv4(){"0.0.0.0:0"}else{"[::]:0"};
                            let Ok(socket)=UdpSocket::bind(bind).await else{dropped+=delivery.socket_error(pid,&r);continue};
                            if socket.connect(target).await.is_err(){dropped+=delivery.socket_error(pid,&r);continue}
                            let socket=Arc::new(socket); let weak=Arc::downgrade(&socket); let events=session.events.clone(); let flow=r.flow; let mut quit=session.stop.subscribe(); let ingress_drops=session.ingress_drops.clone();let returning=session.returning.clone();let small_threshold=ingress::small_threshold(&session.policy);let max_message_bytes=session.policy.max_message_bytes;
                            tasks.spawn(async move {
                                let mut b=vec![0;65536];
                                loop {
                                    let Some(socket)=weak.upgrade() else{break};
                                    tokio::select! {
                                        _=quit.changed()=>break,
                                        value=timeout(Duration::from_secs(5),socket.recv(&mut b))=>match value {
                                            Ok(Ok(n))=>{
                                                returning.update(|d|d.records.application_received+=1);
                                                trace_payload(&returning,trace::Stage::RecordIngress,&b[..n],None);
                                                if n>max_message_bytes{trace_payload(&returning,trace::Stage::RecordDropped,&b[..n],Some(trace::Reason::Oversize));returning.update(|d|d.records.application_oversize_dropped+=1);continue;}
                                                let now=Instant::now();
                                                if let Err(error)=ingress::try_send(&events,Event::Reply(flow,b[..n].to_vec(),now),n,small_threshold){trace_payload(&returning,trace::Stage::RecordDropped,&b[..n],Some(queue_trace_reason(QueueLayer::Ingress,&error)));ingress_drops.fetch_add(1,Ordering::Relaxed);queue_error(&returning,QueueLayer::Ingress,&error,None);}else{trace_payload(&returning,trace::Stage::IngressQueued,&b[..n],None);returning.update(|d|d.records.ingress_queue_enqueued+=1);}
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
                            *last=Instant::now();
                            dropped+=delivery.send(socket,None,r,pid,decoded);
                        }
                    }
                },
                Some(Event::Reply(flow,payload,created))=>{
                    let Some((_,last))=flows.get_mut(&flow) else{trace_payload(&session.returning,trace::Stage::RecordDropped,&payload,Some(trace::Reason::FlowUnavailable));session.returning.update(|d|d.records.application_unavailable_dropped+=1);continue}; *last=Instant::now();
                    let Ok(parts)=messages::split(flow,&mut next_id,payload,session.policy.max_message_bytes) else {break};
                    if !enqueue_message(&tx,parts,created,&session.returning,ingress::small_threshold(&session.policy)){dropped+=1;}
                },
                None=>break,
            },
            wake=stream_wake(&mut streams)=>streams.as_mut().expect("stream adapter").handle(wake),
        }
        while tasks.try_join_next().is_some() {}
    }
    if let Some(mux) = streams.as_mut() {
        mux.close_all();
    }
    messages.close();
    publish_messages(&mut messages, &session.forward);
    dropped += delivery.close();
    decoder.close_retention();
    publish_retention(&decoder, &session.forward);
    let _ = session.stop.send(true);
    events.close();
    while let Ok(event) = events.try_recv() {
        match event {
            Event::Wire(_, data) => {
                session.forward.trace_symbol(
                    trace::Stage::SymbolDropped,
                    &data,
                    None,
                    None,
                    Some(trace::Reason::Shutdown),
                );
                session
                    .forward
                    .update(|d| d.records.receiver_shutdown_dropped += 1);
            }
            Event::Reply(_, payload, _) => {
                trace_payload(
                    &session.returning,
                    trace::Stage::RecordDropped,
                    &payload,
                    Some(trace::Reason::Shutdown),
                );
                session
                    .returning
                    .update(|d| d.records.ingress_shutdown_dropped += 1);
            }
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
        late_stream_records = decoder.late_stream_records,
        dropped,
        "server session stopped"
    );
}

pub struct ServerOptions {
    pub adaptive_fec_retention: bool,
    pub bind: SocketAddr,
    pub cert: std::path::PathBuf,
    pub key: std::path::PathBuf,
    pub token: std::path::PathBuf,
    pub target: Option<SocketAddr>,
    pub tcp_target: Option<SocketAddr>,
    pub stream_proxy: Option<ProxyAccess>,
    pub proxy: Option<Arc<super::proxy::Server>>,
    pub max_rate: u64,
    pub congestion: transport::Congestion,
    pub datagram_send_buffer_bytes: usize,
    pub stats: stats::Metrics,
}
pub async fn serve(options: ServerOptions) -> Result<()> {
    serve_with_ack_request(options, transport::AckRequest::Unchanged).await
}

/// Server-only opt-in experiment; ordinary callers retain the existing policy.
pub async fn serve_with_ack_request(
    options: ServerOptions,
    ack_request: transport::AckRequest,
) -> Result<()> {
    serve_with_mesh(options, ack_request, None).await
}

pub(crate) async fn serve_with_mesh(
    options: ServerOptions,
    ack_request: transport::AckRequest,
    mesh: Option<Arc<mesh::State>>,
) -> Result<()> {
    serve_with_budgets(
        options,
        ack_request,
        mesh,
        Arc::new(Semaphore::new(64)),
        Arc::new(Semaphore::new(128)),
    )
    .await
}

async fn serve_with_budgets(
    options: ServerOptions,
    ack_request: transport::AckRequest,
    mesh: Option<Arc<mesh::State>>,
    pending_connections: Arc<Semaphore>,
    data_connections: Arc<Semaphore>,
) -> Result<()> {
    ensure!(
        (64_000..=super::MAX_RATE_BPS).contains(&options.max_rate),
        "invalid server rate"
    );
    ensure!(
        options.target.is_some()
            || options.tcp_target.is_some()
            || options.stream_proxy.is_some()
            || options.proxy.is_some(),
        "configure a UDP target, a TCP target, a proxy, or several"
    );
    // A shared proxy endpoint also serves aggregate TCP downloads. Match their
    // validated ACK cadence; peers may clamp or decline this QUIC extension.
    // UDP-only servers retain their ordinary ACK request policy.
    let ack_request = if ack_request == transport::AckRequest::Unchanged
        && (options.proxy.is_some() || options.stream_proxy.is_some())
    {
        transport::AckRequest::EveryEight
    } else {
        ack_request
    };
    let endpoint = transport::server_with_session_config(
        options.bind,
        &options.cert,
        &options.key,
        options.congestion,
        options.datagram_send_buffer_bytes,
        ack_request,
        options.proxy.is_some(),
        Some(&options.key.with_extension("tickets")),
    )?;
    let secret = Arc::new(format!("Bearer {}", transport::token(&options.token)?));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let tcp_budget = options
        .proxy
        .as_ref()
        .map(|server| server.stream_budget())
        .unwrap_or_else(|| Arc::new(tcp::Budget::default()));
    let mut tasks = JoinSet::new();
    // This guard drops before the JoinSet, so cancellation queues an explicit
    // server close before an aborted H3 handler can send its generic NO_ERROR.
    let _lifetime = ServerLifetime {
        endpoint: endpoint.clone(),
        sessions: sessions.clone(),
    };
    let mut maintenance = interval(Duration::from_secs(1));
    let mut shutdown = Shutdown::new();
    options.stats.readiness(true, 0);
    info!(address=%endpoint.local_addr()?,target=?options.target,tcp_target=?options.tcp_target,stream_proxy=?options.stream_proxy,proxy=options.proxy.is_some(),congestion=?options.congestion,?ack_request,"HTTP/3 server ready");
    loop {
        tokio::select! {
            _=shutdown.wait()=>break,
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
                let Ok(permit)=pending_connections.clone().try_acquire_owned() else{incoming.refuse();continue};
                let sessions=sessions.clone(); let secret=secret.clone(); let target=options.target; let settings=ServerSessionSettings{max_rate:options.max_rate,adaptive_fec_retention:options.adaptive_fec_retention,mesh:mesh.clone(),data_connections:data_connections.clone(),proxy:options.proxy.clone(),tcp_budget:tcp_budget.clone(),tcp:tcp::Targets{fixed:options.tcp_target,proxy:options.stream_proxy,allow_associations:mesh.is_none() && options.proxy.is_none()}}; let metrics=options.stats.clone();
                tasks.spawn(async move {
                    let mut diagnostic=stats::ConnectionTrace::new(metrics.clone(),incoming.remote_address(),None,"incoming");
                    let result=server_connection(incoming,permit,sessions,secret,target,settings,metrics,&mut diagnostic).await;
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

#[derive(Clone)]
struct ServerSessionSettings {
    proxy: Option<Arc<super::proxy::Server>>,
    data_connections: Arc<Semaphore>,
    mesh: Option<Arc<mesh::State>>,
    max_rate: u64,
    adaptive_fec_retention: bool,
    tcp: tcp::Targets,
    tcp_budget: Arc<tcp::Budget>,
}

async fn cover_response(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ok: bool,
    deadline: tokio::time::Instant,
) -> Result<()> {
    tokio::time::timeout_at(deadline, async {
        stream
            .send_response(
                Response::builder()
                    .status(if ok {
                        StatusCode::OK
                    } else {
                        StatusCode::NOT_FOUND
                    })
                    .header("content-type", "text/html; charset=utf-8")
                    .body(())?,
            )
            .await?;
        stream
            .send_data(Bytes::from_static(if ok {
                WEBSITE.as_bytes()
            } else {
                b"Not found\n"
            }))
            .await?;
        stream.finish().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

fn stream_owner_stopped(stream_transport: bool, reason: Option<&quinn::ConnectionError>) -> bool {
    stream_transport
        && matches!(reason, Some(quinn::ConnectionError::ApplicationClosed(close))
        if close.error_code == quinn::VarInt::from_u32(STREAM_SESSION_STOP))
}

fn exit_stopped(reason: Option<&quinn::ConnectionError>) -> bool {
    matches!(reason, Some(quinn::ConnectionError::ApplicationClosed(close))
        if matches!(close.reason.as_ref(), b"server stopped" | b"shutdown" | b"proxy owner stopped"))
}

fn exit_terminated(reasons: impl Iterator<Item = Option<quinn::ConnectionError>>) -> bool {
    let mut observed = false;
    let mut all_h3_ended = true;
    for reason in reasons {
        observed = true;
        if exit_stopped(reason.as_ref()) {
            return true;
        }
        all_h3_ended &= matches!(reason, Some(quinn::ConnectionError::ApplicationClosed(close))
            if close.error_code == quinn::VarInt::from_u32(0x100));
    }
    observed && all_h3_ended
}

fn aggregate_protocol(protocol: Option<&[u8]>) -> Result<bool> {
    match protocol {
        Some(b"h3") => Ok(false),
        Some(STREAM_ALPN) => Ok(true),
        _ => bail!("unsupported aggregate application protocol"),
    }
}

fn session_profile(
    stream_transport: bool,
    streams: Option<&str>,
    proxy: Option<&str>,
) -> Result<(bool, bool)> {
    if !stream_transport {
        ensure!(
            streams.is_none() && proxy.is_none(),
            "stream profile requires braidpath-stream/2"
        );
        return Ok((false, false));
    }
    ensure!(
        matches!(streams, None | Some("2")) && matches!(proxy, None | Some("2")),
        "unsupported aggregate stream profile"
    );
    ensure!(
        streams.is_some() || proxy.is_some(),
        "stream protocol requires a stream profile"
    );
    Ok((streams.is_some(), proxy.is_some()))
}

#[allow(clippy::too_many_arguments)]
async fn server_connection(
    incoming: quinn::Incoming,
    permit: tokio::sync::OwnedSemaphorePermit,
    sessions: Sessions,
    secret: Arc<String>,
    target: Option<SocketAddr>,
    settings: ServerSessionSettings,
    metrics: stats::Metrics,
    diagnostic: &mut stats::ConnectionTrace,
) -> Result<()> {
    let ServerSessionSettings {
        proxy,
        data_connections,
        mesh,
        max_rate,
        adaptive_fec_retention,
        tcp,
        tcp_budget,
    } = settings;
    let conn = timeout(Duration::from_secs(5), incoming).await??;
    diagnostic.handshake_succeeded(&conn);
    let protocol = conn
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol);
    if protocol.as_deref() == Some(super::proxy::ALPN) {
        let Some(proxy) = proxy else {
            conn.close(0u32.into(), b"proxy disabled");
            bail!("proxy service disabled");
        };
        return proxy.connection(conn, permit).await;
    }
    let stream_transport = match aggregate_protocol(protocol.as_deref()) {
        Ok(stream_transport) => stream_transport,
        Err(error) => {
            conn.close(0u32.into(), b"unsupported application protocol");
            return Err(error);
        }
    };
    diagnostic.enter("http3", "http3_setup");
    let mut admission_deadline =
        tokio::time::Instant::now() + Duration::from_millis(ADMISSION_TIMEOUT_MS);
    let setup = async {
        Ok::<_, anyhow::Error>(
            tokio::time::timeout_at(
                admission_deadline,
                h3::server::builder()
                    .enable_datagram(true)
                    .max_field_section_size(8192)
                    .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone())),
            )
            .await??,
        )
    }
    .await;
    let mut h3 = match setup {
        Ok(h3) => h3,
        Err(error) => {
            conn.close(0u32.into(), b"HTTP/3 admission failed");
            return Err(error);
        }
    };
    diagnostic.succeeded();
    let mut joined: Option<(String, Arc<Session>, u8, u64, u64)> = None;
    let mut request: Option<h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>> = None;
    // Our clients send their first request within their 8-second (data) or
    // 4-second (control) attempt deadline. Unclassified connections hold the
    // small pending budget, so release it soon after that.

    // Data paths hold the shared connection permit. An authenticated mesh
    // control connection moves to the mesh budget and closes when idle.
    let mut pending_permit = Some(permit);
    let mut data_permit = None;
    let mut control_permit = None;
    let mut mesh_authenticated = false;
    let admission_started = Instant::now();
    diagnostic.enter_since("path_admission", "admission_wait", admission_started);
    // The admission timer surrounds the entire request processor, including
    // response writes. A peer withholding stream credit cannot suspend it.
    let (authenticated, admitted) = tokio::sync::oneshot::channel::<()>();
    let mut authenticated = Some(authenticated);
    let absolute_deadline = admission_deadline;
    let admission_guard = async {
        if tokio::time::timeout_at(absolute_deadline, admitted)
            .await
            .is_ok()
        {
            std::future::pending::<()>().await;
        }
    };
    let processing = async {
        loop {
            tokio::select! {
                            _=tokio::time::sleep_until(admission_deadline),if joined.is_none()=>{
                                if mesh_authenticated {break;}
                                diagnostic.enter_since("path_admission","admission_wait",admission_started);
                                diagnostic.failed("admission_deadline_elapsed");
                                bail!("session admission timed out")
                            },
                            accepted=h3.accept()=>{
                                let Some(resolver)=accepted? else{break};
                                diagnostic.enter("http3_request","request_resolve");
                                let request_deadline = tokio::time::Instant::now()+Duration::from_secs(5);
                                let request_deadline = if joined.is_none() {request_deadline.min(admission_deadline)} else {request_deadline};
                                let (req,mut stream)=tokio::time::timeout_at(request_deadline,resolver.resolve_request()).await??;
                                diagnostic.succeeded();
                                if let Some(mesh)=&mesh && req.uri().path().starts_with("/mesh/") {
                                    ensure!(!stream_transport,"mesh control requires h3 protocol");
                                    ensure!(joined.is_none(),"data connection cannot carry mesh control");
                                    if control_permit.is_none() && mesh.authorized(&req) {
                                        // Acquire before handling: no allocations or successful
                                        // responses may escape a full control budget.
                                        control_permit=Some(mesh.control_permit().context("mesh control connection limit reached")?);
                                        pending_permit=None;
                                        mesh_authenticated=true;
                                        if let Some(authenticated)=authenticated.take() {let _=authenticated.send(());}
                                    }
                                    if timeout(Duration::from_secs(5),mesh.handle(&req,&mut stream,conn.remote_address().ip())).await?? {
                                        admission_deadline=tokio::time::Instant::now()+mesh::CONTROL_IDLE;
                                    }
                                    continue;
                                }
                                if req.method()!=Method::POST || req.uri().path()!=SESSION_PATH {
                                    let ok=req.method()==Method::GET && req.uri().path()=="/";
                                    let deadline=if joined.is_none(){admission_deadline}else{tokio::time::Instant::now()+Duration::from_secs(5)};
                                    cover_response(&mut stream,ok,deadline).await?;
                                    if joined.is_some(){diagnostic.enter("established","connected");}
                                    else{diagnostic.enter_since("path_admission","admission_wait",admission_started);}
                                    continue
                                }
                                diagnostic.begin_admission();
                                let auth=req.headers().get("authorization").map(|h|h.as_bytes()).unwrap_or_default();
                                if !bool::from(auth.ct_eq(secret.as_bytes())) {
                                    diagnostic.rejected("authorization_rejected");
                                    let deadline=if joined.is_none(){admission_deadline}else{tokio::time::Instant::now()+Duration::from_secs(5)};
                                    cover_response(&mut stream,false,deadline).await?;
                                    if joined.is_some(){diagnostic.enter("established","connected");}
                                    else{diagnostic.enter_since("path_admission","admission_wait",admission_started);}
                                    continue
                                }
                                ensure!(!mesh_authenticated,"mesh control connection cannot carry a session");
                                if target.is_none() && tcp.fixed.is_none() && tcp.proxy.is_none() {
                                    stream.send_response(Response::builder().status(StatusCode::NOT_FOUND).body(())?).await?;
                                    stream.finish().await?;
                                    continue;
                                }
                                let requested_exit=req.headers().get("braidpath-exit").map(|v|v.to_str()).transpose()?;
                                if requested_exit != mesh.as_ref().map(|state|state.node_id()) {
                                    diagnostic.rejected("exit_identity_mismatch");
                                    let mut response=Response::builder().status(StatusCode::PRECONDITION_FAILED);
                                    if let Some(state)=&mesh {response=response.header("braidpath-exit",state.node_id());}
                                    stream.send_response(response.body(())?).await?;
                                    stream.finish().await?;
                                    continue;
                                }
                                if data_permit.is_none() {
                                    data_permit=Some(data_connections.clone().try_acquire_owned().context("data connection limit reached")?);
                                    pending_permit=None;
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
                                let capacity_probe_bps=req.headers().get("braidpath-capacity-probe-bps").map(|v|v.to_str()).transpose()?.unwrap_or("0").parse::<u64>()?;
                                capacity_probe::validate_format(capacity_probe_bps,req.headers().get("braidpath-capacity-probe-format").map(|v|v.to_str()).transpose()?)?;
                                let guided=req.headers().get("braidpath-probe-guided-recovery").map(|v|v.to_str()).transpose()?;
                                ensure!(guided.is_none() || guided==Some("1"),"invalid probe-guided recovery header");
                                let probe_guided_recovery=guided.is_some();
                                let small_fec_bytes=req.headers().get("braidpath-small-fec-bytes").map(|v|v.to_str()).transpose()?.unwrap_or("0").parse::<u16>()?;
                                let mixed_fec=mixed_fec_header(req.headers())?;
                                let fec_repairs=fec_repairs_header(req.headers())?;
                                let max_message_bytes = req.headers().get("braidpath-message-bytes").map(|v| v.to_str()).transpose()?.unwrap_or("1000").parse::<usize>()?;
                                let streams=req.headers().get("braidpath-streams").map(|v|v.to_str()).transpose()?;
                                let proxy=req.headers().get("braidpath-proxy").map(|v|v.to_str()).transpose()?;
                                let (streams,proxy)=session_profile(stream_transport,streams,proxy)?;
                                ensure!(!streams || tcp.fixed.is_some(),"TCP streams are not enabled on this server");
                                ensure!(!proxy || tcp.proxy.is_some(),"proxy streams are not enabled on this server");
                                let policy=Policy{max_message_bytes,streams,proxy,
            fec_repairs,small_fec_bytes,mixed_fec,probe_guided_recovery,capacity_probe_bps,adaptive:quality_schedule==Some("adaptive"),latency_target_ms,group_rates,quality_schedule:quality_schedule.is_some(),receiver_feedback:feedback.is_some(),fec:parse_fec(header("braidpath-fec")?).map_err(anyhow::Error::msg)?,redundancy:header("braidpath-redundancy")?.parse()?,rate,block_ms:header("braidpath-block-ms")?.parse()?,queue_ms:header("braidpath-queue-ms")?.parse()?};policy.validate()?;
                                if policy.fec==automatic_fec::AUTO {ensure!(req.headers().get_all("braidpath-auto-small").iter().count()==1 && req.headers().get("braidpath-auto-small").is_some_and(|v|v=="1"),"automatic small protection not negotiated");}
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
                                            let (tx,rx)=session_events(policy.streams,policy.proxy);let (stop,_)=watch::channel(false);
                                            let observation_notify=policy.adaptive.then(||Arc::new(Notify::new()));
                                            let session=Arc::new(Session{adaptive_fec_retention,generations:Mutex::new([None;MAX_PATHS]),empty_since:Mutex::new(Some(Instant::now())),events:tx,paths:Arc::new(Mutex::new(Vec::new())),stop,policy,observation_notify,ingress_drops:Arc::new(AtomicU64::new(0)),forward:metrics.scope(&sid,stats::FORWARD),returning:metrics.scope(&sid,stats::RETURN),finished:tokio::sync::Notify::new(),done:std::sync::atomic::AtomicBool::new(false)});
                                            map.insert(sid.clone(),session.clone());
                                            tokio::spawn(session_loop(session.clone(),rx,target,tcp,tcp_budget.clone()));
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
                                            paths.push(OutPath{id:pid,group,conn:conn.clone(),writer:writer::Writer::spawn(&conn),stream:stream_id,quality:Arc::new(Mutex::new(quality::State::new(generation))),capacity_probe:Arc::new(Mutex::new(capacity_probe::State::new(generation))),capacity_probe_enabled:capacity_probe_bps>0,epoch:Instant::now(),probe_reply:Arc::new(Mutex::new(None))});
                                            *session.empty_since.lock().expect("empty time lock")=None;
                                        }
                                        Some(session)
                                    }
                                };
                                let Some(session)=admitted else {
                                    diagnostic.rejected("session_expired");
                                    let mut response=Response::builder().status(StatusCode::GONE);
                                    if let Some(state)=&mesh {response=response.header("braidpath-exit",state.node_id());}
                                    stream.send_response(response.body(())?).await?;
                                    stream.finish().await?;
                                    // FIN only queues the response. Keep the connection alive long
                                    // enough for the client to receive 410 and select a fresh epoch.
                                    let _=timeout(Duration::from_secs(2),conn.closed()).await;
                                    bail!("session expired; a fresh session epoch is required");
                                };
                                metrics.register(&sid,pid,stream_id,stats::RETURN,&conn);
                                let trace_key=trace::PathKey{path_id:pid,generation,connection_id:conn.stable_id() as u64};
                                trace_path(&session.forward,trace::Stage::PathOpened,trace_key);
                                trace_path(&session.returning,trace::Stage::PathOpened,trace_key);
                                joined=Some((sid,session,pid,stream_id,generation));
                                let mut response=Response::builder().status(200).header("braidpath-version","1").header("braidpath-max-payload",MAX_PAYLOAD);if max_message_bytes > MAX_PAYLOAD {response=response.header("braidpath-message-bytes",max_message_bytes);}
                                if feedback.is_some(){response=response.header("braidpath-feedback","2");}
                                if let Some(state)=&mesh {response=response.header("braidpath-exit",state.node_id());}
                                if small_fec_bytes>0 {response=response.header("braidpath-small-fec-bytes",small_fec_bytes);}
                                if mixed_fec {response=response.header("braidpath-mixed-fec","1");}
                                if header("braidpath-fec")?=="auto" {response=response.header("braidpath-auto-small","1");}
                                if streams {response=response.header("braidpath-streams","2");}
                                if proxy {response=response.header("braidpath-proxy","2");}
                                if fec_repairs==2 {response=response.header("braidpath-fec-repairs","2");}
                                if capacity_probe_bps>0 {response=response.header("braidpath-capacity-probe-bps",capacity_probe_bps).header("braidpath-capacity-probe-format",capacity_probe::FORMAT);}
                                if probe_guided_recovery {response=response.header("braidpath-probe-guided-recovery","1");}
                                if let Some(scheduler)=quality_schedule {response=response.header("braidpath-scheduler",scheduler);}stream.send_response(response.body(())?).await?;
                                request=Some(stream);
                                if let Some(authenticated)=authenticated.take() {let _=authenticated.send(());}
                                diagnostic.admitted();
                                info!(path=pid,remote=%conn.remote_address(),"authenticated path joined");
                            },
                            data=conn.read_datagram()=>{
                                let data=data?;
                                if let Some((_,session,pid,stream,generation))=&joined {
                                    let trace_key=trace::PathKey{path_id:*pid,generation:*generation,connection_id:conn.stable_id() as u64};
                                    trace_http(&session.forward,trace::Stage::PeerHttpReceived,&data,*stream,session.policy.receiver_feedback,trace_key,None);
                                    session.forward.path(*pid,|p|p.http_datagrams_received+=1);
                                    if let Ok(payload)=wire::http_payload(&data,*stream) && payload.len()<=(if session.policy.receiver_feedback{quality::MAX_FRAME}else{wire::MAX_WIRE}) {
                                        match measured_payload(&session.paths,*pid,payload,session.policy.receiver_feedback,&session.returning,session.observation_notify.as_deref()) {
                                        Ok(Some(payload))=>{if let Err(error)=session.events.try_send(Event::Wire(*pid,payload)){if let Event::Wire(_,payload)=rejected_item(&error){session.forward.trace_symbol(trace::Stage::SymbolDropped,payload,Some(trace_key),Some(data.len()),Some(queue_trace_reason(QueueLayer::Receiver,&error)));}session.ingress_drops.fetch_add(1,Ordering::Relaxed);queue_error(&session.forward,QueueLayer::Receiver,&error,Some(*pid));}},Ok(None)=>{},Err(_)=>{trace_http(&session.forward,trace::Stage::SymbolDropped,&data,*stream,session.policy.receiver_feedback,trace_key,Some(trace::Reason::InvalidHttp));session.forward.path(*pid,|p|p.invalid_http_datagrams_dropped+=1);}}
                                    } else {trace_http(&session.forward,trace::Stage::SymbolDropped,&data,*stream,session.policy.receiver_feedback,trace_key,Some(trace::Reason::InvalidHttp));session.forward.path(*pid,|p|p.invalid_http_datagrams_dropped+=1);session.forward.update(|d|d.records.invalid_symbols_dropped+=1);}
                                }
                            },
                            body=async {request.as_mut().expect("guarded request").recv_data().await},if request.is_some()=>{
                                let _=body?; break; // No reliable data is defined for this request; FIN ends membership.
                            }
                        }
        }
        Ok(())
    };
    let result: Result<()> = tokio::select! {
        biased;
        _=admission_guard=>{
            diagnostic.enter_since("path_admission","admission_wait",admission_started);
            diagnostic.failed("admission_deadline_elapsed");
            Err(anyhow::anyhow!("session admission timed out"))
        },
        result=processing=>result,
    };
    // Classify the original close/error before our cleanup closes the connection.
    diagnostic.finish(result.as_ref().err());
    let owner_stopped = stream_owner_stopped(stream_transport, conn.close_reason().as_ref());
    conn.close(0u32.into(), b"request closed");
    if let Some((sid, session, pid, _, generation)) = joined {
        let trace_key = trace::PathKey {
            path_id: pid,
            generation,
            connection_id: conn.stable_id() as u64,
        };
        trace_path(&session.forward, trace::Stage::PathClosed, trace_key);
        trace_path(&session.returning, trace::Stage::PathClosed, trace_key);
        let ended = {
            let mut map = sessions.lock().expect("sessions lock");
            let mut paths = session.paths.lock().expect("paths lock");
            paths.retain(|p| p.id != pid || p.conn.stable_id() != conn.stable_id());
            let last = paths.is_empty();
            let ended = owner_stopped || (last && !session.policy.adaptive);
            if ended {
                let _ = session.stop.send(true);
                map.remove(&sid);
                for path in paths.iter() {
                    path.conn.close(0u32.into(), b"stream session stopped");
                }
            } else if last {
                *session.empty_since.lock().expect("empty time lock") = Some(Instant::now());
            }
            ended
        };
        if ended
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
        if ended {
            metrics.retire_session(&sid);
        }
        info!(path = pid, "path left");
    }
    drop((pending_permit, data_permit, control_permit));
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
    pub adaptive_fec_retention: bool,
    pub rotate_source_port: bool,
    pub listen: SocketAddr,
    /// Local TCP listener; each connection becomes one reliable stream.
    pub tcp_listen: Option<SocketAddr>,
    /// Local SOCKS5 and HTTP CONNECT listener for addressed streams.
    pub proxy_listen: Option<SocketAddr>,
    /// Internal proxy frontend attached to the aggregate session instead of a listener.
    pub stream_connector: Option<StreamConnector>,
    pub entrances: Vec<SocketAddr>,
    pub interfaces: Vec<String>,
    pub path_binds: Vec<SocketAddr>,
    pub datagram_send_buffer_bytes: usize,
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
    enabled: bool,
}

enum EntranceUpdates {
    Addresses(watch::Receiver<Vec<SocketAddr>>, mesh::Uplink),
    Routes(watch::Receiver<Vec<mesh::Route>>),
}
impl EntranceUpdates {
    fn current(&mut self) -> Vec<mesh::Route> {
        match self {
            Self::Addresses(rx, uplink) => rx
                .borrow_and_update()
                .iter()
                .copied()
                .map(|address| mesh::Route {
                    address,
                    uplink: uplink.clone(),
                })
                .collect(),
            Self::Routes(rx) => rx.borrow_and_update().clone(),
        }
    }
    async fn changed(&mut self) -> Result<()> {
        match self {
            Self::Addresses(rx, _) => rx.changed().await?,
            Self::Routes(rx) => rx.changed().await?,
        }
        Ok(())
    }
}
async fn entrances_changed(updates: &mut Option<EntranceUpdates>) -> Vec<mesh::Route> {
    if let Some(updates) = updates
        && updates.changed().await.is_ok()
    {
        return updates.current();
    }
    std::future::pending().await
}

#[cfg(test)]
fn reconcile_entrances(
    desired: &[SocketAddr],
    configs: &mut Vec<PathConfig>,
    inflight: &[bool; MAX_PATHS],
    endpoints: &mut [Option<quinn::Endpoint>; MAX_PATHS],
    paths: &Paths,
    rotations: &mut [scheduler::Rotation; MAX_PATHS],
) {
    reconcile_routes(
        &desired.iter().copied().map(Into::into).collect::<Vec<_>>(),
        configs,
        inflight,
        endpoints,
        paths,
        rotations,
    );
}
fn matches_route(config: &PathConfig, route: &mesh::Route) -> bool {
    config.remote == route.address
        && config.interface == route.uplink.interface
        && config.bind == route.uplink.bind.map(|ip| SocketAddr::new(ip, 0))
        && config.group == route.uplink.group
}

fn reconcile_routes(
    desired: &[mesh::Route],
    configs: &mut Vec<PathConfig>,
    inflight: &[bool; MAX_PATHS],
    endpoints: &mut [Option<quinn::Endpoint>; MAX_PATHS],
    paths: &Paths,
    rotations: &mut [scheduler::Rotation; MAX_PATHS],
) {
    // Keep IDs and connections for unchanged addresses, irrespective of the
    // discovery order. Never reuse a slot while its old handshake is in flight.
    for (id, config) in configs.iter_mut().enumerate() {
        if config.enabled
            && !inflight[id]
            && !desired.iter().any(|route| matches_route(config, route))
        {
            config.enabled = false;
            let mut paths = paths.lock().expect("paths lock");
            for path in paths.iter().filter(|p| usize::from(p.id) == id) {
                path.conn.close(0u32.into(), b"entrance retired");
            }
            paths.retain(|p| usize::from(p.id) != id);
            if let Some(endpoint) = endpoints[id].take() {
                endpoint.close(0u32.into(), b"entrance retired");
            }
        }
    }
    for remote in desired {
        if configs
            .iter()
            .any(|c| c.enabled && matches_route(c, remote))
        {
            continue;
        }
        if let Some((id, config)) = configs
            .iter_mut()
            .enumerate()
            .find(|(id, c)| !c.enabled && !inflight[*id])
        {
            config.remote = remote.address;
            config.interface = remote.uplink.interface.clone();
            config.bind = remote.uplink.bind.map(|ip| SocketAddr::new(ip, 0));
            config.group = remote.uplink.group;
            config.enabled = true;
            config.attempted = false;
            // Preserve the generation counter when reusing a path ID so the
            // selected exit's replay protection accepts the replacement.
            rotations[id] = scheduler::Rotation::default();
        } else if configs.len() < MAX_PATHS {
            configs.push(PathConfig {
                remote: remote.address,
                interface: remote.uplink.interface.clone(),
                bind: remote.uplink.bind.map(|ip| SocketAddr::new(ip, 0)),
                group: remote.uplink.group,
                generation: rand::random::<u64>() >> 1,
                attempted: false,
                enabled: true,
            });
        }
    }
}

/// Keep the local application socket while explicitly replacing an expired session epoch.
pub async fn client(options: ClientOptions) -> Result<()> {
    client_with_entrances(options, None).await
}

/// Mesh control publishes addresses only when membership or a lease changes.
/// Existing paths and the local UDP socket survive entrance replacement.
pub(crate) async fn client_with_entrances(
    options: ClientOptions,
    entrances: Option<watch::Receiver<Vec<SocketAddr>>>,
) -> Result<()> {
    client_with_health(options, entrances, None).await
}

pub(crate) async fn client_with_health(
    options: ClientOptions,
    entrances: Option<watch::Receiver<Vec<SocketAddr>>>,
    health: Option<watch::Sender<mesh::PathHealth>>,
) -> Result<()> {
    client_inner(
        options,
        entrances.map(|rx| EntranceUpdates::Addresses(rx, mesh::Uplink::default())),
        health,
        None,
    )
    .await
}

/// Mesh credentials are shared; the selected exit must be bound independently
/// on every admission, including retries through a different entrance.
pub(crate) async fn client_with_mesh_exit(
    options: ClientOptions,
    entrances: Option<watch::Receiver<Vec<SocketAddr>>>,
    health: Option<watch::Sender<mesh::PathHealth>>,
    exit: String,
) -> Result<()> {
    let mut options = options;
    ensure!(
        options.interfaces.len() <= 1,
        "mesh proxy accepts one uplink interface"
    );
    let uplink = mesh::Uplink {
        interface: entrances.as_ref().and_then(|_| options.interfaces.pop()),
        ..Default::default()
    };
    client_inner(
        options,
        entrances.map(|rx| EntranceUpdates::Addresses(rx, uplink)),
        health,
        Some(exit),
    )
    .await
}

pub(crate) async fn client_with_routes(
    options: ClientOptions,
    routes: watch::Receiver<Vec<mesh::Route>>,
    health: watch::Sender<mesh::PathHealth>,
    exit: String,
) -> Result<()> {
    client_inner(
        options,
        Some(EntranceUpdates::Routes(routes)),
        Some(health),
        Some(exit),
    )
    .await
}

async fn client_inner(
    mut options: ClientOptions,
    mut entrances: Option<EntranceUpdates>,
    health: Option<watch::Sender<mesh::PathHealth>>,
    exit: Option<String>,
) -> Result<()> {
    if entrances.is_some() {
        // Path replacement needs authenticated monotonic generations, carried
        // by feedback v2 even when adaptive pacing is disabled.
        options.policy.receiver_feedback = true;
    }
    options.policy.validate()?;
    ensure!(
        entrances.is_none()
            || (options.interfaces.is_empty()
                && options.path_binds.is_empty()
                && options.path_groups.is_empty()),
        "dynamic routes carry their own uplink configuration"
    );
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
    ensure!(
        options.policy.streams == options.tcp_listen.is_some(),
        "TCP streams require a TCP listener"
    );
    ensure!(
        options.policy.proxy
            == (options.proxy_listen.is_some() || options.stream_connector.is_some()),
        "proxy streams require a proxy listener"
    );
    let socket = Arc::new(UdpSocket::bind(options.listen).await?);
    let mut listeners = tcp::Listeners::default();
    // Neither listener authenticates its callers: every caller spends the
    // tunnel credential, and a proxy caller also gets a UDP relay.
    let exposed = |address: SocketAddr, kind: &str| {
        if !address.ip().is_loopback() {
            warn!(listen = %address, "{kind} listener is not on loopback; it has no authentication");
        }
    };
    if let Some(address) = options.tcp_listen {
        let listener = TcpListener::bind(address).await?;
        info!(listen=%listener.local_addr()?,"TCP listener bound");
        exposed(address, "TCP");
        listeners.fixed = Some(Arc::new(listener));
    }
    if let Some(address) = options.proxy_listen {
        let listener = TcpListener::bind(address).await?;
        info!(listen=%listener.local_addr()?,"proxy listener bound");
        exposed(address, "proxy");
        listeners.proxy = Some(Arc::new(listener));
    }
    let mut shutdown = Shutdown::new();
    loop {
        let result = client_session(
            &options,
            socket.clone(),
            listeners.clone(),
            &mut shutdown,
            &mut entrances,
            health.as_ref(),
            exit.as_deref(),
        )
        .await;
        if (options.policy.adaptive || entrances.is_some())
            && options
                .stream_connector
                .as_ref()
                .is_none_or(|connector| !connector.is_closed())
            && result
                .as_ref()
                .err()
                .is_some_and(|error| error.is::<SessionExpired>())
        {
            info!(
                "server session expired; creating a fresh authenticated epoch on the existing local listener"
            );
            tokio::select! {
                _=shutdown.wait()=>return Ok(()),
                _=tokio::time::sleep(Duration::from_secs(1))=>{}
            }
            continue;
        }
        return result;
    }
}

async fn client_session(
    options: &ClientOptions,
    socket: Arc<UdpSocket>,
    listeners: tcp::Listeners,
    shutdown: &mut Shutdown,
    entrances: &mut Option<EntranceUpdates>,
    health: Option<&watch::Sender<mesh::PathHealth>>,
    exit: Option<&str>,
) -> Result<()> {
    let token = transport::token(&options.token)?;
    let sid = transport::hex(&rand::random::<[u8; 16]>());
    let paths: Paths = Arc::new(Mutex::new(Vec::new()));
    let forward = options.stats.scope(&sid, stats::FORWARD);
    let returning = options.stats.scope(&sid, stats::RETURN);
    let (wire_tx, mut wire_rx) = mpsc::channel::<(u8, Bytes)>(WIRE_QUEUE);
    let mut tasks = JoinSet::new();
    let mut endpoints: [Option<quinn::Endpoint>; MAX_PATHS] = std::array::from_fn(|_| None);
    let mut configs = Vec::<PathConfig>::new();
    let mut rotations: [scheduler::Rotation; MAX_PATHS] =
        std::array::from_fn(|_| Default::default());
    let mut inflight = [false; MAX_PATHS];
    let mut elective_inflight = [false; MAX_PATHS];
    let mut delivery_health: [path_health::DeliveryHealth; MAX_PATHS] =
        std::array::from_fn(|_| Default::default());
    let mut reachability: [liveness::Liveness; MAX_PATHS] = Default::default();
    let mut telemetry: [transport::ProxyTelemetry; MAX_PATHS] =
        std::array::from_fn(|_| Default::default());
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
    let recover_paths = options.policy.adaptive || entrances.is_some();
    let mut desired = entrances.as_mut().map(EntranceUpdates::current);
    if let Some(routes) = &desired {
        reconcile_routes(
            routes,
            &mut configs,
            &inflight,
            &mut endpoints,
            &paths,
            &mut rotations,
        );
    } else {
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
                    enabled: true,
                });
            }
        }
    }
    let (tx, rx) = mpsc::channel(QUEUE);
    let (stop, stop_rx) = watch::channel(false);
    let observation_notify = options.policy.adaptive.then(|| Arc::new(Notify::new()));
    tasks.spawn(sender(
        rx,
        paths.clone(),
        options.policy.clone(),
        stop_rx,
        forward.clone(),
        observation_notify.clone(),
    ));
    // Streams do not survive a session epoch; a new epoch accepts new connections.
    let mut streams = tcp::Mux::client(
        listeners,
        &options.policy,
        forward.clone(),
        options.stream_connector.clone(),
    );
    let small_threshold = ingress::small_threshold(&options.policy);
    let mut input = vec![0; 65536];
    let mut peers: HashMap<SocketAddr, (u32, Instant)> = HashMap::new();
    let mut reverse = HashMap::new();
    let mut next_flow = 0u32;
    let mut next_id = 0u64;
    let mut decoder = Receiver::configured(
        Duration::from_millis(options.policy.queue_ms),
        options.adaptive_fec_retention,
    )
    .with_dual_repairs(options.policy.fec_repairs == 2);
    publish_retention(&decoder, &returning);
    let mut messages = messages::Reassembly::new(
        options.policy.max_message_bytes,
        options.policy.admission_lifetime(),
    )
    .with_scope(returning.clone());
    let mut delivery = local_delivery::Queue::new(
        returning.clone(),
        Duration::from_millis(
            options
                .policy
                .queue_ms
                .min(options.policy.latency_target_ms),
        ),
    );
    let mut tick = interval(Duration::from_millis(200));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut drops = 0u64;
    let mut has_session = false;
    let mut announced = false;
    let mut last_stats = 0u64;
    let result:Result<()>=async {loop {
        if let Some(mux)=streams.as_mut() {
            mux.service_io();
            mux.flush(&mut tcp::Out{tx:&tx,next_id:&mut next_id,scope:&forward,small_threshold});
        }
        tokio::select! {
            _=shutdown.wait()=>break,
            _=async {options.stream_connector.as_ref().expect("connector").closed().await},if options.stream_connector.is_some()=>break,
            updated=entrances_changed(entrances)=>{
                ensure!(!updated.is_empty() && updated.len()<=MAX_PATHS,"invalid entrance update");
                desired=Some(updated);
            },
            _=retention_deadline(&decoder)=>{decoder.expire_adaptive(Instant::now());publish_retention(&decoder,&returning);},
            _=messages::deadline(&messages)=>{messages.expire(Instant::now()); publish_messages(&mut messages, &returning);},
            completed=delivery.ready()=>drops+=completed,
            _=tick.tick()=>{
                let now_us=epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                if options.policy.streams || options.policy.proxy {
                    ensure!(!exit_terminated(paths.lock().expect("paths lock").iter().map(|path|path.conn.close_reason())), "selected stream exit shut down");
                }
                if let Some(desired)=&desired {
                    reconcile_routes(desired,&mut configs,&inflight,&mut endpoints,&paths,&mut rotations);
                    let configured=configs.iter().filter(|c|c.enabled).count();
                    options.stats.state(|s|s.configured_paths=configured);
                }
                peers.retain(|_,(id,last)|{if last.elapsed()<Duration::from_secs(60){true}else{reverse.remove(id);false}});
                let current=paths.lock().expect("paths lock").clone();
                if options.policy.streams || options.policy.proxy {
                    for path in &current { telemetry[usize::from(path.id)].report(&path.conn,"client",exit.unwrap_or("local")); }
                }
                if let Some(health)=health {
                    let mut samples = Vec::new();
                    for (id, config) in configs.iter().enumerate().filter(|(_, c)| c.enabled) {
                        if let Some(path) = current.iter().find(|p| usize::from(p.id) == id) {
                            let elapsed = quality_time(path);
                            let q = path.quality.lock().expect("quality").snapshot_at(elapsed);
                            let stalled = delivery_health[id].stalled(elapsed, &q);
                            // Stream ACKs may be carried on a different path. Native
                            // QUIC ACK progress still qualifies this path's reachability,
                            // even before eight measured application symbols were sent.
                            reachability[id].observe(&path.conn, Instant::now());
                            let silent = reachability[id].silent();
                            if stalled && path.conn.close_reason().is_none() {
                                tracing::debug!(path=id, group=path.group, "mesh data delivery stalled; reconnecting");
                                path.conn.close(0u32.into(), b"mesh delivery stalled");
                            }
                            let estimate = q.sender_estimate;
                            let failed = stalled || silent || path.conn.close_reason().is_some();
                            samples.push(mesh::PathSample { address: config.remote, group: path.group,
                                failed,
                                delivered: !failed && estimate.sample_symbols >= 8 && estimate.delivered_updated_us.is_some_and(|at| elapsed.saturating_sub(at) < 2_000_000) && estimate.updated_us.is_some_and(|at| elapsed.saturating_sub(at) < 2_000_000),
                                rtt_ms: path.conn.rtt().as_secs_f64() * 1000.0, loss: estimate.loss_rate });
                        } else if config.attempted && !inflight[id] {
                            samples.push(mesh::PathSample { address: config.remote, group: config.group, failed: true, delivered: false, rtt_ms: 0.0, loss: 0.0 });
                        }
                    }
                    let addresses = samples.iter().filter(|s| !s.failed).map(|s| s.address).collect();
                    health.send_replace(mesh::PathHealth{checked:Instant::now(),addresses,samples});
                }
                let live=current.iter().filter(|p|p.conn.close_reason().is_none()).count();
                if announced && !recover_paths && live==0 {bail!("all paths failed");}
                // With no working path, try every configured entrance (at most
                // eight) so blackholes cannot block a healthy later candidate.
                // Background reconnects/rotations keep the two-attempt bound.
                let attempt_limit=if live==0 {MAX_PATHS}else{2};
                for (id,config) in configs.iter_mut().enumerate() {
                    if inflight.iter().filter(|busy|**busy).count()>=attempt_limit {break;}
                    if inflight[id] || !config.enabled {continue;}
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
                    // An initial failed path can join an already established
                    // session without coupling recovery to adaptive rate control.
                    // Previously joined fixed-mode paths keep their old policy.
                    let recovery=(!config.attempted || recover_paths
                        || (has_session && endpoints[id].is_none()))
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
                    let ack_request=if metrics.legacy_recovery(){transport::AckRequest::Unchanged}else{transport::AckRequest::EveryEight};
                    let congestion=options.congestion;let rejoin=has_session;
                    let exit=exit.map(str::to_owned);
                    let datagram_send_buffer_bytes=options.datagram_send_buffer_bytes;
                    let mut cancelled=stop.subscribe();
                    inflight[id]=true;
                    elective_inflight[id]=elective;
                    forward.path(id as u8,|p|{p.reconnect_attempts+=1;if elective{p.rotation_attempts+=1;}});
                    tasks.spawn(async move {
                        let mut diagnostic=stats::ConnectionTrace::new(metrics,config.remote,Some(id as u8),"quic_connect");
                        let attempt:Result<Option<Rejoined>>=async {
                            let endpoint=transport::client_bound_with_session_alpn(config.remote,&ca,config.interface.as_deref(),congestion,bind,datagram_send_buffer_bytes,ack_request,policy.streams || policy.proxy)?;
                            info!(path=id,generation,local=%endpoint.local_addr()?,remote=%config.remote,"path attempt source socket");
                            let connected=tokio::select! {
                                biased;
                                _=cancelled.changed()=>{
                                    endpoint.close(0u32.into(),b"connection attempt cancelled");
                                    diagnostic.cancelled();
                                    return Ok(None);
                                },
                                connected=timeout(Duration::from_secs(8),
                                    connect_path(&endpoint,config.remote,&name,&token,&sid,id as u8,config.group,generation,rejoin,&policy,exit.as_deref(),&mut diagnostic))=>connected??
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
                if !announced && !recover_paths && configs.iter().all(|c|c.attempted) && !inflight.iter().any(|v|*v) {
                    ensure!(live>0,"no authenticated paths available");
                    announced=true;
                    options.stats.readiness(true,configs.iter().filter(|c|c.enabled).count());
                    info!(listen=%socket.local_addr()?,paths=live,congestion=?options.congestion,"UDP client ready");
                }
                if now_us.saturating_sub(last_stats)>=2_000_000 {
                    last_stats=now_us;
                    info!(session=%sid,live,configured=configs.iter().filter(|c|c.enabled).count(),originals=decoder.originals,recovered=decoder.recovered,duplicates=decoder.duplicates,late_stream_records=decoder.late_stream_records,invalid=decoder.invalid,drops,ingress_drops=ingress_drops.load(Ordering::Relaxed),"client path status");
                    if let Some(mux)=streams.as_mut(){mux.report_progress();}
                }
            },
            rebuilt=rejoin_rx.recv()=>{
                let Some((pid,generation,rebuild))=rebuilt else {bail!("path supervisor ended")};
                let id=usize::from(pid);inflight[id]=false;
                if desired.as_ref().is_some_and(|addresses|!addresses.iter().any(|route| matches_route(&configs[id], route))) {
                    if let Ok((value,_))=rebuild {value.endpoint.close(0u32.into(),b"entrance retired");}
                    continue;
                }
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
                                writer:writer::Writer::spawn(&value.conn),
                                quality:Arc::new(Mutex::new(quality::State::new(generation))),capacity_probe:Arc::new(Mutex::new(capacity_probe::State::new(generation))),capacity_probe_enabled:options.policy.capacity_probe_bps>0,epoch:Instant::now(),
                                probe_reply:Arc::new(Mutex::new(None))});
                        }
                        if let Some(old)=endpoints[id].replace(value.endpoint) {old.close(0u32.into(),b"path replaced");}
                        tasks.spawn(drive_client_path(value.conn,value.stream,value.driver,value.request,value.send,diagnostic,pid,generation,
                            wire_tx.clone(),ingress_drops.clone(),returning.clone(),forward.clone(),paths.clone(),options.policy.receiver_feedback,observation_notify.clone()));
                        has_session=true;
                        if recover_paths && !announced {
                            options.stats.readiness(true,configs.iter().filter(|c|c.enabled).count());
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
                trace_payload(&forward,trace::Stage::RecordIngress,&input[..n],None);
                if n>options.policy.max_message_bytes {drops+=1;trace_payload(&forward,trace::Stage::RecordDropped,&input[..n],Some(trace::Reason::Oversize));forward.update(|d|d.records.application_oversize_dropped+=1);continue;}
                if !peers.contains_key(&peer) {
                    if peers.len()>=MAX_FLOWS {drops+=1;trace_payload(&forward,trace::Stage::RecordDropped,&input[..n],Some(trace::Reason::FlowLimit));forward.update(|d|d.records.application_flow_limit_dropped+=1);continue;}
                    next_flow=next_flow.checked_add(1).filter(|flow| *flow < associate::FLAG).context("flow id exhausted")?;
                    peers.insert(peer,(next_flow,created));reverse.insert(next_flow,peer);
                }
                let (flow,last)=peers.get_mut(&peer).expect("inserted peer");*last=created;
                let parts=messages::split(*flow,&mut next_id,input[..n].to_vec(),options.policy.max_message_bytes)?;
                if !enqueue_message(&tx,parts,created,&forward,ingress::small_threshold(&options.policy)) {
                    drops+=1;
                } else {forward.update(|d|{d.records.ingress_queue_enqueued+=1;});}
            },
            data=wire_rx.recv()=>{
                let Some((pid,data))=data else {bail!("all receivers ended")};
                let records=receive_records(&mut decoder,&returning,pid,&data,streams.as_ref());
                let decoded=Instant::now();
                for record in records {
                    if let Some(mux)=streams.as_mut() && (stream::stream_id(record.flow).is_some() || associate::is_flow(record.flow)) {mux.receive(record);continue}
                    let Some((record, decoded)) = messages.receive(record, decoded) else {publish_messages(&mut messages, &returning);continue;};
                    publish_messages(&mut messages, &returning);
                    if let Some(peer)=reverse.get(&record.flow) {
                        if let Some((_,last))=peers.get_mut(peer) {*last=Instant::now();}
                        drops+=delivery.send(&socket,Some(*peer),record,pid,decoded);
                    } else {returning.trace_record(trace::Stage::RecordDropped,&record,None,Some(trace::Reason::FlowUnavailable));returning.update(|d|d.records.udp_target_flow_dropped+=1);returning.path(pid,|p|p.udp_target_flow_dropped+=1);}
                }
            },
            wake=stream_wake(&mut streams)=>streams.as_mut().expect("stream adapter").handle(wake),
        }
        while let Some(completion)=tasks.try_join_next() {completion.context("path task failed")?;}
    }Ok(())}.await;
    // Publish the owner's explicit epoch close before dropping H3 drivers.
    for endpoint in endpoints.iter().flatten() {
        if options.policy.streams || options.policy.proxy {
            endpoint.close(STREAM_SESSION_STOP.into(), b"stream session stopped");
        } else {
            endpoint.close(0u32.into(), b"client session stopped");
        }
    }
    if let Some(mux) = streams.as_mut() {
        mux.close_all();
    }
    messages.close();
    publish_messages(&mut messages, &returning);
    delivery.close();
    decoder.close_retention();
    publish_retention(&decoder, &returning);
    let _ = stop.send(true);
    options
        .stats
        .readiness(false, configs.iter().filter(|c| c.enabled).count());
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
    while let Ok((_, data)) = wire_rx.try_recv() {
        returning.trace_symbol(
            trace::Stage::SymbolDropped,
            &data,
            None,
            None,
            Some(trace::Reason::Shutdown),
        );
        returning.update(|d| d.records.receiver_shutdown_dropped += 1);
    }
    options.stats.state(|s| {
        s.shutdown_complete = joined;
        s.drain_incomplete |= !joined;
    });
    options.stats.retire_session(&sid);
    info!(
        originals = decoder.originals,
        recovered = decoder.recovered,
        late_stream_records = decoder.late_stream_records,
        "client session receiver stopped"
    );
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
    generation: u64,
    tx: mpsc::Sender<(u8, Bytes)>,
    ingress_drops: Arc<AtomicU64>,
    returning: Scope,
    measurement_scope: Scope,
    path_view: Paths,
    feedback: bool,
    observation_notify: Option<Arc<Notify>>,
) {
    // Dropping the last SendRequest closes the HTTP/3 connection.
    let _send = send;
    let trace_key = trace::PathKey {
        path_id: pid,
        generation,
        connection_id: conn.stable_id() as u64,
    };
    trace_path(&returning, trace::Stage::PathOpened, trace_key);
    trace_path(&measurement_scope, trace::Stage::PathOpened, trace_key);
    let result:Result<()>=async {loop {tokio::select! {
                        e=driver.wait_idle()=>return Err(e.into()),
                        body=request.recv_data()=>{let _=body?;return Ok(())},
                        d=conn.read_datagram()=>match d {
                            Ok(d)=>{
                                trace_http(&returning,trace::Stage::PeerHttpReceived,&d,stream,feedback,trace_key,None);
                                returning.path(pid,|p|p.http_datagrams_received+=1);
                                if let Ok(p)=wire::http_payload(&d,stream) && p.len()<=(if feedback{quality::MAX_FRAME}else{wire::MAX_WIRE}) {
                                    match measured_payload(&path_view,pid,p,feedback,&measurement_scope,observation_notify.as_deref()) {Ok(Some(p))=>{if let Err(error)=tx.try_send((pid,p)){returning.trace_symbol(trace::Stage::SymbolDropped,&rejected_item(&error).1,Some(trace_key),Some(d.len()),Some(queue_trace_reason(QueueLayer::Receiver,&error)));ingress_drops.fetch_add(1,Ordering::Relaxed);queue_error(&returning,QueueLayer::Receiver,&error,Some(pid));}},Ok(None)=>{},Err(_)=>{trace_http(&returning,trace::Stage::SymbolDropped,&d,stream,feedback,trace_key,Some(trace::Reason::InvalidHttp));returning.path(pid,|p|p.invalid_http_datagrams_dropped+=1);}}
                                }else{trace_http(&returning,trace::Stage::SymbolDropped,&d,stream,feedback,trace_key,Some(trace::Reason::InvalidHttp));returning.path(pid,|p|p.invalid_http_datagrams_dropped+=1);returning.update(|d|d.records.invalid_symbols_dropped+=1);}
                            },
                            Err(e)=>return Err(e.into()),
                        }
                    }}}.await;
    let normal = diagnostic.finish(result.as_ref().err());
    trace_path(&returning, trace::Stage::PathClosed, trace_key);
    trace_path(&measurement_scope, trace::Stage::PathClosed, trace_key);
    if normal {
        info!(context=%diagnostic.context(),"client path closed");
    } else {
        warn!(context=%diagnostic.context(),error=?result.err(),"client path ended");
    }
    if conn.close_reason().is_none() {
        conn.close(0u32.into(), b"path ended");
    }
}

type H3Client = h3::client::Connection<h3_quinn::Connection, Bytes>;
type H3Send = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3Request = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
fn validate_message_echo(headers: &http::HeaderMap, expected: usize) -> Result<()> {
    let actual = headers
        .get("braidpath-message-bytes")
        .map(|v| v.to_str())
        .transpose()?
        .unwrap_or("1000")
        .parse::<usize>()?;
    ensure!(
        actual == expected,
        "UDP message fragmentation capability not negotiated"
    );
    Ok(())
}

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
    exit: Option<&str>,
    diagnostic: &mut stats::ConnectionTrace,
) -> Result<(quinn::Connection, u64, H3Client, H3Request, H3Send)> {
    macro_rules! admit {
        ($conn:expr) => {
            admit_path(
                $conn, name, token, sid, pid, group, generation, rejoin, policy, exit, diagnostic,
            )
        };
    }
    // With a resumption ticket the session request travels as 0-RTT data, so
    // admission completes one round trip after the first packet.
    let (conn, accepted) = match endpoint.connect(remote, name)?.into_0rtt() {
        Ok(early) => early,
        Err(connecting) => {
            let conn = connecting.await?;
            diagnostic.handshake_succeeded(&conn);
            return admit!(conn).await;
        }
    };
    let outcome = diagnostic.early_data(&conn, accepted);
    let mut rejection = outcome.clone();
    let error = tokio::select! {
        admitted = admit!(conn.clone()) => match admitted {
            Ok(admitted) => return Ok(admitted),
            Err(error) => error,
        },
        Ok(_) = rejection.wait_for(|o| *o == Some(stats::EarlyData::Rejected)) => anyhow::anyhow!("0-RTT rejected"),
    };
    let mut outcome = outcome;
    let rejected = outcome
        .wait_for(Option::is_some)
        .await
        .is_ok_and(|o| *o == Some(stats::EarlyData::Rejected));
    if !rejected {
        return Err(error);
    }
    // The server lost or refused the ticket; early data never reached it.
    info!(path = pid, "0-RTT rejected; retrying with a full handshake");
    conn.close(0u32.into(), b"0-RTT rejected");
    diagnostic.retry_handshake();
    let conn = endpoint.connect(remote, name)?.await?;
    diagnostic.handshake_succeeded(&conn);
    admit!(conn).await
}

#[allow(clippy::too_many_arguments)]
async fn admit_path(
    conn: quinn::Connection,
    name: &str,
    token: &str,
    sid: &str,
    pid: u8,
    group: u8,
    generation: u64,
    rejoin: bool,
    policy: &Policy,
    exit: Option<&str>,
    diagnostic: &mut stats::ConnectionTrace,
) -> Result<(quinn::Connection, u64, H3Client, H3Request, H3Send)> {
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
        .header(
            "braidpath-fec",
            if policy.fec == automatic_fec::AUTO {
                "auto".to_owned()
            } else {
                policy.fec.to_string()
            },
        )
        .header("braidpath-redundancy", u16::from(policy.redundancy))
        .header("braidpath-rate", policy.rate)
        .header("braidpath-block-ms", policy.block_ms)
        .header("braidpath-queue-ms", policy.queue_ms);
    if policy.max_message_bytes > MAX_PAYLOAD {
        req = req.header("braidpath-message-bytes", policy.max_message_bytes);
    }
    if let Some(exit) = exit {
        req = req.header("braidpath-exit", exit);
    }
    if policy.fec == automatic_fec::AUTO {
        req = req.header("braidpath-auto-small", "1");
    }
    if policy.small_fec_bytes > 0 {
        req = req.header("braidpath-small-fec-bytes", policy.small_fec_bytes);
    }
    if policy.mixed_fec {
        req = req.header("braidpath-mixed-fec", "1");
    }
    if policy.streams {
        req = req.header("braidpath-streams", "2");
    }
    if policy.proxy {
        req = req.header("braidpath-proxy", "2");
    }
    if policy.fec_repairs == 2 {
        req = req.header("braidpath-fec-repairs", "2");
    }
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
    if policy.probe_guided_recovery {
        req = req.header("braidpath-probe-guided-recovery", "1");
    }
    if policy.capacity_probe_bps > 0 {
        req = req
            .header("braidpath-capacity-probe-bps", policy.capacity_probe_bps)
            .header("braidpath-capacity-probe-format", capacity_probe::FORMAT);
    }
    let req = req.body(())?;
    // Sent without waiting for peer SETTINGS, so that 0-RTT saves its round trip.
    let mut stream = send.send_request(req).await?;
    let response = tokio::select! {e=driver.wait_idle()=>bail!("HTTP/3 closed during admission: {e}"),r=stream.recv_response()=>r?};
    // Check before 410 handling: an old or different exit must never trigger
    // an automatic fresh epoch with shared cluster credentials.
    ensure!(
        response
            .headers()
            .get("braidpath-exit")
            .and_then(|v| v.to_str().ok())
            == exit
            && response.status() != StatusCode::PRECONDITION_FAILED,
        "mesh exit identity mismatch or unsupported peer; selected exit {:?}",
        exit
    );
    if response.status() == StatusCode::GONE {
        diagnostic.rejected("session_expired");
        conn.close(0u32.into(), b"session epoch expired");
        return Err(SessionExpired.into());
    }
    diagnostic.enter("http3", "peer_settings");
    // Poll the driver so peer SETTINGS are processed before datagrams are used.
    tokio::select! {
        e=driver.wait_idle()=>bail!("HTTP/3 closed before settings: {e}"),
        _=async {while !send.settings().enable_datagram(){tokio::time::sleep(Duration::from_millis(1)).await;}}=>{}
    }
    diagnostic.succeeded();
    diagnostic.enter("path_admission", "admission");
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
        policy.fec != automatic_fec::AUTO
            || response
                .headers()
                .get_all("braidpath-auto-small")
                .iter()
                .count()
                == 1
                && response
                    .headers()
                    .get("braidpath-auto-small")
                    .is_some_and(|v| v == "1"),
        "automatic small protection not negotiated"
    );
    ensure!(
        policy.small_fec_bytes == 0
            || response
                .headers()
                .get("braidpath-small-fec-bytes")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u16>().ok())
                == Some(policy.small_fec_bytes),
        "small-record FEC not negotiated"
    );
    ensure!(
        mixed_fec_header(response.headers())? == policy.mixed_fec,
        "mixed FEC not negotiated"
    );
    let echoed_streams = response
        .headers()
        .get("braidpath-streams")
        .map(|v| v.to_str())
        .transpose()?;
    let echoed_proxy = response
        .headers()
        .get("braidpath-proxy")
        .map(|v| v.to_str())
        .transpose()?;
    ensure!(
        session_profile(policy.streams || policy.proxy, echoed_streams, echoed_proxy)?
            == (policy.streams, policy.proxy),
        "aggregate stream profile not negotiated"
    );
    validate_fec_repairs_echo(response.headers(), policy.fec_repairs)?;
    validate_message_echo(response.headers(), policy.max_message_bytes)?;
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
    ensure!(
        !policy.probe_guided_recovery
            || response
                .headers()
                .get("braidpath-probe-guided-recovery")
                .and_then(|v| v.to_str().ok())
                == Some("1"),
        "probe-guided recovery not negotiated"
    );
    ensure!(
        policy.capacity_probe_bps == 0
            || response
                .headers()
                .get("braidpath-capacity-probe-bps")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                == Some(policy.capacity_probe_bps),
        "capacity probe budget not negotiated"
    );
    capacity_probe::validate_format(
        policy.capacity_probe_bps,
        response
            .headers()
            .get("braidpath-capacity-probe-format")
            .and_then(|v| v.to_str().ok()),
    )?;
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
mod entrance_tests;

#[cfg(test)]
mod reprobe_tests;

#[cfg(all(test, unix))]
mod shutdown_tests;

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

#[cfg(test)]
mod stream_profile_tests {
    use super::*;

    #[test]
    fn reliable_server_ingress_keeps_a_bounded_four_path_burst() {
        for (streams, proxy) in [(true, false), (false, true), (true, true)] {
            let (tx, mut rx) = session_events(streams, proxy);
            // Four QUIC readers may each run one ready burst before the
            // decoder actor gets CPU. The previous 256-slot queue lost 75%.
            for id in 0..1024u32 {
                tx.try_send(Event::Wire(
                    (id % 4) as u8,
                    Bytes::copy_from_slice(&id.to_be_bytes()),
                ))
                .unwrap_or_else(|_| {
                    panic!("a bounded ready burst must not create local packet loss")
                });
            }
            assert_eq!(tx.max_capacity(), WIRE_QUEUE);
            for id in 1024..WIRE_QUEUE as u32 {
                assert!(
                    tx.try_send(Event::Wire(
                        (id % 4) as u8,
                        Bytes::copy_from_slice(&id.to_be_bytes()),
                    ))
                    .is_ok()
                );
            }
            assert!(matches!(
                tx.try_send(Event::Wire(0, Bytes::new())),
                Err(mpsc::error::TrySendError::Full(_))
            ));
            for id in 0..WIRE_QUEUE as u32 {
                let Event::Wire(path, data) = rx.try_recv().unwrap() else {
                    panic!("unexpected event")
                };
                assert_eq!(path, (id % 4) as u8);
                assert_eq!(data.as_ref(), id.to_be_bytes());
            }
            assert_eq!(tx.capacity(), WIRE_QUEUE);
            rx.close();
            assert!(matches!(
                tx.try_send(Event::Wire(0, Bytes::new())),
                Err(mpsc::error::TrySendError::Closed(_))
            ));
        }
    }

    #[test]
    fn raw_udp_server_ingress_retains_its_latency_queue_budget() {
        let (tx, _rx) = session_events(false, false);
        assert_eq!(tx.max_capacity(), QUEUE);
        for _ in 0..QUEUE {
            assert!(tx.try_send(Event::Wire(0, Bytes::new())).is_ok());
        }
        assert!(matches!(
            tx.try_send(Event::Wire(0, Bytes::new())),
            Err(mpsc::error::TrySendError::Full(_))
        ));
    }

    fn peer_close(code: u32, reason: &'static [u8]) -> quinn::ConnectionError {
        quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: code.into(),
            reason: Bytes::from_static(reason),
        })
    }

    #[test]
    fn an_explicit_stream_owner_stop_is_distinct_from_a_recoverable_path_close() {
        let stopped = peer_close(STREAM_SESSION_STOP, b"stream session stopped");
        assert!(stream_owner_stopped(true, Some(&stopped)));
        assert!(!stream_owner_stopped(false, Some(&stopped)));
        for reason in [
            peer_close(0, b"entrance retired"),
            peer_close(0, b"mesh delivery stalled"),
            quinn::ConnectionError::TimedOut,
            quinn::ConnectionError::LocallyClosed,
        ] {
            assert!(!stream_owner_stopped(true, Some(&reason)));
        }
        assert!(!stream_owner_stopped(true, None));
    }

    #[test]
    fn a_stopped_exit_ends_its_flows_but_a_relay_outage_does_not() {
        for reason in [
            b"server stopped".as_slice(),
            b"shutdown",
            b"proxy owner stopped",
        ] {
            assert!(exit_stopped(Some(&peer_close(0, reason))));
        }
        assert!(!exit_stopped(Some(&peer_close(
            0x100,
            b"Connection was closed by the server"
        ))));
        assert!(!exit_stopped(Some(&peer_close(0, b"entrance retired"))));
        assert!(!exit_stopped(Some(&quinn::ConnectionError::TimedOut)));
        assert!(!exit_stopped(Some(&quinn::ConnectionError::LocallyClosed)));
        assert!(!exit_stopped(None));
    }

    #[test]
    fn one_h3_path_end_does_not_terminate_a_healthy_aggregate() {
        let h3_end = || Some(peer_close(0x100, b"Connection was closed by the server"));
        assert!(!exit_terminated([h3_end(), None].into_iter()));
        assert!(!exit_terminated(
            [h3_end(), Some(quinn::ConnectionError::TimedOut)].into_iter()
        ));
        assert!(exit_terminated([h3_end(), h3_end()].into_iter()));
        assert!(exit_terminated(
            [Some(peer_close(0, b"server stopped")), None].into_iter()
        ));
        assert!(!exit_terminated(std::iter::empty()));
    }

    #[test]
    fn aggregate_protocol_requires_explicit_supported_alpn() {
        assert!(!aggregate_protocol(Some(b"h3")).unwrap());
        assert!(aggregate_protocol(Some(STREAM_ALPN)).unwrap());
        assert!(aggregate_protocol(None).is_err());
        assert!(aggregate_protocol(Some(super::super::proxy::ALPN)).is_err());
        assert!(aggregate_protocol(Some(b"braidpath-stream/1")).is_err());
    }

    #[test]
    fn reliable_stream_profiles_cannot_cross_protocol_or_version() {
        assert_eq!(session_profile(false, None, None).unwrap(), (false, false));
        assert_eq!(
            session_profile(true, Some("2"), None).unwrap(),
            (true, false)
        );
        assert_eq!(
            session_profile(true, None, Some("2")).unwrap(),
            (false, true)
        );
        assert_eq!(
            session_profile(true, Some("2"), Some("2")).unwrap(),
            (true, true)
        );
        for (transport, streams, proxy) in [
            (false, Some("1"), None),
            (false, None, Some("2")),
            (false, Some("2"), Some("2")),
            (true, None, None),
            (true, Some("1"), None),
            (true, None, Some("1")),
            (true, Some("2"), Some("1")),
        ] {
            assert!(session_profile(transport, streams, proxy).is_err());
        }
    }
}
