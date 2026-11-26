//! Reliable byte streams over the unreliable aggregate record service.
//!
//! A stream travels as ordinary records on two flows, one for data and one for
//! acknowledgments, so multipath scheduling and FEC apply to it unchanged. The
//! sender retains bytes until they are cumulatively acknowledged, repairs loss
//! from selective acknowledgments, a send-time threshold and probe timeouts, and
//! obeys the receiver's window. Per-path congestion control stays below this
//! layer: it adds no rate controller and promises no delivery deadline.
//!
//! Sequence space equals byte offsets, plus one virtual byte at the final size
//! for FIN. This module performs no I/O; callers supply the clock.
use super::{MAX_PATHS, MAX_PAYLOAD};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const STREAM_FLAG: u32 = 1 << 30;
pub const ACK_FLAG: u32 = 1 << 29;
// Bit 28 marks an addressed TCP stream; bit 27 identifies UDP associations.
// Keep the addressed bit in stream IDs while excluding the association bit.
pub const MAX_STREAM_ID: u32 = ((1 << 27) - 1) | (1 << 28);
const DATA_HEADER: usize = 10;
pub const MAX_SEGMENT: usize = MAX_PAYLOAD - DATA_HEADER;
/// Negotiated reliable carriers may amortize framing over larger chunks.
pub(crate) const RELIABLE_PAYLOAD: usize = 32 * 1024 + DATA_HEADER;
/// Both peers assume this window before the first acknowledgment.
pub const INITIAL_WINDOW: u64 = 256 * 1024;
/// A stream's flight plus the data held behind one hole while it is repaired,
/// about two RTTs: at 110 ms, 8 MiB capped a stream near 600 Mbit/s without
/// loss and far lower after each one.
pub const MAX_WINDOW: u64 = 32 * 1024 * 1024;
const MAX_OFFSET: u64 = 1 << 62;
const ACK_HEADER: usize = 26;
const MAX_RANGES: usize = 64;
/// Recently stored out-of-order offsets the next acknowledgments describe first.
const RECENT_RANGES: usize = 2 * MAX_RANGES;
const ACK_EVERY: u32 = 16;
const ACK_DELAY: Duration = Duration::from_millis(2);
/// A bulk receiver acknowledges by segment count at most this often. Every
/// acknowledgement repeats its ranges, so at hundreds of Mbit/s count-driven
/// acknowledgements alone can fill an asymmetric uplink; a few milliseconds is
/// small against loss detection that waits for reordering of a whole RTT.
const ACK_SPACING: Duration = Duration::from_millis(4);
const INITIAL_RTT: Duration = Duration::from_millis(250);
const RTT_WINDOW: Duration = Duration::from_secs(1);
const REORDER_BASE: f64 = 1.25;
const REORDER_MAX: f64 = 2.0;
const MAX_PTO: Duration = Duration::from_secs(2);
const DEAD_AFTER: Duration = Duration::from_secs(30);
/// Copies sent without a loss declaration may produce up to this many duplicate
/// bytes that are not evidence of reordering.
const EXPECTED_DUPLICATES_MAX: u64 = 2 * (RELIABLE_PAYLOAD - DATA_HEADER) as u64;
/// A persistent SACK hole in a bulk flight may get one bounded extra copy.
/// Small tails already have their separate probe policy.
const HEAD_PROBE_MIN_FLIGHT: u64 = 64 * 1024;

const UNKNOWN_PATH: usize = MAX_PATHS;

const DATA: u8 = 0;
const ACK: u8 = 1;
const RESET: u8 = 2;
const FIN_BIT: u8 = 2;

pub fn data_flow(id: u32) -> u32 {
    STREAM_FLAG | id
}
pub fn ack_flow(id: u32) -> u32 {
    STREAM_FLAG | ACK_FLAG | id
}
/// Whether a stream-lane record carries acknowledgments.
pub fn is_ack_flow(flow: u32) -> bool {
    stream_id(flow).is_some() && flow & ACK_FLAG != 0
}
pub(crate) fn is_ack_request(payload: &[u8]) -> bool {
    payload.len() == DATA_HEADER && payload[..2] == [DATA, 0]
}
/// The stream identifier of a stream-lane record, if it is one.
pub fn stream_id(flow: u32) -> Option<u32> {
    (flow & STREAM_FLAG != 0 && flow & !(STREAM_FLAG | ACK_FLAG | MAX_STREAM_ID) == 0)
        .then_some(flow & MAX_STREAM_ID)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ack {
    /// Every sequence number below this has been received.
    pub cumulative: u64,
    /// The sender may transmit data offsets below this.
    pub limit: u64,
    /// Total payload bytes received more than once; spurious-retransmit evidence.
    pub duplicate_bytes: u64,
    /// Received data above `cumulative`: ascending, disjoint `[start, end)`.
    pub ranges: Vec<(u64, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Data {
        offset: u64,
        fin: bool,
        data: Vec<u8>,
    },
    Ack(Ack),
    Reset,
}
impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Data { offset, fin, data } => {
                let mut out = Vec::with_capacity(DATA_HEADER + data.len());
                out.extend([DATA, if *fin { FIN_BIT } else { 0 }]);
                out.extend(offset.to_be_bytes());
                out.extend(data);
                out
            }
            Frame::Ack(ack) => {
                let mut out = Vec::with_capacity(ACK_HEADER + 8 * ack.ranges.len());
                out.push(ACK);
                out.extend(ack.cumulative.to_be_bytes());
                out.extend(ack.limit.to_be_bytes());
                out.extend(ack.duplicate_bytes.to_be_bytes());
                out.push(ack.ranges.len() as u8);
                for (start, end) in &ack.ranges {
                    out.extend(((start - ack.cumulative) as u32).to_be_bytes());
                    out.extend(((end - start) as u32).to_be_bytes());
                }
                out
            }
            Frame::Reset => vec![RESET],
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let u64_at = |i: usize| Some(u64::from_be_bytes(b.get(i..i + 8)?.try_into().ok()?));
        let u32_at = |i: usize| {
            Some(u64::from(u32::from_be_bytes(
                b.get(i..i + 4)?.try_into().ok()?,
            )))
        };
        match *b.first()? {
            DATA if b.len() >= DATA_HEADER && b[1] & !FIN_BIT == 0 => {
                let offset = u64_at(2)?;
                let data = b[DATA_HEADER..].to_vec();
                (offset.checked_add(data.len() as u64)? < MAX_OFFSET).then_some(Frame::Data {
                    offset,
                    fin: b[1] & FIN_BIT != 0,
                    data,
                })
            }
            ACK if b.len() >= ACK_HEADER => {
                let count = usize::from(b[25]);
                if count > MAX_RANGES || b.len() != ACK_HEADER + 8 * count {
                    return None;
                }
                let cumulative = u64_at(1)?;
                let mut ranges = Vec::with_capacity(count);
                let mut floor = cumulative;
                for i in 0..count {
                    let at = ACK_HEADER + 8 * i;
                    let start = cumulative.checked_add(u32_at(at)?)?;
                    let end = start.checked_add(u32_at(at + 4)?)?;
                    // A range must leave a gap below it, else it would be cumulative.
                    if start <= floor || end <= start || end >= MAX_OFFSET {
                        return None;
                    }
                    ranges.push((start, end));
                    floor = end;
                }
                (cumulative < MAX_OFFSET).then_some(Frame::Ack(Ack {
                    cumulative,
                    limit: u64_at(9)?,
                    duplicate_bytes: u64_at(17)?,
                    ranges,
                }))
            }
            RESET if b.len() == 1 => Some(Frame::Reset),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    pub max_data_segment_bytes: u64,
    pub pmtu_splits: u64,
    pub opened: u64,
    pub completed: u64,
    pub reset_local: u64,
    pub reset_peer: u64,
    pub rejected: u64,
    pub active: u64,
    /// Local socket events waiting for the stream actor.
    pub pending_io_events: u64,
    /// Reliable-stream bytes held in the local sender queue.
    pub local_sender_queued_bytes: u64,
    /// Retained stream bytes, including unsent bytes and ACK-waiting data.
    pub send_retained_bytes: u64,
    pub send_unsent_bytes: u64,
    pub send_window_blocked_streams: u64,
    pub receive_buffered_bytes: u64,
    pub receive_out_of_order_bytes: u64,
    pub bytes_from_application: u64,
    pub bytes_to_application: u64,
    /// Payload bytes from accepted native records, including partial overlaps.
    pub native_return_accepted_bytes: u64,
    pub segments_sent: u64,
    pub retransmitted_segments: u64,
    pub retransmitted_bytes: u64,
    /// Bounded additional short-tail copies queued, before native admission.
    pub tail_probes_queued: u64,
    /// Bounded additional copies of head-of-line repairs queued, before native admission.
    pub head_copies_queued: u64,
    /// Retransmissions caused by an original leaving the local sender queue unsent.
    pub local_drop_retransmits: u64,
    /// Small stream frames requeued after leaving the local queue unsent.
    pub local_small_retry_frames: u64,
    pub probe_timeouts: u64,
    pub spurious_retransmit_reports: u64,
    pub duplicate_bytes_received: u64,
    pub acks_sent: u64,
    pub acks_received: u64,
    /// SOCKS5 UDP associations opened, and their datagrams.
    pub udp_associations: u64,
    pub udp_datagrams_to_tunnel: u64,
    pub udp_datagrams_from_tunnel: u64,
    pub udp_datagrams_dropped: u64,
    /// Game-only association events handled outside the TCP completion FIFO.
    pub udp_io_events_prioritized: u64,
    pub udp_io_wait_us_sum: u64,
    pub udp_io_wait_us_max: u64,
}

#[derive(Clone, Copy)]
struct Rtt {
    smoothed: Option<Duration>,
    variation: Duration,
    minimum: Duration,
    high: [Duration; 2],
    window_start: Option<Instant>,
    first_sample: Option<Instant>,
    newest_transmission: Option<Instant>,
}
impl Default for Rtt {
    fn default() -> Self {
        Self {
            smoothed: None,
            variation: Duration::ZERO,
            minimum: Duration::MAX,
            high: [Duration::ZERO; 2],
            window_start: None,
            first_sample: None,
            newest_transmission: None,
        }
    }
}
impl Rtt {
    fn sample_transmission(&mut self, sent_at: Instant, now: Instant) {
        // A bounded SACK can report previously omitted, older ranges in a
        // later ACK. They release bytes but cannot supersede a measurement
        // from a newer original on this same route.
        if self.newest_transmission.is_none_or(|at| sent_at > at) {
            self.newest_transmission = Some(sent_at);
            self.sample(now.saturating_duration_since(sent_at), now);
        }
    }
    fn sample(&mut self, rtt: Duration, now: Instant) {
        match self.smoothed {
            None => {
                self.smoothed = Some(rtt);
                self.variation = rtt / 2;
            }
            Some(s) => {
                let error = s.abs_diff(rtt);
                self.variation = (self.variation * 3 + error) / 4;
                self.smoothed = Some((s * 7 + rtt) / 8);
            }
        }
        self.minimum = self.minimum.min(rtt);
        self.first_sample.get_or_insert(now);
        // Two adjacent windows keep the slowest active path visible: with
        // multipath, segments routed over it are often the last to arrive.
        let age = self
            .window_start
            .map(|start| now.saturating_duration_since(start));
        if age.is_none_or(|age| age >= RTT_WINDOW) {
            self.high = [
                rtt,
                if age.is_some_and(|age| age < RTT_WINDOW * 2) {
                    self.high[0]
                } else {
                    Duration::ZERO
                },
            ];
            self.window_start = Some(now);
        } else {
            self.high[0] = self.high[0].max(rtt);
        }
    }
    fn observed_high(&self, now: Instant) -> Option<Duration> {
        self.observed_max(now)
            .zip(self.smoothed)
            .map(|(high, s)| high.max(s + 4 * self.variation))
    }
    /// The largest sample of the two recent windows, without the variance
    /// bound. The first sample's variance is half the RTT, so the bound
    /// alone would make a new stream wait three RTTs.
    fn observed_max(&self, now: Instant) -> Option<Duration> {
        let age = now.saturating_duration_since(self.window_start?);
        if age < RTT_WINDOW {
            Some(self.high[0].max(self.high[1]))
        } else if age < RTT_WINDOW * 2 {
            Some(self.high[0])
        } else {
            None
        }
    }

    /// The windowed maximum, or the variance bound while few samples exist.
    /// A slower path is unobserved until its first acknowledgment returns, so
    /// the initial estimate remains a floor for one initial RTT of sampling.
    fn high(&self, now: Instant) -> Duration {
        let Some(smoothed) = self.smoothed else {
            return INITIAL_RTT;
        };
        let observed = self.observed_high(now).unwrap_or(smoothed);
        if self
            .first_sample
            .is_some_and(|at| now.saturating_duration_since(at) < INITIAL_RTT)
        {
            observed.max(INITIAL_RTT)
        } else {
            observed
        }
    }
}

#[derive(Clone)]
struct Segment {
    end: u64,
    path: usize,
    tried_paths: u8,
    sent_at: Instant,
    expected_ack_rtt: Duration,
    transmissions: u32,
    network_transmissions: u32,
    admitted_on_datagram: bool,
    /// Consecutive retransmissions without any acknowledgment progress between them.
    stalls: u32,
    /// Backed-off deadline while stalled; otherwise timed from `sent_at`.
    deadline: Option<Instant>,
    probe_transmission: Option<u32>,
    local_retry_pending: bool,
    /// The native reliable writer owns recovery while its path is reachable.
    reliable: Option<Arc<AtomicBool>>,
}

impl Segment {
    /// A local requeue preserves the already selected first repair round.
    fn first_datagram_repair_ready(&self) -> bool {
        self.admitted_on_datagram
            && self.network_transmissions == 1 + u32::from(self.local_retry_pending)
    }
}

/// Native segments share the reachability flag of the writer which owns them.
struct CarrierFlight {
    reachable: Arc<AtomicBool>,
    offsets: BTreeSet<u64>,
}

/// One reliable sending half. Data offsets start at zero.
///
/// A transmission is lost once it is older than the reorder threshold and a
/// later transmission was delivered, or older than 1.5 thresholds without that
/// evidence. While acknowledgments still progress, random loss is repaired at
/// that pace; only retransmissions with no progress since the previous attempt
/// back off. Each segment has its own timer, so a tail loss never waits for an
/// exponentially backed-off connection timer.
pub struct Sender {
    pub(crate) pmtu_splits: u64,
    pub(crate) ordered_udp_gap_repair: bool,
    buffer: VecDeque<u8>,
    base: u64,
    written: u64,
    next: u64,
    fin: Option<u64>,
    fin_sent: bool,
    limit: u64,
    acked: u64,
    segments: BTreeMap<u64, Segment>,
    fresh: [BTreeSet<(Instant, u64)>; MAX_PATHS + 1],
    reliable_flight: Vec<CarrierFlight>,
    repeated: BTreeSet<(Instant, u64)>,
    lost: BTreeSet<u64>,
    rack: Option<Instant>,
    rtt: Rtt,
    path_rtt: [Rtt; MAX_PATHS],
    transport_rtt: [Duration; MAX_PATHS],
    reorder: f64,
    peer_duplicates: u64,
    last_progress: Option<Instant>,
    probe_at: Option<Instant>,
    probe_count: u32,
    probe_due: bool,
    open_pending: bool,
    open_sent: bool,
    tail_probe_due: bool,
    /// The head-of-line segment and the repair to follow with one copy once admitted.
    head_copy: Option<(u64, u32)>,
    head_probe: Option<(u64, u32, Instant)>,
    head_probe_due: bool,
    last_head_probe: Option<Instant>,
    /// Copies awaiting their admission/drop callback. Keep them independently
    /// of segments: the original can be acknowledged while its copy is queued.
    pending_copies: BTreeMap<(u64, u32), u64>,
    /// Duplicate bytes the peer may report because of copies admitted to Quinn.
    expected_duplicates: u64,
}

/// A frame chosen for transmission, with the identity a local drop reports.
pub struct Transmit {
    pub frame: Frame,
    pub start: u64,
    pub transmission: u32,
    /// The network send round. Local requeues and extra copies share it.
    pub(crate) network_attempt: u32,
    /// Repair an original DATAGRAM once on the same carrier class.
    pub(crate) first_datagram_repair: bool,
    pub retransmission: bool,
    pub tail_probe: bool,
    pub head_copy: bool,
    /// This attempt replaces an original that never reached native admission.
    pub local_retry: bool,
    /// Path already carrying a stalled reliable segment; rescue prefers a sibling.
    pub avoid_path: Option<u8>,
    /// Bitmask of paths already tried for this segment across network retries.
    pub avoid_mask: u8,
}

impl Sender {
    /// `open` makes an empty stream announce itself with a zero-length segment.
    pub fn new(open: bool) -> Self {
        Self {
            pmtu_splits: 0,
            ordered_udp_gap_repair: false,
            buffer: VecDeque::new(),
            base: 0,
            written: 0,
            next: 0,
            fin: None,
            fin_sent: false,
            limit: INITIAL_WINDOW,
            acked: 0,
            segments: BTreeMap::new(),
            fresh: Default::default(),
            reliable_flight: Vec::new(),
            repeated: BTreeSet::new(),
            lost: BTreeSet::new(),
            rack: None,
            rtt: Rtt::default(),
            path_rtt: [Rtt::default(); MAX_PATHS],
            transport_rtt: [Duration::ZERO; MAX_PATHS],
            reorder: REORDER_BASE,
            peer_duplicates: 0,
            last_progress: None,
            probe_at: None,
            probe_count: 0,
            probe_due: false,
            open_pending: open,
            open_sent: false,
            tail_probe_due: false,
            head_copy: None,
            head_probe: None,
            head_probe_due: false,
            last_head_probe: None,
            pending_copies: BTreeMap::new(),
            expected_duplicates: 0,
        }
    }
    pub fn push(&mut self, data: &[u8]) {
        assert!(self.fin.is_none(), "data after local end of stream");
        self.buffer.extend(data);
        self.written += data.len() as u64;
    }
    pub fn finish(&mut self) {
        self.fin.get_or_insert(self.written);
    }
    /// Highest data offset the application has supplied.
    pub fn written(&self) -> u64 {
        self.written
    }
    /// (next offset, retained segments, fresh timers, backed-off timers, ready losses).
    pub(crate) fn recovery_state(&self) -> (u64, usize, usize, usize, usize) {
        (
            self.next,
            self.segments.len(),
            self.fresh.iter().map(BTreeSet::len).sum(),
            self.repeated.len(),
            self.lost.len(),
        )
    }
    pub fn limit(&self) -> u64 {
        self.limit
    }
    /// Low-frequency diagnostics, outside the per-packet recovery path.
    pub(crate) fn recovery_diagnostics(&self, now: Instant) -> impl std::fmt::Debug {
        (
            self.reorder,
            self.buffer.len(),
            self.buffer.capacity(),
            self.segments.first_key_value().map(|(start, segment)| {
                (
                    *start,
                    segment.path,
                    segment.transmissions,
                    segment.stalls,
                    now.saturating_duration_since(segment.sent_at).as_millis(),
                    self.path_threshold(segment.path, now).as_millis(),
                )
            }),
        )
    }
    /// Read-only gauges, excluding FIN's virtual sequence byte.
    pub(crate) fn pending_data(&self) -> (u64, u64, bool) {
        let unsent = self.written.saturating_sub(self.next);
        (
            self.written.saturating_sub(self.base),
            unsent,
            unsent > 0 && self.next >= self.limit,
        )
    }

    /// Lowest data offset still retained for retransmission.
    pub fn retained_from(&self) -> u64 {
        self.base
    }
    pub fn finished(&self) -> bool {
        self.fin.is_some_and(|f| self.acked > f)
    }
    /// No acknowledgment progress while the peer owed one for too long.
    pub fn failed(&self, now: Instant) -> bool {
        self.awaiting_peer()
            && self
                .last_progress
                .is_some_and(|at| now.saturating_duration_since(at) >= DEAD_AFTER)
    }
    pub fn has_transmit(&self) -> bool {
        self.tail_probe_due
            || self.head_probe_due
            || self.head_copy_ready().is_some()
            || !self.lost.is_empty()
            || (self.next < self.written && self.next < self.limit)
            || (self.fin == Some(self.next) && !self.fin_sent)
            || self.probe_due
            || self.open_due()
    }
    fn open_due(&self) -> bool {
        self.open_pending && !self.open_sent && self.written == 0
    }
    fn awaiting_peer(&self) -> bool {
        !self.segments.is_empty() || self.needs_probe()
    }
    /// Ask for lost stream ACKs even when native QUIC owns payload recovery.
    fn needs_probe(&self) -> bool {
        !self.reliable_flight.is_empty()
            || (self.segments.is_empty()
                && ((self.open_pending && self.open_sent)
                    || (self.next < self.written && self.next >= self.limit)))
    }
    fn threshold(&self, now: Instant) -> Duration {
        self.rtt.high(now).mul_f64(self.reorder) + Duration::from_millis(2)
    }
    fn path_threshold(&self, path: usize, now: Instant) -> Duration {
        if path == UNKNOWN_PATH {
            return self.threshold(now);
        }
        // QUIC already measured this route before stream admission, including
        // its variance. A slow unrelated route must not delay loss recovery
        // here. Stream samples additionally cover the ACK's return route and
        // receiver scheduling.
        self.transport_rtt[path]
            .max(self.path_rtt[path].observed_max(now).unwrap_or_default())
            .mul_f64(self.reorder)
            + Duration::from_millis(2)
    }
    fn probe_interval(&self, now: Instant) -> Duration {
        let base = self.rtt.high(now) * 2 + Duration::from_millis(20);
        (base * 2u32.pow(self.probe_count.min(6))).min(MAX_PTO)
    }
    fn unschedule(&mut self, start: u64) {
        let segment = &self.segments[&start];
        if let Some(owner) = &segment.reliable {
            if let Some(i) = self
                .reliable_flight
                .iter()
                .position(|f| Arc::ptr_eq(&f.reachable, owner))
            {
                let offsets = &mut self.reliable_flight[i].offsets;
                offsets.remove(&start);
                if offsets.is_empty() {
                    self.reliable_flight.swap_remove(i);
                }
            }
            return;
        }
        match segment.deadline {
            Some(at) => self.repeated.remove(&(at, start)),
            None => self.fresh[segment.path].remove(&(segment.sent_at, start)),
        };
    }
    fn mark_lost(&mut self, start: u64) {
        self.unschedule(start);
        self.segments
            .get_mut(&start)
            .expect("lost segment")
            .reliable = None;
        self.lost.insert(start);
    }
    fn send_segment(&mut self, start: u64, end: u64, now: Instant, probe: bool) -> Transmit {
        let fin = self.fin.is_some_and(|f| end == f + 1);
        let data_end = if fin { end - 1 } else { end };
        let from = (start - self.base) as usize;
        let to = (data_end - self.base) as usize;
        let (head, tail) = self.buffer.as_slices();
        let mut data = Vec::with_capacity(to - from);
        if from < head.len() {
            data.extend_from_slice(&head[from..to.min(head.len())]);
        }
        if to > head.len() {
            data.extend_from_slice(&tail[from.saturating_sub(head.len())..to - head.len()]);
        }
        if self.segments.is_empty() {
            // Failure detection measures from the first send into an empty flight.
            self.last_progress = Some(now);
        }
        let threshold = self.threshold(now);
        let progress = self.last_progress;
        let segment = self.segments.entry(start).or_insert(Segment {
            end,
            path: UNKNOWN_PATH,
            tried_paths: 0,
            sent_at: now,
            expected_ack_rtt: Duration::ZERO,
            transmissions: 0,
            network_transmissions: 0,
            admitted_on_datagram: false,
            stalls: 0,
            deadline: None,
            probe_transmission: None,
            local_retry_pending: false,
            reliable: None,
        });
        let first_datagram_repair = !probe && segment.first_datagram_repair_ready();
        let local_retry = !probe && std::mem::take(&mut segment.local_retry_pending);
        let previous_path =
            (segment.path != UNKNOWN_PATH && !local_retry).then_some(segment.path as u8);
        let tried_paths = segment.tried_paths;
        if !probe && segment.transmissions > 0 && !local_retry {
            let stalled = progress.is_none_or(|at| at <= segment.sent_at);
            segment.stalls = if stalled { segment.stalls + 1 } else { 0 };
        }
        segment.transmissions += 1;
        if !probe && !local_retry {
            segment.network_transmissions += 1;
        }
        let transmission = segment.transmissions;
        if probe {
            // A probe is a bounded additional copy, not a loss declaration.
            // Preserve the original timer, route and failure/backoff evidence.
            segment.probe_transmission = Some(transmission);
            self.pending_copies
                .insert((start, transmission), data_end - start);
        } else if segment.stalls == 0 {
            segment.sent_at = now;
            segment.path = UNKNOWN_PATH;
            segment.deadline = None;
            self.fresh[UNKNOWN_PATH].insert((now, start));
        } else {
            segment.sent_at = now;
            segment.path = UNKNOWN_PATH;
            let backoff = 1.5f64.powi(segment.stalls as i32).min(16.0);
            let at = now + threshold.mul_f64(backoff).min(MAX_PTO * 4);
            segment.deadline = Some(at);
            self.repeated.insert((at, start));
        }
        let (avoid_path, avoid_mask) = if probe || (transmission > 1 && !local_retry) {
            (previous_path, tried_paths)
        } else {
            (None, 0)
        };
        Transmit {
            frame: Frame::Data {
                offset: start,
                fin,
                data,
            },
            start,
            transmission,
            network_attempt: segment.network_transmissions,
            first_datagram_repair,
            retransmission: transmission > 1,
            tail_probe: probe,
            head_copy: false,
            local_retry,
            avoid_path,
            avoid_mask,
        }
    }
    /// Split only a selected oversized flight record. Already queued callbacks
    /// retain their old transmission IDs and cannot retime these new children.
    fn split_for_payload(&mut self, start: u64, maximum: usize) -> bool {
        let segment = &self.segments[&start];
        let data_end = segment.end - u64::from(self.fin.is_some_and(|f| segment.end == f + 1));
        if data_end - start <= maximum as u64 {
            return false;
        }
        if !self.lost.remove(&start) {
            self.unschedule(start);
        }
        // Both children await fresh admission. Neither belongs to the carrier
        // which accepted the original record.
        let head = self.segments.get_mut(&start).expect("segment");
        head.reliable = None;
        let tail = head.clone();
        let cut = start + maximum as u64;
        head.end = cut;
        self.segments.insert(cut, tail);
        self.pmtu_splits += 1;
        self.lost.insert(start);
        self.lost.insert(cut);
        self.head_copy = self.head_copy.filter(|(offset, _)| *offset != start);
        self.head_probe = self.head_probe.filter(|(offset, _, _)| *offset != start);
        true
    }

    pub fn poll_transmit(&mut self, now: Instant) -> Option<Transmit> {
        self.poll_transmit_sized(now, MAX_PAYLOAD)
    }

    pub(crate) fn poll_transmit_sized(&mut self, now: Instant, payload: usize) -> Option<Transmit> {
        self.poll_transmit_limited(now, payload, crate::runtime::MAX_STREAM_PAYLOAD)
    }
    pub(crate) fn poll_transmit_reliable(
        &mut self,
        now: Instant,
        payload: usize,
    ) -> Option<Transmit> {
        self.poll_transmit_limited(now, payload, RELIABLE_PAYLOAD)
    }
    fn poll_transmit_limited(
        &mut self,
        now: Instant,
        payload: usize,
        bound: usize,
    ) -> Option<Transmit> {
        let maximum = payload.clamp(DATA_HEADER + 1, bound) - DATA_HEADER;
        if let Some(start) = self.lost.pop_first() {
            if self.split_for_payload(start, maximum) {
                return self.poll_transmit_limited(now, payload, bound);
            }
            let end = self.segments[&start].end;
            let t = self.send_segment(start, end, now, false);
            if start == self.acked && !t.local_retry {
                self.head_copy = Some((start, t.transmission));
            }
            return Some(t);
        }
        if let Some((start, end)) = self.head_copy_ready() {
            if self.split_for_payload(start, maximum) {
                return self.poll_transmit_limited(now, payload, bound);
            }
            self.head_copy = None;
            let mut t = self.send_segment(start, end, now, true);
            (t.tail_probe, t.head_copy) = (false, true);
            return Some(t);
        }
        if self.head_probe_due {
            self.head_probe_due = false;
            if let Some((start, at)) = self.head_probe_deadline()
                && now >= at
            {
                if self.split_for_payload(start, maximum) {
                    return self.poll_transmit_limited(now, payload, bound);
                }
                let segment = &self.segments[&start];
                let end = segment.end;
                let avoid_path = segment.reliable.is_some().then_some(segment.path as u8);
                self.head_probe = None;
                self.last_head_probe = Some(now);
                let mut t = self.send_segment(start, end, now, true);
                let avoid_mask = if avoid_path.is_some() {
                    t.avoid_mask
                } else {
                    0
                };
                (t.tail_probe, t.head_copy, t.avoid_path, t.avoid_mask) =
                    (false, true, avoid_path, avoid_mask);
                return Some(t);
            }
        }
        if self.tail_probe_due {
            self.tail_probe_due = false;
            if let Some((at, start)) = self.tail_probe_deadline()
                && now >= at
            {
                if self.split_for_payload(start, maximum) {
                    return self.poll_transmit_limited(now, payload, bound);
                }
                let end = self.segments[&start].end;
                return Some(self.send_segment(start, end, now, true));
            }
        }
        if self.next < self.written && self.next < self.limit {
            let len = (self.written - self.next)
                .min(self.limit - self.next)
                .min(maximum as u64);
            let start = self.next;
            self.next += len;
            let fin = self.fin == Some(self.next);
            self.fin_sent |= fin;
            self.open_sent = true;
            return Some(self.send_segment(start, self.next + u64::from(fin), now, false));
        }
        if self.fin == Some(self.next) && !self.fin_sent {
            self.fin_sent = true;
            self.open_sent = true;
            return Some(self.send_segment(self.next, self.next + 1, now, false));
        }
        if self.probe_due || self.open_due() {
            // Zero-length data asks for an acknowledgment; it is not retained.
            self.probe_due = false;
            self.open_sent = true;
            self.probe_at = Some(now);
            self.last_progress.get_or_insert(now);
            return Some(Transmit {
                frame: Frame::Data {
                    offset: self.next,
                    fin: false,
                    data: Vec::new(),
                },
                start: self.next,
                transmission: 0,
                network_attempt: 0,
                first_datagram_repair: false,
                retransmission: false,
                tail_probe: false,
                head_copy: false,
                local_retry: false,
                avoid_path: None,
                avoid_mask: 0,
            });
        }
        None
    }
    /// Start loss timing on the route that actually admitted this transmission.
    /// Copies and stale callbacks cannot replace a newer transmission's clock.
    pub fn admitted(
        &mut self,
        start: u64,
        transmission: u32,
        path: u8,
        rtt: Duration,
        at: Instant,
    ) {
        self.admitted_via(start, transmission, path, rtt, Duration::ZERO, at, None);
    }

    /// Native stream admission delegates loss recovery to that carrier. A
    /// cross-path SACK or its local write queue is not a native packet loss.
    #[cfg(test)]
    pub(crate) fn admitted_reliable(
        &mut self,
        start: u64,
        transmission: u32,
        path: u8,
        rtt: Duration,
        at: Instant,
        reachable: Arc<AtomicBool>,
    ) {
        self.admitted_reliable_with_ect(
            start,
            transmission,
            path,
            rtt,
            Duration::ZERO,
            at,
            reachable,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admitted_reliable_with_ect(
        &mut self,
        start: u64,
        transmission: u32,
        path: u8,
        rtt: Duration,
        expected_ack_rtt: Duration,
        at: Instant,
        reachable: Arc<AtomicBool>,
    ) {
        self.admitted_via(
            start,
            transmission,
            path,
            rtt,
            expected_ack_rtt,
            at,
            Some(reachable),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn admitted_via(
        &mut self,
        start: u64,
        transmission: u32,
        path: u8,
        rtt: Duration,
        expected_ack_rtt: Duration,
        at: Instant,
        reliable: Option<Arc<AtomicBool>>,
    ) {
        let path = usize::from(path);
        if path >= MAX_PATHS {
            return;
        }
        if let Some(bytes) = self.pending_copies.remove(&(start, transmission)) {
            if let Some(segment) = self.segments.get_mut(&start) {
                segment.tried_paths |= 1 << path;
            }
            self.expected_duplicates =
                (self.expected_duplicates + bytes).min(EXPECTED_DUPLICATES_MAX);
            return;
        }
        if self
            .segments
            .get(&start)
            .is_none_or(|s| s.transmissions != transmission || s.path != UNKNOWN_PATH)
        {
            return;
        }
        if !self.lost.remove(&start) {
            self.unschedule(start);
        }
        self.transport_rtt[path] = rtt.max(Duration::from_millis(1));
        let threshold = self.path_threshold(path, at);
        let segment = self.segments.get_mut(&start).expect("admitted segment");
        segment.local_retry_pending = false;
        segment.path = path;
        segment.tried_paths |= 1 << path;
        segment.sent_at = at;
        segment.expected_ack_rtt = expected_ack_rtt;
        segment.admitted_on_datagram = reliable.is_none();
        segment.reliable = reliable;
        if let Some(owner) = &segment.reliable {
            segment.deadline = None;
            if let Some(flight) = self
                .reliable_flight
                .iter_mut()
                .find(|f| Arc::ptr_eq(&f.reachable, owner))
            {
                flight.offsets.insert(start);
            } else {
                self.reliable_flight.push(CarrierFlight {
                    reachable: owner.clone(),
                    offsets: BTreeSet::from([start]),
                });
            }
            self.probe_at.get_or_insert(at);
            if self.fin_sent {
                self.schedule_head_probe(at, false);
            }
        } else if segment.stalls == 0 {
            segment.deadline = None;
            self.fresh[path].insert((at, start));
        } else {
            let backoff = 1.5f64.powi(segment.stalls as i32).min(16.0);
            let deadline = at + threshold.mul_f64(backoff).min(MAX_PTO * 4);
            segment.deadline = Some(deadline);
            self.repeated.insert((deadline, start));
        }
    }

    /// A transmission left the local queue without admission. Retransmit it
    /// unless a later transmission or an acknowledgment has superseded it.
    pub fn locally_dropped(&mut self, start: u64, transmission: u32) -> bool {
        if self.pending_copies.remove(&(start, transmission)).is_some() {
            return false;
        }
        if self.segments.get(&start).is_none_or(|s| {
            s.transmissions != transmission || s.probe_transmission == Some(transmission)
        }) || self.lost.contains(&start)
        {
            return false;
        }
        self.segments
            .get_mut(&start)
            .expect("current segment")
            .local_retry_pending = true;
        self.mark_lost(start);
        true
    }
    /// Returns newly released retained bytes and whether the peer reported a
    /// duplicate, or `None` for unsent data or an oversized receive window.
    pub fn on_ack(&mut self, ack: &Ack, now: Instant) -> Option<(u64, bool)> {
        let sent_end = self.next + u64::from(self.fin_sent && self.fin == Some(self.next));
        if ack.cumulative > sent_end
            || ack.ranges.last().is_some_and(|r| r.1 > sent_end)
            || ack.limit > ack.cumulative.saturating_add(MAX_WINDOW)
        {
            return None;
        }
        self.open_pending = false;
        self.probe_at = None;
        let raised = ack.limit > self.limit;
        self.limit = self.limit.max(ack.limit.min(MAX_OFFSET));
        let cumulative = ack.cumulative.max(self.acked);
        let mut delivered = Vec::new();
        while let Some((&start, segment)) = self.segments.first_key_value() {
            if start >= cumulative {
                break;
            }
            if segment.end > cumulative {
                // PMTU resegmentation can acknowledge only part of a retained
                // record. Keep its unacknowledged tail retransmittable.
                let lost = self.lost.remove(&start);
                if !lost {
                    self.unschedule(start);
                }
                let segment = self.segments.remove(&start).expect("first segment");
                self.segments.insert(cumulative, segment);
                self.mark_lost(cumulative);
                break;
            }
            self.unschedule_delivered(start);
            delivered.push(self.segments.remove(&start).expect("first segment"));
        }
        for &(start, end) in &ack.ranges {
            let covered: Vec<u64> = self
                .segments
                .range(start..end)
                .filter(|(_, s)| s.end <= end)
                .map(|(k, _)| *k)
                .collect();
            for key in covered {
                self.unschedule_delivered(key);
                delivered.push(self.segments.remove(&key).expect("covered segment"));
            }
        }
        // Only new first-transmission deliveries on the missing record's own
        // path are evidence for a short datagram flight. Other paths can
        // routinely overtake it while it is healthy.
        let small_udp_hole = self.ordered_udp_gap_repair
            && !ack.ranges.is_empty()
            && self.written.saturating_sub(cumulative) <= HEAD_PROBE_MIN_FLIGHT
            && self.segments.get(&cumulative).is_some_and(|head| {
                head.reliable.is_none()
                    && head.path != UNKNOWN_PATH
                    && delivered
                        .iter()
                        .filter(|s| {
                            s.path == head.path
                                && s.sent_at > head.sent_at
                                && s.end > head.end
                                && s.network_transmissions == 1
                                && s.probe_transmission.is_none()
                                && s.reliable.is_none()
                        })
                        .nth(2)
                        .is_some()
            });
        let progressed = !delivered.is_empty() || cumulative > self.acked || raised;
        let mut newest_sample: Option<Instant> = None;
        let mut path_samples: [Option<Instant>; MAX_PATHS] = [None; MAX_PATHS];
        for segment in delivered {
            if segment.network_transmissions == 1 && segment.probe_transmission.is_none() {
                newest_sample =
                    Some(newest_sample.map_or(segment.sent_at, |at| at.max(segment.sent_at)));
                if segment.path != UNKNOWN_PATH {
                    let sample = &mut path_samples[segment.path];
                    *sample = Some(sample.map_or(segment.sent_at, |at| at.max(segment.sent_at)));
                }
            }
            self.rack = Some(
                self.rack
                    .map_or(segment.sent_at, |r| r.max(segment.sent_at)),
            );
        }
        // One ACK can retire old, previously omitted SACK ranges together
        // with newly received bytes. Older members measure acknowledgment
        // aggregation, not the current route RTT. Preserve Karn's rule and
        // sample only the newest original transmission on each route.
        if let Some(at) = newest_sample {
            self.rtt.sample_transmission(at, now);
        }
        for (path, at) in path_samples.into_iter().enumerate() {
            if let Some(at) = at {
                self.path_rtt[path].sample_transmission(at, now);
            }
        }
        let reported = ack.duplicate_bytes.saturating_sub(self.peer_duplicates);
        let expected = reported.min(self.expected_duplicates);
        self.expected_duplicates -= expected;
        let spurious = reported > expected;
        self.peer_duplicates = self.peer_duplicates.max(ack.duplicate_bytes);
        if spurious {
            self.reorder = (self.reorder * 1.25).min(REORDER_MAX);
        } else if progressed {
            self.reorder = (self.reorder * 0.98).max(REORDER_BASE);
        }
        if progressed {
            self.last_progress = Some(now);
            self.probe_count = 0;
            self.probe_due = false;
            self.tail_probe_due = false;
        }
        self.acked = cumulative;
        let release_to = cumulative.min(self.written).max(self.base);
        let released = release_to - self.base;
        self.buffer.drain(..released as usize);
        if self.buffer.capacity() > (128 * 1024).max(self.buffer.len().saturating_mul(4)) {
            self.buffer.shrink_to_fit();
        }
        self.base = release_to;
        if self.needs_probe() {
            self.probe_at = Some(now);
        }
        self.detect_losses(now);
        self.schedule_head_probe(now, small_udp_hole);
        Some((released, spurious))
    }
    fn unschedule_delivered(&mut self, start: u64) {
        if !self.lost.remove(&start) {
            self.unschedule(start);
        }
    }
    fn fresh_deadline(&self, sent_at: Instant, threshold: Duration) -> Instant {
        let delay = if self.rack.is_some_and(|rack| sent_at < rack) {
            threshold
        } else {
            threshold.mul_f64(1.5)
        };
        // Delayed ACKs must not move the first repair beyond the peer's
        // failure deadline. Repeated repairs retain their bounded backoff.
        sent_at + delay.min(MAX_PTO)
    }

    /// A repair of the segment holding back in-order delivery gets one extra
    /// copy on its own admission, so a single further loss of either copy does
    /// not stall the receiver for another loss timer. It waits until the repair
    /// is admitted (so that admission keeps the repair's timer) and is dropped
    /// once the repair is superseded.
    fn head_copy_ready(&self) -> Option<(u64, u64)> {
        let (start, transmission) = self.head_copy?;
        let s = self.segments.get(&start)?;
        (start == self.acked
            && s.reliable.is_none()
            && s.transmissions == transmission
            && s.path != UNKNOWN_PATH
            && s.probe_transmission.is_none()
            && !self.lost.contains(&start))
        .then_some((start, s.end))
    }

    /// The next transmit may use the mux reserve if it repairs a short piece
    /// close enough to the cumulative gap to release the next UDP datagram.
    pub(crate) fn short_udp_repair_ready(&self, now: Instant, payload: usize) -> bool {
        let (start, segment, first_datagram_repair) = if let Some(&start) = self.lost.first() {
            let segment = &self.segments[&start];
            if segment.network_transmissions == 0
                || (segment.local_retry_pending
                    && (segment.network_transmissions < 2 || segment.tried_paths == 0))
            {
                return false;
            }
            (start, segment, segment.first_datagram_repair_ready())
        } else if let Some((start, _)) = self.head_copy_ready() {
            (start, &self.segments[&start], false)
        } else if self.head_probe_due
            && let Some((start, due)) = self.head_probe_deadline()
            && now >= due
        {
            (start, &self.segments[&start], false)
        } else {
            return false;
        };
        let fin = u64::from(self.fin.is_some_and(|offset| segment.end == offset + 1));
        let end = segment.end - fin;
        // Parallel TCP writers can keep the producer above its watermark over
        // a whole burst. Let first repairs for the missing DATAGRAM prefix
        // compete in the existing reserve, up to one native record of offsets.
        // Keep the smaller range for extra copies and repeated repairs.
        let maximum_ahead = if first_datagram_repair {
            RELIABLE_PAYLOAD - DATA_HEADER
        } else {
            3 * payload.saturating_sub(DATA_HEADER)
        };
        end - start + DATA_HEADER as u64 <= payload as u64
            && end - self.base <= maximum_ahead as u64
    }

    pub(crate) fn head_probe_is_reliable(&self) -> bool {
        self.lost.is_empty()
            && self.head_copy_ready().is_none()
            && self.head_probe_due
            && self.head_probe_deadline().is_some_and(|(start, _)| {
                self.segments
                    .get(&start)
                    .is_some_and(|s| s.reliable.is_some())
            })
    }

    fn head_probe_deadline(&self) -> Option<(u64, Instant)> {
        let (start, transmission, at) = self.head_probe?;
        let segment = self.segments.get(&start)?;
        (start == self.acked
            && segment.transmissions == transmission
            && segment.path != UNKNOWN_PATH
            && segment.probe_transmission.is_none()
            && !self.lost.contains(&start))
        .then_some((start, at))
    }

    fn schedule_head_probe(&mut self, now: Instant, small_udp_hole: bool) {
        if self.head_probe_deadline().is_some() {
            return;
        }
        self.head_probe = None;
        self.head_probe_due = false;
        let Some((&start, segment)) = self.segments.first_key_value() else {
            return;
        };
        let overtaken = self.rack.is_some_and(|later| later > segment.sent_at);
        let has_sibling_path = self
            .transport_rtt
            .iter()
            .enumerate()
            .any(|(i, d)| i != segment.path && !d.is_zero());
        let is_reliable_tail = segment.reliable.is_some()
            && has_sibling_path
            && self.fin_sent
            && self.next >= self.written
            && self.segments.len() <= 2;
        if start != self.acked
            || segment.network_transmissions != 1
            || segment.probe_transmission.is_some()
            || segment.path == UNKNOWN_PATH
            || self.lost.contains(&start)
            || (!overtaken && !is_reliable_tail)
        {
            return;
        }
        if segment.reliable.is_some() {
            // Bounded cross-path rescue for reliable stream segments:
            // measure stall deadline against the queue-aware expected ACK RTT
            // recorded at native handoff so healthy BDP queues send zero
            // spurious duplicates, while overtaken holes or stalled multi-path
            // tail chunks recover promptly onto a healthier sibling path.
            let rtt = self.transport_rtt[segment.path].max(Duration::from_millis(20));
            let expected = segment.expected_ack_rtt.max(rtt);
            // Measure stall deadline against the queue-aware expected ACK RTT
            // recorded at native handoff so healthy BDP queues send zero
            // spurious duplicates, while overtaken stragglers or stalled tail
            // chunks recover promptly onto a clean sibling (`native_return::drain`
            // suppresses speculative copies when all siblings are in heavy loss).
            let stall_delay = if overtaken {
                expected
                    .mul_f64(2.0)
                    .max(rtt.mul_f64(3.0))
                    .clamp(Duration::from_millis(320), Duration::from_millis(950))
            } else {
                expected
                    .mul_f64(2.2)
                    .max(rtt.mul_f64(2.5))
                    .clamp(Duration::from_millis(350), Duration::from_millis(1_000))
            };
            let stall_at = segment.sent_at + stall_delay;
            let rescue_rtt = self
                .transport_rtt
                .iter()
                .enumerate()
                .filter(|&(i, d)| i != segment.path && !d.is_zero())
                .map(|(_, &d)| d)
                .min()
                .unwrap_or(rtt);
            let settle_at =
                now + (rescue_rtt / 2).clamp(Duration::from_millis(40), Duration::from_millis(120));
            let rate_limit_at = self.last_head_probe.map_or(now, |last| {
                last + if is_reliable_tail {
                    rescue_rtt.clamp(Duration::from_millis(120), Duration::from_millis(260))
                } else {
                    rescue_rtt
                        .mul_f64(2.0)
                        .clamp(Duration::from_millis(260), Duration::from_millis(500))
                }
            });
            let at = stall_at.max(settle_at).max(rate_limit_at);
            self.head_probe = Some((start, segment.transmissions, at));
            return;
        }
        if self.written - self.base <= HEAD_PROBE_MIN_FLIGHT && !small_udp_hole {
            return;
        }
        let rtt = self.transport_rtt[segment.path].max(Duration::from_millis(1));
        // Give normal cross-path reordering and a newer cumulative ACK time
        // to settle. One copy per RTT per stream bounds duplicate traffic even
        // when successive old ACKs name different holes. The original loss
        // timer and admission budgets remain intact if either copy is lost.
        let at = (now + (rtt / 4).clamp(Duration::from_millis(10), Duration::from_millis(50)))
            .max(self.last_head_probe.map_or(now, |last| last + rtt));
        if small_udp_hole {
            tracing::debug!(target: "braidpath::ordered_udp_repair", offset = start,
                path = segment.path, "short UDP gap probe scheduled");
        }
        self.head_probe = Some((start, segment.transmissions, at));
    }

    fn tail_probe_deadline(&self) -> Option<(Instant, u64)> {
        if self.segments.len() != 1 || !self.lost.is_empty() {
            return None;
        }
        let (&start, s) = self.segments.first_key_value()?;
        if s.path == UNKNOWN_PATH
            || s.reliable.is_some()
            || s.network_transmissions != 1
            || s.probe_transmission.is_some()
            // A sparse HTTPS response can occupy a full negotiated segment.
            // It still has no following packet to reveal loss with a SACK.
            // Keep the one-segment/one-probe bound, including the FIN byte.
            || s.end - start > crate::runtime::MAX_STREAM_PAYLOAD as u64
            // A lone SACK hole below delivered data is not a tail. Its RACK
            // and bounded head-probe policy already control recovery.
            || s.end < self.next + u64::from(self.fin_sent && self.fin == Some(self.next))
            || self.next < self.written
        {
            return None;
        }
        let rtt =
            self.transport_rtt[s.path].max(self.path_rtt[s.path].smoothed.unwrap_or_default());
        Some((
            s.sent_at + (rtt.mul_f64(1.125) + ACK_DELAY).min(MAX_PTO),
            start,
        ))
    }
    fn detect_losses(&mut self, now: Instant) {
        // Poll each actual writer once. Reconnects can leave two generations
        // of the same path slot in flight, with independent ownership.
        let failed: Vec<_> = self
            .reliable_flight
            .iter()
            .filter(|f| !f.reachable.load(Ordering::Acquire))
            .flat_map(|f| f.offsets.iter().copied())
            .collect();
        for start in failed {
            self.mark_lost(start);
        }
        // The oldest transmission has the earliest deadline within its route.
        for path in 0..=MAX_PATHS {
            let threshold = self.path_threshold(path, now);
            while let Some(&(sent_at, start)) = self.fresh[path].first() {
                if now < self.fresh_deadline(sent_at, threshold) {
                    break;
                }
                self.mark_lost(start);
            }
        }
        while let Some(&(at, start)) = self.repeated.first() {
            if now < at {
                break;
            }
            self.mark_lost(start);
        }
    }
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        [
            // The existing sender updates native reachability from QUIC ACK
            // progress. Poll only while native bytes await their stream ACK;
            // this also recovers if the whole original connection disappears.
            (!self.reliable_flight.is_empty()).then_some(now + Duration::from_millis(50)),
            self.head_probe_deadline()
                .filter(|_| !self.head_probe_due)
                .map(|(_, at)| at),
            self.tail_probe_deadline()
                .filter(|_| !self.tail_probe_due)
                .map(|(at, _)| at),
            self.fresh
                .iter()
                .enumerate()
                .filter_map(|(path, fresh)| {
                    fresh.first().map(|(sent_at, _)| {
                        self.fresh_deadline(*sent_at, self.path_threshold(path, now))
                    })
                })
                .min(),
            self.repeated.first().map(|(at, _)| *at),
            (self.needs_probe() && !self.probe_due)
                .then(|| self.probe_at.map(|at| at + self.probe_interval(now)))
                .flatten(),
            self.awaiting_peer()
                .then(|| self.last_progress.map(|at| at + DEAD_AFTER))
                .flatten(),
        ]
        .into_iter()
        .flatten()
        .min()
    }
    /// Returns true when a window or open probe became due.
    pub fn on_timeout(&mut self, now: Instant) -> bool {
        self.detect_losses(now);
        let head =
            !self.head_probe_due && self.head_probe_deadline().is_some_and(|(_, at)| now >= at);
        self.head_probe_due |= head;
        let tail =
            !self.tail_probe_due && self.tail_probe_deadline().is_some_and(|(at, _)| now >= at);
        self.tail_probe_due |= tail;
        if self.probe_due
            || !self.needs_probe()
            || self
                .probe_at
                .is_some_and(|at| now < at + self.probe_interval(now))
        {
            return tail || head;
        }
        self.probe_due = true;
        if self.open_pending {
            self.open_sent = false;
        }
        self.probe_count += 1;
        true
    }
}

/// Why a receiving half rejected a frame. Either ends the stream with RESET.
#[derive(Debug, PartialEq, Eq)]
pub enum Violation {
    FlowControl,
    FinalSize,
}

/// One reliable receiving half.
pub struct Receiver {
    cumulative: u64,
    ranges: BTreeMap<u64, Vec<u8>>,
    recent: VecDeque<u64>,
    out_of_order: u64,
    final_size: Option<u64>,
    consumed: u64,
    advertised: u64,
    duplicates: u64,
    unacknowledged: u32,
    ack_due: Option<Instant>,
    ack_now: bool,
    last_ack: Option<Instant>,
    ack_spacing: Duration,
    last_duplicate_ack: Option<Instant>,
    duplicate_ack_pending: bool,
}
impl Default for Receiver {
    fn default() -> Self {
        Self {
            cumulative: 0,
            ranges: BTreeMap::new(),
            recent: VecDeque::new(),
            out_of_order: 0,
            final_size: None,
            consumed: 0,
            advertised: INITIAL_WINDOW,
            duplicates: 0,
            unacknowledged: 0,
            ack_due: None,
            ack_now: false,
            last_ack: None,
            ack_spacing: ACK_SPACING,
            last_duplicate_ack: None,
            duplicate_ack_pending: false,
        }
    }
}
impl Receiver {
    /// Offer receive credit with the opening flight, before the first response.
    /// A lost offer is repeated by the normal ACK for incoming data.
    pub(crate) fn request_opening_credit(&mut self) {
        if self.last_ack.is_none() && self.cumulative == 0 {
            self.ack_now = true;
        }
    }

    /// Limit reverse traffic when many established downloads are active.
    /// FIN, open probes, and window updates keep their immediate ACKs.
    pub(crate) fn set_bulk_ack_spacing(&mut self, shared: bool) {
        self.ack_spacing = if shared { ACK_SPACING * 4 } else { ACK_SPACING };
    }

    /// A frame can add at most one range node. Later gaps in an overlapping
    /// frame extend the preceding retained range instead of allocating nodes.
    pub(crate) fn needs_range(&self, offset: u64, len: usize) -> bool {
        len > 0
            && offset > self.cumulative
            && self
                .ranges
                .range(..=offset)
                .next_back()
                .is_none_or(|(start, data)| start + (data.len() as u64) < offset)
    }
    pub(crate) fn range_count(&self) -> usize {
        self.ranges.len()
    }
    /// Unique bytes a frame would add; duplicates never reserve memory twice.
    pub fn additional_bytes(&self, offset: u64, len: usize) -> usize {
        let end = offset + len as u64;
        let mut cursor = offset.max(self.cumulative).min(end);
        if let Some((&start, data)) = self.ranges.range(..=cursor).next_back() {
            cursor = cursor.max(start + data.len() as u64).min(end);
        }
        let mut additional = 0;
        for (&start, data) in self.ranges.range(cursor..end) {
            additional += start.saturating_sub(cursor);
            cursor = cursor.max(start + data.len() as u64).min(end);
        }
        (additional + end - cursor) as usize
    }
    pub fn cumulative(&self) -> u64 {
        self.cumulative
    }
    pub(crate) fn receive_diagnostics(&self) -> (u64, u64, u64, usize) {
        (
            self.cumulative,
            self.consumed,
            self.out_of_order,
            self.ranges.len(),
        )
    }
    /// Accept a data frame; returns in-order bytes now ready for the application.
    pub fn on_data(
        &mut self,
        offset: u64,
        fin: bool,
        mut data: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<u8>, Violation> {
        let end = offset + data.len() as u64;
        let ack_immediately = data.is_empty() || fin;
        if end > self.advertised {
            return Err(Violation::FlowControl);
        }
        let highest = self
            .ranges
            .last_key_value()
            .map_or(self.cumulative, |(k, v)| k + v.len() as u64);
        if fin && (self.final_size.is_some_and(|f| f != end) || end < highest) {
            return Err(Violation::FinalSize);
        }
        if self.final_size.is_some_and(|f| end > f) {
            return Err(Violation::FinalSize);
        }
        if fin {
            self.final_size = Some(end);
        }
        let mut ready = Vec::new();
        let mut start = offset.max(self.cumulative);
        let mut duplicate = start.min(end) - offset;
        while start < end {
            // Store only the gaps between existing ranges; overlaps are duplicates.
            let covering = self
                .ranges
                .range(..=start)
                .next_back()
                .map(|(k, v)| (*k, k + v.len() as u64))
                .filter(|(_, e)| *e > start);
            if let Some((_, covered_end)) = covering {
                let skip = covered_end.min(end) - start;
                duplicate += skip;
                start += skip;
                continue;
            }
            let gap_end = self
                .ranges
                .range(start..)
                .next()
                .map_or(end, |(k, _)| (*k).min(end));
            // Take ownership of a whole record. Only an overlap needs a
            // new allocation for the uncovered slice.
            let piece = if start == offset && gap_end == end {
                std::mem::take(&mut data)
            } else {
                data[(start - offset) as usize..(gap_end - offset) as usize].to_vec()
            };
            if start == self.cumulative {
                self.cumulative = gap_end;
                ready = piece;
            } else {
                self.out_of_order += piece.len() as u64;
                // Data arriving after a hole extends the range before it, so
                // acknowledgments walk the holes rather than every segment.
                match self
                    .ranges
                    .range_mut(..start)
                    .next_back()
                    .filter(|(k, v)| **k + v.len() as u64 == start)
                {
                    Some((_, before)) => before.extend_from_slice(&piece),
                    None => {
                        self.ranges.insert(start, piece);
                    }
                }
                if self.recent.len() == RECENT_RANGES {
                    self.recent.pop_front();
                }
                self.recent.push_back(start);
            }
            start = gap_end;
        }
        while let Some(entry) = self.ranges.first_entry() {
            if *entry.key() != self.cumulative {
                break;
            }
            let piece = entry.remove();
            self.out_of_order -= piece.len() as u64;
            self.cumulative += piece.len() as u64;
            ready.extend(piece);
        }
        self.duplicates += duplicate;
        self.unacknowledged += 1;
        if ack_immediately {
            self.ack_now = true;
        } else if duplicate > 0 {
            // One immediate duplicate report preserves loss-recovery feedback.
            // A burst of redundant repairs must not bypass ACK spacing for
            // every segment: each SACK may walk thousands of retained holes.
            self.duplicate_ack_pending = true;
            match self.last_duplicate_ack.map(|at| at + self.ack_spacing) {
                Some(spaced) if now < spaced => {
                    self.ack_due = Some(self.ack_due.map_or(spaced, |due| due.min(spaced)));
                }
                _ => self.ack_now = true,
            }
        } else if self.unacknowledged >= ACK_EVERY {
            match self.last_ack.map(|at| at + self.ack_spacing) {
                Some(spaced) if now < spaced => {
                    self.ack_due = Some(self.ack_due.map_or(spaced, |due| due.min(spaced)));
                }
                _ => self.ack_now = true,
            }
        } else {
            // While acknowledgements flow, the delay timer keeps the same spacing.
            let delayed = self.last_ack.map_or(now + ACK_DELAY, |at| {
                (now + ACK_DELAY).max(at + self.ack_spacing)
            });
            self.ack_due.get_or_insert(delayed);
        }
        Ok(ready)
    }
    /// The application consumed `bytes`; a larger window may be advertised.
    pub fn consumed(&mut self, bytes: u64, window: u64) {
        self.consumed += bytes;
        if self.consumed + window >= self.advertised + window / 4 {
            self.ack_now = true;
        }
    }
    pub fn duplicates(&self) -> u64 {
        self.duplicates
    }
    pub fn fin_received(&self) -> bool {
        self.final_size == Some(self.cumulative)
    }
    pub fn finished(&self) -> bool {
        self.final_size
            .is_some_and(|f| self.consumed == f && self.cumulative == f)
    }
    /// The acknowledgment of everything, including FIN, once finished: what a
    /// retired stream answers if the peer missed it and sends its FIN again.
    pub fn final_ack(&self) -> Option<Ack> {
        self.finished().then(|| Ack {
            cumulative: self.cumulative + 1,
            limit: self.advertised,
            duplicate_bytes: self.duplicates,
            ranges: Vec::new(),
        })
    }
    /// Bytes held locally: delivered but unconsumed, plus out-of-order data.
    pub fn buffered(&self) -> u64 {
        self.cumulative - self.consumed + self.out_of_order
    }
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.ack_now { None } else { self.ack_due }
    }
    /// The acknowledgment could not be queued; send one at the next chance.
    pub fn defer_ack(&mut self) {
        self.ack_now = true;
    }
    pub fn ack_pending(&self, now: Instant) -> bool {
        self.ack_now || self.ack_due.is_some_and(|at| now >= at)
    }
    pub fn take_ack(&mut self, now: Instant, window: u64) -> Option<Ack> {
        if !self.ack_pending(now) {
            return None;
        }
        self.ack_now = false;
        self.ack_due = None;
        self.last_ack = Some(now);
        if self.duplicate_ack_pending {
            self.last_duplicate_ack = Some(now);
            self.duplicate_ack_pending = false;
        }
        self.unacknowledged = 0;
        self.advertised = self.advertised.max(self.consumed + window.min(MAX_WINDOW));
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for (start, data) in &self.ranges {
            let end = start + data.len() as u64;
            match ranges.last_mut() {
                Some(last) if last.1 == *start => last.1 = end,
                _ => ranges.push((*start, end)),
            }
        }
        if ranges.len() > MAX_RANGES {
            // Sustained loss can leave more holes than one frame describes.
            // As with TCP SACK, describe the most recently received data
            // first: a repair that fills an old hole, then the newest data.
            // The sender forgets a range once acknowledged, so a range only
            // needs to appear until one acknowledgment carrying it arrives.
            let mut chosen = vec![false; ranges.len()];
            let mut count = 0;
            let recent = self.recent.iter().rev().filter_map(|offset| {
                let i = ranges.partition_point(|r| r.0 <= *offset).checked_sub(1)?;
                (*offset < ranges[i].1).then_some(i)
            });
            for i in recent.chain((0..ranges.len()).rev()) {
                if count == MAX_RANGES {
                    break;
                }
                if !chosen[i] {
                    chosen[i] = true;
                    count += 1;
                }
            }
            let mut i = 0;
            ranges.retain(|_| {
                i += 1;
                chosen[i - 1]
            });
        }
        Some(Ack {
            cumulative: self.cumulative + u64::from(self.fin_received()),
            limit: self.advertised,
            duplicate_bytes: self.duplicates,
            ranges,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reliable_chunks_do_not_raise_the_datagram_segment_bound() {
        let now = Instant::now();
        let mut reliable = Sender::new(false);
        let mut datagram = Sender::new(false);
        let bytes = vec![7; 64 * 1024];
        reliable.push(&bytes);
        datagram.push(&bytes);
        let Frame::Data { data: large, .. } = reliable
            .poll_transmit_reliable(now, usize::MAX)
            .unwrap()
            .frame
        else {
            panic!("expected data")
        };
        let Frame::Data { data: small, .. } =
            datagram.poll_transmit_sized(now, usize::MAX).unwrap().frame
        else {
            panic!("expected data")
        };
        assert_eq!(large.len(), RELIABLE_PAYLOAD - DATA_HEADER);
        assert_eq!(
            small.len(),
            crate::runtime::MAX_STREAM_PAYLOAD - DATA_HEADER
        );
    }

    #[test]
    fn splitting_a_native_record_releases_its_writer_and_admission_timer() {
        let at = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&[0; 4096]);
        let whole = sender.poll_transmit_reliable(at, RELIABLE_PAYLOAD).unwrap();
        sender.admitted_reliable(
            whole.start,
            whole.transmission,
            0,
            Duration::from_millis(80),
            at,
            Arc::new(AtomicBool::new(true)),
        );
        assert!(sender.split_for_payload(0, 1024));
        let first = sender.poll_transmit_sized(at, DATA_HEADER + 1024).unwrap();
        sender.admitted_reliable(
            first.start,
            first.transmission,
            1,
            Duration::from_millis(90),
            at,
            Arc::new(AtomicBool::new(true)),
        );
        assert!(sender.repeated.is_empty());
        assert!(sender.fresh[UNKNOWN_PATH].is_empty());
        assert!(sender.segments[&1024].reliable.is_none());
        assert_eq!(sender.reliable_flight.len(), 1);
    }

    #[test]
    fn same_slot_replacement_releases_only_the_failed_writers_offsets() {
        let at = Instant::now();
        let old = Arc::new(AtomicBool::new(true));
        let new = Arc::new(AtomicBool::new(true));
        let mut sender = Sender::new(false);
        for owner in [&old, &new, &old, &new] {
            sender.push(&[0; 1024]);
            let t = sender.poll_transmit_reliable(at, RELIABLE_PAYLOAD).unwrap();
            sender.admitted_reliable(
                t.start,
                t.transmission,
                0,
                Duration::from_millis(80),
                at,
                owner.clone(),
            );
        }
        old.store(false, Ordering::Release);
        sender.detect_losses(at);
        assert_eq!(sender.lost, BTreeSet::from([0, 2048]));
        assert_eq!(sender.reliable_flight.len(), 1);
        assert!(Arc::ptr_eq(&sender.reliable_flight[0].reachable, &new));
        assert_eq!(
            sender.reliable_flight[0].offsets,
            BTreeSet::from([1024, 3072])
        );
    }

    #[test]
    fn native_carrier_wait_does_not_trigger_an_overlay_repair() {
        let at = Instant::now();
        let mut sender = Sender::new(false);
        let reachable = Arc::new(AtomicBool::new(true));
        sender.push(&vec![5; 3 * 32 * 1024]);
        for path in [0, 1, 1] {
            let sent = sender.poll_transmit_reliable(at, RELIABLE_PAYLOAD).unwrap();
            sender.admitted_reliable(
                sent.start,
                sent.transmission,
                path,
                Duration::from_millis(100),
                at,
                reachable.clone(),
            );
        }
        sender
            .on_ack(
                &Ack {
                    cumulative: 0,
                    limit: MAX_WINDOW,
                    duplicate_bytes: 0,
                    ranges: vec![(32 * 1024, 3 * 32 * 1024)],
                },
                at + Duration::from_millis(70),
            )
            .unwrap();
        // The first native response stream is still delivering its queued
        // bytes. A later path's SACK is not a loss of this reliable carrier.
        let later = at + Duration::from_millis(230);
        sender.on_timeout(later);
        assert!(
            sender
                .poll_transmit_reliable(later, RELIABLE_PAYLOAD)
                .is_none()
        );
        assert!(sender.next_deadline(later).unwrap() > later);
        assert_eq!(sender.reliable_flight.len(), 1);

        // A real outage releases the original carrier's ownership, without
        // waiting for a long connection idle timeout or a stream failure.
        reachable.store(false, Ordering::Release);
        sender.on_timeout(later);
        let repair = sender
            .poll_transmit_reliable(later, RELIABLE_PAYLOAD)
            .unwrap();
        assert_eq!(repair.start, 0);
        assert!(repair.retransmission);
        let replacement = Arc::new(AtomicBool::new(true));
        sender.admitted_reliable(
            repair.start,
            repair.transmission,
            1,
            Duration::from_millis(100),
            later,
            replacement.clone(),
        );
        sender.on_timeout(later + Duration::from_millis(300));
        if let Some(probe) =
            sender.poll_transmit_reliable(later + Duration::from_millis(300), RELIABLE_PAYLOAD)
        {
            assert!(is_ack_request(&probe.frame.encode()));
            assert!(!probe.retransmission);
        }
        assert!(
            !sender.locally_dropped(0, 1),
            "stale cancellation cannot replace the new owner"
        );
        let (released, _) = sender
            .on_ack(
                &Ack {
                    cumulative: 3 * 32 * 1024,
                    limit: MAX_WINDOW,
                    duplicate_bytes: 0,
                    ranges: vec![],
                },
                later + Duration::from_millis(310),
            )
            .unwrap();
        assert_eq!(released, 3 * 32 * 1024);
        assert!(sender.reliable_flight.is_empty());
    }

    #[test]
    fn cancelled_native_write_retries_and_datagram_loss_timers_remain_active() {
        let at = Instant::now();
        let mut native = Sender::new(false);
        native.push(&[3; 4096]);
        let sent = native.poll_transmit_reliable(at, RELIABLE_PAYLOAD).unwrap();
        native.admitted_reliable(
            sent.start,
            sent.transmission,
            0,
            Duration::from_millis(20),
            at,
            Arc::new(AtomicBool::new(true)),
        );
        assert!(native.locally_dropped(sent.start, sent.transmission));
        let retry = native.poll_transmit_reliable(at, RELIABLE_PAYLOAD).unwrap();
        assert!(retry.retransmission && retry.local_retry);

        let mut datagram = Sender::new(false);
        datagram.push(&[3; MAX_SEGMENT]);
        let sent = datagram.poll_transmit(at).unwrap();
        datagram.admitted(
            sent.start,
            sent.transmission,
            0,
            Duration::from_millis(20),
            at,
        );
        let later = at + Duration::from_millis(230);
        datagram.on_timeout(later);
        assert!(datagram.poll_transmit(later).unwrap().retransmission);
    }

    #[test]
    fn native_delivery_still_requests_an_ack_when_the_stream_ack_was_lost() {
        let at = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![7; 32 * 1024]);
        let sent = sender.poll_transmit_reliable(at, RELIABLE_PAYLOAD).unwrap();
        sender.admitted_reliable(
            sent.start,
            sent.transmission,
            0,
            Duration::from_millis(100),
            at,
            Arc::new(AtomicBool::new(true)),
        );
        // QUIC delivery can succeed while the separate DATAGRAM stream ACK
        // disappears. Request another ACK without sending the payload again.
        let later = at + Duration::from_millis(600);
        sender.on_timeout(later);
        let probe = sender
            .poll_transmit_reliable(later, RELIABLE_PAYLOAD)
            .expect("a native flight still needs end-to-end ACK recovery");
        assert!(matches!(probe.frame, Frame::Data { fin: false, ref data, .. } if data.is_empty()));
        assert!(!probe.retransmission);
        assert_eq!(probe.transmission, 0);
    }

    #[test]
    fn a_healthy_native_flight_does_not_hide_later_datagram_loss_on_the_same_path() {
        let at = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![3; 64 * 1024]);
        let native = sender.poll_transmit_reliable(at, RELIABLE_PAYLOAD).unwrap();
        sender.admitted_reliable(
            native.start,
            native.transmission,
            0,
            Duration::from_millis(20),
            at,
            Arc::new(AtomicBool::new(true)),
        );
        let datagram = sender.poll_transmit(at).unwrap();
        sender.admitted(
            datagram.start,
            datagram.transmission,
            0,
            Duration::from_millis(20),
            at,
        );
        // Fill the rest of the flight on the reliable carrier.
        while let Some(sent) = sender.poll_transmit_reliable(at, RELIABLE_PAYLOAD) {
            sender.admitted_reliable(
                sent.start,
                sent.transmission,
                0,
                Duration::from_millis(20),
                at,
                Arc::new(AtomicBool::new(true)),
            );
        }
        let later = at + Duration::from_millis(230);
        sender.on_timeout(later);
        let repair = sender.poll_transmit(later).unwrap();
        assert_eq!(repair.start, datagram.start);
        assert!(repair.retransmission);
        assert!(!sender.lost.contains(&native.start));
    }

    #[test]
    fn transfer_gauges_distinguish_ack_retention_from_peer_window_blockage() {
        let mut sender = Sender::new(false);
        let data = vec![0; sender.limit() as usize * 2];
        sender.push(&data);
        let now = Instant::now();
        assert_eq!(
            sender.pending_data(),
            (data.len() as u64, data.len() as u64, false)
        );
        while sender.poll_transmit(now).is_some() {}
        let (retained, unsent, blocked) = sender.pending_data();
        assert_eq!(retained, data.len() as u64);
        assert!(unsent > 0 && unsent < retained);
        assert!(blocked);
        assert_eq!(
            sender.pending_data(),
            (retained, unsent, blocked),
            "sampling cannot mutate recovery"
        );
    }

    #[test]
    fn mtu_reduction_repairs_old_flights_with_late_callbacks_and_fin() {
        for deliver_old in [false, true] {
            let now = Instant::now();
            let mut sender = Sender::new(false);
            let mut receiver = Receiver::default();
            let bytes: Vec<u8> = (0..12_345).map(|i| (i % 251) as u8).collect();
            sender.push(&bytes);
            sender.finish();
            let mut old = Vec::new();
            while let Some(t) = sender.poll_transmit_sized(now, 1400) {
                sender.admitted(t.start, t.transmission, 0, INITIAL_RTT, now);
                old.push(t);
            }
            assert!(old.iter().any(|t| t.frame.encode().len() == 1400));
            for t in &old {
                sender.mark_lost(t.start);
            }
            let later = now + Duration::from_millis(10);
            let mut ready = Vec::new();
            let first = sender.poll_transmit_sized(later, 700).unwrap();
            assert!(first.frame.encode().len() <= 700);
            let current = sender.segments[&first.start].transmissions;
            // A send/drop callback for the old large record cannot replace
            // the split child's current timer or declare that child lost.
            sender.admitted(old[0].start, old[0].transmission, 1, INITIAL_RTT, later);
            assert!(!sender.locally_dropped(old[0].start, old[0].transmission));
            assert_eq!(sender.segments[&first.start].transmissions, current);
            if let Frame::Data { offset, fin, data } = first.frame {
                ready.extend(receiver.on_data(offset, fin, data, later).unwrap());
            }
            if deliver_old {
                // The old large record may arrive after its smaller repair.
                for t in old.iter().rev() {
                    if let Frame::Data { offset, fin, data } = &t.frame {
                        ready.extend(
                            receiver
                                .on_data(*offset, *fin, data.clone(), later)
                                .unwrap(),
                        );
                    }
                }
            }
            while let Some(t) = sender.poll_transmit_sized(later, 700) {
                assert!(t.frame.encode().len() <= 700);
                sender.admitted(t.start, t.transmission, 1, INITIAL_RTT, later);
                if let Frame::Data { offset, fin, data } = t.frame {
                    ready.extend(receiver.on_data(offset, fin, data, later).unwrap());
                }
            }
            assert_eq!(ready, bytes);
            assert!(sender.pmtu_splits > 0);
            let ack = receiver.take_ack(later + ACK_SPACING, MAX_WINDOW).unwrap();
            sender.on_ack(&ack, later + ACK_SPACING).unwrap();
            assert!(sender.finished());
            assert_eq!(sender.recovery_state(), (bytes.len() as u64, 0, 0, 0, 0));
            assert!(sender.buffer.is_empty());
        }
    }

    #[test]
    fn range_slot_prediction_covers_overlaps_bridges_and_head_repairs() {
        let mut receiver = Receiver::default();
        let now = Instant::now();
        let mut state = 7u64;
        for _ in 0..2048 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let offset = 1 + (state >> 16) % 4096;
            let len = (state as usize % 128) + 1;
            let before = receiver.range_count();
            let needed = receiver.needs_range(offset, len);
            receiver.on_data(offset, false, vec![3; len], now).unwrap();
            assert!(receiver.range_count() <= before + usize::from(needed));
        }
        assert!(!receiver.needs_range(0, 8192));
        receiver.on_data(0, false, vec![3; 8192], now).unwrap();
        assert_eq!(receiver.range_count(), 0);
        assert_eq!(receiver.cumulative(), 8192);
    }

    #[test]
    fn a_reopened_route_does_not_inherit_expired_stream_rtt_maxima() {
        let at = Instant::now();
        let mut sender = Sender::new(false);
        sender.path_rtt[0].sample(Duration::from_millis(500), at);
        sender.transport_rtt[0] = Duration::from_millis(110);
        assert!(
            sender.path_threshold(0, at + Duration::from_secs(3)) < Duration::from_millis(150),
            "an idle/reopened route must use its current native RTT instead of an expired stream sample"
        );
        sender.path_rtt[0].sample(Duration::from_millis(110), at + Duration::from_secs(3));
        assert_eq!(
            sender.path_rtt[0].observed_max(at + Duration::from_secs(3)),
            Some(Duration::from_millis(110)),
            "the first ACK after idle must not rotate an expired sample back into the window"
        );
    }

    #[test]
    fn delayed_sack_ranges_do_not_replace_the_newest_route_rtt_sample() {
        let start = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![7; 3 * MAX_SEGMENT]);
        for delay in [0, 180, 190] {
            let at = start + Duration::from_millis(delay);
            let t = sender.poll_transmit(at).unwrap();
            sender.admitted(t.start, t.transmission, 0, Duration::from_millis(110), at);
        }
        let at = start + Duration::from_millis(300);
        sender
            .on_ack(
                &Ack {
                    cumulative: (3 * MAX_SEGMENT) as u64,
                    limit: INITIAL_WINDOW,
                    ..Default::default()
                },
                at,
            )
            .unwrap();
        assert_eq!(
            sender.path_rtt[0].observed_max(at),
            Some(Duration::from_millis(110)),
            "older bytes in one cumulative/SACK batch must not turn acknowledgment aggregation into path delay"
        );
        assert!(sender.path_threshold(0, at) < Duration::from_millis(150));
    }

    #[test]
    fn later_ack_of_older_sack_ranges_cannot_reinflate_route_rtt() {
        let start = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![7; 3 * MAX_SEGMENT]);
        for delay in [0, 180, 190] {
            let at = start + Duration::from_millis(delay);
            let t = sender.poll_transmit(at).unwrap();
            sender.admitted(t.start, t.transmission, 0, Duration::from_millis(110), at);
        }
        sender
            .on_ack(
                &Ack {
                    ranges: vec![(2 * MAX_SEGMENT as u64, 3 * MAX_SEGMENT as u64)],
                    limit: INITIAL_WINDOW,
                    ..Default::default()
                },
                start + Duration::from_millis(300),
            )
            .unwrap();
        let later = start + Duration::from_millis(800);
        sender
            .on_ack(
                &Ack {
                    cumulative: 3 * MAX_SEGMENT as u64,
                    limit: INITIAL_WINDOW,
                    ..Default::default()
                },
                later,
            )
            .unwrap();
        assert_eq!(
            sender.path_rtt[0].observed_max(later),
            Some(Duration::from_millis(110))
        );
        assert_eq!(
            sender.rtt.observed_max(later),
            Some(Duration::from_millis(110))
        );
        assert!(sender.path_threshold(0, later) < Duration::from_millis(150));
        // A real newer original still reports a changed route; this is not
        // a clamp or an override of native congestion/liveness detection.
        sender.push(&vec![8; MAX_SEGMENT]);
        let sent = start + Duration::from_millis(810);
        let t = sender.poll_transmit(sent).unwrap();
        sender.admitted(t.start, t.transmission, 0, Duration::from_millis(300), sent);
        let now = sent + Duration::from_millis(300);
        sender
            .on_ack(
                &Ack {
                    cumulative: 4 * MAX_SEGMENT as u64,
                    limit: INITIAL_WINDOW,
                    ..Default::default()
                },
                now,
            )
            .unwrap();
        assert_eq!(
            sender.path_rtt[0].observed_max(now),
            Some(Duration::from_millis(300))
        );
    }

    #[test]
    fn a_shared_ack_keeps_the_newest_sample_for_each_original_route() {
        let start = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![7; 4 * MAX_SEGMENT]);
        for (delay, path, rtt) in [(0, 0, 300), (90, 0, 210), (180, 1, 120), (190, 1, 110)] {
            let at = start + Duration::from_millis(delay);
            let t = sender.poll_transmit(at).unwrap();
            sender.admitted(
                t.start,
                t.transmission,
                path,
                Duration::from_millis(rtt),
                at,
            );
        }
        let at = start + Duration::from_millis(300);
        sender
            .on_ack(
                &Ack {
                    cumulative: (4 * MAX_SEGMENT) as u64,
                    limit: INITIAL_WINDOW,
                    ..Default::default()
                },
                at,
            )
            .unwrap();
        assert_eq!(
            sender.path_rtt[0].observed_max(at),
            Some(Duration::from_millis(210))
        );
        assert_eq!(
            sender.path_rtt[1].observed_max(at),
            Some(Duration::from_millis(110))
        );
        assert_eq!(
            sender.rtt.observed_max(at),
            Some(Duration::from_millis(110))
        );
    }

    #[test]
    fn oversized_peer_window_is_rejected_before_credit_changes() {
        let now = Instant::now();
        let mut sender = Sender::new(false);
        for limit in [u64::MAX, MAX_OFFSET, MAX_WINDOW + 1] {
            assert!(
                sender
                    .on_ack(
                        &Ack {
                            limit,
                            ..Default::default()
                        },
                        now
                    )
                    .is_none()
            );
            assert_eq!(sender.limit(), INITIAL_WINDOW);
        }
        assert!(
            sender
                .on_ack(
                    &Ack {
                        limit: MAX_WINDOW,
                        ..Default::default()
                    },
                    now
                )
                .is_some()
        );
        assert_eq!(sender.limit(), MAX_WINDOW);
    }

    #[test]
    fn short_tail_probe_preserves_original_loss_timer_and_is_used_once() {
        let now = Instant::now();
        let mut s = Sender::new(false);
        s.push(&[7; 64]);
        let t = s.poll_transmit(now).unwrap();
        assert!(
            s.tail_probe_deadline().is_none(),
            "no probe before actual admission"
        );
        s.admitted(t.start, t.transmission, 0, Duration::from_millis(50), now);
        let loss = s.fresh_deadline(now, s.path_threshold(0, now));
        let probe_at = s.next_deadline(now).unwrap();
        assert!(probe_at >= now + Duration::from_millis(50) && probe_at < loss);
        assert!(s.on_timeout(probe_at));
        let probe = s.poll_transmit(probe_at).unwrap();
        assert!(probe.tail_probe && probe.retransmission);
        assert!(s.lost.is_empty());
        assert_eq!(s.segments[&0].stalls, 0);
        assert_eq!(s.segments[&0].sent_at, now);
        assert_eq!(s.next_deadline(probe_at), Some(loss));
        s.admitted(
            probe.start,
            probe.transmission,
            1,
            Duration::from_millis(10),
            probe_at,
        );
        assert_eq!(
            s.next_deadline(probe_at),
            Some(loss),
            "probe admission cannot retime the original"
        );
        assert!(!s.locally_dropped(probe.start, probe.transmission));
        assert!(s.poll_transmit(probe_at).is_none());
        s.on_timeout(loss);
        let repair = s.poll_transmit(loss).unwrap();
        assert!(repair.retransmission && !repair.tail_probe);
        assert!(s.tail_probe_deadline().is_none());
    }

    #[test]
    fn full_segment_tail_probe_is_bounded_and_cancelled_by_ack() {
        for bytes in [1032, crate::runtime::MAX_STREAM_PAYLOAD - DATA_HEADER] {
            for acknowledged in [false, true] {
                let now = Instant::now();
                let mut sender = Sender::new(false);
                sender.push(&vec![7; bytes]);
                let original = sender
                    .poll_transmit_sized(now, crate::runtime::MAX_STREAM_PAYLOAD)
                    .unwrap();
                assert!(sender.tail_probe_deadline().is_none());
                sender.admitted(0, original.transmission, 0, Duration::from_millis(90), now);
                let loss = sender.fresh_deadline(now, sender.path_threshold(0, now));
                let (probe_at, _) = sender.tail_probe_deadline().unwrap();
                assert!(probe_at >= now + Duration::from_millis(90) && probe_at < loss);
                if acknowledged {
                    sender
                        .on_ack(
                            &Ack {
                                cumulative: bytes as u64,
                                limit: INITIAL_WINDOW,
                                ..Default::default()
                            },
                            now + Duration::from_millis(90),
                        )
                        .unwrap();
                    assert!(sender.tail_probe_deadline().is_none());
                    sender.on_timeout(probe_at);
                    assert!(sender.poll_transmit(probe_at).is_none());
                } else {
                    sender.on_timeout(probe_at);
                    let probe = sender
                        .poll_transmit_sized(probe_at, crate::runtime::MAX_STREAM_PAYLOAD)
                        .unwrap();
                    assert!(probe.tail_probe && probe.retransmission);
                    sender.admitted(
                        0,
                        probe.transmission,
                        1,
                        Duration::from_millis(90),
                        probe_at,
                    );
                    assert_eq!(sender.next_deadline(probe_at), Some(loss));
                    assert!(sender.poll_transmit(probe_at).is_none());
                }
            }
        }
    }

    #[test]
    fn deferred_tail_probe_does_not_leave_an_expired_wakeup() {
        let now = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![7; 1032]);
        let original = sender
            .poll_transmit_sized(now, crate::runtime::MAX_STREAM_PAYLOAD)
            .unwrap();
        sender.admitted(0, original.transmission, 0, Duration::from_millis(90), now);
        let (probe_at, _) = sender.tail_probe_deadline().unwrap();
        let loss_at = sender.fresh_deadline(now, sender.path_threshold(0, now));
        sender.on_timeout(probe_at);
        // The mux may defer polling this stream while its shared byte budget
        // is occupied. Readiness must survive without a past timer spinning.
        assert!(sender.has_transmit());
        assert_eq!(
            sender.next_deadline(probe_at + Duration::from_millis(1)),
            Some(loss_at)
        );
        let probe = sender
            .poll_transmit_sized(probe_at, crate::runtime::MAX_STREAM_PAYLOAD)
            .unwrap();
        assert!(probe.tail_probe && probe.start == 0);
    }

    #[test]
    fn deferred_ack_probe_does_not_leave_an_expired_wakeup() {
        let now = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![7; RELIABLE_PAYLOAD - DATA_HEADER]);
        let original = sender
            .poll_transmit_reliable(now, RELIABLE_PAYLOAD)
            .unwrap();
        let reachable = Arc::new(AtomicBool::new(true));
        sender.admitted_reliable(
            original.start,
            original.transmission,
            0,
            Duration::from_millis(40),
            now,
            reachable,
        );
        let probe_at = now + sender.probe_interval(now);
        assert!(sender.on_timeout(probe_at));
        assert!(sender.has_transmit());
        // While backpressured before `poll_transmit`, `on_timeout` must not
        // re-fire or leave a past wakeup timer spinning.
        assert!(!sender.on_timeout(probe_at + Duration::from_millis(1)));
        assert!(
            sender
                .next_deadline(probe_at + Duration::from_millis(1))
                .is_none_or(|at| at > probe_at + Duration::from_millis(1))
        );
        let probe = sender
            .poll_transmit_reliable(probe_at + Duration::from_millis(2), RELIABLE_PAYLOAD)
            .unwrap();
        assert_eq!(probe.transmission, 0);
    }

    #[test]
    fn sack_of_a_separate_fin_does_not_turn_a_data_hole_into_a_tail() {
        let now = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&[7; 200]);
        let data = sender.poll_transmit(now).unwrap();
        sender.admitted(0, data.transmission, 0, Duration::from_millis(90), now);
        sender.finish();
        let fin = sender.poll_transmit(now).unwrap();
        assert_eq!(fin.start, 200);
        sender.admitted(
            fin.start,
            fin.transmission,
            0,
            Duration::from_millis(90),
            now,
        );
        sender
            .on_ack(
                &Ack {
                    ranges: vec![(200, 201)],
                    limit: INITIAL_WINDOW,
                    ..Default::default()
                },
                now + Duration::from_millis(90),
            )
            .unwrap();
        assert_eq!(sender.segments.len(), 1);
        assert!(sender.tail_probe_deadline().is_none());

        let mut combined = Sender::new(false);
        combined.push(&[7; 200]);
        combined.finish();
        let data_fin = combined.poll_transmit(now).unwrap();
        combined.admitted(0, data_fin.transmission, 0, Duration::from_millis(90), now);
        assert!(combined.tail_probe_deadline().is_some());
    }

    #[test]
    fn delayed_single_segment_admission_starts_both_tail_and_loss_clocks() {
        let now = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&[7; 200]);
        let original = sender.poll_transmit(now).unwrap();
        assert!(sender.tail_probe_deadline().is_none());
        let admitted = now + Duration::from_millis(90);
        sender.admitted(
            0,
            original.transmission,
            0,
            Duration::from_millis(20),
            admitted,
        );
        let probe_at = admitted + Duration::from_millis(20).mul_f64(1.125) + ACK_DELAY;
        let loss_at = sender.fresh_deadline(admitted, sender.path_threshold(0, admitted));
        assert_eq!(sender.next_deadline(admitted), Some(probe_at));
        sender.admitted(
            0,
            original.transmission,
            1,
            Duration::from_secs(1),
            admitted,
        );
        assert_eq!(sender.next_deadline(admitted), Some(probe_at));
        sender.on_timeout(probe_at);
        let probe = sender.poll_transmit(probe_at).unwrap();
        assert!(probe.tail_probe && probe.retransmission && probe.start == 0);
        sender.admitted(
            0,
            probe.transmission,
            1,
            Duration::from_millis(80),
            probe_at,
        );
        sender.admitted(
            0,
            original.transmission,
            0,
            Duration::from_millis(1),
            probe_at,
        );
        assert_eq!(sender.next_deadline(probe_at), Some(loss_at));
    }

    #[test]
    fn short_ordered_udp_hole_uses_new_same_path_deliveries_once() {
        let now = Instant::now();
        let rtt = Duration::from_millis(100);
        for (udp, route, newer, expect) in [
            (true, 0, 3, true),
            (true, 0, 2, false),
            (true, 1, 3, false),
            (false, 0, 3, false),
        ] {
            let mut sender = Sender::new(false);
            sender.ordered_udp_gap_repair = udp;
            // A previously reordered flight has raised the ordinary loss threshold.
            sender.reorder = REORDER_MAX;
            sender.push(&vec![7; 4 * MAX_SEGMENT]);
            for i in 0..4 {
                let at = now + Duration::from_millis(i);
                let t = sender.poll_transmit(at).unwrap();
                sender.admitted(
                    t.start,
                    t.transmission,
                    if i == 0 { 0 } else { route },
                    rtt,
                    at,
                );
            }
            let ack = Ack {
                cumulative: 0,
                limit: INITIAL_WINDOW,
                duplicate_bytes: 0,
                ranges: vec![(MAX_SEGMENT as u64, ((newer + 1) * MAX_SEGMENT) as u64)],
            };
            let received = now + rtt;
            sender.on_ack(&ack, received).unwrap();
            sender.on_ack(&ack, received).unwrap();
            assert_eq!(sender.head_probe_deadline().is_some(), expect);
            let regular_repair = sender.fresh_deadline(now, sender.path_threshold(0, received));
            if !udp {
                assert!(regular_repair >= now + Duration::from_millis(195));
                sender.on_timeout(regular_repair);
                let t = sender.poll_transmit(regular_repair).unwrap();
                assert!(t.retransmission && !t.head_copy && t.start == 0);
            }
            if expect {
                let (offset, at) = sender.head_probe_deadline().unwrap();
                assert_eq!(offset, 0);
                assert_eq!(at, received + rtt / 4);
                assert!(sender.on_timeout(at));
                let copy = sender.poll_transmit(at).unwrap();
                assert!(copy.head_copy && !copy.tail_probe && copy.start == 0);
                assert!(sender.poll_transmit(at).is_none());
            }
        }
    }

    fn bulk_hole(now: Instant, missing: usize) -> Sender {
        let mut sender = Sender::new(false);
        sender.reorder = REORDER_MAX;
        sender.push(&vec![7; 96 * MAX_SEGMENT]);
        for i in 0..96 {
            let at = now + Duration::from_micros(i * 10);
            let t = sender.poll_transmit(at).unwrap();
            sender.admitted(t.start, t.transmission, 0, Duration::from_millis(100), at);
        }
        sender
            .on_ack(
                &Ack {
                    limit: INITIAL_WINDOW,
                    ranges: vec![(missing as u64 * MAX_SEGMENT as u64, sender.next)],
                    ..Default::default()
                },
                now + Duration::from_millis(100),
            )
            .unwrap();
        sender
    }

    #[test]
    fn persistent_bulk_sack_hole_gets_one_copy_before_the_loss_timer() {
        let now = Instant::now();
        let mut sender = bulk_hole(now, 1);
        let original_timer = sender.fresh_deadline(now, sender.path_threshold(0, now));
        let (_, probe_at) = sender.head_probe_deadline().unwrap();
        assert!(probe_at >= now + Duration::from_millis(125));
        assert!(probe_at < original_timer);
        assert!(!sender.has_transmit(), "a future probe cannot busy-poll");
        assert!(sender.on_timeout(probe_at));
        assert!(sender.has_transmit());
        assert_eq!(
            sender.next_deadline(probe_at),
            Some(original_timer),
            "a queued probe cannot leave an expired wakeup spinning"
        );
        let copy = sender.poll_transmit(probe_at).unwrap();
        assert!(copy.head_copy && copy.retransmission && !copy.tail_probe);
        assert_eq!(copy.start, 0);
        assert!(sender.lost.is_empty());
        assert_eq!(sender.segments[&0].sent_at, now);
        assert_eq!(sender.segments[&0].stalls, 0);
        assert_eq!(sender.next_deadline(probe_at), Some(original_timer));
        assert!(sender.poll_transmit(probe_at).is_none());
    }

    #[test]
    fn a_new_cumulative_ack_cancels_the_bulk_hole_probe() {
        let now = Instant::now();
        let mut sender = bulk_hole(now, 1);
        let (_, probe_at) = sender.head_probe_deadline().unwrap();
        sender
            .on_ack(
                &Ack {
                    cumulative: sender.next,
                    limit: sender.next + INITIAL_WINDOW,
                    ..Default::default()
                },
                probe_at - Duration::from_millis(1),
            )
            .unwrap();
        assert!(sender.head_probe_deadline().is_none());
        assert!(!sender.on_timeout(probe_at));
        assert!(!sender.has_transmit());
        assert!(sender.poll_transmit(probe_at).is_none());
        assert_eq!(sender.retained_from(), sender.written());
        assert!(sender.pending_copies.is_empty());
    }

    #[test]
    fn a_locally_dropped_bulk_probe_keeps_the_original_repair_live() {
        let now = Instant::now();
        let mut sender = bulk_hole(now, 1);
        let (_, at) = sender.head_probe_deadline().unwrap();
        sender.on_timeout(at);
        let copy = sender.poll_transmit(at).unwrap();
        assert!(!sender.locally_dropped(copy.start, copy.transmission));
        assert!(sender.pending_copies.is_empty());
        let loss = sender.next_deadline(at).unwrap();
        sender.on_timeout(loss);
        let repair = sender.poll_transmit(loss).unwrap();
        assert!(repair.retransmission && !repair.head_copy);
        assert_eq!(repair.start, 0);
    }

    #[test]
    fn successive_bulk_holes_cannot_probe_faster_than_one_copy_per_rtt() {
        let now = Instant::now();
        let mut sender = bulk_hole(now, 2);
        let (_, at) = sender.head_probe_deadline().unwrap();
        sender.on_timeout(at);
        let copy = sender.poll_transmit(at).unwrap();
        sender.admitted(
            copy.start,
            copy.transmission,
            1,
            Duration::from_millis(100),
            at,
        );
        sender
            .on_ack(
                &Ack {
                    cumulative: MAX_SEGMENT as u64,
                    limit: INITIAL_WINDOW,
                    ..Default::default()
                },
                at + Duration::from_millis(1),
            )
            .unwrap();
        let (_, next) = sender.head_probe_deadline().unwrap();
        assert!(next >= at + Duration::from_millis(100));
    }

    #[test]
    fn short_probe_ack_cancels_timers_and_a_new_flight_can_probe() {
        let now = Instant::now();
        let mut s = Sender::new(false);
        s.push(&[1; 64]);
        let t = s.poll_transmit(now).unwrap();
        s.admitted(t.start, t.transmission, 0, Duration::from_millis(50), now);
        let at = s.next_deadline(now).unwrap();
        s.on_timeout(at);
        assert!(s.poll_transmit(at).unwrap().tail_probe);
        s.on_ack(
            &Ack {
                cumulative: 64,
                limit: INITIAL_WINDOW,
                ..Default::default()
            },
            at,
        )
        .unwrap();
        assert!(s.next_deadline(at).is_none());
        s.push(&[2; 64]);
        let t = s.poll_transmit(at).unwrap();
        s.admitted(t.start, t.transmission, 0, Duration::from_millis(50), at);
        assert!(s.tail_probe_deadline().is_some());
    }

    #[test]
    fn a_new_stream_probes_its_lost_tail_after_one_measured_rtt() {
        let now = Instant::now();
        let mut s = Sender::new(false);
        // A destination header, then the first request bytes.
        s.push(&[1; 7]);
        let header = s.poll_transmit(now).unwrap();
        s.push(&[2; 64]);
        let request = s.poll_transmit(now).unwrap();
        for t in [&header, &request] {
            s.admitted(t.start, t.transmission, 0, Duration::from_millis(70), now);
        }
        // Only the header arrives; its acknowledgment is the stream's first sample.
        let at = now + Duration::from_millis(73);
        let ack = Ack {
            cumulative: 7,
            limit: INITIAL_WINDOW,
            duplicate_bytes: 0,
            ranges: Vec::new(),
        };
        s.on_ack(&ack, at).unwrap();
        let (probe_at, start) = s.tail_probe_deadline().unwrap();
        assert_eq!(start, 7);
        assert!(
            probe_at <= now + Duration::from_millis(90),
            "{:?}",
            probe_at - now
        );
        let loss_at = s.next_deadline(at).unwrap();
        assert!(loss_at <= now + Duration::from_millis(90));
    }

    #[test]
    fn head_of_line_repair_is_copied_once_after_admission_without_retiming() {
        let now = Instant::now();
        let mut s = Sender::new(false);
        s.push(&[7; 3 * MAX_SEGMENT]);
        for _ in 0..3 {
            let t = s.poll_transmit(now).unwrap();
            s.admitted(t.start, t.transmission, 0, Duration::from_millis(50), now);
        }
        // The first segment is lost; later data arrived.
        let ack = Ack {
            cumulative: 0,
            limit: INITIAL_WINDOW,
            duplicate_bytes: 0,
            ranges: vec![(MAX_SEGMENT as u64, 3 * MAX_SEGMENT as u64)],
        };
        let at = now + Duration::from_millis(60);
        s.on_ack(&ack, at).unwrap();
        let loss = s.next_deadline(at).unwrap();
        s.on_timeout(loss);
        let repair = s.poll_transmit(loss).unwrap();
        assert!(repair.retransmission && !repair.head_copy && repair.start == 0);
        assert!(
            !s.has_transmit() && s.poll_transmit(loss).is_none(),
            "no copy before the repair is admitted"
        );
        s.admitted(0, repair.transmission, 1, Duration::from_millis(50), loss);
        let deadline = s.next_deadline(loss);
        assert!(s.has_transmit());
        let copy = s.poll_transmit(loss).unwrap();
        assert!(copy.head_copy && !copy.tail_probe && copy.start == 0);
        s.admitted(0, copy.transmission, 2, Duration::from_millis(10), loss);
        assert_eq!(
            s.next_deadline(loss),
            deadline,
            "the copy keeps the repair's timer"
        );
        assert!(!s.locally_dropped(0, copy.transmission));
        assert!(s.lost.is_empty() && s.poll_transmit(loss).is_none());
        // A later repair of the same segment is not copied again.
        let again = s.next_deadline(loss).unwrap();
        s.on_timeout(again);
        let repair = s.poll_transmit(again).unwrap();
        s.admitted(0, repair.transmission, 0, Duration::from_millis(50), again);
        assert!(!repair.head_copy && s.poll_transmit(again).is_none());
    }

    #[test]
    fn only_the_head_of_line_repair_is_copied() {
        let now = Instant::now();
        let mut s = Sender::new(false);
        s.push(&[7; 3 * MAX_SEGMENT]);
        for _ in 0..3 {
            let t = s.poll_transmit(now).unwrap();
            s.admitted(t.start, t.transmission, 0, Duration::from_millis(50), now);
        }
        // The first two segments are lost; the third arrived.
        let ack = Ack {
            cumulative: 0,
            limit: INITIAL_WINDOW,
            duplicate_bytes: 0,
            ranges: vec![(2 * MAX_SEGMENT as u64, 3 * MAX_SEGMENT as u64)],
        };
        let at = now + Duration::from_millis(60);
        s.on_ack(&ack, at).unwrap();
        let loss = s.next_deadline(at).unwrap();
        s.on_timeout(loss);
        let mut sent = Vec::new();
        while let Some(t) = s.poll_transmit(loss) {
            s.admitted(t.start, t.transmission, 0, Duration::from_millis(50), loss);
            sent.push((t.start, t.head_copy));
        }
        let segment = MAX_SEGMENT as u64;
        assert_eq!(sent, [(0, false), (segment, false), (0, true)]);
    }

    #[test]
    fn duplicates_from_a_copy_are_not_reordering_evidence() {
        let now = Instant::now();
        let mut s = Sender::new(false);
        s.push(&[7; 2 * MAX_SEGMENT]);
        for _ in 0..2 {
            let t = s.poll_transmit(now).unwrap();
            s.admitted(t.start, t.transmission, 0, Duration::from_millis(50), now);
        }
        let at = now + Duration::from_millis(60);
        let ack = |duplicate_bytes, cumulative| Ack {
            cumulative,
            limit: INITIAL_WINDOW,
            duplicate_bytes,
            ranges: vec![(MAX_SEGMENT as u64, 2 * MAX_SEGMENT as u64)]
                .into_iter()
                .filter(|r| r.0 >= cumulative)
                .collect(),
        };
        s.on_ack(&ack(0, 0), at).unwrap();
        let loss = s.next_deadline(at).unwrap();
        s.on_timeout(loss);
        let repair = s.poll_transmit(loss).unwrap();
        s.admitted(0, repair.transmission, 0, Duration::from_millis(50), loss);
        let copy = s.poll_transmit(loss).unwrap();
        assert!(copy.head_copy);
        s.admitted(
            copy.start,
            copy.transmission,
            0,
            Duration::from_millis(50),
            loss,
        );
        let reorder = s.reorder;
        let segment = MAX_SEGMENT as u64;
        let done = 2 * segment;
        assert!(!s.on_ack(&ack(segment, done), loss).unwrap().1);
        assert!(
            s.reorder <= reorder,
            "the expected duplicate is not spurious"
        );
        assert!(s.on_ack(&ack(2 * segment, done), loss).unwrap().1);
        assert!(s.reorder > reorder, "a further duplicate still is");
    }

    #[test]
    fn an_unsent_head_copy_cannot_hide_a_spurious_repair() {
        for dropped in [false, true] {
            let now = Instant::now();
            let mut s = Sender::new(false);
            s.push(&[7; 2 * MAX_SEGMENT]);
            for _ in 0..2 {
                let t = s.poll_transmit(now).unwrap();
                s.admitted(t.start, t.transmission, 0, Duration::from_millis(50), now);
            }
            let n = MAX_SEGMENT as u64;
            let at = now + Duration::from_millis(60);
            s.on_ack(
                &Ack {
                    cumulative: 0,
                    limit: INITIAL_WINDOW,
                    duplicate_bytes: 0,
                    ranges: vec![(n, 2 * n)],
                },
                at,
            )
            .unwrap();
            let loss = s.next_deadline(at).unwrap();
            s.on_timeout(loss);
            let repair = s.poll_transmit(loss).unwrap();
            s.admitted(0, repair.transmission, 0, Duration::from_millis(50), loss);
            let copy = s.poll_transmit(loss).unwrap();
            assert!(copy.head_copy);
            let deadline = s.next_deadline(loss);
            if dropped {
                assert!(!s.locally_dropped(0, copy.transmission));
                assert!(s.pending_copies.is_empty());
            }
            // The original arrives after its repair. The copy is still local
            // or was discarded there, so it cannot explain the duplicate.
            let reorder = s.reorder;
            assert!(
                s.on_ack(
                    &Ack {
                        cumulative: 2 * n,
                        limit: INITIAL_WINDOW,
                        duplicate_bytes: n,
                        ranges: vec![],
                    },
                    loss
                )
                .unwrap()
                .1,
                "dropped={dropped}"
            );
            assert!(s.reorder > reorder);
            assert!(deadline.is_some());
            if !dropped {
                // Discarding a queued copy must still retire its accounting
                // after the original's ACK has removed the segment.
                assert!(!s.locally_dropped(0, copy.transmission));
                assert!(s.pending_copies.is_empty());
            }
        }
    }

    #[test]
    fn a_copy_admitted_after_acknowledgment_is_credited_only_once() {
        let now = Instant::now();
        let mut s = Sender::new(false);
        s.push(&[7; 64]);
        let original = s.poll_transmit(now).unwrap();
        s.admitted(0, original.transmission, 0, Duration::from_millis(50), now);
        let probe_at = s.next_deadline(now).unwrap();
        s.on_timeout(probe_at);
        let copy = s.poll_transmit(probe_at).unwrap();
        assert!(copy.tail_probe);
        let ack = |duplicate_bytes| Ack {
            cumulative: 64,
            limit: INITIAL_WINDOW,
            duplicate_bytes,
            ranges: vec![],
        };
        s.on_ack(&ack(0), probe_at).unwrap();
        assert!(s.segments.is_empty());
        assert_eq!(s.expected_duplicates, 0, "a queued copy grants no credit");
        // The repair can still leave the local queue after its segment was
        // acknowledged; duplicated callbacks must not add a second allowance.
        for _ in 0..2 {
            s.admitted(0, copy.transmission, 1, Duration::from_millis(50), probe_at);
        }
        assert!(!s.on_ack(&ack(64), probe_at).unwrap().1);
        assert!(s.on_ack(&ack(128), probe_at).unwrap().1);
        assert!(s.pending_copies.is_empty());
    }

    #[test]
    fn short_tail_probe_does_not_inherit_an_old_ack_outlier() {
        let now = Instant::now();
        let mut s = Sender::new(false);
        s.path_rtt[0].sample(Duration::from_millis(200), now - Duration::from_millis(250));
        for i in 1..20 {
            s.path_rtt[0].sample(
                Duration::from_millis(70),
                now - Duration::from_millis(250 - i * 10),
            );
        }
        s.push(&[7; 64]);
        let t = s.poll_transmit(now).unwrap();
        s.admitted(t.start, t.transmission, 0, Duration::from_millis(70), now);
        let full_repair = s.fresh_deadline(now, s.path_threshold(0, now));
        let (probe, _) = s.tail_probe_deadline().unwrap();
        assert!(
            probe <= now + Duration::from_millis(110),
            "{:?}",
            probe - now
        );
        assert!(full_repair >= now + Duration::from_millis(200));
        s.on_timeout(probe);
        assert!(s.poll_transmit(probe).unwrap().tail_probe);
        assert_eq!(s.next_deadline(probe), Some(full_repair));
    }

    #[test]
    fn bulk_and_slow_return_path_do_not_get_an_early_short_probe() {
        let now = Instant::now();
        let mut bulk = Sender::new(false);
        bulk.push(&vec![0; MAX_SEGMENT * 2]);
        for _ in 0..2 {
            let t = bulk.poll_transmit(now).unwrap();
            bulk.admitted(t.start, t.transmission, 0, Duration::from_millis(10), now);
        }
        assert!(bulk.tail_probe_deadline().is_none());
        let mut short = Sender::new(false);
        short.push(&[0; 64]);
        let t = short.poll_transmit(now).unwrap();
        short.admitted(t.start, t.transmission, 0, Duration::from_millis(10), now);
        short.path_rtt[0].sample(Duration::from_millis(200), now);
        assert!(short.tail_probe_deadline().unwrap().0 >= now + Duration::from_millis(200));
    }

    #[test]
    fn delayed_ack_cannot_move_loss_recovery_past_the_peer_failure_deadline() {
        let now = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![7; MAX_SEGMENT * 2]);
        for _ in 0..2 {
            let sent = sender.poll_transmit(now).unwrap();
            sender.admitted(
                sent.start,
                sent.transmission,
                0,
                Duration::from_millis(5),
                now,
            );
        }
        // A delayed first-transmission ACK can inflate the RTT variance bound.
        // It cannot postpone repairing the preceding hole until after DEAD_AFTER.
        let late = now + Duration::from_secs(10);
        sender
            .on_ack(
                &Ack {
                    cumulative: 0,
                    limit: INITIAL_WINDOW,
                    duplicate_bytes: 0,
                    ranges: vec![(MAX_SEGMENT as u64, (MAX_SEGMENT * 2) as u64)],
                },
                late,
            )
            .unwrap();
        let recovery = sender
            .poll_transmit(late)
            .expect("repair the old hole despite inflated RTT");
        assert!(recovery.retransmission);
        assert_eq!(recovery.start, 0);
        assert!(!sender.failed(late));
    }

    #[test]
    fn a_finished_receiver_keeps_an_acknowledgment_of_everything() {
        let now = Instant::now();
        let mut r = Receiver::default();
        assert_eq!(r.on_data(0, true, b"done".to_vec(), now).unwrap(), b"done");
        assert!(r.final_ack().is_none(), "not yet consumed");
        r.consumed(4, MAX_WINDOW);
        let ack = r.final_ack().unwrap();
        // Four bytes and the virtual FIN byte, as the live acknowledgment says.
        assert_eq!(ack.cumulative, 5);
        assert_eq!(r.take_ack(now, MAX_WINDOW).unwrap().cumulative, 5);
        assert!(ack.ranges.is_empty());
    }

    fn data(frame: &Frame) -> (u64, bool, Vec<u8>) {
        match frame {
            Frame::Data { offset, fin, data } => (*offset, *fin, data.clone()),
            other => panic!("expected data, got {other:?}"),
        }
    }

    #[test]
    fn frames_round_trip_and_malformed_input_is_rejected() {
        let frames = [
            Frame::Data {
                offset: 7,
                fin: true,
                data: vec![1, 2, 3],
            },
            Frame::Data {
                offset: 0,
                fin: false,
                data: Vec::new(),
            },
            Frame::Ack(Ack {
                cumulative: 10,
                limit: 99,
                duplicate_bytes: 4,
                ranges: vec![(12, 15), (20, 21)],
            }),
            Frame::Reset,
        ];
        for frame in frames {
            assert_eq!(Frame::decode(&frame.encode()), Some(frame));
        }
        let full = Frame::Data {
            offset: 0,
            fin: false,
            data: vec![9; MAX_SEGMENT],
        }
        .encode();
        assert_eq!(full.len(), MAX_PAYLOAD);
        let ranges = (0..MAX_RANGES as u64)
            .map(|i| (2 * i + 1, 2 * i + 2))
            .collect();
        let ack = Frame::Ack(Ack {
            cumulative: 0,
            limit: 1,
            duplicate_bytes: 0,
            ranges,
        })
        .encode();
        assert!(ack.len() <= MAX_PAYLOAD);
        // Adjacent or overlapping ranges, unknown bits and trailing bytes are invalid.
        let mut adjacent = Frame::Ack(Ack {
            cumulative: 10,
            limit: 0,
            duplicate_bytes: 0,
            ranges: vec![(12, 15), (20, 21)],
        })
        .encode();
        adjacent[ACK_HEADER + 8..ACK_HEADER + 12].copy_from_slice(&5u32.to_be_bytes());
        assert_eq!(Frame::decode(&adjacent), None);
        let mut touching = Frame::Ack(Ack {
            cumulative: 10,
            limit: 0,
            duplicate_bytes: 0,
            ranges: vec![(12, 15)],
        })
        .encode();
        touching[ACK_HEADER..ACK_HEADER + 4].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(Frame::decode(&touching), None);
        assert_eq!(Frame::decode(&[DATA, 4, 0, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(Frame::decode(&[RESET, 0]), None);
        assert_eq!(Frame::decode(&[9]), None);
        assert_eq!(Frame::decode(&[]), None);
        assert_eq!(stream_id(data_flow(5)), Some(5));
        assert_eq!(stream_id(ack_flow(5)), Some(5));
        assert_eq!(stream_id(5), None);
    }

    /// Lossy, reordering channel. Record deduplication happens below streams.
    struct Link {
        seed: u64,
    }
    impl Link {
        fn next(&mut self) -> u64 {
            self.seed ^= self.seed << 13;
            self.seed ^= self.seed >> 7;
            self.seed ^= self.seed << 17;
            self.seed
        }
    }

    fn transfer(size: usize, loss: u64, seed: u64) -> (Snapshot, Duration) {
        let payload: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        let mut sender = Sender::new(false);
        let mut receiver = Receiver::default();
        let mut link = Link { seed };
        let start = Instant::now();
        let mut now = start;
        let mut supplied = 0;
        let mut output = Vec::new();
        // (arrival, frame) in flight each way. Paths differ: 10 ms or 40 ms.
        let mut forward: Vec<(Instant, Frame)> = Vec::new();
        let mut backward: Vec<(Instant, Frame)> = Vec::new();
        let mut stats = Snapshot::default();
        let step = Duration::from_micros(250);
        while !(sender.finished() && receiver.finished()) {
            assert!(now - start < Duration::from_secs(120), "transfer stalled");
            let window = 512 * 1024;
            let room = (sender.limit() + 64 * 1024).saturating_sub(sender.written());
            let n = (room as usize).min(payload.len() - supplied).min(64 * 1024);
            if n > 0 {
                sender.push(&payload[supplied..supplied + n]);
                supplied += n;
            }
            if supplied == payload.len() {
                sender.finish();
            }
            // At most four segments per 250 us, about 127 Mbit/s.
            for _ in 0..4 {
                let Some(t) = sender.poll_transmit(now) else {
                    break;
                };
                stats.segments_sent += 1;
                if t.retransmission {
                    stats.retransmitted_segments += 1;
                }
                if link.next() % 100 < loss {
                    continue;
                }
                let delay = if link.next().is_multiple_of(2) {
                    10
                } else {
                    40
                };
                forward.push((now + Duration::from_millis(delay), t.frame.clone()));
            }
            if sender.next_deadline(now).is_some_and(|at| now >= at) && sender.on_timeout(now) {
                stats.probe_timeouts += 1;
            }
            forward.sort_by_key(|(at, _)| *at);
            while forward.first().is_some_and(|(at, _)| *at <= now) {
                let (offset, fin, bytes) = data(&forward.remove(0).1);
                let ready = receiver
                    .on_data(offset, fin, bytes, now)
                    .expect("valid data");
                output.extend(ready);
            }
            let consumed = output.len() as u64 - (receiver.consumed);
            receiver.consumed(consumed, window);
            if let Some(ack) = receiver.take_ack(now, window)
                && link.next() % 100 >= loss
            {
                backward.push((now + Duration::from_millis(10), Frame::Ack(ack)));
            }
            while backward.first().is_some_and(|(at, _)| *at <= now) {
                let Frame::Ack(ack) = backward.remove(0).1 else {
                    unreachable!()
                };
                let (_, spurious) = sender.on_ack(&ack, now).expect("valid ack");
                stats.spurious_retransmit_reports += u64::from(spurious);
            }
            now += step;
        }
        assert_eq!(output, payload, "stream integrity");
        assert!(sender.retained_from() == payload.len() as u64);
        (stats, now - start)
    }

    #[test]
    fn lossy_reordering_multipath_transfer_is_exact_and_bounded() {
        // Bounds are about six times the deterministic results of this model.
        for (loss, seed, bound) in [(0, 1, 200), (2, 2, 2_000), (10, 3, 3_500), (30, 4, 10_000)] {
            let (stats, elapsed) = transfer(600_000, loss, seed);
            if loss == 0 {
                assert_eq!(stats.retransmitted_segments, 0, "no loss, no retransmit");
            }
            assert!(
                stats.segments_sent <= 607 + 607 * loss / 10,
                "loss {loss}: {}",
                stats.segments_sent
            );
            assert!(
                elapsed < Duration::from_millis(bound),
                "loss {loss}: {elapsed:?}"
            );
        }
    }

    #[test]
    fn empty_streams_announce_reliably_and_finish() {
        let t0 = Instant::now();
        let mut sender = Sender::new(true);
        let first = sender.poll_transmit(t0).expect("open");
        assert_eq!(data(&first.frame), (0, false, Vec::new()));
        assert!(sender.poll_transmit(t0).is_none());
        // The open was lost; the probe timeout repeats it.
        let deadline = sender.next_deadline(t0).expect("open timer");
        assert!(sender.on_timeout(deadline));
        let again = sender.poll_transmit(deadline).expect("open repeated");
        assert_eq!(data(&again.frame), (0, false, Vec::new()));
        let mut receiver = Receiver::default();
        assert!(
            receiver
                .on_data(0, false, Vec::new(), deadline)
                .unwrap()
                .is_empty()
        );
        let ack = receiver
            .take_ack(deadline, INITIAL_WINDOW)
            .expect("immediate ack");
        sender.on_ack(&ack, deadline).unwrap();
        assert!(
            sender.next_deadline(deadline).is_none(),
            "acknowledged open stops probing"
        );
        sender.finish();
        let fin = sender.poll_transmit(deadline).unwrap();
        assert_eq!(data(&fin.frame), (0, true, Vec::new()));
        let (offset, fin_flag, bytes) = data(&fin.frame);
        receiver.on_data(offset, fin_flag, bytes, deadline).unwrap();
        assert!(receiver.fin_received() && receiver.finished());
        let ack = receiver.take_ack(deadline, INITIAL_WINDOW).unwrap();
        assert_eq!(ack.cumulative, 1);
        sender.on_ack(&ack, deadline).unwrap();
        assert!(sender.finished());
    }

    #[test]
    fn window_limits_sending_and_closed_window_is_probed() {
        let t0 = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![1; INITIAL_WINDOW as usize + 5000]);
        let mut receiver = Receiver::default();
        let mut sent = 0;
        while let Some(t) = sender.poll_transmit(t0) {
            let (offset, fin, bytes) = data(&t.frame);
            sent += bytes.len() as u64;
            receiver.on_data(offset, fin, bytes, t0).unwrap();
        }
        assert_eq!(sent, INITIAL_WINDOW);
        // Data past the advertised window is a violation.
        assert_eq!(
            receiver.on_data(INITIAL_WINDOW, false, vec![0], t0),
            Err(Violation::FlowControl)
        );
        // Everything is acknowledged but the application consumed nothing.
        let ack = receiver.take_ack(t0, 0).unwrap();
        assert_eq!(ack.limit, INITIAL_WINDOW);
        sender.on_ack(&ack, t0).unwrap();
        assert!(!sender.has_transmit());
        let deadline = sender.next_deadline(t0).expect("window probe timer");
        assert!(sender.on_timeout(deadline));
        let probe = sender.poll_transmit(deadline).unwrap();
        assert_eq!(data(&probe.frame), (INITIAL_WINDOW, false, Vec::new()));
        receiver.consumed(INITIAL_WINDOW, INITIAL_WINDOW);
        let (offset, fin, bytes) = data(&probe.frame);
        receiver.on_data(offset, fin, bytes, deadline).unwrap();
        let ack = receiver.take_ack(deadline, INITIAL_WINDOW).unwrap();
        assert_eq!(ack.limit, 2 * INITIAL_WINDOW);
        sender.on_ack(&ack, deadline).unwrap();
        assert!(sender.has_transmit());
    }

    #[test]
    fn selective_ack_retransmits_only_the_gap_after_the_reorder_threshold() {
        let t0 = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![3; 4 * MAX_SEGMENT]);
        let mut segments = Vec::new();
        for i in 0..4 {
            segments.push(sender.poll_transmit(t0 + Duration::from_millis(i)).unwrap());
        }
        let mut receiver = Receiver::default();
        let at = t0 + Duration::from_millis(20);
        for t in segments.iter().skip(1) {
            let (offset, fin, bytes) = data(&t.frame);
            receiver.on_data(offset, fin, bytes, at).unwrap();
        }
        let ack = receiver.take_ack(at + ACK_DELAY, INITIAL_WINDOW).unwrap();
        assert_eq!(ack.cumulative, 0);
        assert_eq!(
            ack.ranges,
            vec![(MAX_SEGMENT as u64, 4 * MAX_SEGMENT as u64)]
        );
        sender.on_ack(&ack, at).unwrap();
        // Not yet: the first segment may still be on a slower path.
        assert!(sender.poll_transmit(at).is_none());
        let deadline = sender.next_deadline(at).unwrap();
        assert!(deadline > at);
        sender.on_timeout(deadline);
        let repair = sender.poll_transmit(deadline).unwrap();
        assert!(repair.retransmission);
        assert_eq!(data(&repair.frame).0, 0);
        assert!(
            sender.poll_transmit(deadline).is_none(),
            "acknowledged ranges stay acknowledged"
        );
        // A duplicate report widens the reorder threshold.
        let (offset, fin, bytes) = data(&segments[0].frame);
        receiver
            .on_data(offset, fin, bytes.clone(), deadline)
            .unwrap();
        receiver.on_data(offset, fin, bytes, deadline).unwrap();
        let before = sender.threshold(deadline);
        let ack = receiver.take_ack(deadline, INITIAL_WINDOW).unwrap();
        assert_eq!(ack.cumulative, 4 * MAX_SEGMENT as u64);
        let (released, spurious) = sender.on_ack(&ack, deadline).unwrap();
        assert_eq!((released, spurious), (4 * MAX_SEGMENT as u64, true));
        assert!(sender.threshold(deadline) > before);
    }

    #[test]
    fn count_driven_acknowledgements_are_spaced_but_signals_are_not() {
        let t0 = Instant::now();
        let mut receiver = Receiver::default();
        let segment = vec![1; MAX_SEGMENT];
        let mut offset = 0;
        let mut take = |receiver: &mut Receiver, at: Instant, n: u32| {
            for _ in 0..n {
                receiver
                    .on_data(offset, false, segment.clone(), at)
                    .unwrap();
                offset += MAX_SEGMENT as u64;
            }
            receiver.take_ack(at, MAX_WINDOW)
        };
        assert!(
            take(&mut receiver, t0, ACK_EVERY).is_some(),
            "first count ACK is immediate"
        );
        let soon = t0 + Duration::from_millis(1);
        assert!(take(&mut receiver, soon, 3 * ACK_EVERY).is_none(), "spaced");
        assert_eq!(receiver.next_deadline(), Some(t0 + ACK_SPACING));
        let ack = receiver.take_ack(t0 + ACK_SPACING, MAX_WINDOW).unwrap();
        assert_eq!(
            ack.cumulative,
            4 * u64::from(ACK_EVERY) * MAX_SEGMENT as u64
        );
        // A duplicate is a loss-recovery signal and is acknowledged at once.
        let again = t0 + ACK_SPACING + Duration::from_millis(1);
        receiver.on_data(0, false, segment.clone(), again).unwrap();
        assert!(receiver.take_ack(again, MAX_WINDOW).is_some());
    }

    #[test]
    fn shared_bulk_spacing_coalesces_data_acks_but_preserves_window_updates() {
        let t0 = Instant::now();
        let mut receiver = Receiver::default();
        receiver.set_bulk_ack_spacing(true);
        receiver.on_data(0, false, Vec::new(), t0).unwrap();
        assert!(receiver.take_ack(t0, INITIAL_WINDOW).is_some());

        let now = t0 + Duration::from_millis(1);
        for i in 0..ACK_EVERY {
            receiver.on_data(u64::from(i), false, vec![0], now).unwrap();
        }
        assert_eq!(receiver.next_deadline(), Some(t0 + 4 * ACK_SPACING));
        assert!(
            receiver
                .take_ack(t0 + ACK_SPACING, INITIAL_WINDOW)
                .is_none()
        );

        receiver.consumed(u64::from(ACK_EVERY), MAX_WINDOW);
        let ack = receiver.take_ack(now, MAX_WINDOW).unwrap();
        assert_eq!(ack.cumulative, u64::from(ACK_EVERY));
        assert_eq!(ack.limit, MAX_WINDOW + u64::from(ACK_EVERY));
    }

    #[test]
    fn duplicate_repair_bursts_coalesce_feedback_without_delaying_fin_or_probes() {
        let t0 = Instant::now();
        let mut receiver = Receiver::default();
        let segment = vec![1; MAX_SEGMENT];
        receiver.on_data(0, false, segment.clone(), t0).unwrap();
        receiver.take_ack(t0 + ACK_DELAY, MAX_WINDOW).unwrap();
        let first = t0 + ACK_DELAY + Duration::from_micros(1);
        receiver.on_data(0, false, segment.clone(), first).unwrap();
        assert!(
            receiver.take_ack(first, MAX_WINDOW).is_some(),
            "first duplicate reports immediately"
        );
        for i in 1..1000 {
            let at = first + Duration::from_micros(i);
            receiver.on_data(0, false, segment.clone(), at).unwrap();
            assert!(
                receiver.take_ack(at, MAX_WINDOW).is_none(),
                "burst must not rebuild and queue a SACK per duplicate"
            );
        }
        let due = first + ACK_SPACING;
        assert_eq!(receiver.next_deadline(), Some(due));
        let ack = receiver.take_ack(due, MAX_WINDOW).unwrap();
        assert_eq!(ack.duplicate_bytes, 1000 * MAX_SEGMENT as u64);
        assert_eq!(ack.cumulative, MAX_SEGMENT as u64);
        let now = due + Duration::from_micros(1);
        receiver.on_data(0, false, segment, now).unwrap();
        assert!(receiver.take_ack(now, MAX_WINDOW).is_none());
        receiver
            .on_data(MAX_SEGMENT as u64, true, Vec::new(), now)
            .unwrap();
        assert_eq!(
            receiver.take_ack(now, MAX_WINDOW).unwrap().cumulative,
            MAX_SEGMENT as u64 + 1
        );
        receiver.on_data(0, false, Vec::new(), now).unwrap();
        assert!(
            receiver.take_ack(now, MAX_WINDOW).is_some(),
            "window probes remain immediate"
        );
    }

    #[test]
    fn holes_beyond_one_frame_acknowledge_the_newest_data() {
        let t0 = Instant::now();
        let count = 2 * (MAX_RANGES + 10);
        let mut sender = Sender::new(false);
        sender.push(&vec![5; count * MAX_SEGMENT]);
        let segments: Vec<_> = (0..count)
            .map(|_| sender.poll_transmit(t0).unwrap())
            .collect();
        let mut receiver = Receiver::default();
        let at = t0 + Duration::from_millis(20);
        // Every even segment is lost: one hole below each received segment.
        for t in segments.iter().skip(1).step_by(2) {
            let (offset, fin, bytes) = data(&t.frame);
            receiver.on_data(offset, fin, bytes, at).unwrap();
        }
        let ack = receiver.take_ack(at + ACK_DELAY, INITIAL_WINDOW).unwrap();
        assert_eq!(ack.ranges.len(), MAX_RANGES);
        assert_eq!(
            ack.ranges.last().unwrap().1,
            (count * MAX_SEGMENT) as u64,
            "the newest range is reported"
        );
        assert_eq!(
            Frame::decode(&Frame::Ack(ack.clone()).encode()),
            Some(Frame::Ack(ack.clone()))
        );
        sender.on_ack(&ack, at).unwrap();
        let deadline = sender.next_deadline(at).unwrap();
        sender.on_timeout(deadline);
        let mut repaired = Vec::new();
        while let Some(t) = sender.poll_transmit(deadline) {
            repaired.push(data(&t.frame).0 / MAX_SEGMENT as u64);
        }
        // The oldest received data was carried by earlier acknowledgments in a
        // real flow; here it stays unreported and may repeat. Nothing in the
        // reported ranges does.
        let unreported = (count - 2 * MAX_RANGES) as u64;
        assert!(
            repaired.iter().all(|i| i % 2 == 0 || *i < unreported),
            "{repaired:?}"
        );
        assert!(repaired.contains(&(count as u64 - 2)));

        // A repair of an old hole is the most recent arrival and is described
        // although more than one frame of newer ranges lies above it.
        let (offset, fin, bytes) = data(&segments[2].frame);
        receiver.on_data(offset, fin, bytes, deadline).unwrap();
        let ack = receiver
            .take_ack(deadline + ACK_DELAY, INITIAL_WINDOW)
            .unwrap();
        assert_eq!(ack.ranges.len(), MAX_RANGES);
        let segment = MAX_SEGMENT as u64;
        assert!(
            ack.ranges.contains(&(segment, 4 * segment)),
            "{:?}",
            ack.ranges[0]
        );
        assert_eq!(ack.ranges.last().unwrap().1, count as u64 * segment);
        assert!(ack.ranges.windows(2).all(|w| w[0].1 < w[1].0));
    }

    #[test]
    fn data_after_one_hole_is_held_as_one_range() {
        let now = Instant::now();
        let mut receiver = Receiver::default();
        let segment = MAX_SEGMENT as u64;
        for i in 1..100u64 {
            let ready = receiver
                .on_data(i * segment, false, vec![i as u8; MAX_SEGMENT], now)
                .unwrap();
            assert!(ready.is_empty());
        }
        assert_eq!(receiver.ranges.len(), 1);
        let ack = receiver.take_ack(now, INITIAL_WINDOW).unwrap();
        assert_eq!(ack.ranges, vec![(segment, 100 * segment)]);
        let ready = receiver
            .on_data(0, false, vec![0; MAX_SEGMENT], now)
            .unwrap();
        let expected: Vec<u8> = (0..100u8)
            .flat_map(|i| std::iter::repeat_n(i, MAX_SEGMENT))
            .collect();
        assert_eq!(ready, expected);
        assert_eq!(receiver.buffered(), 100 * segment);
        assert!(receiver.ranges.is_empty());
    }

    #[test]
    fn fast_path_loss_does_not_wait_for_an_unrelated_slow_path() {
        let t0 = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![1; MAX_SEGMENT * 3]);
        for (i, path, rtt) in [(0, 0, 20), (1, 1, 200), (2, 0, 20)] {
            let at = t0 + Duration::from_millis(i);
            let t = sender.poll_transmit(at).unwrap();
            sender.admitted(
                t.start,
                t.transmission,
                path,
                Duration::from_millis(rtt),
                at,
            );
        }
        let at = t0 + Duration::from_millis(22);
        sender
            .on_ack(
                &Ack {
                    cumulative: 0,
                    limit: INITIAL_WINDOW,
                    duplicate_bytes: 0,
                    ranges: vec![(2 * MAX_SEGMENT as u64, 3 * MAX_SEGMENT as u64)],
                },
                at,
            )
            .unwrap();
        let deadline = sender.next_deadline(at).unwrap();
        assert!(deadline < t0 + Duration::from_millis(100));
        sender.on_timeout(deadline);
        let repair = sender.poll_transmit(deadline).unwrap();
        assert_eq!(repair.start, 0);
        assert!(repair.retransmission);
        assert!(
            sender.poll_transmit(deadline).is_none(),
            "slow segment is still within its route RTT"
        );
    }

    #[test]
    fn admission_restarts_the_clock_and_stale_copies_cannot_move_it() {
        let t0 = Instant::now();
        let mut sender = Sender::new(false);
        // Leave unsent data so this checks the normal loss/admission clock,
        // independently of the earlier single-segment tail probe.
        sender.push(&[1; 2 * MAX_SEGMENT]);
        let t = sender.poll_transmit(t0).unwrap();
        let at = t0 + Duration::from_millis(90);
        sender.admitted(t.start, t.transmission, 0, Duration::from_millis(20), at);
        let deadline = sender.next_deadline(at).unwrap();
        assert!(deadline > at + Duration::from_millis(25));
        sender.admitted(t.start, t.transmission, 1, Duration::from_secs(1), at);
        assert_eq!(
            sender.next_deadline(at),
            Some(deadline),
            "a copy cannot replace the first admission"
        );
        sender.on_timeout(deadline);
        let repair = sender.poll_transmit(deadline).unwrap();
        assert!(repair.start == 0 && repair.retransmission && !repair.tail_probe);
        sender.admitted(
            repair.start,
            repair.transmission,
            1,
            Duration::from_millis(80),
            deadline,
        );
        let retry_deadline = sender.next_deadline(deadline);
        sender.admitted(
            t.start,
            t.transmission,
            0,
            Duration::from_millis(1),
            deadline,
        );
        assert_eq!(
            sender.next_deadline(deadline),
            retry_deadline,
            "a stale callback cannot retime a retransmission"
        );
    }

    #[test]
    fn local_drop_retransmits_only_the_current_transmission() {
        let t0 = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&[5; 100]);
        let first = sender.poll_transmit(t0).unwrap();
        assert!(sender.locally_dropped(first.start, first.transmission));
        assert!(
            !sender.locally_dropped(first.start, first.transmission),
            "already queued"
        );
        let second = sender.poll_transmit(t0).unwrap();
        assert!(second.retransmission && second.local_retry);
        assert!(
            !sender.locally_dropped(first.start, first.transmission),
            "stale report"
        );
        // Local queue drops before any network admission must not trigger
        // exponential network stall backoff on the first actual transmission.
        assert_eq!(sender.segments[&0].stalls, 0);
    }

    #[test]
    fn reliable_head_rescue_emits_bounded_cross_path_copy_when_overtaken_by_sibling() {
        let t0 = Instant::now();
        let mut sender = Sender::new(false);
        sender.on_ack(
            &Ack {
                cumulative: 0,
                limit: 256 * 1024,
                duplicate_bytes: 0,
                ranges: vec![],
            },
            t0,
        );
        sender.push(&vec![9u8; 64 * 1024]);
        let seg0 = sender.poll_transmit_reliable(t0, RELIABLE_PAYLOAD).unwrap();
        let seg1 = sender
            .poll_transmit_reliable(t0 + Duration::from_millis(1), RELIABLE_PAYLOAD)
            .unwrap();
        let reachable0 = Arc::new(AtomicBool::new(true));
        let reachable1 = Arc::new(AtomicBool::new(true));
        sender.admitted_reliable(
            seg0.start,
            seg0.transmission,
            1,
            Duration::from_millis(100),
            t0,
            reachable0,
        );
        sender.admitted_reliable(
            seg1.start,
            seg1.transmission,
            2,
            Duration::from_millis(100),
            t0 + Duration::from_millis(1),
            reachable1,
        );
        // Without a sibling overtaking seg0, no reliable head rescue is armed.
        assert!(sender.head_probe_deadline().is_none());

        // Sibling path 2 delivers seg1 while seg0 remains stuck on path 1.
        let ack_at = t0 + Duration::from_millis(110);
        let seg1_end = seg1.start
            + match &seg1.frame {
                Frame::Data { data, .. } => data.len() as u64,
                _ => unreachable!(),
            };
        sender.on_ack(
            &Ack {
                cumulative: 0,
                limit: 256 * 1024,
                duplicate_bytes: 0,
                ranges: vec![(seg1.start, seg1_end)],
            },
            ack_at,
        );
        let (rescue_start, rescue_at) = sender.head_probe_deadline().expect("rescue armed");
        assert_eq!(rescue_start, seg0.start);
        assert!(rescue_at >= t0 + Duration::from_millis(250));

        // Before the stall threshold, nothing fires.
        assert!(!sender.on_timeout(rescue_at - Duration::from_millis(1)));
        assert!(!sender.head_probe_is_reliable());

        // At deadline, one bounded rescue copy fires, avoiding stuck path 1.
        assert!(sender.on_timeout(rescue_at));
        assert!(sender.head_probe_is_reliable());
        let rescue = sender
            .poll_transmit_reliable(rescue_at, RELIABLE_PAYLOAD)
            .expect("rescue transmit");
        assert!(rescue.head_copy);
        assert_eq!(rescue.start, seg0.start);
        assert_eq!(rescue.avoid_path, Some(1));
        assert!(
            sender.head_probe_deadline().is_none(),
            "at most one rescue copy per stuck transmission"
        );

        // Admitting the rescue copy registers expected duplicate bytes so the
        // eventual late arrival from path 1 is not misclassified as spurious.
        let seg0_len = match &seg0.frame {
            Frame::Data { data, .. } => data.len() as u64,
            _ => unreachable!(),
        };
        sender.admitted_reliable(
            rescue.start,
            rescue.transmission,
            2,
            Duration::from_millis(100),
            rescue_at,
            Arc::new(AtomicBool::new(true)),
        );
        let (_, spurious) = sender
            .on_ack(
                &Ack {
                    cumulative: seg1_end,
                    limit: 256 * 1024 + seg1_end,
                    duplicate_bytes: seg0_len,
                    ranges: vec![],
                },
                rescue_at + Duration::from_millis(100),
            )
            .expect("ack");
        assert!(
            !spurious,
            "expected duplicate from rescued 32 KiB segment must not count as spurious"
        );
    }

    #[test]
    fn receiver_rejects_final_size_changes_and_counts_duplicates() {
        let t0 = Instant::now();
        let mut receiver = Receiver::default();
        assert_eq!(
            receiver.on_data(10, false, vec![1; 10], t0).unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(
            receiver.on_data(5, true, vec![1; 3], t0),
            Err(Violation::FinalSize)
        );
        assert_eq!(
            receiver.on_data(0, false, vec![2; 15], t0).unwrap().len(),
            20
        );
        assert_eq!(receiver.duplicates(), 5);
        assert_eq!(receiver.on_data(20, true, vec![3; 5], t0).unwrap().len(), 5);
        assert_eq!(
            receiver.on_data(26, false, vec![1], t0),
            Err(Violation::FinalSize)
        );
        assert!(receiver.fin_received());
        assert!(!receiver.finished(), "nothing consumed yet");
        receiver.consumed(25, INITIAL_WINDOW);
        assert!(receiver.finished());
    }

    #[test]
    fn invalid_acknowledgments_are_rejected() {
        let t0 = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&[1; 10]);
        sender.poll_transmit(t0).unwrap();
        let beyond = Ack {
            cumulative: 11,
            limit: 0,
            duplicate_bytes: 0,
            ranges: Vec::new(),
        };
        assert!(sender.on_ack(&beyond, t0).is_none());
        let ranged = Ack {
            cumulative: 0,
            limit: 0,
            duplicate_bytes: 0,
            ranges: vec![(5, 12)],
        };
        assert!(sender.on_ack(&ranged, t0).is_none());
    }

    #[test]
    fn unacknowledged_streams_fail_after_bounded_retransmission() {
        let start = Instant::now();
        let mut now = start;
        let mut sender = Sender::new(false);
        sender.push(&[1; 10]);
        sender.poll_transmit(now).unwrap();
        let mut transmissions = 1;
        while !sender.failed(now) {
            now = sender.next_deadline(now).expect("retransmission timer");
            sender.on_timeout(now);
            if sender.poll_transmit(now).is_some() {
                transmissions += 1;
            }
        }
        assert!(now - start >= DEAD_AFTER && now - start < DEAD_AFTER + MAX_PTO * 4);
        assert!((5..20).contains(&transmissions), "{transmissions}");
    }

    #[test]
    fn datagram_tail_probe_and_retransmission_avoid_failed_path() {
        let t0 = Instant::now();
        let mut sender = Sender::new(false);
        sender.push(&vec![9u8; 990]);

        let first = sender
            .poll_transmit_sized(t0, crate::runtime::MAX_STREAM_PAYLOAD)
            .expect("initial segment");
        assert_eq!(first.avoid_path, None);

        // Local pre-admission drop must not blame any network path.
        assert!(sender.locally_dropped(first.start, first.transmission));
        let local_retry = sender
            .poll_transmit_sized(t0, crate::runtime::MAX_STREAM_PAYLOAD)
            .expect("local retry");
        assert!(local_retry.local_retry);
        assert_eq!(local_retry.avoid_path, None);

        // Admit onto path 1 (e.g., high-loss path). Both tail probe and loss
        // retransmission must prefer any non-1 sibling path.
        sender.admitted(
            local_retry.start,
            local_retry.transmission,
            1,
            Duration::from_millis(85),
            t0,
        );
        let probe_at = sender.next_deadline(t0).expect("tail probe deadline");
        sender.on_timeout(probe_at);
        let probe = sender
            .poll_transmit_sized(probe_at, crate::runtime::MAX_STREAM_PAYLOAD)
            .expect("tail probe");
        assert!(probe.tail_probe);
        assert_eq!(probe.avoid_path, Some(1));

        let loss_at = sender.next_deadline(probe_at).expect("loss deadline");
        sender.on_timeout(loss_at);
        let retry = sender
            .poll_transmit_sized(loss_at, crate::runtime::MAX_STREAM_PAYLOAD)
            .expect("loss retransmit");
        assert!(retry.retransmission);
        assert_eq!(retry.avoid_path, Some(1));
    }

    #[test]
    fn multipath_reliable_tail_rescues_final_stalled_chunk_and_skips_single_path() {
        let t0 = Instant::now();
        // Single-path streams must never schedule a redundant tail rescue on
        // their own QUIC stream.
        let mut single = Sender::new(false);
        single.push(&vec![3u8; 32 * 1024]);
        single.finish();
        let only = single
            .poll_transmit_reliable(t0, RELIABLE_PAYLOAD)
            .expect("single tail");
        single.admitted_reliable_with_ect(
            only.start,
            only.transmission,
            1,
            Duration::from_millis(100),
            Duration::from_millis(120),
            t0,
            Arc::new(AtomicBool::new(true)),
        );
        assert!(single.head_probe_deadline().is_none());

        // Multi-path stream: chunk 0 completes on fast path 1 while final
        // chunk 1 (+ FIN) stalls on slower path 3 with no following chunk to
        // advance `rack`. It must arm one bounded cross-path rescue avoiding 3.
        let mut multi = Sender::new(false);
        let chunk_len = RELIABLE_PAYLOAD - DATA_HEADER;
        multi.push(&vec![5u8; 2 * chunk_len]);
        multi.finish();
        let seg0 = multi
            .poll_transmit_reliable(t0, RELIABLE_PAYLOAD)
            .expect("seg0");
        let seg1 = multi
            .poll_transmit_reliable(t0, RELIABLE_PAYLOAD)
            .expect("seg1");
        multi.admitted_reliable_with_ect(
            seg0.start,
            seg0.transmission,
            1,
            Duration::from_millis(95),
            Duration::from_millis(110),
            t0,
            Arc::new(AtomicBool::new(true)),
        );
        multi.admitted_reliable_with_ect(
            seg1.start,
            seg1.transmission,
            3,
            Duration::from_millis(140),
            Duration::from_millis(160),
            t0 + Duration::from_millis(5),
            Arc::new(AtomicBool::new(true)),
        );
        multi.on_ack(
            &Ack {
                cumulative: chunk_len as u64,
                limit: MAX_WINDOW,
                duplicate_bytes: 0,
                ranges: Vec::new(),
            },
            t0 + Duration::from_millis(105),
        );
        let (tail_start, tail_at) = multi
            .head_probe_deadline()
            .expect("stalled multi-path final chunk arms rescue");
        assert_eq!(tail_start, seg1.start);
        assert!(tail_at >= t0 + Duration::from_millis(350));
        assert!(multi.on_timeout(tail_at));
        assert!(multi.head_probe_is_reliable());
        let rescue = multi
            .poll_transmit_reliable(tail_at, RELIABLE_PAYLOAD)
            .expect("tail rescue transmit");
        assert!(rescue.head_copy);
        assert_eq!(rescue.start, seg1.start);
        assert_eq!(rescue.avoid_path, Some(3));
        assert!(multi.head_probe_deadline().is_none());
    }
}
