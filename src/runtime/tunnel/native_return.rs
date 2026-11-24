//! Opt-in download carrier on the authenticated HTTP/3 response body.
//!
//! Only stream DATA (including FIN) uses this lane. Uploads, acknowledgments,
//! resets and UDP retain the datagram carrier. Offsets and the existing stream
//! credit remain authoritative, including recovery after a path disappears.
use super::{OutPath, QueuedRecord, outbound, stream};
use anyhow::{Result, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};

/// Addressed UDP is latency traffic even when its message needs fragments.
/// This affects only the native download return session's path ordering.
/// It does not enable game coding, copies, or bypass admission gates.
pub(super) fn latency_datagram(native_returning: bool, game_mode: bool, flow: Option<u32>) -> bool {
    native_returning
        && !game_mode
        && flow.is_some_and(|flow| super::associate::is_flow(flow & !super::messages::FLAG))
}

#[derive(Clone, Copy)]
struct UdpRoute {
    index: usize,
    delay_ms: f64,
    loss: Option<f64>,
}
fn rank_udp(routes: &mut [UdpRoute], slack_ms: f64) {
    let fastest = routes
        .iter()
        .map(|p| p.delay_ms)
        .fold(f64::INFINITY, f64::min);
    let timely = fastest + slack_ms;
    let has_unmeasured_timely = routes
        .iter()
        .any(|p| p.delay_ms <= timely && p.loss.is_none());
    let best_loss = routes
        .iter()
        .filter(|p| p.delay_ms <= timely)
        .filter_map(|p| p.loss)
        .fold(1.0f64, f64::min);
    let tier = |p: &UdpRoute| {
        if p.delay_ms > timely {
            2
        } else if p
            .loss
            .is_some_and(|loss| loss > best_loss + 0.001 || (has_unmeasured_timely && loss >= 0.05))
        {
            1
        } else {
            0
        }
    };
    routes.sort_by(|a, b| {
        tier(a)
            .cmp(&tier(b))
            .then_with(|| a.delay_ms.total_cmp(&b.delay_ms))
    });
}
/// A near-equal, demonstrably healthier route is worth a few milliseconds for
/// an unreliable fragment or interactive segment. QUIC loss and fresh receiver
/// feedback are transport/session evidence; this is only ordering and never
/// removes a fallback.
pub(super) fn udp_order(order: Vec<usize>, paths: &[OutPath], target_ms: u64) -> Vec<usize> {
    let mut routes: Vec<_> = order
        .into_iter()
        .map(|index| {
            let path = &paths[index];
            let stats = path.conn.stats();
            let quic_loss = (stats.path.sent_packets >= 64
                || (stats.path.sent_packets >= 16 && stats.path.lost_packets >= 4))
                .then(|| {
                    (stats.path.lost_packets as f64 / stats.path.sent_packets as f64).min(1.0)
                });
            let feedback_loss = {
                let now_us = super::quality_time(path);
                let q = path.quality.lock().expect("quality lock");
                let est = &q.snapshot.sender_estimate;
                (est.expected >= 16
                    && est
                        .updated_us
                        .is_some_and(|at| now_us.saturating_sub(at) <= 3_000_000)
                    && est.loss_rate.is_finite())
                .then(|| est.loss_rate.clamp(0.0, 1.0))
            };
            let loss = match (quic_loss, feedback_loss) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            UdpRoute {
                index,
                delay_ms: super::small_delivery::delay_ms(path),
                loss,
            }
        })
        .collect();
    rank_udp(&mut routes, target_ms.min(20) as f64);
    routes.into_iter().map(|p| p.index).collect()
}

pub(super) const PAYLOAD: usize = stream::RELIABLE_PAYLOAD;
const HEADER_BYTES: usize = 16;
// A native record spans multiple QUIC packets. Pay the same conservative
// per-packet allowance as datagrams, including when operator caps are low.
const PACKET_ALLOWANCE: usize = 80;
const PACKET_PAYLOAD: usize = super::MAX_PAYLOAD;
pub(super) const BURST: usize = wire_cost(PAYLOAD + HEADER_BYTES);
const fn wire_cost(bytes: usize) -> usize {
    bytes + bytes.div_ceil(PACKET_PAYLOAD) * PACKET_ALLOWANCE
}
/// Start each native stream with a bounded send window so low-bandwidth or
/// freshly-joined paths cannot accumulate multi-second QUIC stream backlogs,
/// while idle or newly-warmed high-BDP paths retain enough initial flight for
/// immediate multi-path BBR Startup.
pub(super) const INITIAL_SEND_WINDOW: u64 = 1024 * 1024;
const MIN_SEND_WINDOW: u64 = 128 * 1024;
const SLOW_PATH_MIN_WINDOW: u64 = 96 * 1024;
pub(super) const RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;
const MAX_SEND_WINDOW: u64 = RECEIVE_WINDOW as u64;
const SEND_WINDOW_GROWTH: u64 = 64 * 1024;
const SEND_WINDOW_MAX_GROWTH: u64 = 1024 * 1024;
const SEND_WINDOW_BRAKE: u64 = 128 * 1024;
const LOSS_HOLD_US: u64 = 1_000_000;
const LOSS_CAUTIOUS_US: u64 = 3_000_000;
const BRAKE_COOLDOWN_MIN_US: u64 = 200_000;
const SLOW_PATH_BACKLOG_THRESHOLD: u64 = 128 * 1024;
const SLOW_PATH_WRITER_MARGIN: u64 = 2 * PAYLOAD as u64;
const COLD_BULK_MIN_BYTES: u64 = 256 * 1024;
const PATH_QUEUE: usize = 4;

/// Keep startup/backpressure bounded by measured native `cwnd` and severe loss.
/// Idle intervals (zero buffered stream bytes) must never crush earned or
/// initial `send_window` on keepalive loss or opposite-direction RTT inflation;
/// once unsent backlog persists for an RTT, clamp to `cwnd_cap`, and step down
/// below inflated BBRv1 `cwnd` on sustained policers.
#[derive(Default)]
pub(super) struct Credit {
    connection: Option<usize>,
    sampled_us: u64,
    sent: u64,
    lost: u64,
    current: u64,
    loss_ceiling: Option<u64>,
    loss_hold_until_us: u64,
    loss_cautious_until_us: u64,
    last_brake_us: u64,
    first_backlog_us: Option<u64>,
    policer_streak: u8,
}
#[derive(Clone, Copy)]
struct CreditSample {
    cwnd: u64,
    rtt_us: u64,
    sent: u64,
    lost: u64,
    queued: bool,
    deeply_queued: bool,
    probing: bool,
    storage_limited: bool,
    retained: u64,
    unsent: u64,
    bulk_written: u64,
    faster_route: bool,
}

// A cwnd/RTT bound is sufficient to distinguish a much slower path. Actual
// unsent bytes must also show that its current window is building a queue.
pub(super) fn service_bound(conn: &quinn::Connection) -> u64 {
    conn.cwnd_hint().saturating_mul(1_000) / conn.rtt_hint().as_micros().max(1) as u64
}

fn path_completion_rank(
    probing: bool,
    rtt_us: u64,
    queued_bytes: u64,
    next_bytes: u64,
    service_bytes_per_ms: u64,
    cold_unmeasured: bool,
    best_service_bytes_per_ms: u64,
) -> (bool, u64) {
    let delay_us = rtt_us / 2;
    // A freshly joined path starts at initial cwnd and would otherwise look
    // artificially tiny until its sibling completely fills its 2-4 MiB buffer.
    // Give a cold idle path one bounded probe-level service floor while it has
    // zero queued backlog so BBR can measure its actual bandwidth.
    let service = if cold_unmeasured && queued_bytes == 0 {
        service_bytes_per_ms
            .max(best_service_bytes_per_ms / 2)
            .max(1)
    } else {
        service_bytes_per_ms.max(1)
    };
    (
        probing,
        delay_us.saturating_add(
            queued_bytes
                .saturating_add(next_bytes)
                .saturating_mul(1_000)
                / service,
        ),
    )
}

impl Credit {
    pub(super) fn observe(
        &mut self,
        conn: &quinn::Connection,
        now_us: u64,
        target_ms: u64,
        best_service: u64,
        bulk_written: u64,
    ) -> Option<u64> {
        let identity = conn.stable_id();
        if self.connection != Some(identity) {
            let stats = conn.stats();
            *self = Self {
                connection: Some(identity),
                sampled_us: now_us,
                sent: stats.path.sent_packets,
                lost: stats.path.lost_packets,
                current: INITIAL_SEND_WINDOW,
                loss_ceiling: None,
                loss_hold_until_us: 0,
                loss_cautious_until_us: 0,
                last_brake_us: 0,
                first_backlog_us: None,
                policer_streak: 0,
            };
            return None;
        }
        if now_us.saturating_sub(self.sampled_us) < 100_000 {
            return None;
        }
        let stats = conn.stats();
        let rtt = conn.rtt_hint();
        let rtt_us = rtt.as_micros().min(u128::from(u64::MAX)) as u64;
        let queued_ms = rtt.saturating_sub(conn.min_rtt_hint()).as_secs_f64() * 1000.0;
        let (retained, unsent) = conn.stream_send_buffer_bytes();
        self.update(
            now_us,
            CreditSample {
                cwnd: stats.path.cwnd,
                rtt_us,
                sent: stats.path.sent_packets,
                lost: stats.path.lost_packets,
                queued: queued_ms > target_ms as f64 * 0.5,
                deeply_queued: queued_ms > target_ms.max(20) as f64,
                probing: conn.probing_rtt_hint(),
                // Retained data can already be in the network. Expand once
                // storage is well utilized and QUIC has packetized most of it.
                storage_limited: retained + 2 * PAYLOAD as u64 >= self.current
                    && unsent <= 3 * PAYLOAD as u64,
                retained,
                unsent,
                bulk_written,
                faster_route: service_bound(conn).saturating_mul(3) < best_service,
            },
        )
    }

    fn update(&mut self, now_us: u64, sample: CreditSample) -> Option<u64> {
        let packets = sample.sent.saturating_sub(self.sent);
        let losses = sample.lost.saturating_sub(self.lost);
        self.sampled_us = now_us;
        self.sent = sample.sent;
        self.lost = sample.lost;
        if sample.unsent > SLOW_PATH_BACKLOG_THRESHOLD {
            self.first_backlog_us.get_or_insert(now_us);
        } else {
            self.first_backlog_us = None;
        }
        if sample.retained == 0 && sample.unsent == 0 {
            self.policer_streak = 0;
            if self.current < MIN_SEND_WINDOW && !sample.faster_route {
                self.current = MIN_SEND_WINDOW;
                return Some(MIN_SEND_WINDOW);
            }
            return None;
        }
        if sample.probing {
            return None;
        }
        let backlog_persisted = self.first_backlog_us.is_some_and(|since| {
            now_us.saturating_sub(since) >= sample.rtt_us.max(BRAKE_COOLDOWN_MIN_US)
        });
        let exercised = sample.bulk_written >= INITIAL_SEND_WINDOW || backlog_persisted;
        // Bound QUIC stream send storage proportionally to actual `cwnd` once
        // bulk traffic has exercised the path, so a 25-95 KiB cwnd link never
        // buffers 2 MiB of stale stream bytes. Do not pull an earned window
        // down solely on a 1-RTT BBR `RecoveryState` cwnd dip unless unsent
        // stream bytes have actually persisted for an RTT.
        let raw_cwnd_cap = sample
            .cwnd
            .saturating_mul(2)
            .max(sample.cwnd.saturating_add(SLOW_PATH_WRITER_MARGIN))
            .clamp(MIN_SEND_WINDOW, MAX_SEND_WINDOW);
        let cwnd_cap = if exercised {
            raw_cwnd_cap
        } else {
            raw_cwnd_cap.max(INITIAL_SEND_WINDOW)
        };
        let effective_cap = if backlog_persisted {
            cwnd_cap
        } else {
            cwnd_cap.max(self.current).min(MAX_SEND_WINDOW)
        };
        // Queue-only braking trims excess unsent buffer above `cwnd + headroom`
        // so Quinn BBR never becomes `app_limited` (`in_flight < cwnd` with
        // `unsent == 0`), which would trap BBR in `Mode::Startup` (`2.89x`
        // pacing gain) or starve `ProbeBw` below full pipe occupancy.
        let bdp_floor = sample
            .cwnd
            .saturating_add(2 * SLOW_PATH_WRITER_MARGIN)
            .clamp(
                MIN_SEND_WINDOW,
                (MAX_SEND_WINDOW * 3 / 4).min(effective_cap),
            );
        let slow_window = sample
            .cwnd
            .saturating_add(SLOW_PATH_WRITER_MARGIN)
            .clamp(SLOW_PATH_MIN_WINDOW, effective_cap);
        let exercised_slow = exercised && sample.faster_route;
        if packets >= 32 && losses.saturating_mul(100) >= packets.saturating_mul(40) {
            self.policer_streak = self.policer_streak.saturating_add(1);
        } else if packets >= 16 {
            self.policer_streak = 0;
        }
        let policer_loss = (exercised_slow
            && packets >= 32
            && losses.saturating_mul(100) >= packets.saturating_mul(25))
            || self.policer_streak >= 2;
        // Only severe loss (>= 5%, or >= 3% while also queued) indicates buffer
        // overflow / policer overshoot; 1-2% random WAN loss must not collapse
        // a healthy BBR path's stream window.
        let severe_loss = policer_loss
            || (packets >= 24
                && (losses.saturating_mul(100) >= packets.saturating_mul(5)
                    || (sample.queued && losses.saturating_mul(100) >= packets.saturating_mul(3))));
        let brake_ready = self.last_brake_us == 0
            || now_us.saturating_sub(self.last_brake_us)
                >= sample.rtt_us.max(BRAKE_COOLDOWN_MIN_US);
        let must_shrink = self.current > effective_cap
            || (exercised_slow
                && slow_window < self.current
                && sample.unsent > SLOW_PATH_BACKLOG_THRESHOLD);
        let restore_floor = self.current < MIN_SEND_WINDOW && !sample.faster_route;
        let can_grow = sample.storage_limited && packets >= 12 && !sample.deeply_queued;
        if !must_shrink
            && !restore_floor
            && !can_grow
            && packets < 32
            && !sample.queued
            && !severe_loss
        {
            return None;
        }
        let next = if severe_loss {
            // Shrink excess buffering above `bdp_floor` at most once per RTT on
            // moderate loss. Under >=20% policer loss (where BBRv1 ignores loss
            // on shallow/zero-queue policers and inflates `cwnd`), allow the
            // window to step down to `MIN_SEND_WINDOW` / `SLOW_PATH_MIN_WINDOW`.
            self.loss_hold_until_us = now_us.saturating_add(LOSS_HOLD_US);
            self.loss_cautious_until_us = now_us.saturating_add(LOSS_CAUTIOUS_US);
            if brake_ready {
                let target = if policer_loss {
                    let floor = if exercised_slow {
                        SLOW_PATH_MIN_WINDOW
                    } else {
                        MIN_SEND_WINDOW
                    };
                    (self.current / 2).max(floor).min(effective_cap)
                } else {
                    (self.current.saturating_mul(3) / 4)
                        .max(bdp_floor)
                        .min(effective_cap)
                };
                self.loss_ceiling = Some(target);
                self.last_brake_us = now_us;
                target
            } else {
                self.current.min(effective_cap)
            }
        } else if exercised_slow
            && slow_window < effective_cap
            && sample.unsent > SLOW_PATH_BACKLOG_THRESHOLD
        {
            slow_window
        } else if sample.deeply_queued
            && sample.unsent > SLOW_PATH_WRITER_MARGIN
            && self.current > bdp_floor
            && brake_ready
        {
            self.last_brake_us = now_us;
            (self.current.saturating_mul(3) / 4)
                .max(bdp_floor)
                .min(effective_cap)
        } else if sample.queued
            && sample.unsent > SLOW_PATH_WRITER_MARGIN
            && self.current > bdp_floor
            && brake_ready
        {
            // A short RTT excursion need not discard an entire flight of
            // earned storage. Only trim when unsent stream backlog exists
            // above the path's BDP floor.
            self.last_brake_us = now_us;
            self.current
                .saturating_sub(SEND_WINDOW_BRAKE)
                .max(bdp_floor)
                .min(effective_cap)
        } else if restore_floor {
            MIN_SEND_WINDOW.min(cwnd_cap)
        } else if can_grow {
            if now_us < self.loss_hold_until_us {
                self.loss_ceiling
                    .map_or(self.current, |ceiling| self.current.min(ceiling))
                    .min(cwnd_cap)
            } else if now_us < self.loss_cautious_until_us {
                (self.current + SEND_WINDOW_GROWTH).min(cwnd_cap)
            } else {
                self.loss_ceiling = None;
                let step = self
                    .current
                    .clamp(SEND_WINDOW_GROWTH, SEND_WINDOW_MAX_GROWTH);
                (self.current + step).min(cwnd_cap)
            }
        } else {
            self.current.min(effective_cap)
        };
        if next == self.current {
            return None;
        }
        self.current = next;
        Some(next)
    }
}

#[derive(Clone)]
pub(super) struct Writer {
    pub(super) tx: mpsc::Sender<WritePart>,
    reachable: Arc<AtomicBool>,
    written_bytes: Arc<AtomicU64>,
}
impl Writer {
    pub(super) fn set_reachable(&self, reachable: bool) {
        self.reachable
            .store(reachable && !self.tx.is_closed(), Ordering::Release);
    }
    pub(super) fn written_bytes(&self) -> u64 {
        self.written_bytes.load(Ordering::Relaxed)
    }
}
pub(super) struct Reader {
    pub(super) rx: mpsc::Receiver<WritePart>,
    reachable: Arc<AtomicBool>,
    ready: Option<Arc<Notify>>,
}
impl Drop for Reader {
    fn drop(&mut self) {
        self.rx.close();
        self.reachable.store(false, Ordering::Release);
        if let Some(ready) = &self.ready {
            ready.notify_one();
        }
    }
}

/// Retains the stream's failure callback while the bounded native writer owns
/// the payload, without retaining its producer-queue reservation.
pub(super) struct Flight {
    hold: Option<Arc<outbound::Hold>>,
    written: bool,
}
impl Flight {
    fn new(
        pending: outbound::Pending,
        path: u8,
        rtt: std::time::Duration,
        reachable: Arc<AtomicBool>,
    ) -> Self {
        Self::new_with_ect(pending, path, rtt, std::time::Duration::ZERO, reachable)
    }

    fn new_with_ect(
        pending: outbound::Pending,
        path: u8,
        rtt: std::time::Duration,
        expected_rtt: std::time::Duration,
        reachable: Arc<AtomicBool>,
    ) -> Self {
        if let Some(hold) = &pending.hold {
            hold.reliable_handoff_with_ect(path, rtt, expected_rtt, Instant::now(), reachable);
        }
        Self {
            hold: pending.hold,
            written: false,
        }
    }
}
impl Drop for Flight {
    fn drop(&mut self) {
        if !self.written
            && let Some(hold) = &self.hold
        {
            hold.reliable_cancel();
        }
    }
}
pub(super) struct WritePart {
    data: Bytes,
    start: Option<Flight>,
    last: bool,
    reservation: Option<Reservation>,
}

type Refunds = [AtomicUsize; super::MAX_PATHS];

struct Reservation {
    refunds: Arc<Refunds>,
    ready: Arc<Notify>,
    group: usize,
    cost: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if self.cost != 0 {
            self.refunds[self.group].fetch_add(self.cost, Ordering::Relaxed);
        }
        self.ready.notify_one();
    }
}

#[cfg(test)]
pub(super) fn channel() -> (Writer, Reader) {
    writer_channel(PATH_QUEUE, None)
}

pub(super) fn channel_with_notify(ready: Option<Arc<Notify>>) -> (Writer, Reader) {
    writer_channel(PATH_QUEUE, ready)
}

pub(super) fn mixed_channel() -> (Writer, Reader) {
    writer_channel(1, None)
}

fn writer_channel(queue: usize, ready: Option<Arc<Notify>>) -> (Writer, Reader) {
    let (tx, rx) = mpsc::channel(queue);
    let reachable = Arc::new(AtomicBool::new(true));
    (
        Writer {
            tx,
            reachable: reachable.clone(),
            written_bytes: Arc::new(AtomicU64::new(0)),
        },
        Reader {
            rx,
            reachable,
            ready,
        },
    )
}

pub(super) fn data(flow: u32, payload: &[u8]) -> bool {
    stream::stream_id(flow).is_some() && !stream::is_ack_flow(flow) && payload.first() == Some(&0)
}
pub(super) fn bulk_data(flow: u32, payload: &[u8]) -> bool {
    // An ACK request must bypass a full native response body. It retains no
    // payload and uses the same short DATAGRAM lane as other stream control.
    data(flow, payload) && !stream::is_ack_request(payload)
}
pub(super) fn enqueue(item: QueuedRecord, queue: &mut outbound::Queue) {
    let QueuedRecord {
        record,
        created,
        hold,
    } = item;
    let mut encoded = Vec::with_capacity(HEADER_BYTES + record.payload.len());
    encoded.extend((record.payload.len() as u32).to_be_bytes());
    encoded.extend(record.flow.to_be_bytes());
    encoded.extend(record.id.to_be_bytes());
    encoded.extend(record.payload);
    // Queue rejection drops the unadmitted hold; the stream retains its bytes
    // and retries through the normal bounded producer backpressure.
    let _ = queue.push(outbound::Pending {
        game_datagram: false,
        data: encoded.into(),
        created,
        flow: Some(record.flow),
        record_id: Some(record.id),
        block: None,
        small: false,
        hold,
    });
}

/// Uses the same aggregate/group credit as datagrams. Each successful pop
/// rotates logical flows, and a full path never blocks an available sibling.
pub(super) fn drain(
    queue: &mut outbound::Queue,
    paths: &[OutPath],
    silent: u8,
    cursor: &mut usize,
    pacer: &mut outbound::Pacer,
    groups: &mut [outbound::Pacer; super::MAX_PATHS],
) {
    if queue.front(false).is_none() {
        return;
    }
    #[derive(Clone, Copy, Default)]
    struct PathSnapshot {
        active: bool,
        probing: bool,
        rtt_us: u64,
        retained: u64,
        unsent: u64,
        service: u64,
        written: u64,
    }
    let mut snapshots = [PathSnapshot::default(); super::MAX_PATHS];
    let mut active_native = 0usize;
    let mut best_service = 0u64;
    for path in paths.iter() {
        if !path.open() || silent & (1 << path.id) != 0 {
            continue;
        }
        let Some(writer) = &path.native_return else {
            continue;
        };
        if !writer.reachable.load(Ordering::Acquire) {
            continue;
        }
        let id = usize::from(path.id);
        let (retained, unsent) = path.conn.stream_send_buffer_bytes();
        let probing = path.conn.probing_rtt_hint();
        let rtt_us = path.conn.rtt_hint().as_micros() as u64;
        let mut service = service_bound(&path.conn);
        if retained == 0
            && unsent == 0
            && let Some(pacing_bps) = path.conn.congestion_state().metrics().pacing_rate
        {
            // Exiting idle after a keepalive loss can leave BBR `window()` at
            // `min_cwnd` for one RTT while `pacing_rate` still reflects the
            // measured bottleneck bandwidth.
            service = service.max(pacing_bps / 8_000);
        }
        snapshots[id] = PathSnapshot {
            active: true,
            probing,
            rtt_us,
            retained,
            unsent,
            service,
            written: writer.written_bytes(),
        };
        active_native += 1;
        if !probing {
            best_service = best_service.max(service);
        }
    }
    let mut local_dispatched = [0u64; super::MAX_PATHS];
    let mut deferred_rescues = 0;
    for _ in 0..16 {
        let Some(front) = queue.front(false) else {
            break;
        };
        let cost = wire_cost(front.data.len());
        if !pacer.available(cost) {
            break;
        }
        let mut order: Vec<_> = (0..paths.len())
            .map(|n| (*cursor + n) % paths.len())
            .collect();
        let avoid_path = front.hold.as_ref().and_then(|hold| hold.avoid_path());
        let mut path_ranks: [(bool, u64); super::MAX_PATHS] = [(true, u64::MAX); super::MAX_PATHS];
        let mut straggler_limit_us = u64::MAX;
        let has_non_avoid = avoid_path.is_some() && active_native >= 2;
        if active_native >= 2 {
            // In-order TCP delivery waits for the oldest record, and interactive
            // responses larger than the DATAGRAM bypass should avoid a deeply
            // queued or RTT-probing sibling path. Rank 2+ paths by estimated
            // completion time using total unacknowledged stream bytes (`retained`
            // plus staged channel records) so paths fill proportionally to drain
            // rate and finish together without straggler tail stalls.
            let mut best_ect_us = u64::MAX;
            for path in paths.iter() {
                let id = usize::from(path.id);
                let snap = snapshots[id];
                if !snap.active {
                    continue;
                }
                let Some(writer) = &path.native_return else {
                    continue;
                };
                let slots = writer.tx.capacity();
                let staged = ((writer.tx.max_capacity() - slots) * PAYLOAD) as u64;
                let queued = snap
                    .retained
                    .saturating_add(staged)
                    .saturating_add(local_dispatched[id]);
                let cold = snap.written.saturating_add(local_dispatched[id]) < COLD_BULK_MIN_BYTES
                    && snap.unsent.saturating_add(local_dispatched[id])
                        <= SLOW_PATH_BACKLOG_THRESHOLD;
                let rank = path_completion_rank(
                    snap.probing,
                    snap.rtt_us,
                    queued,
                    front.data.len() as u64,
                    snap.service,
                    cold,
                    best_service,
                );
                path_ranks[id] = rank;
                if !rank.0 && (!has_non_avoid || Some(path.id) != avoid_path) {
                    best_ect_us = best_ect_us.min(rank.1);
                }
            }
            if best_ect_us < u64::MAX {
                straggler_limit_us = best_ect_us.saturating_mul(2).saturating_add(150_000);
            }
            order.sort_by_cached_key(|&i| {
                let path = &paths[i];
                let avoided = Some(path.id) == avoid_path;
                let Some(writer) = &path.native_return else {
                    return (true, true, true, u64::MAX);
                };
                let full = writer.tx.capacity() == 0;
                let (probing, ect) = path_ranks[usize::from(path.id)];
                (avoided, full, probing, ect)
            });
        }
        let ready = order.into_iter().find_map(|i| {
            let path = &paths[i];
            let id = usize::from(path.id);
            if !snapshots[id].active || !groups[usize::from(path.group)].available(cost) {
                return None;
            }
            if active_native >= 2 {
                if has_non_avoid && Some(path.id) == avoid_path {
                    return None;
                }
                if straggler_limit_us < u64::MAX {
                    let (probing, ect) = path_ranks[id];
                    if probing || ect > straggler_limit_us {
                        return None;
                    }
                }
            }
            let writer = path.native_return.as_ref()?;
            if !writer.reachable.load(Ordering::Acquire) {
                return None;
            }
            Some((
                i,
                writer.tx.try_reserve().ok()?,
                writer.reachable.clone(),
                writer.written_bytes.clone(),
            ))
        });
        let Some((i, permit, reachable, written_bytes)) = ready else {
            // A rescue can wait for its sibling without holding up other flows.
            deferred_rescues += 1;
            if !has_non_avoid || deferred_rescues >= queue.original_flows() {
                break;
            }
            queue.rotate_original();
            continue;
        };
        deferred_rescues = 0;
        let pending = queue.pop(false).expect("native queue front");
        let id = usize::from(paths[i].id);
        let len = pending.data.len() as u64;
        pacer.spend(cost);
        groups[usize::from(paths[i].group)].spend(cost);
        local_dispatched[id] = local_dispatched[id].saturating_add(len);
        written_bytes.fetch_add(len, Ordering::Relaxed);
        let rtt = paths[i].conn.rtt_hint();
        let expected_rtt = if active_native >= 2 && path_ranks[id].1 < u64::MAX {
            std::time::Duration::from_micros(
                path_ranks[id].1.saturating_add(snapshots[id].rtt_us / 2),
            )
        } else {
            std::time::Duration::ZERO
        };
        let data = pending.data.clone();
        permit.send(WritePart {
            data,
            start: Some(Flight::new_with_ect(
                pending,
                paths[i].id,
                rtt,
                expected_rtt,
                reachable,
            )),
            last: true,
            reservation: None,
        });
        *cursor = (i + 1) % paths.len();
    }
}

// One H3 DATA fragment fits even the minimum sender bucket. H3 boundaries
// are independent of the application record decoded from the response body.
const PART_BYTES: usize = 2048;
const H3_PART_ALLOWANCE: usize = 16;
pub(super) const MIXED_SEND_WINDOW: u64 = 1024 * 1024;
const PART_WIRE_BYTES: usize = wire_cost(PART_BYTES + H3_PART_ALLOWANCE);

struct PathPace {
    connection: usize,
    credit: outbound::Pacer,
    sampled_us: u64,
    packets: u64,
    lost: u64,
    tx_bytes: u64,
    queue_braked: bool,
    last_pressure_us: Option<u64>,
}
impl PathPace {
    fn new(connection: usize, now_us: u64, ceiling: u64) -> Self {
        let mut credit = outbound::Pacer::for_sender(ceiling.min(20_000_000), 2 * PART_WIRE_BYTES);
        credit.set_rate(now_us, credit.rate());
        Self {
            connection,
            credit,
            sampled_us: now_us,
            packets: 0,
            lost: 0,
            tx_bytes: 0,
            queue_braked: false,
            last_pressure_us: None,
        }
    }

    fn observe(&mut self, conn: &quinn::Connection, now_us: u64, ceiling: u64) {
        let elapsed_us = now_us.saturating_sub(self.sampled_us);
        if elapsed_us < 100_000 {
            self.credit.refill(now_us);
            return;
        }
        let stats = conn.stats();
        let path = stats.path;
        let packets = path.sent_packets.saturating_sub(self.packets);
        let lost = path.lost_packets.saturating_sub(self.lost);
        let tx_bytes = stats.udp_tx.bytes.saturating_sub(self.tx_bytes);
        self.packets = path.sent_packets;
        self.lost = path.lost_packets;
        self.tx_bytes = stats.udp_tx.bytes;
        self.sampled_us = now_us;

        let rate = self.credit.rate();
        let actual_bps = (u128::from(tx_bytes) * 8_000_000 / u128::from(elapsed_us.max(1)))
            .min(u128::from(ceiling)) as u64;
        let loss_base = if actual_bps >= 4_000_000 {
            rate.min(actual_bps.max(rate * 3 / 4))
        } else {
            rate
        };
        let rtt_excess = path.rtt.saturating_sub(path.min_rtt);
        let queued = rtt_excess > std::time::Duration::from_millis(10);
        let deeply_queued = packets >= 64 && rtt_excess > std::time::Duration::from_millis(15);
        let lossy = packets >= 64 && lost.saturating_mul(200) > packets;
        // RTT includes both directions. Apply one gentle delay brake per
        // moderate episode without exiting initial ramp on a single upload RTT
        // bump; deep queueing or local loss records real bottleneck pressure so
        // the pacer cruises gently without repeatedly hitting tail drop.
        let next = if lossy {
            self.last_pressure_us = Some(now_us);
            (loss_base * 19 / 20).max(4_000_000)
        } else if deeply_queued && !conn.probing_rtt_hint() {
            self.last_pressure_us = Some(now_us);
            (rate * 19 / 20).max(4_000_000)
        } else if queued && !self.queue_braked && !conn.probing_rtt_hint() {
            if self.last_pressure_us.is_some() {
                self.last_pressure_us = Some(now_us);
            }
            (rate * 19 / 20).max(4_000_000)
        } else if !queued && packets >= 64 && !conn.probing_rtt_hint() {
            let (grown, headroom) = match self.last_pressure_us {
                None => (rate + rate / 10, 112),
                Some(at) if now_us.saturating_sub(at) >= 600_000 => {
                    (rate + (rate / 64).max(300_000), 105)
                }
                Some(_) => (rate, 105),
            };
            let envelope = (actual_bps.saturating_mul(headroom) / 100).max(20_000_000);
            grown.min(envelope.max(rate))
        } else {
            rate
        };
        self.queue_braked = queued;
        self.credit.set_rate(now_us, next.min(ceiling));
    }
}

#[derive(Default)]
pub(super) struct MixedWrites {
    partial: [Option<(usize, Bytes)>; super::MAX_PATHS],
    refunds: Arc<Refunds>,
    pub ready: Arc<Notify>,
    path_pace: [Option<PathPace>; super::MAX_PATHS],
}

impl MixedWrites {
    pub fn path_pace_bps(&self, id: u8, connection: usize) -> Option<u64> {
        self.path_pace[usize::from(id)]
            .as_ref()
            .filter(|pace| pace.connection == connection)
            .map(|pace| pace.credit.rate())
    }

    pub fn refund(
        &self,
        pacer: &mut outbound::Pacer,
        groups: &mut [outbound::Pacer; super::MAX_PATHS],
    ) {
        for (group, refund) in groups.iter_mut().zip(self.refunds.iter()) {
            let returned = refund.swap(0, Ordering::Relaxed);
            if returned != 0 {
                group.refund(returned);
                pacer.refund(returned);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn drain(
        &mut self,
        queue: &mut outbound::Queue,
        paths: &[OutPath],
        silent: u8,
        cursor: &mut usize,
        pacer: &mut outbound::Pacer,
        groups: &mut [outbound::Pacer; super::MAX_PATHS],
        now_us: u64,
        feedback_reserve: usize,
        reserved_group: Option<u8>,
    ) {
        let start = *cursor;
        let mut order: Vec<_> = (0..paths.len())
            .map(|n| (start + n) % paths.len())
            .collect();
        let active_native = paths
            .iter()
            .filter(|p| {
                p.open()
                    && silent & (1 << p.id) == 0
                    && p.native_return
                        .as_ref()
                        .is_some_and(|w| w.reachable.load(Ordering::Acquire))
            })
            .count();
        if active_native >= 2 {
            let best_service = paths
                .iter()
                .filter(|p| {
                    p.open()
                        && silent & (1 << p.id) == 0
                        && p.native_return.is_some()
                        && !p.conn.probing_rtt_hint()
                })
                .map(|p| service_bound(&p.conn))
                .max()
                .unwrap_or(0);
            let next_bytes = queue
                .front(false)
                .map_or(PART_BYTES as u64, |p| p.data.len() as u64);
            // Finish already-started partial records first, then rank idle paths
            // by estimated completion time for new records.
            order.sort_by_cached_key(|&i| {
                let path = &paths[i];
                let id = usize::from(path.id);
                let has_partial = self.partial[id]
                    .as_ref()
                    .is_some_and(|(owner, _)| *owner == path.conn.stable_id() && path.open());
                let Some(writer) = &path.native_return else {
                    return (!has_partial, true, u64::MAX);
                };
                if !path.open() || silent & (1 << id) != 0 || writer.tx.capacity() == 0 {
                    return (!has_partial, true, u64::MAX);
                }
                let (retained, unsent) = path.conn.stream_send_buffer_bytes();
                let queued = retained
                    + ((writer.tx.max_capacity() - writer.tx.capacity()) * PART_BYTES) as u64;
                let cold = writer.written_bytes() < COLD_BULK_MIN_BYTES
                    && unsent <= SLOW_PATH_BACKLOG_THRESHOLD;
                let (probing, ect) = path_completion_rank(
                    path.conn.probing_rtt_hint(),
                    path.conn.rtt_hint().as_micros() as u64,
                    queued,
                    next_bytes,
                    service_bound(&path.conn),
                    cold,
                    best_service,
                );
                (!has_partial, probing, ect)
            });
        }
        for i in order {
            let path = &paths[i];
            let id = usize::from(path.id);
            let connection = path.conn.stable_id();
            if self.partial[id]
                .as_ref()
                .is_some_and(|(owner, _)| *owner != connection || !path.open())
            {
                self.partial[id] = None;
            }
            if !path.open() || silent & (1 << id) != 0 {
                continue;
            }
            let Some(writer) = &path.native_return else {
                continue;
            };
            if !writer.reachable.load(Ordering::Acquire) {
                continue;
            }
            let Ok(permit) = writer.tx.try_reserve() else {
                continue;
            };
            if active_native >= 2 && self.partial[id].is_none() {
                // Only choose a new record here. A partial record must finish
                // on its current H3 writer before the next record can start.
                let avoids_path = |queue: &outbound::Queue| {
                    queue
                        .front(false)
                        .and_then(|record| record.hold.as_ref())
                        .and_then(|hold| hold.avoid_path())
                        == Some(path.id)
                };
                for _ in 0..queue.original_flows().min(16) {
                    if !avoids_path(queue) {
                        break;
                    }
                    queue.rotate_original();
                }
                if avoids_path(queue) {
                    continue;
                }
            }
            let Some(bytes) = self.partial[id]
                .as_ref()
                .map(|(_, b)| b)
                .or_else(|| queue.front(false).map(|pending| &pending.data))
            else {
                continue;
            };
            let count = bytes.len().min(PART_BYTES);
            let cost = wire_cost(count + H3_PART_ALLOWANCE);
            let reserve = super::GAME_PACKET_RESERVE;
            let group = usize::from(path.group);
            let group_reserve = if Some(path.group) == reserved_group {
                feedback_reserve.max(reserve)
            } else {
                reserve
            };
            if !pacer.available(cost + reserve.max(feedback_reserve))
                || !groups[group].available(cost + group_reserve)
            {
                continue;
            }
            let ceiling = pacer.rate().min(groups[group].rate());
            let slot = &mut self.path_pace[id];
            if slot
                .as_ref()
                .is_none_or(|pace| pace.connection != connection)
            {
                *slot = Some(PathPace::new(connection, now_us, ceiling));
            }
            let path_pace = slot.as_mut().expect("path pacer");
            path_pace.observe(&path.conn, now_us, ceiling);
            // Charge actual QUIC STREAM packet overhead on the per-path mixed
            // pacer while keeping the conservative wire allowance on shared caps.
            let pace_cost = count + H3_PART_ALLOWANCE + count.div_ceil(1200) * 48;
            if !path_pace.credit.available(pace_cost) {
                continue;
            }
            path_pace.credit.spend(pace_cost);
            let data = bytes.slice(..count);
            let last = count == bytes.len();
            let remaining = (!last).then(|| (connection, bytes.slice(count..)));
            let flight = self.partial[id].is_none().then(|| {
                Flight::new(
                    queue.pop(false).expect("native queue front"),
                    path.id,
                    path.conn.rtt_hint(),
                    writer.reachable.clone(),
                )
            });
            self.partial[id] = remaining;
            pacer.spend(cost);
            groups[group].spend(cost);
            writer
                .written_bytes
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            permit.send(WritePart {
                data,
                start: flight,
                last,
                reservation: Some(Reservation {
                    refunds: self.refunds.clone(),
                    ready: self.ready.clone(),
                    group,
                    cost,
                }),
            });
            *cursor = (i + 1) % paths.len();
        }
    }
}

pub(super) async fn write(
    conn: quinn::Connection,
    mut stream: h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    mut input: Reader,
) {
    let mut flight = None;
    loop {
        let Some(mut part) = (tokio::select! {
            value = input.rx.recv() => value,
            _ = conn.closed() => break,
        }) else {
            break;
        };
        if let Some(ready) = &input.ready {
            ready.notify_one();
        }
        if let Some(start) = part.start.take() {
            debug_assert!(flight.is_none());
            flight = Some(start);
        }
        let result = tokio::select! {
            biased;
            _ = conn.closed() => break,
            result = async {
                if let Some(reservation) = part.reservation.as_mut() {
                    // Once write starts, a failing H3 operation may have
                    // submitted a prefix. Charge the grant conservatively.
                    reservation.cost = 0;
                }
                stream.send_data(part.data).await
            } => result,
        };
        if result.is_err() {
            conn.close(0u32.into(), b"return stream failed");
            break;
        }
        if part.last {
            flight.take().expect("native record started").written = true;
        }
    }
}

pub(super) async fn write_client(
    conn: quinn::Connection,
    mut stream: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    mut input: Reader,
) {
    let mut flight = None;
    loop {
        let Some(mut part) = (tokio::select! {
            value = input.rx.recv() => value,
            _ = conn.closed() => break,
        }) else {
            break;
        };
        if let Some(ready) = &input.ready {
            ready.notify_one();
        }
        if let Some(start) = part.start.take() {
            debug_assert!(flight.is_none());
            flight = Some(start);
        }
        let result = tokio::select! {
            biased;
            _ = conn.closed() => break,
            result = async {
                if let Some(reservation) = part.reservation.as_mut() {
                    // Once write starts, a failing H3 operation may have
                    // submitted a prefix. Charge the grant conservatively.
                    reservation.cost = 0;
                }
                stream.send_data(part.data).await
            } => result,
        };
        if result.is_err() {
            conn.close(0u32.into(), b"upload stream failed");
            break;
        }
        if part.last {
            flight.take().expect("native record started").written = true;
        }
    }
}

// The channel and deferred queue hold the same permits. A slow path can
// use at most eight staged records, across old and new generations. Each
// driver can also be holding one decoded record while waiting for admission.
pub(super) const RX_PATH_RECORDS: usize = 8;

#[derive(Clone)]
pub(super) struct Ingress {
    pub tx: mpsc::Sender<Incoming>,
    pub slots: Arc<Semaphore>,
}

impl Ingress {
    pub fn new(tx: mpsc::Sender<Incoming>) -> Self {
        Self {
            tx,
            slots: Arc::new(Semaphore::new(RX_PATH_RECORDS)),
        }
    }
}

/// Native ingress gets its own process-wide byte budget before entering a
/// session queue; TCP receive credit then owns the retained/reordered bytes.
pub(super) struct Incoming {
    pub decoded: Decoded,
    _credit: OwnedSemaphorePermit,
    _slot: OwnedSemaphorePermit,
}
impl Incoming {
    pub async fn new(decoded: Decoded, slots: Arc<Semaphore>) -> Result<Self> {
        static BUDGET: OnceLock<Arc<Semaphore>> = OnceLock::new();
        let slot = slots.acquire_owned().await?;
        let budget = BUDGET.get_or_init(|| Arc::new(Semaphore::new(32 * 1024 * 1024)));
        let credit = budget
            .clone()
            .acquire_many_owned(decoded.payload_len as u32)
            .await?;
        Ok(Self {
            decoded,
            _credit: credit,
            _slot: slot,
        })
    }
}

#[derive(Debug)]
pub(super) struct Decoded {
    pub stream_id: u32,
    pub frame: stream::Frame,
    payload_len: usize,
    #[cfg(test)]
    pub record_id: u64,
}

#[derive(Default)]
pub(super) struct Decoder {
    partial: BytesMut,
}
impl Decoder {
    /// Reads at most one bounded frame; DATA boundaries are not record boundaries.
    pub fn next(&mut self, input: &mut impl Buf) -> Result<Option<Decoded>> {
        loop {
            let need = if self.partial.len() < HEADER_BYTES {
                HEADER_BYTES
            } else {
                let len =
                    u32::from_be_bytes(self.partial[..4].try_into().expect("header")) as usize;
                ensure!(
                    (10..=PAYLOAD).contains(&len),
                    "invalid return-stream frame length"
                );
                HEADER_BYTES + len
            };
            let count = (need - self.partial.len()).min(input.remaining());
            if count > 0 {
                self.partial.put((&mut *input).take(count));
            }
            if self.partial.len() < need {
                return Ok(None);
            }
            if need == HEADER_BYTES {
                continue;
            }
            let header = &self.partial[..HEADER_BYTES];
            let payload = &self.partial[HEADER_BYTES..];
            let flow = u32::from_be_bytes(header[4..8].try_into()?);
            let Some(stream_id) = stream::stream_id(flow).filter(|_| !stream::is_ack_flow(flow))
            else {
                anyhow::bail!("invalid return-stream flow");
            };
            let Some(frame @ stream::Frame::Data { .. }) = stream::Frame::decode(payload) else {
                anyhow::bail!("invalid return-stream TCP data frame");
            };
            let decoded = Decoded {
                stream_id,
                frame,
                payload_len: payload.len(),
                #[cfg(test)]
                record_id: u64::from_be_bytes(header[8..16].try_into()?),
            };
            self.partial.clear();
            return Ok(Some(decoded));
        }
    }
    pub fn finish(&self) -> Result<()> {
        ensure!(self.partial.is_empty(), "truncated return-stream frame");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::wire::Record;
    #[test]
    fn native_udp_prefers_a_nearby_healthy_route_without_hiding_fallbacks() {
        let mut routes = [
            UdpRoute {
                index: 0,
                delay_ms: 50.0,
                loss: Some(0.006),
            },
            UdpRoute {
                index: 1,
                delay_ms: 55.0,
                loss: Some(0.0),
            },
            UdpRoute {
                index: 2,
                delay_ms: 80.0,
                loss: Some(0.0),
            },
        ];
        rank_udp(&mut routes, 20.0);
        assert_eq!(routes.map(|p| p.index), [1, 0, 2]);
        assert_eq!(
            routes.len(),
            3,
            "a busy healthy path retains both fallbacks"
        );
        for route in &mut routes {
            route.loss = None;
        }
        rank_udp(&mut routes, 20.0);
        assert_eq!(
            routes.map(|p| p.index),
            [0, 1, 2],
            "unknown loss preserves latency order"
        );
        routes[1].loss = Some(0.0);
        routes[0].loss = Some(0.006);
        rank_udp(&mut routes, 2.0);
        assert_eq!(
            routes.map(|p| p.index),
            [0, 1, 2],
            "health preference stays in the delay budget"
        );
        // A newly joined timely sibling (unknown loss) immediately outranks a
        // timely path with proven >=5% severe packet loss.
        let mut high_loss_vs_fresh = [
            UdpRoute {
                index: 1,
                delay_ms: 40.0,
                loss: Some(0.28),
            },
            UdpRoute {
                index: 2,
                delay_ms: 45.7,
                loss: None,
            },
        ];
        rank_udp(&mut high_loss_vs_fresh, 20.0);
        assert_eq!(high_loss_vs_fresh.map(|p| p.index), [2, 1]);
    }

    #[test]
    fn native_udp_latency_scope_includes_fragments_and_preserves_other_carriers() {
        let flow = super::super::associate::FLAG | 1;
        for udp in [flow, flow | super::super::messages::FLAG] {
            assert!(latency_datagram(true, false, Some(udp)));
            assert!(!latency_datagram(false, false, Some(udp)));
            assert!(!latency_datagram(true, true, Some(udp)));
        }
        for other in [
            None,
            Some(7),
            Some(stream::data_flow(1)),
            Some(stream::ack_flow(1)),
            Some(super::super::messages::FLAG | 7),
        ] {
            assert!(!latency_datagram(true, false, other));
        }
    }

    #[test]
    fn native_credit_grows_only_on_clean_storage_limited_service() {
        let mut credit = Credit {
            current: INITIAL_SEND_WINDOW,
            ..Default::default()
        };
        let cwnd = 2 * 1024 * 1024;
        let bdp_floor = cwnd + 2 * SLOW_PATH_WRITER_MARGIN;
        let mut sample = CreditSample {
            cwnd,
            rtt_us: 100_000,
            sent: 500,
            lost: 0,
            queued: false,
            deeply_queued: false,
            probing: false,
            storage_limited: false,
            retained: 2 * 1024 * 1024,
            unsent: 0,
            bulk_written: INITIAL_SEND_WINDOW,
            faster_route: false,
        };
        assert_eq!(credit.update(100_000, sample), None);
        sample.storage_limited = true;
        let mut now_us = 100_000;
        let mut steps = 0;
        while credit.current < MAX_SEND_WINDOW {
            now_us += 100_000;
            sample.sent += 500;
            let next = credit.update(now_us, sample).expect("clean ramp step");
            assert!(next > INITIAL_SEND_WINDOW);
            steps += 1;
            assert!(
                steps <= 12,
                "clean ramp must reach MAX_SEND_WINDOW promptly"
            );
        }
        assert_eq!(credit.current, MAX_SEND_WINDOW);

        sample.probing = true;
        sample.queued = true;
        sample.unsent = 256 * 1024;
        sample.sent += 500;
        now_us += 100_000;
        assert_eq!(credit.update(now_us, sample), None);
        assert_eq!(credit.current, MAX_SEND_WINDOW);

        sample.probing = false;
        sample.sent += 500;
        now_us += 100_000;
        assert_eq!(
            credit.update(now_us, sample),
            Some(MAX_SEND_WINDOW - SEND_WINDOW_BRAKE)
        );
        // Brake cooldown prevents consecutive cuts inside one RTT.
        let after_mild = credit.current;
        sample.deeply_queued = true;
        sample.sent += 500;
        now_us += 100_000;
        assert_eq!(credit.update(now_us, sample), None);
        assert_eq!(credit.current, after_mild);

        // After the cooldown expires, deeply_queued cuts by 3/4 (down to bdp_floor).
        sample.sent += 500;
        now_us += BRAKE_COOLDOWN_MIN_US;
        assert_eq!(credit.update(now_us, sample), Some(after_mild * 3 / 4));

        // 2% random unqueued WAN loss does not collapse the stream window.
        let before_random = credit.current;
        sample.deeply_queued = false;
        sample.queued = false;
        sample.unsent = 0;
        sample.storage_limited = false;
        sample.sent += 500;
        sample.lost += 10;
        now_us += BRAKE_COOLDOWN_MIN_US;
        assert_eq!(credit.update(now_us, sample), None);
        assert_eq!(credit.current, before_random);

        // Severe (>=5%) packet loss shrinks once per cooldown, holds for LOSS_HOLD_US,
        // and recovers additively (never doubling) during LOSS_CAUTIOUS_US.
        sample.storage_limited = true;
        sample.sent += 500;
        sample.lost += 30;
        now_us += BRAKE_COOLDOWN_MIN_US;
        let after_loss = (before_random * 3 / 4).max(bdp_floor);
        assert_eq!(credit.update(now_us, sample), Some(after_loss));

        // Immediate repeat loss inside cooldown refreshes hold without double-cutting.
        sample.sent += 500;
        sample.lost += 30;
        now_us += 100_000;
        assert_eq!(credit.update(now_us, sample), None);
        assert_eq!(credit.current, after_loss);

        // Clean samples during the loss hold cannot re-expand.
        sample.sent += 500;
        now_us += 100_000;
        assert_eq!(credit.update(now_us, sample), None);
        assert_eq!(credit.current, after_loss);

        // Once the loss hold expires, multiple ticks stay strictly additive.
        sample.sent += 500;
        now_us += LOSS_HOLD_US;
        assert_eq!(
            credit.update(now_us, sample),
            Some(after_loss + SEND_WINDOW_GROWTH)
        );
        sample.sent += 500;
        now_us += 100_000;
        assert_eq!(
            credit.update(now_us, sample),
            Some(after_loss + 2 * SEND_WINDOW_GROWTH)
        );
    }

    #[test]
    fn native_credit_preserves_bdp_on_healthy_probe_bw_rtt_bumps() {
        // Healthy 25 Mbps / 100 ms BBR path (~600 KiB cwnd, ~300 KiB BDP):
        // normal ProbeBW RTT spikes trim excess unsent buffer above `cwnd + headroom`
        // without starving Quinn BBR into `app_limited` (`send_window <= cwnd`).
        let mut credit = Credit {
            current: 2 * INITIAL_SEND_WINDOW,
            ..Default::default()
        };
        let cwnd = 600 * 1024;
        let expected_floor = cwnd + 2 * SLOW_PATH_WRITER_MARGIN;
        let mut sample = CreditSample {
            cwnd,
            rtt_us: 120_000,
            sent: 500,
            lost: 0,
            queued: true,
            deeply_queued: true,
            probing: false,
            storage_limited: false,
            retained: cwnd + 200 * 1024,
            unsent: 200 * 1024,
            bulk_written: INITIAL_SEND_WINDOW,
            faster_route: false,
        };
        let mut now_us = 100_000;
        for _ in 0..10 {
            sample.sent += 200;
            now_us += 100_000;
            credit.update(now_us, sample);
        }
        assert_eq!(credit.current, expected_floor);
        // Once unsent == 0, RTT inflation alone never cuts below `cwnd + headroom`.
        sample.unsent = 0;
        sample.sent += 200;
        now_us += BRAKE_COOLDOWN_MIN_US;
        assert_eq!(credit.update(now_us, sample), None);
        assert_eq!(credit.current, expected_floor);
        // Even severe (10%) loss on a high-cwnd link trims excess buffer without
        // collapsing the stream window below `cwnd + headroom`.
        sample.queued = false;
        sample.deeply_queued = false;
        for _ in 0..5 {
            sample.sent += 100;
            sample.lost += 10;
            now_us += BRAKE_COOLDOWN_MIN_US;
            credit.update(now_us, sample);
        }
        assert_eq!(credit.current, expected_floor);
        // Hard (>=20%) policer loss where BBRv1 ignores packet loss steps down
        // below the inflated BDP floor to MIN_SEND_WINDOW.
        for _ in 0..4 {
            sample.sent += 100;
            sample.lost += 50;
            now_us += BRAKE_COOLDOWN_MIN_US;
            credit.update(now_us, sample);
        }
        assert_eq!(credit.current, MIN_SEND_WINDOW);
    }

    #[test]
    fn native_credit_keeps_initial_window_while_idle_then_clamps_slow_exercised_paths() {
        let mut credit = Credit {
            current: INITIAL_SEND_WINDOW,
            ..Default::default()
        };
        let mut sample = CreditSample {
            cwnd: 25 * 1024,
            rtt_us: 90_000,
            sent: 10,
            lost: 0,
            queued: false,
            deeply_queued: false,
            probing: false,
            storage_limited: false,
            retained: 0,
            unsent: 0,
            bulk_written: 0,
            faster_route: false,
        };
        // Idle keepalives (even past 100+ packets) never crush INITIAL_SEND_WINDOW
        // before bulk data exercises the path.
        for step in 1..=5 {
            sample.sent += 40;
            assert_eq!(credit.update(step * 100_000, sample), None);
            assert_eq!(credit.current, INITIAL_SEND_WINDOW);
        }

        // Even on an already-exercised warm path, idle keepalive losses and BBR
        // `RecoveryState` cwnd dips (`retained == 0 && unsent == 0`) must never
        // collapse earned send_window before the next download starts.
        sample.bulk_written = INITIAL_SEND_WINDOW;
        sample.cwnd = 5_888;
        sample.sent += 60;
        sample.lost += 15;
        sample.deeply_queued = true;
        assert_eq!(credit.update(600_000, sample), None);
        assert_eq!(credit.current, INITIAL_SEND_WINDOW);

        // First burst tick exiting idle (`backlog_persisted == false`) keeps
        // earned window intact while BBR exits `RecoveryState`, then clamps a
        // genuinely slow 25 KiB cwnd path once unsent backlog persists for 1 RTT.
        sample.deeply_queued = false;
        sample.cwnd = 25 * 1024;
        sample.retained = 200 * 1024;
        sample.unsent = 175 * 1024;
        sample.sent += 10;
        assert_eq!(credit.update(700_000, sample), None);
        assert_eq!(credit.current, INITIAL_SEND_WINDOW);

        sample.sent += 10;
        assert_eq!(credit.update(900_000, sample), Some(MIN_SEND_WINDOW));

        // When a much faster sibling joins and backlog forms, tighten further
        // to SLOW_PATH_MIN_WINDOW, then restore MIN_SEND_WINDOW once alone again.
        sample.faster_route = true;
        sample.unsent = 200 * 1024;
        sample.sent += 10;
        assert_eq!(credit.update(1_000_000, sample), Some(SLOW_PATH_MIN_WINDOW));

        sample.unsent = 0;
        sample.sent += 50;
        assert_eq!(credit.update(1_100_000, sample), None);
        assert_eq!(credit.current, SLOW_PATH_MIN_WINDOW);

        sample.faster_route = false;
        assert_eq!(credit.update(1_200_000, sample), Some(MIN_SEND_WINDOW));
    }

    #[tokio::test]
    async fn mixed_native_small_buckets_and_cancelled_parts_preserve_credit() {
        let pair = super::super::sender_ready_tests::Pair::connect().await;
        let mut path = pair.path();
        let (writer, mut reader) = mixed_channel();
        path.native_return = Some(writer);
        let group = usize::from(path.group);
        let paths = [path];
        let mut queue = outbound::Queue::default();
        let mut writes = MixedWrites::default();
        let mut cursor = 0;
        let cost = wire_cost(PART_BYTES + H3_PART_ALLOWANCE);
        let reserve = super::super::GAME_PACKET_RESERVE;
        let mut pacer = outbound::Pacer::new(64_000, cost + reserve);
        let mut groups = std::array::from_fn(|_| outbound::Pacer::new(64_000, cost + reserve));
        let record = encoded();
        for id in [42u64, 43] {
            let mut frame = record.to_vec();
            frame[8..16].copy_from_slice(&id.to_be_bytes());
            queue
                .push(outbound::Pending {
                    game_datagram: false,
                    data: frame.into(),
                    created: Instant::now(),
                    flow: Some(stream::data_flow(17)),
                    record_id: Some(id),
                    block: None,
                    small: false,
                    hold: None,
                })
                .ok()
                .unwrap();
        }
        pacer.refill(2_000_000);
        writes.drain(
            &mut queue,
            &paths,
            0,
            &mut cursor,
            &mut pacer,
            &mut groups,
            2_000_000,
            0,
            None,
        );
        assert!(reader.rx.is_empty(), "group must authorize every fragment");
        groups[group].refill(2_000_000);
        writes.path_pace[0] = Some(PathPace::new(paths[0].conn.stable_id(), 0, 64_000));
        writes.drain(
            &mut queue,
            &paths,
            0,
            &mut cursor,
            &mut pacer,
            &mut groups,
            2_000_000,
            0,
            None,
        );
        assert_eq!(queue.len(), 1);
        assert!(pacer.available(reserve) && groups[group].available(reserve));
        assert!(!pacer.available(reserve + 1) && !groups[group].available(reserve + 1));
        drop(reader.rx.try_recv().unwrap());
        writes.refund(&mut pacer, &mut groups);
        writes.refund(&mut pacer, &mut groups);
        assert!(pacer.available(cost + reserve) && groups[group].available(cost + reserve));
        // Simulate a new path generation, which owns no partially assigned record.
        writes.partial[0] = None;
        let mut received = Vec::new();
        let mut written_at = 2_000_000;
        loop {
            written_at += 1_000_000;
            pacer.refill(written_at);
            groups[group].refill(written_at);
            writes.drain(
                &mut queue,
                &paths,
                0,
                &mut cursor,
                &mut pacer,
                &mut groups,
                written_at,
                0,
                None,
            );
            let mut part = reader.rx.try_recv().unwrap();
            assert_eq!(part.start.is_some(), received.is_empty());
            part.reservation.as_mut().unwrap().cost = 0;
            received.extend_from_slice(&part.data);
            if part.last {
                break;
            }
        }
        let decoded = Decoder::default()
            .next(&mut received.as_slice())
            .unwrap()
            .unwrap();
        assert_eq!(decoded.record_id, 43);
        assert_eq!(received.len(), record.len());
        writes.refund(&mut pacer, &mut groups);
        assert!(!pacer.available(cost + reserve));
    }

    fn encoded() -> Bytes {
        let payload = stream::Frame::Data {
            offset: 345,
            fin: true,
            data: vec![7; 32 * 1024],
        }
        .encode();
        let mut queue = outbound::Queue::default();
        enqueue(
            QueuedRecord {
                record: Record {
                    flow: stream::data_flow(17),
                    id: 42,
                    payload,
                },
                created: Instant::now(),
                hold: None,
            },
            &mut queue,
        );
        queue.pop(false).unwrap().data
    }
    #[test]
    fn one_native_frame_fits_even_the_minimum_operator_rate() {
        let mut cap = outbound::Pacer::for_sender(64_000, BURST);
        cap.refill(5_000_000);
        assert!(cap.available(wire_cost(PAYLOAD + HEADER_BYTES)));
        cap.spend(wire_cost(PAYLOAD + HEADER_BYTES));
        assert!(!cap.available(wire_cost(PAYLOAD + HEADER_BYTES)));
    }

    #[test]
    fn an_empty_ack_request_bypasses_native_data_but_a_fin_keeps_its_carrier() {
        for fin in [false, true] {
            let payload = stream::Frame::Data {
                offset: 32768,
                fin,
                data: vec![],
            }
            .encode();
            assert!(data(stream::data_flow(1), &payload));
            assert_eq!(bulk_data(stream::data_flow(1), &payload), fin);
        }
    }

    #[test]
    fn blocked_native_writer_cannot_pin_the_shared_producer() {
        for written in [false, true] {
            let gauge = Arc::new(outbound::Gauge::default());
            let hold = gauge.hold(9, 123, 1, PAYLOAD, false, false);
            let pending = outbound::Pending {
                game_datagram: false,
                data: Bytes::from_static(b"payload"),
                created: Instant::now(),
                record_id: Some(1),
                flow: Some(stream::data_flow(9)),
                block: None,
                small: false,
                hold: Some(hold),
            };
            let mut flight = Flight::new(
                pending,
                2,
                std::time::Duration::from_millis(100),
                Arc::new(AtomicBool::new(true)),
            );
            assert_eq!(
                gauge.queued(),
                0,
                "a blocked writer cannot block other paths' production"
            );
            let sent = gauge.take_sent();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].path, 2);
            assert!(sent[0].reliable.as_ref().unwrap().load(Ordering::Acquire));
            flight.written = written;
            drop(flight);
            if written {
                assert_eq!(gauge.admitted(), PAYLOAD as u64);
                assert!(gauge.take_dropped().is_empty());
            } else {
                assert_eq!(gauge.admitted(), 0);
                assert_eq!(gauge.take_dropped(), vec![(9, 123, 1)]);
            }
            assert_eq!(
                gauge.queued(),
                0,
                "release exactly once on success or cancellation"
            );
        }
    }

    #[test]
    fn a_closed_native_writer_cannot_be_made_reachable_by_an_old_probe() {
        let (writer, reader) = channel();
        assert!(writer.reachable.load(Ordering::Acquire));
        drop(reader);
        assert!(!writer.reachable.load(Ordering::Acquire));
        writer.set_reachable(true);
        assert!(!writer.reachable.load(Ordering::Acquire));
    }

    #[test]
    fn arbitrary_body_splits_and_coalescing() {
        let encoded = encoded();
        let expected_frame = stream::Frame::decode(&encoded[HEADER_BYTES..]).unwrap();
        for size in [1, 7, 16, 997, 65536] {
            let all = [encoded.as_ref(), encoded.as_ref()].concat();
            let mut decoder = Decoder::default();
            let mut records = Vec::new();
            for chunk in all.chunks(size) {
                let mut input = Bytes::copy_from_slice(chunk);
                while let Some(record) = decoder.next(&mut input).unwrap() {
                    records.push(record);
                }
                assert!(!input.has_remaining());
            }
            decoder.finish().unwrap();
            assert_eq!(records.len(), 2);
            for record in records {
                assert_eq!(record.record_id, 42);
                assert_eq!(record.stream_id, 17);
                assert_eq!(record.payload_len, PAYLOAD);
                assert_eq!(record.frame, expected_frame);
            }
        }
    }
    #[test]
    fn single_download_backlog_rank_accounts_for_queue_and_probing() {
        let fast_clear = path_completion_rank(false, 100_000, 0, 32_768, 12_500, false, 12_500);
        let fast_backlogged =
            path_completion_rank(false, 100_000, 512 * 1024, 32_768, 12_500, false, 12_500);
        let medium_clear = path_completion_rank(false, 110_000, 0, 32_768, 8_000, false, 12_500);
        let slow_clear = path_completion_rank(false, 120_000, 0, 32_768, 2_000, false, 12_500);
        let fast_probing = path_completion_rank(true, 100_000, 0, 32_768, 12_500, false, 12_500);
        assert!(fast_clear < medium_clear);
        assert!(medium_clear < slow_clear);
        assert!(medium_clear < fast_backlogged);
        assert!(slow_clear < fast_probing);
    }

    #[test]
    fn cold_idle_sibling_gets_bounded_warmup_floor_when_primary_builds_backlog() {
        let primary_clear = path_completion_rank(false, 40_000, 0, 32_768, 25_000, false, 25_000);
        let primary_queued =
            path_completion_rank(false, 40_000, 512 * 1024, 32_768, 25_000, false, 25_000);
        // Freshly joined path has tiny initial cwnd (service=200 B/ms) and 60 ms RTT.
        let cold_idle = path_completion_rank(false, 60_000, 0, 32_768, 200, true, 25_000);
        let cold_already_queued =
            path_completion_rank(false, 60_000, 32_768, 32_768, 200, true, 25_000);
        // While primary is uncongested, primary stays preferred.
        assert!(primary_clear < cold_idle);
        // Once primary builds meaningful backlog (~21 ms), cold idle sibling wins
        // one bounded warmup record instead of starving at initial cwnd.
        assert!(cold_idle < primary_queued);
        // Once the cold path already holds a queued record, real measured service governs.
        assert!(primary_queued < cold_already_queued);
    }

    #[test]
    fn mixed_path_pace_exposes_active_connection_rate_with_rate_aware_burst() {
        let mut pace = PathPace::new(77, 100_000, 50_000_000);
        assert_eq!(pace.credit.rate(), 20_000_000);
        // Rate-aware burst holds > 2 ms of 50 Mbps after refill without fixed 4 KiB stall.
        pace.credit.set_rate(100_000, 50_000_000);
        pace.credit.refill(105_000);
        assert!(pace.credit.available(12_000));
        let mut writes = MixedWrites::default();
        writes.path_pace[0] = Some(pace);
        assert_eq!(writes.path_pace_bps(0, 77), Some(50_000_000));
        assert_eq!(writes.path_pace_bps(0, 88), None);
    }

    #[test]
    fn rejects_unbounded_non_data_and_truncation() {
        let mut invalid = Bytes::from_static(&[255; 16]);
        assert!(Decoder::default().next(&mut invalid).is_err());
        let mut truncated = encoded().slice(..20);
        let mut decoder = Decoder::default();
        assert!(decoder.next(&mut truncated).unwrap().is_none());
        assert!(decoder.finish().is_err());
        let mut bad = encoded().to_vec();
        bad[16] = 2;
        assert!(Decoder::default().next(&mut Bytes::from(bad)).is_err());
    }

    #[tokio::test]
    async fn native_drain_avoids_stalled_path_for_head_rescue() {
        let pair0 = super::super::sender_ready_tests::Pair::connect().await;
        let pair1 = super::super::sender_ready_tests::Pair::connect().await;
        let mut p0 = pair0.path();
        let mut p1 = pair1.path();
        p0.id = 0;
        p1.id = 1;
        let (w0, mut r0) = channel();
        let (w1, mut r1) = channel();
        p0.native_return = Some(w0);
        p1.native_return = Some(w1);
        let paths = [p0, p1];
        let gauge = Arc::new(outbound::Gauge::default());
        let hold = gauge.hold_with_avoid(17, 0, 2, PAYLOAD, false, false, Some(0));
        let mut queue = outbound::Queue::default();
        queue
            .push(outbound::Pending {
                game_datagram: false,
                data: encoded(),
                created: Instant::now(),
                record_id: Some(42),
                flow: Some(stream::data_flow(17)),
                block: None,
                small: false,
                hold: Some(hold),
            })
            .ok()
            .unwrap();
        let mut cursor = 0;
        let mut pacer = outbound::Pacer::for_sender(100_000_000, BURST);
        let mut groups = std::array::from_fn(|_| outbound::Pacer::for_sender(100_000_000, BURST));
        pacer.refill(1_000_000);
        for g in &mut groups {
            g.refill(1_000_000);
        }
        drain(&mut queue, &paths, 0, &mut cursor, &mut pacer, &mut groups);
        assert!(queue.is_empty());
        assert!(
            r0.rx.try_recv().is_err(),
            "rescue copy must avoid stalled path 0"
        );
        assert!(
            r1.rx.try_recv().is_ok(),
            "rescue copy must route onto healthy sibling path 1"
        );
    }

    #[tokio::test]
    async fn blocked_head_rescue_leaves_other_flows_sendable_in_native_and_mixed() {
        let pair0 = super::super::sender_ready_tests::Pair::connect().await;
        let pair1 = super::super::sender_ready_tests::Pair::connect().await;
        for mixed in [false, true] {
            let mut paths = [pair0.path(), pair1.path()];
            let mut readers = Vec::new();
            for (id, path) in paths.iter_mut().enumerate() {
                let (writer, reader) = if mixed { mixed_channel() } else { channel() };
                path.id = id as u8;
                path.native_return = Some(writer);
                readers.push(reader);
            }
            let sibling = &paths[1].native_return.as_ref().unwrap().tx;
            let permits: Vec<_> = (0..sibling.max_capacity())
                .map(|_| sibling.try_reserve().unwrap())
                .collect();
            let mut queue = outbound::Queue::default();
            let gauge = Arc::new(outbound::Gauge::default());
            for (id, avoid) in [(17, Some(0)), (18, None)] {
                let mut data = encoded().to_vec();
                data[8..16].copy_from_slice(&u64::from(id).to_be_bytes());
                queue
                    .push(outbound::Pending {
                        game_datagram: false,
                        data: data.into(),
                        created: Instant::now(),
                        record_id: Some(u64::from(id)),
                        flow: Some(stream::data_flow(id)),
                        block: None,
                        small: false,
                        hold: Some(gauge.hold_with_avoid(id, 0, 2, PAYLOAD, false, false, avoid)),
                    })
                    .ok()
                    .unwrap();
            }
            let mut writes = MixedWrites::default();
            let mut cursor = 0;
            let mut pacer = outbound::Pacer::for_sender(100_000_000, BURST);
            let mut groups =
                std::array::from_fn(|_| outbound::Pacer::for_sender(100_000_000, BURST));
            let mut run = |now_us, queue: &mut outbound::Queue| {
                pacer.refill(now_us);
                for group in &mut groups {
                    group.refill(now_us);
                }
                if mixed {
                    writes.drain(
                        queue,
                        &paths,
                        0,
                        &mut cursor,
                        &mut pacer,
                        &mut groups,
                        now_us,
                        0,
                        None,
                    );
                } else {
                    drain(queue, &paths, 0, &mut cursor, &mut pacer, &mut groups);
                }
            };
            run(1_000_000, &mut queue);
            assert_eq!(queue.front(false).unwrap().record_id, Some(17));
            let normal = readers[0].rx.try_recv().expect("other flow uses path 0");
            assert_eq!(&normal.data[8..16], &18u64.to_be_bytes());
            assert!(readers[1].rx.is_empty());

            drop(permits);
            run(2_000_000, &mut queue);
            let rescue = readers[1]
                .rx
                .try_recv()
                .expect("rescue uses sibling path 1");
            assert_eq!(&rescue.data[8..16], &17u64.to_be_bytes());
            assert!(queue.is_empty());
        }
    }
}
