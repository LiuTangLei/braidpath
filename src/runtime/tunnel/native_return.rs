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
        atomic::{AtomicBool, AtomicUsize, Ordering},
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
    let best_loss = routes
        .iter()
        .filter(|p| p.delay_ms <= timely)
        .filter_map(|p| p.loss)
        .fold(1.0f64, f64::min);
    let tier = |p: &UdpRoute| {
        if p.delay_ms > timely {
            2
        } else if p.loss.is_some_and(|loss| loss > best_loss + 0.001) {
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
/// an unreliable fragment. QUIC loss is transport evidence, not UDP delivery
/// proof; this is only ordering and never removes a fallback.
pub(super) fn udp_order(order: Vec<usize>, paths: &[OutPath], target_ms: u64) -> Vec<usize> {
    let mut routes: Vec<_> = order
        .into_iter()
        .map(|index| {
            let path = &paths[index];
            let stats = path.conn.stats();
            UdpRoute {
                index,
                delay_ms: super::small_delivery::delay_ms(path),
                loss: (stats.path.sent_packets >= 64).then(|| {
                    (stats.path.lost_packets as f64 / stats.path.sent_packets as f64).min(1.0)
                }),
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
pub(super) const WINDOW: u32 = 2 * 1024 * 1024;
pub(super) const RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;
const MAX_SEND_WINDOW: u64 = RECEIVE_WINDOW as u64;
const SEND_WINDOW_GROWTH: u64 = 64 * 1024;
const SEND_WINDOW_BRAKE: u64 = 128 * 1024;
const SLOW_PATH_BACKLOG_THRESHOLD: u64 = 256 * 1024;
const SLOW_PATH_WRITER_MARGIN: u64 = 2 * PAYLOAD as u64;
const PATH_QUEUE: usize = 4;

/// Keep startup/backpressure at the established budget. Expand only against
/// exercised native service, without exceeding the current native cwnd.
#[derive(Default)]
pub(super) struct Credit {
    connection: Option<usize>,
    sampled_us: u64,
    sent: u64,
    lost: u64,
    current: u64,
}
#[derive(Clone, Copy)]
struct CreditSample {
    cwnd: u64,
    sent: u64,
    lost: u64,
    queued: bool,
    deeply_queued: bool,
    probing: bool,
    storage_limited: bool,
    unsent: u64,
    faster_route: bool,
}

// A cwnd/RTT bound is sufficient to distinguish a much slower path. Actual
// unsent bytes must also show that its current window is building a queue.
pub(super) fn service_bound(conn: &quinn::Connection) -> u64 {
    conn.cwnd_hint().saturating_mul(1_000) / conn.rtt_hint().as_micros().max(1) as u64
}

fn single_path_rank(
    probing: bool,
    rtt_us: u64,
    queued_bytes: u64,
    next_bytes: u64,
    service_bytes_per_ms: u64,
) -> (bool, u64) {
    let delay_us = rtt_us / 2;
    let service = service_bytes_per_ms.max(1);
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
    ) -> Option<u64> {
        let identity = conn.stable_id();
        if self.connection != Some(identity) {
            let stats = conn.stats();
            *self = Self {
                connection: Some(identity),
                sampled_us: now_us,
                sent: stats.path.sent_packets,
                lost: stats.path.lost_packets,
                current: u64::from(WINDOW),
            };
            return None;
        }
        if now_us.saturating_sub(self.sampled_us) < 100_000 {
            return None;
        }
        let stats = conn.stats();
        let queued_ms = conn
            .rtt_hint()
            .saturating_sub(conn.min_rtt_hint())
            .as_secs_f64()
            * 1000.0;
        let (retained, unsent) = conn.stream_send_buffer_bytes();
        self.update(
            now_us,
            CreditSample {
                cwnd: stats.path.cwnd,
                sent: stats.path.sent_packets,
                lost: stats.path.lost_packets,
                queued: queued_ms > target_ms as f64 * 0.25,
                deeply_queued: queued_ms > target_ms as f64,
                probing: conn.probing_rtt_hint(),
                // Retained data can already be in the network. Expand only if
                // storage is nearly full and QUIC has packetized most of it.
                storage_limited: retained + PAYLOAD as u64 >= self.current
                    && unsent <= 2 * PAYLOAD as u64,
                unsent,
                faster_route: service_bound(conn).saturating_mul(2) < best_service,
            },
        )
    }

    fn update(&mut self, now_us: u64, sample: CreditSample) -> Option<u64> {
        let packets = sample.sent.saturating_sub(self.sent);
        let losses = sample.lost.saturating_sub(self.lost);
        self.sampled_us = now_us;
        self.sent = sample.sent;
        self.lost = sample.lost;
        let floor = u64::from(WINDOW);
        let restore_default = self.current < floor && !sample.faster_route;
        if sample.probing || (!restore_default && packets < 64 && !sample.queued && losses == 0) {
            return None;
        }
        let ceiling = (sample.cwnd.saturating_mul(3) / 4).clamp(floor, MAX_SEND_WINDOW);
        // BBR's cwnd already includes headroom beyond a typical flight.
        // Keep the writer fed without giving the slow path another long queue.
        let slow_window = (sample.cwnd.saturating_mul(3) / 4)
            .saturating_add(SLOW_PATH_WRITER_MARGIN)
            .min(floor);
        let next = if sample.faster_route
            && slow_window < floor
            && (self.current < floor || sample.unsent > SLOW_PATH_BACKLOG_THRESHOLD)
        {
            slow_window
        } else if self.current < floor
            || sample.deeply_queued
            || losses.saturating_mul(100) > packets
        {
            floor
        } else if sample.queued {
            // A short RTT excursion need not discard an entire flight of
            // earned storage. Severe congestion or loss still resets it.
            ceiling.min(self.current.saturating_sub(SEND_WINDOW_BRAKE).max(floor))
        } else if sample.storage_limited {
            ceiling.min(self.current + SEND_WINDOW_GROWTH)
        } else {
            ceiling.min(self.current)
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
}
impl Writer {
    pub(super) fn set_reachable(&self, reachable: bool) {
        self.reachable
            .store(reachable && !self.tx.is_closed(), Ordering::Release);
    }
}
pub(super) struct Reader {
    pub(super) rx: mpsc::Receiver<WritePart>,
    reachable: Arc<AtomicBool>,
}
impl Drop for Reader {
    fn drop(&mut self) {
        self.rx.close();
        self.reachable.store(false, Ordering::Release);
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
        if let Some(hold) = &pending.hold {
            hold.reliable_handoff(path, rtt, Instant::now(), reachable);
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

pub(super) fn channel() -> (Writer, Reader) {
    writer_channel(PATH_QUEUE)
}

pub(super) fn mixed_channel() -> (Writer, Reader) {
    writer_channel(1)
}

fn writer_channel(queue: usize) -> (Writer, Reader) {
    let (tx, rx) = mpsc::channel(queue);
    let reachable = Arc::new(AtomicBool::new(true));
    (
        Writer {
            tx,
            reachable: reachable.clone(),
        },
        Reader { rx, reachable },
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
    parallel_downloads: bool,
) {
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
        if front.hold.as_ref().is_some_and(|hold| hold.interactive()) {
            order.sort_by_key(|&i| paths[i].conn.rtt_hint());
        } else if !parallel_downloads
            && paths
                .iter()
                .filter(|p| p.open() && silent & (1 << p.id) == 0 && p.native_return.is_some())
                .count()
                >= 3
        {
            // In-order TCP delivery waits for the oldest record. Account for
            // the backlog ahead of it when choosing between available paths.
            order.sort_by_cached_key(|&i| {
                let path = &paths[i];
                let Some(writer) = &path.native_return else {
                    return (true, u64::MAX);
                };
                let slots = writer.tx.capacity();
                if slots == 0 || !path.open() || silent & (1 << path.id) != 0 {
                    return (true, u64::MAX);
                }
                let (_, unsent) = path.conn.stream_send_buffer_bytes();
                let queued = unsent + ((writer.tx.max_capacity() - slots) * PAYLOAD) as u64;
                single_path_rank(
                    path.conn.probing_rtt_hint(),
                    path.conn.rtt_hint().as_micros() as u64,
                    queued,
                    front.data.len() as u64,
                    service_bound(&path.conn),
                )
            });
        }
        let ready = order.into_iter().find_map(|i| {
            let path = &paths[i];
            if !path.open()
                || silent & (1 << path.id) != 0
                || !groups[usize::from(path.group)].available(cost)
            {
                return None;
            }
            let writer = path.native_return.as_ref()?;
            if !writer.reachable.load(Ordering::Acquire) {
                return None;
            }
            Some((i, writer.tx.try_reserve().ok()?, writer.reachable.clone()))
        });
        let Some((i, permit, reachable)) = ready else {
            break;
        };
        let pending = queue.pop(false).expect("native queue front");
        pacer.spend(cost);
        groups[usize::from(paths[i].group)].spend(cost);
        let data = pending.data.clone();
        permit.send(WritePart {
            data,
            start: Some(Flight::new(
                pending,
                paths[i].id,
                paths[i].conn.rtt_hint(),
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
        for n in 0..paths.len() {
            let i = (start + n) % paths.len();
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
        let floor = u64::from(WINDOW);
        let mut credit = Credit {
            current: floor,
            ..Default::default()
        };
        let mut sample = CreditSample {
            cwnd: 8 * 1024 * 1024,
            sent: 500,
            lost: 0,
            queued: false,
            deeply_queued: false,
            probing: false,
            storage_limited: false,
            unsent: 0,
            faster_route: false,
        };
        assert_eq!(credit.update(100_000, sample), None);
        sample.storage_limited = true;
        let growth_samples = (MAX_SEND_WINDOW - floor) / SEND_WINDOW_GROWTH;
        for step in 1..=growth_samples {
            sample.sent += 500;
            assert_eq!(
                credit.update((step + 1) * 100_000, sample),
                Some(floor + step * SEND_WINDOW_GROWTH)
            );
        }
        let full_at = (growth_samples + 1) * 100_000;
        sample.probing = true;
        sample.queued = true;
        sample.sent += 500;
        assert_eq!(credit.update(full_at + 100_000, sample), None);
        assert_eq!(credit.current, MAX_SEND_WINDOW);

        sample.probing = false;
        sample.sent += 500;
        assert_eq!(
            credit.update(full_at + 200_000, sample),
            Some(MAX_SEND_WINDOW - SEND_WINDOW_BRAKE)
        );
        sample.deeply_queued = true;
        sample.sent += 500;
        assert_eq!(credit.update(full_at + 300_000, sample), Some(floor));
        sample.deeply_queued = false;
        sample.queued = false;
        sample.sent += 500;
        assert_eq!(
            credit.update(full_at + 400_000, sample),
            Some(floor + SEND_WINDOW_GROWTH)
        );
        sample.sent += 500;
        sample.lost += 20;
        assert_eq!(credit.update(full_at + 500_000, sample), Some(floor));
    }
    #[test]
    fn native_credit_limits_slow_path_write_ahead_while_a_faster_path_is_available() {
        let floor = u64::from(WINDOW);
        let mut credit = Credit {
            current: floor,
            ..Default::default()
        };
        let mut sample = CreditSample {
            cwnd: 512 * 1024,
            sent: 500,
            lost: 0,
            queued: false,
            deeply_queued: false,
            probing: false,
            storage_limited: false,
            unsent: 1024 * 1024,
            faster_route: false,
        };
        assert_eq!(credit.update(100_000, sample), None);
        sample.faster_route = true;
        sample.sent += 500;
        let limited = sample.cwnd * 3 / 4 + SLOW_PATH_WRITER_MARGIN;
        assert_eq!(credit.update(200_000, sample), Some(limited));

        sample.unsent = 0;
        sample.sent += 500;
        assert_eq!(credit.update(300_000, sample), None);
        assert_eq!(credit.current, limited);

        sample.faster_route = false;
        assert_eq!(credit.update(400_000, sample), Some(floor));
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
        let fast_clear = single_path_rank(false, 100_000, 0, 32_768, 12_500);
        let fast_backlogged = single_path_rank(false, 100_000, 512 * 1024, 32_768, 12_500);
        let medium_clear = single_path_rank(false, 110_000, 0, 32_768, 8_000);
        let slow_clear = single_path_rank(false, 120_000, 0, 32_768, 2_000);
        let fast_probing = single_path_rank(true, 100_000, 0, 32_768, 12_500);
        assert!(fast_clear < medium_clear);
        assert!(medium_clear < slow_clear);
        assert!(medium_clear < fast_backlogged);
        assert!(slow_clear < fast_probing);
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
}
