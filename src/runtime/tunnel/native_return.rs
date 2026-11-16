//! Opt-in download carrier on the authenticated HTTP/3 response body.
//!
//! Only stream DATA (including FIN) uses this lane. Uploads, acknowledgments,
//! resets and UDP retain the datagram carrier. Offsets and the existing stream
//! credit remain authoritative, including recovery after a path disappears.
use super::{OutPath, QueuedRecord, outbound, stream, wire::Record};
use anyhow::{Result, ensure};
use bytes::{Buf, Bytes, BytesMut};
use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

pub(super) const HEADER: &str = "braidpath-return-stream";
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
const MAX_SEND_WINDOW: u64 = 3 * 1024 * 1024;
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
impl Credit {
    pub(super) fn observe(
        &mut self,
        conn: &quinn::Connection,
        now_us: u64,
        target_ms: u64,
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
        self.update(
            now_us,
            stats.path.cwnd,
            queued_ms > target_ms as f64 * 0.25,
            conn.probing_rtt_hint(),
            stats.path.sent_packets,
            stats.path.lost_packets,
        )
    }

    fn update(
        &mut self,
        now_us: u64,
        cwnd: u64,
        queued: bool,
        probing: bool,
        sent: u64,
        lost: u64,
    ) -> Option<u64> {
        let packets = sent.saturating_sub(self.sent);
        let losses = lost.saturating_sub(self.lost);
        self.sampled_us = now_us;
        self.sent = sent;
        self.lost = lost;
        if probing || (packets < 64 && !queued && losses == 0) {
            return None;
        }
        let ceiling = (cwnd.saturating_mul(3) / 4).clamp(u64::from(WINDOW), MAX_SEND_WINDOW);
        let next = if !queued && losses.saturating_mul(100) <= packets {
            ceiling.min(self.current.saturating_add(32 * 1024))
        } else {
            u64::from(WINDOW)
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
    pub(super) tx: mpsc::Sender<Flight>,
    reachable: Arc<AtomicBool>,
}
impl Writer {
    pub(super) fn set_reachable(&self, reachable: bool) {
        self.reachable
            .store(reachable && !self.tx.is_closed(), Ordering::Release);
    }
}
pub(super) struct Reader {
    pub(super) rx: mpsc::Receiver<Flight>,
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
    pending: outbound::Pending,
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
            pending,
            written: false,
        }
    }
}
impl Drop for Flight {
    fn drop(&mut self) {
        if !self.written
            && let Some(hold) = &self.pending.hold
        {
            hold.reliable_cancel();
        }
    }
}
pub(super) fn channel() -> (Writer, Reader) {
    let (tx, rx) = mpsc::channel(PATH_QUEUE);
    let reachable = Arc::new(AtomicBool::new(true));
    (
        Writer {
            tx,
            reachable: reachable.clone(),
        },
        Reader { rx, reachable },
    )
}

pub(super) fn requested(headers: &http::HeaderMap) -> Result<bool> {
    let value = headers.get(HEADER).map(|v| v.to_str()).transpose()?;
    ensure!(
        matches!(value, None | Some("1")),
        "unsupported return-stream format"
    );
    Ok(value.is_some())
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
        permit.send(Flight::new(
            pending,
            paths[i].id,
            paths[i].conn.rtt_hint(),
            reachable,
        ));
        *cursor = (i + 1) % paths.len();
    }
}

pub(super) async fn write(
    conn: quinn::Connection,
    mut stream: h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    mut input: Reader,
) {
    loop {
        let Some(mut flight) = (tokio::select! {
            value = input.rx.recv() => value,
            _ = conn.closed() => break,
        }) else {
            break;
        };
        let result = tokio::select! {
            result = stream.send_data(flight.pending.data.clone()) => result,
            _ = conn.closed() => break,
        };
        if result.is_err() {
            conn.close(0u32.into(), b"return stream failed");
            break;
        }
        flight.written = true;
    }
}

/// Native ingress gets its own process-wide byte budget before entering a
/// session queue; TCP receive credit then owns the retained/reordered bytes.
pub(super) struct Incoming {
    pub record: Record,
    _credit: OwnedSemaphorePermit,
}
impl Incoming {
    pub async fn new(record: Record) -> Result<Self> {
        static BUDGET: OnceLock<Arc<Semaphore>> = OnceLock::new();
        let budget = BUDGET.get_or_init(|| Arc::new(Semaphore::new(32 * 1024 * 1024)));
        let credit = budget
            .clone()
            .acquire_many_owned(record.payload.len() as u32)
            .await?;
        Ok(Self {
            record,
            _credit: credit,
        })
    }
}

#[derive(Default)]
pub(super) struct Decoder {
    partial: BytesMut,
}
impl Decoder {
    /// Reads at most one bounded frame; DATA boundaries are not record boundaries.
    pub fn next(&mut self, input: &mut impl Buf) -> Result<Option<Record>> {
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
                self.partial.extend_from_slice(&input.copy_to_bytes(count));
            }
            if self.partial.len() < need {
                return Ok(None);
            }
            if need == HEADER_BYTES {
                continue;
            }
            let mut frame = self.partial.split().freeze();
            let len = frame.get_u32() as usize;
            let flow = frame.get_u32();
            let id = frame.get_u64();
            ensure!(data(flow, &frame), "return-stream frame is not TCP data");
            ensure!(
                stream::Frame::decode(&frame).is_some(),
                "invalid return-stream TCP frame"
            );
            debug_assert_eq!(len, frame.len());
            return Ok(Some(Record {
                flow,
                id,
                payload: frame.to_vec(),
            }));
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
    #[test]
    fn native_credit_grows_in_one_frame_steps_and_keeps_backpressure_on_loss_or_queue() {
        let mut credit = Credit {
            current: u64::from(WINDOW),
            ..Default::default()
        };
        assert_eq!(
            credit.update(100_000, 4 * 1024 * 1024, false, false, 0, 0),
            None
        );
        for n in 1..=32 {
            assert_eq!(
                credit.update(n * 100_000, 4 * 1024 * 1024, false, false, n * 500, 0),
                Some(u64::from(WINDOW) + n * 32768)
            );
        }
        assert_eq!(credit.current, MAX_SEND_WINDOW);
        assert_eq!(
            credit.update(3_300_000, 4096, true, true, 16_100, 0),
            None,
            "a deliberate native RTT probe does not resize retained storage"
        );
        assert_eq!(
            credit.update(3_400_000, 4 * 1024 * 1024, true, false, 16_600, 0),
            Some(u64::from(WINDOW))
        );
        assert_eq!(
            credit.update(3_500_000, 4 * 1024 * 1024, false, false, 17_100, 0),
            Some(u64::from(WINDOW) + 32768)
        );
        assert_eq!(
            credit.update(3_600_000, 4 * 1024 * 1024, false, false, 17_600, 20),
            Some(u64::from(WINDOW))
        );
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
            assert_eq!(records[0].id, 42);
            assert_eq!(records[0].flow, stream::data_flow(17));
            assert_eq!(records[0].payload.len(), PAYLOAD);
        }
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
