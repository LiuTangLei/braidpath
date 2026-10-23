//! Message segmentation above the existing FEC records. No retransmission.
use super::{MAX_PAYLOAD, Record};
use crate::runtime::{MAX_MESSAGE, stats, trace};
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

pub(super) const FLAG: u32 = 1 << 31;
const HEADER: usize = 11;
const CHUNK: usize = MAX_PAYLOAD - HEADER;
const ACTIVE_LIMIT: usize = 64;
const BYTE_LIMIT: usize = ACTIVE_LIMIT * MAX_MESSAGE;
const WINDOW: u64 = 8192;

pub(crate) fn metadata(record: &Record) -> Option<trace::MessageKey> {
    let b = &record.payload;
    if record.flow & FLAG == 0 || b.len() < HEADER {
        return None;
    }
    let base = u64::from_be_bytes(b[..8].try_into().ok()?);
    let total = u16::from_be_bytes(b[8..10].try_into().ok()?);
    let index = b[10];
    let count = usize::from(total).div_ceil(CHUNK);
    if base == 0
        || usize::from(total) <= MAX_PAYLOAD
        || usize::from(total) > MAX_MESSAGE
        || usize::from(index) >= count
        || base.checked_add(u64::from(index)) != Some(record.id)
    {
        return None;
    }
    Some(trace::MessageKey {
        base_record_id: base,
        payload_bytes: total,
        fragments: count as u8,
        fragment_index: Some(index),
        received_mask: None,
    })
}

/// Stack-owned iterator: the common unfragmented path keeps its payload buffer
/// and does not allocate an intermediate record vector.
pub(super) struct Fragments {
    flow: u32,
    base: u64,
    index: usize,
    count: usize,
    payload: Vec<u8>,
}
impl Fragments {
    pub(super) fn is_small(&self, threshold: usize) -> bool {
        self.count == 1 && self.payload.len() <= threshold
    }
    pub(super) fn trace(
        &self,
        scope: &stats::Scope,
        stage: trace::Stage,
        reason: Option<trace::Reason>,
    ) {
        if self.count > 1 {
            scope.trace_with(|context, capture| {
                let mut event = trace::Event::new(context, stage);
                event.record = Some(trace::RecordKey {
                    flow: self.flow,
                    record_id: self.base,
                });
                event.message = Some(trace::MessageKey {
                    base_record_id: self.base,
                    payload_bytes: self.payload.len() as u16,
                    fragments: self.count as u8,
                    fragment_index: None,
                    received_mask: None,
                });
                event.probe = capture.probe_identity(&self.payload);
                event.reason = reason;
                event
            });
        }
    }
}
impl Iterator for Fragments {
    type Item = Record;
    fn next(&mut self) -> Option<Record> {
        if self.index == self.count {
            return None;
        }
        let index = self.index;
        self.index += 1;
        if self.count == 1 {
            return Some(Record {
                flow: self.flow,
                id: self.base,
                payload: std::mem::take(&mut self.payload),
            });
        }
        let chunk = &self.payload[index * CHUNK..((index + 1) * CHUNK).min(self.payload.len())];
        let mut payload = Vec::with_capacity(HEADER + chunk.len());
        payload.extend(self.base.to_be_bytes());
        payload.extend((self.payload.len() as u16).to_be_bytes());
        payload.push(index as u8);
        payload.extend(chunk);
        Some(Record {
            flow: self.flow | FLAG,
            id: self.base + index as u64,
            payload,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.count - self.index;
        (left, Some(left))
    }
}
impl ExactSizeIterator for Fragments {}

pub(super) fn split(
    flow: u32,
    next: &mut u64,
    payload: Vec<u8>,
    limit: usize,
) -> Result<Fragments> {
    ensure!(
        flow < FLAG && payload.len() <= limit && limit <= MAX_MESSAGE,
        "message exceeds negotiated bounds"
    );
    let count = if payload.len() <= MAX_PAYLOAD {
        1
    } else {
        payload.len().div_ceil(CHUNK)
    };
    let base = next
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("message id exhausted"))?;
    *next = next
        .checked_add(count as u64)
        .ok_or_else(|| anyhow::anyhow!("message id exhausted"))?;
    Ok(Fragments {
        flow,
        base,
        index: 0,
        count,
        payload,
    })
}

struct Assembly {
    flow: u32,
    total: usize,
    received: u8,
    data: Vec<u8>,
    created: Instant,
}
pub(super) struct Reassembly {
    scope: Option<stats::Scope>,
    failures: stats::MessageFailures,
    reported_failures: stats::MessageFailures,
    limit: usize,
    ttl: Duration,
    active: BTreeMap<u64, Assembly>,
    finished: BTreeSet<u64>,
    highest: u64,
    bytes: usize,
    reported: (u64, u64),
    pub(super) completed: u64,
    pub(super) dropped: u64,
}
impl Reassembly {
    pub(super) fn new(limit: usize, ttl: Duration) -> Self {
        Self {
            scope: None,
            failures: stats::MessageFailures::default(),
            reported_failures: stats::MessageFailures::default(),
            limit,
            ttl,
            active: BTreeMap::new(),
            finished: BTreeSet::new(),
            highest: 0,
            bytes: 0,
            reported: (0, 0),
            completed: 0,
            dropped: 0,
        }
    }
    pub(super) fn with_scope(mut self, scope: stats::Scope) -> Self {
        self.scope = Some(scope);
        self
    }
    fn trace_assembly(&self, base: u64, a: &Assembly, reason: Option<trace::Reason>) {
        if let Some(scope) = &self.scope {
            scope.trace_with(|context, _| {
                let mut event = trace::Event::new(
                    context,
                    if reason.is_some() {
                        trace::Stage::MessageDropped
                    } else {
                        trace::Stage::MessageReassembled
                    },
                );
                event.record = Some(trace::RecordKey {
                    flow: a.flow,
                    record_id: base,
                });
                event.message = Some(trace::MessageKey {
                    base_record_id: base,
                    payload_bytes: a.total as u16,
                    fragments: a.total.div_ceil(CHUNK) as u8,
                    fragment_index: None,
                    received_mask: Some(a.received),
                });
                event.reason = reason;
                event
            });
        }
    }
    pub(super) fn take_counters(&mut self) -> (u64, u64, stats::MessageFailures) {
        let delta = (
            self.completed - self.reported.0,
            self.dropped - self.reported.1,
            self.failures.since(self.reported_failures),
        );
        self.reported = (self.completed, self.dropped);
        self.reported_failures = self.failures;
        delta
    }
    pub(super) fn close(&mut self) {
        for (base, assembly) in &self.active {
            self.trace_assembly(*base, assembly, Some(trace::Reason::Shutdown));
        }
        self.failures.shutdown += self.active.len() as u64;
        self.dropped += self.active.len() as u64;
        self.active.clear();
        self.bytes = 0;
    }
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.active.values().map(|a| a.created + self.ttl).min()
    }
    fn remove(&mut self, id: u64) -> Option<Assembly> {
        self.finished.insert(id);
        let assembly = self.active.remove(&id)?;
        self.bytes -= assembly.total;
        Some(assembly)
    }
    pub(super) fn expire(&mut self, now: Instant) {
        let ids: Vec<_> = self
            .active
            .iter()
            .filter(|(id, a)| {
                now >= a.created + self.ttl || **id < self.highest.saturating_sub(WINDOW)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            let assembly = self.remove(id).expect("active assembly");
            let reason = if now >= assembly.created + self.ttl {
                self.failures.expired += 1;
                trace::Reason::Expired
            } else {
                self.failures.window += 1;
                trace::Reason::Stale
            };
            self.trace_assembly(id, &assembly, Some(reason));
            self.dropped += 1;
        }
        let floor = self.highest.saturating_sub(WINDOW);
        while self.finished.first().is_some_and(|id| *id < floor) {
            self.finished.pop_first();
        }
    }
    pub(super) fn receive(&mut self, record: Record, now: Instant) -> Option<(Record, Instant)> {
        if record.flow & FLAG == 0 {
            return Some((record, now));
        }
        self.expire(now);
        let b = &record.payload;
        if self.limit <= MAX_PAYLOAD || b.len() < HEADER {
            self.dropped += 1;
            self.failures.invalid += 1;
            return None;
        }
        let base = u64::from_be_bytes(b[..8].try_into().ok()?);
        let total = usize::from(u16::from_be_bytes(b[8..10].try_into().ok()?));
        let index = usize::from(b[10]);
        let count = total.div_ceil(CHUNK);
        if base == 0
            || total <= MAX_PAYLOAD
            || total > self.limit
            || index >= count
            || base.checked_add(index as u64) != Some(record.id)
            || b.len() != HEADER + (total - index * CHUNK).min(CHUNK)
        {
            self.dropped += 1;
            self.failures.invalid += 1;
            return None;
        }
        if base < self.highest.saturating_sub(WINDOW) || self.finished.contains(&base) {
            return None;
        }
        self.highest = self.highest.max(record.id);
        self.expire(now);
        let flow = record.flow & !FLAG;
        if !self.active.contains_key(&base) {
            if self.active.len() >= ACTIVE_LIMIT || self.bytes + total > BYTE_LIMIT {
                self.finished.insert(base);
                self.dropped += 1;
                self.failures.capacity += 1;
                if let Some(scope) = &self.scope {
                    scope.trace_record(
                        trace::Stage::MessageDropped,
                        &record,
                        None,
                        Some(trace::Reason::ByteLimit),
                    );
                }
                return None;
            }
            self.active.insert(
                base,
                Assembly {
                    flow,
                    total,
                    received: 0,
                    data: vec![0; total],
                    created: now,
                },
            );
            self.bytes += total;
        }
        let a = self.active.get_mut(&base)?;
        let start = index * CHUNK;
        let end = start + b.len() - HEADER;
        if a.flow != flow
            || a.total != total
            || (a.received & (1 << index) != 0 && a.data[start..end] != b[HEADER..])
        {
            let assembly = self.remove(base).expect("conflicting assembly");
            self.trace_assembly(base, &assembly, Some(trace::Reason::FragmentConflict));
            self.dropped += 1;
            self.failures.conflict += 1;
            return None;
        }
        a.data[start..end].copy_from_slice(&b[HEADER..]);
        a.received |= 1 << index;
        if a.received != (1 << count) - 1 {
            return None;
        }
        let a = self.remove(base)?;
        self.trace_assembly(base, &a, None);
        self.completed += 1;
        Some((
            Record {
                flow,
                id: base,
                payload: a.data,
            },
            a.created,
        ))
    }
}

pub(super) async fn deadline(receiver: &Reassembly) {
    if let Some(at) = receiver.deadline() {
        tokio::time::sleep_until(at.into()).await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn small_message_reuses_its_buffer_without_fragment_allocation() {
        let payload = vec![5; MAX_PAYLOAD];
        let pointer = payload.as_ptr();
        let mut records = split(1, &mut 0, payload, MAX_MESSAGE).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records.next().unwrap().payload.as_ptr(), pointer);
        assert!(records.next().is_none());
    }
    #[test]
    fn boundaries_reordering_duplicates_and_loss_preserve_messages() {
        for size in [0, 1000, 1001, 1200, 1472, 4096] {
            let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            let parts: Vec<_> = split(3, &mut 0, payload.clone(), MAX_MESSAGE)
                .unwrap()
                .collect();
            assert!(
                parts
                    .iter()
                    .all(|r| r.encode().unwrap().len() <= MAX_PAYLOAD + 12)
            );
            let mut receiver = Reassembly::new(MAX_MESSAGE, Duration::from_millis(100));
            let now = Instant::now();
            let mut completed = Vec::new();
            for part in parts.iter().rev() {
                if let Some((r, _)) = receiver.receive(part.clone(), now) {
                    completed.push(r);
                }
            }
            assert_eq!(completed.len(), 1);
            assert_eq!(completed[0].payload, payload);
            if size > MAX_PAYLOAD {
                for part in &parts {
                    assert!(receiver.receive(part.clone(), now).is_none());
                }
                let mut lost = Reassembly::new(MAX_MESSAGE, Duration::from_millis(100));
                for part in parts.iter().skip(1) {
                    assert!(lost.receive(part.clone(), now).is_none());
                }
                lost.expire(now + Duration::from_millis(100));
                for part in parts {
                    assert!(
                        lost.receive(part, now + Duration::from_millis(101))
                            .is_none()
                    );
                }
                assert!(lost.active.is_empty());
                assert_eq!(lost.bytes, 0);
                assert_eq!(lost.dropped, 1);
            }
        }
        assert!(split(0, &mut 0, vec![0; MAX_MESSAGE + 1], MAX_MESSAGE).is_err());
    }
    #[test]
    fn lifetime_is_not_refreshed_and_memory_is_bounded() {
        let now = Instant::now();
        let ttl = Duration::from_millis(100);
        let mut receiver = Reassembly::new(MAX_MESSAGE, ttl);
        let mut next = 0;
        for _ in 0..10000 {
            let parts: Vec<_> = split(1, &mut next, vec![1; MAX_MESSAGE], MAX_MESSAGE)
                .unwrap()
                .collect();
            assert!(receiver.receive(parts[0].clone(), now).is_none());
            assert!(receiver.bytes <= BYTE_LIMIT);
            assert!(receiver.active.len() <= ACTIVE_LIMIT);
            assert!(receiver.finished.len() <= WINDOW as usize + 1);
        }
        receiver.expire(now + ttl);
        assert_eq!(receiver.bytes, 0);
        let parts: Vec<_> = split(1, &mut next, vec![2; 1200], MAX_MESSAGE)
            .unwrap()
            .collect();
        receiver.receive(parts[0].clone(), now);
        receiver.receive(parts[0].clone(), now + ttl / 2);
        assert!(receiver.receive(parts[1].clone(), now + ttl).is_none());
    }
    #[test]
    fn malformed_or_conflicting_fragments_cannot_deliver_or_allocate_unbounded_memory() {
        let now = Instant::now();
        let parts: Vec<_> = split(1, &mut 0, vec![2; 1200], MAX_MESSAGE)
            .unwrap()
            .collect();
        let mut receiver = Reassembly::new(MAX_MESSAGE, Duration::from_secs(1));
        receiver.receive(parts[0].clone(), now);
        let mut conflict = parts[0].clone();
        conflict.payload[HEADER] ^= 1;
        assert!(receiver.receive(conflict, now).is_none());
        assert!(receiver.receive(parts[1].clone(), now).is_none());
        assert_eq!(receiver.bytes, 0);
        for total in [0u16, 999, 4097, u16::MAX] {
            let mut invalid = parts[0].clone();
            invalid.payload[8..10].copy_from_slice(&total.to_be_bytes());
            assert!(receiver.receive(invalid, now).is_none());
            assert_eq!(receiver.bytes, 0);
        }
        let mut legacy = Reassembly::new(MAX_PAYLOAD, Duration::from_secs(1));
        for part in parts {
            assert!(legacy.receive(part, now).is_none());
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::runtime::{
        mesh, quality, stats,
        tunnel::{coding, enqueue_encoded, outbound},
        wire,
    };
    #[test]
    fn whole_message_admission_never_publishes_a_partial_message() {
        use crate::runtime::{
            QUEUE,
            tunnel::{QueuedRecord, enqueue_message},
        };
        for size in [1001, 1472, MAX_MESSAGE] {
            for threshold in [0, 128] {
                let needed = split(1, &mut 0, vec![0; size], MAX_MESSAGE).unwrap().len();
                let reserve = if threshold == 0 { 0 } else { QUEUE / 16 };
                for available in [needed - 1, needed] {
                    let (tx, mut rx) = tokio::sync::mpsc::channel(QUEUE);
                    let occupied = QUEUE - reserve - available;
                    let now = Instant::now();
                    for id in 0..occupied {
                        tx.try_send(QueuedRecord {
                            record: Record {
                                flow: 2,
                                id: id as u64,
                                payload: vec![0],
                            },
                            created: now,
                        })
                        .unwrap();
                    }
                    let metrics = stats::Metrics::new("atomic-message");
                    let scope = metrics.scope("message", stats::FORWARD);
                    let parts = split(1, &mut 0, vec![7; size], MAX_MESSAGE).unwrap();
                    let accepted = enqueue_message(&tx, parts, now, &scope, threshold);
                    assert_eq!(accepted, available == needed);
                    let mut fragments = Vec::new();
                    while let Ok(item) = rx.try_recv() {
                        if item.record.flow & FLAG != 0 {
                            fragments.push(item.record);
                        }
                    }
                    assert_eq!(fragments.len(), if accepted { needed } else { 0 });
                    assert_eq!(tx.capacity(), QUEUE);
                    if accepted {
                        let mut reassembly = Reassembly::new(MAX_MESSAGE, Duration::from_secs(1));
                        let result = fragments
                            .into_iter()
                            .filter_map(|r| reassembly.receive(r, now))
                            .collect::<Vec<_>>();
                        assert_eq!(result.len(), 1);
                        assert_eq!(result[0].0.payload, vec![7; size]);
                    }
                }
            }
        }
    }

    #[test]
    fn atomic_admission_preserves_small_reserve_and_closed_channel_counters() {
        use crate::runtime::{QUEUE, tunnel::enqueue_message};
        let (tx, mut rx) = tokio::sync::mpsc::channel(QUEUE);
        let metrics = stats::Metrics::new("atomic-reserve");
        let scope = metrics.scope("message", stats::FORWARD);
        let mut id = 0;
        let now = Instant::now();
        for _ in 0..QUEUE - QUEUE / 16 {
            assert!(enqueue_message(
                &tx,
                split(1, &mut id, vec![0; 1000], MAX_MESSAGE).unwrap(),
                now,
                &scope,
                128
            ));
        }
        assert!(!enqueue_message(
            &tx,
            split(1, &mut id, vec![0; 1001], MAX_MESSAGE).unwrap(),
            now,
            &scope,
            128
        ));
        assert!(enqueue_message(
            &tx,
            split(2, &mut id, vec![0; 128], MAX_MESSAGE).unwrap(),
            now,
            &scope,
            128
        ));
        while rx.try_recv().is_ok() {}
        drop(rx);
        assert!(!enqueue_message(
            &tx,
            split(1, &mut id, vec![0; MAX_MESSAGE], MAX_MESSAGE).unwrap(),
            now,
            &scope,
            0
        ));
        let snapshot = metrics.snapshot(false, "running", None).unwrap();
        assert_eq!(
            snapshot["stats"]["directions"][stats::FORWARD]["records"]["messages_admission_dropped"],
            2
        );
        assert_eq!(
            snapshot["stats"]["directions"][stats::FORWARD]["records"]["sender_queue_closed_dropped"],
            5
        );
    }
    #[test]
    fn short_fragment_tails_cannot_use_the_small_message_lane_or_its_reserved_slots() {
        let mut policy = mesh::tests::policy();
        policy.max_message_bytes = MAX_MESSAGE;
        policy.mixed_fec = true;
        policy.small_fec_bytes = 128;
        policy.fec = 2;
        policy.redundancy = 30;
        let parts: Vec<_> = split(7, &mut 0, vec![0; 1001], MAX_MESSAGE)
            .unwrap()
            .collect();
        assert!(parts[1].payload.len() < 128);
        let now = Instant::now();
        let mut encoder = coding::RecordEncoder::new(&policy).unwrap();
        let symbols: Vec<_> = parts
            .iter()
            .flat_map(|r| encoder.encode_ingress(r, now, now).unwrap())
            .collect();
        assert_eq!(symbols.len(), 3);
        assert!(symbols.iter().all(|s| !s.small));
        let (tx, _rx) = tokio::sync::mpsc::channel(crate::runtime::QUEUE);
        let scope = stats::Metrics::new("fragment-priority").scope("message", stats::FORWARD);
        while crate::runtime::tunnel::enqueue_record(
            &tx,
            Record {
                flow: 7,
                id: 1,
                payload: vec![0; 1000],
            },
            now,
            &scope,
            128,
        ) {}
        assert!(!crate::runtime::tunnel::enqueue_record(
            &tx,
            parts[1].clone(),
            now,
            &scope,
            128
        ));
        assert!(crate::runtime::tunnel::enqueue_record(
            &tx,
            Record {
                flow: 8,
                id: 3,
                payload: vec![0; 32]
            },
            now,
            &scope,
            128
        ));
    }
    #[test]
    fn fragments_share_original_deadline_flow_budget_and_minimum_mtu_allowance() {
        let mut policy = mesh::tests::policy();
        policy.max_message_bytes = MAX_MESSAGE;
        policy.fec = 2;
        policy.redundancy = 100;
        let now = Instant::now();
        let created = now - Duration::from_millis(90);
        let parts = split(7, &mut 0, vec![3; MAX_MESSAGE], MAX_MESSAGE).unwrap();
        let mut encoder = coding::RecordEncoder::new(&policy).unwrap();
        let mut queue = outbound::Queue::default();
        let mut blocks = BTreeMap::new();
        let scope = stats::Metrics::new("fragment-clock").scope("message", stats::FORWARD);
        let measurement = quality::State::new(1);
        for part in parts {
            for symbol in encoder.encode_ingress(&part, now, created).unwrap() {
                // Even the largest HTTP datagram stream mapping and quality
                // envelope fit comfortably below a 1200-byte QUIC path MTU.
                let packet =
                    wire::http_datagram((1 << 60) - 4, &measurement.wrap(&symbol.data, 0)).unwrap();
                assert!(packet.len() <= 1120);
                enqueue_encoded(symbol, created, &mut queue, &mut blocks, &policy, &scope);
            }
        }
        assert_eq!(queue.original_flows(), 1);
        assert!(queue.would_be_full(7) == queue.would_be_full(policy.flow(7 | FLAG)));
        let expired = queue.expire(
            created + policy.admission_lifetime(),
            policy.admission_lifetime(),
        );
        assert!(!expired.is_empty());
        assert!(queue.is_empty());
        assert!(expired.iter().all(|p| p.created == created));
        assert!(expired.iter().filter_map(|p| p.flow).all(|flow| flow == 7));
    }
}

#[cfg(test)]
mod accounting_tests {
    use super::*;
    use crate::runtime::{stats, tunnel::publish_messages};
    #[tokio::test]
    async fn missing_fragment_has_a_message_identity_bitmap_and_expiry_reason() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("trace.jsonl");
        let reporter = stats::Reporter::new(
            "fragment-evidence",
            stats::Options {
                stats_interval_ms: 1000,
                trace: trace::Options {
                    packet_trace: Some(file.clone()),
                    packet_trace_probe_header: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let scope = reporter
            .metrics
            .scope("00000000000000000000000000000001", stats::RETURN);
        let mut body = vec![7; 1472];
        body[..4].copy_from_slice(b"BPP2");
        body[4] = 3;
        body[5..8].fill(0);
        body[8..24].copy_from_slice(&17u128.to_be_bytes());
        body[24..28].copy_from_slice(&29u32.to_be_bytes());
        let mut parts = split(3, &mut 0, body, MAX_MESSAGE).unwrap();
        parts.trace(&scope, trace::Stage::MessageAssigned, None);
        let now = Instant::now();
        let mut rx =
            Reassembly::new(MAX_MESSAGE, Duration::from_millis(100)).with_scope(scope.clone());
        let first = parts.next().unwrap();
        scope.trace_record(trace::Stage::RecordDecoded, &first, None, None);
        assert!(rx.receive(first, now).is_none());
        rx.expire(now + Duration::from_millis(100));
        publish_messages(&mut rx, &scope);
        publish_messages(&mut rx, &scope);
        let snapshot = reporter.metrics.snapshot(false, "running", None).unwrap();
        assert_eq!(
            snapshot["stats"]["directions"][stats::RETURN]["records"]["message_reassembly_failures"]
                ["expired"],
            1
        );
        reporter.finish(Ok(())).await.unwrap();
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(file)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        let assigned = rows
            .iter()
            .find(|r| r["stage"] == "message_assigned")
            .unwrap();
        assert_eq!(assigned["probe"]["seq"], 29);
        let lost = rows
            .iter()
            .find(|r| r["stage"] == "message_dropped")
            .unwrap();
        assert_eq!(lost["reason"], "expired");
        assert_eq!(
            lost["message"]["base_record_id"],
            assigned["message"]["base_record_id"]
        );
        assert_eq!(lost["message"]["fragments"], 2);
        assert_eq!(lost["message"]["received_mask"], 1);
    }
    #[test]
    fn reassembly_counters_accumulate_across_sessions_without_double_counting() {
        let metrics = stats::Metrics::new("reassembly");
        for session in ["window_a", "window_b"] {
            let mut rx = Reassembly::new(MAX_MESSAGE, Duration::from_secs(1));
            let scope = metrics.scope(session, stats::RETURN);
            for part in split(1, &mut 0, vec![0; 1200], MAX_MESSAGE).unwrap() {
                rx.receive(part, Instant::now());
                publish_messages(&mut rx, &scope);
            }
            publish_messages(&mut rx, &scope);
            rx.close();
            publish_messages(&mut rx, &scope);
        }
        let value = metrics.snapshot(false, "test", None).unwrap();
        assert_eq!(
            value["stats"]["directions"][stats::RETURN]["records"]["messages_reassembled"],
            2
        );
        for session in ["window_a", "window_b"] {
            assert_eq!(
                value["stats"]["sessions"][session][stats::RETURN]["records"]["messages_reassembled"],
                1
            );
        }
    }
}
