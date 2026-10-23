//! Message segmentation above the existing FEC records. No retransmission.
use super::{MAX_PAYLOAD, Record};
use crate::runtime::MAX_MESSAGE;
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

/// Stack-owned iterator: the common unfragmented path keeps its payload buffer
/// and does not allocate an intermediate record vector.
pub(super) struct Fragments {
    flow: u32,
    base: u64,
    index: usize,
    count: usize,
    payload: Vec<u8>,
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
    pub(super) fn take_counters(&mut self) -> (u64, u64) {
        let delta = (
            self.completed - self.reported.0,
            self.dropped - self.reported.1,
        );
        self.reported = (self.completed, self.dropped);
        delta
    }
    pub(super) fn close(&mut self) {
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
            self.remove(id);
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
            self.remove(base);
            self.dropped += 1;
            return None;
        }
        a.data[start..end].copy_from_slice(&b[HEADER..]);
        a.received |= 1 << index;
        if a.received != (1 << count) - 1 {
            return None;
        }
        let a = self.remove(base)?;
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
