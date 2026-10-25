use super::MAX_PAYLOAD;
use crate::fec::{Decoder, Shard};
use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

pub const HEADER: usize = 13;
pub const MAX_WIRE: usize = HEADER + 12 + MAX_PAYLOAD + 2;
const BLOCK_WINDOW: u64 = 256;
const MESSAGE_WINDOW: u64 = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub flow: u32,
    pub id: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordDisposition {
    New,
    Duplicate,
    LateStream,
}
impl Record {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.payload.len() <= MAX_PAYLOAD,
            "UDP message exceeds {MAX_PAYLOAD} bytes"
        );
        let mut out = Vec::with_capacity(12 + self.payload.len());
        out.extend(self.flow.to_be_bytes());
        out.extend(self.id.to_be_bytes());
        out.extend(&self.payload);
        Ok(out)
    }
    /// Validate a record and read routing/accounting fields without copying its payload.
    pub fn decode_identity(b: &[u8]) -> Result<(u32, u64)> {
        ensure!(
            (12..=12 + MAX_PAYLOAD).contains(&b.len()),
            "invalid record length"
        );
        Ok((
            u32::from_be_bytes(b[..4].try_into()?),
            u64::from_be_bytes(b[4..12].try_into()?),
        ))
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let (flow, id) = Self::decode_identity(b)?;
        Ok(Self {
            flow,
            id,
            payload: b[12..].to_vec(),
        })
    }
}

pub fn shard(s: Shard) -> Bytes {
    let (kind, block, index, body) = match s {
        Shard::Data {
            block,
            index,
            payload,
        } => (0, block, index, payload),
        Shard::Repair {
            block,
            count,
            coded,
        } => (1, block, count, coded),
        Shard::RepairQ {
            block,
            count,
            coded,
        } => (3, block, count, coded),
    };
    frame(kind, block, index, &body)
}
pub fn plain(record: &Record) -> Result<Bytes> {
    Ok(frame(2, 0, 0, &record.encode()?))
}
fn frame(kind: u8, block: u64, index: u8, body: &[u8]) -> Bytes {
    let mut b = Vec::with_capacity(HEADER + body.len());
    b.extend([b'B', b'P', 1, kind]);
    b.extend(block.to_be_bytes());
    b.push(index);
    b.extend(body);
    b.into()
}
fn decode(b: &[u8]) -> Result<Option<Shard>> {
    ensure!(
        (HEADER..=MAX_WIRE).contains(&b.len()) && b[..3] == [b'B', b'P', 1],
        "invalid frame"
    );
    let block = u64::from_be_bytes(b[4..12].try_into()?);
    match b[3] {
        0 => {
            ensure!(b[12] < 32, "invalid symbol index");
            Record::decode_identity(&b[HEADER..])?;
            Ok(Some(Shard::Data {
                block,
                index: b[12],
                payload: b[HEADER..].to_vec(),
            }))
        }
        1 | 3 => {
            ensure!(
                (1..=32).contains(&b[12]) && b.len() >= HEADER + 14,
                "invalid repair"
            );
            let coded = b[HEADER..].to_vec();
            Ok(Some(if b[3] == 1 {
                Shard::Repair {
                    block,
                    count: b[12],
                    coded,
                }
            } else {
                Shard::RepairQ {
                    block,
                    count: b[12],
                    coded,
                }
            }))
        }
        2 => {
            ensure!(block == 0 && b[12] == 0, "invalid plain frame");
            Ok(None)
        }
        _ => bail!("unknown frame type"),
    }
}

/// Exact mapping bytes, including context 0, for allocation-free admission checks.
pub fn http_datagram_overhead(stream: u64) -> Result<usize> {
    ensure!(
        stream < (1u64 << 62) && stream.is_multiple_of(4),
        "invalid request stream"
    );
    let q = stream / 4;
    let n = if q < 64 {
        1
    } else if q < 16384 {
        2
    } else if q < (1 << 30) {
        4
    } else {
        8
    };
    Ok(n + 1)
}

/// RFC 9297 Quarter Stream ID followed by BraidPath context 0.
/// Implemented here to validate mapping explicitly, including nonzero stream IDs.
pub fn http_datagram(stream: u64, payload: &[u8]) -> Result<Bytes> {
    let n = http_datagram_overhead(stream)? - 1;
    let q = stream / 4;
    let mut b = Vec::with_capacity(n + 1 + payload.len());
    let full = q.to_be_bytes();
    b.extend_from_slice(&full[8 - n..]);
    b[0] |= match n {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    b.push(0);
    b.extend(payload);
    Ok(b.into())
}
pub fn http_payload(b: &[u8], stream: u64) -> Result<&[u8]> {
    ensure!(!b.is_empty(), "empty HTTP datagram");
    let n = 1usize << (b[0] >> 6);
    ensure!(b.len() > n, "truncated HTTP datagram");
    let mut q = u64::from(b[0] & 0x3f);
    for v in &b[1..n] {
        q = (q << 8) | u64::from(*v);
    }
    ensure!(
        q < (1u64 << 60) && q * 4 == stream && b[n] == 0,
        "wrong request/context"
    );
    Ok(&b[n + 1..])
}

pub struct Receiver {
    blocks: BTreeMap<u64, Option<(Decoder, Instant)>>,
    // Exact occupancy, maintained at the same mutations as retained_bytes.
    // Publishing per-arrival telemetry must not scan the entire block window.
    live_decoders: usize,
    repair_wait: Duration,
    dual_repairs: bool,
    retention: Option<super::fec_retention::Controller>,
    budget: Option<super::receiver_budget::Controller>,
    block_floor: u64,
    retained_bytes: usize,
    next_expiry: Option<Instant>,
    highest_block: u64,
    delivered: BTreeSet<u64>,
    highest_message: u64,
    pub original_packets: u64,
    pub repair_packets: u64,
    pub stale: u64,
    pub originals: u64,
    pub recovered: u64,
    pub duplicates: u64,
    pub invalid: u64,
    pub late_stream_records: u64,
}
impl Default for Receiver {
    fn default() -> Self {
        Self::with_repair_wait(Duration::from_secs(2))
    }
}
impl Receiver {
    /// Bound reconstruction by time since the first local arrival for a block.
    /// This is not a cross-machine or application delivery deadline: authenticated
    /// originals remain eligible within the independent record-ID window after
    /// their decoder expires. A zero wait disables reconstruction.
    pub fn with_repair_wait(repair_wait: Duration) -> Self {
        Self {
            blocks: BTreeMap::new(),
            live_decoders: 0,
            repair_wait,
            dual_repairs: false,
            retention: None,
            budget: None,
            block_floor: 0,
            retained_bytes: 0,
            next_expiry: None,
            highest_block: 0,
            delivered: BTreeSet::new(),
            highest_message: 0,
            original_packets: 0,
            repair_packets: 0,
            stale: 0,
            originals: 0,
            recovered: 0,
            duplicates: 0,
            invalid: 0,
            late_stream_records: 0,
        }
    }

    /// Optional local receiver policy; it does not alter session wire negotiation
    /// or the sender's queue/deadline. The fixed path preserves its prior behavior.
    pub fn configured(repair_wait: Duration, adaptive: bool) -> Self {
        if adaptive {
            Self {
                retention: Some(super::fec_retention::Controller::default()),
                budget: Some(super::receiver_budget::Controller::default()),
                ..Self::default()
            }
        } else {
            Self::with_repair_wait(repair_wait)
        }
    }

    /// Called only after authenticated session policy negotiation.
    pub fn with_dual_repairs(mut self, enabled: bool) -> Self {
        self.dual_repairs = enabled;
        self
    }

    pub fn retention_snapshot(&self) -> Option<super::fec_retention::Snapshot> {
        self.retention.as_ref().map(|r| {
            let mut snapshot = r.snapshot(self.live_decoders);
            snapshot.receive_budget = self.budget.as_ref().map(|b| b.snapshot());
            snapshot
        })
    }

    /// Wake only adaptive receivers with live state. Retirement also happens on
    /// every arrival, so a delayed timer cannot make an expired repair eligible.
    pub fn next_retention_deadline(&self) -> Option<Instant> {
        self.retention.as_ref()?;
        self.next_expiry
    }

    fn expire_blocks(&mut self, now: Instant) {
        if self.next_expiry.is_none_or(|at| now < at) {
            return;
        }
        self.next_expiry = None;
        for (block, slot) in &mut self.blocks {
            let hold = self
                .retention
                .as_ref()
                .map_or(self.repair_wait, |r| r.hold(*block));
            if slot
                .as_ref()
                .is_some_and(|(_, first)| now.saturating_duration_since(*first) >= hold)
            {
                self.retained_bytes -= slot
                    .as_ref()
                    .expect("live expiring decoder")
                    .0
                    .retained_bytes();
                self.live_decoders -= 1;
                *slot = None;
                if let Some(r) = &mut self.retention {
                    r.retired(*block, true);
                }
            } else if let Some((_, first)) = slot
                && let Some(at) = first.checked_add(hold)
            {
                self.next_expiry = Some(self.next_expiry.map_or(at, |old| old.min(at)));
            }
        }
        if let Some(b) = &mut self.budget {
            b.account(self.retained_bytes, 0);
        }
    }

    pub fn expire_adaptive(&mut self, now: Instant) {
        if self.retention.is_some() {
            self.expire_blocks(now);
        }
    }

    pub fn close_retention(&mut self) {
        if let Some(r) = &mut self.retention {
            self.blocks.clear();
            self.live_decoders = 0;
            r.clear();
            self.retained_bytes = 0;
            self.next_expiry = None;
            if let Some(b) = &mut self.budget {
                b.account(0, 0);
            }
        }
    }

    pub fn receive(&mut self, b: &[u8], now: Instant) -> Result<Vec<Record>> {
        self.receive_observed(b, now, |_, _, _| {})
    }

    /// Observe the actual record-ID decision without retaining payloads or
    /// changing decoder state. Recovered means reconstruction won this arrival
    /// race; it does not prove that the original would never arrive later.
    pub fn receive_observed(
        &mut self,
        b: &[u8],
        now: Instant,
        observe: impl FnMut(&Record, bool, RecordDisposition),
    ) -> Result<Vec<Record>> {
        self.receive_with_late(b, now, |_| false, observe)
    }

    /// Only an existing reliable flow may opt out of the record age window.
    /// In particular, an old opener must never recreate a retired flow.
    pub(crate) fn receive_with_late(
        &mut self,
        b: &[u8],
        now: Instant,
        accepts_late: impl Fn(u32) -> bool,
        mut observe: impl FnMut(&Record, bool, RecordDisposition),
    ) -> Result<Vec<Record>> {
        ensure!(
            self.dual_repairs || b.get(3) != Some(&3),
            "unnegotiated dual repair"
        );
        let decoded = decode(b)?;
        if matches!(decoded, Some(Shard::Repair { .. } | Shard::RepairQ { .. })) {
            self.repair_packets += 1;
        } else {
            self.original_packets += 1;
        }
        // Original delivery does not depend on retaining a FEC decoder. Fast
        // paths can advance the block window before useful originals arrive on
        // slower paths. Only reconstruction state is retired by that window.
        let mut deliveries = match &decoded {
            Some(Shard::Data { payload, .. }) => vec![(Record::decode(payload)?, false)],
            Some(Shard::Repair { .. } | Shard::RepairQ { .. }) => Vec::new(),
            None => vec![(Record::decode(&b[HEADER..])?, false)],
        };
        if let Some(s) = decoded {
            let repair = matches!(s, Shard::Repair { .. } | Shard::RepairQ { .. });
            let block = s.block();
            let window = if let (Some(b), Some(r)) = (&mut self.budget, &self.retention) {
                if block > self.highest_block || self.blocks.is_empty() {
                    b.observe(block, now, r.maximum_live_hold())
                } else {
                    b.current_blocks()
                }
            } else {
                BLOCK_WINDOW
            };
            self.highest_block = self.highest_block.max(block);
            self.block_floor = self
                .block_floor
                .max(self.highest_block.saturating_sub(window - 1));
            let floor = self.block_floor;
            while self
                .blocks
                .first_key_value()
                .is_some_and(|(id, _)| *id < floor)
            {
                let (_, slot) = self.blocks.pop_first().expect("known first block");
                if let Some((decoder, _)) = slot {
                    self.retained_bytes -= decoder.retained_bytes();
                    self.live_decoders -= 1;
                }
            }
            if let Some(r) = &mut self.retention {
                r.retain_floor(floor);
            }
            self.expire_blocks(now);
            if block < floor {
                if repair {
                    self.stale += 1;
                }
            } else {
                let (token, count) = match &s {
                    Shard::Data { index, .. } => (*index, None),
                    Shard::Repair { count, .. } => (32, Some(*count)),
                    Shard::RepairQ { count, .. } => (33, Some(*count)),
                };
                if let Some(r) = &mut self.retention {
                    r.register(block, now);
                }
                let retained_bytes = &mut self.retained_bytes;
                let live_decoders = &mut self.live_decoders;
                let slot = self.blocks.entry(block).or_insert_with(|| {
                    (!self.repair_wait.is_zero()).then(|| {
                        let decoder = Decoder::new(block);
                        *retained_bytes += decoder.retained_bytes();
                        *live_decoders += 1;
                        (decoder, now)
                    })
                });
                if let Some((decoder, _)) = slot {
                    let duplicate_repair = repair && decoder.is_duplicate(&s);
                    let before = decoder.retained_bytes();
                    let received = decoder.receive(s);
                    let after = decoder.retained_bytes();
                    self.retained_bytes = self.retained_bytes - before + after;
                    match received {
                        Ok(v) => {
                            // The independently validated original above is the
                            // sole original candidate, including decoder repeats.
                            // All candidates share the same record-ID dedup below.
                            let recovered = v
                                .into_iter()
                                .filter(|d| d.recovered)
                                .map(|d| Record::decode(&d.payload))
                                .collect::<Result<Vec<_>>>();
                            match recovered {
                                Ok(records) => {
                                    deliveries.extend(records.into_iter().map(|r| (r, true)));
                                    if duplicate_repair {
                                        self.duplicates += 1;
                                    }
                                }
                                Err(error) => {
                                    self.retained_bytes -= after;
                                    self.live_decoders -= 1;
                                    *slot = None;
                                    if let Some(r) = &mut self.retention {
                                        r.retired(block, false);
                                    }
                                    return Err(error);
                                }
                            }
                        }
                        Err(error) => {
                            self.retained_bytes -= after;
                            self.live_decoders -= 1;
                            *slot = None;
                            if let Some(r) = &mut self.retention {
                                r.retired(block, false);
                            }
                            return Err(error.into());
                        }
                    }
                } else if repair {
                    self.stale += 1;
                }
                if let Some(r) = &mut self.retention {
                    r.observe(block, token, count, now);
                }
                if let Some((_, first)) = slot {
                    let hold = self
                        .retention
                        .as_ref()
                        .map_or(self.repair_wait, |r| r.hold(block));
                    if let Some(at) = first.checked_add(hold) {
                        self.next_expiry = Some(self.next_expiry.map_or(at, |old| old.min(at)));
                    }
                }
            }
        }
        if let Some(budget) = &mut self.budget {
            let mut evicted = 0;
            if self.retained_bytes > super::receiver_budget::MAX_BYTES {
                for (block, slot) in &mut self.blocks {
                    if self.retained_bytes <= super::receiver_budget::MAX_BYTES {
                        break;
                    }
                    if let Some((decoder, _)) = slot.take() {
                        self.retained_bytes -= decoder.retained_bytes();
                        self.live_decoders -= 1;
                        evicted += 1;
                        if let Some(r) = &mut self.retention {
                            r.retired(*block, false);
                        }
                    }
                }
            }
            budget.account(self.retained_bytes, evicted);
        }
        let mut out = Vec::new();
        for (record, repaired) in deliveries {
            self.highest_message = self.highest_message.max(record.id);
            let floor = self.highest_message.saturating_sub(MESSAGE_WINDOW - 1);
            while self.delivered.first().is_some_and(|id| *id < floor) {
                self.delivered.pop_first();
            }
            if record.id < floor && accepts_late(record.flow) {
                // The byte-stream receiver, with its own flow control and
                // byte-offset deduplication, owns late delivery decisions.
                // Do not extend record history or claim a new unique record.
                self.late_stream_records += 1;
                observe(&record, repaired, RecordDisposition::LateStream);
                out.push(record);
                continue;
            }
            if record.id < floor || !self.delivered.insert(record.id) {
                self.duplicates += 1;
                observe(&record, repaired, RecordDisposition::Duplicate);
                continue;
            }
            if repaired {
                self.recovered += 1
            } else {
                self.originals += 1
            }
            observe(&record, repaired, RecordDisposition::New);
            out.push(record);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec::Encoder;

    fn assert_cached_occupancy(receiver: &Receiver) {
        let live = receiver.blocks.values().flatten().count();
        assert_eq!(receiver.live_decoders, live);
        assert_eq!(
            receiver.retained_bytes,
            receiver
                .blocks
                .values()
                .flatten()
                .map(|(decoder, _)| decoder.retained_bytes())
                .sum::<usize>()
        );
        if let Some(snapshot) = receiver.retention_snapshot() {
            assert_eq!(snapshot.live_blocks, live);
        }
    }

    #[test]
    fn cached_occupancy_covers_errors_duplicates_eviction_expiry_and_close() {
        let at = Instant::now();
        for (wait_ms, adaptive) in [(0, false), (100, false), (100, true)] {
            let mut receiver = Receiver::configured(Duration::from_millis(wait_ms), adaptive);
            for block in 0..600u64 {
                let record = Record {
                    flow: 1,
                    id: block,
                    payload: vec![block as u8; 1000],
                };
                let packet = shard(Shard::Data {
                    block,
                    index: 0,
                    payload: record.encode().unwrap(),
                });
                let now = at + Duration::from_micros(block * 30);
                receiver.receive(&packet, now).unwrap();
                assert_cached_occupancy(&receiver);
                receiver.receive(&packet, now).unwrap();
                assert_cached_occupancy(&receiver);
                if block % 11 == 0 {
                    let mut conflicting = record;
                    conflicting.payload[0] ^= 1;
                    let _ = receiver.receive(
                        &shard(Shard::Data {
                            block,
                            index: 0,
                            payload: conflicting.encode().unwrap(),
                        }),
                        now,
                    );
                    assert_cached_occupancy(&receiver);
                }
            }
            // Valid FEC wire data reconstructing an invalid one-byte Record.
            let result = receiver.receive(
                &shard(Shard::Repair {
                    block: 601,
                    count: 1,
                    coded: [vec![0, 1], vec![0; 12]].concat(),
                }),
                at + Duration::from_millis(20),
            );
            assert_eq!(result.is_err(), wait_ms > 0 || adaptive);
            assert_cached_occupancy(&receiver);
            receiver.expire_blocks(at + Duration::from_secs(1));
            assert_cached_occupancy(&receiver);
            assert_eq!(receiver.live_decoders, 0);
            receiver.close_retention();
            receiver.close_retention();
            assert_cached_occupancy(&receiver);
        }
    }

    #[test]
    fn adaptive_block_budget_preserves_a_useful_late_repair_under_high_packet_rate() {
        let at = Instant::now();
        let mut encoder = Encoder::new(2, Duration::from_millis(8)).unwrap();
        let first = Record {
            flow: 1,
            id: 0,
            payload: vec![0; 1000],
        };
        let missing = Record {
            flow: 1,
            id: 1,
            payload: vec![1; 1000],
        };
        let data = encoder
            .push(&first.encode().unwrap(), at)
            .unwrap()
            .remove(0);
        let repair = encoder
            .push(&missing.encode().unwrap(), at)
            .unwrap()
            .remove(1);
        let mut old = Receiver::with_repair_wait(Duration::from_millis(100));
        let mut new = Receiver::configured(Duration::from_millis(100), true);
        for receiver in [&mut old, &mut new] {
            receiver.receive(&shard(data.clone()), at).unwrap();
        }
        for block in 1..=600 {
            let r = Record {
                flow: 1,
                id: block + 1,
                payload: vec![block as u8; 1000],
            };
            let packet = shard(Shard::Data {
                block,
                index: 0,
                payload: r.encode().unwrap(),
            });
            let now = at + Duration::from_micros(block * 100);
            old.receive(&packet, now).unwrap();
            new.receive(&packet, now).unwrap();
        }
        assert!(
            old.receive(&shard(repair.clone()), at + Duration::from_millis(90))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            new.receive(&shard(repair), at + Duration::from_millis(90))
                .unwrap(),
            vec![missing]
        );
        let s = new.retention_snapshot().unwrap();
        assert_eq!(s.window_evicted_live_blocks, 0);
        assert!(s.receive_budget.as_ref().unwrap().current_blocks > 256);
        assert!(new.retained_bytes <= super::super::receiver_budget::MAX_BYTES);
    }

    #[test]
    fn widening_never_revives_a_block_already_retired_by_the_id_floor() {
        let at = Instant::now();
        let mut receiver = Receiver::configured(Duration::from_millis(100), true);
        let packet = |block, id| {
            shard(Shard::Data {
                block,
                index: 0,
                payload: Record {
                    flow: 1,
                    id,
                    payload: vec![4; 1000],
                }
                .encode()
                .unwrap(),
            })
        };
        receiver.receive(&packet(0, 0), at).unwrap();
        receiver.receive(&packet(1000, 1000), at).unwrap();
        let old_floor = receiver.block_floor;
        assert!(old_floor > 0);
        receiver
            .receive(&packet(1064, 1064), at + Duration::from_millis(6))
            .unwrap();
        assert!(receiver.budget.as_ref().unwrap().current_blocks() > 256);
        assert!(receiver.block_floor >= old_floor);
        receiver
            .receive(&packet(0, 0), at + Duration::from_millis(7))
            .unwrap();
        assert!(!receiver.blocks.contains_key(&0));
    }

    #[test]
    fn decoder_byte_limit_and_timer_expiry_keep_dynamic_state_bounded() {
        let at = Instant::now();
        let mut receiver = Receiver::configured(Duration::from_millis(100), true);
        for block in 0..400 {
            for index in 0..32u8 {
                let r = Record {
                    flow: 1,
                    id: block * 32 + u64::from(index),
                    payload: vec![index; 1000],
                };
                receiver
                    .receive(
                        &shard(Shard::Data {
                            block,
                            index,
                            payload: r.encode().unwrap(),
                        }),
                        at + Duration::from_micros(block * 100),
                    )
                    .unwrap();
                assert!(receiver.retained_bytes <= super::super::receiver_budget::MAX_BYTES);
                assert_cached_occupancy(&receiver);
            }
        }
        let expected: usize = receiver
            .blocks
            .values()
            .flatten()
            .map(|(d, _)| d.retained_bytes())
            .sum();
        assert_eq!(receiver.retained_bytes, expected);
        assert!(
            receiver
                .retention_snapshot()
                .unwrap()
                .receive_budget
                .unwrap()
                .byte_evicted_blocks
                > 0
        );
        receiver.expire_adaptive(at + Duration::from_millis(400));
        assert_cached_occupancy(&receiver);
        assert_eq!(receiver.retained_bytes, 0);
        assert_eq!(receiver.next_retention_deadline(), None);
        receiver.close_retention();
        assert_cached_occupancy(&receiver);
        assert_eq!(
            receiver
                .retention_snapshot()
                .unwrap()
                .receive_budget
                .unwrap()
                .retained_decoder_bytes,
            0
        );
    }

    #[test]
    fn observed_receive_distinguishes_repair_first_from_later_duplicate_original() {
        let now = Instant::now();
        let record = Record {
            flow: 9,
            id: 71,
            payload: vec![4; 1000],
        };
        let mut encoder = Encoder::new(1, Duration::from_millis(5)).unwrap();
        let symbols: Vec<_> = encoder
            .push(&record.encode().unwrap(), now)
            .unwrap()
            .into_iter()
            .map(shard)
            .collect();
        assert_eq!(symbols.len(), 2);
        let mut receiver = Receiver::default();
        let mut observed = Vec::new();
        let recovered = receiver
            .receive_observed(&symbols[1], now, |r, repaired, duplicate| {
                observed.push((r.flow, r.id, repaired, duplicate))
            })
            .unwrap();
        let duplicate = receiver
            .receive_observed(&symbols[0], now, |r, repaired, duplicate| {
                observed.push((r.flow, r.id, repaired, duplicate))
            })
            .unwrap();
        assert_eq!(recovered, [record]);
        assert!(duplicate.is_empty());
        assert_eq!(
            observed,
            [
                (9, 71, true, RecordDisposition::New),
                (9, 71, false, RecordDisposition::Duplicate)
            ]
        );
        assert_eq!(
            (receiver.recovered, receiver.originals, receiver.duplicates),
            (1, 0, 1)
        );
    }

    fn coded_block(count: u8) -> (Vec<Record>, Vec<Bytes>) {
        let now = Instant::now();
        let mut encoder = Encoder::new(count, Duration::from_millis(5)).unwrap();
        let records: Vec<_> = (0..count)
            .map(|id| Record {
                flow: 7,
                id: u64::from(id),
                payload: vec![id; 17],
            })
            .collect();
        let symbols = records
            .iter()
            .flat_map(|record| encoder.push(&record.encode().unwrap(), now).unwrap())
            .map(shard)
            .collect();
        (records, symbols)
    }

    #[test]
    fn fast_blocks_do_not_discard_slow_path_originals() {
        let now = Instant::now();
        let mut fec = Receiver::with_repair_wait(Duration::from_millis(100));
        let mut plain_receiver = Receiver::default();
        let mut arrivals = Vec::new();
        // Simulate 25,000 originals/s, four records/block, and 60 ms of path
        // delay difference. The 256-block FEC window spans only 40.96 ms.
        // Repairs are absent so FEC recovery cannot hide an original drop.
        let total = 4 * (BLOCK_WINDOW + 44);
        for id in 0..total {
            let record = Record {
                flow: 1,
                id,
                payload: vec![(id % 251) as u8; MAX_PAYLOAD],
            };
            let arrival = Duration::from_micros(id * 40)
                + if id % 2 == 0 {
                    Duration::ZERO
                } else {
                    Duration::from_millis(60)
                };
            arrivals.push((
                arrival,
                id,
                shard(Shard::Data {
                    block: id / 4,
                    index: (id % 4) as u8,
                    payload: record.encode().unwrap(),
                }),
                plain(&record).unwrap(),
            ));
        }
        arrivals.sort_by_key(|(arrival, id, _, _)| (*arrival, *id));
        for (arrival, _, symbol, uncoded) in &arrivals {
            let received = fec.receive(symbol, now + *arrival).unwrap();
            let control = plain_receiver.receive(uncoded, now + *arrival).unwrap();
            assert_eq!(received, control);
            assert!(fec.blocks.len() <= BLOCK_WINDOW as usize);
            assert!(fec.delivered.len() <= MESSAGE_WINDOW as usize);
        }
        assert_eq!(fec.originals, total);
        assert_eq!(fec.original_packets, total);
        assert_eq!(fec.recovered, 0);
        assert_eq!(fec.stale, 0);
        assert!(!fec.blocks.contains_key(&0));
        let old_original = &arrivals.iter().find(|(_, id, _, _)| *id == 1).unwrap().2;
        assert!(
            fec.receive(old_original, now + Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );
        assert_eq!(fec.duplicates, 1);
        assert!(!fec.blocks.contains_key(&0));
    }

    #[test]
    fn expired_decoder_still_delivers_late_original_once() {
        let now = Instant::now();
        let (records, symbols) = coded_block(2);
        let mut receiver = Receiver::with_repair_wait(Duration::from_millis(20));
        assert_eq!(
            receiver.receive(&symbols[0], now).unwrap(),
            vec![records[0].clone()]
        );
        assert!(
            receiver
                .receive(&symbols[2], now + Duration::from_millis(20))
                .unwrap()
                .is_empty()
        );
        assert_eq!(receiver.recovered, 0);
        assert_eq!(receiver.stale, 1);
        assert!(receiver.blocks.get(&0).unwrap().is_none());
        assert_eq!(
            receiver
                .receive(&symbols[1], now + Duration::from_millis(30))
                .unwrap(),
            vec![records[1].clone()]
        );
        assert!(receiver.blocks.get(&0).unwrap().is_none());
        assert!(
            receiver
                .receive(&symbols[1], now + Duration::from_millis(31))
                .unwrap()
                .is_empty()
        );
        assert!(
            receiver
                .receive(&symbols[2], now + Duration::from_millis(32))
                .unwrap()
                .is_empty()
        );
        assert_eq!(receiver.originals, 2);
        assert_eq!(receiver.duplicates, 1);
        assert_eq!(receiver.stale, 2);
        assert!(receiver.blocks.get(&0).unwrap().is_none());
    }

    #[test]
    fn adaptive_retention_learns_late_material_without_reviving_expired_block() {
        let at = Instant::now();
        let mut adaptive = Receiver::configured(Duration::from_millis(1), true);
        let mut fixed = Receiver::with_repair_wait(Duration::from_millis(100));
        let (_, symbols) = coded_block(2);
        for receiver in [&mut adaptive, &mut fixed] {
            assert_eq!(receiver.receive(&symbols[0], at).unwrap().len(), 1);
            assert!(
                receiver
                    .receive(&symbols[2], at + Duration::from_millis(140))
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(receiver.recovered, 0);
        }
        assert_eq!(adaptive.retention_snapshot().unwrap().current_ms, 180);
        // Old tombstone cannot be reopened, even though the global horizon grew.
        assert!(
            adaptive
                .receive(&symbols[2], at + Duration::from_millis(141))
                .unwrap()
                .is_empty()
        );
        let records: Vec<_> = (2..4)
            .map(|id| Record {
                flow: 7,
                id,
                payload: vec![id as u8; 17],
            })
            .collect();
        let mut encoder = Encoder::new(2, Duration::from_secs(1)).unwrap();
        let mut next: Vec<_> = records
            .iter()
            .flat_map(|r| encoder.push(&r.encode().unwrap(), at).unwrap())
            .collect();
        for shard in &mut next {
            match shard {
                Shard::Data { block, .. }
                | Shard::Repair { block, .. }
                | Shard::RepairQ { block, .. } => *block = 1,
            }
        }
        let next: Vec<_> = next.into_iter().map(shard).collect();
        let first = at + Duration::from_millis(150);
        for receiver in [&mut adaptive, &mut fixed] {
            assert_eq!(
                receiver.receive(&next[0], first).unwrap(),
                vec![records[0].clone()]
            );
        }
        assert_eq!(
            adaptive
                .receive(&next[2], first + Duration::from_millis(150))
                .unwrap(),
            vec![records[1].clone()]
        );
        assert!(
            fixed
                .receive(&next[2], first + Duration::from_millis(150))
                .unwrap()
                .is_empty()
        );
        assert_eq!(adaptive.recovered, 1);
        assert_eq!(adaptive.retention_snapshot().unwrap().late_samples, 1);
    }

    #[test]
    fn adaptive_timer_releases_payloads_but_keeps_bounded_learning_metadata() {
        let at = Instant::now();
        let (_, symbols) = coded_block(2);
        let mut r = Receiver::configured(Duration::from_millis(900), true);
        r.receive(&symbols[0], at).unwrap();
        assert_eq!(
            r.next_retention_deadline(),
            Some(at + Duration::from_millis(100))
        );
        r.expire_adaptive(at + Duration::from_millis(100));
        assert_eq!(r.next_retention_deadline(), None);
        let snapshot = r.retention_snapshot().unwrap();
        assert_eq!(
            (
                snapshot.live_blocks,
                snapshot.metadata_blocks,
                snapshot.deadline_retired_blocks
            ),
            (0, 1, 1)
        );
        assert!(
            r.receive(&symbols[2], at + Duration::from_millis(180))
                .unwrap()
                .is_empty()
        );
        assert_eq!(r.retention_snapshot().unwrap().current_ms, 230);
        // Uncoded original delivery remains independent of expired FEC state.
        assert_eq!(
            r.receive(&symbols[1], at + Duration::from_millis(500))
                .unwrap()
                .len(),
            1
        );
        r.close_retention();
        assert_eq!(r.retention_snapshot().unwrap().metadata_blocks, 0);
    }

    #[test]
    fn adaptive_receiver_hard_cap_and_block_window_do_not_grow() {
        let at = Instant::now();
        let mut r = Receiver::configured(Duration::ZERO, true);
        for block in 0..600u64 {
            let record = Record {
                flow: 1,
                id: block,
                payload: vec![1; 32],
            };
            let packet = shard(Shard::Data {
                block,
                index: 0,
                payload: record.encode().unwrap(),
            });
            r.receive(&packet, at + Duration::from_micros(block))
                .unwrap();
            let snapshot = r.retention_snapshot().unwrap();
            assert!(r.blocks.len() <= 256 && snapshot.metadata_blocks <= 256);
            assert!(snapshot.current_ms <= super::super::fec_retention::MAX_MS);
        }
        r.expire_adaptive(at + Duration::from_millis(251));
        assert_eq!(r.retention_snapshot().unwrap().live_blocks, 0);
        assert!(r.retention_snapshot().unwrap().window_evicted_live_blocks > 0);
    }

    #[test]
    fn repair_wait_uses_first_arrival_and_excludes_deadline_boundary() {
        let now = Instant::now();
        let (records, symbols) = coded_block(3);
        let wait = Duration::from_millis(10);
        for (repair_at, expected_recovery) in
            [(wait - Duration::from_nanos(1), true), (wait, false)]
        {
            let mut receiver = Receiver::with_repair_wait(wait);
            receiver.receive(&symbols[0], now).unwrap();
            receiver
                .receive(&symbols[1], now + Duration::from_millis(9))
                .unwrap();
            let delivered = receiver.receive(&symbols[3], now + repair_at).unwrap();
            if expected_recovery {
                assert_eq!(delivered, vec![records[2].clone()]);
                assert_eq!(receiver.recovered, 1);
                assert_eq!(receiver.stale, 0);
            } else {
                assert!(delivered.is_empty());
                assert_eq!(receiver.recovered, 0);
                assert_eq!(receiver.stale, 1);
                assert!(receiver.blocks.get(&0).unwrap().is_none());
            }
        }
    }

    #[test]
    fn expired_repair_first_block_does_not_recover_on_late_original() {
        let now = Instant::now();
        let (records, symbols) = coded_block(2);
        let mut receiver = Receiver::with_repair_wait(Duration::from_millis(10));
        assert!(receiver.receive(&symbols[2], now).unwrap().is_empty());
        assert_eq!(
            receiver
                .receive(&symbols[0], now + Duration::from_millis(10))
                .unwrap(),
            vec![records[0].clone()]
        );
        assert_eq!(receiver.recovered, 0);
        assert_eq!(
            receiver.stale, 0,
            "a delivered original is not a stale drop"
        );
        assert!(receiver.blocks.get(&0).unwrap().is_none());
        assert_eq!(
            receiver
                .receive(&symbols[1], now + Duration::from_millis(11))
                .unwrap(),
            vec![records[1].clone()]
        );
        assert_eq!(receiver.originals, 2);
    }

    #[test]
    fn retired_originals_still_obey_record_window_and_wire_validation() {
        let now = Instant::now();
        let mut receiver = Receiver::default();
        let record = Record {
            flow: 1,
            id: MESSAGE_WINDOW,
            payload: vec![1],
        };
        receiver.receive(&plain(&record).unwrap(), now).unwrap();
        let old = Record { id: 0, ..record };
        let original = shard(Shard::Data {
            block: 0,
            index: 0,
            payload: old.encode().unwrap(),
        });
        assert!(receiver.receive(&original, now).unwrap().is_empty());
        assert_eq!(receiver.duplicates, 1);
        assert_eq!(receiver.originals, 1);
        assert!(
            receiver
                .receive(&original, now + Duration::from_secs(3))
                .unwrap()
                .is_empty()
        );
        assert!(receiver.blocks.get(&0).unwrap().is_none());
        let mut invalid_index = original.to_vec();
        invalid_index[12] = 32;
        assert!(
            receiver
                .receive(&invalid_index, now + Duration::from_secs(3))
                .is_err()
        );
        assert!(
            receiver
                .receive(&frame(0, 0, 0, &[0; 11]), now + Duration::from_secs(3))
                .is_err()
        );
    }

    #[test]
    fn negotiated_stream_bytes_survive_the_record_window_without_duplicate_application_data() {
        use super::super::stream::{self, Frame};
        let at = Instant::now();
        let mut receiver = Receiver::default();
        let advance = Record {
            flow: stream::ack_flow(1),
            id: MESSAGE_WINDOW + 1,
            payload: Frame::Ack(Default::default()).encode(),
        };
        receiver.receive(&plain(&advance).unwrap(), at).unwrap();
        let late = Record {
            flow: stream::data_flow(1),
            id: 0,
            payload: Frame::Data {
                offset: 0,
                fin: false,
                data: b"late".to_vec(),
            }
            .encode(),
        };
        let mut bytes = stream::Receiver::default();
        let mut delivered = Vec::new();
        for _ in 0..2 {
            let records = receiver
                .receive_with_late(
                    &plain(&late).unwrap(),
                    at,
                    |flow| flow == stream::data_flow(1),
                    |_, _, _| {},
                )
                .unwrap();
            assert_eq!(
                records,
                vec![late.clone()],
                "late TCP data belongs to byte-level deduplication"
            );
            for record in records {
                let Frame::Data { offset, fin, data } = Frame::decode(&record.payload).unwrap()
                else {
                    panic!("data")
                };
                delivered.extend(bytes.on_data(offset, fin, data, at).unwrap());
            }
        }
        assert_eq!(delivered, b"late");
        assert_eq!(bytes.duplicates(), 4);
        assert_eq!(receiver.late_stream_records, 2);
        assert_eq!(
            receiver.delivered.len(),
            1,
            "late IDs do not expand record history"
        );
        let udp = Record {
            flow: 1,
            ..late.clone()
        };
        assert!(
            receiver
                .receive(&plain(&udp).unwrap(), at)
                .unwrap()
                .is_empty()
        );
        let mut unnegotiated = Receiver::default();
        unnegotiated.receive(&plain(&advance).unwrap(), at).unwrap();
        assert!(
            unnegotiated
                .receive(&plain(&late).unwrap(), at)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn active_decoder_rejects_conflicting_original_and_duplicate_repairs_count_once() {
        let now = Instant::now();
        let (_, symbols) = coded_block(2);
        let mut receiver = Receiver::default();
        receiver.receive(&symbols[0], now).unwrap();
        let mut conflicting = symbols[0].to_vec();
        *conflicting.last_mut().unwrap() ^= 1;
        assert!(receiver.receive(&conflicting, now).is_err());
        assert!(receiver.blocks.get(&0).unwrap().is_none());
        assert_eq!(receiver.originals, 1);
        let mut receiver = Receiver::default();
        assert!(receiver.receive(&symbols[2], now).unwrap().is_empty());
        assert!(receiver.receive(&symbols[2], now).unwrap().is_empty());
        assert_eq!(receiver.duplicates, 1);
        assert_eq!(receiver.repair_packets, 2);
    }

    #[test]
    fn zero_repair_wait_disables_reconstruction_without_discarding_originals() {
        let now = Instant::now();
        let (records, symbols) = coded_block(2);
        let mut receiver = Receiver::with_repair_wait(Duration::ZERO);
        assert_eq!(
            receiver.receive(&symbols[0], now).unwrap(),
            vec![records[0].clone()]
        );
        assert!(receiver.receive(&symbols[2], now).unwrap().is_empty());
        assert_eq!(receiver.recovered, 0);
        assert!(receiver.blocks.get(&0).unwrap().is_none());
        assert_eq!(
            receiver.receive(&symbols[1], now).unwrap(),
            vec![records[1].clone()]
        );
    }

    #[test]
    fn sender_preflight_lengths_and_record_identity_match_wire_frames() {
        let streams = [
            (0, 2),
            (4, 2),
            (252, 2),
            (256, 3),
            (65_532, 3),
            (65_536, 5),
            ((1u64 << 32) - 4, 5),
            (1u64 << 32, 9),
            ((1u64 << 62) - 4, 9),
        ];
        for (flow, id) in [
            (0, 0),
            (0x0123_4567, 0x89ab_cdef_0123_4567),
            (u32::MAX, u64::MAX),
        ] {
            for payload_len in [0, 1, 128, 1000, MAX_PAYLOAD] {
                let record = Record {
                    flow,
                    id,
                    payload: vec![0xa5; payload_len],
                };
                let encoded = record.encode().unwrap();
                assert_eq!(Record::decode_identity(&encoded).unwrap(), (flow, id));
                assert_eq!(Record::decode(&encoded).unwrap(), record);
                let symbol = plain(&record).unwrap();
                let quality = super::super::quality::State::new(7);
                for (stream, overhead) in streams {
                    assert_eq!(http_datagram_overhead(stream).unwrap(), overhead);
                    for feedback in [false, true] {
                        let payload = if feedback {
                            quality.wrap(&symbol, 1234)
                        } else {
                            symbol.clone()
                        };
                        let predicted = overhead
                            + symbol.len()
                            + if feedback {
                                super::super::quality::HEADER
                            } else {
                                0
                            };
                        let frame = http_datagram(stream, &payload).unwrap();
                        assert_eq!(frame.len(), predicted);
                        assert_eq!(http_payload(&frame, stream).unwrap(), payload.as_ref());
                    }
                }
                assert_eq!(
                    quality.snapshot.sent_symbols, 0,
                    "previews spend no sequence"
                );
            }
        }
        for len in (0..12).chain([13 + MAX_PAYLOAD]) {
            let invalid = vec![0; len];
            assert!(Record::decode_identity(&invalid).is_err());
            assert!(Record::decode(&invalid).is_err());
        }
        for stream in [1, 2, 3, 257, 1u64 << 62, u64::MAX - 3] {
            assert!(http_datagram_overhead(stream).is_err());
            assert!(http_datagram(stream, &[]).is_err());
        }
    }

    #[test]
    fn http_mapping_checks_all_varint_widths() {
        for stream in [0, 4, 252, 256, 65536, 1u64 << 40] {
            let b = http_datagram(stream, b"hello").unwrap();
            assert_eq!(http_payload(&b, stream).unwrap(), b"hello");
            assert!(http_payload(&b, stream + 4).is_err());
            for n in 0..b.len() - 5 {
                assert!(http_payload(&b[..n], stream).is_err());
            }
        }
    }
    #[test]
    fn recovery_retains_delivery_identity_and_suppresses_late_original() {
        let now = Instant::now();
        let mut enc = Encoder::new(4, Duration::from_millis(5)).unwrap();
        let mut shards = Vec::new();
        for id in 0..4 {
            shards.extend(
                enc.push(
                    &Record {
                        flow: 7,
                        id,
                        payload: vec![id as u8; 17],
                    }
                    .encode()
                    .unwrap(),
                    now,
                )
                .unwrap(),
            );
        }
        let mut rx = Receiver::default();
        let mut out = Vec::new();
        for (i, s) in shards.iter().enumerate() {
            if i != 1 {
                out.extend(rx.receive(&shard(s.clone()), now).unwrap());
            }
        }
        assert_eq!(out.len(), 4);
        assert_eq!(rx.recovered, 1);
        assert!(
            rx.receive(&shard(shards[1].clone()), now)
                .unwrap()
                .is_empty()
        );
        assert_eq!(rx.duplicates, 1);
        assert_eq!(rx.original_packets, 4);
        assert!(
            out.iter()
                .all(|r| r.flow == 7 && r.payload == vec![r.id as u8; 17])
        );
    }
    #[test]
    fn expired_blocks_cannot_be_reallocated() {
        let now = Instant::now();
        let mut rx = Receiver::default();
        let record = Record {
            flow: 1,
            id: 1,
            payload: vec![1],
        };
        let one = shard(Shard::Data {
            block: 0,
            index: 0,
            payload: record.encode().unwrap(),
        });
        rx.receive(&one, now).unwrap();
        rx.receive(&one, now + Duration::from_secs(3)).unwrap();
        assert!(rx.blocks.get(&0).unwrap().is_none());
        assert!(
            rx.receive(&one, now + Duration::from_secs(4))
                .unwrap()
                .is_empty()
        );
        assert!(rx.blocks.get(&0).unwrap().is_none());
        for n in 0..HEADER {
            assert!(rx.receive(&one[..n], now).is_err());
        }
    }
}
