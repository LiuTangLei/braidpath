//! Independent coding lanes with one dense block-id space.
//!
//! Existing single-mode sessions use the original encoder path unchanged.
//! Mixed sessions keep short records out of bulk XOR blocks. Lane-local codec
//! block identifiers are remapped only at first-original generation, so an open
//! bulk block and immediate small blocks remain distinct without separating
//! their receiver-window namespaces.
#[cfg(test)]
use super::encode_record;
use super::{Policy, Record, wire};
use crate::fec::{DualEncoder, Encoder, Shard};
use anyhow::{Result, ensure};
use bytes::Bytes;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub(super) struct EncodedSymbol {
    pub data: Bytes,
    pub small: bool,
}

struct Lane {
    encoder: LaneEncoder,
    active: Option<(u64, u64)>,
}

enum LaneEncoder {
    Single(Encoder),
    Dual(DualEncoder),
}

impl Lane {
    fn new(k: u8, age: Duration, repairs: u8) -> Result<Self> {
        Ok(Self {
            encoder: if repairs == 2 {
                LaneEncoder::Dual(DualEncoder::new(k, age)?)
            } else {
                LaneEncoder::Single(Encoder::new(k, age)?)
            },
            active: None,
        })
    }

    fn remap(
        &mut self,
        shards: Vec<Shard>,
        next_block: &mut u64,
        small: bool,
    ) -> Result<Vec<EncodedSymbol>> {
        let mut out = Vec::with_capacity(shards.len());
        let mut shards = shards.into_iter().peekable();
        while let Some(mut shard) = shards.next() {
            let local = shard.block();
            let original = matches!(shard, Shard::Data { .. });
            let global = if let Some((active, global)) = self.active {
                ensure!(active == local, "mixed encoder changed an unfinished block");
                global
            } else {
                ensure!(original, "mixed repair has no original block mapping");
                // Match the legacy codec's exhaustion boundary; never wrap or
                // give two live lanes the same receiver block identifier.
                ensure!(*next_block != u64::MAX, "mixed block id exhausted");
                let global = *next_block;
                *next_block += 1;
                self.active = Some((local, global));
                global
            };
            match &mut shard {
                Shard::Data { block, .. }
                | Shard::Repair { block, .. }
                | Shard::RepairQ { block, .. } => *block = global,
            }
            if !original && shards.peek().is_none_or(|next| next.block() != local) {
                self.active = None;
            }
            out.push(EncodedSymbol {
                data: wire::shard(shard),
                small,
            });
        }
        Ok(out)
    }

    fn push(
        &mut self,
        bytes: &[u8],
        now: Instant,
        next_block: &mut u64,
        small: bool,
    ) -> Result<Vec<EncodedSymbol>> {
        let shards = match &mut self.encoder {
            LaneEncoder::Single(e) => e.push(bytes, now)?,
            LaneEncoder::Dual(e) => e.push(bytes, now)?,
        };
        self.remap(shards, next_block, small)
    }

    fn flush_due(
        &mut self,
        now: Instant,
        next_block: &mut u64,
        small: bool,
    ) -> Result<Vec<EncodedSymbol>> {
        let shards = match &mut self.encoder {
            LaneEncoder::Single(e) => e.flush_due(now).into_iter().collect(),
            LaneEncoder::Dual(e) => e.flush_due(now),
        };
        self.remap(shards, next_block, small)
    }
}

enum Mode {
    Automatic {
        lane: Lane,
        small: Lane,
        small_repairs: u8,
        k: u8,
        age: Duration,
        next_block: u64,
    },
    Legacy {
        encoder: Encoder,
        policy: Policy,
    },
    Mixed {
        bulk: Lane,
        small: Lane,
        cutoff: usize,
        next_block: u64,
    },
}

pub(super) struct RecordEncoder {
    mode: Mode,
}

impl RecordEncoder {
    pub(super) fn new(policy: &Policy) -> Result<Self> {
        policy.validate()?;
        let age = Duration::from_millis(policy.block_ms);
        let mode = if policy.fec == super::super::automatic_fec::AUTO {
            Mode::Automatic {
                lane: Lane::new(1, age, 1)?,
                small: Lane::new(1, age, 1)?,
                small_repairs: 1,
                k: 0,
                age,
                next_block: 0,
            }
        } else if policy.mixed_fec {
            Mode::Mixed {
                bulk: Lane::new(policy.fec, age, policy.fec_repairs)?,
                small: Lane::new(1, age, 1)?,
                cutoff: usize::from(policy.small_fec_bytes),
                next_block: 0,
            }
        } else {
            Mode::Legacy {
                encoder: Encoder::new(policy.fec.max(1), age)?,
                policy: policy.clone(),
            }
        };
        Ok(Self { mode })
    }

    pub(super) fn encode(&mut self, record: &Record, now: Instant) -> Result<Vec<EncodedSymbol>> {
        match &mut self.mode {
            Mode::Automatic {
                lane,
                small,
                small_repairs,
                k,
                next_block,
                ..
            } => {
                // Stream ACKs are control even when selective ranges exceed a
                // size cutoff. Short records get independent immediate blocks.
                let control = record.payload.len() <= 128
                    || record.flow
                        & (super::super::stream::STREAM_FLAG | super::super::stream::ACK_FLAG)
                        == (super::super::stream::STREAM_FLAG | super::super::stream::ACK_FLAG);
                if control {
                    let mut out = small.push(&record.encode()?, now, next_block, true)?;
                    for _ in 1..*small_repairs {
                        out.push(out.last().expect("k=1 repair").clone());
                    }
                    Ok(out)
                } else if *k == 0 {
                    Ok(vec![EncodedSymbol {
                        data: wire::plain(record)?,
                        small: false,
                    }])
                } else {
                    lane.push(&record.encode()?, now, next_block, false)
                }
            }
            Mode::Legacy { encoder, policy } => {
                // Keep the legacy branch and one output collection. Wrapping a
                // Vec<Bytes> afterwards would add an allocation to every record.
                if policy.fec == 0
                    && (policy.small_fec_bytes == 0
                        || record.payload.len() > usize::from(policy.small_fec_bytes))
                {
                    Ok(vec![EncodedSymbol {
                        data: wire::plain(record)?,
                        small: false,
                    }])
                } else {
                    Ok(encoder
                        .push(&record.encode()?, now)?
                        .into_iter()
                        .map(|shard| EncodedSymbol {
                            data: wire::shard(shard),
                            small: policy.small_fec_bytes > 0,
                        })
                        .collect())
                }
            }
            Mode::Mixed {
                bulk,
                small,
                cutoff,
                next_block,
            } => {
                let bytes = record.encode()?;
                // Small arrivals cannot postpone a due bulk repair. The sender
                // also drives this same flush from its existing bounded timer.
                let mut out = bulk.flush_due(now, next_block, false)?;
                if record.payload.len() <= *cutoff {
                    out.extend(small.push(&bytes, now, next_block, true)?);
                } else {
                    out.extend(bulk.push(&bytes, now, next_block, false)?);
                }
                Ok(out)
            }
        }
    }

    pub(super) fn flush_due(&mut self, now: Instant) -> Result<Vec<EncodedSymbol>> {
        match &mut self.mode {
            Mode::Automatic {
                lane, next_block, ..
            } => lane.flush_due(now, next_block, false),
            Mode::Legacy { encoder, policy } => Ok(encoder
                .flush_due(now)
                .map(|shard| EncodedSymbol {
                    data: wire::shard(shard),
                    small: policy.small_fec_bytes > 0,
                })
                .into_iter()
                .collect()),
            Mode::Mixed {
                bulk,
                small,
                next_block,
                ..
            } => {
                let mut out = bulk.flush_due(now, next_block, false)?;
                out.extend(small.flush_due(now, next_block, true)?);
                Ok(out)
            }
        }
    }

    /// Finish the old block before replacing its codec. Global block IDs keep
    /// increasing across plain intervals and changes of k; in-flight repairs
    /// retain their original count and cannot collide with later blocks.
    pub(super) fn set_fec(&mut self, next: u8) -> Result<Vec<EncodedSymbol>> {
        let Mode::Automatic {
            lane,
            k,
            age,
            next_block,
            small_repairs,
            ..
        } = &mut self.mode
        else {
            anyhow::bail!("fixed FEC encoder cannot change strength");
        };
        ensure!(
            [0, 4, 8, 16, 32].contains(&next),
            "invalid automatic FEC strength"
        );
        *small_repairs = match next {
            4 => 3,
            8 => 2,
            _ => 1,
        };
        if next == *k {
            return Ok(Vec::new());
        }
        let LaneEncoder::Single(encoder) = &mut lane.encoder else {
            unreachable!()
        };
        let shards = encoder.flush().into_iter().collect();
        let out = lane.remap(shards, next_block, false)?;
        *lane = Lane::new(next.max(1), *age, 1)?;
        *k = next;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        budget_admitted, enqueue_encoded, mixed_fec_header, outbound, repair_allowed,
        small_delivery, stats,
    };
    use super::*;
    use crate::runtime::{MAX_PATHS, wire::Receiver};
    use std::collections::BTreeMap;

    fn policy(fec: u8, cutoff: u16, mixed: bool) -> Policy {
        Policy {
            streams: false,
            proxy: false,
            fec_repairs: 1,
            adaptive: false,
            capacity_probe_bps: 0,
            probe_guided_recovery: false,
            latency_target_ms: 100,
            group_rates: [8_000_000; MAX_PATHS],
            receiver_feedback: false,
            quality_schedule: false,
            fec,
            small_fec_bytes: cutoff,
            mixed_fec: mixed,
            redundancy: if cutoff > 0 && !mixed { 0 } else { 50 },
            rate: 8_000_000,
            block_ms: 10,
            queue_ms: 100,
        }
    }

    fn record(id: u64, bytes: usize) -> Record {
        Record {
            flow: if bytes <= 128 { 1 } else { 2 },
            id,
            payload: vec![id as u8; bytes],
        }
    }

    #[test]
    fn automatic_switches_preserve_partial_blocks_and_delayed_repairs() {
        let mut p = policy(super::super::super::automatic_fec::AUTO, 0, false);
        p.receiver_feedback = true;
        let now = Instant::now();
        let mut encoder = RecordEncoder::new(&p).unwrap();
        let mut symbols = Vec::new();
        let mut id = 0;
        for k in [4, 0, 32, 16, 8, 4, 0] {
            symbols.extend(encoder.set_fec(k).unwrap());
            // Both a complete and an unfinished block before the next switch.
            for _ in 0..k.max(1) + 1 {
                id += 1;
                symbols.extend(encoder.encode(&record(id, 1000), now).unwrap());
            }
        }
        let mut receiver = Receiver::with_repair_wait(Duration::from_millis(100));
        let mut delivered = Vec::new();
        let mut delayed = Vec::new();
        let mut repair_ids = std::collections::BTreeSet::new();
        // Reorder repairs ahead of originals, and lose one original per coded
        // block, including the partial blocks closed during a mode change.
        for symbol in symbols.iter().rev() {
            if symbol.data[3] == 0 && symbol.data[12] == 0 {
                delayed.push(symbol);
                continue;
            }
            if symbol.data[3] == 1 {
                assert!(repair_ids.insert(block(symbol)));
            }
            delivered.extend(receiver.receive(&symbol.data, now).unwrap());
        }
        let mut ids: Vec<_> = delivered.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, (1..=id).collect::<Vec<_>>());
        assert_eq!(receiver.recovered as usize, delayed.len());
        assert_eq!(
            repair_ids.into_iter().collect::<Vec<_>>(),
            (0..10).collect::<Vec<_>>()
        );
        for symbol in delayed {
            assert!(receiver.receive(&symbol.data, now).unwrap().is_empty());
        }
    }

    #[test]
    fn automatic_policy_requires_loss_feedback_and_rejects_fixed_lane_options() {
        let mut p = policy(super::super::super::automatic_fec::AUTO, 0, false);
        assert!(p.validate().is_err());
        p.receiver_feedback = true;
        assert!(p.validate().is_ok());
        let mut invalid = p.clone();
        invalid.redundancy = 0;
        assert!(invalid.validate().is_err());
        let mut invalid = p.clone();
        invalid.small_fec_bytes = 128;
        assert!(invalid.validate().is_err());
        let mut invalid = p.clone();
        invalid.mixed_fec = true;
        assert!(invalid.validate().is_err());
        p.fec_repairs = 2;
        assert!(p.validate().is_err());
    }

    #[test]
    fn automatic_small_lane_covers_large_acks_and_keeps_bulk_plain_when_clean() {
        let mut p = policy(super::super::super::automatic_fec::AUTO, 0, false);
        p.receiver_feedback = true;
        let now = Instant::now();
        let mut e = RecordEncoder::new(&p).unwrap();
        let bulk = e.encode(&record(1, 1000), now).unwrap();
        assert_eq!(bulk[0].data[3], 2);
        assert!(!bulk[0].small);
        let short = e.encode(&record(2, 64), now).unwrap();
        assert_eq!(short.len(), 2);
        assert!(short.iter().all(|s| s.small));
        e.set_fec(4).unwrap();
        let ack = Record {
            flow: super::super::super::stream::ack_flow(3),
            id: 3,
            payload: vec![0; 538],
        };
        let protected = e.encode(&ack, now).unwrap();
        assert_eq!(protected.len(), 4);
        assert!(
            protected
                .iter()
                .all(|s| s.small && block(s) != block(&short[0]))
        );
        let mut receiver = Receiver::with_repair_wait(Duration::from_millis(100));
        // All three repair copies describe the same k=1 block. Any one works;
        // the others and the delayed original remain harmless duplicates.
        assert_eq!(receiver.receive(&protected[1].data, now).unwrap()[0].id, 3);
        for s in [&protected[2], &protected[3], &protected[0]] {
            assert!(receiver.receive(&s.data, now).unwrap().is_empty());
        }
    }

    #[test]
    fn automatic_small_credit_is_per_admitted_original_and_limits_copy_count() {
        let mut p = policy(super::super::super::automatic_fec::AUTO, 0, false);
        p.receiver_feedback = true;
        let now = Instant::now();
        let mut e = RecordEncoder::new(&p).unwrap();
        e.set_fec(4).unwrap();
        let mut queue = outbound::Queue::default();
        let mut blocks = BTreeMap::new();
        let metrics = stats::Metrics::new("client").scope("auto-budget", stats::FORWARD);
        let mut budget = outbound::RepairBudget::new(30);
        budget.enable_small_rate(1_000_000);
        budget.refill_small(1_000_000);
        for s in e.encode(&record(1, 64), now).unwrap() {
            enqueue_encoded(s, now, &mut queue, &mut blocks, &p, &metrics);
        }
        let copy = queue.front(true).unwrap().clone();
        assert!(!repair_allowed(
            &p,
            &budget,
            &blocks,
            &copy,
            copy.data.len() + 30
        ));
        let original = queue.pop(false).unwrap();
        budget_admitted(
            &p,
            &mut budget,
            &mut blocks,
            &original,
            original.data.len() + 30,
            &metrics,
        );
        blocks.get_mut(&original.block.unwrap()).unwrap().paths = 1;
        for _ in 0..3 {
            let copy = queue.pop(true).unwrap();
            assert!(small_delivery::applies(&p, &copy));
            assert!(repair_allowed(
                &p,
                &budget,
                &blocks,
                &copy,
                copy.data.len() + 30
            ));
            budget_admitted(
                &p,
                &mut budget,
                &mut blocks,
                &copy,
                copy.data.len() + 30,
                &metrics,
            );
        }
        assert!(!repair_allowed(
            &p,
            &budget,
            &blocks,
            &copy,
            copy.data.len() + 30
        ));
        assert!(
            !budget.can_repair(1),
            "small originals never fund bulk repair"
        );
    }

    fn block(symbol: &EncodedSymbol) -> u64 {
        u64::from_be_bytes(symbol.data[4..12].try_into().unwrap())
    }

    #[test]
    fn legacy_modes_preserve_exact_encoded_bytes_and_flush() {
        let start = Instant::now();
        for p in [
            policy(0, 0, false),
            policy(0, 128, false),
            policy(4, 0, false),
        ] {
            let mut old = Encoder::new(p.fec.max(1), Duration::from_millis(p.block_ms)).unwrap();
            let mut new = RecordEncoder::new(&p).unwrap();
            for (offset, item) in [
                (0, record(1, 128)),
                (1, record(2, 1000)),
                (2, record(3, 64)),
                (20, record(4, 1000)),
            ] {
                let now = start + Duration::from_millis(offset);
                let expected = encode_record(&item, &mut old, &p, now).unwrap();
                let actual: Vec<_> = new
                    .encode(&item, now)
                    .unwrap()
                    .into_iter()
                    .map(|s| s.data)
                    .collect();
                assert_eq!(actual, expected);
            }
            let now = start + Duration::from_millis(40);
            let expected: Vec<_> = old.flush_due(now).map(wire::shard).into_iter().collect();
            let actual: Vec<_> = new
                .flush_due(now)
                .unwrap()
                .into_iter()
                .map(|s| s.data)
                .collect();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn mixed_lanes_keep_small_immediate_and_bulk_blocks_independent() {
        let p = policy(3, 128, true);
        let start = Instant::now();
        let mut encoder = RecordEncoder::new(&p).unwrap();
        let first = encoder.encode(&record(1, 1000), start).unwrap();
        assert_eq!(first.len(), 1);
        assert!(!first[0].small);
        assert_eq!(block(&first[0]), 0);
        let short = encoder
            .encode(&record(2, 128), start + Duration::from_millis(1))
            .unwrap();
        assert_eq!(short.len(), 2);
        assert!(short.iter().all(|s| s.small && block(s) == 1));
        assert_eq!(short[0].data[3], 0);
        assert_eq!(short[1].data[3], 1);
        let second = encoder
            .encode(&record(3, 1000), start + Duration::from_millis(2))
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(block(&second[0]), 0);
        let third = encoder
            .encode(&record(4, 1000), start + Duration::from_millis(3))
            .unwrap();
        assert_eq!(third.len(), 2);
        assert!(third.iter().all(|s| !s.small && block(s) == 0));
        assert_eq!(third[1].data[12], 3);
        let next = encoder
            .encode(&record(5, 64), start + Duration::from_millis(4))
            .unwrap();
        assert!(next.iter().all(|s| s.small && block(s) == 2));
    }

    #[test]
    fn mixed_partial_bulk_flush_keeps_its_count_and_deadline() {
        let p = policy(4, 128, true);
        let start = Instant::now();
        let mut encoder = RecordEncoder::new(&p).unwrap();
        encoder.encode(&record(1, 1000), start).unwrap();
        encoder
            .encode(&record(2, 1000), start + Duration::from_millis(2))
            .unwrap();
        assert!(
            encoder
                .flush_due(start + Duration::from_millis(9))
                .unwrap()
                .is_empty()
        );
        let due = encoder
            .encode(&record(3, 128), start + Duration::from_millis(10))
            .unwrap();
        assert_eq!(due.len(), 3);
        assert!(!due[0].small);
        assert_eq!(block(&due[0]), 0);
        assert_eq!(due[0].data[3], 1);
        assert_eq!(due[0].data[12], 2);
        assert!(due[1..].iter().all(|s| s.small && block(s) == 1));
        assert!(
            encoder
                .flush_due(start + Duration::from_millis(20))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn mixed_interleaved_blocks_recover_through_the_real_receiver() {
        let p = policy(3, 128, true);
        let start = Instant::now();
        let mut encoder = RecordEncoder::new(&p).unwrap();
        let mut symbols = Vec::new();
        for item in [
            record(1, 1000),
            record(2, 128),
            record(3, 1000),
            record(4, 1000),
        ] {
            symbols.extend(encoder.encode(&item, start).unwrap());
        }
        let mut receiver = Receiver::with_repair_wait(Duration::from_millis(100));
        let mut delivered = Vec::new();
        for symbol in symbols {
            // Lose the first bulk original and the small original. Their two
            // independent repairs must reconstruct the original business IDs.
            if symbol.data[3] == 0
                && ((block(&symbol) == 0 && symbol.data[12] == 0) || symbol.small)
            {
                continue;
            }
            delivered.extend(receiver.receive(&symbol.data, start).unwrap());
        }
        let mut ids: Vec<_> = delivered.into_iter().map(|r| r.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, [1, 2, 3, 4]);
        assert_eq!(receiver.recovered, 2);
    }

    #[test]
    fn mixed_global_block_exhaustion_never_wraps_or_reuses_an_id() {
        let p = policy(4, 128, true);
        let mut encoder = RecordEncoder::new(&p).unwrap();
        let Mode::Mixed { next_block, .. } = &mut encoder.mode else {
            unreachable!()
        };
        *next_block = u64::MAX - 1;
        let first = encoder.encode(&record(1, 128), Instant::now()).unwrap();
        assert!(first.iter().all(|s| block(s) == u64::MAX - 1));
        assert!(encoder.encode(&record(2, 128), Instant::now()).is_err());
    }

    #[test]
    fn mixed_policy_requires_explicit_complete_budget_and_version() {
        let mut p = policy(4, 128, true);
        assert!(p.validate().is_ok());
        p.mixed_fec = false;
        assert!(p.validate().is_err());
        p.mixed_fec = true;
        p.redundancy = 0;
        assert!(p.validate().is_err());
        p.redundancy = 30;
        p.fec = 0;
        assert!(p.validate().is_err());
        p.fec = 4;
        p.small_fec_bytes = 0;
        assert!(p.validate().is_err());
        let mut headers = http::HeaderMap::new();
        assert!(!mixed_fec_header(&headers).unwrap());
        headers.insert("braidpath-mixed-fec", http::HeaderValue::from_static("1"));
        assert!(mixed_fec_header(&headers).unwrap());
        for value in ["0", "2", "true"] {
            headers.insert(
                "braidpath-mixed-fec",
                http::HeaderValue::from_str(value).unwrap(),
            );
            assert!(mixed_fec_header(&headers).is_err());
        }
    }

    #[test]
    fn mixed_budget_separates_lanes_and_bypasses_unfunded_bulk_repair() {
        let mut p = policy(1, 128, true);
        p.redundancy = 25;
        let now = Instant::now();
        let mut encoder = RecordEncoder::new(&p).unwrap();
        let mut queue = outbound::Queue::default();
        let mut blocks = BTreeMap::new();
        let metrics = stats::Metrics::new("client").scope("mixed-budget", stats::FORWARD);
        let mut budget = outbound::RepairBudget::new(p.redundancy);
        for item in [record(1, 1000), record(2, 128)] {
            for symbol in encoder.encode(&item, now).unwrap() {
                enqueue_encoded(symbol, now, &mut queue, &mut blocks, &p, &metrics);
            }
        }
        assert!(!queue.front(true).unwrap().small, "bulk was enqueued first");
        let mut admitted_bulk_bytes = 0;
        for expected_id in [1, 2] {
            let original = queue.pop(false).unwrap();
            assert_eq!(original.record_id, Some(expected_id));
            let bytes = wire::http_datagram(0, &original.data).unwrap().len();
            if !original.small {
                admitted_bulk_bytes += bytes;
            }
            budget_admitted(&p, &mut budget, &mut blocks, &original, bytes, &metrics);
            blocks.get_mut(&original.block.unwrap()).unwrap().paths |= 1;
            assert_eq!(small_delivery::applies(&p, &original), original.small);
        }
        let bulk = queue.front(true).unwrap().clone();
        assert!(!repair_allowed(
            &p,
            &budget,
            &blocks,
            &bulk,
            bulk.data.len() + 2
        ));
        assert!(queue.promote_ready_repair(|pending| {
            repair_allowed(&p, &budget, &blocks, pending, pending.data.len() + 2)
        }));
        let small = queue.pop(true).unwrap();
        assert!(small.small);
        let widest_frame = wire::http_datagram(1_u64 << 40, &small.data).unwrap();
        let reserved = blocks[&small.block.unwrap()].small_repair_reserved;
        assert_eq!(reserved, widest_frame.len());
        assert!(repair_allowed(&p, &budget, &blocks, &small, reserved));
        assert!(!repair_allowed(&p, &budget, &blocks, &small, reserved + 1));
        budget_admitted(&p, &mut budget, &mut blocks, &small, reserved, &metrics);
        assert!(!repair_allowed(&p, &budget, &blocks, &small, reserved));
        assert!(
            !budget.can_repair(bulk.data.len() + 2),
            "small admission lends no bulk credit"
        );
        assert_eq!(queue.front(true).unwrap().block, bulk.block);
        assert!(queue.front(false).is_none());
        let mut symbols = None;
        metrics.metrics.state(|state| {
            symbols = Some(
                state.sessions[&metrics.session][stats::FORWARD]
                    .symbols
                    .clone(),
            );
        });
        let symbols = symbols.unwrap();
        assert_eq!(symbols.mixed_small_repair_reserved_bytes, reserved as u64);
        assert_eq!(symbols.mixed_small_repair_admitted_bytes, reserved as u64);
        assert_eq!(symbols.mixed_small_repairs_quinn_admitted, 1);
        assert_eq!(
            symbols.mixed_bulk_original_admitted_bytes,
            admitted_bulk_bytes as u64
        );
        assert_eq!(symbols.mixed_bulk_repair_admitted_bytes, 0);
    }

    #[test]
    fn mixed_partial_repair_expiration_uses_oldest_ingress_and_rejects_orphan_copy() {
        let p = policy(4, 128, true);
        let start = Instant::now();
        let mut encoder = RecordEncoder::new(&p).unwrap();
        let mut queue = outbound::Queue::default();
        let mut blocks = BTreeMap::new();
        let metrics = stats::Metrics::new("client").scope("mixed-age", stats::FORWARD);
        let budget = outbound::RepairBudget::new(100);
        for (id, bytes, offset) in [(1, 1000, 0), (2, 1000, 2), (3, 128, 10)] {
            let created = start + Duration::from_millis(offset);
            for symbol in encoder.encode(&record(id, bytes), created).unwrap() {
                enqueue_encoded(symbol, created, &mut queue, &mut blocks, &p, &metrics);
            }
        }
        let expired = queue.expire(start + Duration::from_millis(20), Duration::from_millis(20));
        assert_eq!(expired.len(), 2);
        assert!(expired.iter().any(|p| p.record_id == Some(1)));
        let repair = expired.iter().find(|p| p.record_id.is_none()).unwrap();
        assert!(!repair.small);
        assert_eq!(repair.created, start);
        let copy = queue.front(true).unwrap();
        assert!(copy.small);
        assert_eq!(copy.created, start + Duration::from_millis(10));
        assert!(!repair_allowed(
            &p,
            &budget,
            &blocks,
            copy,
            copy.data.len() + 2
        ));
    }
}
