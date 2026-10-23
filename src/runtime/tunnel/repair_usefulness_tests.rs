use super::*;
use std::collections::BTreeSet;

fn policy() -> Policy {
    Policy {
        adaptive: false,
        capacity_probe_bps: 0,
        probe_guided_recovery: false,
        latency_target_ms: 100,
        group_rates: [100_000_000; MAX_PATHS],
        receiver_feedback: true,
        quality_schedule: true,
        fec: 16,
        fec_repairs: 2,
        small_fec_bytes: 128,
        mixed_fec: true,
        redundancy: 13,
        rate: 100_000_000,
        block_ms: 8,
        queue_ms: 100,
    }
}

fn fill_flow(queue: &mut outbound::Queue, now: Instant) {
    for id in 0..outbound::PER_FLOW_LIMIT {
        let r = Record {
            flow: 1,
            id: 1_000_000 + id as u64,
            payload: vec![1; 1000],
        };
        queue
            .push(outbound::Pending {
                data: wire::plain(&r).unwrap(),
                created: now,
                record_id: Some(r.id),
                flow: Some(1),
                block: None,
                small: false,
            })
            .unwrap_or_else(|_| panic!("fixture queue full"));
    }
}

fn fixture(enabled: bool, erased: &[u8]) -> (BTreeSet<u64>, u64, u64, u64) {
    let p = policy();
    let now = Instant::now();
    let metrics = stats::Metrics::new_with_repair_guard("client", enabled);
    let scope = metrics.scope("repair-proof", stats::FORWARD);
    let mut encoder = coding::RecordEncoder::new(&p).unwrap();
    let mut queue = outbound::Queue::default();
    let mut blocks = BTreeMap::new();
    let mut receiver =
        Receiver::configured(Duration::from_millis(100), false).with_dual_repairs(true);
    let mut ids = BTreeSet::new();
    for index in 0..16u8 {
        if erased.contains(&index) {
            fill_flow(&mut queue, now);
        }
        let r = Record {
            flow: 1,
            id: u64::from(index),
            payload: vec![index; 1000 - usize::from(index)],
        };
        for symbol in encoder.encode(&r, now).unwrap() {
            enqueue_encoded(symbol, now, &mut queue, &mut blocks, &p, &scope);
        }
        while let Some(original) = queue.pop(false) {
            if original.block.is_some() {
                for r in receiver.receive(&original.data, now).unwrap() {
                    assert!(ids.insert(r.id));
                }
            }
        }
        assert!(queue.len() <= QUEUE);
    }
    let mut repairs = 0;
    while let Some(repair) = queue.pop(true) {
        repairs += 1;
        for r in receiver.receive(&repair.data, now).unwrap() {
            assert!(ids.insert(r.id));
        }
    }
    let snapshot = metrics.snapshot(true, "stopped", None).unwrap();
    assert_eq!(snapshot["repair_usefulness_guard"], enabled);
    let counters = &snapshot["stats"]["directions"][stats::FORWARD]["symbols"];
    let generated = counters["repairs_generated"].as_u64().unwrap();
    let skipped = counters["repairs_locally_unrecoverable_skipped"]
        .as_u64()
        .unwrap();
    assert_eq!(generated, repairs + skipped);
    assert_eq!(counters["originals_queue_full_dropped"], erased.len());
    (ids, repairs, skipped, receiver.recovered)
}

#[test]
fn useful_repairs_survive_zero_one_and_two_permanent_rejections() {
    for erased in [vec![], vec![3], vec![3, 12]] {
        let off = fixture(false, &erased);
        let on = fixture(true, &erased);
        assert_eq!(off, on);
        assert_eq!(on.0, (0..16).collect());
        assert_eq!(on.1, 2);
        assert_eq!(on.3, erased.len() as u64);
    }
}

#[test]
fn three_or_more_permanent_rejections_skip_only_repairs_and_keep_identical_delivery() {
    for erased in [vec![0, 1, 2], vec![0, 7, 15], (0..16).collect()] {
        let off = fixture(false, &erased);
        let on = fixture(true, &erased);
        assert_eq!(on.0, off.0);
        assert_eq!(on.0.len(), 16 - erased.len());
        assert_eq!((off.1, off.2, off.3), (2, 0, 0));
        assert_eq!((on.1, on.2, on.3), (0, 2, 0));
    }
}

#[test]
fn pending_originals_are_not_erasures_and_deadlines_never_change() {
    let p = policy();
    let now = Instant::now();
    let metrics = stats::Metrics::new_with_repair_guard("client", true);
    let scope = metrics.scope("pending", stats::FORWARD);
    let mut encoder = coding::RecordEncoder::new(&p).unwrap();
    let mut q = outbound::Queue::default();
    let mut blocks = BTreeMap::new();
    for id in 0..16 {
        let r = Record {
            flow: 1,
            id,
            payload: vec![7; 1000],
        };
        for s in encoder.encode(&r, now).unwrap() {
            enqueue_encoded(s, now, &mut q, &mut blocks, &p, &scope);
        }
    }
    assert_eq!(q.len(), 18);
    assert!(q.block_pending(0));
    assert_eq!(q.front(true).unwrap().created, now);
    assert_eq!(blocks[&0].locally_rejected_originals, 0);
    assert!(!q.promote_ready_repair(|_| true));
    assert_eq!(
        q.expire(now + p.admission_lifetime(), p.admission_lifetime())
            .len(),
        18
    );
    assert!(q.is_empty());
}

#[test]
fn missing_metadata_short_blocks_invalid_headers_and_small_lane_keep_repairs() {
    let p = policy();
    let now = Instant::now();
    let meta = BlockSend {
        created: now,
        paths: 0,
        locally_rejected_originals: 0b111,
        small_repair_limit: 0,
        small_repair_reserved: 0,
    };
    let mut data = vec![0u8; wire::HEADER];
    data[3] = 1;
    data[12] = 16;
    assert!(repair_locally_unrecoverable(
        Some(&p),
        &data,
        false,
        Some(&meta)
    ));
    assert!(!repair_locally_unrecoverable(
        Some(&p),
        &data,
        true,
        Some(&meta)
    ));
    assert!(!repair_locally_unrecoverable(Some(&p), &data, false, None));
    assert!(!repair_locally_unrecoverable(
        None,
        &data,
        false,
        Some(&meta)
    ));
    for count in [0, 1, 2, 33, 255] {
        data[12] = count;
        assert!(!repair_locally_unrecoverable(
            Some(&p),
            &data,
            false,
            Some(&meta)
        ));
    }
    data[12] = 32;
    assert!(repair_locally_unrecoverable(
        Some(&p),
        &data,
        false,
        Some(&meta)
    ));
    for kind in [0, 2, 255] {
        data[3] = kind;
        assert!(!repair_locally_unrecoverable(
            Some(&p),
            &data,
            false,
            Some(&meta)
        ));
    }
    assert!(!repair_locally_unrecoverable(
        Some(&p),
        &[],
        false,
        Some(&meta)
    ));
}

#[test]
fn block_bitmap_fits_existing_64bit_metadata_layout_and_adds_no_queue_slots() {
    #[allow(dead_code)]
    struct LegacyBlockSend {
        created: Instant,
        paths: u8,
        small_repair_limit: usize,
        small_repair_reserved: usize,
    }
    if std::mem::size_of::<usize>() == 8 {
        assert_eq!(
            std::mem::size_of::<BlockSend>(),
            std::mem::size_of::<LegacyBlockSend>()
        );
    }
    assert_eq!(QUEUE, 256);
    assert_eq!(outbound::PER_FLOW_LIMIT, 64);
    assert_eq!(outbound::REPAIR_LIMIT, 64);
}

#[test]
fn repeated_rejection_of_one_index_does_not_fake_three_missing_originals() {
    let p = policy();
    let now = Instant::now();
    let metrics = stats::Metrics::new_with_repair_guard("client", true);
    let scope = metrics.scope("duplicate-bit", stats::FORWARD);
    let mut q = outbound::Queue::default();
    let mut blocks = BTreeMap::new();
    fill_flow(&mut q, now);
    let r = Record {
        flow: 1,
        id: 4,
        payload: vec![4; 1000],
    };
    let data = wire::shard(crate::fec::Shard::Data {
        block: 0,
        index: 4,
        payload: r.encode().unwrap(),
    });
    for _ in 0..10 {
        enqueue_encoded(
            coding::EncodedSymbol {
                data: data.clone(),
                small: false,
                oldest_ingress: None,
            },
            now,
            &mut q,
            &mut blocks,
            &p,
            &scope,
        );
    }
    assert_eq!(blocks[&0].locally_rejected_originals.count_ones(), 1);
    let mut parity = vec![0; wire::HEADER];
    parity[3] = 3;
    parity[12] = 16;
    assert!(!repair_locally_unrecoverable(
        Some(&p),
        &parity,
        false,
        blocks.get(&0)
    ));
}

#[test]
fn unrelated_bulk_rejection_cannot_remove_small_copy_or_spend_its_credit() {
    let p = policy();
    let now = Instant::now();
    let metrics = stats::Metrics::new_with_repair_guard("client", true);
    let scope = metrics.scope("small-copy", stats::FORWARD);
    let mut q = outbound::Queue::default();
    let mut blocks = BTreeMap::new();
    fill_flow(&mut q, now);
    let mut encoder = coding::RecordEncoder::new(&p).unwrap();
    for id in 0..16 {
        let r = Record {
            flow: 1,
            id,
            payload: vec![7; 1000],
        };
        for s in encoder.encode(&r, now).unwrap() {
            enqueue_encoded(s, now, &mut q, &mut blocks, &p, &scope);
        }
    }
    assert!(q.front(true).is_none());
    let small = Record {
        flow: 2,
        id: 16,
        payload: vec![8; 128],
    };
    for s in encoder.encode(&small, now).unwrap() {
        enqueue_encoded(s, now, &mut q, &mut blocks, &p, &scope);
    }
    assert_eq!(q.len(), outbound::PER_FLOW_LIMIT + 2);
    let repair = q.front(true).unwrap();
    assert!(repair.small);
    assert_eq!(blocks[&repair.block.unwrap()].locally_rejected_originals, 0);
    let budget = outbound::RepairBudget::new(13);
    assert!(!repair_allowed(
        &p,
        &budget,
        &blocks,
        repair,
        repair_frame_floor(&p, repair)
    ));
    assert!(!budget.can_repair(1), "pruning created no repair credit");
}
