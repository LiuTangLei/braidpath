use super::*;
use std::collections::BTreeSet;

fn dual_policy() -> Policy {
    Policy {
        streams: false,
        adaptive: false,
        capacity_probe_bps: 0,
        probe_guided_recovery: false,
        latency_target_ms: 100,
        group_rates: [200_000_000; MAX_PATHS],
        receiver_feedback: true,
        quality_schedule: true,
        fec: 16,
        fec_repairs: 2,
        small_fec_bytes: 128,
        mixed_fec: true,
        redundancy: 13,
        rate: 200_000_000,
        block_ms: 8,
        queue_ms: 100,
    }
}

#[test]
fn negotiated_repair_count_rejects_missing_unknown_or_duplicate_echoes() {
    let mut h = http::HeaderMap::new();
    assert_eq!(fec_repairs_header(&h).unwrap(), 1);
    assert!(validate_fec_repairs_echo(&h, 1).is_ok());
    assert!(validate_fec_repairs_echo(&h, 2).is_err());
    h.insert("braidpath-fec-repairs", "2".parse().unwrap());
    assert!(validate_fec_repairs_echo(&h, 2).is_ok());
    assert!(validate_fec_repairs_echo(&h, 1).is_err());
    h.append("braidpath-fec-repairs", "2".parse().unwrap());
    assert!(fec_repairs_header(&h).is_err());
    for invalid in ["", "1", "02", "3", "2,2"] {
        h.clear();
        h.insert("braidpath-fec-repairs", invalid.parse().unwrap());
        assert!(fec_repairs_header(&h).is_err());
    }
    let mut p = dual_policy();
    assert!(p.validate().is_ok());
    p.mixed_fec = false;
    assert!(p.validate().is_err());
    p.mixed_fec = true;
    p.fec = 1;
    assert!(p.validate().is_err());
    p.fec = 16;
    p.fec_repairs = 3;
    assert!(p.validate().is_err());
}

#[test]
fn mixed_small_lane_is_immediate_while_both_bulk_parities_share_the_correct_block() {
    let p = dual_policy();
    let now = Instant::now();
    let mut encoder = coding::RecordEncoder::new(&p).unwrap();
    let mut all = Vec::new();
    let small = Record {
        flow: 2,
        id: 8,
        payload: vec![88; 128],
    };
    for i in 0..16 {
        if i == 8 {
            let symbols = encoder.encode(&small, now).unwrap();
            assert_eq!(symbols.len(), 2);
            assert!(symbols.iter().all(|s| s.small));
            assert_eq!((symbols[0].data[3], symbols[1].data[3]), (0, 1));
            all.extend(symbols);
        }
        let record = Record {
            flow: 1,
            id: if i >= 8 { i + 1 } else { i },
            payload: vec![i as u8; 1000],
        };
        all.extend(encoder.encode(&record, now).unwrap());
    }
    let bulk_repairs: Vec<_> = all
        .iter()
        .filter(|s| !s.small && matches!(s.data[3], 1 | 3))
        .collect();
    assert_eq!(bulk_repairs.len(), 2);
    assert_eq!(bulk_repairs[0].data[4..13], bulk_repairs[1].data[4..13]);
    assert_eq!(bulk_repairs[0].data[12], 16);
    let mut receiver =
        Receiver::configured(Duration::from_millis(100), true).with_dual_repairs(true);
    let mut ids = BTreeSet::new();
    for s in all {
        if s.data[3] == 0 && !s.small && s.data[12] < 2 {
            continue;
        }
        for record in receiver.receive(&s.data, now).unwrap() {
            assert!(ids.insert(record.id));
        }
    }
    assert_eq!(ids, (0..17).collect());
    assert_eq!(receiver.recovered, 2);
    let next = encoder
        .encode(
            &Record {
                flow: 1,
                id: 17,
                payload: vec![1; 1000],
            },
            now,
        )
        .unwrap();
    assert_eq!(
        u64::from_be_bytes(next[0].data[4..12].try_into().unwrap()),
        2
    );
    let due = encoder.flush_due(now + Duration::from_millis(8)).unwrap();
    assert_eq!(due.len(), 2);
    assert!(due.iter().all(|s| s.data[12] == 1));
}

#[test]
fn independent_repairs_are_both_charged_to_the_bulk_budget_not_decoded_as_records() {
    let p = dual_policy();
    let now = Instant::now();
    let metrics = stats::Metrics::new("client");
    let scope = metrics.scope("dual-budget", stats::FORWARD);
    let mut encoder = coding::RecordEncoder::new(&p).unwrap();
    let mut queue = outbound::Queue::default();
    let mut blocks = BTreeMap::new();
    for id in 0..16 {
        let record = Record {
            flow: 1,
            id,
            payload: vec![id as u8; 1000],
        };
        for s in encoder.encode(&record, now).unwrap() {
            enqueue_encoded(s, now, &mut queue, &mut blocks, &p, &scope);
        }
    }
    assert_eq!(queue.len(), 18);
    let mut budget = outbound::RepairBudget::new(13);
    while let Some(original) = queue.pop(false) {
        assert!(original.record_id.is_some());
        let size = repair_frame_floor(&p, &original);
        budget_admitted(&p, &mut budget, &mut blocks, &original, size, &scope);
    }
    let mut admitted = 0;
    while let Some(repair) = queue.pop(true) {
        assert!(repair.record_id.is_none() && repair.flow.is_none());
        assert!(matches!(repair.data[3], 1 | 3));
        let bytes = repair_frame_floor(&p, &repair);
        assert!(repair_allowed(&p, &budget, &blocks, &repair, bytes));
        budget_admitted(&p, &mut budget, &mut blocks, &repair, bytes, &scope);
        admitted += 1;
        assert_eq!(queue.repair_pending(0), admitted == 1);
    }
    assert_eq!(admitted, 2);
    assert!(!budget.can_repair(1027));
    metrics.state(|s| {
        let counters = &s.sessions["dual-budget"][stats::FORWARD].symbols;
        assert_eq!(counters.originals_generated, 16);
        assert_eq!(counters.repairs_generated, 2);
        assert_eq!(counters.mixed_bulk_repairs_quinn_admitted, 2);
        assert_eq!(counters.mixed_small_repairs_quinn_admitted, 0);
    });
}

#[test]
fn short_dual_block_cannot_manufacture_repair_credit() {
    let p = dual_policy();
    let now = Instant::now();
    let metrics = stats::Metrics::new("client");
    let scope = metrics.scope("dual-short", stats::FORWARD);
    let mut encoder = coding::RecordEncoder::new(&p).unwrap();
    let mut queue = outbound::Queue::default();
    let mut blocks = BTreeMap::new();
    let record = Record {
        flow: 1,
        id: 0,
        payload: vec![1; 1000],
    };
    for s in encoder
        .encode(&record, now)
        .unwrap()
        .into_iter()
        .chain(encoder.flush_due(now + Duration::from_millis(8)).unwrap())
    {
        enqueue_encoded(s, now, &mut queue, &mut blocks, &p, &scope);
    }
    let mut budget = outbound::RepairBudget::new(13);
    let original = queue.pop(false).unwrap();
    budget_admitted(
        &p,
        &mut budget,
        &mut blocks,
        &original,
        repair_frame_floor(&p, &original),
        &scope,
    );
    for _ in 0..2 {
        let repair = queue.pop(true).unwrap();
        assert!(!repair_allowed(
            &p,
            &budget,
            &blocks,
            &repair,
            repair_frame_floor(&p, &repair)
        ));
        account_budget_skipped(&p, &repair, &scope);
    }
    metrics.state(|s| {
        let counters = &s.sessions["dual-short"][stats::FORWARD].symbols;
        assert_eq!(counters.mixed_bulk_repairs_generated, 2);
        assert_eq!(counters.mixed_bulk_repairs_budget_skipped, 2);
        assert_eq!(counters.mixed_bulk_repairs_quinn_admitted, 0);
    });
}
