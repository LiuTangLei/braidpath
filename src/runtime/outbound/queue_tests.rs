use super::*;

fn item(id: u64, block: Option<u64>, flow: Option<u32>, created: Instant) -> Pending {
    Pending {
        data: Bytes::from(id.to_be_bytes().to_vec()),
        created,
        record_id: flow.map(|_| id),
        flow,
        block,
        small: false,
    }
}

fn assert_indexes(queue: &Queue) {
    let mut originals = BTreeMap::new();
    let mut repairs = BTreeMap::new();
    for p in queue.flows.values().flatten() {
        if let Some(block) = p.block {
            *originals.entry(block).or_insert(0) += 1;
        }
    }
    for p in &queue.repairs {
        if let Some(block) = p.block {
            *repairs.entry(block).or_insert(0) += 1;
        }
    }
    assert_eq!(queue.original_blocks, originals);
    assert_eq!(queue.repair_blocks, repairs);
    assert_eq!(
        queue.len,
        queue.flows.values().map(VecDeque::len).sum::<usize>() + queue.repairs.len()
    );
    assert!(queue.len <= QUEUE);
    assert!(queue.original_blocks.len() + queue.repair_blocks.len() <= queue.len);
    for block in 0..40 {
        assert_eq!(queue.block_pending(block), originals.contains_key(&block));
        assert_eq!(queue.repair_pending(block), repairs.contains_key(&block));
    }
}

#[test]
fn indexes_survive_dual_repairs_rejection_expiry_and_full_drain() {
    let now = Instant::now();
    let mut q = Queue::default();
    for i in 0..PER_FLOW_LIMIT {
        q.push(item(i as u64, Some(7), Some(1), now))
            .unwrap_or_else(|_| panic!("capacity"));
    }
    assert!(q.push(item(999, Some(8), Some(1), now)).is_err());
    assert!(!q.block_pending(8));
    for i in 0..REPAIR_LIMIT {
        q.push(item(i as u64, Some(7), None, now))
            .unwrap_or_else(|_| panic!("repair capacity"));
    }
    assert!(q.push(item(999, Some(9), None, now)).is_err());
    assert!(!q.repair_pending(9));
    assert_indexes(&q);
    assert!(!q.promote_ready_repair(|_| true));
    for _ in 0..PER_FLOW_LIMIT {
        q.pop(false).unwrap();
    }
    assert!(q.promote_ready_repair(|_| true));
    q.pop(true).unwrap();
    assert!(
        q.repair_pending(7),
        "other repair symbols still retain this block"
    );
    assert_eq!(
        q.expire(now + Duration::from_millis(10), Duration::from_millis(10))
            .len(),
        REPAIR_LIMIT - 1
    );
    assert_indexes(&q);
    assert!(q.is_empty());
    assert!(q.oldest_created.is_none());
}

#[test]
fn expiry_hint_preserves_fifo_originals_and_out_of_order_repair_ages() {
    let at = Instant::now();
    let mut q = Queue::default();
    for p in [
        item(0, Some(0), Some(1), at + Duration::from_millis(10)),
        item(1, Some(1), Some(1), at),
        item(2, Some(2), None, at + Duration::from_millis(10)),
        item(3, Some(3), None, at),
    ] {
        assert!(q.push(p).is_ok());
    }
    let expired = q.expire(at + Duration::from_millis(5), Duration::from_millis(5));
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].block, Some(3));
    assert!(
        q.block_pending(1),
        "older original cannot bypass its unexpired FIFO head"
    );
    assert_eq!(q.oldest_created, Some(at));
    assert!(
        q.expire(at + Duration::from_millis(14), Duration::from_millis(5))
            .is_empty()
    );
    assert_eq!(
        q.expire(at + Duration::from_millis(15), Duration::from_millis(5))
            .len(),
        3
    );
    assert_indexes(&q);
    assert!(
        q.push(item(4, None, Some(1), at + Duration::from_secs(1)))
            .is_ok()
    );
    assert_eq!(
        q.expire(at, Duration::ZERO).len(),
        1,
        "zero-age retains previous saturating-clock semantics"
    );
}

#[test]
fn seeded_operations_match_scan_based_queries_and_expiration() {
    let epoch = Instant::now();
    let mut q = Queue::default();
    let mut rng = 0x19c7_e5b4_1320_8765u64;
    for i in 0..20_000u64 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let now = epoch + Duration::from_micros(i * 3);
        match rng % 7 {
            0..=2 => {
                let block = (!rng.is_multiple_of(11)).then_some((rng >> 8) % 40);
                let flow = (!rng.is_multiple_of(3)).then_some(((rng >> 16) % 4) as u32);
                let created = now - Duration::from_micros((rng >> 24) % 300);
                let _ = q.push(item(i, block, flow, created));
            }
            3 => {
                q.pop(rng & 8 != 0);
            }
            4 => q.rotate_original(),
            5 => {
                let marker = rng % 5;
                let expected = q
                    .repairs
                    .iter()
                    .position(|p| {
                        !p.block.is_some_and(|block| {
                            q.flows
                                .values()
                                .any(|f| f.iter().any(|p| p.block == Some(block)))
                        }) && p.data[7] % 5 != marker as u8
                    })
                    .map(|n| q.repairs[n].data.clone());
                assert_eq!(
                    q.promote_ready_repair(|p| p.data[7] % 5 != marker as u8),
                    expected.is_some()
                );
                if let Some(expected) = expected {
                    assert_eq!(q.front(true).unwrap().data, expected);
                }
            }
            _ => {
                let age = Duration::from_micros((rng >> 32) % 500);
                let mut expected = Vec::new();
                for flow in q.flows.values() {
                    expected.extend(
                        flow.iter()
                            .take_while(|p| now.saturating_duration_since(p.created) >= age)
                            .map(|p| p.data.clone()),
                    );
                }
                expected.extend(
                    q.repairs
                        .iter()
                        .filter(|p| now.saturating_duration_since(p.created) >= age)
                        .map(|p| p.data.clone()),
                );
                assert_eq!(
                    q.expire(now, age)
                        .iter()
                        .map(|p| p.data.clone())
                        .collect::<Vec<_>>(),
                    expected
                );
            }
        }
        assert_indexes(&q);
    }
    while q.pop(false).is_some() {}
    while q.pop(true).is_some() {}
    assert_indexes(&q);
    assert!(q.oldest_created.is_none());
}
