use braidpath::fec::{Decoder, DualEncoder, Encoder, Error, MAX_PAYLOAD, Shard};
use braidpath::runtime::wire::{self, Receiver, Record};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

fn payloads(k: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| {
            (0..[0, 1, 17, 128, 999, MAX_PAYLOAD][i % 6])
                .map(|j| ((i * 31 + j * 7) % 256) as u8)
                .collect()
        })
        .collect()
}

fn encoded(data: &[Vec<u8>]) -> Vec<Shard> {
    let mut e = DualEncoder::new(data.len() as u8, Duration::from_millis(8)).unwrap();
    let now = Instant::now();
    data.iter().flat_map(|p| e.push(p, now).unwrap()).collect()
}

#[test]
fn every_pair_of_erased_symbols_recovers_with_unequal_lengths_and_reordering() {
    for k in [1, 2, 4, 8, 16, 32] {
        let data = payloads(k);
        let symbols = encoded(&data);
        assert_eq!(symbols.len(), k + 2);
        for first in 0..symbols.len() {
            for second in first + 1..symbols.len() {
                for backwards in [false, true] {
                    let mut selected: Vec<_> = symbols
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != first && *i != second)
                        .map(|(_, s)| s.clone())
                        .collect();
                    if backwards {
                        selected.reverse();
                    }
                    let mut receiver = Decoder::new(0);
                    let mut delivered = BTreeMap::new();
                    for symbol in selected {
                        for d in receiver.receive(symbol.clone()).unwrap() {
                            assert!(delivered.insert(d.index as usize, d.payload).is_none());
                        }
                        assert!(
                            receiver.receive(symbol).unwrap().is_empty(),
                            "identical symbol is idempotent"
                        );
                    }
                    assert_eq!(
                        delivered.values().cloned().collect::<Vec<_>>(),
                        data,
                        "k={k} erased={first},{second} reversed={backwards}"
                    );
                }
            }
        }
    }
}

#[test]
fn default_original_and_p_parity_bytes_are_unchanged() {
    for k in [1, 2, 8, 16, 32] {
        let data = payloads(k);
        let now = Instant::now();
        let mut single = Encoder::new(k as u8, Duration::from_millis(8)).unwrap();
        let old: Vec<_> = data
            .iter()
            .flat_map(|p| single.push(p, now).unwrap())
            .collect();
        let new: Vec<_> = encoded(&data)
            .into_iter()
            .filter(|s| !matches!(s, Shard::RepairQ { .. }))
            .collect();
        assert_eq!(old, new);
    }
}

#[test]
fn originals_leave_immediately_and_short_blocks_flush_both_equations() {
    let now = Instant::now();
    let mut e = DualEncoder::new(16, Duration::from_millis(8)).unwrap();
    assert!(matches!(
        e.push(b"one", now).unwrap().as_slice(),
        [Shard::Data {
            block: 0,
            index: 0,
            ..
        }]
    ));
    assert!(e.flush_due(now + Duration::from_millis(7)).is_empty());
    let repairs = e.flush_due(now + Duration::from_millis(8));
    assert!(matches!(
        &repairs[..],
        [
            Shard::Repair {
                block: 0,
                count: 1,
                ..
            },
            Shard::RepairQ {
                block: 0,
                count: 1,
                ..
            }
        ]
    ));
    assert!(e.flush().is_empty());
    assert!(matches!(
        e.push(b"two", now + Duration::from_millis(9))
            .unwrap()
            .as_slice(),
        [Shard::Data { block: 1, .. }]
    ));
    let next = e.push(b"three", now + Duration::from_millis(18)).unwrap();
    assert!(matches!(
        &next[..],
        [
            Shard::Repair { block: 1, .. },
            Shard::RepairQ { block: 1, .. },
            Shard::Data { block: 2, .. }
        ]
    ));
}

#[test]
fn three_missing_originals_do_not_produce_bogus_delivery_and_late_original_unlocks_two() {
    let data = payloads(16);
    let symbols = encoded(&data);
    let mut decoder = Decoder::new(0);
    let mut total = 0;
    for symbol in symbols.iter().skip(3) {
        total += decoder.receive(symbol.clone()).unwrap().len();
    }
    assert_eq!(total, 13);
    let unlocked = decoder.receive(symbols[0].clone()).unwrap();
    assert_eq!(unlocked.len(), 3);
    assert_eq!(unlocked.iter().filter(|d| d.recovered).count(), 2);
    for d in unlocked {
        assert_eq!(d.payload, data[d.index as usize]);
    }
}

#[test]
fn independent_repair_metadata_conflicts_and_bounds_are_rejected() {
    let data = payloads(4);
    let symbols = encoded(&data);
    let mut decoder = Decoder::new(0);
    decoder.receive(symbols[4].clone()).unwrap();
    let mut conflicting = symbols[5].clone();
    if let Shard::RepairQ { count, .. } = &mut conflicting {
        *count = 3;
    }
    assert_eq!(decoder.receive(conflicting), Err(Error::ConflictingShard));
    let mut mismatched_size = symbols[5].clone();
    if let Shard::RepairQ { coded, .. } = &mut mismatched_size {
        coded.push(0);
    }
    assert_eq!(
        decoder.receive(mismatched_size),
        Err(Error::ConflictingShard)
    );
    decoder.receive(symbols[5].clone()).unwrap();
    let mut corrupt_duplicate = symbols[5].clone();
    if let Shard::RepairQ { coded, .. } = &mut corrupt_duplicate {
        coded[2] ^= 1;
    }
    assert_eq!(
        decoder.receive(corrupt_duplicate),
        Err(Error::ConflictingShard)
    );
    for count in [0, 33, 255] {
        assert_eq!(
            Decoder::new(0).receive(Shard::RepairQ {
                block: 0,
                count,
                coded: vec![0; 4]
            }),
            Err(Error::InvalidShard)
        );
    }
    assert_eq!(
        Decoder::new(0).receive(Shard::RepairQ {
            block: 0,
            count: 2,
            coded: vec![0]
        }),
        Err(Error::InvalidShard)
    );
    assert_eq!(
        Decoder::new(1).receive(symbols[5].clone()),
        Err(Error::WrongBlock)
    );
}

#[test]
fn unnegotiated_q_is_rejected_and_negotiated_wire_restores_two_records_once() {
    let now = Instant::now();
    let mut encoder = DualEncoder::new(16, Duration::from_millis(8)).unwrap();
    let records: Vec<_> = (0..16)
        .map(|i| Record {
            id: i,
            flow: 7,
            payload: vec![i as u8; 128 + i as usize],
        })
        .collect();
    let symbols: Vec<_> = records
        .iter()
        .flat_map(|r| encoder.push(&r.encode().unwrap(), now).unwrap())
        .collect();
    let q = wire::shard(symbols[17].clone());
    assert_eq!(q[3], 3);
    assert!(Receiver::default().receive(&q, now).is_err());
    let mut receiver =
        Receiver::configured(Duration::from_millis(100), true).with_dual_repairs(true);
    let mut out = BTreeMap::new();
    for symbol in symbols.iter().skip(2).rev() {
        for r in receiver.receive(&wire::shard(symbol.clone()), now).unwrap() {
            assert!(out.insert(r.id, r).is_none());
        }
    }
    assert_eq!(out.into_values().collect::<Vec<_>>(), records);
    assert_eq!(receiver.recovered, 2);
    assert!(
        receiver
            .receive(&wire::shard(symbols[0].clone()), now)
            .unwrap()
            .is_empty()
    );
    assert!(receiver.receive(&q, now).unwrap().is_empty());
    receiver.close_retention();
    let snapshot = receiver.retention_snapshot().unwrap();
    assert_eq!(snapshot.live_blocks, 0);
    assert_eq!(snapshot.metadata_blocks, 0);
}

#[test]
fn same_erasure_at_equal_nominal_overhead_demonstrates_independent_equations() {
    let now = Instant::now();
    let data: Vec<Vec<u8>> = (0..16).map(|i| vec![i as u8; 1000]).collect();
    let mut single = Encoder::new(8, Duration::from_millis(8)).unwrap();
    let one: Vec<_> = data
        .iter()
        .flat_map(|p| single.push(p, now).unwrap())
        .collect();
    let two = encoded(&data);
    assert_eq!(
        one.len(),
        two.len(),
        "both send 16 originals and two equally sized repairs"
    );
    let mut old = [Decoder::new(0), Decoder::new(1)];
    let mut new = Decoder::new(0);
    let mut old_delivered = 0;
    let mut new_delivered = 0;
    // Erase exactly original0 and original1, keep all other original/repair symbols.
    for s in one {
        if matches!(
            &s,
            Shard::Data {
                block: 0,
                index: 0 | 1,
                ..
            }
        ) {
            continue;
        }
        old_delivered += old[s.block() as usize].receive(s).unwrap().len();
    }
    for s in two {
        if matches!(&s, Shard::Data { index: 0 | 1, .. }) {
            continue;
        }
        new_delivered += new.receive(s).unwrap().len();
    }
    assert_eq!((old_delivered, new_delivered), (14, 16));
}
