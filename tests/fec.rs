use braidpath::{
    fec::{Decoder, Encoder, Error, MAX_PAYLOAD, Shard},
    path,
};
use std::time::{Duration, Instant};

fn encode(payloads: &[Vec<u8>]) -> Vec<Shard> {
    let mut encoder = Encoder::new(payloads.len() as u8, Duration::from_millis(3)).unwrap();
    let now = Instant::now();
    payloads
        .iter()
        .flat_map(|p| encoder.push(p, now).unwrap())
        .collect()
}

#[test]
fn every_single_erasure_including_repair_and_every_arrival_order() {
    let payloads = vec![vec![], vec![1], vec![2; 29], vec![3; MAX_PAYLOAD]];
    let shards = encode(&payloads);
    fn permutations(items: &mut [Shard], index: usize, check: &mut impl FnMut(&[Shard])) {
        if index == items.len() {
            check(items);
            return;
        }
        for i in index..items.len() {
            items.swap(i, index);
            permutations(items, index + 1, check);
            items.swap(i, index);
        }
    }
    for erased in 0..shards.len() {
        let mut remaining: Vec<_> = shards
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != erased)
            .map(|(_, s)| s.clone())
            .collect();
        permutations(&mut remaining, 0, &mut |order| {
            let mut decoder = Decoder::new(0);
            let mut delivered = Vec::new();
            for shard in order {
                delivered.extend(decoder.receive(shard.clone()).unwrap());
                assert!(decoder.receive(shard.clone()).unwrap().is_empty());
            }
            delivered.sort_by_key(|d| d.index);
            assert_eq!(
                delivered
                    .iter()
                    .map(|d| d.payload.clone())
                    .collect::<Vec<_>>(),
                payloads
            );
            assert_eq!(
                delivered.iter().filter(|d| d.recovered).count(),
                usize::from(erased < payloads.len())
            );
            // The late original of a recovered symbol must not deliver again.
            assert!(decoder.receive(shards[erased].clone()).unwrap().is_empty());
        });
    }
}

#[test]
fn two_lost_data_packets_remain_missing_until_one_arrives() {
    let shards = encode(&[vec![10], vec![20], vec![30], vec![40]]);
    let mut decoder = Decoder::new(0);
    let mut delivered = Vec::new();
    for i in [2, 3, 4] {
        delivered.extend(decoder.receive(shards[i].clone()).unwrap());
    }
    assert_eq!(delivered.len(), 2);
    assert!(delivered.iter().all(|p| !p.recovered));
    let repaired = decoder.receive(shards[0].clone()).unwrap();
    assert_eq!(repaired.len(), 2);
    assert!(
        repaired
            .iter()
            .any(|d| d.index == 1 && d.payload == [20] && d.recovered)
    );
}

#[test]
fn partial_block_flushes_on_deadline_without_holding_original() {
    let start = Instant::now();
    let mut encoder = Encoder::new(8, Duration::from_millis(3)).unwrap();
    let original = encoder.push(b"interactive", start).unwrap();
    assert!(matches!(
        &original[..],
        [Shard::Data {
            block: 0,
            index: 0,
            ..
        }]
    ));
    assert!(
        encoder
            .flush_due(start + Duration::from_millis(2))
            .is_none()
    );
    let repair = encoder.flush_due(start + Duration::from_millis(3)).unwrap();
    let delivery = Decoder::new(0).receive(repair).unwrap();
    assert_eq!(delivery[0].payload, b"interactive");
    assert!(delivery[0].recovered);
    assert!(encoder.flush().is_none());
    assert!(matches!(
        encoder
            .push(b"next", start + Duration::from_millis(4))
            .unwrap()[0],
        Shard::Data {
            block: 1,
            index: 0,
            ..
        }
    ));
}

#[test]
fn a_new_packet_flushes_an_expired_block_before_starting_the_next() {
    let start = Instant::now();
    let mut encoder = Encoder::new(4, Duration::from_millis(2)).unwrap();
    encoder.push(b"first", start).unwrap();
    let out = encoder
        .push(b"second", start + Duration::from_millis(2))
        .unwrap();
    assert!(matches!(
        &out[..],
        [
            Shard::Repair {
                block: 0,
                count: 1,
                ..
            },
            Shard::Data {
                block: 1,
                index: 0,
                ..
            }
        ]
    ));
}

#[test]
fn bounds_and_conflicts_are_rejected() {
    assert!(Encoder::new(0, Duration::from_millis(1)).is_err());
    assert!(Encoder::new(33, Duration::from_millis(1)).is_err());
    assert!(Encoder::new(4, Duration::ZERO).is_err());
    let mut encoder = Encoder::new(4, Duration::from_millis(1)).unwrap();
    assert_eq!(
        encoder.push(&vec![0; MAX_PAYLOAD + 1], Instant::now()),
        Err(Error::PayloadTooLarge)
    );
    assert!(encoder.flush().is_none());
    let mut decoder = Decoder::new(0);
    assert_eq!(
        decoder.receive(Shard::Data {
            block: 1,
            index: 0,
            payload: vec![]
        }),
        Err(Error::WrongBlock)
    );
    assert_eq!(
        decoder.receive(Shard::Data {
            block: 0,
            index: 32,
            payload: vec![]
        }),
        Err(Error::InvalidShard)
    );
    decoder
        .receive(Shard::Data {
            block: 0,
            index: 0,
            payload: vec![1],
        })
        .unwrap();
    assert_eq!(
        decoder.receive(Shard::Data {
            block: 0,
            index: 0,
            payload: vec![2]
        }),
        Err(Error::ConflictingShard)
    );
    assert_eq!(
        decoder.receive(Shard::Repair {
            block: 0,
            count: 0,
            coded: vec![0; 3]
        }),
        Err(Error::InvalidShard)
    );
    assert_eq!(
        decoder.receive(Shard::Repair {
            block: 0,
            count: 1,
            coded: vec![0]
        }),
        Err(Error::InvalidShard)
    );
    assert_eq!(
        Decoder::new(0).receive(Shard::Repair {
            block: 0,
            count: 1,
            coded: vec![0, 1]
        }),
        Err(Error::InvalidShard)
    );
}

#[test]
fn single_interface_and_multiple_entrances_are_first_class() {
    assert_eq!(path::candidates(1, 1).count(), 1);
    assert_eq!(path::candidates(1, 3).count(), 3);
    let paths: Vec<_> = path::candidates(2, 3).collect();
    assert_eq!(paths.len(), 6);
    assert_eq!(
        paths.iter().collect::<std::collections::HashSet<_>>().len(),
        6
    );
    assert_eq!(path::candidates(0, 3).count(), 0);
}
