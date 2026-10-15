//! Deterministic encoded-cost proof for the bounded 64 Mbit/s recovery study.
//! No sockets, timers or capacity claims: actual runtime admission still decides.
use braidpath::{
    fec::{DualEncoder, Encoder, Shard},
    runtime::{
        quality,
        wire::{self, Record},
    },
};
use std::time::{Duration, Instant};

#[test]
fn recovery_profile_counts_repairs_inside_the_unchanged_total_budget() {
    let start = Instant::now();
    let mut bulk = DualEncoder::new(16, Duration::from_millis(8)).unwrap();
    let mut small = Encoder::new(1, Duration::from_millis(8)).unwrap();
    let quality = quality::State::new(1);
    let mut originals = 0u64;
    let mut repairs = 0u64;
    let mut total_cost = 0u64;
    let mut original_frames = 0u64;
    let mut repair_frames = 0u64;
    let mut maximum_frame = 0usize;
    for id in 0..80_000u64 {
        let record = Record {
            flow: 1,
            id,
            payload: vec![7; 1000],
        };
        for shard in bulk
            .push(
                &record.encode().unwrap(),
                start + Duration::from_micros(id * 125),
            )
            .unwrap()
        {
            let original = matches!(&shard, Shard::Data { .. });
            let frame = wire::http_datagram(0, &quality.wrap(&wire::shard(shard), 0))
                .unwrap()
                .len();
            maximum_frame = maximum_frame.max(frame);
            total_cost += frame as u64 + 80;
            if original {
                originals += 1;
                original_frames += frame as u64;
            } else {
                repairs += 1;
                repair_frames += frame as u64;
            }
        }
    }
    assert!(bulk.flush().is_empty());
    assert_eq!((originals, repairs), (80_000, 10_000));
    assert!(repair_frames * 100 <= original_frames * 13);
    // 200 interactive replies plus the two control records. Both small symbols
    // count against the total budget, even though only one unique payload counts.
    for id in 0..202 {
        let record = Record {
            flow: 2,
            id,
            payload: vec![3; if id < 200 { 128 } else { 36 }],
        };
        let symbols = small.push(&record.encode().unwrap(), start).unwrap();
        assert_eq!(symbols.len(), 2);
        for shard in symbols {
            let frame = wire::http_datagram(0, &quality.wrap(&wire::shard(shard), 0))
                .unwrap()
                .len();
            maximum_frame = maximum_frame.max(frame);
            total_cost += frame as u64 + 80;
        }
    }
    let configured_bytes = 100_000_000u64 / 8 * 10;
    assert!(
        total_cost < configured_bytes * 9 / 10,
        "control/probe headroom required"
    );
    assert!(maximum_frame <= 1200);
    println!(
        "originals={originals} repairs={repairs} counted_cost_bps={} total_cap_bps=100000000 max_frame={maximum_frame}",
        total_cost * 8 / 10
    );
}
