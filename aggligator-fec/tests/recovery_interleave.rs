//! Regression: per-lane FEC indices are strided, but round-robin source
//! production is a DENSE application sequence. ARQ must retain that sequence.
use aggligator_fec::{
    Config,
    interleave::{InterleavedEncoder, source_sequence},
    recovery::{Feedback, SendWindow},
};
use std::time::Duration;

#[test]
fn round_robin_interleaved_sources_fit_dense_arq_across_block_boundaries() {
    for (k, m, lanes) in [(8, 4, 1), (16, 2, 8), (64, 8, 8), (32, 4, 16)] {
        let cfg = Config {
            data_shards: k,
            repair_shards: m,
            max_block_delay: Duration::from_millis(40),
            ..Config::default()
        };
        let mut encoder = InterleavedEncoder::new(cfg, lanes).unwrap();
        let mut history = SendWindow::new(4096, 8 * 1024 * 1024, Duration::from_millis(100), 10).unwrap();
        let mut expected = 0u64;
        for seq in 0u64..2055 {
            let now = Duration::from_micros(seq * 40);
            for frame in encoder.push(seq.to_be_bytes().to_vec(), now).unwrap() {
                if let Some(mapped) = source_sequence(&frame, lanes).unwrap() {
                    assert_eq!(mapped, expected, "k={k}, m={m}, lanes={lanes}");
                    history.retain_at(mapped, &frame).unwrap();
                    expected += 1;
                }
            }
        }
        assert_eq!(expected, 2055);
        for frame in encoder.flush().unwrap() {
            assert!(source_sequence(&frame, lanes).unwrap().is_none());
        }
        history
            .feedback(Feedback { next: 2055, base: 2055, limit: 2055, missing: 0 }, Duration::from_secs(1))
            .unwrap();
        assert!(history.is_empty());
        assert_eq!(history.bytes(), 0);
    }
}
