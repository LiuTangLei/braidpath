//! Local CPU microbenchmark, NOT tunnel/network throughput.
use aggligator_fec::{Config, Decoder, Encoder, Frame};
use std::{error::Error, hint::black_box, time::{Duration, Instant}};

fn main() -> Result<(), Box<dyn Error>> {
    let iterations = 5000u64;
    println!("codec-only CPU benchmark; arch={}; excludes sockets, crypto, congestion control and ARQ", std::env::consts::ARCH);
    println!("profile,missing_sources_per_block,encode_source_mbps,decode_source_mbps,encode_block_p99_us,decode_block_p99_us");
    for (k, m, missing) in [(8, 4, 2), (8, 8, 4), (8, 8, 8)] {
        let cfg = Config { data_shards: k, repair_shards: m, max_payload: 1000, ..Config::default() };
        let mut encoder = Encoder::new(cfg.clone())?;
        let mut decoder = Decoder::new(cfg)?;
        let mut encode_times = Vec::new();
        let mut decode_times = Vec::new();
        for round in 0..iterations {
            let payloads: Vec<Vec<u8>> = (0..k).map(|index| {
                let mut state = round.wrapping_mul(7919) + index as u64 + 1;
                (0..1000).map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                }).collect()
            }).collect();
            let start = Instant::now();
            let mut frames = Vec::new();
            for payload in &payloads {
                frames.extend(encoder.push(black_box(payload.clone()), Duration::ZERO)?);
            }
            let encode = start.elapsed().as_nanos() as u64;
            let start = Instant::now();
            let mut delivered = 0;
            for frame in &frames {
                // Feed k independent symbols: k-missing originals and missing repairs.
                let use_frame = match frame {
                    Frame::Source { index, .. } => usize::from(*index) >= missing,
                    Frame::Repair { index, .. } => usize::from(*index) < missing,
                };
                if use_frame {
                    for packet in decoder.input(black_box(frame))? {
                        assert_eq!(packet.payload, payloads[packet.seq as usize % k]);
                        delivered += 1;
                    }
                }
            }
            let decode = start.elapsed().as_nanos() as u64;
            assert_eq!(delivered, k);
            if round >= 100 { // Warm caches first; no timed samples are selectively discarded.
                encode_times.push(encode);
                decode_times.push(decode);
            }
        }
        let source_bits = encode_times.len() as f64 * k as f64 * 1000.0 * 8.0;
        let encode_mbps = source_bits * 1000.0 / encode_times.iter().sum::<u64>().max(1) as f64;
        let decode_mbps = source_bits * 1000.0 / decode_times.iter().sum::<u64>().max(1) as f64;
        encode_times.sort_unstable();
        decode_times.sort_unstable();
        let p99 = (encode_times.len() * 99).div_ceil(100) - 1;
        println!("{k}+{m},{missing},{encode_mbps:.2},{decode_mbps:.2},{:.2},{:.2}",
            encode_times[p99] as f64 / 1000.0, decode_times[p99] as f64 / 1000.0);
    }
    Ok(())
}
