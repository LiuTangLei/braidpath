//! Deterministic in-memory demonstration; no sockets and no latency measurement.
use braidpath::{
    fec::{Decoder, Encoder, Shard},
    path,
};
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths: Vec<_> = path::candidates(1, 3).collect();
    let mut encoder = Encoder::new(4, Duration::from_millis(3))?;
    let now = Instant::now();
    let mut sent = Vec::new();
    for payload in [b"one".as_slice(), b"two", b"three", b"four"] {
        sent.extend(encoder.push(payload, now)?);
    }
    let mut decoder = Decoder::new(0);
    let mut delivered = Vec::new();
    for (n, shard) in sent.into_iter().enumerate() {
        let route = paths[n % paths.len()]; // Demonstration only, not a scheduler.
        if matches!(shard, Shard::Data { index: 1, .. }) {
            println!("erase data 1 on {route:?}");
            continue;
        }
        for packet in decoder.receive(shard)? {
            println!(
                "deliver {}: {} (recovered={})",
                packet.index,
                String::from_utf8_lossy(&packet.payload),
                packet.recovered
            );
            delivered.push(packet);
        }
    }
    assert_eq!(delivered.len(), 4);
    assert_eq!(delivered.iter().filter(|p| p.recovered).count(), 1);
    println!("4/4 packets delivered; one erasure repaired without retransmission.");
    println!("Synthetic codec example only; no network performance claim.");
    Ok(())
}
