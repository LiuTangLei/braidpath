//! Finite offline receiver replay. Payloads are synthetic but exact lengths,
//! source IDs/block membership and receiver-local symbol arrival times are given
//! by the corpus. This is not a network or end-to-end deadline measurement.
use anyhow::{Context, Result, ensure};
use braidpath::{
    fec::{Encoder, Shard},
    runtime::wire::{self, Receiver, Record},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

#[derive(Deserialize)]
struct Original {
    index: u8,
    flow: u32,
    id: u64,
    bytes: usize,
}
#[derive(Deserialize)]
struct Block {
    block: u64,
    count: u8,
    originals: Vec<Original>,
}
#[derive(Deserialize)]
struct Arrival {
    at_ns: u64,
    block: u64,
    kind: String,
    index_or_count: u8,
}
#[derive(Deserialize)]
struct Corpus {
    blocks: Vec<Block>,
    arrivals: Vec<Arrival>,
    expected_delivered: Vec<u64>,
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: receiver_retention_replay CORPUS.json")?;
    let raw = std::fs::read(path)?;
    ensure!(raw.len() <= 32 * 1024 * 1024, "corpus size bound");
    let corpus: Corpus = serde_json::from_slice(&raw)?;
    ensure!(
        corpus.blocks.len() <= 100_000 && corpus.arrivals.len() <= 200_000,
        "finite replay limit"
    );
    let base = Instant::now();
    let mut symbols = BTreeMap::new();
    let mut originals = BTreeMap::new();
    for block in &corpus.blocks {
        ensure!(
            block.originals.len() == usize::from(block.count),
            "block member census"
        );
        let mut encoder = Encoder::new(block.count, Duration::from_secs(1))?;
        for (index, o) in block.originals.iter().enumerate() {
            ensure!(
                usize::from(o.index) == index && o.bytes <= 1000,
                "bounded ordered original"
            );
            let record = Record {
                flow: o.flow,
                id: o.id,
                payload: vec![(o.id % 251) as u8; o.bytes],
            };
            ensure!(
                originals.insert(o.id, record.clone()).is_none(),
                "unique source record ID"
            );
            for mut packet in encoder.push(&record.encode()?, base)? {
                let (kind, index) = match &mut packet {
                    Shard::Data {
                        block: b, index, ..
                    } => {
                        *b = block.block;
                        ("original", *index)
                    }
                    Shard::Repair {
                        block: b, count, ..
                    } => {
                        *b = block.block;
                        ("repair", *count)
                    }
                };
                ensure!(
                    symbols
                        .insert((block.block, kind, index), wire::shard(packet))
                        .is_none(),
                    "unique symbol"
                );
            }
        }
    }
    let expected: BTreeSet<_> = corpus.expected_delivered.into_iter().collect();
    let mut results = Vec::new();
    let mut sets = Vec::new();
    for adaptive in [false, true] {
        let mut receiver = Receiver::configured(Duration::from_millis(100), adaptive);
        let mut delivered = BTreeSet::new();
        let mut changes = Vec::new();
        let mut last_horizon = 0;
        let mut last_at = 0;
        for arrival in &corpus.arrivals {
            ensure!(
                arrival.at_ns >= last_at && arrival.at_ns <= 120_000_000_000,
                "receiver-local monotonic order/bound"
            );
            last_at = arrival.at_ns;
            let at = base + Duration::from_nanos(arrival.at_ns);
            let symbol = symbols
                .get(&(arrival.block, arrival.kind.as_str(), arrival.index_or_count))
                .context("arrival not in generated source symbols")?;
            for record in receiver.receive(symbol, at)? {
                ensure!(
                    originals.get(&record.id) == Some(&record),
                    "synthetic payload integrity"
                );
                ensure!(delivered.insert(record.id), "duplicate business delivery");
            }
            if let Some(s) = receiver.retention_snapshot() {
                ensure!(
                    s.metadata_blocks <= 256 && s.live_blocks <= 256,
                    "bounded state"
                );
                if s.current_ms != last_horizon {
                    changes.push(json!({"at_ns":arrival.at_ns,"current_ms":s.current_ms}));
                    last_horizon = s.current_ms;
                }
            }
        }
        results.push(
            json!({"adaptive":adaptive,"source_records":originals.len(),"delivered":delivered.len(),
            "reconstructed":receiver.recovered,"stale_repair_symbols":receiver.stale,
            "missing_from_captured_delivery":expected.difference(&delivered).collect::<Vec<_>>(),
            "extra_vs_captured_delivery":delivered.difference(&expected).collect::<Vec<_>>(),
            "retention":receiver.retention_snapshot(),"horizon_changes":changes}),
        );
        sets.push(delivered);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"scope":"Synthetic payloads and actual recorded symbol timestamps; real codec and receiver, no sockets, no end-to-end timing assertion.",
        "baseline_matches_captured_record_set":sets[0]==expected,
        "adaptive_gained_ids":sets[1].difference(&sets[0]).collect::<Vec<_>>(),
        "adaptive_lost_ids":sets[0].difference(&sets[1]).collect::<Vec<_>>(),
        "results":results})
        )?
    );
    Ok(())
}
