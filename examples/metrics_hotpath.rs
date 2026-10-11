//! Local CPU diagnostic of the real metrics API; no sockets or network claim.
use braidpath::runtime::stats::{Metrics, RETURN};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    time::Instant,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let count: u64 = std::env::args()
        .nth(1)
        .as_deref()
        .unwrap_or("500000")
        .parse()?;
    if count == 0 || count > 5_000_000 {
        return Err("record count must be 1..5000000".into());
    }
    let metrics = Metrics::new("metrics-hotpath");
    let scope = metrics.scope("diagnostic-session", RETURN);
    let started = Instant::now();
    for id in 0..count {
        scope.update(|d| {
            d.records.application_received += 1;
            d.symbols.originals_generated += 1;
            d.generated_record_ids.add(id);
        });
        if id.is_multiple_of(4) {
            scope.update(|d| {
                d.symbols.originals_queue_full_dropped += 1;
                d.locally_dropped_original_ids.add(id);
            });
        } else {
            scope.update(|d| {
                d.symbols.originals_quinn_admitted += 1;
                d.quinn_admitted_record_ids.add(id);
            });
        }
    }
    let elapsed = started.elapsed();
    let mut fingerprint = DefaultHasher::new();
    let mut recent_count = 0;
    metrics.state(|s| {
        let aggregate = &s.directions[RETURN];
        let session = &s.sessions["diagnostic-session"][RETURN];
        for d in [aggregate, session] {
            assert_eq!(d.records.application_received, count);
            assert_eq!(d.symbols.originals_generated, count);
            assert_eq!(
                d.symbols.originals_quinn_admitted + d.symbols.originals_queue_full_dropped,
                count
            );
        }
        assert!(aggregate.generated_record_ids.recent.is_empty());
        assert!(aggregate.quinn_admitted_record_ids.recent.is_empty());
        assert!(aggregate.locally_dropped_original_ids.recent.is_empty());
        assert_eq!(session.generated_record_ids.highest_id, count - 1);
        recent_count = session.generated_record_ids.recent.len();
        assert_eq!(recent_count as u64, count.min(8192));
        // Serialize only after timing. Equal fingerprints accompany the exact
        // counter assertions; this is not a cryptographic identity or a rate gate.
        serde_json::to_string(s).unwrap().hash(&mut fingerprint);
    });
    println!(
        "{}",
        serde_json::json!({
            "records":count,"scope_updates":count*2,"elapsed_ns":elapsed.as_nanos(),
            "ns_per_update":elapsed.as_nanos() as f64/(count*2) as f64,
            "state_fingerprint":fingerprint.finish(),"recent_ids":recent_count,
            "scope":"local metrics hot path only; no sockets or end-to-end throughput"
        })
    );
    Ok(())
}
