// Test-only adapter over the candidate's real coding and budget entry points.
#![allow(clippy::too_many_arguments)]
use super::*;

fn replay_modes() -> &'static [&'static str] {
    &["candidate_mixed"]
}
fn replay_implementation_identity() -> &'static str {
    "candidate source bound by root frozen HEAD; real RecordEncoder and budget_admitted"
}
fn replay_policy(_mode: &str, block_ms: u64, queue_ms: u64) -> Policy {
    Policy {
        adaptive: false,
        capacity_probe_bps: 0,
        probe_guided_recovery: false,
        latency_target_ms: 100,
        group_rates: [8_000_000; MAX_PATHS],
        receiver_feedback: false,
        quality_schedule: false,
        fec: 4,
        small_fec_bytes: 128,
        mixed_fec: true,
        redundancy: 25,
        rate: 8_000_000,
        block_ms,
        queue_ms,
    }
}
type RealEncoder = coding::RecordEncoder;
fn replay_encoder(policy: &Policy) -> RealEncoder {
    coding::RecordEncoder::new(policy).unwrap()
}
fn replay_encode(
    encoder: &mut RealEncoder,
    record: &Record,
    _policy: &Policy,
    now: Instant,
) -> Vec<DriverSymbol> {
    encoder
        .encode(record, now)
        .unwrap()
        .into_iter()
        .map(|symbol| DriverSymbol {
            data: symbol.data,
            small: symbol.small,
        })
        .collect()
}
fn replay_flush_due(encoder: &mut RealEncoder, now: Instant) -> Vec<DriverSymbol> {
    encoder
        .flush_due(now)
        .unwrap()
        .into_iter()
        .map(|symbol| DriverSymbol {
            data: symbol.data,
            small: symbol.small,
        })
        .collect()
}
fn replay_enqueue(
    symbol: DriverSymbol,
    created: Instant,
    queue: &mut outbound::Queue,
    blocks: &mut BTreeMap<u64, BlockSend>,
    policy: &Policy,
    metrics: &Scope,
) {
    enqueue_encoded(
        coding::EncodedSymbol {
            data: symbol.data,
            small: symbol.small,
        },
        created,
        queue,
        blocks,
        policy,
        metrics,
    );
}
fn replay_lane(_mode: &str, pending: &outbound::Pending) -> &'static str {
    if pending.small { "small_k1" } else { "bulk_k4" }
}
fn replay_budget_skipped(policy: &Policy, pending: &outbound::Pending, metrics: &Scope) {
    account_budget_skipped(policy, pending, metrics);
}
fn replay_budget_admitted(
    policy: &Policy,
    budget: &mut outbound::RepairBudget,
    blocks: &mut BTreeMap<u64, BlockSend>,
    pending: &outbound::Pending,
    frame_bytes: usize,
    metrics: &Scope,
) {
    // The production SendAccounting::commit calls this exact helper. Here its
    // invocation represents a virtual admission and never a Quinn socket send.
    budget_admitted(policy, budget, blocks, pending, frame_bytes, metrics);
}
include!("mixed_fec_replay_driver.rs");
