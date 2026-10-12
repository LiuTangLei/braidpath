//! Timing preference for the explicitly enabled one-copy small-record mode.
//! These are relative delivery estimates, never a clock-synchronized one-way SLA.
use super::{OutPath, Policy, outbound};
use std::time::Duration;

pub(super) fn applies(policy: &Policy, pending: &outbound::Pending) -> bool {
    policy.small_fec_bytes > 0 && pending.block.is_some()
}

fn delay_estimate(min_rtt_ms: f64, rtt_ms: f64, transit_ms: f64, queued: usize, cwnd: u64) -> f64 {
    let baseline = min_rtt_ms.min(rtt_ms).max(0.0);
    // Round-trip excess and receiver transit variation can describe the same
    // queue; take the maximum, not their sum. Assign all RTT excess to the
    // sending direction conservatively. Only the base propagation uses RTT/2.
    let network = (rtt_ms - baseline).max(transit_ms).max(0.0);
    let local = queued as f64 * rtt_ms / cwnd.max(1) as f64;
    baseline * 0.5 + network + local
}

fn estimate(path: &OutPath) -> f64 {
    let native = path.conn.stats();
    let rtt_ms = path.conn.rtt().as_secs_f64() * 1000.0;
    let feedback = path.quality.lock().expect("quality lock");
    let received = &feedback.snapshot.sender_estimate;
    let transit_ms = if received
        .updated_us
        .is_some_and(|at| super::quality_time(path).saturating_sub(at) <= 3_000_000)
    {
        received.delay_variation_ms
    } else {
        0.0
    };
    delay_estimate(
        native.path.min_rtt.as_secs_f64() * 1000.0,
        rtt_ms,
        transit_ms,
        path.empty_datagram_space
            .saturating_sub(path.conn.datagram_send_buffer_space()),
        native.path.cwnd,
    )
}

pub(super) fn mask(paths: &[OutPath], eligible: u8, remaining: Duration, target_ms: u64) -> u8 {
    let estimates: Vec<_> = paths
        .iter()
        .filter(|path| eligible & (1 << path.id) != 0 && path.conn.close_reason().is_none())
        .map(|path| (path.id, estimate(path)))
        .collect();
    let Some(best) = estimates.iter().map(|(_, cost)| *cost).reduce(f64::min) else {
        return 0;
    };
    // Small records trade bulk shares for timeliness. Keep diversity among
    // near-equal paths, but never spend more than 20ms (or the smaller remaining
    // admission budget) solely to move a copy onto another path.
    let slack = (target_ms.min(20) as f64).min(remaining.as_secs_f64() * 1000.0);
    estimates
        .into_iter()
        .filter(|(_, cost)| *cost <= best + slack)
        .fold(0, |mask, (id, _)| mask | (1 << id))
}

pub(super) fn copy_ready(path: &OutPath, used: u8) -> bool {
    if used & (1 << path.id) == 0 {
        return true;
    }
    // Quinn removes outgoing DATAGRAM frames while constructing a packet under
    // its connection lock. An empty queue means the admitted original can no
    // longer be co-packed with a newly admitted same-path copy. No ACK or fixed
    // sleep is required; the sender's existing 1ms tick rechecks this gate.
    path.conn.datagram_send_buffer_space() >= path.empty_datagram_space
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_queue_and_rtt_excess_are_not_double_counted() {
        assert_eq!(delay_estimate(120.0, 400.0, 248.0, 0, 12_000), 340.0);
        assert_eq!(delay_estimate(120.0, 122.0, 248.0, 0, 12_000), 308.0);
        assert_eq!(delay_estimate(120.0, 122.0, 1.0, 0, 12_000), 62.0);
        assert_eq!(delay_estimate(120.0, 120.0, 0.0, 1200, 12_000), 72.0);
    }
}
