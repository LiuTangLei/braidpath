//! Bounded timing preferences for independent small-record coding.
//! These are relative delivery estimates, never a clock-synchronized one-way SLA.
use super::{OutPath, Policy, outbound};
use std::time::Duration;

pub(super) fn applies(policy: &Policy, pending: &outbound::Pending) -> bool {
    pending.block.is_some()
        && if policy.fec == super::super::automatic_fec::AUTO {
            pending.small
        } else {
            policy.small_fec_bytes > 0 && (!policy.mixed_fec || pending.small)
        }
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

/// Relative delivery estimate for ranking paths: half the base RTT plus
/// network and local queueing.
pub(super) fn delay_ms(path: &OutPath) -> f64 {
    estimate(path).delay_ms
}

#[derive(Clone, Copy)]
struct Quality {
    loss_rate: f64,
    weight: i32,
}

#[derive(Clone, Copy)]
struct Estimate {
    id: u8,
    delay_ms: f64,
    quality: Option<Quality>,
}

fn estimate(path: &OutPath) -> Estimate {
    let native = path.conn.stats();
    let rtt_ms = path.conn.rtt().as_secs_f64() * 1000.0;
    let feedback = path.quality.lock().expect("quality lock");
    let received = &feedback.snapshot.sender_estimate;
    let now_us = super::quality_time(path);
    let fresh = received
        .updated_us
        .is_some_and(|at| now_us.saturating_sub(at) <= 3_000_000);
    let transit_ms = if fresh {
        received.delay_variation_ms
    } else {
        0.0
    };
    Estimate {
        id: path.id,
        delay_ms: delay_estimate(
            native.path.min_rtt.as_secs_f64() * 1000.0,
            rtt_ms,
            transit_ms,
            path.empty_datagram_space
                .saturating_sub(path.conn.datagram_send_buffer_space()),
            native.path.cwnd,
        ),
        quality: (fresh && received.expected >= 16).then(|| Quality {
            loss_rate: received.loss_rate,
            weight: super::scheduler::weight(received, now_us, rtt_ms),
        }),
    }
}

/// Read the same bounded, local timing heuristic in both experimental arms.
/// This is not a synchronized one-way measurement or independent loss model.
pub(super) fn frontier_sample(
    path: &OutPath,
    frame_bytes: usize,
    used: u8,
) -> Option<super::super::sender_frontier::Sample> {
    let e = estimate(path);
    let quality = e.quality?;
    Some(super::super::sender_frontier::Sample {
        id: path.id,
        finish_ms: e.delay_ms,
        loss: quality.loss_rate,
        immediately_ready: path.conn.close_reason().is_none()
            && path.conn.datagram_send_buffer_space() >= frame_bytes
            && path
                .conn
                .max_datagram_size()
                .is_some_and(|m| m >= frame_bytes),
        already_used: used & (1 << path.id) != 0,
    })
}

pub(super) fn mask(
    paths: &[OutPath],
    eligible: u8,
    remaining: Duration,
    target_ms: u64,
    used: u8,
) -> u8 {
    let estimates: Vec<_> = paths
        .iter()
        .filter(|path| eligible & (1 << path.id) != 0 && path.conn.close_reason().is_none())
        .map(estimate)
        .collect();
    // Small records trade bulk shares for timeliness. Keep diversity among
    // near-equal paths, but never spend more than 20ms (or the smaller remaining
    // admission budget) solely to move a copy onto another path.
    let slack = (target_ms.min(20) as f64).min(remaining.as_secs_f64() * 1000.0);
    select_copy_mask(&estimates, slack, used)
}

/// Ordinary interactive traffic chooses timing before transient pacing credit.
/// The opt-in small-record policy retains its separate loss preference.
pub(super) fn latency_mask(
    paths: &[OutPath],
    eligible: u8,
    remaining: Duration,
    target_ms: u64,
) -> u8 {
    let estimates: Vec<_> = paths
        .iter()
        .filter(|path| eligible & (1 << path.id) != 0 && path.conn.close_reason().is_none())
        .map(estimate)
        .collect();
    let slack = (target_ms.min(20) as f64).min(remaining.as_secs_f64() * 1000.0);
    timing_mask(&estimates, slack)
}

fn timing_mask(estimates: &[Estimate], slack: f64) -> u8 {
    let Some(best) = estimates.iter().map(|path| path.delay_ms).reduce(f64::min) else {
        return 0;
    };
    estimates
        .iter()
        .filter(|path| path.delay_ms <= best + slack)
        .fold(0, |mask, path| mask | (1 << path.id))
}

fn select_mask(estimates: &[Estimate], slack: f64) -> u8 {
    let timely = timing_mask(estimates, slack);
    if timely == 0 {
        return 0;
    }
    // Fresh loss evidence must retain its existing quality preference: a cheap
    // RTT on a lossy path cannot alone exclude a healthier, higher-weight peer.
    // Compare every peer with the fixed timing set, never the expanded result.
    // Unknown anchors and equal loss/weights keep the ordinary timing decision.
    estimates
        .iter()
        .filter(|path| timely & (1 << path.id) == 0)
        .filter(|path| {
            path.quality.is_some_and(|quality| {
                estimates
                    .iter()
                    .filter(|anchor| timely & (1 << anchor.id) != 0)
                    .all(|anchor| {
                        anchor.quality.is_some_and(|other| {
                            quality.loss_rate < other.loss_rate && quality.weight > other.weight
                        })
                    })
            })
        })
        .fold(timely, |mask, path| mask | (1 << path.id))
}

// The original and first copy keep the existing timing choice. Later
// already-budgeted copies may hedge on another route before one further RTT
// of the fastest route (three times its relative one-way estimate). This is
// a bounded ranking heuristic, not a delivery SLA or independent loss model.
fn select_copy_mask(estimates: &[Estimate], slack: f64, used: u8) -> u8 {
    let timely = select_mask(estimates, slack);
    if used.count_ones() < 2 || timely == 0 || timely & !used != 0 {
        return timely;
    }
    let mut earliest = f64::INFINITY;
    let mut loss_ceiling = 1.0f64;
    for anchor in estimates.iter().filter(|p| timely & (1 << p.id) != 0) {
        let Some(quality) = anchor.quality else {
            return timely;
        };
        if !quality.loss_rate.is_finite() || !(0.0..=1.0).contains(&quality.loss_rate) {
            return timely;
        }
        // Match automatic FEC's strongest-loss tier; low-loss traffic keeps
        // its original timing preference instead of spending copies on a
        // slower backup. A later retry can still use the usual small lane.
        if super::super::automatic_fec::target(quality.loss_rate) != 4 {
            return timely;
        }
        earliest = earliest.min(anchor.delay_ms);
        loss_ceiling = loss_ceiling.min(quality.loss_rate);
    }
    estimates
        .iter()
        .filter(|p| used & (1 << p.id) == 0 && p.delay_ms <= earliest * 3.0)
        .filter(|p| {
            p.quality.is_some_and(|q| {
                q.loss_rate.is_finite() && (0.0..=loss_ceiling).contains(&q.loss_rate)
            })
        })
        .fold(timely, |mask, p| mask | (1 << p.id))
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
    fn later_copies_can_hedge_on_unused_routes_before_another_fast_round_trip() {
        let paths = [
            path(0, 35.0, 0.5, 8),
            path(1, 50.0, 0.5, 8),
            path(2, 75.0, 0.5, 8),
            path(3, 100.0, 0.5, 8),
            path(4, 200.0, 0.5, 8),
        ];
        assert_eq!(select_copy_mask(&paths, 20.0, 0), 3);
        assert_eq!(select_copy_mask(&paths, 20.0, 1), 3);
        assert_eq!(
            select_copy_mask(&paths, 20.0, 3),
            15,
            "after two fast distinct routes, remaining copies should reach useful unused routes rather than repeat both fast routes"
        );
        assert_eq!(
            select_copy_mask(&paths, 20.0, 5),
            3,
            "an unused timely route keeps its ordinary preference"
        );
    }

    #[test]
    fn low_loss_copies_keep_the_original_timing_preference() {
        let paths = [
            path(0, 35.0, 0.01, 8),
            path(1, 50.0, 0.01, 8),
            path(2, 75.0, 0.01, 8),
            path(3, 100.0, 0.01, 8),
        ];
        assert_eq!(select_copy_mask(&paths, 20.0, 3), 3);
    }

    #[test]
    fn later_copy_hedges_require_fresh_no_worse_loss_and_bounded_arrival() {
        let mut unknown = path(2, 75.0, 0.1, 8);
        unknown.quality = None;
        let paths = [
            path(0, 35.0, 0.1, 8),
            path(1, 50.0, 0.1, 8),
            unknown,
            path(3, 90.0, 0.2, 8),
            path(4, 200.0, 0.1, 8),
            path(5, 80.0, 0.05, 8),
        ];
        assert_eq!(select_copy_mask(&paths, 20.0, 3), 3 | (1 << 5));
        let mut unknown_anchor = paths;
        unknown_anchor[0].quality = None;
        assert_eq!(select_copy_mask(&unknown_anchor, 20.0, 3), 3);
    }

    #[test]
    fn receiver_queue_and_rtt_excess_are_not_double_counted() {
        assert_eq!(delay_estimate(120.0, 400.0, 248.0, 0, 12_000), 340.0);
        assert_eq!(delay_estimate(120.0, 122.0, 248.0, 0, 12_000), 308.0);
        assert_eq!(delay_estimate(120.0, 122.0, 1.0, 0, 12_000), 62.0);
        assert_eq!(delay_estimate(120.0, 120.0, 0.0, 1200, 12_000), 72.0);
    }

    fn path(id: u8, delay_ms: f64, loss_rate: f64, weight: i32) -> Estimate {
        Estimate {
            id,
            delay_ms,
            quality: Some(Quality { loss_rate, weight }),
        }
    }

    #[test]
    fn small_quality_guard_restores_only_fresh_strictly_better_peers() {
        let anchor = path(0, 5.0, 0.3, 8);
        assert_eq!(
            select_mask(
                &[
                    anchor,
                    path(1, 60.0, 0.0, 15),
                    path(2, 80.0, 0.0, 8),
                    path(3, 80.0, 0.3, 15),
                    path(4, 80.0, 0.4, 16),
                ],
                20.0,
            ),
            3,
            "lower loss and higher existing weight are both required"
        );
        let mut unknown = path(1, 60.0, 0.0, 15);
        unknown.quality = None;
        assert_eq!(select_mask(&[anchor, unknown], 20.0), 1);
    }

    #[test]
    fn small_quality_guard_compares_every_original_timing_anchor() {
        let anchor = path(0, 5.0, 0.3, 8);
        let healthy = path(2, 60.0, 0.0, 15);
        let mut second = path(1, 10.0, 0.3, 8);
        assert_eq!(select_mask(&[anchor, second, healthy], 20.0), 7);
        second.quality = None;
        assert_eq!(select_mask(&[anchor, second, healthy], 20.0), 3);
        second.quality = Some(Quality {
            loss_rate: 0.0,
            weight: 8,
        });
        assert_eq!(select_mask(&[anchor, second, healthy], 20.0), 3);
    }

    #[test]
    fn small_quality_guard_uses_fixed_anchors_independent_of_peer_order() {
        let anchor = path(0, 5.0, 0.4, 5);
        let better = path(1, 60.0, 0.2, 10);
        let intermediate = path(2, 80.0, 0.3, 8);
        assert_eq!(select_mask(&[anchor, better, intermediate], 20.0), 7);
        assert_eq!(select_mask(&[intermediate, better, anchor], 20.0), 7);
    }
}
