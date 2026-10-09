//! Grant coordination tests use real controller observations and admissions.
//! No controller internals are overwritten to manufacture a ready trial.
use super::{MAX_PATHS, ReprobePath, adaptive, grant_reprobes};

fn two_ready() -> ([adaptive::PathController; MAX_PATHS], u64) {
    let mut controllers = std::array::from_fn(|_| adaptive::PathController::new(20_000_000, 20));
    let mut admitted = [0u64; 2];
    let mut delivered = [0u64; 2];
    let mut report_bytes = [0u64; 2];
    let mut report_expected = [0u64; 2];
    let mut report_symbols = [0u64; 2];
    let mut report_rate = [0.0; 2];
    for now in (0..20_000_000u64).step_by(100) {
        if now > 0 && now.is_multiple_of(500_000) {
            for id in 0..2 {
                report_rate[id] = (delivered[id] - report_bytes[id]) as f64 * 16.0;
                report_bytes[id] = delivered[id];
                report_symbols[id] = admitted[id] - report_expected[id];
                report_expected[id] = admitted[id];
            }
        }
        if now.is_multiple_of(100_000) {
            for id in 0..2 {
                let report = now / 500_000;
                controllers[id].observe(&adaptive::Observation {
                    now_us: now,
                    generation: 7,
                    report_number: report,
                    feedback_age_us: (report > 0).then_some(now % 500_000),
                    positive_delivery_age_us: (report > 0).then_some(now % 500_000),
                    delivered_bytes: report_bytes[id],
                    delivered_bps: (report > 0).then_some(report_rate[id]),
                    delivery_sample_span_us: if report > 0 { 500_000 } else { 0 },
                    delivery_report_time_us: (report > 0).then_some(100_000_000 + report * 500_000),
                    reprobe_enabled: true,
                    finalized_expected: Some(report_expected[id]),
                    finalized_lost: Some(report_expected[id] / 5),
                    feedback_sample_symbols: report_symbols[id],
                    loss_sample_rate: Some(0.2),
                    rtt_ms: 80.0,
                    probe_latest_rtt_ms: Some(80.0),
                    probe_sample_id: report + 1,
                    probe_age_us: Some(now % 500_000),
                    offered_backlog: true,
                    ..Default::default()
                });
            }
            if controllers[..2]
                .iter()
                .all(|c| c.reprobe_candidate(now).is_some())
            {
                return (controllers, now);
            }
        }
        for id in 0..2 {
            while controllers[id].allow(now, 1200, 0.0) {
                controllers[id].admitted_symbol(now, 1200, 1000);
                admitted[id] += 1;
                if !admitted[id].is_multiple_of(5) {
                    delivered[id] += 1000;
                }
            }
        }
    }
    panic!("actual exercised, low-queue controllers did not become trial candidates");
}

fn paths(group1: u8) -> [ReprobePath; 2] {
    [
        ReprobePath { id: 0, group: 0 },
        ReprobePath {
            id: 1,
            group: group1,
        },
    ]
}

#[test]
fn reprobe_group_and_aggregate_saturation_prevent_additional_rates() {
    for group_saturated in [false, true] {
        let (mut controllers, now) = two_ready();
        let sum: u64 = controllers[..2]
            .iter()
            .map(|c| c.decision(now).pacing_bps)
            .sum();
        let original: Vec<_> = controllers[..2]
            .iter()
            .map(|c| c.decision(now).pacing_bps)
            .collect();
        let mut caps = [20_000_000; MAX_PATHS];
        if group_saturated {
            caps[0] = sum;
        }
        let mut cursor = 0;
        grant_reprobes(
            &paths(0),
            &mut controllers,
            if group_saturated { 20_000_000 } else { sum },
            &caps,
            &mut cursor,
            now,
        );
        assert!(controllers[..2].iter().all(|c| !c.reprobe_active()));
        assert_eq!(
            original,
            controllers[..2]
                .iter()
                .map(|c| c.decision(now).pacing_bps)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            cursor, 0,
            "a denied grant does not consume the next path's turn"
        );
    }
}

#[test]
fn reprobe_only_one_trial_per_group_and_removed_owner_cannot_block_live_path() {
    let (mut controllers, now) = two_ready();
    let mut cursor = 0;
    grant_reprobes(
        &paths(0),
        &mut controllers,
        20_000_000,
        &[20_000_000; MAX_PATHS],
        &mut cursor,
        now,
    );
    assert!(controllers[0].reprobe_active());
    assert!(!controllers[1].reprobe_active());
    assert_eq!(cursor, 1);
    // The sender supplies only current open paths. A removed path may remain
    // in the fixed controller array, but owns neither a live lease nor budget.
    let live = [ReprobePath { id: 1, group: 0 }];
    let request = controllers[1].reprobe_candidate(now).unwrap();
    grant_reprobes(
        &live,
        &mut controllers,
        request.trial_bps,
        &[request.trial_bps; MAX_PATHS],
        &mut cursor,
        now,
    );
    assert!(controllers[1].reprobe_active());
    assert_eq!(controllers[1].decision(now).pacing_bps, request.trial_bps);
}

#[test]
fn reprobe_different_groups_share_aggregate_headroom() {
    let (mut controllers, now) = two_ready();
    let a = controllers[0].reprobe_candidate(now).unwrap();
    let b = controllers[1].reprobe_candidate(now).unwrap();
    let aggregate = a.trial_bps + b.baseline_bps;
    let mut cursor = 0;
    grant_reprobes(
        &paths(1),
        &mut controllers,
        aggregate,
        &[20_000_000; MAX_PATHS],
        &mut cursor,
        now,
    );
    assert!(controllers[0].reprobe_active());
    assert!(!controllers[1].reprobe_active());
    assert!(
        controllers[..2]
            .iter()
            .map(|c| c.decision(now).pacing_bps)
            .sum::<u64>()
            <= aggregate
    );
}

#[test]
fn reprobe_generation_reset_releases_group_to_next_candidate() {
    let (mut controllers, now) = two_ready();
    let mut cursor = 0;
    grant_reprobes(
        &paths(0),
        &mut controllers,
        20_000_000,
        &[20_000_000; MAX_PATHS],
        &mut cursor,
        now,
    );
    assert!(controllers[0].reprobe_active());
    let later = now + 100_000;
    controllers[0].observe(&adaptive::Observation {
        now_us: later,
        generation: 8,
        reprobe_enabled: true,
        rtt_ms: 80.0,
        probe_latest_rtt_ms: Some(80.0),
        probe_sample_id: 1,
        probe_age_us: Some(0),
        offered_backlog: true,
        ..Default::default()
    });
    assert!(!controllers[0].reprobe_active());
    assert!(controllers[0].reprobe_candidate(later).is_none());
    grant_reprobes(
        &paths(0),
        &mut controllers,
        20_000_000,
        &[20_000_000; MAX_PATHS],
        &mut cursor,
        later,
    );
    assert!(
        controllers[1].reprobe_active(),
        "the rotating grant reaches the other still-fresh candidate"
    );
}
