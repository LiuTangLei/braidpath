//! Independent probe service is bounded exploration credit, never path capacity.
use super::{CONTROL_US, FRESH_US, LossEvidence, Observation, PROBE_US, service};
use crate::runtime::quality;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Reference {
    pub observed_us: u64,
    pub receiver_span_us: u64,
    pub local_span_us: u64,
    pub local_started_us: u64,
    pub admitted_probe_symbols: u64,
    pub measured_body_bps: f64,
    /// Conservative wire allowance: at most half the received probe BODY rate.
    pub budget_bps: u64,
    pub probe_loss_expected: u64,
    pub probe_loss_lost: u64,
}
impl Reference {
    pub(super) fn covers_loss(&self, expected: u128, lost: u128) -> bool {
        let (Ok(expected), Ok(lost)) = (u64::try_from(expected), u64::try_from(lost)) else {
            return false;
        };
        expected >= 16 && self.within_count_resolution(expected, lost)
    }
    pub(super) fn within_count_resolution(&self, expected: u64, lost: u64) -> bool {
        expected > 0
            && self.probe_loss_expected >= 64
            && lost <= expected
            && // Different finite prefixes have one-symbol count resolution.
            // This does not change the recorded counts or assign missing IDs.
            u128::from(lost.saturating_sub(1)) * u128::from(self.probe_loss_expected)
                <= u128::from(self.probe_loss_lost) * u128::from(expected)
    }
}

#[derive(Default)]
pub(super) struct Window {
    service: service::Window,
    loss: LossEvidence,
    last_number: u64,
    valid: bool,
    previous_service: Option<(f64, u64)>,
    budget_bps: Option<u64>,
}
impl Window {
    pub(super) fn observe(&mut self, probe: &quality::Snapshot, now_us: u64, generation: u64) {
        let estimate = &probe.sender_estimate;
        let positive_age = estimate
            .delivered_updated_us
            .and_then(|at| probe.sampled_us.checked_sub(at));
        let loss_age = estimate
            .updated_us
            .and_then(|at| probe.sampled_us.checked_sub(at));
        self.valid = probe.generation == generation
            && positive_age.is_some_and(|age| age <= CONTROL_US)
            && loss_age.is_some_and(|age| age <= PROBE_US)
            && estimate.sample_span_us > 0
            && estimate.sample_span_us <= FRESH_US
            && estimate
                .delivered_bps
                .is_some_and(|bps| bps.is_finite() && bps > 0.0)
            && probe.sent_symbols.checked_mul(972) == Some(probe.sent_bytes)
            && estimate.received_bytes <= probe.sent_bytes
            && estimate.expected <= probe.sent_symbols
            && estimate.lost <= estimate.expected
            && estimate.report_time_us.is_some();
        if !self.valid || estimate.report_number <= self.last_number {
            return;
        }
        self.last_number = estimate.report_number;
        self.service.observe(
            estimate.report_number,
            estimate.report_time_us,
            estimate.received_bytes,
            now_us,
            Some((probe.sent_bytes, probe.sent_symbols)),
        );
        if let Some(sample) = self
            .service
            .discovery_with_counts(now_us, 32, 16 * 972)
            .filter(|sample| sample.observed_us == now_us)
        {
            let lower = self
                .previous_service
                .filter(|(_, at)| now_us.checked_sub(*at).is_some_and(|age| age <= FRESH_US))
                .map_or(sample.bps, |(bps, _)| bps.min(sample.bps));
            self.budget_bps = Some((lower * 0.5) as u64);
            self.previous_service = Some((sample.bps, now_us));
        }
        self.loss.observe(
            &Observation {
                now_us,
                report_number: estimate.report_number,
                feedback_age_us: loss_age,
                finalized_expected: Some(estimate.expected),
                finalized_lost: Some(estimate.lost),
                ..Default::default()
            },
            true,
        );
    }
    pub(super) fn reference(&self, now_us: u64) -> Option<Reference> {
        if !self.valid {
            return None;
        }
        let sample = self.service.discovery_with_counts(now_us, 32, 16 * 972)?;
        let admission = sample.admission?;
        let (expected, lost) = self.loss.counts();
        if now_us.checked_sub(sample.observed_us)? > CONTROL_US
            || admission.span_us < PROBE_US
            || admission.symbols < 32
            || sample.bps < 16.0 * 972.0 * 8_000_000.0 / sample.span_us as f64
            || expected < 64
        {
            return None;
        }
        Some(Reference {
            observed_us: sample.observed_us,
            receiver_span_us: sample.span_us,
            local_span_us: admission.span_us,
            local_started_us: admission.started_us,
            admitted_probe_symbols: admission.symbols,
            measured_body_bps: sample.bps,
            budget_bps: self.budget_bps?.min((sample.bps * 0.5) as u64),
            probe_loss_expected: u64::try_from(expected).ok()?,
            probe_loss_lost: u64::try_from(lost).ok()?,
        })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(in crate::runtime::adaptive) fn probe(step: u64) -> quality::Snapshot {
        let now = step * 100_000;
        let sent = step * 50;
        let finalized = step.saturating_sub(5) / 5 * 250;
        let bytes = (sent - sent * 2 / 3) * 972;
        let previous = sent.saturating_sub(50);
        let previous_bytes = (previous - previous * 2 / 3) * 972;
        quality::Snapshot {
            generation: 7,
            sampled_us: now,
            sent_symbols: sent,
            sent_bytes: sent * 972,
            sender_estimate: quality::Estimate {
                expected: finalized,
                lost: finalized * 2 / 3,
                received: finalized - finalized * 2 / 3,
                report_number: step + 1,
                report_time_us: Some(9_000_000_000 + now),
                received_bytes: bytes,
                delivered_bps: Some((bytes - previous_bytes) as f64 * 80.0),
                sample_span_us: 100_000,
                updated_us: Some(now - now % PROBE_US),
                delivered_updated_us: Some(now),
                ..Default::default()
            },
            ..Default::default()
        }
    }
    fn window() -> Window {
        let mut window = Window::default();
        for step in 0..=30 {
            window.observe(&probe(step), step * 100_000, 7);
        }
        window
    }
    #[test]
    fn sufficient_probe_counts_in_a_longer_bounded_interval_are_not_hidden_by_500ms_sampling() {
        let mut window = Window::default();
        for step in 0..=30 {
            let mut sample = probe(step);
            let sent = step * 6;
            let expected = step.saturating_sub(5) / 5 * 30;
            sample.sent_symbols = sent;
            sample.sent_bytes = sent * 972;
            sample.sender_estimate.expected = expected;
            sample.sender_estimate.lost = expected * 2 / 3;
            sample.sender_estimate.received = expected / 3;
            sample.sender_estimate.received_bytes = step * 2 * 972;
            sample.sender_estimate.delivered_bps = Some(155_520.0);
            window.observe(&sample, step * 100_000, 7);
        }
        // 500ms holds only 30 admissions and 10 bodies; 800ms holds 48/16.
        let reference = window
            .reference(3_000_000)
            .expect("qualified bounded interval");
        assert_eq!(reference.receiver_span_us, 800_000);
        assert_eq!(reference.local_span_us, 800_000);
        assert_eq!(reference.admitted_probe_symbols, 48);
        assert_eq!(reference.budget_bps, 77_760);
        assert!(reference.probe_loss_expected >= 64);
        assert!(window.reference(3_200_001).is_none(), "no freshness loan");
    }
    #[test]
    fn cumulative_probe_counts_cannot_borrow_delivery_older_than_the_existing_horizon() {
        let mut window = Window::default();
        for step in 0..=200 {
            let mut sample = probe(step);
            sample.sent_symbols = step * 6;
            sample.sent_bytes = sample.sent_symbols * 972;
            let expected = step.saturating_sub(5) / 5 * 30;
            sample.sender_estimate.expected = expected;
            sample.sender_estimate.received = expected / 12;
            sample.sender_estimate.lost = expected - expected / 12;
            sample.sender_estimate.received_bytes = step / 2 * 972;
            sample.sender_estimate.delivered_bps = Some(if step % 2 == 0 { 77_760.0 } else { 0.0 });
            window.observe(&sample, step * 100_000, 7);
        }
        // One hundred cumulative received bodies exist, but at most fifteen
        // are in the three-second horizon. Never relax the sixteen-body floor.
        assert!(window.reference(20_000_000).is_none());
    }
    #[test]
    fn only_paired_positive_probe_intervals_provide_conservative_credit() {
        let window = window();
        let reference = window.reference(3_000_000).unwrap();
        assert!(reference.receiver_span_us >= PROBE_US);
        assert!(reference.local_span_us >= PROBE_US);
        assert!(reference.admitted_probe_symbols >= 32);
        assert!(reference.budget_bps as f64 <= reference.measured_body_bps * 0.5);
        assert!(reference.covers_loss(48, 32));
        assert!(!reference.covers_loss(48, 40));
        assert!(!reference.covers_loss(16, 16));
        assert!(!reference.covers_loss(0, 0));
    }
    #[test]
    fn repeats_staleness_zero_service_future_time_and_foreign_generation_cannot_renew_credit() {
        let mut repeated = window();
        let mut evidence = probe(30);
        evidence.sampled_us += CONTROL_US;
        repeated.observe(&evidence, 3_000_000 + CONTROL_US, 7);
        assert_eq!(
            repeated
                .reference(3_000_000 + CONTROL_US)
                .unwrap()
                .observed_us,
            3_000_000
        );
        assert!(repeated.reference(3_000_000 + CONTROL_US + 1).is_none());
        for invalid in 0..5 {
            let mut window = window();
            let mut evidence = probe(31);
            match invalid {
                0 => {
                    evidence.sender_estimate.delivered_updated_us =
                        Some(evidence.sampled_us - CONTROL_US - 1)
                }
                1 => evidence.sender_estimate.delivered_bps = Some(0.0),
                2 => evidence.sender_estimate.delivered_updated_us = Some(evidence.sampled_us + 1),
                3 => evidence.generation = 8,
                _ => evidence.sender_estimate.sample_span_us = 0,
            }
            window.observe(&evidence, 3_100_000, 7);
            assert!(window.reference(3_100_000).is_none(), "invalid={invalid}");
        }
    }
}
