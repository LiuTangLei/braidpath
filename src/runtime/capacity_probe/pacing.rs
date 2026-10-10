//! Probe-data allowance follows sustained demand and fresh path delay evidence.
use crate::runtime::outbound;
use serde::Serialize;
const LOW_BPS: u64 = 64_000;
const GROWTH_US: u64 = 500_000;
const BRAKE_US: u64 = 100_000;
const FRESH_US: u64 = 3_000_000;
#[derive(Clone, Default)]
pub struct Demand {
    pub now_us: u64,
    pub generation: u64,
    pub backlog: bool,
    pub blocked: bool,
    pub queue_ms: f64,
    pub target_ms: f64,
    pub rtt_ms: Option<f64>,
    pub rtt_age_us: Option<u64>,
    pub rtt_sample_id: u64,
    pub received_probe_bytes: u64,
    pub positive_probe_age_us: Option<u64>,
}
#[derive(Clone, Default, Serialize)]
pub struct RateSnapshot {
    pub generation: Option<u64>,
    pub pacing_bps: u64,
    pub increases: u64,
    pub reductions: u64,
    pub last_change_us: u64,
    pub backlog_since_us: Option<u64>,
}
pub struct Controller {
    pacer: outbound::Pacer,
    state: RateSnapshot,
    last_observed_us: Option<u64>,
    idle_since_us: Option<u64>,
    blocked_since_us: Option<u64>,
    last_rtt_used: u64,
    last_growth_bytes: u64,
    last_clock_us: u64,
    last_rtt_request_us: Option<u64>,
    rtt_request_interval_us: u64,
}
impl Controller {
    pub fn new(ceiling: u64) -> Self {
        Self {
            pacer: outbound::Pacer::new(ceiling.min(LOW_BPS), 2178),
            state: RateSnapshot {
                pacing_bps: ceiling.min(LOW_BPS),
                ..Default::default()
            },
            last_observed_us: None,
            idle_since_us: None,
            blocked_since_us: None,
            last_rtt_used: 0,
            last_growth_bytes: 0,
            last_clock_us: 0,
            last_rtt_request_us: None,
            rtt_request_interval_us: BRAKE_US,
        }
    }
    pub fn observe(&mut self, demand: &Demand, ceiling: u64) {
        let now = demand.now_us;
        if now < self.last_clock_us {
            return;
        }
        if self.state.generation != Some(demand.generation) {
            *self = Self::new(ceiling);
            self.state.generation = Some(demand.generation);
            self.state.last_change_us = now;
            self.last_rtt_used = demand.rtt_sample_id;
            self.last_growth_bytes = demand.received_probe_bytes;
            self.pacer = outbound::Pacer::new(0, 2178);
            self.pacer.set_rate(now, self.state.pacing_bps);
        }
        if self
            .last_observed_us
            .is_some_and(|old| now - old > FRESH_US)
        {
            self.state.backlog_since_us = None;
            self.idle_since_us = None;
            self.blocked_since_us = None;
        }
        self.last_observed_us = Some(now);
        self.last_clock_us = now;
        if demand.backlog {
            self.state.backlog_since_us.get_or_insert(now);
            self.idle_since_us = None;
        } else {
            self.state.backlog_since_us = None;
            self.idle_since_us.get_or_insert(now);
        }
        if demand.blocked {
            self.blocked_since_us.get_or_insert(now);
        } else {
            self.blocked_since_us = None;
        }
        let minimum = ceiling.min(LOW_BPS);
        let previous = self.state.pacing_bps;
        // A larger allocation must restart a zero/small pilot without needing
        // delivery from packets that its old allowance cannot send. This is a
        // bounded configured startup rate, not measured capacity or free tokens.
        let mut next = previous.clamp(minimum, ceiling);
        let rtt = demand.rtt_ms.filter(|rtt| rtt.is_finite() && *rtt > 0.0);
        self.rtt_request_interval_us =
            rtt.map_or(BRAKE_US, |rtt| ((rtt * 500.0).ceil() as u64).max(BRAKE_US));
        let request_us = demand
            .rtt_age_us
            .filter(|age| *age <= 200_000)
            .zip(rtt)
            .and_then(|(age, rtt)| {
                now.checked_sub(age)?
                    .checked_sub((rtt * 1000.0).ceil() as u64)
            });
        let new_reply = demand.rtt_sample_id > self.last_rtt_used
            && request_us.is_some_and(|at| at > self.state.last_change_us);
        let valid_queue = demand.queue_ms.is_finite()
            && demand.queue_ms >= 0.0
            && demand.target_ms.is_finite()
            && demand.target_ms > 0.0;
        let blocked = self.blocked_since_us.is_some_and(|at| now - at >= BRAKE_US);
        if self.idle_since_us.is_some_and(|at| now - at >= GROWTH_US) {
            next = next.min(minimum);
        } else if (blocked
            || (valid_queue && demand.queue_ms > demand.target_ms * 0.5 && new_reply))
            && now - self.state.last_change_us >= BRAKE_US
        {
            next = (next * 4 / 5).max(minimum);
        } else if next == previous
            && self
                .state
                .backlog_since_us
                .is_some_and(|at| now - at >= GROWTH_US)
            && now - self.state.last_change_us >= GROWTH_US
            && new_reply
            && valid_queue
            && demand.queue_ms <= demand.target_ms * 0.25
            && !demand.blocked
            && demand
                .positive_probe_age_us
                .is_some_and(|age| age <= GROWTH_US)
            && demand.received_probe_bytes > self.last_growth_bytes
        {
            let headroom = (demand.target_ms * 0.8 - demand.queue_ms).max(0.0);
            let gain = 1.0 + (headroom / (rtt.unwrap() + 100.0)).min(0.25);
            next = ((next as f64 * gain) as u64).min(ceiling);
        }
        if next != previous {
            if next > previous {
                self.state.increases = self.state.increases.saturating_add(1);
                self.last_growth_bytes = demand.received_probe_bytes;
            } else {
                self.state.reductions = self.state.reductions.saturating_add(1);
            }
            self.state.last_change_us = now;
            self.last_rtt_used = demand.rtt_sample_id;
            self.state.pacing_bps = next;
            self.pacer.set_rate(now, next);
        }
    }
    pub fn available(&mut self, now: u64, cost: usize) -> bool {
        if self.state.generation.is_none() || now < self.last_clock_us {
            return false;
        }
        self.last_clock_us = now;
        self.pacer.refill(now);
        self.pacer.available(cost)
    }
    pub fn admitted(&mut self, cost: usize) {
        self.pacer.spend(cost);
    }
    pub fn snapshot(&self) -> RateSnapshot {
        self.state.clone()
    }
    pub fn rtt_request_due(&self, now: u64) -> bool {
        // Measurement must not depend on the fresh reply it is trying to obtain.
        // Keep the existing health cadence when business demand is absent.
        now >= self.last_clock_us
            && self.state.pacing_bps > 0
            && self.state.generation.is_some()
            && self.last_observed_us.is_some_and(|at| now - at <= 200_000)
            && self
                .state
                .backlog_since_us
                .is_some_and(|at| now - at >= GROWTH_US)
            && self
                .last_rtt_request_us
                .is_none_or(|at| now.saturating_sub(at) >= self.rtt_request_interval_us)
    }
    pub fn rtt_request_admitted(&mut self, now: u64) {
        if now >= self.last_clock_us {
            self.last_clock_us = now;
            self.last_rtt_request_us = Some(now);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn demand(now: u64, backlog: bool) -> Demand {
        Demand {
            now_us: now,
            generation: 7,
            backlog,
            queue_ms: 0.0,
            target_ms: 20.0,
            rtt_ms: Some(80.0),
            rtt_age_us: Some(0),
            rtt_sample_id: now / 100_000 + 1,
            received_probe_bytes: now / 10,
            positive_probe_age_us: Some(0),
            ..Default::default()
        }
    }
    #[test]
    fn restored_probe_allocation_resumes_at_the_bounded_startup_rate_without_credit() {
        for initial_ceiling in [0, LOW_BPS / 4] {
            let mut controller = Controller::new(initial_ceiling);
            for now in (0..=500_000).step_by(1000) {
                if now % 100_000 == 0 {
                    let mut sample = demand(now, true);
                    sample.received_probe_bytes = 0;
                    sample.positive_probe_age_us = None;
                    controller.observe(&sample, initial_ceiling);
                }
                while controller.available(now, 1082) {
                    controller.admitted(1082);
                }
            }
            let mut sample = demand(500_000, true);
            sample.received_probe_bytes = 0;
            sample.positive_probe_age_us = None;
            controller.observe(&sample, 4_375_000);
            assert_eq!(controller.snapshot().pacing_bps, LOW_BPS);
            assert!(
                !controller.available(500_000, 1082),
                "rate restoration minted credit"
            );
        }
    }

    #[test]
    fn allocation_restore_cannot_spend_a_reply_from_the_smaller_pilot() {
        let mut controller = Controller::new(LOW_BPS / 4);
        let mut symbols = 0;
        let mut last_arrival = 0;
        for now in (0..=1_000_000).step_by(1000) {
            if now % 100_000 == 0 {
                let mut sample = demand(now, true);
                sample.received_probe_bytes = 0;
                sample.positive_probe_age_us = None;
                controller.observe(&sample, LOW_BPS / 4);
            }
            while controller.available(now, 1082) {
                controller.admitted(1082);
                symbols += 1;
                last_arrival = now + 80_000;
            }
        }
        assert_eq!(symbols, 1);
        let mut sample = demand(1_000_000, true);
        sample.received_probe_bytes = symbols * 972;
        sample.positive_probe_age_us = Some(sample.now_us - last_arrival);
        controller.observe(&sample, 4_375_000);
        assert_eq!(controller.snapshot().pacing_bps, LOW_BPS);
    }

    #[test]
    fn sustained_measurement_requests_rtt_even_without_recent_reply() {
        let mut controller = Controller::new(4_375_000);
        for now in (0..=500_000).step_by(100_000) {
            let mut sample = demand(now, true);
            sample.rtt_age_us = Some(500_000);
            controller.observe(&sample, 4_375_000);
        }
        assert!(controller.rtt_request_due(500_000));
        // A rejected send or repeated query spends neither the request nor data allowance.
        assert!(controller.rtt_request_due(500_000));
        controller.rtt_request_admitted(500_000);
        assert!(!controller.rtt_request_due(599_999));
        assert!(controller.rtt_request_due(600_000));
        controller.rtt_request_admitted(600_000);
        assert!(!controller.rtt_request_due(600_000));
        assert_eq!(controller.snapshot().pacing_bps, LOW_BPS);
    }
    #[test]
    fn independent_rtt_request_needs_current_continuous_demand_and_live_generation() {
        let mut controller = Controller::new(4_375_000);
        assert!(!controller.rtt_request_due(500_000));
        for now in (0..=500_000).step_by(100_000) {
            controller.observe(&demand(now, true), 4_375_000);
        }
        assert!(controller.rtt_request_due(500_000));
        assert!(!controller.rtt_request_due(499_999));
        assert!(!controller.rtt_request_due(700_001));
        controller.observe(&demand(600_000, false), 4_375_000);
        assert!(!controller.rtt_request_due(600_000));
        let mut next = demand(700_000, true);
        next.generation = 8;
        controller.observe(&next, 4_375_000);
        assert!(!controller.rtt_request_due(700_000));
        for now in (800_000..=1_200_000).step_by(100_000) {
            next.now_us = now;
            controller.observe(&next, 4_375_000);
        }
        assert!(controller.rtt_request_due(1_200_000));
        controller.observe(&next, 0);
        assert!(!controller.rtt_request_due(1_200_000));
    }
    #[test]
    fn sparse_traffic_keeps_independent_probe_data_low_despite_configured_high_ceiling() {
        let mut controller = Controller::new(4_375_000);
        let mut bytes = 0;
        for now in (0..=2_000_000).step_by(1000) {
            if now % 100_000 == 0 {
                controller.observe(&demand(now, false), 4_375_000);
            }
            while controller.available(now, 1082) {
                controller.admitted(1082);
                bytes += 1082;
            }
        }
        assert!(
            bytes <= LOW_BPS * 2 / 8,
            "idle probe bytes={bytes}; high configured allowance must not become continuous load"
        );
        assert_eq!(controller.snapshot().pacing_bps, LOW_BPS);
    }
    #[test]
    fn sustained_demand_needs_new_delivery_and_post_change_round_trips_to_grow() {
        for missing in 0..3 {
            let mut controller = Controller::new(4_375_000);
            for now in (0..=20_000_000).step_by(100_000) {
                let mut sample = demand(now, true);
                if missing == 1 {
                    sample.received_probe_bytes = 0;
                    sample.positive_probe_age_us = None;
                }
                if missing == 2 {
                    sample.rtt_sample_id = 1;
                }
                controller.observe(&sample, 4_375_000);
            }
            if missing == 0 {
                assert!(controller.snapshot().pacing_bps > LOW_BPS * 4);
                assert!(controller.snapshot().pacing_bps <= 4_375_000);
            } else {
                assert_eq!(controller.snapshot().pacing_bps, LOW_BPS);
            }
        }
    }
    #[test]
    fn queue_blocking_idle_and_new_generation_remove_old_probe_allowance() {
        for trigger in 0..4 {
            let mut controller = Controller::new(4_375_000);
            for now in (0..=20_000_000).step_by(100_000) {
                controller.observe(&demand(now, true), 4_375_000);
            }
            let before = controller.snapshot().pacing_bps;
            for now in (20_100_000..=21_000_000).step_by(100_000) {
                let mut sample = demand(now, true);
                match trigger {
                    0 => sample.queue_ms = 40.0,
                    1 => sample.blocked = true,
                    2 => sample.backlog = false,
                    _ => sample.generation = 8,
                }
                controller.observe(&sample, 4_375_000);
            }
            assert!(
                controller.snapshot().pacing_bps < before,
                "trigger={trigger}"
            );
        }
    }
    #[test]
    fn rate_changes_generations_and_backward_time_cannot_mint_send_credit() {
        let mut controller = Controller::new(4_375_000);
        assert!(!controller.available(1_000_000, 1082));
        controller.observe(&demand(1_000_000, true), 4_375_000);
        assert!(!controller.available(1_000_000, 1082));
        assert!(controller.available(1_200_000, 1082));
        controller.admitted(1082);
        assert!(!controller.available(1_000_000, 1082));
        controller.observe(&demand(1_000_000, true), 8_750_000);
        assert_eq!(controller.snapshot().pacing_bps, LOW_BPS);
        let mut new_generation = demand(1_300_000, true);
        new_generation.generation = 8;
        controller.observe(&new_generation, 4_375_000);
        assert!(!controller.available(1_300_000, 1082));
        controller.observe(&demand(1_400_000, true), 8000);
        assert_eq!(controller.snapshot().pacing_bps, 8000);
    }
}
