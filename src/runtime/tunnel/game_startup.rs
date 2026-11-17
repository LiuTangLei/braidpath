//! A shared first-flight allowance; ordinary path congestion brakes stay active.
use super::{MAX_PATHS, quality};

const INITIAL_BPS: u64 = 4_000_000;
const SAMPLE_US: u64 = 200_000;
const IDLE_US: u64 = 500_000;

#[derive(Clone, Copy, Debug)]
pub(super) struct Report {
    pub path: u8,
    pub generation: u64,
    pub bytes: u64,
    pub symbols: u64,
}

pub(super) struct Budget {
    rate_bps: u64,
    baseline: [Option<Report>; MAX_PATHS],
    sampled_us: u64,
    last_demand_us: Option<u64>,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            rate_bps: INITIAL_BPS,
            baseline: [None; MAX_PATHS],
            sampled_us: 0,
            last_demand_us: None,
        }
    }
}

impl Budget {
    pub fn rate_bps(&self) -> u64 {
        self.rate_bps
    }

    pub fn observe(&mut self, now_us: u64, demand: bool, reports: &[Report]) -> u64 {
        let mut current = [None; MAX_PATHS];
        for report in reports {
            current[usize::from(report.path)] = Some(*report);
        }
        let generations_changed = current
            .iter()
            .zip(&self.baseline)
            .any(|(a, b)| a.map(|v| v.generation) != b.map(|v| v.generation));
        let idle = self
            .last_demand_us
            .is_some_and(|last| now_us.saturating_sub(last) >= IDLE_US);
        if generations_changed || idle || self.last_demand_us.is_none() {
            self.rate_bps = INITIAL_BPS;
            self.baseline = current;
            self.sampled_us = now_us;
            self.last_demand_us = None;
        }
        if !demand {
            return self.rate_bps;
        }
        self.last_demand_us = Some(now_us);
        let span = now_us.saturating_sub(self.sampled_us);
        if span < SAMPLE_US {
            return self.rate_bps;
        }
        let mut delivered = 0u128;
        for (a, b) in current.iter().zip(&self.baseline) {
            if let (Some(a), Some(b)) = (a, b) {
                // Symbols exclude the feedback envelope and transport cost.
                let overhead = (quality::HEADER + 9 + 80) as u128;
                delivered += u128::from(a.bytes.saturating_sub(b.bytes))
                    + u128::from(a.symbols.saturating_sub(b.symbols)) * overhead;
            }
        }
        let measured = delivered * 8_000_000 / u128::from(span);
        // This only qualifies startup growth. Loss on one route is not
        // evidence that all routes share a bottleneck. Existing path and
        // qualified shared-loss controllers retain the congestion brakes.
        let trial = (measured * 5 / 4).min(u128::from(self.rate_bps) * 5 / 4);
        self.rate_bps = self.rate_bps.max(trial.min(u128::from(u64::MAX)) as u64);
        self.baseline = current;
        self.sampled_us = now_us;
        self.rate_bps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reports(bytes: u64) -> Vec<Report> {
        (0..4)
            .map(|path| Report {
                path,
                generation: 1,
                bytes,
                symbols: 0,
            })
            .collect()
    }
    #[test]
    fn four_paths_share_one_budget_and_delivery_qualifies_bounded_growth() {
        let mut b = Budget::default();
        assert_eq!(b.observe(0, true, &reports(0)), INITIAL_BPS);
        assert_eq!(b.observe(100_000, true, &reports(10_000)), INITIAL_BPS);
        assert_eq!(b.observe(200_000, true, &reports(25_000)), 5_000_000);
        assert_eq!(b.observe(400_000, true, &reports(25_000)), 5_000_000);
        assert_eq!(b.observe(600_000, true, &reports(1_000_000_000)), 6_250_000);
    }
    #[test]
    fn idle_and_new_generations_relearn_without_spending_cached_delivery() {
        let mut b = Budget::default();
        b.observe(0, true, &reports(0));
        b.observe(200_000, true, &reports(25_000));
        assert_eq!(
            b.observe(1_000_000, false, &reports(1_000_000)),
            INITIAL_BPS
        );
        assert_eq!(b.observe(1_100_000, true, &reports(1_000_000)), INITIAL_BPS);
        let mut changed = reports(0);
        changed[0].generation += 1;
        assert_eq!(b.observe(1_200_000, true, &changed), INITIAL_BPS);
    }
    #[test]
    fn sparse_delivery_cannot_collapse_the_startup_envelope() {
        let mut b = Budget::default();
        b.observe(0, true, &reports(0));
        assert_eq!(b.observe(200_000, true, &reports(25_000)), 5_000_000);
        for index in 2..=100 {
            // Control-only or asymmetric delivery must not cause an
            // additional process-wide congestion penalty.
            assert_eq!(
                b.observe(index * SAMPLE_US, true, &reports(25_000 + index)),
                5_000_000
            );
        }
    }
}
