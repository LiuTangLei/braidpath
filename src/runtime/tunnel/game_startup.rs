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
    pub report_time_us: Option<u64>,
    pub admitted_bytes: u64,
    pub admitted_symbols: u64,
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
        let mut measured = 0.0;
        for (a, b) in current.iter().zip(&self.baseline) {
            let (Some(a), Some(b)) = (a, b) else {
                continue;
            };
            let Some(receiver_span) = a
                .report_time_us
                .zip(b.report_time_us)
                .and_then(|(end, start)| end.checked_sub(start))
                .filter(|span| *span > 0)
            else {
                continue;
            };
            let bytes = a.bytes.saturating_sub(b.bytes);
            let admitted = a.admitted_bytes.saturating_sub(b.admitted_bytes);
            let symbols = a.admitted_symbols.saturating_sub(b.admitted_symbols);
            if admitted == 0 {
                continue;
            }
            // Byte progress and its receiver clock are one interval. Loss
            // finalization publishes symbol counts later, so those counts
            // cannot price immediate byte delivery. Estimate framing from
            // actual admissions instead; path controllers remain authoritative.
            let wire_ratio =
                1.0 + symbols as f64 * (quality::HEADER + 9 + 80) as f64 / admitted as f64;
            measured += bytes as f64 * wire_ratio * 8_000_000.0 / receiver_span as f64;
        }
        // This only qualifies startup growth. Loss on one route is not
        // evidence that all routes share a bottleneck. Existing path and
        // qualified shared-loss controllers retain the congestion brakes.
        let trial = (measured * 1.25).min(self.rate_bps as f64 * 1.25);
        self.rate_bps = self.rate_bps.max(trial as u64);
        self.baseline = current;
        self.sampled_us = now_us;
        self.rate_bps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reports(bytes: u64, time_us: u64) -> Vec<Report> {
        (0..4)
            .map(|path| Report {
                path,
                generation: 1,
                bytes,
                report_time_us: Some(time_us),
                admitted_bytes: bytes,
                admitted_symbols: 0,
            })
            .collect()
    }
    #[test]
    fn four_paths_share_one_budget_and_delivery_qualifies_bounded_growth() {
        let mut b = Budget::default();
        assert_eq!(b.observe(0, true, &reports(0, 0)), INITIAL_BPS);
        assert_eq!(
            b.observe(100_000, true, &reports(10_000, 100_000)),
            INITIAL_BPS
        );
        assert_eq!(
            b.observe(200_000, true, &reports(25_000, 200_000)),
            5_000_000
        );
        assert_eq!(
            b.observe(400_000, true, &reports(25_000, 400_000)),
            5_000_000
        );
        assert_eq!(
            b.observe(600_000, true, &reports(1_000_000_000, 600_000)),
            6_250_000
        );
    }
    #[test]
    fn idle_and_new_generations_relearn_without_spending_cached_delivery() {
        let mut b = Budget::default();
        b.observe(0, true, &reports(0, 0));
        b.observe(200_000, true, &reports(25_000, 200_000));
        assert_eq!(
            b.observe(1_000_000, false, &reports(1_000_000, 1_000_000)),
            INITIAL_BPS
        );
        assert_eq!(
            b.observe(1_100_000, true, &reports(1_000_000, 1_100_000)),
            INITIAL_BPS
        );
        let mut changed = reports(0, 0);
        changed[0].generation += 1;
        assert_eq!(b.observe(1_200_000, true, &changed), INITIAL_BPS);
    }
    #[test]
    fn sparse_delivery_cannot_collapse_the_startup_envelope() {
        let mut b = Budget::default();
        b.observe(0, true, &reports(0, 0));
        assert_eq!(
            b.observe(200_000, true, &reports(25_000, 200_000)),
            5_000_000
        );
        for index in 2..=100 {
            // Control-only or asymmetric delivery must not cause an
            // additional process-wide congestion penalty.
            assert_eq!(
                b.observe(
                    index * SAMPLE_US,
                    true,
                    &reports(25_000 + index, index * SAMPLE_US)
                ),
                5_000_000
            );
        }
    }

    #[test]
    fn short_record_framing_does_not_wait_for_loss_finalization() {
        let mut b = Budget::default();
        b.observe(0, true, &reports(0, 0));
        let mut sample = reports(16_000, 200_000);
        for r in &mut sample {
            r.admitted_symbols = 200;
        }
        // 2.56 Mbps of symbol bytes represents 6.304 Mbps of admitted
        // wire cost. Finalized loss counts are intentionally not an input.
        assert_eq!(b.observe(200_000, true, &sample), 5_000_000);
        assert_eq!(b.observe(400_000, true, &sample), 5_000_000);
    }

    #[test]
    fn receiver_interval_qualifies_delivery_without_feedback_arrival_compression() {
        let mut b = Budget::default();
        b.observe(0, true, &reports(0, 10_000_000));
        // Feedback arrives after 200 ms but spans only 100 ms at the peer.
        assert_eq!(
            b.observe(200_000, true, &reports(12_500, 10_100_000)),
            5_000_000
        );
        // A delayed report spanning 1 s must not be priced as 200 ms.
        assert_eq!(
            b.observe(400_000, true, &reports(50_000, 11_100_000)),
            5_000_000
        );
        let mut missing_clock = reports(1_000_000_000, 11_300_000);
        for r in &mut missing_clock {
            r.report_time_us = None;
        }
        assert_eq!(b.observe(600_000, true, &missing_clock), 5_000_000);
    }
}
