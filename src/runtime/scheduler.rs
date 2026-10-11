//! Optional quality weights; every open path retains original-symbol probes.
use super::{MAX_PATHS, quality::Estimate};
pub fn weight(estimate: &Estimate, now_us: u64, rtt_ms: f64) -> i32 {
    if estimate.expected < 16
        || estimate
            .updated_us
            .is_none_or(|t| now_us.saturating_sub(t) > 3_000_000)
    {
        return 2;
    }
    let score = (1.0 - estimate.loss_rate).max(0.0).powi(4)
        / (1.0 + (estimate.delay_variation_ms + rtt_ms) / 50.0);
    (score * 32.0).round().clamp(1.0, 32.0) as i32
}
/// A path without this symbol's business allowance is not owed its service share.
pub fn ready_candidates(
    candidates: &[(u8, i32)],
    mut ready: impl FnMut(u8) -> bool,
) -> Vec<(u8, i32)> {
    candidates
        .iter()
        .copied()
        .filter(|&(id, _)| ready(id))
        .collect()
}
#[derive(Default)]
pub struct Scheduler {
    debt: [i64; MAX_PATHS],
}
impl Scheduler {
    /// Preview byte-weighted service order. A failed attempt spends no service credit.
    pub fn order(&self, candidates: &[(u8, i32)], bytes: usize) -> Vec<u8> {
        let bytes = bytes.min(65_536) as i64;
        let mut order = candidates.to_vec();
        order.sort_by_key(|(id, weight)| {
            std::cmp::Reverse(self.debt[usize::from(*id)] + i64::from((*weight).max(1)) * bytes)
        });
        order.into_iter().map(|(id, _)| id).collect()
    }
    /// Account the path that actually accepted this symbol, including a fallback.
    pub fn commit(&mut self, candidates: &[(u8, i32)], actual: u8, bytes: usize) {
        if !candidates.iter().any(|(id, _)| *id == actual) {
            return;
        }
        // Adaptive weights use sixteen units per former unit. Preserve the
        // same service-debt bound in those units, including max-size symbols.
        const LIMIT: i64 = 1 << 32;
        let bytes = bytes.min(65_536) as i64;
        let sum: i64 = candidates.iter().map(|(_, w)| i64::from((*w).max(1))).sum();
        for &(id, weight) in candidates {
            self.debt[usize::from(id)] = (self.debt[usize::from(id)]
                + i64::from(weight.max(1)) * bytes
                - if id == actual { sum * bytes } else { 0 })
            .clamp(-LIMIT, LIMIT);
        }
    }
}
#[derive(Default)]
pub struct Rotation {
    failures: u8,
    inflight: bool,
    bad_since: Option<u64>,
    next_rotation_us: u64,
    next_retry_us: u64,
}
impl Rotation {
    pub fn consider(&mut self, estimate: &Estimate, path_time_us: u64, now_us: u64) -> bool {
        let bad = estimate.expected >= 32
            && estimate
                .updated_us
                .is_some_and(|t| path_time_us.saturating_sub(t) < 3_000_000)
            && (estimate.loss_rate > 0.05 || estimate.delay_variation_ms > 100.0);
        if !bad {
            self.bad_since = None;
            return false;
        }
        let since = *self.bad_since.get_or_insert(now_us);
        if self.inflight
            || now_us < self.next_rotation_us
            || now_us < self.next_retry_us
            || now_us.saturating_sub(since) < 4_000_000
        {
            return false;
        }
        self.inflight = true;
        self.bad_since = None;
        true
    }
    pub fn finished(&mut self) {
        self.inflight = false;
    }
    /// Disconnected/initially unavailable paths remain recoverable with bounded backoff.
    pub fn should_retry(&mut self, now_us: u64, is_open: bool) -> bool {
        if is_open || self.inflight || now_us < self.next_retry_us {
            return false;
        }
        self.inflight = true;
        true
    }
    pub fn connection_failed(&mut self, now_us: u64) {
        self.inflight = false;
        self.bad_since = None;
        self.failures = self.failures.saturating_add(1).min(6);
        let delay = (1_000_000u64 << self.failures).min(60_000_000);
        self.next_retry_us = now_us.saturating_add(delay);
    }
    pub fn connection_succeeded(&mut self, now_us: u64) {
        self.inflight = false;
        self.failures = 0;
        self.bad_since = None;
        self.next_retry_us = now_us.saturating_add(1_000_000);
    }
    pub fn rotation_succeeded(&mut self, now_us: u64) {
        self.connection_succeeded(now_us);
        self.next_rotation_us = now_us.saturating_add(30_000_000);
    }
}
pub fn admit_generation(highest: &mut Option<u64>, generation: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        highest.is_none_or(|previous| generation > previous),
        "generation replay or regression"
    );
    *highest = Some(generation);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_bulk_allowance_cannot_accumulate_debt_against_later_small_packets() {
        let candidates = [(0, 16), (1, 16)];
        let mut scheduler = Scheduler::default();
        // Path 1 can hold a small packet, but cannot admit the bulk symbol.
        let mut small_budget = crate::runtime::outbound::Pacer::new(0, 200);
        small_budget.set_rate(0, 64_000);
        small_budget.refill(100_000);
        assert!(small_budget.available(183));
        assert!(!small_budget.available(1055));
        for _ in 0..10_000 {
            let ready = ready_candidates(&candidates, |id| id == 0 || small_budget.available(1055));
            scheduler.commit(&ready, 0, 1055);
        }
        let mut small = [0; 2];
        for _ in 0..200 {
            let ready = ready_candidates(&candidates, |_| true);
            let selected = scheduler.order(&ready, 183)[0];
            scheduler.commit(&ready, selected, 183);
            small[usize::from(selected)] += 1;
        }
        assert_eq!(
            small,
            [100, 100],
            "bulk allowance must not pin small packets: {small:?}"
        );
        assert_eq!(scheduler.debt, [0; MAX_PATHS]);
    }
    #[test]
    fn recovery_remains_bounded_and_available_after_many_outages() {
        let q = Estimate {
            expected: 32,
            loss_rate: 0.2,
            updated_us: Some(0),
            ..Default::default()
        };
        let mut r = Rotation::default();
        assert!(!r.consider(&q, 0, 0));
        assert!(!r.consider(&q, 0, 3_999_999));
        assert!(r.consider(&q, 0, 4_000_000));
        assert!(!r.consider(&q, 0, 10_000_000));
        r.connection_succeeded(10_000_000);
        assert!(!r.should_retry(10_999_999, false));
        assert!(r.should_retry(11_000_000, false));
        r.connection_failed(11_000_000);
        assert!(!r.should_retry(12_999_999, false));
        assert!(r.should_retry(13_000_000, false));
        for n in 1..100 {
            let now = 42_000_000 + n * 60_000_000;
            r.connection_failed(now);
            assert!(!r.should_retry(now, false));
            assert!(r.should_retry(now + 60_000_000, false));
        }
        let mut highest = None;
        for generation in 7..10_000 {
            admit_generation(&mut highest, generation).unwrap();
            assert!(admit_generation(&mut highest, generation).is_err());
            assert!(admit_generation(&mut highest, generation - 1).is_err());
        }
        assert_eq!(highest, Some(9999));
        let mut r = Rotation::default();
        assert!(!r.consider(&q, 0, 0));
        assert!(!r.consider(&q, 4_000_000, 4_000_000));
        assert!(!r.consider(&q, 0, 4_000_000));
        assert!(r.consider(&q, 0, 8_000_000));
    }
    #[test]
    fn initial_connection_does_not_spend_elective_rotation_cooldown() {
        let q = Estimate {
            expected: 32,
            loss_rate: 0.2,
            updated_us: Some(0),
            ..Default::default()
        };
        let mut rotation = Rotation::default();
        rotation.connection_succeeded(0);
        assert!(!rotation.consider(&q, 0, 0));
        assert!(rotation.consider(&q, 0, 4_000_000));
        rotation.rotation_succeeded(4_000_000);
        assert!(!rotation.consider(&q, 0, 5_000_000));
        assert!(!rotation.consider(&q, 0, 9_000_000));
        assert!(rotation.consider(&q, 0, 34_000_000));
    }
    #[test]
    fn bad_paths_keep_probe_share_and_recovered_quality_restores_weight() {
        let mut s = Scheduler::default();
        let mut counts = [0; 2];
        for _ in 0..330 {
            let candidates = [(0, 32), (1, 1)];
            let id = s.order(&candidates, 1000)[0];
            s.commit(&candidates, id, 1000);
            counts[id as usize] += 1;
        }
        assert_eq!(counts, [320, 10]);
        let mut q = Estimate {
            expected: 100,
            loss_rate: 0.4,
            updated_us: Some(0),
            ..Default::default()
        };
        let bad = weight(&q, 1_000_000, 50.0);
        q.loss_rate = 0.0;
        assert!(weight(&q, 1_000_000, 50.0) > bad);
        assert_eq!(weight(&q, 4_000_000, 50.0), 2);
        for _ in 0..1000 {
            s.commit(&[(1, 1)], 1, 1000);
        }
        assert!(s.debt.iter().all(|d| d.abs() <= 1 << 28));
    }
    #[test]
    fn failed_attempts_spend_no_credit_and_fallback_is_charged() {
        let mut s = Scheduler::default();
        let candidates = [(0, 1), (1, 1)];
        for _ in 0..10_000 {
            assert_eq!(s.order(&candidates, 1000), vec![0, 1]);
        }
        s.commit(&candidates, 1, 1000);
        assert_eq!(s.order(&candidates, 1000), vec![0, 1]);
        s.commit(&candidates, 0, 1000);
        assert_eq!(s.debt, [0; MAX_PATHS]);
    }
    #[test]
    fn mixed_packet_sizes_balance_bytes_instead_of_packet_counts() {
        let mut s = Scheduler::default();
        let candidates = [(0, 1), (1, 1)];
        let mut bytes = [0i64; 2];
        for n in 0..2000 {
            let size = if n % 3 == 0 { 1000 } else { 64 };
            let path = s.order(&candidates, size)[0];
            s.commit(&candidates, path, size);
            bytes[path as usize] += size as i64;
        }
        assert!((bytes[0] - bytes[1]).abs() <= 1000);
    }

    #[test]
    fn adaptive_016_scaled_clean_order_and_maximum_packet_debts_are_equivalent() {
        let mut ordinary = Scheduler::default();
        let mut scaled = Scheduler::default();
        let mut exceeded_old_numerical_bound = false;
        let mut ordinary_bytes = [0u64; MAX_PATHS];
        let mut scaled_bytes = [0u64; MAX_PATHS];
        for round in 0..2048 {
            let candidates: Vec<_> = (0..MAX_PATHS)
                .map(|id| {
                    (
                        id as u8,
                        if round < 1024 {
                            128
                        } else {
                            (id as i32 + 1) * 16
                        },
                    )
                })
                .collect();
            let scaled_candidates: Vec<_> =
                candidates.iter().map(|&(id, w)| (id, w * 16)).collect();
            let bytes = [65_536, 1200, 64, 65_536][round % 4];
            let order = ordinary.order(&candidates, bytes);
            assert_eq!(scaled.order(&scaled_candidates, bytes), order);
            let accepted = order[0];
            ordinary.commit(&candidates, accepted, bytes);
            scaled.commit(&scaled_candidates, accepted, bytes);
            ordinary_bytes[usize::from(accepted)] += bytes as u64;
            scaled_bytes[usize::from(accepted)] += bytes as u64;
            for id in 0..MAX_PATHS {
                // The reference remains below the former bound, so it also
                // represents the original scheduler for this complete run.
                assert!(ordinary.debt[id].abs() <= 1 << 28);
                assert_eq!(scaled.debt[id], ordinary.debt[id] * 16);
                assert!(scaled.debt[id].abs() <= 1 << 32);
                exceeded_old_numerical_bound |= scaled.debt[id].abs() > 1 << 28;
            }
        }
        assert!(exceeded_old_numerical_bound);
        assert_eq!(scaled_bytes, ordinary_bytes);
        assert!(scaled_bytes.iter().all(|bytes| *bytes > 0));
    }
}
