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
#[derive(Default)]
pub struct Scheduler {
    debt: [i32; MAX_PATHS],
}
impl Scheduler {
    /// Smooth weighted round robin, with bounded debt and a nonzero probe share.
    pub fn order(&mut self, candidates: &[(u8, i32)]) -> Vec<u8> {
        let sum: i32 = candidates.iter().map(|(_, w)| *w).sum();
        for &(id, w) in candidates {
            self.debt[usize::from(id)] = (self.debt[usize::from(id)] + w).clamp(-256, 256);
        }
        let mut order = candidates.to_vec();
        order.sort_by_key(|(id, _)| std::cmp::Reverse(self.debt[usize::from(*id)]));
        if let Some((id, _)) = order.first() {
            self.debt[usize::from(*id)] = (self.debt[usize::from(*id)] - sum).clamp(-256, 256);
        }
        order.into_iter().map(|(id, _)| id).collect()
    }
}
#[derive(Default)]
pub struct Rotation {
    attempts: u8,
    inflight: bool,
    bad_since: Option<u64>,
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
        if self.inflight || self.attempts >= 3 || now_us.saturating_sub(since) < 4_000_000 {
            return false;
        }
        self.attempts += 1;
        self.inflight = true;
        self.bad_since = None;
        true
    }
    pub fn finished(&mut self) {
        self.inflight = false;
    }
}
pub fn admit_generation(history: &mut Vec<u64>, generation: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        history.len() < 4 && !history.contains(&generation),
        "generation replay/rejoin limit"
    );
    history.push(generation);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persistent_quality_rotation_is_bounded_and_generations_cannot_replay() {
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
        r.finished();
        assert!(r.consider(&q, 0, 14_000_000));
        r.finished();
        assert!(!r.consider(&q, 0, 15_000_000));
        assert!(r.consider(&q, 0, 19_000_000));
        r.finished();
        assert!(!r.consider(&q, 0, 30_000_000));
        let mut history = Vec::new();
        admit_generation(&mut history, 7).unwrap();
        assert!(admit_generation(&mut history, 7).is_err());
        for n in 8..11 {
            admit_generation(&mut history, n).unwrap();
        }
        assert!(admit_generation(&mut history, 11).is_err());
        assert_eq!(history.len(), 4);
        let mut r = Rotation::default();
        assert!(!r.consider(&q, 0, 0));
        assert!(!r.consider(&q, 4_000_000, 4_000_000));
        assert!(!r.consider(&q, 0, 4_000_000));
        assert!(r.consider(&q, 0, 8_000_000));
    }
    #[test]
    fn bad_paths_keep_probe_share_and_recovered_quality_restores_weight() {
        let mut s = Scheduler::default();
        let mut counts = [0; 2];
        for _ in 0..330 {
            counts[s.order(&[(0, 32), (1, 1)])[0] as usize] += 1;
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
            s.order(&[(1, 1)]);
        }
        assert!(s.debt.iter().all(|d| d.abs() <= 256));
    }
}
