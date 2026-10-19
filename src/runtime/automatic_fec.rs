//! Sender-local XOR strength from authenticated, finalized pre-FEC path counts.
use super::{MAX_PATHS, quality};
use serde::Serialize;

/// Policy/wire sentinel; numeric CLI values remain fixed configurations.
pub const AUTO: u8 = u8::MAX;
const PERIOD_US: u64 = 500_000;
const FRESH_US: u64 = 3_000_000;
const LOWER_HOLD_US: u64 = 3_000_000;
const MIN_SYMBOLS: u64 = 64;
/// Qualified feedback below `MIN_SYMBOLS` accumulates for at most this long.
const WINDOW_US: u64 = 2_000_000;
/// Conservative bulk strength when admitted traffic loses feedback.
const DEFAULT: u8 = 4;
// Each weaker level has its own continuous evidence window. A safe change
// between weaker targets must not restart every level's downgrade clock.
const LOWER_LEVELS: [(u8, f64); 4] = [(8, 0.03), (16, 0.01), (32, 0.005), (0, 0.001)];

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub data_shards: u8,
    pub repair_shards: u8,
    pub loss_rate: Option<f64>,
    pub sample_symbols: u64,
    pub sample_lost: u64,
    pub feedback_paths: u8,
    pub transitions: u64,
    /// Returns to the default strength while sending without feedback.
    pub unknown_restores: u64,
    pub updated_us: Option<u64>,
}

#[derive(Clone, Copy, Default)]
struct Cursor {
    generation: u64,
    expected: u64,
    lost: u64,
    sent: u64,
}

/// Qualified symbols not yet numerous enough for a full observation.
#[derive(Clone, Copy)]
struct Window {
    started_us: u64,
    expected: u64,
    lost: u64,
}

pub struct Controller {
    paths: [Cursor; MAX_PATHS],
    next_us: u64,
    lower: [Option<u64>; 4],
    window: Option<Window>,
    /// When symbols were first sent on active paths after the latest
    /// qualified feedback, and how many have been sent since.
    unconfirmed: Option<(u64, u64)>,
    snapshot: Snapshot,
}

fn strength(k: u8) -> u8 {
    match k {
        0 => 0,
        32 => 1,
        16 => 2,
        8 => 3,
        4 => 4,
        _ => unreachable!(),
    }
}

pub(super) fn target(loss: f64) -> u8 {
    if loss < 0.001 {
        0
    } else if loss < 0.005 {
        32
    } else if loss < 0.01 {
        16
    } else if loss < 0.03 {
        8
    } else {
        4
    }
}

impl Default for Controller {
    fn default() -> Self {
        Self {
            paths: [Cursor::default(); MAX_PATHS],
            next_us: 0,
            lower: [None; 4],
            window: None,
            unconfirmed: None,
            snapshot: Snapshot {
                data_shards: 0,
                repair_shards: 0,
                loss_rate: None,
                sample_symbols: 0,
                sample_lost: 0,
                feedback_paths: 0,
                transitions: 0,
                unknown_restores: 0,
                updated_us: None,
            },
        }
    }
}

impl Controller {
    pub fn due(&self, now_us: u64) -> bool {
        now_us >= self.next_us
    }
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot.clone()
    }

    /// Every path clock belongs to its current connection generation. Call at
    /// most once per observation period; counters span skipped delivery reports.
    /// Inactive/stale paths advance their baseline but cannot steer live traffic.
    pub fn observe<'a>(
        &mut self,
        now_us: u64,
        paths: impl IntoIterator<Item = (u8, bool, &'a quality::Snapshot)>,
    ) -> Option<u8> {
        if now_us < self.next_us {
            return None;
        }
        self.next_us = now_us.saturating_add(PERIOD_US);
        let (mut expected, mut lost, mut count, mut sent) = (0u64, 0u64, 0u8, 0u64);
        for (id, active, path) in paths {
            let cursor = &mut self.paths[usize::from(id)];
            if cursor.generation != path.generation {
                if active {
                    self.lower = [None; 4];
                    self.window = None;
                    self.unconfirmed = None;
                }
                *cursor = Cursor {
                    generation: path.generation,
                    ..Default::default()
                };
            }
            let estimate = &path.sender_estimate;
            let n = estimate.expected.saturating_sub(cursor.expected);
            let missing = estimate.lost.saturating_sub(cursor.lost);
            if active {
                sent = sent.saturating_add(path.sent_symbols.saturating_sub(cursor.sent));
            }
            *cursor = Cursor {
                generation: path.generation,
                expected: estimate.expected,
                lost: estimate.lost,
                sent: path.sent_symbols,
            };
            if active
                && n > 0
                && estimate
                    .updated_us
                    .is_some_and(|at| path.sampled_us.saturating_sub(at) <= FRESH_US)
            {
                expected = expected.saturating_add(n);
                lost = lost.saturating_add(missing.min(n));
                count += 1;
            }
        }
        if expected > 0 {
            self.unconfirmed = None;
        } else if sent > 0 {
            let (since, n) = self.unconfirmed.unwrap_or((now_us, 0));
            self.unconfirmed = Some((since, n.saturating_add(sent)));
        }
        if let Some((since, n)) = self.unconfirmed
            && n > 0
            && now_us.saturating_sub(since) >= FRESH_US
            && strength(self.snapshot.data_shards) < strength(DEFAULT)
        {
            // Sending continues but its loss is unknown: protect as before
            // the first qualified feedback, still within the repair budget.
            self.window = None;
            self.snapshot.loss_rate = None;
            self.snapshot.unknown_restores += 1;
            return self.switch(DEFAULT);
        }
        // Sparse feedback accumulates for a bounded time. Partial windows
        // can add protection but never remove it.
        let mut window = match self.window {
            Some(window) if now_us.saturating_sub(window.started_us) <= WINDOW_US => window,
            _ => Window {
                started_us: now_us,
                expected: 0,
                lost: 0,
            },
        };
        window.expected = window.expected.saturating_add(expected);
        window.lost = window.lost.saturating_add(lost);
        let (expected, lost) = (window.expected, window.lost);
        self.window = (expected < MIN_SYMBOLS && expected > 0).then_some(window);
        self.snapshot.sample_symbols = expected;
        self.snapshot.sample_lost = lost;
        self.snapshot.feedback_paths = count;
        if expected < MIN_SYMBOLS {
            // Counted against a full window, as if every symbol still to
            // come arrived: no more protection than full evidence of the
            // same losses would select.
            let floor = lost as f64 / MIN_SYMBOLS as f64;
            let higher = target(floor);
            if strength(higher) > strength(self.snapshot.data_shards) {
                self.window = None;
                self.snapshot.loss_rate =
                    Some(self.snapshot.loss_rate.map_or(floor, |old| old.max(floor)));
                self.snapshot.updated_us = Some(now_us);
                return self.switch(higher);
            }
            // Feedback and observation clocks can straddle each other. One
            // empty tick must not perpetually restart a healthy path's hold;
            // it cannot complete the hold either. Longer gaps still cancel it.
            if self
                .snapshot
                .updated_us
                .is_none_or(|at| now_us.saturating_sub(at) > PERIOD_US * 2)
            {
                self.lower = [None; 4];
            }
            return None;
        }
        let raw = lost as f64 / expected as f64;
        if self
            .snapshot
            .updated_us
            .is_some_and(|at| now_us.saturating_sub(at) > PERIOD_US * 2)
        {
            self.lower = [None; 4];
        }
        let smooth = self.snapshot.loss_rate.map_or(raw, |old| (old + raw) * 0.5);
        self.snapshot.loss_rate = Some(smooth);
        self.snapshot.updated_us = Some(now_us);
        let current = self.snapshot.data_shards;
        let higher = target(raw.max(smooth));
        let next = if strength(higher) > strength(current) {
            self.lower = [None; 4];
            higher
        } else {
            // Keep 20% clearance and three seconds of full, fresh samples for
            // each level separately. Both raw and smoothed loss must qualify:
            // averaging cannot authorize a level contradicted by recent loss.
            let mut next = current;
            for (hold, (level, boundary)) in self.lower.iter_mut().zip(LOWER_LEVELS) {
                if raw.max(smooth) < boundary * 0.8 {
                    let since = *hold.get_or_insert(now_us);
                    if now_us.saturating_sub(since) >= LOWER_HOLD_US
                        && strength(level) < strength(next)
                    {
                        next = level;
                    }
                } else {
                    *hold = None;
                }
            }
            next
        };
        if next == current {
            return None;
        }
        self.switch(next)
    }

    fn switch(&mut self, next: u8) -> Option<u8> {
        if strength(next) >= strength(self.snapshot.data_shards) {
            self.lower = [None; 4];
        }
        self.snapshot.data_shards = next;
        self.snapshot.repair_shards = u8::from(next != 0);
        self.snapshot.transitions += 1;
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(generation: u64, n: u64, lost: u64, now: u64) -> quality::Snapshot {
        let mut s = quality::Snapshot {
            generation,
            sampled_us: now,
            ..Default::default()
        };
        s.sent_symbols = n;
        s.sender_estimate.expected = n;
        s.sender_estimate.lost = lost;
        s.sender_estimate.updated_us = Some(now);
        s
    }
    #[test]
    fn clean_then_burst_then_clean_changes_both_ways() {
        let mut c = Controller::default();
        let mut lost = 0;
        for i in 0..=40 {
            let now = i * PERIOD_US;
            if i == 9 {
                lost += 100;
            }
            let s = sample(1, (i + 1) * 1000, lost, now);
            c.observe(now, [(0, true, &s)]);
            if i == 5 {
                assert_eq!(c.snapshot.data_shards, 0);
            }
            if i == 6 {
                assert_eq!(c.snapshot.data_shards, 0);
            }
            if i == 9 {
                assert_eq!(c.snapshot.data_shards, 4);
            }
            // Each lower level becomes eligible after its own full hold;
            // taking an earlier safe step must not erase the others' evidence.
            for (tick, k) in [(17, 8), (18, 16), (19, 32), (21, 0)] {
                if i == tick {
                    assert_eq!(c.snapshot.data_shards, k);
                }
            }
        }
        assert_eq!(c.snapshot.data_shards, 0);
        assert_eq!(c.snapshot.transitions, 5);
    }
    #[test]
    fn stages_match_loss_and_ignore_duplicate_or_empty_reports() {
        for (loss, k) in [(0, 0), (2, 32), (7, 16), (20, 8), (40, 4)] {
            let mut c = Controller::default();
            for i in 0..=8 {
                let s = sample(1, (i + 1) * 1000, (i + 1) * loss, i * PERIOD_US);
                c.observe(i * PERIOD_US, [(0, true, &s)]);
            }
            assert_eq!(c.snapshot.data_shards, k);
            let before = c.snapshot.transitions;
            let s = sample(1, 9000, 9 * loss, 10_000_000);
            for i in 20..=40 {
                c.observe(i * PERIOD_US, [(0, true, &s)]);
            }
            assert_eq!(c.snapshot.transitions, before);
        }
    }
    #[test]
    fn weighted_counts_exclude_inactive_and_stale_paths_and_reset_generations() {
        let mut c = Controller::default();
        let a = sample(1, 100_000, 0, 0);
        let b = sample(1, 100, 100, 0);
        let dead = sample(1, 1_000_000, 1_000_000, 0);
        let mut stale = dead.clone();
        stale.sampled_us = FRESH_US + 1;
        c.observe(
            0,
            [
                (0, true, &a),
                (1, true, &b),
                (2, false, &dead),
                (3, true, &stale),
            ],
        );
        assert_eq!(c.snapshot.sample_symbols, 100_100);
        assert_eq!(c.snapshot.sample_lost, 100);
        assert_eq!(c.snapshot.feedback_paths, 2);
        let new = sample(2, 1000, 100, PERIOD_US);
        c.observe(PERIOD_US, [(0, true, &new)]);
        assert_eq!(c.snapshot.sample_symbols, 1000);
        assert_eq!(c.snapshot.sample_lost, 100);
    }
    #[test]
    fn sparse_or_missing_feedback_cannot_downgrade() {
        let mut c = Controller::default();
        c.switch(4);
        for i in 0..20 {
            let s = sample(1, (i + 1) * 10, 0, i * PERIOD_US);
            c.observe(i * PERIOD_US, [(0, true, &s)]);
        }
        assert_eq!(c.snapshot.data_shards, 4);
        assert_eq!(c.snapshot.loss_rate, None);
    }

    /// Clean bulk feedback that turns FEC off; returns the cumulative counts.
    fn switch_off(c: &mut Controller) -> (u64, u64) {
        for i in 0..=8 {
            let s = sample(1, (i + 1) * 1000, 0, i * PERIOD_US);
            c.observe(i * PERIOD_US, [(0, true, &s)]);
        }
        assert_eq!(c.snapshot.data_shards, 0);
        (9000, 8 * PERIOD_US)
    }

    #[test]
    fn sparse_heavy_loss_after_clean_bulk_restores_protection() {
        for (per_tick, lost_per_tick, ticks) in [(10, 5, 1), (63, 31, 1), (2, 1, 4)] {
            let mut c = Controller::default();
            let (mut n, mut now) = switch_off(&mut c);
            let mut lost = 0;
            for _ in 0..ticks {
                now += PERIOD_US;
                n += per_tick;
                lost += lost_per_tick;
                let s = sample(1, n, lost, now);
                c.observe(now, [(0, true, &s)]);
            }
            assert_eq!(c.snapshot.data_shards, 4, "{per_tick}/{lost_per_tick}");
        }
    }

    #[test]
    fn sparse_windows_are_bounded_and_cannot_remove_protection() {
        let mut c = Controller::default();
        let (mut n, mut now) = switch_off(&mut c);
        // One loss every three seconds among sparse symbols never shares a
        // window with the next one.
        let mut lost = 0;
        for i in 0..24 {
            now += PERIOD_US;
            n += 5;
            if i % 6 == 0 {
                lost += 1;
            }
            let s = sample(1, n, lost, now);
            c.observe(now, [(0, true, &s)]);
        }
        assert_eq!(c.snapshot.data_shards, 8, "single sparse losses select 8+1");
        // Sparse clean feedback keeps that protection.
        for _ in 0..40 {
            now += PERIOD_US;
            n += 10;
            let s = sample(1, n, lost, now);
            c.observe(now, [(0, true, &s)]);
        }
        assert_eq!(c.snapshot.data_shards, 8);
    }

    #[test]
    fn small_lossy_samples_after_a_new_generation_restore_protection() {
        let mut c = Controller::default();
        let (_, mut now) = switch_off(&mut c);
        let (mut n, mut lost) = (0, 0);
        for _ in 0..2 {
            now += PERIOD_US;
            n += 20;
            lost += 4;
            let s = sample(2, n, lost, now);
            c.observe(now, [(0, true, &s)]);
        }
        assert_eq!(c.snapshot.data_shards, 4);
    }

    #[test]
    fn sending_without_feedback_returns_to_the_default() {
        let mut c = Controller::default();
        let (n, mut now) = switch_off(&mut c);
        let mut s = sample(1, n, 0, now);
        // Feedback delayed for less than three seconds keeps the target.
        for _ in 0..5 {
            now += PERIOD_US;
            s.sent_symbols += 100;
            s.sampled_us = now;
            c.observe(now, [(0, true, &s)]);
        }
        assert_eq!(c.snapshot.data_shards, 0);
        s.sender_estimate.expected = s.sent_symbols - 100;
        s.sender_estimate.updated_us = Some(now + PERIOD_US);
        for _ in 0..5 {
            now += PERIOD_US;
            s.sent_symbols += 100;
            s.sampled_us = now;
            c.observe(now, [(0, true, &s)]);
        }
        assert_eq!(c.snapshot.data_shards, 0);
        assert_eq!(c.snapshot.unknown_restores, 0);
        // Three seconds of sending without feedback: unknown loss is protected.
        for _ in 0..3 {
            now += PERIOD_US;
            s.sent_symbols += 100;
            s.sampled_us = now;
            c.observe(now, [(0, true, &s)]);
        }
        assert_eq!(c.snapshot.data_shards, 4);
        assert_eq!(c.snapshot.unknown_restores, 1);
        assert_eq!(c.snapshot.loss_rate, None);
        // An idle session without feedback is not a reason to protect.
        let mut idle = Controller::default();
        let (n, mut now) = switch_off(&mut idle);
        let mut s = sample(1, n, 0, now);
        for _ in 0..20 {
            now += PERIOD_US;
            s.sampled_us = now;
            idle.observe(now, [(0, true, &s)]);
        }
        assert_eq!(idle.snapshot.data_shards, 0);
    }

    #[test]
    fn an_idle_gap_breaks_the_downgrade_hold() {
        let mut c = Controller::default();
        c.switch(4);
        let first = sample(1, 1000, 0, 0);
        c.observe(0, [(0, true, &first)]);
        let after_gap = sample(1, 2000, 0, 10_000_000);
        c.observe(10_000_000, [(0, true, &after_gap)]);
        assert_eq!(c.snapshot.data_shards, 4);
    }

    #[test]
    fn generation_change_discards_pending_sparse_and_unknown_evidence() {
        let mut c = Controller::default();
        c.observe(0, [(0, true, &sample(1, 40, 0, 0))]);
        c.observe(PERIOD_US, [(0, true, &sample(2, 24, 0, PERIOD_US))]);
        assert_eq!(c.snapshot.sample_symbols, 24);
        assert_eq!(c.snapshot.loss_rate, None);
        let mut c = Controller::default();
        let (n, now) = switch_off(&mut c);
        let mut old = sample(1, n, 0, now);
        old.sent_symbols += 10;
        old.sampled_us += PERIOD_US;
        c.observe(now + PERIOD_US, [(0, true, &old)]);
        for i in 2..=12 {
            let new = sample(2, 0, 0, now + i * PERIOD_US);
            c.observe(now + i * PERIOD_US, [(0, true, &new)]);
        }
        assert_eq!(
            c.snapshot.data_shards, 0,
            "retired traffic cannot protect a new idle generation"
        );
    }

    #[test]
    fn sparse_sending_without_feedback_restores_protection_but_idle_does_not() {
        let mut c = Controller::default();
        let (n, now) = switch_off(&mut c);
        let mut s = sample(1, n, 0, now);
        s.sent_symbols += 10;
        for i in 1..=20 {
            s.sampled_us = now + i * PERIOD_US;
            c.observe(now + i * PERIOD_US, [(0, true, &s)]);
        }
        assert_eq!(c.snapshot.data_shards, 4);
        assert_eq!(c.snapshot.unknown_restores, 1);
    }

    #[test]
    fn report_clock_jitter_does_not_prevent_clean_downgrade() {
        let mut c = Controller::default();
        c.switch(4);
        for i in 0..=6 {
            let s = sample(1, (i / 2 + 1) * 1000, 0, i * PERIOD_US);
            c.observe(i * PERIOD_US, [(0, true, &s)]);
        }
        assert_eq!(c.snapshot.data_shards, 0);
        // Repeating that same report never performs another transition.
        let s = sample(1, 4000, 0, 10_000_000);
        c.observe(10_000_000, [(0, true, &s)]);
        assert_eq!(c.snapshot.transitions, 2);
    }

    #[test]
    fn varying_safe_targets_cannot_pin_the_strongest_grade() {
        let mut c = Controller::default();
        c.switch(4);
        c.snapshot.loss_rate = Some(0.008);
        let mut lost = 0;
        for i in 0..=6 {
            lost += if i % 2 == 0 { 2 } else { 20 };
            let now = i * PERIOD_US;
            c.observe(now, [(0, true, &sample(1, (i + 1) * 1000, lost, now))]);
            if i < 6 {
                assert_eq!(c.snapshot.data_shards, 4, "the full hold still applies");
            }
        }
        assert_eq!(c.snapshot.data_shards, 8);
    }

    #[test]
    fn downgrade_uses_the_strongest_qualified_loss_not_only_smoothed_target() {
        let mut c = Controller::default();
        c.switch(4);
        c.snapshot.loss_rate = Some(0.008);
        let mut lost = 0;
        for i in 0..=6 {
            lost += if i % 2 == 0 { 2 } else { 14 };
            let now = i * PERIOD_US;
            c.observe(now, [(0, true, &sample(1, (i + 1) * 1000, lost, now))]);
        }
        // Every smoothed sample selected16, but the 1.4% raw intervals still
        // need8+1. They must not count toward a weaker stage's clean hold.
        assert_eq!(c.snapshot.data_shards, 8);
    }

    #[test]
    fn strong_loss_breaks_a_pending_downgrade() {
        let mut c = Controller::default();
        c.switch(4);
        c.snapshot.loss_rate = Some(0.008);
        let mut lost = 0;
        for i in 0..=10 {
            lost += if i == 3 {
                30
            } else if i % 2 == 0 {
                2
            } else {
                20
            };
            let now = i * PERIOD_US;
            c.observe(now, [(0, true, &sample(1, (i + 1) * 1000, lost, now))]);
            if i < 10 {
                assert_eq!(c.snapshot.data_shards, 4, "dirty evidence resets the hold");
            }
        }
        assert_eq!(c.snapshot.data_shards, 8);
    }

    #[test]
    fn fifty_percent_loss_never_qualifies_a_weaker_level() {
        let mut c = Controller::default();
        for i in 0..=20 {
            let now = i * PERIOD_US;
            c.observe(
                now,
                [(0, true, &sample(1, (i + 1) * 1000, (i + 1) * 500, now))],
            );
            assert_eq!(c.snapshot.data_shards, 4);
        }
    }
}
