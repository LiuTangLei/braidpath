//! Receiver-local retention control. No sender clocks, pacing or payload buffering.
//!
//! The rolling tail is deliberately not inferred from successful reconstructions
//! alone: first arrivals and a unique-symbol mask survive in bounded tombstones.
//! A late distinct symbol can teach the next blocks, never revive an expired one.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub const MIN_MS: u64 = 50;
pub const INITIAL_MS: u64 = 100;
pub const MAX_MS: u64 = 250;
const TAIL_SECONDS: u64 = 8;
const DECAY_BLOCKS: u64 = 32;

#[derive(Clone, Default, Debug, Serialize)]
pub struct Snapshot {
    pub enabled: bool,
    pub current_ms: u64,
    pub minimum_ms: u64,
    pub maximum_ms: u64,
    pub peak_ms: u64,
    pub samples: u64,
    pub late_samples: u64,
    pub duplicate_samples_ignored: u64,
    pub outside_cap_samples_ignored: u64,
    pub increases: u64,
    pub decreases: u64,
    pub deadline_retired_blocks: u64,
    pub window_evicted_live_blocks: u64,
    pub live_blocks: usize,
    pub metadata_blocks: usize,
}

#[derive(Clone, Copy)]
struct Bucket {
    epoch: u64,
    peak_ms: u64,
    blocks: u64,
}
impl Default for Bucket {
    fn default() -> Self {
        Self {
            epoch: u64::MAX,
            peak_ms: 0,
            blocks: 0,
        }
    }
}

struct Timing {
    first: Instant,
    hold: Duration,
    retired: bool,
    seen: u64,
    repair_count: Option<u8>,
    sampled_epoch: Option<u64>,
}

pub struct Controller {
    blocks: BTreeMap<u64, Timing>,
    buckets: [Bucket; TAIL_SECONDS as usize],
    epoch: Option<Instant>,
    last_decrease: Option<Instant>,
    state: Snapshot,
}
impl Default for Controller {
    fn default() -> Self {
        Self {
            blocks: BTreeMap::new(),
            buckets: [Bucket::default(); TAIL_SECONDS as usize],
            epoch: None,
            last_decrease: None,
            state: Snapshot {
                enabled: true,
                current_ms: INITIAL_MS,
                minimum_ms: MIN_MS,
                maximum_ms: MAX_MS,
                peak_ms: INITIAL_MS,
                ..Snapshot::default()
            },
        }
    }
}
impl Controller {
    pub fn register(&mut self, block: u64, now: Instant) {
        self.epoch.get_or_insert(now);
        self.last_decrease.get_or_insert(now);
        self.blocks.entry(block).or_insert(Timing {
            first: now,
            hold: Duration::from_millis(self.state.current_ms),
            retired: false,
            seen: 0,
            repair_count: None,
            sampled_epoch: None,
        });
    }

    pub fn retain_floor(&mut self, floor: u64) {
        let mut live_evicted = 0;
        self.blocks.retain(|id, timing| {
            if *id < floor {
                live_evicted += u64::from(!timing.retired);
                false
            } else {
                true
            }
        });
        self.state.window_evicted_live_blocks += live_evicted;
    }

    pub fn hold(&self, block: u64) -> Duration {
        self.blocks
            .get(&block)
            .expect("registered receiver block")
            .hold
    }

    pub fn retired(&mut self, block: u64, deadline: bool) {
        if let Some(t) = self.blocks.get_mut(&block) {
            if !t.retired && deadline {
                self.state.deadline_retired_blocks += 1;
            }
            t.retired = true;
        }
    }

    /// token 0..31 is an actual original index; 32/33 are independent P/Q repairs.
    /// Called only after wire validation and a successful receiver operation.
    pub fn observe(&mut self, block: u64, token: u8, count: Option<u8>, now: Instant) {
        let Some(t) = self.blocks.get_mut(&block) else {
            return;
        };
        if token > 33 {
            return;
        }
        if token >= 32 {
            let Some(count) = count.filter(|c| (1..=32).contains(c)) else {
                return;
            };
            if t.repair_count.is_some_and(|old| old != count)
                || ((t.seen & u64::from(u32::MAX)) >> count) != 0
            {
                return;
            }
            t.repair_count = Some(count);
        } else if t.repair_count.is_some_and(|count| token >= count) {
            return;
        }
        let mask = 1u64 << token;
        if t.seen & mask != 0 {
            self.state.duplicate_samples_ignored += 1;
            return;
        }
        let had_first = t.seen != 0;
        t.seen |= mask;
        if !had_first {
            return;
        }
        let age = now.saturating_duration_since(t.first);
        // Do not let ancient traffic bias a horizon at which it cannot recover.
        if age >= Duration::from_millis(MAX_MS) {
            self.state.outside_cap_samples_ignored += 1;
            return;
        }
        self.state.samples += 1;
        self.state.late_samples += u64::from(t.retired);
        let epoch = now
            .saturating_duration_since(self.epoch.expect("registered epoch"))
            .as_secs();
        let b = &mut self.buckets[(epoch % TAIL_SECONDS) as usize];
        if b.epoch != epoch {
            *b = Bucket {
                epoch,
                peak_ms: 0,
                blocks: 0,
            };
        }
        // Round upward so timer granularity never underestimates observed skew.
        let age_ms = age.as_micros().div_ceil(1000) as u64;
        b.peak_ms = b.peak_ms.max(age_ms);
        if t.sampled_epoch != Some(epoch) {
            b.blocks += 1;
            t.sampled_epoch = Some(epoch);
        }
        let mut peak = 0;
        let mut samples = 0;
        for b in &self.buckets {
            if b.epoch <= epoch && epoch - b.epoch < TAIL_SECONDS {
                peak = peak.max(b.peak_ms);
                samples += b.blocks;
            }
        }
        let target = (peak.saturating_mul(5).div_ceil(4) + 5).clamp(MIN_MS, MAX_MS);
        if target > self.state.current_ms {
            self.state.current_ms = target;
            self.state.peak_ms = self.state.peak_ms.max(target);
            self.state.increases += 1;
            self.last_decrease = Some(now);
            for t in self.blocks.values_mut() {
                // Widen only still-live deadlines, anchored to the first arrival.
                // Already-retired OR merely-not-yet-swept expired state stays dead.
                if !t.retired && now.saturating_duration_since(t.first) < t.hold {
                    t.hold = t.hold.max(Duration::from_millis(target));
                }
            }
        } else if samples >= DECAY_BLOCKS
            && target < self.state.current_ms
            && (target + 5 <= self.state.current_ms || target == MIN_MS)
            && now.saturating_duration_since(self.last_decrease.expect("registered decay clock"))
                >= Duration::from_secs(1)
        {
            let step = (self.state.current_ms / 10).max(5);
            self.state.current_ms = target.max(self.state.current_ms.saturating_sub(step));
            self.last_decrease = Some(now);
            self.state.decreases += 1;
            // Shrinking affects only new blocks, never an in-flight promise.
        }
    }

    pub fn snapshot(&self, live_blocks: usize) -> Snapshot {
        Snapshot {
            live_blocks,
            metadata_blocks: self.blocks.len(),
            ..self.state.clone()
        }
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn late_sample_teaches_future_without_reviving_a_tombstone() {
        let at = Instant::now();
        let mut c = Controller::default();
        c.register(0, at);
        c.observe(0, 0, None, at);
        c.retired(0, true);
        c.observe(0, 32, Some(2), at + Duration::from_millis(180));
        assert_eq!(c.state.current_ms, 230);
        assert!(c.blocks[&0].retired);
        assert_eq!(c.hold(0), Duration::from_millis(100));
        c.register(1, at + Duration::from_millis(181));
        assert_eq!(c.hold(1), Duration::from_millis(230));
        assert_eq!(c.state.late_samples, 1);
    }
    #[test]
    fn duplicates_and_ancient_symbols_do_not_train_or_extend_deadlines() {
        let at = Instant::now();
        let mut c = Controller::default();
        c.register(0, at);
        c.observe(0, 0, None, at);
        for ms in [90, 99, 150, 240] {
            c.observe(0, 0, None, at + Duration::from_millis(ms));
        }
        c.observe(0, 1, None, at + Duration::from_millis(1000));
        assert_eq!(c.state.samples, 0);
        assert_eq!(c.state.current_ms, INITIAL_MS);
        assert_eq!(c.state.duplicate_samples_ignored, 4);
        assert_eq!(c.state.outside_cap_samples_ignored, 1);
        assert_eq!(c.hold(0), Duration::from_millis(INITIAL_MS));
    }
    #[test]
    fn increases_are_capped_and_do_not_revive_unswept_expired_blocks() {
        let at = Instant::now();
        let mut c = Controller::default();
        c.register(0, at);
        c.observe(0, 0, None, at);
        c.register(1, at + Duration::from_millis(190));
        c.observe(0, 1, None, at + Duration::from_millis(240));
        assert_eq!(c.state.current_ms, MAX_MS);
        assert_eq!(c.hold(0), Duration::from_millis(100));
        assert_eq!(c.hold(1), Duration::from_millis(MAX_MS));
    }
    #[test]
    fn fresh_samples_allow_slow_decay_without_shortening_open_blocks() {
        let at = Instant::now();
        let mut c = Controller::default();
        c.register(0, at);
        c.observe(0, 0, None, at);
        c.retired(0, true);
        c.observe(0, 1, None, at + Duration::from_millis(180));
        for second in 1..25u64 {
            for index in 0..40 {
                let id = second * 40 + index;
                c.retain_floor(id.saturating_sub(255));
                let now = at + Duration::from_secs(second) + Duration::from_millis(index * 20);
                c.register(id, now);
                c.observe(id, 0, None, now);
                let hold = c.hold(id);
                c.observe(id, 1, None, now + Duration::from_millis(1));
                assert!(c.hold(id) >= hold);
                if second < 8 {
                    assert_eq!(c.state.current_ms, 230);
                }
                assert!(c.blocks.len() <= 256);
            }
        }
        assert_eq!(c.state.current_ms, MIN_MS);
        assert!(c.state.decreases > 0);
    }
    #[test]
    fn sparse_or_conflicting_feedback_does_not_shrink_or_inflate() {
        let at = Instant::now();
        let mut c = Controller::default();
        for id in 0..8 {
            let now = at + Duration::from_secs(id * 10);
            c.register(id, now);
            c.observe(id, 0, None, now);
            c.observe(id, 32, Some(1), now + Duration::from_millis(1));
            c.observe(id, 31, None, now + Duration::from_millis(190));
        }
        assert_eq!(c.state.current_ms, INITIAL_MS);
        assert_eq!(c.state.samples, 8);
    }
}
