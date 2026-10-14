//! Receiver-local block-rate budget. Widening never renews a symbol's lifetime.
use serde::Serialize;
use std::time::{Duration, Instant};

pub const MIN_BLOCKS: u64 = 256;
pub const MAX_BLOCKS: u64 = 2048;
pub const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub current_blocks: u64,
    pub peak_blocks: u64,
    pub maximum_blocks: u64,
    pub retained_decoder_bytes: usize,
    pub peak_decoder_bytes: usize,
    pub maximum_decoder_bytes: usize,
    pub byte_evicted_blocks: u64,
    pub measured_blocks_per_second: u64,
}

pub struct Controller {
    anchor: Option<(u64, Instant)>,
    high: u64,
    rate_buckets: [(Option<Instant>, u64); 8],
    cursor: usize,
    last_decay: Option<Instant>,
    state: Snapshot,
}

impl Default for Controller {
    fn default() -> Self {
        Self {
            anchor: None,
            high: 0,
            rate_buckets: [(None, 0); 8],
            cursor: 0,
            last_decay: None,
            state: Snapshot {
                current_blocks: MIN_BLOCKS,
                peak_blocks: MIN_BLOCKS,
                maximum_blocks: MAX_BLOCKS,
                retained_decoder_bytes: 0,
                peak_decoder_bytes: 0,
                maximum_decoder_bytes: MAX_BYTES,
                byte_evicted_blocks: 0,
                measured_blocks_per_second: 0,
            },
        }
    }
}

impl Controller {
    pub fn current_blocks(&self) -> u64 {
        self.state.current_blocks
    }
    pub fn observe(&mut self, block: u64, now: Instant, hold: Duration) -> u64 {
        let Some((first, at)) = self.anchor else {
            self.anchor = Some((block, now));
            self.high = block;
            self.last_decay = Some(now);
            return self.state.current_blocks;
        };
        if block <= self.high {
            return self.state.current_blocks;
        }
        self.high = block;
        let elapsed = now.saturating_duration_since(at);
        let advances = block.saturating_sub(first);
        if elapsed >= Duration::from_millis(25)
            || (advances >= 64 && elapsed >= Duration::from_millis(1))
        {
            let rate = (u128::from(advances) * 1_000_000 / elapsed.as_micros().max(1))
                .min(u128::from(u64::MAX)) as u64;
            let slot = &mut self.rate_buckets[self.cursor];
            if slot
                .0
                .is_some_and(|at| now.saturating_duration_since(at) >= Duration::from_millis(125))
            {
                self.cursor = (self.cursor + 1) % self.rate_buckets.len();
                self.rate_buckets[self.cursor] = (Some(now), rate);
            } else {
                slot.0.get_or_insert(now);
                slot.1 = slot.1.max(rate);
            }
            self.anchor = Some((block, now));
            let peak = self
                .rate_buckets
                .iter()
                .filter(|(at, _)| {
                    at.is_some_and(|at| now.saturating_duration_since(at) < Duration::from_secs(1))
                })
                .map(|(_, rate)| *rate)
                .max()
                .unwrap_or(rate);
            self.state.measured_blocks_per_second = peak;
            // Include time-derived headroom and room for the independent small lane.
            let target = (u128::from(peak) * hold.as_micros() * 5 / 4 / 1_000_000 + 32)
                .clamp(u128::from(MIN_BLOCKS), u128::from(MAX_BLOCKS))
                as u64;
            if target > self.state.current_blocks {
                self.state.current_blocks = target;
                self.last_decay = Some(now);
            } else if self
                .last_decay
                .is_some_and(|at| now.saturating_duration_since(at) >= Duration::from_secs(1))
            {
                self.state.current_blocks =
                    target.max(self.state.current_blocks - self.state.current_blocks / 10);
                self.last_decay = Some(now);
            }
            self.state.peak_blocks = self.state.peak_blocks.max(self.state.current_blocks);
        }
        self.state.current_blocks
    }

    pub fn account(&mut self, bytes: usize, evicted: u64) {
        debug_assert!(bytes <= MAX_BYTES);
        self.state.retained_decoder_bytes = bytes;
        self.state.peak_decoder_bytes = self.state.peak_decoder_bytes.max(bytes);
        self.state.byte_evicted_blocks += evicted;
    }

    pub fn snapshot(&self) -> Snapshot {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn high_rate_widens_before_the_original_window_is_exhausted() {
        let start = Instant::now();
        let mut c = Controller::default();
        c.observe(0, start, Duration::from_millis(100));
        let size = c.observe(
            150,
            start + Duration::from_millis(25),
            Duration::from_millis(100),
        );
        assert!((750..=MAX_BLOCKS).contains(&size));
        assert_eq!(
            c.observe(
                90,
                start + Duration::from_millis(200),
                Duration::from_millis(250)
            ),
            size
        );
        assert_eq!(
            c.observe(
                150,
                start + Duration::from_millis(240),
                Duration::from_millis(250)
            ),
            size
        );
    }
    #[test]
    fn sparse_input_stays_small_and_bursts_never_exceed_the_bound() {
        let start = Instant::now();
        let mut sparse = Controller::default();
        for i in 0..100 {
            assert_eq!(
                sparse.observe(
                    i,
                    start + Duration::from_millis(i * 20),
                    Duration::from_millis(100)
                ),
                MIN_BLOCKS
            );
        }
        let mut burst = Controller::default();
        burst.observe(1, start, Duration::from_millis(250));
        assert_eq!(
            burst.observe(
                1_000_000,
                start + Duration::from_millis(1),
                Duration::from_millis(250)
            ),
            MAX_BLOCKS
        );
        for i in 0..100 {
            assert!(
                burst.observe(
                    1_000_001 + i,
                    start + Duration::from_millis(30 + i * 100),
                    Duration::from_millis(50)
                ) <= MAX_BLOCKS
            );
        }
        assert!(burst.snapshot().current_blocks < MAX_BLOCKS);
    }
}
