//! Reverse-path guard for an asymmetric access uplink.
//!
//! A bulk sender makes its peer send acknowledgements in proportion: native
//! QUIC ACKs, reliable-stream ACKs and their copies. When every route leaves
//! the peer through one small uplink, that reverse load can exceed it. A
//! direct-drop policer then discards the peer's requests and ACKs without any
//! queueing delay, so neither delay-based pacing nor this direction's own loss
//! reports see congestion. This endpoint does see it, as finalized loss on
//! the symbols it receives from the peer.
//!
//! Reverse loss alone is not evidence of a shared uplink: a lossy route loses
//! symbols at any rate. Every decision therefore uses the loss that at least
//! two thirds of the measured routes reach, so one or two lossy routes cannot
//! move it while a shared uplink, which drops on all of them, does. A trial lowers this direction's aggregate
//! rate and keeps the cap only when reverse loss falls by at least half. A
//! rejected trial records that loss as a rate-independent floor, which follows
//! steady loss and decays once it goes away. The cap then
//! follows reverse loss with multiplicative decrease and slow increase. It
//! bounds the aggregate pacer only; per-path controllers and native congestion
//! control remain in force. This is a heuristic, not a capacity measurement.
use super::MAX_PATHS;
use serde::Serialize;

/// Each decision spans one window of finalized reverse symbols.
const WINDOW_US: u64 = 500_000;
/// A window below this many reverse symbols is no evidence either way.
const MIN_SYMBOLS: u64 = 64;
const MIN_PATH_SYMBOLS: u64 = 16;
/// Below this rate the reverse load a sender induces is negligible.
const MIN_TRIGGER_BPS: f64 = 2_000_000.0;
const MIN_CAP_BPS: f64 = 1_000_000.0;
const ONSET_LOSS: f64 = 0.05;
const FLOOR_MARGIN: f64 = 0.04;
const CLEAR_LOSS: f64 = 0.02;
const CLEAR_MARGIN: f64 = 0.015;
const TRIAL_FRACTION: f64 = 0.7;
/// Reverse loss under the trial cap must be at most this fraction of before.
const RELIEF: f64 = 0.5;
const DECREASE: f64 = 0.85;
const INCREASE: f64 = 1.05;
/// A cap binds while the measured rate reaches this fraction of it.
const BINDING: f64 = 0.8;
/// Per-window decay of a rejected trial's floor (half-life about 17 seconds).
const FLOOR_DECAY: f64 = 0.98;
const RETEST_US: u64 = 20_000_000;
/// Windows with demand well below the cap before the guard opens again.
const RELEASE_WINDOWS: u32 = 20;

/// Cumulative finalized reverse-symbol counts of one path generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub generation: u64,
    pub expected: u64,
    pub received: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Open,
    Trial {
        cap: f64,
        loss_before: f64,
        windows: u8,
    },
    Limited {
        cap: f64,
        slack_windows: u32,
        /// The window after a decrease still carries the old reverse load.
        cooling: bool,
    },
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct Snapshot {
    /// Current aggregate cap; None while the guard is open.
    pub cap_bps: Option<u64>,
    pub trials: u64,
    pub confirmed: u64,
    pub rejected: u64,
    pub decreases: u64,
    pub releases: u64,
    /// Reverse loss of the last decided window that most routes reach, before FEC.
    pub reverse_loss: Option<f64>,
    /// Rate-independent reverse loss learned from a rejected trial.
    pub floor: f64,
}

pub struct Guard {
    last: [Option<Counts>; MAX_PATHS],
    expected: [u64; MAX_PATHS],
    lost: [u64; MAX_PATHS],
    window_start_us: Option<u64>,
    sent_at_start: u64,
    onset_windows: u8,
    retest_after_us: u64,
    state: State,
    snapshot: Snapshot,
}

impl Default for Guard {
    fn default() -> Self {
        Self {
            last: [None; MAX_PATHS],
            expected: [0; MAX_PATHS],
            lost: [0; MAX_PATHS],
            window_start_us: None,
            sent_at_start: 0,
            onset_windows: 0,
            retest_after_us: 0,
            state: State::Open,
            snapshot: Snapshot::default(),
        }
    }
}

impl Guard {
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot.clone()
    }

    pub fn cap_bps(&self) -> Option<u64> {
        self.snapshot.cap_bps
    }

    /// `paths` are cumulative reverse counts by path id; `sent_bytes` is this
    /// direction's cumulative transmitted symbol bytes over all paths.
    /// Returns whether the cap changed.
    pub fn observe(&mut self, now_us: u64, paths: &[(usize, Counts)], sent_bytes: u64) -> bool {
        for &(id, counts) in paths {
            let Some(slot) = self.last.get_mut(id) else {
                continue;
            };
            // A new generation restarts its own baseline; counts never go back.
            if let Some(old) = *slot
                && old.generation == counts.generation
                && counts.expected >= old.expected
                && counts.received >= old.received
            {
                let expected = counts.expected - old.expected;
                let received = (counts.received - old.received).min(expected);
                self.expected[id] += expected;
                self.lost[id] += expected - received;
            }
            *slot = Some(counts);
        }
        let Some(start) = self.window_start_us else {
            self.window_start_us = Some(now_us);
            self.sent_at_start = sent_bytes;
            return false;
        };
        let elapsed = now_us.saturating_sub(start);
        if elapsed < WINDOW_US {
            return false;
        }
        let rate = sent_bytes.saturating_sub(self.sent_at_start) as f64 * 8e6 / elapsed as f64;
        let loss = self.window_loss();
        self.expected = [0; MAX_PATHS];
        self.lost = [0; MAX_PATHS];
        self.window_start_us = Some(now_us);
        self.sent_at_start = sent_bytes;
        let before = self.snapshot.cap_bps;
        self.decide(now_us, loss, rate);
        self.snapshot.cap_bps = match self.state {
            State::Open => None,
            State::Trial { cap, .. } | State::Limited { cap, .. } => Some(cap as u64),
        };
        self.snapshot.cap_bps != before
    }

    /// The loss that at least two thirds of the measured paths reach.
    fn window_loss(&self) -> Option<f64> {
        if self.expected.iter().sum::<u64>() < MIN_SYMBOLS {
            return None;
        }
        let mut losses: Vec<f64> = self
            .expected
            .iter()
            .zip(self.lost)
            .filter(|(expected, _)| **expected >= MIN_PATH_SYMBOLS)
            .map(|(expected, lost)| lost as f64 / *expected as f64)
            .collect();
        if losses.is_empty() {
            return None;
        }
        losses.sort_by(|a, b| b.total_cmp(a));
        Some(losses[(losses.len() * 2).div_ceil(3) - 1])
    }

    fn decide(&mut self, now_us: u64, loss: Option<f64>, rate: f64) {
        self.snapshot.floor *= FLOOR_DECAY;
        if loss.is_some() {
            self.snapshot.reverse_loss = loss;
        }
        // A learned floor follows steady rate-independent loss and decays once
        // that loss goes away; only a rise above it can start another trial.
        if self.state == State::Open
            && self.snapshot.floor > 0.0
            && let Some(loss) = loss
            && loss < self.snapshot.floor + FLOOR_MARGIN
        {
            self.snapshot.floor = self.snapshot.floor.max(loss);
        }
        let floor = self.snapshot.floor;
        let congested = |loss: f64| loss >= ONSET_LOSS.max(floor + FLOOR_MARGIN);
        self.state = match self.state {
            State::Open => {
                let onset = loss.is_some_and(congested)
                    && rate >= MIN_TRIGGER_BPS
                    && now_us >= self.retest_after_us;
                self.onset_windows = if onset { self.onset_windows + 1 } else { 0 };
                if self.onset_windows >= 2 {
                    self.onset_windows = 0;
                    self.snapshot.trials += 1;
                    State::Trial {
                        cap: (rate * TRIAL_FRACTION).max(MIN_CAP_BPS),
                        loss_before: loss.expect("onset loss"),
                        windows: 0,
                    }
                } else {
                    State::Open
                }
            }
            State::Trial {
                cap,
                loss_before,
                windows,
            } => match loss {
                // The first window still carries reverse load of the old rate.
                Some(_) if windows == 0 => State::Trial {
                    cap,
                    loss_before,
                    windows: 1,
                },
                Some(loss) if loss <= loss_before * RELIEF => {
                    self.snapshot.confirmed += 1;
                    State::Limited {
                        cap,
                        slack_windows: 0,
                        cooling: false,
                    }
                }
                Some(_) => {
                    self.snapshot.rejected += 1;
                    self.snapshot.floor = self.snapshot.floor.max(loss_before);
                    self.retest_after_us = now_us.saturating_add(RETEST_US);
                    State::Open
                }
                None if windows < 4 => State::Trial {
                    cap,
                    loss_before,
                    windows: windows + 1,
                },
                // The peer stopped sending: no answer, and no reverse load.
                None => State::Open,
            },
            State::Limited {
                cap,
                slack_windows,
                cooling,
            } => {
                let decrease = !cooling && loss.is_some_and(congested);
                let cap = match loss {
                    _ if cooling => cap,
                    Some(_) if decrease => {
                        self.snapshot.decreases += 1;
                        (cap.min(rate) * DECREASE).max(MIN_CAP_BPS)
                    }
                    Some(loss) if loss >= CLEAR_LOSS.max(floor + CLEAR_MARGIN) => cap,
                    // Grow only a cap that binds; one far above the rate the
                    // sender reaches would no longer describe the uplink.
                    _ if rate >= cap * BINDING => cap * INCREASE,
                    _ => cap,
                };
                let slack_windows = if rate * 2.0 < cap {
                    slack_windows + 1
                } else {
                    0
                };
                if slack_windows >= RELEASE_WINDOWS {
                    self.snapshot.releases += 1;
                    State::Open
                } else {
                    State::Limited {
                        cap,
                        slack_windows,
                        cooling: decrease,
                    }
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive one window per call: `loss` of `symbols` on each of `paths`
    /// reverse paths while this direction sends at `rate_bps`.
    struct Drive {
        guard: Guard,
        now_us: u64,
        sent: u64,
        counts: [Counts; 4],
    }

    impl Drive {
        fn new() -> Self {
            let mut drive = Self {
                guard: Guard::default(),
                now_us: 1_000_000,
                sent: 0,
                counts: [Counts {
                    generation: 7,
                    expected: 0,
                    received: 0,
                }; 4],
            };
            drive.call();
            drive
        }

        fn call(&mut self) -> bool {
            let paths: Vec<_> = self.counts.iter().copied().enumerate().collect();
            self.guard.observe(self.now_us, &paths, self.sent)
        }

        fn window(&mut self, losses: [f64; 4], rate_bps: f64) -> Option<u64> {
            for (counts, loss) in self.counts.iter_mut().zip(losses) {
                counts.expected += 200;
                counts.received += 200 - (200.0 * loss).round() as u64;
            }
            self.now_us += WINDOW_US;
            self.sent += (rate_bps * WINDOW_US as f64 / 8e6) as u64;
            self.call();
            self.guard.cap_bps()
        }
    }

    #[test]
    fn rate_dependent_shared_reverse_loss_caps_this_direction() {
        let mut d = Drive::new();
        assert_eq!(d.window([0.0; 4], 80e6), None);
        assert_eq!(
            d.window([0.15; 4], 120e6),
            None,
            "one window is not an onset"
        );
        let cap = d.window([0.15; 4], 120e6).expect("trial");
        assert_eq!(cap, 84_000_000);
        // The first window under the trial still carries the old reverse load.
        assert_eq!(d.window([0.15; 4], 84e6), Some(cap));
        assert_eq!(
            d.window([0.01; 4], 84e6),
            Some(cap),
            "relief confirms the cap"
        );
        assert_eq!(d.guard.snapshot().confirmed, 1);
        // Clean windows grow slowly; renewed reverse loss decreases it.
        let grown = d.window([0.0; 4], 84e6).unwrap();
        assert_eq!(grown, (84e6 * INCREASE) as u64);
        let reduced = d.window([0.12; 4], 88e6).unwrap();
        assert_eq!(
            reduced,
            (88e6 * DECREASE) as u64,
            "from the lower of rate and cap"
        );
        // A sender limited elsewhere cannot inflate the cap.
        for _ in 0..10 {
            assert_eq!(d.window([0.0; 4], reduced as f64 * 0.6), Some(reduced));
        }
        // Loss under a non-binding cap decreases from the rate actually sent.
        let rate = reduced as f64 * 0.6;
        assert_eq!(d.window([0.12; 4], rate), Some((rate * DECREASE) as u64));
    }

    #[test]
    fn steady_loss_on_a_minority_of_routes_cannot_hold_a_confirmed_cap_down() {
        let mut d = Drive::new();
        // A shared uplink overrun at startup drops on every route.
        d.window([0.10, 0.28, 0.22, 0.06], 146e6);
        let cap = d.window([0.10, 0.28, 0.22, 0.06], 146e6).expect("trial");
        d.window([0.10, 0.28, 0.22, 0.06], cap as f64);
        d.window([0.0, 0.12, 0.13, 0.0], cap as f64);
        assert_eq!(d.guard.snapshot().confirmed, 1);
        // Two routes keep losing 12-14% at every rate; the others are clean.
        let mut cap = d.guard.cap_bps().unwrap();
        for _ in 0..40 {
            let next = d.window([0.0, 0.12, 0.14, 0.0], cap as f64).unwrap();
            assert!(next >= cap, "{next} < {cap}");
            cap = next;
        }
        assert_eq!(d.guard.snapshot().decreases, 0);
        // Loss on the clean routes too is the shared uplink again.
        let reduced = d.window([0.06, 0.22, 0.24, 0.06], cap as f64).unwrap();
        assert!((reduced as f64 / (cap as f64 * DECREASE) - 1.0).abs() < 1e-6);
        assert_eq!(
            d.window([0.06, 0.22, 0.24, 0.06], reduced as f64),
            Some(reduced),
            "the next window still carries the load before the decrease"
        );
    }

    #[test]
    fn rate_independent_reverse_loss_is_learned_and_released() {
        let mut d = Drive::new();
        d.window([0.5; 4], 60e6);
        assert!(
            d.window([0.5; 4], 60e6).is_some(),
            "high loss starts a trial"
        );
        d.window([0.5; 4], 42e6);
        assert_eq!(
            d.window([0.5; 4], 42e6),
            None,
            "loss did not follow the rate"
        );
        let snapshot = d.guard.snapshot();
        assert_eq!((snapshot.trials, snapshot.rejected), (1, 1));
        assert!(snapshot.floor > 0.45);
        // The learned floor keeps steady random loss from retrying the trial.
        for _ in 0..80 {
            assert_eq!(d.window([0.5; 4], 60e6), None);
        }
        assert_eq!(d.guard.snapshot().trials, 1);
    }

    #[test]
    fn one_lossy_route_or_low_rate_never_starts_a_trial() {
        let mut d = Drive::new();
        for _ in 0..10 {
            assert_eq!(d.window([0.4, 0.0, 0.0, 0.0], 100e6), None);
        }
        for _ in 0..10 {
            assert_eq!(
                d.window([0.2; 4], 1e6),
                None,
                "a slow sender induces no reverse load"
            );
        }
        assert_eq!(d.guard.snapshot().trials, 0);
    }

    #[test]
    fn sparse_or_new_generation_counts_are_no_evidence() {
        let mut d = Drive::new();
        d.window([0.2; 4], 100e6);
        // A path restarted with a new generation: its counts restart from zero.
        d.counts[0] = Counts {
            generation: 8,
            expected: 5,
            received: 0,
        };
        for counts in &mut d.counts[1..] {
            counts.expected += 10;
        }
        d.now_us += WINDOW_US;
        d.sent += 6_250_000;
        d.call();
        assert_eq!(
            d.guard.cap_bps(),
            None,
            "30 symbols cannot continue an onset"
        );
        assert_eq!(d.guard.snapshot().reverse_loss, Some(0.2));
    }

    #[test]
    fn a_cap_far_above_demand_opens_again() {
        let mut d = Drive::new();
        d.window([0.2; 4], 50e6);
        d.window([0.2; 4], 50e6);
        d.window([0.2; 4], 35e6);
        d.window([0.0; 4], 35e6);
        assert!(d.guard.cap_bps().is_some());
        for _ in 0..RELEASE_WINDOWS {
            d.window([0.0; 4], 5e6);
        }
        assert_eq!(d.guard.cap_bps(), None);
        assert_eq!(d.guard.snapshot().releases, 1);
    }
}
