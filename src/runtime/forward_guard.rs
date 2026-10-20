//! Forward guard for a bottleneck that every path shares.
//!
//! When all routes reach the peer through one access link, a direct-drop
//! policer or shallow buffer on that link drops symbols on every path without
//! queueing delay. Each per-path controller then sees loss on a clear queue,
//! and a per-path test cannot tell its own excess from the others': when one
//! path slows, the others take the capacity it releases, so its loss barely
//! moves and looks rate-independent.
//!
//! This guard decides over the aggregate instead. Onset uses the forward loss
//! that at least two thirds of the measured paths reach, so loss confined to
//! one or two routes cannot move it. Delivery is the measured send rate less
//! the aggregate finalized loss; the peer's byte reports arrive too unevenly
//! for half-second windows. A trial caps the aggregate pacer below the
//! measured rate by three quarters of the loss above the learned floor, within
//! 10% to 40%, and compares delivery before and under the cap. Rate-independent
//! loss loses the same fraction of a lower rate, so delivery falls with the
//! cap; an overrun bottleneck delivers about the same at the lower rate, as
//! long as the cut does not go far below it, which is why the cut follows the
//! excess. A trial whose delivery falls by less than half of the cut keeps the
//! cap. A rejected trial records the loss as a rate-independent floor, as the
//! reverse guard does.
//!
//! A kept cap follows the loss above the floor it learned under the cap: loss
//! beyond the floor in two windows, or twice as far in one, sets the cap to
//! the rate that delivers the measured delivery at the floor loss, and a clean
//! binding window grows it by 5%, or by 1% within 5% of the rate the last
//! decrease cut from. Reports of the old load arrive for two more windows,
//! which decide nothing. A decrease that leaves the loss unchanged shows that
//! the loss no longer depends on the rate there, and raises the floor instead
//! of falling further. It bounds the aggregate pacer only. This is a
//! heuristic, not a capacity measurement.
use super::MAX_PATHS;
use serde::Serialize;

/// Each decision spans one window of finalized forward symbols.
const WINDOW_US: u64 = 500_000;
/// A path's window is evidence only with this many finalized symbols.
const MIN_PATH_SYMBOLS: u64 = 100;
const MIN_TRIGGER_BPS: f64 = 2_000_000.0;
const MIN_CAP_BPS: f64 = 1_000_000.0;
const ONSET_LOSS: f64 = 0.05;
const FLOOR_MARGIN: f64 = 0.04;
/// Loss above a kept cap's floor that decreases it.
const EXCESS: f64 = 0.03;
/// A trial cuts this fraction of the loss above the floor, within bounds.
const TRIAL_GAIN: f64 = 0.75;
const TRIAL_MIN: f64 = 0.6;
const TRIAL_MAX: f64 = 0.9;
/// Under the trial cap delivery must keep at least this fraction of the cut.
const HELD: f64 = 0.5;
/// A trial whose rate stayed this far above its cap did not bind.
const UNBOUND: f64 = 0.07;
const INCREASE: f64 = 1.05;
/// Growth within `PLATEAU` of the rate the last decrease cut from.
const PLATEAU_INCREASE: f64 = 1.01;
const PLATEAU: f64 = 0.05;
/// Windows after a decrease that still carry reports of the old load.
const COOLING_WINDOWS: u8 = 2;
/// A decrease cuts at most to this fraction of the lower of cap and rate.
const MAX_CUT: f64 = 0.7;
const MIN_CUT: f64 = 0.95;
/// A cap binds while the measured rate reaches this fraction of it.
const BINDING: f64 = 0.8;
/// Per-window decay of a rejected trial's floor (half-life about 17 seconds).
const FLOOR_DECAY: f64 = 0.98;
/// Per-window step of a kept cap's floor toward lower measured loss.
const FLOOR_FOLLOW: f64 = 0.1;
/// A rejected loss stays below the onset through its floor; a loss well
/// above it is tested again after this.
const RETEST_US: u64 = 3_000_000;
/// Loss this multiple of the floor, plus its margin, retests at once.
const RETEST_LOSS: f64 = 1.5;
const INCONCLUSIVE_RETEST_US: u64 = 5_000_000;
const RELEASE_WINDOWS: u32 = 20;

/// Cumulative finalized counts of one path generation from the peer's reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub generation: u64,
    pub expected: u64,
    pub lost: u64,
}

/// One window: the measured send rate and the aggregate loss reported for it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Window {
    sent: f64,
    loss: f64,
}

impl Window {
    fn delivered(self) -> f64 {
        self.sent * (1.0 - self.loss)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Open,
    Trial {
        cap: f64,
        before: Window,
        loss_before: f64,
        windows: u8,
        /// Sums of sent and delivered rates over the measured windows.
        sent: f64,
        delivered: f64,
        measured: u8,
        loss_under: f64,
    },
    Limited {
        cap: f64,
        floor: f64,
        slack_windows: u32,
        /// Rate the latest decrease cut from.
        peak: f64,
        cooling: u8,
        /// The previous window's loss was beyond the floor.
        excess: bool,
        /// Loss before the latest decrease, to check that it fell.
        decreased_from: Option<f64>,
    },
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct Snapshot {
    /// Current aggregate cap; None while the guard is open.
    pub cap_bps: Option<u64>,
    pub trials: u64,
    pub confirmed: u64,
    pub rejected: u64,
    pub inconclusive: u64,
    pub decreases: u64,
    pub releases: u64,
    /// Forward loss of the last decided window that most routes reach, before FEC.
    pub forward_loss: Option<f64>,
    /// Aggregate send rate of the last window and its delivery net of loss.
    pub sent_bps: u64,
    pub delivered_bps: u64,
    /// Rate-independent forward loss learned from a rejected trial.
    pub floor: f64,
    /// Loss a kept cap tolerates as independent of its rate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_floor: Option<f64>,
}

pub struct Guard {
    last: [Option<Counts>; MAX_PATHS],
    expected: [u64; MAX_PATHS],
    lost: [u64; MAX_PATHS],
    connected: usize,
    window_start_us: Option<u64>,
    sent_at_start: u64,
    previous: Option<Window>,
    /// Onset of the last three windows, newest in the lowest bit.
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
            connected: 0,
            window_start_us: None,
            sent_at_start: 0,
            previous: None,
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

    /// Whether loss that most paths share is being tested or limited here;
    /// per-path loss tests cannot attribute it meanwhile.
    pub fn shared_loss(&self) -> bool {
        self.state != State::Open || self.onset_windows != 0
    }

    /// `paths` are cumulative forward counts by path id; `sent_bytes` is this
    /// direction's cumulative transmitted symbol bytes over all paths.
    /// Returns whether the cap changed.
    pub fn observe(&mut self, now_us: u64, paths: &[(usize, Counts)], sent_bytes: u64) -> bool {
        self.connected = paths.iter().filter(|(id, _)| *id < MAX_PATHS).count();
        for &(id, counts) in paths {
            let Some(slot) = self.last.get_mut(id) else {
                continue;
            };
            // A new generation restarts its own baseline; counts never go back.
            if let Some(old) = *slot
                && old.generation == counts.generation
                && counts.expected >= old.expected
                && counts.lost >= old.lost
            {
                let expected = counts.expected - old.expected;
                self.expected[id] += expected;
                self.lost[id] += (counts.lost - old.lost).min(expected);
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
        let sent = sent_bytes.saturating_sub(self.sent_at_start) as f64 * 8e6 / elapsed as f64;
        let common = self.common_loss();
        let (expected, lost) = (
            self.expected.iter().sum::<u64>(),
            self.lost.iter().sum::<u64>(),
        );
        let window = common.map(|_| Window {
            sent,
            loss: lost as f64 / expected.max(1) as f64,
        });
        self.expected = [0; MAX_PATHS];
        self.lost = [0; MAX_PATHS];
        self.window_start_us = Some(now_us);
        self.sent_at_start = sent_bytes;
        let before = self.snapshot.cap_bps;
        self.snapshot.sent_bps = sent as u64;
        if let Some(window) = window {
            self.snapshot.delivered_bps = window.delivered() as u64;
        }
        self.decide(now_us, common.zip(window), sent);
        self.previous = window;
        (self.snapshot.cap_bps, self.snapshot.cap_floor) = match self.state {
            State::Open => (None, None),
            State::Trial { cap, .. } => (Some(cap as u64), None),
            State::Limited { cap, floor, .. } => (Some(cap as u64), Some(floor)),
        };
        self.snapshot.cap_bps != before
    }

    /// The loss that at least two thirds of the connected paths reach.
    fn common_loss(&self) -> Option<f64> {
        let needed = (self.connected * 2).div_ceil(3).max(1);
        let mut losses: Vec<f64> = self
            .expected
            .iter()
            .zip(self.lost)
            .filter(|(expected, _)| **expected >= MIN_PATH_SYMBOLS)
            .map(|(expected, lost)| lost as f64 / *expected as f64)
            .collect();
        if losses.len() < needed {
            return None;
        }
        losses.sort_by(|a, b| b.total_cmp(a));
        Some(losses[needed - 1])
    }

    /// `report` is the common loss and the window, when reports measured it.
    fn decide(&mut self, now_us: u64, report: Option<(f64, Window)>, sent: f64) {
        let loss = report.map(|(loss, _)| loss);
        self.snapshot.floor *= FLOOR_DECAY;
        if loss.is_some() {
            self.snapshot.forward_loss = loss;
        }
        if self.state == State::Open
            && self.snapshot.floor > 0.0
            && let Some(loss) = loss
            && loss < self.snapshot.floor + FLOOR_MARGIN
        {
            self.snapshot.floor = self.snapshot.floor.max(loss);
        }
        let floor = self.snapshot.floor;
        self.state = match self.state {
            State::Open => {
                // Loss well above a rejected one is no longer that loss.
                let onset = loss.is_some_and(|loss| {
                    loss >= ONSET_LOSS.max(floor + FLOOR_MARGIN)
                        && (now_us >= self.retest_after_us
                            || loss >= floor * RETEST_LOSS + FLOOR_MARGIN)
                }) && sent >= MIN_TRIGGER_BPS;
                self.onset_windows = (self.onset_windows << 1 | u8::from(onset)) & 0b111;
                match report {
                    // Two of three windows: one noisy report cannot hide it.
                    Some((loss, window)) if onset && self.onset_windows.count_ones() >= 2 => {
                        self.onset_windows = 0;
                        self.snapshot.trials += 1;
                        let before = match self.previous {
                            Some(previous) => {
                                let sent = window.sent + previous.sent;
                                Window {
                                    sent: sent / 2.0,
                                    loss: 1.0
                                        - (window.delivered() + previous.delivered())
                                            / sent.max(1.0),
                                }
                            }
                            None => window,
                        };
                        let fraction =
                            (1.0 - TRIAL_GAIN * (loss - floor)).clamp(TRIAL_MIN, TRIAL_MAX);
                        State::Trial {
                            cap: (before.sent * fraction).max(MIN_CAP_BPS),
                            before,
                            loss_before: loss,
                            windows: 0,
                            sent: 0.0,
                            delivered: 0.0,
                            measured: 0,
                            loss_under: 0.0,
                        }
                    }
                    _ => State::Open,
                }
            }
            State::Trial {
                cap,
                before,
                loss_before,
                windows,
                mut sent,
                mut delivered,
                mut measured,
                mut loss_under,
            } => {
                // The first window still carries the old rate's reports.
                if windows > 0
                    && let Some((loss, window)) = report
                {
                    sent += window.sent;
                    delivered += window.delivered();
                    loss_under = loss_under.max(loss);
                    measured += 1;
                }
                if measured >= 2 {
                    let n = f64::from(measured);
                    let cut = sent / n / before.sent.max(1.0);
                    let kept = delivered / n / before.delivered().max(1.0);
                    if sent / n > cap * (1.0 + UNBOUND) {
                        self.snapshot.inconclusive += 1;
                        self.retest_after_us = now_us.saturating_add(INCONCLUSIVE_RETEST_US);
                        State::Open
                    } else if kept >= cut + HELD * (1.0 - cut) {
                        self.snapshot.confirmed += 1;
                        // Loss under the trial cap may still include the
                        // overrun; a decrease that leaves it unchanged
                        // teaches the rest.
                        State::Limited {
                            cap,
                            floor: loss_under.min(floor),
                            slack_windows: 0,
                            peak: before.sent,
                            cooling: 0,
                            excess: false,
                            decreased_from: None,
                        }
                    } else {
                        self.snapshot.rejected += 1;
                        self.snapshot.floor = self.snapshot.floor.max(loss_before);
                        self.retest_after_us = now_us.saturating_add(RETEST_US);
                        State::Open
                    }
                } else if windows >= 5 {
                    // The sender stopped: no answer, and no load.
                    State::Open
                } else {
                    State::Trial {
                        cap,
                        before,
                        loss_before,
                        windows: windows + 1,
                        sent,
                        delivered,
                        measured,
                        loss_under,
                    }
                }
            }
            State::Limited {
                mut cap,
                mut floor,
                slack_windows,
                mut peak,
                mut cooling,
                mut excess,
                mut decreased_from,
            } => {
                if cooling > 0 {
                    cooling -= 1;
                } else if let Some((loss, window)) = report {
                    if let Some(from) = decreased_from.take()
                        && loss >= from - EXCESS / 2.0
                    {
                        // A lower rate lost as much: this loss is the path's.
                        floor = floor.max(loss);
                    }
                    if loss < floor {
                        floor += (loss - floor) * FLOOR_FOLLOW;
                    }
                    let beyond = loss > floor + EXCESS;
                    // Reports lag the pace: this loss may describe the
                    // previous window's rate.
                    let sent = self
                        .previous
                        .map_or(window.sent, |previous| previous.sent.max(window.sent));
                    let base = cap.min(sent);
                    if beyond && (excess || loss > floor + 2.0 * EXCESS) {
                        self.snapshot.decreases += 1;
                        cooling = COOLING_WINDOWS;
                        decreased_from = Some(loss);
                        peak = base;
                        cap = (sent * (1.0 - loss) / (1.0 - floor).max(0.05))
                            .clamp(base * MAX_CUT, base * MIN_CUT)
                            .max(MIN_CAP_BPS);
                    } else if loss <= floor + EXCESS / 2.0 && window.sent >= cap * BINDING {
                        // Grow only a cap that binds; one far above the rate
                        // the sender reaches would no longer describe the link.
                        // Near the rate that overran last, grow slowly.
                        cap *= if (cap / peak - 1.0).abs() < PLATEAU {
                            PLATEAU_INCREASE
                        } else {
                            INCREASE
                        };
                    }
                    excess = beyond && cooling == 0;
                }
                let slack_windows = if sent * 2.0 < cap {
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
                        floor,
                        slack_windows,
                        peak,
                        cooling,
                        excess,
                        decreased_from,
                    }
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive one window per call: each of four paths finalizes 1000 symbols
    /// with its loss while the aggregate sends `sent_bps`.
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
                    lost: 0,
                }; 4],
            };
            drive.call();
            drive
        }

        fn call(&mut self) -> bool {
            let paths: Vec<_> = self.counts.iter().copied().enumerate().collect();
            self.guard.observe(self.now_us, &paths, self.sent)
        }

        fn window(&mut self, losses: [f64; 4], sent_bps: f64) -> Option<u64> {
            for (counts, loss) in self.counts.iter_mut().zip(losses) {
                counts.expected += 1000;
                counts.lost += (1000.0 * loss).round() as u64;
            }
            self.now_us += WINDOW_US;
            self.sent += (sent_bps * WINDOW_US as f64 / 8e6) as u64;
            self.call();
            self.guard.cap_bps()
        }

        /// A policer of `capacity_bps` behind `random` loss, sent at `sent_bps`.
        fn policed(&mut self, sent_bps: f64, capacity_bps: f64, random: f64) -> Option<u64> {
            let passed = sent_bps.min(capacity_bps) * (1.0 - random);
            self.window([1.0 - passed / sent_bps; 4], sent_bps)
        }
    }

    #[test]
    fn an_overrun_shared_bottleneck_is_capped_near_its_rate() {
        let mut d = Drive::new();
        // Random loss alone: one trial learns it.
        d.policed(80e6, 1e9, 0.11);
        let trial = d.policed(80e6, 1e9, 0.11).expect("trial") as f64;
        assert!(d.guard.shared_loss(), "a trial defers per-path tests");
        for _ in 0..3 {
            d.policed(trial, 1e9, 0.11);
        }
        assert_eq!(d.guard.cap_bps(), None);
        assert_eq!(d.guard.snapshot().rejected, 1);
        assert!(!d.guard.shared_loss());
        // Overrunning a 90 Mbit/s policer more than twice over.
        assert_eq!(d.policed(200e6, 90e6, 0.11), None);
        let trial = d.policed(200e6, 90e6, 0.11).expect("trial") as f64;
        assert!((110e6..=130e6).contains(&trial), "{trial}");
        for _ in 0..3 {
            d.policed(trial, 90e6, 0.11);
        }
        let snapshot = d.guard.snapshot();
        assert_eq!((snapshot.confirmed, snapshot.rejected), (1, 1));
        // Under the cap the pace follows delivery to the bottleneck and
        // settles near it, with loss close to the random floor.
        let mut cap = trial;
        for _ in 0..200 {
            cap = d.policed(cap, 90e6, 0.11).unwrap() as f64;
        }
        assert!((85e6..=100e6).contains(&cap), "{cap}");
        let floor = d.guard.snapshot().cap_floor.unwrap();
        assert!((0.09..=0.13).contains(&floor), "{floor}");
    }

    #[test]
    fn a_mild_overrun_is_cut_by_its_excess_and_confirmed() {
        let mut d = Drive::new();
        d.policed(107e6, 86e6, 0.05);
        let trial = d.policed(107e6, 86e6, 0.05).expect("trial") as f64;
        assert!(trial > 86e6, "the cut stays above the bottleneck: {trial}");
        for _ in 0..3 {
            d.policed(trial, 86e6, 0.05);
        }
        assert_eq!(d.guard.snapshot().confirmed, 1);
    }

    #[test]
    fn rate_independent_loss_is_rejected_and_learned() {
        let mut d = Drive::new();
        d.window([0.3; 4], 100e6);
        let trial = d.window([0.3; 4], 100e6).expect("trial") as f64;
        for _ in 0..3 {
            d.window([0.3; 4], trial);
        }
        assert_eq!(d.guard.cap_bps(), None);
        let snapshot = d.guard.snapshot();
        assert_eq!((snapshot.trials, snapshot.rejected), (1, 1));
        assert!(snapshot.floor > 0.25);
        assert!(!d.guard.shared_loss());
        for _ in 0..80 {
            assert_eq!(d.window([0.3; 4], 100e6), None);
        }
        assert_eq!(d.guard.snapshot().trials, 1);
    }

    #[test]
    fn a_trial_the_sender_does_not_follow_decides_nothing() {
        let mut d = Drive::new();
        d.window([0.3; 4], 100e6);
        d.window([0.3; 4], 100e6).expect("trial");
        for _ in 0..3 {
            d.window([0.3; 4], 95e6);
        }
        let snapshot = d.guard.snapshot();
        assert_eq!((snapshot.inconclusive, snapshot.floor), (1, 0.0));
        assert_eq!(d.guard.cap_bps(), None);
    }

    #[test]
    fn a_decrease_that_leaves_loss_unchanged_raises_the_floor() {
        let mut d = Drive::new();
        d.policed(200e6, 90e6, 0.0);
        let trial = d.policed(200e6, 90e6, 0.0).unwrap() as f64;
        for _ in 0..3 {
            d.policed(trial, 90e6, 0.0);
        }
        assert_eq!(d.guard.snapshot().cap_floor, Some(0.0));
        // The bottleneck is gone; random loss the floor does not know yet.
        let mut cap = d.guard.cap_bps().unwrap() as f64;
        for _ in 0..200 {
            cap = d.policed(cap, 1e9, 0.08).unwrap() as f64;
        }
        assert!(cap >= trial, "the cap must not ratchet down: {cap}");
        let floor = d.guard.snapshot().cap_floor.unwrap();
        assert!((0.07..=0.09).contains(&floor), "{floor}");
    }

    #[test]
    fn one_noisy_window_neither_starts_nor_cuts() {
        let mut d = Drive::new();
        for _ in 0..10 {
            d.window([0.0; 4], 100e6);
            assert_eq!(d.window([0.08; 4], 100e6), None);
            d.window([0.0; 4], 100e6);
        }
        assert_eq!(d.guard.snapshot().trials, 0);
        d.policed(200e6, 90e6, 0.0);
        let trial = d.policed(200e6, 90e6, 0.0).unwrap();
        for _ in 0..3 {
            d.policed(trial as f64, 90e6, 0.0);
        }
        let mut cap = d.guard.cap_bps().unwrap() as f64;
        for _ in 0..40 {
            cap = d.policed(cap, 90e6, 0.0).unwrap() as f64;
        }
        let decreases = d.guard.snapshot().decreases;
        let steady = d.policed(cap, 1e9, 0.0).unwrap() as f64;
        d.window([0.04; 4], steady);
        d.window([0.0; 4], steady);
        assert_eq!(d.guard.snapshot().decreases, decreases);
    }

    #[test]
    fn loss_on_a_minority_of_routes_or_a_slow_sender_never_starts_a_trial() {
        let mut d = Drive::new();
        for _ in 0..10 {
            assert_eq!(d.window([0.4, 0.3, 0.0, 0.0], 100e6), None);
        }
        for _ in 0..10 {
            assert_eq!(d.window([0.3; 4], 1e6), None);
        }
        assert_eq!(d.guard.snapshot().trials, 0);
    }

    #[test]
    fn a_cap_far_above_demand_opens_again() {
        let mut d = Drive::new();
        d.policed(200e6, 90e6, 0.0);
        let trial = d.policed(200e6, 90e6, 0.0).unwrap() as f64;
        for _ in 0..3 {
            d.policed(trial, 90e6, 0.0);
        }
        assert!(d.guard.cap_bps().is_some());
        for _ in 0..RELEASE_WINDOWS {
            d.window([0.0; 4], 5e6);
        }
        assert_eq!(d.guard.cap_bps(), None);
        assert_eq!(d.guard.snapshot().releases, 1);
    }
}
