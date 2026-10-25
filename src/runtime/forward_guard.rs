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
//! one or two routes cannot move it. Delivery comes from the peer's unique
//! byte counts over its own report intervals. Current local admissions and
//! delayed finalized loss need not describe the same cohort, so multiplying
//! them can falsely confirm a low cap after startup or a pace change.
//! A trial caps the aggregate pacer below the
//! measured rate by three quarters of the loss above the learned floor, within
//! 10% to 40%, and compares delivery before and under the cap. Rate-independent
//! loss loses the same fraction of a lower rate, so delivery falls with the
//! cap; an overrun bottleneck delivers about the same at the lower rate, as
//! long as the cut does not go far below it, which is why the cut follows the
//! excess. A trial whose delivery falls by less than half of the cut keeps the
//! cap. A rejected trial records the loss as a rate-independent floor, as the
//! reverse guard does. If actual sending exercised the cut, each qualified
//! same-generation path can reuse its smaller before/after loss once through
//! the per-path controller's existing finite cache; queues and new loss remain
//! independently protected.
//!
//! A kept cap follows loss above its learned floor. Below the most recent
//! overrun rate it grows by 5%; at or above 95% of that rate it only probes by
//! 1%, including after crossing that rate. Every cut waits for every connected
//! path's finalized prefix to pass the symbol admitted at the cut. Initial
//! trials decide on two subsequent qualified report windows, without a blind
//! timer. Kept-cap decreases also wait at least two seconds. Only subsequent
//! report intervals enter decisions. An unchanged
//! loss raises the floor only if the actual sending rate also fell by 5%.
//! This bounds the aggregate pacer, not individual path clocks or native
//! congestion control, and remains a heuristic rather than a capacity proof.
use super::MAX_PATHS;
use serde::Serialize;

/// Each decision spans one window of finalized forward symbols.
const WINDOW_US: u64 = 500_000;
/// A provisional cut need not hold for half a second once a substantial fresh
/// cohort is finalized. Thin feedback retains the ordinary window cadence.
const TRIAL_WINDOW_US: u64 = 100_000;
const MIN_TRIAL_SYMBOLS: u64 = 1024;
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
/// Slow growth at and above this neighborhood of the last overrun rate.
const PLATEAU_INCREASE: f64 = 1.01;
const PLATEAU: f64 = 0.05;
/// Minimum settling time; finalized sequence watermarks must also pass the cut.
const SETTLE_US: u64 = 2_000_000;
const TRIAL_WINDOWS: u8 = 20;
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
    /// Cumulative local admission, used to identify pre-cut feedback.
    pub sent_symbols: u64,
    pub expected: u64,
    pub lost: u64,
    /// Unique received symbol bytes, independent of FEC recovery.
    pub received_bytes: u64,
    /// Receiver-local time of that byte report; never a sender timestamp.
    pub report_time_us: Option<u64>,
}

/// A same-generation loss observation under a rejected aggregate trial.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct RandomLoss {
    pub generation: u64,
    pub fraction: f64,
}

/// Local admission and independently measured peer delivery rates.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Window {
    sent: f64,
    delivered: f64,
}

impl Window {
    fn delivered(self) -> f64 {
        self.delivered
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Open,
    Trial {
        cap: f64,
        before: Window,
        loss_before: f64,
        paths_before: [Option<RandomLoss>; MAX_PATHS],
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
        /// The previous window's loss was beyond the floor.
        excess: bool,
        /// Loss before the latest decrease, to check that it fell.
        decreased_from: Option<(f64, f64)>,
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
    /// Post-cut symbols are pending (plus a grace period after kept-cap decreases).
    pub settling: bool,
    pub growth_threshold_bps: Option<u64>,
    pub releases: u64,
    /// Forward loss of the last decided window that most routes reach, before FEC.
    pub forward_loss: Option<f64>,
    /// Local symbol admission rate and last qualified peer delivery rate.
    pub sent_bps: u64,
    pub delivered_bps: u64,
    /// Delivery in the current receiver-clock window, absent for incomplete,
    /// stale or changed-generation byte baselines.
    pub receiver_delivery_bps: Option<u64>,
    pub delivery_unavailable_windows: u64,
    /// Rate-independent forward loss learned from a rejected trial.
    pub floor: f64,
    /// Loss a kept cap tolerates as independent of its rate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_floor: Option<f64>,
}

pub struct Guard {
    last: [Option<Counts>; MAX_PATHS],
    delivery_start: [Option<Counts>; MAX_PATHS],
    settlement: Option<Settlement>,
    window_losses: [Option<RandomLoss>; MAX_PATHS],
    learned_losses: [Option<RandomLoss>; MAX_PATHS],
    expected: [u64; MAX_PATHS],
    lost: [u64; MAX_PATHS],
    connected: usize,
    window_start_us: Option<u64>,
    sent_at_start: u64,
    previous: Option<Window>,
    /// Onset of the last three windows, newest in the lowest bit.
    onset_windows: u8,
    retest_after_us: u64,
    inconclusive_cooldown: bool,
    state: State,
    snapshot: Snapshot,
}

impl Default for Guard {
    fn default() -> Self {
        Self {
            last: [None; MAX_PATHS],
            delivery_start: [None; MAX_PATHS],
            settlement: None,
            window_losses: [None; MAX_PATHS],
            learned_losses: [None; MAX_PATHS],
            expected: [0; MAX_PATHS],
            lost: [0; MAX_PATHS],
            connected: 0,
            window_start_us: None,
            sent_at_start: 0,
            previous: None,
            onset_windows: 0,
            retest_after_us: 0,
            inconclusive_cooldown: false,
            state: State::Open,
            snapshot: Snapshot::default(),
        }
    }
}

/// Local admission watermarks avoid comparing sender and receiver clocks.
struct Settlement {
    started_us: u64,
    marks: [Option<Counts>; MAX_PATHS],
}

impl Guard {
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot.clone()
    }

    /// Consumed once so periodic observations cannot renew a path's cache.
    pub(crate) fn take_random_loss(&mut self) -> [Option<RandomLoss>; MAX_PATHS] {
        std::mem::replace(&mut self.learned_losses, [None; MAX_PATHS])
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
        self.learned_losses = [None; MAX_PATHS];
        self.connected = paths.iter().filter(|(id, _)| *id < MAX_PATHS).count();
        let mut present = [false; MAX_PATHS];
        for &(id, counts) in paths {
            if id >= MAX_PATHS {
                continue;
            }
            present[id] = true;
            if let Some(wait) = self.settlement.as_mut()
                && wait.marks[id].is_none_or(|mark| mark.generation != counts.generation)
            {
                // A replacement cannot prove delivery of the previous generation.
                wait.marks[id] = Some(counts);
                wait.started_us = now_us;
            }
        }
        for (id, present) in present.iter().enumerate() {
            if !present {
                self.last[id] = None;
                self.delivery_start[id] = None;
                self.expected[id] = 0;
                self.lost[id] = 0;
            }
        }
        // A provisional trial can finish as soon as its post-cut evidence is
        // complete. Kept caps still cool down before the next decrease: their
        // feedback may describe a queue that has not yet drained.
        let settle_us = if matches!(self.state, State::Trial { .. }) {
            0
        } else {
            SETTLE_US
        };
        let ready = self.settlement.as_ref().is_none_or(|wait| {
            now_us.saturating_sub(wait.started_us) >= settle_us
                && paths
                    .iter()
                    .filter(|(id, _)| *id < MAX_PATHS)
                    .all(|(id, _)| match (wait.marks[*id], self.last[*id]) {
                        (Some(mark), Some(old)) => {
                            old.generation == mark.generation && old.expected >= mark.sent_symbols
                        }
                        _ => false,
                    })
        });
        if ready {
            self.settlement = None;
        }
        for &(id, counts) in paths {
            let Some(slot) = self.last.get_mut(id) else {
                continue;
            };
            // A new generation restarts its own baseline; counts never go back.
            if ready
                && let Some(old) = *slot
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
        if !ready {
            // A cut must not be judged on byte progress from before its
            // admission watermark. Refresh this baseline while it settles.
            self.delivery_start = self.last;
        }
        let Some(start) = self.window_start_us else {
            self.window_start_us = Some(now_us);
            self.sent_at_start = sent_bytes;
            self.delivery_start = self.last;
            return false;
        };
        let elapsed = now_us.saturating_sub(start);
        let complete_trial_cohort = ready
            && matches!(self.state, State::Trial { .. })
            && elapsed >= TRIAL_WINDOW_US
            && self.expected.iter().sum::<u64>() >= MIN_TRIAL_SYMBOLS
            && self.common_loss().is_some();
        if elapsed < WINDOW_US && !complete_trial_cohort {
            return false;
        }
        let sent = sent_bytes.saturating_sub(self.sent_at_start) as f64 * 8e6 / elapsed as f64;
        let common = self.common_loss();
        let delivered = self.receiver_delivery(paths);
        self.snapshot.receiver_delivery_bps = delivered.map(|rate| rate as u64);
        if delivered.is_none() {
            self.snapshot.delivery_unavailable_windows += 1;
        }
        let window = common
            .zip(delivered)
            .map(|(_, delivered)| Window { sent, delivered });
        self.window_losses = std::array::from_fn(|id| {
            (self.expected[id] >= MIN_PATH_SYMBOLS)
                .then(|| {
                    self.last[id].map(|counts| RandomLoss {
                        generation: counts.generation,
                        fraction: self.lost[id] as f64 / self.expected[id] as f64,
                    })
                })
                .flatten()
        });
        self.expected = [0; MAX_PATHS];
        self.lost = [0; MAX_PATHS];
        self.window_start_us = Some(now_us);
        self.sent_at_start = sent_bytes;
        self.delivery_start = self.last;
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
        if self
            .snapshot
            .cap_bps
            .is_some_and(|cap| before.is_none_or(|old| cap < old))
        {
            // Discard every report interval that may straddle this rate change.
            self.settlement = Some(Settlement {
                started_us: now_us,
                marks: self.last,
            });
            self.previous = None;
        }
        self.snapshot.settling = self.settlement.is_some();
        self.snapshot.growth_threshold_bps = match self.state {
            State::Limited { peak, .. } => Some((peak * (1.0 - PLATEAU)) as u64),
            _ => None,
        };
        self.snapshot.cap_bps != before
    }

    fn receiver_delivery(&self, paths: &[(usize, Counts)]) -> Option<f64> {
        if paths.is_empty() {
            return None;
        }
        let mut total = 0.0;
        for &(id, counts) in paths {
            let start = self.delivery_start.get(id).copied().flatten()?;
            if start.generation != counts.generation {
                return None;
            }
            let bytes = counts.received_bytes.checked_sub(start.received_bytes)?;
            let elapsed = counts.report_time_us?.checked_sub(start.report_time_us?)?;
            if elapsed == 0 {
                return None;
            }
            total += bytes as f64 * 8e6 / elapsed as f64;
        }
        Some(total)
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
                            || (!self.inconclusive_cooldown
                                && loss >= floor * RETEST_LOSS + FLOOR_MARGIN))
                }) && sent >= MIN_TRIGGER_BPS;
                self.onset_windows = (self.onset_windows << 1 | u8::from(onset)) & 0b111;
                match report {
                    // Two of three windows: one noisy report cannot hide it.
                    Some((loss, window)) if onset && self.onset_windows.count_ones() >= 2 => {
                        self.onset_windows = 0;
                        self.inconclusive_cooldown = false;
                        self.snapshot.trials += 1;
                        let before = match self.previous {
                            Some(previous) => {
                                let sent = window.sent + previous.sent;
                                Window {
                                    sent: sent / 2.0,
                                    delivered: (window.delivered() + previous.delivered()) / 2.0,
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
                            paths_before: self.window_losses,
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
                paths_before,
                windows,
                mut sent,
                mut delivered,
                mut measured,
                mut loss_under,
            } => {
                // observe() admits only post-cut finalized intervals after settlement.
                if let Some((loss, window)) = report {
                    sent += window.sent;
                    delivered += window.delivered();
                    loss_under = loss_under.max(loss);
                    measured += 1;
                }
                if measured >= 2 {
                    let n = f64::from(measured);
                    let cut = sent / n / before.sent.max(1.0);
                    let kept = delivered / n / before.delivered().max(1.0);
                    if sent / n > cap * (1.0 + UNBOUND)
                        || before.delivered() > before.sent * (1.0 + UNBOUND)
                        || delivered > sent * (1.0 + UNBOUND)
                    {
                        // Receiver progress can lead current admissions while
                        // older in-flight traffic drains. Those windows cannot
                        // establish either capacity or rate-independent loss.
                        self.snapshot.inconclusive += 1;
                        self.inconclusive_cooldown = true;
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
                            excess: false,
                            decreased_from: None,
                        }
                    } else if loss_under + EXCESS < loss_before {
                        // Delivery fell, but loss also improved substantially:
                        // an over-deep cut or changing traffic is inconclusive,
                        // not evidence that the old loss was rate-independent.
                        self.snapshot.inconclusive += 1;
                        self.inconclusive_cooldown = true;
                        self.retest_after_us = now_us.saturating_add(INCONCLUSIVE_RETEST_US);
                        State::Open
                    } else {
                        self.snapshot.rejected += 1;
                        if cut <= MIN_CUT && sent / n >= cap * BINDING {
                            // Do not repeat the same rate test per path. Use
                            // only that path's smaller qualified before/after
                            // loss; a clean route cannot inherit a noisy one's.
                            self.learned_losses = std::array::from_fn(|id| {
                                match (paths_before[id], self.window_losses[id]) {
                                    (Some(before), Some(after))
                                        if before.generation == after.generation =>
                                    {
                                        Some(RandomLoss {
                                            generation: after.generation,
                                            fraction: before.fraction.min(after.fraction),
                                        })
                                    }
                                    _ => None,
                                }
                            });
                        }
                        self.snapshot.floor = self.snapshot.floor.max(loss_before.min(loss_under));
                        self.retest_after_us = now_us.saturating_add(RETEST_US);
                        State::Open
                    }
                } else if windows >= TRIAL_WINDOWS {
                    // Missing post-cut reports cannot establish random loss.
                    self.snapshot.inconclusive += 1;
                    self.inconclusive_cooldown = true;
                    self.retest_after_us = now_us.saturating_add(INCONCLUSIVE_RETEST_US);
                    State::Open
                } else {
                    State::Trial {
                        cap,
                        before,
                        loss_before,
                        paths_before,
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
                mut excess,
                mut decreased_from,
            } => {
                if let Some((loss, window)) = report {
                    if let Some((from, previous_sent)) = decreased_from.take()
                        && window.sent <= previous_sent * MIN_CUT
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
                        decreased_from = Some((loss, sent));
                        peak = base;
                        cap = (sent * (1.0 - loss) / (1.0 - floor).max(0.05))
                            .clamp(base * MAX_CUT, base * MIN_CUT)
                            .max(MIN_CAP_BPS);
                    } else if loss <= floor + EXCESS / 2.0 && window.sent >= cap * BINDING {
                        // Grow only a cap that binds; one far above the rate
                        // the sender reaches would no longer describe the link.
                        // Near the rate that overran last, grow slowly.
                        cap *= if cap >= peak * (1.0 - PLATEAU) {
                            PLATEAU_INCREASE
                        } else {
                            INCREASE
                        };
                    }
                    excess = beyond;
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
                    sent_symbols: 0,
                    expected: 0,
                    lost: 0,
                    received_bytes: 0,
                    report_time_us: Some(1_000_000),
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
            self.window_rates(
                losses,
                sent_bps,
                losses.map(|loss| sent_bps * (1.0 - loss) / 4.0),
            )
        }

        fn window_rates(
            &mut self,
            losses: [f64; 4],
            sent_bps: f64,
            delivered: [f64; 4],
        ) -> Option<u64> {
            for ((counts, loss), received_bps) in self.counts.iter_mut().zip(losses).zip(delivered)
            {
                counts.sent_symbols += 1000;
                counts.expected += 1000;
                counts.lost += (1000.0 * loss).round() as u64;
                counts.received_bytes += (received_bps * WINDOW_US as f64 / 8e6) as u64;
                counts.report_time_us = counts.report_time_us.map(|at| at + WINDOW_US);
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
        for _ in 0..TRIAL_WINDOWS {
            if !matches!(d.guard.state, State::Trial { .. }) {
                break;
            }
            d.policed(trial, 1e9, 0.11);
        }
        assert_eq!(d.guard.cap_bps(), None);
        assert_eq!(d.guard.snapshot().rejected, 1);
        assert!(!d.guard.shared_loss());
        // Overrunning a 90 Mbit/s policer more than twice over.
        assert_eq!(d.policed(200e6, 90e6, 0.11), None);
        let trial = d.policed(200e6, 90e6, 0.11).expect("trial") as f64;
        assert!((110e6..=130e6).contains(&trial), "{trial}");
        for _ in 0..TRIAL_WINDOWS {
            if !matches!(d.guard.state, State::Trial { .. }) {
                break;
            }
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
        for _ in 0..TRIAL_WINDOWS {
            if !matches!(d.guard.state, State::Trial { .. }) {
                break;
            }
            d.policed(trial, 86e6, 0.05);
        }
        assert_eq!(d.guard.snapshot().confirmed, 1);
    }

    #[test]
    fn rate_independent_loss_is_rejected_and_learned() {
        let mut d = Drive::new();
        d.window([0.3; 4], 100e6);
        let trial = d.window([0.3; 4], 100e6).expect("trial") as f64;
        for _ in 0..TRIAL_WINDOWS {
            if !matches!(d.guard.state, State::Trial { .. }) {
                break;
            }
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
        for _ in 0..TRIAL_WINDOWS {
            if !matches!(d.guard.state, State::Trial { .. }) {
                break;
            }
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
        for _ in 0..TRIAL_WINDOWS {
            if !matches!(d.guard.state, State::Trial { .. }) {
                break;
            }
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
        let trial = d
            .policed(200e6, 90e6, 0.0)
            .unwrap_or_else(|| d.policed(200e6, 90e6, 0.0).unwrap());
        for _ in 0..TRIAL_WINDOWS {
            if !matches!(d.guard.state, State::Trial { .. }) {
                break;
            }
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
        for _ in 0..TRIAL_WINDOWS {
            if !matches!(d.guard.state, State::Trial { .. }) {
                break;
            }
            d.policed(trial, 90e6, 0.0);
        }
        assert!(d.guard.cap_bps().is_some());
        for _ in 0..RELEASE_WINDOWS {
            d.window([0.0; 4], 5e6);
        }
        assert_eq!(d.guard.cap_bps(), None);
        assert_eq!(d.guard.snapshot().releases, 1);
    }
    #[test]
    fn growth_above_the_last_overrun_rate_stays_slow() {
        let mut d = Drive::new();
        d.guard.state = State::Limited {
            cap: 120e6,
            floor: 0.11,
            slack_windows: 0,
            peak: 100e6,
            excess: false,
            decreased_from: None,
        };
        let cap = d.window([0.11; 4], 120e6).unwrap();
        assert!(
            cap <= 121_200_001,
            "must not resume 5% growth above the peak: {cap}"
        );
    }

    #[test]
    fn delayed_old_loss_cannot_raise_a_kept_caps_floor() {
        let mut d = Drive::new();
        d.guard.state = State::Limited {
            cap: 100e6,
            floor: 0.11,
            slack_windows: 0,
            peak: 150e6,
            excess: false,
            decreased_from: None,
        };
        let cap = d.window([0.30; 4], 100e6).unwrap() as f64;
        assert!(cap < 100e6);
        for _ in 0..3 {
            d.window([0.30; 4], cap);
        }
        let floor = d.guard.snapshot().cap_floor.unwrap();
        assert!(
            floor <= 0.12,
            "old pre-cut loss must not become the floor: {floor}"
        );
    }
    #[test]
    fn old_prefix_is_rejected_even_after_the_minimum_wait() {
        let mut d = Drive::new();
        d.guard.state = State::Limited {
            cap: 100e6,
            floor: 0.11,
            slack_windows: 0,
            peak: 150e6,
            excess: false,
            decreased_from: None,
        };
        // A large outstanding prefix takes more than two seconds to finalize.
        for c in &mut d.counts {
            c.sent_symbols = 20_000;
        }
        let cap = d.window([0.30; 4], 100e6).unwrap();
        for _ in 0..8 {
            d.window([0.30; 4], cap as f64);
        }
        assert!(d.guard.snapshot().settling);
        assert_eq!(d.guard.snapshot().decreases, 1);
        assert_eq!(d.guard.snapshot().cap_floor, Some(0.11));
        // Only reports past the admission watermark can end the wait.
        for c in &mut d.counts {
            c.expected = 22_000;
            c.lost = 6_600;
        }
        d.call();
        d.window([0.11; 4], cap as f64);
        assert!(!d.guard.snapshot().settling);
        assert!(d.guard.snapshot().cap_floor.unwrap() < 0.12);
    }

    #[test]
    fn a_replaced_path_restarts_settlement_without_using_its_old_prefix() {
        let mut d = Drive::new();
        // Keep an outstanding prefix: proof, rather than a blind timer,
        // prevents this trial from finishing before the replacement.
        d.counts[0].sent_symbols = 10_000;
        d.window([0.3; 4], 100e6);
        let cap = d.window([0.3; 4], 100e6).unwrap();
        for _ in 0..3 {
            d.window([0.3; 4], cap as f64);
        }
        d.counts[0] = Counts {
            generation: 8,
            sent_symbols: 10_000,
            expected: 0,
            lost: 0,
            received_bytes: 0,
            report_time_us: Some(1_000_000),
        };
        for _ in 0..5 {
            d.window([0.3; 4], cap as f64);
        }
        assert!(d.guard.snapshot().settling);
        assert_eq!(d.guard.snapshot().rejected, 0);
        assert_eq!(d.guard.snapshot().confirmed, 0);
        // Disconnection removes that generation's evidence and wait mark.
        let paths: Vec<_> = d.counts.iter().copied().enumerate().skip(1).collect();
        d.now_us += WINDOW_US;
        d.guard.observe(d.now_us, &paths, d.sent);
        assert!(!d.guard.snapshot().settling);
    }

    #[test]
    fn lowering_a_cap_without_lowering_actual_send_cannot_teach_random_loss() {
        let mut d = Drive::new();
        d.guard.state = State::Limited {
            cap: 100e6,
            floor: 0.11,
            slack_windows: 0,
            peak: 150e6,
            excess: false,
            decreased_from: None,
        };
        d.window([0.30; 4], 100e6);
        for _ in 0..8 {
            d.window([0.30; 4], 100e6);
        }
        assert_eq!(d.guard.snapshot().cap_floor, Some(0.11));
    }

    #[test]
    fn delayed_shared_loss_does_not_create_a_high_random_floor() {
        use std::collections::VecDeque;
        let mut d = Drive::new();
        // Four windows of delayed loss: more than the former one-second cooling.
        let mut pending = VecDeque::from([0.0; 4]);
        let mut cap = 180e6_f64;
        let mut measured_loss = 0.0;
        for i in 0..240 {
            let rate = d.guard.cap_bps().map_or(cap, |v| v as f64);
            let loss = 1.0 - rate.min(90e6) * 0.89 / rate;
            pending.push_back(loss);
            measured_loss = pending.pop_front().unwrap();
            // Admission runs four finalized windows ahead, as on a delayed peer.
            for c in &mut d.counts {
                c.sent_symbols = c.expected + 4_000;
            }
            d.window_rates([measured_loss; 4], rate, [rate.min(90e6) * 0.89 / 4.0; 4]);
            cap = rate;
            if i > 60 {
                assert!(rate < 115e6, "sawtooth escaped: {rate}");
                assert!(
                    d.guard.snapshot().cap_floor.unwrap_or(0.0) < 0.17,
                    "old overload was learned as random loss"
                );
            }
        }
        assert!(d.guard.snapshot().confirmed > 0);
        assert!(measured_loss < 0.25);
        assert!(cap > 75e6, "must keep useful throughput: {cap}");
    }

    #[test]
    fn delayed_loss_and_changed_admission_cannot_falsely_confirm_a_low_cap() {
        let mut d = Drive::new();
        // The loss report describes older traffic; local admission has already
        // slowed while the peer still receives the preceding faster cohort.
        d.window_rates([0.4; 4], 800e6, [700e6 / 4.0; 4]);
        let cap = d.window_rates([0.4; 4], 500e6, [650e6 / 4.0; 4]).unwrap() as f64;
        assert_eq!(d.guard.snapshot().delivered_bps, 650_000_000);
        for _ in 0..2 {
            d.window_rates([0.0; 4], cap, [cap / 4.0; 4]);
        }
        // Actual delivery fell substantially under the trial. Inferring it as
        // current admissions * old loss would claim that it was preserved.
        assert_eq!(d.guard.snapshot().confirmed, 0);
        assert_eq!(d.guard.snapshot().inconclusive, 1);
        assert_eq!(d.guard.snapshot().floor, 0.0);
        assert_eq!(d.guard.cap_bps(), None);
    }

    #[test]
    fn inconclusive_trial_keeps_its_cooldown_even_without_a_random_loss_floor() {
        let mut d = Drive::new();
        d.window([0.3; 4], 100e6);
        d.window([0.3; 4], 100e6).unwrap();
        // The sender did not follow the trial, so no capacity or random-loss
        // conclusion is possible. A zero floor must not bypass its retry wait.
        for _ in 0..2 {
            d.window([0.3; 4], 100e6);
        }
        assert_eq!(d.guard.snapshot().inconclusive, 1);
        assert_eq!(d.guard.snapshot().floor, 0.0);
        let trials = d.guard.snapshot().trials;
        for _ in 0..9 {
            assert_eq!(d.window([0.3; 4], 100e6), None);
            assert_eq!(d.guard.snapshot().trials, trials);
        }
        d.window([0.3; 4], 100e6);
        assert!(
            d.window([0.3; 4], 100e6).is_some(),
            "fresh onset may retry after cooling"
        );
        assert_eq!(d.guard.snapshot().trials, trials + 1);
    }

    #[test]
    fn receiver_delivery_uses_each_receivers_interval_and_rejects_invalid_baselines() {
        let mut d = Drive::new();
        for (id, counts) in d.counts.iter_mut().enumerate() {
            counts.report_time_us = Some(1_000_000 + id as u64 * 90_000_000);
        }
        d.guard.delivery_start = std::array::from_fn(|id| d.counts.get(id).copied());
        d.window([0.1; 4], 80e6);
        assert_eq!(d.guard.snapshot().receiver_delivery_bps, Some(72_000_000));
        let baseline = d.guard.last;
        d.window([0.1; 4], 80e6);
        d.guard.delivery_start = baseline;
        for case in 0..4 {
            let mut paths: Vec<_> = d.counts.iter().copied().enumerate().collect();
            match case {
                0 => paths[1].1.report_time_us = None,
                1 => paths[1].1.report_time_us = Some(0),
                2 => paths[1].1.received_bytes = 0,
                3 => paths[1].1.generation += 1,
                _ => unreachable!(),
            }
            assert_eq!(d.guard.receiver_delivery(&paths), None);
        }
    }

    #[test]
    fn missing_receiver_clock_cannot_be_replaced_by_inferred_delivery() {
        let mut d = Drive::new();
        d.counts[1].report_time_us = None;
        for _ in 0..3 {
            assert_eq!(d.window([0.4; 4], 100e6), None);
        }
        assert_eq!(d.guard.snapshot().trials, 0);
        assert_eq!(d.guard.snapshot().delivery_unavailable_windows, 3);
        d.counts[1].report_time_us = Some(10_000_000);
        // The first complete report establishes a new byte baseline.
        d.window([0.4; 4], 100e6);
        assert_eq!(d.guard.snapshot().receiver_delivery_bps, None);
        d.window([0.4; 4], 100e6);
        assert_eq!(d.guard.snapshot().receiver_delivery_bps, Some(60_000_000));
    }
    #[test]
    fn qualified_random_loss_trial_does_not_wait_for_an_extra_timer() {
        let mut d = Drive::new();
        d.window([0.11; 4], 100e6);
        let cap = d.window([0.11; 4], 100e6).unwrap() as f64;
        // All four finalized prefixes are already past the cut. Two complete
        // post-cut intervals prove that delivery fell with rate, not congestion.
        for _ in 0..2 {
            d.window([0.11; 4], cap);
        }
        assert_eq!(
            d.guard.snapshot().rejected,
            1,
            "qualified feedback must not leave a random-loss startup capped"
        );
        assert_eq!(d.guard.cap_bps(), None);
    }

    #[test]
    fn a_trial_cannot_skip_its_old_prefix_to_reject_loss_early() {
        let mut d = Drive::new();
        for c in &mut d.counts {
            c.sent_symbols = 20_000;
        }
        d.window([0.11; 4], 100e6);
        let cap = d.window([0.11; 4], 100e6).unwrap() as f64;
        for _ in 0..8 {
            d.window([0.11; 4], cap);
        }
        assert!(d.guard.snapshot().settling);
        assert_eq!(
            (d.guard.snapshot().confirmed, d.guard.snapshot().rejected),
            (0, 0)
        );
        assert_eq!(d.guard.snapshot().floor, 0.0);
    }
    #[test]
    fn rejected_shared_trial_exports_only_each_paths_conservative_loss() {
        let mut d = Drive::new();
        let before = [0.0, 0.10, 0.12, 0.14];
        let after = [0.20, 0.11, 0.11, 0.13];
        d.window(before, 100e6);
        let cap = d.window(before, 100e6).unwrap() as f64;
        for _ in 0..2 {
            d.window(after, cap);
        }
        assert_eq!(d.guard.snapshot().rejected, 1);
        let floors = d.guard.take_random_loss();
        for (id, loss) in [0.0, 0.10, 0.11, 0.13].into_iter().enumerate() {
            assert_eq!(
                floors[id],
                Some(RandomLoss {
                    generation: 7,
                    fraction: loss
                })
            );
        }
        assert!(
            d.guard.take_random_loss().iter().all(Option::is_none),
            "one-shot proof"
        );
    }

    #[test]
    fn idle_sender_cannot_export_a_random_loss_baseline() {
        let mut d = Drive::new();
        d.window([0.11; 4], 100e6);
        d.window([0.11; 4], 100e6).unwrap();
        for _ in 0..2 {
            d.window([0.11; 4], 1e6);
        }
        assert_eq!(d.guard.snapshot().rejected, 1);
        assert!(d.guard.take_random_loss().iter().all(Option::is_none));
    }
    fn trial_tick(d: &mut Drive, cap: f64, symbols: u64) {
        for counts in &mut d.counts {
            counts.sent_symbols += symbols;
            counts.expected += symbols;
            counts.lost += symbols * 11 / 100;
            counts.received_bytes += (cap * 0.89 * TRIAL_WINDOW_US as f64 / 8e6 / 4.0) as u64;
            counts.report_time_us = counts.report_time_us.map(|at| at + TRIAL_WINDOW_US);
        }
        d.now_us += TRIAL_WINDOW_US;
        d.sent += (cap * TRIAL_WINDOW_US as f64 / 8e6) as u64;
        d.call();
    }

    #[test]
    fn substantial_post_cut_cohorts_finish_a_trial_without_half_second_padding() {
        let mut d = Drive::new();
        d.window([0.11; 4], 100e6);
        let cap = d.window([0.11; 4], 100e6).unwrap() as f64;
        trial_tick(&mut d, cap, 400);
        assert_eq!(
            d.guard.snapshot().rejected,
            0,
            "two cohorts are still required"
        );
        trial_tick(&mut d, cap, 400);
        assert_eq!(d.guard.snapshot().rejected, 1);
        assert!(d.guard.take_random_loss()[..4].iter().all(Option::is_some));
    }

    #[test]
    fn thin_feedback_accumulates_at_the_original_cadence() {
        let mut d = Drive::new();
        d.window([0.11; 4], 100e6);
        let cap = d.window([0.11; 4], 100e6).unwrap() as f64;
        let start = d.guard.window_start_us;
        for _ in 0..4 {
            trial_tick(&mut d, cap, 20);
        }
        assert_eq!(
            d.guard.window_start_us, start,
            "do not discard a thin cohort"
        );
        trial_tick(&mut d, cap, 20);
        assert_eq!(d.guard.snapshot().rejected, 0);
        for _ in 0..5 {
            trial_tick(&mut d, cap, 20);
        }
        assert_eq!(d.guard.snapshot().rejected, 1);
    }

    #[test]
    fn faster_trial_windows_cannot_include_the_pre_cut_prefix() {
        let mut d = Drive::new();
        d.window([0.11; 4], 100e6);
        for counts in &mut d.counts {
            counts.sent_symbols += 20_000;
        }
        let cap = d.window([0.11; 4], 100e6).unwrap() as f64;
        for _ in 0..2 {
            trial_tick(&mut d, cap, 400);
        }
        assert!(d.guard.snapshot().settling);
        assert_eq!(d.guard.snapshot().rejected, 0);
        assert!(d.guard.take_random_loss().iter().all(Option::is_none));
    }
}
