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
use std::collections::VecDeque;

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

// Admission runs are bounded by count, not traffic volume. A busy run is
// split every 100 ms, so partial finalized prefixes can be interpolated without
// retaining per-packet allocations. Missing/evicted history cannot qualify loss.
const HISTORY_RUNS: usize = 512;
const RUN_US: u64 = 100_000;
const IDLE_GAP_US: u64 = 5_000;

#[derive(Clone, Copy)]
struct AdmissionRun {
    start: u64,
    end: u64,
    from_us: u64,
    to_us: u64,
    bytes: u64,
    backlogged: bool,
}

#[derive(Default)]
struct Admissions {
    generation: Option<u64>,
    runs: VecDeque<AdmissionRun>,
}

#[derive(Clone, Copy, Default)]
struct Cohort {
    bytes: f64,
    span_us: f64,
    symbols: u64,
    backlogged: u64,
}

impl Admissions {
    fn record(&mut self, generation: u64, run: AdmissionRun) {
        if self.generation != Some(generation) {
            self.generation = Some(generation);
            self.runs.clear();
        }
        if let Some(last) = self.runs.back_mut()
            && last.end == run.start
            && last.backlogged == run.backlogged
            && run.to_us.saturating_sub(last.from_us) <= RUN_US
            && run.from_us.saturating_sub(last.to_us) <= IDLE_GAP_US
        {
            last.end = run.end;
            last.to_us = run.to_us;
            last.bytes += run.bytes;
            return;
        }
        if self.runs.len() == HISTORY_RUNS {
            self.runs.pop_front();
        }
        self.runs.push_back(run);
    }

    fn cohort(&mut self, generation: u64, start: u64, end: u64) -> Option<Cohort> {
        if self.generation != Some(generation) || end <= start {
            return None;
        }
        while self.runs.front().is_some_and(|run| run.end <= start) {
            self.runs.pop_front();
        }
        let mut next = start;
        let mut cohort = Cohort::default();
        for run in &self.runs {
            if run.start > next {
                return None;
            }
            let stop = end.min(run.end);
            let n = stop.saturating_sub(next);
            let fraction = n as f64 / (run.end - run.start) as f64;
            cohort.bytes += run.bytes as f64 * fraction;
            cohort.span_us += run.to_us.saturating_sub(run.from_us) as f64 * fraction;
            cohort.symbols += n;
            if run.backlogged {
                cohort.backlogged += n;
            }
            next = stop;
            if next == end {
                return Some(cohort);
            }
        }
        None
    }
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
        refined: bool,
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
    /// Admission rate of the finalized cohort, excluding application-idle gaps.
    pub cohort_sent_bps: Option<u64>,
    pub backlogged_fraction: Option<f64>,
    pub cohort_unavailable_windows: u64,
    pub nonbinding_windows: u64,
    pub shared_loss: bool,
    pub recent_common_loss: Option<f64>,
    /// Early congestion hint only; never teaches floors or confirms a trial.
    pub native_common_loss: Option<f64>,
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
    admissions: [Admissions; MAX_PATHS],
    cohorts: [Cohort; MAX_PATHS],
    cohort_missing: [bool; MAX_PATHS],
    window_start_us: Option<u64>,
    sent_at_start: u64,
    previous: Option<Window>,
    /// Onset of the last three windows, newest in the lowest bit.
    onset_windows: u8,
    retest_after_us: u64,
    inconclusive_cooldown: bool,
    recent_common_loss: Option<f64>,
    native_last: [Option<(u64, u64, u64)>; MAX_PATHS],
    native_window_us: Option<u64>,
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
            admissions: std::array::from_fn(|_| Admissions::default()),
            cohorts: [Cohort::default(); MAX_PATHS],
            cohort_missing: [false; MAX_PATHS],
            window_start_us: None,
            sent_at_start: 0,
            previous: None,
            onset_windows: 0,
            retest_after_us: 0,
            inconclusive_cooldown: false,
            recent_common_loss: None,
            native_last: [None; MAX_PATHS],
            native_window_us: None,
            state: State::Open,
            snapshot: Snapshot::default(),
        }
    }
}

/// Local admission watermarks avoid comparing sender and receiver clocks.
struct Settlement {
    started_us: u64,
    minimum_us: u64,
    marks: [Option<Counts>; MAX_PATHS],
}

impl Guard {
    /// Record only successful admission, in the same sequence space as quality.
    pub(crate) fn admitted(
        &mut self,
        id: usize,
        generation: u64,
        symbol: u64,
        bytes: usize,
        now_us: u64,
        backlogged: bool,
    ) {
        let Some(history) = self.admissions.get_mut(id) else {
            return;
        };
        let from_us = history
            .runs
            .back()
            .filter(|run| {
                history.generation == Some(generation)
                    && run.backlogged == backlogged
                    && now_us.saturating_sub(run.to_us) <= IDLE_GAP_US
            })
            .map_or(now_us, |run| run.to_us);
        history.record(
            generation,
            AdmissionRun {
                start: symbol,
                end: symbol + 1,
                from_us,
                to_us: now_us,
                bytes: bytes as u64,
                backlogged,
            },
        );
    }

    pub fn snapshot(&self) -> Snapshot {
        self.snapshot.clone()
    }

    /// Native packet-loss hints arrive before the receiver's deliberate loss
    /// finalization grace. They only hold rapid native-window growth while
    /// most busy paths lose packets; the cohort/receiver test still owns every
    /// cap and random-loss verdict.
    pub(crate) fn observe_native(
        &mut self,
        now_us: u64,
        paths: &[(usize, u64, u64, u64)],
        backlogged: bool,
    ) {
        if self
            .native_window_us
            .is_some_and(|at| now_us.saturating_sub(at) < TRIAL_WINDOW_US)
        {
            return;
        }
        let connected = paths.len();
        let mut losses = Vec::with_capacity(connected);
        let mut present = [false; MAX_PATHS];
        for &(id, generation, sent, lost) in paths {
            let Some(slot) = self.native_last.get_mut(id) else {
                continue;
            };
            present[id] = true;
            if let Some((old_generation, old_sent, old_lost)) = *slot
                && old_generation == generation
                && sent >= old_sent
                && lost >= old_lost
                && sent - old_sent >= MIN_PATH_SYMBOLS
            {
                losses
                    .push((lost - old_lost).min(sent - old_sent) as f64 / (sent - old_sent) as f64);
            }
            *slot = Some((generation, sent, lost));
        }
        for (id, present) in present.iter().enumerate() {
            if !present {
                self.native_last[id] = None;
            }
        }
        self.native_window_us = Some(now_us);
        self.snapshot.native_common_loss = if backlogged && losses.len() >= connected.clamp(1, 2) {
            losses.sort_by(|a, b| b.total_cmp(a));
            Some(losses[(losses.len() * 2).div_ceil(3) - 1])
        } else {
            None
        };
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
        self.state != State::Open
            || self.onset_windows != 0
            || self
                .snapshot
                .native_common_loss
                .is_some_and(|loss| loss >= ONSET_LOSS.max(self.snapshot.floor + FLOOR_MARGIN))
            || self
                .recent_common_loss
                .is_some_and(|loss| loss >= ONSET_LOSS.max(self.snapshot.floor + FLOOR_MARGIN))
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
            if self.last[id].is_some_and(|old| old.generation != counts.generation) {
                self.expected[id] = 0;
                self.lost[id] = 0;
                self.cohorts[id] = Cohort::default();
                self.cohort_missing[id] = false;
                self.delivery_start[id] = None;
            }
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
                self.cohorts[id] = Cohort::default();
                self.cohort_missing[id] = false;
                self.admissions[id] = Admissions::default();
            }
        }
        // A provisional trial can finish as soon as its post-cut evidence is
        // complete. Kept caps still cool down before the next decrease: their
        // feedback may describe a queue that has not yet drained.
        let ready = self.settlement.as_ref().is_none_or(|wait| {
            now_us.saturating_sub(wait.started_us) >= wait.minimum_us
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
                if expected > 0 {
                    if let Some(cohort) =
                        self.admissions[id].cohort(counts.generation, old.expected, counts.expected)
                    {
                        self.cohorts[id].bytes += cohort.bytes;
                        self.cohorts[id].span_us += cohort.span_us;
                        self.cohorts[id].symbols += cohort.symbols;
                        self.cohorts[id].backlogged += cohort.backlogged;
                    } else {
                        self.cohort_missing[id] = true;
                    }
                }
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
        self.recent_common_loss = self.common_loss();
        self.snapshot.recent_common_loss = self.recent_common_loss;
        self.snapshot.shared_loss = self.shared_loss();
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
        // Finalized loss can arrive while the application is idle. Match its
        // sequence prefix to the state and rate at admission, not today's send
        // window. Peer byte delivery remains independently clocked; it is never
        // inferred by multiplying this rate by delayed loss.
        let mut cohort_rate = 0.0;
        let mut symbols = 0;
        let mut backlogged = 0;
        let mut qualified = true;
        for id in 0..MAX_PATHS {
            if self.expected[id] < MIN_PATH_SYMBOLS {
                continue;
            }
            let c = self.cohorts[id];
            symbols += c.symbols;
            backlogged += c.backlogged;
            qualified &= !self.cohort_missing[id]
                && c.symbols == self.expected[id]
                && c.span_us > 0.0
                && c.backlogged as f64 >= c.symbols as f64 * 0.9;
            cohort_rate += c.bytes * 8e6 / c.span_us.max(1.0);
        }
        qualified &= symbols > 0;
        self.snapshot.backlogged_fraction =
            (symbols > 0).then(|| backlogged as f64 / symbols as f64);
        self.snapshot.cohort_sent_bps = qualified.then_some(cohort_rate as u64);
        if !qualified {
            self.snapshot.cohort_unavailable_windows += 1;
        }
        let window = common
            .zip(delivered)
            .filter(|_| qualified)
            .map(|(_, delivered)| Window {
                sent: cohort_rate,
                delivered,
            });
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
        self.cohorts = [Cohort::default(); MAX_PATHS];
        self.cohort_missing = [false; MAX_PATHS];
        self.window_start_us = Some(now_us);
        self.sent_at_start = sent_bytes;
        self.delivery_start = self.last;
        let before = self.snapshot.cap_bps;
        self.snapshot.sent_bps = sent as u64;
        if let Some(window) = window {
            self.snapshot.delivered_bps = window.delivered() as u64;
        }
        self.decide(now_us, common.zip(window), sent);
        if let Some(window) = window {
            self.previous = Some(window);
        }
        (self.snapshot.cap_bps, self.snapshot.cap_floor) = match self.state {
            State::Open => (None, None),
            State::Trial { cap, .. } => (Some(cap as u64), None),
            State::Limited { cap, floor, .. } => (Some(cap as u64), Some(floor)),
        };
        if self.snapshot.cap_bps.is_some_and(|cap| before != Some(cap)) {
            // Discard every report interval that may straddle this rate change.
            self.settlement = Some(Settlement {
                started_us: now_us,
                minimum_us: if matches!(self.state, State::Trial { .. })
                    || before.is_some_and(|old| self.snapshot.cap_bps.is_some_and(|cap| cap > old))
                {
                    0
                } else {
                    SETTLE_US
                },
                marks: self.last,
            });
            self.previous = None;
        }
        self.snapshot.settling = self.settlement.is_some();
        self.snapshot.growth_threshold_bps = match self.state {
            State::Limited { peak, .. } => Some((peak * (1.0 - PLATEAU)) as u64),
            _ => None,
        };
        self.snapshot.shared_loss = self.shared_loss();
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

    /// The loss that at least two thirds of paths with a qualified data
    /// interval reach. Idle connected routes cannot disprove congestion on
    /// the routes carrying this flight. Multiple connected routes still need
    /// at least two measured participants before treating loss as shared.
    fn common_loss(&self) -> Option<f64> {
        let mut losses: Vec<f64> = self
            .expected
            .iter()
            .zip(self.lost)
            .filter(|(expected, _)| **expected >= MIN_PATH_SYMBOLS)
            .map(|(expected, lost)| lost as f64 / *expected as f64)
            .collect();
        if losses.len() < self.connected.clamp(1, 2) {
            return None;
        }
        let needed = (losses.len() * 2).div_ceil(3).max(1);
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
                }) && report.is_some_and(|(_, window)| window.sent >= MIN_TRIGGER_BPS);
                if report.is_some() {
                    self.onset_windows = (self.onset_windows << 1 | u8::from(onset)) & 0b111;
                }
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
                            refined: false,
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
                refined,
                windows,
                mut sent,
                mut delivered,
                mut measured,
                mut loss_under,
            } => {
                // observe() admits only post-cut finalized intervals after settlement.
                if let Some((loss, window)) = report
                    && window.sent >= cap * BINDING
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
                    } else if kept >= cut + HELD * (1.0 - cut)
                        || (loss_under <= floor + EXCESS / 2.0
                            && loss_before >= loss_under + 2.0 * EXCESS
                            && cut <= MIN_CUT
                            && kept >= cut * (1.0 + EXCESS))
                    {
                        // A binding cut that eliminates excess loss and
                        // improves delivery per admitted byte is useful even
                        // when envelope cost makes the real cut deeper than
                        // intended. Reopening it recreates the measured overrun.
                        // Independent delivery must still beat the actual cut;
                        // changed/leading byte cohorts fail the checks above.
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
                        if !refined && loss_under > floor + EXCESS && sent / n >= cap * BINDING {
                            // A startup burst can make the original delivery
                            // reference unattainable after its queue drains.
                            // The cut nevertheless reduced loss while binding.
                            // Rebase ONE further trial on measured post-cut
                            // service instead of reopening at the old peak and
                            // reproducing that overrun. This proves no capacity
                            // or random-loss floor; the new cut must settle and
                            // collect its own two qualified cohorts as usual.
                            let before = Window {
                                sent: sent / n,
                                delivered: delivered / n,
                            };
                            let fraction = (1.0 - TRIAL_GAIN * (loss_under - floor))
                                .clamp(TRIAL_MIN, TRIAL_MAX);
                            self.snapshot.trials += 1;
                            State::Trial {
                                cap: (before.sent * fraction)
                                    .min(cap * TRIAL_MAX)
                                    .max(MIN_CAP_BPS),
                                before,
                                loss_before: loss_under,
                                paths_before: self.window_losses,
                                refined: true,
                                windows: 0,
                                sent: 0.0,
                                delivered: 0.0,
                                measured: 0,
                                loss_under: 0.0,
                            }
                        } else {
                            self.inconclusive_cooldown = true;
                            self.retest_after_us = now_us.saturating_add(INCONCLUSIVE_RETEST_US);
                            State::Open
                        }
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
                        if cut <= MIN_CUT && sent / n >= cap * BINDING {
                            self.snapshot.floor =
                                self.snapshot.floor.max(loss_before.min(loss_under));
                        }
                        self.retest_after_us = now_us.saturating_add(RETEST_US);
                        State::Open
                    }
                } else if windows >= TRIAL_WINDOWS {
                    // Unexercised/missing cohorts cannot establish random loss.
                    // Retry on fresh qualified demand without a five-second blackout.
                    self.snapshot.inconclusive += 1;
                    self.inconclusive_cooldown = false;
                    self.retest_after_us = now_us;
                    State::Open
                } else {
                    if report.is_none_or(|(_, window)| window.sent < cap * BINDING) {
                        self.snapshot.nonbinding_windows += 1;
                    }
                    State::Trial {
                        cap,
                        before,
                        loss_before,
                        paths_before,
                        refined,
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
                if let Some((loss, window)) = report
                    && window.sent >= cap * BINDING
                {
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
        admitted_at_us: u64,
        admitted_bytes: u64,
    }

    impl Drive {
        fn new() -> Self {
            let mut drive = Self {
                guard: Guard::default(),
                now_us: 1_000_000,
                sent: 0,
                admitted_at_us: 1_000_000,
                admitted_bytes: 0,
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
            let last_us = self.admitted_at_us;
            let bytes = self.sent.saturating_sub(self.admitted_bytes) / 4;
            for (id, c) in self.counts.iter().enumerate() {
                let history = &mut self.guard.admissions[id];
                let start = history
                    .runs
                    .back()
                    .filter(|_| history.generation == Some(c.generation))
                    .map_or(0, |run| run.end);
                if c.sent_symbols > start {
                    history.record(
                        c.generation,
                        AdmissionRun {
                            start,
                            end: c.sent_symbols,
                            from_us: last_us,
                            to_us: self.now_us,
                            bytes,
                            backlogged: true,
                        },
                    );
                }
            }
            self.admitted_at_us = self.now_us;
            self.admitted_bytes = self.sent;
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

    fn active_window(d: &mut Drive, loss: [Option<f64>; 4]) {
        for (counts, loss) in d.counts.iter_mut().zip(loss) {
            counts.report_time_us = counts.report_time_us.map(|at| at + WINDOW_US);
            if let Some(loss) = loss {
                let lost = (1000.0 * loss) as u64;
                counts.sent_symbols += 1000;
                counts.expected += 1000;
                counts.lost += lost;
                counts.received_bytes += (1000 - lost) * 1025;
                d.sent += 1000 * 1025;
            }
        }
        d.now_us += WINDOW_US;
        d.call();
    }

    #[test]
    fn idle_connected_paths_cannot_hide_loss_on_both_active_routes() {
        let mut d = Drive::new();
        active_window(&mut d, [Some(0.3), Some(0.3), None, None]);
        assert_eq!(d.guard.cap_bps(), None);
        active_window(&mut d, [Some(0.3), Some(0.3), None, None]);
        assert_eq!(d.guard.snapshot().trials, 1);
        assert!(d.guard.cap_bps().is_some());
        assert!(d.guard.shared_loss());
    }

    #[test]
    fn shared_loss_still_requires_two_measured_routes_and_a_qualified_majority() {
        for loss in [
            [Some(0.3), None, None, None],
            [Some(0.3), Some(0.0), None, None],
            [Some(0.3), Some(0.3), Some(0.0), Some(0.0)],
        ] {
            let mut d = Drive::new();
            for _ in 0..4 {
                active_window(&mut d, loss);
            }
            assert_eq!(d.guard.snapshot().trials, 0, "{loss:?}");
            assert_eq!(d.guard.cap_bps(), None);
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
    fn a_drained_startup_burst_can_rebase_one_bound_loss_reducing_trial() {
        let mut d = Drive::new();
        for _ in 0..2 {
            d.window_rates([0.35; 4], 220e6, [160e6 / 4.0; 4]);
        }
        let original_cap = d.guard.cap_bps().unwrap() as f64;
        for _ in 0..2 {
            d.window_rates([0.15; 4], original_cap * 0.9, [120e6 / 4.0; 4]);
        }
        let refined_cap = d.guard.cap_bps().expect("keep a bounded follow-up") as f64;
        assert!(refined_cap < original_cap);
        assert!(matches!(d.guard.state, State::Trial { refined: true, .. }));
        assert_eq!(d.guard.snapshot().inconclusive, 1);
        assert_eq!(d.guard.snapshot().trials, 2);
        assert_eq!(d.guard.snapshot().floor, 0.0);
        assert!(d.guard.take_random_loss().iter().all(Option::is_none));
        for _ in 0..2 {
            d.window_rates([0.02; 4], refined_cap, [115e6 / 4.0; 4]);
        }
        assert_eq!(d.guard.snapshot().confirmed, 1);
        assert!(d.guard.cap_bps().is_some());
    }

    #[test]
    fn an_ambiguous_followup_cannot_refine_forever_or_learn_a_floor() {
        let mut d = Drive::new();
        for _ in 0..2 {
            d.window_rates([0.35; 4], 220e6, [160e6 / 4.0; 4]);
        }
        let cap = d.guard.cap_bps().unwrap() as f64;
        for _ in 0..2 {
            d.window_rates([0.15; 4], cap * 0.9, [120e6 / 4.0; 4]);
        }
        let cap = d.guard.cap_bps().unwrap() as f64;
        for _ in 0..2 {
            d.window_rates([0.10; 4], cap, [90e6 / 4.0; 4]);
        }
        assert_eq!(d.guard.cap_bps(), None);
        assert_eq!(d.guard.snapshot().trials, 2);
        assert_eq!(d.guard.snapshot().inconclusive, 2);
        assert_eq!(d.guard.snapshot().floor, 0.0);
        assert!(d.guard.take_random_loss().iter().all(Option::is_none));
    }

    #[test]
    fn a_refined_trial_must_wait_for_its_own_admission_prefix() {
        let mut d = Drive::new();
        for _ in 0..2 {
            d.window_rates([0.35; 4], 220e6, [160e6 / 4.0; 4]);
        }
        let cap = d.guard.cap_bps().unwrap() as f64;
        d.window_rates([0.15; 4], cap * 0.9, [120e6 / 4.0; 4]);
        for counts in &mut d.counts {
            counts.sent_symbols += 20_000;
        }
        d.window_rates([0.15; 4], cap * 0.9, [120e6 / 4.0; 4]);
        assert!(matches!(d.guard.state, State::Trial { refined: true, .. }));
        let cap = d.guard.cap_bps().unwrap() as f64;
        for _ in 0..8 {
            d.window_rates([0.02; 4], cap, [115e6 / 4.0; 4]);
        }
        assert!(d.guard.snapshot().settling);
        assert_eq!(d.guard.snapshot().confirmed, 0);
        assert_eq!(d.guard.snapshot().rejected, 0);
        assert_eq!(d.guard.snapshot().floor, 0.0);
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
        assert!(
            d.guard
                .settlement
                .as_ref()
                .is_none_or(|wait| wait.minimum_us == 0 && wait.started_us == d.now_us),
            "the old cut settled; only a fresh growth watermark may remain"
        );
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
        assert_eq!(d.guard.snapshot().rejected, 0);
        assert_eq!(d.guard.snapshot().floor, 0.0);
        assert!(d.guard.take_random_loss().iter().all(Option::is_none));
    }
    #[test]
    fn a_binding_cut_that_eliminates_loss_and_improves_efficiency_keeps_the_cap() {
        let mut d = Drive::new();
        for _ in 0..2 {
            d.window_rates([0.1; 4], 134e6, [120e6 / 4.0; 4]);
        }
        let cap = d.guard.cap_bps().unwrap();
        for _ in 0..2 {
            d.window_rates([0.0; 4], 106e6, [106e6 / 4.0; 4]);
        }
        assert_eq!(d.guard.cap_bps(), Some(cap));
        assert_eq!(d.guard.snapshot().confirmed, 1);
        assert_eq!(d.guard.snapshot().floor, 0.0);
    }

    #[test]
    fn block_upload_cohorts_survive_idle_gaps_and_delayed_feedback() {
        for (burst, busy, gap) in [(250e6_f64, 3, 1), (200e6, 3, 2), (250e6, 2, 1)] {
            for delay in [1, 2] {
                for phase in 0..busy + gap {
                    let mut guard = Guard::default();
                    let mut now = 1_000_000;
                    let mut sent = 0;
                    let mut counts = [Counts {
                        generation: 7,
                        sent_symbols: 0,
                        expected: 0,
                        lost: 0,
                        received_bytes: 0,
                        report_time_us: Some(now),
                    }; 4];
                    guard.observe(
                        now,
                        &counts.into_iter().enumerate().collect::<Vec<_>>(),
                        sent,
                    );
                    let mut pending = VecDeque::new();
                    let mut late_sent = 0.0;
                    let mut late_lost = 0.0;
                    for step in 0..120 {
                        let backlogged = (step + phase) % (busy + gap) < busy;
                        let rate = if backlogged {
                            guard.cap_bps().map_or(burst, |cap| burst.min(cap as f64))
                        } else {
                            2e6
                        };
                        let passed = rate.min(130e6);
                        let loss = 1.0 - passed / rate;
                        let bytes = (rate * WINDOW_US as f64 / 8e6 / 4.0) as u64;
                        let symbols = (bytes / 1400).max(1);
                        for (id, c) in counts.iter_mut().enumerate() {
                            guard.admissions[id].record(
                                c.generation,
                                AdmissionRun {
                                    start: c.sent_symbols,
                                    end: c.sent_symbols + symbols,
                                    from_us: now,
                                    to_us: now + WINDOW_US,
                                    bytes,
                                    backlogged,
                                },
                            );
                            c.sent_symbols += symbols;
                        }
                        pending.push_back((
                            symbols,
                            (symbols as f64 * loss).round() as u64,
                            (passed * WINDOW_US as f64 / 8e6 / 4.0) as u64,
                        ));
                        if pending.len() > delay {
                            let (expected, lost, received) = pending.pop_front().unwrap();
                            for c in &mut counts {
                                c.expected += expected;
                                c.lost += lost;
                                c.received_bytes += received;
                            }
                        }
                        for c in &mut counts {
                            c.report_time_us = c.report_time_us.map(|at| at + WINDOW_US);
                        }
                        sent += bytes * 4;
                        now += WINDOW_US;
                        guard.observe(
                            now,
                            &counts.into_iter().enumerate().collect::<Vec<_>>(),
                            sent,
                        );
                        let snapshot = guard.snapshot();
                        let case = (burst, busy, gap, delay, phase, step);
                        assert_eq!(
                            snapshot.floor, 0.0,
                            "false random floor: {case:?} {snapshot:?}"
                        );
                        if let Some(cap) = guard.cap_bps() {
                            assert!(
                                cap >= 65_000_000,
                                "idle collapsed the cap: {case:?} {snapshot:?}"
                            );
                        }
                        if step >= 60 && backlogged {
                            late_sent += rate;
                            late_lost += rate - passed;
                        }
                    }
                    let snapshot = guard.snapshot();
                    let case = (burst, busy, gap, delay, phase);
                    assert!(
                        snapshot.confirmed > 0,
                        "never limited: {case:?} {snapshot:?}"
                    );
                    assert!(
                        late_lost / late_sent <= 0.05,
                        "excess loss: {case:?} {} {snapshot:?}",
                        late_lost / late_sent
                    );
                    let cap = guard.cap_bps().expect("short idle must retain the cap");
                    assert!(
                        (117_000_000..=136_500_000).contains(&cap),
                        "wrong cap: {case:?} {snapshot:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn native_common_loss_holds_growth_without_granting_capacity_or_random_loss() {
        let mut g = Guard::default();
        let baseline = (0..4).map(|id| (id, 7, 1_000, 0)).collect::<Vec<_>>();
        g.observe_native(0, &baseline, true);
        let lost = (0..4).map(|id| (id, 7, 2_000, 200)).collect::<Vec<_>>();
        g.observe_native(100_000, &lost, true);
        assert!(g.shared_loss());
        assert_eq!(g.cap_bps(), None);
        assert_eq!(g.snapshot.floor, 0.0);
        assert!(g.take_random_loss().iter().all(Option::is_none));
        let clean = (0..4).map(|id| (id, 7, 3_000, 200)).collect::<Vec<_>>();
        g.observe_native(200_000, &clean, true);
        assert!(!g.shared_loss());
        let idle = (0..4).map(|id| (id, 7, 4_000, 500)).collect::<Vec<_>>();
        g.observe_native(300_000, &idle, false);
        assert!(
            !g.shared_loss(),
            "idle cannot classify a shared native flight"
        );
        let one = (0..4)
            .map(|id| (id, 7, 5_000, if id == 0 { 900 } else { 500 }))
            .collect::<Vec<_>>();
        g.observe_native(400_000, &one, true);
        assert!(
            !g.shared_loss(),
            "a single lossy route is not a common bottleneck"
        );
    }

    #[test]
    fn admission_history_is_bounded_and_cannot_cross_generations_or_missing_prefixes() {
        let mut guard = Guard::default();
        for symbol in 0..HISTORY_RUNS as u64 + 10 {
            guard.admitted(0, 7, symbol, 1400, symbol * RUN_US, true);
        }
        let history = &mut guard.admissions[0];
        assert_eq!(history.runs.len(), HISTORY_RUNS);
        assert!(
            history.cohort(7, 0, 20).is_none(),
            "evicted prefix is unknown"
        );
        assert!(history.cohort(8, 20, 30).is_none());
        assert!(history.cohort(7, 20, 30).is_some());
        guard.admitted(0, 8, 0, 1400, 100_000_000, true);
        assert_eq!(guard.admissions[0].runs.len(), 1);
        assert!(guard.admissions[0].cohort(7, 20, 30).is_none());
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
