//! Receiver-service-validated exploration for original-only traffic.
//!
//! A low queue is permission to measure, never a capacity estimate. Temporary
//! baseline/trial phases defer ordinary loss brakes for a bounded interval;
//! positive service at the trial pace must be measured before that pace is kept.
use super::{FRESH_US, Observation};
use serde::Serialize;
use std::collections::VecDeque;

const QUALIFY_US: u64 = 2_000_000;
const MAX_PHASE_US: u64 = 4_000_000;
const SAMPLE_US: u64 = 1_500_000;
const SUCCESS_COOLDOWN_US: u64 = 1_000_000;
const MAX_EVENTS: usize = 16;
const MAX_SAMPLES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Watching,
    Baseline,
    Ready,
    Trial,
    Holding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    BaselineStarted,
    BaselineReady,
    TrialStarted,
    ServiceImproved,
    ServiceDidNotImprove,
    ServiceRegressed,
    InsufficientEvidence,
    DemandPaused,
    FeedbackStale,
    HardQueue,
    FastLoss,
    TransportBlocked,
    HealthLost,
    Disabled,
    CleanServiceRestored,
}

#[derive(Clone, Debug, Serialize)]
pub struct Transition {
    pub number: u64,
    pub at_us: u64,
    pub generation: u64,
    pub reason: Reason,
    pub from: Phase,
    pub to: Phase,
    pub baseline_bps: u64,
    pub trial_bps: u64,
    /// Unique symbol-byte service. FEC/redundancy must be disabled; this is not
    /// application payload goodput or a claim about physical path capacity.
    pub baseline_symbol_bps: Option<f64>,
    pub measured_symbol_bps: Option<f64>,
    pub receiver_span_us: u64,
    pub report_number: Option<u64>,
    pub receiver_window_start_us: Option<u64>,
    pub receiver_window_end_us: Option<u64>,
    pub reports: usize,
    pub actual_admission_bytes: u64,
    pub integrated_allowance_bytes: f64,
    pub trial_admission_bytes: u64,
    pub queue_delay_ms: f64,
    pub loss_expected: u64,
    pub loss_lost: u64,
    pub clean_loss: CleanSummary,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub phase: Phase,
    pub enabled: bool,
    pub next_attempt_us: u64,
    pub failure_streak: u8,
    pub total_transitions: u64,
    pub evicted_transitions: u64,
    pub transitions: VecDeque<Transition>,
    pub clean_loss: CleanSummary,
}

#[derive(Clone, Copy, Debug)]
pub struct Request {
    pub generation: u64,
    pub baseline_bps: u64,
    pub trial_bps: u64,
}

#[derive(Clone, Copy)]
struct Cursor {
    number: u64,
    receiver_us: u64,
    bytes: u64,
}

impl Cursor {
    fn from_sample(sample: &Observation) -> Option<Self> {
        (sample.delivery_sample_span_us > 0 && sample.delivery_sample_span_us <= FRESH_US)
            .then_some(Self {
                number: sample.report_number,
                receiver_us: sample.delivery_report_time_us?,
                bytes: sample.delivered_bytes,
            })
    }
}

#[derive(Clone, Default)]
struct Window {
    cursor: Option<Cursor>,
    samples: VecDeque<(u64, u64)>,
}

impl Window {
    fn push(&mut self, current: Cursor) -> bool {
        let Some(previous) = self.cursor else {
            self.cursor = Some(current);
            return false;
        };
        if current.number <= previous.number
            || current.receiver_us <= previous.receiver_us
            || current.bytes < previous.bytes
        {
            return false;
        }
        let span = current.receiver_us - previous.receiver_us;
        let bytes = current.bytes - previous.bytes;
        self.cursor = Some(current);
        if span > FRESH_US {
            self.samples.clear();
            return false;
        }
        if self.samples.len() == MAX_SAMPLES {
            self.samples.pop_front();
        }
        // Both deltas use the same consumed report endpoints, including skipped
        // quality reports. The latest individual sample_span cannot normalize a
        // multi-report cumulative byte delta.
        self.samples.push_back((span, bytes));
        true
    }

    fn span(&self) -> u64 {
        self.samples.iter().map(|(span, _)| *span).sum()
    }

    fn rate(&self) -> Option<f64> {
        let span = self.span();
        (span > 0).then(|| {
            self.samples
                .iter()
                .map(|(_, bytes)| *bytes as f64)
                .sum::<f64>()
                * 8_000_000.0
                / span as f64
        })
    }

    fn complete(&self) -> bool {
        self.samples.len() >= 3 && self.span() >= SAMPLE_US
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CleanSummary {
    pub reports: usize,
    pub expected: u64,
    pub lost: u64,
    /// The endpoints are receiver-local report times, not arrival spacing.
    pub first_receiver_report_us: Option<u64>,
    pub last_receiver_report_us: Option<u64>,
}

#[derive(Default)]
struct CleanEvidence {
    batches: VecDeque<(u64, u64, u64)>,
    last_report_number: Option<u64>,
    anchored: bool,
}

impl CleanEvidence {
    fn clear(&mut self) {
        self.batches.clear();
        self.anchored = false;
    }

    fn observe(&mut self, input: &Input<'_>) {
        if input
            .sample
            .feedback_age_us
            .is_none_or(|age| age > FRESH_US)
        {
            self.clear();
            return;
        }
        if !input.new_report
            || self
                .last_report_number
                .is_some_and(|n| input.sample.report_number <= n)
        {
            return;
        }
        self.last_report_number = Some(input.sample.report_number);
        let Some(cursor) = Cursor::from_sample(input.sample) else {
            self.clear();
            return;
        };
        let Some((expected, lost)) = input.loss_batch.filter(|(expected, _)| *expected > 0) else {
            return;
        };
        if !self.anchored {
            // A cumulative prefix from before construction, idle or stale
            // feedback establishes the cursor; it is not new clean evidence.
            self.anchored = true;
            return;
        }
        if u128::from(lost) * 50 > u128::from(expected)
            || self
                .batches
                .back()
                .is_some_and(|(at, _, _)| cursor.receiver_us <= *at)
        {
            self.clear();
            // This newly consumed dirty report is a valid subsequent baseline.
            self.anchored = true;
            return;
        }
        while self
            .batches
            .front()
            .is_some_and(|(at, _, _)| cursor.receiver_us.saturating_sub(*at) > FRESH_US)
        {
            self.batches.pop_front();
        }
        if self.batches.len() == 8 {
            self.batches.pop_front();
        }
        self.batches.push_back((cursor.receiver_us, expected, lost));
    }

    fn summary(&self) -> CleanSummary {
        let (expected, lost) = self
            .batches
            .iter()
            .fold((0u64, 0u64), |(n, l), (_, dn, dl)| {
                (n.saturating_add(*dn), l.saturating_add(*dl))
            });
        CleanSummary {
            reports: self.batches.len(),
            expected,
            lost,
            first_receiver_report_us: self.batches.front().map(|(at, _, _)| *at),
            last_receiver_report_us: self.batches.back().map(|(at, _, _)| *at),
        }
    }

    fn complete(&self) -> bool {
        let proof = self.summary();
        proof.reports >= 3
            && proof.expected >= 32
            && u128::from(proof.lost) * 50 <= u128::from(proof.expected)
            && proof
                .last_receiver_report_us
                .zip(proof.first_receiver_report_us)
                .is_some_and(|(end, start)| end.saturating_sub(start) >= 1_000_000)
    }
}

#[derive(Clone)]
struct AdmissionSample {
    at_us: u64,
    span_us: u64,
    wire_bytes: u64,
    symbol_bytes: u64,
    allowance_bytes: f64,
}

#[derive(Clone)]
struct Measurement {
    started_us: u64,
    settle_until_us: u64,
    window: Window,
    admitted: u64,
    allowance: f64,
    admission_samples: VecDeque<AdmissionSample>,
}

impl Measurement {
    fn new(now: u64, settle_us: u64) -> Self {
        Self {
            started_us: now,
            settle_until_us: now.saturating_add(settle_us),
            window: Window::default(),
            admitted: 0,
            allowance: 0.0,
            admission_samples: VecDeque::new(),
        }
    }

    fn observe(&mut self, input: &Input<'_>) {
        if input.control_sample
            && input.sample.now_us.saturating_sub(input.admission_span_us) >= self.started_us
        {
            self.admitted = self.admitted.saturating_add(input.admitted);
            self.allowance += input.allowance;
            while self.admission_samples.front().is_some_and(|sample| {
                input.sample.now_us.saturating_sub(sample.at_us) >= QUALIFY_US
            }) {
                self.admission_samples.pop_front();
            }
            if self.admission_samples.len() == 16 {
                self.admission_samples.pop_front();
            }
            self.admission_samples.push_back(AdmissionSample {
                at_us: input.sample.now_us,
                span_us: input.admission_span_us,
                wire_bytes: input.admitted,
                symbol_bytes: input.admitted_symbol_bytes,
                allowance_bytes: input.allowance,
            });
        }
        if input.new_report
            && input.sample.now_us >= self.settle_until_us
            && let Some(cursor) = Cursor::from_sample(input.sample)
        {
            // Only after sender-monotonic settling do we anchor the unrelated
            // receiver clock. Every measured interval follows that anchor.
            self.window.push(cursor);
        }
    }

    fn exercised(&self) -> bool {
        let (admitted, allowance) =
            self.admission_samples
                .iter()
                .fold((0u64, 0.0), |(a, b), sample| {
                    (
                        a.saturating_add(sample.wire_bytes),
                        b + sample.allowance_bytes,
                    )
                });
        allowance > 0.0 && admitted as f64 >= allowance * 0.9
    }

    fn service_keeps_up(&self, clean_after_receiver_us: Option<u64>) -> bool {
        if !self.window.complete()
            || !self.exercised()
            || !self.window.cursor.zip(clean_after_receiver_us).is_some_and(
                |(cursor, clean_after)| {
                    cursor.receiver_us.saturating_sub(self.window.span()) >= clean_after
                },
            )
        {
            return false;
        }
        let (wire, symbol, allowance, span) =
            self.admission_samples
                .iter()
                .fold((0u64, 0u64, 0.0, 0u64), |(w, s, a, t), sample| {
                    (
                        w.saturating_add(sample.wire_bytes),
                        s.saturating_add(sample.symbol_bytes),
                        a + sample.allowance_bytes,
                        t.saturating_add(sample.span_us),
                    )
                });
        // Both cost conversion and exercise use the same recent admission
        // window in this settled, unchanged-pace measurement. Packet-size mix
        // cannot borrow the conversion ratio of a single latest control tick.
        span >= SAMPLE_US
            && symbol > 0
            && allowance > 0.0
            && self.window.rate().is_some_and(|rate| {
                rate * wire as f64 / symbol as f64 >= allowance * 8_000_000.0 / span as f64 * 0.85
            })
    }
}

#[derive(Clone)]
struct Reference {
    rate_bps: u64,
    symbol_bps: f64,
    window: Window,
}

enum State {
    Watching,
    Baseline {
        rate: u64,
        measure: Measurement,
    },
    Ready {
        reference: Reference,
        since_us: u64,
        measure: Measurement,
    },
    Trial {
        reference: Reference,
        rate: u64,
        measure: Measurement,
        admitted: u64,
    },
    Holding {
        reference: Reference,
        measure: Measurement,
        idle: bool,
    },
}

pub(super) struct Input<'a> {
    pub sample: &'a Observation,
    pub rate_bps: u64,
    pub maximum_bps: u64,
    pub queue_ms: f64,
    pub target_ms: f64,
    pub fresh: bool,
    pub healthy: bool,
    pub fast_loss: bool,
    pub blocked: bool,
    pub ordinary_loss: bool,
    pub last_growth_us: u64,
    pub stalled: bool,
    pub new_report: bool,
    pub control_sample: bool,
    pub admission_span_us: u64,
    pub admitted: u64,
    pub admitted_symbol_bytes: u64,
    pub allowance: f64,
    pub loss_expected: u64,
    pub loss_lost: u64,
    pub loss_batch: Option<(u64, u64)>,
}

#[derive(Default)]
pub(super) struct Action {
    pub protect_ordinary_loss: bool,
    pub maximum_rate: Option<u64>,
}

pub(super) struct Controller {
    state: State,
    qualify: Option<Measurement>,
    clean_loss: CleanEvidence,
    enabled: bool,
    generation: u64,
    next_attempt_us: u64,
    failure_streak: u8,
    last_observed_us: u64,
    last_report_us: Option<u64>,
    settle_us: u64,
    candidate_maximum: u64,
    candidate_allowed: bool,
    events: VecDeque<Transition>,
    total_events: u64,
    queue_ms: f64,
    loss_expected: u64,
    loss_lost: u64,
}

impl Default for Controller {
    fn default() -> Self {
        Self {
            state: State::Watching,
            qualify: None,
            clean_loss: CleanEvidence::default(),
            enabled: false,
            generation: 0,
            next_attempt_us: 0,
            failure_streak: 0,
            last_observed_us: 0,
            last_report_us: None,
            settle_us: 1_000_000,
            candidate_maximum: 0,
            candidate_allowed: false,
            events: VecDeque::new(),
            total_events: 0,
            queue_ms: 0.0,
            loss_expected: 0,
            loss_lost: 0,
        }
    }
}

impl Controller {
    fn phase(&self) -> Phase {
        match self.state {
            State::Watching => Phase::Watching,
            State::Baseline { .. } => Phase::Baseline,
            State::Ready { .. } => Phase::Ready,
            State::Trial { .. } => Phase::Trial,
            State::Holding { .. } => Phase::Holding,
        }
    }

    fn event(&mut self, now: u64, reason: Reason, to: Phase) {
        let (base, trial, reference, window, admitted, allowance, trial_admitted) =
            match &self.state {
                State::Watching => (0, 0, None, None, 0, 0.0, 0),
                State::Baseline { rate, measure } => (
                    *rate,
                    *rate,
                    None,
                    Some(&measure.window),
                    measure.admitted,
                    measure.allowance,
                    0,
                ),
                State::Ready { reference, .. } => (
                    reference.rate_bps,
                    reference.rate_bps,
                    Some(reference.symbol_bps),
                    Some(&reference.window),
                    0,
                    0.0,
                    0,
                ),
                State::Trial {
                    reference,
                    rate,
                    measure,
                    admitted,
                } => (
                    reference.rate_bps,
                    *rate,
                    Some(reference.symbol_bps),
                    Some(&measure.window),
                    measure.admitted,
                    measure.allowance,
                    *admitted,
                ),
                State::Holding {
                    reference, measure, ..
                } => (
                    reference.rate_bps,
                    reference.rate_bps,
                    Some(reference.symbol_bps),
                    Some(&measure.window),
                    measure.admitted,
                    measure.allowance,
                    0,
                ),
            };
        self.total_events = self.total_events.saturating_add(1);
        let event = Transition {
            number: self.total_events,
            at_us: now,
            generation: self.generation,
            reason,
            from: self.phase(),
            to,
            baseline_bps: base,
            trial_bps: trial,
            baseline_symbol_bps: reference,
            measured_symbol_bps: window.and_then(Window::rate),
            receiver_span_us: window.map_or(0, Window::span),
            report_number: window.and_then(|w| w.cursor.map(|c| c.number)),
            receiver_window_start_us: window
                .and_then(|w| w.cursor.map(|c| c.receiver_us.saturating_sub(w.span()))),
            receiver_window_end_us: window.and_then(|w| w.cursor.map(|c| c.receiver_us)),
            reports: window.map_or(0, |w| w.samples.len()),
            actual_admission_bytes: admitted,
            integrated_allowance_bytes: allowance,
            trial_admission_bytes: trial_admitted,
            queue_delay_ms: self.queue_ms,
            loss_expected: self.loss_expected,
            loss_lost: self.loss_lost,
            clean_loss: self.clean_loss.summary(),
        };
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn abort(&mut self, now: u64, reason: Reason, failure: bool) -> Option<u64> {
        let maximum = match &self.state {
            State::Trial { reference, .. } => Some(reference.rate_bps),
            _ => None,
        };
        if !matches!(self.state, State::Watching) {
            self.event(now, reason, Phase::Watching);
            if failure {
                self.failure_streak = self.failure_streak.saturating_add(1).min(5);
                let cooldown = (1_000_000u64 << self.failure_streak).min(30_000_000);
                self.next_attempt_us = now.saturating_add(cooldown);
            }
        }
        self.state = State::Watching;
        self.qualify = None;
        self.clean_loss.clear();
        maximum
    }

    pub(super) fn deadline(&self) -> Option<u64> {
        match &self.state {
            State::Baseline { measure, .. } | State::Trial { measure, .. } => {
                Some(measure.started_us.saturating_add(MAX_PHASE_US))
            }
            State::Ready { since_us, .. } => Some(since_us.saturating_add(MAX_PHASE_US)),
            _ => None,
        }
    }

    pub(super) fn expire(&mut self, now: u64) -> Option<u64> {
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            self.abort(now, Reason::InsufficientEvidence, true)
        } else {
            None
        }
    }

    pub(super) fn observe(&mut self, input: Input<'_>) -> Action {
        let now = input.sample.now_us;
        self.enabled = input.sample.reprobe_enabled;
        self.generation = input.sample.generation;
        self.last_observed_us = now;
        self.queue_ms = input.queue_ms;
        self.loss_expected = input.loss_expected;
        self.loss_lost = input.loss_lost;
        self.candidate_maximum = input.maximum_bps;
        self.candidate_allowed =
            input.queue_ms <= input.target_ms * 0.4 && !input.sample.transport_blocked;
        self.settle_us = (input.sample.rtt_ms.max(0.0) * 2000.0) as u64;
        self.settle_us = self
            .settle_us
            .max(input.sample.delivery_sample_span_us.saturating_mul(2))
            .max(1_000_000);
        if input.new_report && Cursor::from_sample(input.sample).is_some() {
            self.last_report_us = Some(now);
        }
        let hard_reason = if !self.enabled {
            Some(Reason::Disabled)
        } else if !input.healthy {
            Some(Reason::HealthLost)
        } else if !input.fresh
            || (!matches!(self.state, State::Watching)
                && self
                    .last_report_us
                    .is_none_or(|at| now.saturating_sub(at) > FRESH_US))
        {
            Some(Reason::FeedbackStale)
        } else if input.queue_ms > input.target_ms * 0.5 {
            Some(Reason::HardQueue)
        } else if input.fast_loss {
            Some(Reason::FastLoss)
        } else if input.blocked {
            Some(Reason::TransportBlocked)
        } else {
            None
        };
        if let Some(reason) = hard_reason {
            return Action {
                maximum_rate: self.abort(now, reason, true),
                ..Action::default()
            };
        }
        if !input.sample.offered_backlog {
            self.clean_loss.clear();
            if let State::Holding { measure, idle, .. } = &mut self.state {
                *idle = true;
                *measure = Measurement::new(now, self.settle_us);
                self.qualify = None;
                return Action {
                    protect_ordinary_loss: true,
                    ..Action::default()
                };
            }
            return Action {
                maximum_rate: self.abort(now, Reason::DemandPaused, false),
                ..Action::default()
            };
        }
        if input.queue_ms > input.target_ms * 0.4 || input.sample.transport_blocked {
            self.qualify = None;
            self.clean_loss.clear();
            // A trial may continue below the hard queue threshold, but cannot
            // be validated or newly granted until the lower queue objective is met.
            if matches!(self.state, State::Watching) {
                return Action::default();
            }
        } else {
            self.clean_loss.observe(&input);
        }
        let clean_service_evidence = self.clean_loss.complete() && self.candidate_allowed;
        let clean_after_receiver_us = self.clean_loss.summary().first_receiver_report_us;
        match &mut self.state {
            State::Watching => {
                if now < self.next_attempt_us
                    || input.rate_bps.saturating_mul(105).div_ceil(100) > input.maximum_bps
                    || self
                        .last_report_us
                        .is_none_or(|at| now.saturating_sub(at) > FRESH_US)
                {
                    self.qualify = None;
                    return Action::default();
                }
                let qualify = self.qualify.get_or_insert_with(|| Measurement::new(now, 0));
                qualify.observe(&input);
                // Low-queue, actual-use qualification is continuous regardless
                // of temporary settling after a brake. Entry additionally
                // requires the ordinary controller to be blocked *now*. Do not
                // capture a healthy known-service recovery already in progress.
                // A report can briefly lag a growth step even after the usual
                // 600 ms settling guard. Require ordinary growth itself to be
                // quiet, without resetting continuous demand on safety brakes.
                if now.saturating_sub(qualify.started_us) >= QUALIFY_US
                    && now.saturating_sub(input.last_growth_us) >= QUALIFY_US
                    && (input.ordinary_loss || input.stalled)
                {
                    let exercised = qualify.exercised();
                    let qualification = qualify.clone();
                    self.qualify = None;
                    if exercised {
                        self.event(now, Reason::BaselineStarted, Phase::Baseline);
                        if let Some(event) = self.events.back_mut() {
                            event.baseline_bps = input.rate_bps;
                            event.trial_bps = input.rate_bps;
                            event.actual_admission_bytes = qualification.admitted;
                            event.integrated_allowance_bytes = qualification.allowance;
                            event.receiver_span_us = qualification.window.span();
                            event.reports = qualification.window.samples.len();
                            event.measured_symbol_bps = qualification.window.rate();
                            if let Some(cursor) = qualification.window.cursor {
                                event.report_number = Some(cursor.number);
                                event.receiver_window_start_us = Some(
                                    cursor
                                        .receiver_us
                                        .saturating_sub(qualification.window.span()),
                                );
                                event.receiver_window_end_us = Some(cursor.receiver_us);
                            }
                        }
                        self.state = State::Baseline {
                            rate: input.rate_bps,
                            measure: Measurement::new(now, self.settle_us),
                        };
                    }
                }
            }
            State::Baseline { rate, measure } => {
                if *rate != input.rate_bps {
                    return Action {
                        maximum_rate: self.abort(now, Reason::ServiceRegressed, true),
                        ..Action::default()
                    };
                }
                measure.observe(&input);
                if clean_service_evidence && measure.service_keeps_up(clean_after_receiver_us) {
                    return Action {
                        maximum_rate: self.abort(now, Reason::CleanServiceRestored, false),
                        ..Action::default()
                    };
                }
                if measure.window.complete()
                    && measure.exercised()
                    && input.queue_ms <= input.target_ms * 0.4
                    && let Some(symbol_bps) = measure.window.rate().filter(|rate| *rate > 0.0)
                {
                    let reference = Reference {
                        rate_bps: *rate,
                        symbol_bps,
                        window: measure.window.clone(),
                    };
                    let ready_measure = measure.clone();
                    self.event(now, Reason::BaselineReady, Phase::Ready);
                    self.state = State::Ready {
                        reference,
                        since_us: now,
                        measure: ready_measure,
                    };
                }
            }
            State::Ready {
                reference, measure, ..
            } => {
                if reference.rate_bps != input.rate_bps {
                    return Action {
                        maximum_rate: self.abort(now, Reason::ServiceRegressed, false),
                        ..Action::default()
                    };
                }
                measure.observe(&input);
                if clean_service_evidence && measure.service_keeps_up(clean_after_receiver_us) {
                    return Action {
                        maximum_rate: self.abort(now, Reason::CleanServiceRestored, false),
                        ..Action::default()
                    };
                }
                if input.new_report {
                    reference.window = measure.window.clone();
                    if reference.window.complete()
                        && reference
                            .window
                            .rate()
                            .is_some_and(|rate| rate < reference.symbol_bps * 0.9)
                        && input.allowance > 0.0
                        && input.admitted as f64 >= input.allowance * 0.9
                    {
                        return Action {
                            maximum_rate: self.abort(now, Reason::ServiceRegressed, true),
                            ..Action::default()
                        };
                    }
                    if let Some(rate) = reference.window.rate() {
                        // Waiting for the shared group grant cannot lower the
                        // comparison baseline and manufacture an eventual gain.
                        reference.symbol_bps = reference.symbol_bps.max(rate);
                    }
                }
            }
            State::Trial {
                reference,
                rate,
                measure,
                ..
            } => {
                measure.observe(&input);
                if clean_service_evidence && measure.service_keeps_up(clean_after_receiver_us) {
                    return Action {
                        maximum_rate: self.abort(now, Reason::CleanServiceRestored, false),
                        ..Action::default()
                    };
                }
                if measure.window.complete() && measure.exercised() {
                    let observed = measure.window.rate().unwrap_or(0.0);
                    let required_gain =
                        1.0 + (*rate as f64 / reference.rate_bps as f64 - 1.0) * 0.4;
                    if observed >= reference.symbol_bps * required_gain
                        && input.queue_ms <= input.target_ms * 0.4
                    {
                        let reference = Reference {
                            rate_bps: *rate,
                            symbol_bps: observed,
                            window: measure.window.clone(),
                        };
                        let mut holding = Measurement::new(now, 0);
                        holding.window = measure.window.clone();
                        self.event(now, Reason::ServiceImproved, Phase::Holding);
                        self.failure_streak = 0;
                        self.next_attempt_us = now.saturating_add(SUCCESS_COOLDOWN_US);
                        self.state = State::Holding {
                            reference,
                            measure: holding,
                            idle: false,
                        };
                    } else {
                        return Action {
                            maximum_rate: self.abort(now, Reason::ServiceDidNotImprove, true),
                            ..Action::default()
                        };
                    }
                }
            }
            State::Holding {
                reference,
                measure,
                idle,
            } => {
                if reference.rate_bps != input.rate_bps {
                    return Action {
                        maximum_rate: self.abort(now, Reason::ServiceRegressed, false),
                        ..Action::default()
                    };
                }
                if *idle {
                    *measure = Measurement::new(now, self.settle_us);
                    *idle = false;
                }
                measure.observe(&input);
                if clean_service_evidence && measure.service_keeps_up(clean_after_receiver_us) {
                    return Action {
                        maximum_rate: self.abort(now, Reason::CleanServiceRestored, false),
                        ..Action::default()
                    };
                }
                if self
                    .last_report_us
                    .is_none_or(|at| now.saturating_sub(at) > FRESH_US)
                {
                    return Action {
                        maximum_rate: self.abort(now, Reason::FeedbackStale, true),
                        ..Action::default()
                    };
                }
                if measure.exercised()
                    && measure.window.complete()
                    && measure
                        .window
                        .rate()
                        .is_some_and(|rate| rate < reference.symbol_bps * 0.9)
                {
                    return Action {
                        maximum_rate: self.abort(now, Reason::ServiceRegressed, true),
                        ..Action::default()
                    };
                }
                // Application-limited intervals cannot establish a lower
                // capacity. Holding keeps only the previously measured pace;
                // actual used admission is still required for another trial.
            }
        }
        Action {
            protect_ordinary_loss: !matches!(self.state, State::Watching),
            maximum_rate: None,
        }
    }

    pub(super) fn candidate(&self, now: u64) -> Option<Request> {
        if !self.enabled
            || !self.candidate_allowed
            || now < self.next_attempt_us
            || now.saturating_sub(self.last_observed_us) > 100_000
            || self
                .last_report_us
                .is_none_or(|at| now.saturating_sub(at) > FRESH_US)
        {
            return None;
        }
        let reference = match &self.state {
            State::Ready { reference, .. } => reference,
            State::Holding {
                reference,
                measure,
                idle,
            } if !idle && measure.exercised() && measure.window.complete() => reference,
            _ => return None,
        };
        let trial_bps = reference
            .rate_bps
            .saturating_mul(3)
            .div_ceil(2)
            .min(self.candidate_maximum);
        (trial_bps >= reference.rate_bps.saturating_mul(105).div_ceil(100)).then_some(Request {
            generation: self.generation,
            baseline_bps: reference.rate_bps,
            trial_bps,
        })
    }

    pub(super) fn start(&mut self, now: u64, maximum: u64) -> Option<u64> {
        let request = self.candidate(now)?;
        if request.trial_bps > maximum {
            return None;
        }
        let reference = match &self.state {
            State::Ready { reference, .. } => reference.clone(),
            State::Holding {
                reference, measure, ..
            } => Reference {
                rate_bps: reference.rate_bps,
                // Use the recent, fully exercised window at this same pace.
                // Improved service during holding is not caused by a future trial.
                symbol_bps: measure.window.rate()?.max(reference.symbol_bps * 0.9),
                window: measure.window.clone(),
            },
            _ => return None,
        };
        self.event(now, Reason::TrialStarted, Phase::Trial);
        if let Some(event) = self.events.back_mut() {
            event.trial_bps = request.trial_bps;
            event.baseline_symbol_bps = Some(reference.symbol_bps);
        }
        self.state = State::Trial {
            reference,
            rate: request.trial_bps,
            measure: Measurement::new(now, self.settle_us),
            admitted: 0,
        };
        Some(request.trial_bps)
    }

    pub(super) fn active(&self) -> bool {
        matches!(self.state, State::Trial { .. })
    }

    pub(super) fn admitted(&mut self, bytes: usize) {
        if let State::Trial { admitted, .. } = &mut self.state {
            *admitted = admitted.saturating_add(bytes as u64);
        }
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        Snapshot {
            phase: self.phase(),
            enabled: self.enabled,
            next_attempt_us: self.next_attempt_us,
            failure_streak: self.failure_streak,
            total_transitions: self.total_events,
            evicted_transitions: self.total_events.saturating_sub(self.events.len() as u64),
            transitions: self.events.clone(),
            clean_loss: self.clean_loss.summary(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Driver {
        controller: Controller,
        now: u64,
        rate: u64,
        bytes: u64,
        report: u64,
        ordinary_loss: bool,
        last_growth_us: u64,
        loss_batch: (u64, u64),
        loss_fresh: bool,
    }

    impl Driver {
        fn new() -> Self {
            Self {
                controller: Controller::default(),
                now: 0,
                rate: 400_000,
                bytes: 0,
                report: 0,
                ordinary_loss: true,
                last_growth_us: 0,
                loss_batch: (20, 4),
                loss_fresh: true,
            }
        }

        fn tick(&mut self, symbol_bps: u64, backlog: bool) {
            self.now += 100_000;
            let new_report = self.now.is_multiple_of(500_000);
            if new_report {
                self.report += 1;
                self.bytes += symbol_bps / 16;
            }
            let sample = Observation {
                now_us: self.now,
                generation: 71,
                report_number: self.report,
                feedback_age_us: Some(if self.loss_fresh { 0 } else { FRESH_US + 1 }),
                positive_delivery_age_us: Some(0),
                delivered_bytes: self.bytes,
                delivered_bps: Some(symbol_bps as f64),
                delivery_sample_span_us: 500_000,
                delivery_report_time_us: Some(7_000_000_000 + self.report * 500_000),
                reprobe_enabled: true,
                rtt_ms: 80.0,
                offered_backlog: backlog,
                ..Observation::default()
            };
            let allowance = self.rate as f64 / 40.0;
            let action = self.controller.observe(Input {
                sample: &sample,
                rate_bps: self.rate,
                maximum_bps: 20_000_000,
                queue_ms: 0.0,
                target_ms: 20.0,
                fresh: true,
                healthy: true,
                fast_loss: false,
                blocked: false,
                ordinary_loss: self.ordinary_loss,
                last_growth_us: self.last_growth_us,
                stalled: false,
                new_report,
                control_sample: self.now.is_multiple_of(200_000),
                admission_span_us: 200_000,
                admitted: if backlog { allowance as u64 } else { 0 },
                admitted_symbol_bytes: if backlog { allowance as u64 } else { 0 },
                allowance,
                loss_expected: 100,
                loss_lost: 20,
                loss_batch: new_report.then_some(self.loss_batch),
            });
            if let Some(maximum) = action.maximum_rate {
                self.rate = self.rate.min(maximum);
            }
        }

        fn ready(&mut self) {
            for _ in 0..100 {
                self.tick(self.rate * 4 / 5, true);
                if self.controller.candidate(self.now).is_some() {
                    return;
                }
            }
            panic!("baseline did not qualify");
        }

        fn holding() -> Self {
            let mut driver = Self::new();
            driver.ready();
            let request = driver.controller.candidate(driver.now).unwrap();
            driver.rate = driver
                .controller
                .start(driver.now, request.trial_bps)
                .unwrap();
            for _ in 0..39 {
                driver.tick(driver.rate * 4 / 5, true);
                if driver.controller.phase() == Phase::Holding {
                    return driver;
                }
            }
            panic!("growing receiver service did not validate the trial");
        }
    }

    #[test]
    fn reprobe_009_coalesced_reports_use_matching_cumulative_receiver_endpoints() {
        let mut window = Window::default();
        window.push(Cursor {
            number: 10,
            receiver_us: 70_000_000,
            bytes: 10_000,
        });
        window.push(Cursor {
            number: 13,
            receiver_us: 71_500_000,
            bytes: 160_000,
        });
        assert_eq!(window.rate(), Some(800_000.0));
        assert_eq!(window.span(), 1_500_000);
        assert!(
            !window.complete(),
            "one observed report cannot impersonate three"
        );
        assert!(!window.push(Cursor {
            number: 12,
            receiver_us: 71_000_000,
            bytes: 110_000
        }));
        assert!(!window.push(Cursor {
            number: 13,
            receiver_us: 71_500_000,
            bytes: 160_000
        }));
        assert_eq!(window.rate(), Some(800_000.0));
        for number in 14..30 {
            window.push(Cursor {
                number,
                receiver_us: 71_500_000 + (number - 13) * 500_000,
                bytes: 160_000 + (number - 13) * 50_000,
            });
        }
        assert_eq!(window.samples.len(), MAX_SAMPLES);
        assert_eq!(window.rate(), Some(800_000.0));
    }

    #[test]
    fn reprobe_009_qualification_cannot_join_distant_demand_fragments() {
        let mut driver = Driver::new();
        for _ in 0..12 {
            driver.tick(320_000, true);
        }
        driver.ordinary_loss = false;
        for _ in 0..30 {
            driver.tick(0, false);
        }
        driver.ordinary_loss = true;
        for _ in 0..12 {
            driver.tick(320_000, true);
        }
        assert_eq!(driver.controller.phase(), Phase::Watching);
        for _ in 0..12 {
            driver.tick(320_000, true);
        }
        assert_eq!(driver.controller.phase(), Phase::Baseline);
    }

    #[test]
    fn reprobe_009_events_capture_the_actual_state_and_trial_rate() {
        let driver = Driver::holding();
        let events = &driver.controller.events;
        let baseline = events
            .iter()
            .find(|e| e.reason == Reason::BaselineStarted)
            .unwrap();
        assert_eq!(
            (baseline.from, baseline.to),
            (Phase::Watching, Phase::Baseline)
        );
        assert_eq!(baseline.baseline_bps, 400_000);
        let trial = events
            .iter()
            .find(|e| e.reason == Reason::TrialStarted)
            .unwrap();
        assert_eq!((trial.from, trial.to), (Phase::Ready, Phase::Trial));
        assert_eq!((trial.baseline_bps, trial.trial_bps), (400_000, 600_000));
        let success = events
            .iter()
            .find(|e| e.reason == Reason::ServiceImproved)
            .unwrap();
        assert_eq!((success.from, success.to), (Phase::Trial, Phase::Holding));
        assert_eq!(success.baseline_symbol_bps, Some(320_000.0));
        assert_eq!(success.measured_symbol_bps, Some(480_000.0));
        assert!(success.reports >= 3 && success.receiver_span_us >= SAMPLE_US);
    }

    #[test]
    fn reprobe_009_holding_preserves_idle_reference_but_revokes_exercised_service_regression() {
        let mut driver = Driver::holding();
        let proven_rate = driver.rate;
        for _ in 0..20 {
            driver.tick(480_000, true);
        }
        // One modestly lower receiver interval cannot defeat the weighted window.
        for _ in 0..5 {
            driver.tick(384_000, true);
        }
        assert_eq!(driver.controller.phase(), Phase::Holding);
        for _ in 0..20 {
            driver.tick(0, false);
        }
        assert_eq!(driver.controller.phase(), Phase::Holding);
        assert!(driver.controller.candidate(driver.now).is_none());
        assert_eq!(driver.rate, proven_rate);
        for _ in 0..30 {
            driver.tick(480_000, true);
        }
        assert_eq!(driver.controller.phase(), Phase::Holding);
        for _ in 0..25 {
            driver.tick(240_000, true);
        }
        assert_eq!(driver.controller.phase(), Phase::Watching);
        assert!(
            driver
                .controller
                .events
                .iter()
                .any(|e| e.reason == Reason::ServiceRegressed)
        );
    }

    #[test]
    fn reprobe_009r2_clean_exit_requires_new_loss_and_exercised_receiver_service() {
        let mut driver = Driver::holding();
        let proven_rate = driver.rate;
        // Fresh positive bytes at the full allowance cannot hide persistent20%
        // finalized loss. The existing protection must remain in that case.
        for _ in 0..25 {
            driver.tick(proven_rate, true);
        }
        assert_eq!(driver.controller.phase(), Phase::Holding);
        assert!(!driver.controller.clean_loss.complete());

        driver.loss_batch = (20, 0);
        driver.ordinary_loss = false;
        // Clean loss alone is not enough if measured service still underuses
        // the fully exercised operational allowance.
        for _ in 0..25 {
            driver.tick(proven_rate * 4 / 5, true);
        }
        assert!(driver.controller.clean_loss.complete());
        assert_eq!(driver.controller.phase(), Phase::Holding);
        for _ in 0..25 {
            driver.tick(proven_rate, true);
        }
        assert_eq!(driver.controller.phase(), Phase::Watching);
        assert_eq!(
            driver.rate, proven_rate,
            "clean exit cannot jump to remembered capacity"
        );
        let event = driver
            .controller
            .events
            .iter()
            .find(|event| event.reason == Reason::CleanServiceRestored)
            .unwrap();
        assert_eq!((event.from, event.to), (Phase::Holding, Phase::Watching));
        assert!(event.clean_loss.reports >= 3 && event.clean_loss.expected >= 32);
        assert!(event.receiver_span_us >= SAMPLE_US && event.reports >= 3);
    }

    #[test]
    fn reprobe_009r2_qualified_watcher_does_not_capture_unblocked_normal_growth() {
        let mut driver = Driver::new();
        driver.ordinary_loss = false;
        for _ in 0..50 {
            driver.tick(driver.rate, true);
        }
        assert_eq!(driver.controller.phase(), Phase::Watching);
        assert!(driver.controller.candidate(driver.now).is_none());
        // The continuous low-queue, actual-use qualification remains intact
        // while ordinary growth is unblocked. A later real shortfall may use
        // it without incorrectly stitching together separate demand periods.
        driver.ordinary_loss = true;
        driver.tick(driver.rate * 4 / 5, true);
        assert_eq!(driver.controller.phase(), Phase::Baseline);
        let event = driver.controller.events.back().unwrap();
        assert!(event.actual_admission_bytes as f64 >= event.integrated_allowance_bytes * 0.9);
    }

    #[test]
    fn reprobe_009r3_recent_normal_growth_cannot_be_captured_by_lagged_loss() {
        let mut driver = Driver::new();
        driver.ordinary_loss = false;
        for _ in 0..50 {
            driver.tick(driver.rate, true);
        }
        driver.last_growth_us = driver.now;
        driver.ordinary_loss = true;
        // Mature physical qualification and a newly settled shortfall do not
        // prove that recovery stopped only 600 ms after its last growth step.
        for _ in 0..6 {
            driver.tick(driver.rate * 4 / 5, true);
        }
        assert_eq!(driver.now - driver.last_growth_us, 600_000);
        assert_eq!(driver.controller.phase(), Phase::Watching);
        for _ in 0..13 {
            // A brake's short settling interval may temporarily remove loss
            // pressure, but cannot reset the independently exercised demand.
            driver.ordinary_loss = !driver.ordinary_loss;
            driver.tick(driver.rate * 4 / 5, true);
        }
        assert_eq!(driver.now - driver.last_growth_us, 1_900_000);
        assert_eq!(driver.controller.phase(), Phase::Watching);
        driver.ordinary_loss = true;
        driver.tick(driver.rate * 4 / 5, true);
        assert_eq!(driver.now - driver.last_growth_us, QUALIFY_US);
        assert_eq!(driver.controller.phase(), Phase::Baseline);
    }

    #[test]
    fn reprobe_009r2_first_prefix_and_stale_loss_cannot_manufacture_clean_evidence() {
        let mut driver = Driver::new();
        driver.ordinary_loss = false;
        driver.loss_batch = (1_000_000, 0);
        for _ in 0..5 {
            driver.tick(400_000, true);
        }
        assert_eq!(driver.controller.clean_loss.summary().expected, 0);
        driver.loss_batch = (1, 0);
        for _ in 0..15 {
            driver.tick(400_000, true);
        }
        assert_eq!(driver.controller.clean_loss.summary().expected, 3);
        assert!(!driver.controller.clean_loss.complete());
        driver.loss_fresh = false;
        driver.loss_batch = (1_000_000, 0);
        for _ in 0..10 {
            driver.tick(400_000, true);
        }
        assert_eq!(driver.controller.clean_loss.summary().reports, 0);
        driver.loss_fresh = true;
        for _ in 0..5 {
            driver.tick(400_000, true);
        }
        assert_eq!(
            driver.controller.clean_loss.summary().reports,
            0,
            "first report after stale reset only anchors"
        );
    }

    #[test]
    fn reprobe_009r2_clean_trial_exit_withdraws_unvalidated_extra_credit() {
        let mut driver = Driver::new();
        driver.ready();
        let request = driver.controller.candidate(driver.now).unwrap();
        let baseline = request.baseline_bps;
        driver.rate = driver
            .controller
            .start(driver.now, request.trial_bps)
            .unwrap();
        driver.loss_batch = (20, 0);
        driver.ordinary_loss = false;
        for _ in 0..39 {
            driver.tick(driver.rate, true);
            if driver.controller.phase() == Phase::Watching {
                break;
            }
        }
        assert_eq!(driver.controller.phase(), Phase::Watching);
        assert_eq!(driver.rate, baseline);
        assert!(driver.controller.events.iter().any(|event| {
            event.reason == Reason::CleanServiceRestored && event.from == Phase::Trial
        }));
    }
}
