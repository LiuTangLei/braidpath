//! Bounded per-path admission control. Rates are operational budgets, not capacity claims.
use serde::Serialize;
use std::collections::VecDeque;

mod reprobe;
mod service;
pub use reprobe::Request as ReprobeRequest;

const FRESH_US: u64 = 3_000_000;
const CONTROL_US: u64 = 200_000;
const PROBE_US: u64 = 500_000;
const FAST_PROBE_US: u64 = 100_000;
const BRAKE_US: u64 = 100_000;
const RETRY_GROWTH_US: u64 = 500_000;
const START_BPS: u64 = 256_000;
const MIN_BPS: u64 = 64_000;
const LOSS_WINDOW_US: u64 = 4_000_000;
const LOSS_BATCHES: usize = 8;
const WEIGHT_EVIDENCE_SYMBOLS: u64 = 16;

#[derive(Default)]
struct LossEvidence {
    // Each entry is one observed, nonempty finalized prefix delta. Report
    // arrival batches are not assumed to be independent statistical trials.
    batches: VecDeque<(u64, u64, u64)>,
    previous: Option<(u64, u64)>,
}

impl LossEvidence {
    fn observe(&mut self, sample: &Observation, new_report: bool) -> Option<(u64, u64)> {
        while self
            .batches
            .front()
            .is_some_and(|(at, _, _)| sample.now_us.saturating_sub(*at) > LOSS_WINDOW_US)
        {
            self.batches.pop_front();
        }
        if !new_report {
            return None;
        }
        let delta = match (sample.finalized_expected, sample.finalized_lost) {
            (Some(expected), Some(lost)) => {
                let (old_expected, old_lost) = self.previous.unwrap_or((0, 0));
                if lost > expected || expected < old_expected || lost < old_lost {
                    self.batches.clear();
                    return None;
                }
                let delta = (expected - old_expected, lost - old_lost);
                if delta.1 > delta.0 {
                    self.batches.clear();
                    return None;
                }
                // Invalid samples cannot replace the last good prefix and
                // cause its already-counted cohorts to be counted again.
                self.previous = Some((expected, lost));
                delta
            }
            (None, None) => {
                // Older callers/tests supply a paired finalized interval. The
                // live runtime uses cumulative integers, including skipped reports.
                let loss = sample.loss_sample_rate.filter(|v| v.is_finite())?;
                let expected = sample.feedback_sample_symbols;
                let lost = (loss.clamp(0.0, 1.0) * expected as f64).round() as u64;
                (expected, lost)
            }
            _ => return None,
        };
        if delta.1 > delta.0 {
            self.batches.clear();
            return None;
        }
        // A newly consumed delivery report can contain a finalized prefix that
        // was already stale before this observation. Advance its valid baseline
        // above, but never turn that old cohort into fresh loss evidence later.
        if delta.0 == 0 || sample.feedback_age_us.is_none_or(|age| age > FRESH_US) {
            return None;
        }
        if self.batches.len() == LOSS_BATCHES {
            self.batches.pop_front();
        }
        self.batches.push_back((sample.now_us, delta.0, delta.1));
        Some(delta)
    }

    fn counts(&self) -> (u128, u128) {
        self.batches.iter().fold((0, 0), |(n, lost), (_, dn, dl)| {
            (n + u128::from(*dn), lost + u128::from(*dl))
        })
    }

    fn ordinary(&self) -> bool {
        let (expected, lost) = self.counts();
        self.batches.len() >= 2 && expected >= 64 && lost * 20 > expected
    }

    fn fraction(&self) -> f64 {
        let (expected, lost) = self.counts();
        if expected == 0 {
            0.0
        } else {
            lost as f64 / expected as f64
        }
    }
}

#[derive(Clone, Copy)]
struct WeightLoss {
    rate: f64,
    report: u64,
    observed_us: u64,
    age_us: u64,
}

#[derive(Clone, Copy)]
struct WeightBatch {
    expected: u64,
    lost: u64,
    observed_us: u64,
    age_us: u64,
}

#[derive(Default)]
struct WeightWindow {
    batches: VecDeque<WeightBatch>,
    expected: u64,
    lost: u64,
}

impl WeightWindow {
    fn observe(&mut self, now_us: u64, age_us: u64, expected: u64, lost: u64) {
        if self.batches.back().is_some_and(|batch| {
            batch
                .age_us
                .saturating_add(now_us.saturating_sub(batch.observed_us))
                > FRESH_US
        }) {
            self.batches.clear();
            self.expected = 0;
            self.lost = 0;
        }
        self.batches.push_back(WeightBatch {
            expected,
            lost,
            observed_us: now_us,
            age_us,
        });
        // These are disjoint valid cumulative deltas in one generation, so
        // their sum cannot exceed the latest u64 cumulative prefix.
        self.expected += expected;
        self.lost += lost;
        // Keep whole report batches; never guess which symbols in a batch lost.
        // Nonempty deltas leave at most 16 batches in this shortest suffix.
        while let Some(batch) = self.batches.front().copied()
            && self.expected - batch.expected >= WEIGHT_EVIDENCE_SYMBOLS
        {
            self.batches.pop_front();
            self.expected -= batch.expected;
            self.lost -= batch.lost;
        }
    }

    fn effective_rate(&self, raw: f64) -> f64 {
        if self.expected >= WEIGHT_EVIDENCE_SYMBOLS {
            raw.max(self.lost as f64 / self.expected as f64)
        } else {
            raw
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Unknown,
    Healthy,
    Degraded,
    Probing,
}

#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub pacing_bps: u64,
    pub eligible: bool,
    pub weight: i32,
    pub weight_loss_rate: Option<f64>,
    pub weight_loss_age_us: Option<u64>,
    pub weight_loss_report: Option<u64>,
    pub weight_loss_effective_rate: Option<f64>,
    pub weight_loss_window_expected: Option<u64>,
    pub weight_loss_window_lost: Option<u64>,
    pub weight_loss_window_oldest_age_us: Option<u64>,
    pub state: Health,
    pub queue_delay_ms: f64,
    pub probe_due: bool,
    pub observed_delivery_bps: Option<f64>,
    pub loss_evidence_expected: u64,
    pub loss_evidence_lost: u64,
    pub loss_pressure: bool,
    pub cautious: bool,
}

/// Rich bounded diagnostics are cloned only for scheduled statistics. Packet
/// admission and scheduling use the allocation-free `Decision` above.
#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    #[serde(flatten)]
    pub decision: Decision,
    pub reprobe: reprobe::Snapshot,
    pub rate_changes: VecDeque<RateChange>,
    pub rate_changes_total: u64,
    pub rate_changes_evicted: u64,
    pub last_control: ControlSample,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RateReason {
    InitialGrowth,
    KnownServiceRecovery,
    CautiousGrowth,
    ServiceDiscovery,
    GrowthWithdrawalBrake,
    QueueBrake,
    DeliveryShortfallBrake,
    FastLossBrake,
    LossBrake,
    TransportBlockedBrake,
    ReprobeStart,
    ReprobeRollback,
}

/// Diagnostic identity of the original selected absolute RTT. Exact numeric
/// ties are labelled Quinn; this enum does not participate in control.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RttSource {
    #[default]
    Unavailable,
    Quinn,
    Probe,
}

/// A finalized interval's provable loss after the last actual congestion brake.
/// Raw loss remains in the ordinary history, health hold and trial safety input.
#[derive(Clone, Debug, Serialize)]
pub struct BrakeLoss {
    pub admitted_symbols: u64,
    pub previous_brake_symbols: Option<u64>,
    pub expected: u64,
    pub lost: u64,
    pub pressure_override: bool,
    pub actionable: bool,
}

impl BrakeLoss {
    fn from_batch(
        sample: &Observation,
        batch: (u64, u64),
        previous_brake_symbols: Option<u64>,
        pressure_override: bool,
    ) -> Option<Self> {
        let admitted_symbols = sample.admitted_symbols?;
        let end = sample.finalized_expected?;
        sample.finalized_lost?;
        let (expected, lost) = batch;
        let start = end.checked_sub(expected)?;
        if end > admitted_symbols
            || lost > expected
            || previous_brake_symbols.is_some_and(|boundary| boundary > admitted_symbols)
        {
            return None;
        }
        let old = if pressure_override {
            0
        } else {
            previous_brake_symbols
                .map_or(0, |boundary| boundary.saturating_sub(start).min(expected))
        };
        // Every old symbol could explain one loss. Do not assign an ambiguous
        // straddling batch's losses to its new part without that lower bound.
        let expected = expected - old;
        let lost = lost.saturating_sub(old);
        Some(Self {
            admitted_symbols,
            previous_brake_symbols,
            expected,
            lost,
            pressure_override,
            actionable: expected >= 8 && u128::from(lost) * 2 >= u128::from(expected),
        })
    }
}

/// Recent successful business or queued demand, independent of whether one
/// observation happens to find the queue empty. This is not capacity evidence.
#[derive(Clone, Debug, Default)]
struct DemandActivity {
    since_us: Option<u64>,
    last_activity_us: Option<u64>,
}

impl DemandActivity {
    fn update(&mut self, now_us: u64, active: bool) {
        // Expire before refreshing: an event at the boundary starts a new
        // segment and cannot retroactively cover an inactive interval.
        if self.last_activity_us.is_some_and(|last| {
            now_us
                .checked_sub(last)
                .is_none_or(|elapsed| elapsed >= CONTROL_US)
        }) {
            *self = Self::default();
        }
        if active {
            self.since_us.get_or_insert(now_us);
            self.last_activity_us = Some(now_us);
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceAdmission {
    pub symbol_bytes: u64,
    pub symbols: u64,
    pub symbol_bps: f64,
    pub span_us: u64,
    pub started_us: u64,
    pub backlog_since_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_since_us: Option<u64>,
    pub last_pace_change_us: u64,
    pub deficit: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct GrowthMonitorReply {
    /// Quality's authenticated, deduplicated reply count, not a wire nonce.
    pub sample_id: u64,
    pub observed_us: u64,
    pub age_us: u64,
    pub inferred_request_us: u64,
    pub rtt_ms: f64,
}

/// Two observations of one actual ordinary increase, not a capacity estimate.
#[derive(Clone, Debug, Serialize)]
pub struct GrowthMonitor {
    pub generation: u64,
    pub armed_us: u64,
    pub latest_observed_us: u64,
    pub previous_bps: u64,
    pub pacing_bps: u64,
    pub last_probe_sample_id: u64,
    pub successful_request_us: [Option<u64>; 2],
    pub first_reply: Option<GrowthMonitorReply>,
    pub second_reply: Option<GrowthMonitorReply>,
    pub withdrawn: bool,
}

impl GrowthMonitor {
    fn arm(sample: &Observation, previous_bps: u64, pacing_bps: u64) -> Self {
        Self {
            generation: sample.generation,
            armed_us: sample.now_us,
            latest_observed_us: sample.now_us,
            previous_bps,
            pacing_bps,
            last_probe_sample_id: sample.probe_sample_id,
            successful_request_us: [None, None],
            first_reply: None,
            second_reply: None,
            withdrawn: false,
        }
    }

    fn live_at(&self, now_us: u64) -> bool {
        now_us
            .checked_sub(self.armed_us)
            .is_some_and(|age| age <= FRESH_US)
    }

    fn request_due(&self, now_us: u64) -> bool {
        self.live_at(now_us)
            && now_us >= self.latest_observed_us
            && now_us > self.armed_us
            && self.successful_request_us[1].is_none()
    }

    fn probe_admitted(&mut self, now_us: u64) {
        if !self.live_at(now_us) || now_us < self.latest_observed_us || now_us <= self.armed_us {
            return;
        }
        if self.successful_request_us[0].is_none() {
            self.successful_request_us[0] = Some(now_us);
        } else if self.successful_request_us[0]
            .is_some_and(|first| now_us >= first.saturating_add(FAST_PROBE_US))
            && self.successful_request_us[1].is_none()
        {
            self.successful_request_us[1] = Some(now_us);
        }
    }

    fn observe(&mut self, sample: &Observation, probe_rtt_ms: f64) -> bool {
        if sample.generation != self.generation
            || !self.live_at(sample.now_us)
            || sample
                .now_us
                .checked_sub(self.latest_observed_us)
                .is_none_or(|gap| gap > FRESH_US)
            || sample.probe_sample_id < self.last_probe_sample_id
        {
            return false;
        }
        self.latest_observed_us = sample.now_us;
        if sample.probe_sample_id > self.last_probe_sample_id {
            self.last_probe_sample_id = sample.probe_sample_id;
            if let Some(age_us) = sample.probe_age_us.filter(|age| *age <= CONTROL_US)
                && let Some(request_us) = sample
                    .now_us
                    .checked_sub(age_us)
                    .and_then(|at| at.checked_sub((probe_rtt_ms * 1000.0).ceil() as u64))
                && request_us > self.armed_us
                && self.successful_request_us[0].is_some()
                && self.first_reply.as_ref().is_none_or(|first| {
                    sample.probe_sample_id > first.sample_id
                        && request_us > first.inferred_request_us
                })
            {
                // A skipped reply counter contributes only this visible reply.
                let reply = GrowthMonitorReply {
                    sample_id: sample.probe_sample_id,
                    observed_us: sample.now_us,
                    age_us,
                    inferred_request_us: request_us,
                    rtt_ms: probe_rtt_ms,
                };
                if self.first_reply.is_none() {
                    self.first_reply = Some(reply);
                } else if self.successful_request_us[1].is_some() {
                    self.second_reply = Some(reply);
                }
            }
        }
        true
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ControlSample {
    pub at_us: u64,
    pub generation: u64,
    pub report_number: u64,
    pub delivery_report_time_us: Option<u64>,
    pub delivery_sample_span_us: u64,
    pub admitted_bytes: u64,
    pub integrated_allowance_bytes: f64,
    pub admission_span_us: u64,
    pub local_rtt_ms: Option<f64>,
    pub probe_rtt_ms: Option<f64>,
    pub probe_age_us: Option<u64>,
    pub probe_sample_id: u64,
    pub selected_rtt_ms: Option<f64>,
    pub rtt_source: RttSource,
    pub mixed_min_rtt_ms: Option<f64>,
    pub rtt_excess_ms: f64,
    pub transport_wait_ms: f64,
    pub rtt_fresh: bool,
    pub probe_fresh: bool,
    pub delivery_fresh: bool,
    pub new_rtt: bool,
    pub new_probe: bool,
    pub new_queue: bool,
    /// Diagnostic observations only, not calibrated or trusted baselines.
    pub observed_local_min_rtt_ms: Option<f64>,
    pub observed_probe_min_rtt_ms: Option<f64>,
    pub queue_delay_ms: f64,
    pub transport_blocked: bool,
    pub offered_backlog: bool,
    pub latest_symbol_delivery_bps: Option<f64>,
    /// A real short report retained until the next control tick. `used` marks
    /// the evidence actually consumed by an initial pacing increase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_delivery_credit: Option<InitialDeliveryCredit>,
    /// Short reports remain raw startup evidence; service decisions use this
    /// independently accumulated interval once fast feedback has been seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_symbol_delivery_bps: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_sample_span_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_admission: Option<ServiceAdmission>,
    /// Actual one-use restoration from the latest qualified post-brake service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain_service_target_bps: Option<u64>,
    /// Actual two-reply evidence for the latest ordinary growth increment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub growth_monitor: Option<GrowthMonitor>,
    /// The current retry step ceiling after withdrawing an increment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub growth_retry_ceiling_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_probe_excess_ms: Option<f64>,
    pub ordinary_loss_pressure: bool,
    pub fast_loss: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brake_loss: Option<BrakeLoss>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct InitialDeliveryCredit {
    pub report_number: u64,
    pub delivered_bytes: u64,
    pub observed_us: u64,
    pub positive_age_at_observation_us: u64,
    pub wire_delivery_bps: f64,
    pub used: bool,
}

impl InitialDeliveryCredit {
    fn fresh_at(self, now_us: u64) -> bool {
        now_us.checked_sub(self.observed_us).is_some_and(|elapsed| {
            elapsed <= CONTROL_US
                && self
                    .positive_age_at_observation_us
                    .checked_add(elapsed)
                    .is_some_and(|age| age <= CONTROL_US)
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RateChange {
    pub number: u64,
    pub at_us: u64,
    pub previous_bps: u64,
    pub pacing_bps: u64,
    pub reason: RateReason,
    pub control: ControlSample,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Observation {
    pub now_us: u64,
    pub generation: u64,
    pub report_number: u64,
    /// Age of newly finalized loss, not the age of positive byte delivery.
    pub feedback_age_us: Option<u64>,
    /// Positive delivery on this path, independently of all-loss report freshness.
    pub positive_delivery_age_us: Option<u64>,
    pub delivered_bytes: u64,
    /// Receiver-local report interval; feedback arrival spacing can be compressed.
    pub delivered_bps: Option<f64>,
    /// Receiver-local delivery clock and interval, independent of loss age.
    pub delivery_report_time_us: Option<u64>,
    pub delivery_sample_span_us: u64,
    /// Only original-only traffic may use raw symbol delivery to validate a trial.
    pub reprobe_enabled: bool,
    pub feedback_sample_symbols: u64,
    /// Cumulative finalized sequence counts recover reports skipped between
    /// controller observations. They are distinct from current delivery bytes.
    pub finalized_expected: Option<u64>,
    pub finalized_lost: Option<u64>,
    /// Successful sequence count from this generation's authoritative Quality
    /// State. A controller-local mirror can miss admissions before first observe.
    pub admitted_symbols: Option<u64>,
    /// Cumulative successful measured-symbol bytes in this Quality generation,
    /// in the same units as delivered_bytes, not the control-round wire count.
    pub admitted_symbol_bytes: Option<u64>,
    /// Quality-share EWMA. Pacing brakes use bounded finalized-count evidence.
    pub loss_rate: f64,
    pub loss_sample_rate: Option<f64>,
    pub rtt_ms: f64,
    /// Diagnostic EWMA retained for stats and older callers.
    pub probe_rtt_ms: Option<f64>,
    pub probe_latest_rtt_ms: Option<f64>,
    pub probe_sample_id: u64,
    pub probe_age_us: Option<u64>,
    /// Independent clocks make this unsafe as a lone congestion trigger.
    pub transit_excess_ms: f64,
    pub send_queue_bytes: usize,
    pub offered_backlog: bool,
    pub transport_blocked: bool,
}

struct GrowthRetry {
    baseline_bps: u64,
    increment_bps: u64,
    observed_us: u64,
}

pub struct PathController {
    maximum_bps: u64,
    target_ms: f64,
    generation: Option<u64>,
    born_us: u64,
    rate_bps: u64,
    min_rtt_ms: Option<f64>,
    /// Diagnostic-only minima; no controller or weighting calculation reads them.
    observed_local_min_rtt_ms: Option<f64>,
    observed_probe_min_rtt_ms: Option<f64>,
    queue_delay_ms: f64,
    health: Health,
    eligible: bool,
    last_evidence_us: Option<u64>,
    no_delivery_confirmed_us: Option<u64>,
    last_probe_us: Option<u64>,
    last_control_us: u64,
    last_growth_us: u64,
    /// A short receiver interval grants at most one initial-growth step. Both
    /// the report and its cumulative positive bytes must advance for another.
    last_initial_growth_report: Option<(u64, u64)>,
    initial_delivery_credit: Option<InitialDeliveryCredit>,
    growth_monitor: Option<GrowthMonitor>,
    growth_retry: Option<GrowthRetry>,
    last_growth_probe: Option<u64>,
    fast_feedback_seen: bool,
    fast_probe_min_rtt_ms: Option<f64>,
    /// A queue established by a startup probe survives the switch to caution
    /// until a new probe observes drainage or the original evidence expires.
    startup_probe_pressure: Option<(f64, u64)>,
    growth_not_before_us: u64,
    last_brake_us: Option<u64>,
    last_brake_admitted_symbols: Option<u64>,
    last_probe_sample_id: u64,
    last_rtt_ms: Option<f64>,
    last_local_rtt_ms: Option<f64>,
    last_transport_wait_ms: f64,
    admitted_bytes: u64,
    admitted_symbol_bytes: u64,
    allowance_bytes: f64,
    wire_per_symbol: f64,
    blocked_since_us: Option<u64>,
    backlog_since_us: Option<u64>,
    demand_activity: DemandActivity,
    delay_since_us: Option<u64>,
    braked_queue_ms: Option<f64>,
    last_report: Option<(u64, u64, u64)>,
    delivery_bps: Option<f64>,
    latest_delivery_bps: Option<f64>,
    service_window: service::Window,
    /// Short-lived service measured while bytes left faster than we admitted.
    draining_bps: Option<(f64, u64)>,
    drain_restore_pending: bool,
    /// Previously achieved delivery, retained across temporary congestion. An
    /// application-limited sample never decreases this exploration reference.
    remembered_bps: f64,
    congestion_seen: bool,
    weight_loss: Option<WeightLoss>,
    weight_window: WeightWindow,
    loss_evidence: LossEvidence,
    loss_pressure: bool,
    pressure_episode_exercised: Option<bool>,
    pressure_episode_braked: bool,
    tokens: f64,
    token_us: u64,
    reprobe: reprobe::Controller,
    rate_changes: VecDeque<RateChange>,
    rate_changes_total: u64,
    last_control: ControlSample,
}

impl PathController {
    /// The target is an added-delay control objective, not a hard end-to-end bound.
    pub fn new(max_rate_bps: u64, latency_target_ms: u64) -> Self {
        let maximum_bps = max_rate_bps.max(1);
        Self {
            maximum_bps,
            target_ms: latency_target_ms.max(1) as f64,
            generation: None,
            born_us: 0,
            rate_bps: maximum_bps.min(START_BPS),
            min_rtt_ms: None,
            observed_local_min_rtt_ms: None,
            observed_probe_min_rtt_ms: None,
            queue_delay_ms: 0.0,
            health: Health::Unknown,
            eligible: true,
            last_evidence_us: None,
            no_delivery_confirmed_us: None,
            last_probe_us: None,
            last_control_us: 0,
            last_growth_us: 0,
            last_initial_growth_report: None,
            initial_delivery_credit: None,
            growth_monitor: None,
            growth_retry: None,
            last_growth_probe: None,
            fast_feedback_seen: false,
            fast_probe_min_rtt_ms: None,
            startup_probe_pressure: None,
            growth_not_before_us: 0,
            last_brake_us: None,
            last_brake_admitted_symbols: None,
            last_probe_sample_id: 0,
            last_rtt_ms: None,
            last_local_rtt_ms: None,
            last_transport_wait_ms: 0.0,
            admitted_bytes: 0,
            admitted_symbol_bytes: 0,
            allowance_bytes: 0.0,
            wire_per_symbol: 1.0,
            blocked_since_us: None,
            backlog_since_us: None,
            demand_activity: DemandActivity::default(),
            delay_since_us: None,
            braked_queue_ms: None,
            last_report: None,
            delivery_bps: None,
            latest_delivery_bps: None,
            service_window: service::Window::default(),
            draining_bps: None,
            drain_restore_pending: false,
            remembered_bps: 0.0,
            congestion_seen: false,
            weight_loss: None,
            weight_window: WeightWindow::default(),
            loss_evidence: LossEvidence::default(),
            loss_pressure: false,
            pressure_episode_exercised: None,
            pressure_episode_braked: false,
            tokens: 2400.0,
            token_us: 0,
            reprobe: reprobe::Controller::default(),
            rate_changes: VecDeque::new(),
            rate_changes_total: 0,
            last_control: ControlSample::default(),
        }
    }

    pub fn observe(&mut self, observation: &Observation) {
        let now = observation.now_us;
        if self.generation != Some(observation.generation) {
            *self = Self::new(self.maximum_bps, self.target_ms as u64);
            self.generation = Some(observation.generation);
            self.born_us = now;
            self.last_control_us = now;
            self.last_growth_us = now;
            self.token_us = now;
        }
        let rate_before_refill = self.rate_bps;
        self.refill(now);
        let observation_contiguous = now
            .checked_sub(self.last_control.at_us)
            .is_some_and(|elapsed| elapsed <= FRESH_US);
        if !observation_contiguous {
            self.demand_activity = DemandActivity::default();
        }
        self.demand_activity
            .update(now, observation.offered_backlog);
        if observation.offered_backlog {
            if now
                .checked_sub(self.last_control.at_us)
                .is_none_or(|elapsed| elapsed > FRESH_US)
            {
                self.backlog_since_us = Some(now);
            } else {
                self.backlog_since_us.get_or_insert(now);
            }
        } else {
            self.backlog_since_us = None;
        }
        let previous_rate = self.rate_bps;
        let mut rate_reason = RateReason::ReprobeRollback;
        if self.admitted_symbol_bytes > 0 {
            self.wire_per_symbol =
                (self.admitted_bytes as f64 / self.admitted_symbol_bytes as f64).clamp(1.0, 16.0);
        }
        let feedback_fresh = observation
            .feedback_age_us
            .is_some_and(|age| age <= FRESH_US);
        let probe_rtt = observation
            .probe_latest_rtt_ms
            .or(observation.probe_rtt_ms)
            .filter(|rtt| rtt.is_finite() && *rtt > 0.0);
        let probe_fresh =
            observation.probe_age_us.is_some_and(|age| age <= FRESH_US) && probe_rtt.is_some();
        let delivery_fresh = observation
            .positive_delivery_age_us
            .is_some_and(|age| age <= FRESH_US);
        let fresh = delivery_fresh || probe_fresh;
        if fresh {
            let age = [
                observation
                    .positive_delivery_age_us
                    .filter(|_| delivery_fresh),
                observation.probe_age_us.filter(|_| probe_fresh),
            ]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(FRESH_US);
            self.last_evidence_us = Some(now.saturating_sub(age));
        }
        if self.no_delivery_confirmed_us.is_some_and(|failed_at| {
            self.last_evidence_us
                .is_some_and(|positive_at| positive_at > failed_at)
        }) {
            self.no_delivery_confirmed_us = None;
        }

        // Unique byte delivery can precede sequence-prefix finalization. Consume
        // its new authenticated report without waiting for a fresh loss cohort.
        let previous_report = self.last_report;
        let new_report = (feedback_fresh || delivery_fresh)
            && self
                .last_report
                .is_none_or(|(number, _, _)| observation.report_number > number);
        let new_loss_report = new_report && feedback_fresh;
        let short_delivery_interval = observation.delivery_report_time_us.is_some()
            && observation.delivery_sample_span_us > 0
            && observation.delivery_sample_span_us <= CONTROL_US
            && observation
                .delivered_bps
                .is_some_and(|rate| rate.is_finite() && rate > 0.0);
        let mut new_service_report = false;
        if new_report {
            if !self.fast_feedback_seen && short_delivery_interval && !self.pressure_episode_braked
            {
                // Do not import a legacy transient's provisional flag when
                // short feedback starts. An actual prior brake keeps its flag.
                self.pressure_episode_exercised = None;
            }
            self.fast_feedback_seen |= short_delivery_interval;
            let accumulated = self.service_window.observe(
                observation.report_number,
                observation.delivery_report_time_us,
                observation.delivered_bytes,
                now,
                observation
                    .admitted_symbol_bytes
                    .zip(observation.admitted_symbols),
            );
            new_service_report = !self.fast_feedback_seen || accumulated;
            let explicit = observation
                .delivered_bps
                .filter(|rate| rate.is_finite() && *rate >= 0.0);
            let inferred = self
                .last_report
                .and_then(|(_, previous_bytes, previous_us)| {
                    let elapsed = now.saturating_sub(previous_us);
                    (elapsed > 0 && observation.delivered_bytes >= previous_bytes).then(|| {
                        (observation.delivered_bytes - previous_bytes) as f64 * 8_000_000.0
                            / elapsed as f64
                    })
                });
            if let Some(rate) = explicit.or(inferred) {
                self.latest_delivery_bps = Some(rate);
                self.delivery_bps =
                    Some(self.delivery_bps.map_or(rate, |old| old * 0.5 + rate * 0.5));
                let service = if self.fast_feedback_seen {
                    self.service_window.latest(now).map(|sample| sample.bps)
                } else {
                    Some(rate)
                };
                if observation.offered_backlog
                    && new_service_report
                    && let Some(service) = service
                {
                    self.remembered_bps = self
                        .remembered_bps
                        .max((service * self.wire_per_symbol).min(self.maximum_bps as f64));
                }
            }
            self.last_report = Some((observation.report_number, observation.delivered_bytes, now));
        }
        let loss_batch = self.loss_evidence.observe(observation, new_report);
        if let Some((expected, lost)) = loss_batch
            && let Some(cumulative_expected) = observation.finalized_expected
            && observation.finalized_lost.is_some()
            && observation.loss_rate.is_finite()
            && (0.0..=1.0).contains(&observation.loss_rate)
            && let Some(age_us) = observation.feedback_age_us.filter(|age| *age <= FRESH_US)
        {
            // Collect real symbols before maturity, with a separate age even
            // while no raw sample qualifies. Legacy interval inputs cannot enter.
            self.weight_window.observe(now, age_us, expected, lost);
            // Sparse traffic can qualify over its cumulative finalized history
            // without exercising a pacing budget. Only a new nonempty loss
            // interval refreshes quality; probes and byte progress cannot.
            if cumulative_expected >= WEIGHT_EVIDENCE_SYMBOLS {
                self.weight_loss = Some(WeightLoss {
                    rate: observation.loss_rate,
                    report: observation.report_number,
                    observed_us: now,
                    age_us,
                });
            }
        }
        let ordinary_loss = self.loss_evidence.ordinary();

        let local_rtt = (observation.rtt_ms.is_finite() && observation.rtt_ms > 0.0)
            .then_some(observation.rtt_ms);
        // A new authenticated probe is a current sample, not the diagnostic EWMA.
        // Between probes Quinn detects a rising queue. When Quinn is declining,
        // a recent lower probe corroborates drainage instead of waiting for its EWMA.
        let rtt = match (local_rtt, probe_rtt.filter(|_| probe_fresh)) {
            (Some(local), Some(probe)) => {
                let young = observation.probe_age_us.is_some_and(|age| age <= BRAKE_US);
                let declining = self
                    .last_local_rtt_ms
                    .is_some_and(|old| local <= old + 0.25);
                if young
                    || (declining && observation.probe_age_us.is_some_and(|age| age <= PROBE_US))
                {
                    Some(local.min(probe))
                } else {
                    Some(local)
                }
            }
            (local, probe) => local.or(probe),
        };
        let new_probe = probe_fresh && observation.probe_sample_id != self.last_probe_sample_id;
        let new_rtt = fresh
            && rtt.is_some_and(|value| {
                self.last_rtt_ms
                    .is_none_or(|old| (value - old).abs() > 0.25)
            });
        let mut rtt_excess = 0.0;
        if fresh && let Some(rtt) = rtt {
            let minimum = self.min_rtt_ms.get_or_insert(rtt);
            *minimum = (*minimum).min(rtt);
            rtt_excess = (rtt - *minimum).max(0.0);
        }
        let service_sample = self
            .fast_feedback_seen
            .then(|| self.service_window.latest(now))
            .flatten();
        let service_bps = if self.fast_feedback_seen {
            service_sample.map(|sample| sample.bps)
        } else {
            self.latest_delivery_bps
        };
        let wire_delivery_bps = service_bps.map(|rate| rate * self.wire_per_symbol);
        let fast_initial = self.fast_feedback_seen && !self.congestion_seen;
        if self
            .startup_probe_pressure
            .is_some_and(|(_, at)| now.saturating_sub(at) > FRESH_US)
        {
            self.startup_probe_pressure = None;
        }
        let current_startup_probe_excess = if (fast_initial
            || self.startup_probe_pressure.is_some())
            && probe_fresh
            && observation
                .probe_age_us
                .is_some_and(|age| age <= CONTROL_US)
        {
            probe_rtt.map(|probe| {
                let minimum = self.fast_probe_min_rtt_ms.get_or_insert(probe);
                *minimum = (*minimum).min(probe);
                (probe - *minimum).max(0.0)
            })
        } else {
            None
        };
        if new_probe && let Some(excess) = current_startup_probe_excess {
            self.startup_probe_pressure = if excess > self.target_ms * 0.5 {
                Some((
                    excess,
                    now.saturating_sub(observation.probe_age_us.unwrap_or(0)),
                ))
            } else {
                None
            };
        }
        let startup_probe_excess = self
            .startup_probe_pressure
            .map(|(excess, _)| excess)
            .or_else(|| {
                fast_initial
                    .then_some(current_startup_probe_excess)
                    .flatten()
            });
        let drain_hint = wire_delivery_bps.unwrap_or(0.0).max(self.rate_bps as f64);
        // A bounded two-datagram burst briefly waiting for Quinn's driver is not congestion.
        let queued_beyond_burst = observation.send_queue_bytes.saturating_sub(2400);
        let transport_wait = queued_beyond_burst as f64 * 8000.0 / drain_hint;
        let previous_queue = self.queue_delay_ms;
        self.queue_delay_ms = rtt_excess
            .max(transport_wait)
            .max(startup_probe_excess.unwrap_or(0.0));
        let queue_rising = self.queue_delay_ms > previous_queue + 0.25;
        let new_queue =
            new_rtt || new_probe || (transport_wait - self.last_transport_wait_ms).abs() > 0.25;

        let loss = if feedback_fresh {
            observation
                .loss_sample_rate
                .or_else(|| {
                    (observation.feedback_sample_symbols > 0).then_some(observation.loss_rate)
                })
                .filter(|rate| rate.is_finite())
                .unwrap_or(0.0)
                .clamp(0.0, 1.0)
        } else {
            0.0
        };
        let fast_loss = loss_batch.is_some_and(|(expected, lost)| {
            expected >= 8 && u128::from(lost) * 2 >= u128::from(expected)
        });
        if new_loss_report
            && observation.feedback_sample_symbols >= 8
            && loss >= 0.999
            && self.latest_delivery_bps == Some(0.0)
            && observation
                .positive_delivery_age_us
                .is_none_or(|age| age > PROBE_US)
            && observation.probe_age_us.is_none_or(|age| age > PROBE_US)
        {
            // An alternate path may carry fresh reports that this path delivered
            // nothing. A sampled all-loss interval plus overdue positive probes
            // can stop business before the general three-second stale deadline.
            self.no_delivery_confirmed_us = Some(now);
        }
        let blocked_since = if observation.transport_blocked {
            Some(*self.blocked_since_us.get_or_insert(now))
        } else {
            self.blocked_since_us = None;
            None
        };
        let blocked_pressure = blocked_since.is_some_and(|since| {
            now.saturating_sub(since) >= (self.target_ms * 1000.0).max(100_000.0) as u64
        }) && wire_delivery_bps
            .is_none_or(|rate| rate < self.rate_bps as f64 * 0.85);
        let delay_pressure = self.queue_delay_ms > self.target_ms * 0.5;
        let persistent_delay = if delay_pressure {
            let since = *self.delay_since_us.get_or_insert(now);
            now.saturating_sub(since) >= BRAKE_US
                || self.queue_delay_ms >= self.target_ms * 4.0
                // A sub-target pulse still holds growth but must persist before
                // braking. At the target, a rising startup probe brakes at once.
                || (fast_initial
                    && new_probe
                    && queue_rising
                    && self.queue_delay_ms >= self.target_ms)
        } else {
            self.delay_since_us = None;
            self.braked_queue_ms = None;
            false
        };
        let admission_span = now.saturating_sub(self.last_control_us);
        // Integrate the allowance at the rates that actually applied. Comparing
        // old admissions with a later reduced rate can manufacture utilization.
        let exercised =
            self.allowance_bytes > 0.0 && self.admitted_bytes as f64 >= self.allowance_bytes * 0.9;
        let allowance_rate = if admission_span == 0 {
            0.0
        } else {
            self.allowance_bytes * 8_000_000.0 / admission_span as f64
        };
        // Finalized loss can describe an older packet cohort. Corroborate it
        // independently with current service under an exercised, settled pace;
        // do not interpret a delayed warmup loss as today's capacity ceiling.
        let service_shortfall = feedback_fresh
            && exercised
            && allowance_rate > 0.0
            && wire_delivery_bps.is_some_and(|rate| rate < allowance_rate * 0.85);
        let last_change = self.last_growth_us.max(self.last_brake_us.unwrap_or(0));
        let settled_shortfall =
            service_shortfall && now.saturating_sub(last_change) >= PROBE_US + BRAKE_US;
        self.loss_pressure = ordinary_loss && settled_shortfall;
        let probe_began_us = probe_fresh
            .then_some(observation.probe_age_us.zip(probe_rtt))
            .flatten()
            .and_then(|(age, rtt)| {
                now.checked_sub(age)?
                    .checked_sub((rtt * 1000.0).ceil() as u64)
            });
        // Severity belongs to the current contributing component. A retained
        // probe queue cannot repeatedly exempt an older loss cohort from its
        // brake watermark, nor borrow authority from a small local RTT change.
        let severe_local = fresh
            && local_rtt
                .zip(self.min_rtt_ms)
                .is_some_and(|(local, minimum)| local - minimum >= self.target_ms * 4.0);
        let severe_probe = new_probe
            && probe_began_us
                .is_some_and(|began| self.last_brake_us.is_none_or(|brake| began > brake))
            && ((rtt.is_some() && rtt != local_rtt && rtt_excess >= self.target_ms * 4.0)
                || current_startup_probe_excess
                    .is_some_and(|excess| excess >= self.target_ms * 4.0));
        let severe_pressure = self.queue_delay_ms >= self.target_ms * 4.0
            && (severe_local || severe_probe || transport_wait >= self.target_ms * 4.0);
        let brake_loss = self
            .fast_feedback_seen
            .then_some(loss_batch)
            .flatten()
            .and_then(|batch| {
                BrakeLoss::from_batch(
                    observation,
                    batch,
                    self.last_brake_admitted_symbols,
                    severe_pressure || blocked_pressure || settled_shortfall,
                )
            });
        let fast_loss_actionable = brake_loss
            .as_ref()
            .map_or(fast_loss, |evidence| evidence.actionable);
        let actionable_loss_fraction = brake_loss.as_ref().map_or_else(
            || loss_batch.map_or(0.0, |(n, lost)| lost as f64 / n as f64),
            |evidence| {
                if evidence.expected == 0 {
                    0.0
                } else {
                    evidence.lost as f64 / evidence.expected as f64
                }
            },
        );
        let loss_counts = self.loss_evidence.counts();
        // Preserve the exact inputs and intermediate values at an action. These
        // observed minima are never substituted for the original mixed minimum.
        if fresh && let Some(local) = local_rtt {
            let minimum = self.observed_local_min_rtt_ms.get_or_insert(local);
            *minimum = (*minimum).min(local);
        }
        if new_probe && let Some(probe) = probe_rtt {
            let minimum = self.observed_probe_min_rtt_ms.get_or_insert(probe);
            *minimum = (*minimum).min(probe);
        }
        let rtt_source = match rtt {
            Some(value) if local_rtt == Some(value) => RttSource::Quinn,
            Some(_) => RttSource::Probe,
            None => RttSource::Unavailable,
        };
        self.last_control = ControlSample {
            at_us: now,
            generation: observation.generation,
            report_number: observation.report_number,
            delivery_report_time_us: observation.delivery_report_time_us,
            delivery_sample_span_us: observation.delivery_sample_span_us,
            admitted_bytes: self.admitted_bytes,
            integrated_allowance_bytes: self.allowance_bytes,
            admission_span_us: admission_span,
            local_rtt_ms: local_rtt,
            probe_rtt_ms: probe_rtt,
            probe_age_us: observation.probe_age_us,
            probe_sample_id: observation.probe_sample_id,
            selected_rtt_ms: rtt,
            rtt_source,
            mixed_min_rtt_ms: self.min_rtt_ms,
            rtt_excess_ms: rtt_excess,
            transport_wait_ms: transport_wait,
            rtt_fresh: fresh,
            probe_fresh,
            delivery_fresh,
            new_rtt,
            new_probe,
            new_queue,
            observed_local_min_rtt_ms: self.observed_local_min_rtt_ms,
            observed_probe_min_rtt_ms: self.observed_probe_min_rtt_ms,
            queue_delay_ms: self.queue_delay_ms,
            transport_blocked: observation.transport_blocked,
            offered_backlog: observation.offered_backlog,
            latest_symbol_delivery_bps: self.latest_delivery_bps,
            initial_delivery_credit: None,
            service_symbol_delivery_bps: service_sample.map(|sample| sample.bps),
            service_sample_span_us: service_sample.map(|sample| sample.span_us),
            service_admission: None,
            drain_service_target_bps: None,
            growth_monitor: None,
            growth_retry_ceiling_bps: None,
            startup_probe_excess_ms: startup_probe_excess,
            ordinary_loss_pressure: self.loss_pressure,
            fast_loss,
            brake_loss,
        };
        let trial_action = self.reprobe.observe(reprobe::Input {
            sample: observation,
            rate_bps: self.rate_bps,
            maximum_bps: self.maximum_bps,
            queue_ms: self.queue_delay_ms,
            target_ms: self.target_ms,
            fresh,
            healthy: self.no_delivery_confirmed_us.is_none(),
            fast_loss,
            blocked: blocked_pressure,
            ordinary_loss: self.loss_pressure,
            last_growth_us: self.last_growth_us,
            stalled: self.congestion_seen
                && now.saturating_sub(self.last_growth_us) >= LOSS_WINDOW_US,
            new_report,
            control_sample: admission_span >= CONTROL_US,
            admission_span_us: admission_span,
            admitted: self.admitted_bytes,
            admitted_symbol_bytes: self.admitted_symbol_bytes,
            allowance: self.allowance_bytes,
            loss_expected: loss_counts.0.min(u128::from(u64::MAX)) as u64,
            loss_lost: loss_counts.1.min(u128::from(u64::MAX)) as u64,
            loss_batch,
        });
        if let Some(maximum) = trial_action.maximum_rate {
            // Rollback can only remove trial credit. A real safety reduction
            // that already went below the baseline must never be undone.
            self.rate_bps = self.rate_bps.min(maximum);
            if self.rate_bps < previous_rate {
                // Withdrawing trial credit is not the congestion brake. Do
                // not start its debounce here and suppress a real brake from
                // this same observation (fast loss, queue or transport block).
                self.growth_not_before_us = now.saturating_add(RETRY_GROWTH_US);
            }
        }
        let protect_ordinary_loss = trial_action.protect_ordinary_loss;
        let new_loss = fast_loss_actionable
            || (loss_batch.is_some() && self.loss_pressure && !protect_ordinary_loss);
        let loss_for_brake = if fast_loss_actionable {
            actionable_loss_fraction
        } else {
            self.loss_evidence.fraction()
        };
        // A fresh receiver interval can expose a service collapse even when
        // probes are lost and the configured allowance exceeds actual demand.
        // Compare actual symbol rates over each clock's own paired interval.
        // A full stable local interval and recent actual business activity avoid
        // treating idle traffic or an earlier pace as current capacity evidence.
        let last_pace_change = self
            .rate_changes
            .back()
            .map_or(last_change, |change| last_change.max(change.at_us));
        let activity_since_us = if self.fast_feedback_seen {
            self.demand_activity.since_us
        } else {
            None
        };
        let service_admission = service_sample.and_then(|sample| {
            sample.admission.map(|admission| ServiceAdmission {
                symbol_bytes: admission.symbol_bytes,
                symbols: admission.symbols,
                symbol_bps: admission.bps,
                span_us: admission.span_us,
                started_us: admission.started_us,
                backlog_since_us: self.backlog_since_us,
                activity_since_us,
                last_pace_change_us: last_pace_change,
                deficit: new_service_report
                    && admission.span_us >= PROBE_US
                    && admission.symbols >= 8
                    && admission.bps > 0.0
                    && admission.started_us >= last_pace_change
                    && activity_since_us.is_some_and(|since| since <= admission.started_us)
                    && sample.bps < admission.bps * 0.85
                    && wire_delivery_bps
                        .is_some_and(|rate| rate < self.rate_bps as f64 * 0.85)
                    // A rollback in this observation has not yet been logged.
                    && self.rate_bps == previous_rate,
            })
        });
        let service_deficit = service_admission
            .as_ref()
            .is_some_and(|sample| sample.deficit);
        self.last_control.service_admission = service_admission;
        // Positive underdelivery is exactly what the bounded reprobe compares
        // at its baseline/trial pace. Braking it before that comparison can
        // invalidate every measurement. Zero service remains an immediate
        // deficit; queue, fast-loss and blocked-transport protections still run.
        let service_deficit_actionable =
            service_deficit && (!protect_ordinary_loss || service_bps == Some(0.0));
        let pressure = delay_pressure
            || (self.loss_pressure && !protect_ordinary_loss)
            || fast_loss
            || blocked_pressure
            || service_deficit_actionable;
        if pressure {
            if !self.fast_feedback_seen {
                self.pressure_episode_exercised.get_or_insert(exercised);
            }
        } else if new_loss_report && observation.feedback_sample_symbols > 0 {
            // A clear RTT alone can precede the delayed loss report for this
            // episode. Require a genuinely new, finalized clear interval too.
            self.pressure_episode_exercised = None;
            self.pressure_episode_braked = false;
        }
        let delivery_shortfall = (new_service_report
            && delay_pressure
            && admission_span > 0
            && now.saturating_sub(self.last_growth_us) >= PROBE_US + BRAKE_US
            && exercised
            && wire_delivery_bps.is_some_and(|rate| rate < self.rate_bps as f64 * 0.85))
            || service_deficit_actionable;
        if delivery_shortfall {
            // Current exercised underdelivery or a qualified paired service
            // deficit replaces an older high hint, including with zero service.
            self.draining_bps = wire_delivery_bps.map(|rate| (rate, now));
        }
        if new_service_report
            && delay_pressure
            && let Some(delivery) =
                wire_delivery_bps.filter(|rate| *rate > self.rate_bps as f64 * 1.1)
        {
            // An application-limited drain interval is not a new lower capacity.
            self.draining_bps = Some((delivery, now));
        }
        let recent_drain = self
            .draining_bps
            .filter(|(_, at)| now.saturating_sub(*at) <= FRESH_US)
            .map(|(rate, _)| rate);
        let startup = now.saturating_sub(self.born_us) < FRESH_US;

        // Congestion changes the pace, not reachability. Keeping useful originals
        // flowing also lets the receiver produce fresh delivery and loss samples.
        self.eligible = (fresh || startup) && self.no_delivery_confirmed_us.is_none();
        self.health = if self.no_delivery_confirmed_us.is_some() {
            Health::Probing
        } else if !fresh {
            if startup {
                Health::Unknown
            } else {
                Health::Probing
            }
        } else if pressure {
            Health::Degraded
        } else {
            Health::Healthy
        };

        let positive_young = observation
            .positive_delivery_age_us
            .is_some_and(|age| age <= CONTROL_US);
        let short_report_valid = short_delivery_interval
            && positive_young
            && previous_report.is_none_or(|(number, bytes, _)| {
                observation.report_number >= number
                    && observation.delivered_bytes >= bytes
                    && (observation.report_number != number || observation.delivered_bytes == bytes)
                    && (!new_report || observation.delivered_bytes > bytes)
            });
        if !fast_initial
            || !self.eligible
            || !observation.offered_backlog
            || !observation_contiguous
            || !short_report_valid
            || self.rate_bps != previous_rate
            || self.initial_delivery_credit.is_some_and(|credit| {
                !credit.fresh_at(now) || credit.observed_us <= last_pace_change
            })
        {
            self.initial_delivery_credit = None;
        }
        if fast_initial
            && self.eligible
            && observation.offered_backlog
            && observation_contiguous
            && short_report_valid
            && !pressure
            && self.rate_bps == previous_rate
            && now > last_pace_change
            && new_report
            && previous_report.is_some_and(|(number, bytes, _)| {
                observation.report_number > number && observation.delivered_bytes > bytes
            })
            && allowance_rate > 0.0
            && let Some(wire_rate) = observation
                .delivered_bps
                .map(|rate| rate * self.wire_per_symbol)
                .filter(|rate| rate.is_finite() && *rate >= allowance_rate * 0.85)
        {
            // Keep the newest qualifying report, not the highest historical
            // rate. A lower positive report neither erases it nor renews its age.
            self.initial_delivery_credit = Some(InitialDeliveryCredit {
                report_number: observation.report_number,
                delivered_bytes: observation.delivered_bytes,
                observed_us: now,
                positive_age_at_observation_us: observation.positive_delivery_age_us.unwrap_or(0),
                wire_delivery_bps: wire_rate,
                used: false,
            });
        }
        self.last_control.initial_delivery_credit = self.initial_delivery_credit;

        let independent_local_pressure = (rtt == local_rtt && rtt_excess > self.target_ms * 0.5)
            || local_rtt
                .zip(self.last_local_rtt_ms)
                .is_some_and(|(current, previous)| current > previous + 0.25)
            || transport_wait > self.target_ms * 0.5;
        let pre_brake_probe_pressure = self.fast_feedback_seen
            && self.queue_delay_ms < self.target_ms * 4.0
            && !independent_local_pressure
            && ((rtt.is_some() && rtt != local_rtt && rtt_excess > self.target_ms * 0.5)
                || startup_probe_excess.is_some_and(|excess| excess > self.target_ms * 0.5))
            && probe_began_us
                .zip(self.last_brake_us)
                .is_some_and(|(began, brake)| began <= brake);
        let new_delay = persistent_delay
            && !pre_brake_probe_pressure
            && self.braked_queue_ms.is_none_or(|last| {
                new_queue && self.queue_delay_ms > last + (self.target_ms * 0.1).max(1.0)
            });
        let new_pressure =
            new_delay || delivery_shortfall || new_loss || (blocked_pressure && new_service_report);
        // An unused allowance is not traffic that can be drained. Sparse idle
        // echo/probe jitter must not turn its small delivery sample into a path
        // capacity estimate. Backlog, blocked transport or the separately
        // qualified actual-admission deficit still permits a safety brake.
        let active_demand =
            observation.offered_backlog || exercised || blocked_pressure || service_deficit;
        if self.eligible
            && active_demand
            && new_pressure
            && self
                .last_brake_us
                .is_none_or(|at| now.saturating_sub(at) >= BRAKE_US)
        {
            // Pace below the observed drain while a queue exists. A single old
            // RTT/loss value cannot cause repeated multiplicative reductions.
            // Larger queues get a temporary drain interval; capacity memory survives it.
            let drain_fraction = (1.0
                - (self.queue_delay_ms - self.target_ms * 0.25).max(0.0) / 200.0)
                .clamp(0.25, 0.97);
            let service_hint = wire_delivery_bps
                .map(|rate| rate.max(recent_drain.unwrap_or(0.0)))
                .or(recent_drain);
            let episode_exercised = self.pressure_episode_exercised.unwrap_or(exercised);
            let mut desired = service_hint
                .filter(|rate| {
                    *rate > 0.0
                        && (episode_exercised
                            || delivery_shortfall
                            || *rate >= self.rate_bps as f64)
                })
                .map_or(self.rate_bps as f64 * 0.8, |rate| rate * drain_fraction);
            if delay_pressure
                && queue_rising
                && (self.queue_delay_ms - previous_queue > self.target_ms * 0.5
                    || self
                        .last_report
                        .is_none_or(|(_, _, at)| now.saturating_sub(at) > PROBE_US))
            {
                // An old high delivery report can be stuck behind the new queue.
                desired = desired.min(self.rate_bps as f64 * 0.75);
            }
            if new_loss {
                desired = desired
                    .min(self.rate_bps as f64 * (1.0 - loss_for_brake * 0.5).clamp(0.5, 0.95));
            }
            let floor = MIN_BPS.min(self.maximum_bps) as f64;
            let reduced = desired.max(floor).min(self.rate_bps as f64) as u64;
            if reduced < self.rate_bps {
                if self.fast_feedback_seen {
                    self.pressure_episode_exercised.get_or_insert(exercised);
                }
                self.pressure_episode_braked = true;
                // Safety always brakes. Exercise qualification is captured
                // before the first reduction, never manufactured from use of
                // a later, smaller allowance while the old evidence drains.
                let capacity_evidence = new_delay
                    || delivery_shortfall
                    || (blocked_pressure && new_service_report)
                    || (new_loss && settled_shortfall);
                // Shared admission can keep a busy path below 90% of its own
                // allowance. A real queue brake plus a recent, continuously
                // backlogged business interval still establishes congestion.
                // This changes caution, not the measured service or brake rate.
                let backlogged_queue = self.fast_feedback_seen
                    && new_delay
                    && service_sample.is_some_and(|sample| {
                        now.saturating_sub(sample.observed_us) <= PROBE_US
                            && sample.admission.is_some_and(|admission| {
                                admission.span_us >= PROBE_US
                                    && admission.symbols >= 8
                                    && admission.symbol_bytes > 0
                                    && self
                                        .backlog_since_us
                                        .is_some_and(|since| since <= admission.started_us)
                            })
                    });
                self.congestion_seen |= service_deficit
                    || backlogged_queue
                    || (self.pressure_episode_exercised == Some(true) && capacity_evidence);
                if new_delay {
                    self.braked_queue_ms = Some(self.queue_delay_ms);
                    self.drain_restore_pending = true;
                }
                self.rate_bps = reduced;
                rate_reason = if fast_loss_actionable {
                    RateReason::FastLossBrake
                } else if new_delay {
                    RateReason::QueueBrake
                } else if blocked_pressure {
                    RateReason::TransportBlockedBrake
                } else if delivery_shortfall {
                    RateReason::DeliveryShortfallBrake
                } else {
                    RateReason::LossBrake
                };
                self.record_brake(observation);
            }
        }

        // Independent brakes have already run. Only the still-owned increment
        // can be withdrawn; small queue changes leave its second observation due.
        if !self.eligible
            || !observation.offered_backlog
            || !observation_contiguous
            || !fresh
            || self.growth_retry.as_ref().is_some_and(|rejected| {
                now.checked_sub(rejected.observed_us)
                    .is_none_or(|age| age > FRESH_US)
            })
        {
            self.growth_retry = None;
        }
        let mut monitor_withdrawn = false;
        if !self.fast_feedback_seen
            || !self.congestion_seen
            || !self.eligible
            || !observation.offered_backlog
            || !observation_contiguous
            || !fresh
            || !probe_fresh
            || self.rate_bps != previous_rate
            || self.rate_bps != rate_before_refill
            || self.growth_monitor.as_mut().is_some_and(|monitor| {
                monitor.pacing_bps != self.rate_bps
                    || !monitor.observe(observation, probe_rtt.unwrap_or(f64::INFINITY))
            })
        {
            self.growth_monitor = None;
        }
        if self
            .growth_monitor
            .as_ref()
            .is_some_and(|monitor| monitor.second_reply.is_some())
        {
            let mut monitor = self.growth_monitor.take().unwrap();
            let rising = monitor
                .first_reply
                .as_ref()
                .zip(monitor.second_reply.as_ref())
                .is_some_and(|(first, second)| second.rtt_ms > first.rtt_ms + 0.25);
            if rising && self.queue_delay_ms > self.target_ms * 0.25 {
                self.rate_bps = monitor.previous_bps;
                rate_reason = RateReason::GrowthWithdrawalBrake;
                monitor.withdrawn = true;
                monitor_withdrawn = true;
                self.record_brake(observation);
                self.growth_retry = Some(GrowthRetry {
                    baseline_bps: monitor.previous_bps,
                    increment_bps: monitor.pacing_bps - monitor.previous_bps,
                    observed_us: now,
                });
            } else if let Some(rejected) = self
                .growth_retry
                .as_mut()
                .filter(|rejected| rejected.baseline_bps == monitor.pacing_bps)
            {
                // Only the owned retry's two actual clear replies can recover
                // its step. Do not forget a failed gain after one smaller step.
                rejected.increment_bps = rejected.increment_bps.saturating_mul(2);
                rejected.observed_us = now;
            }
            self.last_control.growth_monitor = Some(monitor);
        } else {
            self.last_control.growth_monitor = self.growth_monitor.clone();
        }
        let mut ordinary_growth = false;
        let unused_growth_probe = probe_fresh
            && observation
                .probe_age_us
                .is_some_and(|age| age <= CONTROL_US)
            && self.last_growth_probe.is_none_or(|used| {
                observation.probe_sample_id > used
                    && probe_rtt.is_some_and(|rtt| {
                        let sent_us = now
                            .saturating_sub(observation.probe_age_us.unwrap_or(u64::MAX))
                            .saturating_sub((rtt * 1000.0).ceil() as u64);
                        sent_us > self.last_growth_us
                    })
            });
        let growth_probe_ready = !self.fast_feedback_seen || unused_growth_probe;
        // Ordinary cautious growth spends one completed service endpoint.
        // The independently measured post-brake restoration below keeps its
        // own stricter service qualification and the original probe guard.
        let ordinary_growth_ready = growth_probe_ready
            && self.growth_monitor.is_none()
            && (!self.fast_feedback_seen
                || !self.congestion_seen
                || self.discovery_service_window(now).is_some());
        // Near service, an increment adds (gain - 1) * held_time of queue.
        // Ordinary cautious growth needs two replies to settle its monitor:
        // even immediate requests hold the increment for their spacing + RTT.
        // Initial byte-feedback growth does not use that two-reply monitor.
        // This remains a heuristic: scheduling and shared traffic can extend
        // the feedback horizon; it is not a hard queue or capacity bound.
        let growth_gain_limit = if self.fast_feedback_seen {
            let headroom = (self.target_ms * 0.8 - self.queue_delay_ms).max(0.0);
            let reply_spacing_ms = if self.congestion_seen {
                FAST_PROBE_US as f64 / 1000.0
            } else {
                0.0
            };
            probe_rtt.map_or(1.0, |rtt| {
                1.0 + (headroom / (rtt + reply_spacing_ms)).min(0.5)
            })
        } else {
            1.5
        };
        let elapsed = now.saturating_sub(self.last_control_us);
        if elapsed >= CONTROL_US {
            if !monitor_withdrawn
                && fresh
                && self.eligible
                && !pressure
                && !protect_ordinary_loss
                && self.drain_restore_pending
            {
                // RTT observations are more frequent than control ticks. Keep
                // the drainage transition pending so an intervening clear RTT
                // cannot erase restoration before the next control tick.
                let measured_restore = service_sample.and_then(|sample| {
                    let braked_at = self.last_brake_us?;
                    let admission = sample.admission?;
                    let sent_us = now
                        .checked_sub(observation.probe_age_us?)?
                        .checked_sub((probe_rtt? * 1000.0).ceil() as u64)?;
                    // These are two independent-clock intervals. The local
                    // admission interval must follow every pace change; its
                    // excess receiver delivery then corroborates old drainage.
                    (self.fast_feedback_seen
                        && positive_young
                        && growth_probe_ready
                        && sent_us > self.last_growth_us
                        && sent_us > braked_at
                        && self.rate_bps == rate_before_refill
                        && self.rate_bps == previous_rate
                        && now
                            .checked_sub(sample.observed_us)
                            .is_some_and(|age| age <= CONTROL_US)
                        && sample.span_us >= PROBE_US
                        && admission.span_us >= PROBE_US
                        && admission.symbols >= 8
                        && admission.bps > 0.0
                        && admission.started_us >= braked_at
                        && admission.started_us >= last_pace_change
                        && self
                            .backlog_since_us
                            .is_some_and(|since| since <= admission.started_us)
                        && sample.bps > admission.bps * 1.1)
                        .then(|| {
                            (sample.bps * self.wire_per_symbol * 0.9).min(self.maximum_bps as f64)
                                as u64
                        })
                });
                if let Some(restored) = measured_restore.filter(|target| *target > self.rate_bps) {
                    self.rate_bps = restored;
                    rate_reason = RateReason::KnownServiceRecovery;
                    self.last_growth_us = now;
                    self.drain_restore_pending = false;
                    self.last_control.drain_service_target_bps = Some(restored);
                } else if let Some(drain) = recent_drain
                    && ordinary_growth_ready
                {
                    let ceiling = if self.fast_feedback_seen {
                        self.rate_bps as f64 * growth_gain_limit
                    } else {
                        self.maximum_bps as f64
                    };
                    let restored = self.limit_growth_retry(
                        (drain * 0.9).min(self.maximum_bps as f64).min(ceiling) as u64,
                        now,
                    );
                    if restored > self.rate_bps {
                        ordinary_growth = true;
                        self.rate_bps = restored;
                        rate_reason = RateReason::KnownServiceRecovery;
                        self.last_growth_us = now;
                    }
                    self.drain_restore_pending = false;
                } else if recent_drain.is_none() {
                    self.drain_restore_pending = false;
                }
            }
            if !monitor_withdrawn
                && fresh
                && self.eligible
                && !pressure
                && !protect_ordinary_loss
                && (!observation.reprobe_enabled || delivery_fresh)
                // Credible loss with underdelivery must get a settled service
                // observation before recovery explores further. The retained
                // capacity shortcut otherwise bypasses receiver-keeps-up and
                // can restart growth faster than loss can be corroborated.
                && !(ordinary_loss && service_shortfall)
                && observation.offered_backlog
                && exercised
                && now >= self.growth_not_before_us
            {
                let initial_delivery_bps = self
                    .latest_delivery_bps
                    .map(|rate| rate * self.wire_per_symbol);
                let receiver_keeps_up =
                    initial_delivery_bps.is_some_and(|rate| rate >= allowance_rate * 0.85);
                let unused_short_report = self.last_report.is_some_and(|(number, bytes, at)| {
                    number == observation.report_number
                        && bytes > 0
                        && now.saturating_sub(at) <= CONTROL_US
                        && observation
                            .positive_delivery_age_us
                            .is_some_and(|age| age <= CONTROL_US)
                        && self
                            .last_initial_growth_report
                            .is_none_or(|(used, delivered)| number > used && bytes > delivered)
                });
                let retained_credit = self.initial_delivery_credit.filter(|credit| {
                    !self.congestion_seen
                        && short_delivery_interval
                        && credit.fresh_at(now)
                        && credit.observed_us > last_pace_change.max(self.last_growth_us)
                        && credit.wire_delivery_bps >= allowance_rate * 0.85
                        && self
                            .last_initial_growth_report
                            .is_none_or(|(number, bytes)| {
                                credit.report_number > number && credit.delivered_bytes > bytes
                            })
                });
                let retained_support = retained_credit.is_some();
                // A new qualified service endpoint can support one bounded
                // discovery beyond retained delivery. Its arrival may precede
                // this control tick; an intervening increase spends the credit.
                // The receiver interval itself can overlap an earlier pace.
                let service_discovery = !ordinary_loss
                    && self.queue_delay_ms <= self.target_ms * 0.25
                    && observation
                        .positive_delivery_age_us
                        .is_some_and(|age| age <= CONTROL_US)
                    && self.discovery_service_window(now).is_some_and(|sample| {
                        sample.bps * self.wire_per_symbol >= allowance_rate * 0.85
                    });
                let (interval, gain, ceiling): (u64, f64, f64) = if !self.congestion_seen {
                    // The initial search is fast only when actual admissions and
                    // receiver delivery support it, not at 60% use of an unused budget.
                    // Short authenticated byte reports close the loop sooner;
                    // RTT also limits their gain without bypassing a brake.
                    (
                        if short_delivery_interval {
                            CONTROL_US
                        } else {
                            400_000
                        },
                        1.5,
                        self.maximum_bps as f64,
                    )
                } else if service_discovery {
                    (CONTROL_US, 1.25, self.maximum_bps as f64)
                } else if self.in_known_service_range() {
                    // Revisit a previously exercised range in small, observable
                    // steps. A failed trial brakes and waits before another attempt.
                    (CONTROL_US, 1.25, self.remembered_bps * 0.95)
                } else {
                    (500_000, 1.03, self.maximum_bps as f64)
                };
                let gain = gain.min(growth_gain_limit);
                if now.saturating_sub(self.last_growth_us) >= interval
                    && (self.congestion_seen || receiver_keeps_up || retained_support)
                    && (self.congestion_seen
                        || !short_delivery_interval
                        || unused_short_report
                        || retained_support)
                    && ordinary_growth_ready
                {
                    let before_growth = self.rate_bps;
                    let proposed = ((self.rate_bps as f64 * gain).min(ceiling) as u64)
                        .max(self.rate_bps)
                        .min(self.maximum_bps);
                    self.rate_bps = self.limit_growth_retry(proposed, now);
                    ordinary_growth |= self.rate_bps > before_growth;
                    rate_reason = if !self.congestion_seen {
                        if self.rate_bps > before_growth || !self.fast_feedback_seen {
                            let supporting_report = if short_delivery_interval
                                && (!receiver_keeps_up || !unused_short_report)
                            {
                                retained_credit
                                    .map(|credit| (credit.report_number, credit.delivered_bytes))
                            } else {
                                self.last_report.map(|(number, bytes, _)| (number, bytes))
                            };
                            self.last_initial_growth_report = supporting_report;
                            if let Some(credit) = self.last_control.initial_delivery_credit.as_mut()
                                && supporting_report
                                    == Some((credit.report_number, credit.delivered_bytes))
                            {
                                credit.used = true;
                            }
                        }
                        RateReason::InitialGrowth
                    } else if service_discovery {
                        RateReason::ServiceDiscovery
                    } else if self.in_known_service_range() {
                        RateReason::KnownServiceRecovery
                    } else {
                        RateReason::CautiousGrowth
                    };
                    if self.rate_bps > before_growth
                        || self.congestion_seen
                        || !self.fast_feedback_seen
                    {
                        // A capped initial no-op consumes neither report nor
                        // growth time. Legacy and recovery timing stay intact.
                        self.last_growth_us = now;
                    }
                }
            }
            // A no-op waiting for evidence is not a new pacing interval. Keep
            // the paired admission/allowance history until the first delivery
            // report, or until the probe requested for a young service endpoint
            // returns. Otherwise the next control tick can outlive that endpoint.
            // No evidence age is renewed, and an actual rate change, pressure,
            // idle or expiry still settles this bounded window.
            let pending_evidence = self.fast_feedback_seen
                && self.rate_bps == previous_rate
                && observation_contiguous
                && fresh
                && self.eligible
                && observation.offered_backlog
                && !pressure
                && ((!self.congestion_seen
                    && self.last_initial_growth_report.is_none()
                    && elapsed < FRESH_US)
                    || (!growth_probe_ready && self.discovery_service_window(now).is_some()));
            if !pending_evidence {
                self.last_control_us = now;
                self.admitted_bytes = 0;
                self.admitted_symbol_bytes = 0;
                self.allowance_bytes = 0.0;
            }
        }
        if self.rate_bps > previous_rate {
            // Ordinary search and both recovery paths spend the same probe
            // credit. A new control tick cannot reuse a previous clear reply.
            self.last_growth_probe = Some(observation.probe_sample_id);
        }
        self.rate_bps = self.rate_bps.min(self.maximum_bps).max(1);
        if ordinary_growth
            && self.rate_bps > previous_rate
            && self.last_control.growth_retry_ceiling_bps.is_some()
            && let Some(rejected) = self.growth_retry.as_mut()
        {
            rejected.baseline_bps = self.rate_bps;
            rejected.increment_bps = (self.rate_bps - previous_rate).saturating_mul(2);
        }
        self.record_rate_change(now, previous_rate, rate_reason);
        if ordinary_growth
            && self.rate_bps > previous_rate
            && self.fast_feedback_seen
            && self.congestion_seen
        {
            self.growth_monitor = Some(GrowthMonitor::arm(
                observation,
                previous_rate,
                self.rate_bps,
            ));
        }
        self.last_probe_sample_id = observation.probe_sample_id;
        self.last_rtt_ms = rtt;
        self.last_local_rtt_ms = local_rtt;
        self.last_transport_wait_ms = transport_wait;
        self.tokens = self.tokens.min(2400.0);
    }

    fn in_known_service_range(&self) -> bool {
        (self.rate_bps as f64) < self.remembered_bps * 0.90
    }

    fn limit_growth_retry(&mut self, proposed_bps: u64, now_us: u64) -> u64 {
        if let Some(rejected) = self.growth_retry.as_ref().filter(|rejected| {
            rejected.baseline_bps == self.rate_bps
                && now_us
                    .checked_sub(rejected.observed_us)
                    .is_some_and(|age| age <= FRESH_US)
        }) {
            // Bisect only the rejected increment, never raise the rollback
            // baseline or infer a capacity ceiling from shared queue growth.
            let ceiling = rejected
                .baseline_bps
                .saturating_add(rejected.increment_bps / 2);
            self.last_control.growth_retry_ceiling_bps = Some(ceiling);
            proposed_bps.min(ceiling)
        } else {
            proposed_bps
        }
    }

    fn discovery_service_window(&self, now_us: u64) -> Option<service::Sample> {
        (self.fast_feedback_seen && self.congestion_seen)
            .then(|| self.service_window.discovery_latest(now_us))
            .flatten()
            .filter(|sample| {
                sample.observed_us > self.last_growth_us
                    && now_us.saturating_sub(sample.observed_us) <= CONTROL_US
            })
    }

    fn probe_request_due(&self, now_us: u64, stale: bool) -> bool {
        let Some(last_probe_us) = self.last_probe_us else {
            return true;
        };
        let elapsed = now_us.saturating_sub(last_probe_us);
        if elapsed >= PROBE_US {
            return true;
        }
        if elapsed < FAST_PROBE_US {
            return false;
        }
        let active = self.fast_feedback_seen
            && self.eligible
            && !stale
            && self.last_control.offered_backlog
            && self.last_control.probe_rtt_ms.is_some_and(|rtt| {
                rtt.is_finite() && rtt > 0.0 && rtt * 1000.0 <= CONTROL_US as f64
            });
        let probe_age = self
            .last_control
            .probe_age_us
            .map(|age| age.saturating_add(now_us.saturating_sub(self.last_control.at_us)));
        let young = active && probe_age.is_some_and(|age| age <= CONTROL_US);
        let fast_opportunity = !self.congestion_seen
            || self.health != Health::Healthy
            || self.queue_delay_ms > self.target_ms * 0.25
            || self.last_control.transport_blocked
            || self.reprobe.active()
            || self
                .growth_monitor
                .as_ref()
                .is_some_and(|monitor| monitor.request_due(now_us));
        let phase_repair = active
            && self.congestion_seen
            && now_us >= self.last_control.at_us
            && last_probe_us <= self.last_growth_us
            && now_us >= self.last_growth_us.saturating_add(FAST_PROBE_US)
            && probe_age.is_some_and(|age| age <= FRESH_US);
        let service_request = active
            && self.congestion_seen
            && now_us >= self.last_control.at_us
            && elapsed >= CONTROL_US
            && probe_age.is_some_and(|age| age <= FRESH_US)
            && self
                .discovery_service_window(now_us)
                .is_some_and(|sample| last_probe_us < sample.observed_us);
        // These opportunities are independent. New service cannot cancel an
        // owed request after growth just because the old reply aged past 200ms.
        // Only probe_admitted spends the repair; without a reply the original
        // 500ms health deadline remains, rather than repeated stale retries.
        (young && fast_opportunity) || service_request || phase_repair
    }

    pub fn decision(&self, now_us: u64) -> Decision {
        let stale = now_us.saturating_sub(self.born_us) >= FRESH_US
            && self
                .last_evidence_us
                .is_none_or(|time| now_us.saturating_sub(time) > FRESH_US);
        let weight_loss = self.weight_loss.and_then(|sample| {
            let age = sample
                .age_us
                .saturating_add(now_us.saturating_sub(sample.observed_us));
            (age <= FRESH_US).then_some((sample, age))
        });
        let effective_loss =
            weight_loss.map(|(sample, _)| self.weight_window.effective_rate(sample.rate));
        let reliability = effective_loss.map_or(1.0, |loss| (1.0 - loss).powi(4).clamp(0.25, 1.0));
        let base_weight = ((self.rate_bps as f64 / 64_000.0)
            / (1.0
                + self.min_rtt_ms.unwrap_or(50.0) / 50.0
                + self.queue_delay_ms / self.target_ms))
            .round()
            .clamp(1.0, 128.0);
        Decision {
            pacing_bps: self.rate_bps,
            eligible: self.eligible && !stale,
            weight: (base_weight * 16.0 * reliability)
                .round()
                .clamp(4.0, 2048.0) as i32,
            weight_loss_rate: weight_loss.map(|(sample, _)| sample.rate),
            weight_loss_age_us: weight_loss.map(|(_, age)| age),
            weight_loss_report: weight_loss.map(|(sample, _)| sample.report),
            weight_loss_effective_rate: effective_loss,
            weight_loss_window_expected: weight_loss.map(|_| self.weight_window.expected),
            weight_loss_window_lost: weight_loss.map(|_| self.weight_window.lost),
            weight_loss_window_oldest_age_us: weight_loss.and_then(|_| {
                self.weight_window.batches.front().map(|batch| {
                    batch
                        .age_us
                        .saturating_add(now_us.saturating_sub(batch.observed_us))
                })
            }),
            state: if stale { Health::Probing } else { self.health },
            queue_delay_ms: self.queue_delay_ms,
            probe_due: self.probe_request_due(now_us, stale),
            observed_delivery_bps: self.delivery_bps,
            loss_evidence_expected: self.loss_evidence.counts().0.min(u128::from(u64::MAX)) as u64,
            loss_evidence_lost: self.loss_evidence.counts().1.min(u128::from(u64::MAX)) as u64,
            loss_pressure: self.loss_pressure,
            cautious: self.congestion_seen,
        }
    }

    pub fn snapshot(&self, now_us: u64) -> Snapshot {
        Snapshot {
            decision: self.decision(now_us),
            reprobe: self.reprobe.snapshot(),
            rate_changes: self.rate_changes.clone(),
            rate_changes_total: self.rate_changes_total,
            rate_changes_evicted: self
                .rate_changes_total
                .saturating_sub(self.rate_changes.len() as u64),
            last_control: self.last_control.clone(),
        }
    }

    pub fn allow(&mut self, now_us: u64, bytes: usize, queue_age_ms: f64) -> bool {
        self.refill(now_us);
        self.decision(now_us).eligible
            && queue_age_ms.is_finite()
            && queue_age_ms >= 0.0
            && queue_age_ms <= self.target_ms
            && self.tokens >= bytes as f64
    }

    pub fn admitted(&mut self, now_us: u64, bytes: usize) {
        self.admitted_symbol(now_us, bytes, bytes);
    }

    pub fn admitted_symbol(
        &mut self,
        now_us: u64,
        wire_bytes: usize,
        measured_symbol_bytes: usize,
    ) {
        self.refill(now_us);
        self.demand_activity
            .update(now_us, wire_bytes > 0 && measured_symbol_bytes > 0);
        self.tokens = (self.tokens - wire_bytes as f64).max(0.0);
        self.admitted_bytes = self.admitted_bytes.saturating_add(wire_bytes as u64);
        self.admitted_symbol_bytes = self
            .admitted_symbol_bytes
            .saturating_add(measured_symbol_bytes as u64);
        self.reprobe.admitted(wire_bytes);
    }

    pub fn probe_admitted(&mut self, now_us: u64) {
        self.last_probe_us = Some(now_us);
        if let Some(monitor) = self.growth_monitor.as_mut() {
            monitor.probe_admitted(now_us);
        }
    }

    pub fn reprobe_candidate(&self, now_us: u64) -> Option<ReprobeRequest> {
        if !self.decision(now_us).eligible {
            return None;
        }
        self.reprobe.candidate(now_us).filter(|request| {
            self.generation == Some(request.generation) && self.rate_bps == request.baseline_bps
        })
    }

    /// The sender owns all paths and grants only one trial per bottleneck group.
    /// Its ceiling also accounts for the other live paths' operational budgets.
    pub fn start_reprobe(&mut self, now_us: u64, maximum_trial_bps: u64) -> bool {
        self.refill(now_us);
        if self.reprobe_candidate(now_us).is_none() {
            return false;
        }
        let previous = self.rate_bps;
        let Some(rate) = self
            .reprobe
            .start(now_us, maximum_trial_bps.min(self.maximum_bps))
        else {
            return false;
        };
        self.rate_bps = rate;
        self.last_growth_us = now_us;
        // Do not carry the pre-trial burst into a finite extra-credit interval.
        self.tokens = 0.0;
        self.record_rate_change(now_us, previous, RateReason::ReprobeStart);
        true
    }

    pub fn reprobe_active(&self) -> bool {
        self.reprobe.active()
    }

    fn record_brake(&mut self, observation: &Observation) {
        self.last_brake_us = Some(observation.now_us);
        self.last_brake_admitted_symbols = self
            .fast_feedback_seen
            .then_some(observation.admitted_symbols)
            .flatten()
            .filter(|admitted| {
                self.last_brake_admitted_symbols
                    .is_none_or(|boundary| *admitted >= boundary)
                    && observation
                        .finalized_expected
                        .zip(observation.finalized_lost)
                        .is_some_and(|(expected, lost)| lost <= expected && expected <= *admitted)
            });
        self.growth_not_before_us = observation.now_us.saturating_add(RETRY_GROWTH_US);
    }

    fn record_rate_change(&mut self, now_us: u64, previous_bps: u64, reason: RateReason) {
        if previous_bps == self.rate_bps {
            return;
        }
        self.initial_delivery_credit = None;
        self.growth_monitor = None;
        let owned_retry = self.last_control.growth_retry_ceiling_bps.is_some()
            && self
                .growth_retry
                .as_ref()
                .is_some_and(|rejected| rejected.baseline_bps == self.rate_bps)
            && matches!(
                reason,
                RateReason::ServiceDiscovery
                    | RateReason::KnownServiceRecovery
                    | RateReason::CautiousGrowth
            );
        if !matches!(reason, RateReason::GrowthWithdrawalBrake) && !owned_retry {
            self.growth_retry = None;
        }
        self.rate_changes_total = self.rate_changes_total.saturating_add(1);
        if self.rate_changes.len() == 16 {
            self.rate_changes.pop_front();
        }
        self.rate_changes.push_back(RateChange {
            number: self.rate_changes_total,
            at_us: now_us,
            previous_bps,
            pacing_bps: self.rate_bps,
            reason,
            control: self.last_control.clone(),
        });
    }

    fn refill(&mut self, now_us: u64) {
        if let Some(deadline) = self
            .reprobe
            .deadline()
            .filter(|deadline| now_us >= *deadline)
        {
            let old_rate = self.rate_bps;
            // Split the integral at the finite phase boundary even if the
            // observer is delayed. Calling allow alone cannot extend a trial.
            let before =
                deadline.saturating_sub(self.token_us) as f64 * old_rate as f64 / 8_000_000.0;
            self.allowance_bytes += before;
            self.tokens = (self.tokens + before).min(2400.0);
            self.token_us = self.token_us.max(deadline);
            if let Some(maximum) = self.reprobe.expire(now_us) {
                self.rate_bps = self.rate_bps.min(maximum);
                self.growth_not_before_us = now_us.saturating_add(RETRY_GROWTH_US);
                self.record_rate_change(now_us, old_rate, RateReason::ReprobeRollback);
            }
        }
        let allowance =
            now_us.saturating_sub(self.token_us) as f64 * self.rate_bps as f64 / 8_000_000.0;
        self.allowance_bytes += allowance;
        self.tokens = (self.tokens + allowance).min(2400.0);
        self.token_us = self.token_us.max(now_us);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn observation(now_us: u64, rtt_ms: f64) -> Observation {
        Observation {
            now_us,
            generation: 7,
            report_number: now_us / 500_000 + 1,
            feedback_age_us: Some(0),
            positive_delivery_age_us: Some(0),
            delivered_bytes: now_us / 20,
            feedback_sample_symbols: 32,
            loss_sample_rate: Some(0.0),
            rtt_ms,
            probe_rtt_ms: Some(rtt_ms),
            probe_latest_rtt_ms: Some(rtt_ms),
            probe_sample_id: now_us / 500_000 + 1,
            probe_age_us: Some(0),
            offered_backlog: true,
            ..Default::default()
        }
    }

    fn exercise_budget(controller: &mut PathController, start: u64, duration: u64) -> u64 {
        let mut admitted = 0;
        for now in (start..start + duration).step_by(1000) {
            while controller.allow(now, 1000, 0.0) {
                controller.admitted(now, 1000);
                admitted += 1000;
            }
        }
        admitted
    }

    fn admitted_report_026(
        controller: &mut PathController,
        previous: &Observation,
        now: u64,
        delivery_limit: u64,
    ) -> Observation {
        let span = now - previous.now_us;
        let admitted = exercise_budget(controller, previous.now_us, span);
        let delivered = admitted.min(delivery_limit);
        let mut sample = short_observation_022(now, 80.0);
        sample.delivered_bytes = previous.delivered_bytes + delivered;
        sample.delivered_bps = Some(delivered as f64 * 8_000_000.0 / span as f64);
        sample.delivery_sample_span_us = span;
        sample.admitted_symbols = Some(previous.admitted_symbols.unwrap_or(0) + admitted / 1000);
        sample.admitted_symbol_bytes = Some(previous.admitted_symbol_bytes.unwrap_or(0) + admitted);
        sample
    }

    fn initial_credit_026(maximum: u64) -> (PathController, Observation) {
        let mut controller = PathController::new(maximum, 20);
        let mut sample = short_observation_022(0, 80.0);
        sample.delivered_bytes = 0;
        sample.delivered_bps = Some(0.0);
        sample.admitted_symbol_bytes = Some(0);
        controller.observe(&sample);
        // Isolate sustained service from the independent 2,400-byte startup
        // burst. Every reported byte below was actually admitted by the pacer.
        controller.tokens = 0.0;
        for now in [100_000, 200_000] {
            sample = admitted_report_026(&mut controller, &sample, now, u64::MAX);
            controller.observe(&sample);
        }
        (controller, sample)
    }

    #[test]
    fn startup_pending_evidence_keeps_the_exercised_window() {
        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = short_observation_022(0, 80.0);
        sample.delivered_bytes = 0;
        sample.delivered_bps = Some(0.0);
        sample.admitted_symbol_bytes = Some(0);
        controller.observe(&sample);
        controller.tokens = 0.0;
        // Real business keeps using the initial allowance, but the receiver's
        // first reports cover only the leading part of that business.
        for now in [100_000, 200_000] {
            sample = admitted_report_026(&mut controller, &sample, now, 1000);
            controller.observe(&sample);
        }
        assert_eq!(controller.rate_bps, START_BPS);
        assert!(controller.last_initial_growth_report.is_none());
        sample = admitted_report_026(&mut controller, &sample, 300_000, u64::MAX);
        controller.observe(&sample);
        assert!(
            controller.rate_bps > START_BPS,
            "a no-op at 200ms must not defer the first usable evidence to 400ms"
        );
        assert_eq!(controller.last_control.admission_span_us, 300_000);
        assert_eq!(controller.last_growth_us, 300_000);
        let grown = controller.rate_bps;
        controller.observe(&sample);
        sample = admitted_report_026(&mut controller, &sample, 400_000, u64::MAX);
        controller.observe(&sample);
        assert_eq!(
            controller.rate_bps, grown,
            "actual growth still waits 200ms"
        );
    }

    #[test]
    fn service_probe_arrival_can_use_the_completed_control_window() {
        let (mut controller, sample) = service_endpoint_032();
        let before = controller.rate_bps;
        let mut waiting = admitted_report_026(&mut controller, &sample, 600_000, u64::MAX);
        waiting.probe_sample_id = sample.probe_sample_id;
        waiting.probe_age_us = Some(CONTROL_US + 1);
        controller.observe(&waiting);
        assert_eq!(controller.rate_bps, before);
        assert!(controller.discovery_service_window(600_000).is_some());
        // The probe requested for the 500ms service endpoint arrives between
        // ticks. Both that endpoint and this real reply are still young.
        controller.probe_admitted(600_000);
        let mut ready = monitor_reply_034(&mut controller, &waiting, 680_000, 80.0, 600_000);
        ready.probe_sample_id = sample.probe_sample_id + 1;
        controller.observe(&ready);
        assert!(
            controller.rate_bps > before,
            "a no-op must not postpone this usable pair until the endpoint expires"
        );
        assert_eq!(controller.last_growth_us, 680_000);
        let grown = controller.rate_bps;
        controller.observe(&ready);
        assert_eq!(controller.rate_bps, grown);
        assert!(controller.discovery_service_window(680_000).is_none());
    }

    #[test]
    fn shared_admission_below_path_allowance_still_confirms_a_backlogged_queue() {
        for demand in ["continuous", "sparse", "interrupted"] {
            let mut controller = PathController::new(START_BPS, 20);
            let mut delivered = 0;
            let mut reported = 0;
            for now in (0..=600_000).step_by(1000) {
                if now > 0 && now % 40_000 == 0 && controller.allow(now, 1000, 0.0) {
                    controller.admitted(now, 1000);
                    delivered += 1000;
                }
                if now % 100_000 != 0 {
                    continue;
                }
                let mut sample =
                    short_observation_022(now, if now == 600_000 { 110.0 } else { 80.0 });
                sample.delivered_bytes = delivered;
                sample.delivered_bps = Some((delivered - reported) as f64 * 80.0);
                sample.admitted_symbol_bytes = Some(delivered);
                sample.admitted_symbols = Some(delivered / 1000);
                sample.offered_backlog =
                    demand != "sparse" && !(demand == "interrupted" && now == 300_000);
                controller.observe(&sample);
                reported = delivered;
            }
            assert!(
                (controller.last_control.admitted_bytes as f64)
                    < controller.last_control.integrated_allowance_bytes * 0.9
            );
            assert_eq!(
                controller.congestion_seen,
                demand == "continuous",
                "{demand}"
            );
            if demand == "continuous" {
                assert_eq!(controller.last_brake_us, Some(600_000));
                assert_eq!(controller.pressure_episode_exercised, Some(false));
                assert!(controller.rate_bps < START_BPS);
            }
        }
    }

    #[test]
    fn growth_monitor_observes_the_first_post_growth_request_without_extra_wait() {
        let (mut controller, sample) = monitored_growth_034();
        // Last successful request was 400ms. The global 100ms spacing has
        // already elapsed when this growth occurs at 600ms.
        assert!(!controller.decision(600_000).probe_due);
        assert!(controller.decision(601_000).probe_due);
        controller.probe_admitted(601_000);
        assert!(!controller.decision(700_999).probe_due);
        let mut first = monitor_reply_034(&mut controller, &sample, 685_000, 84.0, 601_000);
        first.probe_sample_id = sample.probe_sample_id + 1;
        controller.observe(&first);
        assert_eq!(controller.rate_bps, 334_506);
        assert!(controller.decision(701_000).probe_due);
        controller.probe_admitted(701_000);
        let mut second = monitor_reply_034(&mut controller, &first, 787_000, 86.0, 701_000);
        second.probe_sample_id = first.probe_sample_id + 1;
        controller.observe(&second);
        assert_eq!(controller.rate_bps, 307_200);
        assert!(matches!(
            controller.rate_changes.back().unwrap().reason,
            RateReason::GrowthWithdrawalBrake
        ));
        let monitor = controller.last_control.growth_monitor.as_ref().unwrap();
        assert_eq!(
            monitor.successful_request_us,
            [Some(601_000), Some(701_000)]
        );
        assert_eq!(
            monitor.first_reply.as_ref().unwrap().inferred_request_us,
            601_000
        );
        assert_eq!(
            monitor.second_reply.as_ref().unwrap().inferred_request_us,
            701_000
        );
    }

    #[test]
    fn startup_pending_evidence_does_not_retain_idle_pressure_or_old_windows() {
        for boundary in ["idle", "pressure", "expired", "legacy"] {
            let mut controller = PathController::new(20_000_000, 20);
            let mut sample = short_observation_022(0, 80.0);
            sample.delivered_bytes = 0;
            sample.delivered_bps = Some(0.0);
            controller.observe(&sample);
            controller.tokens = 0.0;
            for now in [100_000, 200_000] {
                sample = admitted_report_026(&mut controller, &sample, now, 1000);
                controller.observe(&sample);
            }
            assert_eq!(controller.last_control_us, 0);
            let now = if boundary == "expired" {
                FRESH_US
            } else {
                300_000
            };
            sample = admitted_report_026(&mut controller, &sample, now, 1000);
            match boundary {
                "idle" => sample.offered_backlog = false,
                "pressure" => {
                    sample.rtt_ms = 110.0;
                    sample.probe_rtt_ms = Some(110.0);
                    sample.probe_latest_rtt_ms = Some(110.0);
                }
                "legacy" => {
                    controller.fast_feedback_seen = false;
                    sample.delivery_sample_span_us = PROBE_US;
                }
                _ => {}
            }
            controller.observe(&sample);
            assert_eq!(controller.last_control_us, now, "{boundary}");
            assert_eq!(controller.admitted_bytes, 0, "{boundary}");
            assert_eq!(controller.allowance_bytes, 0.0, "{boundary}");
            assert!(controller.rate_bps <= START_BPS, "{boundary}");
        }
    }

    #[test]
    fn event_observation_036_keeps_controller_growth_and_pressure_time_gates() {
        use super::super::outbound::ObservationSchedule;

        let (mut controller, mut sample) = initial_credit_026(20_000_000);
        assert_eq!(sample.now_us, 200_000);
        assert_eq!(controller.last_growth_us, 200_000);
        let mut schedule = ObservationSchedule::default();
        for at in [0, 100_000, 200_000] {
            assert!(schedule.take_due(at).is_some());
        }
        let grown_at_200 = controller.rate_bps;
        sample = admitted_report_026(&mut controller, &sample, 300_000, u64::MAX);
        schedule.evidence_received();
        assert!(schedule.take_due(300_000).is_some());
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, grown_at_200);

        // Another path can wake this sender while this path's report remains
        // unchanged. Its real admissions continue, and report/probe ages advance.
        let admitted = exercise_budget(&mut controller, 300_000, 99_000);
        sample.admitted_symbols = Some(sample.admitted_symbols.unwrap() + admitted / 1000);
        sample.admitted_symbol_bytes = Some(sample.admitted_symbol_bytes.unwrap() + admitted);
        sample.now_us = 399_000;
        sample.feedback_age_us = Some(99_000);
        sample.positive_delivery_age_us = Some(99_000);
        sample.probe_age_us = Some(99_000);
        schedule.evidence_received();
        assert!(schedule.take_due(sample.now_us).is_some());
        controller.observe(&sample);
        assert_eq!(
            controller.rate_bps, grown_at_200,
            "199ms cannot authorize the next growth"
        );
        schedule.evidence_received();
        assert!(schedule.take_due(399_999).is_none());
        let admitted = exercise_budget(&mut controller, 399_000, 1000);
        sample.admitted_symbols = Some(sample.admitted_symbols.unwrap() + admitted / 1000);
        sample.admitted_symbol_bytes = Some(sample.admitted_symbol_bytes.unwrap() + admitted);
        sample.now_us = 400_000;
        sample.feedback_age_us = Some(100_000);
        sample.positive_delivery_age_us = Some(100_000);
        sample.probe_age_us = Some(100_000);
        assert!(schedule.take_due(sample.now_us).is_some());
        controller.observe(&sample);
        assert!(controller.rate_bps > grown_at_200);
        assert_eq!(controller.last_growth_us, 400_000);

        let before_pressure = controller.rate_bps;
        let pressure_probe = sample.probe_sample_id + 1;
        let mut previous_at = 400_000;
        for at in [401_000, 450_000, 500_000, 501_000] {
            let admitted = exercise_budget(&mut controller, previous_at, at - previous_at);
            sample.admitted_symbols = Some(sample.admitted_symbols.unwrap() + admitted / 1000);
            sample.admitted_symbol_bytes = Some(sample.admitted_symbol_bytes.unwrap() + admitted);
            sample.now_us = at;
            sample.feedback_age_us = Some(at - 300_000);
            sample.positive_delivery_age_us = Some(at - 300_000);
            sample.rtt_ms = 95.0;
            sample.probe_rtt_ms = Some(95.0);
            sample.probe_latest_rtt_ms = Some(95.0);
            sample.probe_sample_id = pressure_probe;
            sample.probe_age_us = Some(at - 401_000);
            schedule.evidence_received();
            assert!(schedule.take_due(at).is_some());
            controller.observe(&sample);
            assert_eq!(controller.queue_delay_ms, 15.0);
            if at < 501_000 {
                assert_eq!(
                    controller.rate_bps, before_pressure,
                    "less than100ms pressure must hold, not brake"
                );
                assert!(controller.last_brake_us.is_none());
            } else {
                assert!(controller.rate_bps < before_pressure);
                assert_eq!(controller.last_brake_us, Some(501_000));
                assert!(matches!(
                    controller.rate_changes.back().unwrap().reason,
                    RateReason::QueueBrake
                ));
            }
            previous_at = at;
        }
    }

    fn cautious_probe_028() -> (PathController, Observation) {
        let (mut controller, mut sample) = initial_credit_026(20_000_000);
        controller.congestion_seen = true;
        controller.remembered_bps = controller.rate_bps as f64;
        controller.probe_admitted(300_000);
        sample = admitted_report_026(&mut controller, &sample, 400_000, u64::MAX);
        // The request at300ms returned after80ms, before this observation.
        sample.probe_age_us = Some(20_000);
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 307_200);
        assert_eq!(controller.health, Health::Healthy);
        assert!(controller.service_window.latest(400_000).is_none());
        (controller, sample)
    }

    fn service_endpoint_032() -> (PathController, Observation) {
        let (mut controller, sample) = cautious_probe_028();
        controller.probe_admitted(400_000);
        let mut sample = admitted_report_026(&mut controller, &sample, 500_000, u64::MAX);
        sample.probe_age_us = Some(20_000);
        controller.observe(&sample);
        assert_eq!(
            controller
                .discovery_service_window(500_000)
                .unwrap()
                .observed_us,
            500_000
        );
        (controller, sample)
    }

    fn monitored_growth_034() -> (PathController, Observation) {
        let (mut controller, sample) = service_endpoint_032();
        let sample = admitted_report_026(&mut controller, &sample, 600_000, u64::MAX);
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 334_506);
        let monitor = controller.growth_monitor.as_ref().unwrap();
        assert_eq!(
            (monitor.previous_bps, monitor.pacing_bps),
            (307_200, 334_506)
        );
        assert_eq!(monitor.armed_us, 600_000);
        assert!(!controller.drain_restore_pending);
        (controller, sample)
    }

    #[test]
    fn monitored_growth_accounts_for_two_reply_feedback_horizon() {
        let (mut controller, previous) = service_endpoint_032();
        let sample = admitted_report_026(&mut controller, &previous, 600_000, u64::MAX);
        let baseline = controller.rate_bps;
        controller.observe(&sample);
        let grown = controller.rate_bps;
        assert!(grown > baseline);
        let armed = controller.growth_monitor.as_ref().unwrap().armed_us;
        let first_request = armed + 1;
        controller.probe_admitted(first_request);
        let mut first = monitor_reply_034(
            &mut controller,
            &sample,
            first_request + 80_000,
            80.0,
            first_request,
        );
        first.probe_sample_id = sample.probe_sample_id + 1;
        first.report_number = sample.report_number + 1;
        controller.observe(&first);
        assert!(
            controller
                .growth_monitor
                .as_ref()
                .unwrap()
                .first_reply
                .is_some()
        );
        assert!(
            controller
                .growth_monitor
                .as_ref()
                .unwrap()
                .second_reply
                .is_none()
        );
        let second_request = first_request + FAST_PROBE_US;
        controller.probe_admitted(second_request);
        let mut second = monitor_reply_034(
            &mut controller,
            &first,
            second_request + 80_000,
            80.0,
            second_request,
        );
        second.probe_sample_id = first.probe_sample_id + 1;
        second.report_number = first.report_number + 1;
        controller.observe(&second);
        assert!(controller.growth_monitor.is_none());
        assert_eq!(controller.rate_bps, grown);
        // A bottleneck serving the exercised baseline accumulates this extra
        // queue until the second real reply can settle the owned increment.
        let held_ms = (second.now_us - armed) as f64 / 1000.0;
        let added_queue_ms = (grown - baseline) as f64 / baseline as f64 * held_ms;
        assert!(
            added_queue_ms <= controller.target_ms * 0.8 + 0.001,
            "increment held for {held_ms}ms adds {added_queue_ms}ms of queue"
        );
    }

    #[test]
    fn clear_monitored_growth_uses_new_rolling_service_without_waiting_for_capacity_tick() {
        let (mut controller, sample) = monitored_growth_034();
        let grown = controller.rate_bps;
        controller.probe_admitted(601_000);
        let mut first = monitor_reply_034(&mut controller, &sample, 681_000, 80.0, 601_000);
        first.probe_sample_id = sample.probe_sample_id + 1;
        controller.observe(&first);
        controller.probe_admitted(701_000);
        let mut second = monitor_reply_034(&mut controller, &first, 781_000, 80.0, 701_000);
        second.probe_sample_id = first.probe_sample_id + 1;
        controller.observe(&second);
        assert!(controller.growth_monitor.is_none());
        let mut next = monitor_reply_034(&mut controller, &second, 800_000, 80.0, 701_000);
        next.probe_sample_id = second.probe_sample_id;
        controller.observe(&next);
        assert!(
            controller.rate_bps > grown,
            "new 500ms rolling delivery and two actual clear replies must not wait for the next disjoint capacity interval"
        );
        assert_eq!(controller.last_growth_us, 800_000);
        assert_eq!(
            controller
                .service_window
                .latest(800_000)
                .unwrap()
                .observed_us,
            500_000,
            "capacity memory retains its original disjoint interval"
        );
    }

    #[test]
    fn new_service_endpoint_cannot_replace_an_unsettled_growth_monitor() {
        let (mut controller, mut sample) = monitored_growth_034();
        let grown = controller.rate_bps;
        let original = controller.growth_monitor.clone().unwrap();
        let reply_id = sample.probe_sample_id;
        for now in [700_000, 800_000, 900_000] {
            sample = admitted_report_026(&mut controller, &sample, now, u64::MAX);
            sample.probe_sample_id = reply_id;
            sample.probe_age_us = Some(now - 600_000);
            controller.observe(&sample);
        }
        controller.probe_admitted(900_000);
        let mut first = monitor_reply_034(&mut controller, &sample, 1_000_000, 80.0, 900_000);
        first.probe_sample_id = reply_id + 1;
        controller.observe(&first);
        assert_eq!(
            controller.rate_bps, grown,
            "one clear reply cannot replace the increment still awaiting its second actual reply"
        );
        assert_eq!(
            controller.growth_monitor.as_ref().unwrap().armed_us,
            original.armed_us
        );
        assert!(
            controller
                .growth_monitor
                .as_ref()
                .unwrap()
                .first_reply
                .is_some()
        );
    }

    fn monitor_reply_034(
        controller: &mut PathController,
        previous: &Observation,
        now: u64,
        rtt_ms: f64,
        request_us: u64,
    ) -> Observation {
        let mut sample = admitted_report_026(controller, previous, now, u64::MAX);
        // This fixture uses the actual probe source, without a synthetic Quinn
        // RTT that could mask its queue in the selected minimum.
        sample.rtt_ms = 0.0;
        sample.probe_rtt_ms = Some(rtt_ms);
        sample.probe_latest_rtt_ms = Some(rtt_ms);
        sample.probe_age_us = Some(now - request_us - (rtt_ms * 1000.0).ceil() as u64);
        sample
    }

    fn first_monitored_reply_034(rtt_ms: f64) -> (PathController, Observation) {
        let (mut controller, sample) = monitored_growth_034();
        controller.probe_admitted(600_000);
        assert_eq!(
            controller
                .growth_monitor
                .as_ref()
                .unwrap()
                .successful_request_us,
            [None, None]
        );
        let mut held = admitted_report_026(&mut controller, &sample, 700_000, u64::MAX);
        held.probe_sample_id = sample.probe_sample_id;
        held.probe_age_us = Some(100_000);
        controller.observe(&held);
        controller.probe_admitted(700_000);
        let sample = monitor_reply_034(&mut controller, &held, 800_000, rtt_ms, 700_000);
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 334_506);
        let monitor = controller.growth_monitor.as_ref().unwrap();
        assert!(monitor.first_reply.is_some());
        assert!(monitor.second_reply.is_none());
        controller.probe_admitted(800_000);
        (controller, sample)
    }

    #[test]
    fn growth_monitor_034_withdraws_only_its_increment_after_original_brakes() {
        let (mut controller, sample) = first_monitored_reply_034(84.0);
        assert_eq!(
            controller.queue_delay_ms, 4.0,
            "first rise retains monitoring"
        );
        let remembered = controller.remembered_bps;
        let draining = controller.draining_bps;
        let count = controller.rate_changes_total;
        let sample = monitor_reply_034(&mut controller, &sample, 900_000, 86.0, 800_000);
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 307_200);
        assert_eq!(controller.rate_changes_total, count + 1);
        assert!(matches!(
            controller.rate_changes.back().unwrap().reason,
            RateReason::GrowthWithdrawalBrake
        ));
        assert_eq!(controller.last_brake_us, Some(900_000));
        assert_eq!(
            controller.last_brake_admitted_symbols,
            sample.admitted_symbols
        );
        assert_eq!(controller.growth_not_before_us, 900_000 + RETRY_GROWTH_US);
        assert_eq!(controller.last_growth_us, 600_000);
        assert_eq!(controller.remembered_bps, remembered);
        assert_eq!(controller.draining_bps, draining);
        assert!(!controller.drain_restore_pending);
        let evidence = controller.last_control.growth_monitor.as_ref().unwrap();
        assert!(evidence.withdrawn);
        assert_eq!(
            evidence.first_reply.as_ref().unwrap().inferred_request_us,
            700_000
        );
        assert_eq!(
            evidence.second_reply.as_ref().unwrap().inferred_request_us,
            800_000
        );
        assert!(controller.growth_monitor.is_none());
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 307_200);
        assert_eq!(controller.rate_changes_total, count + 1);
        assert!(controller.last_control.growth_monitor.is_none());
        controller.probe_admitted(900_000);
        let clear = monitor_reply_034(&mut controller, &sample, 1_000_000, 80.0, 900_000);
        controller.observe(&clear);
        assert_eq!(
            controller.rate_bps, 307_200,
            "cooldown prevents immediate re-increase"
        );

        let (mut controller, sample) = first_monitored_reply_034(95.0);
        let previous = controller.growth_monitor.as_ref().unwrap().previous_bps;
        let sample = monitor_reply_034(&mut controller, &sample, 900_000, 100.0, 800_000);
        controller.observe(&sample);
        assert!(
            controller.rate_bps < previous,
            "original queue brake may reduce further"
        );
        assert!(matches!(
            controller.rate_changes.back().unwrap().reason,
            RateReason::QueueBrake
        ));
        assert_eq!(controller.last_brake_us, Some(900_000));
        assert!(controller.growth_monitor.is_none());
        assert!(
            controller.last_control.growth_monitor.is_none(),
            "never undo the original brake"
        );
    }

    #[test]
    fn growth_withdrawal_retries_a_smaller_increment_at_the_same_rate() {
        let (mut controller, sample) = first_monitored_reply_034(84.0);
        let rejected_rate = controller.rate_bps;
        let sample = monitor_reply_034(&mut controller, &sample, 900_000, 86.0, 800_000);
        controller.observe(&sample);
        let baseline = controller.rate_bps;
        assert_eq!(baseline, 307_200);
        let mut sample = sample;
        for now in (1_000_000..=2_000_000).step_by(100_000) {
            controller.probe_admitted(now - 100_000);
            sample = monitor_reply_034(&mut controller, &sample, now, 80.0, now - 100_000);
            controller.observe(&sample);
            if controller.rate_bps > baseline {
                assert!(now >= 900_000 + RETRY_GROWTH_US);
                assert!(
                    controller.rate_bps < rejected_rate,
                    "a rejected increment must not be retried unchanged at the same baseline"
                );
                assert_eq!(
                    controller.rate_bps,
                    baseline + (rejected_rate - baseline) / 2
                );
                assert_eq!(
                    controller.growth_monitor.as_ref().unwrap().previous_bps,
                    baseline
                );
                assert_eq!(
                    controller.last_control.growth_retry_ceiling_bps,
                    Some(controller.rate_bps)
                );
                assert_eq!(
                    controller.growth_retry.as_ref().unwrap().baseline_bps,
                    controller.rate_bps
                );
                let retry = controller.rate_bps;
                for next in [now + 100_000, now + 200_000] {
                    controller.probe_admitted(next - 99_000);
                    sample = monitor_reply_034(&mut controller, &sample, next, 80.0, next - 99_000);
                    controller.observe(&sample);
                }
                assert!(
                    controller
                        .last_control
                        .growth_monitor
                        .as_ref()
                        .is_some_and(|monitor| monitor.armed_us == now
                            && monitor.second_reply.is_some()
                            && !monitor.withdrawn),
                    "two clear replies complete the owned retry before another gain"
                );
                for next in (now + 300_000..=now + 1_000_000).step_by(100_000) {
                    controller.probe_admitted(next - 100_000);
                    sample =
                        monitor_reply_034(&mut controller, &sample, next, 80.0, next - 100_000);
                    controller.observe(&sample);
                    if controller.rate_bps > retry {
                        assert!(controller.rate_bps <= retry + 2 * (retry - baseline));
                        return;
                    }
                }
                panic!("a successful retry must not leave a permanent growth ceiling");
            }
        }
        panic!("fresh service, actual admissions and clear probes must permit a bounded retry");
    }

    #[test]
    fn successful_smaller_retry_recovers_its_step_without_jumping_to_the_rejected_gain() {
        let (mut controller, sample) = first_monitored_reply_034(84.0);
        let mut sample = monitor_reply_034(&mut controller, &sample, 900_000, 86.0, 800_000);
        controller.observe(&sample);
        let baseline = controller.rate_bps;
        let mut retry_at = None;
        for now in (1_000_000..=2_000_000).step_by(100_000) {
            controller.probe_admitted(now - 100_000);
            sample = monitor_reply_034(&mut controller, &sample, now, 80.0, now - 100_000);
            controller.observe(&sample);
            if controller.rate_bps > baseline {
                retry_at = Some(now);
                break;
            }
        }
        let at = retry_at.expect("fresh service must authorize the smaller retry");
        let retry = controller.rate_bps;
        for now in [at + 100_000, at + 200_000] {
            controller.probe_admitted(now - 99_000);
            sample = monitor_reply_034(&mut controller, &sample, now, 80.0, now - 99_000);
            controller.observe(&sample);
        }
        assert!(
            controller
                .last_control
                .growth_monitor
                .as_ref()
                .is_some_and(|monitor| monitor.armed_us == at
                    && monitor.second_reply.is_some()
                    && !monitor.withdrawn)
        );
        if controller.rate_bps > retry {
            assert!(controller.rate_bps <= retry + 2 * (retry - baseline));
            assert!(controller.last_control.growth_retry_ceiling_bps.is_some());
            return;
        }
        for now in (at + 300_000..=at + 1_000_000).step_by(100_000) {
            controller.probe_admitted(now - 100_000);
            sample = monitor_reply_034(&mut controller, &sample, now, 80.0, now - 100_000);
            controller.observe(&sample);
            if controller.rate_bps > retry {
                assert!(
                    controller.rate_bps <= retry + 2 * (retry - baseline),
                    "two clear replies recover at most twice the confirmed increment"
                );
                assert!(controller.last_control.growth_retry_ceiling_bps.is_some());
                return;
            }
        }
        panic!("confirmation must permit step recovery, not permanently freeze growth");
    }

    #[test]
    fn another_retry_withdrawal_halves_only_the_new_failed_increment() {
        let (mut controller, sample) = first_monitored_reply_034(84.0);
        let mut sample = monitor_reply_034(&mut controller, &sample, 900_000, 86.0, 800_000);
        controller.observe(&sample);
        let baseline = controller.rate_bps;
        let mut retry_at = None;
        for now in (1_000_000..=2_000_000).step_by(100_000) {
            controller.probe_admitted(now - 100_000);
            sample = monitor_reply_034(&mut controller, &sample, now, 80.0, now - 100_000);
            controller.observe(&sample);
            if controller.rate_bps > baseline {
                retry_at = Some(now);
                break;
            }
        }
        let at = retry_at.unwrap();
        let increment = controller.rate_bps - baseline;
        for (now, rtt) in [(at + 100_000, 84.0), (at + 200_000, 86.0)] {
            controller.probe_admitted(now - 99_000);
            sample = monitor_reply_034(&mut controller, &sample, now, rtt, now - 99_000);
            controller.observe(&sample);
        }
        assert_eq!(
            controller.rate_bps, baseline,
            "withdraw only the owned retry"
        );
        for now in (at + 300_000..=at + 1_300_000).step_by(100_000) {
            controller.probe_admitted(now - 100_000);
            sample = monitor_reply_034(&mut controller, &sample, now, 80.0, now - 100_000);
            controller.observe(&sample);
            if controller.rate_bps > baseline {
                assert!(now >= at + 200_000 + RETRY_GROWTH_US);
                assert_eq!(controller.rate_bps, baseline + increment / 2);
                return;
            }
        }
        panic!("the smaller step must remain discoverable after cooldown");
    }

    #[test]
    fn growth_retry_does_not_survive_idle_stale_generation_or_other_pace_changes() {
        for boundary in [
            "idle",
            "stale",
            "gap",
            "regressed",
            "generation",
            "queue_brake",
        ] {
            let (mut controller, sample) = first_monitored_reply_034(84.0);
            let mut sample = monitor_reply_034(&mut controller, &sample, 900_000, 86.0, 800_000);
            controller.observe(&sample);
            assert!(controller.growth_retry.is_some());
            sample.now_us = 1_000_000;
            match boundary {
                "idle" => sample.offered_backlog = false,
                "stale" => {
                    sample.feedback_age_us = Some(FRESH_US + 1);
                    sample.positive_delivery_age_us = Some(FRESH_US + 1);
                    sample.probe_age_us = Some(FRESH_US + 1);
                }
                "gap" => sample.now_us += FRESH_US,
                "regressed" => sample.now_us = 899_999,
                "generation" => sample.generation += 1,
                "queue_brake" => {
                    sample.probe_sample_id += 1;
                    sample.probe_latest_rtt_ms = Some(110.0);
                    sample.probe_rtt_ms = Some(110.0);
                    sample.probe_age_us = Some(0);
                }
                _ => unreachable!(),
            }
            controller.observe(&sample);
            if boundary == "queue_brake" {
                sample.now_us += BRAKE_US;
                sample.probe_sample_id += 1;
                controller.observe(&sample);
            }
            assert!(controller.growth_retry.is_none(), "{boundary}");
            if boundary == "queue_brake" {
                assert!(controller.rate_bps < 307_200);
                assert!(matches!(
                    controller.rate_changes.back().unwrap().reason,
                    RateReason::QueueBrake
                ));
            }
        }
    }

    #[test]
    fn growth_monitor_034_keeps_small_rises_and_releases_completed_samples() {
        for (first, second) in [(80.2, 84.9), (85.5, 85.75), (86.0, 85.5)] {
            let (mut controller, sample) = first_monitored_reply_034(first);
            let count = controller.rate_changes_total;
            let sample = monitor_reply_034(&mut controller, &sample, 900_000, second, 800_000);
            controller.observe(&sample);
            assert_eq!(controller.rate_bps, 334_506, "{first} -> {second}");
            assert_eq!(controller.rate_changes_total, count);
            let evidence = controller.last_control.growth_monitor.as_ref().unwrap();
            assert!(evidence.second_reply.is_some());
            assert!(!evidence.withdrawn);
            assert!(controller.growth_monitor.is_none());
            controller.observe(&sample);
            assert!(controller.last_control.growth_monitor.is_none());
        }
    }

    #[test]
    fn growth_monitor_034_bounds_requests_and_actual_reply_evidence() {
        let (mut controller, sample) = monitored_growth_034();
        controller.probe_admitted(600_000);
        assert_eq!(
            controller
                .growth_monitor
                .as_ref()
                .unwrap()
                .successful_request_us,
            [None, None]
        );
        for _ in 0..2 {
            assert!(controller.decision(700_000).probe_due);
            assert_eq!(controller.last_probe_us, Some(600_000));
            assert_eq!(
                controller
                    .growth_monitor
                    .as_ref()
                    .unwrap()
                    .successful_request_us,
                [None, None]
            );
        }
        controller.probe_admitted(700_000);
        let mut spacing = controller.growth_monitor.clone().unwrap();
        spacing.probe_admitted(799_999);
        assert_eq!(spacing.successful_request_us, [Some(700_000), None]);
        spacing.probe_admitted(800_000);
        spacing.probe_admitted(900_000);
        assert_eq!(
            spacing.successful_request_us,
            [Some(700_000), Some(800_000)]
        );
        assert!(!controller.decision(799_999).probe_due);
        assert!(controller.decision(800_000).probe_due);
        controller.probe_admitted(800_000);
        for now in [900_000, 1_299_999] {
            assert!(
                !controller.decision(now).probe_due,
                "missing reply at {now}"
            );
        }
        assert!(
            controller.decision(1_300_000).probe_due,
            "health deadline is independent"
        );

        // Start from the monitor armed by a real increase. Component evidence
        // isolates authenticated visible reply ids from unrelated control ticks.
        let mut monitor = controller.growth_monitor.clone().unwrap();
        let mut reply = sample.clone();
        reply.now_us = 800_000;
        reply.probe_sample_id += 2;
        reply.probe_age_us = Some(16_000);
        assert!(monitor.observe(&reply, 84.0));
        assert_eq!(
            monitor.first_reply.as_ref().unwrap().sample_id,
            reply.probe_sample_id
        );
        assert!(
            monitor.second_reply.is_none(),
            "a skipped id is only one visible reply"
        );
        assert!(monitor.observe(&reply, 84.0));
        assert!(monitor.second_reply.is_none(), "duplicate id");
        reply.now_us = 900_000;
        reply.probe_sample_id += 1;
        reply.probe_age_us = Some(116_000);
        assert!(monitor.observe(&reply, 84.0));
        assert!(
            monitor.second_reply.is_none(),
            "same inferred request origin"
        );
        reply.now_us = 1_000_000;
        reply.probe_sample_id += 1;
        reply.probe_age_us = Some(114_000);
        assert!(monitor.observe(&reply, 86.0));
        let first = monitor.first_reply.as_ref().unwrap();
        assert!(first.age_us + reply.now_us - first.observed_us > CONTROL_US);
        assert_eq!(first.inferred_request_us, 700_000);
        assert_eq!(
            monitor.second_reply.as_ref().unwrap().inferred_request_us,
            800_000
        );

        let mut unrenewed = controller.growth_monitor.clone().unwrap();
        let mut held = sample;
        held.now_us = unrenewed.armed_us + FRESH_US;
        assert!(unrenewed.observe(&held, 80.0));
        held.now_us += 1;
        assert!(
            !unrenewed.observe(&held, 80.0),
            "observation cannot renew the fixed lifetime"
        );
    }

    #[test]
    fn growth_monitor_034_releases_lifecycle_without_blocking_growth() {
        for invalid in ["idle", "probe", "clock", "gap", "generation"] {
            let (mut controller, mut sample) = monitored_growth_034();
            match invalid {
                "idle" => sample.offered_backlog = false,
                "probe" => sample.probe_age_us = Some(FRESH_US + 1),
                "clock" => sample.now_us -= 1,
                "gap" => sample.now_us += FRESH_US + 1,
                "generation" => sample.generation += 1,
                _ => unreachable!(),
            }
            controller.observe(&sample);
            assert!(controller.growth_monitor.is_none(), "{invalid}");
            assert!(
                controller.last_control.growth_monitor.is_none(),
                "{invalid}"
            );
        }
        let (mut controller, _) = monitored_growth_034();
        let before = controller.rate_bps;
        controller.record_rate_change(700_000, before, RateReason::CautiousGrowth);
        assert_eq!(
            controller.growth_monitor.as_ref().unwrap().armed_us,
            600_000,
            "no-op does not renew"
        );
        controller.rate_bps -= 1;
        controller.record_rate_change(700_000, before, RateReason::ReprobeRollback);
        assert!(
            controller.growth_monitor.is_none(),
            "any actual recorded pace change releases ownership"
        );

        let (mut controller, mut sample) = monitored_growth_034();
        let reply_id = sample.probe_sample_id;
        for now in [700_000, 800_000, 900_000] {
            sample = admitted_report_026(&mut controller, &sample, now, u64::MAX);
            sample.probe_sample_id = reply_id;
            sample.probe_age_us = Some(now - 600_000);
            controller.observe(&sample);
        }
        controller.probe_admitted(900_000);
        sample = monitor_reply_034(&mut controller, &sample, 1_000_000, 80.0, 900_000);
        controller.observe(&sample);
        assert_eq!(
            controller.rate_bps, 334_506,
            "a new service endpoint cannot replace the owned monitor after one reply"
        );
        let evidence = controller.last_control.growth_monitor.as_ref().unwrap();
        assert_eq!(evidence.armed_us, 600_000);
        assert!(evidence.first_reply.is_some());
        assert!(evidence.second_reply.is_none());
        let current = controller.growth_monitor.as_ref().unwrap();
        assert_eq!(current.armed_us, 600_000);
        controller.probe_admitted(1_100_000);
        sample = monitor_reply_034(&mut controller, &sample, 1_200_000, 80.0, 1_100_000);
        controller.observe(&sample);
        assert!(controller.rate_bps > 334_506);
        assert_eq!(controller.last_growth_us, 1_200_000);
        assert!(
            controller
                .last_control
                .growth_monitor
                .as_ref()
                .unwrap()
                .second_reply
                .is_some()
        );

        let (mut controller, sample) = initial_credit_026(20_000_000);
        let next = admitted_report_026(&mut controller, &sample, 400_000, u64::MAX);
        controller.observe(&next);
        assert_eq!(controller.rate_bps, 368_640);
        assert!(
            controller.growth_monitor.is_none(),
            "initial search is unchanged"
        );

        let mut controller = PathController::new(20_000_000, 20);
        controller.observe(&observation(0, 80.0));
        controller.rate_bps = 500_000;
        controller.remembered_bps = 4_000_000.0;
        controller.congestion_seen = true;
        exercise_budget(&mut controller, 0, CONTROL_US);
        controller.observe(&observation(CONTROL_US, 80.0));
        assert_eq!(controller.rate_bps, 625_000);
        assert!(
            controller.growth_monitor.is_none(),
            "legacy growth is unchanged"
        );

        let (mut controller, sample) = draining_service_029(0, 1_000_000);
        controller.observe(&sample);
        assert_eq!(
            controller.last_control.drain_service_target_bps,
            Some(controller.rate_bps)
        );
        assert!(
            controller.growth_monitor.is_none(),
            "independent measured restoration is not armed"
        );
    }

    #[test]
    fn service_clock_032_requests_once_per_endpoint_with_bounded_old_reply() {
        let (controller, _) = cautious_probe_028();
        assert!(!controller.decision(500_000).probe_due, "no endpoint");
        assert!(controller.decision(800_000).probe_due, "health deadline");

        for age in [100_000, CONTROL_US + 1, FRESH_US, FRESH_US + 1] {
            let (mut controller, _) = service_endpoint_032();
            // A quiet pending restoration also obtains its replacement from
            // this endpoint, without an independent 100ms polling stream.
            controller.drain_restore_pending = age == CONTROL_US + 1;
            // Isolate the existing response-age boundary at the query time.
            // The new service still comes from the real admitted-byte fixture.
            controller.last_control.probe_age_us = Some(age - 100_000);
            assert!(!controller.decision(599_999).probe_due);
            assert_eq!(controller.decision(600_000).probe_due, age <= FRESH_US);
            if age <= FRESH_US {
                let rate = controller.rate_bps;
                for _ in 0..2 {
                    assert!(controller.decision(600_000).probe_due);
                    assert_eq!(controller.last_probe_us, Some(400_000));
                    assert_eq!(controller.rate_bps, rate);
                }
                controller.probe_admitted(600_000);
                for now in [700_000, 800_000, 1_099_999] {
                    assert!(
                        !controller.decision(now).probe_due,
                        "same endpoint at {now}"
                    );
                }
                assert!(controller.decision(1_100_000).probe_due);
            } else {
                assert!(controller.decision(900_000).probe_due);
            }
        }
    }

    #[test]
    fn service_clock_032_growth_spends_endpoint_and_still_requires_young_probe() {
        for hint in [false, true] {
            let (mut controller, mut sample) = service_endpoint_032();
            controller.remembered_bps = 4_000_000.0;
            if hint {
                controller.draining_bps = Some((2_000_000.0, sample.now_us));
                controller.drain_restore_pending = true;
            }
            let before = controller.rate_bps;
            sample = admitted_report_026(&mut controller, &sample, 600_000, u64::MAX);
            sample.rtt_ms = 88.0;
            sample.probe_rtt_ms = Some(88.0);
            sample.probe_latest_rtt_ms = Some(88.0);
            controller.observe(&sample);
            let first = controller.rate_bps;
            assert_eq!(first, (before as f64 * (1.0 + 8.0 / 188.0)) as u64);
            assert_eq!(controller.last_growth_us, 600_000);
            assert!(matches!(
                controller.rate_changes.back().unwrap().reason,
                RateReason::KnownServiceRecovery
            ));
            assert!(!controller.drain_restore_pending);

            if hint {
                controller.drain_restore_pending = true;
            }
            for now in [800_000, 1_000_000] {
                controller.probe_admitted(now - 100_000);
                sample = monitor_reply_034(&mut controller, &sample, now, 88.0, now - 100_000);
                controller.observe(&sample);
                if now == 800_000 {
                    assert_eq!(controller.rate_bps, first, "endpoint already consumed");
                    assert_eq!(controller.last_growth_us, 600_000);
                    assert_eq!(controller.drain_restore_pending, hint);
                } else {
                    assert!(controller.rate_bps > first, "new completed interval");
                    assert_eq!(controller.last_growth_us, now);
                    assert!(!controller.drain_restore_pending);
                }
            }
        }

        let (mut controller, sample) = service_endpoint_032();
        controller.remembered_bps = 4_000_000.0;
        let before = controller.rate_bps;
        let mut next = admitted_report_026(&mut controller, &sample, 600_000, u64::MAX);
        next.probe_age_us = Some(CONTROL_US + 1);
        controller.observe(&next);
        assert_eq!(
            controller.rate_bps, before,
            "old reply cannot approve growth"
        );
        assert!(
            controller.decision(600_000).probe_due,
            "it can request new evidence"
        );
        // A new probe alone cannot refresh the receiver endpoint.
        exercise_budget(&mut controller, 600_000, 200_001);
        next.now_us = 800_001;
        next.probe_sample_id += 1;
        next.probe_age_us = Some(0);
        controller.observe(&next);
        assert_eq!(
            controller.rate_bps, before,
            "young reply cannot renew old service"
        );
    }

    #[test]
    fn service_clock_032_preserves_initial_legacy_safety_and_measured_drain() {
        let (mut controller, sample) = initial_credit_026(20_000_000);
        let next = admitted_report_026(&mut controller, &sample, 400_000, u64::MAX);
        controller.observe(&next);
        assert_eq!(controller.rate_bps, 368_640);
        assert!(controller.service_window.latest(400_000).is_none());
        controller.congestion_seen = true;
        controller.probe_admitted(400_000);
        assert!(
            controller.decision(700_000).probe_due,
            "independent phase repair"
        );

        let (mut controller, _) = cautious_probe_028();
        assert!(!controller.decision(400_000).probe_due);
        controller.queue_delay_ms = 6.0;
        assert!(
            controller.decision(400_000).probe_due,
            "pressure remains fast"
        );

        let mut controller = PathController::new(20_000_000, 20);
        controller.observe(&observation(0, 80.0));
        controller.rate_bps = 500_000;
        controller.remembered_bps = 4_000_000.0;
        controller.congestion_seen = true;
        exercise_budget(&mut controller, 0, CONTROL_US);
        controller.observe(&observation(CONTROL_US, 80.0));
        assert!(!controller.fast_feedback_seen);
        assert!(controller.service_window.latest(CONTROL_US).is_none());
        assert_eq!(controller.rate_bps, 625_000);

        let (mut controller, sample) = draining_service_029(0, 1_000_000);
        let before = controller.rate_bps;
        let latest = controller.service_window.latest(sample.now_us).unwrap();
        let target = (latest.bps * controller.wire_per_symbol * 0.9) as u64;
        controller.observe(&sample);
        assert!(target > (before as f64 * 1.2) as u64);
        assert_eq!(controller.rate_bps, target);
        assert_eq!(
            controller.last_control.drain_service_target_bps,
            Some(target)
        );
        assert!(!controller.drain_restore_pending);
        let mut repeated = sample.clone();
        repeated.now_us += 100_000;
        repeated.probe_age_us = Some(120_000);
        controller.observe(&repeated);
        assert_eq!(controller.rate_bps, target);
        assert_eq!(controller.last_control.drain_service_target_bps, None);
    }

    #[test]
    fn growth_monitor_030_follows_actual_changes_and_expires() {
        let (mut controller, _) = initial_credit_026(20_000_000);
        controller.congestion_seen = true;
        controller.remembered_bps = controller.rate_bps as f64;
        let change = controller.rate_changes.back().unwrap();
        assert_eq!(change.at_us, 200_000);
        assert!(change.pacing_bps > change.previous_bps);
        // Supply the preceding successful request to the existing real-growth
        // fixture. A request on the growth tick is only a safety observation.
        controller.probe_admitted(100_000);
        assert!(!controller.decision(199_999).probe_due);
        assert!(!controller.decision(200_000).probe_due);
        controller.probe_admitted(200_000);
        assert!(!controller.decision(299_999).probe_due);
        assert!(controller.decision(300_000).probe_due);
        controller.probe_admitted(300_000);
        assert!(!controller.decision(400_000).probe_due);

        // Cautious no-ops can advance last_growth_us, but must neither append
        // a real rate change nor renew its strictly shorter-than-200ms window.
        let count = controller.rate_changes_total;
        controller.last_growth_us = 400_000;
        controller.record_rate_change(400_000, controller.rate_bps, RateReason::CautiousGrowth);
        assert_eq!(controller.rate_changes_total, count);
        assert_eq!(controller.rate_changes.back().unwrap().at_us, 200_000);
        assert!(!controller.decision(400_000).probe_due);

        for reason in [RateReason::QueueBrake, RateReason::ReprobeRollback] {
            let (mut controller, _) = initial_credit_026(20_000_000);
            controller.congestion_seen = true;
            controller.remembered_bps = controller.rate_bps as f64;
            controller.probe_admitted(250_000);
            assert!(!controller.decision(350_000).probe_due);
            let previous = controller.rate_bps;
            controller.rate_bps -= 1;
            controller.record_rate_change(300_000, previous, reason);
            assert!(!controller.decision(350_000).probe_due);
        }

        let (mut controller, _) = initial_credit_026(20_000_000);
        controller.congestion_seen = true;
        controller.remembered_bps = controller.rate_bps as f64;
        controller.probe_admitted(240_000);
        let previous = controller.rate_bps;
        controller.rate_bps += 1;
        controller.record_rate_change(350_000, previous, RateReason::CautiousGrowth);
        assert!(!controller.decision(340_000).probe_due, "future change");
        assert!(!controller.decision(350_000).probe_due);
        controller.last_control.offered_backlog = false;
        assert!(!controller.decision(350_000).probe_due, "idle");
        controller.last_control.offered_backlog = true;
        assert!(!controller.probe_request_due(350_000, true), "stale path");
        controller.last_control.probe_age_us = Some(CONTROL_US);
        assert!(!controller.decision(350_000).probe_due, "old reply");
    }

    #[test]
    fn growth_monitor_030_preserves_probe_credit_and_phase_repair() {
        for post_growth in [false, true] {
            let (mut controller, sample) = initial_credit_026(20_000_000);
            controller.congestion_seen = true;
            controller.remembered_bps = controller.rate_bps as f64 * 2.0;
            controller.probe_admitted(100_000);
            assert!(!controller.decision(200_000).probe_due);
            controller.probe_admitted(200_000);
            let previous = controller.rate_bps;
            let used = controller.last_growth_probe;
            for _ in 0..2 {
                assert!(controller.decision(300_000).probe_due);
                assert_eq!(controller.last_probe_us, Some(200_000));
                assert_eq!(controller.last_growth_probe, used);
                assert_eq!(controller.rate_bps, previous);
            }
            // A rejected request leaves the opportunity intact. A successful
            // repair gives a distinct, strictly post-growth request origin.
            if post_growth {
                controller.probe_admitted(300_000);
            }
            let mut next = admitted_report_026(&mut controller, &sample, 400_000, u64::MAX);
            next.probe_age_us = Some(if post_growth { 20_000 } else { 120_000 });
            controller.observe(&next);
            // 032 also needs a completed service interval before cautious growth.
            assert_eq!(controller.rate_bps, 307_200);
            assert_eq!(controller.last_growth_us, 200_000);
            assert_eq!(controller.last_growth_probe, used);
            if post_growth {
                let reply = next.probe_sample_id;
                next = admitted_report_026(&mut controller, &next, 500_000, u64::MAX);
                next.probe_sample_id = reply;
                next.probe_age_us = Some(120_000);
                controller.observe(&next);
                assert!(controller.discovery_service_window(500_000).is_some());
                controller.probe_admitted(500_000);
                next = admitted_report_026(&mut controller, &next, 600_000, u64::MAX);
                next.probe_age_us = Some(20_000);
                controller.observe(&next);
                assert_eq!(controller.rate_bps, 334_506);
                assert_eq!(controller.last_growth_us, 600_000);
                assert_eq!(controller.last_growth_probe, Some(next.probe_sample_id));
            }
        }

        let (mut controller, sample) = initial_credit_026(20_000_000);
        controller.congestion_seen = true;
        controller.remembered_bps = controller.rate_bps as f64;
        controller.probe_admitted(200_000);
        assert!(controller.decision(300_000).probe_due);
        controller.probe_admitted(300_000);
        for now in [400_000, 500_000, 799_999] {
            assert!(!controller.decision(now).probe_due, "no reply at {now}");
        }
        assert!(controller.decision(800_000).probe_due);

        let mut next = short_observation_022(900_000, 80.0);
        next.generation = sample.generation + 1;
        next.report_number = 1;
        next.delivered_bytes = 0;
        next.delivered_bps = Some(0.0);
        next.admitted_symbols = Some(0);
        next.admitted_symbol_bytes = Some(0);
        next.probe_rtt_ms = None;
        next.probe_latest_rtt_ms = None;
        next.probe_sample_id = 0;
        next.probe_age_us = None;
        controller.observe(&next);
        assert!(controller.rate_changes.is_empty());
        assert!(controller.last_probe_us.is_none());
        assert_eq!(controller.rate_bps, START_BPS);
        assert!(controller.decision(900_000).probe_due);
    }

    #[test]
    fn probe_cadence_028_keeps_young_control_and_fast_opportunities() {
        let (controller, _) = cautious_probe_028();
        assert!(!controller.decision(399_999).probe_due);
        assert!(!controller.decision(400_000).probe_due);
        assert!(!controller.decision(499_999).probe_due);
        assert!(!controller.decision(500_000).probe_due);
        assert!(controller.decision(800_000).probe_due);

        for opportunity in ["initial", "queue", "health", "blocked", "drain", "known"] {
            let (mut controller, _) = cautious_probe_028();
            match opportunity {
                "initial" => controller.congestion_seen = false,
                "queue" => controller.queue_delay_ms = 6.0,
                "health" => controller.health = Health::Degraded,
                "blocked" => controller.last_control.transport_blocked = true,
                "drain" => controller.drain_restore_pending = true,
                "known" => controller.remembered_bps *= 2.0,
                _ => unreachable!(),
            }
            assert!(!controller.decision(399_999).probe_due, "{opportunity}");
            assert_eq!(
                controller.decision(400_000).probe_due,
                !matches!(opportunity, "known" | "drain"),
                "{opportunity}"
            );
            if matches!(opportunity, "known" | "drain") {
                assert!(!controller.decision(499_999).probe_due);
                assert!(!controller.decision(500_000).probe_due);
                assert!(controller.decision(800_000).probe_due);
            }
        }

        let (mut controller, _) = cautious_probe_028();
        controller.service_window = service::Window::default();
        assert!(
            !controller
                .service_window
                .observe(1, Some(100_000_000), 0, 0, None)
        );
        assert!(
            controller
                .service_window
                .observe(2, Some(100_500_000), 20_000, 500_000, None,)
        );
        controller.last_control.at_us = 500_000;
        controller.last_control.probe_age_us = Some(20_000);
        controller.probe_admitted(400_000);
        assert!(controller.discovery_service_window(500_000).is_some());
        assert!(!controller.decision(500_000).probe_due);
        assert!(!controller.decision(599_999).probe_due);
        assert!(controller.decision(600_000).probe_due);

        let (mut controller, started, _) = granted_reprobe();
        assert!(controller.reprobe.active());
        controller.fast_feedback_seen = true;
        controller.congestion_seen = true;
        controller.health = Health::Healthy;
        controller.queue_delay_ms = 0.0;
        controller.drain_restore_pending = false;
        controller.remembered_bps = controller.rate_bps as f64;
        controller.service_window = service::Window::default();
        controller.last_growth_us = 0;
        controller.last_control.at_us = started;
        controller.last_control.offered_backlog = true;
        controller.last_control.transport_blocked = false;
        controller.last_control.probe_rtt_ms = Some(80.0);
        controller.last_control.probe_age_us = Some(0);
        controller.probe_admitted(started);
        assert!(controller.decision(started + FAST_PROBE_US).probe_due);

        for unavailable in ["legacy", "idle", "excluded", "rtt", "age"] {
            let (mut controller, _) = cautious_probe_028();
            match unavailable {
                "legacy" => controller.fast_feedback_seen = false,
                "idle" => controller.last_control.offered_backlog = false,
                "excluded" => controller.eligible = false,
                "rtt" => controller.last_control.probe_rtt_ms = Some(200.001),
                "age" => controller.last_control.probe_age_us = None,
                _ => unreachable!(),
            }
            assert!(!controller.decision(500_000).probe_due, "{unavailable}");
            assert!(controller.decision(800_000).probe_due, "{unavailable}");
        }
    }

    #[test]
    fn probe_cadence_028_new_service_cannot_cancel_an_owed_phase_repair() {
        let (mut controller, mut sample) = initial_credit_026(20_000_000);
        controller.congestion_seen = true;
        controller.remembered_bps = controller.rate_bps as f64;
        controller.probe_admitted(200_000);
        let used_probe = sample.probe_sample_id;
        // Actual admissions and positive byte reports continue, but no new
        // probe reply arrives. The completed500ms service interval is real.
        for now in [300_000, 400_000, 500_000] {
            sample = admitted_report_026(&mut controller, &sample, now, u64::MAX);
            sample.probe_sample_id = used_probe;
            sample.probe_age_us = Some(now - 200_000);
            controller.observe(&sample);
        }
        assert_eq!(controller.last_growth_us, 200_000);
        assert_eq!(controller.rate_bps, 307_200);
        let service = controller.discovery_service_window(500_000).unwrap();
        assert_eq!(service.observed_us, 500_000);
        assert!(service.bps >= controller.rate_bps as f64 * 0.85);
        assert_eq!(controller.last_control.probe_age_us, Some(300_000));
        assert!(controller.decision(500_000).probe_due);
        // A regressed query cannot use the newer observation for this repair.
        assert!(!controller.decision(499_999).probe_due);
        controller.service_window = service::Window::default();
        assert!(controller.decision(500_000).probe_due);
        controller.last_control.probe_age_us = Some(FRESH_US + 1);
        assert!(!controller.decision(500_000).probe_due);
        assert!(controller.decision(700_000).probe_due);
    }

    #[test]
    fn probe_cadence_028_repairs_equal_tick_once_after_successful_admission() {
        let (mut controller, _) = initial_credit_026(20_000_000);
        controller.congestion_seen = true;
        controller.remembered_bps = controller.rate_bps as f64;
        assert_eq!(controller.last_growth_us, 200_000);
        controller.probe_admitted(200_000);
        assert!(!controller.decision(200_000).probe_due);
        assert!(!controller.decision(299_999).probe_due);
        let rate = controller.rate_bps;
        let used = controller.last_growth_probe;
        // Budget/transport rejection does not call probe_admitted. Querying
        // repeatedly therefore leaves the still-owed request unconsumed.
        for _ in 0..2 {
            assert!(controller.decision(300_000).probe_due);
            assert_eq!(controller.last_probe_us, Some(200_000));
        }
        controller.probe_admitted(300_000);
        assert_eq!(controller.rate_bps, rate);
        assert_eq!(controller.last_growth_probe, used);
        for now in [300_000, 399_999, 400_000, 500_000, 700_000, 799_999] {
            assert!(!controller.decision(now).probe_due, "{now}");
        }
        // No reply returned: the old response ages normally and cannot
        // create an endless200ms retry stream after the single repair.
        assert_eq!(controller.last_control.probe_age_us, Some(0));
        assert_eq!(controller.last_control.at_us, 200_000);
        assert!(controller.decision(800_000).probe_due);
    }

    #[test]
    fn probe_cadence_028_preserves_reply_credit_and_generation_reset() {
        for reply in ["used", "old", "same_tick", "fresh"] {
            let (mut controller, sample) = initial_credit_026(20_000_000);
            let previous_probe = sample.probe_sample_id;
            controller.probe_admitted(300_000);
            let mut next = admitted_report_026(&mut controller, &sample, 400_000, u64::MAX);
            match reply {
                "used" => next.probe_sample_id = previous_probe,
                "old" => next.probe_age_us = Some(CONTROL_US + 1),
                // At400ms,80ms RTT plus120ms age puts the request exactly
                // at the prior200ms increase; strict post-growth still fails.
                "same_tick" => next.probe_age_us = Some(120_000),
                "fresh" => {}
                _ => unreachable!(),
            }
            controller.observe(&next);
            assert_eq!(
                controller.rate_bps,
                if reply == "fresh" { 368_640 } else { 307_200 },
                "{reply}",
            );
        }

        let (mut controller, sample) = cautious_probe_028();
        controller.probe_admitted(500_000);
        let mut next = short_observation_022(600_000, 80.0);
        next.generation = sample.generation + 1;
        next.report_number = 1;
        next.delivered_bytes = 0;
        next.delivered_bps = Some(0.0);
        next.admitted_symbols = Some(0);
        next.admitted_symbol_bytes = Some(0);
        next.probe_rtt_ms = None;
        next.probe_latest_rtt_ms = None;
        next.probe_sample_id = 0;
        next.probe_age_us = None;
        controller.observe(&next);
        assert_eq!(controller.rate_bps, START_BPS);
        assert!(!controller.congestion_seen);
        assert!(controller.last_probe_us.is_none());
        assert!(controller.last_growth_probe.is_none());
        assert!(controller.decision(600_000).probe_due);
    }

    // One admitted-byte sequence supplies all restoration tests. A receiver
    // initially withholds every tenth symbol, then drains those real bytes
    // after a severe probe has actually reduced the established allowance.
    fn draining_service_029(start_us: u64, start_bps: u64) -> (PathController, Observation) {
        let mut controller = PathController::new(start_bps * 4, 20);
        let mut quality = crate::runtime::quality::State::new(7);
        let mut sample = short_observation_022(start_us, 80.0);
        sample.report_number = 1;
        sample.probe_sample_id = 1;
        sample.delivered_bytes = 0;
        sample.delivered_bps = Some(0.0);
        sample.admitted_symbol_bytes = Some(0);
        controller.observe(&sample);
        controller.rate_bps = start_bps;
        controller.tokens = 0.0;
        controller.last_growth_probe = Some(1);
        let mut received = 0;
        let mut extra_drain = 0;
        for step in 1..=16 {
            let now = start_us + step * 100_000;
            if step == 16 {
                controller.probe_admitted(now - 100_000);
            }
            let before = quality.snapshot.sent_bytes;
            for at in (now - 100_000..now).step_by(1000) {
                while controller.allow(at, 500, 0.0) {
                    controller.admitted_symbol(at, 500, 500);
                    quality.admitted(500);
                }
            }
            let admitted = quality.snapshot.sent_bytes - before;
            let previous_received = received;
            received = if step <= 5 {
                (quality.snapshot.sent_symbols - quality.snapshot.sent_symbols / 10) * 500
            } else if step == 6 {
                received + admitted / 5 / 500 * 500
            } else if (11..=15).contains(&step) {
                received + admitted + extra_drain
            } else {
                received + admitted
            };
            assert!(received <= quality.snapshot.sent_bytes);
            if step == 6 {
                extra_drain = (quality.snapshot.sent_bytes - received) / 6 / 500 * 500;
            }
            sample = short_observation_022(now, if step < 6 || step == 16 { 80.0 } else { 280.0 });
            sample.report_number = step + 1;
            sample.rtt_ms = 0.0;
            sample.probe_sample_id = if step < 6 {
                1
            } else if step == 16 {
                3
            } else {
                2
            };
            sample.probe_age_us = Some(if step < 6 {
                now - start_us
            } else if step == 16 {
                20_000
            } else {
                now - start_us - 600_000
            });
            sample.delivered_bytes = received;
            sample.delivered_bps = Some((received - previous_received) as f64 * 80.0);
            sample.admitted_symbols = Some(quality.snapshot.sent_symbols);
            sample.admitted_symbol_bytes = Some(quality.snapshot.sent_bytes);
            if step == 16 {
                let latest = controller.service_window.latest(now).unwrap();
                let admitted = latest.admission.unwrap();
                assert_eq!(latest.observed_us, start_us + 1_500_000);
                assert_eq!(admitted.started_us, start_us + 1_000_000);
                assert!(admitted.symbols >= 8);
                assert!(latest.bps > admitted.bps * 1.1);
                assert!(controller.drain_restore_pending);
                return (controller, sample);
            }
            controller.observe(&sample);
            if step >= 6 {
                assert_eq!(controller.last_brake_us, Some(start_us + 600_000));
                assert!(controller.congestion_seen);
            }
            if step == 6 {
                assert!(controller.rate_bps < start_bps);
                assert!(matches!(
                    controller.rate_changes.back().unwrap().reason,
                    RateReason::QueueBrake
                ));
            }
        }
        unreachable!()
    }

    #[test]
    fn probe_cadence_029_recovery_keeps_phase_and_control_cadence() {
        let (mut controller, sample) = cautious_probe_028();
        controller.probe_admitted(400_000);
        let mut next = admitted_report_026(&mut controller, &sample, 500_000, u64::MAX);
        next.probe_age_us = Some(20_000);
        controller.observe(&next);
        assert!(controller.discovery_service_window(500_000).is_some());
        controller.remembered_bps = controller.rate_bps as f64 * 2.0;
        assert!(!controller.decision(500_000).probe_due);
        assert!(!controller.decision(599_999).probe_due);
        assert!(controller.decision(600_000).probe_due);
        let before = controller.rate_bps;
        next = admitted_report_026(&mut controller, &next, 600_000, u64::MAX);
        controller.observe(&next);
        assert!(controller.rate_bps > before);
        assert_eq!(controller.last_growth_us, 600_000);
        controller.probe_admitted(600_000);
        assert!(!controller.decision(699_999).probe_due);
        assert!(controller.decision(700_000).probe_due);
        assert!(
            controller.decision(700_000).probe_due,
            "rejected request keeps its opportunity"
        );
        controller.probe_admitted(700_000);
        for (now, due) in [(800_000, true), (900_000, false), (1_199_999, false)] {
            assert_eq!(
                controller.decision(now).probe_due,
                due,
                "missing reply at {now}"
            );
        }
        assert!(controller.decision(1_200_000).probe_due);
    }

    #[test]
    fn drain_service_029_restores_latest_post_brake_service_once() {
        for cap in ["latest", "maximum", "no_increase"] {
            let (mut controller, sample) = draining_service_029(0, 1_000_000);
            let latest = controller.service_window.latest(sample.now_us).unwrap();
            let before = controller.rate_bps;
            let measured = (latest.bps * controller.wire_per_symbol * 0.9) as u64;
            assert!(measured > (before as f64 * 1.2) as u64);
            // Neither this older high hint nor memory may replace latest D.
            controller.draining_bps = Some((3_000_000.0, sample.now_us - 200_000));
            controller.remembered_bps = 4_000_000.0;
            if cap == "maximum" {
                controller.maximum_bps = (before + measured) / 2;
            } else if cap == "no_increase" {
                controller.maximum_bps = before;
            }
            let target = measured.min(controller.maximum_bps);
            let changes = controller.rate_changes_total;
            controller.observe(&sample);
            assert_eq!(controller.rate_bps, target, "{cap}");
            assert_eq!(
                controller.last_control.drain_service_target_bps,
                (target > before).then_some(target),
                "{cap}"
            );
            assert!(!controller.drain_restore_pending);
            assert_eq!(
                controller.rate_changes_total,
                changes + u64::from(target > before)
            );
            if target > before {
                assert_eq!(controller.last_growth_probe, Some(sample.probe_sample_id));
                assert_eq!(controller.last_growth_us, sample.now_us);
                assert!(matches!(
                    controller.rate_changes.back().unwrap().reason,
                    RateReason::KnownServiceRecovery
                ));
                assert_eq!(
                    controller
                        .rate_changes
                        .back()
                        .unwrap()
                        .control
                        .drain_service_target_bps,
                    Some(target)
                );
            }
            let mut repeated = sample.clone();
            repeated.now_us += 100_000;
            repeated.probe_age_us = Some(120_000);
            controller.observe(&repeated);
            assert_eq!(controller.rate_bps, target);
            assert_eq!(controller.last_control.drain_service_target_bps, None);
            assert!(
                serde_json::to_value(&controller.last_control)
                    .unwrap()
                    .get("drain_service_target_bps")
                    .is_none()
            );
        }
    }

    #[test]
    fn drain_service_029_rejects_unqualified_service_windows() {
        for invalid in [
            "old",
            "missing",
            "regressed",
            "sparse",
            "local_span",
            "receiver_span",
            "not_draining",
            "before_brake",
            "pace_change",
        ] {
            let (mut controller, mut sample) = draining_service_029(0, 1_000_000);
            let latest = controller.service_window.latest(sample.now_us).unwrap();
            let admission = latest.admission.unwrap();
            let mut observed = latest.observed_us;
            let mut local_span = admission.span_us;
            let mut receiver_span = latest.span_us;
            let mut symbols = admission.symbols;
            let mut delivered = (latest.bps * latest.span_us as f64 / 8_000_000.0).round() as u64;
            match invalid {
                "old" => observed = sample.now_us - CONTROL_US - 1,
                "sparse" => symbols = 7,
                "local_span" => local_span = PROBE_US - 1,
                "receiver_span" => receiver_span = PROBE_US - 1,
                "not_draining" => delivered = admission.symbol_bytes,
                "before_brake" => local_span = observed - controller.last_brake_us.unwrap() + 1,
                "pace_change" => {
                    let before = controller.rate_bps;
                    controller.rate_bps -= 1;
                    controller.record_rate_change(
                        admission.started_us + 1,
                        before,
                        RateReason::ReprobeRollback,
                    );
                }
                "missing" | "regressed" => {}
                _ => unreachable!(),
            }
            let received_end = controller.last_report.unwrap().1;
            let sent_end = (
                sample.admitted_symbol_bytes.unwrap(),
                sample.admitted_symbols.unwrap(),
            );
            let sent_start = (sent_end.0 - admission.symbol_bytes, sent_end.1 - symbols);
            let receiver_end = 100_000_000 + observed;
            controller.service_window = service::Window::default();
            assert!(!controller.service_window.observe(
                1,
                Some(receiver_end - receiver_span),
                received_end - delivered,
                observed - local_span,
                (invalid != "missing").then_some(sent_start)
            ));
            if invalid == "regressed" {
                assert!(!controller.service_window.observe(
                    2,
                    Some(receiver_end - receiver_span + 100_000),
                    received_end - delivered,
                    observed - local_span + 100_000,
                    Some((sent_start.0 - 1, sent_start.1))
                ));
            }
            let complete = controller.service_window.observe(
                3,
                Some(receiver_end),
                received_end,
                observed,
                (invalid != "missing").then_some(sent_end),
            );
            assert_eq!(complete, invalid != "receiver_span", "{invalid}");
            // The clear probe arrives between reports. Retain the actual last
            // accepted report instead of completing a new, now-long-enough
            // receiver interval while testing the existing sample's validity.
            sample.report_number = controller.last_report.unwrap().0;
            sample.delivered_bytes = received_end;
            sample.delivery_report_time_us = controller.last_control.delivery_report_time_us;
            sample.positive_delivery_age_us = Some(100_000);
            let before = controller.rate_bps;
            controller.observe(&sample);
            assert_eq!(
                controller.last_control.drain_service_target_bps, None,
                "{invalid}"
            );
            assert_eq!(
                controller.rate_bps,
                if matches!(invalid, "old" | "receiver_span") {
                    before
                } else {
                    (before as f64 * (1.0 + 16.0 / 180.0)) as u64
                },
                "old fallback: {invalid}"
            );
            if matches!(invalid, "old" | "receiver_span") {
                assert!(controller.drain_restore_pending, "{invalid}");
            }
        }
    }

    #[test]
    fn drain_service_029_preserves_probe_pressure_and_legacy_fallback() {
        for guard in [
            "used_probe",
            "old_probe",
            "pre_brake_probe",
            "pressure",
            "positive_age",
            "idle",
            "interrupted",
            "generation",
            "gap",
            "clock",
            "not_pending",
            "legacy",
        ] {
            let (mut controller, mut sample) = draining_service_029(0, 1_000_000);
            let before = controller.rate_bps;
            let legacy_target = (controller.draining_bps.unwrap().0 * 0.9) as u64;
            match guard {
                "used_probe" => controller.last_growth_probe = Some(sample.probe_sample_id),
                "old_probe" => sample.probe_age_us = Some(CONTROL_US + 1),
                "pre_brake_probe" => {
                    // Long propagation can produce a young clear reply whose
                    // request still predates/equaled the actual brake.
                    let rtt = (sample.now_us - controller.last_brake_us.unwrap()) as f64 / 1000.0;
                    controller.min_rtt_ms = Some(rtt);
                    controller.fast_probe_min_rtt_ms = Some(rtt);
                    controller.startup_probe_pressure = None;
                    sample.probe_latest_rtt_ms = Some(rtt);
                    sample.probe_rtt_ms = Some(rtt);
                    sample.probe_age_us = Some(0);
                }
                "pressure" => sample.send_queue_bytes = 5000,
                "positive_age" => sample.positive_delivery_age_us = Some(CONTROL_US + 1),
                "idle" => sample.offered_backlog = false,
                "interrupted" => controller.backlog_since_us = Some(1_100_000),
                "generation" => {
                    sample.generation += 1;
                    sample.report_number = 1;
                    sample.delivered_bytes = 0;
                    sample.delivered_bps = Some(0.0);
                    sample.admitted_symbols = Some(0);
                    sample.admitted_symbol_bytes = Some(0);
                }
                "gap" => sample.now_us += FRESH_US + 1,
                "clock" => sample.now_us = controller.last_control.at_us - 1,
                "not_pending" => controller.drain_restore_pending = false,
                "legacy" => {
                    controller.fast_feedback_seen = false;
                    sample.delivery_sample_span_us = PROBE_US;
                }
                _ => unreachable!(),
            }
            controller.observe(&sample);
            assert_eq!(
                controller.last_control.drain_service_target_bps, None,
                "{guard}"
            );
            if guard == "legacy" {
                assert_eq!(controller.rate_bps, legacy_target);
                assert!(!controller.fast_feedback_seen);
            } else {
                assert!(
                    controller.rate_bps <= ((before as f64 * 1.2) as u64).max(START_BPS),
                    "{guard}"
                );
            }
            if guard == "generation" {
                assert!(controller.last_brake_us.is_none());
                assert!(!controller.drain_restore_pending);
                assert!(controller.service_window.latest(sample.now_us).is_none());
            }
        }

        // Reuse a genuinely granted finite trial. Its expiry in refill and
        // its explicit disable in observe must both reject the new exception,
        // while leaving the existing bounded fallback semantics intact.
        for expiry in [false, true] {
            let (trial, started, baseline) = granted_reprobe();
            let now = started + if expiry { 4_000_000 } else { 3_800_000 };
            let (mut controller, mut sample) =
                draining_service_029(now - 1_600_000, trial.rate_bps * 8);
            assert!(controller.rate_bps > baseline);
            controller.reprobe = trial.reprobe;
            sample.reprobe_enabled = expiry;
            assert!(controller.reprobe.active());
            controller.observe(&sample);
            assert!(!controller.reprobe.active());
            assert_eq!(controller.last_control.drain_service_target_bps, None);
            assert!(controller.rate_bps <= (baseline as f64 * 1.2) as u64);
            if expiry {
                assert!(
                    controller
                        .rate_changes
                        .iter()
                        .any(|change| change.at_us == now
                            && matches!(change.reason, RateReason::ReprobeRollback)
                            && change.pacing_bps == baseline)
                );
            }
        }
    }

    #[test]
    fn initial_delivery_credit_026_carries_off_tick_delivery_and_spends_it_once() {
        let (mut controller, mut sample) = initial_credit_026(20_000_000);
        assert_eq!(controller.rate_bps, 307_200);
        assert_eq!(controller.last_initial_growth_report, Some((3, 6000)));
        assert!(
            controller
                .last_control
                .initial_delivery_credit
                .unwrap()
                .used
        );
        sample = admitted_report_026(&mut controller, &sample, 300_000, u64::MAX);
        controller.observe(&sample);
        let credit = controller.initial_delivery_credit.unwrap();
        assert_eq!(credit.observed_us, 300_000);
        assert_eq!(credit.wire_delivery_bps, 320_000.0);
        assert_eq!(controller.rate_bps, 307_200);

        // The next receiver interval contains only three of four admitted
        // datagrams; the fourth has not yet arrived. Its lower rate cannot
        // itself support growth, but the real preceding report still can.
        sample = admitted_report_026(&mut controller, &sample, 400_000, 3000);
        assert_eq!(sample.delivered_bps, Some(240_000.0));
        assert!(sample.delivered_bytes < sample.admitted_symbol_bytes.unwrap());
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 368_640);
        assert_eq!(controller.last_control.report_number, 5);
        assert_eq!(controller.last_initial_growth_report, Some((4, 10_000)));
        let used = controller.last_control.initial_delivery_credit.unwrap();
        assert_eq!(used.report_number, 4);
        assert!(used.used);
        assert!(controller.initial_delivery_credit.is_none());

        let changes = controller.rate_changes_total;
        exercise_budget(&mut controller, 400_000, 200_000);
        sample.now_us = 600_000;
        sample.positive_delivery_age_us = Some(200_000);
        sample.probe_sample_id += 2;
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 368_640);
        assert_eq!(controller.rate_changes_total, changes);
        assert!(controller.initial_delivery_credit.is_none());
    }

    #[test]
    fn initial_delivery_credit_026_keeps_capture_age_without_refreshing_replays() {
        let (mut controller, mut sample) = initial_credit_026(20_000_000);
        sample = admitted_report_026(&mut controller, &sample, 300_000, u64::MAX);
        sample.positive_delivery_age_us = Some(150_000);
        controller.observe(&sample);
        let mut replay = sample.clone();
        let admitted = exercise_budget(&mut controller, 300_000, 50_000);
        replay.now_us = 350_000;
        replay.admitted_symbols = replay.admitted_symbols.map(|count| count + admitted / 1000);
        replay.admitted_symbol_bytes = replay.admitted_symbol_bytes.map(|bytes| bytes + admitted);
        replay.probe_age_us = Some(50_000);
        replay.positive_delivery_age_us = Some(200_000);
        controller.observe(&replay);
        assert_eq!(
            controller.initial_delivery_credit.unwrap().observed_us,
            300_000
        );
        assert_eq!(
            controller
                .initial_delivery_credit
                .unwrap()
                .positive_age_at_observation_us,
            150_000
        );
        sample = admitted_report_026(&mut controller, &replay, 400_000, 1000);
        // The350ms observation replayed the300ms report, so this is still a
        // receiver interval from300ms to400ms, with only1000 delivered bytes.
        sample.delivery_sample_span_us = 100_000;
        sample.delivered_bps = Some(80_000.0);
        controller.observe(&sample);
        // Capture is only100ms old, but its positive evidence is250ms old.
        assert!(controller.initial_delivery_credit.is_none());
        assert_eq!(controller.rate_bps, 307_200);
        assert_eq!(controller.last_initial_growth_report, Some((3, 6000)));
    }

    #[test]
    fn initial_delivery_credit_026_clears_invalid_idle_changed_and_new_generation_state() {
        for invalid in [
            "zero",
            "missing",
            "span",
            "bytes",
            "report",
            "clock",
            "gap",
            "idle",
            "generation",
            "caution",
            "rollback",
        ] {
            let (mut controller, mut sample) = initial_credit_026(20_000_000);
            sample = admitted_report_026(&mut controller, &sample, 300_000, u64::MAX);
            controller.observe(&sample);
            assert!(controller.initial_delivery_credit.is_some(), "{invalid}");
            sample.now_us = 350_000;
            sample.positive_delivery_age_us = Some(50_000);
            sample.probe_age_us = Some(50_000);
            match invalid {
                "zero" => {
                    sample.report_number += 1;
                    sample.delivered_bps = Some(0.0);
                }
                "missing" => sample.positive_delivery_age_us = None,
                "span" => sample.delivery_sample_span_us = 0,
                "bytes" => sample.delivered_bytes -= 1000,
                "report" => sample.report_number -= 1,
                "clock" => sample.now_us = 299_999,
                "gap" => sample.now_us = 3_300_001,
                "idle" => sample.offered_backlog = false,
                "generation" => {
                    sample.generation += 1;
                    sample.report_number = 1;
                    sample.delivered_bytes = 0;
                    sample.delivered_bps = Some(0.0);
                }
                "caution" => controller.congestion_seen = true,
                "rollback" => {
                    let previous = controller.rate_bps;
                    controller.rate_bps = 256_000;
                    controller.record_rate_change(350_000, previous, RateReason::ReprobeRollback);
                    assert!(controller.initial_delivery_credit.is_none());
                }
                _ => unreachable!(),
            }
            controller.observe(&sample);
            assert!(controller.initial_delivery_credit.is_none(), "{invalid}");
            assert!(
                controller.last_control.initial_delivery_credit.is_none(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn initial_delivery_credit_026_preserves_legacy_and_does_not_spend_capped_noops() {
        let (controller, _) = initial_credit_026(START_BPS);
        assert_eq!(controller.rate_bps, START_BPS);
        assert_eq!(controller.last_growth_us, 0);
        assert!(controller.last_initial_growth_report.is_none());
        assert_eq!(controller.rate_changes_total, 0);
        assert!(controller.initial_delivery_credit.is_some());
        assert!(
            !controller
                .last_control
                .initial_delivery_credit
                .unwrap()
                .used
        );

        let mut legacy = PathController::new(20_000_000, 20);
        let mut sample = observation(0, 80.0);
        sample.delivered_bytes = 0;
        sample.delivered_bps = Some(0.0);
        sample.delivery_report_time_us = Some(100_000_000);
        sample.delivery_sample_span_us = PROBE_US;
        legacy.observe(&sample);
        legacy.tokens = 0.0;
        let admitted = exercise_budget(&mut legacy, 0, PROBE_US);
        sample.now_us = PROBE_US;
        sample.report_number += 1;
        sample.delivered_bytes = admitted;
        sample.delivered_bps = Some(admitted as f64 * 8_000_000.0 / PROBE_US as f64);
        sample.delivery_report_time_us = Some(100_000_000 + PROBE_US);
        sample.probe_sample_id += 1;
        legacy.observe(&sample);
        assert_eq!(legacy.rate_bps, 384_000);
        assert!(!legacy.fast_feedback_seen);
        assert!(legacy.initial_delivery_credit.is_none());
        assert!(
            serde_json::to_value(&legacy.last_control)
                .unwrap()
                .get("initial_delivery_credit")
                .is_none()
        );
    }

    fn old_severe_loss_026() -> (PathController, Observation) {
        let mut quality = crate::runtime::quality::State::new(7);
        for _ in 0..64 {
            quality.admitted(1000);
        }
        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = short_observation_022(0, 80.0);
        sample.admitted_symbols = Some(quality.snapshot.sent_symbols);
        controller.observe(&sample);
        sample = short_observation_022(200_000, 180.0);
        sample.admitted_symbols = Some(64);
        sample.finalized_expected = Some(16);
        sample.finalized_lost = Some(16);
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 128_000);
        assert_eq!(controller.braked_queue_ms, Some(100.0));
        assert_eq!(controller.last_brake_us, Some(200_000));
        sample = short_observation_022(700_000, 170.0);
        sample.admitted_symbols = Some(64);
        sample.finalized_expected = Some(16);
        sample.finalized_lost = Some(16);
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 128_000);
        assert_eq!(controller.last_brake_us, Some(200_000));
        // This probe began530ms, after the last brake, but has already been
        // observed before the next old loss prefix arrives at800ms.
        let probe_id = sample.probe_sample_id;
        sample = short_observation_022(800_000, 170.0);
        sample.probe_sample_id = probe_id;
        sample.probe_age_us = Some(100_000);
        sample.admitted_symbols = Some(64);
        sample.finalized_expected = Some(32);
        sample.finalized_lost = Some(32);
        (controller, sample)
    }

    #[test]
    fn severe_loss_override_026_requires_a_new_post_brake_probe() {
        for evidence in ["reused", "pre_brake", "new_post_brake"] {
            let (mut controller, mut sample) = old_severe_loss_026();
            match evidence {
                "reused" => {}
                "pre_brake" => {
                    sample.probe_sample_id += 1;
                    sample.probe_age_us = Some(500_000);
                    sample.rtt_ms = 0.0;
                }
                "new_post_brake" => {
                    sample.probe_sample_id += 1;
                    sample.probe_age_us = Some(0);
                }
                _ => unreachable!(),
            }
            controller.observe(&sample);
            let loss = controller.last_control.brake_loss.as_ref().unwrap();
            assert!(controller.last_control.fast_loss);
            assert_eq!(controller.loss_evidence.counts(), (32, 32));
            assert_eq!(
                loss.pressure_override,
                evidence == "new_post_brake",
                "{evidence}"
            );
            assert_eq!(loss.actionable, evidence == "new_post_brake", "{evidence}");
            if evidence == "new_post_brake" {
                assert!(controller.rate_bps < 128_000);
                assert!(matches!(
                    controller.rate_changes.back().unwrap().reason,
                    RateReason::FastLossBrake
                ));
            } else {
                assert_eq!(controller.rate_bps, 128_000);
                assert_eq!(controller.last_brake_us, Some(200_000));
                assert_eq!((loss.expected, loss.lost), (0, 0));
            }
        }
    }

    #[test]
    fn severe_loss_override_026_keeps_component_safety_without_borrowed_severity() {
        for component in ["local", "transport", "small_local", "low_selected"] {
            let (mut controller, mut sample) = old_severe_loss_026();
            match component {
                "local" => sample.rtt_ms = 170.0,
                "transport" => sample.send_queue_bytes = 4400,
                "small_local" => sample.rtt_ms = 81.0,
                "low_selected" => {
                    sample.rtt_ms = 170.0;
                    sample.probe_latest_rtt_ms = Some(80.0);
                    sample.probe_sample_id += 1;
                    sample.probe_age_us = Some(0);
                }
                _ => unreachable!(),
            }
            controller.observe(&sample);
            let expected = matches!(component, "local" | "transport");
            let loss = controller.last_control.brake_loss.as_ref().unwrap();
            assert_eq!(loss.pressure_override, expected, "{component}");
            assert_eq!(loss.actionable, expected, "{component}");
            if expected {
                assert!(controller.rate_bps < 128_000);
            } else {
                assert_eq!(controller.rate_bps, 128_000);
            }
            if component == "low_selected" {
                assert_eq!(controller.last_control.local_rtt_ms, Some(170.0));
                assert_eq!(controller.last_control.selected_rtt_ms, Some(80.0));
                assert_eq!(controller.last_control.queue_delay_ms, 0.0);
            }
        }
    }

    fn paired_controller_023(mode: &str) -> (PathController, Observation) {
        let mut quality = crate::runtime::quality::State::new(7);
        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = short_observation_022(0, 80.0);
        sample.admitted_symbol_bytes = Some(0);
        controller.observe(&sample);
        controller.rate_bps = 2_000_000;
        let mut received = 0;
        for step in 1..=10 {
            let now = step * 100_000;
            let sparse = mode == "sparse" && step > 5;
            let inactive =
                (mode == "idle" && step > 5) || (mode == "interrupted" && (6..=7).contains(&step));
            if !inactive {
                for at in (now - 100_000..now).step_by(if sparse { 100_000 } else { 10_000 }) {
                    assert!(controller.allow(at, 1000, 0.0));
                    controller.admitted_symbol(at, 1000, 1000);
                    quality.admitted(1000);
                }
            }
            let delivered = if step <= 5 || mode == "normal" {
                10_000
            } else if mode == "zero" || sparse || inactive {
                0
            } else {
                1_000
            };
            received += delivered;
            sample.now_us = now;
            sample.report_number = step + 1;
            sample.delivery_report_time_us = Some(100_000_000 + now);
            sample.delivered_bytes = received;
            sample.delivered_bps = Some(delivered as f64 * 80.0);
            sample.admitted_symbols = Some(quality.snapshot.sent_symbols);
            sample.admitted_symbol_bytes = Some(quality.snapshot.sent_bytes);
            // Probe replies stop after the stable baseline. The old flat RTT
            // alone cannot reveal the later collapse in receiver service.
            sample.probe_sample_id = 1;
            sample.probe_age_us = Some(now);
            sample.positive_delivery_age_us = Some(if delivered == 0 { now - 500_000 } else { 0 });
            sample.offered_backlog = mode != "idle"
                && !(mode == "interrupted" && (6..=7).contains(&step))
                && !(mode == "empty_active" && step % 2 == 0);
            if step == 10 {
                controller.draining_bps = Some((5_000_000.0, now - 100_000));
            }
            controller.observe(&sample);
            if mode == "pace_change" && step == 8 {
                let previous = controller.rate_bps;
                controller.rate_bps = 1_600_000;
                controller.record_rate_change(now, previous, RateReason::ReprobeRollback);
            }
        }
        (controller, sample)
    }

    #[test]
    fn demand_activity_037_brakes_empty_queues_with_real_admission_progress() {
        let (mut controller, mut sample) = paired_controller_023("empty_active");
        let control = &controller.last_control;
        assert!(controller.fast_feedback_seen);
        assert!(!control.offered_backlog);
        assert_eq!(control.queue_delay_ms, 0.0);
        assert!(!control.new_probe);
        assert!((control.admitted_bytes as f64) < control.integrated_allowance_bytes * 0.9);
        let paired = control.service_admission.as_ref().unwrap();
        assert_eq!(paired.backlog_since_us, None);
        assert_eq!(paired.activity_since_us, Some(0));
        assert_eq!(
            (paired.started_us, paired.span_us, paired.symbols),
            (500_000, 500_000, 50)
        );
        assert!(paired.deficit);
        assert_eq!(controller.rate_bps, 77_600);
        assert_eq!(controller.last_brake_us, Some(1_000_000));
        assert_eq!(
            controller.last_brake_admitted_symbols,
            sample.admitted_symbols
        );
        assert_eq!(controller.pressure_episode_exercised, Some(false));
        assert!(controller.congestion_seen);
        assert!(matches!(
            controller.rate_changes.back().unwrap().reason,
            RateReason::DeliveryShortfallBrake
        ));

        // A later observation of this same endpoint cannot spend it again.
        let changes = controller.rate_changes_total;
        sample.now_us += 100_000;
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 77_600);
        assert_eq!(controller.rate_changes_total, changes);
        assert!(
            !controller
                .last_control
                .service_admission
                .as_ref()
                .unwrap()
                .deficit
        );
    }

    #[test]
    fn demand_activity_037_expires_before_refresh_and_ignores_control_only_work() {
        for gap in [CONTROL_US - 1, CONTROL_US] {
            let mut activity = DemandActivity::default();
            activity.update(10_000, true);
            activity.update(10_000 + gap, true);
            assert_eq!(
                activity.since_us,
                Some(if gap < CONTROL_US {
                    10_000
                } else {
                    10_000 + gap
                })
            );
            assert_eq!(activity.last_activity_us, Some(10_000 + gap));
        }

        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = short_observation_022(0, 80.0);
        sample.delivered_bytes = 0;
        sample.delivered_bps = Some(0.0);
        sample.admitted_symbol_bytes = Some(0);
        controller.observe(&sample);
        assert_eq!(controller.demand_activity.since_us, Some(0));
        sample.offered_backlog = false;
        for now in [100_000, CONTROL_US - 1, CONTROL_US] {
            // Successful probes, new control reports, budget queries and a
            // zero-byte callback cannot replace actual business activity.
            if now % 100_000 == 0 {
                controller.probe_admitted(now);
            }
            assert!(controller.allow(now, 100, 0.0));
            controller.admitted_symbol(now, 0, 0);
            sample.now_us = now;
            sample.report_number += 1;
            sample.delivery_report_time_us = Some(100_000_000 + now);
            sample.probe_age_us = Some(now);
            sample.positive_delivery_age_us = Some(now);
            controller.observe(&sample);
            assert_eq!(
                controller.demand_activity.since_us,
                (now < CONTROL_US).then_some(0)
            );
            assert_eq!(
                controller.demand_activity.last_activity_us,
                controller.demand_activity.since_us
            );
        }
        sample.now_us = CONTROL_US + 1;
        sample.offered_backlog = true;
        controller.observe(&sample);
        assert_eq!(controller.demand_activity.since_us, Some(CONTROL_US + 1));

        let (idle, _) = paired_controller_023("idle");
        assert_eq!(idle.demand_activity.since_us, None);
        let (interrupted, _) = paired_controller_023("interrupted");
        let paired = interrupted.last_control.service_admission.as_ref().unwrap();
        assert_eq!(paired.activity_since_us, Some(700_000));
        assert_eq!(paired.started_us, 500_000);
        assert!(!paired.deficit);
    }

    #[test]
    fn demand_activity_037_resets_at_generation_clock_and_observation_gaps() {
        let (mut controller, _) = initial_credit_026(20_000_000);
        for (now, since) in [(300_000, 0), (500_000, 500_000), (499_999, 499_999)] {
            assert!(controller.allow(now, 100, 0.0));
            controller.admitted_symbol(now, 100, 100);
            assert_eq!(controller.demand_activity.since_us, Some(since));
            assert_eq!(controller.demand_activity.last_activity_us, Some(now));
        }

        for boundary in ["generation", "clock", "gap"] {
            let (mut controller, mut sample) = initial_credit_026(20_000_000);
            assert_eq!(controller.demand_activity.since_us, Some(0));
            sample.offered_backlog = false;
            match boundary {
                "generation" => {
                    sample.now_us += 1;
                    sample.generation += 1;
                    sample.report_number = 1;
                    sample.delivered_bytes = 0;
                    sample.delivered_bps = Some(0.0);
                    sample.admitted_symbols = Some(0);
                    sample.admitted_symbol_bytes = Some(0);
                }
                "clock" => sample.now_us -= 1,
                "gap" => {
                    sample.now_us += FRESH_US + 1;
                    // Even recent success cannot bridge a missing controller
                    // observation interval beyond the existing freshness bound.
                    assert!(controller.allow(sample.now_us - 1, 100, 0.0));
                    controller.admitted_symbol(sample.now_us - 1, 100, 100);
                    assert_eq!(controller.demand_activity.since_us, Some(sample.now_us - 1));
                    sample.admitted_symbols = Some(sample.admitted_symbols.unwrap() + 1);
                    sample.admitted_symbol_bytes =
                        Some(sample.admitted_symbol_bytes.unwrap() + 100);
                }
                _ => unreachable!(),
            }
            controller.observe(&sample);
            assert_eq!(controller.demand_activity.since_us, None, "{boundary}");
            assert_eq!(
                controller.demand_activity.last_activity_us, None,
                "{boundary}"
            );
            if boundary == "generation" {
                assert_eq!(controller.generation, Some(sample.generation));
                assert!(controller.last_control.service_admission.is_none());
                assert!(controller.last_brake_us.is_none());
            }
            sample.now_us += 1;
            sample.offered_backlog = true;
            controller.observe(&sample);
            assert_eq!(
                controller.demand_activity.since_us,
                Some(sample.now_us),
                "{boundary}"
            );
        }
    }

    #[test]
    fn demand_activity_037_preserves_numeric_legacy_and_growth_guards() {
        for mode in ["normal", "sparse", "pace_change"] {
            let (controller, _) = paired_controller_023(mode);
            let paired = controller.last_control.service_admission.as_ref().unwrap();
            assert_eq!(paired.activity_since_us, Some(0), "{mode}");
            assert!(!paired.deficit, "{mode}");
            assert!(!controller.congestion_seen, "{mode}");
            match mode {
                "normal" => assert!(
                    controller.last_control.service_symbol_delivery_bps.unwrap()
                        >= paired.symbol_bps * 0.85
                ),
                "sparse" => assert_eq!(paired.symbols, 5),
                "pace_change" => assert!(paired.started_us < paired.last_pace_change_us),
                _ => unreachable!(),
            }
        }

        let mut legacy = PathController::new(20_000_000, 20);
        let mut sample = observation(0, 80.0);
        sample.delivery_sample_span_us = PROBE_US;
        sample.admitted_symbols = Some(0);
        sample.admitted_symbol_bytes = Some(0);
        legacy.observe(&sample);
        let admitted = exercise_budget(&mut legacy, 0, PROBE_US);
        sample = observation(PROBE_US, 80.0);
        sample.delivery_sample_span_us = PROBE_US;
        sample.delivered_bytes = admitted;
        sample.delivered_bps = Some(admitted as f64 * 8_000_000.0 / PROBE_US as f64);
        sample.delivery_report_time_us = Some(100_000_000 + PROBE_US);
        sample.admitted_symbols = Some(admitted / 1000);
        sample.admitted_symbol_bytes = Some(admitted);
        legacy.observe(&sample);
        assert!(legacy.demand_activity.since_us.is_some());
        assert!(!legacy.fast_feedback_seen);
        assert!(legacy.last_control.service_admission.is_none());
        assert!(
            !serde_json::to_string(&legacy.last_control)
                .unwrap()
                .contains("activity_since_us")
        );

        let (mut initial, sample) = initial_credit_026(20_000_000);
        let before = initial.rate_bps;
        let mut empty = admitted_report_026(&mut initial, &sample, 400_000, u64::MAX);
        empty.offered_backlog = false;
        initial.observe(&empty);
        assert_eq!(initial.demand_activity.since_us, Some(0));
        assert_eq!(initial.backlog_since_us, None);
        assert_eq!(initial.rate_bps, before);
        assert_eq!(initial.last_growth_us, 200_000);

        let (mut restoring, mut sample) = draining_service_029(0, 1_000_000);
        sample.offered_backlog = false;
        restoring.observe(&sample);
        assert!(restoring.demand_activity.since_us.is_some());
        assert_eq!(restoring.backlog_since_us, None);
        assert_eq!(restoring.last_control.drain_service_target_bps, None);
    }

    #[test]
    fn service_deficit_023_brakes_real_admissions_without_new_probes_or_exercised_allowance() {
        for (mode, expected_rate) in [("collapse", 77_600), ("zero", 1_600_000)] {
            let (mut controller, mut sample) = paired_controller_023(mode);
            let control = &controller.last_control;
            assert_eq!(control.queue_delay_ms, 0.0);
            assert!(!control.new_probe);
            assert!((control.admitted_bytes as f64) < control.integrated_allowance_bytes * 0.9);
            let paired = control.service_admission.as_ref().unwrap();
            assert!(paired.deficit);
            assert_eq!(paired.symbols, 50);
            assert_eq!(paired.started_us, 500_000);
            assert_eq!(controller.rate_bps, expected_rate);
            assert!(controller.congestion_seen);
            assert_eq!(controller.pressure_episode_exercised, Some(false));
            assert!(matches!(
                controller.rate_changes.back().unwrap().reason,
                RateReason::DeliveryShortfallBrake
            ));
            assert_eq!(
                controller.draining_bps.unwrap().0,
                if mode == "zero" { 0.0 } else { 80_000.0 }
            );

            let changes = controller.rate_changes_total;
            sample.now_us += 100_000;
            controller.observe(&sample);
            assert_eq!(controller.rate_bps, expected_rate);
            assert_eq!(controller.rate_changes_total, changes);
            assert!(
                !controller
                    .last_control
                    .service_admission
                    .as_ref()
                    .unwrap()
                    .deficit
            );
        }
    }

    #[test]
    fn service_deficit_023_rejects_idle_sparse_interrupted_and_transition_windows() {
        for mode in ["normal", "idle", "sparse", "interrupted", "pace_change"] {
            let (controller, _) = paired_controller_023(mode);
            assert!(
                !controller
                    .last_control
                    .service_admission
                    .as_ref()
                    .unwrap()
                    .deficit,
                "{mode}"
            );
            assert!(!controller.congestion_seen, "{mode}");
            assert_eq!(
                controller.rate_bps,
                if mode == "pace_change" {
                    1_600_000
                } else {
                    2_000_000
                }
            );
        }
    }

    #[test]
    fn service_deficit_023_resets_pairing_and_backlog_after_generation_or_observation_gap() {
        for generation_change in [false, true] {
            let (mut controller, mut sample) = paired_controller_023("normal");
            let now = sample.now_us + FRESH_US + 1;
            sample.now_us = now;
            sample.report_number += 1;
            sample.delivery_report_time_us = Some(100_000_000 + now);
            if generation_change {
                sample.generation += 1;
                sample.admitted_symbols = Some(0);
                sample.admitted_symbol_bytes = Some(0);
                sample.delivered_bytes = 0;
            }
            controller.observe(&sample);
            assert_eq!(controller.backlog_since_us, Some(now));
            assert!(controller.last_control.service_admission.is_none());
            assert!(controller.service_window.latest(now).is_none());
            assert!(!controller.congestion_seen);
        }
    }

    #[test]
    fn growth_headroom_023_accounts_for_existing_queue_in_search_and_drain_restore() {
        for restoring in [false, true] {
            let mut controller = PathController::new(20_000_000, 20);
            let mut sample = short_observation_022(0, 80.0);
            controller.observe(&sample);
            if restoring {
                controller.rate_bps = 500_000;
                controller.congestion_seen = true;
                controller.remembered_bps = 4_000_000.0;
                controller.draining_bps = Some((2_000_000.0, 0));
                controller.drain_restore_pending = true;
            }
            let previous = controller.rate_bps;
            let delivered = exercise_budget(&mut controller, 0, CONTROL_US);
            sample = short_observation_022(CONTROL_US, 88.0);
            sample.rtt_ms = 88.0;
            sample.delivered_bytes = delivered;
            sample.delivered_bps = Some(previous as f64);
            controller.observe(&sample);
            if restoring {
                assert_eq!(controller.rate_bps, 500_000);
                assert!(controller.drain_restore_pending);
                let mut delivered = delivered;
                for now in (300_000..=600_000).step_by(100_000) {
                    let admitted = exercise_budget(&mut controller, now - 100_000, 100_000);
                    delivered += admitted;
                    sample = short_observation_022(now, 88.0);
                    sample.rtt_ms = 88.0;
                    sample.delivered_bytes = delivered;
                    sample.delivered_bps = Some(admitted as f64 * 80.0);
                    controller.observe(&sample);
                }
                assert_eq!(controller.last_growth_us, 600_000);
            }
            assert_eq!(controller.queue_delay_ms, 8.0);
            assert_eq!(
                controller.rate_bps,
                if restoring { 521_276 } else { 279_272 }
            );
            assert_eq!(controller.last_growth_probe, Some(sample.probe_sample_id));
            if restoring {
                assert!(!controller.drain_restore_pending);
            }
        }
    }

    fn short_observation_022(now: u64, probe_ms: f64) -> Observation {
        Observation {
            report_number: now / 100_000 + 1,
            probe_sample_id: now / 100_000 + 1,
            probe_latest_rtt_ms: Some(probe_ms),
            delivery_sample_span_us: 100_000,
            delivery_report_time_us: Some(100_000_000 + now),
            delivered_bps: Some(START_BPS as f64),
            delivered_bytes: now / 1000,
            finalized_expected: Some(0),
            finalized_lost: Some(0),
            admitted_symbols: Some(0),
            ..observation(now, 80.0)
        }
    }

    #[test]
    fn causal_braking_022_requires_post_brake_probe_but_keeps_independent_pressure() {
        for safety in ["none", "severe", "quinn", "transport"] {
            let mut controller = PathController::new(20_000_000, 20);
            controller.observe(&short_observation_022(0, 80.0));
            exercise_budget(&mut controller, 0, CONTROL_US);
            controller.observe(&short_observation_022(200_000, 105.0));
            assert_eq!(controller.last_brake_us, Some(200_000));
            let first = controller.rate_bps;
            let mut old_request = short_observation_022(300_000, 125.0);
            match safety {
                "severe" => old_request.probe_latest_rtt_ms = Some(170.0),
                "quinn" => old_request.rtt_ms = 95.0,
                "transport" => old_request.send_queue_bytes = 3000,
                _ => {}
            }
            controller.observe(&old_request);
            if safety == "none" {
                // The reply is new, but 300-125=175 ms precedes the brake.
                assert_eq!(controller.rate_bps, first);
                assert_eq!(controller.last_brake_us, Some(200_000));
                assert!(controller.queue_delay_ms > 10.0);
                // This request began at 270 ms, after the actual brake.
                controller.observe(&short_observation_022(400_000, 130.0));
                assert!(controller.rate_bps < first);
                assert_eq!(controller.last_brake_us, Some(400_000));
            } else {
                assert!(controller.rate_bps < first, "{safety}");
                assert_eq!(controller.last_brake_us, Some(300_000));
            }
        }
    }

    #[test]
    fn causal_braking_022_captures_exercise_at_actual_brake_and_migrates_transients() {
        for legacy_pulse in [false, true] {
            let mut controller = PathController::new(20_000_000, 20);
            let mut initial = short_observation_022(0, 80.0);
            if legacy_pulse {
                initial.delivery_sample_span_us = 500_000;
            }
            controller.observe(&initial);
            let mut pulse = short_observation_022(200_000, 95.0);
            if legacy_pulse {
                pulse.delivery_sample_span_us = 500_000;
                pulse.rtt_ms = 95.0;
            }
            controller.observe(&pulse);
            assert_eq!(controller.last_brake_us, None);
            assert_eq!(
                controller.pressure_episode_exercised,
                legacy_pulse.then_some(false)
            );
            exercise_budget(&mut controller, 200_000, 100_000);
            let mut brake = short_observation_022(300_000, 110.0);
            if legacy_pulse {
                brake.rtt_ms = 110.0;
            }
            controller.observe(&brake);
            assert_eq!(controller.last_brake_us, Some(300_000));
            assert_eq!(controller.pressure_episode_exercised, Some(true));
            assert!(controller.congestion_seen);
        }
    }

    #[test]
    fn causal_braking_022_uses_only_provable_new_loss_and_falls_back_without_coordinates() {
        let mut sample = short_observation_022(1_000_000, 80.0);
        sample.finalized_expected = Some(130);
        sample.finalized_lost = Some(30);
        sample.admitted_symbols = Some(200);
        for (boundary, lost, expected_new, lost_new, actionable) in [
            (Some(130), 40, 0, 0, false),
            (Some(90), 20, 40, 20, true),
            (Some(110), 29, 20, 9, false),
            (Some(110), 30, 20, 10, true),
            (None, 20, 40, 20, true),
        ] {
            sample.finalized_lost = Some(lost);
            let evidence = BrakeLoss::from_batch(&sample, (40, lost), boundary, false).unwrap();
            assert_eq!((evidence.expected, evidence.lost), (expected_new, lost_new));
            assert_eq!(evidence.actionable, actionable);
        }
        sample.finalized_lost = Some(40);
        let override_old = BrakeLoss::from_batch(&sample, (40, 40), Some(130), true).unwrap();
        assert_eq!((override_old.expected, override_old.lost), (40, 40));
        assert!(override_old.actionable);
        assert!(BrakeLoss::from_batch(&sample, (40, 40), Some(201), false).is_none());
        sample.admitted_symbols = None;
        assert!(BrakeLoss::from_batch(&sample, (40, 40), Some(130), false).is_none());
        sample.admitted_symbols = Some(129);
        assert!(BrakeLoss::from_batch(&sample, (40, 40), Some(130), false).is_none());
    }

    fn loss_after_first_brake_022() -> (PathController, Observation) {
        // These symbols were admitted by the new Quality State before its first
        // periodic controller observation; the controller has no matching mirror.
        let mut quality = crate::runtime::quality::State::new(7);
        for _ in 0..64 {
            quality.admitted(1000);
        }
        let mut controller = PathController::new(20_000_000, 20);
        let mut initial = short_observation_022(0, 80.0);
        initial.admitted_symbols = Some(quality.snapshot.sent_symbols);
        controller.observe(&initial);
        assert_eq!(controller.last_brake_admitted_symbols, None);
        let mut first_loss = short_observation_022(200_000, 80.0);
        first_loss.admitted_symbols = Some(quality.snapshot.sent_symbols);
        first_loss.finalized_expected = Some(16);
        first_loss.finalized_lost = Some(16);
        controller.observe(&first_loss);
        assert_eq!(controller.rate_bps, 128_000);
        assert_eq!(controller.last_brake_admitted_symbols, Some(64));
        let mut old_loss = short_observation_022(800_000, 80.0);
        old_loss.admitted_symbols = Some(64);
        old_loss.finalized_expected = Some(32);
        old_loss.finalized_lost = Some(32);
        (controller, old_loss)
    }

    #[test]
    fn causal_braking_022_preserves_raw_loss_and_resets_the_boundary_with_generation() {
        let (mut controller, mut old_loss) = loss_after_first_brake_022();
        controller.observe(&old_loss);
        assert_eq!(controller.rate_bps, 128_000);
        assert_eq!(controller.last_brake_us, Some(200_000));
        assert!(controller.last_control.fast_loss);
        assert!(
            !controller
                .last_control
                .brake_loss
                .as_ref()
                .unwrap()
                .actionable
        );
        assert_eq!(controller.loss_evidence.counts(), (32, 32));
        old_loss.now_us = 900_000;
        controller.observe(&old_loss);
        assert_eq!(controller.loss_evidence.counts(), (32, 32));
        assert!(!controller.last_control.fast_loss);
        assert!(controller.last_control.brake_loss.is_none());

        let mut new_loss = short_observation_022(1_200_000, 80.0);
        new_loss.admitted_symbols = Some(128);
        new_loss.finalized_expected = Some(80);
        new_loss.finalized_lost = Some(80);
        controller.observe(&new_loss);
        assert_eq!(controller.rate_bps, 64_000);
        assert_eq!(controller.last_brake_admitted_symbols, Some(128));

        new_loss.now_us = 1_300_000;
        new_loss.generation = 8;
        new_loss.admitted_symbols = Some(64);
        new_loss.finalized_expected = Some(16);
        new_loss.finalized_lost = Some(16);
        controller.observe(&new_loss);
        assert_eq!(controller.rate_bps, 128_000);
        assert_eq!(controller.last_brake_us, Some(1_300_000));
        assert_eq!(controller.last_brake_admitted_symbols, Some(64));
        assert_eq!(controller.loss_evidence.counts(), (16, 16));
    }

    #[test]
    fn causal_braking_022_keeps_raw_fast_loss_for_missing_coordinates_and_current_pressure() {
        for safety in ["missing", "regressed", "severe", "blocked", "shortfall"] {
            let (mut controller, mut old_loss) = loss_after_first_brake_022();
            match safety {
                "missing" => old_loss.admitted_symbols = None,
                "regressed" => old_loss.admitted_symbols = Some(50),
                "severe" => old_loss.probe_latest_rtt_ms = Some(170.0),
                "blocked" | "shortfall" => {
                    exercise_budget(&mut controller, 200_000, 600_000);
                    old_loss.delivered_bps = Some(0.0);
                    if safety == "blocked" {
                        controller.blocked_since_us = Some(300_000);
                        old_loss.transport_blocked = true;
                    }
                }
                _ => unreachable!(),
            }
            controller.observe(&old_loss);
            assert!(controller.rate_bps < 128_000, "{safety}");
            assert!(matches!(
                controller.rate_changes.back().unwrap().reason,
                RateReason::FastLossBrake
            ));
            if matches!(safety, "missing" | "regressed") {
                assert!(controller.last_control.brake_loss.is_none());
                assert_eq!(controller.last_brake_admitted_symbols, None);
            } else {
                assert!(
                    controller
                        .last_control
                        .brake_loss
                        .as_ref()
                        .unwrap()
                        .pressure_override
                );
            }
        }
    }

    fn cautious_service_021(qualified_at_us: u64, positive_age_us: u64) -> PathController {
        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = observation(0, 80.0);
        sample.delivery_sample_span_us = 100_000;
        sample.delivery_report_time_us = Some(100_000_000);
        sample.delivered_bps = Some(500_000.0);
        controller.observe(&sample);
        controller.rate_bps = 500_000;
        controller.remembered_bps = 500_000.0;
        controller.congestion_seen = true;
        let mut delivered_bytes = 0;
        for now in (100_000..=600_000).step_by(100_000) {
            delivered_bytes += exercise_budget(&mut controller, now - 100_000, 100_000);
            sample.now_us = now;
            sample.report_number = now / 100_000 + 1;
            sample.probe_sample_id = sample.report_number;
            sample.delivered_bytes = delivered_bytes;
            sample.delivery_report_time_us = if now == 500_000 && qualified_at_us == 600_000 {
                None
            } else {
                Some(100_000_000 + now)
            };
            sample.positive_delivery_age_us =
                Some(if now == 600_000 { positive_age_us } else { 0 });
            controller.observe(&sample);
        }
        controller
    }

    #[test]
    fn service_discovery_021_keeps_off_tick_evidence_and_requires_young_delivery() {
        let controller = cautious_service_021(500_000, 0);
        assert!(controller.congestion_seen);
        assert_eq!(controller.rate_bps, 544_444);
        assert_eq!(
            controller
                .service_window
                .latest(600_000)
                .unwrap()
                .observed_us,
            500_000
        );
        assert!(matches!(
            controller.rate_changes.back().unwrap().reason,
            RateReason::ServiceDiscovery
        ));
        // A recent local consumption time cannot make old positive delivery
        // qualify for discovery. The pre-existing cautious step is still valid.
        let stale = cautious_service_021(500_000, CONTROL_US + 1);
        assert_eq!(stale.rate_bps, 515_000);
        assert!(matches!(
            stale.rate_changes.back().unwrap().reason,
            RateReason::CautiousGrowth
        ));
    }

    #[test]
    fn service_discovery_021_cannot_reuse_a_qualified_interval_with_a_new_probe() {
        let mut controller = cautious_service_021(600_000, 0);
        assert_eq!(controller.rate_bps, 544_444);
        assert_eq!(
            controller
                .service_window
                .latest(600_000)
                .unwrap()
                .observed_us,
            600_000
        );
        let previous_bytes = controller.last_report.unwrap().1;
        let admitted = exercise_budget(&mut controller, 600_000, CONTROL_US);
        let mut sample = observation(800_000, 80.0);
        sample.delivery_sample_span_us = 100_000;
        sample.delivery_report_time_us = Some(100_800_000);
        sample.report_number = 9;
        sample.probe_sample_id = 9;
        sample.delivered_bytes = previous_bytes + admitted;
        sample.delivered_bps = Some(600_000.0);
        controller.observe(&sample);
        // The probe is new and began after growth. The still-young service
        // endpoint was already consumed, so it cannot fund another increment.
        assert_eq!(controller.rate_bps, 544_444);
        assert_eq!(controller.last_growth_us, 600_000);
        assert_eq!(controller.rate_changes_total, 1);
    }

    #[test]
    fn startup_probe_021_distinguishes_transient_persistent_and_over_target_delay() {
        for persistent in [false, true] {
            let mut controller = PathController::new(20_000_000, 20);
            let mut sample = observation(0, 80.0);
            sample.delivery_sample_span_us = 100_000;
            sample.delivery_report_time_us = Some(100_000_000);
            sample.delivered_bps = Some(START_BPS as f64);
            controller.observe(&sample);
            sample.delivered_bytes = exercise_budget(&mut controller, 0, CONTROL_US);
            sample.now_us = CONTROL_US;
            sample.report_number = 2;
            sample.probe_sample_id = 2;
            sample.delivery_report_time_us = Some(100_200_000);
            sample.probe_latest_rtt_ms = Some(95.0);
            controller.observe(&sample);
            assert_eq!(controller.rate_bps, START_BPS);
            assert_eq!(controller.queue_delay_ms, 15.0);

            sample.delivered_bytes += exercise_budget(&mut controller, 200_000, 100_000);
            sample.now_us = 300_000;
            sample.report_number = 3;
            sample.probe_sample_id = 3;
            sample.delivery_report_time_us = Some(100_300_000);
            sample.probe_latest_rtt_ms = Some(if persistent { 95.0 } else { 80.0 });
            controller.observe(&sample);
            if persistent {
                assert!(controller.rate_bps < START_BPS);
                assert!(matches!(
                    controller.rate_changes.back().unwrap().reason,
                    RateReason::QueueBrake
                ));
            } else {
                assert_eq!(controller.rate_bps, START_BPS);
                assert_eq!(controller.queue_delay_ms, 0.0);
                sample.delivered_bytes += exercise_budget(&mut controller, 300_000, 100_000);
                sample.now_us = 400_000;
                sample.report_number = 4;
                sample.probe_sample_id = 4;
                sample.delivery_report_time_us = Some(100_400_000);
                sample.probe_latest_rtt_ms = Some(110.0);
                controller.observe(&sample);
                assert!(controller.rate_bps < START_BPS);
                assert_eq!(controller.queue_delay_ms, 30.0);
                assert_eq!(controller.last_brake_us, Some(400_000));
            }
        }
    }

    #[test]
    fn fast_growth_020_scales_increment_to_round_trip_queue_budget() {
        for (rtt_ms, expected) in [(20.0, 384_000), (80.0, 307_200)] {
            let mut controller = PathController::new(20_000_000, 20);
            let mut sample = observation(0, rtt_ms);
            sample.delivery_sample_span_us = 100_000;
            sample.delivery_report_time_us = Some(100_000_000);
            sample.delivered_bps = Some(START_BPS as f64);
            controller.observe(&sample);
            exercise_budget(&mut controller, 0, CONTROL_US);
            sample.now_us = CONTROL_US;
            sample.report_number = 2;
            sample.delivered_bytes = 6400;
            sample.delivery_report_time_us = Some(100_200_000);
            controller.observe(&sample);
            assert_eq!(controller.rate_bps, expected);
        }
    }

    #[test]
    fn fast_recovery_020_spends_one_probe_and_caps_drain_restoration() {
        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = observation(0, 80.0);
        sample.delivery_sample_span_us = 100_000;
        sample.delivery_report_time_us = Some(100_000_000);
        sample.delivered_bps = Some(500_000.0);
        controller.observe(&sample);
        controller.rate_bps = 500_000;
        controller.remembered_bps = 4_000_000.0;
        controller.congestion_seen = true;
        controller.draining_bps = Some((2_000_000.0, 0));
        controller.drain_restore_pending = true;

        // 032 waits for actual cumulative delivery to complete the first 500ms
        // service interval. The original gain and one-probe assertions follow.
        for now in (100_000..=500_000).step_by(100_000) {
            sample.delivered_bytes += exercise_budget(&mut controller, now - 100_000, 100_000);
            sample.now_us = now;
            sample.report_number = now / 100_000 + 1;
            sample.delivery_report_time_us = Some(100_000_000 + now);
            sample.probe_age_us = Some(now);
            controller.observe(&sample);
            assert_eq!(controller.rate_bps, 500_000);
            assert!(controller.drain_restore_pending);
        }
        controller.probe_admitted(500_000);
        sample.delivered_bytes += exercise_budget(&mut controller, 500_000, 100_000);
        sample.now_us = 600_000;
        sample.report_number = 7;
        sample.delivery_report_time_us = Some(100_600_000);
        sample.probe_sample_id += 1;
        sample.probe_age_us = Some(20_000);
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 544_444);
        assert!(!controller.drain_restore_pending);
        assert_eq!(controller.last_growth_probe, Some(sample.probe_sample_id));

        controller.drain_restore_pending = true;
        controller.probe_admitted(700_000);
        sample.delivered_bytes += exercise_budget(&mut controller, 600_000, CONTROL_US);
        sample.probe_sample_id += 1;
        sample.now_us = 800_000;
        sample.report_number = 8;
        sample.delivered_bps = Some(600_000.0);
        sample.delivery_report_time_us = Some(100_800_000);
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 544_444);
        assert!(controller.drain_restore_pending);

        sample.delivered_bytes += exercise_budget(&mut controller, 800_000, CONTROL_US);
        controller.probe_admitted(900_000);
        sample.now_us = 1_000_000;
        sample.report_number = 9;
        sample.delivery_report_time_us = Some(101_000_000);
        sample.probe_sample_id += 1;
        controller.observe(&sample);
        // The old 2 Mbps hint cannot jump directly to 1.8 Mbps or stack a
        // second recovery step on the same tick and authenticated reply.
        assert_eq!(controller.rate_bps, 592_839);
        assert!(!controller.drain_restore_pending);
        controller.probe_admitted(1_000_000);
        assert!(!controller.decision(1_099_999).probe_due);
        assert!(controller.decision(1_100_000).probe_due);
    }

    #[test]
    fn fast_growth_019_requires_a_young_probe_started_after_previous_growth() {
        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = observation(0, 20.0);
        sample.delivery_sample_span_us = 100_000;
        sample.delivery_report_time_us = Some(100_000_000);
        sample.delivered_bps = Some(START_BPS as f64);
        controller.observe(&sample);
        exercise_budget(&mut controller, 0, CONTROL_US);
        sample.now_us = CONTROL_US;
        sample.report_number = 2;
        sample.delivered_bytes = 6400;
        sample.delivery_report_time_us = Some(100_200_000);
        controller.observe(&sample);
        let first = controller.rate_bps;
        assert!(first > START_BPS);

        exercise_budget(&mut controller, CONTROL_US, CONTROL_US);
        sample.now_us = 400_000;
        sample.report_number = 3;
        sample.delivered_bytes += first / 40;
        sample.delivered_bps = Some(first as f64);
        sample.delivery_report_time_us = Some(100_400_000);
        sample.probe_sample_id = 2;
        sample.probe_age_us = Some(190_000);
        // The response is new and young, but its request began at190ms,
        // before the200ms growth. It cannot validate that increased pace.
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, first);

        exercise_budget(&mut controller, 400_000, CONTROL_US);
        sample.now_us = 600_000;
        sample.report_number = 4;
        sample.delivered_bytes += first / 40;
        sample.delivery_report_time_us = Some(100_600_000);
        sample.probe_sample_id = 3;
        sample.probe_age_us = Some(0);
        controller.observe(&sample);
        assert!(controller.rate_bps > first);
        controller.probe_admitted(600_000);
        assert!(!controller.decision(699_999).probe_due);
        assert!(controller.decision(700_000).probe_due);
        controller.eligible = false;
        assert!(!controller.decision(700_000).probe_due);
        controller.eligible = true;
        controller.last_control.probe_rtt_ms = Some(450.0);
        assert!(!controller.decision(700_000).probe_due);
        controller.last_control.probe_rtt_ms = Some(20.0);
        controller.last_control.offered_backlog = false;
        assert!(!controller.decision(700_000).probe_due);
        assert!(controller.decision(1_100_000).probe_due);
    }

    #[test]
    fn fast_growth_019_brakes_on_new_probe_queue_before_smoothed_quinn_rtt() {
        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = observation(0, 20.0);
        sample.delivery_sample_span_us = 100_000;
        sample.delivery_report_time_us = Some(100_000_000);
        sample.delivered_bps = Some(START_BPS as f64);
        controller.observe(&sample);
        exercise_budget(&mut controller, 0, CONTROL_US);
        sample.now_us = CONTROL_US;
        sample.report_number = 2;
        sample.delivered_bytes = 6400;
        sample.delivery_report_time_us = Some(100_200_000);
        sample.probe_sample_id = 2;
        controller.observe(&sample);
        let grown = controller.rate_bps;

        exercise_budget(&mut controller, CONTROL_US, CONTROL_US);
        sample.now_us = 400_000;
        sample.report_number = 3;
        sample.delivered_bytes += grown / 40;
        sample.delivery_report_time_us = Some(100_400_000);
        sample.delivered_bps = Some(grown as f64);
        sample.probe_sample_id = 3;
        sample.probe_rtt_ms = Some(40.0);
        sample.probe_latest_rtt_ms = Some(40.0);
        // Quinn is still20ms; the new real probe has gained20ms of queue.
        // The first observation of that rise must brake the fast search.
        controller.observe(&sample);
        assert!(controller.rate_bps < grown);
        assert_eq!(controller.last_control.selected_rtt_ms, Some(20.0));
        assert_eq!(controller.last_control.startup_probe_excess_ms, Some(20.0));
        assert_eq!(controller.last_control.queue_delay_ms, 20.0);
        assert!(matches!(
            controller.rate_changes.back().unwrap().reason,
            RateReason::QueueBrake
        ));
        assert!(controller.congestion_seen);
        assert!(controller.service_window.latest(sample.now_us).is_none());
        assert_eq!(controller.remembered_bps, 0.0);
        let braked = controller.rate_bps;
        // Entering caution cannot erase the queue while the same probe is
        // still the newest observation and Quinn remains at its old20ms.
        sample.now_us = 500_000;
        sample.probe_age_us = Some(100_000);
        controller.observe(&sample);
        assert_eq!(controller.last_control.queue_delay_ms, 20.0);
        assert!(controller.rate_bps <= braked);
        sample.now_us = 600_000;
        sample.probe_sample_id += 1;
        sample.probe_rtt_ms = Some(20.0);
        sample.probe_latest_rtt_ms = Some(20.0);
        sample.probe_age_us = Some(0);
        controller.observe(&sample);
        assert_eq!(controller.last_control.queue_delay_ms, 0.0);
        assert!(controller.startup_probe_pressure.is_none());
        controller.probe_admitted(600_000);
        assert!(!controller.decision(699_999).probe_due);
        // 032 has no new service endpoint here after the queue clears.
        // The existing 500ms health deadline remains independently available.
        assert!(!controller.decision(700_000).probe_due);
        assert!(!controller.decision(799_999).probe_due);
        assert!(!controller.decision(800_000).probe_due);
        assert!(controller.decision(1_100_000).probe_due);
    }

    #[test]
    fn fast_delivery_growth_018_requires_new_bytes_and_cannot_reuse_a_report() {
        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = observation(0, 20.0);
        sample.delivery_sample_span_us = 100_000;
        sample.delivery_report_time_us = Some(100_000_000);
        sample.delivered_bps = Some(START_BPS as f64);
        controller.observe(&sample);

        exercise_budget(&mut controller, 0, CONTROL_US);
        sample.now_us = CONTROL_US;
        sample.report_number = 2;
        sample.delivered_bytes = 6400;
        sample.delivery_report_time_us = Some(100_200_000);
        controller.observe(&sample);
        let first = controller.decision(sample.now_us).pacing_bps;
        assert!(first > START_BPS);

        // Neither replaying a fast report nor increasing only its number may
        // fund another step, even with backlog and an exercised allowance.
        for step in 2..=4 {
            let start = (step - 1) * CONTROL_US;
            exercise_budget(&mut controller, start, CONTROL_US);
            sample.now_us = step * CONTROL_US;
            sample.positive_delivery_age_us = Some(sample.now_us - CONTROL_US);
            if step == 4 {
                sample.report_number = 3;
                sample.delivery_report_time_us = Some(100_800_000);
                sample.positive_delivery_age_us = Some(0);
                sample.delivered_bps = Some(first as f64);
            }
            controller.observe(&sample);
            assert_eq!(controller.decision(sample.now_us).pacing_bps, first);
        }

        exercise_budget(&mut controller, 800_000, CONTROL_US);
        sample.now_us = 1_000_000;
        sample.report_number = 4;
        sample.delivered_bytes += first / 40;
        sample.delivery_report_time_us = Some(101_000_000);
        sample.probe_sample_id += 1;
        controller.observe(&sample);
        assert!(controller.decision(sample.now_us).pacing_bps > first);
    }

    #[test]
    fn fast_delivery_growth_018_does_not_override_queue_brakes_or_idle_demand() {
        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = observation(0, 20.0);
        sample.delivery_sample_span_us = 100_000;
        sample.delivery_report_time_us = Some(100_000_000);
        sample.delivered_bps = Some(START_BPS as f64);
        sample.offered_backlog = false;
        controller.observe(&sample);
        sample.now_us = CONTROL_US;
        sample.report_number = 2;
        sample.delivered_bytes = 64;
        sample.delivery_report_time_us = Some(100_200_000);
        controller.observe(&sample);
        assert_eq!(controller.decision(sample.now_us).pacing_bps, START_BPS);

        sample.offered_backlog = true;
        exercise_budget(&mut controller, CONTROL_US, CONTROL_US);
        sample.now_us = 400_000;
        sample.report_number = 3;
        sample.delivered_bytes += 6400;
        sample.delivery_report_time_us = Some(100_400_000);
        sample.rtt_ms = 120.0;
        sample.probe_rtt_ms = Some(120.0);
        sample.probe_latest_rtt_ms = Some(120.0);
        sample.probe_sample_id += 1;
        controller.observe(&sample);
        let braked = controller.decision(sample.now_us).pacing_bps;
        assert!(braked < START_BPS);
        assert!(matches!(
            controller.rate_changes.back().unwrap().reason,
            RateReason::QueueBrake
        ));

        // A new generation starts from the original bound; a previous fast
        // report cannot become initial-growth credit on the replacement path.
        sample.generation += 1;
        sample.now_us += 100_000;
        sample.report_number = 1;
        sample.delivered_bytes = 0;
        controller.observe(&sample);
        assert_eq!(controller.decision(sample.now_us).pacing_bps, START_BPS);
        assert!(controller.last_initial_growth_report.is_none());
    }

    fn weight_observation_016(
        now: u64,
        report: u64,
        expected: u64,
        lost: u64,
        loss_ewma: f64,
        rtt: f64,
    ) -> Observation {
        let mut sample = observation(now, rtt);
        sample.report_number = report;
        sample.finalized_expected = Some(expected);
        sample.finalized_lost = Some(lost);
        sample.loss_rate = loss_ewma;
        sample.offered_backlog = false;
        sample
    }

    #[test]
    fn weight_016_sparse_finalized_quality_changes_share_without_pacing_collapse() {
        let mut controller = PathController::new(8_000_000, 20);
        controller.observe(&weight_observation_016(0, 1, 32, 0, 0.0, 150.0));
        let clean = controller.decision(0);
        let mut sparse = weight_observation_016(5_000_000, 2, 36, 1, 0.25, 150.0);
        sparse.offered_backlog = true;
        controller.observe(&sparse);
        let impaired = controller.decision(sparse.now_us);
        assert_eq!(impaired.loss_evidence_expected, 4);
        assert_eq!(impaired.loss_evidence_lost, 1);
        assert!(impaired.weight < clean.weight);
        assert!(impaired.weight >= clean.weight / 4);
        assert_eq!(impaired.pacing_bps, clean.pacing_bps);
        assert_eq!(impaired.pacing_bps, START_BPS);
        assert!(impaired.eligible);
        assert!(!impaired.loss_pressure);
        assert!(!impaired.cautious);
        assert_eq!(impaired.queue_delay_ms, 0.0);
        assert_eq!(impaired.weight_loss_rate, Some(0.25));
        assert_eq!(impaired.weight_loss_report, Some(2));
        assert_eq!(impaired.weight_loss_age_us, Some(0));
    }

    #[test]
    fn weight_016_uses_original_evidence_age_even_in_a_younger_sender_epoch() {
        let mut controller = PathController::new(8_000_000, 20);
        controller.observe(&weight_observation_016(0, 1, 0, 0, 0.0, 150.0));
        let neutral = controller.decision(0).weight;
        let mut report = weight_observation_016(100_000, 2, 16, 4, 0.25, 150.0);
        report.feedback_age_us = Some(2_900_000);
        controller.observe(&report);
        let used = controller.decision(100_000);
        assert!(used.weight < neutral);
        assert_eq!(used.weight_loss_age_us, Some(2_900_000));
        // Reusing the report with a younger claimed age cannot refresh it.
        report.now_us = 150_000;
        report.feedback_age_us = Some(0);
        controller.observe(&report);
        assert_eq!(
            controller.decision(150_000).weight_loss_age_us,
            Some(2_950_000)
        );
        assert_eq!(
            controller.decision(200_000).weight_loss_age_us,
            Some(FRESH_US)
        );
        let expired = controller.decision(200_001);
        assert_eq!(expired.weight, neutral);
        assert_eq!(expired.weight_loss_rate, None);
        assert_eq!(expired.weight_loss_report, None);
        assert_eq!(expired.weight_loss_age_us, None);
        assert_eq!(expired.weight_loss_effective_rate, None);
        assert_eq!(expired.weight_loss_window_expected, None);
        assert_eq!(expired.weight_loss_window_lost, None);
        assert_eq!(expired.weight_loss_window_oldest_age_us, None);
    }

    #[test]
    fn weight_016_only_valid_nonempty_finalized_intervals_refresh_quality() {
        for condition in [
            "duplicate",
            "reordered",
            "empty",
            "byte_only",
            "probe_only",
            "stale",
            "nan",
            "negative",
            "above_one",
            "regressed",
            "lost_above_expected",
            "lost_delta_above_expected",
            "missing_expected",
            "missing_lost",
            "legacy",
        ] {
            let mut controller = PathController::new(8_000_000, 20);
            controller.observe(&weight_observation_016(0, 1, 0, 0, 0.0, 150.0));
            controller.observe(&weight_observation_016(100_000, 2, 16, 4, 0.25, 150.0));
            let mut report = weight_observation_016(1_000_000, 3, 20, 5, 0.0, 150.0);
            match condition {
                "duplicate" => report.report_number = 2,
                "reordered" => report.report_number = 1,
                "empty" | "byte_only" => {
                    report.finalized_expected = Some(16);
                    report.finalized_lost = Some(4);
                    report.feedback_sample_symbols = 0;
                    if condition == "byte_only" {
                        report.delivered_bytes = 100_000;
                    }
                }
                "probe_only" => {
                    report.feedback_age_us = None;
                    report.positive_delivery_age_us = None;
                }
                "stale" => report.feedback_age_us = Some(FRESH_US + 1),
                "nan" => report.loss_rate = f64::NAN,
                "negative" => report.loss_rate = -0.1,
                "above_one" => report.loss_rate = 1.1,
                "regressed" => report.finalized_expected = Some(15),
                "lost_above_expected" => report.finalized_lost = Some(21),
                "lost_delta_above_expected" => {
                    report.finalized_expected = Some(17);
                    report.finalized_lost = Some(6);
                }
                "missing_expected" => report.finalized_expected = None,
                "missing_lost" => report.finalized_lost = None,
                "legacy" => {
                    report.finalized_expected = None;
                    report.finalized_lost = None;
                    report.feedback_sample_symbols = 32;
                    report.loss_sample_rate = Some(0.0);
                }
                _ => unreachable!(),
            }
            controller.observe(&report);
            let decision = controller.decision(report.now_us);
            assert_eq!(decision.weight_loss_report, Some(2), "{condition}");
            assert_eq!(decision.weight_loss_rate, Some(0.25), "{condition}");
            assert_eq!(decision.weight_loss_age_us, Some(900_000), "{condition}");
            assert_eq!(
                decision.weight_loss_effective_rate,
                Some(0.25),
                "{condition}"
            );
            assert_eq!(
                decision.weight_loss_window_expected,
                Some(16),
                "{condition}"
            );
            assert_eq!(decision.weight_loss_window_lost, Some(4), "{condition}");
            assert_eq!(
                decision.weight_loss_window_oldest_age_us,
                Some(900_000),
                "{condition}"
            );
            assert_eq!(
                controller.decision(3_100_001).weight_loss_rate,
                None,
                "{condition}"
            );
        }
    }

    #[test]
    fn weight_016_requires_cumulative_maturity_and_resets_or_recovers_quality() {
        for legacy in [false, true] {
            let mut controller = PathController::new(8_000_000, 20);
            controller.observe(&weight_observation_016(0, 1, 0, 0, 0.0, 150.0));
            let clean = controller.decision(0).weight;
            let mut report = weight_observation_016(100_000, 2, 15, 4, 0.25, 150.0);
            if legacy {
                report.finalized_expected = None;
                report.finalized_lost = None;
                report.feedback_sample_symbols = 32;
                report.loss_sample_rate = Some(0.25);
            }
            controller.observe(&report);
            assert_eq!(controller.decision(report.now_us).weight, clean);
            assert_eq!(controller.decision(report.now_us).weight_loss_report, None);
        }
        let mut controller = PathController::new(8_000_000, 20);
        controller.observe(&weight_observation_016(0, 1, 32, 8, 0.25, 150.0));
        let bad = controller.decision(0).weight;
        controller.observe(&weight_observation_016(500_000, 2, 36, 8, 0.0, 150.0));
        let recovered = controller.decision(500_000);
        assert!(recovered.weight > bad);
        assert_eq!(recovered.weight_loss_rate, Some(0.0));
        assert_eq!(recovered.weight_loss_report, Some(2));
        let mut next = weight_observation_016(600_000, 0, 0, 0, 0.0, 150.0);
        next.generation += 1;
        controller.observe(&next);
        let reset = controller.decision(next.now_us);
        assert_eq!(reset.weight_loss_report, None);
        assert_eq!(reset.weight_loss_effective_rate, None);
        assert_eq!(reset.weight_loss_window_expected, None);
        assert_eq!(reset.weight_loss_window_lost, None);
        assert_eq!(reset.weight_loss_window_oldest_age_us, None);
        // A new generation is neutral; four clean symbols in the old generation
        // did not yet replace the impaired whole report batch.
        assert_eq!(reset.weight, 16);
        assert!(reset.weight > recovered.weight);
        assert_eq!(reset.pacing_bps, START_BPS);
        let mut worst = weight_observation_016(700_000, 1, 32, 32, 1.0, 150.0);
        worst.generation = next.generation;
        controller.observe(&worst);
        assert_eq!(controller.decision(worst.now_us).weight, reset.weight / 4);
        assert!(controller.decision(worst.now_us).weight > 0);
    }

    #[test]
    fn weight_017_retains_whole_batches_until_enough_clean_symbols_replace_them() {
        let mut controller = PathController::new(8_000_000, 20);
        controller.observe(&weight_observation_016(0, 1, 0, 0, 0.0, 150.0));
        let neutral = controller.decision(0).weight;
        controller.observe(&weight_observation_016(100_000, 2, 32, 8, 0.25, 150.0));
        for clean_batches in 1..=4 {
            let now = 100_000 + clean_batches * 1_100_000;
            controller.observe(&weight_observation_016(
                now,
                2 + clean_batches,
                32 + clean_batches * 4,
                8,
                0.0,
                150.0,
            ));
            let decision = controller.decision(now);
            assert_eq!(decision.weight_loss_rate, Some(0.0));
            assert_eq!(decision.weight_loss_age_us, Some(0));
            assert_eq!(decision.pacing_bps, START_BPS);
            if clean_batches < 4 {
                let expected = 32 + clean_batches * 4;
                assert_eq!(decision.weight_loss_window_expected, Some(expected));
                assert_eq!(decision.weight_loss_window_lost, Some(8));
                assert_eq!(
                    decision.weight_loss_effective_rate,
                    Some(8.0 / expected as f64)
                );
                assert_eq!(
                    decision.weight_loss_window_oldest_age_us,
                    Some(clean_batches * 1_100_000)
                );
                assert!(decision.weight < neutral);
            } else {
                assert_eq!(decision.weight_loss_window_expected, Some(16));
                assert_eq!(decision.weight_loss_window_lost, Some(0));
                assert_eq!(decision.weight_loss_effective_rate, Some(0.0));
                assert_eq!(decision.weight, neutral);
                assert_eq!(decision.weight_loss_window_oldest_age_us, Some(3_300_000));
            }
        }
    }

    #[test]
    fn weight_017_collects_pre_maturity_symbols_with_bounded_history_and_fast_deterioration() {
        let mut controller = PathController::new(8_000_000, 20);
        controller.observe(&weight_observation_016(0, 1, 0, 0, 0.0, 150.0));
        let neutral = controller.decision(0).weight;
        for expected in 1..=64 {
            let now = expected * 100_000;
            controller.observe(&weight_observation_016(
                now,
                expected + 1,
                expected,
                1,
                0.0,
                150.0,
            ));
            let decision = controller.decision(now);
            assert!(controller.weight_window.batches.len() <= 16);
            if expected < 16 {
                assert_eq!(decision.weight_loss_rate, None);
                assert_eq!(decision.weight_loss_effective_rate, None);
                assert_eq!(decision.weight_loss_window_expected, None);
                assert_eq!(decision.weight, neutral);
            } else {
                assert_eq!(decision.weight_loss_window_expected, Some(16));
                assert_eq!(
                    decision.weight_loss_window_lost,
                    Some(u64::from(expected == 16))
                );
                if expected == 16 {
                    assert_eq!(decision.weight_loss_rate, Some(0.0));
                    assert_eq!(decision.weight_loss_effective_rate, Some(1.0 / 16.0));
                    assert!(decision.weight < neutral);
                } else {
                    assert_eq!(decision.weight_loss_effective_rate, Some(0.0));
                    assert_eq!(decision.weight, neutral);
                }
            }
            assert_eq!(decision.pacing_bps, START_BPS);
        }
        controller.observe(&weight_observation_016(6_500_000, 66, 65, 2, 1.0, 150.0));
        let worse = controller.decision(6_500_000);
        assert_eq!(worse.weight_loss_window_expected, Some(16));
        assert_eq!(worse.weight_loss_window_lost, Some(1));
        assert_eq!(worse.weight_loss_effective_rate, Some(1.0));
        assert_eq!(worse.weight, neutral / 4);
        assert_eq!(worse.pacing_bps, START_BPS);
    }

    #[test]
    fn weight_017_expires_pre_maturity_history_by_original_age_before_accepting_a_new_batch() {
        let mut controller = PathController::new(8_000_000, 20);
        controller.observe(&weight_observation_016(0, 1, 0, 0, 0.0, 150.0));
        let neutral = controller.decision(0).weight;
        let mut early = weight_observation_016(100_000, 2, 15, 7, 7.0 / 15.0, 150.0);
        early.feedback_age_us = Some(2_900_000);
        controller.observe(&early);
        assert_eq!(controller.decision(100_000).weight_loss_rate, None);
        assert_eq!(controller.weight_window.expected, 15);
        early.now_us = 150_000;
        early.feedback_age_us = Some(0);
        controller.observe(&early);
        controller.observe(&weight_observation_016(200_001, 3, 16, 7, 0.0, 150.0));
        let fresh = controller.decision(200_001);
        assert_eq!(fresh.weight_loss_report, Some(3));
        assert_eq!(fresh.weight_loss_window_expected, Some(1));
        assert_eq!(fresh.weight_loss_window_lost, Some(0));
        assert_eq!(fresh.weight_loss_window_oldest_age_us, Some(0));
        assert_eq!(fresh.weight_loss_effective_rate, Some(0.0));
        assert_eq!(fresh.weight, neutral);

        let expired = controller.decision(3_200_002);
        assert_eq!(expired.weight_loss_rate, None);
        assert_eq!(expired.weight_loss_effective_rate, None);
        assert_eq!(expired.weight_loss_window_expected, None);
        controller.observe(&weight_observation_016(3_200_003, 4, 32, 15, 0.0, 150.0));
        let resumed = controller.decision(3_200_003);
        assert_eq!(resumed.weight_loss_window_expected, Some(16));
        assert_eq!(resumed.weight_loss_window_lost, Some(8));
        assert_eq!(resumed.weight_loss_window_oldest_age_us, Some(0));
        assert_eq!(resumed.weight_loss_effective_rate, Some(0.5));
        assert_eq!(resumed.weight, neutral / 4);
        assert_eq!(resumed.pacing_bps, START_BPS);
    }

    #[test]
    fn weight_016_sparse_multipath_schedule_reduces_and_restores_damaged_share() {
        use crate::runtime::scheduler::Scheduler;
        fn choose(scheduler: &mut Scheduler, weights: &[(u8, i32)]) -> [usize; 4] {
            let mut counts = [0; 4];
            for _ in 0..700 {
                let accepted = scheduler.order(weights, 128)[0];
                scheduler.commit(weights, accepted, 128);
                counts[usize::from(accepted)] += 1;
            }
            assert_eq!(counts.iter().sum::<usize>(), 700);
            counts
        }
        let mut paths: [PathController; 4] = std::array::from_fn(|id| {
            let mut path = PathController::new(8_000_000, 20);
            let rtt = if id == 1 { 150.0 } else { 50.0 };
            path.observe(&weight_observation_016(0, 1, 32, 0, 0.0, rtt));
            path
        });
        let weights = |paths: &[PathController; 4], now| {
            paths
                .iter()
                .enumerate()
                .map(|(id, p)| (id as u8, p.decision(now).weight))
                .collect::<Vec<_>>()
        };
        let mut scheduler = Scheduler::default();
        let initial_weights = weights(&paths, 0);
        let initial = choose(&mut scheduler, &initial_weights);
        for (id, path) in paths.iter_mut().enumerate() {
            path.observe(&weight_observation_016(
                5_000_000,
                2,
                36,
                u64::from(id == 1),
                if id == 1 { 0.25 } else { 0.0 },
                if id == 1 { 150.0 } else { 50.0 },
            ));
            assert_eq!(path.decision(5_000_000).pacing_bps, START_BPS);
            assert!(path.decision(5_000_000).eligible);
        }
        let impaired = choose(&mut scheduler, &weights(&paths, 5_000_000));
        assert!(impaired[1] > 0);
        assert!(impaired[1] < initial[1] / 2);
        for (id, path) in paths.iter_mut().enumerate() {
            path.observe(&weight_observation_016(
                5_500_000,
                3,
                40,
                u64::from(id == 1),
                0.0,
                if id == 1 { 150.0 } else { 50.0 },
            ));
        }
        let restored_weights = weights(&paths, 5_500_000);
        assert_eq!(restored_weights, initial_weights);
        let restored = choose(&mut scheduler, &restored_weights);
        assert!(restored[1].abs_diff(initial[1]) <= 1);
        eprintln!(
            "016 sparse fixed-quality selection populations: initial={initial:?}, impaired={impaired:?}, restored={restored:?}; 700 requests each"
        );
    }

    fn rtt_evidence_observation(
        now: u64,
        local: f64,
        probe: Option<(u64, f64, u64)>,
    ) -> Observation {
        let mut sample = observation(now, local);
        sample.feedback_sample_symbols = 0;
        sample.delivered_bps = Some(START_BPS as f64);
        sample.probe_sample_id = probe.map_or(0, |(id, _, _)| id);
        sample.probe_rtt_ms = probe.map(|(_, rtt, _)| rtt);
        sample.probe_latest_rtt_ms = sample.probe_rtt_ms;
        sample.probe_age_us = probe.map(|(_, _, age)| age);
        sample
    }

    #[test]
    fn rtt_evidence_012_records_the_existing_mixed_baseline_brake_without_fixing_it() {
        let mut controller = PathController::new(START_BPS, 20);
        controller.observe(&rtt_evidence_observation(0, 100.0, Some((1, 80.0, 0))));
        controller.observe(&rtt_evidence_observation(
            600_000,
            100.0,
            Some((1, 80.0, 600_000)),
        ));
        assert_eq!(controller.last_control.selected_rtt_ms, Some(100.0));
        assert!(controller.last_control.new_rtt);
        assert!(!controller.last_control.new_probe);
        assert!(controller.last_control.new_queue);
        controller.observe(&rtt_evidence_observation(
            700_000,
            100.0,
            Some((1, 80.0, 700_000)),
        ));
        // The known 009-r3 defect remains: stable estimators with different
        // offsets still create 20ms of mixed-baseline pressure and a brake.
        assert_eq!(controller.rate_bps, 236_800);
        let event = controller.rate_changes.back().unwrap();
        assert_eq!(event.at_us, 700_000);
        assert!(matches!(event.reason, RateReason::QueueBrake));
        let sample = &event.control;
        assert_eq!(sample.at_us, event.at_us);
        assert_eq!(sample.local_rtt_ms, Some(100.0));
        assert_eq!(sample.probe_rtt_ms, Some(80.0));
        assert_eq!(sample.probe_sample_id, 1);
        assert_eq!(sample.probe_age_us, Some(700_000));
        assert_eq!(sample.selected_rtt_ms, Some(100.0));
        assert_eq!(sample.rtt_source, RttSource::Quinn);
        assert_eq!(sample.mixed_min_rtt_ms, Some(80.0));
        assert_eq!(sample.rtt_excess_ms, 20.0);
        assert_eq!(sample.transport_wait_ms, 0.0);
        assert_eq!(sample.queue_delay_ms, 20.0);
        assert_eq!(sample.observed_local_min_rtt_ms, Some(100.0));
        assert_eq!(sample.observed_probe_min_rtt_ms, Some(80.0));
        assert!(sample.rtt_fresh && sample.probe_fresh && sample.delivery_fresh);
        assert!(!sample.new_rtt && !sample.new_probe && !sample.new_queue);
    }

    #[test]
    fn rtt_evidence_012_keeps_unknown_stale_and_generation_fields_faithful() {
        let mut controller = PathController::new(START_BPS, 20);
        controller.observe(&rtt_evidence_observation(0, 100.0, None));
        assert_eq!(controller.last_control.probe_rtt_ms, None);
        assert_eq!(controller.last_control.probe_age_us, None);
        assert_eq!(controller.last_control.observed_probe_min_rtt_ms, None);
        assert_eq!(controller.last_control.rtt_source, RttSource::Quinn);
        assert!(!controller.last_control.probe_fresh);
        let mut stale =
            rtt_evidence_observation(4_000_000, f64::NAN, Some((7, 20.0, FRESH_US + 1)));
        stale.positive_delivery_age_us = Some(FRESH_US + 1);
        controller.observe(&stale);
        let sample = &controller.last_control;
        assert_eq!(sample.local_rtt_ms, None);
        assert_eq!(sample.probe_rtt_ms, Some(20.0));
        assert_eq!(sample.probe_sample_id, 7);
        assert_eq!(sample.probe_age_us, Some(FRESH_US + 1));
        assert_eq!(sample.selected_rtt_ms, None);
        assert_eq!(sample.rtt_source, RttSource::Unavailable);
        assert_eq!(sample.mixed_min_rtt_ms, Some(100.0));
        assert_eq!(sample.rtt_excess_ms, 0.0);
        assert_eq!(sample.observed_local_min_rtt_ms, Some(100.0));
        assert_eq!(sample.observed_probe_min_rtt_ms, None);
        assert!(!sample.rtt_fresh && !sample.probe_fresh && !sample.delivery_fresh);
        assert!(!sample.new_rtt && !sample.new_probe && !sample.new_queue);
        let mut next = rtt_evidence_observation(4_500_000, 220.0, Some((1, 200.0, 0)));
        next.generation += 1;
        controller.observe(&next);
        let sample = &controller.last_control;
        assert_eq!(sample.generation, next.generation);
        assert_eq!(sample.observed_local_min_rtt_ms, Some(220.0));
        assert_eq!(sample.observed_probe_min_rtt_ms, Some(200.0));
        assert_eq!(sample.mixed_min_rtt_ms, Some(200.0));
        assert_eq!(sample.selected_rtt_ms, Some(200.0));
        assert_eq!(sample.rtt_source, RttSource::Probe);
        assert_eq!(sample.rtt_excess_ms, 0.0);
        assert!(sample.new_rtt && sample.new_probe && sample.new_queue);
    }

    #[test]
    fn rtt_evidence_012_records_transport_pressure_and_original_event_flags() {
        let mut controller = PathController::new(START_BPS, 20);
        controller.observe(&rtt_evidence_observation(0, 100.0, Some((1, 100.0, 0))));
        assert_eq!(controller.last_control.rtt_source, RttSource::Quinn);
        let mut queued = rtt_evidence_observation(500_000, 100.0, Some((2, 100.0, 0)));
        queued.send_queue_bytes = 5000;
        controller.observe(&queued);
        let event = controller.rate_changes.back().unwrap();
        assert!(matches!(event.reason, RateReason::QueueBrake));
        assert_eq!(event.control.selected_rtt_ms, Some(100.0));
        assert_eq!(event.control.mixed_min_rtt_ms, Some(100.0));
        assert_eq!(event.control.rtt_excess_ms, 0.0);
        assert_eq!(event.control.transport_wait_ms, 81.25);
        assert_eq!(event.control.queue_delay_ms, 81.25);
        assert!(!event.control.new_rtt);
        assert!(event.control.new_probe && event.control.new_queue);
        let event_count = controller.rate_changes_total;
        queued.now_us = 600_000;
        queued.probe_age_us = Some(100_000);
        controller.observe(&queued);
        assert!(!controller.last_control.new_rtt);
        assert!(!controller.last_control.new_probe);
        assert!(!controller.last_control.new_queue);
        assert_eq!(controller.last_control.rtt_excess_ms, 0.0);
        assert_eq!(controller.last_control.transport_wait_ms, 81.25);
        assert_eq!(controller.rate_changes_total, event_count);
    }

    #[test]
    fn rtt_evidence_012_observed_minima_cannot_change_control_or_admission() {
        let mut ordinary = PathController::new(2_000_000, 20);
        let mut changed_diagnostics = PathController::new(2_000_000, 20);
        let initial = rtt_evidence_observation(0, 100.0, Some((1, 80.0, 0)));
        ordinary.observe(&initial);
        changed_diagnostics.observe(&initial);
        for now in (100_000..=2_000_000).step_by(100_000) {
            let pressure = (500_000..1_000_000).contains(&now);
            let local = if pressure { 140.0 } else { 100.0 };
            let raw = if pressure { 120.0 } else { 80.0 };
            let mut sample =
                rtt_evidence_observation(now, local, Some((now / 500_000 + 1, raw, now % 500_000)));
            sample.send_queue_bytes = if now >= 1_500_000 { 5000 } else { 0 };
            // Deliberately poison only the two diagnostic scalars. No selected
            // minimum, event, weight, queue, pace or eligibility may read them.
            changed_diagnostics.observed_local_min_rtt_ms = Some(0.001);
            changed_diagnostics.observed_probe_min_rtt_ms = Some(50_000.0);
            ordinary.observe(&sample);
            changed_diagnostics.observe(&sample);
            assert_eq!(
                serde_json::to_value(ordinary.decision(now)).unwrap(),
                serde_json::to_value(changed_diagnostics.decision(now)).unwrap(),
                "{now}"
            );
            assert_eq!(
                ordinary.rate_changes_total,
                changed_diagnostics.rate_changes_total
            );
            let allowed = ordinary.allow(now, 1000, 0.0);
            assert_eq!(allowed, changed_diagnostics.allow(now, 1000, 0.0));
            if allowed {
                ordinary.admitted(now, 1000);
                changed_diagnostics.admitted(now, 1000);
            }
        }
    }

    /// Actual token admission with a separate deterministic 20% erasure sink.
    /// Receiver clocks deliberately have an unrelated offset. This helper stops
    /// at the first granted trial so each safety test exercises a real baseline.
    fn granted_reprobe() -> (PathController, u64, u64) {
        let mut controller = PathController::new(20_000_000, 20);
        let mut admitted = 0u64;
        let mut previous_received = 0u64;
        let mut sample = observation(0, 80.0);
        sample.reprobe_enabled = true;
        sample.report_number = 0;
        sample.delivered_bytes = 0;
        sample.finalized_expected = Some(0);
        sample.finalized_lost = Some(0);
        controller.observe(&sample);
        for now in (100_000..20_000_000u64).step_by(100_000) {
            admitted += exercise_budget(&mut controller, now - 100_000, 100_000);
            sample.now_us = now;
            sample.probe_age_us = Some(now % PROBE_US);
            sample.probe_sample_id = now / PROBE_US + 1;
            if now.is_multiple_of(PROBE_US) {
                let sent = admitted / 1000;
                let received = (sent - sent / 5) * 1000;
                sample.report_number += 1;
                sample.delivered_bps = Some((received - previous_received) as f64 * 16.0);
                sample.delivered_bytes = received;
                sample.delivery_report_time_us = Some(8_000_000_000 + now);
                sample.delivery_sample_span_us = PROBE_US;
                sample.feedback_sample_symbols = 32;
                sample.finalized_expected = Some(sent);
                sample.finalized_lost = Some(sent / 5);
                sample.loss_sample_rate = Some(0.2);
                previous_received = received;
            }
            sample.feedback_age_us = Some(now % PROBE_US);
            sample.positive_delivery_age_us = Some(now % PROBE_US);
            controller.observe(&sample);
            if let Some(request) = controller.reprobe_candidate(now) {
                assert!(!controller.start_reprobe(now, request.trial_bps - 1));
                assert!(controller.start_reprobe(now, request.trial_bps));
                assert!(controller.reprobe_active());
                return (controller, now, request.baseline_bps);
            }
        }
        panic!("fully used low-queue erasure path did not offer a bounded trial");
    }

    #[test]
    fn short_byte_feedback_does_not_cancel_positive_service_validated_reprobes() {
        let mut controller = PathController::new(20_000_000, 20);
        let mut sample = short_observation_022(0, 80.0);
        sample.reprobe_enabled = true;
        sample.report_number = 0;
        sample.delivered_bytes = 0;
        sample.admitted_symbol_bytes = Some(0);
        sample.admitted_symbols = Some(0);
        sample.finalized_expected = Some(0);
        sample.finalized_lost = Some(0);
        controller.observe(&sample);
        let mut admitted = 0;
        let mut received = 0;
        let mut confirmed_trials = 0;
        let mut last_transition = 0;
        let mut positive_at = 0;
        for now in (100_000..=30_000_000).step_by(100_000) {
            controller.probe_admitted(now - 100_000);
            admitted += exercise_budget(&mut controller, now - 100_000, 100_000);
            let sent = admitted / 1000;
            let next_received = (sent - sent / 5) * 1000;
            sample.now_us = now;
            sample.report_number += 1;
            sample.delivery_report_time_us = Some(8_000_000_000 + now);
            sample.delivery_sample_span_us = 100_000;
            sample.delivered_bytes = next_received;
            sample.delivered_bps = Some((next_received - received) as f64 * 80.0);
            sample.admitted_symbol_bytes = Some(admitted);
            sample.admitted_symbols = Some(sent);
            sample.probe_sample_id += 1;
            sample.probe_age_us = Some(20_000);
            if next_received > received {
                positive_at = now;
            }
            sample.positive_delivery_age_us = Some(now - positive_at);
            sample.feedback_age_us = Some(now % PROBE_US);
            if now % PROBE_US == 0 {
                let previous = sample.finalized_expected.unwrap();
                sample.finalized_expected = Some(sent);
                sample.finalized_lost = Some(sent / 5);
                sample.feedback_sample_symbols = sent - previous;
                sample.loss_sample_rate = Some(0.2);
            } else {
                sample.feedback_sample_symbols = 0;
                sample.loss_sample_rate = None;
            }
            received = next_received;
            controller.observe(&sample);
            if let Some(request) = controller.reprobe_candidate(now) {
                assert!(controller.start_reprobe(now, request.trial_bps));
            }
            let snapshot = controller.reprobe.snapshot();
            for event in &snapshot.transitions {
                if event.number > last_transition
                    && event.reason == reprobe::Reason::ServiceImproved
                {
                    confirmed_trials += 1;
                    assert!(
                        event.measured_symbol_bps.unwrap() > event.baseline_symbol_bps.unwrap()
                    );
                    assert!(event.receiver_span_us >= 1_500_000);
                }
            }
            last_transition = snapshot.total_transitions;
        }
        assert!(
            confirmed_trials >= 3,
            "positive measured service must allow repeated bounded recovery; confirmed={confirmed_trials}, pace={}",
            controller.rate_bps
        );
        assert!(
            controller.rate_bps > START_BPS,
            "a measured erasure path must not remain pinned to the floor"
        );
    }

    fn fresh_after_trial(controller: &PathController, now: u64) -> Observation {
        let (number, bytes, _) = controller.last_report.unwrap();
        let (expected, lost) = controller.loss_evidence.previous.unwrap();
        Observation {
            now_us: now,
            report_number: number + 1,
            delivered_bytes: bytes + 10_000,
            delivered_bps: Some(160_000.0),
            delivery_report_time_us: Some(
                controller.last_control.delivery_report_time_us.unwrap() + PROBE_US,
            ),
            delivery_sample_span_us: PROBE_US,
            reprobe_enabled: true,
            finalized_expected: Some(expected + 16),
            finalized_lost: Some(lost + 3),
            feedback_sample_symbols: 16,
            loss_sample_rate: Some(3.0 / 16.0),
            ..observation(now, 80.0)
        }
    }

    #[test]
    fn reprobe_protection_cannot_hide_a_paired_zero_service_deficit() {
        let (mut controller, started, _) = granted_reprobe();
        let trial_rate = controller.rate_bps;
        let (number, received, _) = controller.last_report.unwrap();
        let (expected, lost) = controller.loss_evidence.previous.unwrap();
        let receiver_us = controller.last_control.delivery_report_time_us.unwrap();
        let mut admitted = expected * 1000;
        let mut braked = false;
        for step in 1..=12 {
            let now = started + step * 100_000;
            controller.probe_admitted(now - 100_000);
            admitted += exercise_budget(&mut controller, now - 100_000, 100_000);
            let mut sample = short_observation_022(now, 80.0);
            sample.reprobe_enabled = true;
            sample.probe_age_us = Some(20_000);
            sample.report_number = number + step;
            // A real positive short report activates the byte-feedback API;
            // all subsequent successfully admitted symbols are missing.
            sample.delivered_bytes = received + 2000;
            sample.delivered_bps = Some(if step == 1 { 160_000.0 } else { 0.0 });
            sample.delivery_report_time_us = Some(receiver_us + step * 100_000);
            sample.admitted_symbols = Some(admitted / 1000);
            sample.admitted_symbol_bytes = Some(admitted);
            sample.finalized_expected = Some(expected);
            sample.finalized_lost = Some(lost);
            sample.feedback_sample_symbols = 0;
            sample.loss_sample_rate = None;
            sample.positive_delivery_age_us = Some((step - 1) * 100_000);
            controller.observe(&sample);
            braked |= controller.rate_changes.back().is_some_and(|event| {
                event.at_us == now
                    && matches!(event.reason, RateReason::DeliveryShortfallBrake)
                    && event.control.service_symbol_delivery_bps == Some(0.0)
                    && event
                        .control
                        .service_admission
                        .as_ref()
                        .is_some_and(|a| a.deficit)
            });
        }
        assert!(
            braked,
            "a bounded trial must not shield fully missing current service"
        );
        assert!(controller.rate_bps < trial_rate);
        assert!(!controller.reprobe_active());
    }

    #[test]
    fn reprobe_009_hard_queue_fast_loss_and_disable_remove_trial_before_next_admission() {
        for condition in ["queue", "loss", "disable"] {
            let (mut controller, started, baseline) = granted_reprobe();
            let mut sample = fresh_after_trial(&controller, started + 100_000);
            match condition {
                "queue" => {
                    sample.rtt_ms = 120.0;
                    sample.probe_rtt_ms = Some(120.0);
                    sample.probe_latest_rtt_ms = Some(120.0);
                    sample.probe_sample_id += 1;
                }
                "loss" => {
                    let (_, lost) = controller.loss_evidence.previous.unwrap();
                    sample.finalized_lost = Some(lost + 16);
                    sample.loss_sample_rate = Some(1.0);
                }
                _ => sample.reprobe_enabled = false,
            }
            controller.observe(&sample);
            assert!(!controller.reprobe_active(), "{condition}");
            assert!(
                controller.rate_bps <= baseline,
                "rollback raised a braked rate: {condition}"
            );
            assert!(controller.reprobe_candidate(sample.now_us).is_none());
        }
    }

    #[test]
    fn reprobe_009_persistent_transport_blocking_aborts_trial() {
        let (mut controller, started, baseline) = granted_reprobe();
        for offset in [100_000, 200_000] {
            let mut sample = fresh_after_trial(&controller, started + offset);
            sample.delivered_bps = Some(0.0);
            sample.transport_blocked = true;
            controller.observe(&sample);
        }
        assert!(!controller.reprobe_active());
        assert!(controller.rate_bps <= baseline);
        assert!(
            controller
                .snapshot(started + 200_000)
                .reprobe
                .transitions
                .iter()
                .any(|event| { event.reason == reprobe::Reason::TransportBlocked })
        );
    }

    #[test]
    fn reprobe_009_duplicate_reports_cannot_validate_and_allow_cannot_extend_deadline() {
        let (mut controller, started, baseline) = granted_reprobe();
        let old_report = controller.last_report.unwrap().0;
        for offset in (100_000..4_000_000u64).step_by(100_000) {
            let mut sample = fresh_after_trial(&controller, started + offset);
            sample.report_number = old_report;
            sample.delivered_bps = Some(100_000_000.0);
            // Replayed or reordered evidence cannot become a successful trial
            // even if an independent authenticated probe keeps the path healthy.
            controller.observe(&sample);
        }
        let _ = controller.allow(started + 4_000_000, 1000, 0.0);
        assert!(!controller.reprobe_active());
        assert!(controller.rate_bps <= baseline);
        assert!(
            !controller
                .snapshot(started + 4_000_000)
                .reprobe
                .transitions
                .iter()
                .any(|event| { event.reason == reprobe::Reason::ServiceImproved })
        );

        let (mut controller, started, baseline) = granted_reprobe();
        // No observe calls at all: refill itself still withdraws finite credit.
        let _ = controller.allow(started + 4_100_000, 1000, 0.0);
        assert!(!controller.reprobe_active());
        assert!(controller.rate_bps <= baseline);
    }

    #[test]
    fn reprobe_009_generation_reset_discards_trial_and_its_service_reference() {
        let (mut controller, started, _) = granted_reprobe();
        let mut sample = observation(started + 100_000, 80.0);
        sample.generation += 1;
        sample.reprobe_enabled = true;
        controller.observe(&sample);
        assert!(!controller.reprobe_active());
        assert_eq!(controller.rate_bps, START_BPS);
        assert_eq!(
            controller.snapshot(sample.now_us).reprobe.total_transitions,
            0
        );
        assert!(controller.reprobe_candidate(sample.now_us).is_none());
    }

    #[test]
    fn reprobe_009_expiry_rollback_does_not_debounce_same_observation_safety_brake() {
        let (mut controller, started, baseline) = granted_reprobe();
        assert!(baseline > MIN_BPS);
        let mut sample = fresh_after_trial(&controller, started + 4_000_000);
        let (_, lost) = controller.loss_evidence.previous.unwrap();
        sample.finalized_lost = Some(lost + 16);
        sample.loss_sample_rate = Some(1.0);
        controller.observe(&sample);
        assert!(!controller.reprobe_active());
        assert!(
            controller.rate_bps < baseline,
            "expiry cannot consume the real brake's debounce interval"
        );
        assert!(matches!(
            controller.rate_changes.back().unwrap().reason,
            RateReason::FastLossBrake
        ));
    }

    fn finalized(now: u64, number: u64, expected: u64, lost: u64) -> Observation {
        Observation {
            report_number: number,
            finalized_expected: Some(expected),
            finalized_lost: Some(lost),
            ..observation(now, 80.0)
        }
    }

    #[test]
    fn delivery_freshness_008_accepts_positive_bytes_before_loss_finalizes() {
        use crate::runtime::quality::{Report, State};

        let mut quality = State::new(7);
        let mut controller = PathController::new(3_000_000, 20);
        let sample = |quality: &State, now_us| {
            let estimate = &quality.snapshot.sender_estimate;
            Observation {
                generation: quality.snapshot.generation,
                report_number: estimate.report_number,
                feedback_age_us: estimate.updated_us.map(|at| now_us - at),
                positive_delivery_age_us: estimate.delivered_updated_us.map(|at| now_us - at),
                delivered_bytes: estimate.received_bytes,
                delivered_bps: estimate.delivered_bps,
                feedback_sample_symbols: estimate.sample_symbols,
                finalized_expected: Some(estimate.expected),
                finalized_lost: Some(estimate.lost),
                loss_sample_rate: Some(estimate.sample_loss_rate),
                offered_backlog: false,
                ..observation(now_us, 80.0)
            }
        };
        quality.admitted(1000);
        let mut report = Report {
            id: 0,
            generation: 7,
            sent: 0,
            number: 1,
            expected: 1,
            received: 1,
            delay_us: 0,
            received_bytes: 1000,
            report_time_us: 500_000,
        };
        quality.apply(&report, 500_000).unwrap();
        controller.observe(&sample(&quality, 500_000));
        for (number, now) in [(2, 1_000_000), (3, 6_000_000)] {
            report.number = number;
            report.report_time_us = now;
            quality.apply(&report, now).unwrap();
            controller.observe(&sample(&quality, now));
        }
        let admitted = exercise_budget(&mut controller, 6_000_000, 500_000);
        for _ in 0..admitted / 1000 {
            quality.admitted(1000);
        }
        // Like007c after idle, unique bytes are delivered immediately while the
        // sequence prefix has not finalized any new symbols. Use real Quality
        // timestamps/deltas rather than assigning an invented fresh loss age.
        report.number = 4;
        report.report_time_us = 6_500_000;
        report.received_bytes += admitted;
        quality.apply(&report, 6_500_000).unwrap();
        let mut current = sample(&quality, 6_500_000);
        current.offered_backlog = true;
        assert_eq!(current.feedback_sample_symbols, 0);
        assert_eq!(current.feedback_age_us, Some(6_000_000));
        assert_eq!(current.positive_delivery_age_us, Some(0));
        controller.observe(&current);
        println!(
            "008 idle-to-backlog: admitted={admitted}; current_delivery={:?}; consumed_delivery={:?}; pace={}",
            current.delivered_bps, controller.latest_delivery_bps, controller.rate_bps
        );
        assert_eq!(controller.latest_delivery_bps, current.delivered_bps);
        assert!(
            controller.rate_bps > START_BPS,
            "confirmed service can resume discovery"
        );
        assert_eq!(controller.loss_evidence.counts(), (0, 0));
        assert!(!controller.loss_pressure);
        assert!(!controller.congestion_seen);
    }

    #[test]
    fn delivery_freshness_008_skipped_stale_loss_prefix_is_not_recounted() {
        let mut evidence = LossEvidence::default();
        evidence.observe(&finalized(0, 1, 40, 4), true);
        let mut stale = finalized(5_000_000, 3, 140, 20);
        stale.feedback_age_us = Some(FRESH_US + 1);
        stale.positive_delivery_age_us = Some(0);
        assert_eq!(evidence.observe(&stale, true), None);
        assert_eq!(evidence.previous, Some((140, 20)));
        assert_eq!(evidence.counts(), (0, 0));
        assert_eq!(
            evidence.observe(&finalized(5_500_000, 4, 160, 22), true),
            Some((20, 2))
        );
        assert_eq!(evidence.counts(), (20, 2));
        // Invalid stale counters must not replace the last valid prefix.
        stale.now_us = 6_000_000;
        stale.report_number = 5;
        stale.finalized_expected = Some(150);
        assert_eq!(evidence.observe(&stale, true), None);
        assert_eq!(evidence.previous, Some((160, 22)));
        assert_eq!(
            evidence.observe(&finalized(6_500_000, 6, 180, 24), true),
            Some((20, 2))
        );
        assert_eq!(evidence.counts(), (20, 2));
        let mut empty = finalized(9_000_000, 7, 180, 24);
        empty.feedback_sample_symbols = 0;
        empty.loss_sample_rate = Some(1.0);
        evidence.observe(&empty, true);
        empty.now_us = 10_500_001;
        evidence.observe(&empty, false);
        assert_eq!(
            evidence.counts(),
            (0, 0),
            "empty reports cannot renew loss age"
        );
    }

    #[test]
    fn delivery_freshness_008_keeps_report_order_and_generation_guards() {
        let mut controller = PathController::new(3_000_000, 20);
        let mut current = finalized(0, 10, 100, 10);
        current.feedback_age_us = Some(FRESH_US + 1);
        current.feedback_sample_symbols = 0;
        current.delivered_bps = Some(256_000.0);
        current.delivered_bytes = 1000;
        current.offered_backlog = false;
        controller.observe(&current);
        assert_eq!(controller.latest_delivery_bps, Some(256_000.0));
        assert_eq!(controller.loss_evidence.counts(), (0, 0));
        for (now, number) in [(100_000, 10), (200_000, 9)] {
            let mut duplicate = current.clone();
            duplicate.now_us = now;
            duplicate.report_number = number;
            duplicate.delivered_bytes = 2000;
            duplicate.delivered_bps = Some(9_000_000.0);
            duplicate.finalized_expected = Some(200);
            duplicate.finalized_lost = Some(40);
            controller.observe(&duplicate);
            assert_eq!(controller.latest_delivery_bps, Some(256_000.0));
            assert_eq!(controller.loss_evidence.previous, Some((100, 10)));
        }
        current.now_us = 300_000;
        current.report_number = 11;
        current.delivered_bps = Some(320_000.0);
        current.finalized_expected = Some(130);
        current.finalized_lost = Some(13);
        controller.observe(&current);
        assert_eq!(controller.latest_delivery_bps, Some(320_000.0));
        assert_eq!(controller.loss_evidence.counts(), (0, 0));
        current.now_us = 400_000;
        current.generation += 1;
        current.report_number = 1;
        current.delivered_bytes = 153;
        current.delivered_bps = Some(64_000.0);
        current.finalized_expected = Some(0);
        current.finalized_lost = Some(0);
        controller.observe(&current);
        assert_eq!(controller.latest_delivery_bps, Some(64_000.0));
        assert_eq!(controller.last_report.unwrap().0, 1);
        assert_eq!(controller.loss_evidence.previous, Some((0, 0)));
        assert_eq!(controller.loss_evidence.counts(), (0, 0));
        assert_eq!(controller.rate_bps, START_BPS);
    }

    #[test]
    fn delivery_freshness_008_zero_delivery_reports_cannot_revive_health() {
        let mut controller = PathController::new(3_000_000, 20);
        let mut sample = finalized(0, 1, 16, 0);
        sample.delivered_bps = Some(128_000.0);
        sample.offered_backlog = false;
        controller.observe(&sample);
        for n in 1..=10 {
            let now = n * 500_000;
            sample.now_us = now;
            sample.report_number = n + 1;
            sample.feedback_age_us = Some(now);
            sample.positive_delivery_age_us = Some(now);
            sample.probe_age_us = Some(now);
            sample.feedback_sample_symbols = 0;
            sample.delivered_bps = Some(0.0);
            controller.observe(&sample);
            assert_eq!(controller.last_evidence_us, Some(0));
            if now > FRESH_US {
                assert!(!controller.decision(now).eligible);
                assert_eq!(controller.decision(now).state, Health::Probing);
            }
        }
        assert_eq!(controller.loss_evidence.counts(), (0, 0));
        sample.now_us = 5_500_000;
        sample.report_number = 12;
        sample.feedback_age_us = Some(0);
        sample.positive_delivery_age_us = Some(sample.now_us);
        sample.probe_age_us = Some(sample.now_us);
        sample.feedback_sample_symbols = 8;
        sample.loss_sample_rate = Some(1.0);
        sample.finalized_expected = Some(24);
        sample.finalized_lost = Some(8);
        controller.observe(&sample);
        assert!(!controller.decision(sample.now_us).eligible);
        assert!(controller.no_delivery_confirmed_us.is_some());
        assert_eq!(controller.last_evidence_us, Some(0));
        // Actual positive delivery can recover the same generation, without
        // requiring a newly finalized loss interval or a connection reset.
        sample.now_us = 6_000_000;
        sample.report_number = 13;
        sample.feedback_age_us = Some(500_000);
        sample.positive_delivery_age_us = Some(0);
        sample.feedback_sample_symbols = 0;
        sample.delivered_bytes += 153;
        sample.delivered_bps = Some(2448.0);
        controller.observe(&sample);
        assert!(controller.decision(sample.now_us).eligible);
        assert!(controller.no_delivery_confirmed_us.is_none());
    }

    #[test]
    fn delivery_freshness_008_stale_loss_cannot_clear_a_pressure_episode() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&finalized(0, 1, 0, 0));
        let mut pressure = finalized(1_000_000, 2, 0, 0);
        pressure.rtt_ms = 120.0;
        pressure.probe_rtt_ms = Some(120.0);
        pressure.probe_latest_rtt_ms = Some(120.0);
        pressure.offered_backlog = false;
        controller.observe(&pressure);
        assert_eq!(controller.pressure_episode_exercised, Some(false));
        let mut clear = finalized(5_000_000, 3, 100, 10);
        clear.feedback_age_us = Some(FRESH_US + 1);
        clear.delivered_bps = Some(256_000.0);
        clear.offered_backlog = false;
        controller.observe(&clear);
        assert_eq!(controller.pressure_episode_exercised, Some(false));
        clear.now_us = 5_500_000;
        clear.report_number = 4;
        clear.feedback_age_us = Some(0);
        clear.feedback_sample_symbols = 16;
        clear.finalized_expected = Some(116);
        controller.observe(&clear);
        assert_eq!(controller.pressure_episode_exercised, None);
    }

    #[test]
    fn finalized_loss_counts_are_exact_bounded_and_not_report_gap_multiples() {
        let mut evidence = LossEvidence::default();
        assert_eq!(
            evidence.observe(&finalized(0, 1, 40, 2), true),
            Some((40, 2))
        );
        assert_eq!(evidence.observe(&finalized(100_000, 1, 40, 2), false), None);
        // A skipped cumulative prefix supplies one real delta, not five batches.
        assert_eq!(
            evidence.observe(&finalized(500_000, 6, 80, 4), true),
            Some((40, 2))
        );
        assert_eq!(evidence.counts(), (80, 4));
        assert_eq!(evidence.batches.len(), 2);
        assert!(!evidence.ordinary(), "exactly 1/20 is not greater than 5%");
        let mut empty = finalized(1_000_000, 7, 80, 4);
        empty.feedback_sample_symbols = 0;
        empty.loss_sample_rate = Some(1.0);
        assert_eq!(evidence.observe(&empty, true), None);
        assert_eq!(evidence.counts(), (80, 4));
        empty.now_us = LOSS_WINDOW_US + 500_001;
        assert_eq!(evidence.observe(&empty, false), None);
        assert_eq!(evidence.counts(), (0, 0));
        for n in 0..20 {
            evidence.observe(&finalized(5_000_000 + n, n, 100 + n * 10, 5 + n), true);
        }
        assert_eq!(evidence.batches.len(), LOSS_BATCHES);
        assert_eq!(evidence.counts(), (80, 8));
        assert!(evidence.ordinary());
    }

    #[test]
    fn invalid_finalized_prefix_preserves_the_last_good_counting_baseline() {
        for invalid in [(90, 9), (110, 111), (101, 12)] {
            let mut evidence = LossEvidence::default();
            evidence.observe(&finalized(0, 1, 100, 10), true);
            assert_eq!(
                evidence.observe(&finalized(500_000, 2, invalid.0, invalid.1), true),
                None
            );
            assert_eq!(evidence.previous, Some((100, 10)));
            assert_eq!(
                evidence.observe(&finalized(1_000_000, 3, 110, 11), true),
                Some((10, 1))
            );
            assert_eq!(evidence.counts(), (10, 1));
        }
    }

    #[test]
    fn controller_ignores_reordered_reports_and_resets_loss_evidence_with_generation() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&finalized(0, 3, 100, 10));
        controller.observe(&finalized(500_000, 2, 200, 50));
        assert_eq!(controller.loss_evidence.counts(), (100, 10));
        controller.observe(&finalized(1_000_000, 4, 120, 12));
        assert_eq!(controller.loss_evidence.counts(), (120, 12));
        let mut fresh_generation = finalized(1_500_000, 1, 8, 0);
        fresh_generation.generation += 1;
        controller.observe(&fresh_generation);
        assert_eq!(controller.loss_evidence.counts(), (8, 0));
        assert!(!controller.congestion_seen);
    }

    #[test]
    fn datagram_burst_does_not_manufacture_current_service_shortfall() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&finalized(0, 1, 0, 0));
        controller.rate_bps = 150_000;
        let mut sample = finalized(600_000, 2, 40, 4);
        sample.delivered_bps = Some(145_000.0);
        controller.observe(&sample);
        for now in [600_000, 800_000] {
            for _ in 0..2 {
                assert!(controller.allow(now, 1138, 0.0));
                controller.admitted(now, 1138);
            }
            if now == 600_000 {
                sample = finalized(700_000, 3, 80, 8);
                sample.delivered_bps = Some(145_000.0);
                controller.observe(&sample);
                // 2276 bytes / 100 ms = 182080 bps, but the exercised
                // allowance is 150000 bps and delivered service is 145000.
                assert!(!controller.loss_pressure);
                assert_eq!(controller.rate_bps, 150_000);
            }
        }
        sample = finalized(800_000, 4, 120, 12);
        sample.delivered_bps = Some(145_000.0);
        controller.observe(&sample);
        assert!(!controller.loss_pressure);
        assert!(!controller.congestion_seen);
        assert_eq!(controller.rate_bps, 225_000);
    }

    #[test]
    fn newest_severe_loss_brakes_even_after_a_large_clean_finalized_prefix() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&finalized(0, 1, 10_000, 0));
        exercise_budget(&mut controller, 0, 500_000);
        let mut sample = finalized(500_000, 2, 10_008, 8);
        sample.feedback_sample_symbols = 8;
        sample.loss_sample_rate = Some(1.0);
        sample.delivered_bps = Some(256_000.0);
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, START_BPS / 2);
        assert!(
            !controller.congestion_seen,
            "old finalized loss alone is not a current capacity limit"
        );
        assert!(
            controller.eligible,
            "a fresh positive probe keeps reachability independent"
        );
    }

    #[test]
    fn delayed_candidate005_small_loss_cohorts_do_not_set_a_healthy_startup_ceiling() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&finalized(0, 1, 0, 0));
        let cohorts = [(18, 1), (14, 1), (23, 2), (19, 3), (20, 1), (17, 3)];
        let (mut expected, mut lost) = (0, 0);
        for n in 0..20 {
            let start = n * 500_000;
            let bytes = exercise_budget(&mut controller, start, 500_000);
            let (dn, dl) = cohorts[n as usize % cohorts.len()];
            expected += dn;
            lost += dl;
            let mut sample = finalized(start + 500_000, n + 2, expected, lost);
            sample.feedback_sample_symbols = dn;
            sample.loss_sample_rate = Some(dl as f64 / dn as f64);
            // This is a finalized-cohort replay with independent healthy current
            // delivery, not a replay of every WAN timing/queue observation.
            sample.delivered_bps = Some(bytes as f64 * 16.0 * 0.95);
            controller.observe(&sample);
            assert!(!controller.congestion_seen);
            assert!(!controller.loss_pressure);
        }
        assert_eq!(controller.rate_bps, 3_000_000);
    }

    /// A separate no-queue packet model: real admission/token accounting,
    /// deterministic load-independent erasure, and an optional flat-RTT policer.
    /// Delivery intervals and delayed finalized loss counts remain distinct.
    struct FlatLane {
        controller: PathController,
        report: Option<SimReport>,
        reports: VecDeque<SimReport>,
        pending_loss: (u64, u64),
        expected: u64,
        lost: u64,
        interval_sent: u64,
        interval_lost: u64,
        interval_received: u64,
        sent_bytes: u64,
        received_bytes: u64,
        tokens: f64,
        erasure_credit: u64,
        positive_at: Option<u64>,
        rtt_us: u64,
        compressed: bool,
    }

    impl FlatLane {
        fn new(rtt_us: u64, compressed: bool) -> Self {
            Self {
                controller: PathController::new(3_000_000, 20),
                report: None,
                reports: VecDeque::new(),
                pending_loss: (0, 0),
                expected: 0,
                lost: 0,
                interval_sent: 0,
                interval_lost: 0,
                interval_received: 0,
                sent_bytes: 0,
                received_bytes: 0,
                tokens: 2400.0,
                erasure_credit: 0,
                positive_at: None,
                rtt_us,
                compressed,
            }
        }

        fn tick(&mut self, now: u64, capacity: u64, erasure_per_thousand: u64) {
            while self.reports.front().is_some_and(|r| r.due <= now) {
                let report = self.reports.pop_front().unwrap();
                if self.report.is_none_or(|old| report.number > old.number) {
                    if report.bytes > self.report.map_or(0, |old| old.bytes) {
                        self.positive_at = Some(now);
                    }
                    self.report = Some(report);
                }
            }
            if now.is_multiple_of(100_000) {
                self.controller.observe(&Observation {
                    now_us: now,
                    generation: 7,
                    report_number: self.report.map_or(0, |r| r.number),
                    feedback_age_us: self.report.map(|r| now.saturating_sub(r.due)),
                    positive_delivery_age_us: self.positive_at.map(|at| now - at),
                    delivered_bytes: self.report.map_or(0, |r| r.bytes),
                    delivered_bps: self.report.map(|r| r.rate),
                    feedback_sample_symbols: self.report.map_or(0, |r| r.symbols),
                    loss_sample_rate: self.report.map(|r| r.loss),
                    finalized_expected: self.report.map(|r| r.expected),
                    finalized_lost: self.report.map(|r| r.lost),
                    rtt_ms: self.rtt_us as f64 / 1000.0,
                    probe_latest_rtt_ms: Some(self.rtt_us as f64 / 1000.0),
                    probe_sample_id: now / PROBE_US + 1,
                    probe_age_us: Some(now % PROBE_US),
                    offered_backlog: true,
                    ..Default::default()
                });
                assert!(self.controller.decision(now).eligible);
            }
            self.tokens = (self.tokens + capacity as f64 / 8000.0).min(2400.0);
            while self.controller.allow(now, 1000, 0.0) {
                self.controller.admitted(now, 1000);
                self.sent_bytes += 1000;
                self.interval_sent += 1;
                let policed = self.tokens < 1000.0;
                if !policed {
                    self.tokens -= 1000.0;
                }
                self.erasure_credit += erasure_per_thousand;
                let erased = self.erasure_credit >= 1000;
                if erased {
                    self.erasure_credit -= 1000;
                }
                if policed || erased {
                    self.interval_lost += 1;
                } else {
                    self.received_bytes += 1000;
                    self.interval_received += 1;
                }
            }
            if now > 0 && now.is_multiple_of(PROBE_US) {
                let number = now / PROBE_US;
                let (n, lost) = self.pending_loss;
                self.expected += n;
                self.lost += lost;
                let extra = if self.compressed && number % 6 == 5 {
                    PROBE_US
                } else {
                    0
                };
                self.reports.push_back(SimReport {
                    number,
                    due: now + self.rtt_us + extra,
                    bytes: self.received_bytes,
                    rate: self.interval_received as f64 * 16_000.0,
                    symbols: n,
                    loss: if n == 0 { 0.0 } else { lost as f64 / n as f64 },
                    expected: self.expected,
                    lost: self.lost,
                });
                self.pending_loss = (self.interval_sent, self.interval_lost);
                self.interval_sent = 0;
                self.interval_lost = 0;
                self.interval_received = 0;
            }
        }
    }

    #[test]
    fn independent_erasure_does_not_disable_cold_discovery_with_delayed_reports() {
        for (erasure, rtt_us, compressed) in [(60, 80_000, false), (100, 300_000, true)] {
            let mut lane = FlatLane::new(rtt_us, compressed);
            let mut discovered = None;
            let mut tail_bytes = 0;
            for now in (0..60_000_000).step_by(1000) {
                let before = lane.received_bytes;
                lane.tick(now, 3_000_000, erasure);
                if lane.controller.rate_bps >= 2_700_000 {
                    discovered.get_or_insert(now);
                }
                if now >= 50_000_000 {
                    tail_bytes += lane.received_bytes - before;
                }
            }
            let tail_bps = tail_bytes as f64 * 0.8;
            eprintln!(
                "flat erasure={erasure}/1000 rtt_us={rtt_us} compressed={compressed}: discovery={discovered:?}; final={} cautious={} tail_bps={tail_bps}",
                lane.controller.rate_bps, lane.controller.congestion_seen
            );
            assert!(discovered.is_some_and(|at| at <= 12_000_000));
            assert!(!lane.controller.congestion_seen);
            assert!(tail_bps >= 3_000_000.0 * (1.0 - erasure as f64 / 1000.0) * 0.90);
        }
    }

    #[test]
    fn flat_rtt_policer_bounds_cold_and_retained_capacity_exploration() {
        for retained in [false, true] {
            let mut lane = FlatLane::new(300_000, true);
            lane.tick(0, 3_000_000, 0);
            if retained {
                lane.controller.rate_bps = 3_000_000;
                lane.controller.remembered_bps = 3_000_000.0;
                lane.controller.congestion_seen = true;
            }
            let (mut tail_sent, mut tail_received, mut tail_max) = (0, 0, 0);
            for now in (1000..40_000_000).step_by(1000) {
                let before = (lane.sent_bytes, lane.received_bytes);
                lane.tick(now, 700_000, 0);
                if now >= 30_000_000 {
                    tail_sent += lane.sent_bytes - before.0;
                    tail_received += lane.received_bytes - before.1;
                    tail_max = tail_max.max(lane.controller.rate_bps);
                }
            }
            let (sent, received) = (tail_sent as f64 * 0.8, tail_received as f64 * 0.8);
            eprintln!(
                "flat policer retained={retained}: sent={sent} received={received} tail_max={tail_max} final={} cautious={}",
                lane.controller.rate_bps, lane.controller.congestion_seen
            );
            assert!(lane.controller.congestion_seen);
            assert!(
                sent <= 700_000.0 * 1.5,
                "persistent oversupply under flat RTT"
            );
            assert!(
                tail_max <= 700_000 * 2,
                "recovery must not blindly refill the old capacity"
            );
            assert!(received >= 700_000.0 * 0.75);
        }
    }

    #[test]
    fn sparse_idle_jitter_preserves_unused_allowance_then_backlog_can_discover() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 80.0));
        for tick in 1..=50 {
            let now = tick * 100_000;
            // Twenty small records per second; actual admissions consume well
            // below the initial allowance. RTT spikes recur while idle.
            for send in [now - 100_000, now - 50_000] {
                assert!(controller.allow(send, 160, 0.0));
                controller.admitted_symbol(send, 160, 128);
            }
            let rtt = if tick % 10 < 5 { 100.0 } else { 80.0 };
            let mut sample = observation(now, rtt);
            sample.offered_backlog = false;
            sample.delivered_bps = Some(20_480.0);
            sample.delivered_bytes = tick * 256;
            sample.feedback_sample_symbols = 10;
            controller.observe(&sample);
            assert_eq!(controller.rate_bps, START_BPS);
            assert!(!controller.congestion_seen);
        }
        for tick in 1..=10 {
            let start = 5_000_000 + (tick - 1) * 500_000;
            let bytes = exercise_budget(&mut controller, start, 500_000);
            let mut sample = observation(start + 500_000, 80.0);
            sample.delivered_bps = Some(bytes as f64 * 16.0);
            controller.observe(&sample);
        }
        assert!(controller.rate_bps >= 2_500_000);
        assert!(controller.decision(10_000_000).eligible);
    }

    #[test]
    fn exercised_pressure_still_brakes_after_an_idle_pressure_episode() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 80.0));
        let mut idle = observation(200_000, 130.0);
        idle.offered_backlog = false;
        idle.delivered_bps = Some(7_000.0);
        controller.observe(&idle);
        assert_eq!(controller.rate_bps, START_BPS);
        assert_eq!(controller.pressure_episode_exercised, Some(false));
        exercise_budget(&mut controller, 200_000, 200_000);
        let mut active = observation(400_000, 150.0);
        active.delivered_bps = Some(7_000.0);
        active.loss_sample_rate = Some(0.25);
        controller.observe(&active);
        // The idle episode does not immunize subsequent real demand from safety
        // braking, but its low delivery alone cannot select a 64 kbps capacity.
        assert!(controller.rate_bps < START_BPS);
        assert!(controller.rate_bps > MIN_BPS);
        assert!(controller.decision(400_000).eligible);
    }

    #[test]
    fn sparse_packet_briefly_visible_as_backlog_uses_bounded_backoff() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 80.0));
        for tick in 1..=20 {
            let now = tick * 100_000;
            for send in [now - 100_000, now - 50_000] {
                assert!(controller.allow(send, 160, 0.0));
                controller.admitted_symbol(send, 160, 128);
            }
            let mut sample = observation(now, if tick <= 4 { 100.0 } else { 80.0 });
            // The runtime can observe a just-enqueued sparse packet as backlog.
            sample.offered_backlog = tick == 2 || tick == 3;
            sample.delivered_bps = Some(20_480.0);
            sample.feedback_sample_symbols = 10;
            controller.observe(&sample);
            assert!(controller.rate_bps >= START_BPS * 8 / 10);
            assert!(!controller.congestion_seen);
        }
        assert!(controller.rate_bps < START_BPS);
    }

    #[test]
    fn persistent_idle_rtt_offset_still_blocks_capacity_growth() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 80.0));
        let mut idle = observation(500_000, 140.0);
        idle.offered_backlog = false;
        idle.delivered_bps = Some(7_000.0);
        controller.observe(&idle);
        assert_eq!(controller.rate_bps, START_BPS);
        for tick in 1..=20 {
            let start = tick * 500_000;
            let bytes = exercise_budget(&mut controller, start, 500_000);
            let mut active = observation(start + 500_000, 140.0);
            active.delivered_bps = Some(bytes as f64 * 16.0);
            controller.observe(&active);
        }
        // Explicit remaining limitation: this patch does not classify a lasting
        // RTT offset as propagation or permit discovery through standing delay.
        assert!(controller.rate_bps <= START_BPS);
        assert!(controller.decision(10_500_000).eligible);
        assert_eq!(controller.health, Health::Degraded);
    }

    #[test]
    fn normal_congestion_preserves_reachability_and_capacity_memory() {
        let mut controller = PathController::new(10_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 2_400_000;
        controller.remembered_bps = 2_400_000.0;
        for n in 1..101 {
            let now = n * 1_000_000;
            let mut bad = observation(now, 60.0);
            bad.delivered_bps = Some(2_400_000.0);
            controller.observe(&bad);
            bad.now_us += BRAKE_US;
            controller.observe(&bad);
            assert!(controller.decision(now).eligible);
            assert_eq!(controller.decision(now).state, Health::Degraded);
            assert!(controller.allow(now, 1000, 0.0));
            let reduced = controller.rate_bps;
            assert!(reduced > START_BPS);
            let mut clear = observation(now + 500_000, 20.0);
            clear.delivered_bps = Some(reduced as f64);
            controller.observe(&clear);
            assert!(controller.rate_bps >= reduced);
            assert!(controller.rate_bps <= 2_400_000);
            assert!(controller.decision(now + 500_000).eligible);
            assert_eq!(controller.remembered_bps, 2_400_000.0);
        }
    }

    #[test]
    fn stale_idle_burst_waits_for_probe_but_does_not_forget_exercised_rate() {
        let mut controller = PathController::new(10_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 1_200_000;
        let mut idle = observation(10_000_000, 20.0);
        idle.feedback_age_us = Some(10_000_000);
        idle.positive_delivery_age_us = Some(10_000_000);
        idle.probe_age_us = None;
        idle.offered_backlog = false;
        controller.observe(&idle);
        assert!(!controller.allow(10_000_000, 1000, 0.0));
        assert!(controller.decision(10_000_000).probe_due);
        assert_eq!(controller.rate_bps, 1_200_000);
        controller.probe_admitted(10_000_000);
        assert!(!controller.decision(10_000_001).probe_due);
        idle.now_us = 10_500_000;
        idle.probe_age_us = Some(0);
        idle.probe_sample_id += 1;
        controller.observe(&idle);
        assert!(controller.allow(10_500_000, 1000, 0.0));
        assert!(!controller.allow(10_500_000, 1000, 21.0));
        assert_eq!(controller.rate_bps, 1_200_000);
    }

    #[test]
    fn all_loss_reports_cannot_refresh_a_dead_path_and_positive_probe_restores_it() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 1_200_000;
        controller.remembered_bps = 2_400_000.0;
        let mut retained = 0;
        for n in 1..=16 {
            let now = n * PROBE_US;
            let mut lost = observation(now, 20.0);
            lost.positive_delivery_age_us = Some(now);
            lost.probe_age_us = Some(now);
            lost.probe_sample_id = 1;
            lost.delivered_bytes = 0;
            lost.delivered_bps = Some(0.0);
            lost.feedback_sample_symbols = 10;
            lost.loss_sample_rate = Some(1.0);
            controller.observe(&lost);
            if n >= 2 {
                assert!(!controller.decision(now).eligible);
                assert_eq!(controller.decision(now).state, Health::Probing);
                assert_eq!(controller.last_evidence_us, Some(0));
                if n == 2 {
                    retained = controller.rate_bps;
                }
                assert_eq!(controller.rate_bps, retained);
            }
        }
        assert_eq!(controller.remembered_bps, 2_400_000.0);
        let mut reply = observation(8_100_000, 20.0);
        reply.positive_delivery_age_us = Some(8_100_000);
        reply.probe_sample_id = 2;
        reply.delivered_bytes = 0;
        reply.delivered_bps = Some(0.0);
        reply.loss_sample_rate = Some(1.0);
        controller.observe(&reply);
        assert!(controller.allow(reply.now_us, 1000, 0.0));
        assert_eq!(controller.no_delivery_confirmed_us, None);
        assert_eq!(controller.rate_bps, retained);
        assert_eq!(controller.remembered_bps, 2_400_000.0);
    }

    #[test]
    fn useful_congestion_and_current_probes_remain_eligible() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 1_200_000;
        for n in 1..=20 {
            let now = n * PROBE_US;
            let mut impaired = observation(now, 80.0);
            impaired.probe_age_us = Some(now);
            impaired.delivered_bps = Some(350_000.0);
            impaired.loss_sample_rate = Some(0.9);
            controller.observe(&impaired);
            assert!(controller.decision(now).eligible);
        }
        for n in 21..=30 {
            let now = n * PROBE_US;
            let mut probe_only = observation(now, 20.0);
            probe_only.positive_delivery_age_us = Some(now);
            probe_only.delivered_bytes = 0;
            probe_only.delivered_bps = Some(0.0);
            probe_only.loss_sample_rate = Some(1.0);
            controller.observe(&probe_only);
            assert!(controller.decision(now).eligible);
        }
    }

    #[test]
    fn fresh_sparse_loss_reports_do_not_extend_positive_health_deadline() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        for n in 1..=8 {
            let now = n * PROBE_US;
            let mut lost = observation(now, 20.0);
            lost.positive_delivery_age_us = Some(now);
            lost.probe_age_us = None;
            lost.delivered_bytes = 0;
            lost.delivered_bps = Some(0.0);
            lost.feedback_sample_symbols = 1;
            lost.loss_sample_rate = Some(1.0);
            controller.observe(&lost);
        }
        assert_eq!(controller.no_delivery_confirmed_us, None);
        assert_eq!(controller.last_evidence_us, Some(0));
        assert!(!controller.decision(4_000_000).eligible);
    }

    #[test]
    fn drainage_between_control_ticks_restores_the_recent_service_hint() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 2_400_000;
        controller.remembered_bps = 2_400_000.0;
        controller.draining_bps = Some((2_400_000.0, 0));
        controller.observe(&observation(100_000, 100.0));
        assert!(controller.rate_bps < 2_000_000);
        assert!(controller.drain_restore_pending);
        controller.observe(&observation(200_000, 100.0));
        controller.observe(&observation(300_000, 20.0));
        assert!(controller.drain_restore_pending);
        controller.observe(&observation(400_000, 20.0));
        assert_eq!(controller.rate_bps, 2_160_000);
        assert!(!controller.drain_restore_pending);
    }

    #[test]
    fn brief_observation_gap_and_unused_allowance_do_not_replace_drain_memory() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 2_400_000;
        controller.remembered_bps = 2_400_000.0;
        controller.draining_bps = Some((2_400_000.0, 0));
        controller.observe(&observation(100_000, 100.0));
        controller.observe(&observation(200_000, 100.0));
        // No admissions while the observer is delayed. A later low receiver
        // interval describes that pause, not a newly exercised low capacity.
        let mut resumed = observation(600_000, 100.0);
        resumed.delivered_bps = Some(600_000.0);
        controller.observe(&resumed);
        assert_eq!(controller.draining_bps, Some((2_400_000.0, 0)));
        resumed.now_us = 700_000;
        resumed.rtt_ms = 20.0;
        resumed.probe_latest_rtt_ms = Some(20.0);
        controller.observe(&resumed);
        resumed.now_us = 800_000;
        controller.observe(&resumed);
        assert_eq!(controller.rate_bps, 2_160_000);
        assert_eq!(controller.remembered_bps, 2_400_000.0);
    }

    #[test]
    fn clock_drift_diagnostic_cannot_create_congestion_without_rtt_evidence() {
        let mut controller = PathController::new(10_000_000, 20);
        controller.observe(&observation(0, 20.0));
        for seconds in (1..36_000).step_by(100) {
            let now = seconds * 1_000_000;
            let mut sample = observation(now, 20.0);
            sample.transit_excess_ms = seconds as f64 * 0.05;
            sample.offered_backlog = false;
            controller.observe(&sample);
            assert!(controller.decision(now).eligible);
            assert_eq!(controller.decision(now).queue_delay_ms, 0.0);
        }
    }

    #[test]
    fn application_limited_delivery_does_not_become_a_capacity_ceiling() {
        let mut controller = PathController::new(10_000_000, 20);
        controller.observe(&observation(0, 20.0));
        for n in 1..20 {
            let mut sample = observation(n * 500_000, 20.0);
            sample.offered_backlog = false;
            sample.delivered_bytes = n * 10;
            controller.observe(&sample);
        }
        assert_eq!(controller.rate_bps, START_BPS);
        assert!(controller.delivery_bps.unwrap() < START_BPS as f64 / 10.0);
        assert_eq!(controller.remembered_bps, 0.0);
    }

    #[test]
    fn sender_deadline_and_pace_gate_admission_without_quarantining_normal_queue() {
        let mut controller = PathController::new(10_000_000, 20);
        controller.observe(&observation(0, 20.0));
        let mut sample = observation(500_000, 20.0);
        sample.send_queue_bytes = 4096;
        controller.observe(&sample);
        assert!(controller.decision(500_000).queue_delay_ms > 20.0);
        assert!(controller.allow(500_000, 1000, 0.0));
        assert!(!controller.allow(500_000, 1000, 21.0));
    }

    #[test]
    fn conservative_startup_pacing_does_not_invent_queue_delay_for_own_burst() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        for (now, bytes) in [(500_000, 1100), (1_000_000, 2200)] {
            let mut sample = observation(now, 20.0);
            sample.send_queue_bytes = bytes;
            controller.observe(&sample);
            assert_eq!(controller.decision(now).queue_delay_ms, 0.0);
            assert!(controller.allow(now, 1000, 0.0));
        }
    }

    #[test]
    fn constant_rtt_step_with_fresh_reports_does_not_multiply_rate_toward_floor() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 2_000_000;
        let mut first = observation(500_000, 50.0);
        first.delivered_bps = Some(2_000_000.0);
        controller.observe(&first);
        first.now_us += BRAKE_US;
        controller.observe(&first);
        let after_step = controller.rate_bps;
        assert!(after_step < 2_000_000);
        for n in 2..100 {
            let mut stable = observation(n * 500_000, 50.0);
            // Freshly delivered data follows the reduced admission rate. This
            // must not be treated as another capacity drop at an unchanged RTT.
            stable.delivered_bps = Some(controller.rate_bps as f64);
            controller.observe(&stable);
            assert_eq!(controller.rate_bps, after_step);
            assert!(controller.decision(stable.now_us).eligible);
        }
    }

    #[test]
    fn transient_buffer_occupancy_does_not_flap_health() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        for n in 1..100 {
            let mut sample = observation(n * 100_000, 20.0);
            sample.transport_blocked = n % 2 == 1;
            sample.send_queue_bytes = if sample.transport_blocked { 1100 } else { 0 };
            controller.observe(&sample);
            assert!(controller.decision(sample.now_us).eligible);
            assert_eq!(controller.decision(sample.now_us).state, Health::Healthy);
        }
    }

    #[test]
    fn small_packet_overhead_is_not_mistaken_for_missing_delivery_capacity() {
        let mut controller = PathController::new(3_000_000, 20);
        let mut first = observation(0, 20.0);
        first.transport_blocked = true;
        controller.observe(&first);
        let mut symbols = 0u64;
        for now in (0..500_000).step_by(1000) {
            while controller.allow(now, 200, 0.0) {
                controller.admitted_symbol(now, 200, 20);
                symbols += 20;
            }
        }
        let mut sample = observation(500_000, 20.0);
        sample.delivered_bytes = symbols;
        sample.delivered_bps = Some(symbols as f64 * 16.0);
        sample.transport_blocked = true;
        controller.observe(&sample);
        assert!(controller.decision(500_000).eligible);
        assert!(controller.rate_bps > START_BPS);
    }

    #[test]
    fn feedback_arrival_delay_does_not_replace_receiver_interval_rate() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        let mut sample = observation(5_000_000, 20.0);
        sample.delivered_bytes = 640_000;
        sample.delivered_bps = Some(64_000.0);
        controller.observe(&sample);
        assert_eq!(controller.delivery_bps, Some(64_000.0));
    }

    #[test]
    fn unused_allowance_cannot_repeat_candidate001_sixty_percent_growth() {
        let mut controller = PathController::new(8_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 4_374_000;
        // 2.625 Mbps actual admission, the measured 001 condition. The scheduler
        // may leave an allowance unused; that does not justify multiplying it.
        for now in (0..500_000).step_by(3200) {
            if controller.allow(now, 1050, 0.0) {
                controller.admitted(now, 1050);
            }
        }
        let mut sample = observation(500_000, 20.0);
        sample.delivered_bps = Some(2_625_000.0);
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 4_374_000);
    }

    #[test]
    fn cleared_raw_rtt_and_loss_are_not_masked_by_old_ewmas() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 2_000_000;
        let mut sample = observation(500_000, 40.0);
        sample.probe_rtt_ms = Some(100.0);
        sample.probe_latest_rtt_ms = Some(20.0);
        sample.loss_rate = 0.4;
        sample.loss_sample_rate = Some(0.0);
        sample.delivered_bps = Some(2_000_000.0);
        controller.observe(&sample);
        assert_eq!(controller.queue_delay_ms, 0.0);
        assert_eq!(controller.rate_bps, 2_000_000);
        sample.now_us += 200_000;
        sample.probe_age_us = Some(200_000);
        sample.rtt_ms = 35.0;
        controller.observe(&sample);
        assert_eq!(controller.queue_delay_ms, 0.0);
        assert_eq!(controller.rate_bps, 2_000_000);
    }

    #[test]
    fn one_loss_interval_cannot_be_reused_as_multiple_backoffs() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 2_000_000;
        let mut sample = observation(500_000, 20.0);
        sample.loss_sample_rate = Some(0.5);
        sample.delivered_bps = Some(2_000_000.0);
        controller.observe(&sample);
        let after_loss = controller.rate_bps;
        assert!(after_loss < 2_000_000);
        for n in 1..20 {
            sample.now_us = 500_000 + n * 100_000;
            controller.observe(&sample);
            assert_eq!(controller.rate_bps, after_loss);
        }
    }

    #[test]
    fn cold_search_resumes_after_a_brief_unexercised_observation_pause() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        let mut delivered = 0u64;
        let mut report_bytes = 0;
        let mut report_at = 0;
        let mut report_number = 1;
        let mut report_rate = 0.0;
        let mut report_symbols = 0;
        let mut report_loss = 0.0;
        let mut probe_at = 0;
        let mut probe_rtt = 20.0;
        let mut before_pause = 0;
        let mut after_pause = u64::MAX;
        let mut discovered_at = None;
        // Perfect receiver service below the configured 3 Mbps ceiling. The
        // separate FIFO capacity-step tests cover real saturation and drain.
        for now in (0..14_000_000u64).step_by(1000) {
            if (2_000_000..2_250_000).contains(&now) {
                continue;
            }
            while controller.allow(now, 1000, 0.0) {
                controller.admitted(now, 1000);
                delivered += 1000;
            }
            let rtt = if (2_250_000..2_600_000).contains(&now) {
                120.0
            } else {
                20.0
            };
            if now > 0 && now.is_multiple_of(PROBE_US) {
                let bytes = delivered - report_bytes;
                report_rate = bytes as f64 * 8_000_000.0 / (now - report_at) as f64;
                report_symbols = bytes / 1000;
                // Finalized losses from the pause arrive after RTT has cleared.
                // They must not qualify the smaller, now fully used allowance.
                report_loss = if now == 3_000_000 {
                    report_symbols = 26;
                    2.0 / 26.0
                } else {
                    0.0
                };
                report_bytes = delivered;
                report_at = now;
                report_number += 1;
                probe_at = now;
                probe_rtt = rtt;
            }
            if now.is_multiple_of(100_000) {
                let mut sample = observation(now, rtt);
                sample.report_number = report_number;
                sample.feedback_age_us = Some(now - report_at);
                sample.positive_delivery_age_us = Some(now - report_at);
                sample.delivered_bytes = report_bytes;
                sample.delivered_bps = Some(report_rate);
                sample.feedback_sample_symbols = report_symbols;
                sample.loss_sample_rate = Some(report_loss);
                sample.probe_sample_id = probe_at / PROBE_US + 1;
                sample.probe_latest_rtt_ms = Some(probe_rtt);
                sample.probe_age_us = Some(now - probe_at);
                controller.observe(&sample);
                assert!(controller.decision(now).eligible);
                assert!(controller.rate_bps <= 3_000_000);
                if now == 1_900_000 {
                    before_pause = controller.rate_bps;
                }
                if (2_300_000..2_600_000).contains(&now) {
                    after_pause = after_pause.min(controller.rate_bps);
                }
                if now == 3_000_000 {
                    assert!(
                        !controller.congestion_seen,
                        "delayed losses must retain the unexercised episode's qualification"
                    );
                }
                if now >= 2_600_000 && controller.rate_bps >= 2_700_000 {
                    discovered_at.get_or_insert(now);
                }
            }
        }
        eprintln!(
            "cold pause: before={before_pause} after={after_pause} final={} discovered_at_us={discovered_at:?}",
            controller.rate_bps
        );
        assert!(before_pause > START_BPS, "cold search must have started");
        // A low application-limited sample no longer selects the brake's
        // capacity target. Require the existing bounded safety backoff instead
        // of the former >50% cut; recovery and FIFO performance gates are intact.
        assert!(
            after_pause <= before_pause * 8 / 10,
            "the safety brake must still act"
        );
        assert!(
            discovered_at.is_some_and(|at| at <= 8_600_000),
            "a brief pause must not permanently disable healthy capacity discovery"
        );
    }

    #[test]
    fn pressure_qualification_integrates_allowance_before_rate_changes() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 1_000_000;
        for now in (0..80_000).step_by(10_000) {
            assert!(controller.allow(now, 1000, 0.0));
            controller.admitted(now, 1000);
        }
        controller.refill(100_000);
        controller.rate_bps = 250_000;
        controller.refill(200_000);
        assert_eq!(controller.admitted_bytes, 8000);
        assert_eq!(controller.allowance_bytes, 15_625.0);
        // Using only the latest rate would incorrectly call this 128% use;
        // actual admitted bytes used only 51.2% of the changing allowance.
        controller.observe(&observation(200_000, 120.0));
        assert_eq!(controller.pressure_episode_exercised, Some(false));
        assert!(!controller.congestion_seen);
        assert_eq!(controller.allowance_bytes, 0.0);
        controller.refill(300_000);
        assert_eq!(
            controller.allowance_bytes,
            controller.rate_bps as f64 / 80.0
        );
    }

    #[test]
    fn exercised_loss_without_rtt_growth_qualifies_persistent_caution() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 1_000_000;
        exercise_budget(&mut controller, 0, 500_000);
        let mut loss = observation(500_000, 20.0);
        loss.delivered_bps = Some(500_000.0);
        loss.loss_sample_rate = Some(0.5);
        controller.observe(&loss);
        assert_eq!(controller.queue_delay_ms, 0.0);
        assert_eq!(controller.pressure_episode_exercised, Some(true));
        // The first severe interval still brakes immediately, but can describe
        // delayed warmup loss. It does not prove a settled current capacity.
        assert!(!controller.congestion_seen);
        let reduced = controller.rate_bps;
        assert!(reduced < 1_000_000);
        exercise_budget(&mut controller, 500_000, 700_000);
        let mut persistent = observation(1_200_000, 20.0);
        persistent.delivered_bps = Some(250_000.0);
        persistent.feedback_sample_symbols = 64;
        persistent.loss_sample_rate = Some(0.25);
        controller.observe(&persistent);
        assert!(controller.congestion_seen);
        assert!(controller.rate_bps < reduced);
        for n in 0..5 {
            let start = 1_200_000 + n * CONTROL_US;
            let bytes = exercise_budget(&mut controller, start, CONTROL_US);
            let mut clear = observation(start + CONTROL_US, 20.0);
            clear.delivered_bps = Some(bytes as f64 * 8_000_000.0 / CONTROL_US as f64);
            controller.observe(&clear);
        }
        assert!(controller.rate_bps <= 550_000);
        assert!(controller.congestion_seen);
    }

    #[derive(Clone, Copy)]
    struct SimReport {
        number: u64,
        bytes: u64,
        rate: f64,
        due: u64,
        symbols: u64,
        loss: f64,
        expected: u64,
        lost: u64,
    }

    struct SimPacket {
        bits: f64,
        at: u64,
        business: bool,
    }

    /// Deterministic packet admission and FIFO serialization, with delayed
    /// receiver reports and independently smoothed RTT. It deliberately omits
    /// Quinn's congestion control, flow scheduling and application deadlines.
    /// The bounded variant expires packets at 250 ms and caps the FIFO at 64 KiB;
    /// the unbounded variant exposes the cost of stale evidence after a sharp drop.
    struct Lane {
        controller: PathController,
        bounded: bool,
        packets: VecDeque<SimPacket>,
        queue_bits: f64,
        delivered_symbol_bytes: u64,
        delivered_app_bytes: u64,
        report_bytes: u64,
        report_number: u64,
        report: Option<SimReport>,
        last_positive_delivery_at: Option<u64>,
        reports: VecDeque<SimReport>,
        pending_loss: (u64, u64),
        finalized_expected: u64,
        finalized_lost: u64,
        interval_received: u64,
        interval_lost: u64,
        dropped: u64,
        probe: Option<(u64, f64, u64)>,
        probes: VecDeque<(u64, f64, u64)>,
        rtts: VecDeque<(u64, f64)>,
        quinn_rtt_ms: f64,
        next_probe_id: u64,
        ineligible_ticks: u64,
        ineligible_with_fresh_evidence: u64,
    }

    impl Lane {
        const WIRE: usize = 1100;
        const SYMBOL: usize = 1070;
        const NETWORK: usize = 1200;
        const APP: usize = 1000;

        fn new(bounded: bool) -> Self {
            Self {
                controller: PathController::new(8_000_000, 20),
                bounded,
                packets: VecDeque::new(),
                queue_bits: 0.0,
                delivered_symbol_bytes: 0,
                delivered_app_bytes: 0,
                report_bytes: 0,
                report_number: 0,
                report: None,
                last_positive_delivery_at: None,
                reports: VecDeque::new(),
                pending_loss: (0, 0),
                finalized_expected: 0,
                finalized_lost: 0,
                interval_received: 0,
                interval_lost: 0,
                dropped: 0,
                probe: None,
                probes: VecDeque::new(),
                rtts: VecDeque::new(),
                quinn_rtt_ms: 17.0,
                next_probe_id: 0,
                ineligible_ticks: 0,
                ineligible_with_fresh_evidence: 0,
            }
        }

        fn enqueue(&mut self, now: u64, bytes: usize, business: bool) {
            let bits = (bytes * 8) as f64;
            if self.bounded && self.queue_bits + bits > 65536.0 * 8.0 {
                if business {
                    self.interval_lost += 1;
                    self.dropped += 1;
                }
                return;
            }
            self.packets.push_back(SimPacket {
                bits,
                at: now,
                business,
            });
            self.queue_bits += bits;
        }

        fn expire(&mut self, now: u64) {
            while self.bounded
                && self
                    .packets
                    .front()
                    .is_some_and(|p| now.saturating_sub(p.at) >= 250_000)
            {
                let packet = self.packets.pop_front().unwrap();
                self.queue_bits = (self.queue_bits - packet.bits).max(0.0);
                if packet.business {
                    self.interval_lost += 1;
                    self.dropped += 1;
                }
            }
        }

        fn tick(&mut self, now: u64, capacity_bps: f64) {
            self.expire(now);
            let queue_ms = self.queue_bits / capacity_bps * 1000.0;
            // Controls use the same queue; the expiry variant bounds their age.
            // Their loss/retransmission is left to the real protocol tests.
            let rtt = 17.0
                + if self.bounded {
                    queue_ms.min(250.0)
                } else {
                    queue_ms
                } * 2.0;
            if now.is_multiple_of(10_000) {
                self.rtts.push_back((now + 50_000, rtt));
            }
            while self.rtts.front().is_some_and(|(due, _)| *due <= now) {
                let (_, sample) = self.rtts.pop_front().unwrap();
                self.quinn_rtt_ms = self.quinn_rtt_ms * 0.875 + sample * 0.125;
            }
            while self.reports.front().is_some_and(|report| report.due <= now) {
                let report = self.reports.pop_front().unwrap();
                if self.report.is_none_or(|old| report.number > old.number) {
                    if report.bytes > self.report.map_or(0, |old| old.bytes) {
                        self.last_positive_delivery_at = Some(report.due);
                    }
                    self.report = Some(report);
                }
            }
            while self.probes.front().is_some_and(|(due, _, _)| *due <= now) {
                let (due, sample, id) = self.probes.pop_front().unwrap();
                if sample <= 3000.0 && self.probe.is_none_or(|(old, _, _)| id > old) {
                    self.probe = Some((id, sample, due));
                }
            }
            if now.is_multiple_of(100_000) {
                self.controller.observe(&Observation {
                    now_us: now,
                    generation: 7,
                    report_number: self.report.map_or(0, |v| v.number),
                    delivered_bytes: self.report.map_or(0, |v| v.bytes),
                    delivered_bps: self.report.map(|v| v.rate),
                    feedback_age_us: self.report.map(|v| now.saturating_sub(v.due)),
                    positive_delivery_age_us: self
                        .last_positive_delivery_at
                        .map(|at| now.saturating_sub(at)),
                    feedback_sample_symbols: self.report.map_or(0, |v| v.symbols),
                    loss_sample_rate: self.report.map(|v| v.loss),
                    finalized_expected: self.report.map(|v| v.expected),
                    finalized_lost: self.report.map(|v| v.lost),
                    rtt_ms: self.quinn_rtt_ms,
                    probe_latest_rtt_ms: self.probe.map(|v| v.1),
                    probe_rtt_ms: self.probe.map(|v| v.1),
                    probe_sample_id: self.probe.map_or(0, |v| v.0),
                    probe_age_us: self.probe.map(|v| now.saturating_sub(v.2)),
                    offered_backlog: true,
                    ..Default::default()
                });
            }
            if self.controller.decision(now).probe_due {
                self.controller.probe_admitted(now);
                self.next_probe_id += 1;
                if self.probes.len() == 4 {
                    self.probes.pop_front();
                }
                self.probes
                    .push_back((now + (rtt * 1000.0) as u64, rtt, self.next_probe_id));
                self.enqueue(now, 80, false);
            }
            if !self.controller.decision(now).eligible {
                self.ineligible_ticks += 1;
                if self
                    .controller
                    .last_evidence_us
                    .is_some_and(|at| now.saturating_sub(at) <= FRESH_US)
                    && self.controller.no_delivery_confirmed_us.is_none()
                {
                    self.ineligible_with_fresh_evidence += 1;
                }
            }
            while self.controller.allow(now, Self::WIRE, 0.0) {
                self.controller
                    .admitted_symbol(now, Self::WIRE, Self::SYMBOL);
                self.enqueue(now, Self::NETWORK, true);
            }
            let mut service = capacity_bps / 1000.0;
            while service > 0.0 {
                let Some(packet) = self.packets.front_mut() else {
                    break;
                };
                let taken = service.min(packet.bits);
                packet.bits -= taken;
                service -= taken;
                self.queue_bits = (self.queue_bits - taken).max(0.0);
                if packet.bits > 0.0 {
                    break;
                }
                let packet = self.packets.pop_front().unwrap();
                if packet.business {
                    self.delivered_symbol_bytes += Self::SYMBOL as u64;
                    self.delivered_app_bytes += Self::APP as u64;
                    self.interval_received += 1;
                }
            }
            if now > 0 && now.is_multiple_of(PROBE_US) {
                self.report_number += 1;
                let rate = (self.delivered_symbol_bytes - self.report_bytes) as f64 * 16.0;
                self.report_bytes = self.delivered_symbol_bytes;
                let symbols = self.interval_received + self.interval_lost;
                let (finalized_symbols, finalized_lost) = self.pending_loss;
                self.finalized_expected += finalized_symbols;
                self.finalized_lost += finalized_lost;
                self.reports.push_back(SimReport {
                    due: now + (rtt * 1000.0) as u64,
                    number: self.report_number,
                    bytes: self.delivered_symbol_bytes,
                    rate,
                    symbols: finalized_symbols,
                    // Tail loss needs a further feedback interval to finalize;
                    // its numerator and denominator must travel together.
                    loss: if finalized_symbols == 0 {
                        0.0
                    } else {
                        finalized_lost as f64 / finalized_symbols as f64
                    },
                    expected: self.finalized_expected,
                    lost: self.finalized_lost,
                });
                self.pending_loss = (symbols, self.interval_lost);
                self.interval_received = 0;
                self.interval_lost = 0;
            }
        }
    }

    fn capacity_step(bounded: bool) -> ([f64; 3], [u64; 2]) {
        let trace = std::env::var_os("BRAIDPATH_TRACE_ADAPTIVE").is_some();
        let mut lanes = [Lane::new(bounded), Lane::new(bounded)];
        let mut phase_bytes = [0u64; 3];
        let mut maximum_queue_ms: f64 = 0.0;
        let mut steady_bad_queue = Vec::new();
        for now in (0..40_000_000u64).step_by(1000) {
            for (id, lane) in lanes.iter_mut().enumerate() {
                let capacity = if id == 0 && (16_000_000..28_000_000).contains(&now) {
                    350_000.0
                } else {
                    3_000_000.0
                };
                let before = lane.delivered_app_bytes;
                let before_rate = lane.controller.rate_bps;
                let before_use = lane.controller.admitted_bytes;
                let before_allowance = lane.controller.allowance_bytes;
                lane.tick(now, capacity);
                if trace && bounded && id == 0 && now >= 26_000_000 && now.is_multiple_of(100_000) {
                    eprintln!(
                        "fifo t={now} rate={before_rate}->{} used={before_use}/{before_allowance:.0} delivery={:?} q={:.2} loss={:?} loss_pressure={} evidence={:?} last_growth={} last_brake={:?} report={:?}",
                        lane.controller.rate_bps,
                        lane.controller.latest_delivery_bps,
                        lane.controller.queue_delay_ms,
                        lane.report.map(|r| (r.symbols, r.loss)),
                        lane.controller.loss_pressure,
                        lane.controller.loss_evidence.counts(),
                        lane.controller.last_growth_us,
                        lane.controller.last_brake_us,
                        lane.report.map(|r| r.number)
                    );
                }
                if now >= 4_000_000 {
                    let phase = ((now - 4_000_000) / 12_000_000) as usize;
                    phase_bytes[phase] += lane.delivered_app_bytes - before;
                    maximum_queue_ms = maximum_queue_ms.max(lane.queue_bits / capacity * 1000.0);
                }
                if id == 0 && (22_000_000..28_000_000).contains(&now) {
                    steady_bad_queue.push(lane.queue_bits / capacity * 1000.0);
                }
            }
        }
        let rates = phase_bytes.map(|bytes| bytes as f64 * 8.0 / 12.0);
        let ideal_clean = 6_000_000.0 * Lane::APP as f64 / Lane::NETWORK as f64;
        steady_bad_queue.sort_by(f64::total_cmp);
        let queue95 = steady_bad_queue[steady_bad_queue.len() * 95 / 100];
        let stale = lanes.each_ref().map(|lane| lane.ineligible_ticks);
        eprintln!(
            "capacity step bounded={bounded}: window_a={:.0} window_b={:.0} window_c={:.0} app bps; ideal={:.0}; maximum virtual one-way queue={:.2}ms; steady impaired queue p95={:.2}ms; stale ticks={stale:?}; dropped={:?}",
            rates[0],
            rates[1],
            rates[2],
            ideal_clean,
            maximum_queue_ms,
            queue95,
            lanes.each_ref().map(|lane| lane.dropped)
        );
        assert!(
            lanes
                .iter()
                .all(|lane| lane.ineligible_with_fresh_evidence == 0)
        );
        assert!(
            lanes
                .iter()
                .all(|lane| lane.controller.rate_bps <= 8_000_000)
        );
        assert!(rates[0] >= ideal_clean * 0.90, "clean retention: {rates:?}");
        assert!(
            rates[2] >= ideal_clean * 0.90,
            "recovery retention: {rates:?}"
        );
        assert!(rates[1] >= 3_350_000.0 * Lane::APP as f64 / Lane::NETWORK as f64 * 0.85);
        assert!(
            queue95 < 100.0,
            "steady impaired queue grew again: {queue95}"
        );
        (rates, stale)
    }

    #[test]
    fn bounded_capacity_step_restores_clean_aggregation_without_fresh_quarantine() {
        let (_, stale) = capacity_step(true);
        assert_eq!(stale, [0, 0]);
    }

    #[test]
    fn unbounded_capacity_step_retains_delivery_while_exposing_stale_feedback() {
        let _ = capacity_step(false);
    }

    #[test]
    fn flat_high_queue_can_act_on_new_exercised_delivery_shortfall() {
        let mut controller = PathController::new(3_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 1_000_000;
        let mut sample = observation(500_000, 50.0);
        sample.delivered_bps = Some(2_000_000.0);
        controller.observe(&sample);
        sample.now_us += BRAKE_US;
        controller.observe(&sample);
        assert_eq!(controller.rate_bps, 1_000_000);
        assert_eq!(controller.braked_queue_ms, None);
        sample.now_us = 800_000;
        controller.observe(&sample);
        exercise_budget(&mut controller, 800_000, 300_000);
        sample = observation(1_100_000, 50.0);
        sample.delivered_bps = Some(500_000.0);
        controller.observe(&sample);
        assert!(controller.rate_bps < 500_000);
        let reduced = controller.rate_bps;
        for n in 3..10 {
            sample = observation(n * 500_000, 50.0);
            sample.delivered_bps = Some(reduced as f64);
            controller.observe(&sample);
            assert_eq!(controller.rate_bps, reduced);
        }
    }

    #[test]
    fn recovery_growth_revisits_retained_delivery_with_actual_admission() {
        let mut controller = PathController::new(8_000_000, 20);
        controller.observe(&observation(0, 20.0));
        controller.rate_bps = 300_000;
        controller.remembered_bps = 2_700_000.0;
        controller.congestion_seen = true;
        for n in 0..15 {
            let start = n * CONTROL_US;
            let admitted = exercise_budget(&mut controller, start, CONTROL_US);
            let mut sample = observation(start + CONTROL_US, 20.0);
            sample.delivered_bps = Some(admitted as f64 * 8_000_000.0 / CONTROL_US as f64);
            controller.observe(&sample);
        }
        assert!(controller.rate_bps >= 2_500_000);
        assert!(controller.rate_bps < 3_100_000);
    }
}
