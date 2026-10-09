//! Bounded per-path admission control. Rates are operational budgets, not capacity claims.
use serde::Serialize;
use std::collections::VecDeque;

mod reprobe;
pub use reprobe::Request as ReprobeRequest;

const FRESH_US: u64 = 3_000_000;
const CONTROL_US: u64 = 200_000;
const PROBE_US: u64 = 500_000;
const BRAKE_US: u64 = 100_000;
const RETRY_GROWTH_US: u64 = 500_000;
const START_BPS: u64 = 256_000;
const MIN_BPS: u64 = 64_000;
const LOSS_WINDOW_US: u64 = 4_000_000;
const LOSS_BATCHES: usize = 8;

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
    QueueBrake,
    DeliveryShortfallBrake,
    FastLossBrake,
    LossBrake,
    TransportBlockedBrake,
    ReprobeStart,
    ReprobeRollback,
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
    pub queue_delay_ms: f64,
    pub transport_blocked: bool,
    pub offered_backlog: bool,
    pub latest_symbol_delivery_bps: Option<f64>,
    pub ordinary_loss_pressure: bool,
    pub fast_loss: bool,
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

#[derive(Clone, Debug, Default)]
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
    /// Diagnostic EWMA. Control uses bounded finalized-count evidence below.
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

pub struct PathController {
    maximum_bps: u64,
    target_ms: f64,
    generation: Option<u64>,
    born_us: u64,
    rate_bps: u64,
    min_rtt_ms: Option<f64>,
    queue_delay_ms: f64,
    health: Health,
    eligible: bool,
    last_evidence_us: Option<u64>,
    no_delivery_confirmed_us: Option<u64>,
    last_probe_us: Option<u64>,
    last_control_us: u64,
    last_growth_us: u64,
    growth_not_before_us: u64,
    last_brake_us: Option<u64>,
    last_probe_sample_id: u64,
    last_rtt_ms: Option<f64>,
    last_local_rtt_ms: Option<f64>,
    last_transport_wait_ms: f64,
    admitted_bytes: u64,
    admitted_symbol_bytes: u64,
    allowance_bytes: f64,
    wire_per_symbol: f64,
    blocked_since_us: Option<u64>,
    delay_since_us: Option<u64>,
    braked_queue_ms: Option<f64>,
    last_report: Option<(u64, u64, u64)>,
    delivery_bps: Option<f64>,
    latest_delivery_bps: Option<f64>,
    /// Short-lived service measured while bytes left faster than we admitted.
    draining_bps: Option<(f64, u64)>,
    drain_restore_pending: bool,
    /// Previously achieved delivery, retained across temporary congestion. An
    /// application-limited sample never decreases this exploration reference.
    remembered_bps: f64,
    congestion_seen: bool,
    loss_evidence: LossEvidence,
    loss_pressure: bool,
    pressure_episode_exercised: Option<bool>,
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
            queue_delay_ms: 0.0,
            health: Health::Unknown,
            eligible: true,
            last_evidence_us: None,
            no_delivery_confirmed_us: None,
            last_probe_us: None,
            last_control_us: 0,
            last_growth_us: 0,
            growth_not_before_us: 0,
            last_brake_us: None,
            last_probe_sample_id: 0,
            last_rtt_ms: None,
            last_local_rtt_ms: None,
            last_transport_wait_ms: 0.0,
            admitted_bytes: 0,
            admitted_symbol_bytes: 0,
            allowance_bytes: 0.0,
            wire_per_symbol: 1.0,
            blocked_since_us: None,
            delay_since_us: None,
            braked_queue_ms: None,
            last_report: None,
            delivery_bps: None,
            latest_delivery_bps: None,
            draining_bps: None,
            drain_restore_pending: false,
            remembered_bps: 0.0,
            congestion_seen: false,
            loss_evidence: LossEvidence::default(),
            loss_pressure: false,
            pressure_episode_exercised: None,
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
        self.refill(now);
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
        let new_report = (feedback_fresh || delivery_fresh)
            && self
                .last_report
                .is_none_or(|(number, _, _)| observation.report_number > number);
        let new_loss_report = new_report && feedback_fresh;
        if new_report {
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
                if observation.offered_backlog {
                    self.remembered_bps = self
                        .remembered_bps
                        .max((rate * self.wire_per_symbol).min(self.maximum_bps as f64));
                }
            }
            self.last_report = Some((observation.report_number, observation.delivered_bytes, now));
        }
        let loss_batch = self.loss_evidence.observe(observation, new_report);
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
        let wire_delivery_bps = self
            .latest_delivery_bps
            .map(|rate| rate * self.wire_per_symbol);
        let drain_hint = wire_delivery_bps.unwrap_or(0.0).max(self.rate_bps as f64);
        // A bounded two-datagram burst briefly waiting for Quinn's driver is not congestion.
        let queued_beyond_burst = observation.send_queue_bytes.saturating_sub(2400);
        let transport_wait = queued_beyond_burst as f64 * 8000.0 / drain_hint;
        let previous_queue = self.queue_delay_ms;
        self.queue_delay_ms = rtt_excess.max(transport_wait);
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
            now.saturating_sub(since) >= BRAKE_US || self.queue_delay_ms >= self.target_ms * 4.0
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
        let loss_counts = self.loss_evidence.counts();
        self.last_control = ControlSample {
            at_us: now,
            generation: observation.generation,
            report_number: observation.report_number,
            delivery_report_time_us: observation.delivery_report_time_us,
            delivery_sample_span_us: observation.delivery_sample_span_us,
            admitted_bytes: self.admitted_bytes,
            integrated_allowance_bytes: self.allowance_bytes,
            admission_span_us: admission_span,
            queue_delay_ms: self.queue_delay_ms,
            transport_blocked: observation.transport_blocked,
            offered_backlog: observation.offered_backlog,
            latest_symbol_delivery_bps: self.latest_delivery_bps,
            ordinary_loss_pressure: self.loss_pressure,
            fast_loss,
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
        let new_loss =
            fast_loss || (loss_batch.is_some() && self.loss_pressure && !protect_ordinary_loss);
        let loss_for_brake = if fast_loss {
            loss_batch.map_or(0.0, |(n, lost)| lost as f64 / n as f64)
        } else {
            self.loss_evidence.fraction()
        };
        let pressure = delay_pressure
            || (self.loss_pressure && !protect_ordinary_loss)
            || fast_loss
            || blocked_pressure;
        if pressure {
            self.pressure_episode_exercised.get_or_insert(exercised);
        } else if new_loss_report && observation.feedback_sample_symbols > 0 {
            // A clear RTT alone can precede the delayed loss report for this
            // episode. Require a genuinely new, finalized clear interval too.
            self.pressure_episode_exercised = None;
        }
        let delivery_shortfall = new_report
            && delay_pressure
            && admission_span > 0
            && now.saturating_sub(self.last_growth_us) >= PROBE_US + BRAKE_US
            && exercised
            && wire_delivery_bps.is_some_and(|rate| rate < self.rate_bps as f64 * 0.85);
        if delivery_shortfall {
            // A new underdelivery report, exercised integrated allowance and
            // no recent growth can replace an older, higher drain hint. A
            // recent safety brake can still have changed the active rate.
            self.draining_bps = wire_delivery_bps.map(|rate| (rate, now));
        }
        if new_report
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

        let new_delay = persistent_delay
            && self.braked_queue_ms.is_none_or(|last| {
                new_queue && self.queue_delay_ms > last + (self.target_ms * 0.1).max(1.0)
            });
        let new_pressure =
            new_delay || delivery_shortfall || new_loss || (blocked_pressure && new_report);
        // An unused allowance is not traffic that can be drained. Sparse idle
        // echo/probe jitter must not turn its small delivery sample into a path
        // capacity estimate. Backlog or a blocked transport still permits an
        // immediate safety brake, including before exercise is qualified.
        let active_demand = observation.offered_backlog || exercised || blocked_pressure;
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
            let mut desired = service_hint
                .filter(|rate| {
                    *rate > 0.0
                        && (self.pressure_episode_exercised == Some(true)
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
                // Safety always brakes. Persistent caution requires exercise
                // captured before this episode's first reduction, not use of a
                // later, smaller allowance while the old evidence drains.
                let capacity_evidence = new_delay
                    || delivery_shortfall
                    || (blocked_pressure && new_report)
                    || (new_loss && settled_shortfall);
                self.congestion_seen |=
                    self.pressure_episode_exercised == Some(true) && capacity_evidence;
                if new_delay {
                    self.braked_queue_ms = Some(self.queue_delay_ms);
                    self.drain_restore_pending = true;
                }
                self.rate_bps = reduced;
                rate_reason = if fast_loss {
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
                self.last_brake_us = Some(now);
                self.growth_not_before_us = now.saturating_add(RETRY_GROWTH_US);
            }
        }

        let elapsed = now.saturating_sub(self.last_control_us);
        if elapsed >= CONTROL_US {
            if fresh
                && self.eligible
                && !pressure
                && !protect_ordinary_loss
                && self.drain_restore_pending
            {
                // RTT observations are more frequent than control ticks. Keep
                // the drainage transition pending so an intervening clear RTT
                // cannot erase restoration before the next control tick.
                if let Some(drain) = recent_drain {
                    let restored = (drain * 0.9).min(self.maximum_bps as f64) as u64;
                    if restored > self.rate_bps {
                        self.rate_bps = restored;
                        rate_reason = RateReason::KnownServiceRecovery;
                        self.last_growth_us = now;
                    }
                }
                self.drain_restore_pending = false;
            }
            if fresh
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
                let receiver_keeps_up =
                    wire_delivery_bps.is_some_and(|rate| rate >= allowance_rate * 0.85);
                let (interval, gain, ceiling) = if !self.congestion_seen {
                    // The initial search is fast only when actual admissions and
                    // receiver delivery support it, not at 60% use of an unused budget.
                    (400_000, 1.5, self.maximum_bps as f64)
                } else if (self.rate_bps as f64) < self.remembered_bps * 0.90 {
                    // Revisit a previously exercised range in small, observable
                    // steps. A failed trial brakes and waits before another attempt.
                    (CONTROL_US, 1.25, self.remembered_bps * 0.95)
                } else {
                    (500_000, 1.03, self.maximum_bps as f64)
                };
                if now.saturating_sub(self.last_growth_us) >= interval
                    && (self.congestion_seen || receiver_keeps_up)
                {
                    self.rate_bps = ((self.rate_bps as f64 * gain).min(ceiling) as u64)
                        .max(self.rate_bps)
                        .min(self.maximum_bps);
                    rate_reason = if !self.congestion_seen {
                        RateReason::InitialGrowth
                    } else if (self.rate_bps as f64) < self.remembered_bps * 0.90 {
                        RateReason::KnownServiceRecovery
                    } else {
                        RateReason::CautiousGrowth
                    };
                    self.last_growth_us = now;
                }
            }
            self.last_control_us = now;
            self.admitted_bytes = 0;
            self.admitted_symbol_bytes = 0;
            self.allowance_bytes = 0.0;
        }
        self.rate_bps = self.rate_bps.min(self.maximum_bps).max(1);
        self.record_rate_change(now, previous_rate, rate_reason);
        self.last_probe_sample_id = observation.probe_sample_id;
        self.last_rtt_ms = rtt;
        self.last_local_rtt_ms = local_rtt;
        self.last_transport_wait_ms = transport_wait;
        self.tokens = self.tokens.min(2400.0);
    }

    pub fn decision(&self, now_us: u64) -> Decision {
        let stale = now_us.saturating_sub(self.born_us) >= FRESH_US
            && self
                .last_evidence_us
                .is_none_or(|time| now_us.saturating_sub(time) > FRESH_US);
        Decision {
            pacing_bps: self.rate_bps,
            eligible: self.eligible && !stale,
            weight: ((self.rate_bps as f64 / 64_000.0)
                / (1.0
                    + self.min_rtt_ms.unwrap_or(50.0) / 50.0
                    + self.queue_delay_ms / self.target_ms))
                .round()
                .clamp(1.0, 128.0) as i32,
            state: if stale { Health::Probing } else { self.health },
            queue_delay_ms: self.queue_delay_ms,
            probe_due: self
                .last_probe_us
                .is_none_or(|time| now_us.saturating_sub(time) >= PROBE_US),
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
        self.tokens = (self.tokens - wire_bytes as f64).max(0.0);
        self.admitted_bytes = self.admitted_bytes.saturating_add(wire_bytes as u64);
        self.admitted_symbol_bytes = self
            .admitted_symbol_bytes
            .saturating_add(measured_symbol_bytes as u64);
        self.reprobe.admitted(wire_bytes);
    }

    pub fn probe_admitted(&mut self, now_us: u64) {
        self.last_probe_us = Some(now_us);
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

    fn record_rate_change(&mut self, now_us: u64, previous_bps: u64, reason: RateReason) {
        if previous_bps == self.rate_bps {
            return;
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
