//! Flight delivery sampling using the state saved with each transmitted packet.
//! See draft-cheng-iccrg-delivery-rate-estimation-02. This implements the sampling
//! model, not a BBR version upgrade. Recovery owns the snapshots; no packet map
//! or payload allocation is maintained by the controller.
use std::fmt::{Debug, Display, Formatter};

use super::min_max::MinMax;
use crate::congestion::PacketState;
use crate::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
struct Sample {
    state: PacketState,
    sent: Instant,
    acknowledged: Instant,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BandwidthEstimation {
    total_acked: u64,
    acked_at_last_window: u64,
    clock_origin: Option<Instant>,
    delivered_at: Option<Instant>,
    first_sent_at: Option<Instant>,
    app_limited_until: Option<u64>,
    pending: Option<Sample>,
    sample_app_limited: Option<bool>,
    max_filter: MinMax,
}

impl BandwidthEstimation {
    pub(crate) fn on_sent(&mut self, now: Instant, in_flight: u64) -> PacketState {
        self.clock_origin.get_or_insert(now);
        if in_flight == 0 || self.delivered_at.is_none() {
            self.delivered_at = Some(now);
            self.first_sent_at = Some(now);
        }
        PacketState {
            delivered: self.total_acked,
            delivered_at_ns: self.clock(self.delivered_at.unwrap()),
            first_sent_at_ns: self.clock(self.first_sent_at.unwrap()),
            app_limited: self.app_limited_until.is_some(),
        }
    }

    pub(crate) fn on_app_limited(&mut self, in_flight: u64) {
        let until = self.total_acked.saturating_add(in_flight);
        self.app_limited_until = Some(self.app_limited_until.map_or(until, |old| old.max(until)));
    }

    pub(crate) fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        state: Option<PacketState>,
    ) {
        self.total_acked = self.total_acked.saturating_add(bytes);
        self.delivered_at = Some(now);
        if let Some(state) = state {
            // Select the most recent send-time reference within an ACK batch.
            // Reordered ACKs cannot move the next flight's send clock backwards.
            if state.delivered <= self.total_acked
                && sent <= now
                && state.first_sent_at_ns <= self.clock(sent)
                && state.delivered_at_ns <= self.clock(now)
                && self
                    .pending
                    .is_none_or(|old| (state.delivered, sent) >= (old.state.delivered, old.sent))
            {
                self.pending = Some(Sample {
                    state,
                    sent,
                    acknowledged: now,
                });
                self.first_sent_at = Some(self.first_sent_at.map_or(sent, |old| old.max(sent)));
            }
        }
        if self
            .app_limited_until
            .is_some_and(|until| self.total_acked > until)
        {
            self.app_limited_until = None;
        }
    }

    // Relative nanoseconds keep the inline recovery snapshot at 32 bytes,
    // including its optional marker, without a per-packet heap allocation.
    fn clock(&self, at: Instant) -> u64 {
        at.saturating_duration_since(self.clock_origin.unwrap_or(at))
            .as_nanos()
            .min(u64::MAX as u128) as u64
    }

    pub(crate) fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub(crate) fn end_acks(&mut self, round: u64) {
        self.sample_app_limited = None;
        if let Some(sample) = self.pending.take() {
            let elapsed = Duration::from_nanos(
                (self.clock(sample.sent) - sample.state.first_sent_at_ns)
                    .max(self.clock(sample.acknowledged) - sample.state.delivered_at_ns),
            );
            let delivered = self.total_acked - sample.state.delivered;
            if delivered > 0 {
                if let Some(rate) = Self::bw_from_delta(delivered, elapsed) {
                    self.sample_app_limited = Some(sample.state.app_limited);
                    // Lower busy samples age the filter; an application-limited
                    // sample may reveal more capacity but cannot lower the model.
                    if !sample.state.app_limited || rate > self.max_filter.get() {
                        self.max_filter.update_max(round, rate);
                    }
                }
            }
        }
        self.acked_at_last_window = self.total_acked;
    }

    pub(crate) fn sample_app_limited(&self) -> Option<bool> {
        self.sample_app_limited
    }

    pub(crate) fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub(crate) const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let nanos = delta.as_nanos();
        if nanos == 0 {
            return None;
        }
        let rate = bytes as u128 * 1_000_000_000 / nanos;
        Some(if rate > u64::MAX as u128 {
            u64::MAX
        } else {
            rate as u64
        })
    }
}

impl Display for BandwidthEstimation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.3} MB/s",
            self.get_estimate() as f32 / (1024 * 1024) as f32
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        estimate: &mut BandwidthEstimation,
        at: &mut Instant,
        duration: Duration,
        round: u64,
        limited: bool,
    ) {
        if limited {
            estimate.on_app_limited(0);
        }
        let sent = *at;
        let state = estimate.on_sent(sent, 0);
        *at += duration;
        estimate.on_ack(*at, sent, 1000, Some(state));
        estimate.end_acks(round);
    }

    #[test]
    fn lower_delivery_samples_expire_an_old_bandwidth_peak() {
        let mut estimate = BandwidthEstimation::default();
        let mut now = Instant::now();
        sample(&mut estimate, &mut now, Duration::from_millis(1), 1, false);
        assert_eq!(estimate.get_estimate(), 1_000_000);
        for round in 2..=12 {
            sample(
                &mut estimate,
                &mut now,
                Duration::from_millis(10),
                round,
                false,
            );
        }
        assert_eq!(estimate.get_estimate(), 100_000);
    }

    #[test]
    fn application_limited_samples_can_raise_but_not_lower_the_model() {
        let mut estimate = BandwidthEstimation::default();
        let mut now = Instant::now();
        sample(&mut estimate, &mut now, Duration::from_millis(10), 1, false);
        assert_eq!(estimate.get_estimate(), 100_000);
        sample(&mut estimate, &mut now, Duration::from_millis(1), 2, true);
        assert_eq!(estimate.get_estimate(), 1_000_000);
        for round in 3..=20 {
            sample(
                &mut estimate,
                &mut now,
                Duration::from_millis(100),
                round,
                true,
            );
        }
        assert_eq!(estimate.get_estimate(), 1_000_000);
    }

    #[test]
    fn a_stretched_ack_counts_the_entire_delivered_flight() {
        let mut estimate = BandwidthEstimation::default();
        let start = Instant::now();
        let mut flight = Vec::new();
        for index in 0..100 {
            let sent = start + Duration::from_millis(index);
            flight.push((sent, estimate.on_sent(sent, index * 1200)));
        }
        let ack = start + Duration::from_millis(200);
        for (sent, state) in flight {
            estimate.on_ack(ack, sent, 1200, Some(state));
        }
        assert_eq!(estimate.bytes_acked_this_window(), 120_000);
        estimate.end_acks(1);
        assert_eq!(estimate.get_estimate(), 600_000);
        assert_eq!(estimate.bytes_acked_this_window(), 0);
        assert!(estimate.pending.is_none());
    }

    #[test]
    fn reordered_acks_and_idle_restart_keep_the_send_reference_valid() {
        let mut estimate = BandwidthEstimation::default();
        let start = Instant::now();
        let first = estimate.on_sent(start, 0);
        let later = start + Duration::from_millis(100);
        let second = estimate.on_sent(later, 1200);
        estimate.on_ack(
            later + Duration::from_millis(100),
            later,
            1200,
            Some(second),
        );
        estimate.end_acks(1);
        estimate.on_ack(later + Duration::from_millis(101), start, 1200, Some(first));
        estimate.end_acks(1);
        assert_eq!(estimate.first_sent_at, Some(later));
        let restart = start + Duration::from_secs(60);
        let state = estimate.on_sent(restart, 0);
        assert_eq!(state.delivered_at_ns, estimate.clock(restart));
        assert_eq!(state.first_sent_at_ns, estimate.clock(restart));
        estimate.on_ack(
            restart + Duration::from_millis(100),
            restart,
            1200,
            Some(state),
        );
        estimate.end_acks(20);
        assert_eq!(estimate.get_estimate(), 12_000);
    }

    #[test]
    fn rate_conversion_handles_long_intervals_and_zero_clock_delta() {
        assert_eq!(
            BandwidthEstimation::bw_from_delta(u64::MAX, Duration::from_secs(u64::MAX)),
            Some(1)
        );
        assert_eq!(
            BandwidthEstimation::bw_from_delta(u64::MAX, Duration::from_nanos(1)),
            Some(u64::MAX)
        );
        assert_eq!(
            BandwidthEstimation::bw_from_delta(1200, Duration::ZERO),
            None
        );
    }
}
