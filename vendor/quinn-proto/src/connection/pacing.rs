//! Pacing of packet transmissions.

use crate::{Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
pub(super) struct Pacer {
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    tokens: u64,
    prev: Instant,
    rate: Option<u64>,
    waiting_until: Option<Instant>,
    stream_backlogged: bool,
    observation: Observation,
}

#[derive(Default)]
struct Observation {
    refills: u64,
    refill_bytes: u64,
    discarded_bytes: u64,
    late_us: u64,
    max_late_us: u64,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(smoothed_rtt: Duration, window: u64, mtu: u16, now: Instant) -> Self {
        let capacity = optimal_capacity(smoothed_rtt, window, mtu);
        Self {
            capacity,
            last_window: window,
            last_mtu: mtu,
            tokens: capacity,
            prev: now,
            rate: None,
            waiting_until: None,
            stream_backlogged: false,
            observation: Observation::default(),
        }
    }

    /// Preserve the congestion window as an in-flight bound, while a model-based
    /// controller independently controls the rate at which that window is sent.
    pub(super) fn set_rate(&mut self, rate: Option<u64>) {
        let rate = rate.filter(|&rate| rate > 0);
        if self.rate != rate {
            self.rate = rate;
            self.last_window = 0; // Recompute and clamp the burst before sending.
            self.waiting_until = None;
        }
    }

    pub(super) fn set_stream_backlogged(&mut self, active: bool) {
        if self.stream_backlogged != active {
            self.waiting_until = None;
            self.tokens = self.tokens.min(self.capacity);
            self.stream_backlogged = active;
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        if window != self.last_window || mtu != self.last_mtu {
            self.capacity = match self.rate {
                Some(rate) => ((rate as u128 * BURST_INTERVAL_NANOS / 1_000_000_000)
                    .min(u64::MAX as u128) as u64)
                    .clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64),
                None => optimal_capacity(smoothed_rtt, window, mtu),
            };

            // Clamp the tokens
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_mtu = mtu;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        if let Some(rate) = self.rate {
            let elapsed = now.checked_duration_since(self.prev).unwrap_or_default();
            let refill =
                (elapsed.as_nanos() * rate as u128 / 1_000_000_000).min(u64::MAX as u128) as u64;
            let limit = self.refill_limit(now, rate, mtu);
            self.observe_refill(now, refill, limit);
            self.tokens = self.tokens.saturating_add(refill).min(limit);
            self.prev = now;
            if self.tokens >= bytes_to_send {
                return None;
            }
            let missing = bytes_to_send.max(self.capacity) - self.tokens;
            let nanos = (missing as u128 * 1_000_000_000).div_ceil(rate as u128);
            let until = now + Duration::from_nanos(nanos.min(u64::MAX as u128) as u64);
            self.waiting_until = Some(until);
            return Some(until);
        }

        // we disable pacing for extremely large windows
        if window > u64::from(u32::MAX) {
            return None;
        }

        let window = window as u32;

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });

        if smoothed_rtt.as_nanos() == 0 {
            return None;
        }

        let elapsed_rtts = time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64();
        let new_tokens = window as f64 * 1.25 * elapsed_rtts;
        self.tokens = self
            .tokens
            .saturating_add(new_tokens as _)
            .min(self.capacity);

        self.prev = now;

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        let unscaled_delay = smoothed_rtt
            .checked_mul((bytes_to_send.max(self.capacity) - self.tokens) as _)
            .unwrap_or(Duration::MAX)
            / window;

        // divisions come before multiplications to prevent overflow
        // this is the time at which the pacing window becomes empty
        Some(self.prev + (unscaled_delay / 5) * 4)
    }

    fn refill_limit(&self, now: Instant, rate: u64, mtu: u16) -> u64 {
        let due = self.stream_backlogged
            && self
                .waiting_until
                .and_then(|at| now.checked_duration_since(at))
                .is_some_and(|late| late <= Duration::from_millis(20));
        if !due {
            return self.capacity;
        }
        // Retain at most one extra millisecond of earned service after a late
        // backlogged wake. Idle credit, normal wake deadlines and rate remain
        // unchanged; the native congestion window still bounds in-flight data.
        let extra =
            (u128::from(rate) * 1_000_000 / 1_000_000_000).min(u128::from(self.capacity)) as u64;
        self.capacity
            .saturating_add(extra)
            .min(MAX_BURST_SIZE * u64::from(mtu))
    }

    fn observe_refill(&mut self, now: Instant, refill: u64, limit: u64) {
        let Some(until) = self.waiting_until.take() else {
            return;
        };
        let Some(late) = now.checked_duration_since(until) else {
            return;
        };
        // Long idle gaps do not establish loss of backlogged pacing service.
        if late > Duration::from_millis(20) {
            return;
        }
        self.observation.refills += 1;
        self.observation.refill_bytes = self.observation.refill_bytes.saturating_add(refill);
        self.observation.discarded_bytes = self
            .observation
            .discarded_bytes
            .saturating_add(self.tokens.saturating_add(refill).saturating_sub(limit));
        let micros = late.as_micros().min(u128::from(u64::MAX)) as u64;
        self.observation.late_us = self.observation.late_us.saturating_add(micros);
        self.observation.max_late_us = self.observation.max_late_us.max(micros);
    }
}

impl Drop for Pacer {
    fn drop(&mut self) {
        if self.observation.refills > 0 {
            tracing::info!(target: "quinn_proto::pacing_observation",
                refills=self.observation.refills, refill_bytes=self.observation.refill_bytes,
                discarded_bytes=self.observation.discarded_bytes,
                timer_late_us=self.observation.late_us,
                max_timer_late_us=self.observation.max_late_us,
                rate_bytes_per_second=?self.rate, last_window=self.last_window,
                "backlogged pacing observations");
        }
    }
}

/// Calculates a pacer capacity for a certain window and RTT
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space is not high enough. If we miss the interval by more
/// than 25%, we will lose that part of the congestion window since no additional
/// tokens for the extra-elapsed time can be stored.
///
/// Too long burst intervals make pacing less effective.
fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);

    let capacity = ((window as u128 * BURST_INTERVAL_NANOS) / rtt) as u64;

    // Small bursts are less efficient (no GSO), could increase latency and don't effectively
    // use the channel's buffer capacity. Large bursts might block the connection on sending.
    capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
}

/// The burst interval
///
/// The capacity will we refilled in 4/5 of that time.
/// 2ms is chosen here since framework timers might have 1ms precision.
/// If kernel-level pacing is supported later a higher time here might be
/// more applicable.
const BURST_INTERVAL_NANOS: u128 = 2_000_000; // 2ms

/// Allows some usage of GSO, and doesn't slow down the handshake.
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1ms in a benchmark, so larger bursts don't make sense.
const MAX_BURST_SIZE: u64 = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagrams_keep_the_original_bucket_after_late_wakes_and_streams() {
        let at = Instant::now();
        let rtt = Duration::from_millis(100);
        let window = 20 * 1024 * 1024;
        let mut p = Pacer::new(rtt, window, 1000, at);
        p.set_rate(Some(10_000_000));
        for _ in 0..20 {
            assert_eq!(p.delay(rtt, 1000, 1000, window, at), None);
            p.on_transmit(1000);
        }
        assert!(p.delay(rtt, 1000, 1000, window, at).is_some());
        let late = at + Duration::from_millis(3);
        assert_eq!(p.delay(rtt, 1000, 1000, window, late), None);
        assert_eq!(
            p.tokens, 20_000,
            "DATAGRAM does not gain stream catch-up credit"
        );
        p.set_stream_backlogged(true);
        p.tokens = 30_000;
        p.set_stream_backlogged(false);
        assert_eq!(
            p.tokens, 20_000,
            "stream credit cannot leak into DATAGRAM traffic"
        );
    }
    #[test]
    fn a_three_ms_wake_delivers_three_ms_of_modeled_credit() {
        let start = Instant::now();
        let rtt = Duration::from_millis(100);
        let window = 20 * 1024 * 1024;
        let mut p = Pacer::new(rtt, window, 1000, start);
        p.set_rate(Some(10_000_000));
        p.set_stream_backlogged(true);
        for _ in 0..20 {
            assert_eq!(p.delay(rtt, 1000, 1000, window, start), None);
            p.on_transmit(1000);
        }
        assert_eq!(
            p.delay(rtt, 1000, 1000, window, start),
            Some(start + Duration::from_millis(2))
        );
        let late = start + Duration::from_millis(3);
        let mut count = 0;
        while p.delay(rtt, 1000, 1000, window, late).is_none() {
            p.on_transmit(1000);
            count += 1;
            assert!(count < 100);
        }
        assert_eq!(
            count, 30,
            "timer lateness must not throw away earned pacing service"
        );
    }

    #[test]
    fn late_credit_is_bounded_and_idle_or_rate_changes_do_not_bank_it() {
        let at = Instant::now();
        let rtt = Duration::from_millis(100);
        let window = 20 * 1024 * 1024;
        fn send(p: &mut Pacer, now: Instant, rtt: Duration, window: u64) -> u64 {
            let mut n = 0;
            while p.delay(rtt, 1000, 1000, window, now).is_none() {
                p.on_transmit(1000);
                n += 1;
                assert!(n < 1000);
            }
            n
        }
        let mut p = Pacer::new(rtt, window, 1000, at);
        p.set_rate(Some(10_000_000));
        p.set_stream_backlogged(true);
        assert_eq!(send(&mut p, at, rtt, window), 20);
        assert_eq!(
            send(&mut p, at + Duration::from_millis(10), rtt, window),
            30,
            "large scheduling stalls cannot create an unbounded burst"
        );
        let mut idle = Pacer::new(rtt, window, 1000, at);
        idle.set_rate(Some(10_000_000));
        idle.set_stream_backlogged(true);
        for _ in 0..20 {
            assert_eq!(idle.delay(rtt, 1000, 1000, window, at), None);
            idle.on_transmit(1000);
        }
        assert_eq!(
            send(&mut idle, at + Duration::from_secs(1), rtt, window),
            20,
            "idle is the original bucket"
        );
        let mut changed = Pacer::new(rtt, window, 1000, at);
        changed.set_rate(Some(10_000_000));
        changed.set_stream_backlogged(true);
        send(&mut changed, at, rtt, window);
        let later = at + Duration::from_millis(3);
        assert_eq!(changed.delay(rtt, 1000, 1000, window, later), None);
        changed.set_rate(Some(1_000_000));
        assert_eq!(
            send(&mut changed, later, rtt, window),
            10,
            "a lower rate clamps late credit immediately"
        );
    }
    #[test]
    fn repeated_late_wakes_retain_service_without_exceeding_the_rate() {
        let at = Instant::now();
        let rtt = Duration::from_millis(100);
        let window = 20 * 1024 * 1024;
        let mut now = at;
        let mut p = Pacer::new(rtt, window, 1000, at);
        p.set_rate(Some(10_000_000));
        p.set_stream_backlogged(true);
        let mut sent = 0u64;
        for gap in [0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3] {
            now += Duration::from_millis(gap);
            let mut n = 0;
            while p.delay(rtt, 1000, 1000, window, now).is_none() {
                p.on_transmit(1000);
                sent += 1000;
                n += 1;
                assert!(n <= 40);
            }
            let earned = 20_000 + (now - at).as_micros() as u64 * 10;
            assert_eq!(sent, earned);
        }
    }

    #[test]
    fn modeled_rate_does_not_send_an_inflated_window_per_rtt() {
        let now = Instant::now();
        let rtt = Duration::from_millis(100);
        let window = 20 * 1024 * 1024;
        let mut pacer = Pacer::new(rtt, window, 1000, now);
        pacer.set_rate(Some(10_000_000));
        for _ in 0..20 {
            assert_eq!(pacer.delay(rtt, 1000, 1000, window, now), None);
            pacer.on_transmit(1000);
        }
        assert_eq!(pacer.capacity, 20_000);
        assert_eq!(
            pacer.delay(rtt, 1000, 1000, window, now),
            Some(now + Duration::from_millis(2))
        );
        let next = now + Duration::from_millis(1);
        assert_eq!(pacer.delay(rtt, 1000, 1000, window, next), None);
        assert_eq!(pacer.tokens, 10_000);
        // A lower model rate immediately clamps saved tokens and burst credit.
        pacer.set_rate(Some(1_000_000));
        assert_eq!(pacer.delay(rtt, 1000, 1000, window, next), None);
        assert_eq!(pacer.capacity, 10_000);
        assert_eq!(pacer.tokens, 10_000);
        pacer.set_rate(None);
        pacer.delay(rtt, 1000, 1000, window, next);
        assert_eq!(pacer.capacity, optimal_capacity(rtt, window, 1000));
    }

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(Pacer::new(rtt, 30000, 1500, new_instant)
            .delay(Duration::from_micros(0), 0, 1500, 1, old_instant)
            .is_none());
        assert!(Pacer::new(rtt, 30000, 1500, new_instant)
            .delay(Duration::from_micros(0), 1600, 1500, 1, old_instant)
            .is_none());
        assert!(Pacer::new(rtt, 30000, 1500, new_instant)
            .delay(Duration::from_micros(0), 1500, 1500, 3000, old_instant)
            .is_none());
    }

    #[test]
    fn derives_initial_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(Duration::from_millis(0), window, mtu, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(rtt, 1, mtu, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, mtu as u64, mtu, window * 2, now);
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, mtu as u64, mtu, window / 2, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, mtu as u64, mtu * 2, window, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, mtu as u64, 20_000, window, now);
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((BURST_INTERVAL_NANOS * 4 / 5) as u64);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration
        );

        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration * 3 / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }
}
