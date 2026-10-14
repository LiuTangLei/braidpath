//! Byte-accounted pacing clock. Application, repair and retransmit datagrams
//! must all reserve this SAME budget. This does not estimate available bandwidth.
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct PacingClock {
    bytes_per_second: u64,
    next: Duration,
    max_credit: Duration,
}
impl PacingClock {
    pub fn new(bytes_per_second: u64, max_credit: Duration) -> Option<Self> {
        if bytes_per_second == 0 || max_credit > Duration::from_millis(10) {
            return None;
        }
        Some(Self { bytes_per_second, next: Duration::ZERO, max_credit })
    }
    /// Reserve a departure time. Credit after an idle/late wakeup is bounded,
    /// avoiding a giant catch-up burst. The caller sleeps until the returned time.
    pub fn reserve(&mut self, now: Duration, wire_bytes: usize) -> Duration {
        let at = self.next.max(now.saturating_sub(self.max_credit));
        let nanos = (wire_bytes as u128 * 1_000_000_000).div_ceil(self.bytes_per_second as u128);
        let cost = Duration::from_nanos(nanos.min(u64::MAX as u128) as u64);
        self.next = at.saturating_add(cost);
        at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bytes_and_repairs_share_budget_and_idle_credit_is_bounded() {
        let mut p = PacingClock::new(1_000_000, Duration::ZERO).unwrap();
        assert_eq!(p.reserve(Duration::ZERO, 1000), Duration::ZERO);
        assert_eq!(p.reserve(Duration::ZERO, 500), Duration::from_millis(1));
        assert_eq!(p.reserve(Duration::ZERO, 500), Duration::from_micros(1500));
        assert_eq!(p.reserve(Duration::from_secs(10), 1000), Duration::from_secs(10));
        assert_eq!(p.reserve(Duration::from_secs(10), 1000), Duration::from_millis(10001));
    }
    #[test]
    fn zero_rate_is_rejected_and_zero_byte_reservation_is_safe() {
        assert!(PacingClock::new(0, Duration::ZERO).is_none());
        let mut p = PacingClock::new(1, Duration::ZERO).unwrap();
        assert_eq!(p.reserve(Duration::ZERO, 0), Duration::ZERO);
    }
}
