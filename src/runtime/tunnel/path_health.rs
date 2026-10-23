//! Qualify a mesh data failure from admitted traffic with no positive feedback.
//! Idle connections and new generations do not inherit another attempt's loss.
use crate::runtime::quality::Snapshot;

#[derive(Default)]
pub(super) struct DeliveryHealth {
    generation: Option<u64>,
    sent: u64,
    received: u64,
    received_bytes: u64,
    pending: u64,
    since: Option<u64>,
}
impl DeliveryHealth {
    pub(super) fn stalled(&mut self, now_us: u64, quality: &Snapshot) -> bool {
        if self.generation != Some(quality.generation) {
            *self = Self {
                generation: Some(quality.generation),
                ..Default::default()
            };
        }
        if quality.sender_estimate.received > self.received
            || quality.sender_estimate.received_bytes > self.received_bytes
        {
            self.pending = 0;
            self.since = None;
        } else if quality.sent_symbols > self.sent {
            self.pending += quality.sent_symbols - self.sent;
            self.since.get_or_insert(now_us);
        }
        self.sent = quality.sent_symbols;
        self.received = quality.sender_estimate.received;
        self.received_bytes = quality.sender_estimate.received_bytes;
        self.pending >= 8
            && self
                .since
                .is_some_and(|at| now_us.saturating_sub(at) >= 3_000_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_loss_and_generation_changes_have_distinct_health() {
        let mut health = DeliveryHealth::default();
        let mut q = Snapshot::default();
        assert!(!health.stalled(20_000_000, &q));
        q.sent_symbols = 8;
        assert!(!health.stalled(21_000_000, &q));
        // Full loss reports and successful QUIC probes do not prove data delivery.
        q.sender_estimate.updated_us = Some(23_000_000);
        q.probe_updated_us = Some(23_000_000);
        assert!(!health.stalled(23_999_999, &q));
        assert!(health.stalled(24_000_000, &q));
        q.sender_estimate.received = 1;
        assert!(!health.stalled(24_100_000, &q));
        assert!(!health.stalled(100_000_000, &q));
        q.sent_symbols += 8;
        assert!(!health.stalled(101_000_000, &q));
        assert!(health.stalled(104_000_000, &q));
        // Delivery-only reports can precede finalized symbol/loss counts.
        q.sender_estimate.received_bytes = 1000;
        assert!(!health.stalled(104_100_000, &q));
        q = Snapshot {
            generation: 1,
            ..Default::default()
        };
        assert!(!health.stalled(0, &q));
    }
}
