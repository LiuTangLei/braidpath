//! Native BBR deliberately drains its flight during an RTT probe. Do not learn
//! that temporary service dip as a new application pacing ceiling.
use std::time::Duration;

#[derive(Default)]
pub(super) struct Pause {
    generation: Option<u64>,
    started_us: Option<u64>,
    until_us: u64,
}
impl Pause {
    pub(super) fn holds(
        &mut self,
        now_us: u64,
        generation: u64,
        probing: bool,
        rtt: Duration,
        network_queue: bool,
    ) -> bool {
        if self.generation != Some(generation) {
            *self = Self {
                generation: Some(generation),
                ..Default::default()
            };
        }
        if probing {
            self.started_us.get_or_insert(now_us);
            let settle = (rtt * 2).clamp(Duration::from_millis(200), Duration::from_millis(500));
            self.until_us = now_us.saturating_add(settle.as_micros() as u64);
        } else if now_us >= self.until_us {
            self.started_us = None;
        }
        // A long probe or missing feedback must not suspend application safety
        // decisions indefinitely. Native flow control and liveness always run.
        !network_queue
            && self.started_us.is_some_and(|start| {
                now_us.saturating_sub(start) < 750_000 && now_us < self.until_us
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_probe_drain_does_not_retrain_application_pacing() {
        let mut pause = Pause::default();
        let rtt = Duration::from_millis(110);
        assert!(!pause.holds(0, 1, false, rtt, false));
        assert!(pause.holds(100_000, 1, true, rtt, false));
        // Allow one RTT for the final probe reply and one receiver interval
        // for delayed delivery reports after the native probe ended.
        assert!(pause.holds(300_000, 1, false, rtt, false));
        assert!(!pause.holds(320_001, 1, false, rtt, false));
    }

    #[test]
    fn real_network_queue_and_new_generations_are_never_hidden() {
        let mut pause = Pause::default();
        let rtt = Duration::from_millis(110);
        pause.holds(100_000, 1, true, rtt, false);
        assert!(!pause.holds(101_000, 1, true, rtt, true));
        assert!(!pause.holds(102_000, 2, false, rtt, false));
        assert!(!pause.holds(103_000, 1, false, rtt, false));
    }

    #[test]
    fn a_stuck_native_probe_cannot_suspend_safety_indefinitely() {
        let mut pause = Pause::default();
        let rtt = Duration::from_millis(110);
        assert!(pause.holds(100_000, 1, true, rtt, false));
        assert!(!pause.holds(850_000, 1, true, rtt, false));
        assert!(!pause.holds(900_000, 1, false, rtt, false));
        assert!(!pause.holds(1_120_001, 1, false, rtt, false));
        assert!(pause.holds(2_000_000, 1, true, rtt, false));
    }
}
