//! Fast exclusion of a path that has stopped acknowledging.
//!
//! The adaptive controller excludes a dead path from receiver reports, which
//! takes seconds; until then a share of every flow is sent into it. QUIC shows
//! an outage sooner: frames that elicit acknowledgments keep leaving while no
//! ACK frame arrives. Such a path is withheld from data scheduling until any
//! ACK arrives again, which the controller's probes and Quinn's own probes
//! still elicit. This is reachability evidence, not a congestion signal: a
//! queue delays ACKs without stopping them.
use std::time::{Duration, Instant};

/// Never declare an outage sooner than this, whatever the RTT.
const MIN_SILENCE: Duration = Duration::from_millis(100);
/// Quinn's default maximum ACK delay.
const ACK_DELAY: Duration = Duration::from_millis(25);
const CHECK_EVERY: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Counters {
    /// ACK frames received.
    pub acks: u64,
    /// Ack-eliciting frames sent: datagrams, stream data and pings.
    pub eliciting: u64,
}
impl Counters {
    pub fn of(conn: &quinn::Connection) -> Self {
        let (acks, eliciting) = conn.liveness_hint();
        Self { acks, eliciting }
    }
}

#[derive(Default)]
pub(super) struct Liveness {
    connection: Option<usize>,
    acks: u64,
    /// Ack-eliciting frames sent up to the latest ACK arrival.
    answered: u64,
    /// When frames sent after the latest ACK arrival were first seen.
    unanswered_since: Option<Instant>,
    silent: bool,
    checked: Option<Instant>,
}
impl Liveness {
    pub fn observe(&mut self, conn: &quinn::Connection, now: Instant) {
        if self
            .checked
            .is_some_and(|at| now.saturating_duration_since(at) < CHECK_EVERY)
            && self.connection == Some(conn.stable_id())
        {
            return;
        }
        self.update(conn.stable_id(), Counters::of(conn), conn.rtt_hint(), now);
    }

    fn update(&mut self, connection: usize, counters: Counters, rtt: Duration, now: Instant) {
        if self.connection != Some(connection) {
            // A new connection for this path starts with no evidence.
            *self = Self {
                connection: Some(connection),
                acks: counters.acks,
                answered: counters.eliciting,
                ..Self::default()
            };
        }
        self.checked = Some(now);
        if counters.acks != self.acks {
            self.acks = counters.acks;
            self.answered = counters.eliciting;
            self.unanswered_since = None;
            self.silent = false;
            return;
        }
        if counters.eliciting == self.answered {
            return;
        }
        let since = *self.unanswered_since.get_or_insert(now);
        let limit = (rtt * 2 + ACK_DELAY).max(MIN_SILENCE);
        self.silent |= now.saturating_duration_since(since) >= limit;
    }

    /// Ack-eliciting frames have gone unanswered for longer than the path
    /// could explain; withhold data until an acknowledgment arrives.
    pub fn silent(&self) -> bool {
        self.silent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters(acks: u64, eliciting: u64) -> Counters {
        Counters { acks, eliciting }
    }

    #[test]
    fn a_single_unanswered_frame_can_fail_and_recover_without_application_samples() {
        let start = Instant::now();
        let rtt = Duration::from_millis(10);
        let mut path = Liveness::default();
        path.update(1, counters(5, 10), rtt, start);
        path.update(1, counters(5, 11), rtt, start + Duration::from_millis(1));
        assert!(!path.silent());
        path.update(1, counters(5, 11), rtt, start + Duration::from_millis(101));
        assert!(
            path.silent(),
            "reachability does not require eight application symbols"
        );
        path.update(1, counters(6, 11), rtt, start + Duration::from_millis(102));
        assert!(
            !path.silent(),
            "an authenticated QUIC ACK restores the same path"
        );
        path.update(1, counters(6, 11), rtt, start + Duration::from_secs(10));
        assert!(!path.silent(), "an idle path must remain healthy");
    }

    #[test]
    fn unanswered_frames_mark_silence_until_an_ack_arrives() {
        let rtt = Duration::from_millis(20);
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let mut path = Liveness::default();
        path.update(1, counters(5, 10), rtt, at(0));
        // Frames answered promptly keep the path live.
        path.update(1, counters(6, 12), rtt, at(10));
        path.update(1, counters(6, 12), rtt, at(500));
        assert!(!path.silent(), "an idle path is not silent");
        path.update(1, counters(6, 13), rtt, at(510));
        path.update(1, counters(6, 20), rtt, at(600));
        assert!(!path.silent(), "within the 100 ms floor");
        path.update(1, counters(6, 25), rtt, at(611));
        assert!(path.silent());
        path.update(1, counters(6, 26), rtt, at(900));
        assert!(path.silent(), "still unanswered");
        path.update(1, counters(7, 26), rtt, at(901));
        assert!(!path.silent());
    }

    #[test]
    fn the_silence_bound_follows_the_rtt_and_a_new_connection_resets() {
        let rtt = Duration::from_millis(200);
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let mut path = Liveness::default();
        path.update(1, counters(0, 0), rtt, at(0));
        path.update(1, counters(0, 1), rtt, at(1));
        path.update(1, counters(0, 9), rtt, at(400));
        assert!(!path.silent(), "2 RTT + ACK delay is 425 ms");
        path.update(1, counters(0, 9), rtt, at(426));
        assert!(path.silent());
        path.update(2, counters(0, 0), rtt, at(427));
        assert!(!path.silent());
    }
}
