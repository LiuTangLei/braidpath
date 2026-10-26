//! Grouped cumulative observations: every path shares one sampling boundary.
//! Idle baselines and a final tail prevent activity filtering from hiding startup.
use super::*;
use serde::Serialize;

const ACTIVE_US: u64 = 1_000_000;
const IDLE_US: u64 = 30_000_000;

#[derive(Default)]
pub(super) struct Schedule {
    paths: [usize; MAX_PATHS],
    next_us: u64,
    active: bool,
    last_activity_us: u64,
}

impl Schedule {
    fn due(&mut self, now: u64, activity: bool, paths: [usize; MAX_PATHS]) -> Option<&'static str> {
        let changed = paths != self.paths;
        self.paths = paths;
        if activity {
            self.last_activity_us = now;
        }
        let active =
            activity || (self.active && now.saturating_sub(self.last_activity_us) < ACTIVE_US);
        let transition = active != self.active;
        let was_active = self.active;
        self.active = active;
        if !changed && !transition && now < self.next_us {
            return None;
        }
        self.next_us = now.saturating_add(if active { ACTIVE_US } else { IDLE_US });
        Some(if changed {
            "paths"
        } else if !was_active && active {
            "start"
        } else if was_active && !active {
            "tail"
        } else if active {
            "periodic"
        } else {
            "idle"
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe(
        &mut self,
        now: u64,
        queued: usize,
        paths: &[OutPath],
        controllers: &[adaptive::PathController; MAX_PATHS],
        scope: &Scope,
        guard: Option<&forward_guard::Guard>,
        fec: Option<&automatic_fec::Controller>,
    ) {
        if !tracing::enabled!(tracing::Level::INFO) {
            return;
        }
        let mut ids = [0; MAX_PATHS];
        for p in paths {
            ids[usize::from(p.id)] = p.conn.stable_id();
        }
        if let Some(reason) = self.due(now, queued != 0, ids) {
            publish(now, reason, queued, paths, controllers, scope, guard, fec);
        }
    }
}

#[derive(Serialize)]
struct PathFrame {
    path: u8,
    connection: usize,
    generation: u64,
    sent_symbols: u64,
    sent_symbol_bytes: u64,
    sent_packets: u64,
    lost_packets: u64,
    udp_tx_bytes: u64,
    udp_rx_bytes: u64,
    writer_backlog_bytes: usize,
    native_datagram_space_bytes: usize,
    pacing_bps: u64,
    eligible: bool,
    queue_delay_ms: f64,
    last_rate_change: Option<(u64, adaptive::RateReason)>,
    random_loss: Option<(f64, &'static str)>,
}

#[derive(Serialize)]
struct Frame<'a> {
    schema: u8,
    session: &'a str,
    direction: &'static str,
    sample_us: u64,
    reason: &'static str,
    sender_queued_records: usize,
    streams: Option<super::super::stream::Snapshot>,
    streams_sample_age_us: Option<u64>,
    guard: Option<forward_guard::Snapshot>,
    fec: Option<automatic_fec::Snapshot>,
    paths: Vec<PathFrame>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish(
    now: u64,
    reason: &'static str,
    queued: usize,
    paths: &[OutPath],
    controllers: &[adaptive::PathController; MAX_PATHS],
    scope: &Scope,
    guard: Option<&forward_guard::Guard>,
    fec: Option<&automatic_fec::Controller>,
) {
    if !tracing::enabled!(tracing::Level::INFO) {
        return;
    }
    let mut streams = None;
    let mut streams_sample_age_us = None;
    scope.metrics.state(|state| {
        if let Some(direction) = state
            .sessions
            .get(&scope.session)
            .and_then(|directions| directions.get(scope.direction))
        {
            streams = direction.tcp_streams.clone();
            streams_sample_age_us = direction
                .tcp_streams_sampled_at
                .map(|at| at.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
        }
    });
    let frame = Frame {
        schema: 1,
        session: &scope.session,
        direction: scope.direction,
        sample_us: now,
        reason,
        sender_queued_records: queued,
        streams,
        streams_sample_age_us,
        guard: guard.map(forward_guard::Guard::snapshot),
        fec: fec.map(automatic_fec::Controller::snapshot),
        paths: paths
            .iter()
            .map(|path| {
                let native = path.conn.stats();
                let q = path.quality.lock().expect("quality lock");
                let controller = &controllers[usize::from(path.id)];
                let decision = controller.decision(now);
                PathFrame {
                    path: path.id,
                    connection: path.conn.stable_id(),
                    generation: q.snapshot.generation,
                    sent_symbols: q.snapshot.sent_symbols,
                    sent_symbol_bytes: q.snapshot.sent_bytes,
                    sent_packets: native.path.sent_packets,
                    lost_packets: native.path.lost_packets,
                    udp_tx_bytes: native.udp_tx.bytes,
                    udp_rx_bytes: native.udp_rx.bytes,
                    writer_backlog_bytes: path.writer.backlog(),
                    native_datagram_space_bytes: path.conn.datagram_send_buffer_space_hint(),
                    pacing_bps: decision.pacing_bps,
                    eligible: decision.eligible,
                    queue_delay_ms: decision.queue_delay_ms,
                    last_rate_change: controller.last_rate_event(),
                    random_loss: controller.random_loss_diagnostics(now),
                }
            })
            .collect(),
    };
    if let Ok(frame) = serde_json::to_string(&frame) {
        info!(frame = %frame, "transfer snapshot");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_tail_idle_and_replacement_have_complete_group_boundaries() {
        let mut s = Schedule::default();
        let mut ids = [0; MAX_PATHS];
        ids[..4].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(s.due(0, false, ids), Some("paths"));
        assert_eq!(s.due(5_000_000, false, ids), None);
        assert_eq!(s.due(5_000_001, true, ids), Some("start"));
        assert_eq!(s.due(5_500_000, true, ids), None);
        assert_eq!(s.due(6_000_001, true, ids), Some("periodic"));
        assert_eq!(s.due(6_500_000, false, ids), None);
        assert_eq!(s.due(7_000_001, false, ids), Some("tail"));
        assert_eq!(s.due(37_000_001, false, ids), Some("idle"));
        ids[1] = 5;
        assert_eq!(s.due(37_000_002, false, ids), Some("paths"));
        assert_eq!(s.due(37_000_003, true, ids), Some("start"));
    }
}
