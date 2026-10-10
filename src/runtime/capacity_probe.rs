//! Bounded, independent delivery samples; never application records or capacity claims.
use super::{MAX_PATHS, outbound, quality};
use anyhow::{Result, ensure};
use bytes::Bytes;

mod pacing;
pub use pacing::{Controller, Demand, RateSnapshot};

pub const FRAME_BYTES: usize = 1000;
const MARKER: &[u8; 8] = b"BP3PROBE";

/// Own counters, replay window and receiver clock; business/FEC estimates cannot
/// be refreshed or inflated by this stream. All bounds are inherited from Quality.
pub struct State {
    inner: quality::State,
}

impl State {
    pub fn new(generation: u64) -> Self {
        Self {
            inner: quality::State::new(generation),
        }
    }

    pub fn prepare(&self, now_us: u64) -> Bytes {
        let mut body = [0; FRAME_BYTES - quality::HEADER];
        body[..MARKER.len()].copy_from_slice(MARKER);
        let mut frame = self.inner.wrap(&body, now_us).to_vec();
        frame[..4].copy_from_slice(b"BQ3D");
        frame.into()
    }

    pub fn admitted(&mut self) {
        self.inner.admitted(FRAME_BYTES - quality::HEADER);
    }

    pub fn receive(&mut self, frame: &[u8], now_us: u64) -> Result<()> {
        ensure!(
            frame.len() == FRAME_BYTES && &frame[..4] == b"BQ3D",
            "invalid capacity probe"
        );
        ensure!(
            &frame[quality::HEADER..quality::HEADER + MARKER.len()] == MARKER
                && frame[quality::HEADER + MARKER.len()..]
                    .iter()
                    .all(|byte| *byte == 0),
            "invalid capacity probe padding"
        );
        let mut data = [0; FRAME_BYTES];
        data.copy_from_slice(frame);
        data[..4].copy_from_slice(b"BQ1D");
        self.inner.receive(&data, now_us)?;
        Ok(())
    }

    pub fn report(&mut self, id: u8, kind: quality::ReportKind, now_us: u64) -> quality::Report {
        match kind {
            quality::ReportKind::Full => self.inner.report(id, now_us),
            quality::ReportKind::Delivery => self.inner.delivery_report(id, now_us),
        }
    }

    pub fn apply(&mut self, report: &quality::Report, now_us: u64) -> Result<()> {
        let result = self.inner.apply(report, now_us);
        if result.is_err() {
            self.inner.snapshot.invalid_controls += 1;
        }
        result
    }

    pub fn control_admitted(&mut self) {
        self.inner.snapshot.controls_sent += 1;
    }

    pub fn unreported_received_bytes(&self) -> u64 {
        self.inner.unreported_received_bytes()
    }
    pub fn snapshot(&self, now_us: u64) -> quality::Snapshot {
        self.inner.snapshot_at(now_us)
    }
}

/// Multiplex into the existing pending control record and its reserved budget.
/// Both lists have identical membership, so no business record loses feedback.
pub fn control(business: &[quality::Report], probes: &[quality::Report]) -> Bytes {
    let first = quality::control_v2(business);
    let second = quality::control_v2(probes);
    let mut frame = Vec::with_capacity(6 + first.len() + second.len());
    frame.extend(b"BQ3C");
    frame.extend((first.len() as u16).to_be_bytes());
    frame.extend(first);
    frame.extend(second);
    frame.into()
}

pub fn parse_control(frame: &[u8]) -> Result<(Vec<quality::Report>, Vec<quality::Report>)> {
    ensure!(
        frame.len() >= 6 && frame.len() <= 6 + 2 * (5 + MAX_PATHS * 65) && &frame[..4] == b"BQ3C",
        "invalid multiplexed probe feedback"
    );
    let split = 6 + usize::from(u16::from_be_bytes(frame[4..6].try_into().unwrap()));
    ensure!(split <= frame.len(), "invalid probe feedback offset");
    let first = quality::parse_control(&frame[6..split])?;
    let second = quality::parse_control(&frame[split..])?;
    ensure!(
        first.len() == second.len()
            && first.iter().all(|report| second
                .iter()
                .any(|other| report.id == other.id && report.generation == other.generation)),
        "probe feedback membership mismatch"
    );
    Ok((first, second))
}

/// This additional byte allowance never depends on business eligibility. The
/// ordinary aggregate/group/transport limits must also accept each datagram.
pub struct Budget {
    aggregate_ceiling: u64,
    group_ceilings: [u64; MAX_PATHS],
    aggregate: outbound::Pacer,
    groups: [outbound::Pacer; MAX_PATHS],
}

impl Budget {
    pub fn new(rate_bps: u64, group_rates: [u64; MAX_PATHS]) -> Self {
        Self {
            aggregate_ceiling: rate_bps,
            group_ceilings: std::array::from_fn(|id| rate_bps.min(group_rates[id] / 20)),
            aggregate: outbound::Pacer::new(0, 2 * (FRAME_BYTES + 89)),
            groups: std::array::from_fn(|_| outbound::Pacer::new(0, 2 * (FRAME_BYTES + 89))),
        }
    }

    /// Follow the sum of current independent path allowances, below the configured
    /// caps. Integrating the old rate first gives a pace change no new credit.
    pub fn set_rates(&mut self, now_us: u64, group_pacing_bps: [u64; MAX_PATHS]) {
        let mut aggregate = 0u64;
        for (id, rate) in group_pacing_bps.into_iter().enumerate() {
            let bounded = rate.min(self.group_ceilings[id]);
            self.groups[id].set_rate(now_us, bounded);
            aggregate = aggregate.saturating_add(bounded);
        }
        self.aggregate
            .set_rate(now_us, aggregate.min(self.aggregate_ceiling));
    }

    pub fn available(&mut self, now_us: u64, group: u8, bytes: usize) -> bool {
        self.aggregate.refill(now_us);
        let group = &mut self.groups[usize::from(group)];
        group.refill(now_us);
        self.aggregate.available(bytes) && group.available(bytes)
    }

    pub fn admitted(&mut self, group: u8, bytes: usize) {
        self.aggregate.spend(bytes);
        self.groups[usize::from(group)].spend(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_stream_measures_erasure_with_unrelated_clocks_and_no_business_bytes() {
        let mut sender = State::new(7);
        let mut receiver = State::new(7);
        let business = quality::State::new(7);
        for index in 0..100 {
            let frame = sender.prepare(index * 10_000);
            sender.admitted();
            if index % 5 != 0 {
                receiver
                    .receive(&frame, 9_000_000_000 + index * 10_000)
                    .unwrap();
            }
        }
        receiver
            .apply(
                &sender.report(0, quality::ReportKind::Full, 1_000_000),
                9_001_000_000,
            )
            .unwrap();
        let report = receiver.report(0, quality::ReportKind::Full, 9_001_600_000);
        sender.apply(&report, 1_700_000).unwrap();
        let evidence = sender.snapshot(1_700_000).sender_estimate;
        assert_eq!(
            (evidence.expected, evidence.received, evidence.lost),
            (100, 80, 20)
        );
        assert_eq!(
            evidence.received_bytes,
            80 * (FRAME_BYTES - quality::HEADER) as u64
        );
        assert_eq!(business.snapshot.sent_symbols, 0);
        assert_eq!(business.snapshot.received.received_bytes, 0);
        assert!(sender.apply(&report, 1_800_000).is_err());
    }

    #[test]
    fn prepares_without_spending_and_rejects_stale_generation_and_corrupt_payload() {
        let mut sender = State::new(7);
        let frame = sender.prepare(0);
        assert_eq!(sender.prepare(0), frame);
        assert_eq!(sender.snapshot(0).sent_symbols, 0);
        assert!(State::new(8).receive(&frame, 1).is_err());
        let mut corrupt = frame.to_vec();
        corrupt[FRAME_BYTES - 1] = 1;
        assert!(State::new(7).receive(&corrupt, 1).is_err());
        sender.admitted();
        assert_ne!(sender.prepare(0), frame);
    }

    #[test]
    fn budget_has_no_startup_credit_and_never_exceeds_aggregate_or_group_share() {
        let mut budget = Budget::new(64_000, [320_000; MAX_PATHS]);
        let cost = FRAME_BYTES + 89;
        budget.set_rates(0, [64_000; MAX_PATHS]);
        assert!(!budget.available(0, 0, cost));
        let mut admitted = [0usize; MAX_PATHS];
        for now in (1000..=1_000_000).step_by(1000) {
            for (group, bytes) in admitted.iter_mut().enumerate() {
                if budget.available(now, group as u8, cost) {
                    budget.admitted(group as u8, cost);
                    *bytes += cost;
                }
            }
        }
        assert!(admitted.iter().sum::<usize>() <= 8000);
        assert!(admitted.iter().all(|bytes| *bytes <= 2000));
        assert!(admitted.iter().sum::<usize>() > 0);
        let mut off = Budget::new(0, [1_000_000; MAX_PATHS]);
        assert!(!off.available(10_000_000, 0, cost));
    }

    #[test]
    fn aggregate_probe_pacing_cannot_release_all_four_initial_packets_as_a_pulse() {
        let mut budget = Budget::new(17_500_000, [350_000_000; MAX_PATHS]);
        let mut paths: [Controller; 4] = std::array::from_fn(|_| Controller::new(4_375_000));
        for path in &mut paths {
            path.observe(
                &Demand {
                    generation: 7,
                    backlog: true,
                    target_ms: 20.0,
                    ..Default::default()
                },
                4_375_000,
            );
        }
        let cost = FRAME_BYTES + 82;
        let mut initial_packets = 0;
        for now in (0..=140_000).step_by(1000) {
            let mut rates = [0; MAX_PATHS];
            rates[0] = paths.iter().map(|path| path.snapshot().pacing_bps).sum();
            budget.set_rates(now, rates);
            for path in &mut paths {
                if path.available(now, cost) && budget.available(now, 0, cost) {
                    path.admitted(cost);
                    budget.admitted(0, cost);
                    initial_packets += 1;
                }
            }
        }
        assert_eq!(
            initial_packets, 2,
            "a configured cap must not refill at an unmeasured rate"
        );
    }

    #[test]
    fn changing_probe_budget_rates_cannot_mint_credit_or_charge_failed_attempts() {
        let mut budget = Budget::new(1_000_000, [20_000_000; MAX_PATHS]);
        let mut rates = [0; MAX_PATHS];
        rates[0] = 64_000;
        budget.set_rates(0, rates);
        assert!(!budget.available(100_000, 0, 1000));
        rates[0] = 128_000;
        budget.set_rates(100_000, rates);
        assert!(!budget.available(100_000, 0, 1000));
        assert!(budget.available(112_500, 0, 1000));
        assert!(budget.available(112_500, 0, 1000));
        budget.admitted(0, 1000);
        budget.set_rates(112_500, [0; MAX_PATHS]);
        assert!(!budget.available(1_000_000, 0, 1));
        budget.set_rates(1_000_000, rates);
        assert!(!budget.available(1_000_000, 0, 1000));
        assert!(budget.available(1_062_500, 0, 1000));
    }

    #[test]
    fn multiplexed_feedback_preserves_membership_and_rejects_offsets_and_foreign_paths() {
        let mut state = State::new(7);
        let report = state.report(0, quality::ReportKind::Full, 1000);
        let frame = control(std::slice::from_ref(&report), std::slice::from_ref(&report));
        let (first, second) = parse_control(&frame).unwrap();
        assert_eq!((first.len(), second.len()), (1, 1));
        let mut offset = frame.to_vec();
        offset[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(parse_control(&offset).is_err());
        let other = quality::Report {
            id: 1,
            ..report.clone()
        };
        assert!(parse_control(&control(&[report], &[other])).is_err());
    }
}
