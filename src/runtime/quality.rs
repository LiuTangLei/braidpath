//! Authenticated path measurement, independent of record/FEC delivery.
use super::{MAX_PATHS, wire};
use anyhow::{Result, ensure};
use bytes::Bytes;
use serde::Serialize;
use std::collections::{BTreeSet, VecDeque};

pub const HEADER: usize = 28;
pub const MAX_FRAME: usize = wire::MAX_WIRE + HEADER;
pub const INTERVAL_US: u64 = 500_000;
const WINDOW: u64 = 512;
const ENTRY: usize = 49;
const ENTRY_V2: usize = 65;

#[derive(Clone, Default, Debug, Serialize)]
pub struct Estimate {
    pub expected: u64,
    pub received: u64,
    pub lost: u64,
    pub loss_rate: f64,
    /// Receiver transit delta above its running minimum; never absolute latency.
    pub delay_variation_ms: f64,
    pub report_number: u64,
    pub updated_us: Option<u64>,
    /// Last proof of positive path delivery. Finalizing missing symbols alone
    /// refreshes loss information, not reachability.
    pub delivered_updated_us: Option<u64>,
    /// Unique measured symbol bytes received before FEC; not application goodput/capacity.
    pub received_bytes: u64,
    pub delivered_bps: Option<f64>,
    /// Receiver-local end of the latest byte report. Never compare this clock
    /// with the sender's clock; cumulative byte deltas use matching end times.
    /// Legacy reports have no byte clock and cannot qualify capacity trials.
    pub report_time_us: Option<u64>,
    pub sample_span_us: u64,
    pub sample_symbols: u64,
    /// Loss in the newest finalized interval, before smoothing. Zero-symbol
    /// reports do not constitute a new loss sample.
    pub sample_loss_rate: f64,
}
#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub generation: u64,
    /// Local per-generation clock at export, for comparable evidence ages.
    pub sampled_us: u64,
    pub sent_symbols: u64,
    pub sent_bytes: u64,
    pub received: Estimate,
    pub sender_estimate: Estimate,
    pub late: u64,
    pub duplicates: u64,
    pub controls_sent: u64,
    pub controls_received: u64,
    pub invalid_controls: u64,
    pub probes_sent: u64,
    pub replies_received: u64,
    pub probe_rtt_ms: f64,
    /// Most recent authenticated round trip, kept separately from the diagnostic EWMA.
    pub probe_rtt_latest_ms: f64,
    pub probe_updated_us: Option<u64>,
}
pub struct State {
    pub snapshot: Snapshot,
    seen: BTreeSet<u64>,
    pending: VecDeque<(u64, u64)>,
    watermark: u64,
    transit_min: Option<i128>,
    peer_report: u64,
    peer_report_time_us: Option<u64>,
    probes: VecDeque<(u64, u64)>,
    last_probe_reply_nonce: Option<u64>,
}
impl State {
    pub fn new(generation: u64) -> Self {
        Self {
            snapshot: Snapshot {
                generation,
                ..Default::default()
            },
            seen: BTreeSet::new(),
            pending: VecDeque::new(),
            watermark: 0,
            transit_min: None,
            peer_report: 0,
            peer_report_time_us: None,
            probes: VecDeque::new(),
            last_probe_reply_nonce: None,
        }
    }
    pub fn snapshot_at(&self, now_us: u64) -> Snapshot {
        Snapshot {
            sampled_us: now_us,
            ..self.snapshot.clone()
        }
    }
    pub fn admitted(&mut self, bytes: usize) {
        self.snapshot.sent_symbols = self.snapshot.sent_symbols.saturating_add(1);
        self.snapshot.sent_bytes = self.snapshot.sent_bytes.saturating_add(bytes as u64);
    }
    pub fn probe_admitted(&mut self, nonce: u64, now_us: u64) {
        if self.probes.len() == 4 {
            self.probes.pop_front();
        }
        self.probes.push_back((nonce, now_us));
        self.snapshot.probes_sent = self.snapshot.probes_sent.saturating_add(1);
    }
    pub fn apply_probe(&mut self, probe: &Probe, now_us: u64) -> Result<()> {
        ensure!(
            probe.response && probe.generation == self.snapshot.generation,
            "invalid probe generation/kind"
        );
        ensure!(
            self.last_probe_reply_nonce
                .is_none_or(|nonce| probe.nonce > nonce),
            "replayed probe reply"
        );
        let index = self
            .probes
            .iter()
            .position(|(nonce, _)| *nonce == probe.nonce)
            .ok_or_else(|| anyhow::anyhow!("unsolicited probe reply"))?;
        let (_, sent_us) = self.probes[index];
        ensure!(
            now_us >= sent_us && now_us - sent_us <= 3_000_000,
            "stale probe reply"
        );
        self.probes.remove(index);
        self.last_probe_reply_nonce = Some(probe.nonce);
        let rtt_ms = (now_us - sent_us) as f64 / 1000.0;
        self.snapshot.probe_rtt_latest_ms = rtt_ms;
        self.snapshot.probe_rtt_ms = if self.snapshot.probe_updated_us.is_some() {
            self.snapshot.probe_rtt_ms * 0.5 + rtt_ms * 0.5
        } else {
            rtt_ms
        };
        self.snapshot.probe_updated_us = Some(now_us);
        self.snapshot.replies_received = self.snapshot.replies_received.saturating_add(1);
        Ok(())
    }
    pub fn wrap(&self, payload: &[u8], now_us: u64) -> Bytes {
        let mut b = Vec::with_capacity(HEADER + payload.len());
        b.extend(*b"BQ1D");
        b.extend(self.snapshot.generation.to_be_bytes());
        b.extend(self.snapshot.sent_symbols.to_be_bytes());
        b.extend(now_us.to_be_bytes());
        b.extend(payload);
        b.into()
    }
    pub fn receive<'a>(&mut self, b: &'a [u8], now_us: u64) -> Result<&'a [u8]> {
        ensure!(
            (HEADER + wire::HEADER..=MAX_FRAME).contains(&b.len()) && &b[..4] == b"BQ1D",
            "invalid measurement frame"
        );
        ensure!(
            number(b, 4) == self.snapshot.generation,
            "stale measurement generation"
        );
        let seq = number(b, 12);
        ensure!(seq < u64::MAX, "invalid sequence");
        self.mature(now_us);
        let floor = seq.saturating_sub(WINDOW - 1);
        if floor > self.snapshot.received.expected {
            self.finalize(floor);
        }
        if seq < self.snapshot.received.expected {
            self.snapshot.late += 1;
        } else if !self.seen.insert(seq) {
            self.snapshot.duplicates += 1;
        } else {
            self.snapshot.received.delivered_updated_us = Some(now_us);
            self.snapshot.received.received_bytes = self
                .snapshot
                .received
                .received_bytes
                .saturating_add((b.len() - HEADER) as u64);
            let delta = i128::from(now_us) - i128::from(number(b, 20));
            let minimum = self.transit_min.get_or_insert(delta);
            *minimum = (*minimum).min(delta);
            let variation = (delta - *minimum) as f64 / 1000.0;
            self.snapshot.received.delay_variation_ms =
                self.snapshot.received.delay_variation_ms * 0.8 + variation * 0.2;
        }
        Ok(&b[HEADER..])
    }
    fn finalize(&mut self, end: u64) {
        if end <= self.snapshot.received.expected {
            return;
        }
        let received = self.seen.range(..end).count() as u64;
        self.seen.retain(|seq| *seq >= end);
        let r = &mut self.snapshot.received;
        r.expected = end;
        r.received += received;
        r.lost = end - r.received;
        r.loss_rate = r.lost as f64 / end as f64;
    }
    pub fn mature(&mut self, now_us: u64) {
        while self.pending.front().is_some_and(|(due, _)| *due <= now_us) {
            let (_, end) = self.pending.pop_front().expect("pending watermark");
            self.finalize(end);
        }
    }
    pub fn report(&mut self, id: u8, now_us: u64) -> Report {
        self.mature(now_us);
        self.snapshot.received.report_number += 1;
        self.snapshot.received.report_time_us = Some(now_us);
        Report {
            id,
            generation: self.snapshot.generation,
            sent: self.snapshot.sent_symbols,
            number: self.snapshot.received.report_number,
            expected: self.snapshot.received.expected,
            received: self.snapshot.received.received,
            // Keep this diagnostic within its wire bound even if long-lived clock
            // drift exceeds it; otherwise an unrelated scalar would reject byte feedback.
            delay_us: ((self.snapshot.received.delay_variation_ms * 1000.0) as u64).min(60_000_000),
            received_bytes: self.snapshot.received.received_bytes,
            report_time_us: now_us,
        }
    }
    pub fn apply(&mut self, r: &Report, now_us: u64) -> Result<()> {
        let old = self.snapshot.sender_estimate.clone();
        ensure!(
            r.generation == self.snapshot.generation
                && r.number > self.peer_report
                && r.received <= r.expected
                && r.expected <= self.snapshot.sent_symbols
                && r.expected >= old.expected
                && r.received >= old.received
                && r.sent >= self.watermark
                && r.delay_us <= 60_000_000
                && r.received - old.received <= r.expected - old.expected,
            "invalid/stale feedback"
        );
        if r.report_time_us != 0 {
            ensure!(
                r.received_bytes >= old.received_bytes
                    && r.received_bytes <= self.snapshot.sent_bytes
                    && self
                        .peer_report_time_us
                        .is_none_or(|previous| r.report_time_us > previous),
                "invalid byte/rate feedback"
            );
        }
        if r.sent > self.watermark {
            // Reports arrive at a bounded cadence. Keep at most four watermarks.
            if self.pending.len() == 4 {
                let (_, end) = self.pending.pop_front().expect("bounded pending");
                self.finalize(end);
            }
            self.pending
                .push_back((now_us.saturating_add(INTERVAL_US), r.sent));
            self.watermark = r.sent;
        }
        self.peer_report = r.number;
        let delta_expected = r.expected - old.expected;
        let delta_received = r.received - old.received;
        ensure!(
            delta_received <= delta_expected,
            "inconsistent cumulative feedback"
        );
        let rate = if delta_expected == 0 {
            old.loss_rate
        } else {
            1.0 - delta_received as f64 / delta_expected as f64
        };
        let sample_span_us = if r.report_time_us != 0 {
            self.peer_report_time_us
                .map_or(0, |previous| r.report_time_us.saturating_sub(previous))
        } else {
            0
        };
        let delivered_bps = if sample_span_us > 0 {
            Some(
                (r.received_bytes - old.received_bytes) as f64 * 8_000_000.0
                    / sample_span_us as f64,
            )
        } else {
            old.delivered_bps
        };
        if r.report_time_us != 0 {
            self.peer_report_time_us = Some(r.report_time_us);
        }
        self.snapshot.sender_estimate = Estimate {
            expected: r.expected,
            received: r.received,
            lost: r.expected - r.received,
            loss_rate: if old.updated_us.is_none() {
                rate
            } else {
                old.loss_rate * 0.75 + rate * 0.25
            },
            delay_variation_ms: r.delay_us as f64 / 1000.0,
            report_number: r.number,
            updated_us: if delta_expected == 0 {
                old.updated_us
            } else {
                Some(now_us)
            },
            delivered_updated_us: if (r.report_time_us != 0
                && r.received_bytes > old.received_bytes)
                || (r.report_time_us == 0 && delta_received > 0)
            {
                Some(now_us)
            } else {
                old.delivered_updated_us
            },
            received_bytes: if r.report_time_us != 0 {
                r.received_bytes
            } else {
                old.received_bytes
            },
            delivered_bps,
            report_time_us: (r.report_time_us != 0).then_some(r.report_time_us),
            sample_span_us,
            sample_symbols: delta_expected,
            sample_loss_rate: if delta_expected == 0 {
                old.sample_loss_rate
            } else {
                rate
            },
        };
        self.snapshot.controls_received += 1;
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Report {
    pub id: u8,
    pub generation: u64,
    pub sent: u64,
    pub number: u64,
    pub expected: u64,
    pub received: u64,
    pub delay_us: u64,
    pub received_bytes: u64,
    pub report_time_us: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub generation: u64,
    pub nonce: u64,
    pub response: bool,
}
pub fn probe(value: &Probe) -> Bytes {
    let mut out = Vec::with_capacity(20);
    out.extend(if value.response { *b"BQ2R" } else { *b"BQ2P" });
    out.extend(value.generation.to_be_bytes());
    out.extend(value.nonce.to_be_bytes());
    out.into()
}
pub fn parse_probe(bytes: &[u8]) -> Result<Probe> {
    ensure!(
        bytes.len() == 20 && (&bytes[..4] == b"BQ2P" || &bytes[..4] == b"BQ2R"),
        "invalid probe"
    );
    Ok(Probe {
        generation: number(bytes, 4),
        nonce: number(bytes, 12),
        response: bytes[3] == b'R',
    })
}
fn number(b: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(b[offset..offset + 8].try_into().expect("validated frame"))
}
pub fn control(reports: &[Report]) -> Bytes {
    encode_control(reports, false)
}
pub fn control_v2(reports: &[Report]) -> Bytes {
    encode_control(reports, true)
}
fn encode_control(reports: &[Report], v2: bool) -> Bytes {
    assert!(reports.len() <= MAX_PATHS);
    let mut b = Vec::with_capacity(5 + if v2 { ENTRY_V2 } else { ENTRY } * reports.len());
    b.extend(if v2 { *b"BQ2C" } else { *b"BQ1C" });
    b.push(reports.len() as u8);
    for r in reports {
        b.push(r.id);
        for n in [
            r.generation,
            r.sent,
            r.number,
            r.expected,
            r.received,
            r.delay_us,
        ] {
            b.extend(n.to_be_bytes());
        }
        if v2 {
            b.extend(r.received_bytes.to_be_bytes());
            b.extend(r.report_time_us.to_be_bytes());
        }
    }
    b.into()
}
pub fn parse_control(b: &[u8]) -> Result<Vec<Report>> {
    let v2 = b.len() >= 4 && &b[..4] == b"BQ2C";
    let entry = if v2 { ENTRY_V2 } else { ENTRY };
    ensure!(
        b.len() >= 5
            && (&b[..4] == b"BQ1C" || v2)
            && usize::from(b[4]) <= MAX_PATHS
            && b.len() == 5 + entry * usize::from(b[4]),
        "invalid control length"
    );
    let mut ids = BTreeSet::new();
    let mut out = Vec::new();
    for e in b[5..].chunks_exact(entry) {
        ensure!(
            usize::from(e[0]) < MAX_PATHS && ids.insert(e[0]),
            "invalid control path"
        );
        out.push(Report {
            id: e[0],
            generation: number(e, 1),
            sent: number(e, 9),
            number: number(e, 17),
            expected: number(e, 25),
            received: number(e, 33),
            delay_us: number(e, 41),
            received_bytes: if v2 { number(e, 49) } else { 0 },
            report_time_us: if v2 { number(e, 57) } else { 0 },
        });
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn payload() -> Bytes {
        wire::plain(&wire::Record {
            flow: 0,
            id: 1,
            payload: vec![1],
        })
        .unwrap()
    }
    #[test]
    fn idle_control_reports_do_not_refresh_old_quality_samples() {
        let mut state = State::new(7);
        state.snapshot.sent_symbols = 10;
        let mut r = Report {
            id: 0,
            generation: 7,
            sent: 0,
            number: 1,
            expected: 10,
            received: 8,
            delay_us: 1000,
            received_bytes: 0,
            report_time_us: 0,
        };
        state.apply(&r, 1000).unwrap();
        assert_eq!(state.snapshot.sender_estimate.updated_us, Some(1000));
        assert_eq!(
            state.snapshot.sender_estimate.delivered_updated_us,
            Some(1000)
        );
        r.number = 2;
        state.apply(&r, 10_000_000).unwrap();
        assert_eq!(state.snapshot.sender_estimate.updated_us, Some(1000));
        assert_eq!(
            state.snapshot.sender_estimate.delivered_updated_us,
            Some(1000)
        );
        assert!((state.snapshot.sender_estimate.loss_rate - 0.2).abs() < 1e-12);
        state.snapshot.sent_symbols = 12;
        r.number = 3;
        r.expected = 12;
        r.received = 10;
        state.apply(&r, 11_000_000).unwrap();
        assert_eq!(state.snapshot.sender_estimate.updated_us, Some(11_000_000));
    }
    #[test]
    fn finalized_all_loss_reports_refresh_loss_but_not_positive_delivery() {
        let mut state = State::new(7);
        for _ in 0..100 {
            state.admitted(100);
        }
        let mut report = Report {
            id: 0,
            generation: 7,
            sent: 0,
            number: 1,
            expected: 10,
            received: 10,
            delay_us: 0,
            received_bytes: 1000,
            report_time_us: 100_000,
        };
        state.apply(&report, 1_000_000).unwrap();
        for number in 2..=5 {
            report.number = number;
            report.expected = number * 10;
            report.report_time_us += INTERVAL_US;
            let now = 1_000_000 + (number - 1) * INTERVAL_US;
            state.apply(&report, now).unwrap();
            let estimate = &state.snapshot.sender_estimate;
            assert_eq!(estimate.updated_us, Some(now));
            assert_eq!(estimate.delivered_updated_us, Some(1_000_000));
            assert_eq!(estimate.sample_loss_rate, 1.0);
            assert_eq!(estimate.delivered_bps, Some(0.0));
        }
        // A new unique symbol may arrive before its finalized loss interval.
        report.number += 1;
        report.received_bytes += 100;
        report.report_time_us += INTERVAL_US;
        state.apply(&report, 3_500_000).unwrap();
        assert_eq!(state.snapshot.sender_estimate.updated_us, Some(3_000_000));
        assert_eq!(
            state.snapshot.sender_estimate.delivered_updated_us,
            Some(3_500_000)
        );
        assert_eq!(state.snapshot.sender_estimate.sample_symbols, 0);
        let exported = state.snapshot_at(3_600_000);
        assert_eq!(exported.sampled_us, 3_600_000);
        assert_eq!(state.snapshot.sampled_us, 0);
    }
    #[test]
    fn loss_reordering_duplicates_and_tail_are_finalized_without_fec_credit() {
        let mut tx = State::new(7);
        let mut rx = State::new(7);
        let packets: Vec<_> = (0..4)
            .map(|n| {
                let p = tx.wrap(&payload(), n * 1000);
                tx.admitted(p.len() - HEADER);
                p
            })
            .collect();
        rx.receive(&packets[2], 10_000).unwrap();
        rx.receive(&packets[0], 11_000).unwrap();
        rx.receive(&packets[0], 12_000).unwrap();
        assert_eq!(rx.snapshot.received.delivered_updated_us, Some(11_000));
        let r = tx.report(0, 20_000);
        rx.apply(&r, 20_000).unwrap();
        rx.mature(519_999);
        assert_eq!(rx.snapshot.received.expected, 0);
        rx.mature(520_000);
        assert_eq!(
            (
                rx.snapshot.received.expected,
                rx.snapshot.received.received,
                rx.snapshot.received.lost
            ),
            (4, 2, 2)
        );
        rx.receive(&packets[1], 530_000).unwrap();
        assert_eq!(rx.snapshot.received.delivered_updated_us, Some(11_000));
        assert_eq!(rx.snapshot.late, 1);
        assert_eq!(rx.snapshot.duplicates, 1);
        tx.apply(&rx.report(0, 540_000), 540_000).unwrap();
        assert_eq!(tx.snapshot.sender_estimate.loss_rate, 0.5);
    }
    #[test]
    fn authenticated_control_rejects_replay_generation_and_unproven_counts() {
        let mut state = State::new(7);
        state.snapshot.sent_symbols = 10;
        let r = Report {
            id: 0,
            generation: 7,
            sent: 0,
            number: 1,
            expected: 10,
            received: 8,
            delay_us: 1000,
            received_bytes: 0,
            report_time_us: 0,
        };
        let b = control(std::slice::from_ref(&r));
        let decoded = parse_control(&b).unwrap();
        state.apply(&decoded[0], 1).unwrap();
        assert!(state.apply(&r, 2).is_err());
        for invalid in [
            Report {
                generation: 8,
                ..r.clone()
            },
            Report {
                number: 2,
                expected: 11,
                ..r.clone()
            },
            Report {
                number: 2,
                received: 11,
                ..r.clone()
            },
        ] {
            assert!(state.apply(&invalid, 3).is_err());
        }
        assert!(parse_control(&b[..b.len() - 1]).is_err());
        assert!(parse_control(&control(&[r.clone(), r])).is_err());
    }
    #[test]
    fn bounded_window_and_delay_are_clock_offset_invariant() {
        let mut a = State::new(1);
        let mut b = State::new(1);
        let mut tx = State::new(1);
        for n in 0..2000 {
            tx.snapshot.sent_symbols = n;
            let data = tx.wrap(&payload(), n * 1000);
            a.receive(&data, n * 1000 + 10_000 + (n % 3) * 100).unwrap();
            b.receive(&data, n * 1000 + 90_000_000 + (n % 3) * 100)
                .unwrap();
            assert!(a.seen.len() <= 512);
        }
        assert_eq!(
            a.snapshot.received.delay_variation_ms,
            b.snapshot.received.delay_variation_ms
        );
        let stale = State::new(2).wrap(&payload(), 0);
        assert!(a.receive(&stale, 0).is_err());
    }
    #[test]
    fn byte_feedback_uses_receiver_interval_without_synchronized_clocks() {
        let mut tx = State::new(7);
        for _ in 0..12 {
            tx.admitted(100);
        }
        let mut report = Report {
            id: 0,
            generation: 7,
            sent: 0,
            number: 1,
            expected: 10,
            received: 8,
            delay_us: 0,
            received_bytes: 800,
            report_time_us: 100_000,
        };
        let parsed = parse_control(&control_v2(&[report.clone()])).unwrap();
        tx.apply(&parsed[0], 9_000_000).unwrap();
        assert_eq!(tx.snapshot.sender_estimate.delivered_bps, None);
        report.number = 2;
        report.expected = 12;
        report.received = 10;
        report.received_bytes = 1000;
        report.report_time_us = 600_000;
        tx.apply(&report, 19_000_000).unwrap();
        assert_eq!(tx.snapshot.sender_estimate.delivered_bps, Some(3200.0));
        assert_eq!(tx.snapshot.sender_estimate.sample_span_us, 500_000);
        assert_eq!(tx.snapshot.sender_estimate.report_time_us, Some(600_000));
        assert_eq!(tx.snapshot.sender_estimate.sample_symbols, 2);
        assert_eq!(tx.snapshot.sender_estimate.sample_loss_rate, 0.0);
        assert!(tx.snapshot.sender_estimate.loss_rate > 0.0);
        let legacy = parse_control(&control(&[report.clone()])).unwrap();
        assert_eq!(legacy[0].report_time_us, 0);
        report.number = 3;
        report.report_time_us += 500_000;
        report.received_bytes = 1201;
        assert!(tx.apply(&report, 20_000_000).is_err());
        assert_eq!(tx.snapshot.sender_estimate.report_time_us, Some(600_000));
        // A controller may miss intermediate reports between two local polls.
        // The exported cumulative clock/bytes pair remains a matching interval;
        // the last individual sample span is not that cumulative denominator.
        report.received_bytes = 1100;
        tx.apply(&report, 20_000_001).unwrap();
        report.number = 4;
        report.received_bytes = 1200;
        report.report_time_us += 500_000;
        tx.apply(&report, 20_000_002).unwrap();
        let estimate = &tx.snapshot.sender_estimate;
        assert_eq!(estimate.report_time_us, Some(1_600_000));
        assert_eq!(estimate.sample_span_us, 500_000);
        let cumulative = (estimate.received_bytes - 1000) as f64 * 8_000_000.0
            / (estimate.report_time_us.unwrap() - 600_000) as f64;
        assert_eq!(cumulative, 1600.0);
    }
    #[test]
    fn latest_probe_exposes_drainage_before_the_diagnostic_ewma() {
        let mut state = State::new(7);
        state.probe_admitted(1, 0);
        state
            .apply_probe(
                &Probe {
                    generation: 7,
                    nonce: 1,
                    response: true,
                },
                100_000,
            )
            .unwrap();
        state.probe_admitted(2, 100_000);
        state
            .apply_probe(
                &Probe {
                    generation: 7,
                    nonce: 2,
                    response: true,
                },
                101_000,
            )
            .unwrap();
        assert_eq!(state.snapshot.probe_rtt_latest_ms, 1.0);
        assert_eq!(state.snapshot.probe_rtt_ms, 50.5);
        assert_eq!(state.snapshot.replies_received, 2);
    }
    #[test]
    fn independent_probes_require_admitted_nonce_and_current_generation() {
        let mut state = State::new(7);
        let mut reply = Probe {
            generation: 7,
            nonce: 1,
            response: true,
        };
        assert!(state.apply_probe(&reply, 20_000).is_err());
        state.probe_admitted(1, 1000);
        assert_eq!(parse_probe(&probe(&reply)).unwrap(), reply);
        state.apply_probe(&reply, 20_000).unwrap();
        assert_eq!(state.snapshot.probe_rtt_ms, 19.0);
        assert_eq!(state.snapshot.probe_rtt_latest_ms, 19.0);
        assert_eq!(state.snapshot.probe_updated_us, Some(20_000));
        assert!(state.apply_probe(&reply, 21_000).is_err());
        state.probe_admitted(2, 30_000);
        reply.nonce = 2;
        reply.generation = 8;
        assert!(state.apply_probe(&reply, 40_000).is_err());
        reply.generation = 7;
        assert!(state.apply_probe(&reply, 4_000_000).is_err());
        for nonce in 3..1000 {
            state.probe_admitted(nonce, nonce * 1000);
        }
        assert_eq!(state.probes.len(), 4);
        assert!(parse_probe(b"BQ2P").is_err());
    }
}
