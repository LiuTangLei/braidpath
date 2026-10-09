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
}
#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub generation: u64,
    pub sent_symbols: u64,
    pub received: Estimate,
    pub sender_estimate: Estimate,
    pub late: u64,
    pub duplicates: u64,
    pub controls_sent: u64,
    pub controls_received: u64,
    pub invalid_controls: u64,
}
pub struct State {
    pub snapshot: Snapshot,
    seen: BTreeSet<u64>,
    pending: VecDeque<(u64, u64)>,
    watermark: u64,
    transit_min: Option<i128>,
    peer_report: u64,
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
        }
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
        Report {
            id,
            generation: self.snapshot.generation,
            sent: self.snapshot.sent_symbols,
            number: self.snapshot.received.report_number,
            expected: self.snapshot.received.expected,
            received: self.snapshot.received.received,
            delay_us: (self.snapshot.received.delay_variation_ms * 1000.0) as u64,
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
}
fn number(b: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(b[offset..offset + 8].try_into().expect("validated frame"))
}
pub fn control(reports: &[Report]) -> Bytes {
    assert!(reports.len() <= MAX_PATHS);
    let mut b = Vec::with_capacity(5 + ENTRY * reports.len());
    b.extend(*b"BQ1C");
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
    }
    b.into()
}
pub fn parse_control(b: &[u8]) -> Result<Vec<Report>> {
    ensure!(
        b.len() >= 5
            && &b[..4] == b"BQ1C"
            && usize::from(b[4]) <= MAX_PATHS
            && b.len() == 5 + ENTRY * usize::from(b[4]),
        "invalid control length"
    );
    let mut ids = BTreeSet::new();
    let mut out = Vec::new();
    for e in b[5..].as_chunks::<ENTRY>().0 {
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
        };
        state.apply(&r, 1000).unwrap();
        assert_eq!(state.snapshot.sender_estimate.updated_us, Some(1000));
        r.number = 2;
        state.apply(&r, 10_000_000).unwrap();
        assert_eq!(state.snapshot.sender_estimate.updated_us, Some(1000));
        assert!((state.snapshot.sender_estimate.loss_rate - 0.2).abs() < 1e-12);
        state.snapshot.sent_symbols = 12;
        r.number = 3;
        r.expected = 12;
        r.received = 10;
        state.apply(&r, 11_000_000).unwrap();
        assert_eq!(state.snapshot.sender_estimate.updated_us, Some(11_000_000));
    }
    #[test]
    fn loss_reordering_duplicates_and_tail_are_finalized_without_fec_credit() {
        let mut tx = State::new(7);
        let mut rx = State::new(7);
        let packets: Vec<_> = (0..4)
            .map(|n| {
                let p = tx.wrap(&payload(), n * 1000);
                tx.snapshot.sent_symbols += 1;
                p
            })
            .collect();
        rx.receive(&packets[2], 10_000).unwrap();
        rx.receive(&packets[0], 11_000).unwrap();
        rx.receive(&packets[0], 12_000).unwrap();
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
}
