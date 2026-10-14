//! Bounded selective repair state. Cumulative delivery ACKs release history;
//! FEC completion never releases another path's congestion accounting. This
//! module supplies reliability state, not authentication or congestion control.
use crate::Frame;
use std::{collections::VecDeque, fmt, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feedback {
    pub next: u64,
    pub base: u64,
    pub limit: u64,
    pub missing: u64,
}
impl Feedback {
    pub fn validate(self) -> bool {
        let Some(width) = self.limit.checked_sub(self.base) else {
            return false;
        };
        self.next <= self.base && width <= 64 && (width == 64 || self.missing >> width == 0)
    }
    pub fn encode(self) -> Option<[u8; 32]> {
        if !self.validate() {
            return None;
        }
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&self.next.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.base.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.limit.to_be_bytes());
        bytes[24..].copy_from_slice(&self.missing.to_be_bytes());
        Some(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let value = Self {
            next: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            base: u64::from_be_bytes(bytes[8..16].try_into().ok()?),
            limit: u64::from_be_bytes(bytes[16..24].try_into().ok()?),
            missing: u64::from_be_bytes(bytes[24..].try_into().ok()?),
        };
        value.validate().then_some(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    InvalidConfig,
    Full,
    OutOfSequence,
    InvalidFeedback,
    RetryLimit,
}
impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "selective recovery: {self:?}")
    }
}
impl std::error::Error for RecoveryError {}
struct Retained {
    frame: Frame,
    last_retry: Option<Duration>,
    attempts: u8,
    bytes: usize,
    received: bool,
}
pub struct SendWindow {
    entries: VecDeque<Retained>,
    base: u64,
    next: u64,
    bytes: usize,
    max_packets: usize,
    max_bytes: usize,
    cooldown: Duration,
    max_retries: u8,
}
impl SendWindow {
    pub fn new(
        max_packets: usize, max_bytes: usize, cooldown: Duration, max_retries: u8,
    ) -> Result<Self, RecoveryError> {
        if max_packets == 0
            || max_packets > 65536
            || max_bytes == 0
            || max_bytes > 128 * 1024 * 1024
            || cooldown.is_zero()
            || cooldown > Duration::from_secs(10)
            || max_retries == 0
        {
            return Err(RecoveryError::InvalidConfig);
        }
        Ok(Self {
            entries: VecDeque::new(),
            base: 0,
            next: 0,
            bytes: 0,
            max_packets,
            max_bytes,
            cooldown,
            max_retries,
        })
    }
    /// Retry pacing follows the active route RTT, not a fixed geographic guess.
    /// This only changes duplicate-retry suppression; it never acknowledges data.
    pub fn set_retry_cooldown(&mut self, cooldown: Duration) -> Result<(), RecoveryError> {
        if cooldown.is_zero() || cooldown > Duration::from_secs(10) {
            return Err(RecoveryError::InvalidConfig);
        }
        self.cooldown = cooldown;
        Ok(())
    }
    pub fn has_space(&self, bytes: usize) -> bool {
        self.entries.len() < self.max_packets
            && self.bytes.checked_add(bytes).is_some_and(|n| n <= self.max_bytes)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn next(&self) -> u64 {
        self.next
    }
    pub fn acknowledged(&self) -> u64 {
        self.base
    }
    /// Sources only, strictly increasing sequence. Never evicts unacknowledged data.
    pub fn retain(&mut self, frame: &Frame) -> Result<(), RecoveryError> {
        let Frame::Source { base, index, .. } = frame else {
            return Err(RecoveryError::OutOfSequence);
        };
        let seq = base.checked_add(u64::from(*index)).ok_or(RecoveryError::OutOfSequence)?;
        self.retain_at(seq, frame)
    }
    /// Keep an explicitly mapped application sequence (for interleaved FEC).
    pub fn retain_at(&mut self, seq: u64, frame: &Frame) -> Result<(), RecoveryError> {
        let Frame::Source { payload, .. } = frame else {
            return Err(RecoveryError::OutOfSequence);
        };
        if seq != self.next || self.next == u64::MAX {
            return Err(RecoveryError::OutOfSequence);
        }
        if !self.has_space(payload.len()) {
            return Err(RecoveryError::Full);
        }
        self.bytes += payload.len();
        self.next += 1;
        self.entries.push_back(Retained {
            frame: frame.clone(),
            last_retry: None,
            attempts: 0,
            bytes: payload.len(),
            received: false,
        });
        Ok(())
    }
    /// Validated feedback first, then apply cumulative ACK and bounded repair.
    /// Repeated requests cannot repeatedly retransmit inside the cooldown.
    pub fn feedback(&mut self, feedback: Feedback, now: Duration) -> Result<Vec<Frame>, RecoveryError> {
        if !feedback.validate() || feedback.limit > self.next {
            return Err(RecoveryError::InvalidFeedback);
        }
        if feedback.next < self.base {
            return Ok(Vec::new());
        }
        // Validate retry-limit conditions before mutating any retained state.
        for offset in 0..feedback.limit - feedback.base {
            if feedback.missing & (1u64 << offset) != 0 {
                let index = (feedback.base + offset - self.base) as usize;
                if self.entries.get(index).is_some_and(|entry| {
                    !entry.received
                        && entry.attempts >= self.max_retries
                        && entry.last_retry.is_none_or(|last| now.saturating_sub(last) >= self.cooldown)
                }) {
                    return Err(RecoveryError::RetryLimit);
                }
            }
        }
        while self.base < feedback.next {
            let entry = self.entries.pop_front().ok_or(RecoveryError::InvalidFeedback)?;
            self.bytes -= entry.bytes;
            self.base += 1;
        }
        let mut frames = Vec::new();
        for offset in 0..feedback.limit - feedback.base {
            let entry = &mut self.entries[(feedback.base + offset - self.base) as usize];
            if feedback.missing & (1u64 << offset) == 0 {
                entry.received = true;
                continue;
            }
            // A later-arriving stale NACK must not undo a selective receipt ACK.
            if entry.received {
                continue;
            }
            if entry.last_retry.is_some_and(|last| now.saturating_sub(last) < self.cooldown) {
                continue;
            }
            entry.last_retry = Some(now);
            entry.attempts += 1;
            frames.push(entry.frame.clone());
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(seq: u64) -> Frame {
        Frame::Source { block: seq / 8, base: seq / 8 * 8, index: (seq % 8) as u8, payload: vec![9; 100] }
    }
    fn window() -> SendWindow {
        SendWindow::new(4, 400, Duration::from_millis(80), 3).unwrap()
    }
    #[test]
    fn selective_repair_and_duplicate_feedback_are_bounded() {
        let mut w = window();
        for i in 0..4 {
            w.retain(&frame(i)).unwrap();
        }
        let feedback = Feedback { next: 1, base: 1, limit: 4, missing: 0b101 };
        assert_eq!(w.feedback(feedback, Duration::ZERO).unwrap(), vec![frame(1), frame(3)]);
        assert!(w.feedback(feedback, Duration::from_millis(79)).unwrap().is_empty());
        assert_eq!(w.feedback(feedback, Duration::from_millis(80)).unwrap().len(), 2);
        assert_eq!(w.bytes(), 300);
        w.feedback(Feedback { next: 4, base: 4, limit: 4, missing: 0 }, Duration::from_millis(90)).unwrap();
        assert!(w.is_empty());
        assert_eq!(w.bytes(), 0);
    }
    #[test]
    fn stale_nack_cannot_override_known_selective_receipt() {
        let mut w = window();
        w.retain(&frame(0)).unwrap();
        w.retain(&frame(1)).unwrap();
        w.feedback(Feedback { next: 0, base: 0, limit: 2, missing: 1 }, Duration::ZERO).unwrap();
        let retransmit =
            w.feedback(Feedback { next: 0, base: 0, limit: 2, missing: 3 }, Duration::from_millis(100)).unwrap();
        assert_eq!(retransmit, vec![frame(0)]);
    }
    #[test]
    fn full_window_never_evicts_unacked_sources() {
        let mut w = window();
        for i in 0..4 {
            w.retain(&frame(i)).unwrap();
        }
        assert_eq!(w.retain(&frame(4)), Err(RecoveryError::Full));
        assert_eq!(w.acknowledged(), 0);
        assert_eq!(w.next(), 4);
        w.feedback(Feedback { next: 1, base: 1, limit: 1, missing: 0 }, Duration::ZERO).unwrap();
        w.retain(&frame(4)).unwrap();
        assert_eq!(w.len(), 4);
    }
    #[test]
    fn invalid_feedback_cannot_ack_unsent_data() {
        let mut w = window();
        w.retain(&frame(0)).unwrap();
        assert_eq!(
            w.feedback(Feedback { next: 2, base: 2, limit: 2, missing: 0 }, Duration::ZERO),
            Err(RecoveryError::InvalidFeedback)
        );
        assert_eq!(w.len(), 1);
        assert_eq!(w.acknowledged(), 0);
    }
    #[test]
    fn malformed_feedback_is_rejected_and_roundtrips() {
        let fb = Feedback { next: 15, base: 15, limit: 79, missing: u64::MAX };
        assert_eq!(Feedback::decode(&fb.encode().unwrap()), Some(fb));
        assert!(!Feedback { next: u64::MAX, base: 0, limit: 0, missing: 0 }.validate());
        assert!(!Feedback { next: 0, base: 0, limit: 1, missing: 2 }.validate());
        assert!(Feedback::decode(&[0; 25]).is_none());
    }
    #[test]
    fn retry_limit_is_explicit_not_silent_data_loss() {
        let mut w = window();
        w.retain(&frame(0)).unwrap();
        let fb = Feedback { next: 0, base: 0, limit: 1, missing: 1 };
        for t in [0, 80, 160] {
            assert_eq!(w.feedback(fb, Duration::from_millis(t)).unwrap().len(), 1);
        }
        assert_eq!(w.feedback(fb, Duration::from_millis(240)), Err(RecoveryError::RetryLimit));
        assert_eq!(w.len(), 1);
    }
}
