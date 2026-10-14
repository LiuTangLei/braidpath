//! Bounded, sampled ORIGINAL-arrival telemetry; never an application ACK.
//!
//! One out of 16 source sequences is observed. A bitmap covers 1024 source
//! sequences and is delayed after ordered delivery to allow slow originals to
//! arrive after their FEC reconstruction. A zero means missing at the observation
//! deadline, not proven permanent network loss. Fixed-size rings reject stale
//! feedback and do not retain payloads. Feedback must use the session admission
//! boundary; it must NEVER release reliable sender history.
use std::{collections::VecDeque, time::Duration};

const STRIDE: u64 = 16;
pub const SPAN: u64 = 64 * STRIDE;
const SLOTS: usize = 2048;
const MAX_PATHS: usize = 32;
const SETTLE: Duration = Duration::from_millis(150);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawReceipt { pub base: u64, pub received: u64 }
impl RawReceipt {
    pub fn encode(self) -> Option<[u8;16]> {
        if !self.base.is_multiple_of(SPAN) || self.base.checked_add(SPAN).is_none() { return None; }
        let mut bytes=[0;16]; bytes[..8].copy_from_slice(&self.base.to_be_bytes());
        bytes[8..].copy_from_slice(&self.received.to_be_bytes()); Some(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len()!=16 { return None; }
        let item=Self {base:u64::from_be_bytes(bytes[..8].try_into().ok()?),
            received:u64::from_be_bytes(bytes[8..].try_into().ok()?)};
        item.encode()?; Some(item)
    }
}

#[derive(Clone, Copy)]
struct SentSample {seq:u64,path:usize,reported:bool}
pub struct DeliverySender { samples:Vec<Option<SentSample>> }
impl Default for DeliverySender { fn default()->Self {Self {samples:vec![None;SLOTS]}} }
impl DeliverySender {
    /// Call only after a successful original-datagram submission, never for retries.
    pub fn sent(&mut self, seq:u64, path:usize) {
        if path>=MAX_PATHS || !seq.is_multiple_of(STRIDE) {return;}
        let slot=(seq/STRIDE) as usize % SLOTS;
        if self.samples[slot].is_none_or(|old|old.seq<seq) {
            self.samples[slot]=Some(SentSample {seq,path,reported:false});
        }
    }
    /// (observed samples, missing samples) per ORIGINAL path. Duplicate,
    /// overwritten and never-sent sequence observations cannot create evidence.
    pub fn apply(&mut self, receipt:RawReceipt)->[(u32,u32);MAX_PATHS] {
        let mut out=[(0,0);MAX_PATHS];
        if receipt.encode().is_none() {return out;}
        for index in 0..64 {
            let seq=receipt.base+index*STRIDE;
            let slot=(seq/STRIDE) as usize%SLOTS;
            if let Some(sample)=&mut self.samples[slot] && sample.seq==seq && !sample.reported {
                sample.reported=true; out[sample.path].0+=1;
                out[sample.path].1+=u32::from(receipt.received & (1<<index)==0);
            }
        }
        out
    }
}

pub struct DeliveryReceiver {
    originals:Vec<Option<u64>>,
    next_base:u64,
    pending:VecDeque<(u64,Duration)>,
}
impl Default for DeliveryReceiver {
    fn default()->Self {Self {originals:vec![None;SLOTS],next_base:0,pending:VecDeque::new()}}
}
impl DeliveryReceiver {
    pub fn original(&mut self, seq:u64) {
        if !seq.is_multiple_of(STRIDE) {return;}
        let slot=(seq/STRIDE) as usize%SLOTS;
        if self.originals[slot].is_none_or(|old|old<seq) {self.originals[slot]=Some(seq);}
    }
    pub fn ready(&mut self, delivered_next:u64, now:Duration)->Vec<RawReceipt> {
        // Coverage is bounded independently from an arbitrarily long byte stream.
        for _ in 0..8 {
            let Some(end)=self.next_base.checked_add(SPAN) else{break;};
            if end>delivered_next || self.pending.len()>=32 {break;}
            self.pending.push_back((self.next_base,now));self.next_base=end;
        }
        let mut output=Vec::new();
        for _ in 0..8 {
            let Some(&(base,at))=self.pending.front() else {break;};
            if now.saturating_sub(at)<SETTLE {break;}
            self.pending.pop_front();
            // If a receiver was stalled so long that the sampled ring aged out,
            // suppress the entire snapshot instead of falsely declaring losses.
            let expired=(0..64).any(|i|{
                let seq=base+i*STRIDE;
                self.originals[(seq/STRIDE) as usize%SLOTS].is_some_and(|old|old>seq)
            });
            if expired {continue;}
            let mut mask=0u64;
            for i in 0..64 {
                let seq=base+i*STRIDE;
                if self.originals[(seq/STRIDE) as usize%SLOTS]==Some(seq) {mask|=1<<i;}
            }
            output.push(RawReceipt {base,received:mask});
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fec_delivery_is_not_an_original_arrival_and_late_originals_are_counted() {
        let mut tx=DeliverySender::default();let mut rx=DeliveryReceiver::default();
        for seq in 0..SPAN {
            tx.sent(seq,(seq/STRIDE%2) as usize);
            if seq!=0 && seq!=32 {rx.original(seq);}
        }
        assert!(rx.ready(SPAN,Duration::ZERO).is_empty());
        rx.original(32); // The original arrives after FEC, but within the settling interval.
        assert!(rx.ready(SPAN,Duration::from_millis(149)).is_empty());
        let packet=rx.ready(SPAN,Duration::from_millis(150)).pop().unwrap();
        assert_eq!(packet.received,u64::MAX-1);
        assert_eq!(tx.apply(packet)[..2],[(32,1),(32,0)]);
        assert_eq!(tx.apply(packet),[(0,0);32]);
    }
    #[test]
    fn invalid_unsent_and_overwritten_feedback_is_ignored() {
        let mut tx=DeliverySender::default();
        assert!(RawReceipt {base:1,received:0}.encode().is_none());
        assert!(RawReceipt::decode(&[0;17]).is_none());
        assert_eq!(tx.apply(RawReceipt {base:0,received:0}),[(0,0);32]);
        tx.sent(0,0);tx.sent(SLOTS as u64*STRIDE,1);
        assert_eq!(tx.apply(RawReceipt {base:0,received:0}),[(0,0);32]);
        assert_eq!(tx.apply(RawReceipt {base:SLOTS as u64*STRIDE,received:1})[1],(1,0));
    }
    #[test]
    fn expired_receiver_window_does_not_create_false_loss_report() {
        let mut rx=DeliveryReceiver::default();rx.original(0);
        rx.ready(SPAN,Duration::ZERO);
        rx.original(SLOTS as u64*STRIDE);
        assert!(rx.ready(SPAN,Duration::from_secs(1)).is_empty());
    }
}
