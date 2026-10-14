//! Interleave independent small FEC blocks across time. Originals still leave
//! immediately; consecutive application packets are assigned to different code
//! blocks, reducing correlated losses inside each block. The peer must agree on
//! `lanes`. This mapping is an experimental protocol extension, not auto-negotiated.
use crate::{Config, Decoded, Decoder, Encoder, Error, Frame};
use std::time::Duration;

pub struct InterleavedEncoder {
    encoders: Vec<Encoder>,
    next: u64,
}
impl InterleavedEncoder {
    pub fn new(cfg: Config, lanes: usize) -> Result<Self, Error> {
        if lanes == 0 || lanes > 16 {
            return Err(Error::InvalidConfig("interleave lanes must be 1..16"));
        }
        let encoders = (0..lanes).map(|_| Encoder::new(cfg.clone())).collect::<Result<_, _>>()?;
        Ok(Self { encoders, next: 0 })
    }
    pub fn push(&mut self, payload: Vec<u8>, now: Duration) -> Result<Vec<Frame>, Error> {
        let lanes = self.encoders.len();
        let lane = self.next as usize % lanes;
        let frames = self.encoders[lane].push(payload, now)?;
        self.next = self.next.checked_add(1).ok_or(Error::SequenceExhausted)?;
        map_frames(frames, lanes, lane)
    }
    pub fn poll(&mut self, now: Duration) -> Result<Vec<Frame>, Error> {
        let lanes = self.encoders.len();
        let mut out = Vec::new();
        for (lane, enc) in self.encoders.iter_mut().enumerate() {
            out.extend(map_frames(enc.poll(now)?, lanes, lane)?);
        }
        Ok(out)
    }
    pub fn flush(&mut self) -> Result<Vec<Frame>, Error> {
        let lanes = self.encoders.len();
        let mut out = Vec::new();
        for (lane, enc) in self.encoders.iter_mut().enumerate() {
            out.extend(map_frames(enc.flush()?, lanes, lane)?);
        }
        Ok(out)
    }
}
fn map_frames(mut frames: Vec<Frame>, lanes: usize, lane: usize) -> Result<Vec<Frame>, Error> {
    for frame in &mut frames {
        let (block, base) = match frame {
            Frame::Source { block, base, .. } | Frame::Repair { block, base, .. } => (block, base),
        };
        *block = block
            .checked_mul(lanes as u64)
            .and_then(|b| b.checked_add(lane as u64))
            .ok_or(Error::SequenceExhausted)?;
        *base = base
            .checked_mul(lanes as u64)
            .and_then(|b| b.checked_add(lane as u64))
            .ok_or(Error::SequenceExhausted)?;
    }
    Ok(frames)
}
pub fn source_sequence(frame: &Frame, lanes: usize) -> Result<Option<u64>, Error> {
    if lanes == 0 || lanes > 16 {
        return Err(Error::InvalidConfig("interleave lanes must be 1..16"));
    }
    match frame {
        Frame::Source { base, index, .. } => {
            base.checked_add(u64::from(*index) * lanes as u64).map(Some).ok_or(Error::SequenceExhausted)
        }
        _ => Ok(None),
    }
}
pub fn decode(decoder: &mut Decoder, frame: &Frame, lanes: usize) -> Result<Vec<Decoded>, Error> {
    if lanes == 0 || lanes > 16 {
        return Err(Error::InvalidConfig("interleave lanes must be 1..16"));
    }
    frame.validate(super::MAX_PAYLOAD)?;
    let (block, base) = match frame {
        Frame::Source { block, base, .. } | Frame::Repair { block, base, .. } => (*block, *base),
    };
    if block % lanes as u64 != base % lanes as u64 {
        return Err(Error::InvalidFrame("inconsistent interleave lane metadata"));
    }
    let (base, width) = match frame {
        Frame::Source { base, index, .. } => (*base, u64::from(*index)),
        Frame::Repair { base, data, .. } => (*base, u64::from(*data) - 1),
    };
    base.checked_add(width * lanes as u64).ok_or(Error::SequenceExhausted)?;
    let mut out = decoder.input(frame)?;
    for packet in &mut out {
        packet.seq = base + (packet.seq - base) * lanes as u64;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn interleaving_repairs_eight_consecutive_source_losses() {
        let cfg = Config {
            data_shards: 16,
            repair_shards: 1,
            max_block_delay: Duration::from_millis(10),
            ..Config::default()
        };
        let mut encoder = InterleavedEncoder::new(cfg.clone(), 8).unwrap();
        let mut decoder = Decoder::new(cfg).unwrap();
        let mut out = BTreeMap::new();
        let mut frames = Vec::new();
        for seq in 0u64..128 {
            frames.extend(encoder.push(seq.to_be_bytes().to_vec(), Duration::ZERO).unwrap());
        }
        frames.extend(encoder.flush().unwrap());
        for frame in frames.iter().rev() {
            if source_sequence(frame, 8).unwrap().is_some_and(|seq| (40..48).contains(&seq)) {
                continue;
            }
            for packet in decode(&mut decoder, frame, 8).unwrap() {
                out.insert(packet.seq, packet.payload);
            }
        }
        assert_eq!(out.len(), 128);
        for (seq, payload) in out {
            assert_eq!(payload, seq.to_be_bytes());
        }
    }
    #[test]
    fn malformed_interleaved_frames_fail_without_panicking() {
        let mut decoder = Decoder::new(Config::default()).unwrap();
        let invalid = Frame::Repair { block: 0, base: 0, data: 0, parity: 1, index: 0, symbol: vec![0; 2] };
        assert!(decode(&mut decoder, &invalid, 8).is_err());
        let invalid = Frame::Source { block: 0, base: 1, index: 0, payload: vec![1] };
        assert!(decode(&mut decoder, &invalid, 8).is_err());
        assert_eq!(decoder.buffered_blocks(), 0);
    }
    #[test]
    fn shortened_lanes_preserve_original_sequence() {
        let cfg = Config { data_shards: 8, repair_shards: 8, ..Config::default() };
        let mut encoder = InterleavedEncoder::new(cfg.clone(), 4).unwrap();
        let mut decoder = Decoder::new(cfg).unwrap();
        for seq in 0u64..7 {
            encoder.push(seq.to_be_bytes().to_vec(), Duration::ZERO).unwrap();
        }
        let mut out = BTreeMap::new();
        for frame in encoder.poll(Duration::from_millis(3)).unwrap() {
            for packet in decode(&mut decoder, &frame, 4).unwrap() {
                out.insert(packet.seq, packet.payload);
            }
        }
        assert_eq!(out.len(), 7);
        for (seq, payload) in out {
            assert_eq!(payload, seq.to_be_bytes());
        }
    }
}
