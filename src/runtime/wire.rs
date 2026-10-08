use super::MAX_PAYLOAD;
use crate::fec::{Decoder, Shard};
use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

pub const HEADER: usize = 13;
pub const MAX_WIRE: usize = HEADER + 12 + MAX_PAYLOAD + 2;
const BLOCK_WINDOW: u64 = 256;
const MESSAGE_WINDOW: u64 = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub flow: u32,
    pub id: u64,
    pub payload: Vec<u8>,
}
impl Record {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.payload.len() <= MAX_PAYLOAD,
            "UDP message exceeds {MAX_PAYLOAD} bytes"
        );
        let mut out = Vec::with_capacity(12 + self.payload.len());
        out.extend(self.flow.to_be_bytes());
        out.extend(self.id.to_be_bytes());
        out.extend(&self.payload);
        Ok(out)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(
            (12..=12 + MAX_PAYLOAD).contains(&b.len()),
            "invalid record length"
        );
        Ok(Self {
            flow: u32::from_be_bytes(b[..4].try_into()?),
            id: u64::from_be_bytes(b[4..12].try_into()?),
            payload: b[12..].to_vec(),
        })
    }
}

pub fn shard(s: Shard) -> Bytes {
    let (kind, block, index, body) = match s {
        Shard::Data {
            block,
            index,
            payload,
        } => (0, block, index, payload),
        Shard::Repair {
            block,
            count,
            coded,
        } => (1, block, count, coded),
    };
    frame(kind, block, index, &body)
}
pub fn plain(record: &Record) -> Result<Bytes> {
    Ok(frame(2, 0, 0, &record.encode()?))
}
fn frame(kind: u8, block: u64, index: u8, body: &[u8]) -> Bytes {
    let mut b = Vec::with_capacity(HEADER + body.len());
    b.extend([b'B', b'P', 1, kind]);
    b.extend(block.to_be_bytes());
    b.push(index);
    b.extend(body);
    b.into()
}
fn decode(b: &[u8]) -> Result<Option<Shard>> {
    ensure!(
        (HEADER..=MAX_WIRE).contains(&b.len()) && b[..3] == [b'B', b'P', 1],
        "invalid frame"
    );
    let block = u64::from_be_bytes(b[4..12].try_into()?);
    match b[3] {
        0 => {
            ensure!(b[12] < 32, "invalid symbol index");
            Record::decode(&b[HEADER..])?;
            Ok(Some(Shard::Data {
                block,
                index: b[12],
                payload: b[HEADER..].to_vec(),
            }))
        }
        1 => {
            ensure!(
                (1..=32).contains(&b[12]) && b.len() >= HEADER + 14,
                "invalid repair"
            );
            Ok(Some(Shard::Repair {
                block,
                count: b[12],
                coded: b[HEADER..].to_vec(),
            }))
        }
        2 => {
            ensure!(block == 0 && b[12] == 0, "invalid plain frame");
            Ok(None)
        }
        _ => bail!("unknown frame type"),
    }
}

/// RFC 9297 Quarter Stream ID followed by BraidPath context 0.
/// Implemented here to validate mapping explicitly, including nonzero stream IDs.
pub fn http_datagram(stream: u64, payload: &[u8]) -> Result<Bytes> {
    ensure!(
        stream < (1u64 << 62) && stream.is_multiple_of(4),
        "invalid request stream"
    );
    let q = stream / 4;
    let n = if q < 64 {
        1
    } else if q < 16384 {
        2
    } else if q < (1 << 30) {
        4
    } else {
        8
    };
    let mut b = Vec::with_capacity(n + 1 + payload.len());
    let full = q.to_be_bytes();
    b.extend_from_slice(&full[8 - n..]);
    b[0] |= match n {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    b.push(0);
    b.extend(payload);
    Ok(b.into())
}
pub fn http_payload(b: &[u8], stream: u64) -> Result<&[u8]> {
    ensure!(!b.is_empty(), "empty HTTP datagram");
    let n = 1usize << (b[0] >> 6);
    ensure!(b.len() > n, "truncated HTTP datagram");
    let mut q = u64::from(b[0] & 0x3f);
    for v in &b[1..n] {
        q = (q << 8) | u64::from(*v);
    }
    ensure!(
        q < (1u64 << 60) && q * 4 == stream && b[n] == 0,
        "wrong request/context"
    );
    Ok(&b[n + 1..])
}

#[derive(Default)]
pub struct Receiver {
    blocks: BTreeMap<u64, Option<(Decoder, Instant)>>,
    highest_block: u64,
    delivered: BTreeSet<u64>,
    highest_message: u64,
    pub original_packets: u64,
    pub repair_packets: u64,
    pub stale: u64,
    pub originals: u64,
    pub recovered: u64,
    pub duplicates: u64,
    pub invalid: u64,
}
impl Receiver {
    pub fn receive(&mut self, b: &[u8], now: Instant) -> Result<Vec<Record>> {
        let decoded = decode(b)?;
        if matches!(decoded, Some(Shard::Repair { .. })) {
            self.repair_packets += 1;
        } else {
            self.original_packets += 1;
        }
        let deliveries = if let Some(s) = decoded {
            let block = s.block();
            self.highest_block = self.highest_block.max(block);
            let floor = self.highest_block.saturating_sub(BLOCK_WINDOW - 1);
            self.blocks.retain(|k, _| *k >= floor);
            if block < floor {
                self.stale += 1;
                return Ok(Vec::new());
            }
            for slot in self.blocks.values_mut() {
                if slot
                    .as_ref()
                    .is_some_and(|(_, t)| now.duration_since(*t) > Duration::from_secs(2))
                {
                    *slot = None;
                }
            }
            let slot = self
                .blocks
                .entry(block)
                .or_insert_with(|| Some((Decoder::new(block), now)));
            let Some((decoder, _)) = slot else {
                self.stale += 1;
                return Ok(Vec::new());
            };
            let duplicate = decoder.is_duplicate(&s);
            match decoder.receive(s) {
                Ok(v) => {
                    if duplicate {
                        self.duplicates += 1;
                    }
                    v.into_iter()
                        .map(|d| (d.payload, d.recovered))
                        .collect::<Vec<_>>()
                }
                Err(e) => {
                    *slot = None;
                    return Err(e.into());
                }
            }
        } else {
            vec![(b[HEADER..].to_vec(), false)]
        };
        let mut out = Vec::new();
        for (data, repaired) in deliveries {
            let record = Record::decode(&data)?;
            self.highest_message = self.highest_message.max(record.id);
            let floor = self.highest_message.saturating_sub(MESSAGE_WINDOW - 1);
            while self.delivered.first().is_some_and(|id| *id < floor) {
                self.delivered.pop_first();
            }
            if record.id < floor || !self.delivered.insert(record.id) {
                self.duplicates += 1;
                continue;
            }
            if repaired {
                self.recovered += 1
            } else {
                self.originals += 1
            }
            out.push(record);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec::Encoder;
    #[test]
    fn http_mapping_checks_all_varint_widths() {
        for stream in [0, 4, 252, 256, 65536, 1u64 << 40] {
            let b = http_datagram(stream, b"hello").unwrap();
            assert_eq!(http_payload(&b, stream).unwrap(), b"hello");
            assert!(http_payload(&b, stream + 4).is_err());
            for n in 0..b.len() - 5 {
                assert!(http_payload(&b[..n], stream).is_err());
            }
        }
    }
    #[test]
    fn recovery_retains_delivery_identity_and_suppresses_late_original() {
        let now = Instant::now();
        let mut enc = Encoder::new(4, Duration::from_millis(5)).unwrap();
        let mut shards = Vec::new();
        for id in 0..4 {
            shards.extend(
                enc.push(
                    &Record {
                        flow: 7,
                        id,
                        payload: vec![id as u8; 17],
                    }
                    .encode()
                    .unwrap(),
                    now,
                )
                .unwrap(),
            );
        }
        let mut rx = Receiver::default();
        let mut out = Vec::new();
        for (i, s) in shards.iter().enumerate() {
            if i != 1 {
                out.extend(rx.receive(&shard(s.clone()), now).unwrap());
            }
        }
        assert_eq!(out.len(), 4);
        assert_eq!(rx.recovered, 1);
        assert!(
            rx.receive(&shard(shards[1].clone()), now)
                .unwrap()
                .is_empty()
        );
        assert_eq!(rx.duplicates, 1);
        assert_eq!(rx.original_packets, 4);
        assert!(
            out.iter()
                .all(|r| r.flow == 7 && r.payload == vec![r.id as u8; 17])
        );
    }
    #[test]
    fn expired_blocks_cannot_be_reallocated() {
        let now = Instant::now();
        let mut rx = Receiver::default();
        let record = Record {
            flow: 1,
            id: 1,
            payload: vec![1],
        };
        let one = shard(Shard::Data {
            block: 0,
            index: 0,
            payload: record.encode().unwrap(),
        });
        rx.receive(&one, now).unwrap();
        rx.receive(&one, now + Duration::from_secs(3)).unwrap();
        assert!(rx.blocks.get(&0).unwrap().is_none());
        assert!(
            rx.receive(&one, now + Duration::from_secs(4))
                .unwrap()
                .is_empty()
        );
        assert!(rx.blocks.get(&0).unwrap().is_none());
        for n in 0..HEADER {
            assert!(rx.receive(&one[..n], now).is_err());
        }
    }
}
