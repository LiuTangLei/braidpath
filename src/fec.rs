//! Systematic XOR erasure coding: k original packets plus one repair packet.
//!
//! Original packets leave immediately. A caller-driven deadline flushes a partial
//! block; callers must invoke `flush_due` from a timer even when there is no input.
//! Every packet has a coded u16 length, allowing recovery of unequal payloads.
//! This is a baseline codec, not the final adaptive/sliding-window FEC algorithm.

use std::{
    fmt,
    time::{Duration, Instant},
};

mod dual;
pub use dual::DualEncoder;

pub const MAX_PAYLOAD: usize = 1200;
pub const MAX_DATA_SHARDS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidConfig,
    PayloadTooLarge,
    InvalidShard,
    WrongBlock,
    ConflictingShard,
    BlockIdExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// Internal representation only. Do not deserialize untrusted network data into
/// shards until the network layer authenticates the complete metadata and bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shard {
    Data {
        block: u64,
        index: u8,
        payload: Vec<u8>,
    },
    Repair {
        block: u64,
        count: u8,
        coded: Vec<u8>,
    },
    /// Independent weighted parity; meaningful only in an explicitly negotiated session.
    RepairQ {
        block: u64,
        count: u8,
        coded: Vec<u8>,
    },
}

impl Shard {
    pub fn block(&self) -> u64 {
        match self {
            Self::Data { block, .. } | Self::Repair { block, .. } | Self::RepairQ { block, .. } => {
                *block
            }
        }
    }
}

fn symbol(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(payload.len() + 2);
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn xor_into(target: &mut Vec<u8>, source: &[u8]) {
    target.resize(target.len().max(source.len()), 0);
    for (dst, src) in target.iter_mut().zip(source) {
        *dst ^= src;
    }
}

pub struct Encoder {
    k: u8,
    max_age: Duration,
    block: u64,
    count: u8,
    started: Option<Instant>,
    parity: Vec<u8>,
}

impl Encoder {
    pub fn new(k: u8, max_age: Duration) -> Result<Self, Error> {
        if k == 0 || usize::from(k) > MAX_DATA_SHARDS || max_age.is_zero() {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            k,
            max_age,
            block: 0,
            count: 0,
            started: None,
            parity: Vec::new(),
        })
    }

    /// Returns original data immediately, plus any full/expired-block repair.
    /// `now` must come from the same monotonically advancing clock as flush calls.
    pub fn push(&mut self, payload: &[u8], now: Instant) -> Result<Vec<Shard>, Error> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        // Reserve the final identifier so completing a block cannot wrap IDs.
        if self.block == u64::MAX {
            return Err(Error::BlockIdExhausted);
        }
        let mut out: Vec<_> = self.flush_due(now).into_iter().collect();
        if self.block == u64::MAX {
            return Err(Error::BlockIdExhausted);
        }
        self.started.get_or_insert(now);
        out.push(Shard::Data {
            block: self.block,
            index: self.count,
            payload: payload.to_vec(),
        });
        xor_into(&mut self.parity, &symbol(payload));
        self.count += 1;
        if self.count == self.k {
            out.extend(self.flush());
        }
        Ok(out)
    }

    pub fn flush_due(&mut self, now: Instant) -> Option<Shard> {
        if self
            .started
            .is_some_and(|start| now.saturating_duration_since(start) >= self.max_age)
        {
            self.flush()
        } else {
            None
        }
    }

    /// Call on end-of-input as well as on the timer. A short block still costs a
    /// whole repair symbol: configured k does not impose a wire-overhead budget.
    pub fn flush(&mut self) -> Option<Shard> {
        if self.count == 0 {
            return None;
        }
        let repair = Shard::Repair {
            block: self.block,
            count: self.count,
            coded: std::mem::take(&mut self.parity),
        };
        self.block += 1;
        self.count = 0;
        self.started = None;
        Some(repair)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub block: u64,
    pub index: u8,
    pub payload: Vec<u8>,
    pub recovered: bool,
}

/// Bounded state for one block. The future session layer must bound and expire
/// its collection of decoders and suppress replay of already-retired blocks.
/// Delivery is unordered; reliable stream reassembly belongs to the session.
pub struct Decoder {
    block: u64,
    data: Vec<Option<Vec<u8>>>,
    repair: Option<(u8, Vec<u8>)>,
    repair_q: Option<(u8, Vec<u8>)>,
}

impl Decoder {
    pub fn new(block: u64) -> Self {
        Self {
            block,
            data: vec![None; MAX_DATA_SHARDS],
            repair: None,
            repair_q: None,
        }
    }

    /// Observation only; accepting an identical already-held symbol emits no delivery.
    pub(crate) fn is_duplicate(&self, shard: &Shard) -> bool {
        match shard {
            Shard::Data { index, payload, .. } => self
                .data
                .get(usize::from(*index))
                .is_some_and(|p| p.as_ref() == Some(payload)),
            Shard::Repair { count, coded, .. } => self
                .repair
                .as_ref()
                .is_some_and(|p| p.0 == *count && p.1 == *coded),
            Shard::RepairQ { count, coded, .. } => self
                .repair_q
                .as_ref()
                .is_some_and(|p| p.0 == *count && p.1 == *coded),
        }
    }

    /// Each original/recovered packet is returned once during this block's life.
    pub fn receive(&mut self, shard: Shard) -> Result<Vec<Delivery>, Error> {
        if shard.block() != self.block {
            return Err(Error::WrongBlock);
        }
        let mut out = Vec::new();
        match shard {
            Shard::Data { index, payload, .. } => {
                let index = usize::from(index);
                if index >= MAX_DATA_SHARDS
                    || payload.len() > MAX_PAYLOAD
                    || self
                        .repair
                        .iter()
                        .chain(self.repair_q.iter())
                        .any(|(count, coded)| {
                            index >= usize::from(*count) || payload.len() + 2 > coded.len()
                        })
                {
                    return Err(Error::InvalidShard);
                }
                if let Some(existing) = &self.data[index] {
                    return if existing == &payload {
                        Ok(out)
                    } else {
                        Err(Error::ConflictingShard)
                    };
                }
                self.data[index] = Some(payload.clone());
                out.push(Delivery {
                    block: self.block,
                    index: index as u8,
                    payload,
                    recovered: false,
                });
            }
            Shard::Repair { count, coded, .. } => {
                self.insert_repair(false, count, coded)?;
            }
            Shard::RepairQ { count, coded, .. } => self.insert_repair(true, count, coded)?,
        }
        self.recover(&mut out)?;
        Ok(out)
    }

    fn insert_repair(&mut self, q: bool, count: u8, coded: Vec<u8>) -> Result<(), Error> {
        if count == 0
            || usize::from(count) > MAX_DATA_SHARDS
            || !(2..=MAX_PAYLOAD + 2).contains(&coded.len())
            || self.data.iter().enumerate().any(|(i, value)| {
                value
                    .as_ref()
                    .is_some_and(|p| i >= usize::from(count) || p.len() + 2 > coded.len())
            })
        {
            return Err(Error::InvalidShard);
        }
        let (slot, other) = if q {
            (&mut self.repair_q, &self.repair)
        } else {
            (&mut self.repair, &self.repair_q)
        };
        if other
            .as_ref()
            .is_some_and(|(n, bytes)| *n != count || bytes.len() != coded.len())
        {
            return Err(Error::ConflictingShard);
        }
        if let Some(existing) = slot {
            return if existing == &(count, coded) {
                Ok(())
            } else {
                Err(Error::ConflictingShard)
            };
        }
        *slot = Some((count, coded));
        Ok(())
    }

    fn recover(&mut self, out: &mut Vec<Delivery>) -> Result<(), Error> {
        let Some((count, _)) = self.repair.as_ref().or(self.repair_q.as_ref()) else {
            return Ok(());
        };
        let count = usize::from(*count);
        let missing: Vec<_> = (0..count).filter(|i| self.data[*i].is_none()).collect();
        if missing.is_empty()
            || missing.len() > 2
            || (missing.len() == 2 && (self.repair.is_none() || self.repair_q.is_none()))
        {
            return Ok(());
        }
        let residue = |repair: &(u8, Vec<u8>), weighted: bool| {
            let mut bytes = repair.1.clone();
            for (i, data) in self.data[..count].iter().enumerate() {
                if let Some(data) = data {
                    let input = symbol(data);
                    if weighted {
                        dual::weighted_xor(&mut bytes, &input, (i + 1) as u8);
                    } else {
                        xor_into(&mut bytes, &input);
                    }
                }
            }
            bytes
        };
        let reconstructed = if missing.len() == 1 {
            let bytes = if let Some(p) = &self.repair {
                residue(p, false)
            } else {
                let mut bytes = residue(self.repair_q.as_ref().expect("available parity"), true);
                let inverse = dual::inverse((missing[0] + 1) as u8);
                for byte in &mut bytes {
                    *byte = dual::mul(*byte, inverse);
                }
                bytes
            };
            vec![(missing[0], bytes)]
        } else {
            let p = residue(self.repair.as_ref().expect("P parity"), false);
            let q = residue(self.repair_q.as_ref().expect("Q parity"), true);
            let a = (missing[0] + 1) as u8;
            let b = (missing[1] + 1) as u8;
            let divisor = dual::inverse(a ^ b);
            let first: Vec<_> = p
                .iter()
                .zip(&q)
                .map(|(p, q)| dual::mul(*q ^ dual::mul(b, *p), divisor))
                .collect();
            let second = p.iter().zip(&first).map(|(p, x)| p ^ x).collect();
            vec![(missing[0], first), (missing[1], second)]
        };
        // Validate every decoded length/padding before committing either missing symbol.
        let decoded = reconstructed
            .into_iter()
            .map(|(index, bytes)| {
                let len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                if len + 2 > bytes.len() || bytes[len + 2..].iter().any(|b| *b != 0) {
                    return Err(Error::InvalidShard);
                }
                Ok((index, bytes[2..len + 2].to_vec()))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        for (index, payload) in decoded {
            self.data[index] = Some(payload.clone());
            out.push(Delivery {
                block: self.block,
                index: index as u8,
                payload,
                recovered: true,
            });
        }
        Ok(())
    }
}
