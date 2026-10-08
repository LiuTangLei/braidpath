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
}

impl Shard {
    pub fn block(&self) -> u64 {
        match self {
            Self::Data { block, .. } | Self::Repair { block, .. } => *block,
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
}

impl Decoder {
    pub fn new(block: u64) -> Self {
        Self {
            block,
            data: vec![None; MAX_DATA_SHARDS],
            repair: None,
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
                    || self.repair.as_ref().is_some_and(|(count, coded)| {
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
                if let Some(existing) = &self.repair {
                    return if existing == &(count, coded) {
                        Ok(out)
                    } else {
                        Err(Error::ConflictingShard)
                    };
                }
                self.repair = Some((count, coded));
            }
        }
        if let Some((count, coded)) = &self.repair {
            let missing: Vec<_> = (0..usize::from(*count))
                .filter(|i| self.data[*i].is_none())
                .collect();
            if missing.len() == 1 {
                let index = missing[0];
                let mut recovered = coded.clone();
                for payload in self.data[..usize::from(*count)].iter().flatten() {
                    xor_into(&mut recovered, &symbol(payload));
                }
                let len = usize::from(u16::from_be_bytes([recovered[0], recovered[1]]));
                if len + 2 > recovered.len() || recovered[len + 2..].iter().any(|b| *b != 0) {
                    return Err(Error::InvalidShard);
                }
                let payload = recovered[2..len + 2].to_vec();
                self.data[index] = Some(payload.clone());
                out.push(Delivery {
                    block: self.block,
                    index: index as u8,
                    payload,
                    recovered: true,
                });
            }
        }
        Ok(out)
    }
}
