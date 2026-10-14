//! Experimental cross-path systematic Reed-Solomon FEC building blocks.
//!
//! Sources leave the encoder immediately. A full block or a short deadline emits
//! repair symbols. A and the client own the encoders/decoders; forwarding servers
//! only forward datagrams. Symbols from different paths feed ONE decoder.
//!
//! This crate deliberately is NOT a turnkey Aggligator transport yet. The codec
//! does not itself implement a connection protocol. Separate modules provide
//! bounded sender recovery, pacing and optional native UDP IO; runtime reliable
//! ordering, admission and congestion adaptation remain caller responsibilities.
//! Frames need an appropriate integrity/trust boundary before decoding, and the
//! caller must independently maintain bounded reliable delivery state. Reed-Solomon repairs erasures, not
//! arbitrary corruption. The wire format is experimental and is not RFC FECFRAME.
//! Codec cache eviction does not acknowledge, abandon, or deliver missing bytes.
#[cfg(feature = "runtime")]
pub mod datagram;
pub mod delivery;
pub mod interleave;
pub mod pacing;
pub mod path;
#[cfg(feature = "runtime")]
pub mod session;
#[cfg(feature = "runtime")]
pub mod multiplex;
#[cfg(feature = "runtime")]
mod packet;
#[cfg(feature = "runtime")]
pub mod udp_tunnel;
#[cfg(feature = "managed")]
pub mod control;
#[cfg(feature = "managed")]
pub mod configuration;
#[cfg(feature = "managed")]
pub mod managed;
#[cfg(feature = "managed")]
mod warm;
#[cfg(feature = "cli")]
pub mod cli_output;
pub mod recovery;

use reed_solomon_erasure::galois_8::ReedSolomon;
use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt,
    time::Duration,
};

const HEADER: usize = 26;
const MAGIC: &[u8; 4] = b"AF01";
const MAX_DATA: usize = 64;
const MAX_PAYLOAD: usize = 1400;
const MAX_CACHE_BYTES: usize = 512 * 1024 * 1024;

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfig(&'static str),
    InvalidFrame(&'static str),
    ConflictingFrame,
    TimeWentBackwards,
    SequenceExhausted,
    Codec(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid FEC config: {message}"),
            Self::InvalidFrame(message) => write!(f, "invalid FEC frame: {message}"),
            Self::ConflictingFrame => write!(f, "conflicting FEC block metadata or source"),
            Self::TimeWentBackwards => write!(f, "FEC clock moved backwards"),
            Self::SequenceExhausted => write!(f, "FEC session sequence space exhausted"),
            Self::Codec(message) => write!(f, "Reed-Solomon: {message}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<reed_solomon_erasure::Error> for Error {
    fn from(value: reed_solomon_erasure::Error) -> Self {
        Self::Codec(value.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub data_shards: usize,
    /// Zero disables FEC (useful as an otherwise identical ARQ baseline).
    pub repair_shards: usize,
    pub max_payload: usize,
    /// Maximum block formation time, NOT a receiver playout/reorder delay.
    pub max_block_delay: Duration,
    pub max_decode_blocks: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            data_shards: 8,
            repair_shards: 4,
            max_payload: 1100,
            max_block_delay: Duration::from_millis(2),
            max_decode_blocks: 256,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.data_shards == 0 || self.data_shards > MAX_DATA {
            return Err(Error::InvalidConfig("data_shards must be 1..=64"));
        }
        if self.repair_shards > 255 - self.data_shards {
            return Err(Error::InvalidConfig("data_shards + repair_shards must be <=255"));
        }
        if self.max_payload == 0 || self.max_payload > MAX_PAYLOAD {
            return Err(Error::InvalidConfig("max_payload must be 1..=1400"));
        }
        if self.max_block_delay.is_zero() || self.max_block_delay > Duration::from_secs(1) {
            return Err(Error::InvalidConfig("max_block_delay must be >0 and <=1s"));
        }
        if self.max_decode_blocks == 0 || self.max_decode_blocks > 4096 {
            return Err(Error::InvalidConfig("max_decode_blocks must be 1..=4096"));
        }
        let bytes = self
            .max_decode_blocks
            .checked_mul(self.data_shards + self.repair_shards)
            .and_then(|n| n.checked_mul(self.max_payload + 2))
            .ok_or(Error::InvalidConfig("decoder cache size overflow"))?;
        if bytes > MAX_CACHE_BYTES {
            return Err(Error::InvalidConfig("decoder symbol cache exceeds 512MiB"));
        }
        Ok(())
    }
    fn parity_for(&self, data: usize) -> usize {
        (data * self.repair_shards).div_ceil(self.data_shards)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// Original, unpadded payload. `base + index` is the session-global sequence.
    Source { block: u64, base: u64, index: u8, payload: Vec<u8> },
    /// `data` is the ACTUAL number of sources, including shortened blocks.
    /// `index` is the repair index (0..parity), not the complete codeword index.
    Repair { block: u64, base: u64, data: u8, parity: u8, index: u8, symbol: Vec<u8> },
}
impl Frame {
    fn common(&self) -> (u64, u64) {
        match self {
            Self::Source { block, base, .. } | Self::Repair { block, base, .. } => (*block, *base),
        }
    }
    fn validate(&self, max_payload: usize) -> Result<()> {
        if max_payload == 0 || max_payload > MAX_PAYLOAD {
            return Err(Error::InvalidFrame("invalid payload bound"));
        }
        match self {
            Self::Source { base, index, payload, .. } => {
                if usize::from(*index) >= MAX_DATA || payload.len() > max_payload {
                    return Err(Error::InvalidFrame("source index or length out of range"));
                }
                base.checked_add(u64::from(*index)).ok_or(Error::SequenceExhausted)?;
            }
            Self::Repair { base, data, parity, index, symbol, .. } => {
                if *data == 0
                    || usize::from(*data) > MAX_DATA
                    || *parity == 0
                    || usize::from(*data) + usize::from(*parity) > 255
                    || *index >= *parity
                    || symbol.len() < 2
                    || symbol.len() > max_payload + 2
                {
                    return Err(Error::InvalidFrame("repair dimensions, index or length out of range"));
                }
                base.checked_add(u64::from(*data) - 1).ok_or(Error::SequenceExhausted)?;
            }
        }
        Ok(())
    }
    /// Experimental bounded datagram representation. Not authenticated.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }
    /// Appends one complete frame to a reusable or already-prefixed buffer.
    /// Validation happens before any mutation of the supplied buffer.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate(MAX_PAYLOAD)?;
        let (block, base) = self.common();
        let (kind, index, k, m, body) = match self {
            Self::Source { index, payload, .. } => (0, *index, 0, 0, payload),
            Self::Repair { data, parity, index, symbol, .. } => (1, *index, *data, *parity, symbol),
        };
        out.reserve(HEADER + body.len());
        out.extend_from_slice(MAGIC);
        out.push(kind);
        out.extend_from_slice(&block.to_be_bytes());
        out.extend_from_slice(&base.to_be_bytes());
        out.extend_from_slice(&[index, k, m]);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        Ok(())
    }
    pub fn decode(input: &[u8], max_payload: usize) -> Result<Self> {
        if input.len() < HEADER || &input[..4] != MAGIC {
            return Err(Error::InvalidFrame("truncated header or unknown version"));
        }
        let body_len = u16::from_be_bytes([input[24], input[25]]) as usize;
        if body_len > MAX_PAYLOAD + 2 || input.len() != HEADER + body_len {
            return Err(Error::InvalidFrame("truncated body or trailing bytes"));
        }
        let block = u64::from_be_bytes(input[5..13].try_into().unwrap());
        let base = u64::from_be_bytes(input[13..21].try_into().unwrap());
        let (index, k, m) = (input[21], input[22], input[23]);
        let frame = match input[4] {
            0 if k == 0 && m == 0 => Self::Source { block, base, index, payload: input[HEADER..].to_vec() },
            1 => Self::Repair { block, base, index, data: k, parity: m, symbol: input[HEADER..].to_vec() },
            _ => return Err(Error::InvalidFrame("unknown frame kind or reserved fields")),
        };
        frame.validate(max_payload)?;
        Ok(frame)
    }
}

fn codec(cache: &mut BTreeMap<(usize, usize), ReedSolomon>, k: usize, m: usize) -> Result<&mut ReedSolomon> {
    if let Entry::Vacant(entry) = cache.entry((k, m)) {
        entry.insert(ReedSolomon::new(k, m)?);
    }
    Ok(cache.get_mut(&(k, m)).unwrap())
}
fn symbol(payload: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    out[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[2..2 + payload.len()].copy_from_slice(payload);
    out
}
fn unsymbol(input: &[u8], max_payload: usize) -> Result<Vec<u8>> {
    if input.len() < 2 {
        return Err(Error::InvalidFrame("recovered symbol too short"));
    }
    let len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if len > max_payload || len > input.len() - 2 || input[2 + len..].iter().any(|b| *b != 0) {
        return Err(Error::InvalidFrame("invalid recovered length or padding; integrity required"));
    }
    Ok(input[2..2 + len].to_vec())
}

pub struct Encoder {
    cfg: Config,
    block: u64,
    base: u64,
    started: Option<Duration>,
    last_now: Duration,
    sources: Vec<Vec<u8>>,
    codecs: BTreeMap<(usize, usize), ReedSolomon>,
}
impl Encoder {
    pub fn new(cfg: Config) -> Result<Self> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            block: 0,
            base: 0,
            started: None,
            last_now: Duration::ZERO,
            sources: Vec::new(),
            codecs: BTreeMap::new(),
        })
    }
    /// Returns the new original immediately, plus any repairs due at this time.
    pub fn push(&mut self, payload: Vec<u8>, now: Duration) -> Result<Vec<Frame>> {
        if payload.len() > self.cfg.max_payload {
            return Err(Error::InvalidFrame("payload exceeds configured limit"));
        }
        let mut out = self.poll(now)?;
        self.base.checked_add(self.sources.len() as u64).ok_or(Error::SequenceExhausted)?;
        self.started.get_or_insert(now);
        out.push(Frame::Source {
            block: self.block,
            base: self.base,
            index: self.sources.len() as u8,
            payload: payload.clone(),
        });
        self.sources.push(payload);
        if self.sources.len() == self.cfg.data_shards {
            out.extend(self.flush()?);
        }
        Ok(out)
    }
    /// The runtime MUST call this on a timer, even when there are no new writes.
    pub fn poll(&mut self, now: Duration) -> Result<Vec<Frame>> {
        if now < self.last_now {
            return Err(Error::TimeWentBackwards);
        }
        self.last_now = now;
        if self.started.is_some_and(|start| now.saturating_sub(start) >= self.cfg.max_block_delay) {
            self.flush()
        } else {
            Ok(Vec::new())
        }
    }
    /// Seals a shortened block. For 8+4, one source becomes 1+1, NOT 8+4 padding.
    pub fn flush(&mut self) -> Result<Vec<Frame>> {
        let k = self.sources.len();
        if k == 0 {
            return Ok(Vec::new());
        }
        let next_base = self.base.checked_add(k as u64).ok_or(Error::SequenceExhausted)?;
        let next_block = self.block.checked_add(1).ok_or(Error::SequenceExhausted)?;
        let m = self.cfg.parity_for(k);
        let mut out = Vec::with_capacity(m);
        if m > 0 {
            let len = self.sources.iter().map(|p| p.len() + 2).max().unwrap();
            let mut shards: Vec<_> = self.sources.iter().map(|p| symbol(p, len)).collect();
            shards.resize_with(k + m, || vec![0; len]);
            codec(&mut self.codecs, k, m)?.encode(&mut shards)?;
            for (index, repair) in shards.into_iter().skip(k).enumerate() {
                out.push(Frame::Repair {
                    block: self.block,
                    base: self.base,
                    data: k as u8,
                    parity: m as u8,
                    index: index as u8,
                    symbol: repair,
                });
            }
        }
        self.sources.clear();
        self.started = None;
        self.base = next_base;
        self.block = next_block;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub seq: u64,
    pub payload: Vec<u8>,
    pub recovered: bool,
}
struct RepairState {
    k: usize,
    m: usize,
    len: usize,
    symbols: Vec<Option<Vec<u8>>>,
}
struct Block {
    base: u64,
    sources: Vec<Option<Vec<u8>>>,
    repairs: Option<RepairState>,
}

pub struct Decoder {
    cfg: Config,
    blocks: BTreeMap<u64, Block>,
    codecs: BTreeMap<(usize, usize), ReedSolomon>,
}
impl Decoder {
    pub fn new(cfg: Config) -> Result<Self> {
        cfg.validate()?;
        Ok(Self { cfg, blocks: BTreeMap::new(), codecs: BTreeMap::new() })
    }
    pub fn buffered_blocks(&self) -> usize {
        self.blocks.len()
    }
    /// Available sources are emitted immediately, WITHOUT global ordering.
    /// Original duplicates may be emitted again (including after cache eviction)
    /// so the independent ARQ layer can repeat lost ACKs. Deduplicate by `seq`.
    pub fn input(&mut self, frame: &Frame) -> Result<Vec<Decoded>> {
        frame.validate(self.cfg.max_payload)?;
        let (id, base) = frame.common();
        // Validate ALL metadata before mutating a live block or evicting a cache.
        match frame {
            Frame::Source { index, .. } if usize::from(*index) >= self.cfg.data_shards => {
                return Err(Error::InvalidFrame("source index exceeds configured block"));
            }
            Frame::Repair { data, parity, .. }
                if usize::from(*data) > self.cfg.data_shards
                    || usize::from(*parity) != self.cfg.parity_for(usize::from(*data)) =>
            {
                return Err(Error::InvalidFrame("unexpected code dimensions"));
            }
            _ => {}
        }
        if let Some(block) = self.blocks.get(&id) {
            if block.base != base {
                return Err(Error::ConflictingFrame);
            }
            match frame {
                Frame::Source { index, payload, .. } => {
                    let index = usize::from(*index);
                    if block.sources[index].as_ref().is_some_and(|old| old != payload)
                        || block.repairs.as_ref().is_some_and(|r| index >= r.k || payload.len() + 2 > r.len)
                    {
                        return Err(Error::ConflictingFrame);
                    }
                }
                Frame::Repair { data, parity, index, symbol, .. } => {
                    let k = usize::from(*data);
                    if block
                        .sources
                        .iter()
                        .enumerate()
                        .any(|(i, p)| p.as_ref().is_some_and(|p| i >= k || p.len() + 2 > symbol.len()))
                    {
                        return Err(Error::ConflictingFrame);
                    }
                    if let Some(r) = &block.repairs
                        && (r.k != k
                            || r.m != usize::from(*parity)
                            || r.len != symbol.len()
                            || r.symbols[usize::from(*index)].as_ref().is_some_and(|old| old != symbol))
                    {
                        return Err(Error::ConflictingFrame);
                    }
                }
            }
        }
        if !self.blocks.contains_key(&id) {
            if self.blocks.len() == self.cfg.max_decode_blocks {
                self.blocks.pop_first();
            }
            self.blocks.insert(id, Block { base, sources: vec![None; self.cfg.data_shards], repairs: None });
        }
        let block = self.blocks.get_mut(&id).unwrap();
        let mut out = Vec::new();
        match frame {
            Frame::Source { index, payload, .. } => {
                block.sources[usize::from(*index)] = Some(payload.clone());
                out.push(Decoded { seq: base + u64::from(*index), payload: payload.clone(), recovered: false });
            }
            Frame::Repair { data, parity, index, symbol, .. } => {
                let r = block.repairs.get_or_insert_with(|| RepairState {
                    k: usize::from(*data),
                    m: usize::from(*parity),
                    len: symbol.len(),
                    symbols: vec![None; usize::from(*parity)],
                });
                r.symbols[usize::from(*index)] = Some(symbol.clone());
            }
        }
        if let Some(r) = &block.repairs {
            let have_data = block.sources[..r.k].iter().filter(|s| s.is_some()).count();
            let have_repair = r.symbols.iter().filter(|s| s.is_some()).count();
            if have_data < r.k && have_data + have_repair >= r.k {
                let mut shards: Vec<Option<Vec<u8>>> =
                    block.sources[..r.k].iter().map(|p| p.as_ref().map(|p| symbol(p, r.len))).collect();
                shards.extend(r.symbols.iter().cloned());
                codec(&mut self.codecs, r.k, r.m)?.reconstruct_data(&mut shards)?;
                // Validate all reconstructed lengths before releasing any recovered data.
                let mut recovered = Vec::new();
                for (i, shard) in shards.iter().take(r.k).enumerate() {
                    if block.sources[i].is_none() {
                        recovered.push((i, unsymbol(shard.as_ref().unwrap(), self.cfg.max_payload)?));
                    }
                }
                for (i, payload) in recovered {
                    block.sources[i] = Some(payload.clone());
                    out.push(Decoded { seq: base + i as u64, payload, recovered: true });
                }
            }
        }
        Ok(out)
    }
}
