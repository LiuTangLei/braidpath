//! Two independent parity equations over GF(256), polynomial 0x11d.
//! P is the legacy XOR equation; Q weights source i by the distinct nonzero
//! field element i+1. Any two erased symbols in a k+2 block are recoverable.
//! This is a private codec extension, not RFC 5510 wire interoperability.
use super::{Error, MAX_DATA_SHARDS, MAX_PAYLOAD, Shard, symbol, xor_into};
use std::time::{Duration, Instant};

// A row stays hot while encoding one source or eliminating one known symbol.
// Build the same polynomial arithmetic once at compile time, not for every byte.
const fn multiplication_table() -> [[u8; 256]; 256] {
    let mut table = [[0; 256]; 256];
    let mut a = 0;
    while a < 256 {
        let mut b = 1;
        while b < 256 {
            let half = table[a][b >> 1];
            let doubled = (half << 1) ^ if half & 0x80 != 0 { 0x1d } else { 0 };
            table[a][b] = doubled ^ if b & 1 != 0 { a as u8 } else { 0 };
            b += 1;
        }
        a += 1;
    }
    table
}

static MULTIPLICATION: [[u8; 256]; 256] = multiplication_table();

pub(super) fn mul(a: u8, b: u8) -> u8 {
    MULTIPLICATION[usize::from(a)][usize::from(b)]
}

pub(super) fn inverse(value: u8) -> u8 {
    assert_ne!(value, 0, "zero has no multiplicative inverse");
    let mut result = 1;
    let mut base = value;
    let mut power = 254u8;
    while power != 0 {
        if power & 1 != 0 {
            result = mul(result, base);
        }
        base = mul(base, base);
        power >>= 1;
    }
    result
}

pub(super) fn weighted_xor(target: &mut Vec<u8>, input: &[u8], weight: u8) {
    target.resize(target.len().max(input.len()), 0);
    let row = &MULTIPLICATION[usize::from(weight)];
    for (out, value) in target.iter_mut().zip(input) {
        *out ^= row[usize::from(*value)];
    }
}

/// Independent of the unchanged single-repair Encoder API and byte output.
pub struct DualEncoder {
    k: u8,
    max_age: Duration,
    block: u64,
    count: u8,
    started: Option<Instant>,
    p: Vec<u8>,
    q: Vec<u8>,
}

impl DualEncoder {
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
            p: Vec::new(),
            q: Vec::new(),
        })
    }

    pub fn push(&mut self, payload: &[u8], now: Instant) -> Result<Vec<Shard>, Error> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        if self.block == u64::MAX {
            return Err(Error::BlockIdExhausted);
        }
        let mut out = self.flush_due(now);
        if self.block == u64::MAX {
            return Err(Error::BlockIdExhausted);
        }
        self.started.get_or_insert(now);
        out.push(Shard::Data {
            block: self.block,
            index: self.count,
            payload: payload.to_vec(),
        });
        let bytes = symbol(payload);
        xor_into(&mut self.p, &bytes);
        weighted_xor(&mut self.q, &bytes, self.count + 1);
        self.count += 1;
        if self.count == self.k {
            out.extend(self.flush());
        }
        Ok(out)
    }

    pub fn flush_due(&mut self, now: Instant) -> Vec<Shard> {
        if self
            .started
            .is_some_and(|at| now.saturating_duration_since(at) >= self.max_age)
        {
            self.flush()
        } else {
            Vec::new()
        }
    }

    pub fn flush(&mut self) -> Vec<Shard> {
        if self.count == 0 {
            return Vec::new();
        }
        let out = vec![
            Shard::Repair {
                block: self.block,
                count: self.count,
                coded: std::mem::take(&mut self.p),
            },
            Shard::RepairQ {
                block: self.block,
                count: self.count,
                coded: std::mem::take(&mut self.q),
            },
        ];
        self.block += 1;
        self.count = 0;
        self.started = None;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reference_mul(mut a: u8, mut b: u8) -> u8 {
        let mut out = 0;
        while b != 0 {
            if b & 1 != 0 {
                out ^= a;
            }
            let high = a & 0x80 != 0;
            a <<= 1;
            if high {
                a ^= 0x1d;
            }
            b >>= 1;
        }
        out
    }

    #[test]
    fn lookup_matches_polynomial_for_every_field_pair() {
        for a in 0..=255 {
            for b in 0..=255 {
                assert_eq!(mul(a, b), reference_mul(a, b), "a={a} b={b}");
            }
        }
    }

    #[test]
    fn weighted_lookup_preserves_padding_and_existing_target_bytes() {
        let input: Vec<u8> = (0..=255).collect();
        for weight in 0..=255 {
            for len in [0, 17, 256, 279] {
                let mut expected = vec![0x5a; len];
                expected.resize(len.max(input.len()), 0);
                for (out, value) in expected.iter_mut().zip(&input) {
                    *out ^= reference_mul(*value, weight);
                }
                let mut actual = vec![0x5a; len];
                weighted_xor(&mut actual, &input, weight);
                assert_eq!(actual, expected, "weight={weight} len={len}");
            }
        }
    }

    #[test]
    fn every_nonzero_field_element_has_a_valid_inverse() {
        for a in 1..=255 {
            assert_eq!(mul(a, inverse(a)), 1);
        }
        assert_eq!(mul(0x80, 2), 0x1d);
    }
    #[test]
    fn exhaustion_and_invalid_inputs_do_not_wrap_block_ids() {
        assert!(DualEncoder::new(0, Duration::from_millis(1)).is_err());
        assert!(DualEncoder::new(33, Duration::from_millis(1)).is_err());
        assert!(DualEncoder::new(16, Duration::ZERO).is_err());
        let mut encoder = DualEncoder::new(1, Duration::from_millis(1)).unwrap();
        encoder.block = u64::MAX - 1;
        assert_eq!(encoder.push(&[1], Instant::now()).unwrap().len(), 3);
        assert_eq!(
            encoder.push(&[2], Instant::now()),
            Err(Error::BlockIdExhausted)
        );
    }
}
