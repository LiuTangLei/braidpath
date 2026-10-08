//! Experimental building blocks for FEC-assisted multipath transport.
//!
//! This crate has no network runtime, wire format, authentication, or encryption.
//! FEC operates on trusted in-memory shards; it detects erasures, not corruption.
#![forbid(unsafe_code)]

pub mod fec;
pub mod path;
