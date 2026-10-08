//! Experimental building blocks for FEC-assisted multipath transport.
//!
//! The codec operates on trusted shards. The experimental runtime authenticates
//! HTTP/3 sessions before admitting their datagrams to the aggregate decoder.
#![forbid(unsafe_code)]

pub mod fec;
pub mod path;
pub mod runtime;
