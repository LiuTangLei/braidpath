//! Experimental authenticated HTTP/3 datagram transport. No reliable stream service.
pub mod cli;
pub mod probe;
pub mod relay;
pub mod stats;
pub mod transport;
pub mod tunnel;
pub mod wire;

pub const MAX_PAYLOAD: usize = 1000;
pub const MAX_PATHS: usize = 8;
pub const QUEUE: usize = 256;
