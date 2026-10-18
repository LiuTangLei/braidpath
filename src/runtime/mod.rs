//! Experimental authenticated HTTP/3 datagram transport with optional reliable TCP streams.
pub mod adaptive;
pub mod automatic_fec;
pub mod capacity_probe;
pub mod cli;
pub mod fec_retention;
pub mod outbound;
pub mod probe;
pub mod quality;
pub mod receiver_budget;
pub mod relay;
pub mod scheduler;
pub mod sender_frontier;
mod shutdown;
pub mod stats;
pub mod stream;
pub mod trace;
pub mod transport;
pub mod tunnel;
pub mod wire;

pub const MAX_PAYLOAD: usize = 1000;
pub const MAX_PATHS: usize = 8;
pub const QUEUE: usize = 256;
