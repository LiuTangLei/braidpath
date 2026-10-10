//! Experimental authenticated HTTP/3 datagram transport. No reliable stream service.
pub mod adaptive;
pub mod capacity_probe;
pub mod cli;
pub mod outbound;
pub mod probe;
pub mod quality;
pub mod relay;
pub mod scheduler;
pub mod stats;
pub mod transport;
pub mod tunnel;
pub mod wire;

pub const MAX_PAYLOAD: usize = 1000;
pub const MAX_PATHS: usize = 8;
pub const QUEUE: usize = 256;
