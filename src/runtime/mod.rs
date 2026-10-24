//! Authenticated multipath UDP tunnels and QUIC TCP/UDP proxy services.
pub mod adaptive;
pub mod automatic_fec;
pub mod capacity_probe;
pub mod cli;
pub mod fec_retention;
pub mod forward_guard;
pub mod mesh;
pub mod outbound;
pub mod probe;
pub mod proxy;
pub mod quality;
pub mod receiver_budget;
pub mod relay;
pub mod reverse_guard;
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
pub const MAX_MESSAGE: usize = 4096;
pub const MAX_PATHS: usize = 8;
pub const QUEUE: usize = 256;
/// Default operational ceiling; actual throughput remains congestion controlled.
pub const MAX_RATE_BPS: u64 = 10_000_000_000;
