//! Authenticated TCP streams and UDP associations, independent of FEC tunnels.
use anyhow::{Result, ensure};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

mod bond;
mod client;
mod legacy;
mod protocol;
mod server;
mod socks;
pub use client::{ClientOptions, Listener, client};
pub use server::{Server, ServerConfig, Snapshot};

pub(crate) const ALPN: &[u8] = b"braidpath-proxy/1";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const UDP_IDLE: Duration = Duration::from_secs(60);
const MAX_CONNECTIONS: usize = 64;
const MAX_STREAMS: usize = 256;
const MAX_ASSOCIATIONS: usize = 64;
const MAX_DESTINATIONS: usize = 32;

async fn udp_socket(address: std::net::SocketAddr) -> Result<tokio::net::UdpSocket> {
    let socket = tokio::net::UdpSocket::bind(address).await?;
    let options = socket2::SockRef::from(&socket);
    // macOS defaults to a 9 KiB send buffer, which rejects larger UDP messages.
    options.set_send_buffer_size(128 * 1024)?;
    options.set_recv_buffer_size(128 * 1024)?;
    Ok(socket)
}

struct CloseConnection(quinn::Connection);
impl Drop for CloseConnection {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"proxy owner stopped");
    }
}
struct AbortTask(tokio::task::JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// One bounded bucket for both directions and all proxy connections on a host.
struct Rate {
    state: Mutex<(Instant, f64)>,
    bytes_per_sec: f64,
    burst: f64,
}
impl Rate {
    fn new(bps: u64) -> Self {
        let bytes_per_sec = bps as f64 / 8.0;
        // Retain enough credit for 10 ms of traffic. A fixed 128 KiB bucket
        // would discard most refill credit at high rates on millisecond timers.
        let burst = (bytes_per_sec * 0.010).max(131_072.0);
        Self {
            state: Mutex::new((Instant::now(), burst)),
            bytes_per_sec,
            burst,
        }
    }
    fn delay(&self, n: usize) -> Option<Duration> {
        let mut state = self.state.lock().expect("proxy rate");
        let now = Instant::now();
        state.1 = (state.1 + now.duration_since(state.0).as_secs_f64() * self.bytes_per_sec)
            .min(self.burst);
        state.0 = now;
        if state.1 >= n as f64 {
            state.1 -= n as f64;
            None
        } else {
            Some(Duration::from_secs_f64(
                (n as f64 - state.1) / self.bytes_per_sec,
            ))
        }
    }
    async fn acquire(&self, n: usize) {
        while let Some(delay) = self.delay(n) {
            tokio::time::sleep(delay).await;
        }
    }
}

#[cfg(test)]
mod tests;
