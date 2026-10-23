//! Authenticated TCP streams and UDP associations, independent of FEC tunnels.
use anyhow::{Result, ensure};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

mod client;
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
}
impl Rate {
    fn new(bps: u64) -> Self {
        Self {
            state: Mutex::new((Instant::now(), 131_072.0)),
            bytes_per_sec: bps as f64 / 8.0,
        }
    }
    fn delay(&self, n: usize) -> Option<Duration> {
        let mut state = self.state.lock().expect("proxy rate");
        let now = Instant::now();
        state.1 = (state.1 + now.duration_since(state.0).as_secs_f64() * self.bytes_per_sec)
            .min(131_072.0);
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

async fn bridge(
    tcp: TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    rate: Option<&Rate>,
) -> Result<()> {
    let (mut read, mut write) = tcp.into_split();
    let active = Mutex::new(Instant::now());
    let copy = async {
        tokio::try_join!(
            pump(&mut read, &mut send, &active, rate),
            pump(&mut recv, &mut write, &active, rate),
        )?;
        Ok(())
    };
    let idle = async {
        loop {
            let deadline = *active.lock().expect("proxy activity") + IDLE_TIMEOUT;
            tokio::time::sleep_until(deadline).await;
            if active.lock().expect("proxy activity").elapsed() >= IDLE_TIMEOUT {
                break;
            }
        }
    };
    tokio::select! { result = copy => result, _ = idle => anyhow::bail!("proxy TCP idle timeout") }
}
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    active: &Mutex<Instant>,
    rate: Option<&Rate>,
) -> Result<()> {
    let mut buf = [0; 16 * 1024];
    loop {
        let n = read.read(&mut buf).await?;
        if n == 0 {
            write.shutdown().await?;
            return Ok(());
        }
        if let Some(rate) = rate {
            rate.acquire(n).await;
        }
        write.write_all(&buf[..n]).await?;
        *active.lock().expect("proxy activity") = Instant::now();
    }
}

#[cfg(test)]
mod tests;
