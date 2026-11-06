//! Measure both directions of an authenticated UDP path before admitting data.
use super::{client::UdpConnection, protocol::Router, *};
use bytes::Bytes;

const COUNT: usize = 32;
const MAGIC: &[u8; 8] = b"BPUDPCHK";
const INTERVAL: Duration = Duration::from_millis(10);
pub(super) const VALID_FOR: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug)]
pub(super) struct Quality {
    pub received: usize,
    pub rtt: Duration,
}
impl Quality {
    pub fn complete(self) -> bool {
        self.received == COUNT
    }
    pub fn better_than(self, other: Self) -> bool {
        self.received > other.received || (self.received == other.received && self.rtt < other.rtt)
    }
}

// Association zero is the authentication stream, never an application UDP flow.
// Echo only bounded, recognizable probes, after authentication, on the same
// encrypted connection. No destination lookup or external socket is involved.
pub(super) fn is_probe(data: &[u8]) -> bool {
    matches!(data.len(), 128 | 1024)
        && data[..8] == [0; 8]
        && data[8..16] == *MAGIC
        && u32::from_be_bytes(data[24..28].try_into().unwrap()) < COUNT as u32
}

pub(super) async fn measure(conn: &UdpConnection) -> Result<Quality> {
    measure_raw(&conn.raw, &conn.router).await
}

async fn measure_raw(conn: &quinn::Connection, router: &Arc<Router>) -> Result<Quality> {
    let mut registration = router.register(0)?;
    let nonce = rand::random::<u64>().to_be_bytes();
    let mut sent = Vec::with_capacity(COUNT);
    let mut received = [false; COUNT];
    let mut rtts = Vec::with_capacity(COUNT);
    let started = Instant::now();
    let grace = (conn.rtt() * 3).clamp(Duration::from_millis(250), Duration::from_secs(1));
    let deadline = started + INTERVAL * COUNT as u32 + grace;
    let mut tick = tokio::time::interval(INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = conn.closed() => anyhow::bail!("UDP path closed during health probe"),
            _ = tick.tick(), if sent.len() < COUNT => {
                let index = sent.len();
                let mut packet = vec![0; if index.is_multiple_of(2) { 128 } else { 1024 }];
                packet[8..16].copy_from_slice(MAGIC);
                packet[16..24].copy_from_slice(&nonce);
                packet[24..28].copy_from_slice(&(index as u32).to_be_bytes());
                // Admission has its own deadline; a blocked sender must not
                // prevent the other candidate paths from being considered.
                tokio::time::timeout_at(deadline, conn.send_datagram_wait(Bytes::from(packet))).await??;
                sent.push(Instant::now());
            }
            data = registration.recv.recv() => {
                let Some(data) = data else { anyhow::bail!("UDP probe receiver closed"); };
                if !matches!(data.len(), 120 | 1016) || data[..8] != *MAGIC || data[8..16] != nonce {
                    continue;
                }
                let index = u32::from_be_bytes(data[16..20].try_into().unwrap()) as usize;
                if index >= sent.len() || received[index] { continue; }
                let expected = if index.is_multiple_of(2) { 120 } else { 1016 };
                if data.len() != expected { continue; }
                received[index] = true;
                rtts.push(sent[index].elapsed());
                if rtts.len() == COUNT { break; }
            }
        }
    }
    rtts.sort_unstable();
    let quality = Quality {
        received: rtts.len(),
        rtt: rtts.get(rtts.len() / 2).copied().unwrap_or(grace),
    };
    tracing::info!(peer = %conn.remote_address(), expected = COUNT, sent = sent.len(), received = quality.received,
        rtt_us = quality.rtt.as_micros() as u64, "UDP route health probe");
    Ok(quality)
}
