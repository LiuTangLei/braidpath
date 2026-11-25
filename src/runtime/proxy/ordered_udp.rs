//! Preserve UDP message boundaries over the aggregate's reliable byte stream.
use super::{
    client::{Pool, SessionKey},
    protocol::*,
    *,
};
use crate::runtime::tunnel::StreamTarget;
use std::{
    io,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{
    io::DuplexStream,
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, mpsc},
    time::timeout,
};

const DUPLEX_CAPACITY: usize = 128 * 1024;
const EARLY_INITIAL_LIMIT: usize = 16 * 1024;
/// Short-lived request/reply flows (e.g., DNS/NTP or <=4-packet exchanges)
/// release resources faster than long-lived VPN/QUIC destinations.
const SHORT_UDP_IDLE: Duration = Duration::from_secs(15);
const BULK_FLOW_PACKETS: u64 = 4;
const LAZY_RECV_BUF_PACKETS: u64 = 32;

fn idle_limit(port: u16, packets: u64) -> Duration {
    if matches!(port, 53 | 123) || packets <= BULK_FLOW_PACKETS {
        SHORT_UDP_IDLE
    } else {
        UDP_IDLE
    }
}

fn frame(buffer: &mut [u8], len: usize) -> &[u8] {
    buffer[..2].copy_from_slice(&(len as u16).to_be_bytes());
    &buffer[..2 + len]
}

fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn read_frame(mut read: impl AsyncRead + Unpin, buffer: &mut [u8]) -> io::Result<&[u8]> {
    let len = usize::from(read.read_u16().await?);
    if len > MAX_UDP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized UDP frame",
        ));
    }
    read.read_exact(&mut buffer[..len]).await?;
    Ok(&buffer[..len])
}

pub(crate) struct Target {
    stream: DuplexStream,
    bridge: DuplexStream,
    udp: UdpSocket,
    bound: SocketAddr,
    target_port: u16,
    _permit: OwnedSemaphorePermit,
}

impl Target {
    pub(crate) fn into_relay(self) -> (DuplexStream, SocketAddr, impl Future<Output = ()>) {
        let Self {
            stream,
            bridge,
            udp,
            bound,
            target_port,
            _permit,
        } = self;
        let relay = async move {
            let _permit = _permit;
            let (mut read, mut write) = tokio::io::split(bridge);
            let active = Mutex::new(Instant::now());
            let packets = AtomicU64::new(0);
            let uplink = async {
                let mut buffer = vec![0; MAX_UDP];
                loop {
                    let payload = read_frame(&mut read, &mut buffer).await?;
                    udp.send(payload).await?;
                    packets.fetch_add(1, Ordering::Relaxed);
                    *active.lock().expect("UDP activity") = Instant::now();
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            };
            let downlink = async {
                let mut buffer = vec![0; 2 + MAX_UDP + 1];
                let mut rx_packets = 0u64;
                loop {
                    let n = udp.recv(&mut buffer[2..]).await?;
                    if n > MAX_UDP {
                        continue;
                    }
                    rx_packets += 1;
                    if rx_packets == LAZY_RECV_BUF_PACKETS {
                        // Only sustained flows (VPN, HTTP/3 download) allocate
                        // a 2 MiB kernel receive buffer.
                        enlarge_recv_buffer(socket2::SockRef::from(&udp));
                    }
                    write.write_all(frame(&mut buffer, n)).await?;
                    packets.fetch_add(1, Ordering::Relaxed);
                    *active.lock().expect("UDP activity") = Instant::now();
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            };
            let idle = async {
                let mut maintenance = tokio::time::interval(Duration::from_secs(5));
                loop {
                    maintenance.tick().await;
                    let limit = idle_limit(target_port, packets.load(Ordering::Relaxed));
                    if active.lock().expect("UDP activity").elapsed() >= limit {
                        break;
                    }
                }
            };
            tokio::select! {
                _ = uplink => {}
                _ = downlink => {}
                _ = idle => {}
            }
        };
        (stream, bound, relay)
    }
}

const ORDERED_RECV_BUFFER_BYTES: usize = 2 * 1024 * 1024;
const MIN_ORDERED_RECV_BUFFER_BYTES: usize = 256 * 1024;

fn request_recv_buffer(
    max_bytes: usize,
    min_bytes: usize,
    mut set: impl FnMut(usize) -> io::Result<()>,
) -> Option<usize> {
    let mut requested = max_bytes;
    loop {
        if set(requested).is_ok() {
            return Some(requested);
        }
        if requested <= min_bytes {
            return None;
        }
        requested = (requested / 2).max(min_bytes);
    }
}

fn enlarge_recv_buffer(socket: socket2::SockRef<'_>) {
    let requested = request_recv_buffer(
        ORDERED_RECV_BUFFER_BYTES,
        MIN_ORDERED_RECV_BUFFER_BYTES,
        |bytes| socket.set_recv_buffer_size(bytes),
    );
    let granted = socket.recv_buffer_size().ok();
    tracing::debug!(requested, granted, "ordered UDP receive buffer");
}

fn prefer_ipv4(addresses: &mut [SocketAddr]) {
    // UDP connect cannot detect an unreachable dual-stack peer.
    // Prefer A records; an explicit IPv6 address stays IPv6.
    addresses.sort_by_key(|address| address.is_ipv6());
}

pub(crate) async fn connect(
    destination: StreamTarget,
    allow_private: bool,
    gateway: Option<Arc<Server>>,
) -> std::result::Result<Target, u8> {
    timeout(CONNECT_TIMEOUT, async {
        let permit = gateway
            .ok_or(2u8)?
            .reserve_udp_destination()
            .map_err(|_| 1u8)?;
        let mut addresses = resolve_stream_target(&destination, allow_private)
            .await
            .map_err(|error| {
                error
                    .downcast_ref::<ReplyError>()
                    .map_or(4, |error| error.0)
            })?;
        prefer_ipv4(&mut addresses);
        for address in addresses {
            let ip = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let Ok(udp) = udp_socket(ip.parse().expect("wildcard")).await else {
                continue;
            };
            if udp.connect(address).await.is_err() {
                continue;
            }
            let bound = udp.local_addr().map_err(|_| 1u8)?;
            let (stream, bridge) = tokio::io::duplex(DUPLEX_CAPACITY);
            tracing::debug!(port = address.port(), "ordered UDP destination opened");
            return Ok(Target {
                stream,
                bridge,
                udp,
                bound,
                target_port: address.port(),
                _permit: permit,
            });
        }
        Err(4u8)
    })
    .await
    .unwrap_or(Err(4))
}

pub(super) async fn forward(
    pool: &Pool,
    key: &SessionKey,
    target: Address,
    relay: &super::socks::Relay,
    first_payload: Vec<u8>,
    mut requests: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let target_port = target.port();
    let first_framed = encode_frame(&first_payload);
    let (initial, deferred_first) = if first_framed.len() <= EARLY_INITIAL_LIMIT {
        (first_framed, None)
    } else {
        (Vec::new(), Some(first_framed))
    };
    let (flow, stream, bridge, header) = timeout(CONNECT_TIMEOUT, async {
        let connector = pool.prepare_stream(key).await?;
        let mut header = vec![0, 0, 0];
        target.encode(&mut header);
        let flow = connector.open_ordered_udp(target.into(), initial).await?;
        let (stream, bridge) = tokio::io::duplex(DUPLEX_CAPACITY);
        Ok::<_, anyhow::Error>((flow, stream, bridge, header))
    })
    .await??;
    let (mut read, mut write) = tokio::io::split(bridge);
    let active = Mutex::new(Instant::now());
    let packets = AtomicU64::new(1);
    let uplink = async {
        if let Some(first) = deferred_first {
            write.write_all(&first).await?;
        }
        let mut buffer = vec![0; 2 + MAX_UDP];
        while let Some(payload) = requests.recv().await {
            if payload.len() > MAX_UDP {
                continue;
            }
            buffer[2..2 + payload.len()].copy_from_slice(&payload);
            write.write_all(frame(&mut buffer, payload.len())).await?;
            packets.fetch_add(1, Ordering::Relaxed);
            *active.lock().expect("UDP activity") = Instant::now();
        }
        Ok::<_, io::Error>(())
    };
    let downlink = async {
        let mut buffer = vec![0; MAX_UDP];
        let mut response = header;
        let offset = response.len();
        loop {
            let payload = read_frame(&mut read, &mut buffer).await?;
            response.truncate(offset);
            response.extend_from_slice(payload);
            relay.send(&response).await?;
            packets.fetch_add(1, Ordering::Relaxed);
            *active.lock().expect("UDP activity") = Instant::now();
        }
        #[allow(unreachable_code)]
        Ok::<_, io::Error>(())
    };
    let idle = async {
        let mut maintenance = tokio::time::interval(Duration::from_secs(5));
        loop {
            maintenance.tick().await;
            let limit = idle_limit(target_port, packets.load(Ordering::Relaxed));
            if active.lock().expect("UDP activity").elapsed() >= limit {
                break;
            }
        }
    };
    tokio::select! {
        result = flow.run_memory(stream) => result,
        result = uplink => Ok(result?),
        result = downlink => Ok(result?),
        _ = idle => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_buffer_request_falls_back_when_os_caps_below_two_mebibytes() {
        let mut attempts = Vec::new();
        let granted = request_recv_buffer(2 * 1024 * 1024, 256 * 1024, |bytes| {
            attempts.push(bytes);
            if bytes > 1_864_135 {
                Err(io::Error::other("buffer limit"))
            } else {
                Ok(())
            }
        });
        assert_eq!(granted, Some(1024 * 1024));
        assert_eq!(attempts, vec![2 * 1024 * 1024, 1024 * 1024]);

        let none = request_recv_buffer(2 * 1024 * 1024, 256 * 1024, |_| {
            Err(io::Error::other("buffer limit"))
        });
        assert_eq!(none, None);
    }

    #[test]
    fn ordered_udp_prefers_ipv4_for_dual_stack_resolution() {
        let v6: SocketAddr = "[2001:db8::1]:4500".parse().unwrap();
        let v4: SocketAddr = "198.51.100.1:4500".parse().unwrap();
        let mut mixed = vec![v6, v4];
        prefer_ipv4(&mut mixed);
        assert_eq!(mixed, vec![v4, v6]);

        let mut explicit_v6 = vec![v6];
        prefer_ipv4(&mut explicit_v6);
        assert_eq!(explicit_v6, vec![v6]);
    }

    #[test]
    fn adaptive_idle_ttl_reclaims_dns_and_short_exchanges_faster() {
        assert_eq!(idle_limit(53, 100), SHORT_UDP_IDLE);
        assert_eq!(idle_limit(123, 100), SHORT_UDP_IDLE);
        assert_eq!(idle_limit(443, 2), SHORT_UDP_IDLE);
        assert_eq!(idle_limit(443, 10), UDP_IDLE);
        assert_eq!(idle_limit(4500, 10), UDP_IDLE);
    }
}
