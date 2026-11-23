//! Preserve UDP message boundaries over the aggregate's reliable byte stream.
use super::{client::Pool, protocol::*, *};
use crate::runtime::tunnel::StreamTarget;
use std::{io, net::SocketAddr};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{OwnedSemaphorePermit, mpsc},
    time::timeout,
};

// Keep the aggregate's TCP socket adapter and its existing flow control. The
// connected pair is created on loopback and its listener closes immediately.
async fn stream_pair() -> io::Result<(TcpStream, TcpStream)> {
    // Reserve the connecting socket before listening, then verify which peer
    // was accepted. Even a local process cannot inject the stream's bytes.
    let client = tokio::net::TcpSocket::new_v4()?;
    client.bind("127.0.0.1:0".parse().expect("loopback"))?;
    let expected = client.local_addr()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (client, (server, peer)) =
        tokio::try_join!(client.connect(listener.local_addr()?), listener.accept())?;
    if peer != expected {
        return Err(io::Error::other("unexpected loopback peer"));
    }
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;
    Ok((client, server))
}

fn frame(buffer: &mut [u8], len: usize) -> &[u8] {
    buffer[..2].copy_from_slice(&(len as u16).to_be_bytes());
    &buffer[..2 + len]
}

async fn read_frame<'a>(
    mut read: impl AsyncRead + Unpin,
    buffer: &'a mut [u8],
) -> io::Result<&'a [u8]> {
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
    stream: TcpStream,
    bridge: TcpStream,
    udp: UdpSocket,
    bound: SocketAddr,
    _permit: OwnedSemaphorePermit,
}

impl Target {
    pub(crate) fn into_relay(self) -> (TcpStream, SocketAddr, impl Future<Output = ()>) {
        let Self {
            stream,
            mut bridge,
            udp,
            bound,
            _permit,
        } = self;
        let relay = async move {
            let _permit = _permit;
            let (mut read, mut write) = bridge.split();
            let active = Mutex::new(Instant::now());
            let uplink = async {
                let mut buffer = vec![0; MAX_UDP];
                loop {
                    let payload = read_frame(&mut read, &mut buffer).await?;
                    udp.send(payload).await?;
                    *active.lock().expect("UDP activity") = Instant::now();
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            };
            let downlink = async {
                let mut buffer = vec![0; 2 + MAX_UDP + 1];
                loop {
                    let n = udp.recv(&mut buffer[2..]).await?;
                    if n > MAX_UDP {
                        continue;
                    }
                    write.write_all(frame(&mut buffer, n)).await?;
                    *active.lock().expect("UDP activity") = Instant::now();
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            };
            let idle = async {
                let mut maintenance = tokio::time::interval(Duration::from_secs(5));
                loop {
                    maintenance.tick().await;
                    if active.lock().expect("UDP activity").elapsed() >= UDP_IDLE {
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
        let addresses = resolve_stream_target(&destination, allow_private)
            .await
            .map_err(|error| {
                error
                    .downcast_ref::<ReplyError>()
                    .map_or(4, |error| error.0)
            })?;
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
            socket2::SockRef::from(&udp)
                .set_recv_buffer_size(2 * 1024 * 1024)
                .map_err(|_| 1u8)?;
            let bound = udp.local_addr().map_err(|_| 1u8)?;
            let (stream, bridge) = stream_pair().await.map_err(|_| 1u8)?;
            tracing::debug!(port = address.port(), "ordered UDP destination opened");
            return Ok(Target {
                stream,
                bridge,
                udp,
                bound,
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
    exit: &str,
    target: Address,
    relay: &super::socks::Relay,
    mut requests: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let (flow, mut bridge, header) = timeout(CONNECT_TIMEOUT, async {
        let connector = pool.prepare_stream(exit).await?;
        let mut header = vec![0, 0, 0];
        target.encode(&mut header);
        let flow = connector.open_ordered_udp(target.into()).await?;
        let (stream, bridge) = stream_pair().await?;
        Ok::<_, anyhow::Error>(((flow, stream), bridge, header))
    })
    .await??;
    let (flow, stream) = flow;
    let (mut read, mut write) = bridge.split();
    let uplink = async {
        let mut buffer = vec![0; 2 + MAX_UDP];
        while let Some(payload) = requests.recv().await {
            buffer[2..2 + payload.len()].copy_from_slice(&payload);
            write.write_all(frame(&mut buffer, payload.len())).await?;
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
        }
        #[allow(unreachable_code)]
        Ok::<_, io::Error>(())
    };
    tokio::select! {
        result = flow.run(stream) => result,
        result = uplink => Ok(result?),
        result = downlink => Ok(result?),
    }
}
