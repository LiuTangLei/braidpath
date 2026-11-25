use super::{
    client::{Pool, SessionKey, SessionMode},
    protocol::*,
    *,
};
use std::{collections::HashMap, net::SocketAddr};
use tokio::time::timeout;
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet};

async fn reply(tcp: &mut TcpStream, status: u8, bound: SocketAddr) -> Result<()> {
    let mut response = vec![5, status, 0];
    Address::Ip(bound).encode(&mut response);
    tcp.write_all(&response).await?;
    Ok(())
}

pub(super) async fn serve(
    mut tcp: TcpStream,
    pool: Arc<Pool>,
    key: &SessionKey,
    early_reply: bool,
) -> Result<()> {
    let (command, target) = timeout(CONNECT_TIMEOUT, async {
        ensure!(tcp.read_u8().await? == 5, "SOCKS version must be 5");
        let count = tcp.read_u8().await? as usize;
        ensure!(count != 0, "no SOCKS methods");
        let mut methods = vec![0; count];
        tcp.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            tcp.write_all(&[5, 255]).await?;
            anyhow::bail!("SOCKS no acceptable method");
        }
        tcp.write_all(&[5, 0]).await?;
        ensure!(tcp.read_u8().await? == 5, "SOCKS request version");
        let command = tcp.read_u8().await?;
        ensure!(tcp.read_u8().await? == 0, "SOCKS reserved byte");
        Ok::<_, anyhow::Error>((command, Address::read(&mut tcp).await?))
    })
    .await??;
    let unspecified: SocketAddr = "0.0.0.0:0".parse()?;
    if command != TCP && command != UDP {
        reply(&mut tcp, 7, unspecified).await?;
        return Ok(());
    }
    if command == TCP && target.port() == 0 {
        reply(&mut tcp, 4, unspecified).await?;
        return Ok(());
    }
    if command == UDP
        && !matches!(&target, Address::Ip(a) if a.ip().is_unspecified() || a.ip() == tcp.peer_addr()?.ip())
    {
        reply(&mut tcp, 2, unspecified).await?;
        return Ok(());
    }
    if command == TCP {
        let opened = timeout(CONNECT_TIMEOUT, pool.open_stream(key, target, early_reply)).await;
        let flow = match opened {
            Ok(Ok(flow)) => flow,
            Ok(Err(error)) => {
                reply(
                    &mut tcp,
                    error
                        .downcast_ref::<crate::runtime::tunnel::tcp::OpenError>()
                        .map_or_else(
                            || error.downcast_ref::<ReplyError>().map_or(4, |e| e.0),
                            |e| e.0,
                        ),
                    unspecified,
                )
                .await?;
                return Ok(());
            }
            Err(_) => {
                reply(&mut tcp, 4, unspecified).await?;
                return Ok(());
            }
        };
        if early_reply {
            // Once success is visible, abandonment must reset the socket.
            socket2::SockRef::from(&tcp).set_linger(Some(Duration::ZERO))?;
        }
        reply(&mut tcp, 0, flow.bound()).await?;
        return flow.run(tcp).await;
    }
    let connector = match timeout(CONNECT_TIMEOUT, pool.prepare_stream(key)).await {
        Ok(Ok(connector)) => connector,
        _ => {
            reply(&mut tcp, 4, unspecified).await?;
            return Ok(());
        }
    };
    if key.mode == SessionMode::Game {
        return timeout(CONNECT_TIMEOUT, connector.associate(tcp, target.port())).await?;
    }
    udp(tcp, pool, key, target.port()).await
}

pub(super) struct Relay {
    socket: UdpSocket,
    source: Mutex<Option<SocketAddr>>,
    active: Mutex<Instant>,
}

impl Relay {
    pub(super) async fn send(&self, response: &[u8]) -> std::io::Result<()> {
        let source = *self.source.lock().expect("SOCKS UDP source");
        if let Some(source) = source.filter(|_| response.len() <= MAX_UDP) {
            self.socket.send_to(response, source).await?;
            self.touch();
        }
        Ok(())
    }

    fn touch(&self) {
        *self.active.lock().expect("SOCKS UDP activity") = Instant::now();
    }
}

const UDP_QUEUE: usize = 64;

struct RouteEntry {
    send: mpsc::Sender<Vec<u8>>,
    last_used: Instant,
}

async fn udp(mut tcp: TcpStream, pool: Arc<Pool>, key: &SessionKey, port: u16) -> Result<()> {
    let peer = tcp.peer_addr()?;
    let socket = udp_socket(SocketAddr::new(tcp.local_addr()?.ip(), 0)).await?;
    let relay = Arc::new(Relay {
        socket,
        source: Mutex::new((port != 0).then(|| SocketAddr::new(peer.ip(), port))),
        active: Mutex::new(Instant::now()),
    });
    reply(&mut tcp, 0, relay.socket.local_addr()?).await?;
    let mut tasks = JoinSet::new();
    let mut ordered = HashMap::<Address, RouteEntry>::new();
    let mut ordered_drops = 0u64;
    let mut ordered_evictions = 0u64;
    let mut bytes = vec![0; 65_536];
    let mut closed = [0; 1];
    let mut maintenance = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = tcp.read(&mut closed) => break,
            ended = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(Err(error))) = ended {
                    tracing::debug!(session=%key, %error, "ordered UDP route ended");
                }
                ordered.retain(|_, route| !route.send.is_closed());
            }
            _ = maintenance.tick() => {
                if ordered_drops != 0 || ordered_evictions != 0 {
                    tracing::info!(
                        session=%key,
                        ordered_queue_drops = ordered_drops,
                        ordered_lru_evictions = ordered_evictions,
                        "SOCKS ordered UDP maintenance"
                    );
                    ordered_drops = 0;
                    ordered_evictions = 0;
                }
                if relay.active.lock().expect("SOCKS UDP activity").elapsed() >= UDP_IDLE {
                    break;
                }
            }
            received = relay.socket.recv_from(&mut bytes) => {
                let (n, from) = received?;
                let source = *relay.source.lock().expect("SOCKS UDP source");
                if from.ip() != peer.ip() || source.is_some_and(|s| s != from) || n < 4 || bytes[..3] != [0, 0, 0] {
                    continue;
                }
                let Ok((address, payload)) = packet(&bytes[3..n]).await else { continue; };
                let now = Instant::now();
                *relay.source.lock().expect("SOCKS UDP source") = Some(from);
                if ordered.get(&address).is_none_or(|entry| entry.send.is_closed()) {
                    ordered.retain(|_, route| !route.send.is_closed());
                    if ordered.len() >= MAX_DESTINATIONS
                        && let Some(oldest) = ordered
                            .iter()
                            .min_by_key(|(_, entry)| entry.last_used)
                            .map(|(addr, _)| addr.clone())
                    {
                        ordered.remove(&oldest);
                        ordered_evictions += 1;
                    }
                    let (send, recv) = mpsc::channel(UDP_QUEUE);
                    ordered.insert(address.clone(), RouteEntry { send, last_used: now });
                    let pool = pool.clone();
                    let relay = relay.clone();
                    let key = key.clone();
                    let first_payload = payload.to_vec();
                    tasks.spawn(async move {
                        super::ordered_udp::forward(&pool, &key, address, &relay, first_payload, recv).await
                    });
                } else if let Some(entry) = ordered.get_mut(&address) {
                    entry.last_used = now;
                    if entry.send.try_send(payload.to_vec()).is_err() {
                        ordered_drops += 1;
                    }
                }
                relay.touch();
            }
        }
    }
    Ok(())
}
