use super::{
    client::{Pool, UdpConnection},
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
    exit: &str,
    early_reply: bool,
    ordered_ports: Arc<[u16]>,
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
        let opened = timeout(CONNECT_TIMEOUT, pool.open_stream(exit, target, early_reply)).await;
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
    if pool.game_mode {
        let connector = match timeout(CONNECT_TIMEOUT, pool.prepare_stream(exit)).await {
            Ok(Ok(connector)) => connector,
            _ => {
                reply(&mut tcp, 4, unspecified).await?;
                return Ok(());
            }
        };
        return timeout(CONNECT_TIMEOUT, connector.associate(tcp, target.port())).await?;
    }
    // Preserve admission before replying for unchanged native-only listeners.
    let native = if ordered_ports.is_empty() {
        match open_native(&pool, exit).await {
            Ok(native) => Some(native),
            Err(error) => {
                reply(
                    &mut tcp,
                    error.downcast_ref::<ReplyError>().map_or(4, |e| e.0),
                    unspecified,
                )
                .await?;
                return Ok(());
            }
        }
    } else {
        None
    };
    udp(tcp, pool, exit, target.port(), native, &ordered_ports).await
}

struct Native {
    conn: Arc<UdpConnection>,
    send: quinn::SendStream,
    control: quinn::RecvStream,
    registration: Registration,
}

async fn open_native(pool: &Pool, exit: &str) -> Result<Native> {
    timeout(CONNECT_TIMEOUT, async {
        let conn = pool.udp_connection(exit).await?;
        let (mut send, mut control) = conn.raw.open_bi().await?;
        let registration = conn.router.register(send.id().index())?;
        send.write_all(&[UDP]).await?;
        let status = control.read_u8().await?;
        if status != 0 {
            return Err(ReplyError(if status <= 8 { status } else { 1 }).into());
        }
        tracing::debug!(%exit, "UDP association pinned to exit");
        Ok(Native {
            conn,
            send,
            control,
            registration,
        })
    })
    .await?
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

async fn native_forward(
    mut native: Native,
    relay: &Relay,
    mut requests: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let mut ended = [0; 1];
    let mut reassembly = Reassembly::default();
    let mut counter = 0;
    loop {
        tokio::select! {
            _ = native.control.read(&mut ended) => break,
            _ = native.conn.raw.closed() => break,
            request = requests.recv() => {
                let Some(request) = request else { break; };
                let packet_id = counter;
                counter += 1;
                if send_packet(&native.conn.raw, native.send.id().index(), packet_id, &request).await.is_err()
                    && native.conn.raw.close_reason().is_some()
                {
                    break;
                }
            }
            frame = native.registration.recv.recv() => {
                let Some(frame) = frame else { break; };
                let Some(packet) = reassembly.receive(frame, Instant::now()) else { continue; };
                if packet.len() + 3 <= MAX_UDP {
                    let mut response = Vec::with_capacity(packet.len() + 3);
                    response.extend([0, 0, 0]);
                    response.extend(packet);
                    relay.send(&response).await?;
                }
            }
        }
    }
    native.send.finish()?;
    Ok(())
}

const UDP_QUEUE: usize = 64;

fn spawn_native(
    tasks: &mut JoinSet<Result<()>>,
    pool: Arc<Pool>,
    exit: String,
    relay: Arc<Relay>,
    native: Option<Native>,
) -> mpsc::Sender<Vec<u8>> {
    let (send, recv) = mpsc::channel(UDP_QUEUE);
    tasks.spawn(async move {
        let native = match native {
            Some(native) => native,
            None => open_native(&pool, &exit).await?,
        };
        native_forward(native, &relay, recv).await
    });
    send
}

async fn udp(
    mut tcp: TcpStream,
    pool: Arc<Pool>,
    exit: &str,
    port: u16,
    native: Option<Native>,
    ordered_ports: &[u16],
) -> Result<()> {
    let peer = tcp.peer_addr()?;
    let socket = udp_socket(SocketAddr::new(tcp.local_addr()?.ip(), 0)).await?;
    let relay = Arc::new(Relay {
        socket,
        source: Mutex::new((port != 0).then(|| SocketAddr::new(peer.ip(), port))),
        active: Mutex::new(Instant::now()),
    });
    reply(&mut tcp, 0, relay.socket.local_addr()?).await?;
    let mut tasks = JoinSet::new();
    let mut native = native.map(|native| {
        spawn_native(
            &mut tasks,
            pool.clone(),
            exit.into(),
            relay.clone(),
            Some(native),
        )
    });
    let mut ordered = HashMap::<Address, mpsc::Sender<Vec<u8>>>::new();
    let mut ordered_drops = 0u64;
    let mut native_drops = 0u64;
    let mut bytes = vec![0; 65_536];
    let mut closed = [0; 1];
    let mut maintenance = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = tcp.read(&mut closed) => break,
            ended = tasks.join_next(), if !tasks.is_empty() => {
                if ordered_ports.is_empty() { break; }
                if let Some(Ok(Err(error))) = ended {
                    tracing::debug!(%exit, %error, "UDP route ended");
                }
                ordered.retain(|_, route| !route.is_closed());
            }
            _ = maintenance.tick() => {
                if ordered_drops != 0 || native_drops != 0 {
                    tracing::info!(
                        %exit,
                        ordered_queue_drops = ordered_drops,
                        native_queue_drops = native_drops,
                        "SOCKS UDP queue dropped datagrams"
                    );
                    ordered_drops = 0;
                    native_drops = 0;
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
                *relay.source.lock().expect("SOCKS UDP source") = Some(from);
                if ordered_ports.contains(&address.port()) {
                    if ordered.get(&address).is_none_or(mpsc::Sender::is_closed) {
                        ordered.retain(|_, route| !route.is_closed());
                        if ordered.len() >= MAX_DESTINATIONS { continue; }
                        let (send, recv) = mpsc::channel(UDP_QUEUE);
                        ordered.insert(address.clone(), send);
                        let pool = pool.clone();
                        let relay = relay.clone();
                        let exit = exit.to_owned();
                        let address = address.clone();
                        tasks.spawn(async move {
                            super::ordered_udp::forward(&pool, &exit, address, &relay, recv).await
                        });
                    }
                    if let Some(route) = ordered.get(&address)
                        && route.try_send(payload.to_vec()).is_err()
                    {
                        ordered_drops += 1;
                    }
                } else {
                    if native.as_ref().is_none_or(mpsc::Sender::is_closed) {
                        if ordered_ports.is_empty() { break; }
                        native = Some(spawn_native(&mut tasks, pool.clone(), exit.into(), relay.clone(), None));
                    }
                    if native
                        .as_ref()
                        .expect("native UDP route")
                        .try_send(bytes[3..n].to_vec())
                        .is_err()
                    {
                        native_drops += 1;
                    }
                }
                relay.touch();
            }
        }
    }
    Ok(())
}
