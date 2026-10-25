use super::{
    client::{Pool, UdpConnection},
    protocol::*,
    *,
};
use std::net::SocketAddr;
use tokio::time::timeout;

async fn reply(tcp: &mut TcpStream, status: u8, bound: SocketAddr) -> Result<()> {
    let mut response = vec![5, status, 0];
    Address::Ip(bound).encode(&mut response);
    tcp.write_all(&response).await?;
    Ok(())
}
pub(super) async fn serve(mut tcp: TcpStream, pool: Arc<Pool>, exit: &str) -> Result<()> {
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
        let opened = timeout(CONNECT_TIMEOUT, pool.open_stream(exit, target)).await;
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
        reply(&mut tcp, 0, flow.bound()).await?;
        return flow.run(tcp).await;
    }
    let setup = timeout(CONNECT_TIMEOUT, async {
        let conn = timeout(Duration::from_secs(2), pool.udp_connection(exit)).await??;
        let (mut send, mut recv) = conn.raw.open_bi().await?;
        let registration = conn.router.register(send.id().index())?;
        let request = [UDP];
        send.write_all(&request).await?;
        let status = recv.read_u8().await?;
        if status != 0 {
            return Err(ReplyError(if status <= 8 { status } else { 1 }).into());
        }
        tracing::debug!(%exit, "UDP association pinned to exit");
        Ok::<_, anyhow::Error>((conn, send, recv, registration))
    })
    .await;
    let (conn, send, recv, registration) = match setup {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            reply(
                &mut tcp,
                error.downcast_ref::<ReplyError>().map_or(4, |e| e.0),
                unspecified,
            )
            .await?;
            return Ok(());
        }
        _ => {
            reply(&mut tcp, 4, unspecified).await?;
            return Ok(());
        }
    };
    udp(tcp, conn, send, recv, registration, target.port()).await
}

async fn udp(
    mut tcp: TcpStream,
    conn: Arc<UdpConnection>,
    mut send: quinn::SendStream,
    mut control: quinn::RecvStream,
    mut registration: Registration,
    port: u16,
) -> Result<()> {
    let peer = tcp.peer_addr()?;
    let socket = udp_socket(SocketAddr::new(tcp.local_addr()?.ip(), 0)).await?;
    reply(&mut tcp, 0, socket.local_addr()?).await?;
    let mut source = if port == 0 {
        None
    } else {
        Some(SocketAddr::new(peer.ip(), port))
    };
    let mut bytes = vec![0; 65_536];
    let mut closed = [0; 1];
    let mut ended = [0; 1];
    let mut reassembly = Reassembly::default();
    let mut counter = 0;
    let mut active = Instant::now();
    let mut maintenance = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = tcp.read(&mut closed) => break,
            _ = control.read(&mut ended) => break,
            _ = conn.raw.closed() => break,
            _ = maintenance.tick() => { if active.elapsed() >= UDP_IDLE { break; } }
            received = socket.recv_from(&mut bytes) => {
                let (n, from) = received?;
                if from.ip() != peer.ip() || source.is_some_and(|s| s != from) || n < 4 || bytes[..3] != [0,0,0] { continue; }
                if packet(&bytes[3..n]).await.is_err() { continue; }
                source = Some(from);
                let packet_id = counter; counter += 1;
                if send_packet(&conn.raw, send.id().index(), packet_id, &bytes[3..n]).await.is_err() {
                    if conn.raw.close_reason().is_some() { break; }
                    continue;
                }
                active = Instant::now();
            }
            frame = registration.recv.recv() => {
                let Some(frame) = frame else { break; };
                let Some(packet) = reassembly.receive(frame, Instant::now()) else { continue; };
                if let Some(source) = source {
                    if packet.len() + 3 > MAX_UDP { continue; }
                    let mut out = Vec::with_capacity(packet.len() + 3); out.extend([0,0,0]); out.extend(packet);
                    socket.send_to(&out, source).await?; active = Instant::now();
                }
            }
        }
    }
    send.finish()?;
    Ok(())
}
