//! SOCKS5 UDP ASSOCIATE over the session's datagram service.
//!
//! Each association is one flow of unreliable records, `FLAG | n`, carried with
//! the same scheduling and FEC as fixed UDP forwarding. A client record is a
//! SOCKS5 UDP request without its reserved and fragment fields,
//! `[ATYP][address][port][data]`; a server record names the reply's source in
//! the same form. An empty client record ends the association. The server also
//! retires an idle one and recreates it if the client sends again, so no
//! server-to-client close exists.
//!
//! The server resolves names itself (IPv4 first: a datagram has no failed
//! connection to fall back from), applies the same destination rule as
//! CONNECT, and accepts replies only from addresses this association sent to.
//! Fragmented and oversized datagrams are dropped, not reassembled.
use super::{
    proxy::{self, Destination},
    tcp::Io,
};
use crate::runtime::MAX_PAYLOAD;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket, lookup_host},
    sync::mpsc,
    time::timeout,
};

// Bits 31/30/29/28 identify messages, TCP data/ACKs and addressed TCP streams.
pub(super) const FLAG: u32 = 1 << 27;
pub(super) const MAX_ASSOCIATIONS: usize = 64;
/// A server association without traffic in either direction is retired.
pub(super) const IDLE: Duration = Duration::from_secs(120);
/// Datagrams queued toward one server association's socket.
pub(super) const CHANNEL: usize = 256;
/// Distinct addresses one server association may hear replies from.
const MAX_PEERS: usize = 256;
const MAX_NAMES: usize = 64;
const NAME_TTL: Duration = Duration::from_secs(60);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const DATAGRAM: usize = 64 * 1024;

pub(super) fn is_flow(flow: u32) -> bool {
    flow & !(FLAG - 1) == FLAG
}

/// The SOCKS client's latest UDP source, where replies go.
pub(super) type Peer = Arc<Mutex<Option<SocketAddr>>>;

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// A client datagram's tunnel payload: no fragments, a valid address, and
/// within the record limit.
pub(super) fn client_payload(datagram: &[u8]) -> Option<&[u8]> {
    let payload = datagram.strip_prefix(&[0, 0, 0])?;
    let (_, used) = Destination::decode(payload).ok()??;
    (used < payload.len() && payload.len() <= MAX_PAYLOAD).then_some(payload)
}

/// The datagram for the SOCKS client: reserved and fragment fields, then the
/// server's `[ATYP][address][port][data]`.
pub(super) fn to_client(payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(3 + payload.len());
    datagram.extend([0, 0, 0]);
    datagram.extend(payload);
    datagram
}

/// Client: bind the relay beside the address the SOCKS client reached, answer
/// the request with it, then relay until the control connection closes.
pub(super) async fn client(flow: u32, mut tcp: TcpStream, events: mpsc::UnboundedSender<Io>) {
    let (Ok(local), Ok(owner)) = (tcp.local_addr(), tcp.peer_addr()) else {
        return;
    };
    let socket = match UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await {
        Ok(socket) => socket,
        Err(_) => {
            let _ = tcp
                .write_all(&proxy::reply(proxy::Kind::Socks, proxy::GENERAL_FAILURE))
                .await;
            return;
        }
    };
    let Ok(relay) = socket.local_addr() else {
        return;
    };
    if tcp.write_all(&proxy::bound_reply(relay)).await.is_err() {
        return;
    }
    let socket = Arc::new(socket);
    let peer = Peer::default();
    if events
        .send(Io::Associated(flow, socket.clone(), peer.clone()))
        .is_err()
    {
        return;
    }
    let owner = owner.ip().to_canonical();
    let mut buffer = vec![0; DATAGRAM];
    let mut control = [0; 512];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let Ok((n, from)) = received else { break };
                let from = canonical(from);
                // Only the host that opened the association may use it.
                if from.ip() != owner {
                    continue;
                }
                *peer.lock().expect("association peer") = Some(from);
                let datagram = match client_payload(&buffer[..n]) {
                    Some(payload) => Io::Datagram(flow, payload.to_vec()),
                    None => Io::DatagramDropped,
                };
                if events.send(datagram).is_err() {
                    return;
                }
            }
            read = tcp.read(&mut control) => {
                if !matches!(read, Ok(n) if n > 0) {
                    break;
                }
            }
        }
    }
    let _ = events.send(Io::Unassociated(flow));
}

/// Server: one socket per association, reached from both address families
/// where the host allows it.
fn bind_any() -> std::io::Result<UdpSocket> {
    let dual = || -> std::io::Result<std::net::UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_only_v6(false)?;
        socket.bind(&SocketAddr::from(([0u16; 8], 0)).into())?;
        Ok(socket.into())
    };
    let socket = dual().or_else(|_| std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)))?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// The socket address to send to: IPv4 destinations are mapped on a
/// dual-stack socket.
fn outbound(socket: &UdpSocket, target: SocketAddr) -> SocketAddr {
    match (socket.local_addr().map(|a| a.is_ipv6()), target.ip()) {
        (Ok(true), IpAddr::V4(v4)) => SocketAddr::new(v4.to_ipv6_mapped().into(), target.port()),
        _ => target,
    }
}

struct Names(HashMap<String, (Vec<IpAddr>, Instant)>);
impl Names {
    async fn resolve(&mut self, host: &str, port: u16) -> Vec<IpAddr> {
        let now = Instant::now();
        if let Some((addresses, at)) = self.0.get(host)
            && now.saturating_duration_since(*at) < NAME_TTL
        {
            return addresses.clone();
        }
        let addresses: Vec<IpAddr> = timeout(RESOLVE_TIMEOUT, lookup_host((host, port)))
            .await
            .ok()
            .and_then(Result::ok)
            .map(|found| found.map(|a| a.ip().to_canonical()).collect())
            .unwrap_or_default();
        // A datagram has no connection attempt to fall back from; IPv4 is
        // the more widely reachable family, so it goes first.
        let mut addresses = addresses;
        addresses.sort_by_key(|ip| ip.is_ipv6());
        if self.0.len() >= MAX_NAMES {
            self.0
                .retain(|_, (_, at)| now.saturating_duration_since(*at) < NAME_TTL);
        }
        if self.0.len() < MAX_NAMES {
            self.0.insert(host.to_owned(), (addresses.clone(), now));
        }
        addresses
    }
}

/// Server: relay one association's datagrams until its channel closes.
pub(super) async fn server(
    flow: u32,
    allow_private: bool,
    mut datagrams: mpsc::Receiver<Vec<u8>>,
    events: mpsc::UnboundedSender<Io>,
) {
    let Ok(socket) = bind_any() else {
        let _ = events.send(Io::Unassociated(flow));
        return;
    };
    let mut names = Names(HashMap::new());
    let mut sent_to: HashSet<IpAddr> = HashSet::new();
    let mut buffer = vec![0; DATAGRAM];
    loop {
        tokio::select! {
            datagram = datagrams.recv() => {
                let Some(datagram) = datagram else { return };
                let Ok(Some((destination, used))) = Destination::decode(&datagram) else {
                    let _ = events.send(Io::DatagramDropped);
                    continue;
                };
                let target = match destination {
                    Destination::Ip(address) => Some(canonical(address)),
                    Destination::Domain(host, port) => names
                        .resolve(&host, port)
                        .await
                        .into_iter()
                        .find(|ip| proxy::permitted(*ip, allow_private))
                        .map(|ip| SocketAddr::new(ip, port)),
                };
                let Some(target) = target.filter(|t| proxy::permitted(t.ip(), allow_private)) else {
                    let _ = events.send(Io::DatagramDropped);
                    continue;
                };
                if sent_to.len() < MAX_PEERS {
                    sent_to.insert(target.ip());
                }
                if socket.send_to(&datagram[used..], outbound(&socket, target)).await.is_err() {
                    let _ = events.send(Io::DatagramDropped);
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let Ok((n, from)) = received else { continue };
                let from = canonical(from);
                if !sent_to.contains(&from.ip()) {
                    continue;
                }
                let mut payload = Destination::Ip(from).encode();
                payload.extend(&buffer[..n]);
                let reply = if payload.len() <= MAX_PAYLOAD {
                    Io::Datagram(flow, payload)
                } else {
                    Io::DatagramDropped
                };
                if events.send(reply).is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_datagrams_need_whole_unfragmented_addressed_payloads() {
        let mut datagram = vec![0, 0, 0];
        datagram.extend(Destination::Ip("1.2.3.4:53".parse().unwrap()).encode());
        datagram.extend(b"query");
        assert_eq!(client_payload(&datagram), Some(&datagram[3..]));
        let mut fragment = datagram.clone();
        fragment[2] = 1;
        assert_eq!(client_payload(&fragment), None);
        assert_eq!(client_payload(&datagram[..10]), None, "no data");
        assert_eq!(client_payload(&[0, 0, 0, 9, 1, 2]), None, "address type");
        let mut large = datagram.clone();
        large.resize(3 + MAX_PAYLOAD + 1, 0);
        assert_eq!(client_payload(&large), None);
        assert_eq!(to_client(&datagram[3..]), datagram);
        assert!(is_flow(FLAG | 7) && !is_flow(7));
    }

    #[test]
    fn mapped_addresses_compare_and_send_in_their_socket_family() {
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:53".parse().unwrap();
        assert_eq!(canonical(mapped), "192.0.2.1:53".parse().unwrap());
    }

    #[test]
    fn association_stream_and_segmented_message_ids_do_not_overlap() {
        use crate::runtime::stream;
        let serial = FLAG - 1;
        let id = stream::MAX_STREAM_ID;
        assert_eq!(id, serial | (1 << 28));
        for flow in [
            serial,
            super::super::messages::FLAG | serial,
            stream::data_flow(id),
            stream::ack_flow(id),
        ] {
            assert!(!is_flow(flow));
        }
        assert!(is_flow(FLAG | serial));
        assert_eq!(stream::stream_id(FLAG | serial), None);
        assert_eq!(stream::stream_id(super::super::messages::FLAG | id), None);
        for flow in [stream::data_flow(id), stream::ack_flow(id)] {
            assert_eq!(stream::stream_id(flow), Some(id));
        }
        let mixed = FLAG | stream::data_flow(id);
        assert!(!is_flow(mixed));
        assert_eq!(stream::stream_id(mixed), None);
    }
}
