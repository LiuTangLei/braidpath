//! Standard local proxy entrances and addressed-stream destinations.
//!
//! One client port accepts SOCKS5 (RFC 1928, no authentication, CONNECT) and
//! HTTP CONNECT. An addressed stream begins with a destination header in the
//! client's bytes and a one-byte status in the server's bytes, both inside the
//! reliable stream, so no new frame type or session round trip is needed. The
//! server resolves names itself and refuses non-public addresses by default.
use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    time::timeout,
};

/// Status byte values, shared with SOCKS5 reply codes.
pub(super) const OK: u8 = 0;
pub(super) const GENERAL_FAILURE: u8 = 1;
pub(super) const NOT_ALLOWED: u8 = 2;
pub(super) const NETWORK_UNREACHABLE: u8 = 3;
pub(super) const HOST_UNREACHABLE: u8 = 4;
pub(super) const REFUSED: u8 = 5;
const COMMAND_UNSUPPORTED: u8 = 7;
const ADDRESS_UNSUPPORTED: u8 = 8;

const IPV4: u8 = 1;
const DOMAIN: u8 = 3;
const IPV6: u8 = 4;
pub(super) const MAX_HEADER: usize = 1 + 1 + 255 + 2;
const MAX_HTTP_HEAD: usize = 8 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Server policy for client-named destinations.
#[derive(Clone, Copy, Debug)]
pub struct Access {
    /// Permit loopback, private, link-local and shared ranges.
    pub allow_private: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Destination {
    Ip(SocketAddr),
    Domain(String, u16),
}
impl Destination {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_HEADER);
        let port = match self {
            Destination::Ip(SocketAddr::V4(a)) => {
                out.push(IPV4);
                out.extend(a.ip().octets());
                a.port()
            }
            Destination::Ip(SocketAddr::V6(a)) => {
                out.push(IPV6);
                out.extend(a.ip().octets());
                a.port()
            }
            Destination::Domain(host, port) => {
                out.extend([DOMAIN, host.len() as u8]);
                out.extend(host.as_bytes());
                *port
            }
        };
        out.extend(port.to_be_bytes());
        out
    }
    /// `Ok(None)` asks for more bytes; `Err` is a malformed header.
    pub(super) fn decode(b: &[u8]) -> Result<Option<(Self, usize)>, ()> {
        let Some(&kind) = b.first() else {
            return Ok(None);
        };
        let (address, len) = match kind {
            IPV4 => (1..5, 7),
            IPV6 => (1..17, 19),
            DOMAIN => {
                let Some(&n) = b.get(1) else { return Ok(None) };
                if n == 0 {
                    return Err(());
                }
                (2..2 + usize::from(n), 4 + usize::from(n))
            }
            _ => return Err(()),
        };
        if b.len() < len {
            return Ok(None);
        }
        let port = u16::from_be_bytes([b[len - 2], b[len - 1]]);
        let raw = &b[address];
        let destination = match kind {
            IPV4 => Destination::Ip(SocketAddr::new(
                Ipv4Addr::from(<[u8; 4]>::try_from(raw).expect("length")).into(),
                port,
            )),
            IPV6 => Destination::Ip(SocketAddr::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(raw).expect("length")).into(),
                port,
            )),
            _ => Destination::Domain(std::str::from_utf8(raw).map_err(|_| ())?.to_owned(), port),
        };
        Ok(Some((destination, len)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Socks,
    Http,
}

pub(super) struct Request {
    pub kind: Kind,
    pub destination: Destination,
    /// Application bytes already read past the handshake.
    pub early: Vec<u8>,
}

/// The local reply for a status reported by the server.
pub(super) fn reply(kind: Kind, status: u8) -> Vec<u8> {
    match kind {
        // BND.ADDR is not meaningful through a tunnel; report 0.0.0.0:0.
        Kind::Socks => vec![5, status, 0, IPV4, 0, 0, 0, 0, 0, 0],
        Kind::Http => {
            let line = match status {
                OK => "200 Connection established",
                NOT_ALLOWED => "403 Forbidden",
                HOST_UNREACHABLE | NETWORK_UNREACHABLE => "504 Gateway Timeout",
                _ => "502 Bad Gateway",
            };
            format!("HTTP/1.1 {line}\r\n\r\n").into_bytes()
        }
    }
}

/// Read one SOCKS5 or HTTP CONNECT request. Unsupported requests are answered
/// locally and return `None`; the caller then closes the connection.
pub(super) async fn handshake(tcp: &mut TcpStream) -> Option<Request> {
    timeout(HANDSHAKE_TIMEOUT, async {
        let first = tcp.read_u8().await.ok()?;
        if first == 5 {
            socks(tcp).await
        } else {
            http(tcp, first).await
        }
    })
    .await
    .ok()
    .flatten()
}

async fn socks(tcp: &mut TcpStream) -> Option<Request> {
    let methods = tcp.read_u8().await.ok()?;
    let mut offered = vec![0; usize::from(methods)];
    tcp.read_exact(&mut offered).await.ok()?;
    if !offered.contains(&0) {
        let _ = tcp.write_all(&[5, 0xff]).await;
        return None;
    }
    tcp.write_all(&[5, 0]).await.ok()?;
    let mut head = [0; 4];
    tcp.read_exact(&mut head).await.ok()?;
    if head[0] != 5 {
        return None;
    }
    let mut header = vec![head[3]];
    match head[3] {
        IPV4 => header.resize(7, 0),
        IPV6 => header.resize(19, 0),
        DOMAIN => {
            let n = tcp.read_u8().await.ok()?;
            header.push(n);
            header.resize(4 + usize::from(n), 0);
        }
        _ => {
            let _ = tcp
                .write_all(&reply(Kind::Socks, ADDRESS_UNSUPPORTED))
                .await;
            return None;
        }
    }
    let start = if head[3] == DOMAIN { 2 } else { 1 };
    tcp.read_exact(&mut header[start..]).await.ok()?;
    if head[1] != 1 {
        // BIND and UDP ASSOCIATE are not carried.
        let _ = tcp
            .write_all(&reply(Kind::Socks, COMMAND_UNSUPPORTED))
            .await;
        return None;
    }
    let Ok(Some((destination, _))) = Destination::decode(&header) else {
        let _ = tcp
            .write_all(&reply(Kind::Socks, ADDRESS_UNSUPPORTED))
            .await;
        return None;
    };
    Some(Request {
        kind: Kind::Socks,
        destination,
        early: Vec::new(),
    })
}

async fn http(tcp: &mut TcpStream, first: u8) -> Option<Request> {
    let mut head = vec![first];
    let mut buffer = [0; 2048];
    let end = loop {
        if let Some(at) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if head.len() > MAX_HTTP_HEAD {
            let _ = tcp
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                .await;
            return None;
        }
        let n = tcp.read(&mut buffer).await.ok()?;
        if n == 0 {
            return None;
        }
        head.extend(&buffer[..n]);
    };
    let early = head.split_off(end);
    let text = std::str::from_utf8(&head).ok()?;
    let mut words = text.lines().next()?.split_whitespace();
    let (method, authority) = (words.next()?, words.next()?);
    if method != "CONNECT" {
        let _ = tcp
            .write_all(
                b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\n\r\n",
            )
            .await;
        return None;
    }
    let Some(destination) = parse_authority(authority) else {
        let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return None;
    };
    Some(Request {
        kind: Kind::Http,
        destination,
        early,
    })
}

fn parse_authority(authority: &str) -> Option<Destination> {
    if let Ok(address) = authority.parse::<SocketAddr>() {
        return Some(Destination::Ip(address));
    }
    let (host, port) = authority.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(Destination::Ip(SocketAddr::new(ip, port)));
    }
    (!host.is_empty() && host.len() <= 255).then(|| Destination::Domain(host.to_owned(), port))
}

/// Whether the server may connect to `ip`. Without `allow_private`, only
/// globally routable unicast addresses are permitted.
pub(super) fn permitted(ip: IpAddr, allow_private: bool) -> bool {
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    if allow_private {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => public_v4(v4),
            None => !(v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()),
        },
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        || (a == 198 && (18..20).contains(&b))
        || a >= 240)
}

/// Resolve and connect from the server, returning a status byte on failure.
pub(super) async fn connect(
    destination: Destination,
    allow_private: bool,
) -> Result<TcpStream, u8> {
    timeout(CONNECT_TIMEOUT, async {
        let candidates: Vec<SocketAddr> = match destination {
            Destination::Ip(address) => vec![address],
            Destination::Domain(host, port) => lookup_host((host.as_str(), port))
                .await
                .map_err(|_| HOST_UNREACHABLE)?
                .collect(),
        };
        let mut status = if candidates.is_empty() {
            HOST_UNREACHABLE
        } else {
            NOT_ALLOWED
        };
        for address in candidates {
            if !permitted(address.ip(), allow_private) {
                continue;
            }
            match TcpStream::connect(address).await {
                Ok(tcp) => return Ok(tcp),
                Err(error) => {
                    status = match error.kind() {
                        ErrorKind::ConnectionRefused => REFUSED,
                        ErrorKind::NetworkUnreachable => NETWORK_UNREACHABLE,
                        ErrorKind::HostUnreachable => HOST_UNREACHABLE,
                        _ => GENERAL_FAILURE,
                    }
                }
            }
        }
        Err(status)
    })
    .await
    .unwrap_or(Err(HOST_UNREACHABLE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destinations_round_trip_and_partial_headers_wait() {
        for destination in [
            Destination::Ip("1.2.3.4:443".parse().unwrap()),
            Destination::Ip("[2001:db8::1]:80".parse().unwrap()),
            Destination::Domain("example.com".into(), 8443),
        ] {
            let mut bytes = destination.encode();
            bytes.extend(b"payload");
            let (decoded, used) = Destination::decode(&bytes).unwrap().unwrap();
            assert_eq!(decoded, destination);
            assert_eq!(&bytes[used..], b"payload");
            for cut in 0..used {
                assert_eq!(Destination::decode(&bytes[..cut]), Ok(None), "{cut}");
            }
        }
        assert_eq!(Destination::decode(&[9, 0, 0]), Err(()));
        assert_eq!(Destination::decode(&[DOMAIN, 0, 0, 1]), Err(()));
        assert_eq!(Destination::decode(&[DOMAIN, 1, 0xff, 0, 1]), Err(()));
    }

    #[test]
    fn authorities_cover_names_and_literal_addresses() {
        assert_eq!(
            parse_authority("example.com:443"),
            Some(Destination::Domain("example.com".into(), 443))
        );
        assert_eq!(
            parse_authority("1.2.3.4:80"),
            Some(Destination::Ip("1.2.3.4:80".parse().unwrap()))
        );
        assert_eq!(
            parse_authority("[2001:db8::2]:443"),
            Some(Destination::Ip("[2001:db8::2]:443".parse().unwrap()))
        );
        assert_eq!(parse_authority("example.com"), None);
        assert_eq!(parse_authority(":443"), None);
        assert_eq!(parse_authority("host:99999"), None);
    }

    #[test]
    fn only_public_unicast_is_permitted_by_default() {
        for denied in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.1.2.3",
            "255.255.255.255",
            "224.0.0.1",
            "198.18.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::",
            "ff02::1",
        ] {
            assert!(!permitted(denied.parse().unwrap(), false), "{denied}");
        }
        for allowed in ["1.1.1.1", "8.8.8.8", "2606:4700::1111", "::ffff:1.1.1.1"] {
            assert!(permitted(allowed.parse().unwrap(), false), "{allowed}");
        }
        assert!(permitted("127.0.0.1".parse().unwrap(), true));
        assert!(!permitted("0.0.0.0".parse().unwrap(), true));
        assert!(!permitted("224.0.0.1".parse().unwrap(), true));
    }

    #[test]
    fn replies_map_status_to_each_protocol() {
        assert_eq!(
            reply(Kind::Socks, REFUSED),
            vec![5, 5, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        assert!(reply(Kind::Http, OK).starts_with(b"HTTP/1.1 200 "));
        assert!(reply(Kind::Http, NOT_ALLOWED).starts_with(b"HTTP/1.1 403 "));
        assert!(reply(Kind::Http, REFUSED).starts_with(b"HTTP/1.1 502 "));
    }

    #[tokio::test]
    async fn local_handshakes_parse_socks_and_http_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut socks = TcpStream::connect(address).await.unwrap();
            socks.write_all(&[5, 2, 2, 0]).await.unwrap();
            let mut choice = [0; 2];
            socks.read_exact(&mut choice).await.unwrap();
            assert_eq!(choice, [5, 0]);
            socks
                .write_all(&[5, 1, 0, DOMAIN, 3, b'a', b'.', b'b', 0, 80])
                .await
                .unwrap();
            let mut http = TcpStream::connect(address).await.unwrap();
            http.write_all(b"CONNECT [::1]:22 HTTP/1.1\r\nHost: x\r\n\r\nearly")
                .await
                .unwrap();
            let mut get = TcpStream::connect(address).await.unwrap();
            get.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            let mut response = Vec::new();
            get.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 405 "));
            (socks, http)
        });
        let (mut a, _) = listener.accept().await.unwrap();
        let socks = handshake(&mut a).await.unwrap();
        assert_eq!(
            (socks.kind, socks.destination),
            (Kind::Socks, Destination::Domain("a.b".into(), 80))
        );
        let (mut b, _) = listener.accept().await.unwrap();
        let http = handshake(&mut b).await.unwrap();
        assert_eq!(
            http.destination,
            Destination::Ip("[::1]:22".parse().unwrap())
        );
        assert_eq!(http.early, b"early");
        let (mut c, _) = listener.accept().await.unwrap();
        assert!(handshake(&mut c).await.is_none());
        drop(c);
        client.await.unwrap();
    }
}
