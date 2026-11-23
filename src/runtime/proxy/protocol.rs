use super::*;
use anyhow::{Context, bail};
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::LazyLock,
};

pub(super) const TCP: u8 = 1;
pub(super) const UDP: u8 = 3;
pub(super) const MAX_UDP: usize = 65_507;
static DNS_WORKERS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(32)));

#[derive(Debug)]
pub(crate) struct ReplyError(pub(crate) u8);
impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "proxy request rejected (SOCKS reply {})", self.0)
    }
}
impl std::error::Error for ReplyError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum Address {
    Ip(SocketAddr),
    Domain(String, u16),
}
impl From<Address> for crate::runtime::tunnel::StreamTarget {
    fn from(address: Address) -> Self {
        match address {
            Address::Ip(address) => Self::Ip(address),
            Address::Domain(host, port) => Self::Domain(host, port),
        }
    }
}

impl Address {
    pub(super) async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self> {
        let host = match r.read_u8().await? {
            1 => {
                let mut b = [0; 4];
                r.read_exact(&mut b).await?;
                IpAddr::from(b)
            }
            4 => {
                let mut b = [0; 16];
                r.read_exact(&mut b).await?;
                IpAddr::from(b)
            }
            3 => {
                let len = r.read_u8().await? as usize;
                ensure!(len != 0, "empty domain");
                let mut b = vec![0; len];
                r.read_exact(&mut b).await?;
                let name = String::from_utf8(b)?;
                ensure!(
                    name.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_'),
                    "invalid domain"
                );
                return Ok(Self::Domain(name, r.read_u16().await?));
            }
            _ => bail!("unsupported address type"),
        };
        Ok(Self::Ip(SocketAddr::new(host, r.read_u16().await?)))
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        let port = match self {
            Self::Ip(a) => {
                match a.ip() {
                    IpAddr::V4(ip) => {
                        out.push(1);
                        out.extend(ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        out.push(4);
                        out.extend(ip.octets());
                    }
                }
                a.port()
            }
            Self::Domain(name, port) => {
                out.extend([3, name.len() as u8]);
                out.extend(name.as_bytes());
                *port
            }
        };
        out.extend(port.to_be_bytes());
    }
    pub(super) fn port(&self) -> u16 {
        match self {
            Self::Ip(a) => a.port(),
            Self::Domain(_, p) => *p,
        }
    }
    pub(super) async fn resolve(&self, allow_private: bool) -> Result<Vec<SocketAddr>> {
        ensure!(self.port() != 0, "zero destination port");
        let addresses: Vec<_> = match self {
            Self::Ip(a) => vec![*a],
            Self::Domain(name, port) => {
                let permit = DNS_WORKERS
                    .clone()
                    .try_acquire_owned()
                    .context("proxy DNS resolver busy")?;
                let name = name.clone();
                let port = *port;
                // OS resolution can outlive an async timeout. Its permit travels
                // with the blocking worker so cancellation cannot queue unlimited lookups.
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    (name.as_str(), port)
                        .to_socket_addrs()
                        .map(|addresses| addresses.take(16).collect::<Vec<_>>())
                })
                .await??
            }
        };
        ensure!(!addresses.is_empty(), "destination has no addresses");
        // Check the resolved addresses once; connect the checked IP, never resolve twice.
        if !addresses.iter().all(|a| permitted(a.ip(), allow_private)) {
            return Err(ReplyError(2).into());
        }
        Ok(addresses)
    }
}
pub(crate) fn permitted(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return permitted(v4.into(), allow_private);
            }
            !ip.is_unspecified()
                && !ip.is_multicast()
                && (allow_private
                    || (!ip.is_loopback()
                        && !ip.is_unique_local()
                        && !ip.is_unicast_link_local()
                        && (ip.segments()[0] & 0xe000) == 0x2000))
        }
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && (allow_private
                    || !(ip.is_private()
                        || ip.is_loopback()
                        || ip.is_link_local()
                        || a == 0
                        || a >= 224
                        || (a == 100 && (64..128).contains(&b))
                        || (a == 198 && (18..20).contains(&b))))
        }
    }
}

pub(super) async fn packet(data: &[u8]) -> Result<(Address, &[u8])> {
    let mut body = data;
    let address = Address::read(&mut body).await?;
    ensure!(body.len() <= MAX_UDP, "UDP payload too large");
    Ok((address, body))
}
