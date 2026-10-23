use super::*;

/// Inclusive UDP range; allocation scans at most 1,024 sockets off the data path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayPorts {
    first: u16,
    last: u16,
}
impl std::str::FromStr for RelayPorts {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let (first, last) = value.split_once('-').unwrap_or((value, value));
        let first: u16 = first.parse().context("invalid relay port")?;
        let last: u16 = last.parse().context("invalid relay port")?;
        ensure!(
            first != 0 && last >= first && u32::from(last) - u32::from(first) < 1024,
            "relay ports must be PORT or FIRST-LAST, containing 1..1024 nonzero ports"
        );
        Ok(Self { first, last })
    }
}
impl RelayPorts {
    pub(super) fn bind(self, ip: IpAddr) -> Result<std::net::UdpSocket> {
        let count = u32::from(self.last) - u32::from(self.first) + 1;
        let start = rand::random_range(0..count);
        for offset in 0..count {
            let port = u32::from(self.first) + (start + offset) % count;
            match std::net::UdpSocket::bind(SocketAddr::new(ip, port as u16)) {
                Ok(socket) => return Ok(socket),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(error) => return Err(error).context("bind configured relay port"),
            }
        }
        bail!("configured relay ports are all in use")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn port_ranges_are_bounded_and_never_fall_back_outside_the_range() {
        for invalid in ["0", "0-10", "10-9", "1-1025", "65536", "10-20-30", ""] {
            assert!(invalid.parse::<RelayPorts>().is_err(), "accepted {invalid}");
        }
        assert!("1-1024".parse::<RelayPorts>().is_ok());
        assert!("65535".parse::<RelayPorts>().is_ok());
        let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = occupied.local_addr().unwrap();
        let ports: RelayPorts = address.port().to_string().parse().unwrap();
        assert!(ports.bind(address.ip()).is_err());
        drop(occupied);
        let allocated = ports.bind(address.ip()).unwrap();
        assert_eq!(allocated.local_addr().unwrap(), address);
    }
}
