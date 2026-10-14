//! Bounded UDP batching, with a portable fallback. No global socket/sysctl changes.
//!
//! Linux sends up to 32 independent UDP datagrams per syscall. The MTU and each
//! datagram's boundaries remain unchanged. Partial completion is tracked so that
//! retrying a batch never resends its successfully submitted prefix.
use std::{fmt, io, net::SocketAddr};
use tokio::net::UdpSocket;

pub const MAX_BATCH: usize = 32;
#[derive(Clone, Debug)]
pub struct Datagram {
    pub destination: SocketAddr,
    pub payload: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct BatchStats {
    pub sent: usize,
    pub calls: usize,
}
#[derive(Debug)]
pub struct BatchError {
    pub completed: BatchStats,
    pub source: io::Error,
}
impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UDP batch failed after {} datagrams: {}", self.completed.sent, self.source)
    }
}
impl std::error::Error for BatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Submit a batch; this does NOT imply network delivery. No accumulation delay.
/// On error, only the suffix at `error.completed.sent` remains unsubmitted.
/// Like write_all, cancellation may have already submitted a prefix. Do not
/// cancel and restart this function blindly; use a bounded owner task to drain.
pub async fn send_batch(socket: &UdpSocket, packets: &[Datagram]) -> Result<BatchStats, BatchError> {
    let mut completed = BatchStats::default();
    while completed.sent < packets.len() {
        if let Err(source) = socket.writable().await {
            return Err(BatchError { completed, source });
        }
        let end = (completed.sent + MAX_BATCH).min(packets.len());
        let batch = &packets[completed.sent..end];
        completed.calls += 1;
        match try_batch(socket, batch) {
            Ok(0) => {
                return Err(BatchError {
                    completed,
                    source: io::Error::new(io::ErrorKind::WriteZero, "zero UDP batch progress"),
                });
            }
            Ok(n) => completed.sent += n,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => continue,
            Err(source) => return Err(BatchError { completed, source }),
        }
    }
    Ok(completed)
}

#[cfg(target_os = "linux")]
fn try_batch(socket: &UdpSocket, packets: &[Datagram]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;
    socket.try_io(Interest::WRITABLE, || sendmmsg_fd(socket.as_raw_fd(), packets))
}

/// Submit at most MAX_BATCH datagrams without waiting. The socket must be
/// nonblocking. This primitive also supports dedicated paced sender threads.
pub fn try_send_batch(socket: &std::net::UdpSocket, packets: &[Datagram]) -> io::Result<usize> {
    let packets = &packets[..packets.len().min(MAX_BATCH)];
    if packets.is_empty() {
        return Ok(0);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        sendmmsg_fd(socket.as_raw_fd(), packets)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut sent = 0;
        for packet in packets {
            match socket.send_to(&packet.payload, packet.destination) {
                Ok(n) if n == packet.payload.len() => sent += 1,
                Ok(_) => break,
                Err(_) if sent > 0 => break,
                Err(e) => return Err(e),
            }
        }
        Ok(sent)
    }
}

#[cfg(target_os = "linux")]
fn sendmmsg_fd(fd: std::os::fd::RawFd, packets: &[Datagram]) -> io::Result<usize> {
    let addresses: Vec<socket2::SockAddr> = packets.iter().map(|p| p.destination.into()).collect();
    let mut vectors: Vec<libc::iovec> = packets
        .iter()
        .map(|p| libc::iovec { iov_base: p.payload.as_ptr().cast_mut().cast(), iov_len: p.payload.len() })
        .collect();
    let mut messages: Vec<libc::mmsghdr> = addresses
        .iter()
        .enumerate()
        .map(|(i, address)| {
            // SAFETY: zero is a valid empty msghdr/mmsghdr; all nonempty pointers
            // below refer to stable buffers retained through the syscall.
            let mut message: libc::mmsghdr = unsafe { std::mem::zeroed() };
            message.msg_hdr.msg_name = address.as_ptr().cast_mut().cast();
            message.msg_hdr.msg_namelen = address.len();
            message.msg_hdr.msg_iov = &mut vectors[i];
            message.msg_hdr.msg_iovlen = 1;
            message
        })
        .collect();
    // SAFETY: fd is borrowed from a live UDP socket. `messages`, `vectors`,
    // addresses and payload buffers are live and not resized until return.
    // The kernel reads payloads and writes only headers' msg_len fields.
    // MSG_DONTWAIT preserves the Tokio readiness contract.
    let n = unsafe {
        libc::sendmmsg(
            fd,
            messages.as_mut_ptr(),
            messages.len() as u32,
            (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as _,
        )
    };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}
#[cfg(not(target_os = "linux"))]
fn try_batch(socket: &UdpSocket, packets: &[Datagram]) -> io::Result<usize> {
    let mut sent = 0;
    for packet in packets {
        match socket.try_send_to(&packet.payload, packet.destination) {
            Ok(n) if n == packet.payload.len() => sent += 1,
            Ok(_) => break,
            Err(_) if sent > 0 => break, // Preserve the successful prefix; retry suffix next.
            Err(e) => return Err(e),
        }
    }
    Ok(sent)
}
