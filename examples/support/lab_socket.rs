//! Per-socket laboratory receive headroom. No sysctl or production transport changes.
use anyhow::{Result, ensure};
use serde::Serialize;
use socket2::SockRef;
use std::net::UdpSocket;

pub const MIN_RECEIVE_BYTES: usize = 64 * 1024;
pub const MAX_RECEIVE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct SocketEvidence {
    pub role: String,
    pub address: String,
    pub requested_receive_bytes: usize,
    pub requested_send_bytes: usize,
    pub initial_receive_bytes: usize,
    pub initial_send_bytes: usize,
    pub effective_receive_bytes: usize,
    pub effective_send_bytes: usize,
    pub requested_headroom_satisfied: bool,
}

pub fn validate(bytes: usize) -> Result<()> {
    ensure!(
        bytes == 0 || (MIN_RECEIVE_BYTES..=MAX_RECEIVE_BYTES).contains(&bytes),
        "receive headroom must be zero (OS default) or 64KiB..4MiB"
    );
    Ok(())
}

pub fn bind(role: &str, bytes: usize, send_bytes: usize) -> Result<(UdpSocket, SocketEvidence)> {
    validate(bytes)?;
    validate(send_bytes)?;
    // Deliberately not configurable as a public, wildcard or non-loopback bind.
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let options = SockRef::from(&socket);
    let initial = options.recv_buffer_size()?;
    let initial_send = options.send_buffer_size()?;
    if bytes != 0 {
        options.set_recv_buffer_size(bytes)?;
    }
    if send_bytes != 0 {
        options.set_send_buffer_size(send_bytes)?;
    }
    let effective = options.recv_buffer_size()?;
    let report = SocketEvidence {
        role: role.to_owned(),
        address: socket.local_addr()?.to_string(),
        requested_receive_bytes: bytes,
        requested_send_bytes: send_bytes,
        initial_receive_bytes: initial,
        initial_send_bytes: initial_send,
        effective_receive_bytes: effective,
        effective_send_bytes: options.send_buffer_size()?,
        requested_headroom_satisfied: (bytes == 0 || effective >= bytes)
            && (send_bytes == 0 || options.send_buffer_size()? >= send_bytes),
    };
    socket.set_nonblocking(true)?;
    Ok((socket, report))
}

pub fn observe(socket: &UdpSocket, evidence: &mut SocketEvidence) -> Result<()> {
    let options = SockRef::from(socket);
    evidence.effective_receive_bytes = options.recv_buffer_size()?;
    evidence.effective_send_bytes = options.send_buffer_size()?;
    evidence.requested_headroom_satisfied = (evidence.requested_receive_bytes == 0
        || evidence.effective_receive_bytes >= evidence.requested_receive_bytes)
        && (evidence.requested_send_bytes == 0
            || evidence.effective_send_bytes >= evidence.requested_send_bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn headroom_is_bounded_and_loopback_only() {
        for size in [1, MIN_RECEIVE_BYTES - 1, MAX_RECEIVE_BYTES + 1, usize::MAX] {
            assert!(validate(size).is_err());
        }
        let (socket, evidence) = bind("fixture", 0, 0).unwrap();
        assert!(socket.local_addr().unwrap().ip().is_loopback());
        assert_eq!(
            evidence.initial_receive_bytes,
            evidence.effective_receive_bytes
        );
        assert!(evidence.effective_send_bytes > 0);
    }

    #[test]
    fn registered_headroom_survives_a_bounded_sixty_four_packet_burst() {
        let (receiver, evidence) = bind("burst-receiver", 256 * 1024, 0).unwrap();
        assert!(evidence.requested_headroom_satisfied, "{evidence:?}");
        receiver.set_nonblocking(false).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();
        for id in 0..64u8 {
            assert_eq!(sender.send(&[id; 1200]).unwrap(), 1200);
        }
        let mut seen = [false; 64];
        let mut payload = [0; 1500];
        for _ in 0..64 {
            let n = receiver.recv(&mut payload).unwrap();
            assert_eq!(n, 1200);
            let id = usize::from(payload[0]);
            assert!(id < 64 && !seen[id]);
            assert!(payload[..n].iter().all(|b| usize::from(*b) == id));
            seen[id] = true;
        }
        assert!(seen.into_iter().all(|v| v));
    }
}
