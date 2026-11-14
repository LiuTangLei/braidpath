//! Exercise the native Quinn adapter across the quinn-udp API boundary.
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, udp};
use std::{
    future::poll_fn,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    sync::{Arc, Mutex},
    time::Duration,
};

fn socket(ip: IpAddr) -> Arc<dyn AsyncUdpSocket> {
    let socket = UdpSocket::bind((ip, 0)).unwrap();
    socket.set_nonblocking(true).unwrap();
    TokioRuntime.wrap_udp_socket(socket).unwrap()
}

async fn send(socket: &Arc<dyn AsyncUdpSocket>, transmit: &udp::Transmit<'_>) {
    let mut poller = socket.clone().create_io_poller();
    loop {
        match socket.try_send(transmit) {
            Ok(()) => return,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                poll_fn(|cx| poller.as_mut().poll_writable(cx))
                    .await
                    .unwrap();
            }
            Err(e) => panic!("native UDP send: {e}"),
        }
    }
}

async fn receive(socket: &dyn AsyncUdpSocket, count: usize) -> Vec<Vec<u8>> {
    let mut slots = vec![vec![0u8; 8192]; udp::BATCH_SIZE];
    let mut meta = vec![udp::RecvMeta::default(); udp::BATCH_SIZE];
    let mut received = Vec::new();
    while received.len() < count {
        let mut bufs: Vec<_> = slots.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        let n = poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();
        for (slot, info) in slots.iter().zip(&meta).take(n) {
            assert!(info.len > 0 && info.stride > 0);
            assert_eq!(info.dst_ip, Some(socket.local_addr().unwrap().ip()));
            received.extend(slot[..info.len].chunks(info.stride).map(<[u8]>::to_vec));
        }
    }
    received
}

async fn boundaries(ip: IpAddr) {
    let sender = socket(ip);
    let receiver = socket(ip);
    let destination = receiver.local_addr().unwrap();
    let mut expected = vec![vec![1; 1], vec![2; 17], vec![3; 511], vec![4; 2049]];
    for contents in &expected {
        send(
            &sender,
            &udp::Transmit {
                destination,
                ecn: None,
                contents,
                segment_size: None,
                src_ip: None,
            },
        )
        .await;
    }
    if sender.max_transmit_segments() >= 4 {
        let segments = [vec![5; 512], vec![6; 512], vec![7; 512], vec![8; 17]];
        send(
            &sender,
            &udp::Transmit {
                destination,
                ecn: None,
                contents: &segments.concat(),
                segment_size: Some(512),
                src_ip: None,
            },
        )
        .await;
        expected.extend(segments);
    }
    let mut actual = receive(receiver.as_ref(), expected.len()).await;
    expected.sort();
    actual.sort();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn native_udp_ipv4_preserves_packet_and_gso_boundaries() {
    tokio::time::timeout(
        Duration::from_secs(5),
        boundaries(Ipv4Addr::LOCALHOST.into()),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn native_udp_ipv6_preserves_packet_and_gso_boundaries() {
    tokio::time::timeout(
        Duration::from_secs(5),
        boundaries(Ipv6Addr::LOCALHOST.into()),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn oversized_probe_keeps_the_native_socket_usable() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let sender = socket(Ipv4Addr::LOCALHOST.into());
        let receiver = socket(Ipv4Addr::LOCALHOST.into());
        let destination = receiver.local_addr().unwrap();
        for contents in [vec![0; 65536], b"after oversized probe".to_vec()] {
            send(
                &sender,
                &udp::Transmit {
                    destination,
                    ecn: None,
                    contents: &contents,
                    segment_size: None,
                    src_ip: None,
                },
            )
            .await;
        }
        assert_eq!(
            receive(receiver.as_ref(), 1).await,
            [b"after oversized probe".to_vec()]
        );
    })
    .await
    .unwrap();
}

#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn refused_udp_send_remains_visible_to_tracing() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let captured = CapturedLog::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let io = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        // SO_BROADCAST is disabled: the kernel refuses this before transmission.
        assert!(!io.broadcast().unwrap());
        io.set_nonblocking(true).unwrap();
        let socket = TokioRuntime.wrap_udp_socket(io).unwrap();
        send(
            &socket,
            &udp::Transmit {
                destination: (Ipv4Addr::BROADCAST, 9).into(),
                ecn: None,
                contents: b"refused UDP probe",
                segment_size: None,
                src_ip: None,
            },
        )
        .await;
        let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains("sendmsg error"),
            "missing UDP diagnostic: {log}"
        );
    })
    .await
    .unwrap();
}
