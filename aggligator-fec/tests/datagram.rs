#![cfg(feature = "runtime")]
use aggligator_fec::{
    Frame,
    datagram::{Datagram, send_batch},
};
use tokio::{
    net::UdpSocket,
    time::{Duration, timeout},
};

#[tokio::test]
async fn batches_keep_datagram_boundaries_and_destination_order() {
    let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addresses = [a.local_addr().unwrap(), b.local_addr().unwrap()];
    let packets: Vec<_> = (0..71u8)
        .map(|i| Datagram { destination: addresses[i as usize % 2], payload: vec![i; 30 + i as usize] })
        .collect();
    let result = send_batch(&tx, &packets).await.unwrap();
    assert_eq!(result.sent, 71);
    assert!(result.calls >= 3);
    for (path, rx) in [a, b].iter().enumerate() {
        for i in (path..71).step_by(2) {
            let mut bytes = [0; 1500];
            let n = timeout(Duration::from_secs(1), rx.recv(&mut bytes)).await.unwrap().unwrap();
            assert_eq!(&bytes[..n], &vec![i as u8; 30 + i]);
        }
    }
    assert_eq!(send_batch(&tx, &[]).await.unwrap().sent, 0);
}
#[tokio::test]
async fn partial_failure_reports_only_the_submitted_prefix() {
    let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = rx.local_addr().unwrap();
    let error = send_batch(
        &tx,
        &[
            Datagram { destination, payload: vec![1; 20] },
            Datagram { destination, payload: vec![2; 70000] },
            Datagram { destination, payload: vec![3; 20] },
        ],
    )
    .await
    .unwrap_err();
    assert_eq!(error.completed.sent, 1);
    let mut buf = [0; 100];
    assert_eq!(rx.recv(&mut buf).await.unwrap(), 20);
    assert_eq!(buf[0], 1);
    assert!(timeout(Duration::from_millis(20), rx.recv(&mut buf)).await.is_err());
}
#[test]
fn prefixed_serialization_is_identical_and_validation_is_atomic() {
    let frame = Frame::Source { block: 2, base: 16, index: 3, payload: vec![44; 1100] };
    let mut bytes = vec![1, 2, 3];
    frame.encode_into(&mut bytes).unwrap();
    assert_eq!(&bytes[3..], frame.encode().unwrap());
    let old = bytes.clone();
    let invalid = Frame::Source { block: 2, base: 16, index: 3, payload: vec![44; 1500] };
    assert!(invalid.encode_into(&mut bytes).is_err());
    assert_eq!(bytes, old);
}
