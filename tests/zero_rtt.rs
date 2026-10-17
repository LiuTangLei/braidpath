//! QUIC 0-RTT resumption and replay rejection on the runtime's TLS settings.
use braidpath::runtime::transport::{self, Congestion};
use quinn::crypto::rustls::QuicServerConfig;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

type Received = Arc<Mutex<Vec<Vec<u8>>>>;

/// Echo every stream and record what arrived, including 0-RTT streams.
fn echo_server(tls: rustls::ServerConfig) -> (SocketAddr, Received, quinn::Endpoint) {
    let config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let received = Received::default();
    let record = received.clone();
    let server = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let record = record.clone();
            tokio::spawn(async move {
                let Ok(connecting) = incoming.accept() else {
                    return;
                };
                let Ok((conn, _)) = connecting.into_0rtt() else {
                    return;
                };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(message) = recv.read_to_end(1024).await else {
                        return;
                    };
                    record.lock().unwrap().push(message.clone());
                    let _ = send.write_all(&message).await;
                    let _ = send.finish();
                }
            });
        }
    });
    (address, received, server)
}

async fn exchange(conn: &quinn::Connection, message: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(message).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(1024).await.unwrap()
}

/// Forward one client to `server`, keeping its Initial and 0-RTT datagrams.
async fn recording_relay(server: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let back = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    back.connect(server).await.unwrap();
    let address = front.local_addr().unwrap();
    let flight = Arc::new(Mutex::new(Vec::new()));
    let keep = flight.clone();
    tokio::spawn(async move {
        let (mut a, mut b) = ([0u8; 2048], [0u8; 2048]);
        let mut client = None;
        loop {
            tokio::select! {
                Ok((n, from)) = front.recv_from(&mut a) => {
                    client = Some(from);
                    // Long header, packet type Initial (0) or 0-RTT (1).
                    if a[0] & 0x80 != 0 && (a[0] >> 4) & 0x3 <= 1 {
                        keep.lock().unwrap().push(a[..n].to_vec());
                    }
                    let _ = back.send(&a[..n]).await;
                }
                Ok(n) = back.recv(&mut b) => {
                    if let Some(client) = client {
                        let _ = front.send_to(&b[..n], client).await;
                    }
                }
            }
        }
    });
    (address, flight)
}

/// A full connection that leaves the client with tickets, then a 0-RTT
/// connection through a relay that records its first flight.
async fn resume_recorded(server: SocketAddr, ca: &Path) -> (quinn::Endpoint, bool, Vec<Vec<u8>>) {
    let client = transport::client(server, ca, None, Congestion::Bbr).unwrap();
    let first = client.connect(server, "localhost").unwrap();
    let Err(first) = first.into_0rtt() else {
        panic!("0-RTT without a ticket");
    };
    let first = first.await.unwrap();
    assert_eq!(exchange(&first, b"full").await, b"full");
    first.close(0u32.into(), b"done");
    // A fresh endpoint, as a reconnecting path binds one, shares the tickets.
    let (relay, flight) = recording_relay(server).await;
    let reconnect = transport::client(relay, ca, None, Congestion::Bbr).unwrap();
    let Ok((early, accepted)) = reconnect.connect(relay, "localhost").unwrap().into_0rtt() else {
        panic!("no 0-RTT with a fresh ticket");
    };
    assert_eq!(exchange(&early, b"early").await, b"early");
    let accepted = timeout(Duration::from_secs(2), accepted).await.unwrap();
    early.close(0u32.into(), b"done");
    reconnect.wait_idle().await;
    let flight = flight.lock().unwrap().clone();
    assert!(flight.len() >= 2, "Initial and 0-RTT datagrams expected");
    (client, accepted, flight)
}

/// Send a recorded first flight from a new address.
async fn replay(flight: &[Vec<u8>], server: SocketAddr) {
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for datagram in flight {
        attacker.send_to(datagram, server).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
}

/// Resume through a relay, then replay that first flight from a new address.
async fn replay_against(tls: rustls::ServerConfig, ca: &Path) -> (bool, Vec<Vec<u8>>) {
    let (server, received, _endpoint) = echo_server(tls);
    let (_client, accepted, flight) = resume_recorded(server, ca).await;
    // Let the server retire the original connection IDs, then replay.
    tokio::time::sleep(Duration::from_millis(300)).await;
    replay(&flight, server).await;
    let received = received.lock().unwrap().clone();
    (accepted, received)
}

fn identity() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    transport::initialize(&identity, "localhost").unwrap();
    (dir, identity.join("cert.pem"), identity.join("key.pem"))
}

#[tokio::test]
async fn early_data_is_accepted_once_and_a_replayed_flight_is_refused() {
    let (_dir, cert, key) = identity();
    let (accepted, received) =
        replay_against(transport::server_tls(&cert, &key).unwrap(), &cert).await;
    assert!(accepted, "the resumed connection's early data was accepted");
    assert_eq!(received, [b"full".to_vec(), b"early".to_vec()]);
}

/// Control: with tickets that survive use, the same replay is accepted, so the
/// test above observes the single-use store rather than an inert replay.
#[tokio::test]
async fn replay_succeeds_only_when_tickets_are_reusable() {
    #[derive(Debug, Default)]
    struct Reusable(Mutex<HashMap<Vec<u8>, Vec<u8>>>);
    impl rustls::server::StoresServerSessions for Reusable {
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
            self.0.lock().unwrap().insert(key, value);
            true
        }
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.0.lock().unwrap().get(key).cloned()
        }
        fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.get(key)
        }
        fn can_cache(&self) -> bool {
            true
        }
    }
    let (_dir, cert, key) = identity();
    let mut tls = transport::server_tls(&cert, &key).unwrap();
    tls.session_storage = Arc::new(Reusable::default());
    let (accepted, received) = replay_against(tls, &cert).await;
    assert!(accepted);
    assert_eq!(
        received,
        [b"full".to_vec(), b"early".to_vec(), b"early".to_vec()]
    );
}

/// A journal keeps unused tickets across a restart and the take of a used one,
/// so the restarted server resumes the client but refuses the replay.
#[tokio::test]
async fn tickets_survive_a_restart_but_a_replay_of_a_used_one_does_not() {
    let (dir, cert, key) = identity();
    let journal = dir.path().join("key.tickets");
    let (server, _, endpoint) =
        echo_server(transport::persistent_server_tls(&cert, &key, &journal).unwrap());
    let (client, accepted, flight) = resume_recorded(server, &cert).await;
    assert!(accepted);
    endpoint.close(0u32.into(), b"restart");
    endpoint.wait_idle().await;
    drop(endpoint);
    // The journal lock is released once the last connection lets go of it.
    let restarted = timeout(Duration::from_secs(5), async {
        loop {
            match transport::persistent_server_tls(&cert, &key, &journal) {
                Ok(tls) => break tls,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .expect("journal released");
    let (server, received, _endpoint) = echo_server(restarted);
    replay(&flight, server).await;
    assert!(
        received.lock().unwrap().is_empty(),
        "replayed early data accepted"
    );
    let Ok((resumed, accepted)) = client.connect(server, "localhost").unwrap().into_0rtt() else {
        panic!("no ticket left for the restarted server");
    };
    assert_eq!(exchange(&resumed, b"after restart").await, b"after restart");
    assert!(timeout(Duration::from_secs(2), accepted).await.unwrap());
    assert_eq!(*received.lock().unwrap(), [b"after restart".to_vec()]);
}
