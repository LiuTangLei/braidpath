#![cfg(feature = "runtime")]
// Real UDP regression scenarios. No mocked sender/decoder, wall-clock relay faults.
use aggligator_fec::{
    Config,
    session::{self, Session, SessionConfig},
};
use std::{
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    task::JoinHandle,
    time::timeout,
};

#[derive(Clone, Copy)]
enum Fault { SlowFirst, LostTail, None }

#[derive(Default)]
struct Drops { sources: AtomicUsize, retries: AtomicUsize }

struct Relays { tasks: Vec<JoinHandle<()>>, drops: Arc<Drops> }
impl Drop for Relays {
    fn drop(&mut self) { for task in &self.tasks { task.abort(); } }
}

fn config() -> SessionConfig {
    SessionConfig {
        fec: Config { data_shards: 1, repair_shards: 0, max_payload: 1100, ..Config::default() },
        lanes: 1,
        wire_mbps: 80,
        nack_delay: Duration::from_millis(5),
        idle_timeout: Duration::from_secs(5),
        delivery_aware: false,
        adaptive_retries: false,
        low_latency: true,
    }
}

async fn pair(fault: Fault) -> (Session, Session, Relays) {
    let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let ap = a.local_addr().unwrap();
    let bp = b.local_addr().unwrap();
    let mut peers = Vec::new();
    let mut relays = Relays { tasks: Vec::new(), drops: Arc::new(Drops::default()) };
    for path in 0..2 {
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        peers.push(relay.local_addr().unwrap());
        let drops = relays.drops.clone();
        relays.tasks.push(tokio::spawn(async move {
            let mut buffer = [0; 1600];
            let mut sources = 0;
            let mut retries = 0;
            loop {
                let Ok((n, from)) = relay.recv_from(&mut buffer).await else { return; };
                let to = if from == ap { bp } else if from == bp { ap } else { continue; };
                let kind = buffer.get(4).copied().unwrap_or(0);
                // Handshake succeeds, but no RTT sample ever succeeds: configured
                // paths must be usable before and without probe convergence.
                if matches!(fault, Fault::SlowFirst | Fault::LostTail) && matches!(kind, 2 | 3) {
                    continue;
                }
                if matches!(fault, Fault::LostTail) && from == ap {
                    if kind == 1 {
                        drops.sources.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if kind == 8 {
                        retries += 1;
                        if retries == 1 {
                            drops.retries.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                }
                if matches!(fault, Fault::SlowFirst) && path == 0 && matches!(kind, 1 | 8) {
                    sources += 1;
                    if sources % 3 == 0 {
                        drops.sources.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let bytes = buffer[..n].to_vec();
                    let delayed = relay.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(120)).await;
                        let _ = delayed.send_to(&bytes, to).await;
                    });
                    continue;
                }
                let _ = relay.send_to(&buffer[..n], to).await;
            }
        }));
    }
    let cfg = config();
    let (server, client) = tokio::join!(
        session::accept(b, peers.clone(), cfg.clone()),
        session::connect(a, peers, cfg),
    );
    (client.unwrap(), server.unwrap(), relays)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_arrival_wins_without_probes_or_duplicate_application_bytes() {
    timeout(Duration::from_secs(8), async {
        let (mut client, mut server, relays) = pair(Fault::SlowFirst).await;
        const ROUNDS: usize = 120;
        const SIZE: usize = 768;
        let echo = tokio::spawn(async move {
            let mut bytes = vec![0; SIZE];
            for round in 0..ROUNDS {
                server.stream.read_exact(&mut bytes).await.unwrap();
                assert!(bytes.iter().all(|b| *b == round as u8));
                server.stream.write_all(&bytes).await.unwrap();
            }
            let mut extra = Vec::new();
            server.stream.read_to_end(&mut extra).await.unwrap();
            assert!(extra.is_empty(), "a late replica was delivered as extra business data");
            server.stream.shutdown().await.unwrap();
            server.task.await.unwrap().unwrap()
        });
        let mut times = Vec::new();
        let mut reply = vec![0; SIZE];
        for round in 0..ROUNDS {
            let request = vec![round as u8; SIZE];
            let at = Instant::now();
            client.stream.write_all(&request).await.unwrap();
            client.stream.read_exact(&mut reply).await.unwrap();
            times.push(at.elapsed());
            assert_eq!(reply, request);
        }
        let first = times[0];
        times.sort();
        let p99 = times[(ROUNDS * 99).div_ceil(100) - 1];
        eprintln!("replicated UDP, one 120ms/loss path and no probes: first={first:?}, p50={:?}, p99={p99:?}, max={:?}", times[ROUNDS / 2], times[ROUNDS - 1]);
        assert!(p99 < Duration::from_millis(100), "healthy replica waited for the 120ms path");
        assert!(first < Duration::from_millis(100), "first payload waited for an unavailable probe");
        client.stream.shutdown().await.unwrap();
        let mut extra = Vec::new();
        client.stream.read_to_end(&mut extra).await.unwrap();
        assert!(extra.is_empty());
        let sent = client.task.await.unwrap().unwrap();
        let received = echo.await.unwrap();
        assert!(sent.path_source_packets.iter().all(|n| *n > 0), "source packets were not copied onto every configured path");
        assert!(sent.path_state.iter().all(|s| s.srtt_ms == 0.0));
        assert_eq!(sent.tx_payload_bytes, (ROUNDS * SIZE) as u64);
        assert_eq!(received.rx_payload_bytes, (ROUNDS * SIZE) as u64);
        assert!(relays.drops.sources.load(Ordering::Relaxed) > 0);
    }).await.expect("replica race or half-close stalled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_original_and_first_retry_copies_of_an_open_tail_are_recovered_promptly() {
    timeout(Duration::from_secs(6), async {
        let (mut client, mut server, relays) = pair(Fault::LostTail).await;
        let request = b"GET /tail HTTP/1.1\r\nHost: latency.invalid\r\n\r\n";
        let expected = *request;
        let echo = tokio::spawn(async move {
            let mut bytes = vec![0; expected.len()];
            server.stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, expected);
            server.stream.write_all(b"OK").await.unwrap();
            let mut extra = Vec::new();
            server.stream.read_to_end(&mut extra).await.unwrap();
            assert!(extra.is_empty());
            server.stream.shutdown().await.unwrap();
            server.task.await.unwrap().unwrap()
        });
        let at = Instant::now();
        client.stream.write_all(request).await.unwrap();
        let mut reply = [0; 2];
        // Deliberately do not close/flush the stream: the tail extent must discover
        // a completely lost last packet while the HTTP connection stays open.
        timeout(Duration::from_millis(100), client.stream.read_exact(&mut reply)).await
            .expect("tail waited for the former 120ms retry cooldown").unwrap();
        eprintln!("all originals and first retries dropped: open-tail response={:?}", at.elapsed());
        assert_eq!(&reply, b"OK");
        assert!(relays.drops.sources.load(Ordering::Relaxed) >= 2);
        assert_eq!(relays.drops.retries.load(Ordering::Relaxed), 2);
        client.stream.shutdown().await.unwrap();
        let mut extra = Vec::new();
        client.stream.read_to_end(&mut extra).await.unwrap();
        assert!(extra.is_empty());
        let report = client.task.await.unwrap().unwrap();
        echo.await.unwrap();
        assert!(report.tx_retries >= 4);
    }).await.expect("tail recovery or FIN stalled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backpressure_half_close_and_reply_remain_exact_with_replication() {
    timeout(Duration::from_secs(12), async {
        let (mut client, mut server, _relays) = pair(Fault::None).await;
        let data = (0..1_048_576).map(|n| (n * 31 % 251) as u8).collect::<Vec<_>>();
        let expected = data.clone();
        let receiver = tokio::spawn(async move {
            // Outbound delivery capacity is intentionally far smaller than this request.
            tokio::time::sleep(Duration::from_millis(400)).await;
            let mut got = Vec::new();
            server.stream.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, expected);
            got.reverse();
            server.stream.write_all(&got).await.unwrap();
            server.stream.shutdown().await.unwrap();
            server.task.await.unwrap().unwrap()
        });
        client.stream.write_all(&data).await.unwrap();
        client.stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, data.into_iter().rev().collect::<Vec<_>>());
        let sent = client.task.await.unwrap().unwrap();
        let received = receiver.await.unwrap();
        assert_eq!(sent.tx_payload_bytes, 1_048_576);
        assert_eq!(sent.rx_payload_bytes, 1_048_576);
        assert!(received.max_receive_buffer > 16, "test did not exercise reader backpressure");
        assert!(sent.max_send_history <= 8192 && received.max_receive_buffer <= 8192);
    }).await.expect("backpressure, FIN or exact byte delivery failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_wakes_a_parked_idle_sender() {
    let (client, server, _relays) = pair(Fault::None).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    client.task.abort();
    server.task.abort();
    let (a, b) = timeout(Duration::from_millis(250), async {
        tokio::join!(client.task, server.task)
    }).await.expect("parked send worker ignored hard cancellation");
    assert!(a.unwrap_err().is_cancelled());
    assert!(b.unwrap_err().is_cancelled());
}
