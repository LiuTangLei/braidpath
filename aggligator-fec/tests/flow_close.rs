#![cfg(feature = "runtime")]
use aggligator_fec::{
    Config, Frame,
    multiplex::{self, Hub, LinkSocket, Route, LANES},
    recovery::Feedback,
    session::{self, SessionConfig},
};
use std::{
    sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}},
    time::{Duration, Instant},
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UdpSocket, time::timeout};

async fn socket() -> Arc<UdpSocket> {
    Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
}
fn config() -> SessionConfig {
    SessionConfig {
        low_latency: true, delivery_aware: false, lanes: 1, wire_mbps: 80,
        nack_delay: Duration::from_millis(5), idle_timeout: Duration::from_secs(5),
        fec: Config { data_shards: 1, repair_shards: 0, max_payload: 1100, ..Config::default() },
        ..SessionConfig::default()
    }
}
fn envelope(flow: u64, session: u64, kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = b"AFM3".to_vec();
    bytes.extend(flow.to_be_bytes()); bytes.push(0);
    bytes.extend(b"AFL1"); bytes.push(kind); bytes.extend(session.to_be_bytes());
    bytes.extend(body); bytes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clean_retirement_repeats_both_acks_after_750ms_loss_without_reopening_a_flow() {
    timeout(Duration::from_secs(5), async {
        let main = socket().await; let access = socket().await; let relay = socket().await;
        let ma = main.local_addr().unwrap(); let ca = access.local_addr().unwrap(); let ra = relay.local_addr().unwrap();
        let closed_at = Arc::new(Mutex::new(None::<Instant>));
        let seen_closed = closed_at.clone();
        let ack_drops = Arc::new(AtomicUsize::new(0)); let dropped = ack_drops.clone();
        let cancels = Arc::new(AtomicUsize::new(0)); let seen_cancel = cancels.clone();
        let forward = tokio::spawn(async move {
            let mut bytes = [0; 1600];
            loop {
                let (n, from) = relay.recv_from(&mut bytes).await.unwrap();
                let to = if from == ca { ma } else if from == ma { ca } else { continue; };
                if let Some((_, _, body)) = multiplex::decode(&bytes[..n]) {
                    if body[4] == 13 { seen_cancel.fetch_add(1, Ordering::Relaxed); }
                    if from == ma {
                        let cumulative = body[4] == 6 && Feedback::decode(&body[13..]).is_some_and(|f| f.next == 1);
                        let fin = body[4] == 11 && body.len() == 21
                            && u64::from_be_bytes(body[13..21].try_into().unwrap()) == 1;
                        if cumulative || fin {
                            let age = seen_closed.lock().unwrap().map(|at| at.elapsed());
                            // Lose every final acknowledgement until the server has
                            // relinquished its active slot. Then let FIN_ACK through
                            // much earlier than the cumulative ACK, exercising both.
                            let lose = age.is_none_or(|age| age < Duration::from_millis(if cumulative { 750 } else { 100 }));
                            if lose {
                                if cumulative { dropped.fetch_add(1, Ordering::Relaxed); }
                                continue;
                            }
                        }
                    }
                }
                relay.send_to(&bytes[..n], to).await.unwrap();
            }
        });
        let (server, mut incoming) = Hub::server(main.clone(), 80, vec![80]).unwrap();
        server.set_admission(vec!["127.0.0.1".parse().unwrap()], vec![]).unwrap();
        let client = Hub::client(vec![LinkSocket { socket: access.clone(), wire_mbps: 80 }], 80).unwrap();
        let mut routes = vec![None; LANES]; routes[0] = Some(Route { socket: 0, destination: ra });
        client.set_routes(routes).unwrap();
        let held_client = client.open().unwrap();
        let cf = held_client.clone();
        let connecting = tokio::spawn(session::multiplexed(cf, config(), true));
        let held_server = incoming.recv().await.unwrap();
        let mut s = session::multiplexed(held_server.clone(), config(), false).await.unwrap();
        let mut c = connecting.await.unwrap().unwrap();
        let server_done = closed_at.clone();
        let serving = tokio::spawn(async move {
            let mut request = Vec::new();
            s.stream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, [23]);
            s.stream.shutdown().await.unwrap();
            let report = s.task.await.unwrap().unwrap();
            *server_done.lock().unwrap() = Some(Instant::now());
            report
        });
        c.stream.write_all(&[23]).await.unwrap();
        c.stream.shutdown().await.unwrap();
        let mut response = Vec::new(); c.stream.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
        timeout(Duration::from_millis(250), serving).await
            .expect("clean server still held its active slot for the old 600ms grace").unwrap();
        assert_eq!(server.flow_count(), 0, "a held FlowIo handle retained an admission slot");
        assert_eq!(client.flow_count(), 1, "peer forgot unacknowledged request bytes");
        let report = timeout(Duration::from_millis(1500), c.task).await
            .expect("retired server did not repeat the final cumulative ACK").unwrap().unwrap();
        assert!(closed_at.lock().unwrap().unwrap().elapsed() >= Duration::from_millis(750));
        assert!(ack_drops.load(Ordering::Relaxed) > 5);
        assert_eq!(client.flow_count(), 0);
        assert_eq!(server.flow_count(), 0);
        assert_eq!(cancels.load(Ordering::Relaxed), 0, "clean completion was advertised as cancellation");

        // Only an exact repeated FIN can trigger the retained response. DATA,
        // HELLO, a different session, extent or source tuple cannot revive it.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let before = server.counters.tx_packets.load(Ordering::Relaxed);
        let mut fin = 1u64.to_be_bytes().to_vec(); fin.push(1);
        access.send_to(&envelope(held_client.id, report.session_id.wrapping_add(1), 7, &fin), ra).await.unwrap();
        let mut wrong_extent = 2u64.to_be_bytes().to_vec(); wrong_extent.push(1);
        access.send_to(&envelope(held_client.id, report.session_id, 7, &wrong_extent), ra).await.unwrap();
        let mut unfinished = 1u64.to_be_bytes().to_vec(); unfinished.push(0);
        access.send_to(&envelope(held_client.id, report.session_id, 7, &unfinished), ra).await.unwrap();
        let mut frame = Vec::new();
        Frame::Source { block: 0, base: 0, index: 0, payload: vec![23] }.encode_into(&mut frame).unwrap();
        access.send_to(&envelope(held_client.id, report.session_id, 1, &frame), ra).await.unwrap();
        let mut hello = b"FECSTREAM2".to_vec(); hello.extend([1, 0, 1]); hello.extend(1100u16.to_be_bytes());
        access.send_to(&envelope(held_client.id, report.session_id, 9, &hello), ra).await.unwrap();
        socket().await.send_to(&envelope(held_client.id, report.session_id, 7, &fin), ma).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(server.counters.tx_packets.load(Ordering::Relaxed), before);
        assert_eq!(server.flow_count(), 0);
        assert!(incoming.try_recv().is_err());

        access.send_to(&envelope(held_client.id, report.session_id, 7, &fin), ra).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(server.counters.tx_packets.load(Ordering::Relaxed), before + 2, "valid FIN did not elicit both final ACKs");
        assert_eq!(server.flow_count(), 0);

        // A closed reply never outlives the admission or exact route which
        // authorized it. Exercise both the server and client route revocation.
        server.set_admission(vec![], vec![]).unwrap();
        access.send_to(&envelope(held_client.id, report.session_id, 7, &fin), ra).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(server.counters.tx_packets.load(Ordering::Relaxed), before + 2);
        let before_client = client.counters.tx_packets.load(Ordering::Relaxed);
        let mut client_fin = 0u64.to_be_bytes().to_vec(); client_fin.push(1);
        main.send_to(&envelope(held_client.id, report.session_id, 7, &client_fin), ra).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(client.counters.tx_packets.load(Ordering::Relaxed), before_client + 2);
        client.set_routes(vec![None; LANES]).unwrap();
        main.send_to(&envelope(held_client.id, report.session_id, 7, &client_fin), ra).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(client.counters.tx_packets.load(Ordering::Relaxed), before_client + 2);
        forward.abort();
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sequential_short_connections_reclaim_slots_without_waiting_for_flow_handles() {
    timeout(Duration::from_secs(4), async {
        let main = socket().await; let access = socket().await;
        let (server, mut incoming) = Hub::server(main.clone(), 80, vec![80]).unwrap();
        server.set_admission(vec!["127.0.0.1".parse().unwrap()], vec![]).unwrap();
        let client = Hub::client(vec![LinkSocket { socket: access, wire_mbps: 80 }], 80).unwrap();
        let mut routes = vec![None; LANES];
        routes[0] = Some(Route { socket: 0, destination: main.local_addr().unwrap() });
        client.set_routes(routes).unwrap();
        let mut held = Vec::new();
        for value in 0..48u8 {
            let cf = client.open().expect("completed short connections exhausted the shared 32-flow limit");
            held.push(cf.clone());
            let connecting = tokio::spawn(session::multiplexed(cf, config(), true));
            let sf = incoming.recv().await.unwrap(); held.push(sf.clone());
            let mut s = session::multiplexed(sf, config(), false).await.unwrap();
            let mut c = connecting.await.unwrap().unwrap();
            let serving = tokio::spawn(async move {
                let mut request = Vec::new(); s.stream.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, [value]); s.stream.shutdown().await.unwrap();
                s.task.await.unwrap().unwrap()
            });
            c.stream.write_all(&[value]).await.unwrap(); c.stream.shutdown().await.unwrap();
            let mut response = Vec::new(); c.stream.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty());
            c.task.await.unwrap().unwrap(); serving.await.unwrap();
            assert_eq!(client.flow_count(), 0); assert_eq!(server.flow_count(), 0);
        }
        assert_eq!(held.len(), 96, "test must retain old handles while reclaiming active slots");
    }).await.expect("short connections waited for the old per-flow close grace");
}
