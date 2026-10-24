use super::shutdown::Shutdown;
use super::stats::{self, Metrics};
use anyhow::{Result, ensure};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, timeout},
};
use tracing::{debug, info};

mod budget;
use budget::Budget;
pub(crate) use budget::HostBudget;

pub struct Options {
    pub listen: SocketAddr,
    pub target: SocketAddr,
    pub allow: Vec<IpAddr>,
    pub rate: u64,
    pub drop_every: u64,
    pub stats: Metrics,
}
fn count(metrics: &Metrics, direction: &str, f: impl FnOnce(&mut stats::RelayDirection)) {
    metrics.state(|s| {
        // Avoid allocating a String on every datagram once the counter exists.
        if let Some(counters) = s.relay.get_mut(direction) {
            f(counters);
        } else {
            f(s.relay.entry(direction.to_owned()).or_default());
        }
    });
}

struct Mapping {
    back: Arc<UdpSocket>,
    sender: mpsc::Sender<Vec<u8>>,
    activity: Arc<Mutex<Instant>>,
}
fn forward(mapping: &Mapping, data: &[u8], metrics: &Metrics) {
    *mapping.activity.lock().expect("relay activity") = Instant::now();
    // Most packets can go directly to the kernel without allocation or a second
    // task wakeup. Retain the bounded queue only when the socket is backpressured.
    match mapping.back.try_send(data) {
        Ok(n) => count(metrics, stats::FORWARD, |d| {
            d.forwarded += 1;
            d.forwarded_bytes += n as u64;
        }),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            enqueue(&mapping.sender, data, metrics)
        }
        Err(_) => count(metrics, stats::FORWARD, |d| d.socket_send_dropped += 1),
    }
}

fn enqueue(sender: &mpsc::Sender<Vec<u8>>, data: &[u8], metrics: &Metrics) {
    match sender.try_reserve() {
        Ok(permit) => {
            permit.send(data.to_vec());
            count(metrics, stats::FORWARD, |d| d.queue_enqueued += 1);
        }
        Err(error) => count(metrics, stats::FORWARD, |d| match error {
            mpsc::error::TrySendError::Closed(_) => d.mapping_closed_dropped += 1,
            mpsc::error::TrySendError::Full(_) => d.queue_full_dropped += 1,
        }),
    }
}

async fn discard_queued(receiver: &mut mpsc::Receiver<Vec<u8>>, metrics: &Metrics, shutdown: bool) {
    receiver.close();
    // Closing prevents new reservations, but a sender may already own a permit.
    // Await those admitted packets too so a concurrent timeout loses no counts.
    while receiver.recv().await.is_some() {
        count(metrics, stats::FORWARD, |d| {
            if shutdown {
                d.shutdown_dropped += 1;
            } else {
                d.mapping_expired_queue_dropped += 1;
            }
        });
    }
}
/// If an awaited UDP send is cancelled by its mapping timeout, account the consumed datagram.
struct Sending {
    metrics: Metrics,
    direction: &'static str,
    done: bool,
}
impl Drop for Sending {
    fn drop(&mut self) {
        if !self.done {
            count(&self.metrics, self.direction, |d| {
                d.socket_send_cancelled_dropped += 1
            });
        }
    }
}
async fn send(
    socket: &UdpSocket,
    data: &[u8],
    peer: Option<SocketAddr>,
    metrics: &Metrics,
    direction: &'static str,
) -> std::io::Result<()> {
    let mut guard = Sending {
        metrics: metrics.clone(),
        direction,
        done: false,
    };
    let result = match peer {
        Some(peer) => socket.send_to(data, peer).await,
        None => socket.send(data).await,
    };
    guard.done = true;
    count(metrics, direction, |d| match &result {
        Ok(n) => {
            d.forwarded += 1;
            d.forwarded_bytes += *n as u64;
        }
        Err(_) => d.socket_send_dropped += 1,
    });
    result.map(|_| ())
}
pub async fn run(options: Options) -> Result<()> {
    let front = Arc::new(UdpSocket::bind(options.listen).await?);
    run_on_socket(options, front, true).await
}

/// `announce` keeps per-relay lifecycle and statistics logs at info level;
/// mesh allocations, which can be numerous, log them at debug level.
pub(crate) async fn run_on_socket(
    options: Options,
    front: Arc<UdpSocket>,
    announce: bool,
) -> Result<()> {
    run_with_budget(options, front, announce, None).await
}

pub(crate) async fn run_on_socket_with_budget(
    options: Options,
    front: Arc<UdpSocket>,
    announce: bool,
    host: Arc<HostBudget>,
) -> Result<()> {
    run_with_budget(options, front, announce, Some(host)).await
}

async fn run_with_budget(
    options: Options,
    front: Arc<UdpSocket>,
    announce: bool,
    host: Option<Arc<HostBudget>>,
) -> Result<()> {
    ensure!(
        !options.allow.is_empty(),
        "relay requires at least one allowed client source IP"
    );
    ensure!(
        (64_000..=super::MAX_RATE_BPS).contains(&options.rate),
        "invalid relay rate"
    );
    ensure!(
        options.drop_every == 0 || options.drop_every >= 2,
        "invalid impairment interval"
    );
    super::transport::datagram_socket_buffers(
        socket2::SockRef::from(front.as_ref()),
        "relay-front",
    );
    let budget = Arc::new(Budget::new(options.rate, host));
    let mut peers: HashMap<SocketAddr, Mapping> = HashMap::new();
    let mut tasks = JoinSet::new();
    let (stop, _) = watch::channel(false);
    let mut b = vec![0; 65536];
    let mut packets = 0u64;
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let mut shutdown = Shutdown::new();
    options.stats.readiness(true, 0);
    if announce {
        info!(listen=%front.local_addr()?,target=%options.target,drop_every=options.drop_every,"fixed-target relay ready");
    } else {
        debug!(listen=%front.local_addr()?,target=%options.target,"mesh relay allocation ready");
    }
    let result:Result<()>=async {loop {tokio::select!{
        _=shutdown.wait()=>break,
        _=tick.tick()=>{peers.retain(|_,mapping|!mapping.sender.is_closed());if announce {info!(mappings=peers.len(),packets,"relay statistics");} else {debug!(mappings=peers.len(),packets,"mesh relay statistics");}},
        received=front.recv_from(&mut b)=>{
            let (n,peer)=received?;count(&options.stats,stats::FORWARD,|d|d.received+=1);
            if !options.allow.contains(&peer.ip()){count(&options.stats,stats::FORWARD,|d|d.unauthorized_dropped+=1);continue;}
            if n>2048{count(&options.stats,stats::FORWARD,|d|d.oversize_dropped+=1);continue;}
            packets+=1;
            if options.drop_every>0 && packets.is_multiple_of(options.drop_every){count(&options.stats,stats::FORWARD,|d|d.impairment_dropped+=1);continue;}
            if !budget.take(n){count(&options.stats,stats::FORWARD,|d|d.budget_dropped+=1);continue;}
            if peers.get(&peer).is_some_and(|mapping|mapping.sender.is_closed()){peers.remove(&peer);}
            if !peers.contains_key(&peer){
                if peers.len()>=64{count(&options.stats,stats::FORWARD,|d|d.mapping_limit_dropped+=1);continue;}
                let mapping=async{let back=UdpSocket::bind(if options.target.is_ipv4(){"0.0.0.0:0"}else{"[::]:0"}).await?;super::transport::datagram_socket_buffers(socket2::SockRef::from(&back), "relay-back");back.connect(options.target).await?;Ok::<_,std::io::Error>(Arc::new(back))}.await;
                let back=match mapping{Ok(back)=>back,Err(error)=>{count(&options.stats,stats::FORWARD,|d|d.mapping_error_dropped+=1);tracing::debug!(%peer,%error,"relay mapping unavailable");continue;}};
                let activity = Arc::new(Mutex::new(Instant::now()));
                let (tx,mut rx)=mpsc::channel::<Vec<u8>>(32);peers.insert(peer,Mapping { back: back.clone(), sender: tx, activity: activity.clone() });
                let front=front.clone();let budget=budget.clone();let metrics=options.stats.clone();let mut quit=stop.subscribe();
                tasks.spawn(async move {
                    let mut back_buffer=vec![0;2049];
                    loop {
                        let action=async{tokio::select!{
                            data=rx.recv()=>match data{Some(data)=>send(&back,&data,None,&metrics,stats::FORWARD).await,None=>Err(std::io::ErrorKind::BrokenPipe.into())},
                            received=back.recv(&mut back_buffer)=>match received{
                                Ok(n)=>{count(&metrics,stats::RETURN,|d|d.received+=1);
                                    if n>2048{count(&metrics,stats::RETURN,|d|d.oversize_dropped+=1);Ok(())}
                                    else if !budget.take(n){count(&metrics,stats::RETURN,|d|d.budget_dropped+=1);Ok(())}
                                    else{send(&front,&back_buffer[..n],Some(peer),&metrics,stats::RETURN).await}
                                },Err(e)=>Err(e),
                            }
                        }};
                        let completed=tokio::select!{_=quit.changed()=>false,r=timeout(Duration::from_secs(30),action)=>match r { Ok(Ok(())) => true, Err(_) => activity.lock().expect("relay activity").elapsed() < Duration::from_secs(30), _ => false }};
                        if !completed{break;}
                    }
                    let shutting_down = *quit.borrow();
                    discard_queued(&mut rx, &metrics, shutting_down).await;
                });
            }
            forward(peers.get(&peer).expect("inserted mapping"), &b[..n], &options.stats);
        },
        _=tasks.join_next(),if !tasks.is_empty()=>{}
    }}Ok(())}.await;
    options.stats.readiness(false, 0);
    let _ = stop.send(true);
    peers.clear();
    let joined = timeout(Duration::from_secs(2), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    if !joined {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    options.stats.state(|s| {
        s.shutdown_complete = joined;
        s.drain_incomplete = !joined;
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_overload_and_closed_mapping_preserve_drop_accounting() {
        let metrics = Metrics::new("relay-test");
        let (sender, mut receiver) = mpsc::channel(1);
        enqueue(&sender, b"admitted", &metrics);
        enqueue(&sender, b"overload", &metrics);
        assert_eq!(receiver.try_recv().unwrap(), b"admitted");
        assert!(receiver.try_recv().is_err());
        drop(receiver);
        enqueue(&sender, b"closed", &metrics);
        metrics.state(|state| {
            let counters = &state.relay[stats::FORWARD];
            assert_eq!(counters.queue_enqueued, 1);
            assert_eq!(counters.queue_full_dropped, 1);
            assert_eq!(counters.mapping_closed_dropped, 1);
        });
    }

    #[tokio::test]
    async fn mapping_drain_waits_for_an_already_reserved_packet() {
        for shutdown in [false, true] {
            let metrics = Metrics::new("relay-drain-test");
            let (sender, mut receiver) = mpsc::channel(1);
            let permit = sender.try_reserve().unwrap();
            let recorded = metrics.clone();
            let drain = tokio::spawn(async move {
                discard_queued(&mut receiver, &recorded, shutdown).await;
            });
            tokio::task::yield_now().await;
            assert!(!drain.is_finished(), "reserved packet was abandoned");
            assert!(sender.is_closed());
            permit.send(vec![1]);
            timeout(Duration::from_secs(1), drain)
                .await
                .unwrap()
                .unwrap();
            metrics.state(|state| {
                let counters = &state.relay[stats::FORWARD];
                assert_eq!(counters.shutdown_dropped, u64::from(shutdown));
                assert_eq!(counters.mapping_expired_queue_dropped, u64::from(!shutdown));
            });
        }
    }

    #[tokio::test(start_paused = true)]
    async fn direct_forwarding_preserves_one_way_mapping_activity_and_idle_cleanup() {
        // Real sockets, controlled clock; keep timer auto-advance from racing IO.
        let busy = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = front.local_addr().unwrap();
        client.connect(address).await.unwrap();
        let metrics = Metrics::new("one-way-mapping");
        let relay = tokio::spawn(run_on_socket(
            Options {
                listen: address,
                target: target.local_addr().unwrap(),
                allow: vec![address.ip()],
                rate: 10_000_000_000,
                drop_every: 0,
                stats: metrics.clone(),
            },
            front,
            false,
        ));
        let mut original = None;
        for _ in 0..4 {
            client.send(b"one-way").await.unwrap();
            let mut buffer = [0; 16];
            let (n, source) = target.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], b"one-way");
            if let Some(old) = original {
                assert_eq!(source, old, "active one-way mapping expired");
            } else {
                original = Some(source);
            }
            tokio::time::advance(Duration::from_secs(20)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
        metrics.state(|s| {
            assert_eq!(s.relay[stats::FORWARD].forwarded, 4);
            assert!(
                s.relay[stats::FORWARD].queue_enqueued <= 1,
                "steady forwarding still wakes the queue worker"
            );
        });
        tokio::time::advance(Duration::from_secs(40)).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        // The front map retires closed workers on its next five-second sweep.
        tokio::time::advance(Duration::from_secs(6)).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        let _reclaimed = UdpSocket::bind(original.unwrap())
            .await
            .expect("idle mapping retained its socket");
        relay.abort();
        let _ = relay.await;
        busy.abort();
        let _ = busy.await;
    }

    #[cfg(unix)]
    #[test]
    fn mapping_socket_exhaustion_keeps_existing_flows_and_recovers() {
        const CHILD: &str = "BRAIDPATH_RELAY_FD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new("sh")
                .args([
                    "-c",
                    "ulimit -n 64 && exec \"$1\" --exact runtime::relay::tests::mapping_socket_exhaustion_keeps_existing_flows_and_recovers --nocapture",
                    "relay-fd-test",
                ])
                .arg(std::env::current_exe().unwrap())
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // Exhaust only the isolated child's 64-descriptor allowance.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let target_address = target.local_addr().unwrap();
                let echo = tokio::spawn(async move {
                    let mut bytes = [0; 64];
                    loop {
                        let (n, peer) = target.recv_from(&mut bytes).await.unwrap();
                        target.send_to(&bytes[..n], peer).await.unwrap();
                    }
                });
                let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                let address = front.local_addr().unwrap();
                let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                first.connect(address).await.unwrap();
                second.connect(address).await.unwrap();
                let metrics = Metrics::new("relay-fd-test");
                let relay = tokio::spawn(run_on_socket(
                    Options {
                        listen: address,
                        target: target_address,
                        allow: vec![address.ip()],
                        rate: 10_000_000,
                        drop_every: 0,
                        stats: metrics.clone(),
                    },
                    front,
                    true,
                ));
                async fn round_trip(socket: &UdpSocket) {
                    timeout(Duration::from_secs(2), async {
                        socket.send(b"still-alive").await.unwrap();
                        let mut bytes = [0; 64];
                        let n = socket.recv(&mut bytes).await.unwrap();
                        assert_eq!(&bytes[..n], b"still-alive");
                    })
                    .await
                    .unwrap();
                }
                round_trip(&first).await;
                let mut held = Vec::new();
                while let Ok(file) = std::fs::File::open("/dev/null") {
                    held.push(file);
                    assert!(held.len() < 128, "child descriptor limit was not applied");
                }
                second.send(b"cannot-open-mapping").await.unwrap();
                timeout(Duration::from_secs(2), async {
                    loop {
                        let mut dropped = false;
                        metrics
                            .state(|s| dropped = s.relay[stats::FORWARD].mapping_error_dropped > 0);
                        if dropped {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert!(
                    !relay.is_finished(),
                    "one failed mapping terminated the relay"
                );
                round_trip(&first).await;
                drop(held);
                round_trip(&second).await;
                relay.abort();
                echo.abort();
            });
    }
}
