use super::stats::{self, Metrics};
use anyhow::{Result, ensure};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    task::JoinSet,
    time::timeout,
};
use tracing::info;

struct Budget {
    tokens: f64,
    last: Instant,
    rate: f64,
}
impl Budget {
    fn take(&mut self, n: usize) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate)
            .min(16.0 * 2048.0);
        self.last = now;
        let cost = (n + 48) as f64;
        if self.tokens < cost {
            false
        } else {
            self.tokens -= cost;
            true
        }
    }
}
pub struct Options {
    pub listen: SocketAddr,
    pub target: SocketAddr,
    pub allow: Vec<IpAddr>,
    pub rate: u64,
    pub drop_every: u64,
    pub stats: Metrics,
}
fn count(metrics: &Metrics, direction: &str, f: impl FnOnce(&mut stats::RelayDirection)) {
    metrics.state(|s| f(s.relay.entry(direction.to_owned()).or_default()));
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
    ensure!(
        !options.allow.is_empty(),
        "relay requires at least one allowed client source IP"
    );
    ensure!(
        (64_000..=1_000_000_000).contains(&options.rate),
        "invalid relay rate"
    );
    ensure!(
        options.drop_every == 0 || options.drop_every >= 2,
        "invalid impairment interval"
    );
    let front = Arc::new(UdpSocket::bind(options.listen).await?);
    let budget = Arc::new(Mutex::new(Budget {
        tokens: 16.0 * 2048.0,
        last: Instant::now(),
        rate: options.rate as f64 / 8.0,
    }));
    let mut peers: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut tasks = JoinSet::new();
    let (stop, _) = watch::channel(false);
    let mut b = vec![0; 65536];
    let mut packets = 0u64;
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    options.stats.readiness(true, 0);
    info!(listen=%front.local_addr()?,target=%options.target,drop_every=options.drop_every,"fixed-target relay ready");
    let result:Result<()>=async {loop {tokio::select!{
        _=tokio::signal::ctrl_c()=>break,
        _=tick.tick()=>{peers.retain(|_,tx|!tx.is_closed());info!(mappings=peers.len(),packets,"relay statistics");},
        received=front.recv_from(&mut b)=>{
            let (n,peer)=received?;count(&options.stats,stats::FORWARD,|d|d.received+=1);
            if !options.allow.contains(&peer.ip()){count(&options.stats,stats::FORWARD,|d|d.unauthorized_dropped+=1);continue;}
            if n>2048{count(&options.stats,stats::FORWARD,|d|d.oversize_dropped+=1);continue;}
            packets+=1;
            if options.drop_every>0 && packets.is_multiple_of(options.drop_every){count(&options.stats,stats::FORWARD,|d|d.impairment_dropped+=1);continue;}
            if !budget.lock().expect("budget lock").take(n){count(&options.stats,stats::FORWARD,|d|d.budget_dropped+=1);continue;}
            peers.retain(|_,tx|!tx.is_closed());
            if !peers.contains_key(&peer){
                if peers.len()>=64{count(&options.stats,stats::FORWARD,|d|d.mapping_limit_dropped+=1);continue;}
                let mapping=async{let back=UdpSocket::bind(if options.target.is_ipv4(){"0.0.0.0:0"}else{"[::]:0"}).await?;back.connect(options.target).await?;Ok::<_,std::io::Error>(back)}.await;
                let back=match mapping{Ok(back)=>back,Err(error)=>{count(&options.stats,stats::FORWARD,|d|d.mapping_error_dropped+=1);return Err(error.into());}};
                let (tx,mut rx)=mpsc::channel::<Vec<u8>>(32);peers.insert(peer,tx);
                let front=front.clone();let budget=budget.clone();let metrics=options.stats.clone();let mut quit=stop.subscribe();
                tasks.spawn(async move {
                    let mut back_buffer=vec![0;2049];
                    loop {
                        let action=async{tokio::select!{
                            data=rx.recv()=>match data{Some(data)=>send(&back,&data,None,&metrics,stats::FORWARD).await,None=>Err(std::io::ErrorKind::BrokenPipe.into())},
                            received=back.recv(&mut back_buffer)=>match received{
                                Ok(n)=>{count(&metrics,stats::RETURN,|d|d.received+=1);
                                    if n>2048{count(&metrics,stats::RETURN,|d|d.oversize_dropped+=1);Ok(())}
                                    else if !budget.lock().expect("budget lock").take(n){count(&metrics,stats::RETURN,|d|d.budget_dropped+=1);Ok(())}
                                    else{send(&front,&back_buffer[..n],Some(peer),&metrics,stats::RETURN).await}
                                },Err(e)=>Err(e),
                            }
                        }};
                        let completed=tokio::select!{_=quit.changed()=>false,r=timeout(Duration::from_secs(30),action)=>matches!(r,Ok(Ok(())))};
                        if !completed{break;}
                    }
                    rx.close();while rx.try_recv().is_ok(){count(&metrics,stats::FORWARD,|d|if *quit.borrow(){d.shutdown_dropped+=1;}else{d.mapping_expired_queue_dropped+=1;});}
                });
            }
            if let Err(error)=peers.get(&peer).expect("inserted mapping").try_send(b[..n].to_vec()){count(&options.stats,stats::FORWARD,|d|if matches!(error,mpsc::error::TrySendError::Closed(_)){d.mapping_closed_dropped+=1;}else{d.queue_full_dropped+=1;});}else{count(&options.stats,stats::FORWARD,|d|d.queue_enqueued+=1);}
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
