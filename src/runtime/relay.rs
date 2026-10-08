use anyhow::{Result, ensure};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet, time::timeout};
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
    let mut b = vec![0; 65536];
    let mut packets = 0u64;
    let mut drops = 0u64;
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    info!(listen=%front.local_addr()?,target=%options.target,drop_every=options.drop_every,"fixed-target relay ready");
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=tick.tick()=>{peers.retain(|_,tx|!tx.is_closed());info!(mappings=peers.len(),packets,drops,"relay statistics");},
            received=front.recv_from(&mut b)=>{
                let (n,peer)=received?;
                if !options.allow.contains(&peer.ip()) || n>2048 {drops+=1;continue}
                packets+=1;
                if options.drop_every>0 && packets.is_multiple_of(options.drop_every) {drops+=1;continue}
                if !budget.lock().expect("budget lock").take(n){drops+=1;continue}
                peers.retain(|_,tx|!tx.is_closed());
                if !peers.contains_key(&peer){
                    if peers.len()>=64{drops+=1;continue}
                    let back=UdpSocket::bind(if options.target.is_ipv4(){"0.0.0.0:0"}else{"[::]:0"}).await?;
                    back.connect(options.target).await?;
                    let (tx,mut rx)=mpsc::channel::<Vec<u8>>(32);peers.insert(peer,tx);
                    let front=front.clone();let budget=budget.clone();
                    tasks.spawn(async move {
                        let mut back_buffer=vec![0;2049];
                        loop {
                            let action=async {tokio::select! {
                                data=rx.recv()=>match data {Some(data)=>back.send(&data).await.map(|_|()),None=>Err(std::io::ErrorKind::BrokenPipe.into())},
                                received=back.recv(&mut back_buffer)=>match received {
                                    Ok(n) if n<=2048=>{
                                        let allowed=budget.lock().expect("budget lock").take(n);
                                        if allowed {front.send_to(&back_buffer[..n],peer).await.map(|_|())}else{Ok(())}
                                    },
                                    Ok(_)=>Ok(()),Err(e)=>Err(e),
                                }
                            }};
                            if !matches!(timeout(Duration::from_secs(30),action).await,Ok(Ok(()))){break}
                        }
                    });
                }
                if peers.get(&peer).expect("inserted mapping").try_send(b[..n].to_vec()).is_err(){drops+=1;}
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{}
        }
    }
    Ok(())
}
