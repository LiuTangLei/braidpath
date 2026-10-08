use super::{MAX_PAYLOAD, relay, transport, tunnel};
use anyhow::{Result, ensure};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

#[derive(Parser)]
#[command(
    version,
    about = "Experimental FEC-assisted HTTP/3 datagram aggregation"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Create a dedicated test identity. Trust cert.pem explicitly on the client.
    Init {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "localhost")]
        name: String,
    },
    /// Serve a website and authenticated datagrams to one configured UDP target.
    Server {
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long)]
        target: SocketAddr,
        #[arg(long, default_value_t = 10_000_000)]
        max_rate_bps: u64,
    },
    /// Expose a local UDP port through independently encrypted entrances.
    Client {
        #[arg(long, default_value = "127.0.0.1:7000")]
        listen: SocketAddr,
        #[arg(long = "entrance", required = true)]
        entrances: Vec<SocketAddr>,
        #[arg(long = "interface")]
        interfaces: Vec<String>,
        #[arg(long)]
        server_name: String,
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        token_file: PathBuf,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Forward opaque UDP packets only to the configured main server.
    Relay {
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        target: SocketAddr,
        #[arg(long = "allow-source", required = true)]
        allow: Vec<IpAddr>,
        #[arg(long, default_value_t = 20_000_000)]
        rate_bps: u64,
        #[arg(long, default_value_t = 0)]
        drop_every: u64,
    },
    /// Retrieve the ordinary HTTP/3 website without proxy credentials.
    Get {
        #[arg(long)]
        entrance: SocketAddr,
        #[arg(long)]
        server_name: String,
        #[arg(long)]
        ca: PathBuf,
    },
    /// Bounded UDP echo service for an explicitly selected test address.
    Echo {
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: SocketAddr,
    },
    /// Measure a fixed-rate UDP echo workload; emit one JSON result to stdout.
    Probe {
        #[arg(long)]
        target: SocketAddr,
        #[arg(long, default_value_t = 1000)]
        count: u32,
        #[arg(long, default_value_t = 1000)]
        size: usize,
        #[arg(long, default_value_t = 200)]
        pps: u32,
        #[arg(long, default_value_t = 250)]
        deadline_ms: u64,
    },
}
#[derive(Args)]
struct PolicyArgs {
    #[arg(long, default_value_t = 4)]
    fec: u8,
    #[arg(long, default_value_t = 30)]
    redundancy_percent: u8,
    #[arg(long, default_value_t = 10_000_000)]
    rate_bps: u64,
    #[arg(long, default_value_t = 3)]
    block_ms: u64,
    #[arg(long, default_value_t = 100)]
    queue_ms: u64,
}
pub async fn run() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    match Cli::parse().command {
        Command::Init { dir, name } => {
            transport::initialize(&dir, &name)?;
            println!(
                "Identity created in {}. Copy only cert.pem and token to the client.",
                dir.display()
            );
            Ok(())
        }
        Command::Server {
            listen,
            cert,
            key,
            token_file,
            target,
            max_rate_bps,
        } => {
            ensure!(
                (64_000..=1_000_000_000).contains(&max_rate_bps),
                "invalid server rate"
            );
            tunnel::serve(tunnel::ServerOptions {
                bind: listen,
                cert,
                key,
                token: token_file,
                target,
                max_rate: max_rate_bps,
            })
            .await
        }
        Command::Client {
            listen,
            entrances,
            interfaces,
            server_name,
            ca,
            token_file,
            policy,
        } => {
            tunnel::client(tunnel::ClientOptions {
                listen,
                entrances,
                interfaces,
                name: server_name,
                ca,
                token: token_file,
                policy: tunnel::Policy {
                    fec: policy.fec,
                    redundancy: policy.redundancy_percent,
                    rate: policy.rate_bps,
                    block_ms: policy.block_ms,
                    queue_ms: policy.queue_ms,
                },
            })
            .await
        }
        Command::Relay {
            listen,
            target,
            allow,
            rate_bps,
            drop_every,
        } => {
            relay::run(relay::Options {
                listen,
                target,
                allow,
                rate: rate_bps,
                drop_every,
            })
            .await
        }
        Command::Get {
            entrance,
            server_name,
            ca,
        } => {
            println!("{}", tunnel::get(entrance, &server_name, &ca).await?);
            Ok(())
        }
        Command::Echo { listen } => echo(listen).await,
        Command::Probe {
            target,
            count,
            size,
            pps,
            deadline_ms,
        } => probe(target, count, size, pps, deadline_ms).await,
    }
}
async fn echo(listen: SocketAddr) -> Result<()> {
    let socket = UdpSocket::bind(listen).await?;
    tracing::info!(%listen,"test echo ready");
    let mut b = vec![0; MAX_PAYLOAD + 1];
    loop {
        tokio::select! {_=tokio::signal::ctrl_c()=>break,r=socket.recv_from(&mut b)=>{let(n,peer)=r?;if n<=MAX_PAYLOAD{socket.send_to(&b[..n],peer).await?;}}}
    }
    Ok(())
}
#[derive(Serialize)]
struct ProbeResult {
    sent: u32,
    received: usize,
    duplicate: u64,
    corrupt: u64,
    deadline_misses: usize,
    p50_ms: Option<f64>,
    p95_ms: Option<f64>,
    p99_ms: Option<f64>,
    useful_bytes: usize,
    offered_pps: u32,
    send_span_seconds: f64,
    observation_seconds: f64,
    useful_goodput_bps: f64,
    payload_bytes: usize,
    deadline_ms: u64,
    measurement: &'static str,
}
async fn probe(
    target: SocketAddr,
    count: u32,
    size: usize,
    pps: u32,
    deadline_ms: u64,
) -> Result<()> {
    ensure!(
        (16..=MAX_PAYLOAD).contains(&size)
            && (1..=100_000).contains(&count)
            && (1..=20_000).contains(&pps)
            && (1..=10_000).contains(&deadline_ms),
        "invalid bounded probe parameters"
    );
    let socket = UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(target).await?;
    let nonce: u64 = rand::random();
    let mut sent_times = Vec::with_capacity(count as usize);
    let mut arrivals = BTreeMap::<u32, f64>::new();
    let mut duplicates = 0u64;
    let mut corrupt = 0u64;
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / f64::from(pps)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut b = vec![0; 65536];
    let mut sent = 0u32;
    let mut end = None;
    let started = Instant::now();
    loop {
        tokio::select! {
            _=tick.tick(),if sent<count=>{
                let mut data=vec![(sent%251) as u8;size];data[..8].copy_from_slice(&nonce.to_be_bytes());data[8..12].copy_from_slice(&sent.to_be_bytes());
                sent_times.push(Instant::now());socket.send(&data).await?;sent+=1;
                if sent==count {end=Some(tokio::time::Instant::now()+Duration::from_millis(deadline_ms.max(1000)+1000));}
            },
            data=socket.recv(&mut b)=>{
                let n=data?;if n!=size || b[..8]!=nonce.to_be_bytes(){corrupt+=1;continue}
                let id=u32::from_be_bytes(b[8..12].try_into()?);
                if id>=sent || b[12..n].iter().any(|x|*x!=(id%251) as u8){corrupt+=1;continue}
                if arrivals.contains_key(&id){duplicates+=1;continue}
                arrivals.insert(id,sent_times[id as usize].elapsed().as_secs_f64()*1000.0);
            },
            _=async {tokio::time::sleep_until(end.expect("guarded deadline")).await},if end.is_some()=>break,
        }
    }
    let mut rtts = arrivals.values().copied().collect::<Vec<_>>();
    rtts.sort_by(f64::total_cmp);
    let quantile = |p: f64| {
        if rtts.is_empty() {
            None
        } else {
            Some(rtts[((rtts.len() - 1) as f64 * p).ceil() as usize])
        }
    };
    let useful = arrivals
        .values()
        .filter(|r| **r <= deadline_ms as f64)
        .count();
    println!(
        "{}",
        serde_json::to_string(&ProbeResult {
            sent,
            received: arrivals.len(),
            duplicate: duplicates,
            corrupt,
            deadline_misses: sent as usize - useful,
            p50_ms: quantile(0.50),
            p95_ms: quantile(0.95),
            p99_ms: quantile(0.99),
            useful_bytes: useful * size,
            offered_pps: pps,
            send_span_seconds: sent_times
                .last()
                .unwrap()
                .duration_since(sent_times[0])
                .as_secs_f64(),
            observation_seconds: started.elapsed().as_secs_f64(),
            useful_goodput_bps: (useful * size * 8) as f64 / started.elapsed().as_secs_f64(),
            payload_bytes: size,
            deadline_ms,
            measurement: "echo round-trip; quantiles conditional on receipt; misses include lost and late operations"
        })?
    );
    ensure!(
        corrupt == 0 && duplicates == 0 && !arrivals.is_empty(),
        "probe failed integrity/availability"
    );
    Ok(())
}
