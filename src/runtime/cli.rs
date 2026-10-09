use super::{probe, relay, stats, transport, tunnel};
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

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
        /// BBR is the initial latency/throughput default; Cubic is available for comparison.
        #[arg(long, value_enum, default_value_t = transport::Congestion::default())]
        congestion: transport::Congestion,
        #[command(flatten)]
        stats: stats::Options,
    },
    /// Expose a local UDP port through independently encrypted entrances.
    Client {
        #[arg(long, default_value = "127.0.0.1:7000")]
        listen: SocketAddr,
        #[arg(long = "entrance", required = true)]
        entrances: Vec<SocketAddr>,
        #[arg(long = "interface")]
        interfaces: Vec<String>,
        /// One explicit local UDP bind per interface–entrance pair, in path order.
        #[arg(long = "path-bind")]
        path_binds: Vec<SocketAddr>,
        #[arg(long)]
        server_name: String,
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        token_file: PathBuf,
        #[command(flatten)]
        policy: PolicyArgs,
        /// Select this endpoint's sending controller independently of the peer.
        #[arg(long, value_enum, default_value_t = transport::Congestion::default())]
        congestion: transport::Congestion,
        #[command(flatten)]
        stats: stats::Options,
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
        #[command(flatten)]
        stats: stats::Options,
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
    /// Ordinary UDP echo service; readiness is optionally written as JSON.
    Echo {
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: SocketAddr,
        #[arg(long)]
        ready_file: Option<PathBuf>,
    },
    /// Finite echo or directional UDP workload; emit a machine-readable result.
    Probe(probe::ProbeOptions),
    /// Finite one-peer receiver or reverse source with a shared run identifier.
    Sink(probe::SinkOptions),
}
#[derive(Args)]
struct PolicyArgs {
    /// Shift symbols toward healthier paths while retaining bounded probes.
    #[arg(long)]
    quality_schedule: bool,
    /// Rejoin a persistently bad path with a fresh source port, at most three times.
    #[arg(long, requires = "quality_schedule")]
    rotate_source_port: bool,
    /// Report per-path receiver quality; data scheduling remains round robin.
    #[arg(long)]
    receiver_feedback: bool,
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
            congestion,
            stats,
        } => {
            let reporter = stats::Reporter::new("server", stats)?;
            let result = tunnel::serve(tunnel::ServerOptions {
                stats: reporter.metrics.clone(),
                bind: listen,
                cert,
                key,
                token: token_file,
                target,
                max_rate: max_rate_bps,
                congestion,
            })
            .await;
            reporter.finish(result).await
        }
        Command::Client {
            listen,
            entrances,
            interfaces,
            path_binds,
            server_name,
            ca,
            token_file,
            policy,
            congestion,
            stats,
        } => {
            let reporter = stats::Reporter::new("client", stats)?;
            let result = tunnel::client(tunnel::ClientOptions {
                stats: reporter.metrics.clone(),
                listen,
                entrances,
                interfaces,
                path_binds,
                name: server_name,
                ca,
                token: token_file,
                congestion,
                rotate_source_port: policy.rotate_source_port,
                policy: tunnel::Policy {
                    fec: policy.fec,
                    receiver_feedback: policy.receiver_feedback || policy.quality_schedule,
                    quality_schedule: policy.quality_schedule,
                    redundancy: policy.redundancy_percent,
                    rate: policy.rate_bps,
                    block_ms: policy.block_ms,
                    queue_ms: policy.queue_ms,
                },
            })
            .await;
            reporter.finish(result).await
        }
        Command::Relay {
            listen,
            target,
            allow,
            rate_bps,
            drop_every,
            stats,
        } => {
            let reporter = stats::Reporter::new("relay", stats)?;
            let result = relay::run(relay::Options {
                stats: reporter.metrics.clone(),
                listen,
                target,
                allow,
                rate: rate_bps,
                drop_every,
            })
            .await;
            reporter.finish(result).await
        }
        Command::Get {
            entrance,
            server_name,
            ca,
        } => {
            println!("{}", tunnel::get(entrance, &server_name, &ca).await?);
            Ok(())
        }
        Command::Echo { listen, ready_file } => probe::echo(listen, ready_file).await,
        Command::Probe(options) => probe::run_probe(options).await,
        Command::Sink(options) => probe::run_sink(options).await,
    }
}
