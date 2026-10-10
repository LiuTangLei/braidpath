use super::{probe, relay, stats, transport, tunnel};
use anyhow::{Context, Result, ensure};
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
        /// BBR is the supported sending controller.
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
        /// Bottleneck group per interface–entrance pair; defaults to interface index.
        #[arg(long = "path-group")]
        path_groups: Vec<u8>,
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
    /// Adapt path pacing and eligibility to queue growth; automatically recover paths.
    #[arg(long)]
    adaptive: bool,
    /// Independent delivery samples; off by default, capped at 5% with adaptive FEC0.
    #[arg(long, default_value_t = 0)]
    capacity_probe_bps: u64,
    /// Budget for additional local/path queuing, not unavoidable propagation RTT.
    #[arg(long, default_value_t = 20)]
    latency_target_ms: u64,
    /// Explicit shared bottleneck cap, GROUP:BITS_PER_SECOND. Repeated groups are rejected.
    #[arg(long = "group-rate-bps")]
    group_rates: Vec<String>,
    /// Shift symbols toward healthier paths while retaining bounded probes.
    #[arg(long)]
    quality_schedule: bool,
    /// Rejoin persistent forward degradation with a fresh port and bounded cooldown.
    #[arg(long)]
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
            path_groups,
            server_name,
            ca,
            token_file,
            policy,
            congestion,
            stats,
        } => {
            let reporter = stats::Reporter::new("client", stats)?;
            let group_rates = parse_group_rates(&policy.group_rates, policy.rate_bps)?;
            let result = tunnel::client(tunnel::ClientOptions {
                stats: reporter.metrics.clone(),
                listen,
                entrances,
                interfaces,
                path_binds,
                path_groups,
                name: server_name,
                ca,
                token: token_file,
                congestion,
                rotate_source_port: policy.rotate_source_port,
                policy: tunnel::Policy {
                    adaptive: policy.adaptive,
                    capacity_probe_bps: policy.capacity_probe_bps,
                    latency_target_ms: policy.latency_target_ms,
                    group_rates,
                    fec: policy.fec,
                    receiver_feedback: policy.receiver_feedback
                        || policy.quality_schedule
                        || policy.adaptive,
                    quality_schedule: policy.quality_schedule || policy.adaptive,
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

fn parse_group_rates(values: &[String], aggregate: u64) -> Result<[u64; super::MAX_PATHS]> {
    let mut rates = [aggregate; super::MAX_PATHS];
    let mut seen = [false; super::MAX_PATHS];
    for value in values {
        let (group, rate) = value
            .split_once(':')
            .context("group rate must be GROUP:BITS_PER_SECOND")?;
        let group: usize = group.parse()?;
        let rate: u64 = rate.parse()?;
        ensure!(
            group < super::MAX_PATHS && !seen[group],
            "invalid or duplicate bottleneck group"
        );
        ensure!(
            (64_000..=aggregate).contains(&rate),
            "group rate exceeds aggregate cap or is below 64000 bps"
        );
        seen[group] = true;
        rates[group] = rate;
    }
    Ok(rates)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_bottleneck_caps_are_bounded_and_unambiguous() {
        assert_eq!(
            parse_group_rates(&["0:1000000".into()], 2000000).unwrap()[0],
            1000000
        );
        for values in [
            vec!["8:1000000".into()],
            vec!["0:3000000".into()],
            vec!["0:1000000".into(), "0:900000".into()],
        ] {
            assert!(parse_group_rates(&values, 2000000).is_err());
        }
        assert!(Cli::try_parse_from(["braidpath", "server", "--congestion", "cubic"]).is_err());
    }
}
