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

#[cfg(test)]
mod ack_request_tests {
    use super::*;
    #[test]
    fn server_ack_request_defaults_to_every_eight_and_rejects_unregistered_profiles() {
        let base = [
            "braidpath",
            "server",
            "--listen",
            "127.0.0.1:7001",
            "--cert",
            "cert",
            "--key",
            "key",
            "--token-file",
            "token",
            "--target",
            "127.0.0.1:7002",
        ];
        let parsed = Cli::try_parse_from(base).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Server {
                ack_request: transport::AckRequest::EveryEight,
                ..
            }
        ));
        for (name, expected) in [
            ("unchanged", transport::AckRequest::Unchanged),
            ("every-two", transport::AckRequest::EveryTwo),
            ("every-eight", transport::AckRequest::EveryEight),
        ] {
            let parsed =
                Cli::try_parse_from(base.into_iter().chain(["--ack-request", name])).unwrap();
            let Command::Server { ack_request, .. } = parsed.command else {
                panic!("server expected")
            };
            assert_eq!(ack_request, expected);
        }
        assert!(Cli::try_parse_from(base.into_iter().chain(["--ack-request", "no-acks"])).is_err());
    }
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
    /// Serve a website and authenticated sessions to configured UDP/TCP targets.
    Server {
        /// Experimental server-to-peer ACK request. Does not change native BBR,
        /// recovery, or the client's request policy; default remains unchanged.
        #[arg(long, value_enum, default_value_t = transport::AckRequest::EveryEight)]
        ack_request: transport::AckRequest,
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        token_file: PathBuf,
        /// UDP destination for datagram flows.
        #[arg(long, required_unless_present_any = ["tcp_target", "proxy"])]
        target: Option<SocketAddr>,
        /// TCP destination; each client TCP connection becomes one reliable stream.
        #[arg(long)]
        tcp_target: Option<SocketAddr>,
        /// Connect streams from client proxy entrances (SOCKS5, HTTP CONNECT) to
        /// the destination each one names. Names resolve here; only globally
        /// routable unicast addresses are permitted.
        #[arg(long)]
        proxy: bool,
        /// Also permit loopback, private, link-local and shared address ranges.
        #[arg(long, requires = "proxy")]
        proxy_allow_private: bool,
        /// Session sender cap in bits/s; `auto` defers to the client's request.
        #[arg(long, default_value = "auto", value_parser = parse_rate_cap)]
        max_rate_bps: RateCap,
        /// Outgoing Quinn buffer for reverse traffic; bytes include metadata.
        /// Controlled measurements only; this does not bound residence time.
        #[arg(long, default_value_t = 1200, value_parser = clap::value_parser!(u32).range(1200..=76_800))]
        datagram_send_buffer_bytes: u32,
        /// BBR is the supported sending controller.
        #[arg(long, value_enum, default_value_t = transport::Congestion::default())]
        congestion: transport::Congestion,
        /// Adapt local FEC state retention to observed arrival skew (50..250 ms).
        /// Does not change sender queue limits or delay original delivery.
        #[arg(long)]
        adaptive_fec_retention: bool,
        #[command(flatten)]
        stats: stats::Options,
    },
    /// Expose local UDP and optional TCP ports through independently encrypted entrances.
    Client {
        #[arg(long, default_value = "127.0.0.1:7000")]
        listen: SocketAddr,
        /// Accept local TCP connections and carry each as one reliable stream
        /// over all paths. The server must configure --tcp-target.
        #[arg(long)]
        tcp_listen: Option<SocketAddr>,
        /// Accept SOCKS5 CONNECT and HTTP CONNECT on one local port; the server
        /// must enable --proxy. Without authentication: keep it on loopback.
        #[arg(long)]
        proxy_listen: Option<SocketAddr>,
        #[arg(long = "entrance", required = true)]
        entrances: Vec<SocketAddr>,
        /// Linux interface name, or macOS ifindex:<nonzero index>.
        #[arg(long = "interface")]
        interfaces: Vec<String>,
        /// One explicit local UDP bind per interface–entrance pair, in path order.
        #[arg(long = "path-bind")]
        path_binds: Vec<SocketAddr>,
        /// Outgoing Quinn buffer bytes, including metadata; does not bound residence time.
        /// Override only for controlled measurements; normal operation defaults to 1200.
        #[arg(long, default_value_t = 1200, value_parser = clap::value_parser!(u32).range(1200..=76_800))]
        datagram_send_buffer_bytes: u32,
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
        /// Adapt local FEC state retention to observed arrival skew (50..250 ms).
        /// Does not change sender queue limits or delay original delivery.
        #[arg(long)]
        adaptive_fec_retention: bool,
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

#[cfg(test)]
mod dual_cli_tests {
    use super::*;
    #[test]
    fn repair_cli_defaults_to_auto_and_invalid_counts_are_rejected() {
        let base = [
            "braidpath",
            "client",
            "--entrance",
            "127.0.0.1:7001",
            "--server-name",
            "localhost",
            "--ca",
            "cert.pem",
            "--token-file",
            "token",
        ];
        let parsed = Cli::try_parse_from(base).unwrap();
        let Command::Client { policy, .. } = parsed.command else {
            panic!("client")
        };
        assert_eq!(policy.fec_repairs, 1);
        assert_eq!(policy.fec, super::super::automatic_fec::AUTO);
        for value in ["auto", "0", "4", "16", "32"] {
            assert!(Cli::try_parse_from(base.into_iter().chain(["--fec", value])).is_ok());
        }
        for value in ["33", "255", "-1", "unknown"] {
            assert!(Cli::try_parse_from(base.into_iter().chain(["--fec", value])).is_err());
        }
        for value in ["0", "3", "255"] {
            assert!(Cli::try_parse_from(base.into_iter().chain(["--fec-repairs", value])).is_err());
        }
        let parsed = Cli::try_parse_from(base.into_iter().chain([
            "--fec-repairs",
            "2",
            "--mixed-fec",
            "--small-fec-bytes",
            "128",
            "--fec",
            "16",
        ]))
        .unwrap();
        let Command::Client { policy, .. } = parsed.command else {
            panic!("client")
        };
        assert_eq!(policy.fec_repairs, 2);
        assert!(policy.mixed_fec);
    }
}
#[derive(Args)]
struct PolicyArgs {
    /// Adapt path pacing and eligibility to queue growth; automatically recover paths.
    #[arg(long)]
    adaptive: bool,
    /// Independent delivery samples; off by default, capped at 5% with adaptive FEC0.
    #[arg(long, default_value_t = 0)]
    capacity_probe_bps: u64,
    /// Recover cautiously using independent delivery samples; requires original-only probes.
    #[arg(long)]
    probe_guided_recovery: bool,
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
    /// Automatic pre-FEC loss adaptation from no repair to 4+1; a numeric value fixes k.
    #[arg(long, default_value = "auto", value_parser = tunnel::parse_fec)]
    fec: u8,
    /// Independent bulk repair equations. Two requires --mixed-fec; small records still use one copy.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=2))]
    fec_repairs: u8,
    /// Immediate single-record XOR repair cutoff. Use FEC0/redundancy0, or explicit --mixed-fec.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u16).range(0..=1000))]
    small_fec_bytes: u16,
    /// Combine immediate small-record repair with ordinary FEC for larger records.
    /// Redundancy-percent limits large-record repair; every small original permits one repair.
    #[arg(long)]
    mixed_fec: bool,
    #[arg(long, default_value_t = 30)]
    redundancy_percent: u8,
    /// Aggregate cap in bits/s. `auto` (requires --adaptive) sets no operator
    /// cap below the validated maximum; per-path control finds the pace.
    /// Defaults to `auto` with --adaptive and 10000000 otherwise.
    #[arg(long, value_parser = parse_rate_cap)]
    rate_bps: Option<RateCap>,
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
            ack_request,
            listen,
            cert,
            key,
            token_file,
            target,
            tcp_target,
            proxy,
            proxy_allow_private,
            max_rate_bps,
            datagram_send_buffer_bytes,
            congestion,
            adaptive_fec_retention,
            stats,
        } => {
            let reporter = stats::Reporter::new("server", stats)?;
            let result = tunnel::serve_with_ack_request(
                tunnel::ServerOptions {
                    stats: reporter.metrics.clone(),
                    adaptive_fec_retention,
                    bind: listen,
                    cert,
                    key,
                    token: token_file,
                    target,
                    tcp_target,
                    proxy: proxy.then_some(tunnel::ProxyAccess {
                        allow_private: proxy_allow_private,
                    }),
                    max_rate: max_rate_bps.bps(),
                    datagram_send_buffer_bytes: datagram_send_buffer_bytes as usize,
                    congestion,
                },
                ack_request,
            )
            .await;
            reporter.finish(result).await
        }
        Command::Client {
            listen,
            tcp_listen,
            proxy_listen,
            entrances,
            interfaces,
            path_binds,
            datagram_send_buffer_bytes,
            path_groups,
            server_name,
            ca,
            token_file,
            policy,
            congestion,
            adaptive_fec_retention,
            stats,
        } => {
            let rate = client_rate(&policy)?;
            let reporter = stats::Reporter::new("client", stats)?;
            let group_rates = parse_group_rates(&policy.group_rates, rate)?;
            let result = tunnel::client(tunnel::ClientOptions {
                stats: reporter.metrics.clone(),
                adaptive_fec_retention,
                listen,
                tcp_listen,
                proxy_listen,
                entrances,
                interfaces,
                path_binds,
                datagram_send_buffer_bytes: datagram_send_buffer_bytes as usize,
                path_groups,
                name: server_name,
                ca,
                token: token_file,
                congestion,
                rotate_source_port: policy.rotate_source_port,
                policy: tunnel::Policy {
                    streams: tcp_listen.is_some(),
                    proxy: proxy_listen.is_some(),
                    adaptive: policy.adaptive,
                    capacity_probe_bps: policy.capacity_probe_bps,
                    probe_guided_recovery: policy.probe_guided_recovery,
                    latency_target_ms: policy.latency_target_ms,
                    group_rates,
                    fec: policy.fec,
                    fec_repairs: policy.fec_repairs,
                    small_fec_bytes: policy.small_fec_bytes,
                    mixed_fec: policy.mixed_fec,
                    receiver_feedback: policy.receiver_feedback
                        || policy.quality_schedule
                        || policy.adaptive
                        || policy.fec == super::automatic_fec::AUTO,
                    quality_schedule: policy.quality_schedule || policy.adaptive,
                    redundancy: policy.redundancy_percent,
                    rate,
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

/// The validated session maximum, used when no explicit cap is configured.
const AUTO_RATE_BPS: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RateCap {
    Bps(u64),
    Auto,
}

impl RateCap {
    fn bps(self) -> u64 {
        match self {
            Self::Bps(rate) => rate,
            Self::Auto => AUTO_RATE_BPS,
        }
    }
}

/// Fixed-pace (non-adaptive) sessions keep the historical explicit default.
const FIXED_RATE_BPS: u64 = 10_000_000;

fn client_rate(policy: &PolicyArgs) -> Result<u64> {
    let rate = policy.rate_bps.unwrap_or(if policy.adaptive {
        RateCap::Auto
    } else {
        RateCap::Bps(FIXED_RATE_BPS)
    });
    ensure!(
        policy.adaptive || rate != RateCap::Auto,
        "--rate-bps auto requires --adaptive; otherwise the cap is the sending pace"
    );
    Ok(rate.bps())
}

fn parse_rate_cap(value: &str) -> std::result::Result<RateCap, String> {
    if value == "auto" {
        return Ok(RateCap::Auto);
    }
    value
        .parse()
        .map(RateCap::Bps)
        .map_err(|_| "expected bits per second or auto".into())
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
    fn receiver_retention_opt_in_is_local_and_preserves_sender_policy() {
        let client = [
            "braidpath",
            "client",
            "--entrance",
            "127.0.0.1:4433",
            "--server-name",
            "localhost",
            "--ca",
            "cert.pem",
            "--token-file",
            "token",
        ];
        let Command::Client {
            policy,
            adaptive_fec_retention,
            ..
        } = Cli::try_parse_from(client).unwrap().command
        else {
            unreachable!()
        };
        assert!(!adaptive_fec_retention);
        assert_eq!(policy.queue_ms, 100);
        let Command::Client {
            policy,
            adaptive_fec_retention,
            ..
        } = Cli::try_parse_from(client.into_iter().chain([
            "--adaptive-fec-retention",
            "--queue-ms",
            "17",
        ]))
        .unwrap()
        .command
        else {
            unreachable!()
        };
        assert!(adaptive_fec_retention);
        assert_eq!(policy.queue_ms, 17);
        let server = [
            "braidpath",
            "server",
            "--listen",
            "127.0.0.1:4433",
            "--cert",
            "cert.pem",
            "--key",
            "key.pem",
            "--token-file",
            "token",
            "--target",
            "127.0.0.1:7000",
        ];
        let Command::Server {
            adaptive_fec_retention,
            ..
        } = Cli::try_parse_from(server).unwrap().command
        else {
            unreachable!()
        };
        assert!(!adaptive_fec_retention);
        let Command::Server {
            adaptive_fec_retention,
            ..
        } = Cli::try_parse_from(server.into_iter().chain(["--adaptive-fec-retention"]))
            .unwrap()
            .command
        else {
            unreachable!()
        };
        assert!(adaptive_fec_retention);
    }
    #[test]
    fn mixed_fec_and_nested_packet_trace_flags_preserve_disabled_defaults() {
        let base = [
            "braidpath",
            "client",
            "--entrance",
            "127.0.0.1:4433",
            "--server-name",
            "localhost",
            "--ca",
            "cert.pem",
            "--token-file",
            "token",
        ];
        let cli = Cli::try_parse_from(base).unwrap();
        let Command::Client { policy, stats, .. } = cli.command else {
            unreachable!()
        };
        assert!(!policy.mixed_fec);
        assert_eq!(
            (
                policy.fec,
                policy.small_fec_bytes,
                policy.redundancy_percent
            ),
            (super::super::automatic_fec::AUTO, 0, 30)
        );
        assert!(stats.trace.packet_trace.is_none());
        assert!(!stats.trace.packet_trace_probe_header);
        let extra = [
            "--fec",
            "4",
            "--mixed-fec",
            "--small-fec-bytes",
            "128",
            "--packet-trace",
            "capture.jsonl",
            "--packet-trace-probe-header",
        ];
        let cli = Cli::try_parse_from(base.iter().chain(extra.iter())).unwrap();
        let Command::Client { policy, stats, .. } = cli.command else {
            unreachable!()
        };
        assert!(policy.mixed_fec);
        assert_eq!(
            (
                policy.fec,
                policy.small_fec_bytes,
                policy.redundancy_percent
            ),
            (4, 128, 30)
        );
        assert_eq!(
            stats.trace.packet_trace,
            Some(std::path::PathBuf::from("capture.jsonl"))
        );
        assert!(stats.trace.packet_trace_probe_header);
    }
    #[test]
    fn server_datagram_send_buffer_accepts_explicit_bounded_override() {
        let arguments = [
            "braidpath",
            "server",
            "--listen",
            "127.0.0.1:4433",
            "--cert",
            "cert.pem",
            "--key",
            "key.pem",
            "--token-file",
            "token",
            "--target",
            "127.0.0.1:7001",
        ];
        let parse_size = |extra: &[&str]| {
            Cli::try_parse_from(arguments.iter().chain(extra)).map(|cli| match cli.command {
                Command::Server {
                    datagram_send_buffer_bytes,
                    ..
                } => datagram_send_buffer_bytes,
                _ => unreachable!(),
            })
        };
        assert_eq!(parse_size(&[]).unwrap(), 1200);
        for size in ["1200", "9600", "38400", "76800"] {
            assert_eq!(
                parse_size(&["--datagram-send-buffer-bytes", size]).unwrap(),
                size.parse::<u32>().unwrap()
            );
        }
        for size in ["0", "1199", "76801", "4294967296"] {
            assert!(parse_size(&["--datagram-send-buffer-bytes", size]).is_err());
        }
    }

    #[test]
    fn small_fec_bytes_explicit_flag_keeps_bulk_fec_zero() {
        let cli = Cli::try_parse_from([
            "braidpath",
            "client",
            "--entrance",
            "127.0.0.1:4433",
            "--server-name",
            "localhost",
            "--ca",
            "cert.pem",
            "--token-file",
            "token",
            "--fec",
            "0",
            "--small-fec-bytes",
            "128",
        ])
        .expect("bounded small-record repair flag should parse");
        match cli.command {
            Command::Client { policy, .. } => {
                assert_eq!(policy.fec, 0);
                assert_eq!(policy.small_fec_bytes, 128);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn small_fec_bytes_defaults_off_and_rejects_out_of_range_thresholds() {
        let arguments = [
            "braidpath",
            "client",
            "--entrance",
            "127.0.0.1:4433",
            "--server-name",
            "localhost",
            "--ca",
            "cert.pem",
            "--token-file",
            "token",
        ];
        let parse_threshold = |extra: &[&str]| {
            Cli::try_parse_from(arguments.iter().chain(extra)).map(|cli| match cli.command {
                Command::Client { policy, .. } => policy.small_fec_bytes,
                _ => unreachable!(),
            })
        };
        assert_eq!(parse_threshold(&[]).unwrap(), 0);
        for threshold in ["0", "1", "128", "1000"] {
            assert_eq!(
                parse_threshold(&["--small-fec-bytes", threshold]).unwrap(),
                threshold.parse::<u16>().unwrap()
            );
        }
        for threshold in ["-1", "1001", "65535", "65536"] {
            assert!(parse_threshold(&["--small-fec-bytes", threshold]).is_err());
        }
    }

    #[test]
    fn client_datagram_send_buffer_defaults_and_explicit_bounds() {
        let arguments = [
            "braidpath",
            "client",
            "--entrance",
            "127.0.0.1:4433",
            "--server-name",
            "localhost",
            "--ca",
            "cert.pem",
            "--token-file",
            "token",
        ];
        let parse_size = |extra: &[&str]| {
            let parsed = Cli::try_parse_from(arguments.iter().chain(extra));
            parsed.map(|cli| match cli.command {
                Command::Client {
                    datagram_send_buffer_bytes,
                    ..
                } => datagram_send_buffer_bytes,
                _ => unreachable!(),
            })
        };
        assert_eq!(parse_size(&[]).unwrap(), 1200);
        for size in ["1200", "9600", "38400", "76800"] {
            assert_eq!(
                parse_size(&["--datagram-send-buffer-bytes", size]).unwrap(),
                size.parse::<u32>().unwrap()
            );
        }
        for size in ["0", "1199", "76801", "4294967296"] {
            assert!(parse_size(&["--datagram-send-buffer-bytes", size]).is_err());
        }
    }

    #[test]
    fn rate_cap_defaults_to_auto_only_for_adaptive_sessions() {
        let client = [
            "braidpath",
            "client",
            "--entrance",
            "127.0.0.1:4433",
            "--server-name",
            "localhost",
            "--ca",
            "cert.pem",
            "--token-file",
            "token",
        ];
        let rate = |extra: &[&str]| match Cli::try_parse_from(client.iter().chain(extra))
            .unwrap()
            .command
        {
            Command::Client { policy, .. } => client_rate(&policy),
            _ => unreachable!(),
        };
        assert_eq!(rate(&[]).unwrap(), FIXED_RATE_BPS);
        assert_eq!(rate(&["--adaptive"]).unwrap(), AUTO_RATE_BPS);
        assert_eq!(
            rate(&["--adaptive", "--rate-bps", "400000000"]).unwrap(),
            400_000_000
        );
        assert_eq!(rate(&["--rate-bps", "400000000"]).unwrap(), 400_000_000);
        assert_eq!(
            rate(&["--adaptive", "--rate-bps", "auto"]).unwrap(),
            AUTO_RATE_BPS
        );
        // Without adaptive control the cap is the pace, so `auto` is rejected.
        assert!(rate(&["--rate-bps", "auto"]).is_err());
        assert!(Cli::try_parse_from(client.iter().chain(&["--rate-bps", "fast"])).is_err());
        let server = [
            "braidpath",
            "server",
            "--listen",
            "127.0.0.1:4433",
            "--cert",
            "cert.pem",
            "--key",
            "key.pem",
            "--token-file",
            "token",
            "--target",
            "127.0.0.1:7000",
        ];
        let maximum = |extra: &[&str]| match Cli::try_parse_from(server.iter().chain(extra))
            .unwrap()
            .command
        {
            Command::Server { max_rate_bps, .. } => max_rate_bps.bps(),
            _ => unreachable!(),
        };
        assert_eq!(maximum(&[]), AUTO_RATE_BPS);
        assert_eq!(maximum(&["--max-rate-bps", "8000000"]), 8_000_000);
    }

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
