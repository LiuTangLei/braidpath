use super::{mesh, probe, proxy, relay, stats, transport, tunnel};
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
mod proxy_cli_tests {
    use super::*;
    #[test]
    fn server_can_offer_proxy_tunnel_or_both_and_client_can_select_multiple_exits() {
        let base = [
            "braidpath",
            "mesh-server",
            "--dir",
            "state",
            "--id",
            "a",
            "--listen",
            "127.0.0.1:4433",
            "--advertise",
            "127.0.0.1:4433",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        assert!(Cli::try_parse_from(base.into_iter().chain(["--proxy"])).is_ok());
        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--target", "127.0.0.1:9000"])).is_ok()
        );
        assert!(
            Cli::try_parse_from(
                base.into_iter()
                    .chain(["--proxy", "--target", "127.0.0.1:9000"])
            )
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(base.into_iter().chain([
                "--target",
                "127.0.0.1:9000",
                "--proxy-allow-private"
            ]))
            .is_err()
        );
        let client = [
            "braidpath",
            "proxy-client",
            "--connect",
            "127.0.0.1:4433",
            "--connection-key",
            "key",
            "--dir",
            "client",
            "--exit",
            "a",
            "--exit",
            "b",
            "--socks5",
            "a=127.0.0.1:2080",
        ];
        for (args, wait) in [(&[][..], false), (&["--socks5-wait-for-connect"][..], true)] {
            let parsed =
                Cli::try_parse_from(client.into_iter().chain(args.iter().copied())).unwrap();
            assert!(matches!(
                parsed.command,
                Command::ProxyClient { socks5_wait_for_connect, .. } if socks5_wait_for_connect == wait
            ));
        }
        let parsed = Cli::try_parse_from(client.into_iter().chain([
            "--game-exit",
            "a",
            "--game-listen",
            "127.0.0.1:1090",
            "--game-socks5",
            "c=127.0.0.1:1091",
        ]))
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::ProxyClient { game_exit, game_listen, game_socks5, .. }
            if game_exit == ["a"] && game_listen.port() == 1090
                && game_socks5.len() == 1 && game_socks5[0].exit == "c"
        ));
        for flag in [
            &["--game-mode"][..],
            &["--game-mode", "on"][..],
            &["--native-return-stream"][..],
        ] {
            assert!(Cli::try_parse_from(client.into_iter().chain(flag.iter().copied())).is_err());
        }
        assert!(
            Cli::try_parse_from(client.into_iter().chain(["--ordered-udp-port", "4500"])).is_err()
        );
        let parsed = Cli::try_parse_from(
            client
                .into_iter()
                .chain(["--status-socket", "/tmp/bp-proxy.sock"]),
        )
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::ProxyClient {
                status_socket: Some(ref path),
                ..
            } if path == std::path::Path::new("/tmp/bp-proxy.sock")
        ));
        let parsed =
            Cli::try_parse_from(["braidpath", "client-status", "--socket", "/tmp/bp.sock"])
                .unwrap();
        assert!(matches!(
            parsed.command,
            Command::ClientStatus { ref socket } if socket == std::path::Path::new("/tmp/bp.sock")
        ));
        let parsed =
            Cli::try_parse_from(client.into_iter().chain(["--interface", "ifindex:6"])).unwrap();
        assert!(
            matches!(parsed.command, Command::ProxyClient { interface: Some(ref name), .. } if name == "ifindex:6")
        );
        assert!(
            Cli::try_parse_from(client.into_iter().chain(["--socks5", "b=0.0.0.0:1082"])).is_err()
        );
        let parsed = Cli::try_parse_from(client.into_iter().chain([
            "--tcp-forward",
            "a=127.0.0.1:9443",
            "--tcp-forward",
            "c=127.0.0.1:9444",
        ]))
        .unwrap();
        assert!(
            matches!(parsed.command, Command::ProxyClient { tcp_forward, .. }
            if tcp_forward.len() == 2 && tcp_forward[1].exit == "c")
        );
        assert!(
            Cli::try_parse_from(
                client
                    .into_iter()
                    .chain(["--tcp-forward", "a=0.0.0.0:9443",])
            )
            .is_err()
        );
    }

    #[test]
    fn mesh_fixed_tcp_does_not_require_or_enable_private_proxy_access() {
        let server = [
            "braidpath",
            "mesh-server",
            "--dir",
            "state",
            "--id",
            "a",
            "--listen",
            "127.0.0.1:4433",
            "--advertise",
            "127.0.0.1:4433",
            "--tcp-target",
            "127.0.0.1:8443",
        ];
        let parsed = Cli::try_parse_from(server).unwrap();
        assert!(matches!(
            parsed.command,
            Command::MeshServer {
                tcp_target: Some(_),
                target: None,
                proxy: false,
                proxy_allow_private: false,
                ..
            }
        ));
        assert!(Cli::try_parse_from(server.into_iter().chain(["--proxy-allow-private"])).is_err());
        let parsed = Cli::try_parse_from([
            "braidpath",
            "mesh-client",
            "--connect",
            "127.0.0.1:4433",
            "--connection-key",
            "client-key.json",
            "--dir",
            "client",
            "--exit",
            "b",
            "--tcp-listen",
            "127.0.0.1:9443",
            "--adaptive",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::MeshClient {
                tcp_listen: Some(_),
                ..
            }
        ));
    }
}

#[cfg(test)]
mod ack_request_tests {
    use super::*;
    #[test]
    fn server_ack_request_preserves_default_and_rejects_unregistered_profiles() {
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
                ack_request: transport::AckRequest::Unchanged,
                ..
            }
        ));
        for (name, expected) in [
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
    /// Run an equal mesh server; a fresh directory creates cluster keys automatically.
    MeshServer {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        listen: SocketAddr,
        /// Reachable address, with the same UDP port exposed by --listen.
        #[arg(long)]
        advertise: SocketAddr,
        /// Public endpoint of the other address family on the same UDP port.
        #[arg(long, requires = "advertise")]
        advertise_alternate: Option<SocketAddr>,
        /// Relay UDP port or inclusive range (up to 1024 ports); otherwise OS-assigned.
        #[arg(long)]
        relay_ports: Option<mesh::RelayPorts>,
        /// Fixed UDP destination for datagram flows.
        #[arg(long, required_unless_present_any = ["tcp_target", "proxy"])]
        target: Option<SocketAddr>,
        /// Fixed TCP destination; clients cannot select another destination.
        #[arg(long)]
        tcp_target: Option<SocketAddr>,
        /// Enable authenticated TCP/UDP proxy egress on the same QUIC port.
        #[arg(long)]
        proxy: bool,
        /// Allow proxy destinations on private/loopback networks (trusted clients only).
        #[arg(long, requires = "proxy")]
        proxy_allow_private: bool,
        /// Any existing member; persisted peers remain usable if this entry is down.
        #[arg(long)]
        join: Option<SocketAddr>,
        #[arg(long, requires = "join")]
        join_key: Option<PathBuf>,
        #[arg(long, default_value = "auto", value_parser = parse_rate_cap)]
        max_rate_bps: RateCap,
        #[command(flatten)]
        stats: stats::Options,
    },
    /// Offer per-exit SOCKS5 TCP/UDP and fixed-target TCP listeners in one process.
    ProxyClient {
        #[arg(long, required = true)]
        connect: Vec<SocketAddr>,
        #[arg(long)]
        connection_key: PathBuf,
        #[arg(long)]
        dir: PathBuf,
        /// Repeat to select ordinary SOCKS5 exits in listener order.
        #[arg(long)]
        exit: Vec<String>,
        /// Base loopback address; successive exits use successive ports (1080, 1081, ...).
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
        /// Set an ordinary SOCKS5 listener explicitly, EXIT=127.0.0.1:PORT.
        #[arg(long)]
        socks5: Vec<proxy::Listener>,
        /// Repeat to select Game SOCKS5 exits in listener order.
        #[arg(long)]
        game_exit: Vec<String>,
        /// Base loopback address for consecutive Game SOCKS5 listeners.
        #[arg(long, default_value = "127.0.0.1:1090")]
        game_listen: SocketAddr,
        /// Set a Game SOCKS5 listener explicitly, EXIT=127.0.0.1:PORT.
        #[arg(long)]
        game_socks5: Vec<proxy::Listener>,
        /// Forward loopback TCP to an exit's fixed --tcp-target, EXIT=127.0.0.1:PORT.
        #[arg(long)]
        tcp_forward: Vec<proxy::Listener>,
        /// Maximum server paths cooperating on each TCP connection (1..8).
        #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u8).range(1..=8))]
        paths: u8,
        /// Bind all proxy data paths to an uplink (Linux name; macOS ifindex:N).
        #[arg(long)]
        interface: Option<String>,
        /// Wait for the exit's CONNECT result on ordinary SOCKS5 listeners.
        #[arg(long)]
        socks5_wait_for_connect: bool,
        /// Wait for the exit's CONNECT result on Game SOCKS5 listeners.
        #[arg(long)]
        game_socks5_wait_for_connect: bool,
        /// Optional local Unix socket for on-demand read-only JSON status queries.
        #[arg(long)]
        status_socket: Option<PathBuf>,
    },
    /// Discover live distributed servers through any member using a client key.
    Nodes {
        /// Repeat for multiple bootstrap servers; saved members are fallback entries.
        #[arg(long, required = true)]
        connect: Vec<SocketAddr>,
        #[arg(long)]
        connection_key: PathBuf,
        #[arg(long)]
        dir: PathBuf,
    },
    /// Read authenticated server health, resource occupancy and capabilities as JSON.
    MeshStatus {
        #[arg(long)]
        connect: SocketAddr,
        #[arg(long)]
        connection_key: PathBuf,
        #[arg(long)]
        dir: PathBuf,
    },
    /// Read live local client paths, queues and stream occupancy from a --status-socket.
    ClientStatus {
        #[arg(long)]
        socket: PathBuf,
    },
    /// Select an exit and automatically use the other servers as encrypted entrances.
    MeshClient {
        /// Repeat for multiple bootstrap servers; saved members are fallback entries.
        #[arg(long, required = true)]
        connect: Vec<SocketAddr>,
        #[arg(long)]
        connection_key: PathBuf,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        exit: String,
        #[arg(long, default_value = "127.0.0.1:7000")]
        listen: SocketAddr,
        /// Forward local TCP connections to the selected exit's fixed --tcp-target.
        #[arg(long)]
        tcp_listen: Option<SocketAddr>,
        /// Linux uplink interface; repeat for independent networks.
        #[arg(long = "interface")]
        interfaces: Vec<String>,
        /// Local source IP per uplink, also used by its control connections.
        #[arg(long = "source-ip")]
        source_ips: Vec<std::net::IpAddr>,
        #[command(flatten)]
        policy: PolicyArgs,
        #[command(flatten)]
        stats: stats::Options,
        /// Optional local Unix socket for on-demand read-only JSON status queries.
        #[arg(long)]
        status_socket: Option<PathBuf>,
    },
    /// Serve authenticated UDP sessions and optional addressed TCP streams.
    Server {
        /// Experimental server-to-peer ACK request. Does not change native BBR,
        /// recovery, or the client's request policy; default remains unchanged.
        #[arg(long, value_enum, default_value_t = transport::AckRequest::Unchanged)]
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
        /// Ceiling of Quinn's outgoing datagram buffer, bytes including metadata.
        /// Each path fills it with at most 1 ms of its pace; 1200 keeps one datagram.
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
        /// Ceiling of Quinn's outgoing datagram buffer, bytes including metadata.
        /// Each path fills it with at most 1 ms of its pace; 1200 keeps one datagram.
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
    fn repair_cli_defaults_are_legacy_and_invalid_counts_are_rejected() {
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
    /// Prefer low UDP delay: earliest-ready paths, immediate bounded protection,
    /// adaptive pacing, a 10 ms UDP target and a separate TCP admission budget of at least 80 ms.
    #[arg(long, conflicts_with_all = ["fec", "fec_repairs", "small_fec_bytes", "mixed_fec", "latency_target_ms", "queue_ms", "block_ms", "capacity_probe_bps", "probe_guided_recovery"])]
    game_mode: bool,
    /// Use a negotiated reliable QUIC stream for TCP downloads; uploads and UDP stay unchanged.
    #[arg(long)]
    native_return_stream: bool,
    /// Maximum UDP application message; larger messages use bounded fragmentation.
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u16).range(1000..=4096))]
    max_message_bytes: u16,
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
    #[arg(long, default_value = "4", value_parser = tunnel::parse_fec)]
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
    /// Aggregate cap in bits/s. `auto` requires --adaptive or --game-mode.
    /// Standalone Game defaults to 10000000. Mixed Game and other adaptive
    /// sessions default to `auto`.
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
        Command::MeshServer {
            dir,
            id,
            listen,
            advertise,
            advertise_alternate,
            relay_ports,
            target,
            tcp_target,
            proxy,
            proxy_allow_private,
            join,
            join_key,
            max_rate_bps,
            stats,
        } => {
            if let Some(alternate) = advertise_alternate {
                mesh::validate_public_dual_stack(advertise, alternate)?;
            }
            let reporter = stats::Reporter::new("mesh-server", stats)?;
            let result = mesh::serve(mesh::ServerOptions {
                dir,
                id,
                listen,
                advertise,
                advertise_alternate,
                relay_ports,
                target,
                tcp_target,
                proxy: proxy.then_some(proxy::ServerConfig {
                    allow_private: proxy_allow_private,
                }),
                join,
                join_key,
                rate: max_rate_bps.bps(),
                stats: reporter.metrics.clone(),
            })
            .await;
            reporter.finish(result).await
        }
        Command::ProxyClient {
            connect,
            connection_key,
            dir,
            exit,
            listen,
            socks5,
            game_exit,
            game_listen,
            game_socks5,
            tcp_forward,
            paths,
            interface,
            socks5_wait_for_connect,
            game_socks5_wait_for_connect,
            status_socket,
        } => {
            let identity = mesh::ClientIdentity::open(dir, &connection_key)?;
            proxy::client(proxy::ClientOptions {
                identity,
                connect,
                exits: exit,
                listen,
                socks5,
                game_exits: game_exit,
                game_listen,
                game_socks5,
                tcp_forward,
                paths: usize::from(paths),
                interface,
                socks5_early_reply: !socks5_wait_for_connect,
                game_socks5_early_reply: !game_socks5_wait_for_connect,
                status_socket,
            })
            .await
        }
        Command::Nodes {
            connect,
            connection_key,
            dir,
        } => {
            let identity = mesh::ClientIdentity::open(dir, &connection_key)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&identity.discover_any(&connect).await?)?
            );
            Ok(())
        }
        Command::MeshStatus {
            connect,
            connection_key,
            dir,
        } => {
            let identity = mesh::ClientIdentity::open(dir, &connection_key)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&identity.status(connect).await?)?
            );
            Ok(())
        }
        Command::ClientStatus { socket } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&super::status_socket::query(&socket).await?)?
            );
            Ok(())
        }
        Command::MeshClient {
            connect,
            connection_key,
            dir,
            exit,
            listen,
            tcp_listen,
            interfaces,
            source_ips,
            policy,
            stats,
            status_socket,
        } => {
            ensure!(
                !connect.is_empty() && connect.len() <= 32,
                "provide 1..32 discovery entries"
            );
            let rate = client_rate(&policy)?;
            let group_rates = parse_group_rates(&policy.group_rates, rate)?;
            let mut session_policy = policy.build(rate, group_rates);
            session_policy.streams = tcp_listen.is_some();
            session_policy.validate()?;
            let identity = mesh::ClientIdentity::open(dir, &connection_key)?;
            let count = interfaces.len().max(source_ips.len()).max(1);
            ensure!(
                interfaces.is_empty()
                    || source_ips.is_empty()
                    || interfaces.len() == source_ips.len(),
                "interface and source-ip counts must match"
            );
            ensure!(count <= super::MAX_PATHS, "uplink count must be 1..8");
            let uplinks: Vec<_> = (0..count)
                .map(|i| mesh::Uplink {
                    interface: interfaces.get(i).cloned(),
                    bind: source_ips.get(i).copied(),
                    group: i as u8,
                })
                .collect();
            let reporter = stats::Reporter::new("mesh-client", stats)?;
            // Bind local UDP/TCP listeners before bootstrap discovery so cold
            // boots and WAN outages keep local ports bound and never crash-loop.
            let bound_udp = std::sync::Arc::new(tokio::net::UdpSocket::bind(listen).await?);
            let bound_tcp = if let Some(address) = tcp_listen {
                let listener = std::sync::Arc::new(tokio::net::TcpListener::bind(address).await?);
                tracing::info!(listen=%listener.local_addr()?, "TCP listener bound");
                if !address.ip().is_loopback() {
                    tracing::warn!(
                        listen = %address,
                        "TCP listener is not on loopback; it has no authentication"
                    );
                }
                Some(listener)
            } else {
                None
            };
            let _status_guard = if let Some(path) = status_socket {
                let status_metrics = reporter.metrics.clone();
                let status_exit = exit.clone();
                let status_interfaces = interfaces.clone();
                let status_listen = bound_udp.local_addr()?.to_string();
                let status_tcp = bound_tcp
                    .as_ref()
                    .and_then(|l| l.local_addr().ok())
                    .map(|a| a.to_string());
                Some(super::status_socket::spawn(
                    path,
                    std::sync::Arc::new(move || {
                        let iface_info: Vec<_> = status_interfaces
                            .iter()
                            .map(|name| {
                                serde_json::json!({
                                    "name": name,
                                    "ifindex": transport::interface_index(name),
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "schema_version": 1,
                            "role": "mesh-client",
                            "pid": std::process::id(),
                            "exit": status_exit,
                            "listen": status_listen,
                            "tcp_listen": status_tcp,
                            "interfaces": iface_info,
                            "session": super::status_socket::metrics_summary(&status_metrics),
                        })
                    }),
                )?)
            } else {
                None
            };
            let mut shutdown = super::shutdown::Shutdown::new();
            let mut backoff = std::time::Duration::from_secs(1);
            let leases = loop {
                let bootstrap = async {
                    let nodes = identity.discover_on(&connect, &exit, &uplinks).await?;
                    identity
                        .networks_with_metrics(
                            nodes,
                            &exit,
                            uplinks.clone(),
                            reporter.metrics.clone(),
                        )
                        .await
                };
                tokio::select! {
                    biased;
                    _ = shutdown.wait() => return reporter.finish(Ok(())).await,
                    result = bootstrap => match result {
                        Ok(leases) => break leases,
                        Err(error) => {
                            tracing::warn!(
                                %exit,
                                retry_secs = backoff.as_secs(),
                                %error,
                                "mesh bootstrap unavailable; retaining local listeners and retrying"
                            );
                        }
                    }
                }
                tokio::select! {
                    biased;
                    _ = shutdown.wait() => return reporter.finish(Ok(())).await,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(std::time::Duration::from_secs(15));
            };
            let entrances = leases
                .routes()
                .borrow()
                .iter()
                .map(|r| r.address)
                .collect::<Vec<_>>();
            tracing::info!(%exit, paths=entrances.len(), "selected mesh exit and cooperating entrances");
            let result = tunnel::client_with_routes_and_sockets(
                tunnel::ClientOptions {
                    stream_connector: None,
                    listen,
                    tcp_listen: None,
                    proxy_listen: None,
                    entrances,
                    interfaces: vec![],
                    path_binds: vec![],
                    path_groups: vec![],
                    name: identity.name(),
                    ca: identity.dir.join("cert.pem"),
                    token: identity.dir.join("token"),
                    datagram_send_buffer_bytes: transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
                    congestion: transport::Congestion::default(),
                    adaptive_fec_retention: false,
                    rotate_source_port: policy.rotate_source_port,
                    policy: session_policy,
                    stats: reporter.metrics.clone(),
                },
                leases.routes(),
                leases.health(),
                exit,
                bound_udp,
                bound_tcp,
            )
            .await;
            leases.shutdown().await;
            reporter.finish(result).await
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
                    stream_proxy: proxy.then_some(tunnel::ProxyAccess {
                        allow_private: proxy_allow_private,
                    }),
                    proxy: None,
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
            let mut session_policy = policy.build(rate, group_rates);
            session_policy.streams = tcp_listen.is_some();
            session_policy.proxy = proxy_listen.is_some();
            let result = tunnel::client(tunnel::ClientOptions {
                stream_connector: None,
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
                policy: session_policy,
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

/// Operational ceiling used when no explicit cap is configured.
const AUTO_RATE_BPS: u64 = super::MAX_RATE_BPS;

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
    let rate = policy
        .rate_bps
        .unwrap_or(if policy.game_mode && !policy.native_return_stream {
            RateCap::Bps(tunnel::GAME_RATE_BPS)
        } else if policy.adaptive || policy.game_mode {
            RateCap::Auto
        } else {
            RateCap::Bps(FIXED_RATE_BPS)
        });
    ensure!(
        policy.adaptive || policy.game_mode || rate != RateCap::Auto,
        "--rate-bps auto requires --adaptive or --game-mode; otherwise the cap is the sending pace"
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
            (4, 0, 30)
        );
        assert!(stats.trace.packet_trace.is_none());
        assert!(!stats.trace.packet_trace_probe_header);
        let extra = [
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
    fn game_and_adaptive_rate_cap_defaults() {
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
        assert_eq!(rate(&["--game-mode"]).unwrap(), tunnel::GAME_RATE_BPS);
        assert_eq!(
            rate(&["--game-mode", "--native-return-stream"]).unwrap(),
            AUTO_RATE_BPS
        );
        assert_eq!(
            rate(&["--game-mode", "--rate-bps", "auto"]).unwrap(),
            AUTO_RATE_BPS
        );
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
        assert_eq!(maximum(&[]), 10_000_000_000);
        assert_eq!(maximum(&["--max-rate-bps", "10000000000"]), 10_000_000_000);
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

    #[test]
    fn mesh_bootstrap_and_relay_port_options_are_explicit() {
        let nodes = Cli::try_parse_from([
            "braidpath",
            "nodes",
            "--dir",
            "local/client",
            "--connection-key",
            "local/key.json",
            "--connect",
            "127.0.0.1:4433",
            "--connect",
            "127.0.0.1:4434",
        ])
        .unwrap();
        let Command::Nodes { connect, .. } = nodes.command else {
            panic!("wrong command")
        };
        assert_eq!(
            connect,
            vec![
                "127.0.0.1:4433".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:4434".parse().unwrap()
            ]
        );
        let server = [
            "braidpath",
            "mesh-server",
            "--dir",
            "local/node",
            "--id",
            "node",
            "--listen",
            "127.0.0.1:4433",
            "--advertise",
            "127.0.0.1:4433",
            "--target",
            "127.0.0.1:9000",
        ];
        let parsed =
            Cli::try_parse_from(server.iter().chain(&["--relay-ports", "44400-44463"])).unwrap();
        let Command::MeshServer { relay_ports, .. } = parsed.command else {
            panic!("wrong command")
        };
        assert_eq!(relay_ports, Some("44400-44463".parse().unwrap()));
        assert!(Cli::try_parse_from(server.iter().chain(&["--relay-ports", "0"])).is_err());
    }
}

impl PolicyArgs {
    fn build(&self, rate: u64, group_rates: [u64; super::MAX_PATHS]) -> tunnel::Policy {
        let mut policy = tunnel::Policy {
            game_mode: false,
            native_return: self.native_return_stream,
            streams: false,
            proxy: false,
            max_message_bytes: usize::from(self.max_message_bytes),
            adaptive: self.adaptive,
            capacity_probe_bps: self.capacity_probe_bps,
            probe_guided_recovery: self.probe_guided_recovery,
            latency_target_ms: self.latency_target_ms,
            group_rates,
            fec: self.fec,
            fec_repairs: self.fec_repairs,
            small_fec_bytes: self.small_fec_bytes,
            mixed_fec: self.mixed_fec,
            receiver_feedback: self.receiver_feedback
                || self.quality_schedule
                || self.adaptive
                || self.fec == super::automatic_fec::AUTO,
            quality_schedule: self.quality_schedule || self.adaptive,
            redundancy: self.redundancy_percent,
            rate,
            block_ms: self.block_ms,
            queue_ms: self.queue_ms,
        };
        if self.game_mode {
            policy.enable_game();
        }
        policy
    }
}

#[cfg(test)]
mod aggregate_cli_tests {
    use super::*;

    #[test]
    fn game_preset_enables_low_delay_udp_and_preserves_explicit_rate_caps() {
        let args = [
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
            "--game-mode",
            "--rate-bps",
            "8000000",
        ];
        let Command::Client { policy, .. } = Cli::try_parse_from(args).unwrap().command else {
            panic!("client")
        };
        let rate = client_rate(&policy).unwrap();
        let p = policy.build(rate, [rate; super::super::MAX_PATHS]);
        assert!(p.game_mode && p.adaptive && p.receiver_feedback && p.quality_schedule);
        assert!(!p.native_return);
        assert_eq!(p.fec, super::super::automatic_fec::AUTO);
        assert_eq!((p.queue_ms, p.latency_target_ms, p.block_ms), (20, 20, 1));
        assert_eq!(p.rate, 8_000_000);
        assert!(p.validate().is_ok());
        assert!(Cli::try_parse_from(args.into_iter().chain(["--queue-ms", "20"])).is_err());
    }

    #[test]
    fn download_and_game_presets_can_combine_for_both_client_entries() {
        let entries = [
            vec![
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
            ],
            vec![
                "braidpath",
                "mesh-client",
                "--connect",
                "127.0.0.1:7001",
                "--connection-key",
                "key.json",
                "--dir",
                "state",
                "--exit",
                "exit-a",
            ],
        ];
        for entry in entries {
            assert!(Cli::try_parse_from(entry.iter().copied().chain(["--game-mode"])).is_ok());
            assert!(
                Cli::try_parse_from(entry.iter().copied().chain(["--native-return-stream"]))
                    .is_ok()
            );
            assert!(
                Cli::try_parse_from(
                    entry
                        .iter()
                        .copied()
                        .chain(["--game-mode", "--native-return-stream"]),
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn addressed_stream_entry_preserves_defaults_and_accepts_the_historical_profile() {
        let server = [
            "braidpath",
            "server",
            "--listen",
            "127.0.0.1:7001",
            "--cert",
            "cert.pem",
            "--key",
            "key.pem",
            "--token-file",
            "token",
        ];
        assert!(Cli::try_parse_from(server).is_err());
        assert!(Cli::try_parse_from(server.into_iter().chain(["--proxy-allow-private"])).is_err());
        let parsed = Cli::try_parse_from(
            server
                .into_iter()
                .chain(["--proxy", "--proxy-allow-private"]),
        )
        .unwrap();
        let Command::Server {
            target,
            tcp_target,
            proxy,
            proxy_allow_private,
            ack_request,
            datagram_send_buffer_bytes,
            ..
        } = parsed.command
        else {
            panic!("server")
        };
        assert!(target.is_none() && tcp_target.is_none() && proxy && proxy_allow_private);
        assert_eq!(ack_request, transport::AckRequest::Unchanged);
        assert_eq!(datagram_send_buffer_bytes, 1200);

        let client = [
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
        let parsed = Cli::try_parse_from(client.into_iter().chain([
            "--proxy-listen",
            "127.0.0.1:7080",
            "--adaptive",
            "--fec",
            "auto",
            "--rate-bps",
            "auto",
            "--datagram-send-buffer-bytes",
            "76800",
        ]))
        .unwrap();
        let Command::Client {
            tcp_listen,
            proxy_listen,
            policy,
            datagram_send_buffer_bytes,
            ..
        } = parsed.command
        else {
            panic!("client")
        };
        assert!(tcp_listen.is_none() && proxy_listen.is_some());
        assert_eq!(policy.fec, super::super::automatic_fec::AUTO);
        assert_eq!(datagram_send_buffer_bytes, 76_800);
        let rate = client_rate(&policy).unwrap();
        assert_eq!(rate, super::super::MAX_RATE_BPS);
        assert!(
            policy
                .build(rate, [rate; super::super::MAX_PATHS])
                .receiver_feedback
        );
    }
}
