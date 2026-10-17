//! Loopback multipath link emulator for native (non-container) laboratory runs.
//!
//! Each path owns one entrance socket for the client and one upstream socket
//! toward the server. Both directions are an independent FIFO bottleneck with
//! a virtual-clock serializer (IPv4+UDP bytes), one-way propagation delay,
//! seeded random erasure at enqueue and a netem-style packet limit that counts
//! queued and propagating packets. An optional byte-token policer drops excess
//! arrivals without a serialization backlog. JSON lines on stdin change a direction's
//! shape; stdin EOF stops the emulator. Not a WAN model or production relay.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::VecDeque,
    fs,
    io::{BufRead, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    task::JoinSet,
    time::{Instant, MissedTickBehavior, sleep_until},
};
#[path = "support/lab_socket.rs"]
#[allow(dead_code)]
mod lab_socket;

const IP_UDP_BYTES: usize = 28;
const MAX_DATAGRAM: usize = 65_535;
const MAX_PATHS: usize = 8;
const SOCKET_BYTES: usize = 4 * 1024 * 1024;

#[derive(Parser)]
struct Args {
    /// Server address every upstream socket sends to (loopback only).
    #[arg(long)]
    server: SocketAddr,
    /// One path per occurrence: RTT_MS:RATE_MBPS (half the RTT each direction).
    #[arg(long = "path", required = true)]
    paths: Vec<String>,
    #[arg(long, default_value_t = 1024)]
    queue_packets: usize,
    /// Direct-drop token bucket; zero keeps the original FIFO shaper.
    #[arg(long, default_value_t = 0)]
    policer_burst_bytes: usize,
    #[arg(long, default_value_t = 20261016)]
    seed: u64,
    #[arg(long)]
    ready_file: PathBuf,
    #[arg(long)]
    stats_jsonl: PathBuf,
    #[arg(long)]
    final_file: PathBuf,
    #[arg(long, default_value_t = 250)]
    interval_ms: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
struct Shape {
    rate_bps: u64,
    delay_us: u64,
    loss: f64,
    queue_packets: usize,
}

impl Shape {
    fn validate(&self) -> Result<()> {
        ensure!(
            (100_000..=2_000_000_000).contains(&self.rate_bps)
                && self.delay_us <= 1_000_000
                && (0.0..=0.9).contains(&self.loss)
                && (8..=16_384).contains(&self.queue_packets),
            "shape outside bounded laboratory limits"
        );
        Ok(())
    }
}

#[derive(Default, Clone, Serialize)]
struct Counters {
    received_packets: u64,
    received_ip_udp_bytes: u64,
    loss_drops: u64,
    queue_full_drops: u64,
    policer_drops: u64,
    forwarded_packets: u64,
    forwarded_ip_udp_bytes: u64,
    send_errors: u64,
    no_peer_drops: u64,
    peak_packets: usize,
    max_sojourn_us: u64,
}

/// A byte-accounted policer drops excess arrivals without delaying accepted
/// packets behind them. Propagation still uses the existing bounded queue.
struct Policer {
    burst_bytes: usize,
    tokens: f64,
    updated: Instant,
}

impl Policer {
    fn new(burst_bytes: usize, now: Instant) -> Self {
        Self {
            burst_bytes,
            tokens: burst_bytes as f64,
            updated: now,
        }
    }

    fn refill(&mut self, now: Instant, rate_bps: u64) {
        // A receive timestamp can precede a control update that acquired the
        // shared lock first. Never count that elapsed interval a second time.
        let now = now.max(self.updated);
        let elapsed = now.duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate_bps as f64 / 8.0).min(self.burst_bytes as f64);
        self.updated = now;
    }

    fn admit(&mut self, now: Instant, bytes: usize, rate_bps: u64) -> bool {
        self.refill(now, rate_bps);
        if self.tokens < bytes as f64 {
            return false;
        }
        self.tokens -= bytes as f64;
        true
    }
}

struct Direction {
    shape: Shape,
    policer: Option<Policer>,
    counters: Counters,
    in_flight: usize,
    changes: u64,
}

type Shared = Arc<Mutex<Direction>>;

#[derive(Deserialize)]
struct Change {
    path: usize,
    /// "forward", "return" or omitted for both.
    direction: Option<String>,
    rate_mbps: Option<f64>,
    loss_percent: Option<f64>,
    delay_ms: Option<f64>,
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

fn parse_path(text: &str, queue_packets: usize) -> Result<Shape> {
    let (rtt, rate) = text
        .split_once(':')
        .context("path must be RTT_MS:RATE_MBPS")?;
    let rtt: f64 = rtt.parse()?;
    let rate: f64 = rate.parse()?;
    ensure!(rtt.is_finite() && rate.is_finite() && rtt >= 0.0 && rate > 0.0);
    let shape = Shape {
        rate_bps: (rate * 1e6).round() as u64,
        delay_us: (rtt * 500.0).round() as u64,
        loss: 0.0,
        queue_packets,
    };
    shape.validate()?;
    Ok(shape)
}

fn tokio_socket(role: &str) -> Result<(Arc<UdpSocket>, lab_socket::SocketEvidence)> {
    let (socket, evidence) = lab_socket::bind(role, SOCKET_BYTES, SOCKET_BYTES)?;
    Ok((Arc::new(UdpSocket::from_std(socket)?), evidence))
}

/// One shaped direction: receive on `input`, send from `output` to `peer`.
async fn shape_direction(
    input: Arc<UdpSocket>,
    output: Arc<UdpSocket>,
    state: Shared,
    peer: Arc<Mutex<Option<SocketAddr>>>,
    learn_peer: bool,
    fixed_target: Option<SocketAddr>,
    seed: u64,
) -> Result<()> {
    let mut random = StdRng::seed_from_u64(seed);
    let mut queue: VecDeque<(Instant, Instant, Vec<u8>)> = VecDeque::new();
    let mut busy_until = Instant::now();
    let mut last_delivery = Instant::now();
    let mut buffer = vec![0; MAX_DATAGRAM];
    loop {
        let next = queue.front().map(|entry| entry.1);
        tokio::select! {
            received = input.recv_from(&mut buffer) => {
                let (length, from) = match received {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if learn_peer {
                    *peer.lock().unwrap() = Some(from);
                }
                let size = length + IP_UDP_BYTES;
                let mut direction = state.lock().unwrap();
                // Use one post-lock timestamp for admission and delivery, after
                // any rate-control update that settled credit under this lock.
                let now = Instant::now();
                let shape = direction.shape;
                direction.counters.received_packets += 1;
                direction.counters.received_ip_udp_bytes += size as u64;
                if shape.loss > 0.0 && random.random::<f64>() < shape.loss {
                    direction.counters.loss_drops += 1;
                    continue;
                }
                if queue.len() >= shape.queue_packets {
                    direction.counters.queue_full_drops += 1;
                    continue;
                }
                let policed = direction.policer.is_some();
                if direction.policer.as_mut().is_some_and(|policer| !policer.admit(now, size, shape.rate_bps)) {
                    direction.counters.policer_drops += 1;
                    continue;
                }
                let start = if policed { now } else { busy_until.max(now) };
                let serialization = Duration::from_nanos(
                    (size as u128 * 8 * 1_000_000_000 / u128::from(shape.rate_bps)) as u64,
                );
                busy_until = start + serialization;
                let delivery = (busy_until + Duration::from_micros(shape.delay_us)).max(last_delivery);
                last_delivery = delivery;
                queue.push_back((now, delivery, buffer[..length].to_vec()));
                direction.in_flight = queue.len();
                direction.counters.peak_packets = direction.counters.peak_packets.max(queue.len());
            }
            _ = sleep_until(next.unwrap_or_else(Instant::now)), if next.is_some() => {
                let now = Instant::now();
                let target = fixed_target.or(*peer.lock().unwrap());
                while queue.front().is_some_and(|entry| entry.1 <= now) {
                    let (entered, _, data) = queue.pop_front().unwrap();
                    let sent = match target {
                        Some(target) => output.try_send_to(&data, target).is_ok(),
                        None => false,
                    };
                    let mut direction = state.lock().unwrap();
                    if target.is_none() {
                        direction.counters.no_peer_drops += 1;
                    } else if sent {
                        direction.counters.forwarded_packets += 1;
                        direction.counters.forwarded_ip_udp_bytes += (data.len() + IP_UDP_BYTES) as u64;
                        let sojourn = now.duration_since(entered).as_micros() as u64;
                        direction.counters.max_sojourn_us = direction.counters.max_sojourn_us.max(sojourn);
                    } else {
                        direction.counters.send_errors += 1;
                    }
                }
                state.lock().unwrap().in_flight = queue.len();
            }
        }
    }
}

fn snapshot(paths: &[(Shared, Shared)]) -> serde_json::Value {
    let view = |shared: &Shared| {
        let direction = shared.lock().unwrap();
        json!({"shape": direction.shape, "counters": direction.counters,
               "in_flight_packets": direction.in_flight, "changes": direction.changes,
               "policer_burst_bytes": direction.policer.as_ref().map(|p| p.burst_bytes)})
    };
    json!(paths
        .iter()
        .enumerate()
        .map(|(index, (forward, back))| json!({"index": index, "forward": view(forward), "return": view(back)}))
        .collect::<Vec<_>>())
}

fn apply(paths: &[(Shared, Shared)], line: &str) -> Result<()> {
    let change: Change = serde_json::from_str(line)?;
    let (forward, back) = paths.get(change.path).context("unknown path")?;
    let targets: Vec<&Shared> = match change.direction.as_deref() {
        None => vec![forward, back],
        Some("forward") => vec![forward],
        Some("return") => vec![back],
        Some(_) => anyhow::bail!("direction must be forward or return"),
    };
    for shared in targets {
        let mut direction = shared.lock().unwrap();
        let mut shape = direction.shape;
        if let Some(rate) = change.rate_mbps {
            shape.rate_bps = (rate * 1e6).round() as u64;
        }
        if let Some(loss) = change.loss_percent {
            shape.loss = loss / 100.0;
        }
        if let Some(delay) = change.delay_ms {
            shape.delay_us = (delay * 1000.0).round() as u64;
        }
        shape.validate()?;
        // Settle credit at the old rate before the control boundary, so a
        // capacity step cannot retroactively change already elapsed credit.
        let old_rate = direction.shape.rate_bps;
        if let Some(policer) = direction.policer.as_mut() {
            policer.refill(Instant::now(), old_rate);
        }
        direction.shape = shape;
        direction.changes += 1;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.server.ip().is_loopback(),
        "server must be a loopback address"
    );
    ensure!(
        (1..=MAX_PATHS).contains(&args.paths.len()),
        "one to eight paths"
    );
    ensure!(args.interval_ms >= 50, "interval must be at least 50 ms");
    ensure!(
        args.policer_burst_bytes == 0 || (2048..=1_048_576).contains(&args.policer_burst_bytes),
        "policer burst must be zero or 2048..1048576 IPv4+UDP bytes"
    );
    let mut tasks = JoinSet::new();
    let mut paths = Vec::new();
    let mut ready = Vec::new();
    for (index, text) in args.paths.iter().enumerate() {
        let shape = parse_path(text, args.queue_packets)?;
        let (entrance, entrance_evidence) = tokio_socket(&format!("path_{index}_entrance"))?;
        let (upstream, upstream_evidence) = tokio_socket(&format!("path_{index}_upstream"))?;
        let make = || {
            Arc::new(Mutex::new(Direction {
                shape,
                policer: (args.policer_burst_bytes > 0)
                    .then(|| Policer::new(args.policer_burst_bytes, Instant::now())),
                counters: Counters::default(),
                in_flight: 0,
                changes: 0,
            }))
        };
        let (forward, back) = (make(), make());
        let peer = Arc::new(Mutex::new(None));
        let seed = args.seed.wrapping_add(index as u64 * 2);
        tasks.spawn(shape_direction(
            entrance.clone(),
            upstream.clone(),
            forward.clone(),
            peer.clone(),
            true,
            Some(args.server),
            seed,
        ));
        tasks.spawn(shape_direction(
            upstream.clone(),
            entrance.clone(),
            back.clone(),
            peer,
            false,
            None,
            seed + 1,
        ));
        ready.push(json!({"index": index, "entrance": entrance.local_addr()?,
                          "upstream": upstream.local_addr()?, "shape": shape,
                          "sockets": [entrance_evidence, upstream_evidence]}));
        paths.push((forward, back));
    }
    let paths = Arc::new(paths);
    let started = Instant::now();
    fs::write(
        &args.ready_file,
        serde_json::to_vec_pretty(&json!({"pid": std::process::id(), "ready": true,
            "sample_unix_ms": unix_ms(), "server": args.server, "seed": args.seed,
            "rate_boundary": "IPv4+UDP bytes", "queue_limit": "packets queued or propagating",
            "policer_burst_bytes": args.policer_burst_bytes,
            "paths": ready}))?,
    )?;
    let mut stats = fs::File::create(&args.stats_jsonl)?;
    let mut interval = tokio::time::interval(Duration::from_millis(args.interval_ms));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // A plain thread keeps stdin out of the runtime's optional feature set.
    let (control, mut lines) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if control.send(line).is_err() {
                return;
            }
        }
    });
    let mut control_errors = Vec::new();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let row = json!({"sample_unix_ms": unix_ms(),
                                 "elapsed_ms": started.elapsed().as_millis(),
                                 "paths": snapshot(&paths)});
                writeln!(stats, "{row}")?;
            }
            line = lines.recv() => match line.transpose()? {
                Some(line) if line.trim().is_empty() => {}
                Some(line) => {
                    if let Err(error) = apply(&paths, &line) {
                        control_errors.push(format!("{error:#}: {line}"));
                    }
                    writeln!(stats, "{}", json!({"sample_unix_ms": unix_ms(),
                        "elapsed_ms": started.elapsed().as_millis(), "control": line,
                        "paths": snapshot(&paths)}))?;
                }
                None => break,
            },
            finished = tasks.join_next() => {
                anyhow::bail!("shaper task stopped: {finished:?}");
            }
        }
    }
    tasks.abort_all();
    fs::write(
        &args.final_file,
        serde_json::to_vec_pretty(&json!({"final": true, "sample_unix_ms": unix_ms(),
            "elapsed_ms": started.elapsed().as_millis(), "control_errors": control_errors,
            "paths": snapshot(&paths)}))?,
    )?;
    ensure!(
        control_errors.is_empty(),
        "control errors: {control_errors:?}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policer_drops_excess_without_spending_future_credit() {
        let start = Instant::now();
        let mut policer = Policer::new(2048, start);
        assert!(policer.admit(start, 2048, 8_000_000));
        assert!(!policer.admit(start, 1028, 8_000_000));
        assert!(!policer.admit(start + Duration::from_micros(1027), 1028, 8_000_000));
        assert!(policer.admit(start + Duration::from_micros(1028), 1028, 8_000_000));
        assert!(!policer.admit(start + Duration::from_micros(1028), 1, 8_000_000));
    }

    #[test]
    fn policer_bounds_idle_credit_and_accounts_rate_steps() {
        let start = Instant::now();
        let mut policer = Policer::new(2048, start);
        assert!(policer.admit(start, 2048, 8_000_000));
        policer.refill(start + Duration::from_micros(500), 8_000_000);
        assert!(!policer.admit(start + Duration::from_micros(750), 1001, 16_000_000));
        assert!(policer.admit(start + Duration::from_micros(750), 1000, 16_000_000));
        let later = start + Duration::from_secs(30);
        assert!(policer.admit(later, 2048, 16_000_000));
        assert!(!policer.admit(later, 1, 16_000_000));
    }

    #[test]
    fn policer_refill_does_not_recount_a_stale_receive_timestamp() {
        let start = Instant::now();
        let mut policer = Policer::new(2048, start);
        assert!(policer.admit(start, 2048, 8_000_000));
        policer.refill(start + Duration::from_micros(500), 8_000_000);
        policer.refill(start + Duration::from_micros(250), 8_000_000);
        assert!(!policer.admit(start + Duration::from_micros(750), 751, 8_000_000));
        assert!(policer.admit(start + Duration::from_micros(750), 750, 8_000_000));
    }

    #[test]
    fn loss_bounds_match_native_harness() {
        let mut shape = parse_path("30:60", 1024).unwrap();
        shape.loss = 0.9;
        assert!(shape.validate().is_ok());
        shape.loss = 0.9001;
        assert!(shape.validate().is_err());
        shape.loss = f64::NAN;
        assert!(shape.validate().is_err());
    }
}
