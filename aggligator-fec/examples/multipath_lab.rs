//! Deterministic, virtual-time multipath experiment using the REAL FEC codec.
//! This is NOT TCP/QUIC emulation or an Internet throughput benchmark.
//! Run: cargo +1.97.0 run --release -p aggligator-fec --example multipath_lab -- --packets 4096
//! All profiles use the same primary paths, offered application rate, wire cap,
//! original-packet loss decisions, and selective-ARQ/ACK policy.
use aggligator_fec::{Config, Decoder, Encoder, Frame};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap},
    error::Error,
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const PAYLOAD: usize = 1000;
const PATHS: usize = 3;
const ONE_WAY_US: [u64; PATHS] = [50_000, 52_000, 55_000];
const RTO_US: u64 = 180_000;
const TICK_US: u64 = 1000;
const WINDOW: usize = 1024;
const IP_UDP: usize = 28;

#[derive(Clone, Copy)]
enum Scenario { Clean, Independent, Asymmetric, PathBurst, CommonOutage }
impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Self::Clean => "clean", Self::Independent => "independent_10pct",
            Self::Asymmetric => "paths_5_15_25pct", Self::PathBurst => "one_path_bursts",
            Self::CommonOutage => "all_paths_outage_100ms",
        }
    }
    fn loss(self, path: usize, at: u64) -> u64 {
        match self {
            Self::Clean => 0,
            Self::Independent => 1000,
            Self::Asymmetric => [500, 1500, 2500][path],
            Self::PathBurst if path == 1 && at % 500_000 >= 250_000 && at % 500_000 < 400_000 => 10_000,
            Self::CommonOutage if (500_000..600_000).contains(&at) => 10_000,
            Self::PathBurst | Self::CommonOutage => 500,
        }
    }
}

fn mix(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}
fn payload(seq: u64) -> Vec<u8> {
    let mut out = vec![0u8; PAYLOAD];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (seq.wrapping_mul(17).wrapping_add(i as u64) % 251) as u8;
    }
    out[..8].copy_from_slice(&seq.to_le_bytes());
    out
}

#[derive(Clone, Copy)]
struct Ack { next: u64, bitmap: [u64; WINDOW / 64] }
impl Ack {
    fn contains(self, seq: u64) -> bool {
        if seq < self.next { return true; }
        let offset = seq - self.next;
        offset < WINDOW as u64 && self.bitmap[offset as usize / 64] & (1 << (offset % 64)) != 0
    }
}

enum Event { Datagram { path: usize, wire: Vec<u8> }, Ack(Ack) }
struct Scheduled { at: u64, serial: u64, event: Event }
impl PartialEq for Scheduled {
    fn eq(&self, rhs: &Self) -> bool { (self.at, self.serial) == (rhs.at, rhs.serial) }
}
impl Eq for Scheduled {}
impl PartialOrd for Scheduled {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> { Some(self.cmp(rhs)) }
}
impl Ord for Scheduled {
    fn cmp(&self, rhs: &Self) -> Ordering {
        (rhs.at, rhs.serial).cmp(&(self.at, self.serial))
    }
}
struct Pending { frame: Frame, last_sent: u64, attempt: u64 }

struct Network {
    events: BinaryHeap<Scheduled>, serial: u64, scenario: Scenario, seed: u64,
    // One SHARED access bottleneck, not three times the client's bandwidth.
    next_forward: u64, next_reverse: u64, wire_mbps: f64,
    forward_bytes: u64, reverse_bytes: u64, network_drops: u64,
    sources: u64, repairs: u64, retransmits: u64, path_bytes: [u64; PATHS],
}
impl Network {
    fn new(scenario: Scenario, seed: u64, wire_mbps: f64) -> Self {
        Self { events: BinaryHeap::new(), serial: 0, scenario, seed,
            next_forward: 0, next_reverse: 0, wire_mbps,
            forward_bytes: 0, reverse_bytes: 0, network_drops: 0,
            sources: 0, repairs: 0, retransmits: 0, path_bytes: [0; PATHS] }
    }
    fn event(&mut self, at: u64, event: Event) {
        self.serial += 1;
        self.events.push(Scheduled { at, serial: self.serial, event });
    }
    fn frame(&mut self, now: u64, frame: &Frame, attempt: u64) -> Result<u64> {
        let (path, key) = match frame {
            Frame::Source { base, index, .. } => {
                let seq = *base + u64::from(*index);
                if attempt == 0 { self.sources += 1; } else { self.retransmits += 1; }
                // The original data takes the SAME path in every FEC profile.
                (((seq + attempt) % PATHS as u64) as usize,
                 mix(seq ^ attempt.wrapping_mul(0x1234567)))
            }
            Frame::Repair { base, data, index, .. } => {
                self.repairs += 1;
                (((*base + u64::from(*data) + u64::from(*index)) % PATHS as u64) as usize,
                 mix(*base ^ (u64::from(*index) << 48) ^ 0xa5a5_a5a5))
            }
        };
        let wire = frame.encode()?;
        let bytes = (wire.len() + IP_UDP) as u64;
        let sent = now.max(self.next_forward);
        self.next_forward = sent + ((bytes as f64 * 8.0 / self.wire_mbps).ceil() as u64).max(1);
        self.forward_bytes += bytes;
        self.path_bytes[path] += bytes;
        if mix(self.seed ^ key ^ path as u64) % 10_000 < self.scenario.loss(path, sent) {
            self.network_drops += 1;
            return Ok(self.next_forward);
        }
        // A little deterministic path jitter permits genuine arrival reordering.
        let jitter = mix(key ^ self.seed ^ 0x55aa) % 2000;
        self.event(self.next_forward + ONE_WAY_US[path] + jitter, Event::Datagram { path, wire });
        Ok(self.next_forward)
    }
    fn ack(&mut self, now: u64, ack: Ack, ingress: usize) {
        // Repeated cumulative+selective snapshots on two paths tolerate ACK loss.
        // Both baseline and FEC pay exactly this policy's overhead.
        for path in [ingress, (ingress + 1) % PATHS] {
            let bytes = (16 + WINDOW / 8 + IP_UDP) as u64;
            let sent = now.max(self.next_reverse);
            self.next_reverse = sent + ((bytes as f64 * 8.0 / self.wire_mbps).ceil() as u64).max(1);
            self.reverse_bytes += bytes;
            let key = mix(self.serial ^ ack.next ^ ack.bitmap.iter().fold(0, |sum, word| sum ^ word) ^ 0xaa55_aa55);
            if mix(key ^ self.seed ^ path as u64) % 10_000 >= self.scenario.loss(path, sent) {
                self.event(self.next_reverse + ONE_WAY_US[path], Event::Ack(ack));
            }
        }
    }
}

struct Outcome {
    scenario: &'static str, profile: &'static str, delivered: usize, packets: usize,
    fec_recovered: usize, latency: Vec<u64>, completion: u64, ack_drain: u64,
    pending: usize, net: Network,
}
impl Outcome {
    fn print(mut self) {
        self.latency.sort_unstable();
        let percentile = |p: f64| -> f64 {
            if self.latency.is_empty() { return f64::NAN; }
            let index = ((self.latency.len() as f64 * p).ceil() as usize).saturating_sub(1);
            self.latency[index.min(self.latency.len() - 1)] as f64 / 1000.0
        };
        let application_bytes = self.packets as f64 * PAYLOAD as f64;
        let overhead = 100.0 * (self.net.forward_bytes as f64 / application_bytes - 1.0);
        println!("{},{},{}/{},{:.3},{:.3},{:.3},{:.3},{:.3},{},{},{:.2},{},{},{},{},{},{}",
            self.scenario, self.profile, self.delivered, self.packets,
            percentile(0.50), percentile(0.95), percentile(0.99),
            self.completion as f64 / 1000.0, self.ack_drain as f64 / 1000.0,
            self.fec_recovered, self.net.retransmits, overhead, self.net.reverse_bytes,
            self.net.network_drops, self.pending,
            self.net.path_bytes[0], self.net.path_bytes[1], self.net.path_bytes[2]);
    }
}

#[derive(Clone, Copy)]
struct RunSettings { packets: usize, seed: u64, app_mbps: f64, wire_mbps: f64 }

fn run(scenario: Scenario, k: usize, m: usize, profile: &'static str,
       settings: RunSettings) -> Result<Outcome> {
    let RunSettings { packets, seed, app_mbps, wire_mbps } = settings;
    let cfg = Config { data_shards: k, repair_shards: m, max_payload: PAYLOAD,
        max_decode_blocks: WINDOW * 2, max_block_delay: Duration::from_millis(2) };
    let mut encoder = Encoder::new(cfg.clone())?;
    let mut decoder = Decoder::new(cfg)?;
    let mut net = Network::new(scenario, seed, wire_mbps);
    let mut pending: BTreeMap<u64, Pending> = BTreeMap::new();
    let mut received: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut generated = Vec::with_capacity(packets);
    let mut latencies = Vec::with_capacity(packets);
    let mut next_delivery = 0u64;
    let mut remote_next = 0u64;
    let mut next_generation = 0u64;
    let generation_interval = ((PAYLOAD as f64 * 8.0 / app_mbps).ceil() as u64).max(1);
    let mut next_tick = 0u64;
    let mut now = 0u64;
    let mut app_completion = 0;
    let mut recovered = 0usize;
    let mut pending_ack = None;
    // Every run has the SAME bounded deadline policy, including failed samples.
    let deadline = packets as u64 * generation_interval + 30_000_000;
    while now <= deadline {
        let event_at = net.events.peek().map_or(u64::MAX, |event| event.at);
        let generation_at = if generated.len() < packets && pending.len() < WINDOW
            && (generated.len() as u64) < remote_next + WINDOW as u64 {
            next_generation.max(now)
        } else { u64::MAX };
        now = next_tick.min(event_at).min(generation_at);
        if now > deadline { break; }
        if event_at == now {
            let event = net.events.pop().unwrap().event;
            match event {
                Event::Ack(ack) => {
                    remote_next = remote_next.max(ack.next);
                    pending.retain(|seq, _| !ack.contains(*seq));
                }
                Event::Datagram { path, wire } => {
                    let frame = Frame::decode(&wire, PAYLOAD)?;
                    // A production channel must authenticate before this decoder.
                    for decoded in decoder.input(&frame)? {
                        if decoded.seq >= generated.len() as u64 { return Err("decoder invented a sequence".into()); }
                        if decoded.payload != payload(decoded.seq) { return Err("corrupted/reconstructed payload".into()); }
                        if decoded.seq >= next_delivery && !received.contains_key(&decoded.seq) {
                            if decoded.recovered { recovered += 1; }
                            received.insert(decoded.seq, decoded.payload);
                        }
                    }
                    while received.remove(&next_delivery).is_some() {
                        latencies.push(now - generated[next_delivery as usize]);
                        next_delivery += 1;
                        if next_delivery == packets as u64 { app_completion = now; }
                    }
                    let mut bitmap = [0u64; WINDOW / 64];
                    for seq in received.keys() {
                        let offset = (*seq - next_delivery) as usize;
                        if offset < WINDOW { bitmap[offset / 64] |= 1 << (offset % 64); }
                    }
                    pending_ack = Some((Ack { next: next_delivery, bitmap }, path));
                }
            }
        } else if generation_at == now {
            let seq = generated.len() as u64;
            generated.push(now);
            let frames = encoder.push(payload(seq), Duration::from_micros(now))?;
            for frame in frames {
                let departed = net.frame(now, &frame, 0)?;
                if let Frame::Source { base, index, .. } = &frame {
                    let seq = *base + u64::from(*index);
                    // Recovery timers start at actual paced departure, not enqueue time.
                    pending.insert(seq, Pending { frame: frame.clone(), last_sent: departed, attempt: 0 });
                }
            }
            next_generation = now + generation_interval;
        } else {
            // Coalesce snapshots to <=1kHz; ACK-every-datagram would itself
            // overload a 100Mbps upstream during a fast FEC-protected download.
            if let Some((ack, path)) = pending_ack.take() { net.ack(now, ack, path); }
            for frame in encoder.poll(Duration::from_micros(now))? { net.frame(now, &frame, 0)?; }
            for item in pending.values_mut() {
                // Packet retransmission, NEVER a whole-path reset.
                if now.saturating_sub(item.last_sent) >= RTO_US {
                    item.attempt += 1;
                    item.last_sent = net.frame(now, &item.frame, item.attempt)?;
                }
            }
            next_tick = now + TICK_US;
        }
        if next_delivery == packets as u64 && pending.is_empty() { break; }
        if received.len() > WINDOW || decoder.buffered_blocks() > WINDOW * 2 {
            return Err("bounded receive state exceeded".into());
        }
    }
    Ok(Outcome { scenario: scenario.name(), profile, delivered: next_delivery as usize,
        packets, fec_recovered: recovered, latency: latencies, completion: app_completion,
        ack_drain: now, pending: pending.len(), net })
}

fn main() -> Result<()> {
    let mut packets = 4096usize;
    let mut seed = 1u64;
    let mut app_mbps = 40.0f64;
    let mut wire_mbps = 100.0f64;
    let mut only_scenario: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--packets" => packets = args.next().ok_or("missing packets")?.parse()?,
            "--seed" => seed = args.next().ok_or("missing seed")?.parse()?,
            "--app-mbps" => app_mbps = args.next().ok_or("missing app rate")?.parse()?,
            "--wire-mbps" => wire_mbps = args.next().ok_or("missing wire rate")?.parse()?,
            "--scenario" => only_scenario = Some(args.next().ok_or("missing scenario")?),
            "--help" => {
                println!("multipath_lab [--packets 4096] [--seed 1] [--app-mbps 40] [--wire-mbps 100] [--scenario clean|independent_10pct|paths_5_15_25pct|one_path_bursts|all_paths_outage_100ms]");
                return Ok(());
            }
            _ => return Err(format!("unknown option {arg}").into()),
        }
    }
    if packets == 0 || packets > 1_000_000 || !app_mbps.is_finite()
        || !(0.1..=1_000_000.0).contains(&app_mbps) || !wire_mbps.is_finite()
        || !(0.1..=1_000_000.0).contains(&wire_mbps) {
        return Err("invalid packets/rates".into());
    }
    let scenarios = [Scenario::Clean, Scenario::Independent, Scenario::Asymmetric,
        Scenario::PathBurst, Scenario::CommonOutage];
    if only_scenario.as_ref().is_some_and(|name| !scenarios.iter().any(|s| s.name() == name)) {
        return Err("unknown scenario".into());
    }
    eprintln!("MODEL ONLY: 3 paths, one shared {wire_mbps} Mbps wire cap, {app_mbps} Mbps app rate; IPv4+UDP headers counted; fixed packet RTO=180ms; full-1024-packet selective ACK snapshots coalesced to 1ms and duplicated on two paths. No TCP or QUIC congestion-control emulation. Seed={seed}.");
    println!("scenario,profile,delivered,p50_ordered_ms,p95_ordered_ms,p99_ordered_ms,app_complete_ms,sender_drained_ms,fec_recovered,arq_retransmits,forward_overhead_pct,reverse_ack_wire_bytes,forward_network_drops,pending_at_deadline,path0_wire_bytes,path1_wire_bytes,path2_wire_bytes");
    let mut failed = false;
    for scenario in scenarios {
        if only_scenario.as_ref().is_some_and(|name| name != scenario.name()) { continue; }
        for (k,m,name) in [(8,0,"ARQ-only"),(8,4,"FEC-8+4"),(8,8,"FEC-8+8"),(1,1,"mirror-1+1")] {
            let outcome = run(scenario,k,m,name,RunSettings { packets,seed,app_mbps,wire_mbps })?;
            failed |= outcome.delivered != packets || outcome.pending != 0;
            outcome.print();
        }
    }
    if failed { return Err("one or more samples failed to deliver and acknowledge every packet by deadline; failures retained in CSV".into()); }
    Ok(())
}
