//! Bounded real-network measurement harness, NOT a production FEC transport.
//! Optional bounded selective ARQ and byte pacing, no adaptive congestion control.
//! The synthetic source reports pre-repair loss, complete delivery and stalls. Only explicitly configured
//! peer tuples are admitted; stdin EOF and a lifetime guard stop every service.
//! No firewall, sysctl, existing listener, configuration, or log is modified.
#![recursion_limit = "512"]
#[path = "support/paced.rs"]
mod paced;
use aggligator_fec::datagram::{Datagram, send_batch};
use aggligator_fec::recovery::Feedback;
use aggligator_fec::{Config, Decoder, Encoder, Frame};
use serde_json::{Value, json};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    error::Error,
    io::{self, BufRead},
    net::SocketAddr,
    num::NonZeroU32,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval, sleep_until},
};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const MAGIC: &[u8; 4] = b"AFL1";
const HEADER: usize = 13;
const MAX_PACKETS: usize = 2_000_000;

fn emit(value: Value) {
    println!("{value}");
}

// Measurement only: cumulative CPU time, not a system configuration change.
fn cpu_seconds() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        static HZ: std::sync::OnceLock<Option<f64>> = std::sync::OnceLock::new();
        let hz = (*HZ.get_or_init(|| {
            let out = std::process::Command::new("getconf").arg("CLK_TCK").output().ok()?;
            String::from_utf8(out.stdout).ok()?.trim().parse::<f64>().ok().filter(|n| *n > 0.0)
        }))?;
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let fields: Vec<_> = stat.rsplit_once(')')?.1.split_whitespace().collect();
        return Some((fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?) / hz);
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/bin/ps")
            .args(["-p", &std::process::id().to_string(), "-o", "time="])
            .output()
            .ok()?;
        let text = String::from_utf8(out.stdout).ok()?;
        let mut seconds = 0.0;
        for part in text.trim().split(':') {
            seconds = seconds * 60.0 + part.parse::<f64>().ok()?;
        }
        return Some(seconds);
    }
    #[allow(unreachable_code)]
    None
}
fn udp_counters(ipv6: bool) -> Value {
    if !ipv6 {
        let Ok(text) = std::fs::read_to_string("/proc/net/snmp") else {
            return Value::Null;
        };
        let rows: Vec<_> = text.lines().filter(|line| line.starts_with("Udp:")).collect();
        if rows.len() != 2 {
            return Value::Null;
        }
        let values: serde_json::Map<String, Value> = rows[0]
            .split_whitespace()
            .skip(1)
            .zip(rows[1].split_whitespace().skip(1))
            .filter_map(|(name, value)| value.parse::<u64>().ok().map(|n| (format!("Udp4{name}"), json!(n))))
            .collect();
        return Value::Object(values);
    }
    let Ok(text) = std::fs::read_to_string("/proc/net/snmp6") else {
        return Value::Null;
    };
    let mut values = serde_json::Map::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if let (Some(name), Some(value)) = (fields.next(), fields.next())
            && name.starts_with("Udp6")
            && let Ok(value) = value.parse::<u64>()
        {
            values.insert(name.to_string(), json!(value));
        }
    }
    Value::Object(values)
}
fn get_u(v: &Value, key: &str, default: u64) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(default)
}
fn get_s<'a>(v: &'a Value, key: &str, default: &'a str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or(default)
}
fn addr(v: &Value, key: &str) -> Result<SocketAddr> {
    Ok(get_s(v, key, "").parse()?)
}
fn envelope(kind: u8, run: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(MAGIC);
    out.push(kind);
    out.extend_from_slice(&run.to_be_bytes());
    out.extend_from_slice(body);
    out
}
fn parse(input: &[u8]) -> Option<(u8, u64, &[u8])> {
    if input.len() < HEADER || &input[..4] != MAGIC {
        return None;
    }
    Some((input[4], u64::from_be_bytes(input[5..13].try_into().ok()?), &input[13..]))
}
fn stats(samples: &[u64]) -> Value {
    if samples.is_empty() {
        return json!({"count":0});
    }
    let mut s = samples.to_vec();
    s.sort_unstable();
    let p = |n: usize| s[(s.len() * n).div_ceil(100).saturating_sub(1).min(s.len() - 1)] as f64 / 1000.0;
    json!({"count":s.len(),"min_ms":s[0] as f64/1000.0,"p50_ms":p(50),"p95_ms":p(95),"p99_ms":p(99),"max_ms":s[s.len()-1] as f64/1000.0})
}
fn control() -> mpsc::UnboundedReceiver<Value> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else {
                break;
            };
            match serde_json::from_str::<Value>(&line) {
                Ok(v) => {
                    if tx.send(v).is_err() {
                        break;
                    }
                }
                Err(e) => emit(json!({"event":"command_error","message":e.to_string()})),
            }
        }
    });
    rx
}
fn udp_socket(cfg: &Value) -> Result<UdpSocket> {
    let bind = addr(cfg, "bind")?;
    let socket =
        Socket::new(if bind.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 }, Type::DGRAM, Some(Protocol::UDP))?;
    if bind.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    // Per-socket requests only; never change machine-wide sysctls.
    let _ = socket.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    #[cfg(target_os = "macos")]
    if let Some(index) = NonZeroU32::new(get_u(cfg, "ifindex", 0) as u32) {
        if bind.is_ipv6() {
            socket.bind_device_by_index_v6(Some(index))?;
        } else {
            socket.bind_device_by_index_v4(Some(index))?;
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = NonZeroU32::new(0);
    socket.bind(&bind.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}
fn peers(cfg: &Value) -> Result<Vec<SocketAddr>> {
    let values = cfg.get("peers").and_then(Value::as_array).ok_or("missing peers")?;
    if values.is_empty() || values.len() > 8 {
        return Err("peer count must be 1..8".into());
    }
    values.iter().map(|v| Ok(v.as_str().ok_or("peer must be string")?.parse()?)).collect()
}
fn valid_peer(peer: SocketAddr, peers: &[SocketAddr]) -> Option<usize> {
    peers.iter().position(|p| p.ip() == peer.ip() && p.port() == peer.port())
}
// A port-zero peer is a known IPv4 client behind NAT. Learn only its first
// observed port, from a well-formed probe and an explicitly allowlisted IP.
// This is measurement endpoint discovery, NOT authentication or open forwarding.
fn admit_peer(peer: SocketAddr, peers: &mut [SocketAddr], probe: bool) -> Option<usize> {
    if peer.port() == 0 {
        return None;
    }
    if let Some(index) = valid_peer(peer, peers) {
        return Some(index);
    }
    if !probe {
        return None;
    }
    let index = peers.iter().position(|p| p.port() == 0 && p.ip() == peer.ip())?;
    peers[index] = peer;
    emit(json!({"event":"peer_learned","path":index,"peer":peer.to_string()}));
    Some(index)
}
fn data(seq: u64, stamp: u64, size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size];
    for (i, b) in out.iter_mut().enumerate().skip(16) {
        *b = ((seq.wrapping_mul(17) + i as u64) % 251) as u8;
    }
    out[..8].copy_from_slice(&seq.to_be_bytes());
    out[8..16].copy_from_slice(&stamp.to_be_bytes());
    out
}
fn validate_data(seq: u64, payload: &[u8], size: usize) -> bool {
    payload.len() == size
        && u64::from_be_bytes(payload[..8].try_into().unwrap()) == seq
        && payload.iter().enumerate().skip(16).all(|(i, b)| *b == ((seq.wrapping_mul(17) + i as u64) % 251) as u8)
}
struct Run {
    id: u64,
    cfg: Config,
    count: usize,
    size: usize,
    duration: Duration,
    paths: Vec<usize>,
    stride: usize,
    encoder: Encoder,
    decoder: Decoder,
    generated: usize,
    start: Option<Instant>,
    send_done: bool,
    sent_datagrams: u64,
    batch_io: bool,
    paced_thread: bool,
    arq: bool,
    primary_fastest: bool,
    selected_primary: Option<usize>,
    ordered_seconds: Vec<u64>,
    last_ordered_progress: Option<Instant>,
    max_ordered_stall_us: u64,
    interleave_lanes: usize,
    reorder_guard: Duration,
    retransmissions: u64,
    max_history: usize,
    final_unacked: usize,
    arq_arrivals: usize,
    highest_seen: usize,
    nack_gaps: std::collections::BTreeMap<usize, (Instant, Option<Instant>)>,
    quantum: usize,
    wire_mbps: u64,
    source_lateness_us: u64,
    send_batch_calls: u64,
    sent_wire: u64,
    send_errors: u64,
    send_elapsed: f64,
    originals: Vec<bool>,
    decoded: Vec<bool>,
    stamps: Vec<u64>,
    decoded_count: usize,
    original_count: usize,
    next_ordered: usize,
    first_recovered: usize,
    duplicates: u64,
    decode_errors: u64,
    rx_datagrams: u64,
    rx_wire: u64,
    path_tx: Vec<u64>,
    path_rx: Vec<u64>,
    arrival_rtt: Vec<u64>,
    ordered_rtt: Vec<u64>,
    echo_arrival_seen: Vec<bool>,
    echo_ordered_seen: Vec<bool>,
    started_at: Instant,
    first_rx: Option<Instant>,
    last_rx: Option<Instant>,
    max_tick_lag_us: u64,
    cpu_start: Option<f64>,
    ipv6: bool,
    udp_start: Value,
}
impl Run {
    fn new(v: &Value, npaths: usize, ipv6: bool) -> Result<Self> {
        let count = get_u(v, "count", 0) as usize;
        let size = get_u(v, "payload", 1000) as usize;
        let dur = get_u(v, "duration_ms", 5000);
        if count == 0 || count > MAX_PACKETS || !(16..=1400).contains(&size) || !(100..=60_000).contains(&dur) {
            return Err("invalid bounded run dimensions".into());
        }
        let paced = v.get("paced_thread").and_then(Value::as_bool).unwrap_or(false);
        if !paced
            && (v.get("arq").and_then(Value::as_bool).unwrap_or(false) || get_u(v, "interleave_lanes", 1) != 1)
        {
            return Err("ARQ and interleaving require the owned paced runtime".into());
        }
        let cfg = Config {
            data_shards: get_u(v, "k", 8) as usize,
            repair_shards: get_u(v, "m", 0) as usize,
            max_payload: size,
            max_decode_blocks: 2048,
            max_block_delay: Duration::from_millis(get_u(v, "block_delay_ms", 2).clamp(1, 60)),
        };
        let paths: Vec<usize> = v
            .get("paths")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|n| n.as_u64().unwrap_or(99) as usize).collect())
            .unwrap_or_else(|| (0..npaths).collect());
        if paths.is_empty() || paths.iter().any(|p| *p >= npaths) {
            return Err("invalid paths".into());
        }
        let stride = get_u(v, "probe_stride", 32).max(1) as usize;
        Ok(Self {
            id: get_u(v, "run", 1),
            encoder: Encoder::new(cfg.clone())?,
            decoder: Decoder::new(cfg.clone())?,
            cfg,
            count,
            size,
            duration: Duration::from_millis(dur),
            paths,
            stride,
            generated: 0,
            start: None,
            send_done: false,
            sent_datagrams: 0,
            batch_io: v.get("batch_io").and_then(Value::as_bool).unwrap_or(false),
            paced_thread: v.get("paced_thread").and_then(Value::as_bool).unwrap_or(false),
            arq: v.get("arq").and_then(Value::as_bool).unwrap_or(false),
            primary_fastest: v.get("primary_fastest").and_then(Value::as_bool).unwrap_or(false),
            selected_primary: None,
            ordered_seconds: Vec::new(),
            last_ordered_progress: None,
            max_ordered_stall_us: 0,
            interleave_lanes: get_u(v, "interleave_lanes", 1).clamp(1, 16) as usize,
            reorder_guard: Duration::from_millis(get_u(v, "reorder_guard_ms", 100).clamp(10, 500)),
            retransmissions: 0,
            max_history: 0,
            final_unacked: 0,
            arq_arrivals: 0,
            highest_seen: 0,
            nack_gaps: std::collections::BTreeMap::new(),
            quantum: get_u(v, "quantum", 16).clamp(1, 32) as usize,
            wire_mbps: get_u(v, "wire_mbps", 0).min(1000),
            source_lateness_us: 0,
            send_batch_calls: 0,
            sent_wire: 0,
            send_errors: 0,
            send_elapsed: 0.0,
            originals: vec![false; count],
            decoded: vec![false; count],
            stamps: vec![0; count],
            decoded_count: 0,
            original_count: 0,
            next_ordered: 0,
            first_recovered: 0,
            duplicates: 0,
            decode_errors: 0,
            rx_datagrams: 0,
            rx_wire: 0,
            path_tx: vec![0; npaths],
            path_rx: vec![0; npaths],
            arrival_rtt: Vec::new(),
            ordered_rtt: Vec::new(),
            echo_arrival_seen: vec![false; count],
            echo_ordered_seen: vec![false; count],
            started_at: Instant::now(),
            first_rx: None,
            last_rx: None,
            max_tick_lag_us: 0,
            cpu_start: cpu_seconds(),
            ipv6,
            udp_start: udp_counters(ipv6),
        })
    }
    fn report(&self, label: &str, ping: &[Vec<u64>], ping_sent: &[u64]) -> Value {
        let absent = self.originals.iter().zip(&self.decoded).filter(|(raw, dec)| !**raw && **dec).count();
        let denom = self.count.max(1) as f64;
        let bytes = self.decoded_count * self.size;
        let span =
            self.last_rx.zip(self.first_rx).map(|(last, first)| (last - first).as_secs_f64()).unwrap_or(0.0);
        let cpu_used = cpu_seconds().zip(self.cpu_start).map(|(end, start)| (end - start).max(0.0));
        let udp_end = udp_counters(self.ipv6);
        let mut udp_delta = serde_json::Map::new();
        if let (Some(before), Some(after)) = (self.udp_start.as_object(), udp_end.as_object()) {
            for (key, value) in after {
                if let (Some(old), Some(new)) = (before.get(key).and_then(Value::as_u64), value.as_u64()) {
                    udp_delta.insert(key.clone(), json!(new.saturating_sub(old)));
                }
            }
        }
        json!({"event":"report","label":label,"run":self.id,"k":self.cfg.data_shards,"m":self.cfg.repair_shards,
            "expected_sources":self.count,"generated_sources":self.generated,"raw_unique_sources":self.original_count,
            "decoded_unique_sources":self.decoded_count,"missing_before_fec":self.count-self.original_count,
            "missing_after_fec":self.count-self.decoded_count,"loss_before_pct":100.0*(self.count-self.original_count) as f64/denom,
            "loss_after_pct":100.0*(self.count-self.decoded_count) as f64/denom,"recovered_absent_originals":absent,
            "fec_first_deliveries":self.first_recovered,"contiguous_prefix_sources":self.next_ordered,
            "first_unrepaired_seq":if self.next_ordered<self.count{Some(self.next_ordered)}else{None},
            "nominal_decoded_mbps":bytes as f64*8.0/self.duration.as_secs_f64()/1e6,
            "receive_span_mbps":if span>0.0{bytes as f64*8.0/span/1e6}else{0.0},"rx_span_s":span,
            "tx_wire_bytes":self.sent_wire,"tx_datagrams":self.sent_datagrams,"send_errors":self.send_errors,
            "batch_io":self.batch_io,"send_batch_calls":self.send_batch_calls,
            "paced_thread":self.paced_thread,"source_lateness_us":self.source_lateness_us,
            "primary_fastest":self.primary_fastest,"reorder_guard_ms":self.reorder_guard.as_millis(),
            "interleave_lanes":self.interleave_lanes,"selected_primary":self.selected_primary,
            "ordered_payload_bytes_per_second":self.ordered_seconds,
            "ordered_measurement_span_s":self.last_ordered_progress.zip(self.first_rx).map(|(last,first)|last.duration_since(first).as_secs_f64()),
            "max_ordered_stall_ms":self.max_ordered_stall_us as f64/1000.0,
            "timestamp_origin":if self.paced_thread {"scheduled_application"} else {"actual_generation"},
            "send_elapsed_s":self.send_elapsed,"rx_wire_bytes":self.rx_wire,"rx_datagrams":self.rx_datagrams,
            "duplicates":self.duplicates,"decode_errors":self.decode_errors,"path_tx_datagrams":self.path_tx,"path_rx_datagrams":self.path_rx,
            "arrival_echo_rtt":stats(&self.arrival_rtt),"ordered_echo_rtt":stats(&self.ordered_rtt),
            "expected_echo_samples":self.count.div_ceil(self.stride),"path_ping_rtt":ping.iter().map(|s|stats(s)).collect::<Vec<_>>(),
            "path_ping_sent":ping_sent,"max_generator_tick_lag_us":self.max_tick_lag_us,
            "run_age_s":self.started_at.elapsed().as_secs_f64(),"process_cpu_seconds":cpu_used,
            "ip_family":if self.ipv6 {"IPv6"} else {"IPv4"},
            "os_udp_counter_delta":udp_delta,"arq_retransmissions":self.retransmissions,
            "arq_enabled":self.arq,"arq_direct_deliveries":self.arq_arrivals,
            "max_retained_sources":self.max_history,"final_unacked_sources":self.final_unacked})
    }
}
async fn transmit(socket: &UdpSocket, peers: &[SocketAddr], run: &mut Run, frames: Vec<Frame>) -> Result<()> {
    if run.batch_io {
        let mut paths = Vec::with_capacity(frames.len());
        let mut packets = Vec::with_capacity(frames.len());
        for frame in frames {
            let logical = match &frame {
                Frame::Source { base, index, .. } => *base + u64::from(*index),
                Frame::Repair { base, data, index, .. } => *base + u64::from(*data) + u64::from(*index),
            };
            let path = run.paths[logical as usize % run.paths.len()];
            let mut payload = envelope(1, run.id, &[]);
            frame.encode_into(&mut payload)?;
            paths.push(path);
            packets.push(Datagram { destination: peers[path], payload });
        }
        let progress = match send_batch(socket, &packets).await {
            Ok(p) => p,
            Err(error) => {
                run.send_errors += (packets.len() - error.completed.sent) as u64;
                emit(json!({"event":"send_error","error":error.to_string()}));
                error.completed
            }
        };
        run.send_batch_calls += progress.calls as u64;
        for (packet, path) in packets.iter().zip(paths).take(progress.sent) {
            run.sent_datagrams += 1;
            run.path_tx[path] += 1;
            run.sent_wire += (packet.payload.len() + if peers[path].is_ipv6() { 48 } else { 28 }) as u64;
        }
        return Ok(());
    }
    for frame in frames {
        let logical = match &frame {
            Frame::Source { base, index, .. } => *base + u64::from(*index),
            Frame::Repair { base, data, index, .. } => *base + u64::from(*data) + u64::from(*index),
        };
        let path = run.paths[logical as usize % run.paths.len()];
        let wire = envelope(1, run.id, &frame.encode()?);
        match socket.send_to(&wire, peers[path]).await {
            Ok(n) => {
                run.sent_datagrams += 1;
                run.path_tx[path] += 1;
                run.sent_wire += (n + if peers[path].is_ipv6() { 48 } else { 28 }) as u64;
            }
            Err(e) => {
                run.send_errors += 1;
                if run.send_errors < 4 {
                    emit(json!({"event":"send_error","error":e.to_string()}));
                }
            }
        }
    }
    Ok(())
}
async fn endpoint(v: Value) -> Result<()> {
    let socket = udp_socket(&v)?;
    let mut peers = peers(&v)?;
    let ipv6 = socket.local_addr()?.is_ipv6();
    let label = get_s(&v, "label", "endpoint").to_string();
    let mut commands = control();
    let clock = Instant::now();
    let deadline = clock + Duration::from_secs(get_u(&v, "lifetime_s", 1800).min(3600));
    let mut tick = interval(Duration::from_millis(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut feedback_tick = interval(Duration::from_millis(5));
    feedback_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut probe_tick = interval(Duration::from_millis(200));
    probe_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut ping: Vec<Vec<u64>> = vec![Vec::new(); peers.len()];
    let mut ping_sent = vec![0u64; peers.len()];
    // Keep path selection history independent from per-run measurement reset.
    let mut path_min_rtt = vec![u64::MAX; peers.len()];
    let mut run: Option<Run> = None;
    let mut sender_worker: Option<paced::Worker> = None;
    let (sender_done_tx, mut sender_done_rx) = mpsc::unbounded_channel::<paced::Report>();
    let mut buf = vec![0u8; 1600];
    let mut rejected = 0u64;
    let mut ping_since = 0u64;
    emit(
        json!({"event":"ready","label":label,"bind":socket.local_addr()?.to_string(),"peers":peers.iter().map(ToString::to_string).collect::<Vec<_>>() }),
    );
    loop {
        tokio::select! {
            _=sleep_until(deadline)=>break,
            cmd=commands.recv()=>{
                let Some(cmd)=cmd else{break;};
                match get_s(&cmd,"op","") {
                    "prepare"=>match Run::new(&cmd,peers.len(),ipv6) {
                        Ok(r)=>{drop(sender_worker.take());run=Some(r);ping.iter_mut().for_each(Vec::clear);ping_sent.fill(0);ping_since=clock.elapsed().as_micros() as u64;emit(json!({"event":"prepared","run":get_u(&cmd,"run",1),"label":label}));},
                        Err(e)=>emit(json!({"event":"error","error":e.to_string(),"label":label})),
                    },
                    "start"=>{if let Some(r)=&mut run && r.start.is_none() {
                        let start=Instant::now();r.start=Some(start);
                        if r.paced_thread {
                            r.selected_primary=if r.primary_fastest {r.paths.iter().copied().min_by_key(|i|path_min_rtt[*i])} else {None};
                            let raw:std::net::UdpSocket=socket2::SockRef::from(&socket).try_clone()?.into();
                            let request=paced::Request {id:r.id,cfg:r.cfg.clone(),count:r.count,size:r.size,
                                duration:r.duration,paths:r.paths.clone(),peers:peers.clone(),
                                start:start.into_std(),clock:clock.into_std(),quantum:r.quantum,wire_mbps:r.wire_mbps,arq:r.arq,lanes:r.interleave_lanes,
                                primary_path:r.selected_primary};
                            sender_worker=Some(paced::Worker::start(raw,request,sender_done_tx.clone())?);
                        }
                        emit(json!({"event":"started","run":r.id,"label":label}));
                    }},
                    "report"=>{if let Some(r)=&run{emit(r.report(&label,&ping,&ping_sent));}else{emit(json!({"event":"probe_report","label":label,"path_ping_rtt":ping.iter().map(|s|stats(s)).collect::<Vec<_>>(),"path_ping_sent":ping_sent,"rejected":rejected}));}},
                    "reset_probe"=>{ping.iter_mut().for_each(Vec::clear);ping_sent.fill(0);ping_since=clock.elapsed().as_micros() as u64;},

                    "quit"=>break,
                    _=>emit(json!({"event":"error","error":"unknown command"})),
                }
            },
            Some(done)=sender_done_rx.recv()=>{
                if let Some(r)=&mut run && done.id==r.id {
                    r.generated=done.generated;r.sent_datagrams=done.sent;r.sent_wire=done.wire;
                    r.path_tx=done.path_tx;r.send_batch_calls=done.calls;r.send_elapsed=done.elapsed;
                    r.source_lateness_us=done.source_lateness_us;r.send_done=true;
                    r.retransmissions=done.retransmissions;r.max_history=done.max_history;r.final_unacked=done.final_unacked;
                    drop(sender_worker.take());
                    if let Some(error)=done.error {r.send_errors+=1;emit(json!({"event":"error","error":error}));}
                    emit(json!({"event":"sent_done","run":r.id,"label":label,"generated":r.generated,
                        "elapsed_s":r.send_elapsed,"wire_bytes":r.sent_wire,"send_errors":r.send_errors}));
                }
            },
            _=feedback_tick.tick()=>{
                if let Some(r)=&mut run && r.arq && r.start.is_none() {
                    let now=Instant::now();
                    let next=r.next_ordered;
                    r.nack_gaps.retain(|block,_|*block>=next/64);
                    let mut feedbacks=Vec::new();
                    let end=r.highest_seen.min(next.saturating_add(8192));
                    for block in next/64..end.div_ceil(64) {
                        let base=next.max(block*64);let limit=end.min((block+1)*64);
                        let mut mask=0u64;
                        for seq in base..limit {if !r.decoded[seq] {mask|=1u64<<(seq-base);}}
                        if mask==0 {r.nack_gaps.remove(&block);continue;}
                        let entry=r.nack_gaps.entry(block).or_insert((now,None));
                        if now.duration_since(entry.0)>=r.reorder_guard
                            &&entry.1.is_none_or(|last|now.duration_since(last)>=Duration::from_millis(25)) {
                            feedbacks.push(Feedback {next:next as u64,base:base as u64,limit:limit as u64,missing:mask});
                            entry.1=Some(now);
                            if feedbacks.len()==8 {break;}
                        }
                    }
                    if feedbacks.is_empty() {feedbacks.push(Feedback {next:next as u64,base:next as u64,limit:next as u64,missing:0});}
                    let mut targets:Vec<_>=(0..peers.len()).filter(|i|peers[*i].port()!=0).collect();
                    targets.sort_by_key(|i|ping[*i].iter().min().copied().unwrap_or(u64::MAX));
                    let mut packets=Vec::new();
                    for feedback in feedbacks {
                        let wire=envelope(6,r.id,&feedback.encode().unwrap());
                        for path in targets.iter().take(2) {packets.push(Datagram {destination:peers[*path],payload:wire.clone()});}
                    }
                    let _=send_batch(&socket,&packets).await;
                }
            },
            _=probe_tick.tick()=>{
                let stamp=clock.elapsed().as_micros() as u64;
                for (path,peer) in peers.iter().enumerate(){
                    if peer.port()==0 {continue;}
                    let _=socket.send_to(&envelope(0,0,&[]),peer).await;
                    if socket.send_to(&envelope(2,0,&stamp.to_be_bytes()),peer).await.is_ok(){ping_sent[path]+=1;}
                }
            },
            result=socket.recv_from(&mut buf)=>{
                let (n,remote)=result?;
                let Some((kind,id,body))=parse(&buf[..n])else{rejected+=1;continue;};
                let probe=id==0 && ((kind==0&&body.is_empty())||(kind==2&&body.len()==8));
                let Some(path)=admit_peer(remote,&mut peers,probe)else{rejected+=1;continue;};
                match kind {
                    0=>{},
                    2 if body.len()==8=>{let _=socket.send_to(&envelope(3,0,body),remote).await;},
                    3 if body.len()==8=>{
                        let sent=u64::from_be_bytes(body.try_into().unwrap());
                        let now=clock.elapsed().as_micros() as u64;
                        if now>=sent && now-sent<10_000_000 {
                            path_min_rtt[path]=path_min_rtt[path].min(now-sent);
                            if sent>=ping_since&&ping[path].len()<50_000 {ping[path].push(now-sent);}
                        }
                    },
                    4|5 if body.len()==16=>{
                        if let Some(r)=&mut run && r.id==id {
                            let seq=u64::from_be_bytes(body[..8].try_into().unwrap()) as usize;
                            let stamp=u64::from_be_bytes(body[8..].try_into().unwrap());
                            let now=clock.elapsed().as_micros() as u64;
                            if seq<r.count && now>=stamp {
                                if kind==4&&!r.echo_arrival_seen[seq]{r.echo_arrival_seen[seq]=true;r.arrival_rtt.push(now-stamp);}
                                if kind==5&&!r.echo_ordered_seen[seq]{r.echo_ordered_seen[seq]=true;r.ordered_rtt.push(now-stamp);}
                            }
                        }
                    },
                    6 if body.len()==32=>{
                        if let Some(r)=&run && r.id==id && r.arq
                            &&let Some(worker)=&sender_worker &&let Some(feedback)=Feedback::decode(body) {
                            let fastest=(0..peers.len()).filter(|i|peers[*i].port()!=0)
                                .min_by_key(|i|path_min_rtt[*i]).unwrap_or(path);
                            worker.feedback(feedback,fastest);
                        }
                    },
                    7 if body.len()==8=>{
                        if let Some(r)=&mut run &&r.id==id&&r.arq {
                            let extent=u64::from_be_bytes(body.try_into().unwrap());
                            if extent<=r.count as u64 {r.highest_seen=r.highest_seen.max(extent as usize);}
                        }
                    },
                    1|8=>{
                        let Some(r)=&mut run else{continue;};if id!=r.id{continue;}
                        r.rx_datagrams+=1;r.rx_wire+=(n+if remote.is_ipv6(){48}else{28}) as u64;r.path_rx[path]+=1;
                        let now=Instant::now();r.first_rx.get_or_insert(now);r.last_rx=Some(now);
                        let frame=match Frame::decode(body,r.size){Ok(f)=>f,Err(_)=>{r.decode_errors+=1;continue;}};
                        if let Frame::Source {base,index,..}=&frame {
                            let seq=*base+u64::from(*index)*r.interleave_lanes as u64;
                            if seq>=r.count as u64{r.decode_errors+=1;continue;}
                            if kind==1&&!r.originals[seq as usize]{r.originals[seq as usize]=true;r.original_count+=1;}
                        }
                        let decoded=match aggligator_fec::interleave::decode(&mut r.decoder,&frame,r.interleave_lanes){Ok(d)=>d,Err(_)=>{r.decode_errors+=1;continue;}};
                        for d in decoded {
                            let seq=d.seq as usize;
                            if seq>=r.count || !validate_data(d.seq,&d.payload,r.size){r.decode_errors+=1;continue;}
                            if r.decoded[seq]{r.duplicates+=1;continue;}
                            r.decoded[seq]=true;r.decoded_count+=1;if d.recovered{r.first_recovered+=1;}
                            if kind==8&&!d.recovered{r.arq_arrivals+=1;}r.highest_seen=r.highest_seen.max(seq+1);
                            r.stamps[seq]=u64::from_be_bytes(d.payload[8..16].try_into().unwrap());
                            if seq.is_multiple_of(r.stride) {let _=socket.send_to(&envelope(4,r.id,&d.payload[..16]),remote).await;}
                            while r.next_ordered<r.count && r.decoded[r.next_ordered] {
                                let next=r.next_ordered;r.next_ordered+=1;
                                let progress=Instant::now();
                                if let Some(last)=r.last_ordered_progress {r.max_ordered_stall_us=r.max_ordered_stall_us.max(progress.duration_since(last).as_micros() as u64);}
                                r.last_ordered_progress=Some(progress);
                                let second=r.first_rx.map(|first|progress.duration_since(first).as_secs() as usize).unwrap_or(0).min(240);
                                if r.ordered_seconds.len()<=second {r.ordered_seconds.resize(second+1,0);}
                                r.ordered_seconds[second]+=r.size as u64;
                                if next.is_multiple_of(r.stride) {
                                    let mut echo=[0u8;16];echo[..8].copy_from_slice(&(next as u64).to_be_bytes());echo[8..].copy_from_slice(&r.stamps[next].to_be_bytes());
                                    let _=socket.send_to(&envelope(5,r.id,&echo),remote).await;
                                }
                            }
                        }
                    },
                    _=>{rejected+=1;},
                }
            },
            scheduled=tick.tick()=>{
                let Some(r)=&mut run else{continue;};let Some(start)=r.start else{continue;};if r.send_done||r.paced_thread{continue;}
                r.max_tick_lag_us=r.max_tick_lag_us.max(Instant::now().saturating_duration_since(scheduled).as_micros() as u64);
                let elapsed=start.elapsed();
                let wanted=((elapsed.as_secs_f64()/r.duration.as_secs_f64()*r.count as f64) as usize).min(r.count);
                // At most a 1ms source burst. Delayed generators do not dump the
                // entire accumulated backlog into the socket in a single turn.
                let max_batch=(r.count as f64/r.duration.as_secs_f64()/1000.0).ceil() as usize+1;
                let target=wanted.min(r.generated+max_batch.max(1));
                let mut batch=Vec::new();
                while r.generated<target {
                    let stamp=clock.elapsed().as_micros() as u64;
                    let frames=r.encoder.push(data(r.generated as u64,stamp,r.size),clock.elapsed())?;
                    r.generated+=1;
                    if r.batch_io {batch.extend(frames);} else {transmit(&socket,&peers,r,frames).await?;}
                }
                batch.extend(r.encoder.poll(clock.elapsed())?);
                transmit(&socket,&peers,r,batch).await?;
                if r.generated==r.count {
                    let frames=r.encoder.flush()?;transmit(&socket,&peers,r,frames).await?;
                    r.send_done=true;r.send_elapsed=start.elapsed().as_secs_f64();
                    emit(json!({"event":"sent_done","run":r.id,"label":label,"generated":r.generated,"elapsed_s":r.send_elapsed,"wire_bytes":r.sent_wire,"send_errors":r.send_errors}));
                }
            },
        }
    }
    emit(json!({"event":"stopped","label":label,"rejected":rejected}));
    Ok(())
}
async fn relay(v: Value) -> Result<()> {
    let socket = udp_socket(&v)?;
    let client = addr(&v, "client")?;
    let main = addr(&v, "main")?;
    let mut ps = [client, main];
    let label = get_s(&v, "label", "relay");
    let deadline = Instant::now() + Duration::from_secs(get_u(&v, "lifetime_s", 1800).min(3600));
    let mut commands = control();
    let mut tick = interval(Duration::from_millis(250));
    let mut buf = [0u8; 1600];
    let mut counts = [0u64; 2];
    let mut bytes = [0u64; 2];
    let mut errors = 0;
    let mut rejected = 0;
    emit(
        json!({"event":"ready","label":label,"bind":socket.local_addr()?.to_string(),"client":client.to_string(),"main":main.to_string()}),
    );
    loop {
        tokio::select! {
            _=sleep_until(deadline)=>break,
            cmd=commands.recv()=>{let Some(cmd)=cmd else{break;};match get_s(&cmd,"op","") {
                "quit"=>break,
                "report"=>emit(json!({"event":"relay_report","label":label,"up_down_packets":counts,"up_down_bytes":bytes,"send_errors":errors,"rejected":rejected})),
                _=>{},
            }},
            _=tick.tick()=>{for peer in ps{if peer.port()!=0 {let _=socket.send_to(&envelope(0,0,&[]),peer).await;}}},
            result=socket.recv_from(&mut buf)=>{
                let(n,remote)=result?;
                let Some((kind,id,body))=parse(&buf[..n])else{rejected+=1;continue;};
                let probe=id==0 && ((kind==0&&body.is_empty())||(kind==2&&body.len()==8));
                let Some(direction)=admit_peer(remote,&mut ps,probe)else{rejected+=1;continue;};
                if kind==0 || ps[1-direction].port()==0 {continue;}
                match socket.send_to(&buf[..n],ps[1-direction]).await{Ok(_)=>{counts[direction]+=1;bytes[direction]+=n as u64;},Err(_)=>errors+=1,}
            },
        }
    }
    emit(
        json!({"event":"stopped","label":label,"up_down_packets":counts,"up_down_bytes":bytes,"send_errors":errors,"rejected":rejected}),
    );
    Ok(())
}
async fn tcp_relay(v: Value) -> Result<()> {
    let listener = TcpListener::bind(addr(&v, "bind")?).await?;
    let target = addr(&v, "target")?;
    let ips = v.get("client_ips").and_then(Value::as_array).ok_or("missing client_ips")?;
    if ips.is_empty() || ips.len() > 8 {
        return Err("invalid allowlist length".into());
    }
    let allowed: Vec<std::net::IpAddr> = ips
        .iter()
        .map(|ip| {
            ip.as_str()
                .ok_or("invalid allowlist IP")
                .and_then(|ip| ip.parse().map_err(|_| "invalid allowlist IP"))
        })
        .collect::<std::result::Result<_, _>>()?;
    let label = get_s(&v, "label", "tcp-relay");
    let deadline = Instant::now() + Duration::from_secs(get_u(&v, "lifetime_s", 1800).min(3600));
    let mut commands = control();
    let mut tasks = JoinSet::new();
    let mut accepted = 0;
    let mut rejected = 0;
    emit(
        json!({"event":"ready","label":label,"bind":listener.local_addr()?.to_string(),"target":target.to_string()}),
    );
    loop {
        tokio::select! {
            _=sleep_until(deadline)=>break,
            cmd=commands.recv()=>{if cmd.as_ref().is_none_or(|c|get_s(c,"op","")=="quit"){break;}},
            result=listener.accept()=>{
                let(mut stream,remote)=result?;if !allowed.contains(&remote.ip()) || tasks.len()>=8{rejected+=1;continue;}
                accepted+=1;tasks.spawn(async move {
                    if let Ok(mut upstream)=TcpStream::connect(target).await {
                        let _=stream.set_nodelay(true);let _=upstream.set_nodelay(true);
                        let _=tokio::io::copy_bidirectional(&mut stream,&mut upstream).await;
                    }
                });
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    emit(json!({"event":"stopped","label":label,"accepted":accepted,"rejected":rejected}));
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(
            "usage: live_lab endpoint|relay|tcp-relay JSON_CONFIG (commands as JSON lines on stdin)".into()
        );
    }
    let cfg: Value = serde_json::from_str(&args[2])?;
    match args[1].as_str() {
        "endpoint" => endpoint(cfg).await,
        "relay" => relay(cfg).await,
        "tcp-relay" => tcp_relay(cfg).await,
        _ => Err("unknown role".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_peer_learns_only_one_port_from_the_allowlisted_ip() {
        let allowed: SocketAddr = "192.0.2.10:0".parse().unwrap();
        let observed: SocketAddr = "192.0.2.10:49152".parse().unwrap();
        let mut peers = [allowed];
        assert_eq!(admit_peer(observed, &mut peers, false), None);
        assert_eq!(peers, [allowed]);
        assert_eq!(admit_peer("192.0.2.11:49152".parse().unwrap(), &mut peers, true), None);
        assert_eq!(admit_peer(allowed, &mut peers, true), None);
        assert_eq!(admit_peer(observed, &mut peers, true), Some(0));
        assert_eq!(peers, [observed]);
        assert_eq!(admit_peer(observed, &mut peers, false), Some(0));
        assert_eq!(admit_peer("192.0.2.10:49153".parse().unwrap(), &mut peers, true), None);
        assert_eq!(peers, [observed]);
    }

    #[test]
    fn fixed_peer_tuple_is_never_replaced_by_nat_discovery() {
        let fixed: SocketAddr = "192.0.2.20:5702".parse().unwrap();
        let mut peers = [fixed];
        assert_eq!(admit_peer(fixed, &mut peers, false), Some(0));
        assert_eq!(admit_peer("192.0.2.20:60000".parse().unwrap(), &mut peers, true), None);
        assert_eq!(peers, [fixed]);
    }
}
