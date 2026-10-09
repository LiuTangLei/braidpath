//! Finite UDP workloads. One-way delay is relative to the minimum signed transit delta.
use super::MAX_PAYLOAD;
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, ValueEnum};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;

const HEADER: usize = 36;
const MAGIC: &[u8; 4] = b"BPP2";
const REGISTER: u8 = 1;
const ACK: u8 = 2;
const DATA: u8 = 3;
const END: u8 = 4;
const REGISTRATION_ATTEMPTS: u32 = 3;

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Echo,
    Send,
    Receive,
}
#[derive(Clone, Copy, Debug, ValueEnum, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Receive,
    ReverseSource,
}
#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    RawUdp,
    Braidpath,
}

#[derive(Clone, Args)]
pub struct Workload {
    #[arg(long, default_value_t = 1000)]
    pub count: u32,
    /// Datagram size including the measurement header (one-way minimum 36 bytes).
    #[arg(long, default_value_t = 1000)]
    pub size: usize,
    #[arg(long, default_value_t = 200)]
    pub pps: u32,
    #[arg(long, default_value_t = 250)]
    pub deadline_ms: u64,
    /// Observation allowance after the scheduled stream; bounded to 60 seconds.
    #[arg(long, default_value_t = 3000)]
    pub drain_ms: u64,
    #[arg(long, default_value_t = 5000)]
    pub startup_timeout_ms: u64,
    /// Shared unpredictable 128-bit hexadecimal identifier; required for one-way runs.
    #[arg(long)]
    pub run_id: Option<String>,
    /// Descriptive label only: the chosen target determines the actual route.
    #[arg(long, value_enum, default_value_t = Transport::Braidpath)]
    pub transport: Transport,
    #[arg(long)]
    pub result_file: Option<PathBuf>,
    /// Optional bounded JSON packet samples, including explicit missing slots.
    #[arg(long)]
    pub samples_file: Option<PathBuf>,
}
#[derive(Args)]
pub struct ProbeOptions {
    #[arg(long)]
    pub target: SocketAddr,
    /// Distinct source ports allow independent parallel flows through the same tunnel.
    #[arg(long)]
    pub listen: Option<SocketAddr>,
    #[arg(long, value_enum, default_value_t = Mode::Echo)]
    pub mode: Mode,
    #[command(flatten)]
    pub workload: Workload,
}
#[derive(Args)]
pub struct SinkOptions {
    #[arg(long, default_value = "127.0.0.1:9000")]
    pub listen: SocketAddr,
    #[arg(long, value_enum, default_value_t = Role::Receive)]
    pub role: Role,
    #[arg(long)]
    pub ready_file: Option<PathBuf>,
    #[command(flatten)]
    pub workload: Workload,
}

fn unix_us() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_micros()
        .try_into()?)
}
fn run_id(w: &Workload, one_way: bool) -> Result<[u8; 16]> {
    ensure!(
        (1..=100_000).contains(&w.count)
            && (1..=20_000).contains(&w.pps)
            && (if one_way { HEADER } else { 16 }..=MAX_PAYLOAD).contains(&w.size)
            && (1..=10_000).contains(&w.deadline_ms)
            && w.drain_ms <= 60_000
            && (1..=60_000).contains(&w.startup_timeout_ms),
        "invalid bounded probe parameters"
    );
    let Some(text) = &w.run_id else {
        ensure!(
            !one_way,
            "one-way runs require --run-id with 32 random hexadecimal digits"
        );
        return Ok(rand::random());
    };
    ensure!(
        text.len() == 32 && text.bytes().all(|b| b.is_ascii_hexdigit()),
        "run-id must contain 32 hexadecimal digits"
    );
    let mut id = [0u8; 16];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)?;
    }
    ensure!(id != [0; 16], "run-id must be unpredictable and nonzero");
    Ok(id)
}
fn packet(kind: u8, id: &[u8; 16], seq: u32, timestamp: i64, size: usize) -> Vec<u8> {
    let mut b = vec![(seq % 251) as u8; size];
    b[..4].copy_from_slice(MAGIC);
    b[4] = kind;
    b[5..8].fill(0);
    b[8..24].copy_from_slice(id);
    b[24..28].copy_from_slice(&seq.to_be_bytes());
    b[28..36].copy_from_slice(&timestamp.to_be_bytes());
    b
}
fn decode(b: &[u8], id: &[u8; 16]) -> Option<(u8, u32, i64)> {
    if b.len() < HEADER || &b[..4] != MAGIC || b[5..8] != [0; 3] || &b[8..24] != id {
        return None;
    }
    Some((
        b[4],
        u32::from_be_bytes(b[24..28].try_into().ok()?),
        i64::from_be_bytes(b[28..36].try_into().ok()?),
    ))
}
fn write_json(path: Option<&Path>, value: &Value) -> Result<()> {
    if let Some(path) = path {
        std::fs::write(path, serde_json::to_vec(value)?)
            .with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}
fn ready(
    path: Option<&Path>,
    command: &str,
    socket: &UdpSocket,
    run_id: Option<&str>,
) -> Result<()> {
    write_json(
        path,
        &json!({"command":command,"ready":true,"final":false,"listen":socket.local_addr()?.to_string(),"pid":std::process::id(),"run_id":run_id,"instance_id":format!("{:032x}",rand::random::<u128>()),"sample_unix_ms":unix_us()?/1000}),
    )
}

#[derive(Clone, Serialize)]
struct Sample {
    seq: u32,
    send_unix_us: i64,
    receive_unix_us: Option<i64>,
    #[serde(skip_serializing)]
    rtt_ms: Option<f64>,
}
struct State {
    samples: Vec<Option<Sample>>,
    sent_times: Vec<Option<Instant>>,
    sent: u32,
    duplicate: u64,
    corrupt: u64,
    control_sent: u64,
    control_received: u64,
    registration_attempts: u32,
    rejected: u64,
    actual_span: Option<f64>,
    interrupted: bool,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
}
impl State {
    fn new(count: u32) -> Self {
        Self {
            samples: vec![None; count as usize],
            sent_times: vec![None; count as usize],
            sent: 0,
            duplicate: 0,
            corrupt: 0,
            control_sent: 0,
            control_received: 0,
            registration_attempts: 0,
            rejected: 0,
            actual_span: None,
            interrupted: false,
            local_addr: None,
            peer_addr: None,
        }
    }
}
async fn control(
    socket: &UdpSocket,
    kind: u8,
    id: &[u8; 16],
    seq: u32,
    time: i64,
    state: &mut State,
) -> Result<()> {
    socket.send(&packet(kind, id, seq, time, HEADER)).await?;
    state.control_sent += 1;
    Ok(())
}
/// No remote request can select a source count, rate or payload size.
async fn accept(socket: &UdpSocket, id: &[u8; 16], w: &Workload, state: &mut State) -> Result<()> {
    let until = tokio::time::Instant::now() + Duration::from_millis(w.startup_timeout_ms);
    let mut b = [0u8; MAX_PAYLOAD + 1];
    loop {
        tokio::select! {
            _=tokio::time::sleep_until(until)=>bail!("startup timeout waiting for authorized registration"),
            _=tokio::signal::ctrl_c()=>bail!("interrupted during startup"),
            r=socket.recv_from(&mut b)=>{
                let(n,peer)=r?;
                if n==HEADER && decode(&b[..n],id)==Some((REGISTER,0,0)) {
                    state.control_received+=1; socket.connect(peer).await?;
                    control(socket,ACK,id,0,0,state).await?; return Ok(());
                }
                state.rejected+=1;
            }
        }
    }
}
async fn register(
    socket: &UdpSocket,
    id: &[u8; 16],
    w: &Workload,
    state: &mut State,
) -> Result<()> {
    let start = tokio::time::Instant::now();
    let mut b = [0u8; MAX_PAYLOAD + 1];
    for attempt in 0..REGISTRATION_ATTEMPTS {
        state.registration_attempts += 1;
        control(socket, REGISTER, id, 0, 0, state).await?;
        let until = start
            + Duration::from_millis(
                w.startup_timeout_ms * (u64::from(attempt) + 1) / u64::from(REGISTRATION_ATTEMPTS),
            );
        loop {
            tokio::select! {
                _=tokio::time::sleep_until(until)=>break,
                _=tokio::signal::ctrl_c()=>bail!("interrupted during startup"),
                r=socket.recv(&mut b)=>{
                    let n=r?;
                    if n==HEADER && decode(&b[..n],id)==Some((ACK,0,0)) { state.control_received+=1;return Ok(()); }
                    // First authorized reverse data also proves the mapping if the ACK was lost.
                    if valid_data(&b[..n],id,w).is_some() { record(&b[..n],id,w,state,false)?;return Ok(()); }
                    state.rejected+=1;
                }
            }
        }
    }
    bail!("startup timeout after {REGISTRATION_ATTEMPTS} registration attempts")
}
fn valid_data(b: &[u8], id: &[u8; 16], w: &Workload) -> Option<(u32, i64)> {
    let (kind, seq, time) = decode(b, id)?;
    if kind != DATA
        || b.len() != w.size
        || seq >= w.count
        || b[HEADER..].iter().any(|x| *x != (seq % 251) as u8)
    {
        return None;
    }
    Some((seq, time))
}
fn record(
    b: &[u8],
    id: &[u8; 16],
    w: &Workload,
    state: &mut State,
    echo: bool,
) -> Result<Option<u32>> {
    let (seq, send) = if echo {
        if b.len() != w.size || b[..8] != id[..8] {
            state.corrupt += 1;
            return Ok(None);
        }
        let seq = u32::from_be_bytes(b[8..12].try_into()?);
        if seq >= state.sent || b[12..].iter().any(|x| *x != (seq % 251) as u8) {
            state.corrupt += 1;
            return Ok(None);
        }
        (
            seq,
            state.samples[seq as usize]
                .as_ref()
                .expect("sent echo sample")
                .send_unix_us,
        )
    } else if let Some(v) = valid_data(b, id, w) {
        v
    } else {
        state.corrupt += 1;
        return Ok(None);
    };
    let i = seq as usize;
    if state.samples[i]
        .as_ref()
        .and_then(|s| s.receive_unix_us)
        .is_some()
    {
        state.duplicate += 1;
        return Ok(None);
    }
    state.samples[i] = Some(Sample {
        seq,
        send_unix_us: send,
        receive_unix_us: Some(unix_us()?),
        rtt_ms: if echo {
            Some(
                state.sent_times[i]
                    .expect("sent monotonic timestamp")
                    .elapsed()
                    .as_secs_f64()
                    * 1000.,
            )
        } else {
            None
        },
    });
    Ok(Some(seq))
}
fn requested_span(w: &Workload) -> f64 {
    f64::from(w.count - 1) / f64::from(w.pps)
}

/// Observation follows validated sequence progress, with a fixed drain after END.
struct ReceiveWindow {
    until: tokio::time::Instant,
    highest_sequence: Option<u32>,
    end_seen: bool,
}
impl ReceiveWindow {
    fn new(w: &Workload, state: &State, now: tokio::time::Instant) -> Self {
        Self {
            until: now
                + Duration::from_secs_f64(requested_span(w))
                + Duration::from_millis(w.drain_ms),
            highest_sequence: state
                .samples
                .iter()
                .flatten()
                .filter(|sample| sample.receive_unix_us.is_some())
                .map(|sample| sample.seq)
                .max(),
            end_seen: false,
        }
    }
    // Called only for a newly accepted valid record; duplicates/invalid packets
    // never reach this method. Late out-of-order data cannot renew observation.
    fn progress(&mut self, seq: u32, w: &Workload, now: tokio::time::Instant) {
        if !self.end_seen && self.highest_sequence.is_none_or(|highest| seq > highest) {
            self.highest_sequence = Some(seq);
            let remaining = f64::from(w.count - 1 - seq) / f64::from(w.pps);
            self.until = self
                .until
                .max(now + Duration::from_secs_f64(remaining) + Duration::from_millis(w.drain_ms));
        }
    }
    fn end(&mut self, w: &Workload, now: tokio::time::Instant) -> bool {
        if self.end_seen {
            return false;
        }
        self.until = now + Duration::from_millis(w.drain_ms);
        self.end_seen = true;
        true
    }
}

async fn receive_stream(
    socket: &UdpSocket,
    id: &[u8; 16],
    w: &Workload,
    state: &mut State,
) -> Result<f64> {
    let start = Instant::now();
    let mut window = ReceiveWindow::new(w, state, tokio::time::Instant::now());
    let mut b = [0u8; MAX_PAYLOAD + 1];
    loop {
        tokio::select! {
            _=tokio::time::sleep_until(window.until)=>break,
            _=tokio::signal::ctrl_c()=>{state.interrupted=true;break;},
            r=socket.recv(&mut b)=>{
                let n=r?;
                match decode(&b[..n],id) {
                    Some((REGISTER,0,0)) if n==HEADER=>{state.control_received+=1;control(socket,ACK,id,0,0,state).await?;},
                    Some((ACK,0,0)) if n==HEADER=>{state.control_received+=1;},
                    Some((END,count,span)) if n==HEADER && count==w.count && span>=0=>{
                        state.control_received+=1;
                        if window.end(w,tokio::time::Instant::now()) {state.actual_span=Some(span as f64/1_000_000.);}
                    },
                    _=>{
                        if let Some(seq)=record(&b[..n],id,w,state,false)? {
                            window.progress(seq,w,tokio::time::Instant::now());
                        }
                    }
                }
            }
        }
    }
    Ok(start.elapsed().as_secs_f64())
}
async fn send_stream(
    socket: &UdpSocket,
    id: &[u8; 16],
    w: &Workload,
    state: &mut State,
    echo: bool,
) -> Result<f64> {
    let start = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1. / f64::from(w.pps)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut until = None;
    let mut b = [0u8; MAX_PAYLOAD + 1];
    let mut first = None;
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>{state.interrupted=true;break;},
            _=tick.tick(),if state.sent<w.count=>{
                let seq=state.sent;
                let stamp=unix_us()?;
                let data=if echo {let mut b=vec![(seq%251)as u8;w.size];b[..8].copy_from_slice(&id[..8]);b[8..12].copy_from_slice(&seq.to_be_bytes());b} else {packet(DATA,id,seq,stamp,w.size)};
                let instant=Instant::now();
                socket.send(&data).await?;
                first.get_or_insert(instant);
                state.sent_times[seq as usize]=Some(instant);
                state.samples[seq as usize]=Some(Sample{seq,send_unix_us:stamp,receive_unix_us:None,rtt_ms:None});
                state.sent+=1;
                if state.sent==w.count {
                    let span=instant.duration_since(first.expect("first send")).as_secs_f64();state.actual_span=Some(span);
                    if !echo {control(socket,END,id,w.count,(span*1_000_000.)as i64,state).await?;}
                    until=Some(tokio::time::Instant::now()+Duration::from_millis(w.drain_ms));
                }
            },
            r=socket.recv(&mut b)=>{
                let n=r?;
                if echo {record(&b[..n],id,w,state,true)?;} else {
                    match decode(&b[..n],id) {
                        Some((REGISTER,0,0)) if n==HEADER=>{state.control_received+=1;control(socket,ACK,id,0,0,state).await?;},
                        Some((ACK,0,0)) if n==HEADER=>state.control_received+=1,
                        _=>state.rejected+=1,
                    }
                }
            },
            _=async {tokio::time::sleep_until(until.expect("guarded deadline")).await},if until.is_some()=>break,
        }
    }
    Ok(start.elapsed().as_secs_f64())
}

/// Missing operations are infinity, so this is an unconditional nearest-rank quantile.
fn quantile(values: &[f64], count: usize, p: f64) -> Value {
    let index = (p * count as f64).ceil().max(1.) as usize - 1;
    values.get(index).map_or(json!("infinity"), |v| json!(v))
}
fn delays(samples: &[Option<Sample>], echo: bool) -> Vec<f64> {
    if echo {
        return samples.iter().flatten().filter_map(|s| s.rtt_ms).collect();
    }
    let transit = samples
        .iter()
        .flatten()
        .filter_map(|s| {
            s.receive_unix_us
                .map(|receive| i128::from(receive) - i128::from(s.send_unix_us))
        })
        .collect::<Vec<_>>();
    let min = transit.iter().copied().min().unwrap_or(0);
    transit
        .into_iter()
        .map(|v| (v - min) as f64 / 1000.)
        .collect()
}
fn report(
    identity: (&str, &str, &str),
    w: &Workload,
    state: &State,
    observation: f64,
    delivery: bool,
    echo: bool,
) -> Value {
    let (command, mode, direction) = identity;
    let mut result = json!({
        "command":command,"mode":mode,"direction":direction,"transport":w.transport,"local_addr":state.local_addr,"peer_addr":state.peer_addr,
        "route_note":"transport is metadata; target selection determines actual bypass",
        "final":true,"outcome":if state.interrupted {"interrupted"}else{"ok"},
        "requested_count":w.count,"expected_count":w.count,"run_id":w.run_id,"sample_unix_ms":unix_us().ok().map(|us|us/1000),"pid":std::process::id(),"sent":state.sent,"payload_bytes":w.size,"offered_pps":w.pps,
        "requested_send_span_seconds":requested_span(w),"send_span_seconds":state.actual_span,
        "observation_seconds":observation,"deadline_ms":w.deadline_ms,"drain_ms":w.drain_ms,
        "duplicate":state.duplicate,"corrupt":state.corrupt,"rejected_datagrams":state.rejected,
        "control_datagrams_sent":state.control_sent,"control_datagrams_received":state.control_received,
        "registration_attempts":state.registration_attempts,
        "delivery_status":if delivery {"receiver-observed"}else{"unavailable; receiver result is authoritative"},
        "measurement":if echo {"monotonic echo RTT"}else{"relative one-way transit delay; signed UNIX arrival minus send minus minimum; not absolute delay"},
        "loss_denominator":if echo {"successfully sent operations"}else{"configured sender count; reconcile with sender result"},
        "late_definition":if echo {"received RTT above deadline"}else{"received relative one-way delay above deadline"},
        "requested_offered_load_bps":f64::from(w.pps)*(w.size*8)as f64,
        "actual_offered_load_bps":state.actual_span.filter(|v|*v>0.).map(|span|f64::from(state.sent)*(w.size*8)as f64/span),
    });
    if delivery {
        let mut values = delays(&state.samples, echo);
        values.sort_by(f64::total_cmp);
        let count = if echo {
            state.sent as usize
        } else {
            w.count as usize
        };
        let received = values.len();
        let lost = count.saturating_sub(received);
        let late = values.iter().filter(|v| **v > w.deadline_ms as f64).count();
        let useful = received - late;
        let observed_span = state
            .samples
            .iter()
            .flatten()
            .filter(|s| s.receive_unix_us.is_some())
            .map(|s| s.send_unix_us)
            .collect::<Vec<_>>();
        let observed_span = observed_span
            .iter()
            .max()
            .zip(observed_span.iter().min())
            .map(|(max, min)| (i128::from(*max) - i128::from(*min)) as f64 / 1_000_000.);
        let v = result.as_object_mut().unwrap();
        v.extend(json!({"received":received,"lost":lost,"loss_rate":lost as f64/count.max(1)as f64,
            "late":late,"late_rate":late as f64/count.max(1)as f64,"deadline_misses":lost+late,
            "deadline_miss_rate":(lost+late)as f64/count.max(1)as f64,
            "quantile_population":count,"quantiles_include_missing_as_infinity":true,
            "p50_ms":quantile(&values,count,0.50),"p95_ms":quantile(&values,count,0.95),"p99_ms":quantile(&values,count,0.99),
            "useful_bytes":useful*w.size,"useful_goodput_bps":(useful*w.size*8)as f64/observation.max(f64::MIN_POSITIVE),
            "observed_send_span_seconds":observed_span}).as_object().unwrap().clone());
        // Receiver knows count, but cannot claim how many datagrams were actually sent.
        if !echo {
            v.insert("sent".into(), Value::Null);
            v.insert("actual_offered_load_bps".into(), Value::Null);
        }
    }
    result
}
fn save_samples(w: &Workload, state: &State) -> Result<()> {
    if let Some(path) = &w.samples_file {
        let samples = state
            .samples
            .iter()
            .enumerate()
            .map(|(seq, sample)| {
                sample.as_ref().map_or(
                    json!({"seq":seq,"send_unix_us":null,"receive_unix_us":null,"missing":true}),
                    |s| {
                        let mut v = serde_json::to_value(s).expect("sample serializes");
                        v["missing"] = json!(s.receive_unix_us.is_none());
                        v
                    },
                )
            })
            .collect::<Vec<_>>();
        write_json(
            Some(path),
            &json!({"requested_count":w.count,"samples":samples}),
        )?;
    }
    Ok(())
}
fn emit(w: &Workload, result: &Value) -> Result<()> {
    println!("{}", serde_json::to_string(result)?);
    write_json(w.result_file.as_deref(), result)
}
fn finish(w: &Workload, state: &State, result: Result<Value>, command: &str) -> Result<()> {
    let samples_error = save_samples(w, state).err();
    match result {
        Ok(mut value) => {
            let error = if state.interrupted {
                Some("probe interrupted")
            } else if value["delivery_status"] == "receiver-observed"
                && value["received"].as_u64().unwrap_or(0) == 0
            {
                Some("probe unavailable: no valid data received")
            } else if state.corrupt > 0 || state.duplicate > 0 {
                Some("probe integrity failure")
            } else {
                None
            };
            if let Some(error) = error {
                value["outcome"] = json!(if state.interrupted {
                    "interrupted"
                } else {
                    "error"
                });
                value["error"] = json!(error);
            }
            if let Some(samples_error) = &samples_error {
                value["outcome"] = json!("error");
                value["samples_error"] = json!(samples_error.to_string());
            }
            emit(w, &value)?;
            if let Some(samples_error) = samples_error {
                return Err(samples_error);
            }
            if let Some(error) = error {
                bail!("{error}");
            }
            Ok(())
        }
        Err(error) => {
            let mut value = json!({"command":command,"final":true,"outcome":"error","error":error.to_string(),"local_addr":state.local_addr,"peer_addr":state.peer_addr,"transport":w.transport,"requested_count":w.count,"expected_count":w.count,"run_id":w.run_id,"sample_unix_ms":unix_us().ok().map(|us|us/1000),"pid":std::process::id(),"sent":state.sent,"control_datagrams_sent":state.control_sent,"control_datagrams_received":state.control_received,"registration_attempts":state.registration_attempts,"rejected_datagrams":state.rejected});
            if let Some(samples_error) = samples_error {
                value["samples_error"] = json!(samples_error.to_string());
            }
            emit(w, &value)?;
            Err(error)
        }
    }
}
pub async fn run_probe(options: ProbeOptions) -> Result<()> {
    let w = &options.workload;
    // Validate before allocating memory, including on malformed CLI invocations.
    let id = match run_id(w, options.mode != Mode::Echo) {
        Ok(id) => id,
        Err(e) => return finish(w, &State::new(0), Err(e), "probe"),
    };
    let mut state = State::new(w.count);
    let result = async {
        let bind = options.listen.unwrap_or_else(|| {
            if options.target.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            }
        });
        let socket = UdpSocket::bind(bind).await?;
        state.local_addr = Some(socket.local_addr()?);
        socket.connect(options.target).await?;
        let local = socket.local_addr()?;
        state.local_addr = Some(local);
        state.peer_addr = Some(socket.peer_addr()?);
        let (duration, delivery, echo, mode, direction) = match options.mode {
            Mode::Echo => (
                send_stream(&socket, &id, w, &mut state, true).await?,
                true,
                true,
                "echo",
                "round-trip",
            ),
            Mode::Send => {
                register(&socket, &id, w, &mut state).await?;
                (
                    send_stream(&socket, &id, w, &mut state, false).await?,
                    false,
                    false,
                    "send",
                    "client_to_server",
                )
            }
            Mode::Receive => {
                register(&socket, &id, w, &mut state).await?;
                (
                    receive_stream(&socket, &id, w, &mut state).await?,
                    true,
                    false,
                    "receive",
                    "server_to_client",
                )
            }
        };
        let mut value = report(
            ("probe", mode, direction),
            w,
            &state,
            duration,
            delivery,
            echo,
        );
        value["listen"] = json!(local.to_string());
        value["target"] = json!(options.target.to_string());
        Ok(value)
    }
    .await;
    finish(w, &state, result, "probe")
}
pub async fn run_sink(options: SinkOptions) -> Result<()> {
    let w = &options.workload;
    let id = match run_id(w, true) {
        Ok(id) => id,
        Err(e) => return finish(w, &State::new(0), Err(e), "sink"),
    };
    let mut state = State::new(w.count);
    let result = async {
        let socket = UdpSocket::bind(options.listen).await?;
        state.local_addr = Some(socket.local_addr()?);
        ready(
            options.ready_file.as_deref(),
            "sink",
            &socket,
            w.run_id.as_deref(),
        )?;
        accept(&socket, &id, w, &mut state).await?;
        state.local_addr = Some(socket.local_addr()?);
        state.peer_addr = Some(socket.peer_addr()?);
        let (duration, delivery, mode, direction) = match options.role {
            Role::Receive => (
                receive_stream(&socket, &id, w, &mut state).await?,
                true,
                "receive",
                "client_to_server",
            ),
            Role::ReverseSource => (
                send_stream(&socket, &id, w, &mut state, false).await?,
                false,
                "reverse-source",
                "server_to_client",
            ),
        };
        let mut value = report(
            ("sink", mode, direction),
            w,
            &state,
            duration,
            delivery,
            false,
        );
        value["listen"] = json!(socket.local_addr()?.to_string());
        value["peer"] = json!(socket.peer_addr()?.to_string());
        Ok(value)
    }
    .await;
    finish(w, &state, result, "sink")
}
pub async fn echo(listen: SocketAddr, ready_file: Option<PathBuf>) -> Result<()> {
    let result=async {
        let socket=UdpSocket::bind(listen).await?;ready(ready_file.as_deref(),"echo",&socket,None)?;
        tracing::info!(%listen,"test echo ready");
        let mut b=[0u8;MAX_PAYLOAD+1];let mut received=0u64;let mut sent=0u64;
        loop {tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            r=socket.recv_from(&mut b)=>{let(n,peer)=r?;received+=1;if n<=MAX_PAYLOAD {socket.send_to(&b[..n],peer).await?;sent+=1;}}
        }}
        Ok(json!({"command":"echo","final":true,"outcome":"ok","received":received,"sent":sent}))
    }.await;
    match result {
        Ok(v) => {
            println!("{v}");
            Ok(())
        }
        Err(e) => {
            println!(
                "{}",
                json!({"command":"echo","final":true,"outcome":"error","error":format!("{e}")})
            );
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive_workload() -> Workload {
        Workload {
            count: 12,
            size: 100,
            pps: 200,
            deadline_ms: 100,
            drain_ms: 100,
            startup_timeout_ms: 100,
            run_id: None,
            transport: Transport::RawUdp,
            result_file: None,
            samples_file: None,
        }
    }

    #[test]
    fn slow_sequence_progress_keeps_tail_open_without_end_marker() {
        let w = receive_workload();
        let state = State::new(w.count);
        let start = tokio::time::Instant::now();
        let mut window = ReceiveWindow::new(&w, &state, start);
        let nominal_until = window.until;
        for seq in 0..w.count {
            // Explicit instants model 15 ms forwarding at a nominal 5 ms pace;
            // no real timer/scheduler can turn this into a fixture timeout.
            let now = start + Duration::from_millis(15 * u64::from(seq + 1));
            assert!(now < window.until, "sequence {seq} expired");
            window.progress(seq, &w, now);
        }
        let last_arrival = start + Duration::from_millis(180);
        assert!(last_arrival > nominal_until);
        assert_eq!(window.until, last_arrival + Duration::from_millis(100));
        // With no END or further valid progress, expiry remains finite.
        let final_until = window.until;
        window.progress(11, &w, final_until - Duration::from_millis(1));
        assert_eq!(window.until, final_until);
    }

    #[test]
    fn invalid_duplicate_and_out_of_order_packets_do_not_renew_observation() {
        let w = receive_workload();
        let id = [1; 16];
        let mut state = State::new(w.count);
        // Registration can have accepted the first data before receive_stream.
        let first = packet(DATA, &id, 2, 100, w.size);
        assert_eq!(record(&first, &id, &w, &mut state, false).unwrap(), Some(2));
        let start = tokio::time::Instant::now();
        let mut window = ReceiveWindow::new(&w, &state, start);
        assert_eq!(window.highest_sequence, Some(2));
        let until = window.until;
        let now = until - Duration::from_millis(1);
        let mut invalid = packet(DATA, &id, 3, 100, w.size);
        invalid[HEADER] ^= 1;
        for data in [first, invalid, packet(DATA, &id, 1, 100, w.size)] {
            if let Some(seq) = record(&data, &id, &w, &mut state, false).unwrap() {
                window.progress(seq, &w, now);
            }
            assert_eq!(window.until, until);
        }
        assert_eq!(state.duplicate, 1);
        assert_eq!(state.corrupt, 1);
        window.progress(3, &w, now);
        assert!(window.until > until);
    }

    #[test]
    fn first_end_fixes_drain_despite_later_data_or_duplicate_end() {
        let w = receive_workload();
        let start = tokio::time::Instant::now();
        let mut window = ReceiveWindow::new(&w, &State::new(w.count), start);
        let ended = start + Duration::from_millis(30);
        assert!(window.end(&w, ended));
        let until = ended + Duration::from_millis(w.drain_ms);
        assert_eq!(window.until, until);
        let late = until - Duration::from_millis(1);
        window.progress(11, &w, late);
        assert!(!window.end(&w, late));
        assert_eq!(window.until, until);
    }

    #[test]
    fn missing_is_infinity_and_relative_delay_is_offset_invariant() {
        let samples = |offset: i64| {
            vec![
                Some(Sample {
                    seq: 0,
                    send_unix_us: 100_000,
                    receive_unix_us: Some(90_000 + offset),
                    rtt_ms: None,
                }),
                None,
                Some(Sample {
                    seq: 2,
                    send_unix_us: 200_000,
                    receive_unix_us: Some(390_000 + offset),
                    rtt_ms: None,
                }),
            ]
        };
        let mut values = delays(&samples(0), false);
        values.sort_by(f64::total_cmp);
        assert_eq!(values, vec![0., 200.]);
        assert_eq!(values, delays(&samples(9_000_000), false));
        assert_eq!(quantile(&values, 3, 0.5), json!(200.));
        assert_eq!(quantile(&values, 3, 0.95), json!("infinity"));
        assert_eq!(quantile(&[], 3, 0.50), json!("infinity"));
        let w = Workload {
            count: 3,
            size: 100,
            pps: 100,
            deadline_ms: 100,
            drain_ms: 100,
            startup_timeout_ms: 100,
            run_id: None,
            transport: Transport::RawUdp,
            result_file: None,
            samples_file: None,
        };
        let mut state = State::new(3);
        state.samples = samples(0);
        let value = report(
            ("sink", "receive", "client_to_server"),
            &w,
            &state,
            1.,
            true,
            false,
        );
        assert_eq!(value["lost"], 1);
        assert_eq!(value["late"], 1);
        assert_eq!(value["loss_rate"], json!(1. / 3.));
        assert_eq!(value["late_rate"], json!(1. / 3.));
        assert_eq!(value["deadline_miss_rate"], json!(2. / 3.));
    }
}
