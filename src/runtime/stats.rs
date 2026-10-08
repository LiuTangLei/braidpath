//! Bounded, cumulative counters. Record, aggregate-symbol, QUIC-packet and relay
//! UDP-datagram units are deliberately separate; transport loss is not record loss.
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const FORWARD: &str = "client_to_server";
pub const RETURN: &str = "server_to_client";
const MAX_SCOPES: usize = 128;
const ID_WINDOW: u64 = 8192;

#[derive(Args, Clone, Default)]
pub struct Options {
    /// Final cumulative JSON snapshot, including orderly shutdown/error status.
    #[arg(long)]
    pub stats_file: Option<PathBuf>,
    /// Optional periodic cumulative JSON lines; the last line is the final snapshot.
    #[arg(long)]
    pub stats_jsonl: Option<PathBuf>,
    #[arg(long, default_value_t = 1000)]
    pub stats_interval_ms: u64,
}
#[derive(Default, Serialize)]
pub struct Wait {
    pub count: u64,
    pub sum_ms: f64,
    pub max_ms: f64,
    /// Upper bounds [1, 5, 10, 25, 50, 100, 250, 1000, infinity] ms.
    pub histogram: [u64; 9],
}
impl Wait {
    pub fn add(&mut self, age: Duration) {
        let ms = age.as_secs_f64() * 1000.0;
        self.count += 1;
        self.sum_ms += ms;
        self.max_ms = self.max_ms.max(ms);
        let i = [1., 5., 10., 25., 50., 100., 250., 1000.]
            .iter()
            .position(|b| ms <= *b)
            .unwrap_or(8);
        self.histogram[i] += 1;
    }
}
#[derive(Default, Serialize)]
pub struct Records {
    pub application_received: u64,
    pub application_oversize_dropped: u64,
    pub application_flow_limit_dropped: u64,
    pub application_unavailable_dropped: u64,
    pub ingress_queue_enqueued: u64,
    pub ingress_queue_full_dropped: u64,
    pub ingress_queue_closed_dropped: u64,
    pub ingress_shutdown_dropped: u64,
    pub sender_queue_enqueued: u64,
    pub sender_queue_full_dropped: u64,
    pub sender_queue_closed_dropped: u64,
    pub sender_input_consumed: u64,
    pub encoding_dropped: u64,
    pub input_shutdown_dropped: u64,
    pub repair_symbols_received: u64,
    pub original_packets_received: u64,
    pub original_records_delivered: u64,
    pub fec_records_recovered: u64,
    pub deduplicated: u64,
    pub stale_symbols_dropped: u64,
    pub invalid_symbols_dropped: u64,
    pub receiver_queue_full_dropped: u64,
    pub receiver_queue_closed_dropped: u64,
    pub receiver_shutdown_dropped: u64,
    pub udp_target_delivered: u64,
    pub udp_target_bytes: u64,
    pub udp_target_send_dropped: u64,
    pub udp_target_flow_dropped: u64,
}
#[derive(Default, Serialize)]
pub struct Symbols {
    pub originals_generated: u64,
    pub repairs_generated: u64,
    pub repairs_budget_skipped: u64,
    pub originals_enqueued: u64,
    pub repairs_enqueued: u64,
    pub originals_queue_full_dropped: u64,
    pub repairs_queue_full_dropped: u64,
    pub originals_expired_dropped: u64,
    pub repairs_expired_dropped: u64,
    pub expiry_wait: Wait,
    pub originals_shutdown_dropped: u64,
    pub repairs_shutdown_dropped: u64,
    pub originals_quinn_admitted: u64,
    pub repairs_quinn_admitted: u64,
    pub admitted_wait: Wait,
}
#[derive(Default, Serialize)]
pub struct Ids {
    pub highest_id: u64,
    pub floor_id: u64,
    pub recent: BTreeSet<u64>,
}
impl Ids {
    fn is_empty(&self) -> bool {
        self.recent.is_empty()
    }
    pub fn add(&mut self, id: u64) {
        self.highest_id = self.highest_id.max(id);
        self.floor_id = self.highest_id.saturating_sub(ID_WINDOW - 1);
        while self.recent.first().is_some_and(|v| *v < self.floor_id) {
            self.recent.pop_first();
        }
        if id >= self.floor_id {
            self.recent.insert(id);
        }
    }
}
#[derive(Default, Serialize)]
pub struct Direction {
    pub records: Records,
    pub symbols: Symbols,
    #[serde(skip_serializing_if = "Ids::is_empty")]
    pub quinn_admitted_record_ids: Ids,
    #[serde(skip_serializing_if = "Ids::is_empty")]
    pub generated_record_ids: Ids,
    #[serde(skip_serializing_if = "Ids::is_empty")]
    pub locally_dropped_original_ids: Ids,
    #[serde(skip_serializing_if = "Ids::is_empty")]
    pub udp_delivered_record_ids: Ids,
}
#[derive(Default, Serialize)]
pub struct Quinn {
    pub lost_packets: u64,
    pub congestion_events: u64,
    pub min_rtt_ms: f64,
    pub smoothed_rtt_ms: f64,
    pub congestion_window_bytes: u64,
    pub sent_packets: u64,
    pub udp_datagrams_tx: u64,
    pub udp_datagrams_rx: u64,
    pub udp_bytes_tx: u64,
    pub udp_bytes_rx: u64,
    pub http_datagram_frames_tx: u64,
    pub http_datagram_frames_rx: u64,
    pub closed: bool,
}
#[derive(Default, Serialize)]
pub struct Path {
    pub session_id: String,
    pub path_id: u8,
    pub request_stream_id: u64,
    pub authenticated: bool,
    pub quinn_admitted_originals: u64,
    pub quinn_admitted_repairs: u64,
    /// Attempt count, retried frames can increment this multiple times. Not a drop count.
    pub send_buffer_full_attempts: u64,
    pub quinn_send_error_attempts: u64,
    pub http_datagrams_received: u64,
    pub receiver_queue_full_dropped: u64,
    pub receiver_queue_closed_dropped: u64,
    pub invalid_http_datagrams_dropped: u64,
    pub repair_symbols_received: u64,
    pub original_packets_received: u64,
    pub original_records_delivered: u64,
    /// Attributed to the arrival triggering recovery, not the missing original's path.
    pub fec_records_recovered: u64,
    pub deduplicated: u64,
    pub stale_symbols_dropped: u64,
    pub invalid_symbols_dropped: u64,
    /// Local QUIC sender direction; UDP receive counters are the opposite direction.
    pub udp_target_delivered: u64,
    pub udp_target_send_dropped: u64,
    pub udp_target_flow_dropped: u64,
    pub sending_direction: String,
    pub quinn: Quinn,
}
#[derive(Default, Serialize)]
pub struct RelayDirection {
    pub received: u64,
    pub queue_enqueued: u64,
    pub forwarded: u64,
    pub forwarded_bytes: u64,
    pub unauthorized_dropped: u64,
    pub oversize_dropped: u64,
    pub impairment_dropped: u64,
    pub budget_dropped: u64,
    pub mapping_limit_dropped: u64,
    pub mapping_error_dropped: u64,
    pub queue_full_dropped: u64,
    pub mapping_closed_dropped: u64,
    pub socket_send_dropped: u64,
    pub shutdown_dropped: u64,
    pub mapping_expired_queue_dropped: u64,
    pub socket_send_cancelled_dropped: u64,
}
#[derive(Default, Serialize)]
pub struct State {
    pub ready: bool,
    pub configured_paths: usize,
    pub listener_bound: bool,
    pub target_configured: bool,
    pub shutdown_complete: bool,
    pub drain_incomplete: bool,
    pub directions: BTreeMap<String, Direction>,
    pub sessions: BTreeMap<String, BTreeMap<String, Direction>>,
    pub paths: BTreeMap<String, Path>,
    pub relay: BTreeMap<String, RelayDirection>,
    pub omitted_session_scopes: u64,
    pub omitted_path_scopes: u64,
    pub handshake_attempts: u64,
    pub handshake_successes: u64,
    pub handshake_failures: u64,
}
struct Inner {
    state: Mutex<State>,
    connections: Mutex<Vec<(String, quinn::Connection)>>,
    started: Instant,
    role: &'static str,
    instance_id: String,
    changed: tokio::sync::Notify,
}
#[derive(Clone)]
pub struct Metrics(Arc<Inner>);
#[derive(Clone)]
pub struct Scope {
    pub metrics: Metrics,
    pub session: String,
    pub direction: &'static str,
}
impl Metrics {
    pub fn new(role: &'static str) -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(State::default()),
            connections: Mutex::new(Vec::new()),
            started: Instant::now(),
            role,
            instance_id: super::transport::hex(&rand::random::<[u8; 16]>()),
            changed: tokio::sync::Notify::new(),
        }))
    }
    pub fn state(&self, f: impl FnOnce(&mut State)) {
        f(&mut self.0.state.lock().expect("stats lock"));
    }
    pub fn readiness(&self, ready: bool, configured_paths: usize) {
        self.state(|s| {
            s.ready = ready;
            s.listener_bound = ready;
            s.target_configured = ready;
            s.configured_paths = configured_paths;
        });
        self.0.changed.notify_one();
    }
    pub fn scope(&self, session: &str, direction: &'static str) -> Scope {
        self.state(|s| {
            if !s.sessions.contains_key(session) && s.sessions.len() < MAX_SCOPES {
                s.sessions.insert(session.to_owned(), BTreeMap::new());
            } else if !s.sessions.contains_key(session) {
                s.omitted_session_scopes += 1;
            }
        });
        Scope {
            metrics: self.clone(),
            session: session.to_owned(),
            direction,
        }
    }
    pub fn register(
        &self,
        session: &str,
        pid: u8,
        stream: u64,
        direction: &'static str,
        conn: &quinn::Connection,
    ) {
        let key = format!("{session}/{pid}");
        let mut connections = self.0.connections.lock().expect("stats connections lock");
        if connections.len() == MAX_SCOPES {
            self.state(|s| s.omitted_path_scopes += 1);
            return;
        }
        self.state(|s| {
            s.paths.insert(
                key.clone(),
                Path {
                    session_id: session.to_owned(),
                    path_id: pid,
                    request_stream_id: stream,
                    authenticated: true,
                    sending_direction: direction.to_owned(),
                    ..Default::default()
                },
            );
        });
        connections.push((key, conn.clone()));
        self.0.changed.notify_one();
    }
    pub fn snapshot(
        &self,
        final_snapshot: bool,
        outcome: &str,
        error: Option<&str>,
    ) -> Result<serde_json::Value> {
        let connections = self.0.connections.lock().expect("stats connections lock");
        let mut state = self.0.state.lock().expect("stats lock");
        for (key, conn) in connections.iter() {
            if let Some(path) = state.paths.get_mut(key) {
                let q = conn.stats();
                path.quinn = Quinn {
                    lost_packets: q.path.lost_packets,
                    congestion_events: q.path.congestion_events,
                    min_rtt_ms: q.path.min_rtt.as_secs_f64() * 1000.,
                    smoothed_rtt_ms: conn.rtt().as_secs_f64() * 1000.,
                    congestion_window_bytes: q.path.cwnd,
                    sent_packets: q.path.sent_packets,
                    udp_datagrams_tx: q.udp_tx.datagrams,
                    udp_datagrams_rx: q.udp_rx.datagrams,
                    udp_bytes_tx: q.udp_tx.bytes,
                    udp_bytes_rx: q.udp_rx.bytes,
                    http_datagram_frames_tx: q.frame_tx.datagram,
                    http_datagram_frames_rx: q.frame_rx.datagram,
                    closed: conn.close_reason().is_some(),
                };
            }
        }
        Ok(
            serde_json::json!({"schema_version":1,"process_id":std::process::id(),"instance_id":self.0.instance_id,"bounds":{"session_scopes":MAX_SCOPES,"path_scopes":MAX_SCOPES,"record_id_window":ID_WINDOW},"role":self.0.role,"final":final_snapshot,"outcome":outcome,"error":error,"elapsed_ms":self.0.started.elapsed().as_secs_f64()*1000.,"sample_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),"counters":"cumulative; units separated by records/symbols/quinn/relay; pre-path queues have aggregate scope","stats":&*state}),
        )
    }
}
impl Scope {
    pub fn update(&self, mut f: impl FnMut(&mut Direction)) {
        self.metrics.state(|s| {
            let aggregate = s.directions.entry(self.direction.to_owned()).or_default();
            f(aggregate);
            // IDs restart at each session; global totals must not merge these namespaces.
            aggregate.quinn_admitted_record_ids = Ids::default();
            aggregate.generated_record_ids = Ids::default();
            aggregate.locally_dropped_original_ids = Ids::default();
            aggregate.udp_delivered_record_ids = Ids::default();
            if let Some(session) = s.sessions.get_mut(&self.session) {
                f(session.entry(self.direction.to_owned()).or_default());
            }
        });
    }
    pub fn path(&self, pid: u8, f: impl FnOnce(&mut Path)) {
        self.metrics.state(|s| {
            if let Some(p) = s.paths.get_mut(&format!("{}/{pid}", self.session)) {
                f(p);
            }
        });
    }
}
/// Must outlive runtime cleanup. Periodic output is stopped before the final JSON.
pub struct Reporter {
    pub metrics: Metrics,
    options: Options,
    periodic: Option<tokio::task::JoinHandle<Result<()>>>,
    jsonl: Option<Arc<Mutex<File>>>,
}
impl Reporter {
    pub fn new(role: &'static str, options: Options) -> Result<Self> {
        ensure!(
            (10..=60_000).contains(&options.stats_interval_ms),
            "stats interval must be 10..60000 ms"
        );
        ensure!(
            options.stats_file.is_none() || options.stats_file != options.stats_jsonl,
            "final JSON and JSONL require distinct paths"
        );
        if let Some(path) = &options.stats_file {
            File::create(path).with_context(|| format!("create stats file {}", path.display()))?;
        }
        let jsonl = options
            .stats_jsonl
            .as_ref()
            .map(|p| {
                OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(p)
                    .map(|f| Arc::new(Mutex::new(f)))
            })
            .transpose()?;
        let metrics = Metrics::new(role);
        let periodic = jsonl.clone().map(|file| {
            let metrics = metrics.clone();
            let ms = options.stats_interval_ms;
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_millis(ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {_=tick.tick()=>{},_=metrics.0.changed.notified()=>{}}
                    let value = metrics.snapshot(false, "running", None)?;
                    let mut file = file.lock().expect("stats file lock");
                    serde_json::to_writer(&mut *file, &value)?;
                    file.write_all(b"\n")?;
                    file.flush()?;
                }
            })
        });
        Ok(Self {
            metrics,
            options,
            periodic,
            jsonl,
        })
    }
    pub async fn finish(mut self, result: Result<()>) -> Result<()> {
        let mut report_error = None;
        if let Some(task) = self.periodic.take() {
            task.abort();
            if let Ok(Err(e)) = task.await {
                report_error = Some(e);
            }
        }
        let error = result.as_ref().err().map(|e| format!("{e:#}"));
        self.metrics.state(|s| s.ready = false);
        let snapshot = self.metrics.snapshot(
            true,
            if result.is_ok() { "stopped" } else { "error" },
            error.as_deref(),
        )?;
        if let Some(path) = &self.options.stats_file {
            let mut file = File::create(path)?;
            serde_json::to_writer_pretty(&mut file, &snapshot)?;
            file.write_all(b"\n")?;
        }
        if let Some(file) = &self.jsonl {
            let mut file = file.lock().expect("stats file lock");
            serde_json::to_writer(&mut *file, &snapshot)?;
            file.write_all(b"\n")?;
            file.flush()?;
        }
        result?;
        if let Some(e) = report_error {
            return Err(e);
        }
        Ok(())
    }
}
