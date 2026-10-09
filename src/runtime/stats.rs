//! Bounded, cumulative counters. Record, aggregate-symbol, QUIC-packet and relay
//! UDP-datagram units are deliberately separate; transport loss is not record loss.
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
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
const MAX_CONNECTION_EVENTS: usize = 128;
const MAX_PREVIOUS_GENERATIONS: usize = 3;
const MAX_RETIRED_SESSIONS: usize = 8;

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
#[derive(Clone, Default, Serialize)]
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
#[derive(Clone, Default, Serialize)]
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
#[derive(Clone, Default, Serialize)]
pub struct Symbols {
    pub originals_generated: u64,
    pub repairs_generated: u64,
    pub repairs_budget_skipped: u64,
    pub originals_enqueued: u64,
    pub repairs_enqueued: u64,
    pub originals_queue_full_dropped: u64,
    pub repairs_queue_full_dropped: u64,
    pub originals_expired_dropped: u64,
    pub originals_ingress_expired_dropped: u64,
    pub repairs_expired_dropped: u64,
    pub expiry_wait: Wait,
    pub originals_shutdown_dropped: u64,
    pub repairs_shutdown_dropped: u64,
    pub originals_quinn_admitted: u64,
    pub repairs_quinn_admitted: u64,
    pub originals_quinn_admitted_bytes: u64,
    pub repairs_quinn_admitted_bytes: u64,
    pub feedback_deferred: u64,
    pub feedback_admitted: u64,
    pub probes_admitted: u64,
    pub repair_no_diverse_path: u64,
    pub admitted_wait: Wait,
}
#[derive(Clone, Default, Serialize)]
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
#[derive(Clone, Default, Serialize)]
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
#[derive(Clone, Default, Serialize)]
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
    /// Frame counts, not ACK bytes or physical egress bandwidth.
    pub ack_frames_tx: u64,
    pub ack_frames_rx: u64,
    pub ack_frequency_frames_tx: u64,
    pub ack_frequency_frames_rx: u64,
    pub immediate_ack_frames_tx: u64,
    pub immediate_ack_frames_rx: u64,
    pub closed: bool,
}
impl Quinn {
    fn sample(conn: &quinn::Connection) -> Self {
        let q = conn.stats();
        Self {
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
            ack_frames_tx: q.frame_tx.acks,
            ack_frames_rx: q.frame_rx.acks,
            ack_frequency_frames_tx: q.frame_tx.ack_frequency,
            ack_frequency_frames_rx: q.frame_rx.ack_frequency,
            immediate_ack_frames_tx: q.frame_tx.immediate_ack,
            immediate_ack_frames_rx: q.frame_rx.immediate_ack,
            closed: conn.close_reason().is_some(),
        }
    }
}
#[derive(Clone, Serialize)]
pub struct Generation {
    pub connection_id: usize,
    pub quinn: Quinn,
    pub local_socket: Option<String>,
    pub peer_socket: String,
    pub quality: Option<super::quality::Snapshot>,
}
#[derive(Clone, Default, Serialize)]
pub struct Path {
    pub connection_id: usize,
    /// Includes the current generation. Re-registering the same connection is idempotent.
    pub total_generations: u64,
    /// All superseded generations, including those outside the bounded snapshot history.
    pub retired_generations: u64,
    pub previous_generations: Vec<Generation>,
    pub rotation_attempts: u64,
    pub rotation_successes: u64,
    pub rotation_failures: u64,
    pub reconnect_attempts: u64,
    pub reconnect_successes: u64,
    pub reconnect_failures: u64,
    pub adaptive: Option<super::adaptive::Snapshot>,
    pub receiver_feedback: Option<super::quality::Snapshot>,
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
    pub local_socket: Option<String>,
    pub peer_socket: String,
    pub quinn: Quinn,
}
#[derive(Clone, Default, Serialize)]
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
#[derive(Clone, Default, Serialize)]
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
    /// IDs whose scalar scope snapshots are retained after all connection handles retire.
    pub retired_sessions: VecDeque<String>,
    pub retired_session_total: u64,
    pub evicted_session_scopes: u64,
    pub evicted_path_scopes: u64,
    pub handshake_attempts: u64,
    pub handshake_successes: u64,
    pub handshake_failures: u64,
    pub handshake_cancelled: u64,
    pub path_admission_attempts: u64,
    pub path_admission_successes: u64,
    pub path_admission_failures: u64,
    pub path_admission_cancelled: u64,
    pub connection_attempts: u64,
    pub connection_events: VecDeque<ConnectionEvent>,
    pub omitted_connection_events: u64,
}
impl State {
    fn evict_oldest_retired(&mut self) -> bool {
        let Some(session) = self.retired_sessions.pop_front() else {
            return false;
        };
        if self.sessions.remove(&session).is_some() {
            self.evicted_session_scopes += 1;
        }
        let before = self.paths.len();
        self.paths.retain(|_, path| path.session_id != session);
        self.evicted_path_scopes += (before - self.paths.len()) as u64;
        true
    }
}

/// Local diagnostic identifiers are independent of session credentials and IDs.
#[derive(Clone, Serialize)]
pub struct ConnectionEvent {
    pub connection_id: u64,
    pub phase: &'static str,
    pub stage: &'static str,
    pub remote: String,
    pub path_id: Option<u8>,
    pub outcome: &'static str,
    /// Controlled reason codes only, never headers or arbitrary peer close text.
    pub error: Option<&'static str>,
    pub elapsed_ms: f64,
    pub total_elapsed_ms: f64,
    pub process_elapsed_ms: f64,
    pub timeout_ms: Option<u64>,
    pub timeout_scope: Option<&'static str>,
}

/// Observes existing operations and timeouts without imposing additional ones.
pub struct ConnectionTrace {
    metrics: Metrics,
    connection_id: u64,
    remote: std::net::SocketAddr,
    path_id: Option<u8>,
    phase: &'static str,
    stage: &'static str,
    started: Instant,
    stage_started: Instant,
    handshake_complete: bool,
    admission_pending: bool,
    authenticated: bool,
    conn: Option<quinn::Connection>,
    finished: Option<bool>,
}
impl ConnectionTrace {
    pub fn new(
        metrics: Metrics,
        remote: std::net::SocketAddr,
        path_id: Option<u8>,
        stage: &'static str,
    ) -> Self {
        let mut connection_id = 0;
        metrics.state(|s| {
            s.connection_attempts += 1;
            s.handshake_attempts += 1;
            connection_id = s.connection_attempts;
        });
        let now = Instant::now();
        let trace = Self {
            metrics,
            connection_id,
            remote,
            path_id,
            phase: "quic_handshake",
            stage,
            started: now,
            stage_started: now,
            handshake_complete: false,
            admission_pending: false,
            authenticated: false,
            conn: None,
            finished: None,
        };
        trace.event("started", None);
        trace
    }
    fn event(&self, outcome: &'static str, error: Option<&'static str>) {
        let (timeout_ms, timeout_scope) = if self.metrics.0.role == "client" && !self.authenticated
        {
            (Some(8000), Some("whole_path"))
        } else {
            match self.stage {
                "incoming" | "request_resolve" | "peer_settings" => (Some(5000), Some("stage")),
                "admission_wait" => (Some(60000), Some("admission")),
                _ => (None, None),
            }
        };
        let event = ConnectionEvent {
            connection_id: self.connection_id,
            phase: self.phase,
            stage: self.stage,
            remote: self.remote.to_string(),
            path_id: self.path_id,
            outcome,
            error,
            elapsed_ms: self.stage_started.elapsed().as_secs_f64() * 1000.,
            total_elapsed_ms: self.started.elapsed().as_secs_f64() * 1000.,
            process_elapsed_ms: self.metrics.0.started.elapsed().as_secs_f64() * 1000.,
            timeout_ms,
            timeout_scope,
        };
        self.metrics.state(|s| {
            if s.connection_events.len() == MAX_CONNECTION_EVENTS {
                s.connection_events.pop_front();
                s.omitted_connection_events += 1;
            }
            s.connection_events.push_back(event);
        });
        self.metrics.0.changed.notify_one();
    }
    pub fn enter(&mut self, phase: &'static str, stage: &'static str) {
        self.enter_since(phase, stage, Instant::now());
    }
    pub fn enter_since(&mut self, phase: &'static str, stage: &'static str, since: Instant) {
        self.phase = phase;
        self.stage = stage;
        self.stage_started = since;
        self.event("started", None);
    }
    pub fn succeeded(&self) {
        self.event("succeeded", None);
    }
    pub fn handshake_succeeded(&mut self, conn: &quinn::Connection) {
        self.handshake_complete = true;
        self.conn = Some(conn.clone());
        self.metrics.state(|s| s.handshake_successes += 1);
        self.succeeded();
    }
    pub fn begin_admission(&mut self) {
        self.admission_pending = true;
        self.metrics.state(|s| s.path_admission_attempts += 1);
        self.enter("path_admission", "authenticate");
    }
    pub fn path_id(&mut self, pid: u8) {
        self.path_id = Some(pid);
    }
    pub fn admitted(&mut self) {
        self.admission_pending = false;
        self.authenticated = true;
        self.metrics.state(|s| s.path_admission_successes += 1);
        self.succeeded();
        self.enter("established", "connected");
    }
    pub fn rejected(&mut self, reason: &'static str) {
        if self.admission_pending {
            self.metrics.state(|s| s.path_admission_failures += 1);
            self.admission_pending = false;
        }
        self.event("rejected", Some(reason));
    }
    pub fn context(&self) -> String {
        format!(
            "connection={} phase={} stage={} remote={} path={:?} elapsed_ms={:.3} total_elapsed_ms={:.3}",
            self.connection_id,
            self.phase,
            self.stage,
            self.remote,
            self.path_id,
            self.stage_started.elapsed().as_secs_f64() * 1000.,
            self.started.elapsed().as_secs_f64() * 1000.
        )
    }
    pub fn failed(&mut self, reason: &'static str) {
        if !self.handshake_complete {
            self.metrics.state(|s| s.handshake_failures += 1);
        }
        if self.admission_pending {
            self.metrics.state(|s| s.path_admission_failures += 1);
            self.admission_pending = false;
        }
        self.event("failed", Some(reason));
        self.finished = Some(false);
    }
    /// Explicit local cancellation is normal even before authentication finishes.
    /// Preserve an already recorded failure and make repeated cleanup idempotent.
    pub fn cancelled(&mut self) {
        if self.finished.is_some() {
            return;
        }
        self.metrics.state(|s| {
            if !self.handshake_complete {
                s.handshake_cancelled += 1;
            }
            if self.admission_pending {
                s.path_admission_cancelled += 1;
            }
        });
        self.admission_pending = false;
        self.event("cancelled", Some("local_shutdown"));
        self.finished = Some(true);
    }
    /// A known local shutdown or an established peer's code-0 close is normal.
    /// Before admission, peer closure is still an admission failure if attempted.
    pub fn finish(&mut self, error: Option<&anyhow::Error>) -> bool {
        if let Some(normal) = self.finished {
            return normal;
        }
        let close = self.conn.as_ref().and_then(quinn::Connection::close_reason);
        let local = (matches!(close, Some(quinn::ConnectionError::LocallyClosed))
            || error.is_some_and(|e| {
                matches!(
                    e.downcast_ref::<quinn::ConnectionError>(),
                    Some(quinn::ConnectionError::LocallyClosed)
                )
            }))
            && !self.metrics.is_ready()
            && (self.metrics.0.role == "server" || self.authenticated);
        let peer_normal = matches!(&close, Some(quinn::ConnectionError::ApplicationClosed(e)) if e.error_code == quinn::VarInt::from_u32(0))
            || error.is_some_and(|e| {
                e.downcast_ref::<h3::error::ConnectionError>()
                    .is_some_and(|e| e.is_h3_no_error())
                    || e.downcast_ref::<h3::error::StreamError>()
                        .is_some_and(|e| e.is_h3_no_error())
            });
        if local {
            self.cancelled();
            return true;
        }
        if error.is_none() || (peer_normal && (self.authenticated || !self.admission_pending)) {
            self.event("closed", None);
            self.finished = Some(true);
            return true;
        }
        let reason =
            if error.is_some_and(|e| e.downcast_ref::<tokio::time::error::Elapsed>().is_some()) {
                "deadline_elapsed"
            } else {
                "operation_failed"
            };
        self.failed(reason);
        false
    }
}
struct Inner {
    state: Mutex<State>,
    // Only the current connection per logical path is retained. Historical
    // generations hold scalar snapshots and cannot keep retired endpoints alive.
    connections: Mutex<BTreeMap<String, quinn::Connection>>,
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
            connections: Mutex::new(BTreeMap::new()),
            started: Instant::now(),
            role,
            instance_id: super::transport::hex(&rand::random::<[u8; 16]>()),
            changed: tokio::sync::Notify::new(),
        }))
    }
    pub fn state(&self, f: impl FnOnce(&mut State)) {
        f(&mut self.0.state.lock().expect("stats lock"));
    }
    pub fn is_ready(&self) -> bool {
        self.0.state.lock().expect("stats lock").ready
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
            s.retired_sessions.retain(|id| id != session);
            if !s.sessions.contains_key(session) {
                while s.sessions.len() >= MAX_SCOPES && s.evict_oldest_retired() {}
                if s.sessions.len() < MAX_SCOPES {
                    s.sessions.insert(session.to_owned(), BTreeMap::new());
                } else {
                    s.omitted_session_scopes += 1;
                }
            }
        });
        Scope {
            metrics: self.clone(),
            session: session.to_owned(),
            direction,
        }
    }
    /// Release a finished session's connection handles while retaining a small
    /// tail of scalar snapshots for final reports. New active scopes take priority
    /// over this history; process-wide direction totals are never evicted.
    pub fn retire_session(&self, session: &str) {
        let mut connections = self.0.connections.lock().expect("stats connections lock");
        let mut state = self.0.state.lock().expect("stats lock");
        let mut known = state.sessions.contains_key(session);
        for (key, path) in state
            .paths
            .iter_mut()
            .filter(|(_, path)| path.session_id == session)
        {
            known = true;
            if let Some(conn) = connections.remove(key) {
                path.peer_socket = conn.remote_address().to_string();
                path.quinn = Quinn::sample(&conn);
            }
        }
        if known && !state.retired_sessions.iter().any(|id| id == session) {
            state.retired_sessions.push_back(session.to_owned());
            state.retired_session_total += 1;
        }
        while state.retired_sessions.len() > MAX_RETIRED_SESSIONS {
            state.evict_oldest_retired();
        }
        self.0.changed.notify_one();
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
        if !connections.contains_key(&key) && connections.len() >= MAX_SCOPES {
            self.state(|s| s.omitted_path_scopes += 1);
            return;
        }
        let mut accepted = false;
        self.state(|s| {
            s.retired_sessions.retain(|id| id != session);
            if !s.paths.contains_key(&key) {
                while s.paths.len() >= MAX_SCOPES && s.evict_oldest_retired() {}
                if s.paths.len() >= MAX_SCOPES {
                    s.omitted_path_scopes += 1;
                    return;
                }
            }
            let path = s.paths.entry(key.clone()).or_default();
            if path.authenticated && path.connection_id != conn.stable_id() {
                // Capture the old connection at retirement even when no periodic
                // reporter sampled its final traffic. Do not retain its handle.
                if let Some(previous) = connections.get(&key) {
                    path.quinn = Quinn::sample(previous);
                    path.peer_socket = previous.remote_address().to_string();
                }
                if path.previous_generations.len() == MAX_PREVIOUS_GENERATIONS {
                    path.previous_generations.remove(0);
                }
                path.previous_generations.push(Generation {
                    connection_id: path.connection_id,
                    quinn: std::mem::take(&mut path.quinn),
                    local_socket: path.local_socket.take(),
                    peer_socket: path.peer_socket.clone(),
                    quality: path.receiver_feedback.take(),
                });
                path.retired_generations += 1;
                path.total_generations += 1;
                path.adaptive = None;
            } else if !path.authenticated {
                path.total_generations = 1;
            }
            path.connection_id = conn.stable_id();
            path.session_id = session.to_owned();
            path.path_id = pid;
            path.request_stream_id = stream;
            path.authenticated = true;
            path.sending_direction = direction.to_owned();
            path.peer_socket = conn.remote_address().to_string();
            path.quinn = Quinn::sample(conn);
            accepted = true;
        });
        if accepted {
            connections.insert(key, conn.clone());
            self.0.changed.notify_one();
        }
    }
    pub fn snapshot(
        &self,
        final_snapshot: bool,
        outcome: &str,
        error: Option<&str>,
    ) -> Result<serde_json::Value> {
        let (state, elapsed_ms, sample_unix_ms) = {
            let connections = self.0.connections.lock().expect("stats connections lock");
            let mut state = self.0.state.lock().expect("stats lock");
            for (key, conn) in connections.iter() {
                if let Some(path) = state.paths.get_mut(key) {
                    path.peer_socket = conn.remote_address().to_string();
                    path.quinn = Quinn::sample(conn);
                }
            }
            let elapsed_ms = self.0.started.elapsed().as_secs_f64() * 1000.;
            let sample_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
            // Copy bounded scalar state only. The JSON tree can contain several
            // full ID windows and must not keep packet-path metrics locked while
            // it allocates and serializes. No Connection handles enter this copy.
            (state.clone(), elapsed_ms, sample_unix_ms)
        };
        Ok(
            serde_json::json!({"schema_version":1,"process_id":std::process::id(),"instance_id":self.0.instance_id,"bounds":{"session_scopes":MAX_SCOPES,"path_scopes":MAX_SCOPES,"connection_events":MAX_CONNECTION_EVENTS,"record_id_window":ID_WINDOW,"previous_generations_per_path":MAX_PREVIOUS_GENERATIONS,"current_connection_references":MAX_SCOPES,"retired_session_snapshots":MAX_RETIRED_SESSIONS},"role":self.0.role,"final":final_snapshot,"outcome":outcome,"error":error,"elapsed_ms":elapsed_ms,"sample_unix_ms":sample_unix_ms,"counters":"cumulative; units separated by records/symbols/quinn/relay; pre-path queues have aggregate scope","stats":state}),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::transport::{self, Congestion};
    use bytes::Bytes;
    use tokio::time::timeout;

    #[test]
    fn explicit_pre_admission_cancellation_is_normal_and_counted_once() {
        let metrics = Metrics::new("client");
        let mut trace = ConnectionTrace::new(
            metrics.clone(),
            "127.0.0.1:1".parse().unwrap(),
            Some(0),
            "quic_connect",
        );
        trace.cancelled();
        trace.cancelled();
        assert!(trace.finish(Some(&anyhow::anyhow!("connection future cancelled"))));
        metrics.state(|state| {
            assert_eq!(state.handshake_attempts, 1);
            assert_eq!(state.handshake_cancelled, 1);
            assert_eq!(state.handshake_failures, 0);
            assert_eq!(state.path_admission_failures, 0);
            assert_eq!(
                state
                    .connection_events
                    .iter()
                    .filter(|event| event.outcome == "cancelled")
                    .count(),
                1
            );
            assert_eq!(
                state.connection_events.back().unwrap().error,
                Some("local_shutdown")
            );
        });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retired_session_history_never_blocks_new_epochs_or_loses_process_totals() {
        let temp = tempfile::tempdir().unwrap();
        let identity = temp.path().join("identity");
        transport::initialize(&identity, "localhost").unwrap();
        let server = transport::server(
            "127.0.0.1:0".parse().unwrap(),
            &identity.join("cert.pem"),
            &identity.join("key.pem"),
            Congestion::Bbr,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let client =
            transport::client(address, &identity.join("cert.pem"), None, Congestion::Bbr).unwrap();
        let (outgoing, incoming) = timeout(Duration::from_secs(3), async {
            tokio::join!(client.connect(address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await
            })
        })
        .await
        .unwrap();
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        let metrics = Metrics::new("test");
        let epochs = MAX_SCOPES + 72;
        for epoch in 0..epochs {
            let sid = format!("epoch-{epoch}");
            let scope = metrics.scope(&sid, FORWARD);
            scope.update(|direction| {
                direction.records.application_received += 1;
                direction.generated_record_ids.add(0);
            });
            metrics.register(&sid, 0, 0, FORWARD, &outgoing);
            assert_eq!(metrics.0.connections.lock().unwrap().len(), 1);
            metrics.state(|state| {
                assert!(state.sessions.contains_key(&sid));
                assert!(state.paths.contains_key(&format!("{sid}/0")));
                assert_eq!(state.omitted_path_scopes, 0);
                assert_eq!(state.omitted_session_scopes, 0);
            });
            metrics.retire_session(&sid);
            metrics.retire_session(&sid);
            assert!(metrics.0.connections.lock().unwrap().is_empty());
            metrics.state(|state| {
                assert!(state.sessions.len() <= MAX_RETIRED_SESSIONS);
                assert!(state.paths.len() <= MAX_RETIRED_SESSIONS);
                assert_eq!(state.retired_session_total, (epoch + 1) as u64);
            });
        }
        metrics.state(|state| {
            assert_eq!(
                state.directions[FORWARD].records.application_received,
                epochs as u64
            );
            assert_eq!(state.retired_sessions.len(), MAX_RETIRED_SESSIONS);
            assert_eq!(
                state.evicted_session_scopes,
                (epochs - MAX_RETIRED_SESSIONS) as u64
            );
            assert_eq!(
                state.evicted_path_scopes,
                (epochs - MAX_RETIRED_SESSIONS) as u64
            );
            assert!(
                state
                    .sessions
                    .contains_key(&format!("epoch-{}", epochs - 1))
            );
        });
        // At scope pressure, only retired history is evicted. Every new active
        // scope remains observable until the actual concurrent bound is reached.
        for active in 0..MAX_SCOPES {
            let sid = format!("active-{active}");
            metrics.scope(&sid, FORWARD);
            metrics.register(&sid, 0, 0, FORWARD, &outgoing);
            metrics.state(|state| {
                assert!(state.sessions.len() <= MAX_SCOPES);
                assert!(state.paths.len() <= MAX_SCOPES);
                assert!(state.paths.contains_key(&format!("{sid}/0")));
                assert_eq!(state.omitted_session_scopes, 0);
                assert_eq!(state.omitted_path_scopes, 0);
            });
        }
        assert_eq!(metrics.0.connections.lock().unwrap().len(), MAX_SCOPES);
        metrics.scope("overflow", FORWARD);
        metrics.register("overflow", 0, 0, FORWARD, &outgoing);
        metrics.state(|state| {
            assert!(state.retired_sessions.is_empty());
            assert_eq!(state.omitted_session_scopes, 1);
            assert_eq!(state.omitted_path_scopes, 1);
            assert!(state.paths.contains_key("active-0/0"));
            assert_eq!(
                state.directions[FORWARD].records.application_received,
                epochs as u64
            );
        });
        outgoing.close(0u32.into(), b"test complete");
        incoming.close(0u32.into(), b"test complete");
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn repeated_rejoins_keep_current_monitoring_and_bounded_retired_snapshots() {
        let temp = tempfile::tempdir().unwrap();
        let identity = temp.path().join("identity");
        transport::initialize(&identity, "localhost").unwrap();
        let server = transport::server(
            "127.0.0.1:0".parse().unwrap(),
            &identity.join("cert.pem"),
            &identity.join("key.pem"),
            Congestion::Bbr,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let client =
            transport::client(address, &identity.join("cert.pem"), None, Congestion::Bbr).unwrap();
        let metrics = Metrics::new("test");
        let scope = metrics.scope("session", FORWARD);
        let mut ids = Vec::new();
        for generation in 0..140u64 {
            let (outgoing, incoming) = timeout(Duration::from_secs(3), async {
                tokio::join!(client.connect(address, "localhost").unwrap(), async {
                    server.accept().await.unwrap().await
                })
            })
            .await
            .unwrap();
            let outgoing = outgoing.unwrap();
            let incoming = incoming.unwrap();
            ids.push(outgoing.stable_id());
            metrics.register("session", 0, 0, FORWARD, &outgoing);
            // Repeated registration of one connection must not consume history.
            metrics.register("session", 0, 0, FORWARD, &outgoing);
            outgoing
                .send_datagram(Bytes::from_static(b"retirement sample"))
                .unwrap();
            let received = timeout(Duration::from_secs(3), incoming.read_datagram())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.as_ref(), b"retirement sample");
            scope.path(0, |path| path.quinn_admitted_originals += 1);
            assert_eq!(metrics.0.connections.lock().unwrap().len(), 1);
            metrics.state(|state| {
                assert_eq!(state.paths.len(), 1);
                assert_eq!(state.omitted_path_scopes, 0);
                let path = &state.paths["session/0"];
                assert_eq!(path.connection_id, outgoing.stable_id());
                assert_eq!(path.total_generations, generation + 1);
                assert_eq!(path.retired_generations, generation);
                assert_eq!(path.quinn_admitted_originals, generation + 1);
                let old = &ids[..ids.len() - 1];
                let retained = &old[old.len().saturating_sub(MAX_PREVIOUS_GENERATIONS)..];
                assert_eq!(
                    path.previous_generations
                        .iter()
                        .map(|entry| entry.connection_id)
                        .collect::<Vec<_>>(),
                    retained
                );
                for old in &path.previous_generations {
                    // No periodic snapshot was taken. Registration must sample
                    // the old connection's traffic before releasing its handle.
                    assert_eq!(old.quinn.http_datagram_frames_tx, 1);
                    assert!(old.quinn.closed);
                }
            });
            outgoing.close(0u32.into(), b"generation complete");
            incoming.close(0u32.into(), b"generation complete");
        }
        let snapshot = metrics.snapshot(true, "stopped", None).unwrap();
        let path = &snapshot["stats"]["paths"]["session/0"];
        assert_eq!(path["total_generations"], 140);
        assert_eq!(path["retired_generations"], 139);
        assert_eq!(path["quinn"]["http_datagram_frames_tx"], 1);
        assert_eq!(path["previous_generations"].as_array().unwrap().len(), 3);
        assert_eq!(snapshot["stats"]["omitted_path_scopes"], 0);
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
        timeout(Duration::from_secs(3), async {
            tokio::join!(client.wait_idle(), server.wait_idle());
        })
        .await
        .unwrap();
    }
}
