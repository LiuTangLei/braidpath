//! Bounded, cumulative counters. Record, aggregate-symbol, QUIC-packet and relay
//! UDP-datagram units are deliberately separate; transport loss is not record loss.
use super::{trace, wire};
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{File, OpenOptions},
    io::Write,
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
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
    /// Omit dual bulk repairs only when more than two originals in that block
    /// were permanently rejected locally. Off by default; no added credit.
    #[arg(long)]
    pub repair_usefulness_guard: bool,
    /// Per-source RTT baselines are the default. With --legacy-recovery,
    /// re-enable this correction without changing the other legacy controls.
    #[arg(long, hide = true)]
    pub rtt_source_baselines: bool,
    /// Random-loss service accounting with the minimum floor (at most 25%).
    /// Only meaningful with --legacy-recovery; hidden, kept for old scripts.
    #[arg(long, hide = true)]
    pub random_loss_service: bool,
    /// Queue-gated loss pacing, now the default; hidden, kept for old
    /// scripts. Together with --legacy-recovery it re-enables only this part.
    #[arg(long, hide = true)]
    pub queue_gated_loss: bool,
    /// Restore the earlier adaptive controller: 100 ms brake debounce,
    /// post-brake restoration only from a qualified 500 ms service window, and
    /// loss-only brakes at any queue delay (no queue-gated loss pacing), and
    /// the old shared RTT baseline across estimators.
    #[arg(long)]
    pub legacy_recovery: bool,
    /// Experimental native-window service recovery; off by default. Adaptive
    /// health, delay/loss brakes, native BBR and all configured caps remain.
    #[arg(long)]
    pub native_service_guard: bool,
    /// Experimental local small-lane finish preference; defaults off. No new pacing credit.
    #[arg(long)]
    pub frontier_scheduler: bool,
    #[command(flatten)]
    pub trace: trace::Options,
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
    /// Accepted beyond record-ID history; byte-stream dedup decides uniqueness.
    pub late_stream_records_received: u64,
    pub messages_admission_dropped: u64,
    pub messages_reassembled: u64,
    pub message_reassembly_dropped: u64,
    pub message_reassembly_failures: MessageFailures,
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

#[derive(Clone, Copy, Default, Serialize)]
pub struct MessageFailures {
    pub expired: u64,
    pub window: u64,
    pub capacity: u64,
    pub invalid: u64,
    pub conflict: u64,
    pub shutdown: u64,
}
impl MessageFailures {
    pub(crate) fn add(&mut self, other: Self) {
        self.expired += other.expired;
        self.window += other.window;
        self.capacity += other.capacity;
        self.invalid += other.invalid;
        self.conflict += other.conflict;
        self.shutdown += other.shutdown;
    }
    pub(crate) fn since(self, old: Self) -> Self {
        Self {
            expired: self.expired - old.expired,
            window: self.window - old.window,
            capacity: self.capacity - old.capacity,
            invalid: self.invalid - old.invalid,
            conflict: self.conflict - old.conflict,
            shutdown: self.shutdown - old.shutdown,
        }
    }
}
#[derive(Clone, Default, Serialize)]
pub struct UdpDelivery {
    /// Live decoded records waiting at the local UDP boundary, not sender symbols.
    pub pending_records: u64,
    /// Queued UDP payload bytes; bounded queue bookkeeping is separate.
    pub pending_bytes: u64,
    pub peak_pending_records: u64,
    pub peak_pending_bytes: u64,
    /// Includes records retained behind an already blocked local socket/peer flow.
    pub queued_records: u64,
    /// Initial nonblocking send attempts reporting WouldBlock; not terminal drops.
    pub would_block_events: u64,
    pub delayed_delivered: u64,
    /// Local decode-to-completion time for queued records, including terminal drops.
    pub queued_wait: Wait,
    pub expired_dropped: u64,
    pub queue_full_dropped: u64,
    /// Per-socket/peer pending limit, separate from the runtime flow-table limit.
    pub flow_full_dropped: u64,
    /// Pending UDP payload bytes; queue bookkeeping is outside this byte count.
    pub byte_limit_dropped: u64,
    pub socket_error_dropped: u64,
    pub shutdown_dropped: u64,
}
#[derive(Clone, Default, Serialize)]
pub struct Symbols {
    pub originals_generated: u64,
    pub repairs_generated: u64,
    /// Shadow census in both modes. Counts repairs, not recoverable records.
    pub repairs_locally_unrecoverable: u64,
    pub repairs_locally_unrecoverable_bytes: u64,
    /// Generated but not queued/admitted. Bytes exclude quality/HTTP framing.
    pub repairs_locally_unrecoverable_skipped: u64,
    pub repairs_locally_unrecoverable_skipped_bytes: u64,
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
    /// Explicit mixed mode only. Counts are generated symbols, not FEC recoveries.
    pub mixed_small_originals_generated: u64,
    pub mixed_small_repairs_generated: u64,
    pub mixed_bulk_originals_generated: u64,
    pub mixed_bulk_repairs_generated: u64,
    /// Per-admitted-small-original maximum repair authorization. This is not wire traffic.
    pub mixed_small_repair_reserved_bytes: u64,
    /// Actual HTTP DATAGRAM bytes admitted to Quinn; exclude UDP/IP/QUIC encryption overhead.
    pub mixed_small_repair_admitted_bytes: u64,
    pub mixed_bulk_original_admitted_bytes: u64,
    pub mixed_bulk_repair_admitted_bytes: u64,
    pub mixed_small_repairs_quinn_admitted: u64,
    pub mixed_bulk_repairs_quinn_admitted: u64,
    /// Large-record repairs omitted for lack of their own admission-earned credit.
    pub mixed_bulk_repairs_budget_skipped: u64,
    /// Encoded Braid/FEC bytes skipped before path selection, excluding quality/HTTP headers.
    pub mixed_bulk_repair_budget_skipped_bytes: u64,
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
    #[serde(skip)]
    suppressed: bool,
}
impl Ids {
    fn suppressed() -> Self {
        Self {
            suppressed: true,
            ..Self::default()
        }
    }
    fn is_empty(&self) -> bool {
        self.recent.is_empty()
    }
    pub fn add(&mut self, id: u64) {
        if self.suppressed {
            return;
        }
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
    pub udp_delivery: UdpDelivery,
    /// Receiver-local gauges/counters, only in the owning session/direction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec_retention: Option<super::fec_retention::Snapshot>,
    /// Sender-local automatic FEC strength and finalized pre-FEC loss basis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automatic_fec: Option<super::automatic_fec::Snapshot>,
    /// Sender-local cap from reverse loss on the peer's shared uplink.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_guard: Option<super::reverse_guard::Snapshot>,
    /// Sender-local cap from forward loss on a bottleneck all paths share.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_guard: Option<super::forward_guard::Snapshot>,
    /// Sender-owned preview counters; not packet losses or time-at-limit percentages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_frontier: Option<super::sender_frontier::Snapshot>,
    /// Reliable TCP stream counters, published by this endpoint's stream adapter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_streams: Option<super::stream::Snapshot>,
    #[serde(skip_serializing_if = "Ids::is_empty")]
    pub quinn_admitted_record_ids: Ids,
    #[serde(skip_serializing_if = "Ids::is_empty")]
    pub generated_record_ids: Ids,
    #[serde(skip_serializing_if = "Ids::is_empty")]
    pub locally_dropped_original_ids: Ids,
    #[serde(skip_serializing_if = "Ids::is_empty")]
    pub udp_delivered_record_ids: Ids,
}
impl Direction {
    fn aggregate() -> Self {
        Self {
            quinn_admitted_record_ids: Ids::suppressed(),
            generated_record_ids: Ids::suppressed(),
            locally_dropped_original_ids: Ids::suppressed(),
            udp_delivered_record_ids: Ids::suppressed(),
            ..Self::default()
        }
    }
}
#[derive(Clone, Default, Serialize)]
pub struct Quinn {
    pub lost_packets: u64,
    pub congestion_events: u64,
    pub min_rtt_ms: f64,
    pub smoothed_rtt_ms: f64,
    pub congestion_window_bytes: u64,
    /// Controller-reported pacing target in bits/s, not observed delivery capacity.
    pub pacing_rate_bps: Option<u64>,
    /// Native controller phase, not inferred from a smaller congestion window.
    pub native_rtt_probe: bool,
    /// Payload bytes currently available for another outgoing QUIC datagram.
    /// Quinn reserves its datagram metadata; this is not the configured buffer size.
    pub datagram_send_buffer_space_bytes: u64,
    pub sent_packets: u64,
    pub udp_datagrams_tx: u64,
    pub udp_datagrams_rx: u64,
    pub udp_bytes_tx: u64,
    pub udp_bytes_rx: u64,
    /// Quinn's native `ios` counters, not measured kernel syscall counts.
    /// The pinned implementation counts TX transmit batches and RX QUIC packet handling.
    /// A TX datagram/operation ratio indicates batching offered to the UDP layer;
    /// it does not prove that the kernel performed GSO.
    pub udp_io_operations_tx: u64,
    pub udp_io_operations_rx: u64,
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
            pacing_rate_bps: conn.congestion_state().metrics().pacing_rate,
            native_rtt_probe: conn.probing_rtt_hint(),
            datagram_send_buffer_space_bytes: conn.datagram_send_buffer_space() as u64,
            sent_packets: q.path.sent_packets,
            udp_datagrams_tx: q.udp_tx.datagrams,
            udp_datagrams_rx: q.udp_rx.datagrams,
            udp_bytes_tx: q.udp_tx.bytes,
            udp_bytes_rx: q.udp_rx.bytes,
            udp_io_operations_tx: q.udp_tx.ios,
            udp_io_operations_rx: q.udp_rx.ios,
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
    /// Independent probe payload delivery, never business goodput or a capacity estimate.
    pub capacity_probe: Option<super::quality::Snapshot>,
    pub capacity_probe_rate: Option<super::capacity_probe::RateSnapshot>,
    pub session_id: String,
    pub path_id: u8,
    pub request_stream_id: u64,
    pub authenticated: bool,
    pub quinn_admitted_originals: u64,
    pub quinn_admitted_repairs: u64,
    /// The explicitly protected small-record subset of the admission counters.
    pub quinn_admitted_small_originals: u64,
    pub quinn_admitted_small_repairs: u64,
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
    pub mesh_uplinks: Vec<MeshUplink>,
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
    /// Handshakes whose 0-RTT data was accepted (either role) or rejected
    /// (client only).
    pub zero_rtt_accepted: u64,
    pub zero_rtt_rejected: u64,
    pub path_admission_attempts: u64,
    pub path_admission_successes: u64,
    pub path_admission_failures: u64,
    pub path_admission_cancelled: u64,
    pub connection_attempts: u64,
    pub connection_events: VecDeque<ConnectionEvent>,
    pub omitted_connection_events: u64,
}

#[derive(Clone, Serialize)]
pub struct MeshUplink {
    pub group: u8,
    pub interface: Option<String>,
    pub source_ip: Option<String>,
    pub state: &'static str,
    pub usable_paths: usize,
    pub path_limit: usize,
    pub configured_paths: usize,
    pub control_starts: u64,
    pub failure: Option<&'static str>,
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
/// How a handshake that allowed early data completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarlyData {
    Accepted,
    /// Completed without early data: rejected, or (server) none was sent.
    Rejected,
    Failed,
}

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
    /// Set when a handshake that began with early data completes.
    early_confirmed: Option<Arc<std::sync::atomic::AtomicBool>>,
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
            early_confirmed: None,
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
                "http3_setup" | "admission_wait" => {
                    (Some(super::tunnel::ADMISSION_TIMEOUT_MS), Some("admission"))
                }
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
    /// The connection is usable before its handshake completes (client 0-RTT,
    /// server 0.5-RTT). A handshake success is counted when it completes; the
    /// receiver reports the outcome.
    pub fn early_data(
        &mut self,
        conn: &quinn::Connection,
        accepted: quinn::ZeroRttAccepted,
    ) -> tokio::sync::watch::Receiver<Option<EarlyData>> {
        self.conn = Some(conn.clone());
        let confirmed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.early_confirmed = Some(confirmed.clone());
        let metrics = self.metrics.clone();
        let client = self.metrics.0.role == "client";
        let (tx, rx) = tokio::sync::watch::channel(None);
        let conn = conn.clone();
        tokio::spawn(async move {
            // False also when the handshake fails, or (server) no early data was sent.
            let outcome = if accepted.await {
                EarlyData::Accepted
            } else if conn.close_reason().is_none() {
                EarlyData::Rejected
            } else {
                EarlyData::Failed
            };
            let completed = outcome != EarlyData::Failed;
            confirmed.store(completed, std::sync::atomic::Ordering::Relaxed);
            metrics.state(|s| {
                s.handshake_successes += u64::from(completed);
                s.zero_rtt_accepted += u64::from(outcome == EarlyData::Accepted);
                // A client offers early data only with a ticket; a server
                // cannot tell a rejection from a client that sent none.
                s.zero_rtt_rejected += u64::from(client && outcome == EarlyData::Rejected);
            });
            let _ = tx.send(Some(outcome));
        });
        self.succeeded();
        rx
    }
    /// A fresh handshake on the same path attempt, after the server rejected
    /// 0-RTT. The rejected handshake completed and was counted; this one is a
    /// new attempt with its own outcome.
    pub fn retry_handshake(&mut self) {
        self.handshake_complete = false;
        self.early_confirmed = None;
        self.conn = None;
        self.metrics.state(|s| s.handshake_attempts += 1);
        self.enter("quic_handshake", "quic_connect");
    }
    fn handshake_done(&self) -> bool {
        self.handshake_complete
            || self
                .early_confirmed
                .as_ref()
                .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
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
        if !self.handshake_done() {
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
        let handshake_done = self.handshake_done();
        self.metrics.state(|s| {
            if !handshake_done {
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
    legacy_recovery: bool,
    repair_usefulness_guard: bool,
    rtt_source_baselines: bool,
    random_loss_service: bool,
    queue_gated_loss: bool,
    native_service_guard: bool,
    frontier_scheduler: bool,
    state: Mutex<State>,
    // Only the current connection per logical path is retained. Historical
    // generations hold scalar snapshots and cannot keep retired endpoints alive.
    connections: Mutex<BTreeMap<String, quinn::Connection>>,
    started: Instant,
    role: &'static str,
    instance_id: String,
    changed: tokio::sync::Notify,
    trace: trace::Trace,
}
#[derive(Clone)]
pub struct Metrics(Arc<Inner>);
#[derive(Clone)]
pub struct Scope {
    pub metrics: Metrics,
    pub session: String,
    pub direction: &'static str,
    trace_context: Option<trace::Context>,
}
impl Metrics {
    pub fn new(role: &'static str) -> Self {
        Self::new_with_trace(role, trace::Trace::disabled())
    }
    pub fn new_with_trace(role: &'static str, trace: trace::Trace) -> Self {
        Self::configured(role, trace, false)
    }
    fn configured(role: &'static str, trace: trace::Trace, frontier_scheduler: bool) -> Self {
        Self::configured_service(role, trace, frontier_scheduler, false)
    }
    fn configured_service(
        role: &'static str,
        trace: trace::Trace,
        frontier_scheduler: bool,
        native_service_guard: bool,
    ) -> Self {
        Self::configured_rtt(role, trace, frontier_scheduler, native_service_guard, false)
    }
    fn configured_rtt(
        role: &'static str,
        trace: trace::Trace,
        frontier_scheduler: bool,
        native_service_guard: bool,
        rtt_source_baselines: bool,
    ) -> Self {
        Self::configured_repair(
            role,
            trace,
            frontier_scheduler,
            native_service_guard,
            rtt_source_baselines,
            false,
            false,
            false,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn configured_repair(
        role: &'static str,
        trace: trace::Trace,
        frontier_scheduler: bool,
        native_service_guard: bool,
        rtt_source_baselines: bool,
        repair_usefulness_guard: bool,
        random_loss_service: bool,
        queue_gated_loss: bool,
    ) -> Self {
        Self(Arc::new(Inner {
            legacy_recovery: false,
            repair_usefulness_guard,
            rtt_source_baselines,
            random_loss_service,
            queue_gated_loss,
            native_service_guard,
            frontier_scheduler,
            state: Mutex::new(State::default()),
            connections: Mutex::new(BTreeMap::new()),
            started: Instant::now(),
            role,
            instance_id: super::transport::hex(&rand::random::<[u8; 16]>()),
            changed: tokio::sync::Notify::new(),
            trace,
        }))
    }
    pub fn trace(&self) -> &trace::Trace {
        &self.0.trace
    }
    pub fn frontier_scheduler(&self) -> bool {
        self.0.frontier_scheduler
    }
    pub fn native_service_guard(&self) -> bool {
        self.0.native_service_guard
    }
    /// Default: a selected RTT is compared with the minimum of its own source,
    /// so a stable Quinn/probe offset is not queue delay.
    pub fn rtt_source_baselines(&self) -> bool {
        self.0.rtt_source_baselines || !self.0.legacy_recovery
    }
    pub fn random_loss_service(&self) -> bool {
        self.0.random_loss_service
    }
    /// Default throughput pacing: loss-only brakes need a queue or a sustained
    /// transport block. --legacy-recovery restores loss brakes at any queue.
    pub fn queue_gated_loss(&self) -> bool {
        self.0.queue_gated_loss || !self.0.legacy_recovery
    }
    /// Configure before the metrics are shared with any sender.
    fn with_legacy_recovery(mut self, legacy: bool) -> Self {
        Arc::get_mut(&mut self.0)
            .expect("metrics not yet shared")
            .legacy_recovery = legacy;
        self
    }
    pub fn legacy_recovery(&self) -> bool {
        self.0.legacy_recovery
    }
    pub fn repair_usefulness_guard(&self) -> bool {
        self.0.repair_usefulness_guard
    }
    #[cfg(test)]
    pub(crate) fn new_with_repair_guard(role: &'static str, enabled: bool) -> Self {
        Self::configured_repair(
            role,
            trace::Trace::disabled(),
            false,
            false,
            false,
            enabled,
            false,
            false,
        )
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
        let trace_context = if self.trace().enabled() {
            let context = trace::Context::new(session, direction);
            if context.is_none() {
                self.trace().invalid_context();
            }
            context
        } else {
            None
        };
        Scope {
            metrics: self.clone(),
            session: session.to_owned(),
            direction,
            trace_context,
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
                path.capacity_probe = None;
                path.capacity_probe_rate = None;
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
        let mut value = serde_json::json!({"schema_version":1,"process_id":std::process::id(),"instance_id":self.0.instance_id,"bounds":{"session_scopes":MAX_SCOPES,"path_scopes":MAX_SCOPES,"connection_events":MAX_CONNECTION_EVENTS,"record_id_window":ID_WINDOW,"previous_generations_per_path":MAX_PREVIOUS_GENERATIONS,"current_connection_references":MAX_SCOPES,"retired_session_snapshots":MAX_RETIRED_SESSIONS},"role":self.0.role,"final":final_snapshot,"outcome":outcome,"error":error,"elapsed_ms":elapsed_ms,"sample_unix_ms":sample_unix_ms,"counters":"cumulative; units separated by records/symbols/quinn/relay; pre-path queues have aggregate scope","stats":state});
        value["repair_usefulness_guard"] = serde_json::json!(self.0.repair_usefulness_guard);
        if self.trace().enabled() {
            value["packet_trace"] = serde_json::to_value(self.trace().snapshot())?;
        }
        Ok(value)
    }
}
impl Scope {
    pub fn publish_automatic_fec(&self, snapshot: super::automatic_fec::Snapshot) {
        self.metrics.state(|s| {
            if let Some(session) = s.sessions.get_mut(&self.session) {
                session
                    .entry(self.direction.to_owned())
                    .or_default()
                    .automatic_fec = Some(snapshot);
            }
        });
    }
    pub fn publish_reverse_guard(&self, snapshot: super::reverse_guard::Snapshot) {
        self.metrics.state(|s| {
            if let Some(session) = s.sessions.get_mut(&self.session) {
                session
                    .entry(self.direction.to_owned())
                    .or_default()
                    .reverse_guard = Some(snapshot);
            }
        });
    }
    pub fn publish_forward_guard(&self, snapshot: super::forward_guard::Snapshot) {
        self.metrics.state(|s| {
            if let Some(session) = s.sessions.get_mut(&self.session) {
                session
                    .entry(self.direction.to_owned())
                    .or_default()
                    .forward_guard = Some(snapshot);
            }
        });
    }
    pub fn publish_sender_frontier(&self, snapshot: super::sender_frontier::Snapshot) {
        self.metrics.state(|s| {
            if let Some(session) = s.sessions.get_mut(&self.session) {
                session
                    .entry(self.direction.to_owned())
                    .or_default()
                    .sender_frontier = Some(snapshot);
            }
        });
    }
    /// Never overwrite process-wide gauges with the latest of multiple sessions.
    pub fn publish_fec_retention(&self, snapshot: super::fec_retention::Snapshot) {
        self.metrics.state(|s| {
            if let Some(session) = s.sessions.get_mut(&self.session) {
                if let Some(direction) = session.get_mut(self.direction) {
                    direction.fec_retention = Some(snapshot);
                } else {
                    session
                        .entry(self.direction.to_owned())
                        .or_default()
                        .fec_retention = Some(snapshot);
                }
            }
        });
    }
    /// This hook is outside update(): its closure must run once, not once per stats scope.
    pub fn trace_with(&self, make: impl FnOnce(trace::Context, &trace::Trace) -> trace::Event) {
        if let Some(context) = self.trace_context {
            self.metrics
                .trace()
                .emit_with(|| make(context, self.metrics.trace()));
        }
    }
    pub fn trace_record(
        &self,
        stage: trace::Stage,
        record: &wire::Record,
        path: Option<trace::PathKey>,
        reason: Option<trace::Reason>,
    ) {
        self.trace_with(|context, capture| {
            let mut event = trace::Event::new(context, stage);
            event.record = Some(trace::RecordKey {
                flow: record.flow,
                record_id: record.id,
            });
            event.message = super::tunnel::messages::metadata(record);
            event.path = path;
            event.bytes.payload = u32::try_from(record.payload.len()).ok();
            event.probe = capture.probe_identity(&record.payload);
            event.reason = reason;
            event
        });
    }
    pub fn trace_symbol(
        &self,
        stage: trace::Stage,
        data: &[u8],
        path: Option<trace::PathKey>,
        http_bytes: Option<usize>,
        reason: Option<trace::Reason>,
    ) {
        self.trace_with(|context, capture| {
            let mut event = trace::Event::new(context, stage);
            trace_symbol_fields(&mut event, data, capture);
            event.path = path;
            event.bytes.http_datagram = http_bytes.and_then(|n| u32::try_from(n).ok());
            event.reason = reason;
            event
        });
    }
    pub fn update(&self, mut f: impl FnMut(&mut Direction)) {
        self.metrics.state(|s| {
            // Borrow existing keys: constructing an occupied entry used to
            // allocate and discard the same direction String for every packet.
            let aggregate = if s.directions.contains_key(self.direction) {
                s.directions
                    .get_mut(self.direction)
                    .expect("existing direction")
            } else {
                s.directions
                    .entry(self.direction.to_owned())
                    .or_insert_with(Direction::aggregate)
            };
            f(aggregate);
            // IDs restart at each session; global totals must not merge these namespaces.
            // Suppress their insertion, rather than allocate a tree node only
            // to clear it immediately. Session windows below remain enabled.
            aggregate.quinn_admitted_record_ids = Ids::suppressed();
            aggregate.generated_record_ids = Ids::suppressed();
            aggregate.locally_dropped_original_ids = Ids::suppressed();
            aggregate.udp_delivered_record_ids = Ids::suppressed();
            if let Some(session) = s.sessions.get_mut(&self.session) {
                if let Some(direction) = session.get_mut(self.direction) {
                    f(direction);
                } else {
                    f(session.entry(self.direction.to_owned()).or_default());
                }
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
/// Read only observed wire fields. Invalid frames retain byte counts, without fabricated IDs.
pub(super) fn trace_symbol_fields(event: &mut trace::Event, data: &[u8], capture: &trace::Trace) {
    event.bytes.wire = u32::try_from(data.len()).ok();
    if !(wire::HEADER..=wire::MAX_STREAM_WIRE).contains(&data.len()) || data[..3] != [b'B', b'P', 1]
    {
        return;
    }
    let block = u64::from_be_bytes(data[4..12].try_into().expect("validated wire header"));
    let kind = match data[3] {
        0 if data[12] < 32 => trace::SymbolKind::Original,
        1 if (1..=32).contains(&data[12]) && data.len() >= wire::HEADER + 14 => {
            trace::SymbolKind::Repair
        }
        3 if (1..=32).contains(&data[12]) && data.len() >= wire::HEADER + 14 => {
            trace::SymbolKind::RepairQ
        }
        2 if block == 0 && data[12] == 0 => trace::SymbolKind::Plain,
        _ => return,
    };
    event.symbol = Some(trace::SymbolKey {
        kind,
        block,
        index_or_count: data[12],
    });
    if !matches!(kind, trace::SymbolKind::Repair | trace::SymbolKind::RepairQ)
        && let Ok((flow, record_id)) = wire::Record::decode_identity(&data[wire::HEADER..])
    {
        event.record = Some(trace::RecordKey { flow, record_id });
        let payload = &data[wire::HEADER + 12..];
        event.bytes.payload = u32::try_from(payload.len()).ok();
        event.probe = capture.probe_identity(payload);
    }
}
fn write_snapshot(writer: &mut impl Write, snapshot: &impl Serialize, pretty: bool) -> Result<()> {
    // Snapshots contain bounded ID windows. Serialize once in memory rather than
    // issuing one filesystem write for each JSON token (especially on bind mounts).
    let mut bytes = if pretty {
        serde_json::to_vec_pretty(snapshot)?
    } else {
        serde_json::to_vec(snapshot)?
    };
    bytes.push(b'\n');
    writer.write_all(&bytes)?;
    Ok(())
}

async fn write_periodic<W, F>(
    snapshot: F,
    file: Arc<Mutex<W>>,
    stopping: Arc<AtomicBool>,
) -> Result<()>
where
    W: Write + Send + 'static,
    F: FnOnce() -> Result<serde_json::Value> + Send + 'static,
{
    tokio::task::spawn_blocking(move || -> Result<()> {
        if stopping.load(Ordering::Acquire) {
            return Ok(());
        }
        let value = snapshot()?;
        let mut file = file.lock().expect("stats file lock");
        if !stopping.load(Ordering::Acquire) {
            write_snapshot(&mut *file, &value, false)?;
            file.flush()?;
        }
        Ok(())
    })
    .await
    .context("periodic statistics writer task")?
}

/// Must outlive runtime cleanup. Periodic output is stopped before the final JSON.
pub struct Reporter {
    pub metrics: Metrics,
    options: Options,
    periodic: Option<tokio::task::JoinHandle<Result<()>>>,
    stopping: Arc<AtomicBool>,
    jsonl: Option<Arc<Mutex<File>>>,
    trace_guard: Option<trace::Guard>,
}
/// Check aliases before any output is truncated. A new trace file is then
/// exclusively created before either cumulative stats destination is opened.
fn distinct_output_paths(paths: &[Option<&FsPath>]) -> Result<()> {
    let paths: Vec<_> = paths.iter().flatten().copied().collect();
    let canonical = paths
        .iter()
        .map(|path| match std::fs::symlink_metadata(path) {
            Ok(_) => std::fs::canonicalize(path).map_err(anyhow::Error::from),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(FsPath::new("."));
                let name = path
                    .file_name()
                    .context("output path requires a filename")?;
                Ok(std::fs::canonicalize(parent)?.join(name))
            }
            Err(error) => Err(error.into()),
        })
        .collect::<Result<Vec<_>>>()?;
    for i in 0..paths.len() {
        for j in 0..i {
            ensure!(
                canonical[i] != canonical[j],
                "stats and packet trace require distinct paths"
            );
            #[cfg(unix)]
            if let (Ok(a), Ok(b)) = (std::fs::metadata(paths[i]), std::fs::metadata(paths[j])) {
                use std::os::unix::fs::MetadataExt;
                ensure!(
                    a.dev() != b.dev() || a.ino() != b.ino(),
                    "stats and packet trace cannot share a file"
                );
            }
        }
    }
    Ok(())
}
impl Reporter {
    pub fn new(role: &'static str, options: Options) -> Result<Self> {
        ensure!(
            !options.repair_usefulness_guard || matches!(role, "client" | "server"),
            "repair-usefulness-guard applies only to a client or server sender"
        );
        ensure!(
            !options.rtt_source_baselines || matches!(role, "client" | "server"),
            "rtt-source-baselines applies only to a client or server sender"
        );
        ensure!(
            !options.random_loss_service || matches!(role, "client" | "server"),
            "random-loss-service applies only to a client or server sender"
        );
        ensure!(
            !options.queue_gated_loss || matches!(role, "client" | "server"),
            "queue-gated-loss applies only to a client or server sender"
        );
        ensure!(
            !options.legacy_recovery || matches!(role, "client" | "server"),
            "legacy-recovery applies only to a client or server sender"
        );
        ensure!(
            !options.native_service_guard || matches!(role, "client" | "server"),
            "native-service-guard applies only to a client or server sender"
        );
        ensure!(
            !options.frontier_scheduler || matches!(role, "client" | "server"),
            "frontier-scheduler applies only to a client or server sender"
        );
        ensure!(
            (10..=60_000).contains(&options.stats_interval_ms),
            "stats interval must be 10..60000 ms"
        );
        distinct_output_paths(&[
            options.stats_file.as_deref(),
            options.stats_jsonl.as_deref(),
            options.trace.packet_trace.as_deref(),
        ])?;
        let (capture, trace_guard) =
            trace::Trace::start(role, &options.trace).context("start bounded packet trace")?;
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
        let metrics = Metrics::configured_repair(
            role,
            capture,
            options.frontier_scheduler,
            options.native_service_guard,
            options.rtt_source_baselines,
            options.repair_usefulness_guard,
            options.random_loss_service,
            options.queue_gated_loss,
        )
        .with_legacy_recovery(options.legacy_recovery);
        let stopping = Arc::new(AtomicBool::new(false));
        let periodic = jsonl.clone().map(|file| {
            let metrics = metrics.clone();
            let stopping = stopping.clone();
            let ms = options.stats_interval_ms;
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_millis(ms));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {_=tick.tick()=>{},_=metrics.0.changed.notified()=>{}}
                    // At most one report is in flight. JSON allocation,
                    // encoding and blocking filesystem I/O must not occupy a
                    // network worker; skipped ticks never queue more writers.
                    let snapshot_metrics = metrics.clone();
                    write_periodic(
                        move || snapshot_metrics.snapshot(false, "running", None),
                        file.clone(),
                        stopping.clone(),
                    )
                    .await?;
                }
            })
        });
        Ok(Self {
            metrics,
            options,
            periodic,
            stopping,
            jsonl,
            trace_guard: Some(trace_guard),
        })
    }
    pub async fn finish(mut self, result: Result<()>) -> Result<()> {
        let mut report_error = None;
        self.stopping.store(true, Ordering::Release);
        if let Some(task) = self.periodic.take() {
            task.abort();
            if let Ok(Err(e)) = task.await {
                report_error = Some(e);
            }
        }
        let trace_summary = if let Some(guard) = self.trace_guard.take() {
            guard.finish().await
        } else {
            self.metrics.trace().snapshot()
        };
        let result = result
            .and_then(|_| report_error.map_or(Ok(()), Err))
            .and_then(|_| {
                ensure!(
                    !trace_summary.enabled || trace_summary.complete,
                    "packet trace incomplete; inspect packet_trace counters and footer"
                );
                Ok(())
            });
        let error = result.as_ref().err().map(|e| format!("{e:#}"));
        self.metrics.state(|s| s.ready = false);
        let snapshot = self.metrics.snapshot(
            true,
            if result.is_ok() { "stopped" } else { "error" },
            error.as_deref(),
        )?;
        if let Some(path) = &self.options.stats_file {
            let mut file = File::create(path)?;
            write_snapshot(&mut file, &snapshot, true)?;
        }
        if let Some(file) = &self.jsonl {
            let mut file = file.lock().expect("stats file lock");
            write_snapshot(&mut *file, &snapshot, false)?;
            file.flush()?;
        }
        result?;
        Ok(())
    }
}
impl Drop for Reporter {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(task) = self.periodic.take() {
            task.abort();
        }
        // Guard::drop marks cancellation incomplete and wakes the writer.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::transport::{self, Congestion};
    use bytes::Bytes;
    use tokio::time::timeout;

    fn diagnostic_options(dir: &std::path::Path) -> Options {
        Options {
            stats_file: Some(dir.join("final.json")),
            stats_interval_ms: 1000,
            trace: trace::Options {
                packet_trace: Some(dir.join("trace.jsonl")),
                packet_trace_probe_header: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn queue_gated_loss_is_the_default_and_legacy_recovery_restores_loss_brakes() {
        let metrics = |legacy: bool, gated: bool| {
            Metrics::configured_repair(
                "client",
                trace::Trace::disabled(),
                false,
                false,
                false,
                false,
                false,
                gated,
            )
            .with_legacy_recovery(legacy)
        };
        assert!(metrics(false, false).queue_gated_loss());
        assert!(!metrics(true, false).queue_gated_loss());
        assert!(metrics(true, true).queue_gated_loss());
    }

    #[test]
    fn source_specific_rtt_baselines_are_default_with_an_explicit_legacy_control() {
        assert!(Metrics::new("client").rtt_source_baselines());
        assert!(
            !Metrics::new("client")
                .with_legacy_recovery(true)
                .rtt_source_baselines()
        );
        let explicit =
            Metrics::configured_rtt("client", trace::Trace::disabled(), false, false, true)
                .with_legacy_recovery(true);
        assert!(explicit.rtt_source_baselines());
    }

    #[test]
    fn receiver_retention_is_not_merged_across_sessions_or_directions() {
        let metrics = Metrics::new("test");
        let a = metrics.scope("a", FORWARD);
        let b = metrics.scope("b", FORWARD);
        a.update(|_| {});
        b.update(|_| {});
        a.publish_fec_retention(super::super::fec_retention::Snapshot {
            enabled: true,
            current_ms: 100,
            ..Default::default()
        });
        b.publish_fec_retention(super::super::fec_retention::Snapshot {
            enabled: true,
            current_ms: 230,
            ..Default::default()
        });
        let state = metrics.0.state.lock().unwrap();
        assert_eq!(
            state.sessions["a"][FORWARD]
                .fec_retention
                .as_ref()
                .unwrap()
                .current_ms,
            100
        );
        assert_eq!(
            state.sessions["b"][FORWARD]
                .fec_retention
                .as_ref()
                .unwrap()
                .current_ms,
            230
        );
        assert!(state.directions[FORWARD].fec_retention.is_none());
        assert!(!state.sessions["a"].contains_key(RETURN));
    }

    #[test]
    fn frontier_mode_and_sender_census_are_local_and_session_owned() {
        let metrics = Metrics::configured("client", trace::Trace::disabled(), true);
        assert!(metrics.frontier_scheduler());
        assert!(!Metrics::new("client").frontier_scheduler());
        let a = metrics.scope("a", FORWARD);
        let b = metrics.scope("b", RETURN);
        a.update(|_| {});
        b.update(|_| {});
        a.publish_sender_frontier(super::super::sender_frontier::Snapshot {
            head_previews: 7,
            enabled: true,
            ..Default::default()
        });
        b.publish_sender_frontier(super::super::sender_frontier::Snapshot {
            head_previews: 3,
            ..Default::default()
        });
        let state = metrics.0.state.lock().unwrap();
        assert_eq!(
            state.sessions["a"][FORWARD]
                .sender_frontier
                .as_ref()
                .unwrap()
                .head_previews,
            7
        );
        assert_eq!(
            state.sessions["b"][RETURN]
                .sender_frontier
                .as_ref()
                .unwrap()
                .head_previews,
            3
        );
        assert!(state.directions[FORWARD].sender_frontier.is_none());
        assert!(state.directions[RETURN].sender_frontier.is_none());
    }

    #[tokio::test]
    async fn trace_alias_validation_precedes_output_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("keep.json");
        std::fs::write(&existing, b"previous evidence\n").unwrap();
        let mut options = diagnostic_options(dir.path());
        options.stats_file = Some(existing.clone());
        options.trace.packet_trace = Some(dir.path().join(".").join("keep.json"));
        assert!(Reporter::new("client", options).is_err());
        assert_eq!(std::fs::read(&existing).unwrap(), b"previous evidence\n");
        #[cfg(unix)]
        {
            let linked = dir.path().join("linked.json");
            std::fs::hard_link(&existing, &linked).unwrap();
            let mut options = diagnostic_options(dir.path());
            options.stats_file = Some(existing.clone());
            options.stats_jsonl = Some(linked);
            assert!(Reporter::new("client", options).is_err());
            assert_eq!(std::fs::read(&existing).unwrap(), b"previous evidence\n");
            assert!(!dir.path().join("trace.jsonl").exists());
        }
    }

    #[tokio::test]
    async fn trace_record_symbol_and_final_footer_share_exact_identity() {
        let dir = tempfile::tempdir().unwrap();
        let reporter = Reporter::new("client", diagnostic_options(dir.path())).unwrap();
        let scope = reporter
            .metrics
            .scope("00000000000000000000000000000001", FORWARD);
        let mut payload = vec![0; 36];
        payload[..4].copy_from_slice(b"BPP2");
        payload[4] = 3;
        payload[8..24].copy_from_slice(&17u128.to_be_bytes());
        payload[24..28].copy_from_slice(&29u32.to_be_bytes());
        let record = wire::Record {
            flow: 7,
            id: 9,
            payload,
        };
        let frame = wire::plain(&record).unwrap();
        scope.trace_record(trace::Stage::RecordIngress, &record, None, None);
        scope.trace_symbol(trace::Stage::SymbolGenerated, &frame, None, None, None);
        scope.trace_symbol(
            trace::Stage::QuinnApiAdmitted,
            &frame,
            Some(trace::PathKey {
                path_id: 2,
                generation: 41,
                connection_id: 63,
            }),
            Some(frame.len() + 2),
            None,
        );
        reporter.finish(Ok(())).await.unwrap();
        let text = std::fs::read_to_string(dir.path().join("trace.jsonl")).unwrap();
        assert!(text.ends_with('\n'));
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 5);
        for (i, row) in rows[1..4].iter().enumerate() {
            assert_eq!(row["sequence"], i + 1);
            assert_eq!(row["record"], serde_json::json!({"flow":7,"record_id":9}));
            assert_eq!(
                row["probe"],
                serde_json::json!({"run_id":"00000000000000000000000000000011","kind":3,"seq":29})
            );
        }
        assert_eq!(rows[3]["symbol"]["kind"], "plain");
        assert_eq!(rows[3]["path"]["generation"], 41);
        assert_eq!(rows[3]["bytes"]["http_datagram"], frame.len() + 2);
        let final_stats: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("final.json")).unwrap()).unwrap();
        assert_eq!(final_stats["packet_trace"]["complete"], true);
        assert_eq!(rows[4]["summary"], final_stats["packet_trace"]);
    }

    #[tokio::test]
    async fn incomplete_trace_fails_diagnostic_and_is_visible_in_final_stats() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = diagnostic_options(dir.path());
        options.trace.packet_trace_max_events = 1;
        let reporter = Reporter::new("client", options).unwrap();
        let scope = reporter
            .metrics
            .scope("00000000000000000000000000000001", FORWARD);
        let record = wire::Record {
            flow: 1,
            id: 2,
            payload: vec![3],
        };
        scope.trace_record(trace::Stage::RecordIngress, &record, None, None);
        scope.trace_record(trace::Stage::SenderInput, &record, None, None);
        assert!(
            reporter
                .finish(Ok(()))
                .await
                .unwrap_err()
                .to_string()
                .contains("packet trace incomplete")
        );
        let snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("final.json")).unwrap()).unwrap();
        assert_eq!(snapshot["outcome"], "error");
        assert_eq!(snapshot["packet_trace"]["complete"], false);
        assert_eq!(snapshot["packet_trace"]["dropped_event_limit"], 1);
        assert_eq!(snapshot["packet_trace"]["written"], 1);
    }

    #[derive(Default)]
    struct CountingWriter {
        bytes: Vec<u8>,
        writes: usize,
    }
    impl Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_blocked_periodic_snapshot_cannot_stop_io_or_follow_the_final_row() {
        let stopping = Arc::new(AtomicBool::new(false));
        let writer = Arc::new(Mutex::new(Vec::<u8>::new()));
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (progress_tx, progress_rx) = std::sync::mpsc::channel();
        let released = release.clone();
        let guard = std::thread::spawn(move || {
            let progressed = progress_rx.recv_timeout(Duration::from_secs(2)).is_ok();
            let (lock, wake) = &*released;
            *lock.lock().unwrap() = true;
            wake.notify_all();
            progressed
        });
        let job = tokio::spawn(write_periodic(
            move || {
                let _ = entered_tx.send(());
                let (lock, wake) = &*release;
                let mut ready = lock.lock().unwrap();
                while !*ready {
                    ready = wake.wait(ready).unwrap();
                }
                Ok(serde_json::json!({"final":false}))
            },
            writer.clone(),
            stopping.clone(),
        ));
        entered_rx.await.unwrap();
        stopping.store(true, Ordering::Release);
        write_snapshot(
            &mut *writer.lock().unwrap(),
            &serde_json::json!({"final":true}),
            false,
        )
        .unwrap();
        let _ = progress_tx.send(());
        job.await.unwrap().unwrap();
        assert!(
            guard.join().unwrap(),
            "the runtime must progress while serialization/diskwork blocks"
        );
        let text = String::from_utf8(writer.lock().unwrap().clone()).unwrap();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![serde_json::json!({"final":true})],
            "a stopped in-flight report cannot append after final"
        );
    }

    #[test]
    fn populated_snapshot_is_one_write_with_identical_json_and_newline() {
        let metrics = Metrics::new("test");
        let scope = metrics.scope("bounded-session", FORWARD);
        for id in 0..ID_WINDOW {
            scope.update(|d| {
                d.records.application_received += 1;
                d.generated_record_ids.add(id);
                d.quinn_admitted_record_ids.add(id);
            });
        }
        let snapshot = metrics.snapshot(true, "stopped", None).unwrap();
        let mut counts = Vec::new();
        for pretty in [false, true] {
            let mut writer = CountingWriter::default();
            write_snapshot(&mut writer, &snapshot, pretty).unwrap();
            let mut expected = if pretty {
                serde_json::to_vec_pretty(&snapshot).unwrap()
            } else {
                serde_json::to_vec(&snapshot).unwrap()
            };
            expected.push(b'\n');
            assert_eq!(writer.bytes, expected);
            // Exact serializer bytes above cover every value. The default JSON
            // parser can round a floating timestamp by one ULP on readback.
            serde_json::from_slice::<serde_json::Value>(&writer.bytes).unwrap();
            eprintln!(
                "pretty={pretty} snapshot_bytes={} write_calls={}",
                writer.bytes.len(),
                writer.writes
            );
            counts.push(writer.writes);
        }
        assert_eq!(counts, [1, 1]);
    }

    #[test]
    fn snapshot_serialization_and_write_failures_propagate() {
        struct Rejected;
        impl Serialize for Rejected {
            fn serialize<S: serde::Serializer>(
                &self,
                _: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("snapshot serialization rejected"))
            }
        }
        #[derive(Serialize)]
        struct InvalidSnapshot {
            prefix: u64,
            rejected: Rejected,
        }
        struct FailedWriter;
        impl Write for FailedWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("snapshot write rejected"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for pretty in [false, true] {
            let mut writer = CountingWriter::default();
            let failure = write_snapshot(
                &mut writer,
                &InvalidSnapshot {
                    prefix: 1,
                    rejected: Rejected,
                },
                pretty,
            )
            .unwrap_err();
            assert!(
                failure
                    .to_string()
                    .contains("snapshot serialization rejected")
            );
            assert!(writer.bytes.is_empty());
            assert_eq!(writer.writes, 0);
            let failure = write_snapshot(&mut FailedWriter, &serde_json::json!({"ok": 1}), pretty)
                .unwrap_err();
            assert!(failure.to_string().contains("snapshot write rejected"));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn quinn_snapshot_reports_real_datagram_space_and_udp_io_operations() {
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
        let before = Quinn::sample(&outgoing);
        let payload = Bytes::from_static(b"buffer space sample");
        outgoing.send_datagram(payload.clone()).unwrap();
        // No task can drive this current-thread connection between send and sample.
        let queued = Quinn::sample(&outgoing);
        assert!(
            queued.datagram_send_buffer_space_bytes + payload.len() as u64
                <= before.datagram_send_buffer_space_bytes
        );
        assert_eq!(
            queued.datagram_send_buffer_space_bytes,
            outgoing.datagram_send_buffer_space() as u64
        );
        assert_eq!(
            timeout(Duration::from_secs(3), incoming.read_datagram())
                .await
                .unwrap()
                .unwrap(),
            payload
        );
        for conn in [&outgoing, &incoming] {
            let sampled = Quinn::sample(conn);
            let native = conn.stats();
            let native_controller = conn.congestion_state().metrics();
            let serialized = serde_json::to_value(&sampled).unwrap();
            assert!(native_controller.pacing_rate.is_some());
            assert_eq!(
                serialized["pacing_rate_bps"],
                serde_json::to_value(native_controller.pacing_rate).unwrap()
            );
            assert_eq!(serialized["udp_io_operations_tx"], native.udp_tx.ios);
            assert_eq!(serialized["udp_io_operations_rx"], native.udp_rx.ios);
            assert_eq!(serialized["udp_datagrams_tx"], native.udp_tx.datagrams);
            assert_eq!(serialized["udp_datagrams_rx"], native.udp_rx.datagrams);
            assert!(native.udp_tx.ios > 0);
            assert!(native.udp_rx.ios > 0);
            assert_eq!(
                serialized["datagram_send_buffer_space_bytes"],
                conn.datagram_send_buffer_space() as u64
            );
        }
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
        timeout(Duration::from_secs(3), async {
            tokio::join!(client.wait_idle(), server.wait_idle());
        })
        .await
        .unwrap();
    }

    #[test]
    fn suppressed_global_ids_stay_empty_and_keep_the_serialized_schema() {
        let mut ids = Ids::suppressed();
        for id in [0, 1, 8192, 1_000_000, u64::MAX] {
            ids.add(id);
        }
        assert!(ids.recent.is_empty());
        assert_eq!(ids.highest_id, 0);
        assert_eq!(ids.floor_id, 0);
        assert_eq!(
            serde_json::to_value(&ids).unwrap(),
            serde_json::to_value(Ids::default()).unwrap()
        );
    }

    #[test]
    fn aggregate_suppression_preserves_each_session_window_and_all_counters() {
        let metrics = Metrics::new("test");
        for (session, count) in [("first", 10_000u64), ("second", 16)] {
            let scope = metrics.scope(session, RETURN);
            for id in 0..count {
                scope.update(|d| {
                    d.records.application_received += 1;
                    d.symbols.originals_generated += 1;
                    d.generated_record_ids.add(id);
                    if id.is_multiple_of(2) {
                        d.symbols.originals_quinn_admitted += 1;
                        d.records.udp_target_delivered += 1;
                        d.quinn_admitted_record_ids.add(id);
                        d.udp_delivered_record_ids.add(id);
                    } else {
                        d.symbols.originals_queue_full_dropped += 1;
                        d.locally_dropped_original_ids.add(id);
                    }
                });
            }
        }
        metrics.state(|s| {
            let aggregate = &s.directions[RETURN];
            assert_eq!(aggregate.records.application_received, 10_016);
            assert_eq!(aggregate.symbols.originals_generated, 10_016);
            assert_eq!(aggregate.symbols.originals_quinn_admitted, 5008);
            assert_eq!(aggregate.symbols.originals_queue_full_dropped, 5008);
            assert_eq!(aggregate.records.udp_target_delivered, 5008);
            let serialized = serde_json::to_value(aggregate).unwrap();
            for key in [
                "generated_record_ids",
                "quinn_admitted_record_ids",
                "locally_dropped_original_ids",
                "udp_delivered_record_ids",
            ] {
                assert!(serialized.get(key).is_none());
            }
            for (session, count) in [("first", 10_000u64), ("second", 16)] {
                let d = &s.sessions[session][RETURN];
                assert_eq!(d.records.application_received, count);
                assert_eq!(d.symbols.originals_generated, count);
                assert_eq!(d.generated_record_ids.highest_id, count - 1);
                assert_eq!(
                    d.generated_record_ids.recent.len() as u64,
                    count.min(ID_WINDOW)
                );
                assert_eq!(
                    d.quinn_admitted_record_ids.recent.len() as u64,
                    (count / 2).min(ID_WINDOW / 2)
                );
                assert_eq!(
                    d.udp_delivered_record_ids.recent,
                    d.quinn_admitted_record_ids.recent
                );
                assert_eq!(
                    d.locally_dropped_original_ids.recent.len() as u64,
                    (count / 2).min(ID_WINDOW / 2)
                );
            }
        });
    }

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

    #[tokio::test]
    async fn a_full_handshake_after_rejected_early_data_is_a_further_attempt() {
        let temp = tempfile::tempdir().unwrap();
        let identity = temp.path().join("identity");
        transport::initialize(&identity, "localhost").unwrap();
        let cert = identity.join("cert.pem");
        // Two servers with separate ticket stores, as across a restart.
        let servers = [(); 2].map(|()| {
            // Opt this fixture into tickets explicitly. Production endpoints
            // without a journal, and native proxy endpoints, keep 0-RTT disabled.
            let tls = transport::server_tls(&cert, &identity.join("key.pem")).unwrap();
            let mut config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
            ));
            config.transport_config(Arc::new(transport::config(Congestion::Bbr)));
            let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = server.local_addr().unwrap();
            tokio::spawn(async move {
                let mut held = Vec::new();
                while let Some(incoming) = server.accept().await {
                    if let Ok(conn) = incoming.await {
                        held.push(conn);
                    }
                }
            });
            address
        });
        let client = transport::client(servers[0], &cert, None, Congestion::Bbr).unwrap();
        let first = client
            .connect(servers[0], "localhost")
            .unwrap()
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let metrics = Metrics::new("client");
        let mut trace = ConnectionTrace::new(metrics.clone(), servers[1], Some(0), "quic_connect");
        let Ok((conn, accepted)) = client.connect(servers[1], "localhost").unwrap().into_0rtt()
        else {
            panic!("no ticket from the first server");
        };
        let mut outcome = trace.early_data(&conn, accepted);
        let outcome = *timeout(Duration::from_secs(3), outcome.wait_for(Option::is_some))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome, Some(EarlyData::Rejected));
        conn.close(0u32.into(), b"0-RTT rejected");
        trace.retry_handshake();
        let conn = client
            .connect(servers[1], "localhost")
            .unwrap()
            .await
            .unwrap();
        trace.handshake_succeeded(&conn);
        metrics.state(|state| {
            assert_eq!(state.handshake_attempts, 2);
            assert_eq!(state.handshake_successes, 2);
            assert_eq!(state.handshake_failures, 0);
            assert_eq!(state.zero_rtt_rejected, 1);
            assert_eq!(state.zero_rtt_accepted, 0);
        });
        first.close(0u32.into(), b"done");
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
