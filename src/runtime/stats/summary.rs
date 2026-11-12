//! Compact periodic observations. Sampling never clones record-ID histories.
use super::*;
use std::sync::{OnceLock, Weak};

pub const TARGET: &str = "braidpath::summary";
const PERIOD_MS: u64 = 10_000;
const HEARTBEAT_MS: u64 = 300_000;
static OWNERS: OnceLock<Mutex<Vec<Weak<Inner>>>> = OnceLock::new();

pub(crate) fn enabled() -> bool {
    tracing::enabled!(target: "braidpath::summary", tracing::Level::INFO)
}

pub(super) fn register(metrics: &Metrics) {
    if !enabled() || metrics.0.summary_registered.swap(true, Ordering::Relaxed) {
        return;
    }
    let mut owners = OWNERS
        .get_or_init(Default::default)
        .lock()
        .expect("summary registry");
    owners.retain(|owner| owner.strong_count() != 0);
    owners.push(Arc::downgrade(&metrics.0));
}

/// One reporter per executable, across all fixed and SOCKS metric owners.
/// Encoding and journal writes stay off the network runtime workers.
pub fn start() -> Option<tokio::task::JoinHandle<()>> {
    enabled().then(|| {
        tokio::spawn(async {
            let mut reporter = Reporter::default();
            let mut clock = tokio::time::interval(Duration::from_millis(PERIOD_MS));
            clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                clock.tick().await;
                let Ok(next) = tokio::task::spawn_blocking(move || {
                    reporter.report();
                    reporter
                })
                .await
                else {
                    return;
                };
                reporter = next;
            }
        })
    })
}

// Tuple column definitions are versioned and documented in statistics.md.
// id, connection, closed, sent, lost, udp_tx, udp_rx, rtt_us, pacing_bps,
// native_ack_tx, native_ack_rx, local_reverse_expected, local_reverse_received.
type PathRow = (
    u8,
    usize,
    bool,
    u64,
    u64,
    u64,
    u64,
    u64,
    Option<u64>,
    u64,
    u64,
    u64,
    u64,
);
// direction, sender queue, queue sample age ms, expired, ingress drops,
// mux [active, opened, ACK sent, app read, app written, retransmit, duplicate],
// forward cap, reverse cap, FEC [data, repair].
type DirectionRow = (
    String,
    Option<usize>,
    Option<u64>,
    u64,
    u64,
    Option<[u64; 7]>,
    Option<u64>,
    Option<u64>,
    Option<[u8; 2]>,
);

#[derive(Serialize)]
struct Session {
    schema: u8,
    kind: &'static str,
    metric: String,
    role: &'static str,
    label: String,
    session: String,
    retired: bool,
    directions: Vec<DirectionRow>,
    paths: Vec<PathRow>,
    #[serde(skip)]
    activity: u64,
}

struct Sample {
    sessions: Vec<Session>,
    tx: u64,
    open_paths: usize,
}

fn sample(metrics: &Metrics) -> Sample {
    // Same lock order as the existing full reporter. Copy only scalar columns.
    let connections = metrics
        .0
        .connections
        .lock()
        .expect("stats connections lock");
    let state = metrics.0.state.lock().expect("stats lock");
    let mut out = Sample {
        sessions: Vec::with_capacity(state.sessions.len()),
        tx: state.evicted_udp_bytes_tx,
        open_paths: 0,
    };
    for (session, directions) in &state.sessions {
        let mut row = Session {
            schema: 1,
            kind: "session",
            metric: metrics.0.instance_id.clone(),
            role: metrics.0.role,
            label: metrics.0.summary_label.get().cloned().unwrap_or_default(),
            session: session.clone(),
            retired: state.retired_sessions.contains(session),
            directions: Vec::with_capacity(directions.len()),
            paths: Vec::new(),
            activity: 0,
        };
        for (direction, d) in directions {
            let streams = d.tcp_streams.as_ref().map(|s| {
                [
                    s.active,
                    s.opened,
                    s.acks_sent,
                    s.bytes_from_application,
                    s.bytes_to_application,
                    s.retransmitted_bytes,
                    s.duplicate_bytes_received,
                ]
            });
            row.activity = row
                .activity
                .saturating_add(d.records.application_received)
                .saturating_add(d.symbols.originals_generated)
                .saturating_add(d.tcp_streams.as_ref().map_or(0, |s| {
                    s.segments_sent
                        .saturating_add(s.acks_sent)
                        .saturating_add(s.bytes_to_application)
                }));
            row.directions.push((
                direction.clone(),
                d.summary_sender_queue,
                d.summary_sender_sampled_at
                    .map(|t| t.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
                d.symbols
                    .originals_expired_dropped
                    .saturating_add(d.symbols.repairs_expired_dropped)
                    .saturating_add(d.symbols.originals_ingress_expired_dropped),
                d.records
                    .ingress_queue_full_dropped
                    .saturating_add(d.records.ingress_queue_closed_dropped),
                streams,
                d.forward_guard.as_ref().and_then(|g| g.cap_bps),
                d.reverse_guard.as_ref().and_then(|g| g.cap_bps),
                d.automatic_fec
                    .as_ref()
                    .map(|f| [f.data_shards, f.repair_shards]),
            ));
        }
        for (key, path) in state.paths.iter().filter(|(_, p)| p.session_id == *session) {
            let native = connections
                .get(key)
                .map(Quinn::sample)
                .unwrap_or_else(|| path.quinn.clone());
            let q = path.receiver_feedback.as_ref();
            let pacing = path
                .adaptive
                .as_ref()
                .map(|s| s.decision.pacing_bps)
                .or(native.pacing_rate_bps);
            row.paths.push((
                path.path_id,
                path.connection_id,
                native.closed,
                native.sent_packets,
                native.lost_packets,
                native.udp_bytes_tx,
                native.udp_bytes_rx,
                (native.smoothed_rtt_ms * 1000.).max(0.) as u64,
                pacing,
                native.ack_frames_tx,
                native.ack_frames_rx,
                q.map_or(0, |q| q.received.expected),
                q.map_or(0, |q| q.received.received),
            ));
            out.tx = out
                .tx
                .saturating_add(path.retired_udp_bytes_tx)
                .saturating_add(native.udp_bytes_tx);
            out.open_paths += usize::from(!row.retired && !native.closed);
        }
        out.sessions.push(row);
    }
    out
}

#[derive(Default)]
struct Emission {
    activity: Option<u64>,
    last_ms: u64,
    retired: bool,
}
impl Emission {
    fn due(&mut self, activity: u64, retired: bool, now_ms: u64) -> bool {
        let changed = self.activity != Some(activity) || self.retired != retired;
        let heartbeat = !retired && now_ms.saturating_sub(self.last_ms) >= HEARTBEAT_MS;
        self.activity = Some(activity);
        self.retired = retired;
        if changed || heartbeat {
            self.last_ms = now_ms;
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct Reporter {
    rows: BTreeMap<(String, String), Emission>,
    totals: BTreeMap<String, u64>,
    tx: u64,
}
impl Reporter {
    fn report(&mut self) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let owners: Vec<_> = OWNERS
            .get_or_init(Default::default)
            .lock()
            .expect("summary registry")
            .iter()
            .filter_map(Weak::upgrade)
            .map(Metrics)
            .collect();
        let mut live_rows = BTreeSet::new();
        let mut live_metrics = BTreeSet::new();
        let (mut sessions, mut paths) = (0, 0);
        for owner in owners {
            let id = owner.0.instance_id.clone();
            live_metrics.insert(id.clone());
            let sample = sample(&owner);
            let previous = self.totals.insert(id, sample.tx).unwrap_or(0);
            self.tx = self.tx.saturating_add(sample.tx.saturating_sub(previous));
            paths += sample.open_paths;
            for row in sample.sessions {
                sessions += usize::from(!row.retired);
                let key = (row.metric.clone(), row.session.clone());
                live_rows.insert(key.clone());
                if self
                    .rows
                    .entry(key)
                    .or_default()
                    .due(row.activity, row.retired, now_ms)
                    && let Ok(frame) = serde_json::to_string(&row)
                {
                    tracing::info!(target: "braidpath::summary", sample_unix_ms=now_ms, frame=%frame, "session summary");
                }
            }
        }
        self.rows.retain(|key, _| live_rows.contains(key));
        self.totals.retain(|key, _| live_metrics.contains(key));
        let process = Process {
            schema: 1,
            kind: "process",
            pid: std::process::id(),
            sessions,
            paths,
            observed_udp_tx: self.tx,
            usage: usage(),
        };
        if let Ok(frame) = serde_json::to_string(&process) {
            tracing::info!(target: "braidpath::summary", sample_unix_ms=now_ms, frame=%frame, "process summary");
        }
    }
}

#[derive(Serialize)]
struct Process {
    schema: u8,
    kind: &'static str,
    pid: u32,
    sessions: usize,
    paths: usize,
    observed_udp_tx: u64,
    usage: Usage,
}
#[derive(Default, Serialize)]
struct Usage {
    user_us: Option<u64>,
    system_us: Option<u64>,
    rss_bytes: Option<u64>,
    peak_rss_bytes: Option<u64>,
}
#[cfg(not(unix))]
fn usage() -> Usage {
    Usage::default()
}
#[cfg(unix)]
fn usage() -> Usage {
    use nix::sys::{
        resource::{UsageWho, getrusage},
        time::TimeValLike,
    };
    let mut out = Usage::default();
    if let Ok(r) = getrusage(UsageWho::RUSAGE_SELF) {
        out.user_us = Some(r.user_time().num_microseconds().max(0) as u64);
        out.system_us = Some(r.system_time().num_microseconds().max(0) as u64);
        #[cfg(target_os = "macos")]
        {
            out.peak_rss_bytes = Some(r.max_rss().max(0) as u64);
        }
        #[cfg(not(target_os = "macos"))]
        {
            out.peak_rss_bytes = Some((r.max_rss().max(0) as u64).saturating_mul(1024));
        }
    }
    #[cfg(target_os = "linux")]
    {
        out.rss_bytes = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines().find_map(|line| {
                    line.strip_prefix("VmRSS:")
                        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
                        .map(|v| v.saturating_mul(1024))
                })
            });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_idle_heartbeat_and_retirement_are_bounded() {
        let mut s = Emission::default();
        assert!(s.due(0, false, 0));
        assert!(!s.due(0, false, 10_000));
        assert!(s.due(1, false, 20_000));
        assert!(!s.due(1, false, 310_000));
        assert!(s.due(1, false, 320_000));
        assert!(s.due(1, true, 330_000));
        assert!(!s.due(1, true, 900_000));
    }
    #[test]
    fn wire_total_survives_finished_scope_eviction() {
        let metrics = Metrics::new("test");
        metrics.scope("old", FORWARD);
        metrics.state(|s| {
            s.paths.insert(
                "old/0".into(),
                Path {
                    session_id: "old".into(),
                    retired_udp_bytes_tx: 300,
                    quinn: Quinn {
                        udp_bytes_tx: 50,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
            s.retired_sessions.push_back("old".into());
        });
        assert_eq!(sample(&metrics).tx, 350);
        metrics.state(|s| assert!(s.evict_oldest_retired()));
        assert_eq!(sample(&metrics).tx, 350);
        metrics.scope("next", FORWARD);
        metrics.state(|s| {
            s.paths.insert(
                "next/0".into(),
                Path {
                    session_id: "next".into(),
                    quinn: Quinn {
                        udp_bytes_tx: 200,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
        });
        assert_eq!(sample(&metrics).tx, 550);
    }
    #[test]
    fn compact_sampling_excludes_histories_addresses_and_separates_directions() {
        let metrics = Metrics::new("test");
        let forward = metrics.scope("epoch", FORWARD);
        metrics
            .scope("epoch", RETURN)
            .update(|d| d.records.original_records_delivered = 19);
        forward.update(|d| {
            d.tcp_streams = Some(super::super::super::stream::Snapshot {
                active: 2,
                acks_sent: 31,
                bytes_to_application: 1048576,
                ..Default::default()
            });
            d.generated_record_ids.recent.extend(0..8192);
        });
        metrics.state(|s| {
            for id in 0..4 {
                s.paths.insert(
                    format!("epoch/{id}"),
                    Path {
                        session_id: "epoch".into(),
                        path_id: id,
                        connection_id: 100 + usize::from(id),
                        peer_socket: "PRIVATE_ADDRESS".into(),
                        quinn: Quinn {
                            sent_packets: 1000,
                            lost_packets: 11,
                            udp_bytes_tx: 2000,
                            udp_bytes_rx: 500000,
                            smoothed_rtt_ms: 85.,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                );
            }
        });
        let s = sample(&metrics);
        assert_eq!((s.tx, s.open_paths), (8000, 4));
        assert_eq!(s.sessions[0].directions.len(), 2);
        assert_eq!(s.sessions[0].directions[0].5.unwrap()[2], 31);
        let json = serde_json::to_string(&s.sessions[0]).unwrap();
        assert!(!json.contains("PRIVATE") && !json.contains("recent"));
        assert!(json.len() < 1400, "{}", json.len());
    }
}
