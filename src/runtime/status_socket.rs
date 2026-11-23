//! Lightweight read-only local status socket for on-demand client diagnostics.
use crate::runtime::stats;
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use anyhow::{Context, bail, ensure};
#[cfg(unix)]
use std::{
    os::unix::fs::{FileTypeExt, PermissionsExt},
    time::Duration,
};
#[cfg(unix)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinHandle,
    time::timeout,
};

#[cfg(unix)]
const MAX_READERS: usize = 4;
#[cfg(unix)]
const IO_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(unix)]
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) struct Guard {
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(unix)]
    task: JoinHandle<()>,
}

#[cfg(unix)]
impl Drop for Guard {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bind an owner-only Unix domain socket that serves one bounded JSON snapshot
/// per connection, with zero background work while idle.
pub(crate) fn spawn(path: PathBuf, render: Arc<dyn Fn() -> Value + Send + Sync>) -> Result<Guard> {
    #[cfg(not(unix))]
    {
        let _ = (path, render);
        anyhow::bail!("--status-socket is only supported on Unix platforms");
    }
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create status socket dir {}", parent.display()))?;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_socket() {
                    std::fs::remove_file(&path).with_context(|| {
                        format!("remove stale status socket {}", path.display())
                    })?;
                } else {
                    bail!(
                        "refusing to overwrite non-socket status path {}",
                        path.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect status socket path {}", path.display()));
            }
        }
        let listener = UnixListener::bind(&path)
            .with_context(|| format!("bind status socket {}", path.display()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 status socket {}", path.display()))?;
        tracing::info!(path = %path.display(), "client status socket ready");
        let permits = Arc::new(Semaphore::new(MAX_READERS));
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    continue;
                };
                let render = render.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let mut payload = match serde_json::to_vec(&render()) {
                        Ok(bytes) => bytes,
                        Err(_) => return,
                    };
                    payload.push(b'\n');
                    let _ = timeout(IO_TIMEOUT, async {
                        let _ = stream.write_all(&payload).await;
                        let _ = stream.shutdown().await;
                    })
                    .await;
                });
            }
        });
        Ok(Guard { path, task })
    }
}

pub(crate) async fn query(path: &Path) -> Result<Value> {
    #[cfg(not(unix))]
    {
        let _ = path;
        anyhow::bail!("client-status is only supported on Unix platforms");
    }
    #[cfg(unix)]
    {
        let stream = timeout(IO_TIMEOUT, UnixStream::connect(path))
            .await
            .with_context(|| format!("timed out connecting to {}", path.display()))?
            .with_context(|| format!("connect status socket {}", path.display()))?;
        let mut buf = Vec::new();
        timeout(
            IO_TIMEOUT,
            stream.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut buf),
        )
        .await
        .with_context(|| format!("timed out reading status from {}", path.display()))?
        .with_context(|| format!("read status from {}", path.display()))?;
        ensure!(
            buf.len() as u64 <= MAX_RESPONSE_BYTES,
            "client status response exceeded {MAX_RESPONSE_BYTES} bytes"
        );
        serde_json::from_slice(&buf).context("parse client status JSON")
    }
}

/// Extract a compact, bounded diagnostic view from an existing `stats::Metrics`
/// snapshot without adding any hot-path counters or locks.
pub(crate) fn metrics_summary(metrics: &stats::Metrics) -> Value {
    let Ok(snapshot) = metrics.snapshot(false, "live", None) else {
        return json!({ "error": "snapshot unavailable" });
    };
    let stats = &snapshot["stats"];
    let mut paths = Vec::new();
    if let Some(map) = stats["paths"].as_object() {
        for entry in map.values() {
            let quinn = &entry["quinn"];
            paths.push(json!({
                "session_id": entry["session_id"],
                "path_id": entry["path_id"],
                "direction": entry["sending_direction"],
                "authenticated": entry["authenticated"],
                "local_socket": entry["local_socket"],
                "peer_socket": entry["peer_socket"],
                "rtt_ms": quinn["smoothed_rtt_ms"],
                "min_rtt_ms": quinn["min_rtt_ms"],
                "cwnd_bytes": quinn["congestion_window_bytes"],
                "pacing_rate_bps": quinn["pacing_rate_bps"],
                "probing_rtt": quinn["native_rtt_probe"],
                "sent_packets": quinn["sent_packets"],
                "lost_packets": quinn["lost_packets"],
                "congestion_events": quinn["congestion_events"],
                "udp_bytes_tx": quinn["udp_bytes_tx"],
                "udp_bytes_rx": quinn["udp_bytes_rx"],
                "stream_frame_bytes_tx": quinn["stream_frame_bytes_tx"],
                "http_datagram_frame_bytes_tx": quinn["http_datagram_frame_bytes_tx"],
                "stream_send_buffer_bytes": quinn["stream_send_buffer_bytes"],
                "stream_unsent_bytes": quinn["stream_unsent_bytes"],
                "http_datagram_frames_pending": quinn["http_datagram_frames_pending"],
                "reconnect_attempts": entry["reconnect_attempts"],
                "reconnect_successes": entry["reconnect_successes"],
                "reconnect_failures": entry["reconnect_failures"],
                "rotation_attempts": entry["rotation_attempts"],
                "rotation_successes": entry["rotation_successes"],
            }));
        }
    }
    let mut tcp_streams = serde_json::Map::new();
    if let Some(sessions) = stats["sessions"].as_object() {
        for (sid, dirs) in sessions {
            if let Some(dirs) = dirs.as_object() {
                let mut by_dir = serde_json::Map::new();
                for (dir, value) in dirs {
                    if !value["tcp_streams"].is_null() {
                        by_dir.insert(dir.clone(), value["tcp_streams"].clone());
                    }
                }
                if !by_dir.is_empty() {
                    tcp_streams.insert(sid.clone(), Value::Object(by_dir));
                }
            }
        }
    }
    let recent_events: Vec<Value> = stats["connection_events"]
        .as_array()
        .map(|events| events.iter().rev().take(8).cloned().collect())
        .unwrap_or_default();
    let active_paths = paths
        .iter()
        .filter(|p| p["authenticated"].as_bool().unwrap_or(false))
        .count();
    json!({
        "ready": stats["ready"],
        "configured_paths": stats["configured_paths"],
        "active_paths": active_paths,
        "elapsed_ms": snapshot["elapsed_ms"],
        "paths": paths,
        "tcp_streams": tcp_streams,
        "recent_connection_events": recent_events,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn status_socket_serves_json_sets_owner_only_mode_and_refuses_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("existing.txt");
        std::fs::write(&regular, b"do not clobber").unwrap();
        assert!(spawn(regular.clone(), Arc::new(|| json!({}))).is_err());
        assert_eq!(std::fs::read(&regular).unwrap(), b"do not clobber");

        let socket = dir.path().join("client.sock");
        let guard = spawn(
            socket.clone(),
            Arc::new(|| json!({"role": "test", "ok": true})),
        )
        .unwrap();
        let mode = std::fs::symlink_metadata(&socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let reply = query(&socket).await.unwrap();
        assert_eq!(reply["role"], "test");
        assert_eq!(reply["ok"], true);
        drop(guard);
        assert!(!socket.exists());
    }
}
