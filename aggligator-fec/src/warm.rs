//! Unused, pre-handshaken transport sessions. A session is checked out exactly
//! once; application bytes and used target TCP sockets are never replayed/reused.
use crate::{multiplex::Hub, session::{self, Session, SessionConfig}};
use std::{collections::VecDeque, io, sync::{Arc, Mutex}, time::Duration};
use tokio::{sync::Notify, task::{JoinHandle, JoinSet}};

struct Prepared {
    session: Option<Session>,
    epoch: u64,
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(session) = &self.session { session.task.abort(); }
    }
}
impl Prepared {
    fn valid(&self, epoch: u64) -> bool {
        self.epoch == epoch && self.session.as_ref().is_some_and(|s| !s.task.is_finished())
    }
}

/// The existing shared 32-flow admission limit includes the reserve. Active
/// connections can consume all reserve entries; it never reserves extra slots.
struct PoolState { epoch: u64, ready: VecDeque<Prepared> }
pub(crate) struct SessionPool {
    hub: Arc<Hub>,
    cfg: SessionConfig,
    desired: usize,
    state: Mutex<PoolState>,
    refill: Notify,
    available: Notify,
}

impl SessionPool {
    pub(crate) fn new(hub: Arc<Hub>, cfg: SessionConfig, desired: usize, epoch: u64) -> Arc<Self> {
        Arc::new(Self { hub, cfg, desired,
            state: Mutex::new(PoolState { epoch, ready: VecDeque::new() }), refill: Notify::new(), available: Notify::new() })
    }

    pub(crate) fn start(self: &Arc<Self>) -> JoinHandle<()> {
        let pool = self.clone();
        tokio::spawn(async move { pool.maintain().await; })
    }

    pub(crate) fn set_epoch(&self, epoch: u64) {
        let mut state = self.state.lock().expect("warm pool lock");
        if state.epoch != epoch {
            // The master lost its old socket/session state. Never assign a stale
            // unused flow to a new application request after that restart.
            state.epoch = epoch;
            state.ready.clear();
            self.refill.notify_one();
        }
    }

    pub(crate) fn wake(&self) { self.refill.notify_one(); }

    fn take(&self) -> Option<Session> {
        let mut state = self.state.lock().expect("warm pool lock");
        while let Some(mut prepared) = state.ready.pop_front() {
            if prepared.valid(state.epoch) {
                self.refill.notify_one();
                return prepared.session.take();
            }
        }
        self.refill.notify_one();
        None
    }

    /// Wait for at least one genuinely completed handshake before advertising
    /// readiness. A process cold start still pays for its initial network setup.
    pub(crate) async fn prime(&self) -> io::Result<()> {
        if self.desired == 0 { return Ok(()); }
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let available = self.available.notified();
                {
                    let state = self.state.lock().expect("warm pool lock");
                    if state.ready.iter().any(|s| s.valid(state.epoch)) { return; }
                }
                available.await;
            }
        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no warm transport session became ready"))
    }

    pub(crate) async fn checkout(&self) -> io::Result<(Session, bool)> {
        if let Some(session) = self.take() { return Ok((session, true)); }
        // A burst may exhaust the reserve. Connect normally, without replaying
        // any application request or waiting for all spare sessions to refill.
        let epoch = self.state.lock().expect("warm pool lock").epoch;
        let flow = self.hub.open()?;
        let session = session::multiplexed(flow, self.cfg.clone(), true).await?;
        if self.state.lock().expect("warm pool lock").epoch != epoch {
            session.task.abort();
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "master restarted during session establishment"));
        }
        Ok((session, false))
    }

    async fn maintain(&self) {
        if self.desired == 0 { return; }
        let mut builds = JoinSet::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut retry_at = tokio::time::Instant::now();
        let mut announced_epoch = None;
        let mut build_epoch = self.state.lock().expect("warm pool lock").epoch;
        loop {
            let (epoch, count) = {
                let mut state = self.state.lock().expect("warm pool lock");
                let epoch = state.epoch;
                state.ready.retain(|s| s.valid(epoch));
                (epoch, state.ready.len())
            };
            if build_epoch != epoch {
                // Drop also aborts pending handshakes and releases their flow slots.
                builds = JoinSet::new();
                build_epoch = epoch;
                retry_at = tokio::time::Instant::now();
            }
            if count == self.desired && announced_epoch != Some(epoch) {
                crate::cli_output::emit(serde_json::json!({"event":"warm_pool_ready","sessions":count}));
                announced_epoch = Some(epoch);
            }
            if tokio::time::Instant::now() >= retry_at {
                while count + builds.len() < self.desired {
                    let Ok(flow) = self.hub.open_spare() else { break; };
                    let cfg = self.cfg.clone();
                    builds.spawn(async move {
                        let session = session::multiplexed(flow, cfg, true).await?;
                        Ok::<_, io::Error>(Prepared { session: Some(session), epoch })
                    });
                }
            }
            tokio::select! {
                result = builds.join_next(), if !builds.is_empty() => {
                    match result {
                        Some(Ok(Ok(prepared))) => {
                            let mut state = self.state.lock().expect("warm pool lock");
                            if prepared.valid(state.epoch) {
                                state.ready.push_back(prepared);
                                self.available.notify_one();
                            }
                        },
                        Some(Ok(Err(e))) => {
                            retry_at = tokio::time::Instant::now() + Duration::from_millis(250);
                            crate::cli_output::emit(serde_json::json!({"event":"warm_session_error","error":e.to_string()}));
                        },
                        _ => {},
                    }
                },
                _ = self.refill.notified() => {},
                _ = tick.tick() => {},
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multiplex::{LinkSocket, MAX_FLOWS};
    #[tokio::test]
    async fn background_refill_leaves_the_last_slot_for_foreground() {
        let socket=Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let hub=Hub::client(vec![LinkSocket { socket, wire_mbps:80 }],80).unwrap();
        let mut held=Vec::new();
        for _ in 0..MAX_FLOWS-2 {held.push(hub.open().unwrap());}
        held.push(hub.open_spare().unwrap());
        assert!(hub.open_spare().is_err());
        held.push(hub.open().unwrap());
        assert_eq!(hub.flow_count(),MAX_FLOWS);
    }
}
