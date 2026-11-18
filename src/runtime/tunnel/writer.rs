//! Per-path datagram writers.
//!
//! Quinn's connection driver holds the connection lock for its whole poll,
//! including the UDP send. The session sender serves every path, so when it
//! called into Quinn it waited for each busy driver in turn and the paths sent
//! one after another. Each path's writer task now moves datagrams into Quinn;
//! the sender reads only atomics and Quinn's lock-free hints.
//!
//! A path holds at most `budget` bytes in its writer and in Quinn together:
//! what its pace sends in [`HOLD_US`], or a single datagram when that is less.
//! A fast path hands Quinn several datagrams per driver poll (and per UDP send
//! with segmentation offload); a slow path keeps one datagram in flight
//! locally, as before.

use super::{Scope, quality, trace, trace_http, wire};
use bytes::Bytes;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::sync::Notify;

/// Local residence a path's pace may fill beyond one datagram.
pub(super) const HOLD_US: u64 = 1_000;

pub(super) struct Writer {
    conn: quinn::Connection,
    shared: Arc<Shared>,
    /// Quinn's empty datagram buffer space.
    capacity: usize,
}

#[derive(Clone, Copy)]
pub(super) struct GamePacket {
    pub deadline: Instant,
    pub repair: bool,
}

pub(super) struct Observations {
    pub scope: Scope,
    pub path: trace::PathKey,
    pub stream: u64,
    pub feedback: bool,
    pub game_quality: Option<Arc<Mutex<quality::State>>>,
}

struct Frame {
    data: Bytes,
    priority: Priority,
}

enum Priority {
    Control,
    Game(GamePacket),
    Ordinary,
}

impl Priority {
    fn rank(&self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Game(packet) => 1 + u8::from(packet.repair),
            Self::Ordinary => 3,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Game(packet) => Some(packet.deadline),
            _ => None,
        }
    }
}

#[derive(Default)]
struct Shared {
    queue: Mutex<VecDeque<Frame>>,
    /// Bytes in `queue`; never below its contents while a datagram moves.
    queued: AtomicUsize,
    budget: AtomicUsize,
    wake: Notify,
    admission: Notify,
    stopped: AtomicBool,
}

impl Writer {
    pub(super) fn spawn(conn: &quinn::Connection, observations: Option<Observations>) -> Arc<Self> {
        let capacity = conn.datagram_send_buffer_space();
        let shared = Arc::new(Shared::default());
        tokio::spawn(run(conn.clone(), shared.clone(), capacity, observations));
        Arc::new(Self {
            conn: conn.clone(),
            shared,
            capacity,
        })
    }

    /// Bytes this path holds locally, in the writer and in Quinn.
    pub(super) fn held(&self) -> usize {
        self.shared.queued.load(Ordering::Acquire)
            + self
                .capacity
                .saturating_sub(self.conn.datagram_send_buffer_space_hint())
    }

    /// Bytes held beyond the pace budget. The budget is the intended local
    /// residence, so only what exceeds it is queueing.
    pub(super) fn backlog(&self) -> usize {
        self.held()
            .saturating_sub(self.shared.budget.load(Ordering::Relaxed))
    }

    /// Whether a datagram of `bytes` may be handed over now.
    pub(super) fn admits(&self, bytes: usize) -> bool {
        let held = self.held();
        held == 0 || held + bytes <= self.shared.budget.load(Ordering::Relaxed)
    }

    /// Size the local budget from the path's pace.
    pub(super) fn set_pace(&self, bps: u64) {
        let bytes = u128::from(bps) * u128::from(HOLD_US) / 8_000_000;
        self.shared.budget.store(
            (bytes.min(self.capacity as u128)) as usize,
            Ordering::Relaxed,
        );
    }

    /// Queue an ordinary datagram behind existing data. False once closed.
    pub(super) fn send(&self, data: Bytes) -> bool {
        self.send_data(data, None)
    }

    pub(super) fn send_data(&self, data: Bytes, game: Option<GamePacket>) -> bool {
        self.enqueue(data, game.map_or(Priority::Ordinary, Priority::Game))
    }

    /// Queue a control datagram ahead of this path's queued data.
    pub(super) fn send_first(&self, data: Bytes) -> bool {
        self.enqueue(data, Priority::Control)
    }

    fn enqueue(&self, data: Bytes, priority: Priority) -> bool {
        if self.conn.is_closed() || self.shared.stopped.load(Ordering::Relaxed) {
            return false;
        }
        let len = data.len();
        {
            let mut queue = self.shared.queue.lock().expect("writer queue");
            self.shared.queued.fetch_add(len, Ordering::AcqRel);
            let index = match &priority {
                Priority::Control => 0,
                Priority::Game(_) => queue
                    .iter()
                    .position(|other| other.priority.rank() > priority.rank())
                    .unwrap_or(queue.len()),
                Priority::Ordinary => queue.len(),
            };
            queue.insert(index, Frame { data, priority });
        }
        self.shared.wake.notify_one();
        true
    }

    /// Resolves once this path admits `bytes` or closes.
    pub(super) async fn admitted(&self, bytes: usize) {
        loop {
            let drained = self.conn.datagrams_drained();
            tokio::pin!(drained);
            drained.as_mut().enable();
            let admitted = self.shared.admission.notified();
            tokio::pin!(admitted);
            admitted.as_mut().enable();
            if self.admits(bytes) || self.conn.is_closed() {
                return;
            }
            tokio::select! {
                () = &mut drained => {},
                () = &mut admitted => {},
            }
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.shared.stopped.store(true, Ordering::Relaxed);
        self.shared.wake.notify_one();
    }
}

async fn run(
    conn: quinn::Connection,
    shared: Arc<Shared>,
    capacity: usize,
    observations: Option<Observations>,
) {
    let mut profile = super::profile::Writer::new(conn.stable_id());
    loop {
        let drained = conn.datagrams_drained();
        tokio::pin!(drained);
        drained.as_mut().enable();
        if shared.stopped.load(Ordering::Relaxed) || conn.is_closed() {
            break;
        }
        let budget = shared.budget.load(Ordering::Relaxed);
        let mut turn_datagrams = 0;
        let mut blocked_deadline = None;
        loop {
            #[cfg(test)]
            TEST_BEFORE_POP.with(|hook| {
                let f = hook.borrow_mut().take();
                if let Some(f) = f {
                    f();
                }
            });
            let frame = {
                let mut queue = shared.queue.lock().expect("writer queue");
                let Some(front) = queue.front() else {
                    break;
                };
                let deadline = front.priority.deadline();
                let in_quinn = capacity.saturating_sub(conn.datagram_send_buffer_space_hint());
                if in_quinn > 0
                    && in_quinn + front.data.len() > budget
                    && deadline.is_none_or(|at| Instant::now() < at)
                {
                    blocked_deadline = deadline;
                    if let Some(profile) = &mut profile {
                        profile.counters.budget_blocks += 1;
                    }
                    break;
                }
                queue.pop_front().expect("front datagram")
            };
            // Quinn updates its buffer before releasing the writer's byte
            // charge. Its locked deadline check also covers lock contention.
            let Frame { data, priority } = frame;
            let len = data.len();
            let watching = observations
                .as_ref()
                .filter(|_| !matches!(priority, Priority::Control));
            let tracing = watching.is_some_and(|watch| watch.scope.metrics.trace().enabled());
            let game_quality = watching
                .filter(|_| matches!(priority, Priority::Game(_)))
                .and_then(|watch| watch.game_quality.as_ref());
            let observed = (tracing || game_quality.is_some()).then(|| data.clone());
            let deadline = priority.deadline();
            let result = if deadline.is_some_and(|at| Instant::now() >= at) {
                Ok(false)
            } else {
                let called = profile.as_ref().map(|_| Instant::now());
                let result = match deadline {
                    Some(at) => conn.send_datagram_before(data, at),
                    None => conn.send_datagram(data).map(|()| true),
                };
                if let (Some(profile), Some(at)) = (&mut profile, called) {
                    profile.called(at.elapsed());
                }
                result
            };
            if let (Priority::Game(packet), Some(watch)) = (&priority, &observations) {
                watch.scope.path(watch.path.path_id, |p| {
                    // An old writer can complete after the session replaces
                    // its path. Keep new-generation stats independent.
                    if p.connection_id != watch.path.connection_id as usize {
                        return;
                    }
                    match result {
                        Ok(false) => p.writer_expired_game_datagrams += 1,
                        Ok(true) if packet.repair => p.game_copies_admitted_by_quinn += 1,
                        Ok(true) => p.game_originals_admitted_by_quinn += 1,
                        Err(_) => {}
                    }
                });
            }
            if !matches!(result, Ok(true))
                && let (Some(quality), Some(watch), Some(data)) =
                    (game_quality, watching, &observed)
                && let Ok(payload) = wire::http_payload(data, watch.stream)
            {
                quality
                    .lock()
                    .expect("quality lock")
                    .writer_discarded(payload);
            }
            if tracing && let (Some(watch), Some(data)) = (watching, observed) {
                let (stage, reason) = match result {
                    Ok(true) => (trace::Stage::QuinnApiAdmitted, None),
                    Ok(false) => (trace::Stage::SymbolDropped, Some(trace::Reason::Expired)),
                    Err(_) => (
                        trace::Stage::QuinnApiRejected,
                        Some(trace::Reason::QuinnError),
                    ),
                };
                trace_http(
                    &watch.scope,
                    stage,
                    &data,
                    watch.stream,
                    watch.feedback,
                    watch.path,
                    reason,
                );
            }
            turn_datagrams += u64::from(matches!(result, Ok(true)));
            #[cfg(test)]
            {
                let pause = TEST_AFTER_SEND.with(|hook| hook.borrow_mut().take());
                if let Some((ready, proceed)) = pause {
                    let _ = ready.send(());
                    let _ = proceed.await;
                }
            }
            shared.queued.fetch_sub(len, Ordering::AcqRel);
            shared.admission.notify_waiters();
        }
        if let Some(profile) = &mut profile {
            profile.counters.turns += 1;
            profile.counters.max_turn_datagrams =
                profile.counters.max_turn_datagrams.max(turn_datagrams);
        }
        let waiting = profile.as_ref().map(|_| {
            (
                std::time::Instant::now(),
                shared.queued.load(Ordering::Acquire) > 0,
                conn.datagram_send_buffer_space_hint() < capacity,
            )
        });
        // Space and closure both arrive as drain notifications.
        tokio::select! {
            () = &mut drained => {}
            () = shared.wake.notified() => {}
            () = async {
                tokio::time::sleep_until(blocked_deadline.expect("blocked deadline").into()).await;
            }, if blocked_deadline.is_some() => {}
        }
        if let (Some(profile), Some((at, queued, buffered))) = (&mut profile, waiting) {
            profile.waited(at.elapsed(), queued, buffered);
        }
    }
    let mut queue = shared.queue.lock().expect("writer queue");
    shared.queued.fetch_sub(
        queue.drain(..).map(|frame| frame.data.len()).sum(),
        Ordering::AcqRel,
    );
}

// Deterministic tests model preemption on the unlocked queue and after Quinn
// accepts a datagram, before local accounting releases it.
#[cfg(test)]
thread_local! {
    static TEST_BEFORE_POP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static TEST_AFTER_SEND: std::cell::RefCell<Option<(tokio::sync::oneshot::Sender<()>, tokio::sync::oneshot::Receiver<()>)>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn test_before_pop(f: impl FnOnce() + 'static) {
    TEST_BEFORE_POP.with(|hook| *hook.borrow_mut() = Some(Box::new(f)));
}
#[cfg(test)]
pub(super) fn test_after_send() -> (
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let (ready, entered) = tokio::sync::oneshot::channel();
    let (release, proceed) = tokio::sync::oneshot::channel();
    TEST_AFTER_SEND.with(|hook| *hook.borrow_mut() = Some((ready, proceed)));
    (entered, release)
}
