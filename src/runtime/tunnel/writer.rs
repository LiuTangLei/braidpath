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

use bytes::Bytes;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
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

#[derive(Default)]
struct Shared {
    queue: Mutex<VecDeque<Bytes>>,
    /// Bytes in `queue`; never below its contents while a datagram moves.
    queued: AtomicUsize,
    budget: AtomicUsize,
    wake: Notify,
    admission: Notify,
    stopped: AtomicBool,
}

impl Writer {
    pub(super) fn spawn(conn: &quinn::Connection) -> Arc<Self> {
        let capacity = conn.datagram_send_buffer_space();
        let shared = Arc::new(Shared::default());
        tokio::spawn(run(conn.clone(), shared.clone(), capacity));
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

    /// Queue a datagram after this path's queued data. False once closed.
    pub(super) fn send(&self, data: Bytes) -> bool {
        self.enqueue(data, false)
    }

    /// Queue a control datagram ahead of this path's queued data.
    pub(super) fn send_first(&self, data: Bytes) -> bool {
        self.enqueue(data, true)
    }

    fn enqueue(&self, data: Bytes, first: bool) -> bool {
        if self.conn.is_closed() || self.shared.stopped.load(Ordering::Relaxed) {
            return false;
        }
        let len = data.len();
        {
            let mut queue = self.shared.queue.lock().expect("writer queue");
            self.shared.queued.fetch_add(len, Ordering::AcqRel);
            if first {
                queue.push_front(data);
            } else {
                queue.push_back(data);
            }
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

async fn run(conn: quinn::Connection, shared: Arc<Shared>, capacity: usize) {
    loop {
        let drained = conn.datagrams_drained();
        tokio::pin!(drained);
        drained.as_mut().enable();
        if shared.stopped.load(Ordering::Relaxed) || conn.is_closed() {
            break;
        }
        let budget = shared.budget.load(Ordering::Relaxed);
        loop {
            #[cfg(test)]
            TEST_BEFORE_POP.with(|hook| {
                let f = hook.borrow_mut().take();
                if let Some(f) = f {
                    f();
                }
            });
            let (data, len) = {
                let mut queue = shared.queue.lock().expect("writer queue");
                let Some(len) = queue.front().map(Bytes::len) else {
                    break;
                };
                let in_quinn = capacity.saturating_sub(conn.datagram_send_buffer_space_hint());
                if in_quinn > 0 && in_quinn + len > budget {
                    break;
                }
                (queue.pop_front().expect("front datagram"), len)
            };
            // Quinn's space shrinks before the queue does, so `held` never
            // understates. A refused datagram is a closed or resized path.
            let _ = conn.send_datagram(data);
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
        // Space and closure both arrive as drain notifications.
        tokio::select! {
            () = &mut drained => {}
            () = shared.wake.notified() => {}
        }
    }
    let mut queue = shared.queue.lock().expect("writer queue");
    shared.queued.fetch_sub(
        queue.drain(..).map(|data| data.len()).sum(),
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
