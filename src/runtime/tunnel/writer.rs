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
            if self.admits(bytes) || self.conn.is_closed() {
                return;
            }
            drained.await;
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
            let Some(len) = shared
                .queue
                .lock()
                .expect("writer queue")
                .front()
                .map(Bytes::len)
            else {
                break;
            };
            let in_quinn = capacity.saturating_sub(conn.datagram_send_buffer_space_hint());
            if in_quinn > 0 && in_quinn + len > budget {
                break;
            }
            let data = shared
                .queue
                .lock()
                .expect("writer queue")
                .pop_front()
                .expect("front datagram");
            // Quinn's space shrinks before the queue does, so `held` never
            // understates. A refused datagram is a closed or resized path.
            let _ = conn.send_datagram(data);
            shared.queued.fetch_sub(len, Ordering::AcqRel);
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
