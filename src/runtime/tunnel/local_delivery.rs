//! Bounded retry of decoded records at the local UDP boundary.
//!
//! Decoder deduplication is already committed here. A transient WouldBlock must
//! retain the record rather than depend on another original/repair to deliver it.
//! The deadline starts at local decoding; no remote/end-to-end deadline is known.
use super::{MAX_PAYLOAD, QUEUE, Record, Scope, stats};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant as DecodedAt},
};
use tokio::{
    net::UdpSocket,
    time::{Instant, Sleep, sleep_until},
};

const PER_FLOW_LIMIT: usize = QUEUE / 4;
const BYTE_LIMIT: usize = QUEUE * MAX_PAYLOAD;

/// One queue owns all send-readiness polling for its sockets. Poll implementations
/// must register the supplied waker when they return Pending.
pub(super) trait DatagramIo {
    fn try_send(&self, payload: &[u8], peer: Option<SocketAddr>) -> io::Result<usize>;
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        payload: &[u8],
        peer: Option<SocketAddr>,
    ) -> Poll<io::Result<usize>>;
}

impl DatagramIo for UdpSocket {
    fn try_send(&self, payload: &[u8], peer: Option<SocketAddr>) -> io::Result<usize> {
        match peer {
            Some(peer) => UdpSocket::try_send_to(self, payload, peer),
            None => UdpSocket::try_send(self, payload),
        }
    }

    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        payload: &[u8],
        peer: Option<SocketAddr>,
    ) -> Poll<io::Result<usize>> {
        match peer {
            Some(peer) => UdpSocket::poll_send_to(self, cx, payload, peer),
            None => UdpSocket::poll_send(self, cx, payload),
        }
    }
}

struct Pending {
    record: Record,
    pid: u8,
    decoded: Instant,
    deadline: Instant,
}

struct Flow<S> {
    socket: Arc<S>,
    peer: Option<SocketAddr>,
    records: VecDeque<Pending>,
}

#[derive(Clone, Copy)]
enum Reason {
    Expired,
    QueueFull,
    FlowFull,
    ByteLimit,
    SocketError,
    Shutdown,
}

#[derive(Clone, Copy)]
enum Outcome {
    Delivered,
    Dropped(Reason),
}

pub(super) struct Queue<S: DatagramIo = UdpSocket> {
    flows: VecDeque<Flow<S>>,
    records: usize,
    bytes: usize,
    budget: Duration,
    scope: Scope,
    timer: Option<Pin<Box<Sleep>>>,
    closed: bool,
}

impl<S: DatagramIo> Queue<S> {
    pub(super) fn new(scope: Scope, budget: Duration) -> Self {
        Self {
            flows: VecDeque::new(),
            records: 0,
            bytes: 0,
            budget,
            scope,
            timer: None,
            closed: false,
        }
    }

    /// Immediate success neither clones the socket nor allocates queue/timer
    /// storage. Existing pending data for the same socket+peer keeps FIFO order.
    /// Returns terminal drops during this call, for the existing diagnostic log.
    pub(super) fn send(
        &mut self,
        socket: &Arc<S>,
        peer: Option<SocketAddr>,
        record: Record,
        pid: u8,
        decoded: DecodedAt,
    ) -> u64 {
        let decoded = Instant::from_std(decoded);
        let deadline = decoded + self.budget;
        let mut dropped = self.expire(Instant::now());
        if self.closed {
            self.account_drop(pid, Reason::Shutdown, None);
            return dropped + 1;
        }
        if Instant::now() >= deadline {
            self.account_drop(pid, Reason::Expired, None);
            return dropped + 1;
        }
        let flow = self
            .flows
            .iter()
            .position(|flow| Arc::ptr_eq(&flow.socket, socket) && flow.peer == peer);
        if flow.is_none() {
            match socket.try_send(&record.payload, peer) {
                Ok(n) if n == record.payload.len() => {
                    self.account_success(&record, pid, None);
                    return dropped;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.scope
                        .update(|d| d.udp_delivery.would_block_events += 1);
                }
                _ => {
                    self.account_drop(pid, Reason::SocketError, None);
                    return dropped + 1;
                }
            }
        }
        // Setup and the initial attempt consume the same fixed local budget.
        let reason = if Instant::now() >= deadline {
            Some(Reason::Expired)
        } else if self.records >= QUEUE {
            Some(Reason::QueueFull)
        } else if flow.is_some_and(|i| self.flows[i].records.len() >= PER_FLOW_LIMIT) {
            Some(Reason::FlowFull)
        } else if self
            .bytes
            .checked_add(record.payload.len())
            .is_none_or(|bytes| bytes > BYTE_LIMIT)
        {
            Some(Reason::ByteLimit)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.account_drop(pid, reason, None);
            dropped += 1;
            return dropped;
        }
        let bytes = record.payload.len();
        let pending = Pending {
            record,
            pid,
            decoded,
            deadline,
        };
        if let Some(i) = flow {
            self.flows[i].records.push_back(pending);
        } else {
            let mut records = VecDeque::new();
            records.push_back(pending);
            self.flows.push_back(Flow {
                socket: Arc::clone(socket),
                peer,
                records,
            });
        }
        self.records += 1;
        self.bytes += bytes;
        // Scope updates both the session and the process aggregate. Gauges must
        // change by a delta, never be assigned this particular queue's size.
        self.scope.update(|d| {
            let stats = &mut d.udp_delivery;
            stats.pending_records += 1;
            stats.pending_bytes += bytes as u64;
            stats.peak_pending_records = stats.peak_pending_records.max(stats.pending_records);
            stats.peak_pending_bytes = stats.peak_pending_bytes.max(stats.pending_bytes);
            stats.queued_records += 1;
        });
        dropped
    }

    /// Local socket creation/connect failures share the terminal UDP-send total.
    pub(super) fn socket_error(&self, pid: u8) -> u64 {
        self.account_drop(pid, Reason::SocketError, None);
        1
    }

    /// Cancellation does not remove pending records. Each successful poll
    /// finishes at most one record; state and counters are committed together,
    /// without an await between a successful syscall and dequeue/accounting.
    pub(super) async fn ready(&mut self) -> u64 {
        poll_fn(|cx| self.poll_ready(cx)).await
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<u64> {
        if self.closed || self.flows.is_empty() {
            return Poll::Pending;
        }
        for _ in 0..self.flows.len() {
            let outcome = {
                let flow = self.flows.front().expect("nonempty output flows");
                let pending = flow.records.front().expect("nonempty output flow");
                if Instant::now() >= pending.deadline {
                    Some(Outcome::Dropped(Reason::Expired))
                } else {
                    match flow
                        .socket
                        .poll_send(cx, &pending.record.payload, flow.peer)
                    {
                        Poll::Pending => None,
                        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                            None
                        }
                        Poll::Ready(Ok(n)) if n == pending.record.payload.len() => {
                            Some(Outcome::Delivered)
                        }
                        Poll::Ready(_) => Some(Outcome::Dropped(Reason::SocketError)),
                    }
                }
            };
            if let Some(outcome) = outcome {
                let flows = self.flows.len();
                let dropped = self.finish_front(outcome, Instant::now());
                if self.flows.len() == flows {
                    self.flows.rotate_left(1);
                }
                return Poll::Ready(dropped);
            }
            // A blocked socket cannot hold another local UDP flow behind it.
            // Shared client sockets receive the same queue-owner waker.
            self.flows.rotate_left(1);
        }
        let deadline = self
            .flows
            .iter()
            .filter_map(|flow| flow.records.front().map(|pending| pending.deadline))
            .min()
            .expect("pending output deadline");
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(sleep_until(deadline)));
        if timer.deadline() != deadline {
            timer.as_mut().reset(deadline);
        }
        if timer.as_mut().poll(cx).is_ready() {
            // Time may have advanced while polling sockets. The next poll checks
            // expiry before any syscall even if no socket ever becomes writable.
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn expire(&mut self, now: Instant) -> u64 {
        let mut dropped = 0;
        // Visit each original flow once. Finish all expired heads before moving
        // on; revisiting a fresh flow must not skip expired tails in another.
        for _ in 0..self.flows.len() {
            let flows = self.flows.len();
            while self.flows.front().is_some_and(|flow| {
                flow.records.front().expect("nonempty output flow").deadline <= now
            }) {
                dropped += self.finish_front(Outcome::Dropped(Reason::Expired), now);
                if self.flows.len() < flows {
                    break;
                }
            }
            if self.flows.len() == flows {
                self.flows.rotate_left(1);
            }
        }
        dropped
    }

    fn finish_front(&mut self, outcome: Outcome, now: Instant) -> u64 {
        let flow = self.flows.front_mut().expect("nonempty output flows");
        let pending = flow.records.pop_front().expect("nonempty output flow");
        self.records -= 1;
        self.bytes -= pending.record.payload.len();
        if flow.records.is_empty() {
            self.flows.pop_front();
        }
        if self.flows.is_empty() {
            self.timer = None;
        }
        let age = now.saturating_duration_since(pending.decoded);
        match outcome {
            Outcome::Delivered => {
                self.account_success(&pending.record, pending.pid, Some(age));
                0
            }
            Outcome::Dropped(reason) => {
                self.account_drop(
                    pending.pid,
                    reason,
                    Some((pending.record.payload.len(), age)),
                );
                1
            }
        }
    }

    fn retire_pending(stats: &mut stats::UdpDelivery, bytes: usize, age: Duration) {
        stats.pending_records -= 1;
        stats.pending_bytes -= bytes as u64;
        stats.queued_wait.add(age);
    }

    fn account_success(&self, record: &Record, pid: u8, queued_age: Option<Duration>) {
        self.scope.update(|d| {
            if let Some(age) = queued_age {
                Self::retire_pending(&mut d.udp_delivery, record.payload.len(), age);
                d.udp_delivery.delayed_delivered += 1;
            }
            d.records.udp_target_delivered += 1;
            d.records.udp_target_bytes += record.payload.len() as u64;
            d.udp_delivered_record_ids.add(record.id);
        });
        self.scope.path(pid, |p| p.udp_target_delivered += 1);
    }

    fn account_drop(&self, pid: u8, reason: Reason, queued: Option<(usize, Duration)>) {
        self.scope.update(|d| {
            if let Some((bytes, age)) = queued {
                Self::retire_pending(&mut d.udp_delivery, bytes, age);
            }
            let stats = &mut d.udp_delivery;
            match reason {
                Reason::Expired => stats.expired_dropped += 1,
                Reason::QueueFull => stats.queue_full_dropped += 1,
                Reason::FlowFull => stats.flow_full_dropped += 1,
                Reason::ByteLimit => stats.byte_limit_dropped += 1,
                Reason::SocketError => stats.socket_error_dropped += 1,
                Reason::Shutdown => stats.shutdown_dropped += 1,
            }
            d.records.udp_target_send_dropped += 1;
        });
        self.scope.path(pid, |p| p.udp_target_send_dropped += 1);
    }

    /// Explicit stop and Drop are idempotent. No worker, socket reference or
    /// timer remains responsible for a record after this returns.
    pub(super) fn close(&mut self) -> u64 {
        self.closed = true;
        let mut dropped = 0;
        let now = Instant::now();
        while !self.flows.is_empty() {
            dropped += self.finish_front(Outcome::Dropped(Reason::Shutdown), now);
        }
        self.timer = None;
        dropped
    }
}

impl<S: DatagramIo> Drop for Queue<S> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fec::Encoder, runtime::wire};
    use std::{
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
        task::Waker,
    };
    use tokio::time::{advance, timeout};

    #[derive(Clone, Copy)]
    enum Mode {
        Blocked,
        Ready,
        Error,
        Short,
    }

    struct FakeState {
        mode: Mode,
        sent: Vec<Vec<u8>>,
        try_calls: usize,
        poll_calls: usize,
        waker: Option<Waker>,
    }

    struct FakeIo(Mutex<FakeState>);

    impl FakeIo {
        fn new(mode: Mode) -> Arc<Self> {
            Arc::new(Self(Mutex::new(FakeState {
                mode,
                sent: Vec::new(),
                try_calls: 0,
                poll_calls: 0,
                waker: None,
            })))
        }

        fn set(&self, mode: Mode) {
            let waker = {
                let mut state = self.0.lock().unwrap();
                state.mode = mode;
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        fn result(state: &mut FakeState, payload: &[u8]) -> io::Result<usize> {
            match state.mode {
                Mode::Blocked => Err(io::ErrorKind::WouldBlock.into()),
                Mode::Ready => {
                    state.sent.push(payload.to_vec());
                    Ok(payload.len())
                }
                Mode::Error => Err(io::ErrorKind::PermissionDenied.into()),
                Mode::Short => Ok(payload.len().saturating_sub(1)),
            }
        }
    }

    impl DatagramIo for FakeIo {
        fn try_send(&self, payload: &[u8], _peer: Option<SocketAddr>) -> io::Result<usize> {
            let mut state = self.0.lock().unwrap();
            state.try_calls += 1;
            Self::result(&mut state, payload)
        }

        fn poll_send(
            &self,
            cx: &mut Context<'_>,
            payload: &[u8],
            _peer: Option<SocketAddr>,
        ) -> Poll<io::Result<usize>> {
            let mut state = self.0.lock().unwrap();
            state.poll_calls += 1;
            if matches!(state.mode, Mode::Blocked) {
                state.waker = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(Self::result(&mut state, payload))
            }
        }
    }

    fn scope(name: &str) -> Scope {
        let scope = stats::Metrics::new("client").scope(name, stats::RETURN);
        scope.metrics.state(|state| {
            for pid in 0..3 {
                state.paths.insert(
                    format!("{name}/{pid}"),
                    stats::Path {
                        session_id: name.to_owned(),
                        path_id: pid,
                        ..stats::Path::default()
                    },
                );
            }
        });
        scope
    }

    fn counters(scope: &Scope) -> stats::Direction {
        let mut result = stats::Direction::default();
        scope.metrics.state(|state| {
            if let Some(direction) = state.sessions[&scope.session].get(scope.direction) {
                result = direction.clone();
            }
        });
        result
    }

    fn record(id: u64, len: usize) -> Record {
        Record {
            flow: 1,
            id,
            payload: vec![id as u8; len],
        }
    }

    fn decoded_now() -> DecodedAt {
        Instant::now().into_std()
    }

    async fn poll_pending<S: DatagramIo>(queue: &mut Queue<S>) {
        poll_fn(|cx| {
            assert!(queue.poll_ready(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn immediate_success_does_not_allocate_queue_storage_or_clone_socket() {
        let scope = scope("immediate");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
        let socket = FakeIo::new(Mode::Ready);
        assert_eq!(queue.send(&socket, None, record(1, 7), 1, decoded_now()), 0);
        assert_eq!(Arc::strong_count(&socket), 1);
        assert_eq!(queue.flows.capacity(), 0);
        assert!(queue.timer.is_none());
        assert_eq!(socket.0.lock().unwrap().poll_calls, 0);
        let counts = counters(&scope);
        assert_eq!(counts.records.udp_target_delivered, 1);
        assert_eq!(counts.records.udp_target_bytes, 7);
        assert_eq!(counts.udp_delivery.queued_records, 0);
        assert_eq!(counts.records.udp_target_send_dropped, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_flow_does_not_block_other_fast_or_queued_flows() {
        let scope = scope("fair");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
        let first = FakeIo::new(Mode::Blocked);
        let second = FakeIo::new(Mode::Ready);
        let third = FakeIo::new(Mode::Blocked);
        queue.send(&first, None, record(1, 1), 0, decoded_now());
        queue.send(&second, None, record(2, 1), 1, decoded_now());
        queue.send(&third, None, record(3, 1), 2, decoded_now());
        assert_eq!(second.0.lock().unwrap().sent, vec![vec![2]]);
        poll_pending(&mut queue).await;
        third.set(Mode::Ready);
        assert_eq!(queue.ready().await, 0);
        assert_eq!(third.0.lock().unwrap().sent, vec![vec![3]]);
        assert!(first.0.lock().unwrap().sent.is_empty());
        assert_eq!(counters(&scope).udp_delivery.pending_records, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn same_socket_peer_keeps_fifo_even_when_later_record_could_send() {
        let scope = scope("fifo");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
        let socket = FakeIo::new(Mode::Blocked);
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let other_peer: SocketAddr = "127.0.0.1:2".parse().unwrap();
        queue.send(&socket, Some(peer), record(1, 1), 0, decoded_now());
        socket.set(Mode::Ready);
        queue.send(&socket, Some(peer), record(2, 1), 1, decoded_now());
        assert_eq!(socket.0.lock().unwrap().try_calls, 1);
        // The same client socket can immediately deliver a different peer.
        queue.send(&socket, Some(other_peer), record(3, 1), 2, decoded_now());
        assert_eq!(socket.0.lock().unwrap().sent, vec![vec![3]]);
        assert_eq!(queue.ready().await, 0);
        assert_eq!(queue.ready().await, 0);
        assert_eq!(
            socket.0.lock().unwrap().sent,
            vec![vec![3], vec![1], vec![2]]
        );
        let counts = counters(&scope);
        assert_eq!(counts.udp_delivery.queued_records, 2);
        assert_eq!(counts.udp_delivery.would_block_events, 1);
        assert_eq!(counts.udp_delivery.delayed_delivered, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_is_not_renewed_and_writable_at_expiry_cannot_send() {
        let scope = scope("deadline");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
        let socket = FakeIo::new(Mode::Blocked);
        queue.send(&socket, None, record(1, 10), 1, decoded_now());
        poll_pending(&mut queue).await;
        advance(Duration::from_millis(60)).await;
        poll_pending(&mut queue).await;
        queue.send(&socket, None, record(2, 10), 1, decoded_now());
        advance(Duration::from_millis(40)).await;
        socket.set(Mode::Ready);
        assert_eq!(queue.ready().await, 1);
        assert!(socket.0.lock().unwrap().sent.is_empty());
        assert_eq!(queue.ready().await, 0);
        assert_eq!(socket.0.lock().unwrap().sent, vec![vec![2; 10]]);
        let counts = counters(&scope);
        assert_eq!(counts.udp_delivery.expired_dropped, 1);
        assert_eq!(counts.udp_delivery.delayed_delivered, 1);
        assert_eq!(counts.udp_delivery.pending_records, 0);
        assert_eq!(counts.udp_delivery.pending_bytes, 0);
        assert_eq!(counts.udp_delivery.queued_wait.count, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_timer_works_without_socket_wakeup() {
        let scope = scope("timer");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(25));
        let socket = FakeIo::new(Mode::Blocked);
        queue.send(&socket, None, record(1, 1), 0, decoded_now());
        assert_eq!(queue.ready().await, 1);
        assert!(socket.0.lock().unwrap().sent.is_empty());
        assert_eq!(counters(&scope).udp_delivery.expired_dropped, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn decode_budget_includes_setup_time_and_rejects_before_initial_send() {
        let scope = scope("setup-age");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
        let socket = FakeIo::new(Mode::Ready);
        let decoded = decoded_now();
        advance(Duration::from_millis(100)).await;
        assert_eq!(queue.send(&socket, None, record(1, 1), 0, decoded), 1);
        assert_eq!(socket.0.lock().unwrap().try_calls, 0);
        assert_eq!(counters(&scope).udp_delivery.expired_dropped, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_ready_preserves_record_and_stop_is_idempotent() {
        let scope = scope("cancel");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
        let socket = FakeIo::new(Mode::Blocked);
        queue.send(&socket, None, record(1, 11), 1, decoded_now());
        tokio::select! {
            biased;
            _ = queue.ready() => panic!("blocked output became ready"),
            _ = std::future::ready(()) => {},
        }
        assert_eq!(counters(&scope).udp_delivery.pending_records, 1);
        assert_eq!(Arc::strong_count(&socket), 2);
        assert_eq!(queue.close(), 1);
        assert_eq!(queue.close(), 0);
        assert_eq!(Arc::strong_count(&socket), 1);
        assert!(queue.timer.is_none());
        drop(queue);
        let counts = counters(&scope);
        assert_eq!(counts.udp_delivery.shutdown_dropped, 1);
        assert_eq!(counts.records.udp_target_send_dropped, 1);
        assert_eq!(counts.udp_delivery.pending_records, 0);
        assert_eq!(counts.udp_delivery.pending_bytes, 0);
        scope.metrics.state(|state| {
            assert_eq!(state.paths["cancel/1"].udp_target_send_dropped, 1);
        });
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_queue_releases_pending_records_and_socket_handles() {
        let scope = scope("drop");
        let socket = FakeIo::new(Mode::Blocked);
        {
            let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
            queue.send(&socket, None, record(1, 13), 2, decoded_now());
            poll_pending(&mut queue).await;
        }
        assert_eq!(Arc::strong_count(&socket), 1);
        let counts = counters(&scope);
        assert_eq!(counts.udp_delivery.shutdown_dropped, 1);
        assert_eq!(counts.udp_delivery.pending_records, 0);
        assert_eq!(counts.udp_delivery.pending_bytes, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn per_flow_and_total_record_limits_are_enforced() {
        let scope = scope("limits");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
        let sockets: Vec<_> = (0..4).map(|_| FakeIo::new(Mode::Blocked)).collect();
        for (flow, socket) in sockets.iter().enumerate() {
            for index in 0..PER_FLOW_LIMIT {
                assert_eq!(
                    queue.send(
                        socket,
                        None,
                        record((flow * PER_FLOW_LIMIT + index) as u64, MAX_PAYLOAD),
                        0,
                        decoded_now()
                    ),
                    0
                );
            }
            if flow == 0 {
                assert_eq!(
                    queue.send(socket, None, record(999, 1), 0, decoded_now()),
                    1
                );
            }
        }
        let extra = FakeIo::new(Mode::Blocked);
        assert_eq!(
            queue.send(&extra, None, record(1000, 1), 0, decoded_now()),
            1
        );
        assert_eq!(Arc::strong_count(&extra), 1);
        let counts = counters(&scope);
        assert_eq!(counts.udp_delivery.pending_records, QUEUE as u64);
        assert_eq!(counts.udp_delivery.pending_bytes, BYTE_LIMIT as u64);
        assert_eq!(counts.udp_delivery.peak_pending_records, QUEUE as u64);
        assert_eq!(counts.udp_delivery.peak_pending_bytes, BYTE_LIMIT as u64);
        assert_eq!(counts.udp_delivery.flow_full_dropped, 1);
        assert_eq!(counts.udp_delivery.queue_full_dropped, 1);
        assert_eq!(queue.close(), QUEUE as u64);
        assert_eq!(counters(&scope).udp_delivery.pending_bytes, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn byte_limit_is_independent_of_the_record_limit() {
        let scope = scope("bytes");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
        let socket = FakeIo::new(Mode::Blocked);
        // Decoder normally limits every payload to MAX_PAYLOAD. Deliberately
        // oversized synthetic input verifies the queue's independent byte guard.
        assert_eq!(
            queue.send(&socket, None, record(1, BYTE_LIMIT), 0, decoded_now()),
            0
        );
        assert_eq!(queue.send(&socket, None, record(2, 1), 0, decoded_now()), 1);
        let counts = counters(&scope);
        assert_eq!(counts.udp_delivery.pending_records, 1);
        assert_eq!(counts.udp_delivery.pending_bytes, BYTE_LIMIT as u64);
        assert_eq!(counts.udp_delivery.byte_limit_dropped, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_records_free_capacity_before_new_admission() {
        let scope = scope("expired-capacity");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(10));
        let socket = FakeIo::new(Mode::Blocked);
        for id in 0..PER_FLOW_LIMIT {
            queue.send(&socket, None, record(id as u64, 1), 0, decoded_now());
        }
        advance(Duration::from_millis(10)).await;
        assert_eq!(
            queue.send(&socket, None, record(1000, 1), 0, decoded_now()),
            PER_FLOW_LIMIT as u64
        );
        let counts = counters(&scope);
        assert_eq!(counts.udp_delivery.expired_dropped, PER_FLOW_LIMIT as u64);
        assert_eq!(counts.udp_delivery.flow_full_dropped, 0);
        assert_eq!(counts.udp_delivery.pending_records, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_visits_each_mixed_flow_and_clears_all_expired_heads() {
        let scope = scope("mixed-expiry");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
        let first = FakeIo::new(Mode::Blocked);
        let fresh = FakeIo::new(Mode::Blocked);
        let last = FakeIo::new(Mode::Blocked);
        let old = decoded_now();
        for id in 1..=3 {
            queue.send(&first, None, record(id, 10), 0, old);
        }
        advance(Duration::from_millis(60)).await;
        queue.send(&fresh, None, record(4, 10), 1, decoded_now());
        // Delayed setup may submit a previously decoded record after a newer
        // flow. The middle fresh flow cannot terminate the expiry scan early.
        for id in 5..=7 {
            queue.send(&last, None, record(id, 10), 2, old);
        }
        advance(Duration::from_millis(40)).await;
        assert_eq!(queue.send(&fresh, None, record(8, 10), 1, decoded_now()), 6);
        let counts = counters(&scope);
        assert_eq!(counts.udp_delivery.expired_dropped, 6);
        assert_eq!(counts.udp_delivery.pending_records, 2);
        assert_eq!(counts.udp_delivery.pending_bytes, 20);
        assert_eq!(Arc::strong_count(&first), 1);
        assert_eq!(Arc::strong_count(&last), 1);
        assert_eq!(Arc::strong_count(&fresh), 2);
        assert_eq!(queue.flows.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn hard_errors_and_short_writes_are_terminal_once() {
        let scope = scope("errors");
        let mut queue = Queue::new(scope.clone(), Duration::from_millis(100));
        let socket = FakeIo::new(Mode::Error);
        assert_eq!(queue.send(&socket, None, record(1, 2), 1, decoded_now()), 1);
        socket.set(Mode::Blocked);
        queue.send(&socket, None, record(2, 2), 2, decoded_now());
        socket.set(Mode::Short);
        assert_eq!(queue.ready().await, 1);
        assert_eq!(queue.close(), 0);
        let counts = counters(&scope);
        assert_eq!(counts.udp_delivery.socket_error_dropped, 2);
        assert_eq!(counts.records.udp_target_send_dropped, 2);
        assert_eq!(counts.records.udp_target_delivered, 0);
        assert_eq!(counts.udp_delivery.pending_records, 0);
        scope.metrics.state(|state| {
            assert_eq!(state.paths["errors/1"].udp_target_send_dropped, 1);
            assert_eq!(state.paths["errors/2"].udp_target_send_dropped, 1);
        });
    }

    #[tokio::test(start_paused = true)]
    async fn aggregate_pending_gauges_sum_sessions_and_retire_by_delta() {
        let metrics = stats::Metrics::new("server");
        let first = metrics.scope("first", stats::FORWARD);
        let second = metrics.scope("second", stats::FORWARD);
        let socket = FakeIo::new(Mode::Blocked);
        let mut a = Queue::new(first, Duration::from_millis(100));
        let mut b = Queue::new(second, Duration::from_millis(100));
        a.send(&socket, None, record(1, 7), 0, decoded_now());
        b.send(&socket, None, record(1, 11), 0, decoded_now());
        metrics.state(|state| {
            let counts = &state.directions[stats::FORWARD].udp_delivery;
            assert_eq!(counts.pending_records, 2);
            assert_eq!(counts.pending_bytes, 18);
            assert_eq!(counts.peak_pending_records, 2);
        });
        a.close();
        metrics.state(|state| {
            let counts = &state.directions[stats::FORWARD].udp_delivery;
            assert_eq!(counts.pending_records, 1);
            assert_eq!(counts.pending_bytes, 11);
        });
        b.close();
        metrics.state(|state| {
            let counts = &state.directions[stats::FORWARD].udp_delivery;
            assert_eq!(counts.pending_records, 0);
            assert_eq!(counts.pending_bytes, 0);
            assert_eq!(counts.shutdown_dropped, 2);
        });
    }

    /// A deterministic one-shot WouldBlock followed by genuine UDP syscalls.
    /// No socket-buffer pressure or packet impairment is used in this fixture.
    struct FirstBlockedUdp {
        socket: UdpSocket,
        first: AtomicBool,
        held: AtomicBool,
        waker: Mutex<Option<Waker>>,
    }

    impl FirstBlockedUdp {
        fn release(&self) {
            self.held.store(false, Ordering::SeqCst);
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
        }
    }

    impl DatagramIo for FirstBlockedUdp {
        fn try_send(&self, payload: &[u8], peer: Option<SocketAddr>) -> io::Result<usize> {
            if self.first.swap(false, Ordering::SeqCst) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            DatagramIo::try_send(&self.socket, payload, peer)
        }

        fn poll_send(
            &self,
            cx: &mut Context<'_>,
            payload: &[u8],
            peer: Option<SocketAddr>,
        ) -> Poll<io::Result<usize>> {
            if self.held.load(Ordering::SeqCst) {
                *self.waker.lock().unwrap() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            DatagramIo::poll_send(&self.socket, cx, payload, peer)
        }
    }

    async fn receiver_after_would_block_case(connected: bool) {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = target.local_addr().unwrap();
        if connected {
            sender.connect(peer).await.unwrap();
        }
        let socket = Arc::new(FirstBlockedUdp {
            socket: sender,
            first: AtomicBool::new(true),
            held: AtomicBool::new(true),
            waker: Mutex::new(None),
        });
        let destination = (!connected).then_some(peer);
        let scope = scope(if connected {
            "receiver-send"
        } else {
            "receiver-send-to"
        });
        let mut output = Queue::new(scope.clone(), Duration::from_secs(1));
        let now = decoded_now();
        let original = record(7, 128);
        let mut encoder = Encoder::new(1, Duration::from_millis(1)).unwrap();
        let mut frames = encoder
            .push(&original.encode().unwrap(), now)
            .unwrap()
            .into_iter()
            .map(wire::shard);
        let data = frames.next().unwrap();
        let repair = frames.next().unwrap();
        assert!(frames.next().is_none());
        let mut decoder = wire::Receiver::with_repair_wait(Duration::from_secs(1));
        let decoded = super::super::receive_records(&mut decoder, &scope, 1, &data);
        assert_eq!(decoded.len(), 1);
        for record in decoded {
            output.send(&socket, destination, record, 1, decoded_now());
        }
        assert_eq!(decoder.originals, 1);
        assert_eq!(counters(&scope).udp_delivery.pending_records, 1);
        // Poll/register readiness, then cancel the wait exactly as select does.
        poll_pending(&mut output).await;
        assert!(super::super::receive_records(&mut decoder, &scope, 2, &repair).is_empty());
        assert!(super::super::receive_records(&mut decoder, &scope, 1, &data).is_empty());
        assert_eq!(decoder.duplicates, 1);
        assert_eq!(counters(&scope).records.udp_target_delivered, 0);
        socket.release();
        assert_eq!(
            timeout(Duration::from_secs(1), output.ready())
                .await
                .unwrap(),
            0
        );
        let mut received = [0u8; 256];
        let len = timeout(Duration::from_secs(1), target.recv(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[..len], original.payload.as_slice());
        assert!(super::super::receive_records(&mut decoder, &scope, 1, &data).is_empty());
        assert!(
            timeout(Duration::from_millis(20), target.recv(&mut received))
                .await
                .is_err()
        );
        let counts = counters(&scope);
        assert_eq!(counts.records.udp_target_delivered, 1);
        assert_eq!(counts.records.udp_target_send_dropped, 0);
        assert_eq!(counts.udp_delivery.would_block_events, 1);
        assert_eq!(counts.udp_delivery.delayed_delivered, 1);
        assert_eq!(counts.udp_delivery.pending_records, 0);
        assert_eq!(counts.udp_delivery.pending_bytes, 0);
        assert_eq!(counts.udp_delivered_record_ids.recent.len(), 1);
        scope.metrics.state(|state| {
            assert_eq!(
                state.paths[&format!("{}/1", scope.session)].udp_target_delivered,
                1
            );
            assert_eq!(
                state.paths[&format!("{}/2", scope.session)].udp_target_delivered,
                0
            );
        });
    }

    #[tokio::test]
    async fn decoded_record_survives_first_would_block_connected_udp_once() {
        receiver_after_would_block_case(true).await;
    }

    #[tokio::test]
    async fn decoded_record_survives_first_would_block_send_to_once() {
        receiver_after_would_block_case(false).await;
    }
}
