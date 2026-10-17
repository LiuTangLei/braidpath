//! TCP adapters for reliable streams: a client listener and a server target.
//!
//! Each accepted connection is one stream with its own windows and
//! retransmission state, so a stalled transfer never blocks another
//! connection. Stream records share the session's sender queue, paths, pacing
//! and FEC with UDP records. Local backpressure keeps only a short backlog,
//! sized from the measured admission rate, waiting for Quinn admission.
use super::{Policy, QueuedRecord, Scope, enqueue_record, outbound::Gauge};
use crate::runtime::{
    stream::{self, Frame},
    wire::Record,
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Notify, Semaphore, mpsc},
    task::{AbortHandle, JoinSet},
    time::{sleep_until, timeout},
};
use tracing::{debug, warn};

const MAX_STREAMS: usize = 256;
/// Receive memory shared by all streams of one session.
const RECEIVE_BUDGET: u64 = 64 * 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;
/// Local read-ahead beyond the peer's window, so sending never waits on a read.
const READ_AHEAD: u64 = 256 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TOMBSTONE: Duration = Duration::from_secs(120);
const MAX_TOMBSTONES: usize = 4096;
/// Bounds for locally queued stream bytes. One flow may hold 64 records.
const MIN_QUEUED: usize = 8 * 1000;
const MAX_QUEUED: usize = 56 * 1000;
const DRAIN_SAMPLE: Duration = Duration::from_millis(10);
const DRAIN_WINDOW: Duration = Duration::from_secs(1);
const PUBLISH_EVERY: Duration = Duration::from_millis(500);
const RETRY_FULL: Duration = Duration::from_millis(1);

pub(super) enum Io {
    Read(u32, Vec<u8>),
    ReadEnd(u32),
    Written(u32, usize),
    Failed(u32),
    Connected(u32, TcpStream),
}

enum WriteOp {
    Data(Vec<u8>),
    Finish,
}

pub(super) enum Wake {
    Io(Io),
    Accept(io::Result<(TcpStream, SocketAddr)>),
    Queue,
    Timer,
}

/// The session state a mux needs to enqueue records.
pub(super) struct Out<'a> {
    pub tx: &'a mpsc::Sender<QueuedRecord>,
    pub next_id: &'a mut u64,
    pub scope: &'a Scope,
    pub small_threshold: usize,
}
impl Out<'_> {
    fn enqueue(
        &mut self,
        flow: u32,
        payload: Vec<u8>,
        hold: Option<Arc<super::outbound::Hold>>,
    ) -> bool {
        let Some(id) = self.next_id.checked_add(1) else {
            return false;
        };
        *self.next_id = id;
        enqueue_record(
            self.tx,
            Record { flow, id, payload },
            Instant::now(),
            self.scope,
            self.small_threshold,
            hold,
        )
    }
}

struct Stream {
    send: stream::Sender,
    recv: stream::Receiver,
    reads: Option<Arc<Semaphore>>,
    granted: u64,
    writer: Option<mpsc::UnboundedSender<WriteOp>>,
    reset_writer: Option<Arc<Notify>>,
    undelivered: Vec<Vec<u8>>,
    write_finished: bool,
    tasks: Vec<AbortHandle>,
}
impl Stream {
    fn new(open: bool) -> Self {
        Self {
            send: stream::Sender::new(open),
            recv: stream::Receiver::default(),
            reads: None,
            granted: 0,
            writer: None,
            reset_writer: None,
            undelivered: Vec::new(),
            write_finished: false,
            tasks: Vec::new(),
        }
    }
    fn deliver(&mut self, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        match &self.writer {
            Some(writer) => {
                let _ = writer.send(WriteOp::Data(data));
            }
            None => self.undelivered.push(data),
        }
    }
    fn finish_writes(&mut self) {
        if self.recv.fin_received()
            && !self.write_finished
            && let Some(writer) = &self.writer
        {
            let _ = writer.send(WriteOp::Finish);
            self.write_finished = true;
        }
    }
    /// Let the reader take bytes up to the peer window plus local read-ahead.
    fn grant_reads(&mut self) {
        let Some(reads) = &self.reads else { return };
        let target = self.send.limit() + READ_AHEAD;
        if target > self.granted {
            reads.add_permits((target - self.granted) as usize);
            self.granted = target;
        }
    }
    /// The writer task is not aborted: it must apply the RST itself.
    fn abort(&mut self) {
        self.writer = None;
        if let Some(reset) = self.reset_writer.take() {
            reset.notify_one();
        }
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

/// Windowed maximum of the measured local admission rate.
struct Drain {
    sampled_at: Instant,
    admitted: u64,
    window_start: Instant,
    rates: [f64; 2],
}
impl Drain {
    fn new(now: Instant) -> Self {
        Self {
            sampled_at: now,
            admitted: 0,
            window_start: now,
            rates: [0.0; 2],
        }
    }
    fn sample(&mut self, admitted: u64, now: Instant) {
        let elapsed = now.saturating_duration_since(self.sampled_at);
        if elapsed < DRAIN_SAMPLE {
            return;
        }
        let rate = (admitted - self.admitted) as f64 / elapsed.as_secs_f64();
        self.sampled_at = now;
        self.admitted = admitted;
        if now.saturating_duration_since(self.window_start) >= DRAIN_WINDOW {
            self.rates = [rate, self.rates[0]];
            self.window_start = now;
        } else {
            self.rates[0] = self.rates[0].max(rate);
        }
    }
    /// A local drop means the backlog outlived its admission lifetime.
    fn dropped(&mut self) {
        self.rates = [self.rates[0] / 2.0, 0.0];
    }
    fn limit(&self, lifetime: Duration) -> usize {
        let rate = self.rates[0].max(self.rates[1]);
        ((rate * lifetime.as_secs_f64() * 0.5) as usize).clamp(MIN_QUEUED, MAX_QUEUED)
    }
}

pub(super) struct Mux {
    listener: Option<Arc<TcpListener>>,
    target: Option<SocketAddr>,
    streams: HashMap<u32, Stream>,
    turns: VecDeque<u32>,
    closed: HashMap<u32, Instant>,
    control: VecDeque<(u32, Vec<u8>)>,
    next_stream: u32,
    events_tx: mpsc::UnboundedSender<Io>,
    events: mpsc::UnboundedReceiver<Io>,
    tasks: JoinSet<()>,
    gauge: Arc<Gauge>,
    lifetime: Duration,
    drain: Drain,
    blocked_until: Option<Instant>,
    accept_paused_until: Option<Instant>,
    stats: stream::Snapshot,
    closed_duplicates: u64,
    scope: Scope,
    published: Instant,
}

impl Mux {
    fn new(
        listener: Option<Arc<TcpListener>>,
        target: Option<SocketAddr>,
        policy: &Policy,
        scope: Scope,
    ) -> Self {
        let (events_tx, events) = mpsc::unbounded_channel();
        let now = Instant::now();
        Self {
            listener,
            target,
            streams: HashMap::new(),
            turns: VecDeque::new(),
            closed: HashMap::new(),
            control: VecDeque::new(),
            next_stream: 0,
            events_tx,
            events,
            tasks: JoinSet::new(),
            gauge: Arc::new(Gauge::default()),
            lifetime: policy.admission_lifetime(),
            drain: Drain::new(now),
            blocked_until: None,
            accept_paused_until: None,
            stats: stream::Snapshot::default(),
            closed_duplicates: 0,
            scope,
            published: now,
        }
    }
    /// Accepts local connections; the peer connects each stream to its target.
    pub(super) fn client(listener: Arc<TcpListener>, policy: &Policy, scope: Scope) -> Self {
        Self::new(Some(listener), None, policy, scope)
    }
    /// Connects each peer-opened stream to the configured target.
    pub(super) fn server(target: SocketAddr, policy: &Policy, scope: Scope) -> Self {
        Self::new(None, Some(target), policy, scope)
    }

    fn deadline(&self, now: Instant) -> Instant {
        let mut at = self.published + PUBLISH_EVERY;
        for s in self.streams.values() {
            for deadline in [s.send.next_deadline(now), s.recv.next_deadline()]
                .into_iter()
                .flatten()
            {
                at = at.min(deadline);
            }
        }
        for deadline in [self.blocked_until, self.accept_paused_until]
            .into_iter()
            .flatten()
        {
            at = at.min(deadline);
        }
        at
    }

    pub(super) async fn wake(&mut self) -> Wake {
        let now = Instant::now();
        let deadline = tokio::time::Instant::from_std(self.deadline(now));
        let accepting = self.listener.is_some()
            && self.streams.len() < MAX_STREAMS
            && self.accept_paused_until.is_none_or(|at| now >= at);
        let listener = self.listener.clone();
        let queue_waiting = self.streams.values().any(|s| s.send.has_transmit());
        tokio::select! {
            biased;
            Some(event) = self.events.recv() => Wake::Io(event),
            _ = self.gauge.notify.notified(), if queue_waiting => Wake::Queue,
            accepted = async { listener.as_ref().expect("listener").accept().await }, if accepting => Wake::Accept(accepted),
            _ = sleep_until(deadline) => Wake::Timer,
        }
    }

    fn window(&self) -> u64 {
        (RECEIVE_BUDGET / self.streams.len().max(1) as u64)
            .clamp(stream::INITIAL_WINDOW, stream::MAX_WINDOW)
    }

    fn attach(&mut self, id: u32, tcp: TcpStream) {
        let Some(s) = self.streams.get_mut(&id) else {
            return;
        };
        let _ = tcp.set_nodelay(true);
        let (read, write) = tcp.into_split();
        let reads = Arc::new(Semaphore::new(0));
        let (writer, ops) = mpsc::unbounded_channel();
        let reset = Arc::new(Notify::new());
        s.tasks.push(
            self.tasks
                .spawn(read_loop(id, read, reads.clone(), self.events_tx.clone())),
        );
        // Detached so that dropping the mux still lets each writer send its RST.
        tokio::spawn(write_loop(
            id,
            write,
            ops,
            reset.clone(),
            self.events_tx.clone(),
        ));
        s.reset_writer = Some(reset);
        for data in s.undelivered.drain(..) {
            let _ = writer.send(WriteOp::Data(data));
        }
        s.reads = Some(reads);
        s.writer = Some(writer);
        s.grant_reads();
        s.finish_writes();
    }

    fn open(&mut self, id: u32, open: bool) {
        self.streams.insert(id, Stream::new(open));
        self.turns.push_back(id);
        self.stats.opened += 1;
    }

    fn close(&mut self, id: u32) -> Option<Stream> {
        let s = self.streams.remove(&id)?;
        self.turns.retain(|t| *t != id);
        self.closed_duplicates += s.recv.duplicates();
        if self.closed.len() >= MAX_TOMBSTONES
            && let Some(oldest) = self
                .closed
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(id, _)| *id)
        {
            self.closed.remove(&oldest);
        }
        self.closed.insert(id, Instant::now());
        Some(s)
    }

    fn reset(&mut self, id: u32, reason: &str) {
        if let Some(mut s) = self.close(id) {
            debug!(stream = id, reason, "stream reset");
            s.abort();
            self.stats.reset_local += 1;
            // Two independent records; the peer also answers stale frames with RESET.
            for _ in 0..2 {
                self.control
                    .push_back((stream::data_flow(id), Frame::Reset.encode()));
            }
        }
    }

    pub(super) fn handle(&mut self, wake: Wake, out: &mut Out) {
        match wake {
            Wake::Io(event) => self.io(event),
            Wake::Accept(Ok((tcp, _))) => {
                if self.next_stream >= stream::MAX_STREAM_ID {
                    warn!("stream identifiers exhausted; refusing local connection");
                    self.stats.rejected += 1;
                } else {
                    self.next_stream += 1;
                    let id = self.next_stream;
                    self.open(id, true);
                    self.attach(id, tcp);
                }
            }
            Wake::Accept(Err(error)) => {
                warn!(%error, "TCP accept failed");
                self.accept_paused_until = Some(Instant::now() + Duration::from_millis(100));
            }
            Wake::Queue | Wake::Timer => {}
        }
        self.flush(out);
    }

    fn io(&mut self, event: Io) {
        match event {
            Io::Read(id, data) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    self.stats.bytes_from_application += data.len() as u64;
                    s.send.push(&data);
                }
            }
            Io::ReadEnd(id) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    s.send.finish();
                }
            }
            Io::Written(id, n) => {
                let window = self.window();
                if let Some(s) = self.streams.get_mut(&id) {
                    self.stats.bytes_to_application += n as u64;
                    s.recv.consumed(n as u64, window);
                }
            }
            Io::Failed(id) => self.reset(id, "local socket failed"),
            Io::Connected(id, tcp) => self.attach(id, tcp),
        }
    }

    /// Apply one stream record. Call `flush` after a batch of records.
    pub(super) fn receive(&mut self, record: Record) {
        let Some(id) = stream::stream_id(record.flow) else {
            return;
        };
        let Some(frame) = Frame::decode(&record.payload) else {
            self.reset(id, "malformed frame");
            return;
        };
        let now = Instant::now();
        match frame {
            Frame::Reset => {
                if let Some(mut s) = self.close(id) {
                    s.abort();
                    self.stats.reset_peer += 1;
                }
            }
            Frame::Ack(ack) => {
                let Some(s) = self.streams.get_mut(&id) else {
                    return;
                };
                self.stats.acks_received += 1;
                match s.send.on_ack(&ack, now) {
                    Some((_, spurious)) => {
                        self.stats.spurious_retransmit_reports += u64::from(spurious);
                        s.grant_reads();
                    }
                    None => self.reset(id, "invalid acknowledgment"),
                }
            }
            Frame::Data { offset, fin, data } => {
                if !self.streams.contains_key(&id) {
                    let Some(target) = self.target.filter(|_| !self.closed.contains_key(&id))
                    else {
                        // Stale or peer-opened toward a client: tell the peer it is gone.
                        self.control
                            .push_back((stream::data_flow(id), Frame::Reset.encode()));
                        return;
                    };
                    if self.streams.len() >= MAX_STREAMS {
                        self.stats.rejected += 1;
                        self.closed.insert(id, now);
                        self.control
                            .push_back((stream::data_flow(id), Frame::Reset.encode()));
                        return;
                    }
                    self.open(id, false);
                    let events = self.events_tx.clone();
                    let task = self.tasks.spawn(async move {
                        match timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await {
                            Ok(Ok(tcp)) => {
                                let _ = events.send(Io::Connected(id, tcp));
                            }
                            _ => {
                                let _ = events.send(Io::Failed(id));
                            }
                        }
                    });
                    self.streams.get_mut(&id).expect("opened").tasks.push(task);
                }
                let s = self.streams.get_mut(&id).expect("stream");
                match s.recv.on_data(offset, fin, data, now) {
                    Ok(ready) => {
                        s.deliver(ready);
                        s.finish_writes();
                    }
                    Err(violation) => self.reset(
                        id,
                        if violation == stream::Violation::FlowControl {
                            "flow-control violation"
                        } else {
                            "final-size violation"
                        },
                    ),
                }
            }
        }
    }

    /// Run timers, retransmit, send acknowledgments and new data, retire streams.
    pub(super) fn flush(&mut self, out: &mut Out) {
        let now = Instant::now();
        for (id, start, transmission) in self.gauge.take_dropped() {
            if let Some(s) = self.streams.get_mut(&id)
                && s.send.locally_dropped(start, transmission)
            {
                self.stats.local_drop_retransmits += 1;
                self.drain.dropped();
            }
        }
        let mut failed = Vec::new();
        let mut done = Vec::new();
        for (id, s) in &mut self.streams {
            if s.send.on_timeout(now) {
                self.stats.probe_timeouts += 1;
            }
            if s.send.failed(now) {
                failed.push(*id);
            } else if s.send.finished() && s.recv.finished() && s.write_finished {
                done.push(*id);
            }
        }
        for id in failed {
            self.reset(id, "peer stopped acknowledging");
        }
        for id in done {
            // The writer finishes its own shutdown; the reader already ended.
            if self.close(id).is_some() {
                self.stats.completed += 1;
            }
        }
        while let Some((flow, payload)) = self.control.pop_front() {
            if !out.enqueue(flow, payload.clone(), None) {
                self.control.push_front((flow, payload));
                break;
            }
        }
        let window = self.window();
        for (id, s) in &mut self.streams {
            if let Some(ack) = s.recv.take_ack(now, window) {
                if out.enqueue(stream::ack_flow(*id), Frame::Ack(ack).encode(), None) {
                    self.stats.acks_sent += 1;
                } else {
                    s.recv.defer_ack();
                }
            }
        }
        self.pump(out, now);
        self.closed
            .retain(|_, at| now.saturating_duration_since(*at) < TOMBSTONE);
        if now.saturating_duration_since(self.published) >= PUBLISH_EVERY {
            self.publish(now);
        }
    }

    fn pump(&mut self, out: &mut Out, now: Instant) {
        if self.blocked_until.is_some_and(|at| now < at) {
            return;
        }
        self.blocked_until = None;
        self.drain.sample(self.gauge.admitted(), now);
        let limit = self.drain.limit(self.lifetime);
        self.gauge.set_low_water(limit / 2);
        let mut idle = 0;
        while self.gauge.queued() < limit && idle < self.turns.len() {
            let id = self.turns.pop_front().expect("turn");
            self.turns.push_back(id);
            let s = self.streams.get_mut(&id).expect("stream turn");
            let Some(t) = s.send.poll_transmit(now) else {
                idle += 1;
                continue;
            };
            idle = 0;
            let payload = t.frame.encode();
            let hold = (t.transmission > 0)
                .then(|| self.gauge.hold(id, t.start, t.transmission, payload.len()));
            if !out.enqueue(stream::data_flow(id), payload, hold) {
                // The unadmitted hold reports this transmission as dropped.
                self.blocked_until = Some(now + RETRY_FULL);
                break;
            }
            self.stats.segments_sent += 1;
            if t.retransmission {
                self.stats.retransmitted_segments += 1;
                self.stats.retransmitted_bytes += match &t.frame {
                    Frame::Data { data, .. } => data.len() as u64,
                    _ => 0,
                };
            }
        }
    }

    fn publish(&mut self, now: Instant) {
        self.published = now;
        self.stats.active = self.streams.len() as u64;
        self.stats.duplicate_bytes_received = self.closed_duplicates
            + self
                .streams
                .values()
                .map(|s| s.recv.duplicates())
                .sum::<u64>();
        let snapshot = self.stats.clone();
        self.scope
            .update(|d| d.tcp_streams = Some(snapshot.clone()));
    }

    pub(super) fn close_all(&mut self) {
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            if let Some(mut s) = self.close(id) {
                s.abort();
                self.stats.reset_local += 1;
            }
        }
        self.publish(Instant::now());
        self.tasks.abort_all();
    }
}

async fn read_loop(
    id: u32,
    mut read: OwnedReadHalf,
    reads: Arc<Semaphore>,
    events: mpsc::UnboundedSender<Io>,
) {
    let mut buffer = vec![0; READ_CHUNK];
    loop {
        let Ok(first) = reads.acquire().await else {
            return;
        };
        first.forget();
        // Only this task takes permits, so the available count cannot shrink.
        let extra = reads.available_permits().min(READ_CHUNK - 1);
        if extra > 0 {
            reads
                .try_acquire_many(extra as u32)
                .expect("reader-owned permits")
                .forget();
        }
        let capacity = extra + 1;
        match read.read(&mut buffer[..capacity]).await {
            Ok(0) => {
                let _ = events.send(Io::ReadEnd(id));
                return;
            }
            Ok(n) => {
                reads.add_permits(capacity - n);
                if events.send(Io::Read(id, buffer[..n].to_vec())).is_err() {
                    return;
                }
            }
            Err(_) => {
                let _ = events.send(Io::Failed(id));
                return;
            }
        }
    }
}

/// Ends with FIN only after an explicit finish; any other end is an RST, never
/// a FIN that could make a truncated stream look complete.
async fn write_loop(
    id: u32,
    mut write: OwnedWriteHalf,
    mut ops: mpsc::UnboundedReceiver<WriteOp>,
    reset: Arc<Notify>,
    events: mpsc::UnboundedSender<Io>,
) {
    let finished = loop {
        let op = tokio::select! {
            biased;
            _ = reset.notified() => break false,
            op = ops.recv() => op,
        };
        match op {
            Some(WriteOp::Data(data)) => {
                let written = tokio::select! {
                    biased;
                    _ = reset.notified() => break false,
                    written = write.write_all(&data) => written,
                };
                if written.is_err() {
                    let _ = events.send(Io::Failed(id));
                    break false;
                }
                let _ = events.send(Io::Written(id, data.len()));
            }
            Some(WriteOp::Finish) => break write.shutdown().await.is_ok(),
            None => break false,
        }
    };
    if !finished {
        let _ = socket2::SockRef::from(write.as_ref()).set_linger(Some(Duration::ZERO));
        write.forget();
    }
}
