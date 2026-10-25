//! TCP adapters for reliable streams: client listeners and server targets.
//!
//! A fixed stream goes to the server's configured TCP target. An addressed
//! stream comes from a local proxy entrance and names its own destination
//! (see `proxy`). The mux also owns SOCKS5 UDP associations (see `associate`),
//! whose datagrams bypass the stream layer.
//!
//! Each accepted connection is one stream with its own windows and
//! retransmission state, so a stalled transfer never blocks another
//! connection. Stream records share the session's sender queue, paths, pacing
//! and FEC with UDP records. Local backpressure keeps only a short backlog,
//! sized from the measured admission rate, waiting for Quinn admission.
use super::{
    Policy, QueuedRecord, Scope, associate, enqueue_record,
    outbound::Gauge,
    proxy::{self, Destination},
};
use crate::runtime::{
    stream::{self, Frame},
    wire::Record,
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream, UdpSocket,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Notify, Semaphore, mpsc, oneshot, watch},
    task::{AbortHandle, JoinSet},
    time::{sleep_until, timeout},
};
use tracing::{debug, warn};

#[path = "stream_budget.rs"]
mod stream_budget;
pub(crate) use stream_budget::Budget;
use stream_budget::{Credit, Lease};

#[derive(Debug)]
pub(crate) struct OpenError(pub u8);
impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "stream destination refused ({})", self.0)
    }
}
impl std::error::Error for OpenError {}

struct Channel {
    commands: mpsc::Sender<Command>,
    wake: Arc<Notify>,
    closed: AtomicBool,
}
impl Channel {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake.notify_waiters();
        self.wake.notify_one();
    }
}
struct Cancel {
    cancelled: AtomicBool,
    wake: Arc<Notify>,
}
struct CancelGuard(Arc<Cancel>);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.wake.notify_one();
    }
}
enum Command {
    Open {
        target: Destination,
        lease: Arc<Lease>,
        cancel: Arc<Cancel>,
        reply: oneshot::Sender<Result<(u32, SocketAddr), u8>>,
        done: oneshot::Sender<Result<(), String>>,
    },
    Attach(u32, TcpStream),
}
struct ConnectorState {
    budget: Arc<Budget>,
    active: watch::Sender<Option<Arc<Channel>>>,
    stopped: AtomicBool,
    stop: Notify,
}
/// A logical exit's current aggregate session. Existing flows retain their own generation.
#[derive(Clone)]
pub struct Connector(Arc<ConnectorState>);
impl Connector {
    pub(crate) fn new(budget: Arc<Budget>) -> Self {
        let (active, _) = watch::channel(None);
        Self(Arc::new(ConnectorState {
            budget,
            active,
            stopped: AtomicBool::new(false),
            stop: Notify::new(),
        }))
    }
    pub(crate) fn is_closed(&self) -> bool {
        self.0.stopped.load(Ordering::Acquire)
    }
    pub(crate) async fn closed(&self) {
        loop {
            let notified = self.0.stop.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }
    pub(crate) fn close(&self) {
        self.0.stopped.store(true, Ordering::Release);
        if let Some(old) = self.0.active.send_replace(None) {
            old.close();
        }
        self.0.stop.notify_waiters();
    }
    fn register(&self) -> Registration {
        let (commands, receiver) = mpsc::channel(MAX_STREAMS * 2);
        let channel = Arc::new(Channel {
            commands,
            wake: Arc::new(Notify::new()),
            closed: AtomicBool::new(self.is_closed()),
        });
        self.publish_channel(&channel);
        Registration {
            connector: self.clone(),
            channel,
            commands: receiver,
        }
    }
    fn publish_channel(&self, channel: &Arc<Channel>) {
        if let Some(old) = self.0.active.send_replace(Some(channel.clone())) {
            old.close();
        }
        // close() may have run after the channel captured stopped=false but
        // before publication. Retire that channel as well as an older one.
        if self.is_closed() {
            channel.close();
            self.0.active.send_if_modified(|active| {
                if active
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, channel))
                {
                    *active = None;
                    true
                } else {
                    false
                }
            });
        }
    }
    pub(crate) async fn open(&self, target: Destination) -> anyhow::Result<Flow> {
        let mut generation = self.0.active.subscribe();
        let channel = loop {
            anyhow::ensure!(!self.is_closed(), "aggregate connector closed");
            if let Some(channel) = generation.borrow_and_update().clone()
                && !channel.closed.load(Ordering::Acquire)
            {
                break channel;
            }
            generation
                .changed()
                .await
                .map_err(|_| anyhow::anyhow!("aggregate session ended"))?;
        };
        let lease = tokio::select! {
            lease = self.0.budget.flow() => lease,
            _ = generation.changed() => anyhow::bail!("aggregate generation changed during admission"),
        };
        anyhow::ensure!(
            !channel.closed.load(Ordering::Acquire),
            "aggregate generation closed"
        );
        let cancel = Arc::new(Cancel {
            cancelled: AtomicBool::new(false),
            wake: channel.wake.clone(),
        });
        let guard = CancelGuard(cancel.clone());
        let (reply, response) = oneshot::channel();
        let (done, completion) = oneshot::channel();
        channel
            .commands
            .send(Command::Open {
                target,
                lease: lease.clone(),
                cancel,
                reply,
                done,
            })
            .await
            .map_err(|_| anyhow::anyhow!("aggregate generation ended"))?;
        let (id, bound) = response
            .await
            .map_err(|_| anyhow::anyhow!("aggregate open cancelled"))?
            .map_err(OpenError)?;
        Ok(Flow {
            channel,
            id,
            bound,
            completion: Some(completion),
            _cancel: guard,
            _lease: lease,
        })
    }
}
struct Registration {
    connector: Connector,
    channel: Arc<Channel>,
    commands: mpsc::Receiver<Command>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.channel.close();
        self.connector.0.active.send_if_modified(|active| {
            if active
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &self.channel))
            {
                *active = None;
                true
            } else {
                false
            }
        });
    }
}
pub(crate) struct Flow {
    channel: Arc<Channel>,
    id: u32,
    bound: SocketAddr,
    completion: Option<oneshot::Receiver<Result<(), String>>>,
    _cancel: CancelGuard,
    _lease: Arc<Lease>,
}
impl Flow {
    pub(crate) fn bound(&self) -> SocketAddr {
        self.bound
    }
    pub(crate) async fn run(mut self, tcp: TcpStream) -> anyhow::Result<()> {
        // Before Attach succeeds, any failure or cancelled channel send must
        // reset the accepted socket rather than imply a complete empty stream.
        let _ = socket2::SockRef::from(&tcp).set_linger(Some(Duration::ZERO));
        anyhow::ensure!(
            !self.channel.closed.load(Ordering::Acquire),
            "aggregate flow belongs to a retired generation"
        );
        self.channel
            .commands
            .send(Command::Attach(self.id, tcp))
            .await
            .map_err(|_| anyhow::anyhow!("aggregate generation ended"))?;
        self.completion
            .take()
            .expect("flow completion")
            .await
            .map_err(|_| anyhow::anyhow!("aggregate flow ended"))?
            .map_err(anyhow::Error::msg)
    }
}

const MAX_STREAMS: usize = 256;
const MAX_CONTROL: usize = 2 * MAX_STREAMS;
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
/// Stream identifiers with this bit carry a destination header.
const ADDRESSED: u32 = 1 << 28;
/// A stream with at most this much unacknowledged data is latency-bound, not
/// bandwidth-bound: its segments take the earliest path rather than a share
/// of every path.
const INTERACTIVE_BYTES: u64 = 64 * 1024;
/// Association datagrams waiting for the session queue; more are dropped.
const DATAGRAM_QUEUE: usize = 256;

/// Client listeners; the mux exists when either is configured and negotiated.
#[derive(Clone, Default)]
pub(super) struct Listeners {
    pub fixed: Option<Arc<TcpListener>>,
    pub proxy: Option<Arc<TcpListener>>,
}

/// Server destinations; the mux exists when either is configured and negotiated.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Targets {
    pub fixed: Option<SocketAddr>,
    pub proxy: Option<proxy::Access>,
    /// Only standalone legacy entrances use this UDP adapter. Mesh proxies
    /// retain the native proxy association and host-wide DNS/socket budgets.
    pub allow_associations: bool,
}

pub(super) enum Io {
    #[cfg(test)]
    Read(u32, Vec<u8>),
    ReadBudgeted(u32, Vec<u8>, Credit),
    ReadEnd(u32),
    Written(u32, usize),
    Failed(u32),
    Connected(u32, TcpStream),
    /// Server: an addressed stream reached its destination.
    Reached(u32, TcpStream),
    /// Server: an addressed stream's destination failed with this status.
    Refused(u32, u8),
    /// Client: a local proxy handshake completed.
    Proxied(TcpStream, proxy::Request),
    /// Client: a UDP association's relay is bound and answered.
    Associated(u32, Arc<UdpSocket>, associate::Peer),
    /// A datagram for the tunnel: from a SOCKS client, or a server reply.
    Datagram(u32, Vec<u8>),
    DatagramDropped,
    Unassociated(u32),
}

enum Association {
    /// Client: the relay task before its socket is reported.
    Starting(AbortHandle),
    Client {
        socket: Arc<UdpSocket>,
        peer: associate::Peer,
        task: AbortHandle,
    },
    Server {
        datagrams: mpsc::Sender<Vec<u8>>,
        last: Instant,
        task: AbortHandle,
    },
}
impl Association {
    fn task(&self) -> &AbortHandle {
        match self {
            Association::Starting(task)
            | Association::Client { task, .. }
            | Association::Server { task, .. } => task,
        }
    }
}

enum WriteOp {
    Data(Vec<u8>),
    Finish,
}

pub(super) enum Wake {
    Io(Io),
    Accept(io::Result<(TcpStream, SocketAddr)>),
    ProxyAccept(io::Result<(TcpStream, SocketAddr)>),
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
    lease: Arc<Lease>,
    cancel: Option<Arc<Cancel>>,
    open_reply: Option<oneshot::Sender<Result<(u32, SocketAddr), u8>>>,
    completion: Option<oneshot::Sender<Result<(), String>>>,
    status_header: Vec<u8>,
    send: stream::Sender,
    recv: stream::Receiver,
    delivery_blocked_since: Option<Instant>,
    reads: Option<Arc<Semaphore>>,
    granted: u64,
    writer: Option<mpsc::UnboundedSender<WriteOp>>,
    reset_writer: Option<Arc<Notify>>,
    undelivered: Vec<Vec<u8>>,
    write_finished: bool,
    tasks: Vec<AbortHandle>,
    /// Client: the server's status byte has not arrived yet.
    status_pending: bool,
    /// Server: destination header bytes received so far.
    header: Option<Vec<u8>>,
    /// Server: the destination failed; only the status and FIN remain to send.
    refused: bool,
}
impl Stream {
    fn new(open: bool, lease: Arc<Lease>) -> Self {
        Self {
            lease,
            cancel: None,
            open_reply: None,
            completion: None,
            status_header: Vec::new(),
            send: stream::Sender::new(open),
            recv: stream::Receiver::default(),
            delivery_blocked_since: None,
            reads: None,
            granted: 0,
            writer: None,
            reset_writer: None,
            undelivered: Vec::new(),
            write_finished: false,
            tasks: Vec::new(),
            status_pending: false,
            header: None,
            refused: false,
        }
    }
    fn push(&mut self, data: &[u8]) -> bool {
        let Some(credit) = self.lease.tx.try_take(data.len(), true) else {
            return false;
        };
        self.send.push(data);
        self.lease.retain_tx(credit);
        true
    }
    fn complete(&mut self, result: Result<(), String>) {
        if let Some(reply) = self.open_reply.take() {
            let _ = reply.send(Err(proxy::GENERAL_FAILURE));
        }
        if let Some(done) = self.completion.take() {
            let _ = done.send(result);
        }
    }
    fn deliver(&mut self, data: Vec<u8>) {
        if data.is_empty() || self.refused {
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
    budget: Arc<Budget>,
    registration: Option<Registration>,
    listeners: Listeners,
    targets: Targets,
    streams: HashMap<u32, Stream>,
    turns: VecDeque<u32>,
    /// Retired streams; a completed one keeps its final acknowledgment.
    closed: HashMap<u32, (Instant, Option<Vec<u8>>)>,
    closed_order: VecDeque<u32>,
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
    associations: HashMap<u32, Association>,
    next_association: u32,
    datagrams: VecDeque<(u32, Vec<u8>)>,
}

impl Mux {
    fn new(listeners: Listeners, targets: Targets, policy: &Policy, scope: Scope) -> Self {
        let (events_tx, events) = mpsc::unbounded_channel();
        let now = Instant::now();
        Self {
            budget: Arc::new(Budget::default()),
            registration: None,
            listeners,
            targets,
            streams: HashMap::new(),
            turns: VecDeque::new(),
            closed: HashMap::new(),
            closed_order: VecDeque::new(),
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
            associations: HashMap::new(),
            next_association: 0,
            datagrams: VecDeque::new(),
        }
    }
    /// Accepts local connections; the peer connects each stream onward.
    pub(super) fn client(
        listeners: Listeners,
        policy: &Policy,
        scope: Scope,
        connector: Option<Connector>,
    ) -> Option<Self> {
        (listeners.fixed.is_some() || listeners.proxy.is_some() || connector.is_some()).then(|| {
            let mut mux = Self::new(listeners, Targets::default(), policy, scope);
            if let Some(connector) = connector {
                mux.budget = connector.0.budget.clone();
                mux.registration = Some(connector.register());
            }
            mux
        })
    }
    /// Connects peer-opened streams of the kinds this session negotiated.
    pub(super) fn server(
        targets: Targets,
        policy: &Policy,
        scope: Scope,
        budget: Arc<Budget>,
    ) -> Option<Self> {
        let targets = Targets {
            fixed: targets.fixed.filter(|_| policy.streams),
            proxy: targets.proxy.filter(|_| policy.proxy),
            allow_associations: targets.allow_associations && policy.proxy,
        };
        (targets.fixed.is_some() || targets.proxy.is_some()).then(|| {
            let mut mux = Self::new(Listeners::default(), targets, policy, scope);
            mux.budget = budget;
            mux
        })
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

    /// Reserve one bounded local completion per actor turn, even when a
    /// higher-priority network input is continuously ready.
    pub(super) fn service_io(&mut self) {
        self.service_commands();
        if let Ok(event) = self.events.try_recv() {
            self.io(event);
        }
    }

    pub(super) async fn wake(&mut self) -> Wake {
        let now = Instant::now();
        let deadline = tokio::time::Instant::from_std(self.deadline(now));
        let accepting =
            self.streams.len() < MAX_STREAMS && self.accept_paused_until.is_none_or(|at| now >= at);
        let fixed = self.listeners.fixed.clone().filter(|_| accepting);
        let proxy = self.listeners.proxy.clone().filter(|_| accepting);
        let registration = self.registration.as_ref().map(|r| r.channel.clone());
        let queue_waiting = !self.datagrams.is_empty()
            || !self.control.is_empty()
            || self.streams.values().any(|s| s.send.has_transmit());
        tokio::select! {
            biased;
            Some(event) = self.events.recv() => Wake::Io(event),
            _ = async { registration.as_ref().expect("registration").wake.notified().await }, if registration.is_some() => Wake::Queue,
            Some(command) = async { self.registration.as_mut().expect("registration").commands.recv().await }, if registration.is_some() => { self.command(command); Wake::Queue },
            _ = self.gauge.notify.notified(), if queue_waiting => Wake::Queue,
            accepted = async { fixed.as_ref().expect("listener").accept().await }, if fixed.is_some() => Wake::Accept(accepted),
            accepted = async { proxy.as_ref().expect("listener").accept().await }, if proxy.is_some() => Wake::ProxyAccept(accepted),
            _ = sleep_until(deadline) => Wake::Timer,
        }
    }

    fn window(&self) -> u64 {
        (RECEIVE_BUDGET / self.streams.len().max(1) as u64)
            .clamp(stream::INITIAL_WINDOW, stream::MAX_WINDOW)
    }

    fn attach(&mut self, id: u32, tcp: TcpStream) {
        let Some(s) = self.streams.get_mut(&id) else {
            // The stream already reset: close with RST, not FIN.
            let _ = socket2::SockRef::from(&tcp).set_linger(Some(Duration::ZERO));
            return;
        };
        let _ = socket2::SockRef::from(&tcp).set_linger(None);
        let _ = tcp.set_nodelay(true);
        let (read, write) = tcp.into_split();
        let reads = Arc::new(Semaphore::new(0));
        let (writer, ops) = mpsc::unbounded_channel();
        let reset = Arc::new(Notify::new());
        s.tasks.push(self.tasks.spawn(read_loop(
            id,
            read,
            reads.clone(),
            self.events_tx.clone(),
            s.lease.clone(),
        )));
        // Detached so that dropping the mux still lets each writer send its RST.
        tokio::spawn(write_loop(
            id,
            write,
            ops,
            reset.clone(),
            self.events_tx.clone(),
            s.lease.clone(),
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

    fn open(&mut self, id: u32, open: bool) -> bool {
        let Some(lease) = self.budget.try_flow() else {
            return false;
        };
        self.open_lease(id, open, lease);
        true
    }
    fn open_lease(&mut self, id: u32, open: bool, lease: Arc<Lease>) {
        self.streams.insert(id, Stream::new(open, lease));
        self.turns.push_back(id);
        self.stats.opened += 1;
    }
    fn service_commands(&mut self) {
        for _ in 0..MAX_STREAMS * 2 {
            let command = self
                .registration
                .as_mut()
                .and_then(|r| r.commands.try_recv().ok());
            let Some(command) = command else {
                break;
            };
            self.command(command);
        }
        let retired = self
            .registration
            .as_ref()
            .is_some_and(|r| r.channel.closed.load(Ordering::Acquire));
        let cancelled: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, s)| {
                retired
                    || s.cancel
                        .as_ref()
                        .is_some_and(|c| c.cancelled.load(Ordering::Acquire))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in cancelled {
            self.reset(id, "aggregate flow cancelled or generation retired");
        }
    }
    fn command(&mut self, command: Command) {
        match command {
            Command::Open {
                target,
                lease,
                cancel,
                reply,
                done,
            } => {
                if cancel.cancelled.load(Ordering::Acquire)
                    || self
                        .registration
                        .as_ref()
                        .is_none_or(|r| r.channel.closed.load(Ordering::Acquire))
                {
                    return;
                }
                let Some(id) = self.next_id(true) else {
                    let _ = reply.send(Err(proxy::GENERAL_FAILURE));
                    return;
                };
                self.open_lease(id, false, lease);
                let stream = self.streams.get_mut(&id).expect("new stream");
                stream.cancel = Some(cancel);
                stream.open_reply = Some(reply);
                stream.completion = Some(done);
                stream.status_pending = true;
                if !stream.push(&target.encode()) {
                    self.reset(id, "destination header budget exhausted");
                }
            }
            Command::Attach(id, tcp) => {
                let valid = self.streams.get(&id).is_some_and(|s| {
                    !s.status_pending
                        && s.cancel
                            .as_ref()
                            .is_none_or(|c| !c.cancelled.load(Ordering::Acquire))
                }) && self
                    .registration
                    .as_ref()
                    .is_some_and(|r| !r.channel.closed.load(Ordering::Acquire));
                if valid {
                    self.attach(id, tcp);
                } else {
                    let _ = socket2::SockRef::from(&tcp).set_linger(Some(Duration::ZERO));
                }
            }
        }
    }

    fn close(&mut self, id: u32) -> Option<Stream> {
        let s = self.streams.remove(&id)?;
        self.turns.retain(|t| *t != id);
        self.closed_duplicates += s.recv.duplicates();
        let final_ack = s.recv.final_ack().map(|ack| Frame::Ack(ack).encode());
        self.remember_closed(id, Instant::now(), final_ack);
        Some(s)
    }

    /// Refused IDs and completed streams share the same finite replay history.
    fn remember_closed(&mut self, id: u32, now: Instant, final_ack: Option<Vec<u8>>) {
        if !self.closed.contains_key(&id) {
            while self.closed.len() >= MAX_TOMBSTONES || self.closed_order.len() >= MAX_TOMBSTONES {
                let oldest = self
                    .closed_order
                    .pop_front()
                    .expect("closed stream history");
                self.closed.remove(&oldest);
            }
            self.closed_order.push_back(id);
        }
        self.closed.insert(id, (now, final_ack));
    }

    /// Replay responses must remain bounded even while sender admission is full.
    /// Live receive ACKs use their own defer_ack state and are not evicted here.
    fn queue_control(&mut self, flow: u32, payload: Vec<u8>) {
        if self.control.len() >= MAX_CONTROL {
            if let Some((_, pending)) = self
                .control
                .iter_mut()
                .find(|(pending, _)| *pending == flow)
            {
                *pending = payload;
                return;
            }
            self.control.pop_front();
        }
        self.control.push_back((flow, payload));
    }

    fn reset(&mut self, id: u32, reason: &str) {
        if let Some(mut s) = self.close(id) {
            debug!(stream = id, reason, "stream reset");
            s.complete(Err(reason.to_owned()));
            s.abort();
            self.stats.reset_local += 1;
            // Two independent records; the peer also answers stale frames with RESET.
            for _ in 0..2 {
                self.queue_control(stream::data_flow(id), Frame::Reset.encode());
            }
        }
    }

    pub(super) fn handle(&mut self, wake: Wake) {
        self.service_commands();
        match wake {
            Wake::Io(event) => self.io(event),
            Wake::Accept(Ok((tcp, _))) => {
                if let Some(id) = self.next_id(false) {
                    if self.open(id, true) {
                        self.attach(id, tcp);
                    }
                }
            }
            Wake::ProxyAccept(Ok((mut tcp, _))) => {
                let events = self.events_tx.clone();
                self.tasks.spawn(async move {
                    if let Some(request) = proxy::handshake(&mut tcp).await {
                        let _ = events.send(Io::Proxied(tcp, request));
                    }
                });
            }
            Wake::Accept(Err(error)) | Wake::ProxyAccept(Err(error)) => {
                warn!(%error, "TCP accept failed");
                self.accept_paused_until = Some(Instant::now() + Duration::from_millis(100));
            }
            Wake::Queue | Wake::Timer => {}
        }
    }

    fn io(&mut self, event: Io) {
        match event {
            #[cfg(test)]
            Io::Read(id, data) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    self.stats.bytes_from_application += data.len() as u64;
                    if !s.push(&data) {
                        self.reset(id, "TX budget exhausted");
                    }
                }
            }
            Io::ReadBudgeted(id, data, credit) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    self.stats.bytes_from_application += data.len() as u64;
                    s.send.push(&data);
                    s.lease.retain_tx(credit);
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
                    s.lease.release_rx(n);
                }
            }
            Io::Failed(id) => self.reset(id, "local socket failed"),
            Io::Connected(id, tcp) => self.attach(id, tcp),
            Io::Reached(id, tcp) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    let mut response = vec![proxy::OK];
                    match tcp.local_addr() {
                        Ok(bound) => response.extend(Destination::Ip(bound).encode()),
                        Err(_) => {
                            self.reset(id, "destination bound address unavailable");
                            return;
                        }
                    }
                    if !s.push(&response) {
                        self.reset(id, "status header budget exhausted");
                        return;
                    }
                    self.attach(id, tcp);
                }
            }
            Io::Refused(id, status) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    debug!(stream = id, status, "proxy destination refused");
                    s.refused = true;
                    s.undelivered.clear();
                    let _ = s.push(&[status]);
                    s.send.finish();
                    self.stats.rejected += 1;
                }
            }
            Io::Proxied(tcp, request) if request.associate => self.associate(tcp),
            Io::Associated(flow, socket, peer) => {
                if let Some(Association::Starting(task)) = self.associations.remove(&flow) {
                    self.associations
                        .insert(flow, Association::Client { socket, peer, task });
                }
            }
            Io::Datagram(flow, payload) => {
                if let Some(Association::Server { last, .. }) = self.associations.get_mut(&flow) {
                    *last = Instant::now();
                }
                self.queue_datagram(flow, payload);
            }
            Io::DatagramDropped => self.stats.udp_datagrams_dropped += 1,
            Io::Unassociated(flow) => {
                let client = matches!(
                    self.associations.remove(&flow),
                    Some(Association::Client { .. } | Association::Starting(_))
                );
                if client {
                    // Unreliable: two copies; the server also retires it when idle.
                    for _ in 0..2 {
                        self.queue_datagram(flow, Vec::new());
                    }
                }
            }
            Io::Proxied(tcp, request) => {
                if self.streams.len() >= MAX_STREAMS {
                    self.stats.rejected += 1;
                    self.tasks
                        .spawn(refuse(tcp, request.kind, proxy::GENERAL_FAILURE));
                    return;
                }
                let Some(id) = self.next_id(true) else {
                    self.tasks
                        .spawn(refuse(tcp, request.kind, proxy::GENERAL_FAILURE));
                    return;
                };
                if !self.open(id, false) {
                    self.tasks
                        .spawn(refuse(tcp, request.kind, proxy::GENERAL_FAILURE));
                    return;
                }
                let s = self.streams.get_mut(&id).expect("opened");
                if !s.push(&request.destination.encode()) || !s.push(&request.early) {
                    self.reset(id, "proxy header budget exhausted");
                    return;
                }
                self.stats.bytes_from_application += request.early.len() as u64;
                s.status_pending = true;
                // Reply at once, so application data follows the destination
                // header without waiting a tunnel round trip. A refused
                // destination later resets the local connection.
                let events = self.events_tx.clone();
                let owner = s.lease.clone();
                self.tasks.spawn(async move {
                    let _owner = owner;
                    let mut tcp = tcp;
                    // An abort before attach must not look like a clean end.
                    let _ = socket2::SockRef::from(&tcp).set_linger(Some(Duration::ZERO));
                    let _ = events.send(
                        match tcp.write_all(&proxy::reply(request.kind, proxy::OK)).await {
                            Ok(()) => Io::Connected(id, tcp),
                            Err(_) => Io::Failed(id),
                        },
                    );
                });
            }
        }
    }

    /// Client: start a UDP association for a SOCKS5 UDP ASSOCIATE request.
    fn associate(&mut self, tcp: TcpStream) {
        if self.associations.len() >= associate::MAX_ASSOCIATIONS
            || self.next_association + 1 >= associate::FLAG
        {
            self.stats.rejected += 1;
            self.tasks
                .spawn(refuse(tcp, proxy::Kind::Socks, proxy::GENERAL_FAILURE));
            return;
        }
        self.next_association += 1;
        let flow = associate::FLAG | self.next_association;
        let task = self
            .tasks
            .spawn(associate::client(flow, tcp, self.events_tx.clone()));
        self.associations.insert(flow, Association::Starting(task));
        self.stats.udp_associations += 1;
    }

    fn queue_datagram(&mut self, flow: u32, payload: Vec<u8>) {
        if self.datagrams.len() >= DATAGRAM_QUEUE {
            self.stats.udp_datagrams_dropped += 1;
            return;
        }
        self.datagrams.push_back((flow, payload));
    }

    /// An association record from the peer.
    fn datagram(&mut self, record: Record) {
        let flow = record.flow;
        if self.listeners.proxy.is_some() {
            // Client: a reply for the SOCKS client.
            if let Some(Association::Client { socket, peer, .. }) = self.associations.get(&flow)
                && !record.payload.is_empty()
                && let Some(peer) = *peer.lock().expect("association peer")
            {
                self.stats.udp_datagrams_from_tunnel += 1;
                if socket
                    .try_send_to(&associate::to_client(&record.payload), peer)
                    .is_err()
                {
                    self.stats.udp_datagrams_dropped += 1;
                }
            }
            return;
        }
        if !self.targets.allow_associations {
            self.stats.udp_datagrams_dropped += 1;
            return;
        }
        let Some(access) = self.targets.proxy else {
            return;
        };
        if record.payload.is_empty() {
            if let Some(association) = self.associations.remove(&flow) {
                association.task().abort();
            }
            return;
        }
        if !self.associations.contains_key(&flow) {
            if self.associations.len() >= associate::MAX_ASSOCIATIONS {
                self.stats.udp_datagrams_dropped += 1;
                return;
            }
            let (datagrams, receiver) = mpsc::channel(associate::CHANNEL);
            let task = self.tasks.spawn(associate::server(
                flow,
                access.allow_private,
                receiver,
                self.events_tx.clone(),
            ));
            self.associations.insert(
                flow,
                Association::Server {
                    datagrams,
                    last: Instant::now(),
                    task,
                },
            );
            self.stats.udp_associations += 1;
        }
        if let Some(Association::Server {
            datagrams, last, ..
        }) = self.associations.get_mut(&flow)
        {
            *last = Instant::now();
            self.stats.udp_datagrams_from_tunnel += 1;
            if datagrams.try_send(record.payload).is_err() {
                self.stats.udp_datagrams_dropped += 1;
            }
        }
    }

    /// Client stream identifiers; addressed streams set `ADDRESSED`.
    fn next_id(&mut self, addressed: bool) -> Option<u32> {
        if self.next_stream + 1 >= associate::FLAG {
            warn!("stream identifiers exhausted; refusing local connection");
            self.stats.rejected += 1;
            return None;
        }
        self.next_stream += 1;
        Some(self.next_stream | if addressed { ADDRESSED } else { 0 })
    }

    /// Open a peer-initiated stream if this session accepts its kind.
    fn accept_stream(&mut self, id: u32, now: Instant) -> bool {
        let addressed = id & ADDRESSED != 0;
        let accepted = if addressed {
            self.targets.proxy.is_some()
        } else {
            self.targets.fixed.is_some()
        };
        if let Some((_, Some(ack))) = self.closed.get(&id) {
            // The peer missed the final acknowledgment of a completed stream.
            let ack = ack.clone();
            self.queue_control(stream::ack_flow(id), ack);
            self.stats.acks_sent += 1;
            return false;
        }
        if !accepted || self.closed.contains_key(&id) {
            // Stale, unnegotiated, or peer-opened toward a client.
            self.queue_control(stream::data_flow(id), Frame::Reset.encode());
            return false;
        }
        if self.streams.len() >= MAX_STREAMS {
            self.stats.rejected += 1;
            self.remember_closed(id, now, None);
            self.queue_control(stream::data_flow(id), Frame::Reset.encode());
            return false;
        }
        if !self.open(id, false) {
            self.queue_control(stream::data_flow(id), Frame::Reset.encode());
            return false;
        }
        let s = self.streams.get_mut(&id).expect("opened");
        match self.targets.fixed.filter(|_| !addressed) {
            Some(target) => {
                let events = self.events_tx.clone();
                let owner = s.lease.clone();
                s.tasks.push(self.tasks.spawn(async move {
                    let _owner = owner;
                    match timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await {
                        Ok(Ok(tcp)) => {
                            let _ = events.send(Io::Connected(id, tcp));
                        }
                        _ => {
                            let _ = events.send(Io::Failed(id));
                        }
                    }
                }));
            }
            None => s.header = Some(Vec::new()),
        }
        true
    }

    /// Handle in-order bytes: destination headers and status bytes first.
    fn arrived(&mut self, id: u32, mut ready: Vec<u8>) {
        let window = self.window();
        let allow_private = self.targets.proxy.is_some_and(|p| p.allow_private);
        let Some(s) = self.streams.get_mut(&id) else {
            return;
        };
        if let Some(header) = &mut s.header {
            header.append(&mut ready);
            match Destination::decode(header) {
                Ok(None) if s.recv.fin_received() => {
                    return self.reset(id, "incomplete destination");
                }
                Ok(None) => return,
                Err(()) => return self.reset(id, "malformed destination"),
                Ok(Some((destination, used))) => {
                    let mut header = s.header.take().expect("header");
                    ready = header.split_off(used);
                    s.recv.consumed(used as u64, window);
                    s.lease.release_rx(used);
                    let events = self.events_tx.clone();
                    let owner = s.lease.clone();
                    s.tasks.push(self.tasks.spawn(async move {
                        let _owner = owner;
                        let _ =
                            events.send(match proxy::connect(destination, allow_private).await {
                                Ok(tcp) => Io::Reached(id, tcp),
                                Err(status) => Io::Refused(id, status),
                            });
                    }));
                }
            }
        }
        if s.status_pending {
            s.status_header.append(&mut ready);
            let Some(&status) = s.status_header.first() else {
                if s.recv.fin_received() {
                    self.reset(id, "missing destination status");
                }
                return;
            };
            if status != proxy::OK {
                if let Some(reply) = s.open_reply.take() {
                    let _ = reply.send(Err(status));
                }
                self.reset(id, "proxy destination refused");
                return;
            }
            match Destination::decode(&s.status_header[1..]) {
                Ok(Some((Destination::Ip(bound), used))) => {
                    let used = used + 1;
                    ready = s.status_header.split_off(used);
                    s.status_header.clear();
                    s.status_pending = false;
                    s.recv.consumed(used as u64, window);
                    s.lease.release_rx(used);
                    if let Some(reply) = s.open_reply.take() {
                        let _ = reply.send(Ok((id, bound)));
                    }
                }
                Ok(None)
                    if !s.recv.fin_received() && s.status_header.len() <= proxy::MAX_HEADER + 1 =>
                {
                    return;
                }
                _ => {
                    self.reset(id, "malformed destination bound address");
                    return;
                }
            }
        }
        s.deliver(ready);
        s.finish_writes();
    }

    fn admissions(&mut self) {
        for sent in self.gauge.take_sent() {
            let (id, start, transmission) = sent.identity;
            if let Some(s) = self.streams.get_mut(&id) {
                s.send
                    .admitted(start, transmission, sent.path, sent.rtt, sent.at);
            }
        }
    }

    /// Apply one stream record. Call `flush` after a batch of records.
    pub(super) fn receive(&mut self, record: Record) {
        // Admission metadata must arrive before an ACK samples the segment.
        self.admissions();
        if associate::is_flow(record.flow) {
            return self.datagram(record);
        }
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
                    s.complete(Err("peer reset stream".to_owned()));
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
                    Some((released, spurious)) => {
                        s.lease.release_tx(released as usize);
                        self.stats.spurious_retransmit_reports += u64::from(spurious);
                        s.grant_reads();
                    }
                    None => self.reset(id, "invalid acknowledgment"),
                }
            }
            Frame::Data { offset, fin, data } => {
                if !self.streams.contains_key(&id) && !self.accept_stream(id, now) {
                    return;
                }
                let s = self.streams.get_mut(&id).expect("stream");
                let additional = s.recv.additional_bytes(offset, data.len());
                let progress = offset <= s.recv.cumulative()
                    && offset + data.len() as u64 > s.recv.cumulative();
                let Some(credit) = s.lease.rx.try_take(additional, progress) else {
                    return;
                };
                match s.recv.on_data(offset, fin, data, now) {
                    Ok(ready) => {
                        if tracing::enabled!(tracing::Level::DEBUG) {
                            if !ready.is_empty()
                                && let Some(started) = s.delivery_blocked_since.take()
                                && now.saturating_duration_since(started)
                                    >= Duration::from_millis(20)
                            {
                                debug!(stream=id, blocked_ms=now.saturating_duration_since(started).as_secs_f64()*1000.0,
                                    released_bytes=ready.len(), receive=?s.recv.receive_diagnostics(),
                                    "stream receive hole released");
                            }
                            if s.recv.receive_diagnostics().2 > 0 {
                                s.delivery_blocked_since.get_or_insert(now);
                            }
                        }
                        s.lease.retain_rx(credit);
                        self.arrived(id, ready);
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
        self.service_commands();
        let now = Instant::now();
        self.admissions();
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
                failed.push((*id, "peer stopped acknowledging"));
            } else if s.refused && s.send.finished() {
                failed.push((*id, "proxy destination refused"));
            } else if s.send.finished() && s.recv.finished() && s.write_finished {
                done.push(*id);
            }
        }
        for (id, reason) in failed {
            self.reset(id, reason);
        }
        let window = self.window();
        for id in done {
            // The peer's FIN may have arrived in this batch: acknowledge it
            // before the stream retires, or the peer retransmits it.
            if let Some(ack) = self
                .streams
                .get_mut(&id)
                .and_then(|s| s.recv.take_ack(now, window))
            {
                self.queue_control(stream::ack_flow(id), Frame::Ack(ack).encode());
                self.stats.acks_sent += 1;
            }
            // The writer finishes its own shutdown; the reader already ended.
            if let Some(mut stream) = self.close(id) {
                stream.complete(Ok(()));
                self.stats.completed += 1;
            }
        }
        // Live progress and window ACKs get the next available slot even if
        // a peer continuously replenishes rejected-ID replay responses.
        for (id, s) in &mut self.streams {
            if let Some(ack) = s.recv.take_ack(now, window) {
                if out.enqueue(stream::ack_flow(*id), Frame::Ack(ack).encode(), None) {
                    self.stats.acks_sent += 1;
                } else {
                    s.recv.defer_ack();
                }
            }
        }
        while let Some((flow, payload)) = self.control.pop_front() {
            if !out.enqueue(flow, payload.clone(), None) {
                self.control.push_front((flow, payload));
                break;
            }
        }
        while let Some((flow, payload)) = self.datagrams.pop_front() {
            if !out.enqueue(flow, payload.clone(), None) {
                self.datagrams.push_front((flow, payload));
                break;
            }
            if !payload.is_empty() {
                self.stats.udp_datagrams_to_tunnel += 1;
            }
        }
        self.associations
            .retain(|_, association| match association {
                Association::Server { last, task, .. }
                    if now.saturating_duration_since(*last) >= associate::IDLE =>
                {
                    task.abort();
                    false
                }
                _ => true,
            });
        self.pump(out, now);
        // Finished tasks stay in the set until reaped.
        while self.tasks.try_join_next().is_some() {}
        self.closed
            .retain(|_, (at, _)| now.saturating_duration_since(*at) < TOMBSTONE);
        self.closed_order.retain(|id| self.closed.contains_key(id));
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
        // A bulk-filled admission watermark must not hide a tiny request
        // before it reaches the sender's existing per-flow fair queue. The
        // reserve is at most two maximum segments plus one tiny frame;
        // bulk keeps the original limit and all wire budgets remain shared.
        while self.gauge.queued() < limit + 2 * stream::MAX_SEGMENT && idle < self.turns.len() {
            let id = self.turns.pop_front().expect("turn");
            self.turns.push_back(id);
            let s = self.streams.get_mut(&id).expect("stream turn");
            if self.gauge.queued() >= limit && s.send.written() - s.send.retained_from() > 128 {
                idle += 1;
                continue;
            }
            let Some(t) = s.send.poll_transmit(now) else {
                idle += 1;
                continue;
            };
            idle = 0;
            let payload = t.frame.encode();
            let interactive = s.send.written() - s.send.retained_from() <= INTERACTIVE_BYTES;
            let hold = (t.transmission > 0).then(|| {
                self.gauge
                    .hold(id, t.start, t.transmission, payload.len(), interactive)
            });
            if !out.enqueue(stream::data_flow(id), payload, hold) {
                // The unadmitted hold reports this transmission as dropped.
                self.blocked_until = Some(now + RETRY_FULL);
                break;
            }
            self.stats.segments_sent += 1;
            self.stats.tail_probes_queued += u64::from(t.tail_probe);
            self.stats.head_copies_queued += u64::from(t.head_copy);
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
        self.stats.pending_io_events = self.events.len() as u64;
        self.stats.local_sender_queued_bytes = self.gauge.queued() as u64;
        self.stats.duplicate_bytes_received = self.closed_duplicates
            + self
                .streams
                .values()
                .map(|s| s.recv.duplicates())
                .sum::<u64>();
        let snapshot = self.stats.clone();
        self.scope.update(|d| {
            d.tcp_streams = Some(snapshot.clone());
            // Automatic FEC snapshots belong only to the session, not the
            // aggregate scope also visited by update(). Log that scope once.
            if tracing::enabled!(tracing::Level::DEBUG)
                && let Some(fec) = &d.automatic_fec
            {
                debug!(fec=?fec,
                    original_bytes=d.symbols.originals_quinn_admitted_bytes,
                    repair_bytes=d.symbols.repairs_quinn_admitted_bytes,
                    originals_expired=d.symbols.originals_expired_dropped,
                    originals_ingress_expired=d.symbols.originals_ingress_expired_dropped,
                    originals_queue_dropped=d.symbols.originals_queue_full_dropped,
                    "stream sender coding progress");
            }
        });
        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(stats=?self.stats, budget=?self.budget.pressure(), "stream mux progress");
            for (id, s) in &self.streams {
                debug!(
                    stream = id,
                    written = s.send.written(),
                    retained_from = s.send.retained_from(),
                    peer_limit = s.send.limit(),
                    send_finished = s.send.finished(),
                    receive_finished = s.recv.finished(),
                    writer_finished = s.write_finished,
                    pending_io = self.events.len(),
                    local_queued_bytes = self.gauge.queued(),
                    recovery = ?s.send.recovery_state(),
                    recovery_detail = ?s.send.recovery_diagnostics(now),
                    receive = ?s.recv.receive_diagnostics(),
                    next_deadline_ms = ?s.send.next_deadline(now).map(|at| at.saturating_duration_since(now).as_millis()),
                    "stream progress"
                );
            }
        }
    }

    pub(super) fn close_all(&mut self) {
        for (_, association) in self.associations.drain() {
            association.task().abort();
        }
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            if let Some(mut s) = self.close(id) {
                s.complete(Err("aggregate session ended".to_owned()));
                s.abort();
                self.stats.reset_local += 1;
            }
        }
        self.registration.take();
        self.publish(Instant::now());
        self.tasks.abort_all();
        while self.events.try_recv().is_ok() {}
    }
}
impl Drop for Mux {
    fn drop(&mut self) {
        self.close_all();
    }
}

/// Answer a local proxy client that cannot be connected, then close.
async fn refuse(mut tcp: TcpStream, kind: proxy::Kind, status: u8) {
    if tcp.write_all(&proxy::reply(kind, status)).await.is_ok() {
        let _ = tcp.shutdown().await;
    }
}

async fn read_loop(
    id: u32,
    read: OwnedReadHalf,
    reads: Arc<Semaphore>,
    events: mpsc::UnboundedSender<Io>,
    lease: Arc<Lease>,
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
        // Idle sockets keep their flow slot, never shared data credit. A
        // readiness false positive returns both credits before waiting again.
        if read.readable().await.is_err() {
            let _ = events.send(Io::Failed(id));
            return;
        }
        let mut credit = lease.tx.take(capacity).await;
        match read.try_read(&mut buffer[..capacity]) {
            Ok(0) => {
                let _ = events.send(Io::ReadEnd(id));
                return;
            }
            Ok(n) => {
                reads.add_permits(capacity - n);
                credit.truncate(n);
                if let Some(rate) = &lease.rate {
                    rate.acquire(n).await;
                }
                if events
                    .send(Io::ReadBudgeted(id, buffer[..n].to_vec(), credit))
                    .is_err()
                {
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                reads.add_permits(capacity);
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
    lease: Arc<Lease>,
) {
    let finished = loop {
        let op = tokio::select! {
            biased;
            _ = reset.notified() => break false,
            op = ops.recv() => op,
        };
        match op {
            Some(WriteOp::Data(data)) => {
                let started = tracing::enabled!(tracing::Level::DEBUG).then(Instant::now);
                let written = tokio::select! {
                    biased;
                    _ = reset.notified() => break false,
                    written = write_payload(id, &mut write, &data, &lease, &events) => written,
                };
                if written.is_err() {
                    let _ = events.send(Io::Failed(id));
                    break false;
                }
                if let Some(started) = started
                    && started.elapsed() >= Duration::from_millis(20)
                {
                    debug!(
                        stream = id,
                        blocked_ms = started.elapsed().as_secs_f64() * 1000.0,
                        bytes = data.len(),
                        rate_limited = lease.rate.is_some(),
                        "stream local write delayed"
                    );
                }
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

async fn write_payload<W: tokio::io::AsyncWrite + Unpin>(
    id: u32,
    write: &mut W,
    data: &[u8],
    lease: &Lease,
    events: &mpsc::UnboundedSender<Io>,
) -> io::Result<()> {
    // Filling a receive hole can release a contiguous block larger than the
    // host rate bucket's maximum burst. A whole-block request could never be
    // granted; bounded chunks also release receive credit as writes progress.
    for chunk in data.chunks(READ_CHUNK) {
        if let Some(rate) = &lease.rate {
            rate.acquire(chunk.len()).await;
        }
        write.write_all(chunk).await?;
        events
            .send(Io::Written(id, chunk.len()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stream mux ended"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{MAX_PATHS, stats};

    fn proxy_policy() -> Policy {
        Policy {
            max_message_bytes: 1000,
            streams: false,
            proxy: true,
            adaptive: false,
            capacity_probe_bps: 0,
            probe_guided_recovery: false,
            latency_target_ms: 20,
            group_rates: [10_000_000; MAX_PATHS],
            receiver_feedback: true,
            quality_schedule: false,
            fec: 0,
            fec_repairs: 1,
            small_fec_bytes: 0,
            mixed_fec: false,
            redundancy: 0,
            rate: 10_000_000,
            block_ms: 25,
            queue_ms: 100,
        }
    }

    #[tokio::test]
    async fn oversized_peer_window_resets_the_flow_without_overflowing_read_credit() {
        let policy = proxy_policy();
        let metrics = stats::Metrics::new("client");
        let mut mux = Mux::new(
            Listeners::default(),
            Targets::default(),
            &policy,
            metrics.scope("bad-window", stats::FORWARD),
        );
        assert!(mux.open(1, false));
        mux.streams.get_mut(&1).unwrap().reads = Some(Arc::new(Semaphore::new(0)));
        mux.receive(Record {
            flow: stream::ack_flow(1),
            id: 1,
            payload: Frame::Ack(stream::Ack {
                limit: u64::MAX,
                ..Default::default()
            })
            .encode(),
        });
        assert!(mux.streams.is_empty());
        assert_eq!(mux.stats.reset_local, 1);
        assert_eq!(mux.budget.snapshot(), (0, 0));
    }

    #[tokio::test]
    async fn a_failed_flow_attach_resets_the_accepted_socket() {
        for pre_closed in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (client, peer) = tokio::join!(
                TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept()
            );
            let tcp = client.unwrap();
            let (mut peer, _) = peer.unwrap();
            let (commands, receiver) = mpsc::channel(1);
            drop(receiver);
            let channel = Arc::new(Channel {
                commands,
                wake: Arc::new(Notify::new()),
                closed: AtomicBool::new(pre_closed),
            });
            let budget = Arc::new(Budget::default());
            let lease = budget.flow().await;
            let flow = Flow {
                channel: channel.clone(),
                id: 1,
                bound: "0.0.0.0:0".parse().unwrap(),
                completion: None,
                _cancel: CancelGuard(Arc::new(Cancel {
                    cancelled: AtomicBool::new(false),
                    wake: channel.wake.clone(),
                })),
                _lease: lease,
            };
            assert!(flow.run(tcp).await.is_err());
            let error = timeout(Duration::from_secs(1), peer.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            assert_eq!(budget.snapshot(), (0, 0));
        }
    }

    #[test]
    fn connector_registration_rechecks_a_close_between_creation_and_publication() {
        for close_before_publish in [true, false] {
            let connector = Connector::new(Arc::new(Budget::default()));
            // The channel captured stopped=false, before the competing close.
            let (commands, _receiver) = mpsc::channel(1);
            let channel = Arc::new(Channel {
                commands,
                wake: Arc::new(Notify::new()),
                closed: AtomicBool::new(false),
            });
            if close_before_publish {
                connector.close();
            }
            connector.publish_channel(&channel);
            if !close_before_publish {
                connector.close();
            }
            assert!(connector.is_closed());
            assert!(channel.closed.load(Ordering::Acquire));
            assert!(connector.0.active.borrow().is_none());
        }
    }

    #[tokio::test]
    async fn production_aggregate_rejects_legacy_udp_associations_before_socket_or_dns_work() {
        let policy = proxy_policy();
        let metrics = stats::Metrics::new("server");
        let budget = Arc::new(Budget::default());
        let mut mux = Mux::server(
            Targets {
                fixed: None,
                proxy: Some(proxy::Access {
                    allow_private: true,
                }),
                allow_associations: false,
            },
            &policy,
            metrics.scope("no-legacy-udp", stats::RETURN),
            budget.clone(),
        )
        .unwrap();
        let mut payload = Destination::Ip("127.0.0.1:9".parse().unwrap()).encode();
        payload.push(7);
        for id in 1..=128 {
            mux.receive(Record {
                flow: associate::FLAG | id,
                id: u64::from(id),
                payload: payload.clone(),
            });
        }
        assert!(mux.associations.is_empty());
        assert!(mux.tasks.is_empty());
        assert_eq!(mux.stats.udp_associations, 0);
        assert_eq!(mux.stats.udp_datagrams_dropped, 128);
        assert_eq!(budget.snapshot(), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn reassembled_write_larger_than_rate_burst_makes_bounded_progress() {
        use tokio::io::AsyncReadExt;

        let budget = Budget::with_rate(Arc::new(crate::runtime::proxy::Rate::new(64_000)));
        let lease = budget.try_flow().unwrap();
        let size = READ_CHUNK * 3;
        let (mut writer, mut reader) = tokio::io::duplex(size);
        let (events, mut received) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            write_payload(1, &mut writer, &vec![7; size], &lease, &events)
                .await
                .unwrap();
        });
        // The minimum burst grants two chunks. The reassembled block is larger
        // than that burst, so the third chunk must wait for newly earned credit.
        for _ in 0..2 {
            let event = timeout(Duration::from_secs(1), received.recv())
                .await
                .expect("initial bounded writes stalled")
                .unwrap();
            assert!(matches!(event, Io::Written(1, READ_CHUNK)));
        }
        assert!(!task.is_finished());
        assert!(received.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(9)).await;
        timeout(Duration::from_secs(1), task)
            .await
            .expect("a block larger than the burst never completed")
            .unwrap();
        assert!(matches!(
            received.recv().await,
            Some(Io::Written(1, READ_CHUNK))
        ));
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, vec![7; size]);
        assert_eq!(budget.snapshot(), (0, 0));
    }

    #[test]
    fn addressed_stream_ids_survive_data_and_ack_flow_tags() {
        for id in [1, ADDRESSED | 1, ADDRESSED | (associate::FLAG - 1)] {
            let data = stream::data_flow(id);
            let ack = stream::ack_flow(id);
            assert_eq!(stream::stream_id(data), Some(id));
            assert_eq!(stream::stream_id(ack), Some(id));
            assert_eq!(stream::stream_id(data).unwrap() & ADDRESSED, id & ADDRESSED);
            assert_eq!(stream::stream_id(ack).unwrap() & ADDRESSED, id & ADDRESSED);
            assert!(!stream::is_ack_flow(data));
            assert!(stream::is_ack_flow(ack));
            assert!(!associate::is_flow(data));
            assert!(!associate::is_flow(ack));
        }
    }

    fn budget_mux(budget: Arc<Budget>) -> Mux {
        let metrics = stats::Metrics::new("budget-test");
        let mut mux = Mux::new(
            Listeners::default(),
            Targets::default(),
            &test_policy(),
            metrics.scope("budget", stats::FORWARD),
        );
        mux.budget = budget;
        mux
    }
    fn test_policy() -> Policy {
        crate::runtime::mesh::tests::policy()
    }
    fn incoming(id: u32, frame: Frame) -> Record {
        Record {
            flow: stream::data_flow(id),
            id: 1,
            payload: frame.encode(),
        }
    }

    #[test]
    fn host_rx_pressure_drops_unaccepted_ranges_but_admits_the_cumulative_hole() {
        let budget = Arc::new(Budget::default());
        let mut blocked = budget_mux(budget.clone());
        let mut recovering = budget_mux(budget.clone());
        assert!(blocked.open(1, false));
        assert!(recovering.open(2, false));
        recovering.receive(incoming(
            2,
            Frame::Data {
                offset: 10,
                fin: false,
                data: vec![1; 10],
            },
        ));
        let lease = &blocked.streams[&1].lease;
        lease.retain_rx(lease.rx.try_take(32 * 1024 * 1024 - 10, false).unwrap());
        recovering.receive(incoming(
            2,
            Frame::Data {
                offset: 20,
                fin: false,
                data: vec![1; 10],
            },
        ));
        assert_eq!(
            recovering.streams[&2].recv.additional_bytes(20, 10),
            10,
            "dropped data must not enter SACK state"
        );
        recovering.receive(incoming(
            2,
            Frame::Data {
                offset: 0,
                fin: false,
                data: vec![1; 10],
            },
        ));
        assert_eq!(recovering.streams[&2].recv.cumulative(), 20);
        assert_eq!(budget.snapshot().1, 32 * 1024 * 1024 + 10);
        recovering.receive(incoming(
            2,
            Frame::Data {
                offset: 0,
                fin: false,
                data: vec![1; 20],
            },
        ));
        assert_eq!(
            budget.snapshot().1,
            32 * 1024 * 1024 + 10,
            "duplicate bytes have no second charge"
        );
        recovering.io(Io::Written(2, 20));
        assert_eq!(budget.snapshot().1, 32 * 1024 * 1024 - 10);
        drop(recovering);
        drop(blocked);
        assert_eq!(budget.snapshot(), (0, 0));
    }

    #[test]
    fn refused_id_flood_stays_bounded_and_live_ack_resumes_after_output_pressure() {
        let budget = Arc::new(Budget::default());
        let mut mux = budget_mux(budget.clone());
        mux.targets.fixed = Some("127.0.0.1:1".parse().unwrap());
        for id in 1..=MAX_STREAMS as u32 {
            assert!(mux.open(id, false));
        }
        mux.receive(incoming(
            1,
            Frame::Data {
                offset: 0,
                fin: true,
                data: vec![9],
            },
        ));
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(QueuedRecord {
            record: Record {
                flow: 0,
                id: 0,
                payload: Vec::new(),
            },
            created: Instant::now(),
            hold: None,
        })
        .unwrap();
        let scope = mux.scope.clone();
        let mut next_id = 0;
        let first = MAX_STREAMS as u32 + 1;
        let last = first + MAX_TOMBSTONES as u32 + MAX_CONTROL as u32;
        for id in first..=last {
            assert!(!mux.accept_stream(id, Instant::now()));
        }
        for _ in 0..MAX_TOMBSTONES {
            assert!(!mux.accept_stream(last, Instant::now()));
        }
        assert!(
            !mux.closed.contains_key(&first),
            "old rejected IDs must be evicted"
        );
        assert!(
            mux.closed.contains_key(&last),
            "recent rejected IDs retain their replay boundary"
        );
        assert_eq!(mux.closed.len(), MAX_TOMBSTONES);
        assert_eq!(mux.closed_order.len(), MAX_TOMBSTONES);
        assert!(mux.control.len() <= MAX_CONTROL);
        mux.flush(&mut Out {
            tx: &tx,
            next_id: &mut next_id,
            scope: &scope,
            small_threshold: 0,
        });
        assert!(
            mux.streams[&1].recv.ack_pending(Instant::now()),
            "a full sender must defer the live ACK"
        );
        rx.try_recv().unwrap();
        let mut acknowledged = false;
        for turn in 0..=MAX_CONTROL {
            assert!(!mux.accept_stream(last + turn as u32 + 1, Instant::now()));
            mux.flush(&mut Out {
                tx: &tx,
                next_id: &mut next_id,
                scope: &scope,
                small_threshold: 0,
            });
            while let Ok(item) = rx.try_recv() {
                if stream::is_ack_flow(item.record.flow)
                    && stream::stream_id(item.record.flow) == Some(1)
                {
                    let Some(Frame::Ack(ack)) = Frame::decode(&item.record.payload) else {
                        panic!("expected live stream ACK");
                    };
                    assert_eq!(ack.cumulative, 2);
                    acknowledged = true;
                }
            }
            if acknowledged {
                break;
            }
        }
        assert!(
            acknowledged,
            "continuous rejected-ID traffic cannot steal every slot from the active flow's ACK"
        );
        assert!(mux.streams.contains_key(&1));
        drop(mux);
        assert_eq!(budget.snapshot(), (0, 0));
    }

    #[test]
    fn repeated_and_expired_closed_ids_do_not_accumulate_fifo_entries() {
        let mut mux = budget_mux(Arc::new(Budget::default()));
        let now = Instant::now();
        for id in 0..MAX_TOMBSTONES as u32 {
            mux.remember_closed(id, now, None);
        }
        for _ in 0..MAX_TOMBSTONES * 2 {
            mux.remember_closed(7, now, None);
        }
        assert_eq!(mux.closed_order.len(), mux.closed.len());
        let expired = now - TOMBSTONE - Duration::from_secs(1);
        for id in 0..MAX_TOMBSTONES as u32 {
            mux.remember_closed(id, expired, None);
        }
        let (tx, _rx) = mpsc::channel(1);
        let scope = mux.scope.clone();
        let mut next_id = 0;
        mux.flush(&mut Out {
            tx: &tx,
            next_id: &mut next_id,
            scope: &scope,
            small_threshold: 0,
        });
        assert!(mux.closed.is_empty());
        assert!(mux.closed_order.is_empty());
        for id in 10_000..10_000 + MAX_TOMBSTONES as u32 * 2 {
            mux.remember_closed(id, now, None);
        }
        assert!(!mux.closed.contains_key(&10_000));
        assert!(
            mux.closed
                .contains_key(&(10_000 + MAX_TOMBSTONES as u32 * 2 - 1))
        );
        assert_eq!(mux.closed_order.len(), MAX_TOMBSTONES);
    }

    #[test]
    fn cumulative_ack_releases_tx_credit_and_duplicate_ack_does_not_release_more() {
        let budget = Arc::new(Budget::default());
        let mut mux = budget_mux(budget.clone());
        assert!(mux.open(1, false));
        assert!(mux.streams.get_mut(&1).unwrap().push(&vec![1; 1000]));
        let now = Instant::now();
        while mux
            .streams
            .get_mut(&1)
            .unwrap()
            .send
            .poll_transmit(now)
            .is_some()
        {}
        for (cumulative, retained) in [(990, 10), (990, 10), (1000, 0)] {
            mux.receive(incoming(
                1,
                Frame::Ack(stream::Ack {
                    cumulative,
                    limit: stream::INITIAL_WINDOW,
                    duplicate_bytes: 0,
                    ranges: Vec::new(),
                }),
            ));
            assert_eq!(budget.snapshot(), (1, retained));
        }
        drop(mux);
        assert_eq!(budget.snapshot(), (0, 0));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_open_reclaims_credit_even_when_the_command_queue_is_full() {
        let budget = Arc::new(Budget::default());
        let connector = Connector::new(budget.clone());
        let metrics = stats::Metrics::new("cancel-test");
        let mut mux = Mux::client(
            Listeners::default(),
            &test_policy(),
            metrics.scope("cancel", stats::FORWARD),
            Some(connector.clone()),
        )
        .unwrap();
        let target = Destination::Ip("127.0.0.1:1".parse().unwrap());
        let clone = connector.clone();
        let request = tokio::spawn(async move { clone.open(target).await });
        while budget.snapshot().0 == 0 {
            tokio::task::yield_now().await;
        }
        let filler = budget.try_flow().unwrap();
        let channel = mux.registration.as_ref().unwrap().channel.clone();
        while channel.commands.capacity() > 0 {
            let (reply, _) = oneshot::channel();
            let (done, _) = oneshot::channel();
            channel
                .commands
                .try_send(Command::Open {
                    target: Destination::Ip("127.0.0.1:1".parse().unwrap()),
                    lease: filler.clone(),
                    cancel: Arc::new(Cancel {
                        cancelled: AtomicBool::new(true),
                        wake: channel.wake.clone(),
                    }),
                    reply,
                    done,
                })
                .ok()
                .unwrap();
        }
        request.abort();
        assert!(
            request
                .await
                .err()
                .expect("cancelled open task")
                .is_cancelled()
        );
        mux.service_commands();
        drop(filler);
        assert!(mux.streams.is_empty());
        assert_eq!(budget.snapshot(), (0, 0));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn addressed_status_preserves_bound_and_application_tail_and_old_generations_close() {
        let budget = Arc::new(Budget::default());
        let connector = Connector::new(budget.clone());
        let metrics = stats::Metrics::new("generation-test");
        let mut mux = Mux::client(
            Listeners::default(),
            &test_policy(),
            metrics.scope("old", stats::FORWARD),
            Some(connector.clone()),
        )
        .unwrap();
        let clone = connector.clone();
        let request = tokio::spawn(async move {
            clone
                .open(Destination::Ip("127.0.0.1:1".parse().unwrap()))
                .await
        });
        while budget.snapshot().0 == 0 {
            tokio::task::yield_now().await;
        }
        mux.service_commands();
        let id = *mux.streams.keys().next().unwrap();
        let bound: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut response = vec![proxy::OK];
        response.extend(Destination::Ip(bound).encode());
        response.extend(b"payload");
        mux.receive(incoming(
            id,
            Frame::Data {
                offset: 0,
                fin: false,
                data: response,
            },
        ));
        let flow = request.await.unwrap().unwrap();
        assert_eq!(flow.bound(), bound);
        assert_eq!(mux.streams[&id].undelivered.concat(), b"payload");
        let new_mux = Mux::client(
            Listeners::default(),
            &test_policy(),
            metrics.scope("new", stats::FORWARD),
            Some(connector.clone()),
        )
        .unwrap();
        assert!(flow.channel.closed.load(Ordering::Acquire));
        drop(flow);
        mux.service_commands();
        assert!(mux.streams.is_empty());
        assert!(new_mux.streams.is_empty());
        drop(mux);
        drop(new_mux);
        assert_eq!(budget.snapshot(), (0, 0));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refused_addressed_open_preserves_the_remote_socks_status() {
        let budget = Arc::new(Budget::default());
        let connector = Connector::new(budget.clone());
        let metrics = stats::Metrics::new("refused-test");
        let mut mux = Mux::client(
            Listeners::default(),
            &test_policy(),
            metrics.scope("refused", stats::FORWARD),
            Some(connector.clone()),
        )
        .unwrap();
        let request = tokio::spawn(async move {
            connector
                .open(Destination::Ip("127.0.0.1:1".parse().unwrap()))
                .await
        });
        while budget.snapshot().0 == 0 {
            tokio::task::yield_now().await;
        }
        mux.service_commands();
        let id = *mux.streams.keys().next().unwrap();
        mux.receive(incoming(
            id,
            Frame::Data {
                offset: 0,
                fin: true,
                data: vec![proxy::REFUSED],
            },
        ));
        let error = request.await.unwrap().err().expect("refused destination");
        assert_eq!(error.downcast_ref::<OpenError>().unwrap().0, proxy::REFUSED);
        assert!(mux.streams.is_empty());
        drop(mux);
        assert_eq!(budget.snapshot(), (0, 0));
    }

    #[test]
    fn a_half_closed_sender_does_not_release_unwritten_receive_credit() {
        let budget = Budget::default();
        let lease = budget.try_flow().unwrap();
        let now = Instant::now();
        let mut send = stream::Sender::new(false);
        let mut recv = stream::Receiver::default();
        lease.retain_tx(lease.tx.try_take(3, true).unwrap());
        send.push(b"out");
        send.finish();
        let sent = send.poll_transmit(now).unwrap();
        assert!(matches!(sent.frame, Frame::Data { fin: true, .. }));
        lease.retain_rx(lease.rx.try_take(4, true).unwrap());
        assert_eq!(
            recv.on_data(0, true, b"back".to_vec(), now).unwrap(),
            b"back"
        );
        let (released, _) = send
            .on_ack(
                &stream::Ack {
                    cumulative: 4,
                    limit: stream::INITIAL_WINDOW,
                    duplicate_bytes: 0,
                    ranges: Vec::new(),
                },
                now,
            )
            .unwrap();
        assert_eq!(released, 3, "virtual FIN has no byte credit");
        lease.release_tx(released as usize);
        assert!(send.finished());
        assert!(!recv.finished());
        assert_eq!(budget.snapshot(), (1, 4));
        recv.consumed(4, stream::INITIAL_WINDOW);
        lease.release_rx(4);
        assert!(recv.finished());
        assert_eq!(budget.snapshot(), (1, 0));
        drop(lease);
        assert_eq!(budget.snapshot(), (0, 0));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bulk_local_backpressure_cannot_hide_a_tiny_interactive_record() {
        let policy = Policy {
            max_message_bytes: 1000,
            streams: true,
            proxy: false,
            fec_repairs: 1,
            adaptive: true,
            capacity_probe_bps: 0,
            probe_guided_recovery: false,
            latency_target_ms: 20,
            group_rates: [80_000_000; MAX_PATHS],
            receiver_feedback: true,
            quality_schedule: true,
            fec: super::super::super::automatic_fec::AUTO,
            small_fec_bytes: 0,
            mixed_fec: false,
            redundancy: 30,
            rate: 80_000_000,
            block_ms: 25,
            queue_ms: 100,
        };
        policy.validate().unwrap();
        let metrics = stats::Metrics::new("client");
        let scope = metrics.scope("interactive-ingress", stats::FORWARD);
        let mut mux = Mux::new(
            Listeners::default(),
            Targets::default(),
            &policy,
            scope.clone(),
        );
        mux.open(1, false);
        mux.open(2, false);
        mux.streams
            .get_mut(&1)
            .unwrap()
            .send
            .push(&vec![7; READ_CHUNK]);
        mux.streams.get_mut(&2).unwrap().send.push(&[9; 64]);
        // These represent bulk records already waiting on actual admission.
        let held = mux.gauge.hold(1, 0, 1, MIN_QUEUED, false);
        let (tx, mut rx) = mpsc::channel(32);
        let mut next_id = 0;
        let mut out = Out {
            tx: &tx,
            next_id: &mut next_id,
            scope: &scope,
            small_threshold: 0,
        };
        mux.pump(&mut out, Instant::now());
        let first = rx
            .try_recv()
            .expect("the tiny stream must enter while the bulk watermark is full");
        assert_eq!(first.record.flow, stream::data_flow(2));
        assert_eq!(
            Frame::decode(&first.record.payload),
            Some(Frame::Data {
                offset: 0,
                fin: false,
                data: vec![9; 64]
            })
        );
        assert!(
            rx.try_recv().is_err(),
            "bulk must retain its original bound"
        );
        assert_eq!(mux.streams[&1].send.retained_from(), 0);
        // A burst of tiny streams remains globally bounded.
        for id in 3..40 {
            mux.open(id, false);
            mux.streams.get_mut(&id).unwrap().send.push(&[9; 128]);
        }
        mux.pump(&mut out, Instant::now());
        assert!(mux.gauge.queued() <= MIN_QUEUED + 3 * stream::MAX_SEGMENT);
        drop(first);
        drop(held);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socket_reads_and_eof_progress_while_wire_input_stays_ready() {
        let policy = Policy {
            max_message_bytes: 1000,
            streams: true,
            proxy: false,
            fec_repairs: 1,
            adaptive: false,
            capacity_probe_bps: 0,
            probe_guided_recovery: false,
            latency_target_ms: 20,
            group_rates: [10_000_000; MAX_PATHS],
            receiver_feedback: false,
            quality_schedule: false,
            fec: 0,
            small_fec_bytes: 0,
            mixed_fec: false,
            redundancy: 0,
            rate: 10_000_000,
            block_ms: 25,
            queue_ms: 100,
        };
        let metrics = stats::Metrics::new("client");
        let scope = metrics.scope("io-progress", stats::FORWARD);
        let mut mux = Mux::new(
            Listeners::default(),
            Targets::default(),
            &policy,
            scope.clone(),
        );
        mux.open(1, false);
        mux.events_tx.send(Io::Read(1, vec![7; 64])).unwrap();
        mux.events_tx.send(Io::ReadEnd(1)).unwrap();
        let (wire_tx, wire_rx) = mpsc::channel::<()>(1);
        wire_tx.try_send(()).unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let mut next_id = 0;
        let mut out = Out {
            tx: &tx,
            next_id: &mut next_id,
            scope: &scope,
            small_threshold: 0,
        };
        for remaining in [1, 0] {
            // The actor's higher-priority wire input never becomes Pending.
            // Each turn must nevertheless service one local completion.
            assert!(!wire_rx.is_empty());
            mux.service_io();
            assert_eq!(
                mux.events.len(),
                remaining,
                "local I/O must progress one event per turn"
            );
            mux.flush(&mut out);
        }
        assert_eq!(
            Frame::decode(&rx.try_recv().unwrap().record.payload),
            Some(Frame::Data {
                offset: 0,
                fin: false,
                data: vec![7; 64]
            })
        );
        assert_eq!(
            Frame::decode(&rx.try_recv().unwrap().record.payload),
            Some(Frame::Data {
                offset: 64,
                fin: true,
                data: Vec::new()
            }),
            "half-close must leave the application queue even during continuous wire traffic"
        );
        mux.service_io(); // An empty local queue is nonblocking.
    }
}
