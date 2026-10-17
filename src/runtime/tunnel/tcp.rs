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
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream, UdpSocket,
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
}

pub(super) enum Io {
    Read(u32, Vec<u8>),
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
    send: stream::Sender,
    recv: stream::Receiver,
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
            status_pending: false,
            header: None,
            refused: false,
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
    listeners: Listeners,
    targets: Targets,
    streams: HashMap<u32, Stream>,
    turns: VecDeque<u32>,
    /// Retired streams; a completed one keeps its final acknowledgment.
    closed: HashMap<u32, (Instant, Option<Vec<u8>>)>,
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
            listeners,
            targets,
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
            associations: HashMap::new(),
            next_association: 0,
            datagrams: VecDeque::new(),
        }
    }
    /// Accepts local connections; the peer connects each stream onward.
    pub(super) fn client(listeners: Listeners, policy: &Policy, scope: Scope) -> Option<Self> {
        (listeners.fixed.is_some() || listeners.proxy.is_some())
            .then(|| Self::new(listeners, Targets::default(), policy, scope))
    }
    /// Connects peer-opened streams of the kinds this session negotiated.
    pub(super) fn server(targets: Targets, policy: &Policy, scope: Scope) -> Option<Self> {
        let targets = Targets {
            fixed: targets.fixed.filter(|_| policy.streams),
            proxy: targets.proxy.filter(|_| policy.proxy),
        };
        (targets.fixed.is_some() || targets.proxy.is_some())
            .then(|| Self::new(Listeners::default(), targets, policy, scope))
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
        let queue_waiting = !self.datagrams.is_empty()
            || !self.control.is_empty()
            || self.streams.values().any(|s| s.send.has_transmit());
        tokio::select! {
            biased;
            Some(event) = self.events.recv() => Wake::Io(event),
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
                .min_by_key(|(_, (at, _))| *at)
                .map(|(id, _)| *id)
        {
            self.closed.remove(&oldest);
        }
        let final_ack = s.recv.final_ack().map(|ack| Frame::Ack(ack).encode());
        self.closed.insert(id, (Instant::now(), final_ack));
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

    pub(super) fn handle(&mut self, wake: Wake) {
        match wake {
            Wake::Io(event) => self.io(event),
            Wake::Accept(Ok((tcp, _))) => {
                if let Some(id) = self.next_id(false) {
                    self.open(id, true);
                    self.attach(id, tcp);
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
            Io::Reached(id, tcp) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    s.send.push(&[proxy::OK]);
                    self.attach(id, tcp);
                }
            }
            Io::Refused(id, status) => {
                if let Some(s) = self.streams.get_mut(&id) {
                    debug!(stream = id, status, "proxy destination refused");
                    s.refused = true;
                    s.undelivered.clear();
                    s.send.push(&[status]);
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
                self.open(id, false);
                let s = self.streams.get_mut(&id).expect("opened");
                s.send.push(&request.destination.encode());
                s.send.push(&request.early);
                self.stats.bytes_from_application += request.early.len() as u64;
                s.status_pending = true;
                // Reply at once, so application data follows the destination
                // header without waiting a tunnel round trip. A refused
                // destination later resets the local connection.
                let events = self.events_tx.clone();
                self.tasks.spawn(async move {
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
        if self.next_stream + 1 >= ADDRESSED {
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
            self.control.push_back((stream::ack_flow(id), ack.clone()));
            self.stats.acks_sent += 1;
            return false;
        }
        if !accepted || self.closed.contains_key(&id) {
            // Stale, unnegotiated, or peer-opened toward a client.
            self.control
                .push_back((stream::data_flow(id), Frame::Reset.encode()));
            return false;
        }
        if self.streams.len() >= MAX_STREAMS {
            self.stats.rejected += 1;
            self.closed.insert(id, (now, None));
            self.control
                .push_back((stream::data_flow(id), Frame::Reset.encode()));
            return false;
        }
        self.open(id, false);
        let s = self.streams.get_mut(&id).expect("opened");
        match self.targets.fixed.filter(|_| !addressed) {
            Some(target) => {
                let events = self.events_tx.clone();
                s.tasks.push(self.tasks.spawn(async move {
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
                    let events = self.events_tx.clone();
                    s.tasks.push(self.tasks.spawn(async move {
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
            let status = if ready.is_empty() {
                if !s.recv.fin_received() {
                    return;
                }
                proxy::GENERAL_FAILURE
            } else {
                s.recv.consumed(1, window);
                ready.remove(0)
            };
            s.status_pending = false;
            if status != proxy::OK {
                debug!(stream = id, status, "proxy destination refused");
                return self.reset(id, "proxy destination refused");
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
                if !self.streams.contains_key(&id) && !self.accept_stream(id, now) {
                    return;
                }
                let s = self.streams.get_mut(&id).expect("stream");
                match s.recv.on_data(offset, fin, data, now) {
                    Ok(ready) => self.arrived(id, ready),
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
                self.control
                    .push_back((stream::ack_flow(id), Frame::Ack(ack).encode()));
                self.stats.acks_sent += 1;
            }
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
        // Finished tasks stay in the set until reaped.
        while self.tasks.try_join_next().is_some() {}
        self.closed
            .retain(|_, (at, _)| now.saturating_duration_since(*at) < TOMBSTONE);
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
        self.scope
            .update(|d| d.tcp_streams = Some(snapshot.clone()));
        if tracing::enabled!(tracing::Level::DEBUG) {
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
                s.abort();
                self.stats.reset_local += 1;
            }
        }
        self.publish(Instant::now());
        self.tasks.abort_all();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{MAX_PATHS, stats};

    #[tokio::test(flavor = "current_thread")]
    async fn socket_reads_and_eof_progress_while_wire_input_stays_ready() {
        let policy = Policy {
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
