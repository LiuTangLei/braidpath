//! Opt-in, bounded per-record/per-symbol diagnostic evidence.
//!
//! The default Trace has no allocation and emit_with does not evaluate its
//! closure. Enabled producers only copy fixed-size metadata into try_send;
//! JSON serialization and file writes run on one dedicated thread.
//!
//! QuinnApiAdmitted means that Quinn's API accepted a DATAGRAM. It is not a
//! QUIC packet number, OS send completion, NIC transmission, or peer delivery.
//! A missing event is usable as a layer boundary only if the footer AND the
//! final Summary are complete and expected lifecycle hooks are accounted for.
//!
//! finish must follow runtime cleanup, when producers are quiescent. Its bounded
//! wait cannot cancel an OS filesystem syscall: timeout marks the capture
//! incomplete, and a blocked writer can remain until that syscall returns.
//! No payload, payload digest, token, key, IP address, or free-form error string
//! is accepted by Event. Optional BPP2 identification reads only its known
//! structural header, and does not authenticate or validate the payload body.
//!
//! sequence is an emission-attempt ID, not a guaranteed file-line ordering:
//! concurrent producers may enqueue out of order. Reconcile exact integer ID
//! sets and final counts; never convert u64 identifiers to floating point.

use clap::Args;
use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};

pub const DEFAULT_MAX_EVENTS: u64 = 400_000;
pub const DEFAULT_QUEUE_EVENTS: u32 = 4096;
pub const DEFAULT_MAX_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_EVENTS: u64 = 2_000_000;
pub const MAX_QUEUE_EVENTS: u32 = 16_384;
pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
pub const MIN_FILE_BYTES: u64 = 16 * 1024;
pub const FINISH_TIMEOUT: Duration = Duration::from_secs(2);

const LINE_BYTES: usize = 4096;
const FOOTER_RESERVE: u64 = (LINE_BYTES * 2) as u64;
const WRITER_BUFFER_BYTES: usize = 64 * 1024;
const CLOSED_BIT: usize = 1usize << (usize::BITS - 1);

#[derive(Args, Clone, Debug)]
#[group(id = "PacketTraceOptions")]
pub struct Options {
    /// Write opt-in metadata-only packet evidence to a NEW file.
    #[arg(long)]
    pub packet_trace: Option<PathBuf>,
    /// Maximum event attempts; overflow makes the capture incomplete.
    #[arg(long, default_value_t = DEFAULT_MAX_EVENTS, requires = "packet_trace")]
    pub packet_trace_max_events: u64,
    /// Fixed event queue capacity; producers never wait for file output.
    #[arg(long, default_value_t = DEFAULT_QUEUE_EVENTS, requires = "packet_trace")]
    pub packet_trace_queue_events: u32,
    /// Maximum file bytes including reserved header/footer space.
    #[arg(long, default_value_t = DEFAULT_MAX_BYTES, requires = "packet_trace")]
    pub packet_trace_max_bytes: u64,
    /// Identify only structurally valid BPP2 run/type/sequence header fields.
    #[arg(long, requires = "packet_trace")]
    pub packet_trace_probe_header: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            packet_trace: None,
            packet_trace_max_events: DEFAULT_MAX_EVENTS,
            packet_trace_queue_events: DEFAULT_QUEUE_EVENTS,
            packet_trace_max_bytes: DEFAULT_MAX_BYTES,
            packet_trace_probe_header: false,
        }
    }
}

impl Options {
    fn validate(&self) -> io::Result<()> {
        if !(1..=MAX_EVENTS).contains(&self.packet_trace_max_events)
            || !(1..=MAX_QUEUE_EVENTS).contains(&self.packet_trace_queue_events)
            || !(MIN_FILE_BYTES..=MAX_FILE_BYTES).contains(&self.packet_trace_max_bytes)
            || (self.packet_trace_probe_header && self.packet_trace.is_none())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bounded packet trace options",
            ));
        }
        Ok(())
    }
}

/// Wire session/run IDs are serialized as exact 32-digit hex strings, not
/// potentially rounded JSON floating-point numbers. These are not credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Id(pub u128);

impl Id {
    pub fn from_hex(text: &str) -> Option<Self> {
        (text.len() == 32 && text.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| u128::from_str_radix(text, 16).ok().map(Self))
            .flatten()
    }
}

impl Serialize for Id {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{:032x}", self.0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Context {
    pub session: Id,
    pub direction: Direction,
}

impl Context {
    pub fn new(session: &str, direction: &str) -> Option<Self> {
        let direction = match direction {
            "client_to_server" => Direction::ClientToServer,
            "server_to_client" => Direction::ServerToClient,
            _ => return None,
        };
        Some(Self {
            session: Id::from_hex(session)?,
            direction,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RecordKey {
    pub flow: u32,
    pub record_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Plain,
    Original,
    Repair,
    RepairQ,
}

/// These are actual wire fields. A repair index_or_count is its block count,
/// not a record index. Plain frames use zero block/index; their record key is
/// required to distinguish them. Do not derive small/ordinary lanes from IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SymbolKey {
    pub kind: SymbolKind,
    pub block: u64,
    pub index_or_count: u8,
}

/// Sender-only knowledge. The receiver must leave this None unless it has an
/// explicit mapping; the wire format does not encode a coding lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Coding {
    Plain,
    Small,
    Ordinary,
}

/// generation is the negotiated path generation. connection_id is the local
/// conn.stable_id(), scoped by the file's process/trace ID, NOT a wire QUIC CID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PathKey {
    pub path_id: u8,
    pub generation: u64,
    pub connection_id: u64,
}

/// Distinct measurement layers. None means unobserved, never an inferred zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ByteCounts {
    pub payload: Option<u32>,
    pub wire: Option<u32>,
    pub http_datagram: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeIdentity {
    pub run_id: Id,
    pub kind: u8,
    pub seq: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    RecordIngress,
    RecordAssigned,
    IngressQueued,
    SenderInput,
    SymbolGenerated,
    SymbolQueued,
    QuinnApiAdmitted,
    QuinnApiRejected,
    PeerHttpReceived,
    PeerSymbolReceived,
    RecordDecoded,
    RecordDuplicate,
    LocalUdpQueued,
    LocalUdpWouldBlock,
    LocalUdpDelivered,
    RecordDropped,
    SymbolDropped,
    PathOpened,
    PathClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Expired,
    QueueFull,
    FlowFull,
    ByteLimit,
    SocketError,
    Shutdown,
    IngressClosed,
    IngressFull,
    InputClosed,
    SenderClosed,
    SenderFull,
    ReceiverClosed,
    ReceiverFull,
    FlowUnavailable,
    FlowLimit,
    Oversize,
    Encoding,
    InvalidHttp,
    InvalidSymbol,
    Stale,
    Duplicate,
    Budget,
    NoDiversePath,
    NoPath,
    QuinnError,
    GenerationRetired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Event {
    pub context: Context,
    pub stage: Stage,
    pub record: Option<RecordKey>,
    pub symbol: Option<SymbolKey>,
    pub path: Option<PathKey>,
    pub bytes: ByteCounts,
    pub probe: Option<ProbeIdentity>,
    pub reason: Option<Reason>,
    pub coding: Option<Coding>,
    /// true means reconstruction supplied this decoded candidate, not proof
    /// that a later original could not also have arrived before its deadline.
    pub recovered: Option<bool>,
}

impl Event {
    pub const fn new(context: Context, stage: Stage) -> Self {
        Self {
            context,
            stage,
            record: None,
            symbol: None,
            path: None,
            bytes: ByteCounts {
                payload: None,
                wire: None,
                http_datagram: None,
            },
            probe: None,
            reason: None,
            coding: None,
            recovered: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmitResult {
    Disabled,
    Accepted,
    QueueFull,
    EventLimit,
    Closed,
    WriterClosed,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Summary {
    pub enabled: bool,
    pub capture_closed: bool,
    pub attempted: u64,
    pub accepted: u64,
    /// Events successfully serialized into the writer. Final success also
    /// requires successful footer write/flush and the final stats snapshot.
    pub written: u64,
    pub dropped_queue_full: u64,
    pub dropped_event_limit: u64,
    pub dropped_after_close: u64,
    pub dropped_writer_closed: u64,
    pub dropped_file_limit: u64,
    pub invalid_contexts: u64,
    pub accepted_not_written: u64,
    /// Successfully buffered header + event bytes, excluding the footer.
    pub bytes_before_footer: u64,
    pub write_errors: u64,
    pub writer_finished: bool,
    pub footer_written: bool,
    pub orderly_finish: bool,
    pub aborted: bool,
    pub finish_timed_out: bool,
    /// A live/disabled trace is never evidence of complete capture.
    pub complete: bool,
}

#[derive(Default)]
struct Counters {
    attempted: AtomicU64,
    accepted: AtomicU64,
    written: AtomicU64,
    queue_full: AtomicU64,
    event_limit: AtomicU64,
    after_close: AtomicU64,
    writer_closed: AtomicU64,
    file_limit: AtomicU64,
    invalid_contexts: AtomicU64,
    bytes: AtomicU64,
    write_errors: AtomicU64,
    writer_finished: AtomicBool,
    footer_written: AtomicBool,
    orderly_finish: AtomicBool,
    timed_out: AtomicBool,
}

struct Inner {
    sender: mpsc::Sender<Message>,
    origin: Instant,
    // One atomic orders admission and close: an accepted emitter is counted
    // before close can observe zero; no two-location store/load race.
    gate: AtomicUsize,
    aborted: AtomicBool,
    max_events: u64,
    max_bytes: u64,
    probe_header: bool,
    counters: Counters,
}

impl Inner {
    fn close(&self) {
        self.gate.fetch_or(CLOSED_BIT, Ordering::AcqRel);
    }

    fn is_closed(&self) -> bool {
        self.gate.load(Ordering::Acquire) & CLOSED_BIT != 0
    }

    fn in_flight(&self) -> usize {
        self.gate.load(Ordering::Acquire) & !CLOSED_BIT
    }

    fn snapshot(&self) -> Summary {
        let c = &self.counters;
        let accepted = c.accepted.load(Ordering::Acquire);
        let written = c.written.load(Ordering::Acquire);
        let mut s = Summary {
            enabled: true,
            capture_closed: self.is_closed(),
            attempted: c.attempted.load(Ordering::Acquire),
            accepted,
            written,
            dropped_queue_full: c.queue_full.load(Ordering::Acquire),
            dropped_event_limit: c.event_limit.load(Ordering::Acquire),
            dropped_after_close: c.after_close.load(Ordering::Acquire),
            dropped_writer_closed: c.writer_closed.load(Ordering::Acquire),
            dropped_file_limit: c.file_limit.load(Ordering::Acquire),
            invalid_contexts: c.invalid_contexts.load(Ordering::Acquire),
            accepted_not_written: accepted.saturating_sub(written),
            bytes_before_footer: c.bytes.load(Ordering::Acquire),
            write_errors: c.write_errors.load(Ordering::Acquire),
            writer_finished: c.writer_finished.load(Ordering::Acquire),
            footer_written: c.footer_written.load(Ordering::Acquire),
            orderly_finish: c.orderly_finish.load(Ordering::Acquire),
            aborted: self.aborted.load(Ordering::Acquire),
            finish_timed_out: c.timed_out.load(Ordering::Acquire),
            complete: false,
        };
        s.recompute_complete();
        s
    }

    fn abort(&self) {
        self.close();
        self.aborted.store(true, Ordering::Release);
        // If full, the next consumed event observes aborted and closes the
        // receiver; if empty, this wakes a blocked writer immediately.
        let _ = self.sender.try_send(Message::Abort);
    }
}

impl Summary {
    fn recompute_complete(&mut self) {
        self.complete = self.enabled
            && self.capture_closed
            && self.writer_finished
            && self.footer_written
            && self.orderly_finish
            && !self.aborted
            && !self.finish_timed_out
            && self.write_errors == 0
            && self.dropped_queue_full == 0
            && self.dropped_event_limit == 0
            && self.dropped_after_close == 0
            && self.dropped_writer_closed == 0
            && self.dropped_file_limit == 0
            && self.invalid_contexts == 0
            && self.accepted == self.written
            && self.attempted == self.accepted;
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Stamped {
    sequence: u64,
    monotonic_ns: u64,
    #[serde(flatten)]
    event: Event,
}

// Fixed-size slots intentionally avoid allocating one Box on every transport
// event. The queue capacity and header's fixed_message_bytes bound this memory.
#[allow(clippy::large_enum_variant)]
enum Message {
    Event(Stamped),
    Finish,
    Abort,
}

#[derive(Clone, Default)]
pub struct Trace(Option<Arc<Inner>>);

pub struct Guard {
    inner: Option<Arc<Inner>>,
    done: Option<oneshot::Receiver<()>>,
}

impl Trace {
    pub const fn disabled() -> Self {
        Self(None)
    }

    pub fn enabled(&self) -> bool {
        self.0.is_some()
    }

    /// Called before starting the runtime. Only exclusive file creation occurs
    /// here; all serialization, writes and flushes run on the writer thread.
    /// No existing file is truncated, including an existing symlink.
    pub fn start(role: &'static str, options: &Options) -> io::Result<(Self, Guard)> {
        options.validate()?;
        let Some(path) = &options.packet_trace else {
            return Ok((
                Self::disabled(),
                Guard {
                    inner: None,
                    done: None,
                },
            ));
        };
        if role.is_empty()
            || role.len() > 32
            || !role
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid trace role",
            ));
        }
        let mut open = OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let file = open.open(path)?;
        let (sender, receiver) = mpsc::channel(options.packet_trace_queue_events as usize);
        let inner = Arc::new(Inner {
            sender,
            origin: Instant::now(),
            gate: AtomicUsize::new(0),
            aborted: AtomicBool::new(false),
            max_events: options.packet_trace_max_events,
            max_bytes: options.packet_trace_max_bytes,
            probe_header: options.packet_trace_probe_header,
            counters: Counters::default(),
        });
        let header = Header {
            kind: "header",
            schema: "braidpath-packet-trace-v1",
            role,
            process_id: std::process::id(),
            trace_id: Id(rand::random()),
            start_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|d| u64::try_from(d.as_millis()).ok()),
            clock: "local monotonic_ns since trace start; wall anchor is not clock calibration",
            queue_events: options.packet_trace_queue_events,
            max_events: options.packet_trace_max_events,
            max_file_bytes: options.packet_trace_max_bytes,
            fixed_message_bytes: std::mem::size_of::<Message>(),
            line_buffer_bytes: LINE_BYTES,
            writer_buffer_bytes: WRITER_BUFFER_BYTES,
            footer_reserve_bytes: FOOTER_RESERVE,
            bpp2_header_enabled: options.packet_trace_probe_header,
            admitted_boundary: "Quinn API accepted DATAGRAM; not a packet/OS/NIC send",
            complete_requires: "orderly footer and final stats agree; no drops/errors/timeout; all expected runtime stages present; JSONL footer ends with newline",
        };
        let (done_tx, done_rx) = oneshot::channel();
        let writer_inner = Arc::clone(&inner);
        std::thread::Builder::new()
            .name("braidpath-trace".into())
            .spawn(move || {
                let file = run_writer(file, receiver, &writer_inner, &header);
                drop(file);
                let _ = done_tx.send(());
            })?;
        Ok((
            Self(Some(Arc::clone(&inner))),
            Guard {
                inner: Some(inner),
                done: Some(done_rx),
            },
        ))
    }

    /// No event construction, timestamp read, allocation, lock, I/O or await
    /// occurs when disabled. Enabled calls use only atomics and try_send.
    pub fn emit_with(&self, make: impl FnOnce() -> Event) -> EmitResult {
        let Some(inner) = &self.0 else {
            return EmitResult::Disabled;
        };
        let mut state = inner.gate.load(Ordering::Acquire);
        loop {
            if state & CLOSED_BIT != 0 {
                inner.counters.after_close.fetch_add(1, Ordering::Relaxed);
                return EmitResult::Closed;
            }
            match inner.gate.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => state = current,
            }
        }
        let _active = ActiveEmitter(inner);
        let previous = inner.counters.attempted.fetch_add(1, Ordering::Relaxed);
        if previous >= inner.max_events {
            inner.counters.event_limit.fetch_add(1, Ordering::Relaxed);
            return EmitResult::EventLimit;
        }
        let event = make();
        let stamped = Stamped {
            sequence: previous + 1,
            monotonic_ns: u64::try_from(inner.origin.elapsed().as_nanos()).unwrap_or(u64::MAX),
            event,
        };
        match inner.sender.try_send(Message::Event(stamped)) {
            Ok(()) => {
                inner.counters.accepted.fetch_add(1, Ordering::Release);
                EmitResult::Accepted
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                inner.counters.queue_full.fetch_add(1, Ordering::Relaxed);
                EmitResult::QueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                inner.counters.writer_closed.fetch_add(1, Ordering::Relaxed);
                EmitResult::WriterClosed
            }
        }
    }

    pub fn emit(&self, event: Event) -> EmitResult {
        self.emit_with(|| event)
    }

    pub fn snapshot(&self) -> Summary {
        self.0
            .as_ref()
            .map_or_else(Summary::default, |i| i.snapshot())
    }

    /// An enabled hook could not construct its real wire session/direction.
    /// Do not invent a zero context or silently claim complete evidence.
    pub fn invalid_context(&self) {
        if let Some(inner) = &self.0 {
            inner
                .counters
                .invalid_contexts
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn probe_identity(&self, bytes: &[u8]) -> Option<ProbeIdentity> {
        let inner = self.0.as_ref()?;
        if !inner.probe_header {
            return None;
        }
        bpp2_identity(bytes)
    }
}

struct ActiveEmitter<'a>(&'a Inner);

impl Drop for ActiveEmitter<'_> {
    fn drop(&mut self) {
        self.0.gate.fetch_sub(1, Ordering::Release);
    }
}

struct AbortOnDrop(Option<Arc<Inner>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(inner) = &self.0 {
            inner.abort();
        }
    }
}

impl Guard {
    /// Wait at most FINISH_TIMEOUT after runtime cleanup. Disabled summaries
    /// have enabled=false, complete=false; they do not represent a failure.
    /// Enabled incomplete summaries must fail the diagnostic acceptance gate.
    pub async fn finish(mut self) -> Summary {
        let Some(inner) = self.inner.take() else {
            return Summary::default();
        };
        let mut cancellation = AbortOnDrop(Some(Arc::clone(&inner)));
        inner.close();
        let done = self.done.take();
        let completion = tokio::time::timeout(FINISH_TIMEOUT, async {
            while inner.in_flight() != 0 {
                tokio::task::yield_now().await;
            }
            // Only the shutdown caller can wait. Event producers never do.
            inner.sender.send(Message::Finish).await.map_err(|_| ())?;
            done.ok_or(())?.await.map_err(|_| ())
        })
        .await;
        match completion {
            Ok(Ok(())) => {
                cancellation.0 = None;
            }
            Ok(Err(())) => {
                inner.counters.write_errors.fetch_add(1, Ordering::Relaxed);
                inner.abort();
            }
            Err(_) => {
                inner.counters.timed_out.store(true, Ordering::Release);
                inner.abort();
            }
        }
        inner.snapshot()
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            inner.abort();
        }
    }
}

fn bpp2_identity(bytes: &[u8]) -> Option<ProbeIdentity> {
    if bytes.len() < 36
        || bytes.get(..4)? != b"BPP2"
        || bytes[5..8] != [0; 3]
        || !(1..=4).contains(&bytes[4])
    {
        return None;
    }
    Some(ProbeIdentity {
        run_id: Id(u128::from_be_bytes(bytes[8..24].try_into().ok()?)),
        kind: bytes[4],
        seq: u32::from_be_bytes(bytes[24..28].try_into().ok()?),
    })
}

#[derive(Serialize)]
struct Header {
    kind: &'static str,
    schema: &'static str,
    role: &'static str,
    process_id: u32,
    trace_id: Id,
    start_unix_ms: Option<u64>,
    clock: &'static str,
    queue_events: u32,
    max_events: u64,
    max_file_bytes: u64,
    fixed_message_bytes: usize,
    line_buffer_bytes: usize,
    writer_buffer_bytes: usize,
    footer_reserve_bytes: u64,
    bpp2_header_enabled: bool,
    admitted_boundary: &'static str,
    complete_requires: &'static str,
}

#[derive(Serialize)]
struct Footer {
    kind: &'static str,
    summary: Summary,
}

/// A hard stack buffer makes metadata serialization memory-bounded even if
/// future schema changes accidentally grow a line beyond the documented limit.
struct Line {
    bytes: [u8; LINE_BYTES],
    len: usize,
}

impl Line {
    fn new() -> Self {
        Self {
            bytes: [0; LINE_BYTES],
            len: 0,
        }
    }

    fn encode(&mut self, value: &impl Serialize) -> io::Result<&[u8]> {
        self.len = 0;
        serde_json::to_writer(&mut *self, value).map_err(io::Error::other)?;
        self.write_all(b"\n")?;
        Ok(&self.bytes[..self.len])
    }
}

impl Write for Line {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > LINE_BYTES - self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trace line limit",
            ));
        }
        self.bytes[self.len..self.len + input.len()].copy_from_slice(input);
        self.len += input.len();
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_data_line(
    output: &mut impl Write,
    inner: &Inner,
    line: &mut Line,
    value: &impl Serialize,
) -> io::Result<bool> {
    let encoded = line.encode(value)?;
    let previous = inner.counters.bytes.load(Ordering::Relaxed);
    if previous + encoded.len() as u64 > inner.max_bytes - FOOTER_RESERVE {
        return Ok(false);
    }
    output.write_all(encoded)?;
    inner
        .counters
        .bytes
        .fetch_add(encoded.len() as u64, Ordering::Release);
    Ok(true)
}

fn write_stream(
    output: &mut impl Write,
    receiver: &mut mpsc::Receiver<Message>,
    inner: &Inner,
    header: &Header,
) -> io::Result<()> {
    let mut line = Line::new();
    if !write_data_line(output, inner, &mut line, header)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "trace header limit",
        ));
    }
    let mut file_full = false;
    let mut orderly = false;
    loop {
        if inner.aborted.load(Ordering::Acquire) {
            receiver.close();
        }
        match receiver.blocking_recv() {
            Some(Message::Event(event)) => {
                if file_full || !write_data_line(output, inner, &mut line, &event)? {
                    file_full = true;
                    inner.counters.file_limit.fetch_add(1, Ordering::Relaxed);
                } else {
                    inner.counters.written.fetch_add(1, Ordering::Release);
                }
            }
            Some(Message::Finish) => {
                orderly = true;
                receiver.close();
            }
            Some(Message::Abort) => {
                receiver.close();
            }
            None => break,
        }
    }
    inner.close();
    inner
        .counters
        .orderly_finish
        .store(orderly, Ordering::Release);
    // Flush event data before building the final census. A failed flush never
    // produces a success footer; the caller records a write error.
    output.flush()?;
    let mut summary = inner.snapshot();
    summary.footer_written = true;
    summary.writer_finished = true;
    summary.recompute_complete();
    let footer = Footer {
        kind: "footer",
        summary,
    };
    let encoded = line.encode(&footer)?;
    debug_assert!((encoded.len() as u64) <= FOOTER_RESERVE);
    output.write_all(encoded)?;
    output.flush()?;
    inner.counters.footer_written.store(true, Ordering::Release);
    Ok(())
}

fn run_writer<W: Write>(
    output: W,
    mut receiver: mpsc::Receiver<Message>,
    inner: &Inner,
    header: &Header,
) -> W {
    let mut output = BufWriter::with_capacity(WRITER_BUFFER_BYTES, output);
    if write_stream(&mut output, &mut receiver, inner, header).is_err() {
        inner.counters.write_errors.fetch_add(1, Ordering::Relaxed);
        inner.close();
        receiver.close();
        // No file retry. Accepted-not-written remains explicit in final stats;
        // draining releases the bounded queue without inventing trace events.
        while receiver.blocking_recv().is_some() {}
    }
    inner
        .counters
        .writer_finished
        .store(true, Ordering::Release);
    // Avoid BufWriter::drop silently attempting another write after an error.
    let (output, _) = output.into_parts();
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn context() -> Context {
        Context::new("00000000000000000000000000000001", "client_to_server").unwrap()
    }

    fn event(id: u64) -> Event {
        let mut event = Event::new(context(), Stage::RecordIngress);
        event.record = Some(RecordKey {
            flow: 7,
            record_id: id,
        });
        event.bytes.payload = Some(128);
        event
    }

    fn manual_trace(
        capacity: u32,
        max_events: u64,
        max_bytes: u64,
        probe_header: bool,
    ) -> (Trace, mpsc::Receiver<Message>, Header) {
        let (sender, receiver) = mpsc::channel(capacity as usize);
        let inner = Arc::new(Inner {
            sender,
            origin: Instant::now(),
            gate: AtomicUsize::new(0),
            aborted: AtomicBool::new(false),
            max_events,
            max_bytes,
            probe_header,
            counters: Counters::default(),
        });
        let header = Header {
            kind: "header",
            schema: "braidpath-packet-trace-v1",
            role: "test",
            process_id: 1,
            trace_id: Id(1),
            start_unix_ms: Some(1),
            clock: "local monotonic",
            queue_events: capacity,
            max_events,
            max_file_bytes: max_bytes,
            fixed_message_bytes: std::mem::size_of::<Message>(),
            line_buffer_bytes: LINE_BYTES,
            writer_buffer_bytes: WRITER_BUFFER_BYTES,
            footer_reserve_bytes: FOOTER_RESERVE,
            bpp2_header_enabled: probe_header,
            admitted_boundary: "Quinn API only",
            complete_requires: "orderly footer and final stats",
        };
        (Trace(Some(inner)), receiver, header)
    }

    fn enqueue_finish(trace: &Trace) {
        let inner = trace.0.as_ref().unwrap();
        inner.close();
        assert!(inner.sender.try_send(Message::Finish).is_ok());
    }

    fn rows(bytes: &[u8]) -> Vec<serde_json::Value> {
        assert_eq!(bytes.last(), Some(&b'\n'));
        std::str::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn bpp2() -> Vec<u8> {
        let mut data = vec![0x5a; 128];
        data[..4].copy_from_slice(b"BPP2");
        data[4] = 3;
        data[5..8].fill(0);
        data[8..24].copy_from_slice(&0x112233445566778899aabbccddeeff00u128.to_be_bytes());
        data[24..28].copy_from_slice(&123u32.to_be_bytes());
        data[28..36].copy_from_slice(b"TIMESTMP");
        data[36..50].copy_from_slice(b"secret-payload");
        data
    }

    #[test]
    fn disabled_does_not_construct_events_or_parse_probe_data() {
        let trace = Trace::disabled();
        let called = Cell::new(false);
        assert_eq!(
            trace.emit_with(|| {
                called.set(true);
                event(1)
            }),
            EmitResult::Disabled
        );
        trace.invalid_context();
        assert!(!called.get());
        assert!(trace.probe_identity(&bpp2()).is_none());
        let summary = trace.snapshot();
        assert!(!summary.enabled);
        assert!(!summary.complete);
        assert_eq!(summary.attempted, 0);
        assert_eq!(summary.invalid_contexts, 0);
    }

    #[test]
    fn context_and_large_wire_ids_round_trip_without_guessing() {
        assert!(Context::new("session", "client_to_server").is_none());
        assert!(Context::new("00000000000000000000000000000001", "unknown").is_none());
        assert!(Id::from_hex("0000000000000000000000000000000g").is_none());
        let mut event = event(u64::MAX);
        event.context.session = Id(u128::MAX);
        event.symbol = Some(SymbolKey {
            kind: SymbolKind::Repair,
            block: u64::MAX,
            index_or_count: 32,
        });
        event.path = Some(PathKey {
            path_id: 7,
            generation: u64::MAX,
            connection_id: u64::MAX,
        });
        event.probe = Some(ProbeIdentity {
            run_id: Id(u128::MAX),
            kind: 3,
            seq: u32::MAX,
        });
        event.recovered = Some(true);
        let mut line = Line::new();
        let encoded = line.encode(&event).unwrap();
        let value: serde_json::Value = serde_json::from_slice(encoded).unwrap();
        assert_eq!(
            value["context"]["session"],
            "ffffffffffffffffffffffffffffffff"
        );
        assert_eq!(value["record"]["record_id"].as_u64(), Some(u64::MAX));
        assert_eq!(value["path"]["generation"].as_u64(), Some(u64::MAX));
        assert!(value["coding"].is_null());
        assert_eq!(value["recovered"], true);
        assert!(encoded.len() < LINE_BYTES);
        assert!(std::mem::size_of::<Message>() <= 512);
    }

    #[test]
    fn bpp2_identity_is_explicit_header_only_and_opt_in() {
        let (enabled, _receiver, _) = manual_trace(1, 4, MIN_FILE_BYTES, true);
        let (not_opted_in, _receiver2, _) = manual_trace(1, 4, MIN_FILE_BYTES, false);
        let bytes = bpp2();
        assert!(not_opted_in.probe_identity(&bytes).is_none());
        let identity = enabled.probe_identity(&bytes).unwrap();
        assert_eq!(identity.kind, 3);
        assert_eq!(identity.seq, 123);
        assert_eq!(identity.run_id, Id(0x112233445566778899aabbccddeeff00));
        let mut changed = bytes.clone();
        changed[28..].fill(0x33);
        assert_eq!(enabled.probe_identity(&changed), Some(identity));
        let encoded = serde_json::to_string(&identity).unwrap();
        assert!(!encoded.contains("TIMESTMP"));
        assert!(!encoded.contains("secret-payload"));
        assert!(!encoded.contains("timestamp"));
        assert!(!encoded.contains("payload"));
        for offset in [0, 5] {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            assert!(enabled.probe_identity(&bad).is_none());
        }
        let mut bad_kind = bytes.clone();
        bad_kind[4] = 255;
        assert!(enabled.probe_identity(&bad_kind).is_none());
        assert!(enabled.probe_identity(&bytes[..35]).is_none());
    }

    #[test]
    fn full_queue_drops_evidence_without_waiting_or_growing() {
        let (trace, mut receiver, _) = manual_trace(1, 10, MIN_FILE_BYTES, false);
        assert_eq!(trace.emit(event(1)), EmitResult::Accepted);
        assert_eq!(trace.emit(event(2)), EmitResult::QueueFull);
        assert_eq!(trace.emit(event(3)), EmitResult::QueueFull);
        let summary = trace.snapshot();
        assert_eq!(
            (
                summary.attempted,
                summary.accepted,
                summary.dropped_queue_full
            ),
            (3, 1, 2)
        );
        assert!(!summary.complete);
        let Some(Message::Event(first)) = receiver.blocking_recv() else {
            panic!("missing first event");
        };
        assert_eq!(first.sequence, 1);
        assert_eq!(first.event.record.unwrap().record_id, 1);
        assert_eq!(trace.emit(event(4)), EmitResult::Accepted);
        let Some(Message::Event(next)) = receiver.blocking_recv() else {
            panic!("missing next event");
        };
        assert_eq!(next.sequence, 4);
        assert_eq!(trace.0.as_ref().unwrap().in_flight(), 0);
    }

    #[test]
    fn attempt_limit_preserves_gaps_and_skips_event_construction() {
        let (trace, _receiver, _) = manual_trace(4, 1, MIN_FILE_BYTES, false);
        assert_eq!(trace.emit(event(1)), EmitResult::Accepted);
        assert_eq!(
            trace.emit_with(|| panic!("event limit must skip construction")),
            EmitResult::EventLimit
        );
        let summary = trace.snapshot();
        assert_eq!(
            (
                summary.attempted,
                summary.accepted,
                summary.dropped_event_limit
            ),
            (2, 1, 1)
        );
        assert!(!summary.complete);
    }

    #[test]
    fn closed_writer_and_invalid_context_are_not_silent_success() {
        let (trace, receiver, _) = manual_trace(1, 10, MIN_FILE_BYTES, false);
        drop(receiver);
        assert_eq!(trace.emit(event(1)), EmitResult::WriterClosed);
        assert_eq!(trace.snapshot().dropped_writer_closed, 1);
        trace.invalid_context();
        assert_eq!(trace.snapshot().invalid_contexts, 1);
        trace.0.as_ref().unwrap().close();
        assert_eq!(
            trace.emit_with(|| panic!("closed capture must skip construction")),
            EmitResult::Closed
        );
        assert_eq!(trace.snapshot().dropped_after_close, 1);
        assert!(!trace.snapshot().complete);
    }

    #[test]
    fn writer_footer_reconciles_event_ids_and_bytes_after_orderly_close() {
        let (trace, receiver, header) = manual_trace(4, 10, MIN_FILE_BYTES, false);
        assert_eq!(trace.emit(event(1)), EmitResult::Accepted);
        assert_eq!(trace.emit(event(2)), EmitResult::Accepted);
        enqueue_finish(&trace);
        let output = run_writer(Vec::new(), receiver, trace.0.as_ref().unwrap(), &header);
        let rows = rows(&output);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0]["kind"], "header");
        assert_eq!(rows[1]["record"]["record_id"], 1);
        assert_eq!(rows[2]["record"]["record_id"], 2);
        assert_eq!(rows[3]["kind"], "footer");
        assert_eq!(rows[3]["summary"]["complete"], true);
        let summary = trace.snapshot();
        assert!(summary.complete);
        assert_eq!(
            (summary.attempted, summary.accepted, summary.written),
            (2, 2, 2)
        );
        assert!((output.len() as u64) <= MIN_FILE_BYTES);
        // Calling a hook after close is visible in the live/final stats even
        // though an already-written footer covers only its prior closed epoch.
        assert_eq!(trace.emit(event(3)), EmitResult::Closed);
        assert!(!trace.snapshot().complete);
    }

    #[test]
    fn invalid_context_makes_even_an_empty_orderly_footer_incomplete() {
        let (trace, receiver, header) = manual_trace(2, 10, MIN_FILE_BYTES, false);
        trace.invalid_context();
        enqueue_finish(&trace);
        let output = run_writer(Vec::new(), receiver, trace.0.as_ref().unwrap(), &header);
        let values = rows(&output);
        let footer = values.last().unwrap();
        assert_eq!(footer["summary"]["invalid_contexts"], 1);
        assert_eq!(footer["summary"]["complete"], false);
        assert!(!trace.snapshot().complete);
    }

    #[test]
    fn file_limit_keeps_footer_and_marks_unwritten_events_incomplete() {
        let (trace, receiver, header) = manual_trace(65, 100, MIN_FILE_BYTES, false);
        for id in 0..64 {
            assert_eq!(trace.emit(event(id)), EmitResult::Accepted);
        }
        enqueue_finish(&trace);
        let output = run_writer(Vec::new(), receiver, trace.0.as_ref().unwrap(), &header);
        assert!((output.len() as u64) <= MIN_FILE_BYTES);
        let values = rows(&output);
        let footer = values.last().unwrap();
        let summary = trace.snapshot();
        assert!(summary.dropped_file_limit > 0);
        assert_eq!(
            summary.accepted,
            summary.written + summary.dropped_file_limit
        );
        assert!(summary.footer_written);
        assert!(!summary.complete);
        assert_eq!(footer["summary"]["complete"], false);
        assert_eq!(
            footer["summary"]["dropped_file_limit"].as_u64(),
            Some(summary.dropped_file_limit)
        );
    }

    struct FlushFails(Vec<u8>);
    impl Write for FlushFails {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected trace flush failure",
            ))
        }
    }

    #[test]
    fn writer_io_failure_has_no_success_footer_and_is_not_retried() {
        let (trace, receiver, header) = manual_trace(3, 10, MIN_FILE_BYTES, false);
        assert_eq!(trace.emit(event(1)), EmitResult::Accepted);
        enqueue_finish(&trace);
        let output = run_writer(
            FlushFails(Vec::new()),
            receiver,
            trace.0.as_ref().unwrap(),
            &header,
        );
        let values = rows(&output.0);
        assert_eq!(values.len(), 2);
        assert!(
            !values
                .iter()
                .any(|v| v.get("kind") == Some(&serde_json::json!("footer")))
        );
        let summary = trace.snapshot();
        assert_eq!(summary.write_errors, 1);
        assert!(summary.writer_finished);
        assert!(!summary.footer_written);
        assert!(!summary.complete);
    }

    #[test]
    fn line_capacity_is_a_hard_serialization_bound() {
        let mut line = Line::new();
        let too_large = "x".repeat(LINE_BYTES + 1);
        assert!(line.encode(&too_large).is_err());
        assert!(line.len <= LINE_BYTES);
    }

    #[test]
    fn invalid_limits_and_existing_paths_do_not_replace_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        let mut options = Options {
            packet_trace: Some(path.clone()),
            packet_trace_queue_events: 0,
            ..Options::default()
        };
        assert!(Trace::start("test", &options).is_err());
        assert!(!path.exists());
        options.packet_trace_queue_events = 1;
        options.packet_trace_max_events = MAX_EVENTS + 1;
        assert!(Trace::start("test", &options).is_err());
        assert!(!path.exists());
        options.packet_trace_max_events = 1;
        std::fs::write(&path, b"preserve existing evidence").unwrap();
        assert!(Trace::start("test", &options).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"preserve existing evidence");
        #[cfg(unix)]
        {
            let alias = directory.path().join("alias.jsonl");
            std::os::unix::fs::symlink(&path, &alias).unwrap();
            options.packet_trace = Some(alias);
            assert!(Trace::start("test", &options).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), b"preserve existing evidence");
        }
    }

    #[tokio::test]
    async fn file_writer_finishes_after_cleanup_and_disabled_finish_is_not_capture() {
        let (disabled, guard) = Trace::start("test", &Options::default()).unwrap();
        assert!(!disabled.enabled());
        let empty = guard.finish().await;
        assert!(!empty.enabled);
        assert!(!empty.complete);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        let options = Options {
            packet_trace: Some(path.clone()),
            packet_trace_queue_events: 8,
            ..Options::default()
        };
        let (trace, guard) = Trace::start("test", &options).unwrap();
        for id in 0..5 {
            assert_eq!(trace.emit(event(id)), EmitResult::Accepted);
        }
        let summary = guard.finish().await;
        assert!(summary.complete);
        assert_eq!(summary.written, 5);
        let values = rows(&std::fs::read(&path).unwrap());
        assert_eq!(values.len(), 7);
        assert_eq!(values.last().unwrap()["summary"]["complete"], true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }

    #[tokio::test]
    async fn unfinished_guard_is_aborted_even_if_queued_events_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        let options = Options {
            packet_trace: Some(path.clone()),
            packet_trace_queue_events: 4,
            ..Options::default()
        };
        let (trace, mut guard) = Trace::start("test", &options).unwrap();
        let done = guard.done.take().unwrap();
        assert_eq!(trace.emit(event(1)), EmitResult::Accepted);
        drop(guard);
        tokio::time::timeout(FINISH_TIMEOUT, done)
            .await
            .unwrap()
            .unwrap();
        let summary = trace.snapshot();
        assert!(summary.aborted);
        assert!(summary.writer_finished);
        assert!(!summary.orderly_finish);
        assert!(!summary.complete);
        let values = rows(&std::fs::read(path).unwrap());
        assert_eq!(values.last().unwrap()["summary"]["complete"], false);
    }

    #[tokio::test]
    async fn finish_marker_cannot_overtake_a_producer_already_constructing_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        let options = Options {
            packet_trace: Some(path.clone()),
            packet_trace_queue_events: 4,
            ..Options::default()
        };
        let (trace, guard) = Trace::start("test", &options).unwrap();
        let producer = trace.clone();
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let worker = std::thread::spawn(move || {
            producer.emit_with(|| {
                entered_tx.send(()).unwrap();
                release_rx.blocking_recv().unwrap();
                event(19)
            })
        });
        entered_rx.await.unwrap();
        let finish = tokio::spawn(guard.finish());
        while !trace.snapshot().capture_closed {
            tokio::task::yield_now().await;
        }
        assert!(!finish.is_finished());
        release_tx.send(()).unwrap();
        let summary = finish.await.unwrap();
        assert_eq!(worker.join().unwrap(), EmitResult::Accepted);
        assert!(summary.complete);
        assert_eq!(summary.written, 1);
        let values = rows(&std::fs::read(path).unwrap());
        assert_eq!(values[1]["record"]["record_id"], 19);
        assert_eq!(values.last().unwrap()["summary"]["complete"], true);
    }

    #[test]
    fn default_cli_remains_disabled_and_trace_tuning_requires_opt_in() {
        #[derive(clap::Parser)]
        struct Command {
            #[command(flatten)]
            options: Options,
        }
        let plain = <Command as clap::Parser>::try_parse_from(["test"]).unwrap();
        assert!(plain.options.packet_trace.is_none());
        assert_eq!(plain.options.packet_trace_max_events, DEFAULT_MAX_EVENTS);
        assert_eq!(
            plain.options.packet_trace_queue_events,
            DEFAULT_QUEUE_EVENTS
        );
        assert!(!plain.options.packet_trace_probe_header);
        assert!(
            <Command as clap::Parser>::try_parse_from(["test", "--packet-trace-max-events", "10",])
                .is_err()
        );
        let enabled = <Command as clap::Parser>::try_parse_from([
            "test",
            "--packet-trace",
            "trace.jsonl",
            "--packet-trace-probe-header",
            "--packet-trace-max-events",
            "10",
        ])
        .unwrap();
        assert!(enabled.options.packet_trace_probe_header);
        assert_eq!(enabled.options.packet_trace_max_events, 10);
    }

    #[tokio::test(start_paused = true)]
    async fn finish_timeout_is_bounded_and_cannot_claim_complete_writer_output() {
        // Deliberately no writer: a stuck filesystem cannot be interrupted by
        // this module. The public finish must still return incomplete on time.
        let (trace, _receiver, _) = manual_trace(2, 10, MIN_FILE_BYTES, false);
        let (_done_sender, done) = oneshot::channel();
        let guard = Guard {
            inner: Some(Arc::clone(trace.0.as_ref().unwrap())),
            done: Some(done),
        };
        let before = tokio::time::Instant::now();
        let summary = guard.finish().await;
        assert_eq!(tokio::time::Instant::now() - before, FINISH_TIMEOUT);
        assert!(summary.finish_timed_out);
        assert!(summary.aborted);
        assert!(summary.capture_closed);
        assert!(!summary.writer_finished);
        assert!(!summary.footer_written);
        assert!(!summary.complete);
    }

    #[tokio::test]
    async fn cancelling_finish_uses_abort_guard_instead_of_losing_shutdown() {
        let (trace, _receiver, _) = manual_trace(2, 10, MIN_FILE_BYTES, false);
        let (_done_sender, done) = oneshot::channel();
        let guard = Guard {
            inner: Some(Arc::clone(trace.0.as_ref().unwrap())),
            done: Some(done),
        };
        let task = tokio::spawn(guard.finish());
        while !trace.snapshot().capture_closed {
            tokio::task::yield_now().await;
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let summary = trace.snapshot();
        assert!(summary.aborted);
        assert!(!summary.finish_timed_out);
        assert!(!summary.complete);
    }
}
