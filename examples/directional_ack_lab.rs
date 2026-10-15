//! Controlled native QUIC laboratory: real loopback sockets, optional synthetic
//! reverse packet-rate bottleneck, one sender-requested ACK-frequency treatment.
//! Not a WAN benchmark, H3-equivalent adapter, or production configuration.
use anyhow::{Context, Result, ensure};
use braidpath::runtime::transport;
use bytes::Bytes;
use clap::Parser;
use quinn::{
    ClientConfig, Endpoint, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    fs,
    future::{Future, poll_fn},
    io::{BufReader, BufWriter, IoSliceMut, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    sync::watch,
    task::JoinSet,
    time::{Instant, MissedTickBehavior, sleep_until, timeout},
};
#[path = "support/ack_policy.rs"]
mod ack_policy;
use ack_policy::{AckProfile, reference_transport};
#[path = "support/lab_socket.rs"]
mod lab_socket;

const ALPN: &[u8] = b"braidpath-directional-ack-lab/1";
const HEADER: usize = 55;
const BULK: usize = 1000;
const ECHO: usize = 128;
const QUEUE: usize = 256;
const DEADLINE_US: u64 = 100_000;
const LINK_QUEUE: usize = 4096;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_enum)]
    ack_profile: AckProfile,
    /// Synthetic receiver-to-sender packet service limit. Zero means unlimited.
    #[arg(long, default_value_t = 0)]
    reverse_pps: u32,
    #[arg(long, default_value_t = 20)]
    one_way_delay_ms: u64,
    #[arg(long, default_value_t = 20)]
    link_queue_ms: u64,
    #[arg(long, default_value_t = 10_000)]
    bulk_pps: u32,
    #[arg(long, default_value_t = 50)]
    echo_pps: u32,
    #[arg(long, default_value_t = 2000)]
    warmup_ms: u64,
    #[arg(long, default_value_t = 8000)]
    business_ms: u64,
    #[arg(long, default_value_t = 2000)]
    drain_ms: u64,
    /// Receive headroom on the four owned loopback sockets; zero preserves OS defaults.
    #[arg(long, default_value_t = 0)]
    socket_receive_bytes: usize,
    /// Send headroom for owned loopback sockets only, independently registered.
    #[arg(long, default_value_t = 0)]
    socket_send_bytes: usize,
}
impl Args {
    fn validate(&self) -> Result<()> {
        lab_socket::validate(self.socket_receive_bytes)?;
        lab_socket::validate(self.socket_send_bytes)?;
        ensure!(!self.output.exists(), "preserve previous evidence");
        ensure!(
            (1..=20_000).contains(&self.bulk_pps),
            "bounded source required"
        );
        ensure!(
            (1..=100).contains(&self.echo_pps),
            "bounded request source required"
        );
        ensure!(
            self.reverse_pps == 0 || (100..=20_000).contains(&self.reverse_pps),
            "invalid reverse pps"
        );
        ensure!(
            self.one_way_delay_ms <= 50 && self.link_queue_ms <= 100,
            "bounded synthetic delay required"
        );
        ensure!(
            self.warmup_ms <= 3000
                && (100..=10_000).contains(&self.business_ms)
                && (500..=3000).contains(&self.drain_ms),
            "bounded phases required"
        );
        for rate in [self.bulk_pps, self.echo_pps] {
            ensure!(
                (self.warmup_ms * u64::from(rate)).is_multiple_of(1000)
                    && (self.business_ms * u64::from(rate)).is_multiple_of(1000),
                "whole source slots required"
            );
        }
        Ok(())
    }
}
fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    // serde_json streams small tokens. Buffer them so mounted evidence storage
    // does not turn one finite cohort into millions of synchronous file writes.
    // A flush error is still a failed run, not a successful partial artifact.
    let mut writer = BufWriter::with_capacity(64 * 1024, file);
    serde_json::to_writer(&mut writer, value)?;
    writeln!(writer)?;
    writer.flush()?;
    Ok(())
}
fn micros(epoch: Instant) -> u64 {
    epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}
fn frame(kind: u8, seq: u32, run: &[u8; 16], issued: u64) -> Bytes {
    let size = if kind == 0 { BULK } else { ECHO };
    let mut b = vec![(seq % 251) as u8; HEADER + size];
    b[..4].copy_from_slice(b"DACL");
    b[4] = kind;
    b[5..9].copy_from_slice(&seq.to_be_bytes());
    b[9..25].copy_from_slice(run);
    b[25..33].copy_from_slice(&issued.to_be_bytes());
    b[33..HEADER].fill(0);
    b.into()
}
fn decode(b: &[u8], run: &[u8; 16]) -> Result<(u8, usize, u64)> {
    ensure!(
        b.len() >= HEADER && &b[..4] == b"DACL" && b[4] <= 2 && &b[9..25] == run,
        "unknown record identity"
    );
    let kind = b[4];
    let seq = u32::from_be_bytes(b[5..9].try_into()?) as usize;
    let size = if kind == 0 { BULK } else { ECHO };
    ensure!(
        b.len() == HEADER + size
            && b[33..HEADER].iter().all(|x| *x == 0)
            && b[HEADER..].iter().all(|x| *x == (seq % 251) as u8),
        "record corruption"
    );
    Ok((kind, seq, u64::from_be_bytes(b[25..33].try_into()?)))
}
#[derive(Default, Clone, Serialize)]
struct LinkStats {
    input_packets: u64,
    input_bytes: u64,
    forwarded_packets: u64,
    forwarded_bytes: u64,
    queue_discarded_packets: u64,
    foreign_packets: u64,
    shutdown_discarded_packets: u64,
    maximum_queue_packets: usize,
    maximum_model_wait_us: u64,
    maximum_timer_lateness_us: u64,
    receive_batches: u64,
    maximum_receive_batch_packets: usize,
    maximum_forward_batch_packets: usize,
    send_would_block: u64,
}
struct Flight {
    due: Instant,
    data: Bytes,
}
/// One FIFO resource. Admission accounts packet service, propagation is separate.
struct LinkQueue {
    queue: VecDeque<Flight>,
    next_service: Instant,
    service: Duration,
    propagation: Duration,
    max_wait: Duration,
}
impl LinkQueue {
    fn new(pps: u32, delay: Duration, max_wait: Duration) -> Self {
        Self {
            queue: VecDeque::new(),
            next_service: Instant::now(),
            service: if pps == 0 {
                Duration::ZERO
            } else {
                Duration::from_nanos(1_000_000_000 / u64::from(pps))
            },
            propagation: delay,
            max_wait,
        }
    }
    fn offer(&mut self, now: Instant, data: Bytes, stats: &mut LinkStats) {
        stats.input_packets += 1;
        stats.input_bytes += data.len() as u64;
        let start = now.max(self.next_service);
        let wait = start.saturating_duration_since(now);
        if wait > self.max_wait || self.queue.len() >= LINK_QUEUE {
            stats.queue_discarded_packets += 1;
            return;
        }
        let end = start + self.service;
        self.next_service = end;
        stats.maximum_model_wait_us = stats.maximum_model_wait_us.max(wait.as_micros() as u64);
        self.queue.push_back(Flight {
            due: end + self.propagation,
            data,
        });
        stats.maximum_queue_packets = stats.maximum_queue_packets.max(self.queue.len());
    }
}
async fn link_loop(
    input: Arc<dyn quinn::AsyncUdpSocket>,
    output: Arc<dyn quinn::AsyncUdpSocket>,
    allowed: SocketAddr,
    destination: SocketAddr,
    mut queue: LinkQueue,
    stats: Arc<Mutex<LinkStats>>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    ensure!(
        allowed.ip().is_loopback() && destination.ip().is_loopback(),
        "loopback only"
    );
    // Use the carrier's safe platform UDP adapter: it supports recvmmsg/GRO
    // when present and handles readiness once for a bounded receive batch.
    // Sixteen 64KiB slots cap receive workspace at one MiB per relay direction.
    let mut storage = vec![vec![0u8; 65536]; 16];
    let mut slices: Vec<_> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let mut metadata = vec![Default::default(); 16];
    let mut writable = output.clone().create_io_poller();
    loop {
        if *stop.borrow() {
            break;
        }
        // Work-conserving service: an expired timer must not be recreated and
        // cancelled by a hot receive branch before its ready packets advance.
        let mut count = 0;
        let mut bytes = 0;
        let mut maximum_late = 0;
        let mut blocked = false;
        for _ in 0..64 {
            if queue.queue.front().is_none_or(|p| p.due > Instant::now()) {
                break;
            }
            let p = queue.queue.front().unwrap();
            let late = Instant::now().saturating_duration_since(p.due).as_micros() as u64;
            let transmit = quinn::udp::Transmit {
                destination,
                ecn: None,
                contents: &p.data,
                segment_size: None,
                src_ip: None,
            };
            match output.try_send(&transmit) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    blocked = true;
                    stats.lock().unwrap().send_would_block += 1;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
            let n = queue.queue.pop_front().unwrap().data.len();
            count += 1;
            bytes += n as u64;
            maximum_late = maximum_late.max(late);
        }
        if count != 0 {
            let mut s = stats.lock().unwrap();
            s.forwarded_packets += count;
            s.forwarded_bytes += bytes;
            s.maximum_timer_lateness_us = s.maximum_timer_lateness_us.max(maximum_late);
            s.maximum_forward_batch_packets = s.maximum_forward_batch_packets.max(count as usize);
        }
        if count == 64 {
            tokio::task::yield_now().await;
            continue;
        }
        let due = queue.queue.front().filter(|_| !blocked).map(|p| p.due);
        tokio::select! {
            _=stop.changed()=>break,
            r=poll_fn(|cx|input.poll_recv(cx,&mut slices,&mut metadata))=>{
                let buffers=r?;
                let mut received=0;
                let mut counts=stats.lock().unwrap();
                for index in 0..buffers {
                    let meta=&metadata[index];
                    ensure!(meta.len<=slices[index].len() && meta.stride>0,"invalid native UDP batch metadata");
                    for packet in slices[index][..meta.len].chunks(meta.stride) {
                        received+=1;
                        if meta.addr!=allowed {counts.foreign_packets+=1;continue;}
                        ensure!(packet.len()<2048,"oversized or truncated UDP packet");
                        queue.offer(Instant::now(),Bytes::copy_from_slice(packet),&mut counts);
                    }
                }
                counts.receive_batches+=1;
                counts.maximum_receive_batch_packets=counts.maximum_receive_batch_packets.max(received);
            },
            _=async {if let Some(t)=due {sleep_until(t).await}else{std::future::pending::<()>().await}}=>{}
            ready=poll_fn(|cx|writable.as_mut().poll_writable(cx)), if blocked =>{ready?;}
        }
    }
    stats.lock().unwrap().shutdown_discarded_packets += queue.queue.len() as u64;
    Ok(())
}
fn make_endpoint(
    identity: &Path,
    server: bool,
    profile: AckProfile,
    socket: std::net::UdpSocket,
) -> Result<Endpoint> {
    let cert = transport::certificates(&identity.join("cert.pem"))?;
    if server {
        let key = rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(
            identity.join("key.pem"),
        )?))?
        .context("key missing")?;
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert, key)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.max_early_data_size = 0;
        let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
        config.transport_config(Arc::new(reference_transport(profile)));
        Ok(Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?)
    } else {
        let mut roots = rustls::RootCertStore::empty();
        for c in cert {
            roots.add(c)?;
        }
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.enable_early_data = false;
        let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
        config.transport_config(Arc::new(reference_transport(profile)));
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(config);
        Ok(endpoint)
    }
}
async fn auth(conn: &quinn::Connection, server: bool, token: &str) -> Result<()> {
    if server {
        let (mut tx, mut rx) = conn.accept_bi().await?;
        let data = rx.read_to_end(64).await?;
        ensure!(
            data.len() == 64 && bool::from(data.ct_eq(token.as_bytes())),
            "authentication failed"
        );
        tx.write_all(b"ready").await?;
        tx.finish()?;
    } else {
        let (mut tx, mut rx) = conn.open_bi().await?;
        tx.write_all(token.as_bytes()).await?;
        tx.finish()?;
        ensure!(
            rx.read_to_end(5).await? == b"ready",
            "authentication response invalid"
        );
    }
    Ok(())
}
fn native(conn: &quinn::Connection) -> Value {
    let s = conn.stats();
    json!({"udp_packets_tx":s.udp_tx.datagrams,"udp_packets_rx":s.udp_rx.datagrams,
        "udp_bytes_tx":s.udp_tx.bytes,"udp_bytes_rx":s.udp_rx.bytes,
        "ack_frames_tx":s.frame_tx.acks,"ack_frames_rx":s.frame_rx.acks,
        "datagram_frames_tx":s.frame_tx.datagram,"datagram_frames_rx":s.frame_rx.datagram,
        "ack_frequency_tx":s.frame_tx.ack_frequency,"ack_frequency_rx":s.frame_rx.ack_frequency,
        "immediate_ack_tx":s.frame_tx.immediate_ack,"immediate_ack_rx":s.frame_rx.immediate_ack,
        "lost_packets":s.path.lost_packets,"sent_packets":s.path.sent_packets,
        "cwnd_bytes":s.path.cwnd,"rtt_us":conn.rtt().as_micros()})
}
#[derive(Default, Clone, Serialize)]
struct Sample {
    issued_us: Option<u64>,
    admitted_us: Option<u64>,
    server_received_us: Option<u64>,
    reply_admitted_us: Option<u64>,
    received_us: Option<u64>,
    disposition: Option<&'static str>,
}

/// Whole-run observations after the registered drain, before closing QUIC.
/// Raw packet differences include control traffic and possible snapshot races;
/// they locate an observation boundary, not a physical loss cause.
fn boundary_census(counters: &Value, bulk: &[Sample], echo: &[Sample]) -> Value {
    let bulk_admitted = bulk.iter().filter(|s| s.admitted_us.is_some()).count() as u64;
    let bulk_received = bulk.iter().filter(|s| s.received_us.is_some()).count() as u64;
    let request_admitted = echo.iter().filter(|s| s.admitted_us.is_some()).count() as u64;
    let request_received = echo
        .iter()
        .filter(|s| s.server_received_us.is_some())
        .count() as u64;
    let reply_admitted = echo
        .iter()
        .filter(|s| s.reply_admitted_us.is_some())
        .count() as u64;
    let reply_received = echo.iter().filter(|s| s.received_us.is_some()).count() as u64;
    let mut output = serde_json::Map::new();
    for (name, from, to, link, admitted, received) in [
        (
            "server_to_client",
            "server",
            "client",
            "forward",
            bulk_admitted + reply_admitted,
            bulk_received + reply_received,
        ),
        (
            "client_to_server",
            "client",
            "server",
            "reverse",
            request_admitted,
            request_received,
        ),
    ] {
        let tx = &counters[from];
        let rx = &counters[to];
        let model = &counters[link];
        let n = |v: &Value, field: &str| v[field].as_u64().expect("native u64 counter");
        let delta = |a: u64, b: u64| i128::from(a) - i128::from(b);
        output.insert(name.into(), json!({
            "application_api_admitted":admitted, "application_datagrams_received":received,
            "native_datagram_frames_tx":n(tx,"datagram_frames_tx"),
            "native_datagram_frames_rx":n(rx,"datagram_frames_rx"),
            "api_admitted_not_native_transmitted":delta(admitted,n(tx,"datagram_frames_tx")),
            "native_received_not_read_by_application":delta(n(rx,"datagram_frames_rx"),received),
            "endpoint_udp_tx":n(tx,"udp_packets_tx"),"endpoint_udp_rx":n(rx,"udp_packets_rx"),
            "model_received":n(model,"input_packets"),"model_forwarded":n(model,"forwarded_packets"),
            "observed_endpoint_to_model_packet_gap":delta(n(tx,"udp_packets_tx"),n(model,"input_packets")),
            "observed_model_to_endpoint_packet_gap":delta(n(model,"forwarded_packets"),n(rx,"udp_packets_rx")),
            "model_queue_discards":n(model,"queue_discarded_packets"),
            "scope":"cumulative matched-direction boundaries; packet gaps are diagnostic, not assigned network loss"
        }));
    }
    Value::Object(output)
}
struct Pending {
    seq: usize,
    data: Bytes,
    issued: u64,
}
#[derive(Default, Serialize)]
struct AppStats {
    bulk_generated: usize,
    bulk_admitted: usize,
    bulk_queue_dropped: usize,
    bulk_expired: usize,
    bulk_duplicates: usize,
    request_duplicates: usize,
    response_duplicates: usize,
    reply_queue_dropped: usize,
    reply_expired: usize,
    request_queue_dropped: usize,
    request_expired: usize,
    source_max_lateness_us: u64,
    request_max_lateness_us: u64,
    receive_batches: usize,
    receive_batch_frames: usize,
}

/// Consume only immediately available data, without waiting or enlarging any queue.
/// Quinn removes a datagram only when its read future returns Ready.
async fn ready_datagram(conn: &quinn::Connection) -> Result<Option<Bytes>> {
    let mut read = std::pin::pin!(conn.read_datagram());
    poll_fn(|cx| match read.as_mut().poll(cx) {
        Poll::Ready(result) => Poll::Ready(result.map(Some)),
        Poll::Pending => Poll::Ready(Ok(None)),
    })
    .await
    .map_err(Into::into)
}

/// Unlike a periodic retry, this future is woken when Quinn frees send space.
/// Check expiry before polling the sending operation: a late wake must not
/// silently accept a record whose application lifetime has already ended.
async fn wait_datagram_before(
    conn: &quinn::Connection,
    data: Bytes,
    expires: Instant,
) -> Result<bool> {
    let mut send = std::pin::pin!(conn.send_datagram_wait(data));
    let mut expiry = std::pin::pin!(sleep_until(expires));
    poll_fn(|cx| {
        if Instant::now() >= expires || expiry.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(false));
        }
        send.as_mut().poll(cx).map(|result| result.map(|()| true))
    })
    .await
    .map_err(Into::into)
}

struct ReceiverView<'a> {
    run: &'a [u8; 16],
    epoch: Instant,
    bulk: &'a mut [Sample],
    echo: &'a mut [Sample],
    replies: &'a mut VecDeque<Pending>,
    stats: &'a mut AppStats,
}
impl ReceiverView<'_> {
    fn consume(&mut self, at_server: bool, data: Bytes) -> Result<()> {
        let (kind, seq, stamp) = decode(&data, self.run)?;
        let now = micros(self.epoch);
        if at_server {
            ensure!(
                kind == 1 && seq < self.echo.len() && self.echo[seq].issued_us == Some(stamp),
                "request cohort mismatch"
            );
            if self.echo[seq].server_received_us.is_some() {
                self.stats.request_duplicates += 1;
                return Ok(());
            }
            self.echo[seq].server_received_us = Some(now);
            if self.replies.len() >= 64 {
                self.echo[seq].disposition = Some("reply_queue_full");
                self.stats.reply_queue_dropped += 1;
            } else {
                self.replies.push_back(Pending {
                    seq,
                    data: frame(2, seq as u32, self.run, stamp),
                    issued: now,
                });
            }
        } else if kind == 0 {
            ensure!(
                seq < self.bulk.len() && self.bulk[seq].issued_us == Some(stamp),
                "bulk cohort mismatch"
            );
            if self.bulk[seq].received_us.is_some() {
                self.stats.bulk_duplicates += 1;
            } else {
                self.bulk[seq].received_us = Some(now);
            }
        } else {
            ensure!(
                kind == 2 && seq < self.echo.len() && self.echo[seq].issued_us == Some(stamp),
                "response cohort mismatch"
            );
            if self.echo[seq].received_us.is_some() {
                self.stats.response_duplicates += 1;
            } else {
                self.echo[seq].received_us = Some(now);
            }
        }
        Ok(())
    }
}
fn flush(
    conn: &quinn::Connection,
    queue: &mut VecDeque<Pending>,
    samples: &mut [Sample],
    now: u64,
    reply: bool,
) -> Result<(usize, usize)> {
    let (mut admitted, mut expired) = (0, 0);
    for _ in 0..64 {
        let Some(p) = queue.front() else {
            break;
        };
        if now.saturating_sub(p.issued) >= DEADLINE_US {
            let p = queue.pop_front().unwrap();
            samples[p.seq].disposition = Some(if reply {
                "reply_expired"
            } else {
                "send_expired"
            });
            expired += 1;
            continue;
        }
        if conn.datagram_send_buffer_space() < p.data.len() {
            break;
        }
        let p = queue.pop_front().unwrap();
        conn.send_datagram(p.data)?;
        if reply {
            samples[p.seq].reply_admitted_us = Some(now)
        } else {
            samples[p.seq].admitted_us = Some(now)
        };
        admitted += 1;
    }
    Ok((admitted, expired))
}
fn latency(samples: &[Sample]) -> Value {
    let mut complete: Vec<u64> = samples
        .iter()
        .map(|s| match (s.issued_us, s.received_us) {
            (Some(a), Some(b)) => b.saturating_sub(a),
            _ => u64::MAX,
        })
        .collect();
    complete.sort_unstable();
    let p95 = complete[(complete.len() * 95).div_ceil(100) - 1];
    json!({"population":samples.len(),"received":samples.iter().filter(|s|s.received_us.is_some()).count(),
        "issued":samples.iter().filter(|s|s.issued_us.is_some()).count(),
        "admitted":samples.iter().filter(|s|s.admitted_us.is_some()).count(),
        "seen_at_server":samples.iter().filter(|s|s.server_received_us.is_some()).count(),
        "on_time_200ms":complete.iter().filter(|x|**x<=200_000).count(),
        "on_time_fraction":complete.iter().filter(|x|**x<=200_000).count() as f64/samples.len() as f64,
        "p95_ms":if p95==u64::MAX{None}else{Some(p95 as f64/1000.)},
        "basis":"source application issue to response on one monotonic clock; unsent/missing retained"})
}
async fn measure(
    args: &Args,
    server: &quinn::Connection,
    client: &quinn::Connection,
    reverse: &Arc<Mutex<LinkStats>>,
    forward: &Arc<Mutex<LinkStats>>,
) -> Result<Value> {
    let duration = args.warmup_ms + args.business_ms;
    let count = (duration * u64::from(args.bulk_pps) / 1000) as usize;
    let requests = (duration * u64::from(args.echo_pps) / 1000) as usize;
    let split = (args.warmup_ms * u64::from(args.bulk_pps) / 1000) as usize;
    let esplit = (args.warmup_ms * u64::from(args.echo_pps) / 1000) as usize;
    let mut bulk = vec![Sample::default(); count];
    let mut echo = vec![Sample::default(); requests];
    let mut bq = VecDeque::new();
    let mut rq = VecDeque::new();
    let mut eq = VecDeque::new();
    let mut stats = AppStats::default();
    let mut bs = 0;
    let mut es = 0;
    let mut next_sample = 0;
    let run: [u8; 16] = rand::random();
    let epoch = Instant::now();
    let source_end = epoch + Duration::from_millis(duration);
    let end = source_end + Duration::from_millis(args.drain_ms);
    let mut tick = tokio::time::interval(Duration::from_millis(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut snapshots = Vec::new();
    loop {
        let mut received = None;
        // At most one waiter per endpoint. The queued head is only removed in
        // the branch that completed its send (or expired); all other select
        // branches cancel the waiter and leave the original head unchanged.
        let server_head = rq
            .front()
            .map(|p: &Pending| (true, p.seq, p.data.clone(), p.issued))
            .or_else(|| {
                bq.front()
                    .map(|p: &Pending| (false, p.seq, p.data.clone(), p.issued))
            });
        let client_head = eq
            .front()
            .map(|p: &Pending| (p.seq, p.data.clone(), p.issued));
        tokio::select! {
            _=sleep_until(end)=>break,
            _=tick.tick()=>{
                let now=micros(epoch);
                if bs<count || es<requests {
                    for _ in 0..64 {
                        if bs>=count || bs as u64*1_000_000/u64::from(args.bulk_pps)>now {break;}
                        stats.source_max_lateness_us=stats.source_max_lateness_us.max(now.saturating_sub(bs as u64*1_000_000/u64::from(args.bulk_pps)));
                        bulk[bs].issued_us=Some(now);stats.bulk_generated+=1;
                        if bq.len()>=QUEUE {bulk[bs].disposition=Some("queue_full");stats.bulk_queue_dropped+=1;}
                        else {bq.push_back(Pending{seq:bs,data:frame(0,bs as u32,&run,now),issued:now});}
                        bs+=1;
                    }
                    for _ in 0..4 {
                        if es>=requests || es as u64*1_000_000/u64::from(args.echo_pps)>now {break;}
                        stats.request_max_lateness_us=stats.request_max_lateness_us.max(now.saturating_sub(es as u64*1_000_000/u64::from(args.echo_pps)));
                        echo[es].issued_us=Some(now);
                        if eq.len()>=64 {echo[es].disposition=Some("request_queue_full");stats.request_queue_dropped+=1;}
                        else {eq.push_back(Pending{seq:es,data:frame(1,es as u32,&run,now),issued:now});}
                        es+=1;
                    }
                }
            },
            data=server.read_datagram()=>received=Some((true,data?)),
            data=client.read_datagram()=>received=Some((false,data?)),
            ready=async {
                if let Some((_,_,data,issued))=&server_head {
                    wait_datagram_before(server,data.clone(),epoch+Duration::from_micros(*issued+DEADLINE_US)).await
                } else {std::future::pending::<Result<bool>>().await}
            }=>{
                let sent=ready?;let (reply,seq,_,_)=server_head.unwrap();
                let (queue,samples)=if reply {(&mut rq,&mut echo)} else {(&mut bq,&mut bulk)};
                ensure!(queue.pop_front().is_some_and(|p|p.seq==seq),"readiness head changed");
                let now=micros(epoch);
                if sent {
                    if reply {samples[seq].reply_admitted_us=Some(now);}
                    else {samples[seq].admitted_us=Some(now);stats.bulk_admitted+=1;}
                } else if reply {
                    samples[seq].disposition=Some("reply_expired");stats.reply_expired+=1;
                } else {
                    samples[seq].disposition=Some("send_expired");stats.bulk_expired+=1;
                }
            },
            ready=async {
                if let Some((_,data,issued))=&client_head {
                    wait_datagram_before(client,data.clone(),epoch+Duration::from_micros(*issued+DEADLINE_US)).await
                } else {std::future::pending::<Result<bool>>().await}
            }=>{
                let sent=ready?;let (seq,_,_)=client_head.unwrap();
                ensure!(eq.pop_front().is_some_and(|p|p.seq==seq),"request readiness head changed");
                if sent {echo[seq].admitted_us=Some(micros(epoch));}
                else {echo[seq].disposition=Some("send_expired");stats.request_expired+=1;}
            },
        }
        // The old loop received one datagram, then re-evaluated all send queues.
        // A source burst could outpace that loop and evict already received data.
        // Drain a bounded ready batch first; this adds no storage and no waiting.
        {
            let mut receive = ReceiverView {
                run: &run,
                epoch,
                bulk: &mut bulk,
                echo: &mut echo,
                replies: &mut rq,
                stats: &mut stats,
            };
            let mut frames = 0;
            if let Some((at_server, data)) = received {
                receive.consume(at_server, data)?;
                frames += 1;
            }
            for (at_server, conn) in [(true, server), (false, client)] {
                for _ in 0..64 {
                    let Some(data) = ready_datagram(conn).await? else {
                        break;
                    };
                    receive.consume(at_server, data)?;
                    frames += 1;
                }
            }
            receive.stats.receive_batches += usize::from(frames != 0);
            receive.stats.receive_batch_frames += frames;
        }
        let now = micros(epoch);
        let (_, expired) = flush(client, &mut eq, &mut echo, now, false)?;
        stats.request_expired += expired;
        let (_, expired) = flush(server, &mut rq, &mut echo, now, true)?;
        stats.reply_expired += expired;
        let (admitted, expired) = flush(server, &mut bq, &mut bulk, now, false)?;
        stats.bulk_admitted += admitted;
        stats.bulk_expired += expired;
        if now >= next_sample {
            snapshots.push(
                json!({"elapsed_us":now,"server":native(server),"client":native(client),
                "reverse":reverse.lock().unwrap().clone(),"forward":forward.lock().unwrap().clone(),
                "source_generated":bs,"source_admitted":stats.bulk_admitted,"bulk_queue":bq.len(),
                "request_queue":eq.len(),"reply_queue":rq.len()}),
            );
            next_sample = now + 100_000;
        }
    }
    let final_counters = json!({"elapsed_us":micros(epoch),"server":native(server),"client":native(client),
        "reverse":reverse.lock().unwrap().clone(),"forward":forward.lock().unwrap().clone()});
    let boundary = boundary_census(&final_counters, &bulk, &echo);
    let business = &bulk[split..];
    let delivered = business.iter().filter(|s| s.received_us.is_some()).count();
    let span = match (
        business.first().and_then(|s| s.issued_us),
        business.last().and_then(|s| s.issued_us),
    ) {
        (Some(a), Some(b)) => (b - a) as f64 / 1e6 + 1. / f64::from(args.bulk_pps),
        _ => args.business_ms as f64 / 1000.,
    };
    let generator_complete = bs == count && es == requests;
    let expected_balance =
        stats.bulk_admitted + stats.bulk_queue_dropped + stats.bulk_expired + bq.len();
    ensure!(
        expected_balance == stats.bulk_generated,
        "bulk queue accounting mismatch"
    );
    ensure!(
        stats.bulk_duplicates == 0
            && stats.request_duplicates == 0
            && stats.response_duplicates == 0,
        "duplicate delivery"
    );
    for s in &bulk {
        ensure!(
            s.received_us.is_none() || s.admitted_us.is_some(),
            "delivery without source admission"
        );
    }
    eprintln!("source and drain complete; persisting full finite sample cohorts");
    save(
        &args.output.join("samples.json"),
        &json!({"bulk":bulk,"echo":echo,"bulk_split":split,"echo_split":esplit}),
    )?;
    save(&args.output.join("timeline.json"), &snapshots)?;
    let ack_request_confirmed =
        server.stats().frame_tx.ack_frequency > 0 && client.stats().frame_rx.ack_frequency > 0;
    ensure!(
        client.stats().frame_tx.ack_frequency == 0 && server.stats().frame_rx.ack_frequency == 0,
        "client must not request ACK policy change"
    );
    if args.ack_profile != AckProfile::Unchanged {
        ensure!(ack_request_confirmed, "peer ACK request not observed");
    }
    Ok(
        json!({"business_unique_payload_bytes":delivered*BULK,"business_goodput_mbps":delivered as f64*BULK as f64*8./span/1e6,
        "business_source_span_seconds":span,"business_population":count-split,"business_delivered":delivered,
        "business_delivery_fraction":delivered as f64/(count-split) as f64,"business_echo":latency(&echo[esplit..]),
        "generator_complete":generator_complete,"generator_pacing_fraction":(count-split) as f64/span/f64::from(args.bulk_pps),
        "source_prefix_payload_bytes":split*BULK,"application_counters":stats,"final_counters":final_counters,
        "boundary_census":boundary,"ending_application_queues":{"bulk":bq.len(),"request":eq.len(),"reply":rq.len()},
        "ack_request_confirmed":ack_request_confirmed,"client_ack_request_sent":false,
        "phase_aligned_native_counters":"timeline snapshots; boundary-spanning in-flight packets are not per-source-cohort wire attribution",
        "loopback_only":true,"synthetic_reverse_resource":args.reverse_pps>0,
        "production_gain_proven":false,"native_linux_host_reference":false}),
    )
}
async fn run(args: &Args) -> Result<Value> {
    let identity = args.output.join("identity");
    transport::initialize(&identity, "localhost")?;
    let mut evidence = Vec::new();
    let mut sockets = Vec::new();
    let mut clones = Vec::new();
    for role in [
        "server_endpoint",
        "client_endpoint",
        "relay_front",
        "relay_back",
    ] {
        let (socket, report) =
            lab_socket::bind(role, args.socket_receive_bytes, args.socket_send_bytes)?;
        clones.push(socket.try_clone()?);
        sockets.push(socket);
        evidence.push(report);
    }
    let back = sockets.pop().unwrap();
    let front = sockets.pop().unwrap();
    let front_address = front.local_addr()?;
    let client = make_endpoint(
        &identity,
        false,
        AckProfile::Unchanged,
        sockets.pop().unwrap(),
    )?;
    let server = make_endpoint(&identity, true, args.ack_profile, sockets.pop().unwrap())?;
    for (socket, report) in clones.iter().zip(evidence.iter_mut()) {
        lab_socket::observe(socket, report)?;
    }
    save(&args.output.join("sockets.json"), &evidence)?;
    let reverse = Arc::new(Mutex::new(LinkStats::default()));
    let forward = Arc::new(Mutex::new(LinkStats::default()));
    let (stop, rx) = watch::channel(false);
    let mut jobs = JoinSet::new();
    let delay = Duration::from_millis(args.one_way_delay_ms);
    let limit = Duration::from_millis(args.link_queue_ms);
    let (client_address, server_address) = (client.local_addr()?, server.local_addr()?);
    let reverse_stats = reverse.clone();
    let forward_stats = forward.clone();
    let reverse_pps = args.reverse_pps;
    // Exactly one registration per socket. Both directions share a native
    // adapter in one isolated IO driver instead of registering cloned file
    // descriptions independently in different reactors. A blocked writer keeps
    // its head and polls readiness without suspending the receive side.
    jobs.spawn_blocking(move || -> Result<()> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(async move {
                let front = quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, front)?;
                let back = quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, back)?;
                let a = tokio::spawn(link_loop(
                    front.clone(),
                    back.clone(),
                    client_address,
                    server_address,
                    LinkQueue::new(reverse_pps, delay, limit),
                    reverse_stats,
                    rx.clone(),
                ));
                let b = tokio::spawn(link_loop(
                    back,
                    front,
                    server_address,
                    client_address,
                    LinkQueue::new(0, delay, limit),
                    forward_stats,
                    rx,
                ));
                let (a, b) = tokio::join!(a, b);
                a??;
                b??;
                Ok(())
            })
    });
    let connection = async {
        let connecting = client.connect(front_address, "localhost")?;
        let a = async { connecting.await.map_err(anyhow::Error::from) };
        let b = async {
            server
                .accept()
                .await
                .context("server endpoint closed")?
                .await
                .map_err(anyhow::Error::from)
        };
        let (outgoing, incoming) = tokio::try_join!(a, b)?;
        let token = transport::token(&identity.join("token"))?;
        tokio::try_join!(
            auth(&outgoing, false, &token),
            auth(&incoming, true, &token)
        )?;
        Ok::<_, anyhow::Error>((outgoing, incoming))
    };
    let measured = async {
        let (outgoing, incoming) = timeout(Duration::from_secs(5), connection).await??;
        let value = measure(args, &incoming, &outgoing, &reverse, &forward).await;
        incoming.close(0u32.into(), b"finite lab finished");
        outgoing.close(0u32.into(), b"finite lab finished");
        value
    };
    let value = timeout(Duration::from_secs(30), measured).await;
    let _ = stop.send(true);
    let mut clean = true;
    while let Some(task) = timeout(Duration::from_secs(2), jobs.join_next()).await? {
        if !matches!(task, Ok(Ok(()))) {
            clean = false;
        }
    }
    ensure!(clean, "loopback relay task failed");
    let r = reverse.lock().unwrap().clone();
    let f = forward.lock().unwrap().clone();
    for s in [&r, &f] {
        ensure!(
            s.input_packets
                == s.forwarded_packets + s.queue_discarded_packets + s.shutdown_discarded_packets,
            "relay accounting mismatch"
        );
    }
    save(
        &args.output.join("cleanup.json"),
        &json!({"all_owned_relay_tasks_joined":true,"reverse":r,"forward":f,
        "no_external_processes":true,"no_remote_actions":true}),
    )?;
    let mut result = value??;
    result["socket_evidence"] = serde_json::to_value(evidence)?;
    Ok(result)
}
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let args = Args::parse();
    args.validate()?;
    fs::create_dir_all(&args.output)?;
    save(
        &args.output.join("config.json"),
        &json!({"ack_profile":format!("{:?}",args.ack_profile),
        "requested_ack_tuple":args.ack_profile.request(),"client_profile":"Unchanged","reverse_pps":args.reverse_pps,
        "one_way_delay_ms":args.one_way_delay_ms,"link_queue_ms":args.link_queue_ms,
        "bulk_pps":args.bulk_pps,"bulk_payload_bytes":BULK,"record_overhead_bytes":HEADER,"echo_payload_bytes":ECHO,
        "echo_pps":args.echo_pps,"warmup_ms":args.warmup_ms,"business_ms":args.business_ms,"drain_ms":args.drain_ms,
        "runtime_threads":4,"socket_scope":"127.0.0.1 only, ephemeral ports","source":"native in-process source; no Python data path",
        "relay_runtime_threads":2,"relay_executor_isolation":true,
        "relay_receive_adapter":"native QUIC runtime UDP adapter; bounded 16 slots with GRO metadata",
        "socket_receive_bytes":args.socket_receive_bytes,"quic_application_receive_buffer_bytes":256*1200,
        "socket_send_bytes":args.socket_send_bytes,
        "application_send_buffer_bytes":9600,"application_queue_deadline_us":DEADLINE_US,
        "synthetic_not_public_network":true,"production_policy_changed":false}),
    )?;
    let result = run(&args).await;
    match result {
        Ok(value) => {
            save(&args.output.join("result.json"), &value)?;
            println!(
                "{}",
                json!({
            "goodput_mbps":value["business_goodput_mbps"],"echo":value["business_echo"],"generator_complete":value["generator_complete"],
            "ack_negotiated":value["ack_request_confirmed"]})
            );
            Ok(())
        }
        Err(error) => {
            save(
                &args.output.join("error.json"),
                &json!({"error":error.to_string(),"accepted":false}),
            )?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[derive(Debug, Default)]
    struct BlockOnceSocket {
        attempts: std::sync::atomic::AtomicUsize,
        writes: Mutex<Vec<Vec<u8>>>,
        polls: Arc<std::sync::atomic::AtomicUsize>,
    }
    #[derive(Debug)]
    struct ImmediateWritable(Arc<std::sync::atomic::AtomicUsize>);
    impl quinn::UdpPoller for ImmediateWritable {
        fn poll_writable(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }
    impl quinn::AsyncUdpSocket for BlockOnceSocket {
        fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
            Box::pin(ImmediateWritable(self.polls.clone()))
        }
        fn try_send(&self, packet: &quinn::udp::Transmit<'_>) -> std::io::Result<()> {
            if self
                .attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                == 0
            {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            self.writes.lock().unwrap().push(packet.contents.to_vec());
            Ok(())
        }
        fn poll_recv(
            &self,
            _: &mut std::task::Context<'_>,
            _: &mut [IoSliceMut<'_>],
            _: &mut [quinn::udp::RecvMeta],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok("127.0.0.1:9000".parse().unwrap())
        }
    }
    #[tokio::test]
    async fn blocked_relay_head_is_retained_until_native_write_readiness() {
        let socket = Arc::new(BlockOnceSocket::default());
        let statistics = Arc::new(Mutex::new(LinkStats::default()));
        let mut queue = LinkQueue::new(0, Duration::ZERO, Duration::ZERO);
        queue.offer(
            Instant::now(),
            Bytes::from_static(b"same head after WouldBlock"),
            &mut statistics.lock().unwrap(),
        );
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(link_loop(
            socket.clone(),
            socket.clone(),
            "127.0.0.1:9000".parse().unwrap(),
            "127.0.0.1:9001".parse().unwrap(),
            queue,
            statistics.clone(),
            receiver,
        ));
        timeout(Duration::from_secs(1), async {
            while statistics.lock().unwrap().forwarded_packets == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(
            *socket.writes.lock().unwrap(),
            vec![b"same head after WouldBlock".to_vec()]
        );
        assert!(socket.polls.load(std::sync::atomic::Ordering::Relaxed) > 0);
        let stats = statistics.lock().unwrap();
        assert_eq!(
            (
                stats.input_packets,
                stats.forwarded_packets,
                stats.send_would_block
            ),
            (1, 1, 1)
        );
        assert_eq!(stats.shutdown_discarded_packets, 0);
    }

    #[test]
    fn buffered_evidence_is_complete_and_never_replaces_an_attempt() {
        let temporary = tempfile::tempdir().unwrap();
        let file = temporary.path().join("cohort.json");
        let data = json!({"records":vec![vec![7u8;100];2000],"complete":true});
        save(&file, &data).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&file).unwrap()).unwrap(),
            data
        );
        assert!(save(&file, &json!({"replacement":true})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&file).unwrap()).unwrap(),
            data
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_send_wait_does_not_transmit_or_consume_a_later_record() {
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity");
        transport::initialize(&identity, "localhost").unwrap();
        let server = make_endpoint(
            &identity,
            true,
            AckProfile::EveryTwo,
            lab_socket::bind("expiry-server", 256 * 1024, 0).unwrap().0,
        )
        .unwrap();
        let client = make_endpoint(
            &identity,
            false,
            AckProfile::Unchanged,
            lab_socket::bind("expiry-client", 256 * 1024, 0).unwrap().0,
        )
        .unwrap();
        let (outgoing, incoming) = timeout(Duration::from_secs(3), async {
            tokio::join!(
                client
                    .connect(server.local_addr().unwrap(), "localhost")
                    .unwrap(),
                async { server.accept().await.unwrap().await }
            )
        })
        .await
        .unwrap();
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        let token = transport::token(&identity.join("token")).unwrap();
        let (a, b) = tokio::join!(
            auth(&outgoing, false, &token),
            auth(&incoming, true, &token)
        );
        a.unwrap();
        b.unwrap();
        assert!(
            !wait_datagram_before(
                &outgoing,
                Bytes::from_static(b"expired"),
                Instant::now() - Duration::from_millis(1)
            )
            .await
            .unwrap()
        );
        assert_eq!(outgoing.stats().frame_tx.datagram, 0);
        assert!(
            timeout(Duration::from_millis(30), incoming.read_datagram())
                .await
                .is_err()
        );
        assert!(
            wait_datagram_before(
                &outgoing,
                Bytes::from_static(b"valid next record"),
                Instant::now() + Duration::from_secs(1)
            )
            .await
            .unwrap()
        );
        let payload = timeout(Duration::from_secs(1), incoming.read_datagram())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, Bytes::from_static(b"valid next record"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "hardware-dependent 80Mbps calibration; explicitly run in release and retain failures"]
    async fn calibrated_clean_link_preserves_both_request_and_bulk_cohorts() {
        let temporary = tempfile::tempdir().unwrap();
        let args = Args {
            output: temporary.path().join("clean-reference"),
            ack_profile: AckProfile::EveryTwo,
            reverse_pps: 0,
            one_way_delay_ms: 20,
            link_queue_ms: 20,
            bulk_pps: 10_000,
            echo_pps: 50,
            warmup_ms: 1000,
            business_ms: 2000,
            drain_ms: 1000,
            socket_receive_bytes: 1024 * 1024,
            socket_send_bytes: 256 * 1024,
        };
        args.validate().unwrap();
        fs::create_dir_all(&args.output).unwrap();
        let result = run(&args).await.unwrap();
        eprintln!("clean-reference regression: {result}");
        assert_eq!(result["generator_complete"], true);
        assert!(result["generator_pacing_fraction"].as_f64().unwrap() >= 0.95);
        assert_eq!(result["business_population"], 20_000);
        assert_eq!(result["business_delivered"], 20_000);
        assert_eq!(result["business_echo"]["population"], 100);
        assert_eq!(result["business_echo"]["received"], 100);
        assert_eq!(result["business_echo"]["on_time_200ms"], 100);
        for direction in ["server_to_client", "client_to_server"] {
            let counts = &result["boundary_census"][direction];
            assert_eq!(counts["native_received_not_read_by_application"], 0);
            assert_eq!(counts["api_admitted_not_native_transmitted"], 0);
            assert_eq!(counts["model_queue_discards"], 0);
        }
        let evidence: Vec<Value> =
            serde_json::from_slice(&fs::read(args.output.join("sockets.json")).unwrap()).unwrap();
        assert_eq!(evidence.len(), 4);
        for socket in evidence {
            assert_eq!(socket["requested_headroom_satisfied"], true);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn corrected_queues_preserve_both_ack_profiles_at_functional_load() {
        for profile in [AckProfile::EveryTwo, AckProfile::EveryEight] {
            let temporary = tempfile::tempdir().unwrap();
            let args = Args {
                output: temporary.path().join("functional"),
                ack_profile: profile,
                reverse_pps: 0,
                one_way_delay_ms: 20,
                link_queue_ms: 20,
                bulk_pps: 200,
                echo_pps: 20,
                warmup_ms: 500,
                business_ms: 1000,
                drain_ms: 500,
                socket_receive_bytes: 256 * 1024,
                socket_send_bytes: 0,
            };
            args.validate().unwrap();
            fs::create_dir_all(&args.output).unwrap();
            let result = run(&args).await.unwrap();
            assert_eq!(result["generator_complete"], true, "{result}");
            assert_eq!(result["business_delivered"], 200, "{result}");
            assert_eq!(result["business_echo"]["received"], 20, "{result}");
            assert_eq!(result["business_echo"]["on_time_200ms"], 20, "{result}");
            assert_eq!(result["ack_request_confirmed"], true);
            for direction in ["server_to_client", "client_to_server"] {
                assert_eq!(
                    result["boundary_census"][direction]["native_received_not_read_by_application"],
                    0
                );
                assert_eq!(
                    result["boundary_census"][direction]["api_admitted_not_native_transmitted"],
                    0
                );
            }
            eprintln!("functional {profile:?}: {}", result["business_echo"]);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "host-dependent plaintext 80Mbps reference; not a CI speed requirement"]
    async fn plaintext_relay_reference_preserves_sustained_datagrams() {
        let (source, _) = lab_socket::bind("plain-source", 1024 * 1024, 256 * 1024).unwrap();
        let (middle, _) = lab_socket::bind("plain-relay", 1024 * 1024, 256 * 1024).unwrap();
        let (sink, _) = lab_socket::bind("plain-sink", 1024 * 1024, 256 * 1024).unwrap();
        let source = UdpSocket::from_std(source).unwrap();
        let middle = quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, middle).unwrap();
        let sink = UdpSocket::from_std(sink).unwrap();
        let target = middle.local_addr().unwrap();
        let stats = Arc::new(Mutex::new(LinkStats::default()));
        let (stop, watch) = watch::channel(false);
        let task = tokio::spawn(link_loop(
            middle.clone(),
            middle,
            source.local_addr().unwrap(),
            sink.local_addr().unwrap(),
            LinkQueue::new(0, Duration::from_millis(20), Duration::from_millis(20)),
            stats.clone(),
            watch,
        ));
        let epoch = Instant::now();
        let send = tokio::spawn(async move {
            let mut p = [7u8; 1000];
            for seq in 0..20_000u32 {
                sleep_until(epoch + Duration::from_micros(u64::from(seq) * 100)).await;
                p[..4].copy_from_slice(&seq.to_be_bytes());
                source.send_to(&p, target).await.unwrap();
            }
        });
        let mut seen = vec![false; 20_000];
        let mut received = 0;
        let mut p = [0; 2048];
        let deadline = epoch + Duration::from_secs(3);
        loop {
            tokio::select! {
                _=sleep_until(deadline)=>break,
                value=sink.recv(&mut p)=>{
                    assert_eq!(value.unwrap(),1000);
                    let seq=u32::from_be_bytes(p[..4].try_into().unwrap()) as usize;
                    assert!(seq<20_000 && !seen[seq]);assert!(p[4..1000].iter().all(|b|*b==7));
                    seen[seq]=true;received+=1;if received==20_000 {break;}
                }
            }
        }
        send.await.unwrap();
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        eprintln!(
            "plain reference: received={received}; {}",
            serde_json::to_string(&*stats.lock().unwrap()).unwrap()
        );
        assert_eq!(received, 20_000);
    }

    #[test]
    fn queue_applies_bounded_service_without_credit_on_discard() {
        let now = Instant::now();
        let mut q = LinkQueue::new(1000, Duration::from_millis(20), Duration::from_millis(2));
        q.next_service = now;
        let mut s = LinkStats::default();
        for _ in 0..5 {
            q.offer(now, Bytes::from_static(b"x"), &mut s);
        }
        assert_eq!(
            (s.input_packets, s.queue_discarded_packets, q.queue.len()),
            (5, 2, 3)
        );
        assert_eq!(q.next_service, now + Duration::from_millis(3));
        assert_eq!(
            q.queue.front().unwrap().due,
            now + Duration::from_millis(21)
        );
    }
    #[test]
    fn record_checks_identity_payload_and_kind() {
        let run = [3; 16];
        let p = frame(0, 70, &run, 100);
        assert_eq!(p.len(), 1055);
        assert_eq!(decode(&p, &run).unwrap(), (0, 70, 100));
        assert!(decode(&p, &[2; 16]).is_err());
        let mut wrong = p.to_vec();
        wrong[100] ^= 1;
        assert!(decode(&wrong, &run).is_err());
    }
    #[test]
    fn missing_requests_keep_infinite_tail_and_queue_time_is_counted() {
        let s = Sample {
            issued_us: Some(10),
            admitted_us: Some(200),
            received_us: Some(100_010),
            ..Default::default()
        };
        let value = latency(&[s, Sample::default()]);
        assert_eq!(value["population"], 2);
        assert_eq!(value["on_time_fraction"], 0.5);
        assert!(value["p95_ms"].is_null());
    }

    #[test]
    fn census_separates_api_wire_model_and_application_disappearance() {
        let row = Sample {
            issued_us: Some(0),
            admitted_us: Some(1),
            received_us: Some(9),
            ..Default::default()
        };
        let reply = Sample {
            issued_us: Some(0),
            admitted_us: Some(1),
            server_received_us: Some(3),
            reply_admitted_us: Some(4),
            ..Default::default()
        };
        let value = json!({
            "server":{"udp_packets_tx":10,"udp_packets_rx":8,"datagram_frames_tx":2,"datagram_frames_rx":1},
            "client":{"udp_packets_tx":8,"udp_packets_rx":8,"datagram_frames_tx":1,"datagram_frames_rx":1},
            "forward":{"input_packets":9,"forwarded_packets":9,"queue_discarded_packets":0},
            "reverse":{"input_packets":8,"forwarded_packets":8,"queue_discarded_packets":0}});
        let census = boundary_census(&value, &[row], &[reply]);
        let forward = &census["server_to_client"];
        assert_eq!(forward["api_admitted_not_native_transmitted"], 0);
        assert_eq!(forward["observed_endpoint_to_model_packet_gap"], 1);
        assert_eq!(forward["observed_model_to_endpoint_packet_gap"], 1);
        assert_eq!(forward["native_received_not_read_by_application"], 0);
    }
}
