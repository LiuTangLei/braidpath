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
    io::{BufReader, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    net::UdpSocket,
    sync::watch,
    task::JoinSet,
    time::{Instant, MissedTickBehavior, sleep_until, timeout},
};
#[path = "support/ack_policy.rs"]
mod ack_policy;
use ack_policy::{AckProfile, reference_transport};

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
}
impl Args {
    fn validate(&self) -> Result<()> {
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
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer(&mut file, value)?;
    writeln!(file)?;
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
    input: Arc<UdpSocket>,
    output: Arc<UdpSocket>,
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
    let mut b = [0u8; 2048];
    loop {
        let due = queue.queue.front().map(|p| p.due);
        tokio::select! {
            _=stop.changed()=>break,
            r=input.recv_from(&mut b)=>{
                let (n,from)=r?;
                if from!=allowed {stats.lock().unwrap().foreign_packets+=1;continue;}
                ensure!(n<b.len(),"oversized or truncated UDP packet");
                queue.offer(Instant::now(),Bytes::copy_from_slice(&b[..n]),&mut stats.lock().unwrap());
            },
            _=async {if let Some(t)=due {sleep_until(t).await}else{std::future::pending::<()>().await}}=>{
                for _ in 0..64 {
                    if queue.queue.front().is_none_or(|p|p.due>Instant::now()) {break;}
                    let p=queue.queue.pop_front().unwrap();
                    let late=Instant::now().saturating_duration_since(p.due).as_micros() as u64;
                    let n=output.send_to(&p.data,destination).await?;
                    ensure!(n==p.data.len(),"short relay send");
                    let mut s=stats.lock().unwrap();s.forwarded_packets+=1;s.forwarded_bytes+=n as u64;
                    s.maximum_timer_lateness_us=s.maximum_timer_lateness_us.max(late);
                }
            }
        }
    }
    stats.lock().unwrap().shutdown_discarded_packets += queue.queue.len() as u64;
    Ok(())
}
fn make_endpoint(identity: &Path, server: bool, profile: AckProfile) -> Result<Endpoint> {
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
        Ok(Endpoint::server(config, "127.0.0.1:0".parse()?)?)
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
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
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
        tokio::select! {
            _=sleep_until(end)=>break,
            _=tick.tick()=>{
                let now=micros(epoch);
                if bs<count || es<requests {
                    for _ in 0..64 {
                        if bs>=count || bs as u64*1_000_000/u64::from(args.bulk_pps)>now {break;}
                        bulk[bs].issued_us=Some(now);stats.bulk_generated+=1;
                        if bq.len()>=QUEUE {bulk[bs].disposition=Some("queue_full");stats.bulk_queue_dropped+=1;}
                        else {bq.push_back(Pending{seq:bs,data:frame(0,bs as u32,&run,now),issued:now});}
                        bs+=1;
                    }
                    for _ in 0..4 {
                        if es>=requests || es as u64*1_000_000/u64::from(args.echo_pps)>now {break;}
                        echo[es].issued_us=Some(now);
                        if eq.len()>=64 {echo[es].disposition=Some("request_queue_full");stats.request_queue_dropped+=1;}
                        else {eq.push_back(Pending{seq:es,data:frame(1,es as u32,&run,now),issued:now});}
                        es+=1;
                    }
                }
            },
            data=server.read_datagram()=>{
                let data=data?;let (kind,seq,stamp)=decode(&data,&run)?;
                ensure!(kind==1 && seq<echo.len() && echo[seq].issued_us==Some(stamp),"request cohort mismatch");
                if echo[seq].server_received_us.is_some(){stats.request_duplicates+=1;continue;}
                let now=micros(epoch);echo[seq].server_received_us=Some(now);
                if rq.len()>=64 {echo[seq].disposition=Some("reply_queue_full");stats.reply_queue_dropped+=1;}
                else {rq.push_back(Pending{seq,data:frame(2,seq as u32,&run,stamp),issued:now});}
            },
            data=client.read_datagram()=>{
                let data=data?;let (kind,seq,stamp)=decode(&data,&run)?;
                let now=micros(epoch);
                if kind==0 {
                    ensure!(seq<bulk.len() && bulk[seq].issued_us==Some(stamp),"bulk cohort mismatch");
                    if bulk[seq].received_us.is_some(){stats.bulk_duplicates+=1;}else{bulk[seq].received_us=Some(now);}
                }else{
                    ensure!(kind==2 && seq<echo.len() && echo[seq].issued_us==Some(stamp),"response cohort mismatch");
                    if echo[seq].received_us.is_some(){stats.response_duplicates+=1;}else{echo[seq].received_us=Some(now);}
                }
            }
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
        "ack_request_confirmed":ack_request_confirmed,"client_ack_request_sent":false,
        "phase_aligned_native_counters":"timeline snapshots; boundary-spanning in-flight packets are not per-source-cohort wire attribution",
        "loopback_only":true,"synthetic_reverse_resource":args.reverse_pps>0,
        "production_gain_proven":false,"native_linux_host_reference":false}),
    )
}
async fn run(args: &Args) -> Result<Value> {
    let identity = args.output.join("identity");
    transport::initialize(&identity, "localhost")?;
    let server = make_endpoint(&identity, true, args.ack_profile)?;
    let client = make_endpoint(&identity, false, AckProfile::Unchanged)?;
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let reverse = Arc::new(Mutex::new(LinkStats::default()));
    let forward = Arc::new(Mutex::new(LinkStats::default()));
    let (stop, rx) = watch::channel(false);
    let mut jobs = JoinSet::new();
    let delay = Duration::from_millis(args.one_way_delay_ms);
    let limit = Duration::from_millis(args.link_queue_ms);
    jobs.spawn(link_loop(
        front.clone(),
        back.clone(),
        client.local_addr()?,
        server.local_addr()?,
        LinkQueue::new(args.reverse_pps, delay, limit),
        reverse.clone(),
        rx.clone(),
    ));
    jobs.spawn(link_loop(
        back.clone(),
        front.clone(),
        server.local_addr()?,
        client.local_addr()?,
        LinkQueue::new(0, delay, limit),
        forward.clone(),
        rx,
    ));
    let connection = async {
        let connecting = client.connect(front.local_addr()?, "localhost")?;
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
    value?
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
}
