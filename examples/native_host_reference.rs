//! Finite loopback-only QUIC DATAGRAM reference, NOT a production proxy.
//! Native BBR/TLS and transport buffers are reused; no H3 or adaptive controller.
//! Thin=12B routing/sequence header, matched=55B (uncoded Braid+quality+H3 length).
use anyhow::{Context, Result, ensure};
use braidpath::runtime::{outbound, transport};
use bytes::{Bytes, BytesMut};
use clap::{Parser, ValueEnum};
use quinn::{
    ClientConfig, Endpoint, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufReader, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
    task::JoinSet,
    time::{sleep_until, timeout},
};

const ALPN: &[u8] = b"braidpath-host-reference/1";
const MAX_FLOWS: usize = 16;
const MAX_PAYLOAD: usize = 1000;
const QUEUE: usize = 256;
const DEADLINE: Duration = Duration::from_millis(100);
const RATE: u64 = 500_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Role {
    Server,
    Client,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Frame {
    Thin,
    Matched,
}
#[path = "support/ack_policy.rs"]
mod ack_policy;
use ack_policy::{AckProfile, reference_transport};
impl Frame {
    fn header(self) -> usize {
        match self {
            Self::Thin => 12,
            Self::Matched => 55,
        }
    }
    fn tag(self) -> u8 {
        match self {
            Self::Thin => 0,
            Self::Matched => 1,
        }
    }
}
#[derive(Parser)]
struct Args {
    #[arg(long, value_enum)]
    role: Role,
    #[arg(long)]
    listen: SocketAddr,
    /// Server UDP target or client QUIC entrance, always IPv4 loopback.
    #[arg(long)]
    peer: SocketAddr,
    #[arg(long)]
    identity: PathBuf,
    #[arg(long, value_enum)]
    frame: Frame,
    /// Loopback-only, explicit peer ACK-frequency request. No production default change.
    #[arg(long, value_enum, default_value_t = AckProfile::Unchanged)]
    ack_profile: AckProfile,
    #[arg(long)]
    ready_file: PathBuf,
    #[arg(long)]
    stats_file: PathBuf,
    #[arg(long, default_value_t=60, value_parser=clap::value_parser!(u64).range(10..=90))]
    lifetime_seconds: u64,
}
fn local(address: SocketAddr) -> Result<()> {
    ensure!(
        address.is_ipv4() && address.ip().is_loopback() && address.port() > 0,
        "host reference requires explicit IPv4 loopback addresses"
    );
    Ok(())
}
fn encode(frame: Frame, flow: u32, id: u64, data: &[u8]) -> Result<Bytes> {
    ensure!(
        (1..=MAX_FLOWS as u32).contains(&flow) && data.len() <= MAX_PAYLOAD,
        "invalid reference record"
    );
    let mut b = BytesMut::with_capacity(frame.header() + data.len());
    b.extend_from_slice(&flow.to_be_bytes());
    b.extend_from_slice(&id.to_be_bytes());
    b.resize(frame.header(), 0);
    b.extend_from_slice(data);
    Ok(b.freeze())
}
fn decode(frame: Frame, bytes: Bytes) -> Result<(u32, u64, Bytes)> {
    let h = frame.header();
    ensure!(
        (h..=h + MAX_PAYLOAD).contains(&bytes.len()),
        "bad reference frame length"
    );
    let flow = u32::from_be_bytes(bytes[..4].try_into()?);
    ensure!(
        (1..=MAX_FLOWS as u32).contains(&flow),
        "flow outside finite reference bound"
    );
    ensure!(
        bytes[12..h].iter().all(|v| *v == 0),
        "reference padding changed"
    );
    let id = u64::from_be_bytes(bytes[4..12].try_into()?);
    Ok((flow, id, bytes.slice(h..)))
}
fn write_new(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer(&mut f, value)?;
    writeln!(f)?;
    Ok(())
}
fn endpoint(args: &Args) -> Result<Endpoint> {
    let certs = transport::certificates(&args.identity.join("cert.pem"))?;
    let policy = reference_transport(args.ack_profile);
    if args.role == Role::Server {
        let mut key = BufReader::new(fs::File::open(args.identity.join("key.pem"))?);
        let key = rustls_pemfile::private_key(&mut key)?.context("private key missing")?;
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.max_early_data_size = 0;
        let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
        config.transport_config(Arc::new(policy));
        Ok(Endpoint::server(config, args.listen)?)
    } else {
        let mut roots = rustls::RootCertStore::empty();
        for c in certs {
            roots.add(c)?;
        }
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.enable_early_data = false;
        let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
        config.transport_config(Arc::new(policy));
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
        endpoint.set_default_client_config(config);
        Ok(endpoint)
    }
}
async fn authenticate(
    conn: &quinn::Connection,
    role: Role,
    frame: Frame,
    token: &str,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    if role == Role::Client {
        let (mut tx, mut rx) = conn.open_bi().await?;
        let mut request = vec![b'B', b'R', b'H', 1, frame.tag()];
        request.extend_from_slice(token.as_bytes());
        tx.write_all(&request).await?;
        tx.finish()?;
        let response = rx.read_to_end(4).await?;
        ensure!(response == b"BRok", "reference authentication failed");
        Ok((tx, rx))
    } else {
        let (mut tx, mut rx) = conn.accept_bi().await?;
        let request = rx.read_to_end(69).await?;
        ensure!(
            request.len() == 69
                && request[..5] == [b'B', b'R', b'H', 1, frame.tag()]
                && bool::from(request[5..].ct_eq(token.as_bytes())),
            "reference authentication failed"
        );
        tx.write_all(b"BRok").await?;
        tx.finish()?;
        Ok((tx, rx))
    }
}
#[derive(Default)]
struct Counts {
    udp_received: AtomicU64,
    oversize: AtomicU64,
    flow_full: AtomicU64,
    input_enqueued: AtomicU64,
    input_full: AtomicU64,
    input_shutdown: AtomicU64,
    encoded: AtomicU64,
    queue_full: AtomicU64,
    expired: AtomicU64,
    queued_shutdown: AtomicU64,
    api_admitted: AtomicU64,
    api_bytes: AtomicU64,
    api_error: AtomicU64,
    carrier_received: AtomicU64,
    invalid: AtomicU64,
    target_delivered: AtomicU64,
    target_bytes: AtomicU64,
    target_error: AtomicU64,
    buffer_waits: AtomicU64,
}
fn inc(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}
fn load(a: &AtomicU64) -> u64 {
    a.load(Ordering::Relaxed)
}
impl Counts {
    fn snapshot(&self) -> serde_json::Value {
        json!({"udp_received":load(&self.udp_received),"oversize":load(&self.oversize),
        "flow_full":load(&self.flow_full),"input_enqueued":load(&self.input_enqueued),
        "input_full":load(&self.input_full),"input_shutdown":load(&self.input_shutdown),
        "encoded":load(&self.encoded),"queue_full":load(&self.queue_full),"expired":load(&self.expired),
        "queued_shutdown":load(&self.queued_shutdown),"api_admitted":load(&self.api_admitted),
        "api_bytes":load(&self.api_bytes),"api_error":load(&self.api_error),
        "carrier_received":load(&self.carrier_received),"invalid":load(&self.invalid),
        "target_delivered":load(&self.target_delivered),"target_bytes":load(&self.target_bytes),
        "target_error":load(&self.target_error),"buffer_waits":load(&self.buffer_waits)})
    }
    fn closed(&self) -> bool {
        load(&self.input_enqueued) == load(&self.encoded) + load(&self.input_shutdown)
            && load(&self.encoded)
                == load(&self.queue_full)
                    + load(&self.expired)
                    + load(&self.queued_shutdown)
                    + load(&self.api_admitted)
                    + load(&self.api_error)
            && load(&self.udp_received)
                == load(&self.oversize)
                    + load(&self.flow_full)
                    + load(&self.input_enqueued)
                    + load(&self.input_full)
            && load(&self.carrier_received)
                == load(&self.invalid) + load(&self.target_delivered) + load(&self.target_error)
    }
}
struct Input {
    flow: u32,
    payload: Bytes,
    created: Instant,
}
fn offer(tx: &mpsc::Sender<Input>, flow: u32, bytes: &[u8], stats: &Counts) {
    let item = Input {
        flow,
        payload: Bytes::copy_from_slice(bytes),
        created: Instant::now(),
    };
    if tx.try_send(item).is_ok() {
        inc(&stats.input_enqueued)
    } else {
        inc(&stats.input_full)
    }
}
async fn sender(
    conn: quinn::Connection,
    frame: Frame,
    mut rx: mpsc::Receiver<Input>,
    stats: Arc<Counts>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let epoch = Instant::now();
    let mut sequence = 0u64;
    let mut queue = outbound::Queue::default();
    let mut pacer = outbound::Pacer::for_sender(RATE, 9600);
    let mut tick = tokio::time::interval(Duration::from_millis(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    'running: loop {
        tokio::select! {biased;
            _=stop.changed()=>break,
            _=tick.tick()=>{},
            item=rx.recv()=>{
                let Some(item)=item else {break};inc(&stats.encoded);
                let data=encode(frame,item.flow,sequence,&item.payload)?;
                let pending=outbound::Pending{data,created:item.created,record_id:Some(sequence),
                    flow:Some(item.flow),block:None,small:false,hold:None};sequence+=1;
                if queue.push(pending).is_err(){inc(&stats.queue_full)}
            }
        }
        for _ in 0..32 {
            let Some(front) = queue.front(false).cloned() else {
                break;
            };
            if front.created.elapsed() >= DEADLINE {
                queue.pop(false);
                inc(&stats.expired);
                continue;
            }
            pacer.refill(epoch.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
            let cost = front.data.len() + 80;
            if !pacer.available(cost) {
                break;
            }
            let accepted = if conn.datagram_send_buffer_space() >= front.data.len() {
                conn.send_datagram(front.data.clone())
            } else {
                inc(&stats.buffer_waits);
                let until = tokio::time::Instant::from_std(front.created + DEADLINE);
                tokio::select! {biased;
                    _=stop.changed()=>break 'running,
                    r=tokio::time::timeout_at(until,conn.send_datagram_wait(front.data.clone()))=>{
                        match r {Ok(r)=>r,Err(_)=>{queue.pop(false);inc(&stats.expired);continue;}}
                    }
                }
            };
            queue.pop(false);
            if accepted.is_ok() {
                pacer.spend(cost);
                inc(&stats.api_admitted);
                stats
                    .api_bytes
                    .fetch_add(front.data.len() as u64, Ordering::Relaxed);
            } else {
                inc(&stats.api_error);
            }
        }
    }
    rx.close();
    while rx.try_recv().is_ok() {
        inc(&stats.input_shutdown);
    }
    while queue.pop(false).is_some() {
        inc(&stats.queued_shutdown);
    }
    Ok(())
}
async fn bridge(
    args: &Args,
    conn: quinn::Connection,
    stats: Arc<Counts>,
    stop: watch::Receiver<bool>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel(QUEUE);
    let mut tasks = JoinSet::new();
    let (child_stop_tx, child_stop) = watch::channel(false);
    let send_stats = stats.clone();
    let send_conn = conn.clone();
    let send_stop = child_stop.clone();
    let profile = args.frame;
    let send = tokio::spawn(sender(send_conn, profile, rx, send_stats, send_stop));
    let mut stop = stop;
    let mut buf = [0u8; MAX_PAYLOAD + 1];
    let mut peers = BTreeMap::<SocketAddr, u32>::new();
    let mut reverse = BTreeMap::<u32, SocketAddr>::new();
    let mut targets = BTreeMap::<u32, Arc<UdpSocket>>::new();
    let app = Arc::new(
        UdpSocket::bind(if args.role == Role::Client {
            args.listen
        } else {
            "127.0.0.1:0".parse()?
        })
        .await?,
    );
    if args.role == Role::Client {
        write_new(
            &args.ready_file,
            &json!({"ready":true,"authenticated":true,"pid":std::process::id(),"local_socket":app.local_addr()?.to_string(),"quic_remote":conn.remote_address().to_string()}),
        )?;
    }
    let mut error = None;
    let body: Result<()> = async {
    loop {
        tokio::select! {biased;
            _=stop.changed()=>break,
            received=app.recv_from(&mut buf),if args.role==Role::Client=>{
                let (n,peer)=received?;inc(&stats.udp_received);
                if n>MAX_PAYLOAD {inc(&stats.oversize);continue;}
                let flow=if let Some(id)=peers.get(&peer){*id}else{
                    if peers.len()>=MAX_FLOWS {inc(&stats.flow_full);continue;}
                    let id=peers.len() as u32+1;peers.insert(peer,id);reverse.insert(id,peer);id
                };
                offer(&tx,flow,&buf[..n],&stats);
            },
            result=conn.read_datagram()=>{
                let data=match result {Ok(data)=>data,Err(quinn::ConnectionError::ApplicationClosed(ref e))
                    if e.error_code==0u32.into() && e.reason.as_ref()==b"reference complete"=>break,
                    Err(e)=>{error=Some(e.to_string());break;}};
                inc(&stats.carrier_received);
                let (flow,_,payload)=match decode(profile,data){Ok(v)=>v,Err(_)=>{inc(&stats.invalid);continue;}};
                let sent=if args.role==Role::Client {
                    reverse.get(&flow).is_some_and(|peer|app.try_send_to(&payload,*peer).is_ok())
                }else{
                    if let std::collections::btree_map::Entry::Vacant(entry) = targets.entry(flow) {
                        let socket=Arc::new(UdpSocket::bind("127.0.0.1:0").await?);socket.connect(args.peer).await?;
                        let s=socket.clone();let outgoing=tx.clone();let st=stats.clone();let mut shutdown=child_stop.clone();
                        tasks.spawn(async move {
                            let mut b=[0u8;MAX_PAYLOAD+1];
                            loop {tokio::select! {biased;
                                _=shutdown.changed()=>break,
                                r=s.recv(&mut b)=>{let n=r?;inc(&st.udp_received);
                                    if n>MAX_PAYLOAD{inc(&st.oversize);}else{offer(&outgoing,flow,&b[..n],&st);}}
                            }}
                            Ok::<(),std::io::Error>(())
                        });
                        entry.insert(socket);
                    }
                    targets[&flow].try_send(&payload).is_ok()
                };
                if sent {inc(&stats.target_delivered);stats.target_bytes.fetch_add(payload.len() as u64,Ordering::Relaxed);}else{inc(&stats.target_error);}
            }
        }
    }
    if let Some(e)=error {ensure!(*stop.borrow(),"carrier closed during reference: {e}");}
    Ok(())
    }.await;
    // Release all owned tasks on success, interrupt, connection close or I/O error.
    let _ = child_stop_tx.send(true);
    while let Some(r) = timeout(Duration::from_secs(2), tasks.join_next()).await? {
        r??;
    }
    drop(tx);
    timeout(Duration::from_secs(2), send).await???;
    body
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    local(args.listen)?;
    local(args.peer)?;
    ensure!(
        !args.ready_file.exists() && !args.stats_file.exists(),
        "preserve earlier reference outputs"
    );
    let started = Instant::now();
    let token = transport::token(&args.identity.join("token"))?;
    let endpoint = endpoint(&args)?;
    let mut interrupt = Box::pin(tokio::signal::ctrl_c());
    if args.role == Role::Server {
        write_new(
            &args.ready_file,
            &json!({"ready":true,"phase":"listening","pid":std::process::id()}),
        )?;
    }
    let connect = async {
        let conn = if args.role == Role::Server {
            endpoint.accept().await.context("endpoint closed")?.await?
        } else {
            endpoint.connect(args.peer, "localhost")?.await?
        };
        let control = authenticate(&conn, args.role, args.frame, &token).await?;
        Ok::<_, anyhow::Error>((conn, control))
    };
    let (conn, _control) = timeout(Duration::from_secs(8), connect).await??;
    let stats = Arc::new(Counts::default());
    let (stop_tx, stop) = watch::channel(false);
    let expire =
        tokio::time::Instant::from_std(started + Duration::from_secs(args.lifetime_seconds));
    let mut work = Box::pin(bridge(&args, conn.clone(), stats.clone(), stop));
    let result = tokio::select! {
        r=&mut work=>r,
        _=&mut interrupt=>{let _=stop_tx.send(true);timeout(Duration::from_secs(3),&mut work).await?},
        _=sleep_until(expire)=>{let _=stop_tx.send(true);timeout(Duration::from_secs(3),&mut work).await?}
    };
    drop(work);
    let state = conn.stats();
    conn.close(0u32.into(), b"reference complete");
    let _ = timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    let closed = stats.closed();
    let out = json!({"role":format!("{:?}",args.role).to_lowercase(),"pid":std::process::id(),"final":true,
        "outcome":if result.is_ok() && closed {"ok"}else{"error"},"error":result.as_ref().err().map(ToString::to_string),
        "frame":format!("{:?}",args.frame).to_lowercase(),"framing_bytes":args.frame.header(),
        "ack_profile":format!("{:?}",args.ack_profile),
        "lifetime_seconds":args.lifetime_seconds,"elapsed_seconds":started.elapsed().as_secs_f64(),
        "source_stage_accounting_closed":closed,"counters":stats.snapshot(),
        "quinn":{"udp_bytes_tx":state.udp_tx.bytes,"udp_bytes_rx":state.udp_rx.bytes,
            "sent_packets":state.path.sent_packets,"lost_packets":state.path.lost_packets,"cwnd_bytes":state.path.cwnd,
            "ack_frames_tx":state.frame_tx.acks,"ack_frames_rx":state.frame_rx.acks,
            "datagram_frames_tx":state.frame_tx.datagram,"datagram_frames_rx":state.frame_rx.datagram,
            "ack_frequency_frames_tx":state.frame_tx.ack_frequency,"ack_frequency_frames_rx":state.frame_rx.ack_frequency,
            "immediate_ack_frames_tx":state.frame_tx.immediate_ack,"immediate_ack_frames_rx":state.frame_rx.immediate_ack},
        "limits":{"rate_bps":RATE,"queue":QUEUE,"per_flow":outbound::PER_FLOW_LIMIT,"queue_ms":100,"datagram_send_buffer":9600},
        "scope":"loopback-only minimal carrier reference; matched means length only, not H3/FEC/controller equivalence"});
    write_new(&args.stats_file, &out)?;
    result?;
    ensure!(closed, "reference stage accounting did not close");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn native_pair(
        ack_profile: AckProfile,
    ) -> (
        tempfile::TempDir,
        Endpoint,
        Endpoint,
        quinn::Connection,
        quinn::Connection,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let identity = temp.path().join("identity");
        transport::initialize(&identity, "localhost").unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let make = |role| Args {
            role,
            listen: address,
            peer: address,
            identity: identity.clone(),
            frame: Frame::Matched,
            ack_profile,
            ready_file: temp.path().join("ready.json"),
            stats_file: temp.path().join("stats.json"),
            lifetime_seconds: 30,
        };
        let server = endpoint(&make(Role::Server)).unwrap();
        let client = endpoint(&make(Role::Client)).unwrap();
        let (outgoing, incoming) = timeout(Duration::from_secs(3), async {
            tokio::join!(client.connect(address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await
            })
        })
        .await
        .unwrap();
        (temp, server, client, outgoing.unwrap(), incoming.unwrap())
    }
    #[tokio::test]
    async fn authenticated_real_pair_preserves_payload() {
        let (_temp, _server, _client, outgoing, incoming) =
            native_pair(AckProfile::Unchanged).await;
        let token = "a".repeat(64);
        let (a, b) = timeout(Duration::from_secs(2), async {
            tokio::join!(
                authenticate(&outgoing, Role::Client, Frame::Matched, &token),
                authenticate(&incoming, Role::Server, Frame::Matched, &token)
            )
        })
        .await
        .unwrap();
        a.unwrap();
        b.unwrap();
        outgoing
            .send_datagram(encode(Frame::Matched, 1, 44, b"verified").unwrap())
            .unwrap();
        let packet = timeout(Duration::from_secs(2), incoming.read_datagram())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode(Frame::Matched, packet).unwrap(),
            (1, 44, Bytes::from_static(b"verified"))
        );
    }
    #[tokio::test]
    async fn wrong_token_or_profile_never_authenticates() {
        for wrong_profile in [false, true] {
            let (_temp, _server, _client, outgoing, incoming) =
                native_pair(AckProfile::Unchanged).await;
            let expected = "a".repeat(64);
            let actual = if wrong_profile {
                expected.clone()
            } else {
                "b".repeat(64)
            };
            let (a, b) = timeout(Duration::from_secs(2), async {
                tokio::join!(
                    authenticate(
                        &outgoing,
                        Role::Client,
                        if wrong_profile {
                            Frame::Thin
                        } else {
                            Frame::Matched
                        },
                        &actual
                    ),
                    authenticate(&incoming, Role::Server, Frame::Matched, &expected)
                )
            })
            .await
            .unwrap();
            assert!(a.is_err());
            assert!(b.is_err());
        }
    }
    #[tokio::test]
    async fn bounded_ack_request_is_negotiated_without_changing_default() {
        for profile in [
            AckProfile::Unchanged,
            AckProfile::EveryTwo,
            AckProfile::EveryEight,
        ] {
            let (_temp, _server, _client, outgoing, incoming) = native_pair(profile).await;
            let token = "a".repeat(64);
            let (a, b) = timeout(Duration::from_secs(2), async {
                tokio::join!(
                    authenticate(&outgoing, Role::Client, Frame::Matched, &token),
                    authenticate(&incoming, Role::Server, Frame::Matched, &token)
                )
            })
            .await
            .unwrap();
            a.unwrap();
            b.unwrap();
            for id in 0..8 {
                outgoing
                    .send_datagram(encode(Frame::Matched, 1, id, b"bounded ack test").unwrap())
                    .unwrap();
                let value = timeout(Duration::from_secs(2), incoming.read_datagram())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(decode(Frame::Matched, value).unwrap().1, id);
            }
            if profile != AckProfile::Unchanged {
                timeout(Duration::from_secs(2), async {
                    while outgoing.stats().frame_rx.ack_frequency == 0
                        || incoming.stats().frame_rx.ack_frequency == 0
                    {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("both peers must actually receive the ACK request");
                assert!(outgoing.stats().frame_tx.ack_frequency > 0);
                assert!(incoming.stats().frame_tx.ack_frequency > 0);
            } else {
                assert_eq!(outgoing.stats().frame_tx.ack_frequency, 0);
                assert_eq!(incoming.stats().frame_tx.ack_frequency, 0);
            }
        }
    }
    #[test]
    fn framing_roundtrip_and_same_length_as_real_uncoded_path() {
        use braidpath::runtime::{quality, wire};
        for size in [0, 128, 1000] {
            for frame in [Frame::Thin, Frame::Matched] {
                let p = vec![7; size];
                let encoded = encode(frame, 2, 123, &p).unwrap();
                assert_eq!(encoded.len(), size + frame.header());
                let (flow, id, data) = decode(frame, encoded).unwrap();
                assert_eq!((flow, id), (2, 123));
                assert_eq!(&data[..], &p);
            }
            let r = wire::Record {
                flow: 2,
                id: 123,
                payload: vec![7; size],
            };
            let q = quality::State::new(1);
            let actual = wire::http_datagram(0, &q.wrap(&wire::plain(&r).unwrap(), 0)).unwrap();
            assert_eq!(actual.len(), size + Frame::Matched.header());
        }
    }
    #[test]
    fn illegal_or_mixed_frames_do_not_pass() {
        assert!(encode(Frame::Thin, 0, 0, &[]).is_err());
        assert!(encode(Frame::Thin, 17, 0, &[]).is_err());
        assert!(encode(Frame::Matched, 1, 0, &vec![0; 1001]).is_err());
        assert!(decode(Frame::Matched, Bytes::from_static(b"short")).is_err());
        let mut p = encode(Frame::Matched, 1, 0, &[]).unwrap().to_vec();
        p[12] = 1;
        assert!(decode(Frame::Matched, p.into()).is_err());
    }
    #[test]
    fn public_or_unspecified_bind_is_rejected() {
        for p in [
            "0.0.0.0:7000",
            "192.0.2.1:7000",
            "127.0.0.1:0",
            "[::1]:7000",
        ] {
            assert!(local(p.parse().unwrap()).is_err());
        }
        assert!(local("127.0.0.1:7000".parse().unwrap()).is_ok());
    }
    #[test]
    fn empty_and_complete_dispositions_close_but_unaccounted_do_not() {
        let s = Counts::default();
        assert!(s.closed());
        inc(&s.udp_received);
        assert!(!s.closed());
        inc(&s.input_enqueued);
        inc(&s.encoded);
        inc(&s.api_admitted);
        assert!(s.closed());
        inc(&s.carrier_received);
        inc(&s.target_delivered);
        assert!(s.closed());
    }
}
