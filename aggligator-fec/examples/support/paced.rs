//! Owned test-source thread using reusable batching, pacing and recovery state.
//! Data/redundancy/repairs share one byte budget. No path resets or global changes.
use super::{Config, Frame, Result, data, envelope};
use aggligator_fec::interleave::{InterleavedEncoder, source_sequence};
use aggligator_fec::{
    datagram::{Datagram, try_send_batch},
    pacing::PacingClock,
    recovery::{Feedback, SendWindow},
};
use std::{
    collections::VecDeque,
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::sync::mpsc::UnboundedSender;

pub struct Request {
    pub id: u64,
    pub cfg: Config,
    pub count: usize,
    pub size: usize,
    pub duration: Duration,
    pub paths: Vec<usize>,
    pub peers: Vec<SocketAddr>,
    pub start: Instant,
    pub clock: Instant,
    pub quantum: usize,
    pub wire_mbps: u64,
    pub arq: bool,
    pub primary_path: Option<usize>,
    pub lanes: usize,
}
#[derive(Default)]
pub struct Report {
    pub id: u64,
    pub generated: usize,
    pub sent: u64,
    pub wire: u64,
    pub calls: u64,
    pub path_tx: Vec<u64>,
    pub elapsed: f64,
    pub source_lateness_us: u64,
    pub error: Option<String>,
    pub retransmissions: u64,
    pub control_packets: u64,
    pub max_history: usize,
    pub final_unacked: usize,
}
pub struct Worker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    feedback: mpsc::SyncSender<(Feedback, usize)>,
}
impl Worker {
    pub fn start(socket: UdpSocket, request: Request, done: UnboundedSender<Report>) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let id = request.id;
        let (feedback, rx) = mpsc::sync_channel(128);
        let handle = thread::Builder::new().name("fec-paced-send".into()).spawn(move || {
            let mut report = Report { id, path_tx: vec![0; request.peers.len()], ..Default::default() };
            if let Err(error) = generate(socket, &request, &flag, rx, &mut report) {
                report.error = Some(error.to_string());
            }
            report.elapsed = request.start.elapsed().as_secs_f64();
            let _ = done.send(report);
        })?;
        Ok(Self { stop, handle: Some(handle), feedback })
    }
    /// Bounded mailbox; lost feedback is repeated by the receiver. Never block IO.
    pub fn feedback(&self, value: Feedback, path: usize) {
        let _ = self.feedback.try_send((value, path));
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
struct Queued {
    path: usize,
    packet: Datagram,
    retry: bool,
}
fn push(frames: Vec<Frame>, r: &Request, queue: &mut VecDeque<Queued>, retry_path: Option<usize>) -> Result<()> {
    for frame in frames {
        let logical = match &frame {
            Frame::Source { .. } => source_sequence(&frame, r.lanes)?.unwrap(),
            Frame::Repair { base, data, index, .. } => *base + u64::from(*data) + u64::from(*index),
        };
        let path = if let Some(path) = retry_path {
            path
        } else if let Some(primary) = r.primary_path {
            match &frame {
                Frame::Source { .. } => primary,
                Frame::Repair { block, index, .. } => {
                    let alternatives: Vec<_> = r.paths.iter().copied().filter(|p| *p != primary).collect();
                    if alternatives.is_empty() {
                        primary
                    } else {
                        alternatives[(*block as usize + usize::from(*index)) % alternatives.len()]
                    }
                }
            }
        } else {
            r.paths[logical as usize % r.paths.len()]
        };
        let mut payload = envelope(if retry_path.is_some() { 8 } else { 1 }, r.id, &[]);
        frame.encode_into(&mut payload)?;
        queue.push_back(Queued {
            path,
            packet: Datagram { destination: r.peers[path], payload },
            retry: retry_path.is_some(),
        });
    }
    if queue.len() > 512 {
        return Err("paced send queue exceeded bound".into());
    }
    Ok(())
}
fn wait_until(deadline: Instant, stop: &AtomicBool) -> Result<()> {
    while let Some(wait) = deadline.checked_duration_since(Instant::now()) {
        if stop.load(Ordering::Acquire) {
            return Err("sender cancelled".into());
        }
        thread::sleep(wait.min(Duration::from_millis(1)));
    }
    Ok(())
}
fn generate(
    socket: UdpSocket, r: &Request, stop: &AtomicBool, feedback: mpsc::Receiver<(Feedback, usize)>,
    report: &mut Report,
) -> Result<()> {
    if r.quantum == 0 || r.quantum > 32 || r.primary_path.is_some_and(|p| !r.paths.contains(&p)) {
        return Err("invalid paced quantum or primary path".into());
    }
    let header = if r.peers[0].is_ipv6() { 48 } else { 28 };
    let source_wire = r.size + 26 + 13 + header;
    let average_wire =
        source_wire as f64 + (source_wire + 2) as f64 * r.cfg.repair_shards as f64 / r.cfg.data_shards as f64;
    let bytes_per_second = if r.wire_mbps > 0 {
        r.wire_mbps * 125000
    } else {
        (r.count as f64 / r.duration.as_secs_f64() * average_wire).ceil() as u64
    };
    let mut pacer =
        PacingClock::new(bytes_per_second, Duration::from_micros(250)).ok_or("invalid pacing rate")?;
    let mut encoder = InterleavedEncoder::new(r.cfg.clone(), r.lanes)?;
    let mut queue = VecDeque::new();
    let mut history = SendWindow::new(16384, 32 * 1024 * 1024, Duration::from_millis(100), 20)?;
    let due_base = r.start.duration_since(r.clock).as_micros() as u64;
    let mut finish_sent = None::<Instant>;
    while report.generated < r.count || !queue.is_empty() || (r.arq && !history.is_empty()) {
        if stop.load(Ordering::Acquire) {
            return Err("sender cancelled".into());
        }
        if r.start.elapsed() > r.duration * 3 + Duration::from_secs(5) {
            return Err("paced source/recovery deadline exceeded".into());
        }
        let feedbacks: Vec<_> = feedback.try_iter().take(128).collect();
        for (value, path) in feedbacks {
            if !r.arq || path >= r.peers.len() {
                continue;
            }
            let frames = history.feedback(value, r.clock.elapsed())?;
            push(frames, r, &mut queue, Some(path))?;
        }
        // A wire cap above the mean source+FEC rate permits bounded catch-up,
        // but never generates the entire future application stream early.
        if queue.is_empty() && report.generated < r.count && (!r.arq || history.has_space(r.size)) {
            let due = r.start
                + Duration::from_nanos(
                    (report.generated as u128 * r.duration.as_nanos() / r.count as u128) as u64,
                );
            wait_until(due, stop)?;
        }
        while queue.len() < r.quantum && report.generated < r.count && (!r.arq || history.has_space(r.size)) {
            let seq = report.generated;
            let due = due_base + (seq as u128 * r.duration.as_micros() / r.count.max(1) as u128) as u64;
            report.source_lateness_us =
                report.source_lateness_us.max((r.clock.elapsed().as_micros() as u64).saturating_sub(due));
            let frames = encoder.push(data(seq as u64, due, r.size), r.clock.elapsed())?;
            if r.arq {
                for frame in &frames {
                    if let Some(seq) = source_sequence(frame, r.lanes)? {
                        history.retain_at(seq, frame)?;
                    }
                }
                report.max_history = report.max_history.max(history.len());
            }
            push(frames, r, &mut queue, None)?;
            report.generated += 1;
        }
        push(encoder.poll(r.clock.elapsed())?, r, &mut queue, None)?;
        if report.generated == r.count {
            push(encoder.flush()?, r, &mut queue, None)?;
        }
        if r.arq
            && queue.is_empty()
            && !history.is_empty()
            && (report.generated == r.count || !history.has_space(r.size))
            && finish_sent.is_none_or(|at| at.elapsed() >= Duration::from_millis(50))
        {
            // Repeat the produced extent on a full window as well as EOF.
            // Otherwise a complete blackout could fill history, stop new
            // packets, and prevent the receiver from discovering unseen gaps.
            for path in 0..r.peers.len() {
                queue.push_back(Queued {
                    path,
                    retry: false,
                    packet: Datagram {
                        destination: r.peers[path],
                        payload: envelope(7, r.id, &(report.generated as u64).to_be_bytes()),
                    },
                });
            }
            finish_sent = Some(Instant::now());
        }
        if queue.is_empty() {
            thread::sleep(Duration::from_micros(500));
            continue;
        }
        let mut batch = Vec::with_capacity(r.quantum);
        let mut metadata = Vec::with_capacity(r.quantum);
        for _ in 0..r.quantum {
            let Some(item) = queue.pop_front() else {
                break;
            };
            metadata.push((item.path, item.retry));
            batch.push(item.packet);
        }
        let bytes = batch.iter().map(|p| p.payload.len() + header).sum::<usize>();
        wait_until(r.start + pacer.reserve(r.start.elapsed(), bytes), stop)?;
        let mut offset = 0;
        let retry_deadline = Instant::now() + Duration::from_millis(50);
        while offset < batch.len() {
            if stop.load(Ordering::Acquire) {
                return Err("sender cancelled".into());
            }
            report.calls += 1;
            match try_send_batch(&socket, &batch[offset..]) {
                Ok(0) => return Err("no UDP batch progress".into()),
                Ok(n) => {
                    for i in offset..offset + n {
                        let (path, retry) = metadata[i];
                        if batch[i].payload[4] == 7 {
                            report.control_packets += 1;
                        } else {
                            report.sent += 1;
                            report.path_tx[path] += 1;
                        }
                        if retry {
                            report.retransmissions += 1;
                        }
                        report.wire += (batch[i].payload.len() + header) as u64;
                    }
                    offset += n;
                }
                Err(e)
                    if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) =>
                {
                    if Instant::now() > retry_deadline {
                        return Err("UDP enqueue blocked beyond 50ms budget".into());
                    }
                    thread::sleep(Duration::from_micros(50));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    report.final_unacked = history.len();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as AsyncUdp;
    #[tokio::test]
    async fn complete_blackout_until_history_full_can_recover_without_new_sources() {
        const COUNT: usize = 17000;
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.set_nonblocking(true).unwrap();
        let receiver = AsyncUdp::bind("127.0.0.1:0").await.unwrap();
        let peer = receiver.local_addr().unwrap();
        let now = Instant::now();
        let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
        let request = Request {
            id: 8,
            cfg: Config { data_shards: 8, repair_shards: 0, max_payload: 16, ..Config::default() },
            count: COUNT,
            size: 16,
            duration: Duration::from_millis(250),
            paths: vec![0],
            peers: vec![peer],
            start: now,
            clock: now,
            quantum: 16,
            wire_mbps: 100,
            arq: true,
            primary_path: None,
            lanes: 1,
        };
        let worker = Worker::start(sender, request, done_tx).unwrap();
        let mut decoded = vec![false; COUNT];
        let mut next = 0usize;
        let mut extent = 0usize;
        let mut saw_midstream = false;
        let mut bytes = [0; 1600];
        let mut ticker = tokio::time::interval(Duration::from_millis(10));
        let end = tokio::time::Instant::now() + Duration::from_secs(8);
        let result = loop {
            tokio::select! {
                _=tokio::time::sleep_until(end)=>panic!("blackout left a permanently full send history"),
                Some(report)=done_rx.recv()=>break report,
                _=ticker.tick()=>{
                    if extent==0 {continue;}
                    for base in (next..extent).step_by(64).take(4) {
                        let limit=(base+64).min(extent);let mut missing=0;
                        for (seq,seen) in decoded.iter().enumerate().take(limit).skip(base) {
                            if !seen {missing|=1<<(seq-base);}
                        }
                        worker.feedback(Feedback {next:next as u64,base:base as u64,limit:limit as u64,missing},0);
                    }
                    if next==COUNT {worker.feedback(Feedback {next:COUNT as u64,base:COUNT as u64,limit:COUNT as u64,missing:0},0);}
                },
                n=receiver.recv(&mut bytes)=>{
                    let n=n.unwrap();let Some((kind,_,body))=super::super::parse(&bytes[..n]) else{continue;};
                    if kind==7 {
                        let advertised=u64::from_be_bytes(body.try_into().unwrap()) as usize;
                        if advertised<COUNT {saw_midstream=true;}extent=extent.max(advertised);continue;
                    }
                    let Frame::Source {base,index,payload,..}=Frame::decode(body,16).unwrap() else{continue;};
                    if extent==0 {continue;}
                    let seq=(base+u64::from(index)) as usize;
                    assert!(super::super::validate_data(seq as u64,&payload,16));decoded[seq]=true;
                    extent=extent.max(seq+1);while next<COUNT&&decoded[next]{next+=1;}
                },
            }
        };
        assert!(result.error.is_none(), "{:?}", result.error);
        assert!(saw_midstream);
        assert_eq!(result.max_history, 16384);
        assert_eq!(next, COUNT);
        assert_eq!(result.final_unacked, 0);
        drop(worker);
    }
    #[tokio::test]
    async fn selective_retry_recovers_lost_sources_and_tail_with_ack_loss() {
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.set_nonblocking(true).unwrap();
        let receiver = AsyncUdp::bind("127.0.0.1:0").await.unwrap();
        let peer = receiver.local_addr().unwrap();
        let now = Instant::now();
        let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
        let request = Request {
            id: 7,
            cfg: Config { data_shards: 8, repair_shards: 0, ..Config::default() },
            count: 128,
            size: 1000,
            duration: Duration::from_millis(100),
            paths: vec![0],
            peers: vec![peer],
            start: now,
            clock: now,
            quantum: 8,
            wire_mbps: 20,
            arq: true,
            primary_path: None,
            lanes: 1,
        };
        let worker = Worker::start(sender, request, done_tx).unwrap();
        let mut decoded = [false; 128];
        let mut next = 0usize;
        let mut final_seen = false;
        let mut dropped_feedback = false;
        let mut bytes = [0; 1600];
        let mut ticker = tokio::time::interval(Duration::from_millis(10));
        let end = tokio::time::Instant::now() + Duration::from_secs(3);
        let result = loop {
            tokio::select! {
                _=tokio::time::sleep_until(end)=>panic!("reliable worker did not recover tail"),
                Some(report)=done_rx.recv()=>break report,
                _=ticker.tick()=>{
                    if !final_seen {continue;}
                    // Lose the first whole feedback cycle as well.
                    if !dropped_feedback {dropped_feedback=true;continue;}
                    for base in (next..128).step_by(64) {
                        let limit=(base+64).min(128);let mut missing=0;
                        for (seq,seen) in decoded.iter().enumerate().take(limit).skip(base) {
                            if !seen {missing|=1<<(seq-base);}
                        }
                        worker.feedback(Feedback {next:next as u64,base:base as u64,limit:limit as u64,missing},0);
                    }
                    if next==128 {worker.feedback(Feedback {next:128,base:128,limit:128,missing:0},0);}
                },
                n=receiver.recv(&mut bytes)=>{
                    let n=n.unwrap();let Some((kind,_,body))=super::super::parse(&bytes[..n]) else{continue;};
                    if kind==7 {final_seen=true;continue;}
                    let Frame::Source {base,index,payload,..}=Frame::decode(body,1100).unwrap() else{continue;};
                    let seq=(base+u64::from(index)) as usize;
                    if kind==1 && matches!(seq,0|1|33|65|127) {continue;}
                    assert!(super::super::validate_data(seq as u64,&payload,1000));decoded[seq]=true;
                    while next<128&&decoded[next]{next+=1;}
                },
            }
        };
        assert!(result.error.is_none(), "{:?}", result.error);
        assert_eq!(next, 128);
        assert_eq!(result.final_unacked, 0);
        assert!(result.retransmissions >= 5);
        drop(worker);
    }
}
