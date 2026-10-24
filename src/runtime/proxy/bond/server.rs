use super::super::protocol::{Address, ReplyError};
use super::*;
use std::future::Future;
use tokio::{
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::OnceCell,
};

/// The shared host budget is exhausted for a record that can safely wait.
#[derive(Debug)]
struct Busy;
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("aggregate host buffer busy")
    }
}
impl std::error::Error for Busy {}

pub(crate) struct Registry {
    flows: Mutex<BTreeMap<Key, Arc<Flow>>>,
    upstream: Arc<Semaphore>,
    downstream: Arc<Semaphore>,
    reaper: Mutex<Option<AbortTask>>,
}
impl Registry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            flows: Mutex::new(BTreeMap::new()),
            upstream: Arc::new(Semaphore::new(HOST_BUFFER)),
            downstream: Arc::new(Semaphore::new(HOST_BUFFER)),
            reaper: Mutex::new(None),
        })
    }
    pub(crate) fn snapshot(&self) -> (usize, usize) {
        let flows = self.flows.lock().expect("bond registry");
        let reserved: usize = flows.values().map(|flow| flow.reserved()).sum();
        (
            flows.len(),
            HOST_BUFFER * 2 + reserved
                - self.upstream.available_permits()
                - self.downstream.available_permits(),
        )
    }
    pub(crate) fn owns_connection(&self, id: usize) -> bool {
        self.flows
            .lock()
            .expect("bond registry")
            .values()
            .any(|flow| {
                flow.owners
                    .lock()
                    .expect("flow paths")
                    .iter()
                    .any(|c| c.stable_id() == id)
            })
    }
    fn start_reaper(self: &Arc<Self>) {
        let mut task = self.reaper.lock().expect("bond reaper");
        if task.is_some() {
            return;
        }
        let weak = Arc::downgrade(self);
        *task = Some(AbortTask(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(registry) = weak.upgrade() else {
                    break;
                };
                registry.reap(Instant::now());
            }
        })));
    }
    fn remove(&self, key: &Key) {
        let flow = self.flows.lock().expect("bond registry").remove(key);
        if let Some(flow) = flow {
            flow.close();
        }
    }
    pub(super) fn reap(&self, now: Instant) {
        let mut flows = self.flows.lock().expect("bond registry");
        flows.retain(|_, flow| {
            let idle = now
                .saturating_duration_since(*flow.signal.activity.lock().expect("flow activity"))
                >= IDLE_TIMEOUT;
            let dead = flow
                .owners
                .lock()
                .expect("flow paths")
                .iter()
                .all(|c| c.close_reason().is_some());
            let abandoned = {
                let mut since = flow.unreachable.lock().expect("flow unreachable");
                if dead {
                    now.saturating_duration_since(*since.get_or_insert(now)) >= RESUME_GRACE
                } else {
                    *since = None;
                    false
                }
            };
            let retain = !idle && !abandoned && !flow.signal.closed.load(Ordering::Acquire);
            if !retain {
                flow.close();
            }
            retain
        });
    }
    // Charge the bytes actually held. The record at the delivery cursor drains
    // every later one, so it never waits behind them for shared memory; any
    // other record is declined as busy and retried by the client.
    fn upload_credit(
        &self,
        flow: &Flow,
        sequence: u64,
        len: usize,
    ) -> Result<OwnedSemaphorePermit, Busy> {
        match self.upstream.clone().try_acquire_many_owned(len as u32) {
            Ok(permit) => Ok(permit),
            Err(_) if sequence <= flow.upload.cursor() => flow
                .upload_reserve
                .clone()
                .try_acquire_many_owned(len as u32)
                .map_err(|_| Busy),
            Err(_) => Err(Busy),
        }
    }
    fn find(&self, key: &Key, conn: &quinn::Connection) -> Result<Arc<Flow>> {
        let flow = self
            .flows
            .lock()
            .expect("bond registry")
            .get(key)
            .cloned()
            .context("unknown aggregate TCP flow")?;
        flow.observe(conn);
        flow.signal.check()?;
        Ok(flow)
    }
    async fn open(
        self: &Arc<Self>,
        key: Key,
        target: Address,
        conn: &quinn::Connection,
        allow_private: bool,
        rate: Arc<Rate>,
    ) -> Result<Reply> {
        self.start_reaper();
        let flow = {
            let mut flows = self.flows.lock().expect("bond registry");
            if let Some(flow) = flows.get(&key) {
                ensure!(flow.target == target, "aggregate target changed");
                flow.clone()
            } else {
                ensure!(flows.len() < MAX_FLOWS, "aggregate flow limit");
                let flow = Arc::new(Flow::new(target, Arc::new(Signal::new())));
                flows.insert(key, flow.clone());
                flow
            }
        };
        flow.observe(conn);
        let result = flow
            .bound
            .get_or_try_init(|| async {
                let addresses = flow.target.resolve(allow_private).await?;
                let tcp =
                    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addresses.as_slice()))
                        .await??;
                tcp.set_nodelay(true)?;
                let bound = tcp.local_addr()?;
                let (read, write) = tcp.into_split();
                let (upload, download, signal, budget, reserve) = (
                    flow.upload.clone(),
                    flow.download.clone(),
                    flow.signal.clone(),
                    self.downstream.clone(),
                    flow.download_reserve.clone(),
                );
                *flow.engine.lock().expect("bond engine") =
                    Some(AbortTask(tokio::spawn(async move {
                        if let Err(error) = tokio::try_join!(
                            upload.write_to(write, rate.clone()),
                            download.read_from(read, budget, reserve, rate)
                        ) {
                            tracing::debug!(%error, "aggregate TCP target closed");
                            signal.close();
                        }
                    })));
                Ok::<_, anyhow::Error>(bound)
            })
            .await;
        match result {
            Ok(bound) => Ok(Reply::Opened(*bound)),
            Err(error) => {
                self.remove(&key);
                Ok(Reply::Failed(
                    error.downcast_ref::<ReplyError>().map_or(4, |e| e.0),
                ))
            }
        }
    }
    pub(crate) async fn serve(
        self: &Arc<Self>,
        command: u8,
        conn: &quinn::Connection,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        allow_private: bool,
        rate: Arc<Rate>,
    ) -> Result<()> {
        let mut key = [0; 32];
        let parsed = tokio::time::timeout(CONNECT_TIMEOUT, async {
            recv.read_exact(&mut key).await?;
            let flow = if command != OPEN && command != CLOSE { Some(self.find(&key, conn)?) } else { None };
            let mut credit = None;
            let op = match command {
                OPEN => Operation::Open(Address::read(recv).await?),
                PUT => {
                    let owner = flow.as_ref().expect("upload flow");
                    let sequence = recv.read_u64().await?;
                    let offset = recv.read_u64().await?;
                    let len = recv.read_u32().await? as usize;
                    ensure!(len > 0 && len <= CHUNK, "invalid upload chunk");
                    let permit = self.upload_credit(owner, sequence, len)?;
                    let receive = async {
                        let mut data = vec![0; len];
                        recv.read_exact(&mut data).await?;
                        Ok::<_, anyhow::Error>(data)
                    };
                    let data = tokio::select! {
                        result = receive => result?,
                        _ = owner.signal.cancelled() => anyhow::bail!("upload flow closed during ingress"),
                    };
                    credit = Some(permit);
                    Operation::Put {
                        sequence,
                        offset,
                        data: data.into(),
                    }
                }
                PULL => Operation::Pull {
                    sequence: recv.read_u64().await?,
                    acknowledged: recv.read_u64().await?,
                    count: recv.read_u8().await?,
                },
                FIN => Operation::Fin {
                    sequence: recv.read_u64().await?,
                    offset: recv.read_u64().await?,
                },
                ACK_FIN => Operation::AckFin {
                    sequence: recv.read_u64().await?,
                    offset: recv.read_u64().await?,
                },
                UPLOAD_STATUS => Operation::UploadStatus { delivered: recv.read_u64().await? },
                DOWNLOAD_ACK => Operation::DownloadAck { acknowledged: recv.read_u64().await? },
                CLOSE => Operation::Close,
                _ => anyhow::bail!("invalid aggregate command"),
            };
            wire::eof(recv).await?;
            Ok::<_, anyhow::Error>((op, credit, flow))
        })
        .await?;
        let (op, credit, flow) = match parsed {
            Ok(parsed) => parsed,
            Err(error) if error.is::<Busy>() => {
                // Decline the unread body; the client retries without
                // treating this path as failed.
                let _ = recv.stop(0u32.into());
                return wire::respond(send, Reply::Failed(BUSY)).await;
            }
            Err(error) => {
                tracing::debug!(%error, "aggregate request rejected");
                return wire::respond(send, Reply::Failed(1)).await;
            }
        };
        if let Operation::Pull {
            sequence,
            acknowledged,
            count,
        } = op
        {
            return serve_lane(
                flow.expect("validated download flow"),
                send,
                sequence,
                acknowledged,
                count,
            )
            .await;
        }
        let work = async {
            match op {
                Operation::Open(target) => self.open(key, target, conn, allow_private, rate).await,
                Operation::Close => {
                    self.remove(&key);
                    Ok(Reply::Accepted)
                }
                other => {
                    let flow = flow.expect("aggregate flow validated before ingress");
                    match other {
                        Operation::Put {
                            sequence,
                            offset,
                            data,
                        } => {
                            let delivered = flow
                                .upload
                                .insert(
                                    sequence,
                                    Input::Data(Arc::new(Block {
                                        sequence,
                                        offset,
                                        data,
                                        _credit: credit.expect("upload credit"),
                                    })),
                                )
                                .await?;
                            Ok(Reply::Uploaded { delivered })
                        }
                        Operation::UploadStatus { delivered } => Ok(Reply::Uploaded {
                            delivered: flow.upload.status(delivered).await?,
                        }),
                        Operation::DownloadAck { acknowledged } => {
                            flow.download.acknowledge(acknowledged)?;
                            Ok(Reply::Accepted)
                        }
                        Operation::Fin { sequence, offset } => {
                            flow.upload.insert(sequence, Input::Fin(offset)).await?;
                            Ok(Reply::Accepted)
                        }
                        Operation::AckFin { sequence, offset } => {
                            flow.download.ack_fin(sequence, offset)?;
                            Ok(Reply::Accepted)
                        }
                        _ => unreachable!(),
                    }
                }
            }
        };
        let reply = wait_response(send, work).await?;
        wire::respond(send, reply).await
    }
}

fn lane_parameters(count: u8) -> Result<()> {
    ensure!(
        count > 0 && count as usize <= MAX_BATCH,
        "invalid download lane"
    );
    Ok(())
}
// One contiguous record range. The client assigns ranges to paths by expected
// arrival, so a slow path never owns a fixed share of the sequence space.
async fn serve_lane(
    flow: Arc<Flow>,
    send: &mut quinn::SendStream,
    sequence: u64,
    acknowledged: u64,
    count: u8,
) -> Result<()> {
    lane_parameters(count)?;
    send.write_all(&[1, 2, count]).await?;
    let (start, end) = (
        sequence,
        sequence
            .checked_add(count as u64)
            .context("download sequence overflow")?,
    );
    let mut sequence = start;
    while sequence < end {
        let index = (sequence - start) as u8;
        let work = flow.download.next(sequence, acknowledged);
        tokio::pin!(work);
        let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
        let ready = loop {
            tokio::select! {
                result=&mut work=>break result,
                _=send.stopped()=>anyhow::bail!("download lane cancelled"),
                _=heartbeat.tick()=>send.write_all(&[0]).await?,
            }
        };
        match ready {
            Ok(Read::Data(block)) => {
                let (hint, produced) = flow.download.ready(sequence, (count - index) as usize);
                let mut header = vec![1, hint.max(1) as u8];
                header.extend(produced.to_be_bytes());
                header.extend(sequence.to_be_bytes());
                header.extend(block.offset.to_be_bytes());
                header.extend((block.data.len() as u32).to_be_bytes());
                send.write_all(&header).await?;
                send.write_all(&block.data).await?;
                sequence += 1;
            }
            // A replayed range overlaps records another request delivered.
            Ok(Read::Skip(acknowledged)) => {
                sequence = acknowledged.min(end);
                let mut header = vec![4];
                header.extend(sequence.to_be_bytes());
                send.write_all(&header).await?;
            }
            Ok(Read::End(sequence, offset)) => {
                let mut header = vec![2];
                header.extend(sequence.to_be_bytes());
                header.extend(offset.to_be_bytes());
                send.write_all(&header).await?;
                send.finish()?;
                return Ok(());
            }
            Err(error) => {
                tracing::debug!(error=?error,"download lane rejected");
                send.write_all(&[3, 1]).await?;
                send.finish()?;
                return Ok(());
            }
        }
    }
    send.finish()?;
    Ok(())
}

async fn wait_response(
    send: &mut quinn::SendStream,
    work: impl Future<Output = Result<Reply>>,
) -> Result<Reply> {
    tokio::pin!(work);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            result = &mut work => return Ok(match result { Ok(reply) => reply, Err(error) => { tracing::debug!(error=?error, "aggregate operation rejected"); Reply::Failed(1) } }),
            _ = send.stopped() => anyhow::bail!("aggregate request cancelled"),
            _ = heartbeat.tick() => { send.write_all(&[0]).await?; }
        }
    }
}

struct Flow {
    target: Address,
    bound: OnceCell<SocketAddr>,
    signal: Arc<Signal>,
    upload: Arc<Upload>,
    download: Arc<Download>,
    // One record per direction outside the shared host budget, so a flow whose
    // consumer stalls cannot stop every other flow from making progress.
    upload_reserve: Arc<Semaphore>,
    download_reserve: Arc<Semaphore>,
    engine: Mutex<Option<AbortTask>>,
    owners: Mutex<Vec<quinn::Connection>>,
    unreachable: Mutex<Option<Instant>>,
}
impl Flow {
    fn new(target: Address, signal: Arc<Signal>) -> Self {
        Self {
            target,
            bound: OnceCell::new(),
            upload: Arc::new(Upload::new(signal.clone())),
            download: Arc::new(Download::new(signal.clone())),
            signal,
            upload_reserve: Arc::new(Semaphore::new(CHUNK)),
            download_reserve: Arc::new(Semaphore::new(CHUNK)),
            engine: Mutex::new(None),
            owners: Mutex::new(Vec::new()),
            unreachable: Mutex::new(None),
        }
    }
    fn reserved(&self) -> usize {
        CHUNK * 2
            - self.upload_reserve.available_permits()
            - self.download_reserve.available_permits()
    }
    fn observe(&self, conn: &quinn::Connection) {
        let mut owners = self.owners.lock().expect("flow paths");
        owners.retain(|c| c.close_reason().is_none());
        if !owners.iter().any(|c| c.stable_id() == conn.stable_id()) {
            owners.push(conn.clone());
        }
        *self.unreachable.lock().expect("flow unreachable") = None;
        self.signal.touch();
    }
    fn close(&self) {
        self.signal.close();
        self.engine.lock().expect("bond engine").take();
    }
}

enum Input {
    Data(Arc<Block>),
    Fin(u64),
}
struct UploadState {
    sequence: u64,
    offset: u64,
    pending: BTreeMap<u64, Input>,
    finished: bool,
}
struct Upload {
    signal: Arc<Signal>,
    state: Mutex<UploadState>,
}
impl Upload {
    fn new(signal: Arc<Signal>) -> Self {
        Self {
            signal,
            state: Mutex::new(UploadState {
                sequence: 0,
                offset: 0,
                pending: BTreeMap::new(),
                finished: false,
            }),
        }
    }
    async fn insert(&self, sequence: u64, input: Input) -> Result<u64> {
        let finish = matches!(&input, Input::Fin(_));
        {
            let mut state = self.state.lock().expect("upload state");
            self.signal.check()?;
            if sequence < state.sequence {
                return Ok(state.sequence);
            }
            ensure!(
                !state.finished
                    && (sequence < state.sequence.saturating_add(PIPELINE as u64)
                        || (finish && sequence == state.sequence.saturating_add(PIPELINE as u64))),
                "upload record credit exceeded"
            );
            let offset = match &input {
                Input::Data(b) => b.offset,
                Input::Fin(offset) => *offset,
            };
            ensure!(
                offset >= state.offset && offset <= state.offset.saturating_add(WINDOW as u64),
                "upload byte credit exceeded"
            );
            if let Some(existing) = state.pending.get(&sequence) {
                let same = match (existing, &input) {
                    (Input::Data(a), Input::Data(b)) => a.offset == b.offset && a.data == b.data,
                    (Input::Fin(a), Input::Fin(b)) => a == b,
                    _ => false,
                };
                ensure!(same, "conflicting replayed upload");
            } else {
                state.pending.insert(sequence, input);
            }
        }
        self.signal.changed.notify_waiters();
        if finish {
            self.status(sequence).await
        } else {
            Ok(self.state.lock().expect("upload state").sequence)
        }
    }
    fn cursor(&self) -> u64 {
        self.state.lock().expect("upload state").sequence
    }
    async fn status(&self, known: u64) -> Result<u64> {
        loop {
            let changed = self.signal.changed.notified();
            self.signal.check()?;
            {
                let state = self.state.lock().expect("upload state");
                ensure!(
                    known <= state.sequence.saturating_add(PIPELINE as u64),
                    "invalid upload progress cursor"
                );
                if state.sequence > known || state.finished {
                    return Ok(state.sequence);
                }
            }
            changed.await;
        }
    }
    async fn write_to(&self, mut tcp: OwnedWriteHalf, rate: Arc<Rate>) -> Result<()> {
        loop {
            let changed = self.signal.changed.notified();
            self.signal.check()?;
            let next = {
                let state = self.state.lock().expect("upload state");
                match state.pending.get(&state.sequence) {
                    Some(Input::Data(block)) => {
                        ensure!(block.offset == state.offset, "noncontiguous upload offset");
                        Some((Some(block.clone()), state.sequence))
                    }
                    Some(Input::Fin(offset)) => {
                        ensure!(*offset == state.offset, "invalid upload final offset");
                        Some((None, state.sequence))
                    }
                    None => None,
                }
            };
            let Some((block, sequence)) = next else {
                changed.await;
                continue;
            };
            if let Some(block) = &block {
                rate.acquire(block.data.len()).await;
                tcp.write_all(&block.data).await?;
            } else {
                tcp.shutdown().await?;
            }
            {
                let mut state = self.state.lock().expect("upload state");
                state.pending.remove(&sequence);
                state.sequence += 1;
                if let Some(block) = &block {
                    state.offset += block.data.len() as u64;
                } else {
                    state.finished = true;
                }
            }
            self.signal.touch();
            self.signal.changed.notify_waiters();
            if block.is_none() {
                return Ok(());
            }
        }
    }
}

enum Read {
    Data(Arc<Block>),
    /// Records below this cursor were already acknowledged by the client.
    Skip(u64),
    End(u64, u64),
}
struct DownloadState {
    sequence: u64,
    offset: u64,
    acknowledged: u64,
    blocks: BTreeMap<u64, Arc<Block>>,
    end: Option<(u64, u64)>,
}
struct Download {
    signal: Arc<Signal>,
    state: Mutex<DownloadState>,
}
impl Download {
    fn new(signal: Arc<Signal>) -> Self {
        Self {
            signal,
            state: Mutex::new(DownloadState {
                sequence: 0,
                offset: 0,
                acknowledged: 0,
                blocks: BTreeMap::new(),
                end: None,
            }),
        }
    }
    async fn read_from(
        &self,
        mut tcp: OwnedReadHalf,
        budget: Arc<Semaphore>,
        reserve: Arc<Semaphore>,
        rate: Arc<Rate>,
    ) -> Result<()> {
        let mut buffer = vec![0; CHUNK];
        loop {
            let changed = self.signal.changed.notified();
            self.signal.check()?;
            if self.state.lock().expect("download state").blocks.len() >= PIPELINE {
                changed.await;
                continue;
            }
            let mut credit = match budget.clone().try_acquire_many_owned(CHUNK as u32) {
                Ok(credit) => credit,
                Err(_) => tokio::select! {
                    credit = budget.clone().acquire_many_owned(CHUNK as u32) => credit?,
                    credit = reserve.clone().acquire_many_owned(CHUNK as u32) => credit?,
                },
            };
            let n = read_record(&mut tcp, &mut buffer).await?;
            // Retain and charge only the bytes read: interactive replies are
            // short, and a full-size allocation per record would hold 128 KiB.
            drop(credit.split(CHUNK - n));
            let data = if n == CHUNK {
                Bytes::from(std::mem::replace(&mut buffer, vec![0; CHUNK]))
            } else {
                Bytes::copy_from_slice(&buffer[..n])
            };
            if n == 0 {
                let mut state = self.state.lock().expect("download state");
                state.end = Some((state.sequence, state.offset));
                drop(state);
                self.signal.changed.notify_waiters();
                return Ok(());
            }
            rate.acquire(n).await;
            {
                let mut state = self.state.lock().expect("download state");
                let block = Arc::new(Block {
                    sequence: state.sequence,
                    offset: state.offset,
                    data,
                    _credit: credit,
                });
                let sequence = state.sequence;
                state.blocks.insert(sequence, block);
                state.sequence += 1;
                state.offset += n as u64;
            }
            self.signal.touch();
            self.signal.changed.notify_waiters();
        }
    }
    fn acknowledge(&self, acknowledged: u64) -> Result<()> {
        self.signal.check()?;
        let mut state = self.state.lock().expect("download state");
        ensure!(acknowledged <= state.sequence, "unproduced download ACK");
        if acknowledged > state.acknowledged {
            state.acknowledged = acknowledged;
            state.blocks.retain(|&seq, _| seq >= acknowledged);
        }
        drop(state);
        self.signal.changed.notify_waiters();
        Ok(())
    }
    /// Records ready in this contiguous request, and the produced cursor.
    fn ready(&self, sequence: u64, count: usize) -> (usize, u64) {
        let state = self.state.lock().expect("download state");
        let ready = (0..count)
            .take_while(|&i| {
                sequence
                    .checked_add(i as u64)
                    .is_some_and(|seq| state.blocks.contains_key(&seq))
            })
            .count();
        (ready, state.sequence)
    }
    async fn next(&self, sequence: u64, acknowledged: u64) -> Result<Read> {
        self.acknowledge(acknowledged)?;
        loop {
            let changed = self.signal.changed.notified();
            self.signal.check()?;
            {
                let state = self.state.lock().expect("download state");
                if sequence < state.acknowledged {
                    return Ok(Read::Skip(state.acknowledged));
                }
                ensure!(
                    sequence < state.acknowledged.saturating_add(PIPELINE as u64),
                    "download record credit exceeded"
                );
                if let Some(block) = state.blocks.get(&sequence) {
                    return Ok(Read::Data(block.clone()));
                }
                if let Some((last, offset)) = state.end
                    && sequence >= last
                {
                    return Ok(Read::End(last, offset));
                }
            }
            changed.await;
        }
    }
    fn ack_fin(&self, sequence: u64, offset: u64) -> Result<()> {
        let mut state = self.state.lock().expect("download state");
        ensure!(
            state.end == Some((sequence, offset)),
            "invalid download FIN acknowledgement"
        );
        state.blocks.clear();
        state.acknowledged = sequence;
        drop(state);
        self.signal.changed.notify_waiters();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn block(
        sequence: u64,
        offset: u64,
        data: &'static [u8],
        budget: &Arc<Semaphore>,
    ) -> Input {
        Input::Data(Arc::new(Block {
            sequence,
            offset,
            data: Bytes::from_static(data),
            _credit: budget
                .clone()
                .acquire_many_owned(CHUNK as u32)
                .await
                .unwrap(),
        }))
    }
    #[tokio::test]
    async fn reordered_upload_replays_once_and_releases_all_record_credit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut sink, _) = listener.accept().await.unwrap();
        let (_, write) = tcp.into_split();
        let signal = Arc::new(Signal::new());
        let upload = Arc::new(Upload::new(signal));
        let budget = Arc::new(Semaphore::new(CHUNK * 4));
        let writer = {
            let upload = upload.clone();
            tokio::spawn(async move {
                upload
                    .write_to(write, Arc::new(Rate::new(crate::runtime::MAX_RATE_BPS)))
                    .await
            })
        };
        let later = {
            let upload = upload.clone();
            let input = block(1, 3, b"def", &budget).await;
            tokio::spawn(async move { upload.insert(1, input).await })
        };
        tokio::task::yield_now().await;
        assert!(
            upload
                .insert(1, block(1, 3, b"BAD", &budget).await)
                .await
                .is_err()
        );
        assert!(
            upload
                .insert(
                    PIPELINE as u64,
                    block(PIPELINE as u64, 0, b"x", &budget).await
                )
                .await
                .is_err()
        );
        upload
            .insert(0, block(0, 0, b"abc", &budget).await)
            .await
            .unwrap();
        later.await.unwrap().unwrap();
        upload
            .insert(0, block(0, 0, b"abc", &budget).await)
            .await
            .unwrap();
        upload.insert(2, Input::Fin(6)).await.unwrap();
        writer.await.unwrap().unwrap();
        let mut received = Vec::new();
        sink.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"abcdef");
        assert_eq!(budget.available_permits(), CHUNK * 4);
    }
    #[tokio::test]
    async fn fin_remains_admissible_when_all_data_record_credit_is_in_use() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut sink, _) = listener.accept().await.unwrap();
        let (_, write) = tcp.into_split();
        let upload = Arc::new(Upload::new(Arc::new(Signal::new())));
        let budget = Arc::new(Semaphore::new(WINDOW));
        for sequence in 0..PIPELINE as u64 {
            upload
                .insert(sequence, block(sequence, sequence, b"x", &budget).await)
                .await
                .unwrap();
        }
        assert_eq!(budget.available_permits(), 0);
        let finish = {
            let upload = upload.clone();
            tokio::spawn(async move {
                upload
                    .insert(PIPELINE as u64, Input::Fin(PIPELINE as u64))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(
            upload
                .state
                .lock()
                .unwrap()
                .pending
                .contains_key(&(PIPELINE as u64))
        );
        let reader = tokio::spawn(async move {
            let mut bytes = Vec::new();
            sink.read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        upload
            .write_to(write, Arc::new(Rate::new(crate::runtime::MAX_RATE_BPS)))
            .await
            .unwrap();
        finish.await.unwrap().unwrap();
        assert_eq!(reader.await.unwrap(), vec![b'x'; PIPELINE]);
        assert_eq!(budget.available_permits(), WINDOW);
    }
    #[tokio::test]
    async fn short_interactive_reply_does_not_wait_for_a_full_batch_or_eof() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let download = Download::new(Arc::new(Signal::new()));
        let budget = Arc::new(Semaphore::new(CHUNK));
        let Input::Data(record) = block(0, 0, b"reply", &budget).await else {
            unreachable!()
        };
        {
            let mut state = download.state.lock().unwrap();
            state.blocks.insert(0, record);
            state.sequence = 1;
            state.offset = 5;
        }
        let mut response = std::pin::pin!(download.next(0, 0));
        let Poll::Ready(reply) = response
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("interactive reply waited for a larger batch");
        };
        let reply = reply.unwrap();
        assert!(matches!(reply, Read::Data(record) if record.data.as_ref()==b"reply"));
        assert_eq!(budget.available_permits(), 0);
        download.acknowledge(1).unwrap();
        assert_eq!(budget.available_permits(), CHUNK);
    }
    #[tokio::test]
    async fn download_credit_and_final_offset_reject_unearned_acknowledgements() {
        let download = Download::new(Arc::new(Signal::new()));
        let budget = Arc::new(Semaphore::new(CHUNK));
        let Input::Data(record) = block(0, 0, b"payload", &budget).await else {
            unreachable!()
        };
        {
            let mut state = download.state.lock().unwrap();
            state.blocks.insert(0, record);
            state.sequence = 1;
            state.offset = 7;
            state.end = Some((1, 7));
        }
        assert!(download.next(PIPELINE as u64, 0).await.is_err());
        assert!(download.next(1, 2).await.is_err());
        download.state.lock().unwrap().acknowledged = 1;
        assert!(matches!(download.next(0, 0).await.unwrap(), Read::Skip(1)));
        download.state.lock().unwrap().acknowledged = 0;
        for count in [0, 33] {
            assert!(lane_parameters(count).is_err());
        }

        assert!(download.ack_fin(1, 6).is_err());
        assert_eq!(budget.available_permits(), 0);
        assert!(matches!(
            download.next(0, 0).await.unwrap(),
            Read::Data(record) if record.sequence==0
        ));
        assert!(matches!(
            download.next(1, 1).await.unwrap(),
            Read::End(1, 7)
        ));
        assert_eq!(budget.available_permits(), CHUNK);
        download.ack_fin(1, 7).unwrap();
    }
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;
    #[tokio::test]
    async fn exhausted_host_budget_still_admits_the_head_record_and_defers_later_ones() {
        let registry = Registry::new();
        let flow = Flow::new(
            Address::Domain("example.invalid".into(), 80),
            Arc::new(Signal::new()),
        );
        let _others = registry
            .upstream
            .clone()
            .try_acquire_many_owned(HOST_BUFFER as u32)
            .unwrap();
        assert!(registry.upload_credit(&flow, 1, CHUNK).is_err());
        let head = registry.upload_credit(&flow, 0, CHUNK).unwrap();
        // The reserve covers one record; a duplicate head waits for its release.
        assert!(registry.upload_credit(&flow, 0, 1).is_err());
        drop(head);
        drop(_others);
        // Shared credit is charged by size, so short records cost what they hold.
        let small = registry.upload_credit(&flow, 5, 3).unwrap();
        assert_eq!(small.num_permits(), 3);
        assert_eq!(flow.upload_reserve.available_permits(), CHUNK);
    }
    #[tokio::test]
    async fn stalled_consumer_holding_host_download_budget_does_not_stop_another_flow() {
        let budget = Arc::new(Semaphore::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut source = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (tcp, _) = listener.accept().await.unwrap();
        let (read, _write) = tcp.into_split();
        let flow = Flow::new(
            Address::Domain("example.invalid".into(), 80),
            Arc::new(Signal::new()),
        );
        let download = flow.download.clone();
        let reader = tokio::spawn({
            let reserve = flow.download_reserve.clone();
            async move {
                download
                    .read_from(
                        read,
                        budget,
                        reserve,
                        Arc::new(Rate::new(crate::runtime::MAX_RATE_BPS)),
                    )
                    .await
            }
        });
        source.write_all(b"reply").await.unwrap();
        let record = tokio::time::timeout(Duration::from_secs(2), flow.download.next(0, 0))
            .await
            .expect("an exhausted shared budget stalled this flow")
            .unwrap();
        // Only the short reply is charged against the private reserve.
        assert!(matches!(&record, Read::Data(block)
            if block.data.as_ref() == b"reply" && block._credit.num_permits() == 5));
        drop(record);
        reader.abort();
        let _ = reader.await;
        flow.download.acknowledge(1).unwrap();
        assert_eq!(flow.download_reserve.available_permits(), CHUNK);
    }
    #[tokio::test]
    async fn abandoned_session_has_resume_grace_then_releases_retained_credit() {
        let registry = Registry::new();
        let signal = Arc::new(Signal::new());
        let upload = Arc::new(Upload::new(signal.clone()));
        let credit = registry
            .upstream
            .clone()
            .acquire_many_owned(CHUNK as u32)
            .await
            .unwrap();
        upload.state.lock().unwrap().pending.insert(
            1,
            Input::Data(Arc::new(Block {
                sequence: 1,
                offset: 1,
                data: Bytes::from_static(b"x"),
                _credit: credit,
            })),
        );
        let mut flow = Flow::new(
            Address::Domain("example.invalid".into(), 80),
            signal.clone(),
        );
        flow.upload = upload;
        let reserved = flow
            .download_reserve
            .clone()
            .try_acquire_many_owned(CHUNK as u32)
            .unwrap();
        flow.download.state.lock().unwrap().blocks.insert(
            0,
            Arc::new(Block {
                sequence: 0,
                offset: 0,
                data: Bytes::from_static(b"y"),
                _credit: reserved,
            }),
        );
        let flow = Arc::new(flow);
        registry.flows.lock().unwrap().insert([1; 32], flow);
        let now = Instant::now();
        registry.reap(now);
        // A flow's private reserve is reported and reclaimed like shared credit.
        assert_eq!(registry.snapshot(), (1, CHUNK * 2));
        registry.reap(now + RESUME_GRACE);
        assert_eq!(registry.snapshot(), (0, 0));
        assert!(signal.closed.load(Ordering::Acquire));
    }
}
