use super::super::protocol::{Address, ReplyError};
use super::*;
use std::future::Future;
use tokio::{
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::OnceCell,
};

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
        (
            self.flows.lock().expect("bond registry").len(),
            HOST_BUFFER * 2
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
                let signal = Arc::new(Signal::new());
                let flow = Arc::new(Flow {
                    target,
                    bound: OnceCell::new(),
                    upload: Arc::new(Upload::new(signal.clone())),
                    download: Arc::new(Download::new(signal.clone())),
                    signal,
                    engine: Mutex::new(None),
                    owners: Mutex::new(Vec::new()),
                    unreachable: Mutex::new(None),
                });
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
                let (upload, download, signal, budget) = (
                    flow.upload.clone(),
                    flow.download.clone(),
                    flow.signal.clone(),
                    self.downstream.clone(),
                );
                *flow.engine.lock().expect("bond engine") =
                    Some(AbortTask(tokio::spawn(async move {
                        if let Err(error) = tokio::try_join!(
                            upload.write_to(write, rate.clone()),
                            download.read_from(read, budget, rate)
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
                    let sequence = recv.read_u64().await?;
                    let offset = recv.read_u64().await?;
                    let len = recv.read_u32().await? as usize;
                    ensure!(len > 0 && len <= CHUNK, "invalid upload chunk");
                    let receive = async {
                        let permit = self.upstream.clone().try_acquire_many_owned(CHUNK as u32).context("aggregate upload host buffer exhausted")?;
                        let mut data = vec![0; len];
                        recv.read_exact(&mut data).await?;
                        Ok::<_, anyhow::Error>((permit, data))
                    };
                    let (permit, data) = tokio::select! {
                        result = receive => result?,
                        _ = flow.as_ref().expect("upload flow").signal.cancelled() => anyhow::bail!("upload flow closed during ingress"),
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
                    stride: recv.read_u8().await?,
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
            Err(error) => {
                tracing::debug!(%error, "aggregate request rejected");
                return wire::respond(send, Reply::Failed(1)).await;
            }
        };
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
                        Operation::Pull {
                            sequence,
                            acknowledged,
                            stride,
                            count,
                        } => {
                            flow.download
                                .pull(sequence, acknowledged, stride, count)
                                .await
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
    engine: Mutex<Option<AbortTask>>,
    owners: Mutex<Vec<quinn::Connection>>,
    unreachable: Mutex<Option<Instant>>,
}
impl Flow {
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
        rate: Arc<Rate>,
    ) -> Result<()> {
        loop {
            let changed = self.signal.changed.notified();
            self.signal.check()?;
            if self.state.lock().expect("download state").blocks.len() >= PIPELINE {
                changed.await;
                continue;
            }
            let credit = budget.clone().acquire_many_owned(CHUNK as u32).await?;
            let mut data = vec![0; CHUNK];
            let n = read_record(&mut tcp, &mut data).await?;
            data.truncate(n);
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
                    data: data.into(),
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
    async fn pull(&self, sequence: u64, acknowledged: u64, stride: u8, count: u8) -> Result<Reply> {
        let (stride, count) = (stride as u64, count as usize);
        ensure!(
            (1..=8).contains(&stride)
                && count > 0
                && count <= MAX_BATCH
                && count * stride as usize <= PIPELINE,
            "invalid download lane"
        );
        self.acknowledge(acknowledged)?;
        loop {
            let changed = self.signal.changed.notified();
            self.signal.check()?;
            {
                let state = self.state.lock().expect("download state");
                ensure!(
                    sequence >= state.acknowledged
                        && sequence < state.acknowledged.saturating_add(PIPELINE as u64 + stride),
                    "download record credit exceeded"
                );
                let mut blocks = Vec::new();
                for i in 0..count {
                    let next = sequence
                        .checked_add(i as u64 * stride)
                        .context("download sequence overflow")?;
                    let Some(block) = state.blocks.get(&next) else {
                        break;
                    };
                    blocks.push((block.sequence, block.offset, block.data.clone()));
                }
                if !blocks.is_empty() || state.end.is_some_and(|(last, _)| sequence >= last) {
                    return Ok(Reply::Batch {
                        blocks,
                        end: state.end,
                    });
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
        let mut response = std::pin::pin!(download.pull(0, 0, 4, 32));
        let Poll::Ready(reply) = response
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("interactive reply waited for a larger batch");
        };
        let reply = reply.unwrap();
        assert!(
            matches!(reply, Reply::Batch { blocks, end: None } if blocks.len()==1 && blocks[0].2.as_ref()==b"reply")
        );
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
        assert!(
            download
                .pull((PIPELINE * 2) as u64, 0, 4, 32)
                .await
                .is_err()
        );
        assert!(download.pull(1, 2, 4, 32).await.is_err());
        for (stride, count) in [(0, 32), (9, 1), (4, 33), (8, 32)] {
            assert!(download.pull(0, 0, stride, count).await.is_err());
        }

        assert!(download.ack_fin(1, 6).is_err());
        assert_eq!(budget.available_permits(), 0);
        assert!(matches!(
            download.pull(0, 0, 4, 32).await.unwrap(),
            Reply::Batch { blocks, .. } if blocks.len() == 1 && blocks[0].0 == 0
        ));
        assert!(matches!(
            download.pull(1, 1, 4, 32).await.unwrap(),
            Reply::Batch { blocks, end: Some((1, 7)) } if blocks.is_empty()
        ));
        assert_eq!(budget.available_permits(), CHUNK);
        download.ack_fin(1, 7).unwrap();
    }
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;
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
        let flow = Arc::new(Flow {
            target: Address::Domain("example.invalid".into(), 80),
            bound: OnceCell::new(),
            signal: signal.clone(),
            upload,
            download: Arc::new(Download::new(signal.clone())),
            engine: Mutex::new(None),
            owners: Mutex::new(Vec::new()),
            unreachable: Mutex::new(None),
        });
        registry.flows.lock().unwrap().insert([1; 32], flow);
        let now = Instant::now();
        registry.reap(now);
        assert_eq!(registry.snapshot(), (1, CHUNK));
        registry.reap(now + RESUME_GRACE);
        assert_eq!(registry.snapshot(), (0, 0));
        assert!(signal.closed.load(Ordering::Acquire));
    }
}
