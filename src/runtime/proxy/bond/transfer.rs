use super::super::{
    client::Pool,
    protocol::{Address, ReplyError},
};
use super::*;
use tokio::{
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    task::JoinSet,
};

struct Owner {
    pool: Arc<Pool>,
    exit: String,
    key: Key,
    usage: Arc<Mutex<BTreeMap<SocketAddr, (u64, u64)>>>,
    credit: Option<OwnedSemaphorePermit>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        let (pool, exit, key, usage) = (
            self.pool.clone(),
            self.exit.clone(),
            self.key,
            self.usage.clone(),
        );
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let credit = self.credit.take();
            let task = runtime.spawn(async move {
                let _credit = credit;
                let _ = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    pool.call(&exit, key, Operation::Close, &usage),
                )
                .await;
            });
            self.pool.track_cleanup(task);
        }
    }
}
pub(crate) struct ClientFlow {
    bound: SocketAddr,
    owner: Owner,
}
pub(crate) async fn open(pool: Arc<Pool>, exit: &str, target: Address) -> Result<ClientFlow> {
    // This permit covers both the flow and its eventual close RPC. Rapid local
    // cancellations cannot create an unbounded queue of detached cleanup jobs.
    let credit = pool.flow_credit.clone().acquire_owned().await?;
    let owner = Owner {
        pool,
        exit: exit.into(),
        key: rand::random(),
        usage: Arc::new(Mutex::new(BTreeMap::new())),
        credit: Some(credit),
    };
    let reply = owner
        .pool
        .call(exit, owner.key, Operation::Open(target), &owner.usage)
        .await?;
    let bound = match reply {
        Reply::Opened(at) => at,
        Reply::Failed(code) => return Err(ReplyError(code).into()),
        _ => anyhow::bail!("invalid aggregate flow admission"),
    };
    Ok(ClientFlow { bound, owner })
}
impl ClientFlow {
    pub(crate) fn bound(&self) -> SocketAddr {
        self.bound
    }
    pub(crate) async fn run(self, tcp: TcpStream) -> Result<()> {
        let (read, write) = tcp.into_split();
        let activity = Arc::new(Mutex::new(Instant::now()));
        let transfer = async {
            tokio::try_join!(
                upload(read, &self.owner, activity.clone()),
                download(write, &self.owner, activity.clone())
            )?;
            Ok(())
        };
        let idle = async {
            loop {
                let deadline = *activity.lock().expect("flow activity") + IDLE_TIMEOUT;
                tokio::time::sleep_until(deadline).await;
                if activity.lock().expect("flow activity").elapsed() >= IDLE_TIMEOUT {
                    break;
                }
            }
        };
        let result = tokio::select! { r = transfer => r, _ = idle => anyhow::bail!("aggregate TCP idle timeout") };
        tracing::debug!(exit=%self.owner.exit, paths=?self.owner.usage.lock().expect("flow usage"), rtt_us_cwnd_sent_lost=?self.owner.pool.transport_snapshot(&self.owner.exit), service_bytes_per_sec_pending=?self.owner.pool.service_snapshot(&self.owner.exit), completed=result.is_ok(), "aggregate TCP flow finished");
        result
    }
}
async fn accepted(owner: &Owner, op: Operation) -> Result<()> {
    match owner
        .pool
        .call(&owner.exit, owner.key, op, &owner.usage)
        .await?
    {
        Reply::Accepted => Ok(()),
        Reply::Failed(code) => Err(ReplyError(code).into()),
        _ => anyhow::bail!("invalid aggregate TCP acknowledgement"),
    }
}
async fn upload(
    mut tcp: OwnedReadHalf,
    owner: &Owner,
    activity: Arc<Mutex<Instant>>,
) -> Result<()> {
    let budget = Arc::new(Semaphore::new(WINDOW));
    let mut jobs = JoinSet::new();
    let mut buffer = vec![0; CHUNK];
    let mut sequence = 0u64;
    let mut delivered = 0u64;
    let mut offset = 0u64;
    let mut status_pending = false;
    loop {
        if sequence >= delivered.saturating_add(PIPELINE as u64) && !status_pending {
            let (pool, exit, key, usage) = (
                owner.pool.clone(),
                owner.exit.clone(),
                owner.key,
                owner.usage.clone(),
            );
            jobs.spawn(async move {
                let reply = pool
                    .call(&exit, key, Operation::UploadStatus { delivered }, &usage)
                    .await?;
                Ok::<_, anyhow::Error>((reply, true))
            });
            status_pending = true;
        }
        tokio::select! {
            read = read_record(&mut tcp, &mut buffer), if sequence < delivered.saturating_add(PIPELINE as u64) && jobs.len() < PIPELINE => {
                let n = read?; if n == 0 { break; }
                *activity.lock().expect("flow activity") = Instant::now();
                let credit = budget.clone().acquire_many_owned(CHUNK as u32).await?;
                let op = Operation::Put { sequence, offset, data: Bytes::copy_from_slice(&buffer[..n]) };
                let (pool, exit, key, usage) = (owner.pool.clone(), owner.exit.clone(), owner.key, owner.usage.clone());
                jobs.spawn(async move {
                    let _credit = credit;
                    Ok::<_, anyhow::Error>((pool.call(&exit, key, op, &usage).await?, false))
                });
                sequence += 1; offset = offset.checked_add(n as u64).context("aggregate offset overflow")?;
            }
            result = jobs.join_next(), if !jobs.is_empty() => {
                let (reply, status) = result.context("upload workers stopped")???;
                if status { status_pending = false; }
                match reply {
                    Reply::Uploaded { delivered: at } => { ensure!(at <= sequence, "unearned upload progress"); delivered = delivered.max(at); }
                    Reply::Failed(code) => return Err(ReplyError(code).into()),
                    _ => anyhow::bail!("aggregate upload rejected"),
                }
            }
        }
    }
    while let Some(result) = jobs.join_next().await {
        match result??.0 {
            Reply::Uploaded { .. } => {}
            Reply::Failed(code) => return Err(ReplyError(code).into()),
            _ => anyhow::bail!("aggregate upload rejected"),
        }
    }
    tracing::debug!(
        records = sequence,
        bytes = offset,
        "aggregate upload records delivered"
    );
    accepted(owner, Operation::Fin { sequence, offset }).await
}
struct DownloadLane {
    pool: Arc<Pool>,
    exit: String,
    key: Key,
    usage: Arc<Mutex<BTreeMap<SocketAddr, (u64, u64)>>>,
    next: u64,
    stride: u8,
    budget: Arc<Semaphore>,
    acknowledged: Arc<std::sync::atomic::AtomicU64>,
    events: tokio::sync::mpsc::Sender<Incoming>,
}
impl DownloadLane {
    async fn run(mut self) -> Result<()> {
        loop {
            let mut credit = self.budget.clone().acquire_many_owned(CHUNK as u32).await?;
            let extra = (self.budget.available_permits() / CHUNK).min(MAX_BATCH - 1) * CHUNK;
            if extra > 0 {
                credit.merge(self.budget.clone().try_acquire_many_owned(extra as u32)?);
            }
            let count = (credit.num_permits() / CHUNK) as u8;
            let mut sink = StreamSink {
                events: self.events.clone(),
                credit,
                next_sequence: self.next,
                end: None,
                usage: self.usage.clone(),
                route: "0.0.0.0:0".parse().expect("constant address"),
                service: None,
            };
            let op = Operation::Pull {
                sequence: self.next,
                acknowledged: self.acknowledged.load(Ordering::Acquire),
                stride: self.stride,
                count,
            };
            match self
                .pool
                .call_stream(&self.exit, self.key, op, &self.usage, &mut sink)
                .await?
            {
                Reply::Accepted => {}
                Reply::Failed(code) => return Err(ReplyError(code).into()),
                _ => anyhow::bail!("invalid streamed download reply"),
            }
            self.next = sink.next_sequence;
            if sink.end.is_some_and(|(last, _)| self.next >= last) {
                return Ok(());
            }
        }
    }
}
async fn download(
    mut tcp: OwnedWriteHalf,
    owner: &Owner,
    activity: Arc<Mutex<Instant>>,
) -> Result<()> {
    let lanes = owner.pool.download_lanes();
    let acknowledged = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (events, mut incoming) = tokio::sync::mpsc::channel(PIPELINE + 8);
    let mut workers = JoinSet::new();
    for lane in 0..lanes {
        workers.spawn(
            DownloadLane {
                pool: owner.pool.clone(),
                exit: owner.exit.clone(),
                key: owner.key,
                usage: owner.usage.clone(),
                next: lane as u64,
                stride: lanes as u8,
                budget: Arc::new(Semaphore::new((PIPELINE / lanes) * CHUNK)),
                acknowledged: acknowledged.clone(),
                events: events.clone(),
            }
            .run(),
        );
    }
    drop(events);
    let mut acks = JoinSet::new();
    let mut last_ack = 0;
    let mut pending = BTreeMap::new();
    let (mut sequence, mut offset) = (0u64, 0u64);
    let mut end = None;
    loop {
        while let Some(Block {
            offset: at,
            data,
            _credit,
            ..
        }) = pending.remove(&sequence)
        {
            ensure!(
                end.is_none_or(|(last, _)| sequence < last),
                "aggregate data past FIN"
            );
            ensure!(at == offset, "invalid aggregate download offset");
            tcp.write_all(&data).await?;
            offset = offset
                .checked_add(data.len() as u64)
                .context("aggregate offset overflow")?;
            sequence += 1;
            acknowledged.store(sequence, Ordering::Release);
            *activity.lock().expect("flow activity") = Instant::now();
        }
        if let Some((last, bytes)) = end
            && sequence == last
        {
            ensure!(offset == bytes, "invalid aggregate download FIN");
            tracing::debug!(
                records = sequence,
                bytes = offset,
                "aggregate download records delivered"
            );
            accepted(owner, Operation::AckFin { sequence, offset }).await?;
            tcp.shutdown().await?;
            return Ok(());
        }
        if acks.is_empty() && sequence > last_ack {
            let (pool, exit, key, usage) = (
                owner.pool.clone(),
                owner.exit.clone(),
                owner.key,
                owner.usage.clone(),
            );
            last_ack = sequence;
            acks.spawn(async move {
                match pool
                    .call(
                        &exit,
                        key,
                        Operation::DownloadAck {
                            acknowledged: sequence,
                        },
                        &usage,
                    )
                    .await?
                {
                    Reply::Accepted => Ok(()),
                    Reply::Failed(code) => Err(ReplyError(code).into()),
                    _ => anyhow::bail!("invalid download ACK"),
                }
            });
        }
        tokio::select! {
            event=incoming.recv()=> match event.context("streamed download has a missing record")? {
                Incoming::Record(record)=>{ensure!(record.sequence>=sequence && end.is_none_or(|(last,_)|record.sequence<last),"unexpected aggregate download sequence");ensure!(pending.insert(record.sequence,record).is_none(),"duplicate aggregate download");},
                Incoming::End(last,bytes)=>{ensure!(last>=sequence && bytes>=offset && end.is_none_or(|old|old==(last,bytes)),"conflicting aggregate FIN");end=Some((last,bytes));}
            },
            Some(result)=workers.join_next(),if !workers.is_empty()=>{result??;},
            Some(result)=acks.join_next(),if !acks.is_empty()=>{result??;},
        }
    }
}
