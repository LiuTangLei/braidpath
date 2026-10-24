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
        tracing::debug!(exit=%self.owner.exit, paths=?self.owner.usage.lock().expect("flow usage"), completed=result.is_ok(), "aggregate TCP flow finished");
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
            read = tcp.read(&mut buffer), if sequence < delivered.saturating_add(PIPELINE as u64) && jobs.len() < PIPELINE => {
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
    accepted(owner, Operation::Fin { sequence, offset }).await
}
enum DownloadEvent {
    Record(u64, Reply, OwnedSemaphorePermit),
    Status(Reply),
    Acknowledged,
}
async fn download(
    mut tcp: OwnedWriteHalf,
    owner: &Owner,
    activity: Arc<Mutex<Instant>>,
) -> Result<()> {
    let budget = Arc::new(Semaphore::new(WINDOW));
    let mut jobs = JoinSet::new();
    let mut pending: BTreeMap<u64, (u64, Bytes, OwnedSemaphorePermit)> = BTreeMap::new();
    let (mut requested, mut sequence, mut produced, mut offset) = (0u64, 0u64, 0u64, 0u64);
    let (mut status_pending, mut ack_pending) = (false, false);
    let mut acknowledged = 0u64;
    let mut end = None;
    loop {
        while let Some((at, data, _credit)) = pending.remove(&sequence) {
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
            *activity.lock().expect("flow activity") = Instant::now();
        }
        if let Some((final_sequence, final_offset)) = end
            && sequence == final_sequence
        {
            ensure!(offset == final_offset, "invalid aggregate download FIN");
            accepted(owner, Operation::AckFin { sequence, offset }).await?;
            tcp.shutdown().await?;
            return Ok(());
        }
        while requested < produced && requested < sequence.saturating_add(PIPELINE as u64) {
            // Reserve the earliest missing record before any later reply can consume its credit.
            let Ok(credit) = budget.clone().try_acquire_many_owned(CHUNK as u32) else {
                break;
            };
            let (pool, exit, key, usage) = (
                owner.pool.clone(),
                owner.exit.clone(),
                owner.key,
                owner.usage.clone(),
            );
            let request = requested;
            let acknowledged = sequence;
            jobs.spawn(async move {
                let reply = pool
                    .call(
                        &exit,
                        key,
                        Operation::Pull {
                            sequence: request,
                            acknowledged,
                        },
                        &usage,
                    )
                    .await?;
                Ok::<_, anyhow::Error>(DownloadEvent::Record(request, reply, credit))
            });
            requested += 1;
        }
        if !ack_pending && sequence > acknowledged {
            let (pool, exit, key, usage) = (
                owner.pool.clone(),
                owner.exit.clone(),
                owner.key,
                owner.usage.clone(),
            );
            acknowledged = sequence;
            jobs.spawn(async move {
                match pool
                    .call(&exit, key, Operation::DownloadAck { acknowledged }, &usage)
                    .await?
                {
                    Reply::Accepted => Ok(DownloadEvent::Acknowledged),
                    Reply::Failed(code) => Err(ReplyError(code).into()),
                    _ => anyhow::bail!("invalid download ACK"),
                }
            });
            ack_pending = true;
        }
        if !status_pending && end.is_none() {
            let (pool, exit, key, usage) = (
                owner.pool.clone(),
                owner.exit.clone(),
                owner.key,
                owner.usage.clone(),
            );
            let acknowledged = sequence;
            jobs.spawn(async move {
                Ok::<_, anyhow::Error>(DownloadEvent::Status(
                    pool.call(
                        &exit,
                        key,
                        Operation::ReadStatus {
                            produced,
                            acknowledged,
                        },
                        &usage,
                    )
                    .await?,
                ))
            });
            status_pending = true;
        }
        match jobs
            .join_next()
            .await
            .context("aggregate download has a missing record")???
        {
            DownloadEvent::Acknowledged => ack_pending = false,
            DownloadEvent::Status(Reply::Available {
                produced: at,
                end: final_at,
            }) => {
                status_pending = false;
                ensure!(
                    at >= produced && at >= requested,
                    "download producer moved backwards"
                );
                if let Some((last, bytes)) = final_at {
                    ensure!(
                        last == at && last >= sequence && bytes >= offset,
                        "premature aggregate EOF"
                    );
                }
                produced = at;
                end = final_at;
            }
            DownloadEvent::Record(
                request,
                Reply::Data {
                    sequence: received,
                    offset: at,
                    data,
                },
                credit,
            ) => {
                ensure!(
                    received == request && received >= sequence,
                    "unexpected aggregate download sequence"
                );
                ensure!(
                    pending.insert(received, (at, data, credit)).is_none(),
                    "duplicate aggregate reply"
                );
            }
            DownloadEvent::Status(Reply::Failed(code))
            | DownloadEvent::Record(_, Reply::Failed(code), _) => {
                return Err(ReplyError(code).into());
            }
            _ => anyhow::bail!("invalid aggregate download response"),
        }
    }
}
