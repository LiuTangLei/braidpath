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
// Ranges for produced data are small so a slower path never holds a long run
// of the reorder window. Waits for future data use a short latency-first range.
const READY_BATCH: u64 = 4;
const FUTURE_BATCH: u64 = 8;
// Issue the next future waiter before the current one is exhausted, so a
// streaming reply does not pay a request round trip between ranges.
const FUTURE_LOW: u64 = 4;
const HEDGE_RECORDS: u64 = 4;

type Route = Arc<Mutex<SocketAddr>>;
type PullResult = (bool, u64, u64, Result<u64>);
struct Puller {
    pool: Arc<Pool>,
    exit: String,
    key: Key,
    usage: Arc<Mutex<BTreeMap<SocketAddr, (u64, u64)>>>,
    events: tokio::sync::mpsc::Sender<Incoming>,
}
impl Puller {
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        &self,
        set: &mut JoinSet<PullResult>,
        (start, count): (u64, u64),
        acknowledged: u64,
        credit: OwnedSemaphorePermit,
        interactive: bool,
        avoid: Option<SocketAddr>,
        hedge: bool,
    ) -> Route {
        let route = Arc::new(Mutex::new(SocketAddr::from(([0, 0, 0, 0], 0))));
        let mut sink = StreamSink {
            events: self.events.clone(),
            credit,
            next_sequence: start,
            end: None,
            usage: self.usage.clone(),
            route: route.clone(),
            service: None,
            interactive,
            avoid,
        };
        let (pool, exit, key, usage) = (
            self.pool.clone(),
            self.exit.clone(),
            self.key,
            self.usage.clone(),
        );
        set.spawn(async move {
            let op = Operation::Pull {
                sequence: start,
                acknowledged,
                count: count as u8,
            };
            let result = match pool.call_stream(&exit, key, op, &usage, &mut sink).await {
                Ok(Reply::Accepted) => Ok(sink.next_sequence),
                Ok(Reply::Failed(code)) => Err(ReplyError(code).into()),
                Ok(_) => Err(anyhow::anyhow!("invalid streamed download reply")),
                Err(error) => Err(error),
            };
            (hedge, start, count, result)
        });
        route
    }
}
// One scheduler owns the download sequence space. Each request takes the next
// contiguous range and its path is chosen by expected arrival, so records
// follow path capacity instead of a fixed per-lane share. A head record that
// stalls behind later arrivals is re-requested on another path (KCP-style
// fast resend at record granularity); duplicates are discarded here.
async fn download(
    mut tcp: OwnedWriteHalf,
    owner: &Owner,
    activity: Arc<Mutex<Instant>>,
) -> Result<()> {
    let (events, mut incoming) = tokio::sync::mpsc::channel(PIPELINE + HEDGE_RECORDS as usize + 8);
    let puller = Puller {
        pool: owner.pool.clone(),
        exit: owner.exit.clone(),
        key: owner.key,
        usage: owner.usage.clone(),
        events,
    };
    let budget = Arc::new(Semaphore::new(WINDOW));
    let hedge_budget = Arc::new(Semaphore::new(HEDGE_RECORDS as usize * CHUNK));
    let mut pulls = JoinSet::new();
    let mut requests: BTreeMap<u64, (u64, Route)> = BTreeMap::new();
    let mut returned = std::collections::BTreeSet::new();
    let mut hedging = false;
    let mut stall: Option<(u64, Instant)> = None;
    // A path that already left a head stalled: later heads on it re-request at once.
    let mut suspect: Option<(SocketAddr, Instant)> = None;
    // `next` is the first unassigned record; `known` is the exit's produced
    // cursor as last reported, so ranges below it carry real backlog.
    let (mut next, mut known) = (0u64, 0u64);
    let mut acks = JoinSet::new();
    let mut last_ack = 0;
    let mut pending = BTreeMap::new();
    let (mut sequence, mut offset) = (0u64, 0u64);
    let mut end: Option<(u64, u64)> = None;
    loop {
        while let Some(Block {
            offset: at,
            data,
            _credit,
            ..
        }) = pending.remove(&sequence)
        {
            ensure!(at == offset, "invalid aggregate download offset");
            tcp.write_all(&data).await?;
            offset = offset
                .checked_add(data.len() as u64)
                .context("aggregate offset overflow")?;
            sequence += 1;
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
        loop {
            let limit = sequence + PIPELINE as u64;
            let open = end.is_none_or(|(last, _)| next < last);
            let (start, count, interactive) = if let Some(&first) = returned.first() {
                let mut count = 1;
                while count < READY_BATCH && returned.contains(&(first + count)) {
                    count += 1;
                }
                (first, count, false)
            } else if next < known.min(limit) {
                (next, (known.min(limit) - next).min(READY_BATCH), false)
            } else if open && next >= known && next - known < FUTURE_LOW && next < limit {
                (next, (limit - next).min(FUTURE_BATCH), true)
            } else {
                break;
            };
            let count = count.min((budget.available_permits() / CHUNK) as u64);
            if count == 0 {
                break;
            }
            let credit = budget
                .clone()
                .try_acquire_many_owned((count as usize * CHUNK) as u32)?;
            for record in start..start + count {
                returned.remove(&record);
            }
            next = next.max(start + count);
            let route = puller.spawn(
                &mut pulls,
                (start, count),
                sequence,
                credit,
                interactive,
                None,
                false,
            );
            requests.insert(start, (count, route));
        }
        // Later records are buffered while the head is missing: the path
        // carrying it is slower than its estimate, lossy or silently failing.
        let stalled = !pending.is_empty() && sequence < known.min(next);
        stall = match stall {
            Some((at, since)) if stalled && at == sequence => Some((at, since)),
            _ => stalled.then(|| (sequence, Instant::now())),
        };
        let owner_route = |sequence: u64| {
            requests
                .range(..=sequence)
                .next_back()
                .filter(|(start, (count, _))| **start + *count > sequence)
                .map(|(_, (_, route))| *route.lock().expect("download route"))
        };
        let hedge_at = stall.filter(|_| !hedging).map(|(at, since)| {
            let repeat = suspect.is_some_and(|(address, until)| {
                Instant::now() < until && owner_route(at) == Some(address)
            });
            if repeat {
                since
            } else {
                since + owner.pool.hedge_delay(&owner.exit)
            }
        });
        let mut hedge_wait = hedge_at;
        if let Some(at) = hedge_at
            && Instant::now() >= at
        {
            let mut count = 0;
            while count < HEDGE_RECORDS
                && sequence + count < next.min(known)
                && !pending.contains_key(&(sequence + count))
            {
                count += 1;
            }
            if count > 0
                && let Ok(credit) = hedge_budget
                    .clone()
                    .try_acquire_many_owned((count as usize * CHUNK) as u32)
            {
                let avoid = owner_route(sequence);
                if let Some(address) = avoid {
                    let quiet = Duration::from_secs(1);
                    owner.pool.suspect(&owner.exit, address, quiet);
                    suspect = Some((address, Instant::now() + quiet));
                }
                tracing::debug!(
                    sequence,
                    count,
                    ?avoid,
                    "re-requesting stalled download head"
                );
                puller.spawn(
                    &mut pulls,
                    (sequence, count),
                    sequence,
                    credit,
                    false,
                    avoid,
                    true,
                );
                hedging = true;
                hedge_wait = None;
            } else {
                // Nothing could be re-requested now; wait a full delay again.
                let now = Instant::now();
                stall = Some((sequence, now));
                suspect = None;
                hedge_wait = Some(now + owner.pool.hedge_delay(&owner.exit));
            }
        }
        tokio::select! {
            event = incoming.recv() => match event.context("download requests stopped")? {
                Incoming::Record(record, produced) => {
                    known = known.max(produced);
                    // A replayed or re-requested record that is already held.
                    if record.sequence >= sequence && !pending.contains_key(&record.sequence) {
                        ensure!(
                            end.is_none_or(|(last, _)| record.sequence < last),
                            "aggregate data past FIN"
                        );
                        returned.remove(&record.sequence);
                        pending.insert(record.sequence, record);
                    }
                }
                Incoming::End(last, bytes) => {
                    ensure!(
                        last >= sequence && bytes >= offset && end.is_none_or(|old| old == (last, bytes)),
                        "conflicting aggregate FIN"
                    );
                    end = Some((last, bytes));
                    known = known.max(last);
                }
            },
            Some(done) = pulls.join_next() => {
                let (hedge, start, count, result) = done.context("download request task")?;
                if hedge {
                    hedging = false;
                    if let Err(error) = result {
                        tracing::debug!(%error, "download head re-request failed");
                    }
                } else {
                    let cursor = result?;
                    requests.remove(&start);
                    // Anything not delivered below FIN is assigned again.
                    for record in cursor.max(sequence)..start + count {
                        if end.is_none_or(|(last, _)| record < last) && !pending.contains_key(&record) {
                            returned.insert(record);
                        }
                    }
                }
            },
            Some(result) = acks.join_next(), if !acks.is_empty() => { result??; },
            _ = tokio::time::sleep_until(hedge_wait.unwrap_or_else(Instant::now)), if hedge_wait.is_some() => {},
        }
    }
}
