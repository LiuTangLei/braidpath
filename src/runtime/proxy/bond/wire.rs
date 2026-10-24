use super::super::protocol::Address;
use super::*;
use tokio::io::AsyncReadExt;

pub(crate) const OPEN: u8 = 16;
pub(crate) const PUT: u8 = 17;
pub(crate) const PULL: u8 = 18;
pub(crate) const FIN: u8 = 19;
pub(crate) const ACK_FIN: u8 = 20;
pub(crate) const CLOSE: u8 = 21;
pub(crate) const UPLOAD_STATUS: u8 = 22;
pub(crate) const DOWNLOAD_ACK: u8 = 24;
pub(crate) type Key = [u8; 32];

#[derive(Clone)]
pub(crate) enum Operation {
    Open(Address),
    Put {
        sequence: u64,
        offset: u64,
        data: Bytes,
    },
    Pull {
        sequence: u64,
        acknowledged: u64,
        stride: u8,
        count: u8,
    },
    Fin {
        sequence: u64,
        offset: u64,
    },
    AckFin {
        sequence: u64,
        offset: u64,
    },
    UploadStatus {
        delivered: u64,
    },
    DownloadAck {
        acknowledged: u64,
    },
    Close,
}
impl Operation {
    pub(crate) fn command(&self) -> u8 {
        match self {
            Self::Open(_) => OPEN,
            Self::Put { .. } => PUT,
            Self::Pull { .. } => PULL,
            Self::Fin { .. } => FIN,
            Self::AckFin { .. } => ACK_FIN,
            Self::Close => CLOSE,
            Self::UploadStatus { .. } => UPLOAD_STATUS,
            Self::DownloadAck { .. } => DOWNLOAD_ACK,
        }
    }
}
pub(crate) enum Reply {
    Opened(SocketAddr),
    Accepted,
    Uploaded {
        delivered: u64,
    },
    Batch {
        blocks: Vec<(u64, u64, Bytes)>,
        end: Option<(u64, u64)>,
    },
    Failed(u8),
}

pub(crate) enum Incoming {
    Record(Block),
    End(u64, u64),
}
pub(crate) struct StreamSink {
    pub events: tokio::sync::mpsc::Sender<Incoming>,
    pub credit: OwnedSemaphorePermit,
    pub next_sequence: u64,
    pub end: Option<(u64, u64)>,
    pub usage: Arc<Mutex<BTreeMap<SocketAddr, (u64, u64)>>>,
    pub route: SocketAddr,
    pub service: Option<Arc<PathService>>,
}

impl StreamSink {
    async fn record(
        &mut self,
        op: &mut Operation,
        sequence: u64,
        offset: u64,
        data: Bytes,
    ) -> Result<()> {
        let Operation::Pull {
            sequence: next,
            stride,
            count: remaining,
            ..
        } = op
        else {
            unreachable!()
        };
        ensure!(sequence == *next, "unexpected streamed download sequence");
        let credit = self
            .credit
            .split(CHUNK)
            .context("streamed record exceeds reserved credit")?;
        let n = data.len() as u64;
        self.events
            .send(Incoming::Record(Block {
                sequence,
                offset,
                data,
                _credit: credit,
            }))
            .await
            .context("download consumer closed")?;
        self.usage
            .lock()
            .expect("flow usage")
            .entry(self.route)
            .or_default()
            .1 += n;
        *next = next
            .checked_add(*stride as u64)
            .context("download sequence overflow")?;
        *remaining -= 1;
        self.next_sequence = *next;
        Ok(())
    }
}

// Framing is entirely ordered. Mixing an ordered prefix with read_to_end's
// unordered mode can expose already-consumed overlapping retransmissions.
pub(crate) async fn eof(recv: &mut quinn::RecvStream) -> Result<()> {
    ensure!(
        recv.read(&mut [0; 1]).await?.is_none(),
        "trailing aggregate bytes"
    );
    Ok(())
}
async fn end(recv: &mut quinn::RecvStream) -> Result<Option<(u64, u64)>> {
    match recv.read_u8().await? {
        0 => Ok(None),
        1 => Ok(Some((recv.read_u64().await?, recv.read_u64().await?))),
        _ => anyhow::bail!("invalid FIN flag"),
    }
}

pub(crate) async fn rpc(
    conn: &quinn::Connection,
    key: Key,
    op: &mut Operation,
    mut stream: Option<&mut StreamSink>,
) -> Result<Reply> {
    let (mut send, mut recv) = tokio::time::timeout(CONNECT_TIMEOUT, conn.open_bi()).await??;
    let mut header = vec![op.command()];
    header.extend(key);
    match &*op {
        Operation::Open(target) => target.encode(&mut header),
        Operation::Put {
            sequence,
            offset,
            data,
        } => {
            header.extend(sequence.to_be_bytes());
            header.extend(offset.to_be_bytes());
            header.extend((data.len() as u32).to_be_bytes());
        }
        Operation::Pull {
            sequence,
            acknowledged,
            stride,
            count,
        } => {
            header.extend(sequence.to_be_bytes());
            header.extend(acknowledged.to_be_bytes());
            header.extend([*stride, *count]);
        }
        Operation::Fin { sequence, offset } | Operation::AckFin { sequence, offset } => {
            header.extend(sequence.to_be_bytes());
            header.extend(offset.to_be_bytes());
        }
        Operation::UploadStatus { delivered } => header.extend(delivered.to_be_bytes()),
        Operation::DownloadAck { acknowledged } => header.extend(acknowledged.to_be_bytes()),
        Operation::Close => {}
    }
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        send.write_all(&header).await?;
        if let Operation::Put { data, .. } = &*op {
            send.write_all(data).await?;
        }
        send.finish()?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    loop {
        match tokio::time::timeout(PATH_STALL, recv.read_u8()).await?? {
            0 => continue,
            1 => break,
            _ => anyhow::bail!("unsupported aggregate TCP response"),
        }
    }
    let (tag, count, final_at, simple) = tokio::time::timeout(PATH_STALL, async {
        let tag = recv.read_u8().await?;
        let reply = match tag {
            0 => {
                let Address::Ip(at) = Address::read(&mut recv).await? else {
                    anyhow::bail!("invalid bind address")
                };
                Some(Reply::Opened(at))
            }
            1 => Some(Reply::Accepted),
            2 => {
                let count = recv.read_u8().await? as usize;
                let end = end(&mut recv).await?;
                ensure!(
                    count <= MAX_BATCH && (count > 0 || end.is_some()),
                    "invalid download batch"
                );
                return Ok((tag, count, end, None));
            }
            4 => Some(Reply::Failed(recv.read_u8().await?)),
            5 => Some(Reply::Uploaded {
                delivered: recv.read_u64().await?,
            }),
            _ => anyhow::bail!("invalid aggregate TCP reply"),
        };
        Ok::<_, anyhow::Error>((tag, 0, None, reply))
    })
    .await??;
    let mut delivery = if tag == 2 {
        stream
            .as_ref()
            .and_then(|sink| sink.service.as_ref())
            .map(|service| service.start(count))
    } else {
        None
    };
    let reply = if tag == 2 {
        if let Some(sink) = stream.as_deref_mut() {
            let Operation::Pull {
                count: requested, ..
            } = op
            else {
                anyhow::bail!("batch reply to a scalar request")
            };
            ensure!(count <= *requested as usize, "unrequested download records");
            *requested = count as u8;
            let excess = sink.credit.num_permits().saturating_sub(count * CHUNK);
            drop(sink.credit.split(excess));
            if let Some((sequence, offset)) = final_at {
                sink.end = Some((sequence, offset));
                sink.events
                    .send(Incoming::End(sequence, offset))
                    .await
                    .context("download consumer closed")?;
            }
        }
        let mut blocks = Vec::new();
        for _ in 0..count {
            let (sequence, offset, data) = tokio::time::timeout(PATH_STALL, async {
                let sequence = recv.read_u64().await?;
                let offset = recv.read_u64().await?;
                let n = recv.read_u32().await? as usize;
                ensure!(n > 0 && n <= CHUNK, "invalid aggregate TCP chunk");
                let mut data = vec![0; n];
                recv.read_exact(&mut data).await?;
                Ok::<_, anyhow::Error>((sequence, offset, Bytes::from(data)))
            })
            .await??;
            if let Some(sink) = stream.as_deref_mut() {
                let bytes = data.len();
                sink.record(op, sequence, offset, data).await?;
                if let Some(delivery) = &mut delivery {
                    delivery.record(bytes);
                }
            } else {
                blocks.push((sequence, offset, data));
            }
        }
        if stream.is_some() {
            Reply::Accepted
        } else {
            Reply::Batch {
                blocks,
                end: final_at,
            }
        }
    } else {
        simple.expect("simple response")
    };
    tokio::time::timeout(PATH_STALL, eof(&mut recv)).await??;
    Ok(reply)
}

pub(crate) async fn respond(send: &mut quinn::SendStream, reply: Reply) -> Result<()> {
    let mut header = vec![1];
    let records = match reply {
        Reply::Opened(at) => {
            header.push(0);
            Address::Ip(at).encode(&mut header);
            Vec::new()
        }
        Reply::Accepted => {
            header.push(1);
            Vec::new()
        }
        Reply::Uploaded { delivered } => {
            header.push(5);
            header.extend(delivered.to_be_bytes());
            Vec::new()
        }
        Reply::Failed(code) => {
            header.extend([4, code]);
            Vec::new()
        }
        Reply::Batch { blocks, end } => {
            header.extend([2, blocks.len() as u8, u8::from(end.is_some())]);
            if let Some((sequence, offset)) = end {
                header.extend(sequence.to_be_bytes());
                header.extend(offset.to_be_bytes());
            }
            blocks
        }
    };
    send.write_all(&header).await?;
    for (sequence, offset, data) in records {
        let mut header = Vec::with_capacity(20);
        header.extend(sequence.to_be_bytes());
        header.extend(offset.to_be_bytes());
        header.extend((data.len() as u32).to_be_bytes());
        send.write_all(&header).await?;
        send.write_all(&data).await?;
    }
    send.finish()?;
    Ok(())
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    #[tokio::test]
    async fn partial_reply_replays_only_the_unreceived_suffix_and_releases_record_credit() {
        let budget = Arc::new(Semaphore::new(CHUNK * 2));
        let (events, mut received) = tokio::sync::mpsc::channel(2);
        let usage = Arc::new(Mutex::new(BTreeMap::new()));
        let mut sink = StreamSink {
            events,
            credit: budget
                .clone()
                .acquire_many_owned((CHUNK * 2) as u32)
                .await
                .unwrap(),
            next_sequence: 0,
            end: None,
            usage: usage.clone(),
            route: "127.0.0.1:1".parse().unwrap(),
            service: None,
        };
        let mut op = Operation::Pull {
            sequence: 0,
            acknowledged: 0,
            stride: 4,
            count: 2,
        };
        sink.record(&mut op, 0, 0, Bytes::from_static(b"first"))
            .await
            .unwrap();
        let first = received
            .try_recv()
            .expect("first record waited for the entire reply");
        assert!(matches!(
            op,
            Operation::Pull {
                sequence: 4,
                count: 1,
                ..
            }
        ));
        assert_eq!(sink.next_sequence, 4);
        // A transport error at this point retries this cursor, never record 0.
        assert!(
            sink.record(&mut op, 0, 0, Bytes::from_static(b"first"))
                .await
                .is_err()
        );
        assert_eq!(sink.credit.num_permits(), CHUNK);
        sink.record(&mut op, 4, 20, Bytes::from_static(b"second"))
            .await
            .unwrap();
        let second = received.try_recv().unwrap();
        assert!(matches!(
            op,
            Operation::Pull {
                sequence: 8,
                count: 0,
                ..
            }
        ));
        assert_eq!(usage.lock().unwrap().values().next().unwrap().1, 11);
        assert_eq!(budget.available_permits(), 0);
        drop(first);
        drop(second);
        drop(sink);
        assert_eq!(budget.available_permits(), CHUNK * 2);
    }
}
