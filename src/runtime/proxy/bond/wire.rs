use super::super::protocol::Address;
use super::*;
use tokio::io::AsyncReadExt;

pub(crate) const OPEN: u8 = 16;
pub(crate) const PUT: u8 = 17;
pub(crate) const FIN: u8 = 19;
pub(crate) const ACK_FIN: u8 = 20;
pub(crate) const CLOSE: u8 = 21;
pub(crate) const UPLOAD_STATUS: u8 = 22;
pub(crate) const DOWNLOAD_ACK: u8 = 24;
// Contiguous download ranges with the exit's produced cursor in every record.
// The strided v1 request (18) is retired, so a mismatched peer fails explicitly.
pub(crate) const PULL: u8 = 25;
/// Retryable admission refusal; it never marks the carrying path as failed.
pub(crate) const BUSY: u8 = 0x80;
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
    Uploaded { delivered: u64 },
    Failed(u8),
}

pub(crate) enum Incoming {
    /// A record and the number of records the exit had produced when sending it.
    Record(Block, u64),
    End(u64, u64),
}
pub(crate) struct StreamSink {
    pub events: tokio::sync::mpsc::Sender<Incoming>,
    pub credit: OwnedSemaphorePermit,
    pub next_sequence: u64,
    pub end: Option<(u64, u64)>,
    pub usage: Arc<Mutex<BTreeMap<SocketAddr, (u64, u64)>>>,
    pub route: Arc<Mutex<SocketAddr>>,
    pub service: Option<Arc<PathService>>,
    /// Waits for target bytes not yet produced: route by latency, not backlog.
    pub interactive: bool,
    /// Prefer any other path; used when re-requesting a stalled head record.
    pub avoid: Option<SocketAddr>,
}

impl StreamSink {
    async fn record(
        &mut self,
        op: &mut Operation,
        sequence: u64,
        offset: u64,
        produced: u64,
        data: Bytes,
    ) -> Result<()> {
        let Operation::Pull {
            sequence: next,
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
            .send(Incoming::Record(
                Block {
                    sequence,
                    offset,
                    data,
                    _credit: credit,
                },
                produced,
            ))
            .await
            .context("download consumer closed")?;
        let route = *self.route.lock().expect("download route");
        self.usage
            .lock()
            .expect("flow usage")
            .entry(route)
            .or_default()
            .1 += n;
        *next = next.checked_add(1).context("download sequence overflow")?;
        *remaining -= 1;
        self.next_sequence = *next;
        Ok(())
    }
    // Records below `at` were delivered by another request; release their credit.
    fn skip(&mut self, op: &mut Operation, at: u64) -> Result<usize> {
        let Operation::Pull {
            sequence: next,
            count: remaining,
            ..
        } = op
        else {
            unreachable!()
        };
        ensure!(
            at > *next && at - *next <= *remaining as u64,
            "invalid download skip"
        );
        let skipped = (at - *next) as usize;
        drop(self.credit.split(skipped * CHUNK));
        *next = at;
        *remaining -= skipped as u8;
        self.next_sequence = at;
        Ok(skipped)
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
            count,
        } => {
            header.extend(sequence.to_be_bytes());
            header.extend(acknowledged.to_be_bytes());
            header.push(*count);
        }
        Operation::Fin { sequence, offset } | Operation::AckFin { sequence, offset } => {
            header.extend(sequence.to_be_bytes());
            header.extend(offset.to_be_bytes());
        }
        Operation::UploadStatus { delivered } => header.extend(delivered.to_be_bytes()),
        Operation::DownloadAck { acknowledged } => header.extend(acknowledged.to_be_bytes()),
        Operation::Close => {}
    }
    let sent = tokio::time::timeout(CONNECT_TIMEOUT, async {
        send.write_all(&header).await?;
        if let Operation::Put { data, .. } = &*op {
            send.write_all(data).await?;
        }
        send.finish()?;
        Ok::<_, anyhow::Error>(())
    })
    .await?;
    // A busy exit declines the body without reading it; its reply explains why.
    if let Err(error) = sent
        && !matches!(
            error.downcast_ref::<quinn::WriteError>(),
            Some(quinn::WriteError::Stopped(_))
        )
    {
        return Err(error);
    }
    loop {
        match tokio::time::timeout(PATH_STALL, recv.read_u8()).await?? {
            0 => continue,
            1 => break,
            _ => anyhow::bail!("unsupported aggregate TCP response"),
        }
    }
    let (tag, count, simple) = tokio::time::timeout(PATH_STALL, async {
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
                ensure!(
                    count > 0 && count <= MAX_BATCH,
                    "invalid download lane length"
                );
                return Ok((tag, count, None));
            }
            4 => Some(Reply::Failed(recv.read_u8().await?)),
            5 => Some(Reply::Uploaded {
                delivered: recv.read_u64().await?,
            }),
            _ => anyhow::bail!("invalid aggregate TCP reply"),
        };
        Ok::<_, anyhow::Error>((tag, 0, reply))
    })
    .await??;
    let reply = if tag == 2 {
        if let Some(sink) = stream.as_deref_mut() {
            let Operation::Pull {
                count: requested, ..
            } = op
            else {
                anyhow::bail!("lane reply to a scalar operation")
            };
            ensure!(count <= *requested as usize, "unrequested download records");
            *requested = count as u8;
            let excess = sink.credit.num_permits().saturating_sub(count * CHUNK);
            drop(sink.credit.split(excess));
        }
        // Requests for produced data are real backlog; future-data waits are not.
        let mut delivery = stream.as_ref().and_then(|sink| {
            let records = if sink.interactive { 0 } else { count };
            sink.service.as_ref().map(|service| service.start(records))
        });
        ensure!(
            stream.is_some(),
            "download lane requires a streaming consumer"
        );
        let mut received = 0;
        while received < count {
            match tokio::time::timeout(PATH_STALL, recv.read_u8()).await?? {
                0 => continue,
                1 => {
                    let (hint, produced, sequence, offset, n) =
                        tokio::time::timeout(PATH_STALL, async {
                            let hint = recv.read_u8().await? as usize;
                            let produced = recv.read_u64().await?;
                            let sequence = recv.read_u64().await?;
                            let offset = recv.read_u64().await?;
                            let n = recv.read_u32().await? as usize;
                            ensure!(
                                hint > 0
                                    && hint <= count - received
                                    && n > 0
                                    && n <= CHUNK
                                    && produced > sequence,
                                "invalid streamed record"
                            );
                            Ok::<_, anyhow::Error>((hint, produced, sequence, offset, n))
                        })
                        .await??;
                    if let Some(delivery) = &mut delivery {
                        delivery.ready(hint);
                    }
                    let mut data = vec![0; n];
                    tokio::time::timeout(PATH_STALL, recv.read_exact(&mut data)).await??;
                    let data = Bytes::from(data);
                    if let Some(sink) = stream.as_deref_mut() {
                        sink.record(op, sequence, offset, produced, data).await?;
                    }
                    if let Some(delivery) = &mut delivery {
                        delivery.record(n);
                    }
                    received += 1;
                }
                2 => {
                    let at = tokio::time::timeout(PATH_STALL, async {
                        Ok::<_, anyhow::Error>((recv.read_u64().await?, recv.read_u64().await?))
                    })
                    .await??;
                    if let Some(sink) = stream.as_deref_mut() {
                        sink.end = Some(at);
                        if let Operation::Pull { count, .. } = op {
                            *count = 0;
                        }
                        sink.events
                            .send(Incoming::End(at.0, at.1))
                            .await
                            .context("download consumer closed")?;
                    }
                    break;
                }
                3 => {
                    return Ok(Reply::Failed(
                        tokio::time::timeout(PATH_STALL, recv.read_u8()).await??,
                    ));
                }
                4 => {
                    let at = tokio::time::timeout(PATH_STALL, recv.read_u64()).await??;
                    let sink = stream.as_deref_mut().expect("streaming consumer");
                    let skipped = sink.skip(op, at)?;
                    if let Some(delivery) = &mut delivery {
                        delivery.skip(skipped);
                    }
                    received += skipped;
                }
                _ => anyhow::bail!("invalid download lane frame"),
            }
        }
        Reply::Accepted
    } else {
        simple.expect("simple response")
    };
    tokio::time::timeout(PATH_STALL, eof(&mut recv)).await??;
    Ok(reply)
}

pub(crate) async fn respond(send: &mut quinn::SendStream, reply: Reply) -> Result<()> {
    let mut header = vec![1];
    match reply {
        Reply::Opened(at) => {
            header.push(0);
            Address::Ip(at).encode(&mut header);
        }
        Reply::Accepted => header.push(1),
        Reply::Uploaded { delivered } => {
            header.push(5);
            header.extend(delivered.to_be_bytes());
        }
        Reply::Failed(code) => header.extend([4, code]),
    }
    send.write_all(&header).await?;
    send.finish()?;
    Ok(())
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    #[tokio::test]
    async fn replay_skip_releases_only_acknowledged_record_credit_and_accepts_the_suffix() {
        let budget = Arc::new(Semaphore::new(CHUNK * 4));
        let (events, mut received) = tokio::sync::mpsc::channel(4);
        let mut sink = StreamSink {
            events,
            credit: budget
                .clone()
                .acquire_many_owned((CHUNK * 4) as u32)
                .await
                .unwrap(),
            next_sequence: 10,
            end: None,
            usage: Arc::new(Mutex::new(BTreeMap::new())),
            route: Arc::new(Mutex::new("127.0.0.1:1".parse().unwrap())),
            service: None,
            interactive: false,
            avoid: None,
        };
        let mut op = Operation::Pull {
            sequence: 10,
            acknowledged: 10,
            count: 4,
        };
        assert!(sink.skip(&mut op, 10).is_err());
        assert!(sink.skip(&mut op, 15).is_err());
        assert_eq!(budget.available_permits(), 0);
        // Another path delivered 10 and 11 while this request was replaying.
        assert_eq!(sink.skip(&mut op, 12).unwrap(), 2);
        assert_eq!(budget.available_permits(), CHUNK * 2);
        sink.record(&mut op, 12, 20, 14, Bytes::from_static(b"remaining"))
            .await
            .unwrap();
        assert!(matches!(
            received.try_recv().unwrap(),
            Incoming::Record(Block { sequence: 12, .. }, 14)
        ));
        assert_eq!(budget.available_permits(), CHUNK * 3);
        assert_eq!(sink.skip(&mut op, 14).unwrap(), 1);
        assert_eq!(sink.next_sequence, 14);
        assert!(matches!(
            op,
            Operation::Pull {
                sequence: 14,
                count: 0,
                ..
            }
        ));
        assert_eq!(budget.available_permits(), CHUNK * 4);
    }
    #[tokio::test]
    async fn busy_reply_to_an_unread_upload_body_is_retryable_not_a_path_failure() {
        use crate::runtime::transport::{self, AckRequest, Congestion};
        let temp = tempfile::tempdir().unwrap();
        let identity = temp.path().join("identity");
        transport::initialize(&identity, "localhost").unwrap();
        let server = transport::server_with_proxy(
            "127.0.0.1:0".parse().unwrap(),
            &identity.join("cert.pem"),
            &identity.join("key.pem"),
            Congestion::Bbr,
            transport::DEFAULT_DATAGRAM_SEND_BUFFER_BYTES,
            AckRequest::Unchanged,
            true,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let client = transport::proxy_client(address, &identity.join("cert.pem")).unwrap();
        let (outgoing, incoming) =
            tokio::join!(client.connect(address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await
            });
        let (conn, peer) = (outgoing.unwrap(), incoming.unwrap());
        let exit = tokio::spawn(async move {
            let (mut send, mut recv) = peer.accept_bi().await.unwrap();
            // Command, flow key, sequence, offset and length; never the body.
            let mut header = [0; 1 + 32 + 8 + 8 + 4];
            recv.read_exact(&mut header).await.unwrap();
            recv.stop(0u32.into()).unwrap();
            respond(&mut send, Reply::Failed(BUSY)).await.unwrap();
            peer
        });
        // Under load the shared connection window is exhausted and a body is
        // still blocked when the exit declines it. A body above the stream
        // window reproduces that blocked writer deterministically.
        let mut op = Operation::Put {
            sequence: 0,
            offset: 0,
            data: Bytes::from(vec![9; 64 * 1024 * 1024]),
        };
        let reply =
            tokio::time::timeout(Duration::from_secs(5), rpc(&conn, [7; 32], &mut op, None))
                .await
                .unwrap()
                .unwrap();
        assert!(matches!(reply, Reply::Failed(BUSY)));
        assert!(conn.close_reason().is_none());
        drop(exit.await.unwrap());
    }
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
            route: Arc::new(Mutex::new("127.0.0.1:1".parse().unwrap())),
            service: None,
            interactive: false,
            avoid: None,
        };
        let mut op = Operation::Pull {
            sequence: 0,
            acknowledged: 0,
            count: 2,
        };
        sink.record(&mut op, 0, 0, 2, Bytes::from_static(b"first"))
            .await
            .unwrap();
        let first = received
            .try_recv()
            .expect("first record waited for the entire reply");
        assert!(matches!(first, Incoming::Record(_, 2)));
        assert!(matches!(
            op,
            Operation::Pull {
                sequence: 1,
                count: 1,
                ..
            }
        ));
        assert_eq!(sink.next_sequence, 1);
        // A transport error at this point retries this cursor, never record 0.
        assert!(
            sink.record(&mut op, 0, 0, 2, Bytes::from_static(b"first"))
                .await
                .is_err()
        );
        assert_eq!(sink.credit.num_permits(), CHUNK);
        sink.record(&mut op, 1, 5, 2, Bytes::from_static(b"second"))
            .await
            .unwrap();
        let second = received.try_recv().unwrap();
        assert!(matches!(
            op,
            Operation::Pull {
                sequence: 2,
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
