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

pub(crate) async fn rpc(conn: &quinn::Connection, key: Key, op: &Operation) -> Result<Reply> {
    let (mut send, mut recv) = tokio::time::timeout(CONNECT_TIMEOUT, conn.open_bi()).await??;
    let mut header = vec![op.command()];
    header.extend(key);
    match op {
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
        if let Operation::Put { data, .. } = op {
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
    let reply = if tag == 2 {
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            // Bound absence of progress, rather than the duration of a whole
            // multi-megabyte reply on a slower but working route.
            blocks.push(
                tokio::time::timeout(PATH_STALL, async {
                    let sequence = recv.read_u64().await?;
                    let offset = recv.read_u64().await?;
                    let n = recv.read_u32().await? as usize;
                    ensure!(n > 0 && n <= CHUNK, "invalid aggregate TCP chunk");
                    let mut data = vec![0; n];
                    recv.read_exact(&mut data).await?;
                    Ok::<_, anyhow::Error>((sequence, offset, Bytes::from(data)))
                })
                .await??,
            );
        }
        Reply::Batch {
            blocks,
            end: final_at,
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
