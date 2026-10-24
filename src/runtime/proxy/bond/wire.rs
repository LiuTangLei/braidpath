use super::super::protocol::Address;
use super::*;
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;

pub(crate) const OPEN: u8 = 16;
pub(crate) const PUT: u8 = 17;
pub(crate) const PULL: u8 = 18;
pub(crate) const FIN: u8 = 19;
pub(crate) const ACK_FIN: u8 = 20;
pub(crate) const CLOSE: u8 = 21;
pub(crate) const UPLOAD_STATUS: u8 = 22;
pub(crate) const READ_STATUS: u8 = 23;
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
    ReadStatus {
        produced: u64,
        acknowledged: u64,
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
            Self::ReadStatus { .. } => READ_STATUS,
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
    Available {
        produced: u64,
        end: Option<(u64, u64)>,
    },
    Data {
        sequence: u64,
        offset: u64,
        data: Bytes,
    },
    End {
        sequence: u64,
        offset: u64,
    },
    Failed(u8),
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
        } => {
            header.extend(sequence.to_be_bytes());
            header.extend(acknowledged.to_be_bytes());
        }
        Operation::Fin { sequence, offset } | Operation::AckFin { sequence, offset } => {
            header.extend(sequence.to_be_bytes());
            header.extend(offset.to_be_bytes());
        }
        Operation::UploadStatus { delivered } => header.extend(delivered.to_be_bytes()),
        Operation::ReadStatus {
            produced,
            acknowledged,
        } => {
            header.extend(produced.to_be_bytes());
            header.extend(acknowledged.to_be_bytes());
        }
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
    // A pending response is a liveness heartbeat, not an application ACK.
    // It permits an idle target/backpressured TCP sink without replay storms.
    loop {
        match tokio::time::timeout(PATH_STALL, recv.read_u8()).await?? {
            0 => continue,
            1 => break,
            _ => anyhow::bail!("unsupported aggregate TCP response"),
        }
    }
    tokio::time::timeout(PATH_STALL, async {
        let reply = match recv.read_u8().await? {
            0 => {
                let Address::Ip(at) = Address::read(&mut recv).await? else {
                    anyhow::bail!("invalid bind address")
                };
                Reply::Opened(at)
            }
            1 => Reply::Accepted,
            2 => {
                let sequence = recv.read_u64().await?;
                let offset = recv.read_u64().await?;
                let len = recv.read_u32().await? as usize;
                ensure!(len > 0 && len <= CHUNK, "invalid aggregate TCP chunk");
                let mut bytes = vec![0; len];
                recv.read_exact(&mut bytes).await?;
                Reply::Data {
                    sequence,
                    offset,
                    data: bytes.into(),
                }
            }
            3 => Reply::End {
                sequence: recv.read_u64().await?,
                offset: recv.read_u64().await?,
            },
            4 => Reply::Failed(recv.read_u8().await?),
            5 => Reply::Uploaded {
                delivered: recv.read_u64().await?,
            },
            6 => {
                let produced = recv.read_u64().await?;
                let end = match recv.read_u8().await? {
                    0 => None,
                    1 => Some((recv.read_u64().await?, recv.read_u64().await?)),
                    _ => anyhow::bail!("invalid FIN flag"),
                };
                Reply::Available { produced, end }
            }
            _ => anyhow::bail!("invalid aggregate TCP reply"),
        };
        ensure!(
            recv.read_to_end(0).await?.is_empty(),
            "trailing aggregate reply"
        );
        Ok(reply)
    })
    .await?
}

pub(crate) async fn respond(send: &mut quinn::SendStream, reply: Reply) -> Result<()> {
    let mut header = vec![1];
    let data = match reply {
        Reply::Opened(at) => {
            header.push(0);
            Address::Ip(at).encode(&mut header);
            None
        }
        Reply::Accepted => {
            header.push(1);
            None
        }
        Reply::Data {
            sequence,
            offset,
            data,
        } => {
            header.push(2);
            header.extend(sequence.to_be_bytes());
            header.extend(offset.to_be_bytes());
            header.extend((data.len() as u32).to_be_bytes());
            Some(data)
        }
        Reply::End { sequence, offset } => {
            header.push(3);
            header.extend(sequence.to_be_bytes());
            header.extend(offset.to_be_bytes());
            None
        }
        Reply::Uploaded { delivered } => {
            header.push(5);
            header.extend(delivered.to_be_bytes());
            None
        }
        Reply::Available { produced, end } => {
            header.push(6);
            header.extend(produced.to_be_bytes());
            header.push(u8::from(end.is_some()));
            if let Some((seq, offset)) = end {
                header.extend(seq.to_be_bytes());
                header.extend(offset.to_be_bytes());
            }
            None
        }
        Reply::Failed(code) => {
            header.extend([4, code]);
            None
        }
    };
    send.write_all(&header).await?;
    if let Some(data) = data {
        send.write_all(&data).await?;
    }
    send.finish()?;
    Ok(())
}
