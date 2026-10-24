//! One logical TCP flow over independently recoverable, authenticated QUIC paths.
//! Record RPC acknowledgements are independent of QUIC ACKs and of path identity.
use super::*;
use anyhow::Context;
use bytes::Bytes;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

mod server;
mod service;
mod transfer;
mod wire;
pub(crate) use server::Registry;
pub(crate) use service::{Delivery, PathService};
pub(crate) use transfer::open;
pub(crate) use wire::{
    ACK_FIN, BUSY, CLOSE, DOWNLOAD_ACK, FIN, Incoming, Key, OPEN, Operation, PULL, PUT, Reply,
    StreamSink, UPLOAD_STATUS, respond, rpc,
};

pub(super) const CHUNK: usize = 128 * 1024;
const WINDOW: usize = 16 * 1024 * 1024;
const PIPELINE: usize = WINDOW / CHUNK;
const MAX_BATCH: usize = 32;
const HOST_BUFFER: usize = 32 * 1024 * 1024;
pub(crate) const MAX_FLOWS: usize = 256;
const PATH_STALL: Duration = Duration::from_secs(4);
const RESUME_GRACE: Duration = Duration::from_secs(10);

pub(crate) struct Block {
    sequence: u64,
    offset: u64,
    data: Bytes,
    _credit: OwnedSemaphorePermit,
}
struct Signal {
    changed: Notify,
    closed: AtomicBool,
    activity: Mutex<Instant>,
}
impl Signal {
    fn new() -> Self {
        Self {
            changed: Notify::new(),
            closed: AtomicBool::new(false),
            activity: Mutex::new(Instant::now()),
        }
    }
    fn touch(&self) {
        *self.activity.lock().expect("flow activity") = Instant::now();
    }
    fn check(&self) -> Result<()> {
        ensure!(
            !self.closed.load(Ordering::Acquire),
            "aggregate TCP flow closed"
        );
        Ok(())
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
    async fn cancelled(&self) {
        loop {
            let changed = self.changed.notified();
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

// Drain only bytes already available. Small interactive writes never wait for
// a full record, while bulk TCP reads do not spend one RPC on each short read.
async fn read_record(tcp: &mut tokio::net::tcp::OwnedReadHalf, buffer: &mut [u8]) -> Result<usize> {
    let mut n = tcp.read(buffer).await?;
    if n == 0 {
        return Ok(0);
    }
    while n < buffer.len() {
        match tcp.try_read(&mut buffer[n..]) {
            Ok(0) => break,
            Ok(read) => n += read,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(n)
}
