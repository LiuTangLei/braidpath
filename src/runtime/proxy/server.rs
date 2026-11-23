use super::*;
use anyhow::Context;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_SERVER_UDP_DESTINATIONS: usize = 1024;

#[derive(Clone, Copy, Debug, Default)]
pub struct ServerConfig {
    pub allow_private: bool,
}
pub struct Server {
    rate: Arc<Rate>,
    stream_budget: Arc<crate::runtime::tunnel::tcp::Budget>,
    associations: Arc<Semaphore>,
    destinations: Arc<Semaphore>,
    rejected: AtomicU64,
}
#[derive(Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub connections: usize,
    pub streams: usize,
    pub udp_associations: usize,
    pub udp_destinations: usize,
    pub rejected: u64,
    #[serde(default)]
    pub tcp_flows: usize,
    #[serde(default)]
    pub udp_flows: usize,
    #[serde(default)]
    pub buffered_bytes: usize,
    #[serde(default)]
    pub control_streams: usize,
}
impl Server {
    pub fn new(
        _config: ServerConfig,
        token: String,
        _exit: String,
        rate_bps: u64,
    ) -> Result<Arc<Self>> {
        ensure!(
            (64_000..=crate::runtime::MAX_RATE_BPS).contains(&rate_bps),
            "invalid proxy rate"
        );
        ensure!(
            token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid proxy token"
        );
        let rate = Arc::new(Rate::new(rate_bps));
        let stream_budget = Arc::new(crate::runtime::tunnel::tcp::Budget::with_rate(rate.clone()));
        Ok(Arc::new(Self {
            rate,
            stream_budget,
            associations: Arc::new(Semaphore::new(MAX_ASSOCIATIONS)),
            destinations: Arc::new(Semaphore::new(MAX_SERVER_UDP_DESTINATIONS)),
            rejected: AtomicU64::new(0),
        }))
    }
    pub(crate) fn stream_budget(&self) -> Arc<crate::runtime::tunnel::tcp::Budget> {
        self.stream_budget.clone()
    }
    pub(crate) fn reserve_udp_association(&self) -> Result<OwnedSemaphorePermit> {
        self.associations
            .clone()
            .try_acquire_owned()
            .context("proxy UDP association limit")
    }

    pub(crate) fn reserve_udp_destination(&self) -> Result<OwnedSemaphorePermit> {
        self.destinations
            .clone()
            .try_acquire_owned()
            .context("proxy UDP destination limit")
    }

    pub(crate) fn admit_udp_bytes(&self, bytes: usize) -> bool {
        self.rate.delay(bytes).is_none()
    }

    pub fn snapshot(&self) -> Snapshot {
        let (tcp_flows, buffered_bytes) = self.stream_budget.snapshot();
        let udp_flows = self.stream_budget.udp_flows();
        Snapshot {
            tcp_flows,
            udp_flows,
            buffered_bytes,
            connections: 0,
            streams: tcp_flows + udp_flows,
            control_streams: 0,
            udp_associations: MAX_ASSOCIATIONS - self.associations.available_permits(),
            udp_destinations: MAX_SERVER_UDP_DESTINATIONS - self.destinations.available_permits(),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
}
