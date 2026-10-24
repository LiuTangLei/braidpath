//! Host-wide retained stream bytes; a flow's progress reserve is never shared.
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
const SHARED: usize = 32 * 1024 * 1024;
const RESERVED: usize = 128 * 1024;
const FLOWS: usize = 256;

struct Pool {
    shared: Mutex<(usize, usize)>,
    notify: Notify,
}
impl Default for Pool {
    fn default() -> Self {
        Self {
            shared: Mutex::new((0, 0)),
            notify: Notify::new(),
        }
    }
}
pub(crate) struct Budget {
    flows: Arc<Semaphore>,
    tx: Arc<Pool>,
    rx: Arc<Pool>,
    rate: Option<Arc<crate::runtime::proxy::Rate>>,
}
impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}
impl Budget {
    pub(crate) fn new() -> Self {
        Self {
            flows: Arc::new(Semaphore::new(FLOWS)),
            tx: Arc::default(),
            rx: Arc::default(),
            rate: None,
        }
    }
    pub(crate) fn with_rate(rate: Arc<crate::runtime::proxy::Rate>) -> Self {
        Self {
            rate: Some(rate),
            ..Self::default()
        }
    }
    pub(crate) fn snapshot(&self) -> (usize, usize) {
        (
            FLOWS - self.flows.available_permits(),
            self.tx.shared.lock().expect("stream budget").1
                + self.rx.shared.lock().expect("stream budget").1,
        )
    }
    pub(super) fn try_flow(&self) -> Option<Arc<Lease>> {
        let permit = Arc::new(self.flows.clone().try_acquire_owned().ok()?);
        Some(Arc::new(Lease {
            tx: Arc::new(Allowance::new(self.tx.clone(), permit.clone())),
            rx: Arc::new(Allowance::new(self.rx.clone(), permit)),
            tx_held: Mutex::default(),
            rx_held: Mutex::default(),
            rate: self.rate.clone(),
        }))
    }
    pub(super) async fn flow(&self) -> Arc<Lease> {
        let permit = Arc::new(
            self.flows
                .clone()
                .acquire_owned()
                .await
                .expect("stream flow budget"),
        );
        Arc::new(Lease {
            tx: Arc::new(Allowance::new(self.tx.clone(), permit.clone())),
            rx: Arc::new(Allowance::new(self.rx.clone(), permit)),
            tx_held: Mutex::default(),
            rx_held: Mutex::default(),
            rate: self.rate.clone(),
        })
    }
}
pub(super) struct Lease {
    pub tx: Arc<Allowance>,
    pub rx: Arc<Allowance>,
    tx_held: Mutex<VecDeque<Credit>>,
    rx_held: Mutex<VecDeque<Credit>>,
    pub rate: Option<Arc<crate::runtime::proxy::Rate>>,
}
impl Lease {
    pub fn retain_tx(&self, credit: Credit) {
        if credit.len() > 0 {
            self.tx_held.lock().expect("TX credit").push_back(credit);
        }
    }
    pub fn retain_rx(&self, credit: Credit) {
        if credit.len() > 0 {
            self.rx_held.lock().expect("RX credit").push_back(credit);
        }
    }
    pub fn release_tx(&self, bytes: usize) {
        release(&mut self.tx_held.lock().expect("TX credit"), bytes);
    }
    pub fn release_rx(&self, bytes: usize) {
        release(&mut self.rx_held.lock().expect("RX credit"), bytes);
    }
}
fn release(credits: &mut VecDeque<Credit>, mut bytes: usize) {
    while bytes > 0 {
        let Some(front) = credits.front_mut() else {
            break;
        };
        let freed = bytes.min(front.len());
        front.release(freed);
        bytes -= freed;
        if front.len() == 0 {
            credits.pop_front();
        }
    }
}
pub(super) struct Allowance {
    pool: Arc<Pool>,
    reserved: AtomicUsize,
    _flow: Arc<OwnedSemaphorePermit>,
}
impl Allowance {
    fn new(pool: Arc<Pool>, permit: Arc<OwnedSemaphorePermit>) -> Self {
        Self {
            pool,
            reserved: AtomicUsize::new(0),
            _flow: permit,
        }
    }
    pub fn try_take(self: &Arc<Self>, bytes: usize, progress: bool) -> Option<Credit> {
        let mut used = self.pool.shared.lock().expect("stream budget");
        let shared = bytes.min(SHARED - used.0);
        let reserved = bytes - shared;
        if reserved > 0
            && (!progress || reserved > RESERVED - self.reserved.load(Ordering::Relaxed))
        {
            return None;
        }
        used.0 += shared;
        used.1 += bytes;
        self.reserved.fetch_add(reserved, Ordering::Relaxed);
        Some(Credit {
            allowance: self.clone(),
            shared,
            reserved,
        })
    }
    pub async fn take(self: &Arc<Self>, bytes: usize) -> Credit {
        loop {
            let notified = self.pool.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(credit) = self.try_take(bytes, true) {
                return credit;
            }
            notified.await;
        }
    }
}
pub(crate) struct Credit {
    allowance: Arc<Allowance>,
    shared: usize,
    reserved: usize,
}
impl Credit {
    pub fn len(&self) -> usize {
        self.shared + self.reserved
    }
    pub fn truncate(&mut self, keep: usize) {
        self.release(self.len().saturating_sub(keep));
    }
    fn release(&mut self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let reserved = bytes.min(self.reserved);
        let shared = bytes - reserved;
        self.reserved -= reserved;
        self.shared -= shared;
        let mut used = self.allowance.pool.shared.lock().expect("stream budget");
        used.0 -= shared;
        used.1 -= bytes;
        self.allowance
            .reserved
            .fetch_sub(reserved, Ordering::Relaxed);
        drop(used);
        self.allowance.pool.notify.notify_waiters();
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        self.release(self.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_credit_is_shared_and_hole_progress_has_its_own_reserve() {
        let budget = Budget::default();
        let blocked = budget.try_flow().unwrap();
        let other = budget.try_flow().unwrap();
        let held = blocked.rx.try_take(SHARED, false).unwrap();
        assert!(other.rx.try_take(1, false).is_none());
        let repair = other.rx.try_take(RESERVED, true).unwrap();
        assert!(other.rx.try_take(1, true).is_none());
        assert_eq!(budget.snapshot(), (2, SHARED + RESERVED));
        drop(repair);
        drop(held);
        drop(blocked);
        drop(other);
        assert_eq!(budget.snapshot(), (0, 0));
    }
    #[test]
    fn cumulative_ack_releases_exact_bytes_without_recharging_retransmissions() {
        let budget = Budget::default();
        let lease = budget.try_flow().unwrap();
        lease.retain_tx(lease.tx.try_take(1000, true).unwrap());
        lease.release_tx(300);
        assert_eq!(budget.snapshot(), (1, 700));
        lease.release_tx(700);
        assert_eq!(budget.snapshot(), (1, 0));
        let io_owner = lease.clone();
        drop(lease);
        assert_eq!(budget.snapshot().0, 1);
        drop(io_owner);
        assert_eq!(budget.snapshot(), (0, 0));
    }
}
