//! Bidirectional relay accounting. Mesh leases share the server's byte budget;
//! recently busy leases also have bounded fair shares so a hot socket cannot
//! consume every refill before another lease gets a turn.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const BURST: f64 = 16.0 * 2048.0;
const MAX_COST: f64 = 2048.0 + 48.0;
const ACTIVE_FOR: Duration = Duration::from_secs(1);
const REFRESH_EVERY: Duration = Duration::from_millis(100);

pub(super) struct Bucket {
    tokens: f64,
    last: Instant,
    rate: f64,
    burst: f64,
}
impl Bucket {
    fn new(rate: f64, now: Instant) -> Self {
        Self {
            tokens: (rate * 0.010).max(BURST),
            last: now,
            rate,
            burst: (rate * 0.010).max(BURST),
        }
    }
    fn refill(&mut self, now: Instant) {
        // Callers on different workers can arrive out of timestamp order.
        // Never count an already-refilled interval a second time.
        if now <= self.last {
            return;
        }
        self.tokens = (self.tokens
            + now.saturating_duration_since(self.last).as_secs_f64() * self.rate)
            .min(self.burst);
        self.last = now;
    }
}

struct Share {
    bucket: Bucket,
    touched: Option<Instant>,
    active: bool,
}
struct State {
    total: Bucket,
    shares: BTreeMap<u64, Share>,
    next: u64,
    refreshed: Instant,
}
impl State {
    fn rebalance(&mut self, now: Instant) {
        let active = self
            .shares
            .values()
            .filter(|s| {
                s.touched
                    .is_some_and(|at| now.saturating_duration_since(at) < ACTIVE_FOR)
            })
            .count();
        let rate = self.total.rate / active.max(1) as f64;
        let burst = (self.total.burst / active.max(1) as f64).max(MAX_COST);
        for share in self.shares.values_mut() {
            share.bucket.refill(now);
            let busy = share
                .touched
                .is_some_and(|at| now.saturating_duration_since(at) < ACTIVE_FOR);
            share.bucket.tokens = if busy && !share.active {
                burst
            } else if busy {
                share.bucket.tokens.min(burst)
            } else {
                0.0
            };
            share.bucket.rate = if busy { rate } else { 0.0 };
            share.bucket.burst = burst;
            share.active = busy;
        }
        self.refreshed = now;
    }
    fn take(&mut self, id: u64, n: usize, now: Instant) -> bool {
        let now = now.max(self.total.last);
        let share = self.shares.get_mut(&id).expect("registered relay lease");
        let newly_active = !share.active;
        // Unserved demand counts too; otherwise an overloaded lease could lose
        // its share merely because every one of its packets was rejected.
        share.touched = Some(now);
        if newly_active || now.saturating_duration_since(self.refreshed) >= REFRESH_EVERY {
            self.rebalance(now);
        }
        self.total.refill(now);
        let share = self.shares.get_mut(&id).expect("registered relay lease");
        share.bucket.refill(now);
        let cost = (n + 48) as f64;
        if self.total.tokens < cost || share.bucket.tokens < cost {
            return false;
        }
        self.total.tokens -= cost;
        share.bucket.tokens -= cost;
        true
    }
}

pub(crate) struct HostBudget(Mutex<State>);
impl HostBudget {
    pub(crate) fn new(rate: u64) -> Self {
        let now = Instant::now();
        Self(Mutex::new(State {
            total: Bucket::new(rate as f64 / 8.0, now),
            shares: BTreeMap::new(),
            next: 0,
            refreshed: now,
        }))
    }
    fn register(self: &Arc<Self>) -> Lease {
        let mut state = self.0.lock().expect("host relay budget");
        let id = state.next;
        state.next += 1;
        let now = Instant::now();
        state.shares.insert(
            id,
            Share {
                bucket: Bucket::new(0.0, now),
                touched: None,
                active: false,
            },
        );
        Lease {
            host: self.clone(),
            id,
        }
    }
}
pub(super) struct Lease {
    host: Arc<HostBudget>,
    id: u64,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.host.0.lock().expect("host relay budget");
        state.shares.remove(&self.id);
        state.rebalance(Instant::now());
    }
}

pub(super) enum Budget {
    Local(Mutex<Bucket>),
    Shared(Lease),
}
impl Budget {
    pub(super) fn new(rate: u64, host: Option<Arc<HostBudget>>) -> Self {
        match host {
            Some(host) => Self::Shared(host.register()),
            None => Self::Local(Mutex::new(Bucket::new(rate as f64 / 8.0, Instant::now()))),
        }
    }
    pub(super) fn take(&self, n: usize) -> bool {
        let now = Instant::now();
        match self {
            Self::Shared(lease) => lease
                .host
                .0
                .lock()
                .expect("host relay budget")
                .take(lease.id, n, now),
            Self::Local(bucket) => {
                let mut bucket = bucket.lock().expect("relay budget");
                bucket.refill(now);
                let cost = (n + 48) as f64;
                if bucket.tokens < cost {
                    false
                } else {
                    bucket.tokens -= cost;
                    true
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_worker_cannot_reissue_an_already_spent_interval() {
        let start = Instant::now();
        let mut bucket = Bucket::new(1000.0, start);
        bucket.tokens = 0.0;
        bucket.refill(start + Duration::from_secs(1));
        assert_eq!(bucket.tokens, 1000.0);
        bucket.tokens = 0.0;
        bucket.refill(start + Duration::from_millis(500));
        bucket.refill(start + Duration::from_secs(1));
        assert_eq!(bucket.tokens, 0.0);
    }

    #[test]
    fn high_rate_credit_survives_millisecond_worker_scheduling_without_exceeding_its_budget() {
        let host = Arc::new(HostBudget::new(10_000_000_000));
        let lease = host.register();
        let mut state = host.0.lock().unwrap();
        let start = state.total.last;
        // Ten 1 ms batches at 1 Gbit/s must not be cut to the old 32 KiB burst.
        // The old fixed burst rejects most of each batch despite a 10 Gbit/s cap.
        let mut admitted = 0;
        for ms in 0..10 {
            for _ in 0..100 {
                assert!(state.take(lease.id, 1200, start + Duration::from_millis(ms)));
                admitted += 1248;
            }
        }
        assert_eq!(admitted, 1_248_000);
        state.total.tokens = 0.0;
        state.shares.get_mut(&lease.id).unwrap().bucket.tokens = 0.0;
        let now = start + Duration::from_millis(10);
        let mut bytes = 0;
        while state.take(lease.id, 1200, now) {
            bytes += 1248;
        }
        assert!(
            bytes as f64 <= 1_250_000.0,
            "new burst manufactured refill credit"
        );
    }

    #[test]
    fn concurrent_leases_share_one_bidirectional_byte_and_burst_budget() {
        let host = Arc::new(HostBudget::new(1_000_000));
        let leases: Vec<_> = (0..4).map(|_| host.register()).collect();
        let mut state = host.0.lock().unwrap();
        let start = state.total.last;
        let mut bytes = 0;
        let mut served = [0; 4];
        // The first lease always runs first and offers ten times as many
        // packets. Forward and return draws use this exact same account.
        for ms in 0..2000 {
            let now = start + Duration::from_millis(ms);
            for (i, lease) in leases.iter().enumerate() {
                for _ in 0..if i == 0 { 20 } else { 2 } {
                    if state.take(lease.id, 1200, now) {
                        bytes += 1248;
                        served[i] += 1;
                    }
                }
            }
            assert!(bytes as f64 <= BURST + ms as f64 * 125.0);
        }
        assert!(served.iter().all(|n| *n >= 40), "starved lease: {served:?}");
        assert!(
            served[0] <= served[1] + 32,
            "hot lease took others' refill: {served:?}"
        );
    }

    #[test]
    fn inactive_and_released_leases_return_capacity_without_refilling_total() {
        let host = Arc::new(HostBudget::new(1_000_000));
        let hot = host.register();
        let idle = host.register();
        let now = Instant::now();
        {
            let mut state = host.0.lock().unwrap();
            assert!(state.take(hot.id, 1200, now));
            assert!(state.take(idle.id, 1200, now));
            assert_eq!(state.shares[&hot.id].bucket.rate, 62_500.0);
            assert!(state.take(hot.id, 1200, now + ACTIVE_FOR));
            assert_eq!(state.shares[&hot.id].bucket.rate, 125_000.0);
            state.total.tokens = 0.0;
        }
        drop(idle);
        let state = host.0.lock().unwrap();
        assert_eq!(state.shares.len(), 1);
        assert_eq!(
            state.total.tokens, 0.0,
            "lease removal grants no host credit"
        );
    }
}
