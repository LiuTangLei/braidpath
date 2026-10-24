//! Data-ready backlog and observed service, independent of future-data waiters.
use super::*;

#[derive(Default)]
struct Estimate {
    rate: f64,
    pending: usize,
    updated: Option<Instant>,
    generation: u64,
}
#[derive(Default)]
pub(crate) struct PathService(Mutex<Estimate>);
impl PathService {
    pub(crate) fn snapshot(&self) -> (u64, usize) {
        let state = self.0.lock().expect("path service");
        (state.rate as u64, state.pending)
    }
    pub(crate) fn reset(&self) {
        let mut state = self.0.lock().expect("path service");
        state.rate = 0.0;
        state.updated = None;
        state.generation = state.generation.wrapping_add(1);
    }
    pub(crate) fn cost(&self, bytes: usize, rtt: Duration, busy: bool) -> f64 {
        let state = self.0.lock().expect("path service");
        if state.rate == 0.0
            || state
                .updated
                .is_none_or(|at| at.elapsed() > Duration::from_secs(30))
        {
            return if busy { f64::INFINITY } else { 0.0 };
        }
        rtt.as_secs_f64() + (state.pending + bytes) as f64 / state.rate
    }
    pub(crate) fn start(self: &Arc<Self>, records: usize) -> Delivery {
        let mut state = self.0.lock().expect("path service");
        let pending = records * CHUNK;
        state.pending += pending;
        Delivery {
            service: self.clone(),
            generation: state.generation,
            remaining: pending,
            bytes: 0,
            start: Instant::now(),
        }
    }
}
pub(crate) struct Delivery {
    service: Arc<PathService>,
    generation: u64,
    remaining: usize,
    bytes: usize,
    start: Instant,
}
impl Delivery {
    pub(crate) fn record(&mut self, bytes: usize) {
        self.remaining -= CHUNK;
        self.bytes += bytes;
        self.service.0.lock().expect("path service").pending -= CHUNK;
    }
}
impl Drop for Delivery {
    fn drop(&mut self) {
        let mut state = self.service.0.lock().expect("path service");
        state.pending -= self.remaining;
        if self.bytes >= CHUNK && state.generation == self.generation {
            let sample = (self.bytes as f64 / self.start.elapsed().as_secs_f64().max(0.001))
                .min(crate::runtime::MAX_RATE_BPS as f64 / 8.0);
            state.rate = if state.rate == 0.0 {
                sample
            } else {
                state.rate * 0.75 + sample * 0.25
            };
            state.updated = Some(Instant::now());
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn seed(service: &Arc<PathService>, duration: Duration) {
        let mut delivery = service.start(8);
        delivery.start = Instant::now() - duration;
        for _ in 0..8 {
            delivery.record(CHUNK);
        }
    }
    #[test]
    fn future_waiters_do_not_hide_a_fast_path_and_real_backlog_spreads_service() {
        let fast = Arc::new(PathService::default());
        let slow = Arc::new(PathService::default());
        seed(&fast, Duration::from_millis(100));
        seed(&slow, Duration::from_millis(400));
        let rtt = Duration::from_millis(100);
        assert!(
            fast.cost(CHUNK * 8, rtt, true) < slow.cost(CHUNK * 8, rtt, false),
            "future waiter masked usable network capacity"
        );
        let queued = fast.start(128);
        assert!(
            slow.cost(CHUNK * 8, rtt, false) < fast.cost(CHUNK * 8, rtt, true),
            "ready payload backlog did not spread work"
        );
        drop(queued);
        assert_eq!(fast.0.lock().unwrap().pending, 0);
    }
    #[test]
    fn cancelled_payload_returns_backlog_without_overwriting_a_recovered_generation() {
        let service = Arc::new(PathService::default());
        let mut old = service.start(8);
        old.record(CHUNK);
        service.reset();
        drop(old);
        let state = service.0.lock().unwrap();
        assert_eq!(state.pending, 0);
        assert_eq!(state.rate, 0.0);
        drop(state);
        assert_eq!(service.cost(CHUNK, Duration::from_millis(1), false), 0.0);
    }
}
