//! Data-ready backlog and observed service, independent of future-data waiters.
use super::*;

const MIN_SAMPLE: Duration = Duration::from_millis(100);
const SAMPLE_WINDOW: Duration = Duration::from_secs(1);

struct SampleWindow {
    started: Instant,
    bytes: usize,
    baseline: f64,
}
#[derive(Default)]
struct Estimate {
    rate: f64,
    pending: usize,
    // Only ready batches belong to the capacity sample. A future-data waiter
    // must not keep its clock running when the source has stopped producing.
    busy: usize,
    window: Option<SampleWindow>,
    updated: Option<Instant>,
    generation: u64,
}
impl Estimate {
    fn received(&mut self, bytes: usize) {
        let Some(window) = &mut self.window else {
            return;
        };
        window.bytes += bytes;
        let elapsed = window.started.elapsed();
        if elapsed >= MIN_SAMPLE {
            let sample = (window.bytes as f64 / elapsed.as_secs_f64())
                .min(crate::runtime::MAX_RATE_BPS as f64 / 8.0);
            // Every concurrent request contributes to one observation. Keep the
            // baseline fixed within it instead of applying the EWMA per reply.
            self.rate = if window.baseline == 0.0 {
                sample
            } else {
                window.baseline * 0.75 + sample * 0.25
            };
            self.updated = Some(Instant::now());
        }
        if elapsed >= SAMPLE_WINDOW {
            self.window = Some(SampleWindow {
                started: Instant::now(),
                bytes: 0,
                baseline: self.rate,
            });
        }
    }
    fn release_busy(&mut self, bytes: usize) {
        self.busy -= bytes;
        if self.busy == 0 {
            self.window = None;
        }
    }
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
        state.busy = 0;
        state.window = None;
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
        let active = records > 1;
        state.pending += pending;
        if active {
            state.busy += pending;
        }
        Delivery {
            service: self.clone(),
            generation: state.generation,
            remaining: pending,
            active,
        }
    }
}
pub(crate) struct Delivery {
    service: Arc<PathService>,
    generation: u64,
    remaining: usize,
    active: bool,
}
impl Delivery {
    pub(crate) fn ready(&mut self, records: usize) {
        let mut state = self.service.0.lock().expect("path service");
        let extra = (records * CHUNK).saturating_sub(self.remaining);
        state.pending += extra;
        self.remaining += extra;
        if state.generation != self.generation {
            return;
        }
        if self.active {
            state.busy += extra;
        } else if records > 1 {
            state.busy += self.remaining;
            self.active = true;
        }
        if self.active && state.window.is_none() {
            // The first payload header starts the shared clock. Request setup
            // and waiting for a future source record are not delivery samples.
            state.window = Some(SampleWindow {
                started: Instant::now(),
                bytes: 0,
                baseline: state.rate,
            });
        }
    }
    /// Reserved records that will not be transferred on this path.
    pub(crate) fn skip(&mut self, records: usize) {
        let bytes = (records * CHUNK).min(self.remaining);
        self.remaining -= bytes;
        let mut state = self.service.0.lock().expect("path service");
        state.pending -= bytes;
        if self.active && state.generation == self.generation {
            state.release_busy(bytes);
        }
    }
    pub(crate) fn record(&mut self, bytes: usize) {
        self.remaining -= CHUNK;
        let mut state = self.service.0.lock().expect("path service");
        state.pending -= CHUNK;
        if self.active && state.generation == self.generation {
            state.received(bytes);
            state.release_busy(CHUNK);
        }
        if self.remaining == 0 {
            self.active = false;
        }
    }
}
impl Drop for Delivery {
    fn drop(&mut self) {
        let mut state = self.service.0.lock().expect("path service");
        state.pending -= self.remaining;
        if self.active && state.generation == self.generation {
            state.release_busy(self.remaining);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn concurrent_batches_measure_one_shared_path_not_each_requests_share() {
        let service = Arc::new(PathService::default());
        let mut deliveries: Vec<_> = (0..4).map(|_| service.start(4)).collect();
        for delivery in &mut deliveries {
            delivery.ready(4);
        }
        tokio::time::advance(Duration::from_millis(100)).await;
        for delivery in &mut deliveries {
            for _ in 0..4 {
                delivery.record(CHUNK);
            }
        }
        assert_eq!(service.snapshot(), ((CHUNK * 16 * 10) as u64, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn one_buffered_burst_cannot_replace_a_sustained_path_estimate() {
        let service = Arc::new(PathService::default());
        let mut bulk = service.start(16);
        bulk.ready(16);
        tokio::time::advance(Duration::from_millis(100)).await;
        for _ in 0..16 {
            bulk.record(CHUNK);
        }
        let learned = service.snapshot().0;
        let mut burst = service.start(4);
        burst.ready(4);
        tokio::time::advance(Duration::from_millis(1)).await;
        for _ in 0..4 {
            burst.record(CHUNK);
        }
        assert_eq!(service.snapshot(), (learned, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_wait_does_not_extend_a_finished_capacity_sample() {
        let service = Arc::new(PathService::default());
        let mut future = service.start(0);
        future.ready(1);
        let mut first = service.start(8);
        first.ready(8);
        tokio::time::advance(Duration::from_millis(100)).await;
        for _ in 0..8 {
            first.record(CHUNK);
        }
        let rate = service.snapshot().0;
        tokio::time::advance(Duration::from_secs(60)).await;
        future.record(16);
        let mut next = service.start(8);
        next.ready(8);
        tokio::time::advance(Duration::from_millis(100)).await;
        for _ in 0..8 {
            next.record(CHUNK);
        }
        assert_eq!(service.snapshot(), (rate, 0));
        let state = service.0.lock().unwrap();
        assert_eq!(state.busy, 0);
        assert!(state.window.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_and_skips_release_samples_across_path_replacement() {
        let service = Arc::new(PathService::default());
        let mut old = service.start(4);
        old.ready(4);
        service.reset();
        let mut new = service.start(4);
        new.ready(4);
        old.skip(1);
        old.ready(4);
        old.record(CHUNK);
        drop(old);
        tokio::time::advance(Duration::from_millis(100)).await;
        new.record(CHUNK);
        new.skip(1);
        drop(new);
        let state = service.0.lock().unwrap();
        assert_eq!(state.pending, 0);
        assert_eq!(state.busy, 0);
        assert!(state.window.is_none());
        assert_eq!(state.rate as u64, (CHUNK * 10) as u64);
    }
    fn seed(service: &Arc<PathService>, duration: Duration) {
        let mut delivery = service.start(8);
        delivery.ready(8);
        service.0.lock().unwrap().window.as_mut().unwrap().started = Instant::now() - duration;
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
