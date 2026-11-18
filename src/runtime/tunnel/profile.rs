//! Opt-in timing of the reliable-stream pipeline. These are wall
//! durations, not CPU time. Overlapping wait subsets are labelled separately.
use serde::Serialize;
use std::{
    future::Future,
    time::{Duration, Instant},
};

pub(super) fn enabled() -> bool {
    std::env::var_os("BRAIDPATH_PIPELINE_PROFILE").is_some()
}

fn ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn us(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

#[derive(Default, Serialize)]
pub(super) struct SenderCounters {
    pub turns: u64,
    pub input_turns: u64,
    pub tick_turns: u64,
    pub evidence_turns: u64,
    pub ready_turns: u64,
    pub admissions: u64,
    pub queue_peak_records: usize,
    wait_wall_us: u64,
    queued_wait_wall_us: u64,
    native_pending_wait_wall_us: u64,
    turn_wall_us: u64,
    max_turn_wall_us: u64,
    paths_lock_wall_ns: u64,
    max_paths_lock_wall_ns: u64,
}

pub(super) struct Sender {
    pub counters: SenderCounters,
    started: Instant,
    work: Option<Instant>,
    direction: &'static str,
}
impl Sender {
    pub fn new(direction: &'static str) -> Option<Self> {
        enabled().then(|| Self {
            counters: SenderCounters::default(),
            started: Instant::now(),
            work: None,
            direction,
        })
    }
    pub fn waited(&mut self, duration: Duration, queue: usize, native_pending: bool) {
        let elapsed = us(duration);
        self.counters.turns += 1;
        self.counters.queue_peak_records = self.counters.queue_peak_records.max(queue);
        self.counters.wait_wall_us += elapsed;
        if queue > 0 {
            self.counters.queued_wait_wall_us += elapsed;
        }
        if native_pending {
            self.counters.native_pending_wait_wall_us += elapsed;
        }
        self.work = Some(Instant::now());
    }
    pub fn locked(&mut self, duration: Duration) {
        let elapsed = ns(duration);
        self.counters.paths_lock_wall_ns += elapsed;
        self.counters.max_paths_lock_wall_ns = self.counters.max_paths_lock_wall_ns.max(elapsed);
    }
    pub fn finish_turn(&mut self) {
        if let Some(started) = self.work.take() {
            let elapsed = us(started.elapsed());
            self.counters.turn_wall_us += elapsed;
            self.counters.max_turn_wall_us = self.counters.max_turn_wall_us.max(elapsed);
        }
    }
}
impl Drop for Sender {
    fn drop(&mut self) {
        self.finish_turn();
        if let Ok(json) = serde_json::to_string(&self.counters) {
            tracing::info!(target: "braidpath::pipeline_profile", role="sender",
                direction=self.direction, elapsed_wall_us=us(self.started.elapsed()),
                counters=%json, "pipeline timing profile");
        }
    }
}

#[derive(Default, Serialize)]
pub(super) struct WriterCounters {
    pub turns: u64,
    pub api_calls: u64,
    pub budget_blocks: u64,
    pub max_turn_datagrams: u64,
    pub api_wall_ns: u64,
    pub max_api_wall_ns: u64,
    wait_wall_us: u64,
    queued_wait_wall_us: u64,
    native_buffered_wait_wall_us: u64,
}
pub(super) struct Writer {
    pub counters: WriterCounters,
    started: Instant,
    connection: usize,
}
impl Writer {
    pub fn new(connection: usize) -> Option<Self> {
        enabled().then(|| Self {
            counters: WriterCounters::default(),
            started: Instant::now(),
            connection,
        })
    }
    pub fn called(&mut self, duration: Duration) {
        let elapsed = ns(duration);
        self.counters.api_calls += 1;
        self.counters.api_wall_ns += elapsed;
        self.counters.max_api_wall_ns = self.counters.max_api_wall_ns.max(elapsed);
    }
    pub fn waited(&mut self, duration: Duration, queued: bool, native_buffered: bool) {
        let elapsed = us(duration);
        self.counters.wait_wall_us += elapsed;
        if queued {
            self.counters.queued_wait_wall_us += elapsed;
        }
        if native_buffered {
            self.counters.native_buffered_wait_wall_us += elapsed;
        }
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        if let Ok(json) = serde_json::to_string(&self.counters) {
            tracing::info!(target: "braidpath::pipeline_profile", role="writer",
                connection=self.connection, elapsed_wall_us=us(self.started.elapsed()),
                counters=%json, "pipeline timing profile");
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum NativeAdmission {
    Budget,
    Channel,
}

#[derive(Default, Serialize)]
struct NativeReadCounters {
    body_records: u64,
    budget_waits: u64,
    budget_wait_us: u64,
    budget_wait_max_us: u64,
    channel_waits: u64,
    channel_wait_us: u64,
    channel_wait_max_us: u64,
    cancelled_waits: u64,
    datagram_frames_during_wait: u64,
    datagram_reads: u64,
    datagram_read_gap_max_us: u64,
    datagram_read_gap_after_wait_max_us: u64,
}

pub(super) struct NativeReader {
    counters: NativeReadCounters,
    started: Instant,
    last_report: Instant,
    last_datagram: Option<Instant>,
    waited_since_datagram: bool,
    connection: usize,
}

impl NativeReader {
    pub fn new(connection: usize) -> Option<Self> {
        enabled().then(|| {
            let now = Instant::now();
            Self {
                counters: NativeReadCounters::default(),
                started: now,
                last_report: now,
                last_datagram: None,
                waited_since_datagram: false,
                connection,
            }
        })
    }

    pub fn record(&mut self) {
        self.counters.body_records += 1;
        self.report(false);
    }

    pub fn datagram(&mut self, now: Instant) {
        if let Some(previous) = self.last_datagram.replace(now) {
            let gap = us(now.saturating_duration_since(previous));
            self.counters.datagram_read_gap_max_us =
                self.counters.datagram_read_gap_max_us.max(gap);
            if self.waited_since_datagram {
                self.counters.datagram_read_gap_after_wait_max_us =
                    self.counters.datagram_read_gap_after_wait_max_us.max(gap);
            }
        }
        self.waited_since_datagram = false;
        self.counters.datagram_reads += 1;
        self.report(false);
    }

    fn waited(&mut self, kind: NativeAdmission, duration: Duration, frames: u64, cancelled: bool) {
        let duration = us(duration);
        let (count, sum, maximum) = match kind {
            NativeAdmission::Budget => (
                &mut self.counters.budget_waits,
                &mut self.counters.budget_wait_us,
                &mut self.counters.budget_wait_max_us,
            ),
            NativeAdmission::Channel => (
                &mut self.counters.channel_waits,
                &mut self.counters.channel_wait_us,
                &mut self.counters.channel_wait_max_us,
            ),
        };
        *count += 1;
        *sum += duration;
        *maximum = (*maximum).max(duration);
        self.counters.cancelled_waits += u64::from(cancelled);
        self.counters.datagram_frames_during_wait += frames;
        self.waited_since_datagram = true;
        self.report(false);
    }

    fn report(&mut self, final_sample: bool) {
        if !final_sample && self.last_report.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_report = Instant::now();
        if let Ok(json) = serde_json::to_string(&self.counters) {
            tracing::info!(target: "braidpath::pipeline_profile", role="native_reader",
                connection=self.connection, final_sample,
                elapsed_wall_us=us(self.started.elapsed()), counters=%json,
                "native receive admission profile");
        }
    }
}

impl Drop for NativeReader {
    fn drop(&mut self) {
        self.report(true);
    }
}

/// Record only futures that really yield Pending, including cancellation.
/// The frame counter is sampled only at those waits, not for each native record.
pub(super) async fn native_admission<F: Future, C: Fn() -> u64>(
    reader: Option<&std::sync::Mutex<NativeReader>>,
    kind: NativeAdmission,
    frames: C,
    future: F,
) -> F::Output {
    let Some(reader) = reader else {
        return future.await;
    };
    struct Wait<'a, C: Fn() -> u64> {
        reader: &'a std::sync::Mutex<NativeReader>,
        kind: NativeAdmission,
        frames: C,
        pending: Option<(Instant, u64)>,
        completed: bool,
    }
    impl<C: Fn() -> u64> Drop for Wait<'_, C> {
        fn drop(&mut self) {
            if let Some((at, before)) = self.pending {
                let frames = (self.frames)().saturating_sub(before);
                self.reader.lock().expect("native profile lock").waited(
                    self.kind,
                    at.elapsed(),
                    frames,
                    !self.completed,
                );
            }
        }
    }
    let mut future = std::pin::pin!(future);
    let mut wait = Wait {
        reader,
        kind,
        frames,
        pending: None,
        completed: false,
    };
    let output = std::future::poll_fn(|cx| {
        let result = future.as_mut().poll(cx);
        if result.is_pending() && wait.pending.is_none() {
            wait.pending = Some((Instant::now(), (wait.frames)()));
        }
        result
    })
    .await;
    wait.completed = true;
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_reader() -> NativeReader {
        let now = Instant::now();
        NativeReader {
            counters: NativeReadCounters::default(),
            started: now,
            last_report: now,
            last_datagram: None,
            waited_since_datagram: false,
            connection: 0,
        }
    }

    #[tokio::test]
    async fn native_admission_ready_does_not_sample_native_counters() {
        let reader = std::sync::Mutex::new(native_reader());
        let output = native_admission(
            Some(&reader),
            NativeAdmission::Budget,
            || panic!("a ready admission must not query native counters"),
            std::future::ready(7),
        )
        .await;
        assert_eq!(output, 7);
        assert_eq!(reader.lock().unwrap().counters.budget_waits, 0);
    }

    #[tokio::test]
    async fn native_admission_pending_records_frames_once() {
        let reader = std::sync::Mutex::new(native_reader());
        let frames = std::cell::Cell::new(0u64);
        let mut first = true;
        native_admission(
            Some(&reader),
            NativeAdmission::Channel,
            || {
                let value = frames.get();
                frames.set(value + 2);
                value
            },
            std::future::poll_fn(|cx| {
                if std::mem::take(&mut first) {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(())
                }
            }),
        )
        .await;
        assert_eq!(reader.lock().unwrap().counters.channel_waits, 1);
        assert_eq!(reader.lock().unwrap().counters.budget_waits, 0);
        assert_eq!(
            reader.lock().unwrap().counters.datagram_frames_during_wait,
            2
        );
        assert_eq!(reader.lock().unwrap().counters.cancelled_waits, 0);
    }

    #[tokio::test]
    async fn native_admission_cancellation_keeps_the_wait_observation() {
        let reader = std::sync::Mutex::new(native_reader());
        let frames = std::cell::Cell::new(0u64);
        let mut wait = Box::pin(native_admission(
            Some(&reader),
            NativeAdmission::Budget,
            || frames.get(),
            std::future::pending::<()>(),
        ));
        std::future::poll_fn(|cx| {
            assert!(wait.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        frames.set(3);
        drop(wait);
        assert_eq!(reader.lock().unwrap().counters.budget_waits, 1);
        assert_eq!(reader.lock().unwrap().counters.cancelled_waits, 1);
        assert_eq!(
            reader.lock().unwrap().counters.datagram_frames_during_wait,
            3
        );
    }

    #[test]
    fn native_datagram_gaps_separate_wait_association_from_idle_gaps() {
        let mut reader = native_reader();
        let now = Instant::now();
        reader.datagram(now);
        reader.waited(NativeAdmission::Budget, Duration::from_millis(10), 2, false);
        reader.datagram(now + Duration::from_millis(100));
        reader.datagram(now + Duration::from_millis(300));
        assert_eq!(reader.counters.budget_wait_us, 10_000);
        assert_eq!(reader.counters.datagram_read_gap_max_us, 200_000);
        assert_eq!(reader.counters.datagram_read_gap_after_wait_max_us, 100_000);
    }

    #[test]
    fn wait_subsets_do_not_double_count_the_total() {
        let mut p = Writer {
            counters: WriterCounters::default(),
            started: Instant::now(),
            connection: 0,
        };
        p.waited(Duration::from_micros(40), true, true);
        p.waited(Duration::from_micros(60), false, true);
        p.waited(Duration::from_micros(20), false, false);
        p.called(Duration::from_micros(7));
        p.called(Duration::from_micros(3));
        assert_eq!(p.counters.wait_wall_us, 120);
        assert_eq!(p.counters.queued_wait_wall_us, 40);
        assert_eq!(p.counters.native_buffered_wait_wall_us, 100);
        assert_eq!(p.counters.api_wall_ns, 10_000);
        assert_eq!(p.counters.max_api_wall_ns, 7_000);
    }
}
