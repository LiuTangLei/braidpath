//! Opt-in, final-only timing of the reliable-stream pipeline. These are wall
//! durations, not CPU time. Overlapping wait subsets are labelled separately.
use serde::Serialize;
use std::time::{Duration, Instant};

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

#[cfg(test)]
mod tests {
    use super::*;

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
