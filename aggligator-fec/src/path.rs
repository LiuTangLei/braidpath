use std::{cmp, io, time::Duration};

const MAX_PATHS: usize = 32;
const MAX_RTT: Duration = Duration::from_secs(60);
const FAST_THRESHOLD: Duration = Duration::from_millis(5);
const MIN_STALE: Duration = Duration::from_millis(750);

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct PathSnapshot {
    pub srtt_ms: f64,
    pub jitter_ms: f64,
    pub loss: f64,
    /// Smoothed original-arrival deficit at the telemetry deadline, not probe loss.
    pub delivery_loss: f64,
    pub delivery_samples: u64,
    pub weight: u32,
    pub live: bool,
}

#[derive(Clone, Debug, Default)]
struct PathState {
    disabled: bool,
    srtt: Duration,
    jitter: Duration,
    loss: f64,
    delivery_loss: f64,
    delivery_samples: u64,
    delivery_at: Option<Duration>,
    last_probe: Option<Duration>,
    last_success: Option<Duration>,
    penalty: Duration,
}

#[derive(Clone, Debug)]
pub struct PathScheduler {
    count: usize,
    paths: Vec<PathState>,
    last_time: Option<Duration>,
    select_cursor: u64,
    repair_cursor: u64,
    preferred: Option<usize>,
    access_weights:Option<Vec<u32>>,
    access_credit:[i64;4],
    repair_access_credit:[i64;4],
}

impl PathScheduler {
    pub fn new(count: usize) -> Result<Self, io::Error> {
        if !(1..=MAX_PATHS).contains(&count) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path count must be in 1..={MAX_PATHS}"),
            ));
        }

        Ok(Self {
            count,
            paths: vec![PathState::default(); count],
            last_time: None,
            select_cursor: 0,
            repair_cursor: 0,
            preferred: None,
            access_weights:None,
            access_credit:[0;4],
            repair_access_credit:[0;4],
        })
    }

    /// Removal disables this slot without destroying the reliable stream or
    /// reassigning historical path indices. Re-addition requires a fresh probe.
    pub fn set_enabled(&mut self,path:usize,enabled:bool) {
        if !self.valid_path(path){return;}
        if self.paths[path].disabled==enabled {
            self.paths[path]=PathState{disabled:!enabled,..Default::default()};
            if self.preferred==Some(path){self.preferred=None;}
        }
    }
    pub fn is_enabled(&self,path:usize)->bool {self.valid_path(path)&&!self.paths[path].disabled}

    pub fn observe(&mut self, path: usize, rtt: Duration, now: Duration) {
        if !self.is_enabled(path) || !self.is_monotonic(now) {
            return;
        }
        if rtt.is_zero() || rtt > MAX_RTT {
            return;
        }

        let state = &mut self.paths[path];
        let prev = state.srtt;
        let alpha = if prev.is_zero() || rtt > prev { 0.35 } else { 0.2 };
        state.srtt = if prev.is_zero() {
            rtt
        } else {
            let prev_ms = prev.as_secs_f64() * 1000.0;
            let rtt_ms = rtt.as_secs_f64() * 1000.0;
            Duration::from_secs_f64((prev_ms * (1.0 - alpha) + rtt_ms * alpha) / 1000.0)
        };

        let delta = if prev.is_zero() {
            rtt / 2
        } else {
            rtt.abs_diff(prev)
        };
        let jitter = if state.jitter.is_zero() {
            delta
        } else {
            let prior_us = state.jitter.as_micros() as f64;
            let delta_us = delta.as_micros() as f64;
            Duration::from_micros((prior_us * 0.7 + delta_us * 0.3) as u64)
        };
        state.jitter = jitter;
        state.loss = (state.loss * 0.75).clamp(0.0, 1.0);
        state.penalty = state.penalty.saturating_sub(Duration::from_millis(100));
        state.last_probe = Some(now);
        state.last_success = Some(now);
        self.last_time = Some(now);
    }

    /// Passive, sampled payload quality. This does not acknowledge application
    /// data or revive a path. Small probes can stay fast while real packets drop.
    pub fn observe_delivery(&mut self, path: usize, samples: u32, missing: u32, now: Duration) {
        if !self.is_enabled(path) || !self.is_monotonic(now) || samples == 0
            || samples > 64 || missing > samples { return; }
        let state = &mut self.paths[path];
        let alpha = (f64::from(samples) / 64.0).min(0.5);
        let measured = f64::from(missing) / f64::from(samples);
        state.delivery_loss = (state.delivery_loss * (1.0-alpha) + measured*alpha).clamp(0.0,1.0);
        state.delivery_samples = state.delivery_samples.saturating_add(u64::from(samples));
        state.delivery_at = Some(now);
        self.last_time = Some(now);
    }

    pub fn timeout(&mut self, path: usize, now: Duration) {
        if !self.is_enabled(path) || !self.is_monotonic(now) {
            return;
        }

        let state = &mut self.paths[path];
        // Probe loss: a timeout indicates the path failed a probe, not that payload data was lost.
        state.loss = (state.loss + 0.35).clamp(0.0, 1.0);
        state.penalty = (state.penalty + Duration::from_millis(250)).min(Duration::from_secs(2));
        state.last_probe = Some(now);
        // A missing old probe is not proof the path is dead: a newer probe may
        // already have succeeded. Liveness expires from last_success instead.
        self.last_time = Some(now);
    }

    /// Estimated round-trip repair acknowledgement budget on the selected route.
    /// A trans-Pacific retry must not be repeated before its first copy can return.
    pub fn retry_delay(&mut self, now: Duration) -> Duration {
        let Some(path) = self.best(now) else { return Duration::from_millis(500); };
        let state = &self.paths[path];
        state.srtt.saturating_add(state.jitter.saturating_mul(4))
            .saturating_add(Duration::from_millis(20))
            .clamp(Duration::from_millis(120), Duration::from_secs(2))
    }

    pub fn best(&mut self, now: Duration) -> Option<usize> {
        let mut live = [None; MAX_PATHS];
        let live_count = self.collect_live_candidates(now, &mut live);
        if live_count == 0 {
            self.preferred = None;
            return None;
        }

        let mut best_idx = live[0].unwrap();
        let mut best_score = self.score(best_idx, now);
        for candidate in live.iter().take(live_count).flatten() {
            let candidate_score = self.score(*candidate, now);
            if candidate_score < best_score {
                best_idx = *candidate;
                best_score = candidate_score;
            }
        }

        if let Some(preferred) = self.preferred
            && self.is_live(preferred, now)
        {
            let preferred_score = self.score(preferred, now);
            if preferred_score.abs_diff(best_score) <= 1_000 {
                self.preferred = Some(preferred);
                return Some(preferred);
            }
        }

        self.preferred = Some(best_idx);
        Some(best_idx)
    }

    /// Separate physical access links may contribute capacity even if their RTTs
    /// differ. Entrances within one access link are NOT independent bandwidth.
    pub fn set_access_weights(&mut self,weights:Vec<u32>)->io::Result<()> {
        if weights.is_empty()||weights.len()>4||weights.iter().any(|w|*w==0||*w>1000){return Err(io::Error::other("invalid access weights"));}
        if self.access_weights.as_ref()!=Some(&weights){self.access_credit=[0;4];self.repair_access_credit=[0;4];self.access_weights=Some(weights);}Ok(())
    }
    fn access_candidates(&self,now:Duration)->([Option<usize>;4],[i64;4]) {
        let mut best=[None;4];let mut weights=[0;4];
        let Some(config)=&self.access_weights else{return(best,weights);};
        for lane in 0..self.count {
            let group=lane/8;if group>=config.len()||!self.is_live(lane,now){continue;}
            if best[group].is_none_or(|old|self.score(lane,now)<self.score(old,now)){best[group]=Some(lane);}
        }
        let fastest=best.iter().flatten().map(|i|self.score(*i,now)).min().unwrap_or(0);
        for group in 0..config.len(){if let Some(lane)=best[group]{
            let score=self.score(lane,now);
            // Do not force a badly degraded/very remote uplink into the stream.
            if score<=fastest.saturating_mul(3).saturating_add(50_000){
                weights[group]=i64::from(config[group]);
            }
        }}(best,weights)
    }
    pub fn select(&mut self, now: Duration) -> Option<usize> {
        if self.access_weights.as_ref().is_some_and(|w|w.len()>1){
            let(best,weights)=self.access_candidates(now);let total:i64=weights.iter().sum();
            if total==0{return self.best(now);}
            let mut chosen=None;
            for(i,weight)in weights.iter().enumerate(){
                if *weight==0{self.access_credit[i]=0;continue;}
                self.access_credit[i]+=*weight;
                if chosen.is_none_or(|old|self.access_credit[i]>self.access_credit[old]){chosen=Some(i);}
            }
            let group=chosen?;self.access_credit[group]-=total;return best[group];
        }
        let mut live = [None; MAX_PATHS];
        let live_count = self.collect_live_candidates(now, &mut live);
        if live_count == 0 {
            return None;
        }

        let best_idx = self.best(now)?;
        let best_score = self.score(best_idx, now);
        let best_rtt = Duration::from_micros(best_score as u64);
        let threshold = cmp::min(FAST_THRESHOLD, best_rtt / 10);

        let mut near = [None; MAX_PATHS];
        let mut near_count = 0usize;
        for candidate in live.iter().take(live_count).flatten() {
            if self.score(*candidate, now) <= best_score + threshold.as_micros() as u128 {
                near[near_count] = Some(*candidate);
                near_count += 1;
            }
        }

        if near_count <= 1 {
            return Some(best_idx);
        }

        let mut weights = [0u32; MAX_PATHS];
        let mut total = 0u32;
        for index in 0..near_count {
            let candidate = near[index].unwrap();
            let weight = self.share_weight(candidate, now, best_score);
            weights[index] = weight;
            total += weight;
        }
        if total == 0 {
            return Some(best_idx);
        }

        let slot = self.select_cursor % total as u64;
        self.select_cursor = self.select_cursor.wrapping_add(1);
        let mut bucket = slot;
        for index in 0..near_count {
            let weight = weights[index] as u64;
            if bucket < weight {
                return Some(near[index].unwrap());
            }
            bucket -= weight;
        }

        Some(near[0].unwrap())
    }

    pub fn repair(&mut self, now: Duration, avoid: usize) -> Option<usize> {
        if self.access_weights.as_ref().is_some_and(|w|w.len()>1){
            // Balance parity across physical WAN budgets too. Always putting all
            // parity on the non-primary WAN otherwise strands useful capacity.
            let(best,weights)=self.access_candidates(now);let total:i64=weights.iter().sum();
            if total>0{
                let mut chosen=None;
                for(i,weight)in weights.iter().enumerate(){
                    if *weight==0{self.repair_access_credit[i]=0;continue;}
                    self.repair_access_credit[i]+=*weight;
                    if chosen.is_none_or(|old|self.repair_access_credit[i]>self.repair_access_credit[old]){chosen=Some(i);}
                }
                let group=chosen?;self.repair_access_credit[group]-=total;return best[group];
            }
        }
        let mut live = [None; MAX_PATHS];
        let live_count = self.collect_live_candidates(now, &mut live);
        if live_count == 0 {
            return None;
        }

        let mut filtered = [None; MAX_PATHS];
        let mut filtered_count = 0usize;
        for candidate in live.iter().take(live_count).flatten() {
            if !self.valid_path(avoid) || *candidate != avoid {
                filtered[filtered_count] = Some(*candidate);
                filtered_count += 1;
            }
        }
        if filtered_count == 0 {
            return self.best(now);
        }

        let mut best_idx = filtered[0].unwrap();
        let mut best_score = self.score(best_idx, now);
        for candidate in filtered.iter().take(filtered_count).skip(1).flatten() {
            let candidate_score = self.score(*candidate, now);
            if candidate_score < best_score {
                best_idx = *candidate;
                best_score = candidate_score;
            }
        }

        // Compare alternate latency against the actual best route, not only
        // against the best of the alternates (which can all be very slow).
        let primary=self.best(now)?;
        let primary_score=self.score(primary,now);
        let best_rtt = Duration::from_micros(primary_score as u64);
        let repair_budget = cmp::min(Duration::from_millis(50), best_rtt / 2);
        if best_score>primary_score+repair_budget.as_micros(){return Some(primary);}

        let mut near = [None; MAX_PATHS];
        let mut near_count = 0usize;
        for candidate in filtered.iter().take(filtered_count).flatten() {
            let candidate_score = self.score(*candidate, now);
            if candidate_score <= primary_score + repair_budget.as_micros() {
                near[near_count] = Some(*candidate);
                near_count += 1;
            }
        }

        if near_count == 0 {
            return self.best(now);
        }
        if near_count == 1 {
            return Some(near[0].unwrap());
        }

        let mut weights = [0u32; MAX_PATHS];
        let mut total = 0u32;
        for index in 0..near_count {
            let candidate = near[index].unwrap();
            let weight = self.share_weight(candidate, now, best_score);
            weights[index] = weight;
            total += weight;
        }
        if total == 0 {
            return Some(best_idx);
        }

        let slot = self.repair_cursor % total as u64;
        self.repair_cursor = self.repair_cursor.wrapping_add(1);
        let mut bucket = slot;
        for index in 0..near_count {
            let weight = weights[index] as u64;
            if bucket < weight {
                return Some(near[index].unwrap());
            }
            bucket -= weight;
        }

        Some(near[0].unwrap())
    }

    pub fn snapshots(&self, now: Duration) -> Vec<PathSnapshot> {
        let live = self.live_paths(now);
        let best_score = live
            .iter()
            .map(|path| self.score(*path, now))
            .filter(|score| *score != u128::MAX)
            .min()
            .unwrap_or(u128::MAX);

        let threshold = if best_score == u128::MAX {
            Duration::ZERO
        } else {
            let base = Duration::from_micros(best_score as u64);
            cmp::min(FAST_THRESHOLD, base / 10)
        };

        let mut weights = vec![0u32; self.count];
        if best_score != u128::MAX {
            for path in &live {
                if self.score(*path, now) <= best_score + threshold.as_micros() as u128 {
                    weights[*path] = self.share_weight(*path, now, best_score);
                }
            }
            let total: u32 = weights.iter().sum();
            if total == 0 && !live.is_empty() {
                weights[live[0]] = 1;
            }
        }

        if self.access_weights.as_ref().is_some_and(|v|v.len()>1){
            let(best,configured)=self.access_candidates(now);weights.fill(0);
            for(group,lane)in best.into_iter().enumerate(){if let Some(lane)=lane{weights[lane]=configured[group]as u32;}}
        }
        (0..self.count)
            .map(|path| {
                let state = &self.paths[path];
                let live_flag = self.is_live(path, now);
                PathSnapshot {
                    srtt_ms: state.srtt.as_secs_f64() * 1000.0,
                    jitter_ms: state.jitter.as_secs_f64() * 1000.0,
                    loss: state.loss,
                    delivery_loss: self.delivery_loss(path, now),
                    delivery_samples: state.delivery_samples,
                    weight: if live_flag { weights[path] } else { 0 },
                    live: live_flag,
                }
            })
            .collect()
    }

    fn collect_live_candidates(&self, now: Duration, out: &mut [Option<usize>; MAX_PATHS]) -> usize {
        let mut count = 0usize;
        for path in 0..self.count {
            if self.is_live(path, now) {
                out[count] = Some(path);
                count += 1;
            }
        }
        count
    }

    fn valid_path(&self, path: usize) -> bool {
        path < self.count
    }

    fn is_monotonic(&self, now: Duration) -> bool {
        self.last_time
            .map(|last| now >= last)
            .unwrap_or(true)
    }

    fn live_paths(&self, now: Duration) -> Vec<usize> {
        let mut out = [None; MAX_PATHS];
        let live_count = self.collect_live_candidates(now, &mut out);
        out[..live_count]
            .iter()
            .map(|path| path.expect("live candidate must be present"))
            .collect()
    }

    fn is_live(&self, path: usize, now: Duration) -> bool {
        if !self.is_enabled(path) {
            return false;
        }

        let state = &self.paths[path];
        let Some(last_success) = state.last_success else {
            return false;
        };
        if state.srtt.is_zero() {
            return false;
        }
        now.saturating_sub(last_success) <= self.stale_after(state)
    }

    fn stale_after(&self, state: &PathState) -> Duration {
        state.srtt.saturating_mul(3).max(MIN_STALE)
    }

    fn score(&self, path: usize, now: Duration) -> u128 {
        if !self.valid_path(path) || !self.is_live(path, now) {
            return u128::MAX;
        }

        let state = &self.paths[path];
        let srtt = state.srtt.as_micros();
        let jitter = state.jitter.as_micros();
        let penalty = state.penalty.as_micros();
        let loss_penalty = (state.loss * 5_000.0).round() as u128;
        // A missing original can hold many later bytes behind recovery. The
        // quality cost intentionally outweighs a small RTT advantage on a lossy path.
        let delivery_penalty = (self.delivery_loss(path, now) * srtt as f64 * 4.0).round() as u128;
        srtt + jitter + penalty + loss_penalty + delivery_penalty
    }

    fn delivery_loss(&self, path: usize, now: Duration) -> f64 {
        let state = &self.paths[path];
        let age = state.delivery_at.map_or(0.0, |at| now.saturating_sub(at).as_secs_f64());
        // Old failures cannot blacklist a recovered path forever. Fresh telemetry
        // refreshes this value; unused paths become eligible again conservatively.
        state.delivery_loss * 2.0_f64.powf(-(age-10.0).max(0.0)/10.0)
    }

    fn share_weight(&self, path: usize, now: Duration, best_score: u128) -> u32 {
        if !self.valid_path(path) || !self.is_live(path, now) {
            return 0;
        }

        let score = self.score(path, now);
        if score == u128::MAX {
            return 0;
        }
        let drift_us = score.saturating_sub(best_score);
        32u32.saturating_sub((drift_us / 1_000) as u32).max(1)
    }
}
