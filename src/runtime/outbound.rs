//! Bounded per-flow service, one ingress clock, and admission-based repair credit.
use super::{MAX_PATHS, QUEUE};
use bytes::Bytes;
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

/// A single bulk producer and its repair backlog cannot consume all admission slots.
/// These are queue limits, not bandwidth reservations; unused service is work-conserving.
pub const PER_FLOW_LIMIT: usize = QUEUE / 4;
pub const REPAIR_LIMIT: usize = QUEUE / 4;

#[derive(Clone)]
pub struct Pending {
    pub data: Bytes,
    pub created: Instant,
    pub record_id: Option<u64>,
    pub flow: Option<u32>,
    pub block: Option<u64>,
}

#[derive(Default)]
pub struct Queue {
    flows: BTreeMap<u32, VecDeque<Pending>>,
    turns: VecDeque<u32>,
    repairs: VecDeque<Pending>,
    len: usize,
}
impl Queue {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn original_flows(&self) -> usize {
        self.turns.len()
    }
    /// Try another flow without dropping or charging an unaffordable head record.
    pub fn rotate_original(&mut self) {
        if let Some(flow) = self.turns.pop_front() {
            self.turns.push_back(flow);
        }
    }
    pub fn push(&mut self, item: Pending) -> Result<(), Pending> {
        if self.len == QUEUE {
            return Err(item);
        }
        if let Some(flow) = item.flow {
            if self
                .flows
                .get(&flow)
                .is_some_and(|q| q.len() >= PER_FLOW_LIMIT)
            {
                return Err(item);
            }
            let q = self.flows.entry(flow).or_default();
            if q.is_empty() {
                self.turns.push_back(flow);
            }
            q.push_back(item);
        } else {
            if self.repairs.len() >= REPAIR_LIMIT {
                return Err(item);
            }
            self.repairs.push_back(item);
        }
        self.len += 1;
        Ok(())
    }
    pub fn front(&self, repair: bool) -> Option<&Pending> {
        if repair {
            self.repairs.front()
        } else {
            self.turns
                .front()
                .and_then(|f| self.flows.get(f))
                .and_then(|q| q.front())
        }
    }
    pub fn pop(&mut self, repair: bool) -> Option<Pending> {
        let item = if repair {
            self.repairs.pop_front()
        } else {
            let flow = self.turns.pop_front()?;
            let q = self.flows.get_mut(&flow).expect("active flow");
            let item = q.pop_front();
            if q.is_empty() {
                self.flows.remove(&flow);
            } else {
                self.turns.push_back(flow);
            }
            item
        };
        if item.is_some() {
            self.len -= 1;
        }
        item
    }
    pub fn block_pending(&self, block: u64) -> bool {
        self.flows
            .values()
            .any(|q| q.iter().any(|p| p.block == Some(block)))
    }
    pub fn expire(&mut self, now: Instant, age: Duration) -> Vec<Pending> {
        let mut expired = Vec::new();
        for q in self.flows.values_mut() {
            while q
                .front()
                .is_some_and(|p| now.saturating_duration_since(p.created) >= age)
            {
                expired.push(q.pop_front().expect("front"));
            }
        }
        self.flows.retain(|_, q| !q.is_empty());
        self.turns.retain(|f| self.flows.contains_key(f));
        // Repair blocks can span flows with different ingress ages.
        self.repairs.retain(|p| {
            if now.saturating_duration_since(p.created) >= age {
                expired.push(p.clone());
                false
            } else {
                true
            }
        });
        self.len -= expired.len();
        expired
    }
}

pub struct RepairBudget {
    percent: u8,
    credit: u64,
    maximum: u64,
}
impl RepairBudget {
    pub fn new(percent: u8) -> Self {
        Self {
            percent,
            credit: 0,
            maximum: 2 * 1200 * 100,
        }
    }
    pub fn original_admitted(&mut self, bytes: usize) {
        self.credit = self
            .credit
            .saturating_add((bytes as u64).saturating_mul(u64::from(self.percent)))
            .min(self.maximum);
    }
    pub fn can_repair(&self, bytes: usize) -> bool {
        self.credit >= (bytes as u64).saturating_mul(100)
    }
    pub fn repair_admitted(&mut self, bytes: usize) {
        assert!(self.can_repair(bytes));
        self.credit -= bytes as u64 * 100;
    }
}

/// Coalesce accepted feedback without postponing the periodic observation.
#[derive(Default)]
pub struct ObservationSchedule {
    next_periodic_us: u64,
    last_observed_us: Option<u64>,
    evidence_pending: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ObservationCause {
    pub periodic: bool,
    pub evidence: bool,
}

impl ObservationSchedule {
    pub fn evidence_received(&mut self) {
        self.evidence_pending = true;
    }

    pub fn take_due(&mut self, now_us: u64) -> Option<ObservationCause> {
        // The existing sender heartbeat is also the minimum coalescing span.
        // A backward clock or an early caller retains both kinds of work.
        if self.last_observed_us.is_some_and(|last| {
            now_us
                .checked_sub(last)
                .is_none_or(|elapsed| elapsed < 1_000)
        }) {
            return None;
        }
        let periodic = now_us >= self.next_periodic_us;
        if !periodic && !self.evidence_pending {
            return None;
        }
        let cause = ObservationCause {
            periodic,
            evidence: self.evidence_pending,
        };
        if periodic {
            self.next_periodic_us = now_us.saturating_add(100_000);
        }
        self.last_observed_us = Some(now_us);
        self.evidence_pending = false;
        Some(cause)
    }
}

pub struct Pacer {
    tokens: f64,
    last_us: u64,
    rate: u64,
    burst: f64,
}
impl Pacer {
    pub fn new(rate: u64, burst: usize) -> Self {
        Self {
            tokens: 0.0,
            last_us: 0,
            rate,
            burst: burst as f64,
        }
    }
    pub fn refill(&mut self, now_us: u64) {
        self.tokens = (self.tokens
            + now_us.saturating_sub(self.last_us) as f64 * self.rate as f64 / 8_000_000.0)
            .min(self.burst);
        self.last_us = now_us;
    }
    pub fn available(&self, bytes: usize) -> bool {
        self.tokens >= bytes as f64
    }
    pub fn spend(&mut self, bytes: usize) {
        assert!(self.available(bytes));
        self.tokens -= bytes as f64;
    }
}

/// Additional adaptive business credit, shared across paths and bottleneck groups.
/// Protocol feedback and probes keep their separate, configured all-datagram caps.
pub struct BusinessPacer {
    aggregate: Pacer,
    groups: [Pacer; MAX_PATHS],
    maximum_bps: u64,
    group_maximum_bps: [u64; MAX_PATHS],
    last_us: u64,
}

impl BusinessPacer {
    pub fn new(maximum_bps: u64, group_maximum_bps: [u64; MAX_PATHS], burst_bytes: usize) -> Self {
        let burst = burst_bytes.min(2400);
        let startup_bucket = || {
            let mut bucket = Pacer::new(0, burst);
            bucket.tokens = burst as f64;
            bucket
        };
        Self {
            aggregate: startup_bucket(),
            groups: std::array::from_fn(|_| startup_bucket()),
            maximum_bps,
            group_maximum_bps,
            last_us: 0,
        }
    }

    /// Supply current live, eligible path allowances, including paths whose
    /// individual tokens cannot yet afford this packet. Settle the old rates
    /// first; a changed rate or membership never refills the bucket for free.
    pub fn update(&mut self, now_us: u64, budgets: impl IntoIterator<Item = (u8, u64)>) {
        if now_us < self.last_us {
            return;
        }
        self.aggregate.refill(now_us);
        for group in &mut self.groups {
            group.refill(now_us);
        }
        self.last_us = now_us;
        let mut rates = [0u64; MAX_PATHS];
        for (group, rate) in budgets {
            let total = &mut rates[usize::from(group)];
            *total = total.saturating_add(rate);
        }
        let mut total = 0u64;
        for (id, rate) in rates.into_iter().enumerate() {
            let rate = rate.min(self.group_maximum_bps[id]);
            self.groups[id].rate = rate;
            self.groups[id].tokens = self.groups[id].tokens.min(self.groups[id].burst);
            total = total.saturating_add(rate);
        }
        self.aggregate.rate = total.min(self.maximum_bps);
        self.aggregate.tokens = self.aggregate.tokens.min(self.aggregate.burst);
    }

    pub fn available(&self, group: u8, wire_bytes: usize) -> bool {
        let group = &self.groups[usize::from(group)];
        self.aggregate.rate > 0
            && group.rate > 0
            && self.aggregate.available(wire_bytes)
            && group.available(wire_bytes)
    }

    /// Call only after authoritative successful admission. Preview, rejection,
    /// expiry and transport waiting must not debit either level.
    pub fn spend(&mut self, group: u8, wire_bytes: usize) {
        assert!(self.available(group, wire_bytes));
        self.aggregate.spend(wire_bytes);
        self.groups[usize::from(group)].spend(wire_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_observation_036_coalesces_evidence_without_moving_periodic_deadlines() {
        let periodic = Some(ObservationCause {
            periodic: true,
            evidence: false,
        });
        let evidence = Some(ObservationCause {
            periodic: false,
            evidence: true,
        });
        let both = Some(ObservationCause {
            periodic: true,
            evidence: true,
        });
        let mut schedule = ObservationSchedule::default();
        assert_eq!(schedule.take_due(0), periodic);
        schedule.evidence_received();
        schedule.evidence_received();
        assert_eq!(schedule.take_due(999), None);
        assert_eq!(schedule.take_due(1000), evidence);
        assert_eq!(schedule.take_due(1000), None);
        assert_eq!(schedule.take_due(99_499), None);
        schedule.evidence_received();
        assert_eq!(schedule.take_due(99_500), evidence);
        schedule.evidence_received();
        // The event did not postpone the 100ms deadline. Both are retained
        // until the 1ms minimum after the actual 99.5ms observation.
        assert_eq!(schedule.take_due(100_000), None);
        assert_eq!(schedule.take_due(100_499), None);
        assert_eq!(schedule.take_due(100_500), both);
        assert_eq!(schedule.take_due(200_499), None);
        assert_eq!(schedule.take_due(200_500), periodic);
        schedule.evidence_received();
        assert_eq!(schedule.take_due(100_000), None);
        assert_eq!(schedule.take_due(200_500), None);
        assert_eq!(schedule.take_due(201_499), None);
        assert_eq!(schedule.take_due(201_500), evidence);
        for at in [250_000, 275_000, 300_000] {
            schedule.evidence_received();
            assert_eq!(schedule.take_due(at), evidence);
        }
        assert_eq!(schedule.take_due(300_500), None);
        assert_eq!(schedule.take_due(301_000), periodic);
        // A delayed actor skips missed periods instead of replaying them.
        assert_eq!(schedule.take_due(1_000_000), periodic);
        assert_eq!(schedule.take_due(1_001_000), None);
        assert_eq!(schedule.take_due(1_100_000), periodic);
    }

    #[test]
    fn event_observation_036_grants_startup_credit_once_across_groups() {
        let mut business = BusinessPacer::new(10_000_000, [10_000_000; MAX_PATHS], 9600);
        assert!(
            !business.available(0, 1),
            "credit cannot make a zero budget eligible"
        );
        let budgets = [(0, 80_000), (1, 80_000)];
        business.update(0, budgets);
        for _ in 0..3 {
            assert!(business.available(0, 2400));
            assert!(!business.available(0, 2401));
        }
        business.spend(0, 1200);
        assert!(business.available(1, 1200));
        assert!(!business.available(1, 1201));
        business.spend(1, 1200);
        assert!(!business.available(0, 1));
        assert!(!business.available(1, 1));
        business.update(0, [(0, 1_000_000)]);
        business.update(0, []);
        business.update(0, budgets);
        assert!(
            !business.available(0, 1),
            "membership and rate changes do not renew credit"
        );
        business.update(1000, budgets);
        assert!(business.available(0, 20));
        assert!(!business.available(0, 21));
        business.spend(0, 20);
        business.update(1000, budgets);
        assert!(!business.available(1, 1));
        let configured = Pacer::new(10_000_000, 2400);
        assert!(
            !configured.available(1),
            "the original all-datagram pacer is unchanged"
        );
    }

    #[test]
    fn business_pacing_035_bounds_cross_path_bursts_and_both_caps() {
        let budgets = [(0, 365_000); 4];
        let mut business = BusinessPacer::new(350_000_000, [350_000_000; MAX_PATHS], 9600);
        business.update(0, budgets);
        assert!(business.available(0, 2400));
        assert!(!business.available(0, 2401), "one bounded initial credit");
        let mut accepted = 0u64;
        for offset in [0, 1300, 2200, 2400] {
            business.update(500_000 + offset, budgets);
            if business.available(0, 1135) {
                business.spend(0, 1135);
                accepted += 1;
            }
        }
        assert_eq!(
            accepted, 2,
            "four path bursts cannot share four full buckets"
        );
        assert!(accepted * 1135 <= 2400 + 1_460_000 * 2400 / 8_000_000);
        assert!(!business.available(0, 1135));

        let mut caps = [0; MAX_PATHS];
        caps[0] = 160_000;
        caps[1] = 320_000;
        let mut grouped = BusinessPacer::new(400_000, caps, 2400);
        let budgets = [(0, 160_000), (0, 160_000), (1, u64::MAX), (1, u64::MAX)];
        grouped.update(0, budgets);
        grouped.spend(0, 2400);
        grouped.update(40_000, budgets);
        assert!(grouped.available(0, 800));
        assert!(
            !grouped.available(0, 801),
            "group cap applies to its summed paths"
        );
        grouped.spend(0, 800);
        assert!(!grouped.available(0, 1));
        assert!(grouped.available(1, 1200));
        assert!(
            !grouped.available(1, 1201),
            "aggregate cap is smaller than the group sum"
        );
        grouped.spend(1, 1200);
        assert!(
            !grouped.available(1, 1),
            "another group cannot reuse global credit"
        );

        let mut smaller = BusinessPacer::new(8_000_000, [8_000_000; MAX_PATHS], 1200);
        smaller.update(0, [(0, 8_000_000)]);
        smaller.update(1_000_000, [(0, 8_000_000)]);
        assert!(smaller.available(0, 1200));
        assert!(!smaller.available(0, 1201));
    }

    #[test]
    fn business_pacing_035_settles_old_rates_without_minting_or_replaying_credit() {
        let mut business = BusinessPacer::new(10_000_000, [10_000_000; MAX_PATHS], 2400);
        business.update(1_000_000, [(0, 80_000)]);
        assert!(business.available(0, 2400));
        assert!(
            !business.available(0, 2401),
            "first budget exposes only the bounded initial credit"
        );
        business.spend(0, 2400);
        business.update(1_100_000, [(0, 160_000)]);
        assert!(business.available(0, 1000));
        assert!(
            !business.available(0, 1001),
            "the earlier interval used 80 kbit/s"
        );
        for _ in 0..3 {
            assert!(!business.available(0, 1200));
            assert!(
                business.available(0, 1000),
                "preview/rejection spends nothing"
            );
        }
        business.update(1_050_000, [(0, 8_000_000)]);
        business.update(1_150_000, [(0, 160_000)]);
        assert!(business.available(0, 2000));
        assert!(
            !business.available(0, 2001),
            "a regressed clock changes neither time nor rate"
        );
        business.update(1_200_000, [(0, 40_000)]);
        assert!(business.available(0, 2400));
        assert!(!business.available(0, 2401));
        business.spend(0, 2300);
        business.update(1_200_000, [(0, 8_000_000)]);
        business.update(1_200_000, [(0, 40_000)]);
        assert!(business.available(0, 100));
        assert!(
            !business.available(0, 101),
            "same-time rate changes cannot refill credit"
        );
        business.update(1_300_000, [(0, 40_000)]);
        assert!(business.available(0, 600));
        assert!(
            !business.available(0, 601),
            "only the new lower rate earns future credit"
        );
        business.spend(0, 600);
        business.update(1_400_000, []);
        assert!(
            !business.available(0, 1),
            "zero budget blocks business despite earned credit"
        );
        business.update(1_500_000, []);
        business.update(1_500_000, [(0, 80_000)]);
        assert!(business.available(0, 500));
        assert!(
            !business.available(0, 501),
            "rejoining retains only previously earned credit"
        );
    }

    #[test]
    fn business_pacing_035_preserves_path_gates_and_control_when_business_is_zero() {
        use super::super::adaptive::PathController;
        let mut controllers: [PathController; 2] =
            std::array::from_fn(|_| PathController::new(10_000_000, 20));
        let mut business = BusinessPacer::new(10_000_000, [10_000_000; MAX_PATHS], 2400);
        let synchronize = |business: &mut BusinessPacer, controllers: &[PathController; 2], now| {
            business.update(
                now,
                controllers.iter().filter_map(|controller| {
                    let decision = controller.decision(now);
                    decision.eligible.then_some((0, decision.pacing_bps))
                }),
            );
        };
        let mut control = Pacer::new(10_000_000, 2400);
        let mut control_group = Pacer::new(10_000_000, 2400);
        synchronize(&mut business, &controllers, 0);
        for controller in &mut controllers {
            assert!(controller.allow(0, 1200, 0.0));
            assert!(business.available(0, 1200));
            business.spend(0, 1200);
            controller.admitted_symbol(0, 1200, 1090);
        }
        synchronize(&mut business, &controllers, 100);
        assert!(
            controllers
                .iter_mut()
                .all(|controller| controller.allow(100, 1135, 0.0))
        );
        assert!(
            !business.available(0, 1135),
            "individual bursts do not bypass shared credit"
        );
        control.refill(100);
        control_group.refill(100);
        assert!(control.available(102) && control_group.available(102));
        control.spend(102);
        control_group.spend(102);
        assert!(!business.available(0, 1135));

        let allowed = controllers[0].allow(20_000, 1135, 0.0);
        synchronize(&mut business, &controllers, 20_000);
        assert!(allowed && business.available(0, 1135));
        business.spend(0, 1135);
        controllers[0].admitted_symbol(20_000, 1135, 1025);
        synchronize(&mut business, &controllers, 20_000);
        assert!(
            !business.available(0, 1135),
            "success debits global and group exactly once"
        );

        let stale = 3_000_001;
        assert!(
            controllers
                .iter()
                .all(|controller| !controller.decision(stale).eligible)
        );
        synchronize(&mut business, &controllers, stale);
        assert!(!business.available(0, 1));
        assert!(
            controllers
                .iter()
                .all(|controller| controller.decision(stale).probe_due)
        );
        control.refill(stale);
        control_group.refill(stale);
        for wire_bytes in [347, 102] {
            assert!(control.available(wire_bytes) && control_group.available(wire_bytes));
            control.spend(wire_bytes);
            control_group.spend(wire_bytes);
            assert!(
                !business.available(0, 1),
                "health/control does not require business eligibility"
            );
        }
    }

    fn item(flow: u32, id: u64, at: Instant) -> Pending {
        Pending {
            data: Bytes::from_static(b"payload"),
            created: at,
            record_id: Some(id),
            flow: Some(flow),
            block: Some(id / 4),
        }
    }
    #[test]
    fn interactive_flow_gets_a_turn_under_bulk_backlog() {
        let now = Instant::now();
        let mut q = Queue::default();
        for id in 0..PER_FLOW_LIMIT as u64 {
            assert!(q.push(item(1, id, now)).is_ok());
        }
        assert!(q.push(item(2, 200, now)).is_ok());
        assert_eq!(q.pop(false).unwrap().flow, Some(1));
        assert_eq!(q.pop(false).unwrap().flow, Some(2));
        assert_eq!(q.len(), PER_FLOW_LIMIT - 1);
    }
    fn assert_queue_bound(q: &Queue) {
        assert!(q.len() <= QUEUE);
    }
    #[test]
    fn small_flow_can_use_budget_while_bulk_head_waits() {
        let now = Instant::now();
        let mut q = Queue::default();
        let mut bulk = item(1, 1, now);
        bulk.data = Bytes::from(vec![0; 1000]);
        let mut short = item(2, 2, now);
        short.data = Bytes::from(vec![0; 64]);
        q.push(bulk).unwrap_or_else(|_| panic!("bulk admission"));
        q.push(short).unwrap_or_else(|_| panic!("short admission"));
        let mut budget = Pacer::new(128_000, 1200);
        budget.refill(10_000);
        assert!(!budget.available(q.front(false).unwrap().data.len()));
        q.rotate_original();
        assert!(budget.available(q.front(false).unwrap().data.len()));
        budget.spend(q.pop(false).unwrap().data.len());
        assert_eq!(q.original_flows(), 1);
        assert_eq!(q.front(false).unwrap().record_id, Some(1));
        assert_eq!(q.front(false).unwrap().created, now);
        assert_eq!(q.len(), 1);
    }
    #[test]
    fn original_ingress_time_survives_queue_entry_and_expiry() {
        let now = Instant::now();
        let mut q = Queue::default();
        for id in 0..QUEUE {
            assert!(
                q.push(item((id / PER_FLOW_LIMIT) as u32, id as u64, now))
                    .is_ok()
            );
        }
        assert!(q.push(item(2, 999, now)).is_err());
        assert_queue_bound(&q);
        assert_eq!(
            q.expire(now + Duration::from_millis(21), Duration::from_millis(20))
                .len(),
            QUEUE
        );
        assert!(q.is_empty());
        assert!(q.front(false).is_none());
    }
    #[test]
    fn full_single_flow_and_repair_backlogs_leave_room_for_a_short_flow() {
        let now = Instant::now();
        let mut q = Queue::default();
        let mut rejected_originals = 0;
        let mut rejected_repairs = 0;
        for id in 0..QUEUE as u64 {
            if let Err(rejected) = q.push(item(1, id, now)) {
                assert_eq!(rejected.record_id, Some(id));
                rejected_originals += 1;
            }
            let repair = Pending {
                data: Bytes::from_static(b"repair"),
                created: now,
                record_id: None,
                flow: None,
                block: Some(id),
            };
            if let Err(rejected) = q.push(repair) {
                assert_eq!(rejected.block, Some(id));
                rejected_repairs += 1;
            }
        }
        assert_eq!(rejected_originals, QUEUE - PER_FLOW_LIMIT);
        assert_eq!(rejected_repairs, QUEUE - REPAIR_LIMIT);
        assert_eq!(q.len(), PER_FLOW_LIMIT + REPAIR_LIMIT);
        assert!(q.push(item(2, 999, now)).is_ok());
        assert_eq!(q.pop(false).unwrap().flow, Some(1));
        assert_eq!(q.pop(false).unwrap().flow, Some(2));
        assert_queue_bound(&q);
        assert_eq!(
            q.expire(now + Duration::from_millis(21), Duration::from_millis(20))
                .len(),
            PER_FLOW_LIMIT + REPAIR_LIMIT - 1
        );
        assert!(q.is_empty());
    }
    #[test]
    fn discarded_originals_cannot_mint_repair_credit() {
        let mut budget = RepairBudget::new(30);
        assert!(!budget.can_repair(1000));
        for _ in 0..3 {
            budget.original_admitted(1000);
        }
        assert!(!budget.can_repair(1000));
        budget.original_admitted(1000);
        assert!(budget.can_repair(1000));
        budget.repair_admitted(1000);
        assert!(!budget.can_repair(1000));
        for _ in 0..10000 {
            budget.original_admitted(1000);
        }
        budget.repair_admitted(1200);
        budget.repair_admitted(1200);
        assert!(!budget.can_repair(1));
    }
    #[test]
    fn group_budget_cannot_be_bypassed_by_another_path() {
        let mut group = Pacer::new(80_000, 1200);
        group.refill(100_000);
        assert!(group.available(1000));
        group.spend(1000);
        assert!(!group.available(1));
        group.refill(1_000_000);
        assert!(group.available(1200));
        group.spend(1200);
        assert!(!group.available(1));
    }
}
