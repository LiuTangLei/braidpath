//! Bounded per-flow service, one ingress clock, and admission-based repair credit.
use super::QUEUE;
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

#[cfg(test)]
mod tests {
    use super::*;
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
