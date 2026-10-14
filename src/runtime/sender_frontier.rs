//! Bounded sender-owned observations and a conservative small-lane treatment.
//! Counts are previews/attempts, NOT unique records, loss rates or time shares.
use super::MAX_PATHS;
use serde::Serialize;

#[derive(Clone, Copy)]
pub(crate) enum Gate {
    PathIneligible,
    PathAllowance,
    Aggregate,
    Group,
    BusinessAggregate,
    BusinessGroup,
    RepairCredit,
    CopySpacing,
    DatagramSize,
    ApiBuffer,
    ApiError,
    ExpiredBeforeApi,
    ApiAdmitted,
}

#[derive(Clone, Default, Serialize)]
pub struct Counts {
    pub path_ineligible: u64,
    pub path_allowance: u64,
    pub aggregate_budget: u64,
    pub group_budget: u64,
    pub business_aggregate_budget: u64,
    pub business_group_budget: u64,
    pub repair_credit: u64,
    pub copy_spacing: u64,
    pub datagram_size: u64,
    pub api_buffer: u64,
    pub api_error: u64,
    pub expired_before_api: u64,
    pub api_admitted: u64,
}
impl Counts {
    fn add(&mut self, gate: Gate) {
        let counter = match gate {
            Gate::PathIneligible => &mut self.path_ineligible,
            Gate::PathAllowance => &mut self.path_allowance,
            Gate::Aggregate => &mut self.aggregate_budget,
            Gate::Group => &mut self.group_budget,
            Gate::BusinessAggregate => &mut self.business_aggregate_budget,
            Gate::BusinessGroup => &mut self.business_group_budget,
            Gate::RepairCredit => &mut self.repair_credit,
            Gate::CopySpacing => &mut self.copy_spacing,
            Gate::DatagramSize => &mut self.datagram_size,
            Gate::ApiBuffer => &mut self.api_buffer,
            Gate::ApiError => &mut self.api_error,
            Gate::ExpiredBeforeApi => &mut self.expired_before_api,
            Gate::ApiAdmitted => &mut self.api_admitted,
        };
        *counter = counter.saturating_add(1);
    }
}

#[derive(Clone, Default, Serialize)]
pub struct PathCounts {
    pub small: Counts,
    pub other: Counts,
}

#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub enabled: bool,
    pub head_previews: u64,
    pub no_eligible_path_previews: u64,
    pub small_rank_evaluations: u64,
    pub small_rank_opportunities: u64,
    pub small_rank_changes: u64,
    pub readiness_admitted: u64,
    pub readiness_gate_changed: u64,
    pub readiness_failed: u64,
    pub paths: [PathCounts; MAX_PATHS],
}
impl Snapshot {
    pub(crate) fn add(&mut self, path: u8, small: bool, gate: Gate) {
        if let Some(path) = self.paths.get_mut(usize::from(path)) {
            if small {
                &mut path.small
            } else {
                &mut path.other
            }
            .add(gate);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Sample {
    pub id: u8,
    pub finish_ms: f64,
    /// Fresh original-symbol path feedback, never recovery-adjusted success.
    pub loss: f64,
    pub immediately_ready: bool,
    pub already_used: bool,
}

/// Promote a strictly earlier, no-worse-loss alternative in the same diversity
/// tier. No independence assumption, no new credit, no deadline extension.
/// Unknown/stale evidence is excluded by the caller; an unknown first choice
/// keeps the old order. A 2ms hysteresis avoids chasing tiny timing differences.
pub(crate) fn preferred(order: &[u8], samples: &[Sample]) -> Option<u8> {
    let first = *order.first()?;
    let valid = |s: &&Sample| {
        s.id < MAX_PATHS as u8
            && s.finish_ms.is_finite()
            && s.finish_ms >= 0.0
            && s.loss.is_finite()
            && (0.0..1.0).contains(&s.loss)
    };
    let anchor = samples.iter().filter(valid).find(|s| s.id == first)?;
    samples
        .iter()
        .filter(valid)
        .filter(|s| order.contains(&s.id) && s.id != first && s.immediately_ready)
        .filter(|s| s.already_used == anchor.already_used && s.loss <= anchor.loss)
        .filter(|s| s.finish_ms + 2.0 <= anchor.finish_ms)
        .min_by(|a, b| a.finish_ms.total_cmp(&b.finish_ms).then(a.id.cmp(&b.id)))
        .map(|s| s.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(id: u8, finish_ms: f64, loss: f64) -> Sample {
        Sample {
            id,
            finish_ms,
            loss,
            immediately_ready: true,
            already_used: false,
        }
    }
    #[test]
    fn earlier_equal_or_better_loss_is_eligible() {
        assert_eq!(
            preferred(
                &[0, 1, 2],
                &[
                    sample(0, 60.0, 0.1),
                    sample(1, 40.0, 0.1),
                    sample(2, 50.0, 0.0)
                ]
            ),
            Some(1)
        );
    }
    #[test]
    fn does_not_trade_reliability_for_lower_rtt() {
        assert_eq!(
            preferred(&[0, 1], &[sample(0, 60.0, 0.1), sample(1, 10.0, 0.11)]),
            None
        );
    }
    #[test]
    fn unknown_first_choice_and_small_differences_preserve_order() {
        assert_eq!(preferred(&[0, 1], &[sample(1, 10.0, 0.0)]), None);
        assert_eq!(
            preferred(&[0, 1], &[sample(0, 20.0, 0.0), sample(1, 18.1, 0.0)]),
            None
        );
        assert_eq!(preferred(&[], &[]), None);
    }
    #[test]
    fn cannot_restore_filtered_or_blocked_or_used_repair_path() {
        let a = sample(0, 60.0, 0.1);
        let mut b = sample(1, 10.0, 0.0);
        assert_eq!(preferred(&[0], &[a, b]), None);
        b.immediately_ready = false;
        assert_eq!(preferred(&[0, 1], &[a, b]), None);
        b.immediately_ready = true;
        b.already_used = true;
        assert_eq!(preferred(&[0, 1], &[a, b]), None);
    }
    #[test]
    fn invalid_evidence_never_wins() {
        for finish in [f64::NAN, f64::INFINITY, -1.0] {
            assert_eq!(
                preferred(&[0, 1], &[sample(0, 60.0, 0.1), sample(1, finish, 0.0)]),
                None
            );
        }
        for loss in [f64::NAN, -0.1, 1.0, 1.1] {
            assert_eq!(
                preferred(&[0, 1], &[sample(0, 60.0, 0.1), sample(1, 10.0, loss)]),
                None
            );
        }
    }
    #[test]
    fn bounded_lane_counters_do_not_merge_or_overflow() {
        let mut s = Snapshot::default();
        s.add(1, true, Gate::Group);
        s.add(1, false, Gate::PathAllowance);
        s.add(255, true, Gate::Group);
        assert_eq!(s.paths[1].small.group_budget, 1);
        assert_eq!(s.paths[1].other.path_allowance, 1);
        s.paths[1].small.group_budget = u64::MAX;
        s.add(1, true, Gate::Group);
        assert_eq!(s.paths[1].small.group_budget, u64::MAX);
    }
}
