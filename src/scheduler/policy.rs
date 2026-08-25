//! Campaign scheduling policy (coordinator feature).
//!
//! Phase 1 is deliberately simple but fully deterministic:
//!
//! * parent selection: uniform over corpus entries, drawn from a
//!   campaign-seeded stream;
//! * mutation family: fixed per work order, rotated across orders in a
//!   deterministic cycle (so every family is exercised regularly and every
//!   batch stays homogeneous);
//! * splice partners: a second parent drawn from the same stream.
//!
//! Every choice is derived from the campaign seed, so a campaign replays
//! the same experiment sequence given the same corpus (I2 spirit; the
//! campaign checkpoint records the seed and counters).
//!
//! This module is coordinator-gated.

use crate::mutation::{CounterRng, MutatorId};
use crate::scheduler::work_order::WorkOrder;

/// Tunable campaign parameters (defaults in [`SchedulePolicy::default`]).
#[derive(Debug, Clone)]
pub struct SchedulePolicy {
    /// Number of persistent worker processes.
    pub workers: usize,
    /// Mutations per work order (the batch the worker executes locally).
    pub batch_size: u64,
    /// Campaign seed (deterministic identity of the campaign's stream).
    pub seed: u64,
    /// Per-execution timeout in milliseconds (worker watchdog).
    pub timeout_ms: u64,
    /// Hard cap on corpus entries (admission refuses beyond this).
    pub max_corpus_entries: usize,
    /// Hard cap on features sent per work order (frame bound).
    pub max_features_per_order: usize,
}

impl Default for SchedulePolicy {
    fn default() -> SchedulePolicy {
        SchedulePolicy {
            workers: 8,
            batch_size: 1000,
            seed: 0,
            timeout_ms: 5000,
            max_corpus_entries: crate::corpus::MAX_CORPUS_ENTRIES,
            max_features_per_order: crate::scheduler::work_order::MAX_FEATURES_PER_ORDER,
        }
    }
}

/// The deterministic per-order experiment parameters. Carries everything
/// the coordinator needs to construct the next [`WorkOrder`] and to
/// reconstruct the batch afterwards.
#[derive(Debug, Clone)]
pub struct OrderPlan {
    /// Which worker lane this order is destined for.
    pub lane: u16,
    /// Mutation family for the whole batch.
    pub mutator: MutatorId,
    /// Generation / depth.
    pub generation: u32,
    /// First mutation index of the batch.
    pub start_index: u64,
    /// Number of mutations.
    pub count: u64,
    /// Parent corpus entry id (the coordinator resolves bytes before
    /// sending; this keeps provenance in the plan).
    pub parent_short: [u8; 8],
}

/// The order planner. Pure and deterministic given the policy and the
/// current counters; holds no mutable state of its own.
pub struct OrderPlanner {
    policy: SchedulePolicy,
    /// Round-robin mutator rotation counter (per planner; resets on
    /// restart, which is fine: mutator rotation is not part of candidate
    /// identity, the coordinate is).
    rotation: usize,
}

impl OrderPlanner {
    /// Create a planner for a policy.
    pub fn new(policy: &SchedulePolicy) -> OrderPlanner {
        OrderPlanner {
            policy: policy.clone(),
            rotation: 0,
        }
    }

    /// The policy.
    pub fn policy(&self) -> &SchedulePolicy {
        &self.policy
    }

    /// Build the plan for lane `lane`, starting at mutation index
    /// `start_index` for parent `parent_short`.
    pub fn plan_for(
        &mut self,
        lane: u16,
        parent_short: [u8; 8],
        generation: u32,
        start_index: u64,
    ) -> OrderPlan {
        let mutator = MutatorId::ALL[self.rotation % MutatorId::ALL.len()];
        self.rotation += 1;
        OrderPlan {
            lane,
            mutator,
            generation,
            start_index,
            count: self.policy.batch_size,
            parent_short,
        }
    }

    /// Build the actual work order for a plan (the coordinator fills in
    /// parent bytes, partner, dictionary, and new features).
    pub fn build_order(
        &self,
        plan: &OrderPlan,
        parent: Vec<u8>,
        parent_short: [u8; 8],
        partner: Vec<u8>,
        dictionary: &[Vec<u8>],
        new_features: &[u64],
    ) -> WorkOrder {
        WorkOrder {
            campaign_seed: self.policy.seed,
            generation: plan.generation,
            mutator_id: plan.mutator.id(),
            lane_id: plan.lane,
            start_index: plan.start_index,
            index_count: plan.count,
            parent,
            parent_short,
            partner,
            dictionary: dictionary.to_vec(),
            new_features: new_features.to_vec(),
            input_override: Vec::new(),
        }
    }

    /// Draw a deterministic splice partner (a corpus entry chosen from the
    /// campaign stream). The caller provides the parent id to avoid
    /// self-splicing.
    pub fn pick_partner(
        &self,
        rng: &mut CounterRng,
        parents: &[[u8; 8]],
        exclude: [u8; 8],
    ) -> Option<[u8; 8]> {
        if parents.is_empty() {
            return None;
        }
        let mut idx = rng.gen_index(parents.len());
        // Deterministic retry: skip the excluded parent at most len times.
        for _ in 0..parents.len() {
            let candidate = parents[idx];
            if candidate != exclude {
                return Some(candidate);
            }
            idx = (idx + 1) % parents.len();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planner_rotates_all_families_deterministically() {
        let policy = SchedulePolicy::default();
        let mut a = OrderPlanner::new(&policy);
        let mut b = OrderPlanner::new(&policy);
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..(MutatorId::ALL.len() * 3) {
            let pa = a.plan_for(1, [0; 8], 0, i as u64);
            let pb = b.plan_for(1, [0; 8], 0, i as u64);
            assert_eq!(pa.mutator, pb.mutator, "planners must agree");
            seen.insert(pa.mutator);
        }
        assert_eq!(seen.len(), MutatorId::ALL.len());
    }

    #[test]
    fn build_order_carries_plan_fields() {
        let policy = SchedulePolicy {
            seed: 42,
            ..SchedulePolicy::default()
        };
        let mut planner = OrderPlanner::new(&policy);
        let plan = planner.plan_for(7, [1; 8], 3, 100);
        let order = planner.build_order(&plan, b"parent".to_vec(), [1; 8], Vec::new(), &[], &[9]);
        assert_eq!(order.campaign_seed, 42);
        assert_eq!(order.lane_id, 7);
        assert_eq!(order.generation, 3);
        assert_eq!(order.start_index, 100);
        assert_eq!(order.index_count, policy.batch_size);
        assert_eq!(order.mutator_id, plan.mutator.id());
        assert_eq!(order.parent, b"parent");
        assert_eq!(order.parent_short, [1; 8]);
        assert_eq!(order.new_features, vec![9]);
    }

    #[test]
    fn partner_never_self_splices() {
        let mut rng = CounterRng::from_philox([3, 0, 0, 0], [0, 0]);
        let parents = [[1; 8], [2; 8], [3; 8]];
        for _ in 0..100 {
            let p = OrderPlanner::new(&SchedulePolicy::default())
                .pick_partner(&mut rng, &parents, [2; 8]);
            assert!(p.is_some());
            assert_ne!(p.unwrap(), [2; 8]);
        }
    }
}
