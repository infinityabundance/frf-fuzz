//! Campaign scheduling policy (coordinator feature).
//!
//! # Phase 1
//!
//! * parent selection: uniform over corpus entries, drawn from a
//!   campaign-seeded stream;
//! * mutation family: fixed per work order, rotated across orders in a
//!   deterministic cycle (so every family is exercised regularly and every
//!   batch stays homogeneous);
//! * splice partners: a second parent drawn from the same stream.
//!
//! # Phase 2: explicit scheduling classes
//!
//! Feedback is never compressed into one opaque floating-point score. Two
//! explicit classes (master prompt §21):
//!
//! * [`SchedulingClass::Explore`] — discover new control/state surface
//!   (uniform parents, rotated families);
//! * [`SchedulingClass::Amplify`] — follow a weak but persistent structural
//!   residual (re-mutate a drifting lineage's frontier with the exact
//!   mutator family that drifts, continuing its index space).
//!
//! # Phase 3: probe classes
//!
//! * [`SchedulingClass::Discriminate`] — separate two or more plausible
//!   precedents/confusers (probe batches on matched lineages whose precedent
//!   declares a confuser);
//! * [`SchedulingClass::Falsify`] — aggressively test a strong precursor
//!   hypothesis (probe batches on matched lineages whose precedent has no
//!   declared confuser).
//!
//! Classes are selected by a configurable deterministic weighted
//! round-robin over the classes that are currently *available* (a pure
//! function of the campaign seed and a per-planner counter, given the
//! availability flags). Within each class, priorities are fixed-point
//! integers; all ties break deterministically (entry ID order).
//!
//! Every choice is derived from the campaign seed, so a campaign replays
//! the same experiment sequence given the same corpus (I2 spirit; the
//! campaign checkpoint records the seed and counters).
//!
//! This module is coordinator-gated.

use crate::id::ContentId;
use crate::mutation::{CounterRng, MutatorId};
use crate::precedent::ProbeRecipe;
use crate::scheduler::work_order::WorkOrder;
use crate::target_runtime::signals::SignalVector;

/// The explicit scheduling classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SchedulingClass {
    /// Discover new control/state surface (uniform parents, rotated
    /// families).
    Explore = 1,
    /// Follow a weak but persistent structural residual (drifting lineage,
    /// same family).
    Amplify = 2,
    /// Separate two or more plausible precedents/confusers (Phase 3).
    Discriminate = 3,
    /// Aggressively test a strong precursor hypothesis (Phase 3).
    Falsify = 4,
}

impl SchedulingClass {
    /// The stable numeric code.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            SchedulingClass::Explore => "explore",
            SchedulingClass::Amplify => "amplify",
            SchedulingClass::Discriminate => "discriminate",
            SchedulingClass::Falsify => "falsify",
        }
    }

    /// The index into [`SchedulePolicy::class_weights`].
    pub const fn weight_index(self) -> usize {
        (self.code() as usize) - 1
    }
}

/// Which probe-capable classes currently have queued work. Used by the
/// weighted round-robin; a class with an empty queue is not picked.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClassAvail {
    /// The amplify queue is non-empty.
    pub amplify: bool,
    /// The discriminate queue is non-empty.
    pub discriminate: bool,
    /// The falsify queue is non-empty.
    pub falsify: bool,
}

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
    /// Residual-guided admission/amplification (the ablation switch:
    /// `false` degenerates to Phase-1 coverage-only).
    pub residual: bool,
    /// Precedent-guided scheduling (the Phase-3 ablation switch: `false`
    /// disables matching/probes; only meaningful when `residual` is on).
    pub precedent: bool,
    /// Weighted round-robin weights: [Explore, Amplify, Discriminate,
    /// Falsify]. Zero weights disable the class.
    pub class_weights: [u64; 4],
    /// Minimum executions touching a signal for batch-drift detection.
    pub amplify_min_count: u32,
    /// Minimum same-direction run for batch-drift detection.
    pub amplify_min_run: u8,
    /// Minimum cumulative magnitude bucket for batch-drift detection.
    pub amplify_min_sum_bucket: u8,
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
            residual: true,
            precedent: true,
            class_weights: [4, 1, 1, 1],
            amplify_min_count: 4,
            amplify_min_run: 4,
            amplify_min_sum_bucket: 4,
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
    /// The scheduling class that produced this plan.
    pub class: SchedulingClass,
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
    /// The probe relationship, when this order is a DISCRIMINATE/FALSIFY
    /// probe (Phase 3).
    pub probe: Option<ProbePlan>,
}

/// The coordinator-side bookkeeping of one probe order (Phase 3). The
/// worker never sees this: a probe is an ordinary mutation batch; the
/// coordinator evaluates the recipe against the batch's signal summary when
/// the result arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePlan {
    /// Deterministic probe ordinal (per-campaign counter).
    pub seq: u64,
    /// Short key of the current precedent revision the probe tests.
    pub precedent_short: [u8; 8],
    /// The falsifiable relationship being probed.
    pub recipe: ProbeRecipe,
}

/// A lineage the coordinator wants to keep probing: the frontier entry and
/// the mutator family whose mutations drift it.
#[derive(Debug, Clone)]
pub struct AmplifyEntry {
    /// The frontier corpus entry (the newest admitted descendant of the
    /// drifting lineage).
    pub parent: ContentId,
    /// The mutator family that produces the drift.
    pub mutator: u16,
    /// Deterministic fixed-point priority (higher = more urgent).
    pub priority: u64,
}

/// A queued probe order (Phase 3). One per (precedent family, lineage).
#[derive(Debug, Clone)]
pub struct ProbeEntry {
    /// Deterministic probe ordinal (queue position key).
    pub seq: u64,
    /// The class (Discriminate or Falsify).
    pub class: SchedulingClass,
    /// The current precedent revision the probe tests.
    pub precedent: crate::precedent::Precedent,
    /// The object id of that revision (for status updates).
    pub precedent_id: crate::id::ContentId,
    /// The lineage root the match fired on.
    pub root: ContentId,
    /// The mutator family of the matched lineage.
    pub mutator: u16,
    /// The frontier corpus entry to mutate.
    pub frontier: ContentId,
    /// Fixed-point priority (higher first; ties by seq).
    pub priority: u64,
}

/// The order planner. Pure and deterministic given the policy and the
/// current counters; holds no mutable state of its own beyond the mutator
/// rotation and the WRR counter (both are per-dispatch counters, not part
/// of candidate identity — the coordinate is).
pub struct OrderPlanner {
    policy: SchedulePolicy,
    /// Round-robin mutator rotation counter (per planner; resets on
    /// restart, which is fine: mutator rotation is not part of candidate
    /// identity, the coordinate is).
    rotation: usize,
    /// Weighted round-robin class counter (deterministic given the seed).
    class_round: u64,
    /// Seed-derived WRR offset.
    seed_offset: u64,
}

impl OrderPlanner {
    /// Create a planner for a policy.
    pub fn new(policy: &SchedulePolicy) -> OrderPlanner {
        let total: u64 = policy.class_weights.iter().sum();
        OrderPlanner {
            policy: policy.clone(),
            rotation: 0,
            class_round: 0,
            seed_offset: if total == 0 { 0 } else { policy.seed % total },
        }
    }

    /// The policy.
    pub fn policy(&self) -> &SchedulePolicy {
        &self.policy
    }

    /// The next scheduling class under the weighted round-robin, over the
    /// classes that are currently available. When residual guidance is off,
    /// or nothing but Explore is available, the choice degenerates to
    /// Explore.
    pub fn pick_class(&mut self, avail: &ClassAvail) -> SchedulingClass {
        if !self.policy.residual {
            return SchedulingClass::Explore;
        }
        // Build the available ordered class list (fixed class order).
        let mut classes: [(SchedulingClass, u64); 4] = [
            (SchedulingClass::Explore, self.policy.class_weights[0]),
            (SchedulingClass::Amplify, self.policy.class_weights[1]),
            (SchedulingClass::Discriminate, self.policy.class_weights[2]),
            (SchedulingClass::Falsify, self.policy.class_weights[3]),
        ];
        // Drop unavailable classes: Amplify needs its queue; probe classes
        // need the queue AND the precedent scheduling switch.
        if !avail.amplify || !self.policy.residual {
            classes[1].1 = 0;
        }
        let probes_enabled = self.policy.precedent && self.policy.residual;
        if !avail.discriminate || !probes_enabled {
            classes[2].1 = 0;
        }
        if !avail.falsify || !probes_enabled {
            classes[3].1 = 0;
        }
        let total: u64 = classes.iter().map(|(_, w)| *w).sum();
        if total == 0 {
            return SchedulingClass::Explore;
        }
        let slot = (self.class_round + self.seed_offset) % total;
        self.class_round = self.class_round.wrapping_add(1);
        let mut acc = 0u64;
        for (class, weight) in classes {
            acc += weight;
            if slot < acc {
                return class;
            }
        }
        SchedulingClass::Explore
    }

    /// Build the plan for lane `lane`, starting at mutation index
    /// `start_index` for parent `parent_short` (Explore: rotated family).
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
            class: SchedulingClass::Explore,
            mutator,
            generation,
            start_index,
            count: self.policy.batch_size,
            parent_short,
            probe: None,
        }
    }

    /// Build an Amplify plan for a drifting lineage: the frontier parent
    /// with the exact drifting family, continuing the frontier's index
    /// space.
    pub fn plan_amplify(
        &mut self,
        lane: u16,
        entry: &AmplifyEntry,
        generation: u32,
        start_index: u64,
    ) -> OrderPlan {
        OrderPlan {
            lane,
            class: SchedulingClass::Amplify,
            mutator: MutatorId::from_id(entry.mutator)
                .expect("amplify entry mutator must be a stable family"),
            generation,
            start_index,
            count: self.policy.batch_size,
            parent_short: entry.parent.short(),
            probe: None,
        }
    }

    /// Build a probe plan (DISCRIMINATE or FALSIFY) for a matched lineage:
    /// continue the frontier under the recipe's family.
    #[allow(clippy::too_many_arguments)]
    pub fn plan_probe(
        &self,
        lane: u16,
        entry: &ProbeEntry,
        generation: u32,
        start_index: u64,
        probe_seq: u64,
    ) -> OrderPlan {
        OrderPlan {
            lane,
            class: entry.class,
            mutator: MutatorId::from_id(entry.precedent.recipe.family)
                .expect("probe recipe family must be a stable mutator family"),
            generation,
            start_index,
            count: self.policy.batch_size,
            parent_short: entry.frontier.short(),
            probe: Some(ProbePlan {
                seq: probe_seq,
                precedent_short: entry.precedent_id.short(),
                recipe: entry.precedent.recipe,
            }),
        }
    }

    /// Build the actual work order for a plan (the coordinator fills in
    /// parent bytes, partner, dictionary, new features, and the parent's
    /// recorded signal observation — the mutation-residual baseline).
    #[allow(clippy::too_many_arguments)]
    pub fn build_order(
        &self,
        plan: &OrderPlan,
        parent: Vec<u8>,
        parent_short: [u8; 8],
        parent_signals: SignalVector,
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
            parent_signals,
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
        let signals = SignalVector::new();
        let order = planner.build_order(
            &plan,
            b"parent".to_vec(),
            [1; 8],
            signals.clone(),
            Vec::new(),
            &[],
            &[9],
        );
        assert_eq!(order.campaign_seed, 42);
        assert_eq!(order.lane_id, 7);
        assert_eq!(order.generation, 3);
        assert_eq!(order.start_index, 100);
        assert_eq!(order.index_count, policy.batch_size);
        assert_eq!(order.mutator_id, plan.mutator.id());
        assert_eq!(order.parent, b"parent");
        assert_eq!(order.parent_short, [1; 8]);
        assert_eq!(order.parent_signals, signals);
        assert_eq!(order.new_features, vec![9]);
        assert!(plan.probe.is_none());
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

    #[test]
    fn wrr_is_deterministic_and_respects_weights() {
        let policy = SchedulePolicy {
            seed: 0,
            class_weights: [4, 1, 0, 0],
            ..SchedulePolicy::default()
        };
        let mut a = OrderPlanner::new(&policy);
        let mut b = OrderPlanner::new(&policy);
        let mut counts = [0u64; 4];
        let avail = ClassAvail {
            amplify: true,
            ..ClassAvail::default()
        };
        for _ in 0..100 {
            let ca = a.pick_class(&avail);
            let cb = b.pick_class(&avail);
            assert_eq!(ca, cb, "planners must agree");
            counts[ca.weight_index()] += 1;
        }
        // 4:1 over 100 picks -> 80 explore / 20 amplify exactly (period 5).
        assert_eq!(counts, [80, 20, 0, 0]);
    }

    #[test]
    fn wrr_with_probe_classes_is_deterministic() {
        let policy = SchedulePolicy {
            seed: 0,
            class_weights: [4, 1, 1, 2],
            ..SchedulePolicy::default()
        };
        let mut a = OrderPlanner::new(&policy);
        let mut b = OrderPlanner::new(&policy);
        let mut counts = [0u64; 4];
        let avail = ClassAvail {
            amplify: true,
            discriminate: true,
            falsify: true,
        };
        for _ in 0..160 {
            let ca = a.pick_class(&avail);
            let cb = b.pick_class(&avail);
            assert_eq!(ca, cb);
            counts[ca.weight_index()] += 1;
        }
        // Period 8: 80 explore / 20 amplify / 20 discriminate / 40 falsify.
        assert_eq!(counts, [80, 20, 20, 40]);
    }

    #[test]
    fn wrr_degrades_to_explore_without_queues_or_residual() {
        let policy = SchedulePolicy::default();
        let mut planner = OrderPlanner::new(&policy);
        for _ in 0..16 {
            assert_eq!(
                planner.pick_class(&ClassAvail::default()),
                SchedulingClass::Explore
            );
        }
        let policy = SchedulePolicy {
            residual: false,
            ..SchedulePolicy::default()
        };
        let mut planner = OrderPlanner::new(&policy);
        for _ in 0..16 {
            assert_eq!(
                planner.pick_class(&ClassAvail {
                    amplify: true,
                    discriminate: true,
                    falsify: true,
                }),
                SchedulingClass::Explore
            );
        }
    }

    #[test]
    fn probe_classes_require_the_precedent_switch() {
        let policy = SchedulePolicy {
            precedent: false,
            ..SchedulePolicy::default()
        };
        let mut planner = OrderPlanner::new(&policy);
        let avail = ClassAvail {
            discriminate: true,
            falsify: true,
            ..ClassAvail::default()
        };
        for _ in 0..16 {
            assert_ne!(
                planner.pick_class(&avail),
                SchedulingClass::Discriminate,
                "discriminate must require the precedent switch"
            );
            assert_ne!(
                planner.pick_class(&avail),
                SchedulingClass::Falsify,
                "falsify must require the precedent switch"
            );
        }
    }

    #[test]
    fn amplify_plan_uses_the_drifting_family() {
        let policy = SchedulePolicy::default();
        let mut planner = OrderPlanner::new(&policy);
        let entry = AmplifyEntry {
            parent: ContentId::new(b"frontier"),
            mutator: MutatorId::ByteInsert.id(),
            priority: 5,
        };
        let plan = planner.plan_amplify(2, &entry, 9, 1234);
        assert_eq!(plan.class, SchedulingClass::Amplify);
        assert_eq!(plan.mutator, MutatorId::ByteInsert);
        assert_eq!(plan.generation, 9);
        assert_eq!(plan.start_index, 1234);
        assert_eq!(plan.parent_short, entry.parent.short());
        assert_eq!(plan.lane, 2);
        assert!(plan.probe.is_none());
    }

    #[test]
    fn probe_plan_carries_the_recipe() {
        let policy = SchedulePolicy::default();
        let planner = OrderPlanner::new(&policy);
        let mut precedent = crate::precedent::model::Precedent {
            lineage_root: ContentId::new(b"root"),
            mutator: 7,
            profile: crate::precedent::model::PrefixProfile {
                depth: 2,
                axis_mask: 1,
                dir_bits: 1,
                cmp_convergence: 1,
                state_change: 0,
                structured_unknown: true,
            },
            role_mask: 1,
            continuation: crate::precedent::model::Continuation {
                kind: crate::precedent::model::TerminalKind::CrashFinding,
                class: 0,
                axis: 0,
                depth: 24,
                reason: 5,
                terminal_ref: None,
            },
            confuser: crate::precedent::model::ConfuserKind::None,
            created_seq: 1,
            updated_seq: 1,
            status: crate::precedent::model::PrecedentStatus::Candidate,
            prev_revision: None,
            supports: 0,
            contradictions: 0,
            ambiguous_probes: 0,
            recipe: ProbeRecipe::persists(MutatorId::DictionaryInsert, 0, 20, 4, 3),
            evidence: Vec::new(),
        };
        precedent.recipe = ProbeRecipe::persists(MutatorId::DictionaryInsert, 0, 20, 4, 3);
        let entry = ProbeEntry {
            seq: 1,
            class: SchedulingClass::Falsify,
            precedent,
            precedent_id: crate::id::ContentId::new(b"prec"),
            root: ContentId::new(b"rootB"),
            mutator: 7,
            frontier: ContentId::new(b"frontierB"),
            priority: 9,
        };
        let plan = planner.plan_probe(3, &entry, 12, 5000, 7);
        assert_eq!(plan.class, SchedulingClass::Falsify);
        assert_eq!(plan.mutator, MutatorId::DictionaryInsert);
        assert_eq!(plan.parent_short, entry.frontier.short());
        let probe = plan.probe.expect("probe plan must carry the recipe");
        assert_eq!(probe.seq, 7);
        assert_eq!(probe.recipe.axis, 0);
        assert_eq!(probe.recipe.family, MutatorId::DictionaryInsert.id());
    }

    #[test]
    fn scheduling_class_codes_are_stable() {
        assert_eq!(SchedulingClass::Explore.code(), 1);
        assert_eq!(SchedulingClass::Amplify.code(), 2);
        assert_eq!(SchedulingClass::Discriminate.code(), 3);
        assert_eq!(SchedulingClass::Falsify.code(), 4);
        assert_eq!(SchedulingClass::Explore.name(), "explore");
        assert_eq!(SchedulingClass::Amplify.name(), "amplify");
        assert_eq!(SchedulingClass::Discriminate.name(), "discriminate");
        assert_eq!(SchedulingClass::Falsify.name(), "falsify");
    }
}
