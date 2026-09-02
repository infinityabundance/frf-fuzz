//! The frf-fuzz FuzzSemanticBank (master prompt §13; Phase 3).
//!
//! DSFB-Debug supplies the structural *substrate* (`crate::dsfb::debug_bridge`)
//! — envelope grammar, reason codes, policy states — with its own
//! production-debugging motif names deliberately NOT reused for fuzz
//! behavior. This module owns the fuzz-specific semantic bank: a set of
//! named structural classes whose names describe *structural observations of
//! fuzz trajectories*, never causes, never bug claims.
//!
//! # Discipline
//!
//! * `Structured + Unknown` is a valid, first-class terminal result. A
//!   structurally non-trivial observation that matches no class REMAINS
//!   Unknown; it is never force-labelled to the nearest class (I6).
//! * Every named class carries prerequisites (DSFB reason/grammar/policy
//!   evidence), context predicates (signal roles, drift direction,
//!   persistence, convergence), confusers, deterministic thresholds,
//!   provenance, recommended experiment families, and refusal conditions.
//! * Naming is an *observation*, not a verdict on the code: the same
//!   trajectory can move from one class to another as its structure
//!   evolves (e.g. `BoundaryGrazing` -> `PersistentBehavioralDrift` ->
//!   escalation to a crash finding), and the classes never claim to know
//!   *why*.
//! * There are no floating-point values and no probabilities in the bank.
//!   Scores are small integers; classification is a deterministic function
//!   of the evidence (I11).
//!
//! # Roles
//!
//! Axis roles are assigned deterministically from the target's registered
//! signal schema (name + unit keywords). A class whose context predicate
//! requires a role cannot fire when the involved axes have no known role
//! (refusal by unknown role); that keeps the bank from pretending it knows
//! what a signal "means" when the target never told us.
//!
//! This module is coordinator-gated.

use crate::dsfb::debug_bridge::{AxisVerdict, DriftDir};
use crate::dsfb::morphology::{CmpConvergence, MorphologySignature, StateChange};
use crate::error::{Error, Result};
use crate::target_runtime::signals::{SignalDesc, MAX_SIGNALS};
use dsfb_debug::types::{PolicyState, ReasonCode};
use std::ops::BitOr;

/// Version of the bank tables. Bump when a class code or gate changes (codes
/// themselves are stable; see [`FuzzMotif`]).
pub const FUZZ_BANK_VERSION: u8 = 1;

/// Axis roles: a bitset describing what a signal's schema says it measures.
/// Roles are assigned by declared keyword rules (deterministic; see
/// [`role_of`]); a role is a *context predicate*, never a semantic claim the
/// target did not register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxisRole(u16);

impl AxisRole {
    /// No declared role (the schema did not match any keyword).
    pub const NONE: AxisRole = AxisRole(0);
    /// Call-stack / parser / state depth.
    pub const DEPTH: AxisRole = AxisRole(1 << 0);
    /// Allocation / heap / memory.
    pub const ALLOCATION: AxisRole = AxisRole(1 << 1);
    /// Output / emitted records / serialization.
    pub const OUTPUT: AxisRole = AxisRole(1 << 2);
    /// Error / failure / exception surfaces.
    pub const ERROR: AxisRole = AxisRole(1 << 3);
    /// Retry / resubmission.
    pub const RETRY: AxisRole = AxisRole(1 << 4);
    /// Queue / backlog / pending work.
    pub const QUEUE: AxisRole = AxisRole(1 << 5);
    /// Lock / contention.
    pub const LOCK: AxisRole = AxisRole(1 << 6);
    /// Timeout / deadline.
    pub const TIMEOUT: AxisRole = AxisRole(1 << 7);
    /// Parse / tokenize / decode.
    pub const PARSE: AxisRole = AxisRole(1 << 8);
    /// Protocol / state machine.
    pub const STATE: AxisRole = AxisRole(1 << 9);
    /// Scheduling / timer.
    pub const SCHEDULE: AxisRole = AxisRole(1 << 10);
    /// Counting axes (items, records, retries counted as plain counts).
    pub const COUNT: AxisRole = AxisRole(1 << 11);
    /// Sizes / lengths / widths.
    pub const SIZE: AxisRole = AxisRole(1 << 12);

    /// The raw bitset.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// The union of two role sets.
    pub const fn or(self, other: AxisRole) -> AxisRole {
        AxisRole(self.0 | other.0)
    }

    /// Whether any of `other`'s roles are present.
    pub const fn intersects(self, other: AxisRole) -> bool {
        self.0 & other.0 != 0
    }

    /// Whether the role is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for AxisRole {
    type Output = AxisRole;

    fn bitor(self, rhs: AxisRole) -> AxisRole {
        AxisRole::or(self, rhs)
    }
}

/// One keyword rule (role bit + keywords, matched in table order; the first
/// matching rule wins, so the table is ordered most-specific first).
struct RoleRule {
    role: AxisRole,
    keywords: &'static [&'static str],
}

const ROLE_RULES: &[RoleRule] = &[
    RoleRule {
        role: AxisRole::DEPTH,
        keywords: &["depth", "nest", "recurs", "stack"],
    },
    RoleRule {
        role: AxisRole::ALLOCATION,
        keywords: &["alloc", "heap", "mem", "malloc"],
    },
    RoleRule {
        role: AxisRole::OUTPUT,
        keywords: &["output", "emit", "serializ", "write", "response"],
    },
    RoleRule {
        role: AxisRole::ERROR,
        keywords: &[
            "error",
            "exception",
            "panic",
            "fail",
            "invalid",
            "reject",
            "crash",
            "err",
        ],
    },
    RoleRule {
        role: AxisRole::RETRY,
        keywords: &["retry", "resubmit", "attempt", "reconnect", "recover"],
    },
    RoleRule {
        role: AxisRole::QUEUE,
        keywords: &["queue", "backlog", "pending", "wait"],
    },
    RoleRule {
        role: AxisRole::LOCK,
        keywords: &["lock", "mutex", "contention"],
    },
    RoleRule {
        role: AxisRole::TIMEOUT,
        keywords: &["timeout", "deadline", "stale", "slow"],
    },
    RoleRule {
        role: AxisRole::PARSE,
        keywords: &["parse", "token", "decode", "frame", "packet", "syntax"],
    },
    RoleRule {
        role: AxisRole::STATE,
        keywords: &["state", "phase", "mode", "protocol"],
    },
    RoleRule {
        role: AxisRole::SCHEDULE,
        keywords: &["schedule", "timer", "tick", "cron"],
    },
    RoleRule {
        role: AxisRole::SIZE,
        keywords: &["size", "length", "len", "bytes", "width"],
    },
    RoleRule {
        role: AxisRole::COUNT,
        keywords: &["count", "num", "n_", "total", "items"],
    },
];

/// Assign the axis role from a registered signal descriptor (name + unit).
/// Deterministic; unknown names get [`AxisRole::NONE`].
pub fn role_of(desc: &SignalDesc) -> AxisRole {
    let name = desc.name_str().to_ascii_lowercase();
    let unit = desc.unit_str().to_ascii_lowercase();
    let hay = format!("{name} {unit}");
    for rule in ROLE_RULES {
        if rule.keywords.iter().any(|k| hay.contains(k)) {
            return rule.role;
        }
    }
    AxisRole::NONE
}

/// The named fuzz structural classes (stable codes; never renumbered).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum FuzzMotif {
    /// A dominant axis trends monotonically toward/through a boundary and
    /// the comparison/convergence class agrees: the behavior is converging
    /// on a decision point.
    ComparisonConvergence = 1,
    /// Nearly all structural movement concentrates on one axis while others
    /// barely move: the residual is localized to a single behavioral
    /// dimension.
    ResidualLocalization = 2,
    /// A declared allocation axis grows persistently.
    AllocationCreep = 3,
    /// A declared depth/state axis expands monotonically.
    StateDepthExpansion = 4,
    /// A declared parser/state axis oscillates or its touched set shifts:
    /// the parser's state surface is unstable under mutation.
    ParserStateInstability = 5,
    /// An output axis' magnitude or touched pattern shifted sharply: the
    /// output topology changed.
    OutputTopologyShift = 6,
    /// The active error surface migrated between error axes (some
    /// disappeared, others appeared).
    ErrorVariantMigration = 7,
    /// A declared retry axis escalates monotonically.
    RetryEscalation = 8,
    /// Two or more declared schedule/lock/queue axes co-move: schedule
    /// sensitivity to the input.
    ScheduleSensitivity = 9,
    /// A calibrated axis recurrently grazes the envelope boundary without
    /// leaving it (bounded excursions).
    BoundaryGrazing = 10,
    /// A single edge produced an abrupt envelope exit or slew: a sharp
    /// behavioral jump.
    AbruptBehavioralSlew = 11,
    /// One or more calibrated axes drift persistently away from the nominal
    /// (sustained outward drift, low slew).
    PersistentBehavioralDrift = 12,
    /// Structural change propagated across axes with distinct roles.
    CrossSignalPropagation = 13,
}

impl FuzzMotif {
    /// All classes in code order.
    pub const ALL: [FuzzMotif; 13] = [
        FuzzMotif::ComparisonConvergence,
        FuzzMotif::ResidualLocalization,
        FuzzMotif::AllocationCreep,
        FuzzMotif::StateDepthExpansion,
        FuzzMotif::ParserStateInstability,
        FuzzMotif::OutputTopologyShift,
        FuzzMotif::ErrorVariantMigration,
        FuzzMotif::RetryEscalation,
        FuzzMotif::ScheduleSensitivity,
        FuzzMotif::BoundaryGrazing,
        FuzzMotif::AbruptBehavioralSlew,
        FuzzMotif::PersistentBehavioralDrift,
        FuzzMotif::CrossSignalPropagation,
    ];

    /// The stable wire code.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Resolve a code.
    pub const fn from_code(code: u8) -> Option<FuzzMotif> {
        match code {
            1 => Some(FuzzMotif::ComparisonConvergence),
            2 => Some(FuzzMotif::ResidualLocalization),
            3 => Some(FuzzMotif::AllocationCreep),
            4 => Some(FuzzMotif::StateDepthExpansion),
            5 => Some(FuzzMotif::ParserStateInstability),
            6 => Some(FuzzMotif::OutputTopologyShift),
            7 => Some(FuzzMotif::ErrorVariantMigration),
            8 => Some(FuzzMotif::RetryEscalation),
            9 => Some(FuzzMotif::ScheduleSensitivity),
            10 => Some(FuzzMotif::BoundaryGrazing),
            11 => Some(FuzzMotif::AbruptBehavioralSlew),
            12 => Some(FuzzMotif::PersistentBehavioralDrift),
            13 => Some(FuzzMotif::CrossSignalPropagation),
            _ => None,
        }
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            FuzzMotif::ComparisonConvergence => "comparison-convergence",
            FuzzMotif::ResidualLocalization => "residual-localization",
            FuzzMotif::AllocationCreep => "allocation-creep",
            FuzzMotif::StateDepthExpansion => "state-depth-expansion",
            FuzzMotif::ParserStateInstability => "parser-state-instability",
            FuzzMotif::OutputTopologyShift => "output-topology-shift",
            FuzzMotif::ErrorVariantMigration => "error-variant-migration",
            FuzzMotif::RetryEscalation => "retry-escalation",
            FuzzMotif::ScheduleSensitivity => "schedule-sensitivity",
            FuzzMotif::BoundaryGrazing => "boundary-grazing",
            FuzzMotif::AbruptBehavioralSlew => "abrupt-behavioral-slew",
            FuzzMotif::PersistentBehavioralDrift => "persistent-behavioral-drift",
            FuzzMotif::CrossSignalPropagation => "cross-signal-propagation",
        }
    }
}

/// Provenance of a class definition (mirrors the DSFB ladder; Phase 3 ships
/// only framework-design classes, never dataset-derived ones).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MotifProvenance {
    /// The class was derived from first principles in this crate.
    FrameworkDesign = 1,
}

impl MotifProvenance {
    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// The full definition of one named class (metadata + recommended
/// experiments). The *gate logic* lives in the deterministic classifier
/// below; this table is the inspectable contract.
#[derive(Debug, Clone)]
pub struct FuzzMotifDef {
    /// The class.
    pub motif: FuzzMotif,
    /// What structural observation the name denotes (a description, never a
    /// cause claim).
    pub summary: &'static str,
    /// Known confusers: patterns that look like this class but are benign.
    pub confuser: &'static str,
    /// Provenance of the definition.
    pub provenance: MotifProvenance,
    /// Mutation families the class recommends for the next experiments.
    pub recommended: &'static [crate::mutation::MutatorId],
    /// Refusal conditions (human-readable; enforced by the classifier).
    pub refusal: &'static str,
}

/// The bank's static class table (code order).
pub fn motif_def(motif: FuzzMotif) -> FuzzMotifDef {
    match motif {
        FuzzMotif::ComparisonConvergence => FuzzMotifDef {
            motif,
            summary: "a dominant axis trends monotonically while the cmp/convergence class agrees: behavior converging on a decision boundary",
            confuser: "input-size effect on a counting axis (benign volume change)",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::IntegerAddSub,
                crate::mutation::MutatorId::IntegerBoundary,
                crate::mutation::MutatorId::CompareOperandSubstitution,
            ],
            refusal: "no calibrated dominant axis; dominant axis already Escalated; no convergence class",
        },
        FuzzMotif::ResidualLocalization => FuzzMotifDef {
            motif,
            summary: "structural movement concentrates on a single axis while co-moving axes stay quiet",
            confuser: "a single length field dominating behavior (genuinely one-dimensional input)",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::InfluenceRegionMutation,
                crate::mutation::MutatorId::ByteInsert,
            ],
            refusal: "multi-axis Review activity (that is CrossSignalPropagation/PersistentBehavioralDrift territory)",
        },
        FuzzMotif::AllocationCreep => FuzzMotifDef {
            motif,
            summary: "a declared allocation axis grows persistently across the lineage",
            confuser: "benign cache/arena warm-up saturating early then flat",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::ByteInsert,
                crate::mutation::MutatorId::BlockDuplicate,
                crate::mutation::MutatorId::DictionaryInsert,
            ],
            refusal: "dominant axis has no allocation role; no outward monotone drift",
        },
        FuzzMotif::StateDepthExpansion => FuzzMotifDef {
            motif,
            summary: "a declared depth/state axis expands monotonically across the lineage",
            confuser: "input nesting depth legitimately proportional to input length",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::ByteInsert,
                crate::mutation::MutatorId::BlockDuplicate,
            ],
            refusal: "dominant axis has no depth/state role; direction not monotone",
        },
        FuzzMotif::ParserStateInstability => FuzzMotifDef {
            motif,
            summary: "a declared parser/state axis oscillates or its touched surface shifts between edges",
            confuser: "alternating parse branches chosen by a single flag byte",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::BitFlip,
                crate::mutation::MutatorId::ByteFlip,
            ],
            refusal: "no parser/state axis involved; no oscillation or touched-set shift",
        },
        FuzzMotif::OutputTopologyShift => FuzzMotifDef {
            motif,
            summary: "an output axis changed magnitude class or touched pattern sharply",
            confuser: "output length following input length (benign proportionality)",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::BlockDelete,
                crate::mutation::MutatorId::ByteDelete,
            ],
            refusal: "no output axis involved; no sharp magnitude change",
        },
        FuzzMotif::ErrorVariantMigration => FuzzMotifDef {
            motif,
            summary: "the active error surface migrated between error axes",
            confuser: "input randomly switching between distinct early-return error paths",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::ByteFlip,
                crate::mutation::MutatorId::CompareOperandSubstitution,
            ],
            refusal: "fewer than two error axes involved",
        },
        FuzzMotif::RetryEscalation => FuzzMotifDef {
            motif,
            summary: "a declared retry axis escalates monotonically",
            confuser: "a workload that legitimately retries more under larger inputs",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::IntegerAddSub,
                crate::mutation::MutatorId::ByteInsert,
            ],
            refusal: "dominant axis has no retry role; no outward monotone drift",
        },
        FuzzMotif::ScheduleSensitivity => FuzzMotifDef {
            motif,
            summary: "schedule/lock/queue axes co-move with the input",
            confuser: "global contention from a shared input-wide loop",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::BlockOverwrite,
                crate::mutation::MutatorId::BlockDuplicate,
            ],
            refusal: "fewer than two schedule-role axes co-moving",
        },
        FuzzMotif::BoundaryGrazing => FuzzMotifDef {
            motif,
            summary: "a calibrated axis recurrently grazes the envelope boundary without leaving it",
            confuser: "benign cache warm-up oscillating near a fixed high-water mark",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::IntegerBoundary,
                crate::mutation::MutatorId::DictionaryOverwrite,
            ],
            refusal: "any axis Escalated (that is an envelope exit, not grazing); dominant axis uncalibrated",
        },
        FuzzMotif::AbruptBehavioralSlew => FuzzMotifDef {
            motif,
            summary: "a single edge produced an abrupt envelope exit or direction slew",
            confuser: "a format-magic mismatch switching behavior in one step",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::ByteFlip,
                crate::mutation::MutatorId::InterestingInteger,
            ],
            refusal: "no abrupt reason code and no sharp single-edge magnitude jump",
        },
        FuzzMotif::PersistentBehavioralDrift => FuzzMotifDef {
            motif,
            summary: "one or more calibrated axes drift persistently away from the lineage nominal",
            confuser: "dictionary-saturation warm-up: early climb then plateau",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::ByteInsert,
                crate::mutation::MutatorId::DictionaryInsert,
                crate::mutation::MutatorId::BlockDuplicate,
            ],
            refusal: "dominant axis uncalibrated; drift not monotone (oscillatory); nothing sustained",
        },
        FuzzMotif::CrossSignalPropagation => FuzzMotifDef {
            motif,
            summary: "structural change propagated across axes with distinct declared roles",
            confuser: "one shared input region driving several dependent counters",
            provenance: MotifProvenance::FrameworkDesign,
            recommended: &[
                crate::mutation::MutatorId::InfluenceRegionMutation,
                crate::mutation::MutatorId::BlockOverwrite,
            ],
            refusal: "fewer than two Review axes with distinct roles",
        },
    }
}

/// The evidence summary the classifier consumes (built from the phase-2
/// morphology signature plus the phase-3 DSFB axis verdicts of one edge).
#[derive(Debug, Clone)]
pub struct BankEvidence {
    /// The edge's morphology signature (shape fields).
    pub sig: MorphologySignature,
    /// The edge's per-axis DSFB verdicts.
    pub verdicts: Vec<AxisVerdict>,
    /// Per-axis declared roles (index by axis id; from the target schema).
    pub roles: [AxisRole; MAX_SIGNALS],
}

impl BankEvidence {
    /// Build evidence for the classifier.
    pub fn new(sig: &MorphologySignature, verdicts: &[AxisVerdict]) -> BankEvidence {
        BankEvidence {
            sig: sig.clone(),
            verdicts: verdicts.to_vec(),
            roles: [AxisRole::NONE; MAX_SIGNALS],
        }
    }

    /// Set the role of one axis (coordinator fills roles from the schema).
    pub fn set_role(&mut self, axis: u16, role: AxisRole) {
        if let Some(slot) = self.roles.get_mut(axis as usize) {
            *slot = role;
        }
    }

    fn verdict_of(&self, axis: u16) -> Option<&AxisVerdict> {
        self.verdicts.iter().find(|v| v.axis == axis)
    }

    /// Axes with policy ≥ Watch / Review / Escalate among the verdicts.
    fn policy_masks(&self) -> (u64, u64, u64) {
        let mut w = 0u64;
        let mut r = 0u64;
        let mut e = 0u64;
        for v in &self.verdicts {
            if v.policy >= PolicyState::Watch as u8 {
                w |= 1u64 << v.axis;
            }
            if v.policy >= PolicyState::Review as u8 {
                r |= 1u64 << v.axis;
            }
            if v.policy >= PolicyState::Escalate as u8 {
                e |= 1u64 << v.axis;
            }
        }
        (w, r, e)
    }

    /// Reason bits seen on any verdict.
    fn reasons_seen(&self) -> u16 {
        let mut bits = 0u16;
        for v in &self.verdicts {
            bits |= 1u16 << (v.reason & 15);
        }
        bits
    }

    /// Whether the dominant axis has an envelope verdict.
    fn dominant_calibrated(&self) -> bool {
        match self.sig.dominant_axis() {
            Some(a) => self.verdict_of(a).map(|v| v.calibrated).unwrap_or(false),
            None => false,
        }
    }
}

/// The classifier's deterministic output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BankVerdict {
    /// Named class code, or 0 when nothing was named (`Unknown`).
    pub class: u8,
    /// The top candidate's integer score.
    pub top_score: u8,
    /// The runner-up candidate's integer score (0 when no runner-up).
    pub runner_up_score: u8,
    /// Whether multiple classes passed their gates (ambiguous → Unknown).
    pub ambiguous: bool,
}

impl BankVerdict {
    /// The named class, if any.
    pub fn motif(&self) -> Option<FuzzMotif> {
        FuzzMotif::from_code(self.class)
    }

    /// Whether the verdict is a named class.
    pub fn is_named(&self) -> bool {
        self.class != 0
    }

    /// Deterministic match of the verdict against another (used by tests).
    pub fn score_margin(&self) -> u8 {
        self.top_score.saturating_sub(self.runner_up_score)
    }
}

/// The deterministic classifier over one edge's evidence.
///
/// Gate ladder (mirroring the DSFB anti-hallucination structure):
/// 1. zero-tier filter — a candidate needs at least one structural axis;
/// 2. witness-tier gate — the class prerequisites must hold;
/// 3. refusal conditions — disqualifying patterns per class;
/// 4. specificity + margin resolution — among the passing classes the
///    highest integer score wins; ties are resolved by class specificity
///    (role-bound classes are more specific than contextual ones,
///    deterministic), then by class code;
/// 5. ambiguity guard — a candidate is only named when no OTHER class has
///    the same score at the same specificity tier (an exact same-tier tie is
///    genuinely ambiguous and stays Unknown).
///
/// If no class survives, the result is `Unknown` (the caller decides
/// structured vs trivial from the morphology classifier).
///
/// Scores are small deterministic integers: 4 base + corroborating evidence
/// bonuses + the specificity tier (role-bound +2, contextual +1).
pub fn classify_evidence(ev: &BankEvidence) -> BankVerdict {
    let (watch, review, escalate) = ev.policy_masks();
    let reasons = ev.reasons_seen();
    let active = watch != 0;

    // Zero-tier filter: nothing structurally active means nothing can be
    // named (trivial or pre-structural edges stay Unknown).
    if !active {
        return BankVerdict {
            class: 0,
            top_score: 0,
            runner_up_score: 0,
            ambiguous: false,
        };
    }

    // Evaluate every class; keep (code, score-with-specificity) of those
    // whose gates pass.
    let mut passed: Vec<(u8, u8)> = Vec::new();
    for motif in FuzzMotif::ALL {
        if let Some(score) = gate_for(motif, ev, watch, review, escalate, reasons) {
            passed.push((motif.code(), score.saturating_add(specificity(motif))));
        }
    }

    // Deterministic resolution: highest score, then specificity tier desc,
    // then lowest code.
    passed.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| specificity_of(b.0).cmp(&specificity_of(a.0)))
            .then_with(|| a.0.cmp(&b.0))
    });
    match passed.first() {
        None => BankVerdict {
            class: 0,
            top_score: 0,
            runner_up_score: 0,
            ambiguous: false,
        },
        Some((code, score)) => {
            let runner = passed.get(1).map(|(_, s)| *s).unwrap_or(0);
            let runner_code = passed.get(1).map(|(c, _)| *c).unwrap_or(0);
            // Ambiguity guard: an exact same-score, same-specificity rival
            // means the evidence does not decisively separate the classes.
            let ambiguous = runner == *score
                && runner_code != *code
                && specificity_of(runner_code) == specificity_of(*code);
            if ambiguous {
                BankVerdict {
                    class: 0,
                    top_score: *score,
                    runner_up_score: runner,
                    ambiguous: true,
                }
            } else {
                BankVerdict {
                    class: *code,
                    top_score: *score,
                    runner_up_score: runner,
                    ambiguous: false,
                }
            }
        }
    }
}

/// The specificity tier of a class: role-bound classes (2) name a narrower
/// observation than contextual classes (1). Used for deterministic tie
/// resolution; see [`classify_evidence`].
pub const fn specificity(motif: FuzzMotif) -> u8 {
    match motif {
        FuzzMotif::AllocationCreep
        | FuzzMotif::StateDepthExpansion
        | FuzzMotif::ParserStateInstability
        | FuzzMotif::OutputTopologyShift
        | FuzzMotif::RetryEscalation
        | FuzzMotif::ScheduleSensitivity => 2,
        FuzzMotif::ComparisonConvergence
        | FuzzMotif::ResidualLocalization
        | FuzzMotif::ErrorVariantMigration
        | FuzzMotif::BoundaryGrazing
        | FuzzMotif::AbruptBehavioralSlew
        | FuzzMotif::PersistentBehavioralDrift
        | FuzzMotif::CrossSignalPropagation => 1,
    }
}

fn specificity_of(code: u8) -> u8 {
    match FuzzMotif::from_code(code) {
        Some(m) => specificity(m),
        None => 0,
    }
}

/// The per-class gate. Returns the base score (specificity is added by the
/// caller) when the class is named for this evidence, `None` when it is
/// refused. Bonuses are +1 per corroborating structural fact; every class
/// starts at 4.
fn gate_for(
    motif: FuzzMotif,
    ev: &BankEvidence,
    watch: u64,
    review: u64,
    escalate: u64,
    reasons: u16,
) -> Option<u8> {
    let sig = &ev.sig;
    let dominant = ev.sig.dominant_axis();
    let dominant_dir = dominant.map(|a| sig.dir(a as usize)).unwrap_or(0);
    let dominant_role = dominant
        .map(|a| ev.roles[a as usize])
        .unwrap_or(AxisRole::NONE);
    let max_persistence = sig.persistence.iter().copied().max().unwrap_or(0);
    let max_slew = sig.slew_bins.iter().copied().max().unwrap_or(0);
    let review_count = review.count_ones() as u8;

    // Helpers.
    let has_reason = |rc: ReasonCode| reasons & (1u16 << (rc as u8 & 15)) != 0;
    let dominant_outward = dominant_dir == 1;
    let monotone = max_slew == 0 && dominant_outward;
    let any_role = |role: AxisRole| {
        ev.verdicts
            .iter()
            .any(|v| ev.roles[v.axis as usize].intersects(role))
    };
    // Standard corroboration bonuses shared by the drift-family classes.
    let drift_bonus = |score: u8| {
        let mut s = score;
        if has_reason(ReasonCode::SustainedOutwardDrift)
            || has_reason(ReasonCode::EnvelopeViolation)
        {
            s += 1;
        }
        if max_persistence >= 8 {
            s += 1;
        }
        s
    };

    match motif {
        FuzzMotif::ComparisonConvergence => {
            // Requires an actual comparison-convergence class and a
            // calibrated dominant axis approaching the boundary; refuses
            // escalation (an exit is not convergence) and refuses long
            // sustained outward drift (that is PersistentBehavioralDrift's
            // regime, not convergence).
            let cmp_ok = sig.cmp_convergence == CmpConvergence::Converging.code()
                || sig.cmp_convergence == CmpConvergence::Oscillating.code();
            if !cmp_ok || escalate != 0 || review_count == 0 {
                return None;
            }
            if !ev.dominant_calibrated() || !monotone {
                return None;
            }
            if has_reason(ReasonCode::EnvelopeViolation)
                || (dominant_outward
                    && has_reason(ReasonCode::SustainedOutwardDrift)
                    && max_persistence >= 8)
            {
                return None;
            }
            let mut score = 4u8;
            if has_reason(ReasonCode::SustainedOutwardDrift) {
                score += 1;
            }
            if (4..8).contains(&max_persistence) {
                score += 1;
            }
            Some(score)
        }
        FuzzMotif::ResidualLocalization => {
            // Multi-axis morphology, single dominant axis; refuses when two
            // or more axes reached Review (that is propagation, not
            // localization).
            if sig.axis_mask.count_ones() < 2 {
                return None;
            }
            if review_count >= 2 {
                return None;
            }
            if watch.count_ones() == 0 || escalate != 0 {
                return None;
            }
            // The dominant axis must out-scale the runner-up by at least
            // two magnitude buckets.
            let dom = dominant?;
            let dom_bin = sig.mag_bin(dom as usize);
            let runner = (0..MAX_SIGNALS)
                .filter(|i| *i != dom as usize && sig.mag_bins[*i] != 0)
                .map(|i| sig.mag_bins[i])
                .max()
                .unwrap_or(0);
            if dom_bin < runner.saturating_add(2) {
                return None;
            }
            let mut score = 4u8;
            if monotone {
                score += 1;
            }
            if dom_bin >= 4 {
                score += 1;
            }
            Some(score)
        }
        FuzzMotif::AllocationCreep => {
            if !dominant_role.intersects(AxisRole::ALLOCATION) {
                return None;
            }
            if review_count == 0 || escalate != 0 {
                return None;
            }
            if !monotone || !ev.dominant_calibrated() {
                return None;
            }
            Some(drift_bonus(4))
        }
        FuzzMotif::StateDepthExpansion => {
            if !dominant_role.intersects(AxisRole::DEPTH | AxisRole::STATE) {
                return None;
            }
            if review_count == 0 || escalate != 0 {
                return None;
            }
            if !monotone {
                return None;
            }
            Some(drift_bonus(4))
        }
        FuzzMotif::ParserStateInstability => {
            if !any_role(AxisRole::PARSE | AxisRole::STATE) {
                return None;
            }
            let oscillation = sig.cmp_convergence == CmpConvergence::Oscillating.code()
                || max_slew >= 1
                || dominant_dir == DriftDir::Oscillatory.code();
            let shifted = sig.state_change == StateChange::Shifted.code()
                || sig.state_change == StateChange::Expanded.code();
            if !oscillation && !shifted {
                return None;
            }
            if watch.count_ones() == 0 || escalate != 0 {
                return None;
            }
            let mut score = 4u8;
            if shifted {
                score += 1;
            }
            if max_slew >= 2 {
                score += 1;
            }
            Some(score)
        }
        FuzzMotif::OutputTopologyShift => {
            if !any_role(AxisRole::OUTPUT | AxisRole::SIZE) {
                return None;
            }
            let sharp = ev.verdicts.iter().any(|v| {
                ev.roles[v.axis as usize].intersects(AxisRole::OUTPUT | AxisRole::SIZE)
                    && v.dev_mag_bin >= 4
            });
            if !sharp {
                return None;
            }
            if watch.count_ones() == 0 {
                return None;
            }
            let mut score = 4u8;
            if sig.state_change == StateChange::Shifted.code() {
                score += 1;
            }
            if has_reason(ReasonCode::AbruptSlewViolation) {
                score += 1;
            }
            Some(score)
        }
        FuzzMotif::ErrorVariantMigration => {
            let mut err_mask = 0u64;
            for i in 0..MAX_SIGNALS {
                if ev.roles[i].intersects(AxisRole::ERROR) {
                    err_mask |= 1u64 << i;
                }
            }
            let involved = sig.axis_mask & err_mask;
            if involved.count_ones() < 2 {
                return None;
            }
            let touched = sig.state_change == StateChange::Shifted.code()
                || sig.state_change == StateChange::Expanded.code()
                || sig.state_change == StateChange::Contracted.code();
            if !touched || watch.count_ones() == 0 {
                return None;
            }
            let mut score = 4u8;
            if review_count >= 1 {
                score += 1;
            }
            Some(score)
        }
        FuzzMotif::RetryEscalation => {
            if !dominant_role.intersects(AxisRole::RETRY) {
                return None;
            }
            if review_count == 0 || escalate != 0 {
                return None;
            }
            if !monotone || !ev.dominant_calibrated() {
                return None;
            }
            Some(drift_bonus(4))
        }
        FuzzMotif::ScheduleSensitivity => {
            // Two or more schedule/lock/queue/timeout axes co-moving.
            let mut role_mask = 0u64;
            for i in 0..MAX_SIGNALS {
                if ev.roles[i].intersects(
                    AxisRole::SCHEDULE | AxisRole::LOCK | AxisRole::QUEUE | AxisRole::TIMEOUT,
                ) {
                    role_mask |= 1u64 << i;
                }
            }
            let co = sig.coactivation_mask & role_mask;
            let reviewing = review & role_mask;
            if co.count_ones() + reviewing.count_ones() < 2 {
                return None;
            }
            if watch.count_ones() == 0 {
                return None;
            }
            let mut score = 4u8;
            if reviewing.count_ones() >= 1 {
                score += 1;
            }
            Some(score)
        }
        FuzzMotif::BoundaryGrazing => {
            // Bounded recurrent zone touches: boundary-zone reasons, no
            // escalation, no violation reason, calibrated dominant.
            if escalate != 0 || !ev.dominant_calibrated() {
                return None;
            }
            if !has_reason(ReasonCode::BoundaryApproach)
                && !has_reason(ReasonCode::SustainedOutwardDrift)
            {
                return None;
            }
            if has_reason(ReasonCode::EnvelopeViolation)
                || has_reason(ReasonCode::AbruptSlewViolation)
            {
                return None;
            }
            if watch.count_ones() == 0 {
                return None;
            }
            // Sustained long outward drift is PersistentBehavioralDrift
            // territory, not recurrent grazing.
            if max_persistence >= 8 && !has_reason(ReasonCode::BoundaryApproach) {
                return None;
            }
            // Grazing requires recurrence: direction flips, a Review-level
            // zone presence, or at least three consecutive zone touches. A
            // single Watch-level zone touch is not grazing.
            if max_slew == 0 && review_count == 0 && max_persistence < 3 {
                return None;
            }
            let mut score = 4u8;
            if max_slew >= 1 {
                score += 1; // direction flips near the zone: recurrent
            }
            if has_reason(ReasonCode::BoundaryApproach) {
                score += 1;
            }
            Some(score)
        }
        FuzzMotif::AbruptBehavioralSlew => {
            let abrupt_reason = has_reason(ReasonCode::AbruptSlewViolation);
            let sharp_jump = dominant
                .map(|a| sig.mag_bin(a as usize) >= 6)
                .unwrap_or(false);
            if !abrupt_reason && !sharp_jump {
                return None;
            }
            if watch.count_ones() == 0 {
                return None;
            }
            let mut score = 4u8;
            if has_reason(ReasonCode::EnvelopeViolation) {
                score += 1;
            }
            if sharp_jump {
                score += 1;
            }
            Some(score)
        }
        FuzzMotif::PersistentBehavioralDrift => {
            // Sustained outward drift on a calibrated dominant axis;
            // escalation is allowed (the drift continued through the
            // envelope). Monotone only: oscillating zone behavior is
            // BoundaryGrazing's job.
            if review_count == 0 || !ev.dominant_calibrated() {
                return None;
            }
            if !monotone {
                return None;
            }
            if !has_reason(ReasonCode::SustainedOutwardDrift)
                && !has_reason(ReasonCode::EnvelopeViolation)
                && !has_reason(ReasonCode::BoundaryApproach)
            {
                return None;
            }
            let mut score = drift_bonus(4);
            if review_count >= 2 {
                score += 1;
            }
            Some(score)
        }
        FuzzMotif::CrossSignalPropagation => {
            // Two or more axes at Review with DISTINCT roles, coherent
            // outward direction family.
            if review_count < 2 {
                return None;
            }
            let mut roles_seen = AxisRole::NONE;
            let mut outward_ok = true;
            for v in &ev.verdicts {
                if v.policy >= PolicyState::Review as u8 {
                    roles_seen = AxisRole(roles_seen.bits() | ev.roles[v.axis as usize].bits());
                    let d = sig.dir(v.axis as usize);
                    if d != 1 && d != 2 {
                        outward_ok = false;
                    }
                }
            }
            if roles_seen.bits().count_ones() < 2 || !outward_ok {
                return None;
            }
            let mut score = 4u8;
            if sig.state_change == StateChange::Shifted.code() {
                score += 1;
            }
            if max_persistence >= 8 {
                score += 1;
            }
            Some(score)
        }
    }
}

/// Convenience: run the classifier and produce a human-readable one-line
/// description (used by the demo and `report`).
pub fn describe_verdict(ev: &BankEvidence, verdict: &BankVerdict) -> String {
    match verdict.motif() {
        Some(m) => {
            let def = motif_def(m);
            format!(
                "named {} (score {} vs {}{}): {}",
                m.name(),
                verdict.top_score,
                verdict.runner_up_score,
                if verdict.ambiguous { " ambiguous" } else { "" },
                def.summary
            )
        }
        None => {
            let structured = !ev.sig.is_trivial();
            if structured {
                format!(
                    "structured-unknown (best score {} vs {}{})",
                    verdict.top_score,
                    verdict.runner_up_score,
                    if verdict.ambiguous { ", ambiguous" } else { "" }
                )
            } else {
                "trivial".to_string()
            }
        }
    }
}

/// Validate the static bank tables (bounds on codes; invoked by tests).
pub fn validate_bank() -> Result<()> {
    let mut seen = [false; 256];
    for motif in FuzzMotif::ALL {
        let code = motif.code();
        if code == 0 {
            return Err(Error::Encoding("fuzz motif code 0 is reserved"));
        }
        if seen[code as usize] {
            return Err(Error::Encoding("duplicate fuzz motif code"));
        }
        seen[code as usize] = true;
        if FuzzMotif::from_code(code) != Some(motif) {
            return Err(Error::Encoding("fuzz motif code table inconsistent"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsfb::debug_bridge::AxisVerdict;
    use crate::dsfb::morphology::{classify, LineageAccumulator, StructuralClass};
    use crate::observe::residual::MutationResidual;
    use crate::target_runtime::signals::{SignalId, SignalVector};

    fn vec_with(id: u16, v: u64) -> SignalVector {
        let mut s = SignalVector::new();
        s.observe(SignalId(id), v).unwrap();
        s
    }

    fn desc(name: &str, unit: &str) -> SignalDesc {
        let mut d = SignalDesc::empty();
        d.present = true;
        let nb = name.as_bytes();
        d.name_len = nb.len().min(32) as u8;
        d.name[..d.name_len as usize].copy_from_slice(&nb[..d.name_len as usize]);
        let ub = unit.as_bytes();
        d.unit_len = ub.len().min(16) as u8;
        d.unit[..d.unit_len as usize].copy_from_slice(&ub[..d.unit_len as usize]);
        d
    }

    fn role(name: &str, unit: &str) -> AxisRole {
        role_of(&desc(name, unit))
    }

    #[test]
    fn role_assignment_is_deterministic_and_specific() {
        assert_eq!(role("marker_depth", "markers"), AxisRole::DEPTH);
        assert_eq!(role("allocated_bytes", "bytes"), AxisRole::ALLOCATION);
        assert_eq!(role("parsed_items", "count"), AxisRole::PARSE);
        assert_eq!(role("retry_count", "count"), AxisRole::RETRY);
        assert_eq!(role("error_variant", "id"), AxisRole::ERROR);
        assert_eq!(role("output_len", "bytes"), AxisRole::OUTPUT);
        assert_eq!(role("weird_axis", "units"), AxisRole::NONE);
        // "depth" must win over the generic count rule ("count" absent).
        assert!(role("marker_depth", "count").intersects(AxisRole::DEPTH));
    }

    #[test]
    fn codes_are_stable_and_table_is_consistent() {
        assert_eq!(FuzzMotif::ComparisonConvergence.code(), 1);
        assert_eq!(FuzzMotif::CrossSignalPropagation.code(), 13);
        validate_bank().unwrap();
        for m in FuzzMotif::ALL {
            let def = motif_def(m);
            assert_eq!(def.motif, m);
            assert!(!def.summary.is_empty());
            assert!(!def.confuser.is_empty());
        }
    }

    /// Build a drifting-lineage signature on a single axis (like the golden
    /// demo's marker-depth ladder), returning (signature, last edge).
    fn drift_signature(axis: u16, steps: u32, baseline: u64, step: u64) -> MorphologySignature {
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&vec_with(axis, baseline));
        let mut parent = vec_with(axis, baseline);
        let mut sig = acc.push(&MutationResidual::of(&parent, &parent), 0);
        for d in 1..=steps {
            let child = vec_with(axis, baseline + d as u64 * step);
            sig = acc.push(&MutationResidual::of(&child, &parent), d);
            parent = child;
        }
        sig
    }

    fn review_verdict(axis: u16, reason: u8, calibrated: bool) -> AxisVerdict {
        AxisVerdict {
            axis,
            grammar: 1,
            confirmed: 1,
            reason,
            policy: PolicyState::Review as u8,
            dir: DriftDir::Outward.code(),
            calibrated,
            dev_mag_bin: 5,
            persistence: 6,
        }
    }

    #[test]
    fn structured_unknown_when_no_gate_passes() {
        // Only a Watch-level isolated verdict with no sustained drift: no
        // class may be named.
        let sig = drift_signature(0, 3, 0, 1);
        let mut ev = BankEvidence::new(&sig, &[]);
        ev.set_role(0, role("marker_depth", "markers"));
        let v = classify_evidence(&ev);
        assert!(
            !v.is_named(),
            "short non-sustained movement must stay Unknown"
        );
    }

    #[test]
    fn persistent_depth_drift_is_named_state_depth_expansion() {
        // A long monotone climb on a declared depth axis with a Review
        // SustainedOutwardDrift verdict is StateDepthExpansion.
        let sig = drift_signature(0, 12, 0, 1);
        let mut ev = BankEvidence::new(
            &sig,
            &[review_verdict(
                0,
                ReasonCode::SustainedOutwardDrift as u8,
                true,
            )],
        );
        ev.set_role(0, role("marker_depth", "markers"));
        let v = classify_evidence(&ev);
        assert_eq!(
            v.motif(),
            Some(FuzzMotif::StateDepthExpansion),
            "long monotone depth climb must be named: {v:?}"
        );
        assert!(!v.ambiguous);
    }

    #[test]
    fn allocation_creep_requires_allocation_role() {
        // The same monotone climb on a signal WITHOUT an allocation role must
        // not be named AllocationCreep (unknown/other role refuses).
        let sig = drift_signature(0, 12, 0, 1);
        let mut ev = BankEvidence::new(
            &sig,
            &[review_verdict(
                0,
                ReasonCode::SustainedOutwardDrift as u8,
                true,
            )],
        );
        ev.set_role(0, role("weird_axis", "units"));
        let v = classify_evidence(&ev);
        assert_ne!(v.motif(), Some(FuzzMotif::AllocationCreep));
        // With the allocation role it is named (depth rule absent).
        let mut ev2 = BankEvidence::new(
            &sig,
            &[review_verdict(
                0,
                ReasonCode::SustainedOutwardDrift as u8,
                true,
            )],
        );
        ev2.set_role(0, role("allocated_bytes", "bytes"));
        let v2 = classify_evidence(&ev2);
        assert_eq!(v2.motif(), Some(FuzzMotif::AllocationCreep));
    }

    #[test]
    fn noise_edges_never_produce_named_classes() {
        // A noise-only oscillating series whose envelope evaluation stays
        // admissible must never produce a named class: no monotone class
        // applies, and no abrupt/other class may fire from thin evidence.
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&SignalVector::new());
        let mut parent = SignalVector::new();
        let mut sig = acc.push(&MutationResidual::of(&parent, &parent), 0);
        for d in 1..=10u32 {
            let value = if d % 2 == 0 { 20u64 } else { 0u64 };
            let child = vec_with(0, value);
            sig = acc.push(&MutationResidual::of(&child, &parent), d);
            parent = child;
        }
        assert_eq!(classify(&sig), StructuralClass::StructuredUnknown);
        // Even at Watch level with an admissible reason and oscillation,
        // nothing may be named.
        let verdicts = vec![AxisVerdict {
            axis: 0,
            grammar: 0,
            confirmed: 0,
            reason: ReasonCode::Admissible as u8,
            policy: PolicyState::Watch as u8,
            dir: DriftDir::Oscillatory.code(),
            calibrated: true,
            dev_mag_bin: 3,
            persistence: 2,
        }];
        let mut ev = BankEvidence::new(&sig, &verdicts);
        ev.set_role(0, role("marker_depth", "markers"));
        let v = classify_evidence(&ev);
        assert!(
            !v.is_named(),
            "noise oscillation with no zone/abrupt evidence must stay Unknown: {v:?}"
        );
    }

    #[test]
    fn recurrent_zone_oscillation_is_boundary_grazing() {
        // A calibrated axis that oscillates in the envelope zone (recurrent
        // BoundaryApproach touches with direction flips, no escalation) is
        // named BoundaryGrazing — DSFB's own semantics for recurrent zone
        // presence with direction flips. Oscillation must genuinely cross the
        // nominal (baseline 10, values 16/4), which the Phase-2 accumulator
        // counts as direction reversals (slew).
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&vec_with(0, 10));
        let mut parent = vec_with(0, 10);
        let mut sig = acc.push(&MutationResidual::of(&parent, &parent), 0);
        for d in 1..=8u32 {
            let value = if d % 2 == 1 { 16u64 } else { 4u64 };
            let child = vec_with(0, value);
            sig = acc.push(&MutationResidual::of(&child, &parent), d);
            parent = child;
        }
        assert!(sig.slew_bins[0] >= 2, "oscillation must flip directions");
        let verdicts = vec![AxisVerdict {
            axis: 0,
            grammar: 1,
            confirmed: 1,
            reason: ReasonCode::BoundaryApproach as u8,
            policy: PolicyState::Review as u8,
            dir: DriftDir::Oscillatory.code(),
            calibrated: true,
            dev_mag_bin: 3,
            persistence: 2,
        }];
        let mut ev = BankEvidence::new(&sig, &verdicts);
        ev.set_role(0, role("marker_depth", "markers"));
        let v = classify_evidence(&ev);
        assert_eq!(v.motif(), Some(FuzzMotif::BoundaryGrazing), "{v:?}");
    }

    #[test]
    fn abrupt_slew_names_only_with_abrupt_evidence() {
        // A single huge jump (dev magnitude high, AbruptSlew reason) is
        // named; the same morphology with a gentle reason is not.
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&vec_with(0, 0));
        let parent = vec_with(0, 0);
        acc.push(&MutationResidual::of(&parent, &parent), 0);
        let child = vec_with(0, 100);
        let sig = acc.push(&MutationResidual::of(&child, &parent), 1);
        let verdicts = vec![AxisVerdict {
            axis: 0,
            grammar: 2,
            confirmed: 2,
            reason: ReasonCode::AbruptSlewViolation as u8,
            policy: PolicyState::Escalate as u8,
            dir: DriftDir::Outward.code(),
            calibrated: true,
            dev_mag_bin: 6,
            persistence: 1,
        }];
        let mut ev = BankEvidence::new(&sig, &verdicts);
        ev.set_role(0, role("marker_depth", "markers"));
        let v = classify_evidence(&ev);
        assert_eq!(v.motif(), Some(FuzzMotif::AbruptBehavioralSlew));
    }

    #[test]
    fn escalation_alone_is_not_abrupt_slew() {
        // Escalation from a long sustained drift (EnvelopeViolation reason,
        // zero slew) is PersistentBehavioralDrift, NOT AbruptBehavioralSlew.
        let sig = drift_signature(0, 16, 0, 1);
        let verdicts = vec![AxisVerdict {
            axis: 0,
            grammar: 2,
            confirmed: 2,
            reason: ReasonCode::EnvelopeViolation as u8,
            policy: PolicyState::Escalate as u8,
            dir: DriftDir::Outward.code(),
            calibrated: true,
            dev_mag_bin: 6,
            persistence: 12,
        }];
        let mut ev = BankEvidence::new(&sig, &verdicts);
        ev.set_role(0, role("marker_depth", "markers"));
        let v = classify_evidence(&ev);
        assert_eq!(v.motif(), Some(FuzzMotif::PersistentBehavioralDrift));
    }

    #[test]
    fn roleless_sustained_drift_is_persistent_behavioral_drift() {
        // A role-less (unknown semantic) axis with sustained outward drift is
        // named by the generic PersistentBehavioralDrift family — the honest
        // description when no role-specific class applies.
        let sig = drift_signature(0, 10, 0, 1);
        let verdicts = vec![AxisVerdict {
            axis: 0,
            grammar: 1,
            confirmed: 1,
            reason: ReasonCode::SustainedOutwardDrift as u8,
            policy: PolicyState::Review as u8,
            dir: DriftDir::Outward.code(),
            calibrated: true,
            dev_mag_bin: 4,
            persistence: 10,
        }];
        let mut ev = BankEvidence::new(&sig, &verdicts);
        ev.set_role(0, role("weird_axis", "units"));
        let v = classify_evidence(&ev);
        assert_eq!(
            v.motif(),
            Some(FuzzMotif::PersistentBehavioralDrift),
            "role-less sustained drift is PersistentBehavioralDrift: {v:?}"
        );
    }

    #[test]
    fn same_tier_tie_stays_unknown() {
        // When two contextual-tier classes tie exactly, the evidence does not
        // separate them: the result must be Unknown (ambiguous), never an
        // arbitrary pick.
        let sig = drift_signature(0, 6, 0, 1);
        // Review-level, zone-touch reason, monotone outward, moderate
        // persistence: ComparisonConvergence (converging class, calibrated
        // monotone dominant, no escalation, persistence < 8) and
        // BoundaryGrazing (zone reason, no escalation, persistence < 8 and
        // BoundaryApproach present) both pass at the contextual tier with
        // equal scores.
        let verdicts = vec![AxisVerdict {
            axis: 0,
            grammar: 1,
            confirmed: 1,
            reason: ReasonCode::BoundaryApproach as u8,
            policy: PolicyState::Review as u8,
            dir: DriftDir::Outward.code(),
            calibrated: true,
            dev_mag_bin: 3,
            persistence: 4,
        }];
        let mut ev = BankEvidence::new(&sig, &verdicts);
        ev.set_role(0, role("weird_axis", "units"));
        let v = classify_evidence(&ev);
        assert!(
            !v.is_named() && v.ambiguous,
            "same-tier tie must stay Unknown: {v:?}"
        );
    }

    #[test]
    fn classify_is_deterministic() {
        let sig = drift_signature(0, 12, 0, 1);
        let verdicts = vec![review_verdict(
            0,
            ReasonCode::SustainedOutwardDrift as u8,
            true,
        )];
        let mut a = BankEvidence::new(&sig, &verdicts);
        a.set_role(0, role("marker_depth", "markers"));
        let va = classify_evidence(&a);
        for _ in 0..50 {
            let mut b = BankEvidence::new(&sig, &verdicts);
            b.set_role(0, role("marker_depth", "markers"));
            assert_eq!(classify_evidence(&b), va);
        }
    }
}
