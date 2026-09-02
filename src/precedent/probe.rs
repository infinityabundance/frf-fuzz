//! Probe recipes and deterministic falsifiable relationships (master prompt
//! §17; Phase 3).
//!
//! A precedent only guides predictive scheduling when it carries at least one
//! falsifiable experimental relationship: a concrete, deterministic
//! experiment (a probe) plus what the coordinator expects to observe IF the
//! precedent's family holds, and what it expects for the confuser. The probe
//! is executed as an ordinary deterministic mutation batch on the matched
//! lineage's frontier; the coordinator reads the bounded per-batch signal
//! aggregates ([`crate::target_runtime::signals::SignalBatchSummary`]) and
//! evaluates the expectation. No target cooperation and no worker changes are
//! needed: a probe is a normal [`crate::scheduler::work_order::WorkOrder`]
//! carrying a coordinator-side expectation.
//!
//! Outcomes are three-valued: `Support` (the family expectation held),
//! `Contradict` (the confuser expectation held / the family expectation was
//! directly refuted), and `Ambiguous` (weak or unreadable evidence). A
//! contradiction is durable negative knowledge (I10): it is never deleted and
//! never silently overwrites the precedent — it is *recorded* on a new
//! precedent revision.
//!
//! This module is coordinator-gated.

use crate::error::{Error, Result};
use crate::mutation::MutatorId;
use crate::target_runtime::signals::{magnitude_bucket, SignalBatchSummary};

/// Version of the probe-recipe encoding.
pub const PROBE_RECIPE_VERSION: u8 = 1;
/// Version of the probe-evidence encoding (per-evaluation record).
pub const PROBE_EVIDENCE_VERSION: u8 = 1;

/// The three-valued probe outcome. Never a probability (I11): the evidence
/// either held, was refuted, or was unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeOutcome {
    /// The precedent-family expectation held.
    Support = 1,
    /// The expectation was refuted (the confuser expectation held instead).
    Contradict = 2,
    /// The evidence was too weak or conflicting to read either way.
    Ambiguous = 3,
}

impl ProbeOutcome {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<ProbeOutcome> {
        match b {
            1 => Some(ProbeOutcome::Support),
            2 => Some(ProbeOutcome::Contradict),
            3 => Some(ProbeOutcome::Ambiguous),
            _ => None,
        }
    }

    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            ProbeOutcome::Support => "support",
            ProbeOutcome::Contradict => "contradict",
            ProbeOutcome::Ambiguous => "ambiguous",
        }
    }
}

/// What a probe expects to read on one axis of the batch summary. The
/// expectations are *activity* laws, deliberately direction-free at this
/// layer: batch summaries record movement magnitude and run length, not net
/// sign. A family that historically drifted must keep MOVING under continued
/// mutation of the same family; the saturation confuser settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Expectation {
    /// The axis must keep moving: at least `min_count` executions moved it,
    /// the longest same-direction run reaches `min_run`, and the summed
    /// movement magnitude reaches `min_sum_bucket` (log2 bucket).
    MovementPersists = 1,
    /// The axis must settle: fewer than `min_count` executions moved it and
    /// the summed movement stays below `min_sum_bucket`. This is the
    /// confuser-side expectation (warm-up/saturation decay).
    MovementAbates = 2,
}

impl Expectation {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<Expectation> {
        match b {
            1 => Some(Expectation::MovementPersists),
            2 => Some(Expectation::MovementAbates),
            _ => None,
        }
    }

    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            Expectation::MovementPersists => "movement-persists",
            Expectation::MovementAbates => "movement-abates",
        }
    }
}

/// A deterministic falsifiable probe: continue the lineage's frontier under
/// the same mutator family and read the expectation on `axis`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRecipe {
    /// The mutator family the probe orders.
    pub family: u16,
    /// The axis the expectation is read on.
    pub axis: u16,
    /// The expectation.
    pub expectation: Expectation,
    /// `MovementPersists`: minimum executions that moved the axis.
    /// `MovementAbates`: maximum executions that moved the axis.
    pub min_count: u32,
    /// `MovementPersists`: minimum longest same-direction run.
    pub min_run: u8,
    /// `MovementPersists`: minimum summed-magnitude bucket; `MovementAbates`:
    /// maximum summed-magnitude bucket.
    pub min_sum_bucket: u8,
}

impl ProbeRecipe {
    /// Build a `MovementPersists` recipe on `axis` under `family`.
    pub fn persists(
        family: MutatorId,
        axis: u16,
        min_count: u32,
        min_run: u8,
        min_sum_bucket: u8,
    ) -> ProbeRecipe {
        ProbeRecipe {
            family: family.id(),
            axis,
            expectation: Expectation::MovementPersists,
            min_count,
            min_run,
            min_sum_bucket,
        }
    }

    /// Build a `MovementAbates` recipe on `axis` under `family`.
    pub fn abates(family: MutatorId, axis: u16, max_count: u32, max_sum_bucket: u8) -> ProbeRecipe {
        ProbeRecipe {
            family: family.id(),
            axis,
            expectation: Expectation::MovementAbates,
            min_count: max_count,
            min_run: 0,
            min_sum_bucket: max_sum_bucket,
        }
    }

    /// Encode the recipe (canonical, bounded).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(1 + 2 + 2 + 1 + 4 + 1 + 1);
        out.push(PROBE_RECIPE_VERSION);
        out.extend_from_slice(&self.family.to_le_bytes());
        out.extend_from_slice(&self.axis.to_le_bytes());
        out.push(self.expectation.code());
        out.extend_from_slice(&self.min_count.to_le_bytes());
        out.push(self.min_run);
        out.push(self.min_sum_bucket);
        Ok(out)
    }

    /// Decode a recipe payload.
    pub fn decode(bytes: &[u8]) -> Result<ProbeRecipe> {
        let mut pos = 0usize;
        let mut take = |n: usize| -> Result<&[u8]> {
            let end = pos.checked_add(n).ok_or(Error::Overflow)?;
            if end > bytes.len() {
                return Err(Error::Encoding("probe-recipe truncated"));
            }
            let out = &bytes[pos..end];
            pos = end;
            Ok(out)
        };
        let version = take(1)?[0];
        if version != PROBE_RECIPE_VERSION {
            return Err(Error::UnsupportedVersion {
                family: "probe-recipe",
                version: version as u32,
            });
        }
        let family = u16::from_le_bytes(take(2)?.try_into().unwrap());
        let axis = u16::from_le_bytes(take(2)?.try_into().unwrap());
        let expectation = Expectation::from_byte(take(1)?[0])
            .ok_or(Error::Encoding("unknown probe expectation"))?;
        let min_count = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let min_run = take(1)?[0];
        let min_sum_bucket = take(1)?[0];
        if pos != bytes.len() {
            return Err(Error::Encoding("probe-recipe has trailing bytes"));
        }
        Ok(ProbeRecipe {
            family,
            axis,
            expectation,
            min_count,
            min_run,
            min_sum_bucket,
        })
    }
}

/// Evaluate one probe against the batch summary of its order.
///
/// Returns:
///
/// * `Support` — the family expectation held;
/// * `Contradict` — the expectation was refuted (the axis stopped entirely,
///   or the movement law is the opposite of the expectation);
/// * `Ambiguous` — the evidence is weak/conflicting.
pub fn evaluate(recipe: &ProbeRecipe, summary: &SignalBatchSummary) -> ProbeOutcome {
    let axis = recipe.axis as usize;
    if axis >= crate::target_runtime::signals::MAX_SIGNALS {
        return ProbeOutcome::Ambiguous;
    }
    let moved = summary.count[axis];
    let run = summary.max_run[axis];
    let sum_abs = summary.sum_abs_delta[axis];
    let bucket = magnitude_bucket(sum_abs);
    match recipe.expectation {
        Expectation::MovementPersists => {
            if moved >= recipe.min_count && run >= recipe.min_run && bucket >= recipe.min_sum_bucket
            {
                ProbeOutcome::Support
            } else if moved == 0 || bucket < recipe.min_sum_bucket.saturating_sub(1) {
                // The axis essentially stopped: the strongest contradiction.
                ProbeOutcome::Contradict
            } else {
                ProbeOutcome::Ambiguous
            }
        }
        Expectation::MovementAbates => {
            if moved <= recipe.min_count && bucket <= recipe.min_sum_bucket {
                ProbeOutcome::Support
            } else if moved > recipe.min_count && bucket > recipe.min_sum_bucket {
                ProbeOutcome::Contradict
            } else {
                ProbeOutcome::Ambiguous
            }
        }
    }
}

/// One durable probe-evaluation record (stored inside precedent revisions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeEvidence {
    /// The outcome.
    pub outcome: ProbeOutcome,
    /// The campaign admission sequence at evaluation time (deterministic
    /// ordering key).
    pub seq: u64,
    /// The axis the expectation was read on.
    pub axis: u16,
    /// Executions that moved the axis in the probe batch.
    pub moved: u32,
    /// Longest same-direction run in the probe batch.
    pub run: u8,
    /// Summed-magnitude bucket of the probe batch.
    pub sum_bucket: u8,
    /// The probe batch's execution count.
    pub batch_execs: u64,
}

/// Encode one evidence record.
pub fn encode_evidence(ev: &ProbeEvidence) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 1 + 8 + 2 + 4 + 1 + 1 + 8);
    out.push(PROBE_EVIDENCE_VERSION);
    out.push(ev.outcome.code());
    out.extend_from_slice(&ev.seq.to_le_bytes());
    out.extend_from_slice(&ev.axis.to_le_bytes());
    out.extend_from_slice(&ev.moved.to_le_bytes());
    out.push(ev.run);
    out.push(ev.sum_bucket);
    out.extend_from_slice(&ev.batch_execs.to_le_bytes());
    Ok(out)
}

/// Decode one evidence record.
pub fn decode_evidence(bytes: &[u8]) -> Result<ProbeEvidence> {
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > bytes.len() {
            return Err(Error::Encoding("probe-evidence truncated"));
        }
        let out = &bytes[pos..end];
        pos = end;
        Ok(out)
    };
    let version = take(1)?[0];
    if version != PROBE_EVIDENCE_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "probe-evidence",
            version: version as u32,
        });
    }
    let outcome =
        ProbeOutcome::from_byte(take(1)?[0]).ok_or(Error::Encoding("unknown probe outcome"))?;
    let seq = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let axis = u16::from_le_bytes(take(2)?.try_into().unwrap());
    let moved = u32::from_le_bytes(take(4)?.try_into().unwrap());
    let run = take(1)?[0];
    let sum_bucket = take(1)?[0];
    let batch_execs = u64::from_le_bytes(take(8)?.try_into().unwrap());
    if pos != bytes.len() {
        return Err(Error::Encoding("probe-evidence has trailing bytes"));
    }
    Ok(ProbeEvidence {
        outcome,
        seq,
        axis,
        moved,
        run,
        sum_bucket,
        batch_execs,
    })
}

/// Classify how strongly a contradiction refutes the family expectation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContradictionWeight {
    /// The axis never moved: the family expectation was directly refuted.
    Direct = 1,
    /// Activity was weak but non-zero: partial refutation.
    Partial = 2,
}

impl ContradictionWeight {
    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            ContradictionWeight::Direct => "direct",
            ContradictionWeight::Partial => "partial",
        }
    }
}

/// Classify how strongly a contradiction refutes the family expectation.
pub fn contradiction_weight(
    recipe: &ProbeRecipe,
    summary: &SignalBatchSummary,
) -> ContradictionWeight {
    let axis = recipe.axis as usize;
    if axis < crate::target_runtime::signals::MAX_SIGNALS && summary.count[axis] == 0 {
        ContradictionWeight::Direct
    } else {
        ContradictionWeight::Partial
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target_runtime::signals::SignalId;

    fn summary_with(axis: usize, count: u32, run: u8, sum_abs: u64) -> SignalBatchSummary {
        let mut s = SignalBatchSummary::new();
        s.touched |= 1u64 << axis;
        s.count[axis] = count;
        s.max_run[axis] = run;
        s.sum_abs_delta[axis] = sum_abs;
        s.min[axis] = 0;
        s.max[axis] = sum_abs.max(1);
        s
    }

    fn id(axis: usize) -> SignalId {
        SignalId(axis as u16)
    }

    #[test]
    fn recipe_encoding_roundtrip() {
        let r = ProbeRecipe::persists(MutatorId::ByteInsert, 3, 20, 4, 3);
        assert_eq!(ProbeRecipe::decode(&r.encode().unwrap()).unwrap(), r);
        let r2 = ProbeRecipe::abates(MutatorId::DictionaryInsert, 0, 5, 2);
        assert_eq!(ProbeRecipe::decode(&r2.encode().unwrap()).unwrap(), r2);
        let mut bad = r.encode().unwrap();
        bad[0] = 99;
        assert!(ProbeRecipe::decode(&bad).is_err());
        assert!(ProbeRecipe::decode(&r.encode().unwrap()[..4]).is_err());
    }

    #[test]
    fn persists_expectation_support_and_contradict() {
        let r = ProbeRecipe::persists(MutatorId::ByteInsert, 0, 20, 4, 3);
        // 400 executions moved axis 0, run 12, sum 4096 (bucket 13).
        let s = summary_with(0, 400, 12, 4096);
        assert_eq!(evaluate(&r, &s), ProbeOutcome::Support);
        // The axis stopped entirely.
        let s0 = summary_with(0, 0, 0, 0);
        assert_eq!(evaluate(&r, &s0), ProbeOutcome::Contradict);
        // Weak but non-zero: ambiguous.
        let sw = summary_with(0, 3, 1, 4);
        assert_eq!(evaluate(&r, &sw), ProbeOutcome::Ambiguous);
    }

    #[test]
    fn abates_expectation_support_and_contradict() {
        let r = ProbeRecipe::abates(MutatorId::ByteInsert, 0, 5, 2);
        let s = summary_with(0, 2, 1, 2);
        assert_eq!(evaluate(&r, &s), ProbeOutcome::Support);
        let s2 = summary_with(0, 200, 30, 1 << 20);
        assert_eq!(evaluate(&r, &s2), ProbeOutcome::Contradict);
    }

    #[test]
    fn out_of_range_axis_is_ambiguous() {
        let r = ProbeRecipe::persists(MutatorId::ByteInsert, u16::MAX, 1, 1, 1);
        assert_eq!(
            evaluate(&r, &summary_with(0, 5, 5, 5)),
            ProbeOutcome::Ambiguous
        );
    }

    #[test]
    fn evidence_record_roundtrip() {
        let e = ProbeEvidence {
            outcome: ProbeOutcome::Contradict,
            seq: 42,
            axis: 1,
            moved: 0,
            run: 0,
            sum_bucket: 0,
            batch_execs: 500,
        };
        let enc = encode_evidence(&e).unwrap();
        assert_eq!(decode_evidence(&enc).unwrap(), e);
        assert!(decode_evidence(&enc[..enc.len() - 1]).is_err());
    }

    #[test]
    fn outcome_codes_are_stable() {
        assert_eq!(ProbeOutcome::Support.code(), 1);
        assert_eq!(ProbeOutcome::Contradict.code(), 2);
        assert_eq!(ProbeOutcome::Ambiguous.code(), 3);
        assert_eq!(Expectation::MovementPersists.code(), 1);
        assert_eq!(Expectation::MovementAbates.code(), 2);
        assert_eq!(id(0).id(), 0);
    }

    #[test]
    fn contradiction_weight_detects_direct_refutation() {
        let r = ProbeRecipe::persists(MutatorId::ByteInsert, 2, 20, 4, 3);
        let stopped = summary_with(2, 0, 0, 0);
        assert_eq!(
            contradiction_weight(&r, &stopped),
            ContradictionWeight::Direct
        );
        let weak = summary_with(2, 2, 1, 2);
        assert_eq!(
            contradiction_weight(&r, &weak),
            ContradictionWeight::Partial
        );
    }
}
