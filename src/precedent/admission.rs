//! Precedent admission (master prompt §17; Phase 3).
//!
//! Precedents are admitted ONLY from real, durable terminal observations of
//! real lineages (I9: no precedent without provenance). The coordinator calls
//! [`create_from_terminal`] when a lineage that exhibited a structured
//! precursor shape reaches a terminal event (crash finding, timeout finding,
//! boundary witness, escalated episode). The function is a pure constructor:
//! it derives the prefix profile from the supplied precursor signature, the
//! continuation from the terminal event, and a falsifiable probe relationship
//! from the lineage's own mutator family and leading axis — so every
//! admitted precedent immediately carries the ≥1 falsifiable relationship
//! required before it may guide scheduling.
//!
//! Re-admission of the same (root, mutator, profile) family is not a new
//! precedent: it is a terminal *confirmation* revision of the existing
//! precedent (see [`crate::precedent::model`]).
//!
//! This module is coordinator-gated.

use crate::dsfb::morphology::MorphologySignature;
use crate::id::ContentId;
use crate::mutation::MutatorId;
use crate::precedent::model::{ConfuserKind, Continuation, Precedent, PrefixProfile, TerminalKind};
use crate::precedent::probe::ProbeRecipe;

/// How far before the terminal event the coordinator looks back for the
/// precursor signature (generations). A crash that immediately follows the
/// first structured edge has no usable precursor; the coordinator refuses
/// admission in that case.
pub const PRECURSOR_LOOKBACK_MIN: u32 = 3;

/// Derive the probe recipe for a new precedent from the lineage's own facts.
///
/// The falsifiable law: continuing the same mutator family on the frontier
/// must keep the leading axis moving as persistently as it did historically
/// (the family expectation); the declared confuser (when known) predicts the
/// opposite law and is probed by a DISCRIMINATE order.
pub fn derive_recipe(
    mutator: MutatorId,
    leading_axis: u16,
    probe_count: u32,
    min_run: u8,
    min_bucket: u8,
) -> ProbeRecipe {
    ProbeRecipe::persists(mutator, leading_axis, probe_count, min_run, min_bucket)
}

/// Create a candidate precedent from a real terminal observation.
///
/// `precursor` is the lineage signature captured `precursor_depth`
/// generations before the terminal event (the coordinator keeps a bounded
/// history); `leading_axis`/`leading_reason` describe the trajectory's
/// dominant axis at the last structured edge before the terminal event;
/// `terminal_depth` is the lineage generation at the terminal event;
/// `seq` is the current admission sequence (provenance ordering).
#[allow(clippy::too_many_arguments)]
pub fn create_from_terminal(
    lineage_root: ContentId,
    mutator: MutatorId,
    precursor: &MorphologySignature,
    precursor_depth: u32,
    terminal_kind: TerminalKind,
    continuation_class: u8,
    leading_axis: u16,
    leading_reason: u8,
    terminal_depth: u32,
    terminal_ref: Option<ContentId>,
    confuser: ConfuserKind,
    recipe: ProbeRecipe,
    seq: u64,
) -> Option<Precedent> {
    if precursor.is_trivial() {
        // No structural precursor: nothing to remember as a *shape*.
        return None;
    }
    if terminal_depth < precursor_depth.saturating_add(PRECURSOR_LOOKBACK_MIN) {
        // The terminal event followed the first structured edge too quickly:
        // there is no meaningful lead to generalize.
        return None;
    }
    let profile = PrefixProfile::from_signature(precursor, precursor_depth);
    Some(Precedent {
        lineage_root,
        mutator: mutator.id(),
        profile,
        role_mask: 0,
        continuation: Continuation {
            kind: terminal_kind,
            class: continuation_class,
            axis: leading_axis,
            depth: terminal_depth,
            reason: leading_reason,
            terminal_ref,
        },
        confuser,
        created_seq: seq,
        updated_seq: seq,
        status: crate::precedent::model::PrecedentStatus::Candidate,
        prev_revision: None,
        supports: 0,
        contradictions: 0,
        ambiguous_probes: 0,
        recipe,
        evidence: Vec::new(),
    })
}

/// Choose the precursor signature from a bounded lineage history (oldest
/// first). The precursor is the divergence ONSET: the earliest structured
/// signature (at least generation 2, so the very first movement of a
/// lineage is not treated as a shape) whose shape demonstrably persisted at
/// least one further generation (same structural identity), or the last
/// structured signature when no such pair exists. `None` when no usable
/// precursor exists (too short / trivial lineage).
pub fn choose_precursor(
    history: &[(u32, MorphologySignature)],
    terminal_depth: u32,
) -> Option<(MorphologySignature, u32)> {
    if history.is_empty() {
        return None;
    }
    let cutoff = terminal_depth.saturating_sub(PRECURSOR_LOOKBACK_MIN);
    let last = history.last().map(|(d, _)| *d).unwrap_or(0);
    // Pass 1: an early shape that persisted into the following generation.
    for (i, (depth, sig)) in history.iter().enumerate() {
        if *depth < 2 || *depth > cutoff || sig.is_trivial() {
            continue;
        }
        let persisted = history
            .get(i + 1)
            .map(|(d2, sig2)| {
                *d2 <= cutoff && sig2.structural_identity() == sig.structural_identity()
            })
            .unwrap_or(false);
        if persisted || *depth == last {
            return Some((sig.clone(), *depth));
        }
    }
    // Pass 2: fall back to the earliest structured signature in range.
    for (depth, sig) in history {
        if *depth >= 2 && *depth <= cutoff && !sig.is_trivial() {
            return Some((sig.clone(), *depth));
        }
    }
    None
}

/// Whether an existing precedent should absorb a repeated terminal event as
/// a confirmation revision (rather than admitting a duplicate).
pub fn same_family(existing: &Precedent, root: &ContentId, mutator: u16, profile_id: u64) -> bool {
    existing.lineage_root == *root
        && existing.mutator == mutator
        && existing.profile.profile_identity() == profile_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsfb::morphology::LineageAccumulator;
    use crate::observe::residual::MutationResidual;
    use crate::target_runtime::signals::{SignalId, SignalVector};

    fn vec_with(id: u16, v: u64) -> SignalVector {
        let mut s = SignalVector::new();
        s.observe(SignalId(id), v).unwrap();
        s
    }

    fn drifting_history(steps: u32) -> Vec<(u32, MorphologySignature)> {
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&vec_with(0, 0));
        let mut parent = vec_with(0, 0);
        let mut out = Vec::new();
        acc.push(&MutationResidual::of(&parent, &parent), 0);
        let mut sig;
        for d in 1..=steps {
            let child = vec_with(0, d as u64);
            sig = acc.push(&MutationResidual::of(&child, &parent), d);
            out.push((d, sig.clone()));
            parent = child;
        }
        out
    }

    #[test]
    fn creation_requires_structured_precursor_and_lead() {
        let history = drifting_history(24);
        let mutator = MutatorId::DictionaryInsert;
        let recipe = derive_recipe(mutator, 0, 20, 4, 3);
        // Terminal at depth 24: precursor at depth 6 qualifies.
        let created = create_from_terminal(
            ContentId::new(b"root"),
            mutator,
            &history[5].1,
            6,
            TerminalKind::CrashFinding,
            0,
            0,
            5,
            24,
            Some(ContentId::new(b"finding")),
            ConfuserKind::None,
            recipe,
            7,
        );
        assert!(created.is_some());
        let p = created.unwrap();
        assert_eq!(p.profile.depth, 6);
        assert_eq!(
            p.status,
            crate::precedent::model::PrecedentStatus::Candidate
        );
        assert_eq!(p.recipe.axis, 0);
        assert_eq!(p.recipe.family, mutator.id());

        // A trivial precursor refuses creation.
        let trivial = MorphologySignature::trivial(0);
        let none = create_from_terminal(
            ContentId::new(b"root"),
            mutator,
            &trivial,
            2,
            TerminalKind::CrashFinding,
            0,
            0,
            0,
            10,
            Some(ContentId::new(b"finding")),
            ConfuserKind::None,
            recipe,
            7,
        );
        assert!(none.is_none());

        // Terminal too close to the precursor refuses creation (no lead).
        let too_close = create_from_terminal(
            ContentId::new(b"root"),
            mutator,
            &history[8].1,
            9,
            TerminalKind::CrashFinding,
            0,
            0,
            5,
            10,
            Some(ContentId::new(b"finding")),
            ConfuserKind::None,
            recipe,
            7,
        );
        assert!(too_close.is_none());
    }

    #[test]
    fn precursor_choice_takes_early_persisting_shape() {
        let history = drifting_history(24);
        let (_, depth) = choose_precursor(&history, 24).unwrap();
        // The onset: depth 2 (skips the very first movement), whose shape
        // persisted into generation 3.
        assert_eq!(depth, 2);
        // A short lineage has no usable precursor.
        assert!(choose_precursor(&drifting_history(3), 4).is_none());
    }

    #[test]
    fn duplicate_family_is_detected() {
        let history = drifting_history(24);
        let recipe = derive_recipe(MutatorId::DictionaryInsert, 0, 20, 4, 3);
        let p = create_from_terminal(
            ContentId::new(b"root"),
            MutatorId::DictionaryInsert,
            &history[5].1,
            6,
            TerminalKind::CrashFinding,
            0,
            0,
            5,
            24,
            Some(ContentId::new(b"finding")),
            ConfuserKind::None,
            recipe,
            7,
        )
        .unwrap();
        assert!(same_family(
            &p,
            &ContentId::new(b"root"),
            MutatorId::DictionaryInsert.id(),
            p.profile.profile_identity()
        ));
        assert!(!same_family(
            &p,
            &ContentId::new(b"other"),
            MutatorId::DictionaryInsert.id(),
            p.profile.profile_identity()
        ));
    }
}
