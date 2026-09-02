//! Deterministic precedent matching (master prompt §17; Phase 3).
//!
//! Matching is shape-based, not fingerprint-based: a live lineage signature
//! matches a precedent when the precedent's *prefix profile* (captured before
//! its terminal event) is subsumed by the live shape — same axes, same
//! directions on those axes, same comparison-convergence and state-change
//! classes — the lineage mutator family agrees, and the live lineage is
//! still inside the *lead window* (past the profile depth, not yet at the
//! terminal depth). This is the deterministic recognition of a historically
//! observed structural prefix (master prompt §39): never a probability, never
//! causal attribution — only "this shape family was observed before, and its
//! historical continuations include <terminal>".
//!
//! Matching deliberately permits a DIFFERENT root than the precedent's origin
//! lineage: the same structural shape on another seed is the interesting
//! generalization. The mutator family must agree (the shape family).
//!
//! This module is coordinator-gated.

use crate::dsfb::morphology::MorphologySignature;
use crate::precedent::model::{Precedent, PrecedentStatus};

/// The maximum number of generations past the profile depth at which a live
/// signature still counts as a precursor match. Beyond this the trajectory
/// has moved too far past the historical prefix to be a *lead*.
pub const MATCH_LEAD_MAX: u32 = 16;

/// Whether a live signature at `depth` under `mutator` matches a precedent.
pub fn matches(p: &Precedent, sig: &MorphologySignature, depth: u32, mutator: u16) -> bool {
    if !p.schedulable() {
        return false;
    }
    if p.mutator != mutator {
        return false;
    }
    // The live lineage must be past the profile's own depth (the shape has
    // had room to evolve) but not beyond the lead window.
    if depth < p.profile.depth.saturating_add(1) {
        return false;
    }
    if depth > p.profile.depth.saturating_add(MATCH_LEAD_MAX) {
        return false;
    }
    p.profile.subsumed_by(sig)
}

/// All current precedents matching a live signature, deterministically
/// ordered: most axes in the profile first (a richer shape match is more
/// specific), then by profile identity (ties).
pub fn matching_precedents<'a>(
    current: impl Iterator<Item = &'a Precedent>,
    sig: &MorphologySignature,
    depth: u32,
    mutator: u16,
) -> Vec<&'a Precedent> {
    let mut out: Vec<&Precedent> = current
        .filter(|p| matches(p, sig, depth, mutator))
        .collect();
    out.sort_by(|a, b| {
        let ac = a.profile.axis_mask.count_ones();
        let bc = b.profile.axis_mask.count_ones();
        bc.cmp(&ac).then_with(|| {
            a.profile
                .profile_identity()
                .cmp(&b.profile.profile_identity())
        })
    });
    out
}

/// Whether a precedent may still be scheduled against this live lineage:
/// the lineage has no in-flight probe for the precedent and the precedent is
/// schedulable. The caller keeps the in-flight set.
pub fn probe_allowed(p: &Precedent, status_ok: bool, in_flight: bool) -> bool {
    p.schedulable() && status_ok && !in_flight
}

/// Whether a precedent whose terminal kind is a crash/timeout finding is
/// "confirmed again" by another finding on a matched lineage (used by the
/// coordinator's terminal handling).
pub fn terminal_confirms(p: &Precedent) -> bool {
    p.status == PrecedentStatus::Candidate || p.status == PrecedentStatus::Confirmed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsfb::morphology::LineageAccumulator;
    use crate::observe::residual::MutationResidual;
    use crate::precedent::model::{ConfuserKind, Continuation, PrefixProfile, TerminalKind};
    use crate::precedent::probe::ProbeRecipe;
    use crate::target_runtime::signals::{SignalId, SignalVector};

    fn vec_with(id: u16, v: u64) -> SignalVector {
        let mut s = SignalVector::new();
        s.observe(SignalId(id), v).unwrap();
        s
    }

    fn sig_at(steps: u32, baseline: u64, step: u64) -> MorphologySignature {
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&vec_with(0, baseline));
        let mut parent = vec_with(0, baseline);
        let mut sig = acc.push(&MutationResidual::of(&parent, &parent), 0);
        for d in 1..=steps {
            let child = vec_with(0, baseline + d as u64 * step);
            sig = acc.push(&MutationResidual::of(&child, &parent), d);
            parent = child;
        }
        sig
    }

    fn precedent_with_profile(depth: u32) -> Precedent {
        let sig = sig_at(depth, 0, 1);
        Precedent {
            lineage_root: crate::id::ContentId::new(b"rootA"),
            mutator: 7,
            profile: PrefixProfile::from_signature(&sig, depth),
            role_mask: 1,
            continuation: Continuation {
                kind: TerminalKind::CrashFinding,
                class: 0,
                axis: 0,
                depth: 33,
                reason: 5,
                terminal_ref: Some(crate::id::ContentId::new(b"finding")),
            },
            confuser: ConfuserKind::None,
            created_seq: 0,
            updated_seq: 0,
            status: PrecedentStatus::Candidate,
            prev_revision: None,
            supports: 0,
            contradictions: 0,
            ambiguous_probes: 0,
            recipe: ProbeRecipe::persists(crate::mutation::MutatorId::ByteInsert, 0, 20, 4, 3),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn match_requires_family_and_shape() {
        let p = precedent_with_profile(6);
        // Same shape deeper under the same family: matches.
        let live = sig_at(10, 0, 1);
        assert!(matches(&p, &live, 10, 7));
        // Wrong mutator family: no.
        assert!(!matches(&p, &live, 10, 8));
        // Same shape at the profile's own depth: not past the prefix yet.
        assert!(!matches(&p, &sig_at(6, 0, 1), 6, 7));
        // Beyond the lead window: no.
        assert!(!matches(&p, &sig_at(30, 0, 1), 30, 7));
        // A reversed-direction lineage (values decreasing from a high
        // baseline) must not subsume an upward profile.
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&vec_with(0, 40));
        let mut parent = vec_with(0, 40);
        let mut rev = acc.push(&MutationResidual::of(&parent, &parent), 0);
        for d in 1..=10u32 {
            let child = vec_with(0, 40u64.saturating_sub(d as u64));
            rev = acc.push(&MutationResidual::of(&child, &parent), d);
            parent = child;
        }
        assert!(!matches(&p, &rev, 10, 7));
    }

    #[test]
    fn contradicted_precedents_do_not_match() {
        let mut p = precedent_with_profile(6);
        p.status = PrecedentStatus::Contradicted;
        let live = sig_at(10, 0, 1);
        assert!(!matches(&p, &live, 10, 7));
    }

    #[test]
    fn matching_across_roots_is_allowed() {
        // The same shape on a DIFFERENT root lineage matches: this is the
        // cross-seed generalization the bank exists for.
        let p = precedent_with_profile(6);
        let live = sig_at(9, 0, 1);
        assert!(matches(&p, &live, 9, 7));
    }

    #[test]
    fn selection_is_deterministic_and_specificity_ordered() {
        let narrow = precedent_with_profile(6);
        let mut wide = narrow.clone();
        // A second axis in the profile makes it more specific.
        let mut wide_sig = sig_at(6, 0, 1);
        wide_sig.axis_mask |= 1 << 3;
        wide_sig.dir_bits |= (1u128) << (2 * 3);
        wide.profile = PrefixProfile::from_signature(&wide_sig, 6);
        wide.lineage_root = crate::id::ContentId::new(b"rootB");
        // The live lineage must subsume BOTH profiles: axes 0 and 3 moving
        // together under the same family.
        let mut acc = LineageAccumulator::new();
        let mut baseline = vec_with(0, 0);
        baseline.observe(SignalId(3), 0).unwrap();
        acc.init_baseline(&baseline);
        let mut parent = baseline;
        let mut live = acc.push(&MutationResidual::of(&parent, &parent), 0);
        for d in 1..=10u32 {
            let mut child = vec_with(0, d as u64);
            child.observe(SignalId(3), d as u64).unwrap();
            live = acc.push(&MutationResidual::of(&child, &parent), d);
            parent = child;
        }
        let all = [narrow.clone(), wide.clone()];
        // Ensure distinct profile identities (different axis masks).
        assert_ne!(
            narrow.profile.profile_identity(),
            wide.profile.profile_identity()
        );
        let picked = matching_precedents(all.iter(), &live, 10, 7);
        assert_eq!(picked.len(), 2);
        assert_eq!(picked[0].profile.axis_mask, wide.profile.axis_mask);
        assert_eq!(picked[1].profile.axis_mask, narrow.profile.axis_mask);
    }
}
