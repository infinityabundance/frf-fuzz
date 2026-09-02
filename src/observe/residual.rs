//! Residual families (master prompt §12).
//!
//! Residuals are *controlled finite structural differences* between two
//! observations — never called derivatives, never flattened into one score.
//! Each family is a distinct type:
//!
//! * [`MutationResidual`] — R_M(child, parent): which behavioral dimensions
//!   one mutation changed. Computed from the recorded observations of a
//!   corpus edge (Phase 2).
//! * [`TemporalResidual`] — R_T(k): observation(k) vs the declared/local
//!   nominal regime of its lineage. Feeds the `RegimeObserver` (Phase 2).
//! * *Authority residual* R_A(candidate, authority) — the FRF bridge's
//!   differential (Phase 4). FRF itself owns the authority/candidate
//!   semantics and residual dispositions (I4); frf-fuzz never recreates
//!   them. The bridge retains FRF evidence ids verbatim instead.
//! * [`RevisionResidual`] — R_V(Vn, Vn-1, tape): the typed behavioral
//!   difference between two artifact observations of the SAME tape
//!   candidate, computed by revision tape replay across Gemel revision
//!   states (Phase 4).

use crate::target_runtime::signals::{ResidualSketch, SignalVector, MAX_SIGNALS};

/// R_M: child observation minus parent observation, per signal.
///
/// Deltas are exact saturating `i64` differences (checked arithmetic: a
/// wrapped u64 subtraction would produce a wrong sign and corrupt every
/// downstream direction decision). The bucketized sketch is retained for
/// cheap inspection; the exact deltas are the semantic content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationResidual {
    /// The child's recorded observation.
    pub child: SignalVector,
    /// The parent's recorded observation.
    pub parent: SignalVector,
    /// Exact saturating per-signal deltas (child - parent).
    pub deltas: [i64; MAX_SIGNALS],
    /// Child-touched bitmask.
    pub touched: u64,
    /// Child-touched-but-parent-untouched bitmask.
    pub touched_new: u64,
    /// Parent-touched-but-child-untouched bitmask.
    pub touched_lost: u64,
    /// The bucketized sketch (cheap form of the same edge).
    pub sketch: ResidualSketch,
}

impl MutationResidual {
    /// Compute the mutation residual of one edge.
    pub fn of(child: &SignalVector, parent: &SignalVector) -> MutationResidual {
        let deltas = crate::target_runtime::signals::deltas(parent, child);
        MutationResidual {
            child: child.clone(),
            parent: parent.clone(),
            deltas,
            touched: child.touched_mask(),
            touched_new: child.touched_mask() & !parent.touched_mask(),
            touched_lost: parent.touched_mask() & !child.touched_mask(),
            sketch: ResidualSketch::of(parent, child),
        }
    }

    /// Bitmask of signals with any nonzero delta (the moved axes).
    pub fn moved(&self) -> u64 {
        let mut m = 0u64;
        for i in 0..MAX_SIGNALS {
            if self.deltas[i] != 0 {
                m |= 1u64 << i;
            }
        }
        m
    }

    /// The dominant axis: the moved signal with the largest |delta|.
    pub fn dominant_axis(&self) -> Option<u16> {
        let mut best: Option<(u16, u64)> = None;
        for i in 0..MAX_SIGNALS {
            if self.deltas[i] == 0 {
                continue;
            }
            let mag = self.deltas[i].unsigned_abs();
            if best.map(|(_, b)| mag > b).unwrap_or(true) {
                best = Some((i as u16, mag));
            }
        }
        best.map(|(axis, _)| axis)
    }

    /// Exact delta of one signal.
    pub fn delta(&self, i: usize) -> i64 {
        self.deltas[i]
    }
}

/// R_T: one observation against the declared/local nominal of its lineage.
///
/// `nominal` is the lineage baseline (the root observation); `deviation`
/// and `instantaneous` are exact saturating differences. This is what the
/// `RegimeObserver` consumes (dsfb/regime.rs); its semantics are documented
/// independently of any database telemetry grammar (invariant I7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporalResidual {
    /// The current observation.
    pub value: u64,
    /// The declared/local nominal (lineage baseline).
    pub nominal: u64,
    /// value - nominal (exact, saturating).
    pub deviation: i64,
    /// value - previous observation (exact, saturating; 0 for the first).
    pub instantaneous: i64,
}

impl TemporalResidual {
    /// Compute the temporal residual of one observation against a nominal
    /// and the previous value.
    pub fn of(value: u64, nominal: u64, previous: Option<u64>) -> TemporalResidual {
        let dev =
            (value as i128 - nominal as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64;
        let inst = match previous {
            Some(p) => (value as i128 - p as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64,
            None => 0,
        };
        TemporalResidual {
            value,
            nominal,
            deviation: dev,
            instantaneous: inst,
        }
    }
}

/// R_V: observation(Vn, tape) minus observation(Vn-1, tape).
///
/// The revision residual is the *same-tape* behavioral difference across two
/// software revisions (Gemel states): same input bytes, same mutation
/// coordinate, same observation surface — the only varying dimension is the
/// artifact that executed. A nonzero delta is a program-side perturbation
/// between the two states (a branch of development is a natural controlled
/// experiment, docs/DESIGN-GEMEL-BRIDGE.md).
///
/// The shape mirrors [`MutationResidual`] — exact saturating per-signal
/// deltas (`later` minus `earlier`) plus the bucketized sketch — but it is
/// a SEPARATELY TYPED family: a revision difference is never flattened into
/// a mutation difference or vice versa (master prompt §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionResidual {
    /// The later revision's recorded observation.
    pub later: SignalVector,
    /// The earlier revision's recorded observation.
    pub earlier: SignalVector,
    /// Exact saturating per-signal deltas (later - earlier).
    pub deltas: [i64; MAX_SIGNALS],
    /// Later-touched bitmask.
    pub touched: u64,
    /// Later-touched-but-earlier-untouched bitmask.
    pub touched_new: u64,
    /// Earlier-touched-but-later-untouched bitmask.
    pub touched_lost: u64,
    /// The bucketized sketch (cheap form of the same difference).
    pub sketch: ResidualSketch,
}

impl RevisionResidual {
    /// Compute the revision residual of one same-tape observation pair
    /// (`later` revision vs `earlier` revision). The scalar semantics are
    /// identical to the mutation residual's; only the semantic axis differs.
    pub fn of(later: &SignalVector, earlier: &SignalVector) -> RevisionResidual {
        let deltas = crate::target_runtime::signals::deltas(earlier, later);
        RevisionResidual {
            later: later.clone(),
            earlier: earlier.clone(),
            deltas,
            touched: later.touched_mask(),
            touched_new: later.touched_mask() & !earlier.touched_mask(),
            touched_lost: earlier.touched_mask() & !later.touched_mask(),
            sketch: ResidualSketch::of(earlier, later),
        }
    }

    /// Bitmask of signals with any nonzero delta (the perturbed axes).
    pub fn moved(&self) -> u64 {
        let mut m = 0u64;
        for i in 0..MAX_SIGNALS {
            if self.deltas[i] != 0 {
                m |= 1u64 << i;
            }
        }
        m
    }

    /// Exact delta of one signal.
    pub fn delta(&self, i: usize) -> i64 {
        self.deltas[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target_runtime::signals::SignalId;

    #[test]
    fn mutation_residual_computes_exact_deltas() {
        let mut parent = SignalVector::new();
        parent.observe(SignalId(0), 100).unwrap();
        parent.observe(SignalId(1), 5).unwrap();
        let mut child = SignalVector::new();
        child.observe(SignalId(0), 90).unwrap();
        child.observe(SignalId(2), 7).unwrap();
        let r = MutationResidual::of(&child, &parent);
        assert_eq!(r.delta(0), -10);
        assert_eq!(r.delta(1), -5); // parent touched, child did not
        assert_eq!(r.delta(2), 7); // introduced
        assert_eq!(r.touched_new, 1 << 2);
        assert_eq!(r.touched_lost, 1 << 1);
        assert_eq!(r.moved(), 0b111);
        // Dominant axis: the largest |delta| is signal 0 (|-10|).
        assert_eq!(r.dominant_axis(), Some(0));
    }

    #[test]
    fn mutation_residual_wrapping_does_not_invert_sign() {
        // u64 wraparound (u64::MAX -> 0) must not produce a positive delta.
        let mut parent = SignalVector::new();
        parent.observe(SignalId(0), u64::MAX).unwrap();
        let mut child = SignalVector::new();
        child.observe(SignalId(0), 0).unwrap();
        let r = MutationResidual::of(&child, &parent);
        assert_eq!(r.delta(0), i64::MIN); // saturated, negative
    }

    #[test]
    fn temporal_residual_first_sample_has_zero_instantaneous() {
        let r = TemporalResidual::of(10, 0, None);
        assert_eq!(r.deviation, 10);
        assert_eq!(r.instantaneous, 0);
        let r2 = TemporalResidual::of(12, 0, Some(10));
        assert_eq!(r2.instantaneous, 2);
        let r3 = TemporalResidual::of(5, 10, Some(12));
        assert_eq!(r3.deviation, -5);
        assert_eq!(r3.instantaneous, -7);
    }

    #[test]
    fn revision_residual_mirrors_mutation_semantics() {
        let mut earlier = SignalVector::new();
        earlier.observe(SignalId(0), 100).unwrap();
        earlier.observe(SignalId(1), 5).unwrap();
        let mut later = SignalVector::new();
        later.observe(SignalId(0), 90).unwrap();
        later.observe(SignalId(2), 7).unwrap();
        let r = RevisionResidual::of(&later, &earlier);
        // Same arithmetic as MutationResidual::of(child, parent): the ONLY
        // difference is the semantic axis (revision vs mutation).
        let m = MutationResidual::of(&later, &earlier);
        assert_eq!(r.deltas, m.deltas);
        assert_eq!(r.delta(0), -10);
        assert_eq!(r.delta(1), -5);
        assert_eq!(r.delta(2), 7);
        assert_eq!(r.touched_new, 1 << 2);
        assert_eq!(r.touched_lost, 1 << 1);
        assert_eq!(r.moved(), 0b111);
        // Identical same-tape observations produce a zero residual: no
        // program-side perturbation between the two revisions.
        let zero = RevisionResidual::of(&earlier, &earlier);
        assert_eq!(zero.moved(), 0);
        assert!(zero.deltas.iter().all(|d| *d == 0));
    }

    #[test]
    fn revision_residual_never_inverts_sign_on_wraparound() {
        let mut earlier = SignalVector::new();
        earlier.observe(SignalId(0), u64::MAX).unwrap();
        let mut later = SignalVector::new();
        later.observe(SignalId(0), 0).unwrap();
        let r = RevisionResidual::of(&later, &earlier);
        assert_eq!(r.delta(0), i64::MIN); // saturated, negative
    }
}
