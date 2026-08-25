//! Morphology signatures (master prompt §16) and the lineage accumulator.
//!
//! A [`MorphologySignature`] is an *abstract inspectable deterministic
//! representation of shape* — NOT merely a hash. It describes one behavioral
//! divergence evolving along a mutation lineage: which signal axes moved, in
//! which directions, with what magnitude, slew, persistence, and
//! co-activation. The canonical encoding of the *fields* is hashed to obtain
//! the signature ID, but every field is retained for inspection; nothing is
//! normalized away except by a declared law (docs/INVARIANTS.md).
//!
//! All fields are integer/fixed-point/bucket classes; there are no floats in
//! canonical identity (docs/ARCHITECTURE.md §16).
//!
//! # Classification and the `Unknown` discipline
//!
//! Phase 2's classifier distinguishes *trivial* signatures (no structural
//! activity: nothing moved) from *structured* ones (axes moved, directions
//! persist). The FuzzSemanticBank (Phase 3) names classes; until then every
//! structured signature is [`StructuralClass::StructuredUnknown`] — it is
//! NEVER renamed to a closest guess (invariant I6). Structured-Unknown is a
//! first-class, high-value corpus condition (the scheduler treats it as more
//! interesting than stable benign morphology), not a bug claim.

use crate::error::{Error, Result};
use crate::observe::residual::MutationResidual;
use crate::target_runtime::signals::{magnitude_bucket, SignalVector, MAX_SIGNALS};

/// Version of the morphology payload encoding.
pub const MORPHOLOGY_VERSION: u8 = 1;

/// How structurally active a signature is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Triviality {
    /// No structural activity: no axis moved, no cumulative magnitude.
    Trivial = 0,
    /// Non-trivial structure (axes moved) — either named (Phase 3) or
    /// `StructuredUnknown`.
    Structured = 1,
}

/// The classification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StructuralClass {
    /// No structural activity (benign morphology).
    Trivial = 0,
    /// Non-trivial structure that matches no named class. Phase 2 has no
    /// named classes (the FuzzSemanticBank is Phase 3), so every structured
    /// signature is this. Never renamed to a nearest label (I6).
    StructuredUnknown = 1,
}

impl StructuralClass {
    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            StructuralClass::Trivial => "trivial",
            StructuralClass::StructuredUnknown => "structured-unknown",
        }
    }
}

/// The comparison-convergence class of the signal series (Phase-2
/// derivation documented below; the full compare-convergence residual with
/// operand series tracking arrives in Phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CmpConvergence {
    /// No convergence signal measured (no active axis).
    None = 0,
    /// A dominant axis is trending monotonically (cumulative direction
    /// constant, no slew): the behavior is converging toward/through a
    /// boundary.
    Converging = 1,
    /// The dominant axis reversed direction (slew > 0): oscillating around
    /// a region.
    Oscillating = 2,
    /// The dominant axis's cumulative magnitude exceeded the large-delta
    /// class with no reversal: a runaway trend.
    Diverging = 3,
}

impl CmpConvergence {
    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            CmpConvergence::None => "none",
            CmpConvergence::Converging => "converging",
            CmpConvergence::Oscillating => "oscillating",
            CmpConvergence::Diverging => "diverging",
        }
    }
}

/// How the touched-signal set changed on the latest edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StateChange {
    /// No change.
    None = 0,
    /// The child touched signals the parent did not.
    Expanded = 1,
    /// The child dropped signals the parent touched.
    Contracted = 2,
    /// Both (some new, some lost).
    Shifted = 3,
}

impl StateChange {
    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            StateChange::None => "none",
            StateChange::Expanded => "expanded",
            StateChange::Contracted => "contracted",
            StateChange::Shifted => "shifted",
        }
    }
}

/// The inspectable, deterministic morphology signature of one lineage node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MorphologySignature {
    /// Bitmask of structurally involved signals.
    pub axis_mask: u64,
    /// Two bits per signal: cumulative direction (0 none, 1 up, 2 down).
    pub dir_bits: u128,
    /// Per-signal cumulative magnitude buckets.
    pub mag_bins: [u8; MAX_SIGNALS],
    /// Per-signal direction-flip counts (slew).
    pub slew_bins: [u8; MAX_SIGNALS],
    /// Per-signal max consecutive same-direction run (persistence).
    pub persistence: [u8; MAX_SIGNALS],
    /// Signals co-moving with the dominant axis on the latest edge.
    pub coactivation_mask: u64,
    /// Comparison convergence class (Phase-2 derivation; see type docs).
    pub cmp_convergence: u8,
    /// How the touched set changed on the latest edge.
    pub state_change: u8,
    /// Replay stability: 0 unmeasured, 1 stable, 2 unstable. Phase 2 marks
    /// every signature unmeasured unless it was deliberately replayed
    /// (boundary verification).
    pub replay_stability: u8,
    /// This signature matched no named class (Phase 2: always true for
    /// structured signatures; the bank is Phase 3).
    pub structured_unknown: bool,
    /// Lineage depth of this node (generation).
    pub depth: u32,
}

impl MorphologySignature {
    /// A trivial, empty signature.
    pub fn trivial(depth: u32) -> MorphologySignature {
        MorphologySignature {
            axis_mask: 0,
            dir_bits: 0,
            mag_bins: [0; MAX_SIGNALS],
            slew_bins: [0; MAX_SIGNALS],
            persistence: [0; MAX_SIGNALS],
            coactivation_mask: 0,
            cmp_convergence: 0,
            state_change: 0,
            replay_stability: 0,
            structured_unknown: false,
            depth,
        }
    }

    /// The direction (2-bit) of one signal.
    pub fn dir(&self, i: usize) -> u8 {
        ((self.dir_bits >> (2 * i)) & 0b11) as u8
    }

    /// The dominant axis: the signal with the largest cumulative magnitude
    /// bucket (ties broken by lowest signal id — deterministic).
    pub fn dominant_axis(&self) -> Option<u16> {
        let mut best: Option<(u16, u8)> = None;
        for i in 0..MAX_SIGNALS {
            if self.axis_mask & (1u64 << i) == 0 {
                continue;
            }
            let m = self.mag_bins[i];
            if best.map(|(_, b)| m > b).unwrap_or(true) {
                best = Some((i as u16, m));
            }
        }
        best.map(|(a, _)| a)
    }

    /// The cumulative magnitude bucket of one signal.
    pub fn mag_bin(&self, i: usize) -> u8 {
        self.mag_bins[i]
    }

    /// Whether the signature is structurally active at all.
    pub fn is_trivial(&self) -> bool {
        self.axis_mask == 0
    }

    /// The structural identity: a deterministic hash of the SHAPE fields
    /// (axis mask, direction bits, convergence class, state-change class).
    ///
    /// Magnitude and persistence bins are deliberately EXCLUDED: they change
    /// on every step of a drifting trajectory, so admitting on the full
    /// signature floods the corpus (a Phase-2 finding: ~3300 admissions in
    /// 12s on the golden demo). Corpus admission fires on a new structural
    /// identity; the full signature (with magnitudes) is still durable for
    /// inspection. FNV-1a 64 over the identity fields.
    pub fn structural_identity(&self) -> u64 {
        let mut h: u64 = 0xCBF2_9CE4_8422_2325;
        for &b in &self.axis_mask.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        for &b in &self.dir_bits.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        for &b in &[self.cmp_convergence, self.state_change] {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        h
    }

    /// The canonical payload encoding (deterministic; the store hashes it
    /// to obtain the signature ID).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(1 + 8 + 16 + 64 * 4 + 8 + 1 + 1 + 1 + 1 + 4);
        out.push(MORPHOLOGY_VERSION);
        out.extend_from_slice(&self.axis_mask.to_le_bytes());
        out.extend_from_slice(&self.dir_bits.to_le_bytes());
        out.extend_from_slice(&self.mag_bins);
        out.extend_from_slice(&self.slew_bins);
        out.extend_from_slice(&self.persistence);
        out.extend_from_slice(&self.coactivation_mask.to_le_bytes());
        out.push(self.cmp_convergence);
        out.push(self.state_change);
        out.push(self.replay_stability);
        out.push(u8::from(self.structured_unknown));
        out.extend_from_slice(&self.depth.to_le_bytes());
        Ok(out)
    }

    /// Decode a canonical payload.
    pub fn decode(bytes: &[u8]) -> Result<MorphologySignature> {
        // version(1) + axis_mask(8) + dir_bits(16) + 3x64 + coactivation(8)
        // + 4 flag bytes + depth(4).
        let min_len = 1 + 8 + 16 + 64 * 3 + 8 + 4 + 4;
        if bytes.len() < min_len {
            return Err(Error::Encoding("morphology truncated"));
        }
        let version = bytes[0];
        if version != MORPHOLOGY_VERSION {
            return Err(Error::UnsupportedVersion {
                family: "morphology-signature",
                version: version as u32,
            });
        }
        let mut pos = 1usize;
        let mut take = |n: usize| -> Result<&[u8]> {
            let end = pos.checked_add(n).ok_or(Error::Overflow)?;
            if end > bytes.len() {
                return Err(Error::Encoding("morphology truncated"));
            }
            let out = &bytes[pos..end];
            pos = end;
            Ok(out)
        };
        let axis_mask = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let dir_bits = u128::from_le_bytes(take(16)?.try_into().unwrap());
        let mut mag_bins = [0u8; MAX_SIGNALS];
        mag_bins.copy_from_slice(take(64)?);
        let mut slew_bins = [0u8; MAX_SIGNALS];
        slew_bins.copy_from_slice(take(64)?);
        let mut persistence = [0u8; MAX_SIGNALS];
        persistence.copy_from_slice(take(64)?);
        let coactivation_mask = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let cmp_convergence = take(1)?[0];
        let state_change = take(1)?[0];
        let replay_stability = take(1)?[0];
        let structured_unknown = take(1)?[0] != 0;
        let depth = u32::from_le_bytes(take(4)?.try_into().unwrap());
        if pos != bytes.len() {
            return Err(Error::Encoding("morphology has trailing bytes"));
        }
        Ok(MorphologySignature {
            axis_mask,
            dir_bits,
            mag_bins,
            slew_bins,
            persistence,
            coactivation_mask,
            cmp_convergence,
            state_change,
            replay_stability,
            structured_unknown,
            depth,
        })
    }
}

/// Classify a signature. Phase 2: `Trivial` iff nothing moved; every
/// structured signature is `StructuredUnknown` (the bank is Phase 3). The
/// discipline: a non-trivial trajectory is NEVER force-labelled (I6).
pub fn classify(m: &MorphologySignature) -> StructuralClass {
    if m.is_trivial() {
        StructuralClass::Trivial
    } else {
        StructuralClass::StructuredUnknown
    }
}

/// Per-(lineage-root, mutator) accumulator that turns a stream of edge
/// residuals into successive morphology signatures.
///
/// The accumulator is pure state over immutable inputs; replaying the same
/// edges in the same order yields the same signatures (I12 spirit). The
/// coordinator rebuilds one accumulator per lineage from durable
/// `CorpusMeta` signals on restart and verifies the recomputed signature ID
/// against the stored one (fsck).
#[derive(Debug, Clone)]
pub struct LineageAccumulator {
    /// Exact cumulative deltas per signal (vs the lineage baseline).
    cumulative: [i128; MAX_SIGNALS],
    last_dir: [u8; MAX_SIGNALS],
    run: [u8; MAX_SIGNALS],
    max_run: [u8; MAX_SIGNALS],
    slew: [u8; MAX_SIGNALS],
    axis_mask: u64,
    /// The lineage root's recorded observation (the nominal).
    baseline: Option<SignalVector>,
    /// The previous node's recorded observation (coactivation/state-change).
    prev: Option<SignalVector>,
}

impl LineageAccumulator {
    /// A fresh accumulator.
    pub fn new() -> LineageAccumulator {
        LineageAccumulator {
            cumulative: [0; MAX_SIGNALS],
            last_dir: [0; MAX_SIGNALS],
            run: [0; MAX_SIGNALS],
            max_run: [0; MAX_SIGNALS],
            slew: [0; MAX_SIGNALS],
            axis_mask: 0,
            baseline: None,
            prev: None,
        }
    }

    /// Establish the lineage baseline (the root observation). The first
    /// pushed edge is then interpreted as a deviation from this nominal.
    pub fn init_baseline(&mut self, baseline: &SignalVector) {
        self.baseline = Some(baseline.clone());
        self.prev = Some(baseline.clone());
    }

    /// Fold one edge residual and produce the child's signature.
    pub fn push(&mut self, edge: &MutationResidual, depth: u32) -> MorphologySignature {
        if self.baseline.is_none() {
            // Defensive: without an explicit baseline, the first pushed
            // observation becomes the nominal (its signature is trivial).
            self.baseline = Some(edge.parent.clone());
            self.prev = Some(edge.parent.clone());
        }

        let child_touched = edge.child.touched_mask();
        let _prev_touched = self.prev.as_ref().map(|p| p.touched_mask()).unwrap_or(0);
        let state_change = if edge.touched_new != 0 && edge.touched_lost != 0 {
            StateChange::Shifted
        } else if edge.touched_new != 0 {
            StateChange::Expanded
        } else if edge.touched_lost != 0 {
            StateChange::Contracted
        } else {
            StateChange::None
        };

        for i in 0..MAX_SIGNALS {
            let d = edge.deltas[i];
            if d == 0 {
                continue;
            }
            self.cumulative[i] = self.cumulative[i].saturating_add(d as i128);
            let dir: u8 = if self.cumulative[i] > 0 {
                1
            } else if self.cumulative[i] < 0 {
                2
            } else {
                0
            };
            if dir != 0 {
                match (self.last_dir[i], dir) {
                    // A genuine direction REVERSAL (not the initial onset).
                    (prev, next) if prev != 0 && next != prev => {
                        self.slew[i] = self.slew[i].saturating_add(1);
                        self.run[i] = 1;
                    }
                    (prev, next) if prev == next => {
                        self.run[i] = self.run[i].saturating_add(1);
                    }
                    _ => {
                        // Onset: the first movement of this axis.
                        self.run[i] = 1;
                    }
                }
                self.last_dir[i] = dir;
                self.max_run[i] = self.max_run[i].max(self.run[i]);
                self.axis_mask |= 1u64 << i;
            }
        }

        let mut dir_bits: u128 = 0;
        let mut mag_bins = [0u8; MAX_SIGNALS];
        let mut dominant: Option<(u16, u8)> = None;
        // Parallel fixed-size arrays indexed by signal id.
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_SIGNALS {
            if self.axis_mask & (1u64 << i) == 0 {
                continue;
            }
            let dir = self.last_dir[i];
            dir_bits |= (dir as u128) << (2 * i);
            let mag = magnitude_bucket(self.cumulative[i].unsigned_abs() as u64);
            mag_bins[i] = mag;
            if dominant.map(|(_, b)| mag > b).unwrap_or(true) {
                dominant = Some((i as u16, mag));
            }
        }

        // Coactivation: signals that moved on the latest edge together with
        // the dominant axis.
        let mut coactivation_mask = 0u64;
        if let Some((axis, _)) = dominant {
            for i in 0..MAX_SIGNALS {
                if i as u16 != axis && edge.deltas[i] != 0 {
                    coactivation_mask |= 1u64 << i;
                }
            }
        }

        // Phase-2 comparison-convergence class (documented in the type):
        // derive it from the dominant axis's slew and magnitude.
        let cmp_convergence = match dominant {
            None => CmpConvergence::None,
            Some((axis, mag)) => {
                let s = self.slew[axis as usize];
                if s > 0 {
                    CmpConvergence::Oscillating
                } else if mag >= 32 {
                    CmpConvergence::Diverging
                } else {
                    CmpConvergence::Converging
                }
            }
        };

        let mut signature = MorphologySignature {
            axis_mask: self.axis_mask,
            dir_bits,
            mag_bins,
            slew_bins: self.slew,
            persistence: self.max_run,
            coactivation_mask,
            cmp_convergence: cmp_convergence.code(),
            state_change: state_change.code(),
            replay_stability: 0,
            structured_unknown: false,
            depth,
        };
        signature.structured_unknown = classify(&signature) == StructuralClass::StructuredUnknown;
        let _ = child_touched;
        self.prev = Some(edge.child.clone());
        signature
    }
}

impl Default for LineageAccumulator {
    fn default() -> Self {
        LineageAccumulator::new()
    }
}

/// Rebuild a lineage accumulator by replaying the edges of a chain (the
/// parent-first chain of a corpus entry with a matching edge mutator).
pub fn replay_chain(
    accumulator: &mut LineageAccumulator,
    edges: &[(SignalVector, SignalVector, u32)],
) -> Vec<MorphologySignature> {
    let mut out = Vec::with_capacity(edges.len());
    for (parent, child, depth) in edges {
        let edge = MutationResidual::of(child, parent);
        out.push(accumulator.push(&edge, *depth));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target_runtime::signals::SignalId;

    fn vec_with(id: u16, v: u64) -> SignalVector {
        let mut s = SignalVector::new();
        s.observe(SignalId(id), v).unwrap();
        s
    }

    #[test]
    fn signature_encoding_roundtrip_and_stable_size() {
        let mut acc = LineageAccumulator::new();
        acc.push(
            &MutationResidual::of(&vec_with(0, 1), &SignalVector::new()),
            1,
        );
        let sig = acc.push(&MutationResidual::of(&vec_with(0, 3), &vec_with(0, 1)), 2);
        let enc = sig.encode().unwrap();
        assert_eq!(enc.len(), 1 + 8 + 16 + 64 * 3 + 8 + 4 + 4);
        assert_eq!(MorphologySignature::decode(&enc).unwrap(), sig);
    }

    #[test]
    fn structural_identity_ignores_magnitude_bins() {
        // Two signatures with the same shape but different magnitudes must
        // share an identity (admission novelty), yet remain distinct objects
        // (durable inspection).
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&SignalVector::new());
        acc.push(
            &MutationResidual::of(&vec_with(0, 1), &SignalVector::new()),
            0,
        );
        let a = acc.push(&MutationResidual::of(&vec_with(0, 2), &vec_with(0, 1)), 1);
        let b = acc.push(&MutationResidual::of(&vec_with(0, 9), &vec_with(0, 2)), 2);
        assert_eq!(a.structural_identity(), b.structural_identity());
        assert_ne!(a.encode().unwrap(), b.encode().unwrap());
        // A different shape (a second axis) has a different identity.
        let mut acc2 = LineageAccumulator::new();
        acc2.init_baseline(&SignalVector::new());
        acc2.push(
            &MutationResidual::of(&vec_with(0, 1), &SignalVector::new()),
            0,
        );
        let mut child = vec_with(0, 2);
        child.observe(SignalId(1), 5).unwrap();
        let c = acc2.push(&MutationResidual::of(&child, &vec_with(0, 1)), 1);
        assert_ne!(a.structural_identity(), c.structural_identity());
    }

    #[test]
    fn trivial_signature_for_baseline_and_no_movement() {
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&SignalVector::new());
        // A child identical to its parent: nothing moved, trivial.
        let sig = acc.push(&MutationResidual::of(&vec_with(0, 5), &vec_with(0, 5)), 1);
        assert_eq!(classify(&sig), StructuralClass::Trivial);
        // An empty edge: also trivial.
        let sig2 = acc.push(
            &MutationResidual::of(&SignalVector::new(), &SignalVector::new()),
            2,
        );
        assert_eq!(classify(&sig2), StructuralClass::Trivial);
        // The first movement against the baseline is real structure.
        let sig3 = acc.push(&MutationResidual::of(&vec_with(0, 6), &vec_with(0, 5)), 3);
        assert_eq!(classify(&sig3), StructuralClass::StructuredUnknown);
    }

    #[test]
    fn drift_accumulates_structured_unknown() {
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&SignalVector::new());
        acc.push(
            &MutationResidual::of(&vec_with(0, 1), &SignalVector::new()),
            0,
        );
        let mut parent = vec_with(0, 1);
        let mut sig = acc.push(&MutationResidual::of(&vec_with(0, 2), &parent), 1);
        parent = vec_with(0, 2);
        for d in 3..16u64 {
            let child = vec_with(0, d);
            sig = acc.push(&MutationResidual::of(&child, &parent), (d - 1) as u32);
            parent = child;
        }
        assert_eq!(classify(&sig), StructuralClass::StructuredUnknown);
        assert!(sig.structured_unknown);
        assert_eq!(sig.dir(0), 1);
        assert_eq!(sig.persistence[0], 15);
        assert_eq!(sig.slew_bins[0], 0); // no direction flips (onset not a flip)
        assert_eq!(sig.mag_bins[0], magnitude_bucket(15));
        assert_eq!(sig.state_change, StateChange::None.code());
        assert!(sig.dominant_axis() == Some(0));
    }

    #[test]
    fn slew_counts_direction_flips() {
        let mut acc = LineageAccumulator::new();
        let mut baseline = SignalVector::new();
        baseline.observe(SignalId(0), 10).unwrap();
        acc.init_baseline(&baseline);
        // Downward drift: 10 -> 9 -> 8 (cumulative -1, -2; dir 2).
        acc.push(&MutationResidual::of(&vec_with(0, 9), &baseline), 0);
        acc.push(&MutationResidual::of(&vec_with(0, 8), &vec_with(0, 9)), 1);
        // A large upward step: cumulative crosses zero to +2 (dir 1): a
        // genuine direction reversal.
        let sig = acc.push(&MutationResidual::of(&vec_with(0, 12), &vec_with(0, 8)), 2);
        assert_eq!(sig.slew_bins[0], 1);
        assert_eq!(sig.cmp_convergence, CmpConvergence::Oscillating.code());
    }

    #[test]
    fn state_change_classes() {
        let mut acc = LineageAccumulator::new();
        acc.push(
            &MutationResidual::of(&vec_with(0, 1), &SignalVector::new()),
            0,
        );
        // Expand: introduce signal 1.
        let mut child = vec_with(0, 2);
        child.observe(SignalId(1), 9).unwrap();
        let sig = acc.push(&MutationResidual::of(&child, &vec_with(0, 1)), 1);
        assert_eq!(sig.state_change, StateChange::Expanded.code());
    }

    #[test]
    fn coactivation_masks_co_movers() {
        let mut acc = LineageAccumulator::new();
        let mut seed = SignalVector::new();
        seed.observe(SignalId(0), 1).unwrap();
        seed.observe(SignalId(1), 2).unwrap();
        acc.push(&MutationResidual::of(&seed, &SignalVector::new()), 0);
        let mut child = seed.clone();
        child.observe(SignalId(0), 10).unwrap();
        child.observe(SignalId(1), 20).unwrap();
        let sig = acc.push(&MutationResidual::of(&child, &seed), 1);
        // Both axes moved; dominant = whichever has the larger cumulative.
        assert_eq!(sig.axis_mask, 0b11);
        assert!(sig.coactivation_mask & 0b11 != 0);
    }

    #[test]
    fn replay_is_deterministic() {
        let edges = vec![
            (SignalVector::new(), vec_with(0, 1), 0u32),
            (vec_with(0, 1), vec_with(0, 3), 1u32),
            (vec_with(0, 3), vec_with(0, 6), 2u32),
            (vec_with(0, 6), vec_with(0, 5), 3u32),
        ];
        let mut a = LineageAccumulator::new();
        let sa = replay_chain(&mut a, &edges);
        let mut b = LineageAccumulator::new();
        let sb = replay_chain(&mut b, &edges);
        assert_eq!(sa, sb);
        // The final signatures have identical canonical encodings.
        assert_eq!(
            sa.last().unwrap().encode().unwrap(),
            sb.last().unwrap().encode().unwrap()
        );
    }
}
