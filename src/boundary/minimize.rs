//! Deterministic two-sided boundary minimization (master prompt §23).
//!
//! Goal: shrink `distance(left, right)` while preserving the behavioral
//! distinction between the two sides. This produces stronger debugging
//! evidence than minimizing only the crashing input: it localizes the
//! boundary itself.
//!
//! # Algorithm (deterministic, bounded)
//!
//! Iterative greedy coordinate descent over both sides:
//!
//! 1. For every byte position in order: try replacing `left[i]` with
//!    `right[i]` (and vice versa); keep the change if the distinction is
//!    preserved.
//! 2. For length differences: try trimming the longer side's tail one byte
//!    at a time toward the shorter side's length; keep if preserved.
//! 3. Iterate until no improving move preserves the distinction or the
//!    verification budget is exhausted.
//!
//! Every iteration order is fixed (byte index ascending, left before
//! right), so the result is deterministic given the same verify outcomes.
//! All arithmetic is checked; inputs are bounded by [`MAX_INPUT_LEN`].

use crate::error::{Error, Result};
use crate::scheduler::work_order::MAX_INPUT_LEN;

/// The deterministic byte distance between two inputs: the sum of absolute
/// byte differences over the common prefix plus the length difference
/// scaled by 256 (so length differences dominate only after byte
/// differences are exhausted). Integer only; 0 iff the inputs are identical.
pub fn byte_distance(a: &[u8], b: &[u8]) -> u64 {
    let common = a.len().min(b.len());
    let mut d = 0u64;
    for i in 0..common {
        let diff = (a[i] as i64 - b[i] as i64).unsigned_abs();
        d = d.saturating_add(diff);
    }
    let len_diff = (a.len() as i64 - b.len() as i64).unsigned_abs();
    d.saturating_add(len_diff.saturating_mul(256))
}

/// How the two sides of a pair behave (the distinction to preserve).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairSide {
    /// The left side's behavior (regime-A / passing).
    Left,
    /// The right side's behavior (regime-B / failing).
    Right,
}

/// A verify function: classify one input as Left or Right behavior.
/// Returns `Err` when the input could not be classified (the caller's
/// budget exhausted, worker broken, etc.).
pub type VerifyFn<'a> = &'a mut dyn FnMut(&[u8]) -> Result<PairSide>;

/// The outcome of a minimization session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimizeOutcome {
    /// The minimized left input.
    pub left: Vec<u8>,
    /// The minimized right input.
    pub right: Vec<u8>,
    /// Distance before minimization.
    pub start_distance: u64,
    /// Distance after minimization.
    pub end_distance: u64,
    /// Verifications performed.
    pub verifications: u64,
}

/// Minimize a pair two-sidedly. `verify` classifies inputs; the loop keeps
/// a move only when the classification is unchanged and the distance
/// strictly decreased (monotone, terminating).
///
/// The initial inputs must already be a valid pair (Left vs Right); the
/// caller verifies that before calling (or after, via the returned
/// `PairSide` classification checks in `verify`).
pub fn minimize_pair(
    left: &[u8],
    right: &[u8],
    max_verifications: u64,
    verify: VerifyFn<'_>,
) -> Result<MinimizeOutcome> {
    if left.len() > MAX_INPUT_LEN || right.len() > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "boundary input length",
            limit: MAX_INPUT_LEN as u64,
            got: left.len().max(right.len()) as u64,
        });
    }
    let start_distance = byte_distance(left, right);
    let mut l = left.to_vec();
    let mut r = right.to_vec();
    let mut verifications = 0u64;

    let mut verify_budget = |l: &[u8], r: &[u8]| -> Result<bool> {
        if verifications >= max_verifications {
            return Ok(false);
        }
        verifications += 1;
        Ok(verify(l)? == PairSide::Left && verify(r)? == PairSide::Right)
    };

    // Greedy coordinate descent. Deterministic iteration order: byte index
    // ascending, left side before right side, then length trimming.
    let max_iterations = (l.len() + r.len() + 8).min(1 << 20);
    for _ in 0..max_iterations {
        let before = byte_distance(&l, &r);
        let mut improved = false;

        // Phase A: byte alignment moves (both directions).
        let common = l.len().min(r.len());
        for i in 0..common {
            // Left toward right.
            if l[i] != r[i] {
                let mut cand = l.clone();
                cand[i] = r[i];
                if byte_distance(&cand, &r) < before && verify_budget(&cand, &r)? {
                    l = cand;
                    improved = true;
                    break; // restart the sweep from position 0 (deterministic)
                }
            }
            // Right toward left.
            if r[i] != l[i] {
                let mut cand = r.clone();
                cand[i] = l[i];
                if byte_distance(&l, &cand) < before && verify_budget(&l, &cand)? {
                    r = cand;
                    improved = true;
                    break;
                }
            }
        }
        if improved {
            continue;
        }

        // Phase B: length trimming (only when lengths differ).
        if l.len() > r.len() {
            let mut cand = l.clone();
            cand.pop();
            if byte_distance(&cand, &r) < before && verify_budget(&cand, &r)? {
                l = cand;
                continue;
            }
        } else if r.len() > l.len() {
            let mut cand = r.clone();
            cand.pop();
            if byte_distance(&l, &cand) < before && verify_budget(&l, &cand)? {
                r = cand;
                continue;
            }
        }

        // No improving move preserved the distinction: converged.
        break;
    }

    let end_distance = byte_distance(&l, &r);
    Ok(MinimizeOutcome {
        left: l,
        right: r,
        start_distance,
        end_distance,
        verifications,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic distinction: the input "is right" iff it contains a byte
    /// >= 0x80 (a fake boundary). Deterministic and cheap.
    fn verify_fake(input: &[u8]) -> Result<PairSide> {
        if input.iter().any(|b| *b >= 0x80) {
            Ok(PairSide::Right)
        } else {
            Ok(PairSide::Left)
        }
    }

    #[test]
    fn byte_distance_law() {
        assert_eq!(byte_distance(b"", b""), 0);
        assert_eq!(byte_distance(b"a", b"a"), 0);
        assert_eq!(byte_distance(b"a", b"b"), 1);
        assert_eq!(byte_distance(b"a", b"ab"), 256); // length diff dominates
        assert_eq!(byte_distance(b"\x00\x00", b"\xff\xff"), 510);
    }

    #[test]
    fn minimization_shrinks_distance_and_preserves_distinction() {
        // Left: 64 zero bytes (regime A). Right: 64 0xFF bytes (regime B:
        // contains a high byte). The minimization should converge to a tiny
        // boundary pair: all-zeros vs a single 0xFF (distance 255).
        let left = vec![0u8; 64];
        let right = vec![0xFFu8; 64];
        let mut verify = |input: &[u8]| -> Result<PairSide> { verify_fake(input) };
        let outcome = minimize_pair(&left, &right, 1_000_000, &mut verify).unwrap();
        assert_eq!(outcome.start_distance, byte_distance(&left, &right));
        assert!(outcome.end_distance < outcome.start_distance);
        assert_eq!(outcome.end_distance, 255);
        assert_eq!(verify_fake(&outcome.left).unwrap(), PairSide::Left);
        assert_eq!(verify_fake(&outcome.right).unwrap(), PairSide::Right);
    }

    #[test]
    fn identical_inputs_are_rejected_by_convergence() {
        let left = b"same".to_vec();
        let right = b"same".to_vec();
        let mut verify = |input: &[u8]| -> Result<PairSide> { verify_fake(input) };
        let outcome = minimize_pair(&left, &right, 100, &mut verify).unwrap();
        // No move can strictly decrease distance 0: the loop converges
        // immediately with unchanged inputs.
        assert_eq!(outcome.end_distance, 0);
        assert_eq!(outcome.verifications, 0);
    }

    #[test]
    fn minimization_is_deterministic() {
        let left = vec![b'b'; 32];
        let mut right = vec![b'b'; 32];
        right[31] = 0xFF;
        let mut v1 = |input: &[u8]| -> Result<PairSide> { verify_fake(input) };
        let o1 = minimize_pair(&left, &right, 10_000, &mut v1).unwrap();
        let mut v2 = |input: &[u8]| -> Result<PairSide> { verify_fake(input) };
        let o2 = minimize_pair(&left, &right, 10_000, &mut v2).unwrap();
        assert_eq!(o1, o2);
    }

    #[test]
    fn budget_binds() {
        let left = vec![b'a'; 32];
        let mut right = vec![b'a'; 32];
        right[31] = 0xFF;
        let mut verify = |input: &[u8]| -> Result<PairSide> { verify_fake(input) };
        let outcome = minimize_pair(&left, &right, 4, &mut verify).unwrap();
        assert!(outcome.verifications <= 4);
    }
}
