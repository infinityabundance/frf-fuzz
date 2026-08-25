//! Corpus minimization: `tmin` and `cmin`.
//!
//! * [`minimize_input`] (tmin) — shrink one input while preserving a
//!   verification predicate (Phase 1: the crash reproduces). Deterministic
//!   byte-deletion with fixed pass order; no randomness.
//! * [`minimize_corpus`] (cmin) — greedily select the smallest input set
//!   that preserves global coverage. Deterministic: candidates are
//!   processed in a fixed order (feature-count desc, size asc).
//!
//! The two-sided counterfactual boundary minimization (minimize the
//! distance between a passing/failing pair) is a Phase-2 deliverable
//! (boundary witnesses); tmin here is single-sided crash preservation.
//!
//! This module is coordinator-gated.

use crate::id::ContentId;

/// Maximum input length tmin will produce (input length is bounded anyway;
/// this prevents quadratic blowup on adversarial inputs).
pub const MAX_TMIN_INPUT_LEN: usize = 1 << 20;

/// Minimize `input` while `verify` returns true. `verify` must be a pure,
/// deterministic predicate over the bytes (the caller decides what
/// "preserved" means — for Phase 1 tmin it is "the crash still
/// reproduces").
///
/// Algorithm: repeated deletion passes. Each pass tries deleting each byte
/// once (left to right); a deletion that keeps `verify` true is kept.
/// Passes continue until a full pass makes no progress. This is the
/// classic greedy byte-deletion (delta-debugging-lite); it is
/// deterministic, does not reorder bytes, and never re-introduces deleted
/// bytes.
pub fn minimize_input(input: &[u8], verify: &mut dyn FnMut(&[u8]) -> bool) -> Vec<u8> {
    if input.len() > MAX_TMIN_INPUT_LEN {
        return input.to_vec();
    }
    let mut current = input.to_vec();
    // The empty input is the global minimum; accept it if the predicate
    // holds (crash-on-empty is a real finding).
    if verify(&[]) {
        return Vec::new();
    }
    loop {
        let mut progress = false;
        let mut i = 0usize;
        while i < current.len() {
            let mut candidate = Vec::with_capacity(current.len() - 1);
            candidate.extend_from_slice(&current[..i]);
            candidate.extend_from_slice(&current[i + 1..]);
            if verify(&candidate) {
                current = candidate;
                progress = true;
                // Do not advance: the byte at `i` was removed, so the next
                // byte is now at `i` again.
            } else {
                i += 1;
            }
        }
        if !progress {
            break;
        }
    }
    current
}

/// A candidate for cmin: input id + the features it covers + its size.
#[derive(Debug, Clone)]
pub struct CminCandidate {
    /// The corpus entry id.
    pub id: ContentId,
    /// Sorted feature set.
    pub features: Vec<u64>,
    /// Input size in bytes.
    pub size: usize,
}

/// Greedy set-cover corpus minimization: select the smallest set of
/// candidates whose union of features equals the union of ALL candidates.
///
/// Deterministic ordering: candidates are sorted by (covered-so-far
/// contribution desc, size asc, id asc). Each round picks the candidate
/// contributing the most uncovered features, breaking ties by size then by
/// ID. The result is a subset that preserves global coverage — it is
/// NOT guaranteed minimal, but it is deterministic and reproducible.
pub fn minimize_corpus(candidates: Vec<CminCandidate>) -> Vec<ContentId> {
    // Total feature universe.
    let mut universe: Vec<u64> = candidates
        .iter()
        .flat_map(|c| c.features.iter().copied())
        .collect();
    universe.sort_unstable();
    universe.dedup();
    if universe.is_empty() {
        return Vec::new();
    }

    let mut covered: Vec<u64> = Vec::new();
    let mut remaining = candidates;
    let mut chosen: Vec<ContentId> = Vec::new();

    while !remaining.is_empty() && covered.len() < universe.len() {
        // Score each candidate: how many uncovered features it adds.
        // Sort deterministically: contribution desc, size asc, id asc.
        remaining.sort_by(|a, b| {
            let ca = contribution(a, &covered);
            let cb = contribution(b, &covered);
            cb.cmp(&ca)
                .then_with(|| a.size.cmp(&b.size))
                .then_with(|| a.id.to_hex().cmp(&b.id.to_hex()))
        });
        let best = remaining.remove(0);
        let contrib = contribution(&best, &covered);
        if contrib == 0 {
            // No candidate contributes anything new; stop.
            break;
        }
        for f in &best.features {
            if !covered.contains(f) {
                covered.push(*f);
            }
        }
        covered.sort_unstable();
        covered.dedup();
        chosen.push(best.id);
    }
    chosen
}

fn contribution(c: &CminCandidate, covered: &[u64]) -> usize {
    c.features.iter().filter(|f| !covered.contains(f)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(seed: u8) -> ContentId {
        ContentId::new(&[seed; 32])
    }

    #[test]
    fn tmin_removes_irrelevant_bytes() {
        // Predicate: input contains "KEEP".
        let input = b"xxKEEPyy garbage that is irrelevant zz";
        let out = minimize_input(input, &mut |candidate| {
            // "KEEP" must survive as a contiguous substring.
            candidate.windows(4).any(|w| w == b"KEEP")
        });
        assert_eq!(out, b"KEEP");
    }

    #[test]
    fn tmin_empty_if_predicate_holds_empty() {
        let out = minimize_input(b"abc", &mut |_| true);
        assert!(out.is_empty());
    }

    #[test]
    fn tmin_noop_when_nothing_removable() {
        let out = minimize_input(b"abc", &mut |c| c == b"abc");
        assert_eq!(out, b"abc");
    }

    #[test]
    fn tmin_is_deterministic() {
        let input = b"random bytes to shrink deterministically";
        let run = || minimize_input(input, &mut |c| c.windows(6).any(|w| w == b"shrink"));
        assert_eq!(run(), run());
        assert_eq!(run(), run());
    }

    #[test]
    fn cmin_preserves_coverage() {
        // No candidate dominates; the greedy must pick two and cover all.
        let candidates = vec![
            CminCandidate {
                id: cid(1),
                features: vec![1, 2],
                size: 100,
            },
            CminCandidate {
                id: cid(2),
                features: vec![2, 3],
                size: 100,
            },
            CminCandidate {
                id: cid(3),
                features: vec![3, 4],
                size: 100,
            },
            CminCandidate {
                id: cid(4),
                features: vec![1, 4],
                size: 100,
            },
        ];
        let chosen = minimize_corpus(candidates);
        // Greedy: two rounds, each picking the max contributor (ties by size
        // then by content-id hex, so the exact picks depend on the hashes —
        // what matters is coverage and size).
        assert_eq!(chosen.len(), 2);
        let features_by_id = [
            (cid(1), vec![1, 2]),
            (cid(2), vec![2, 3]),
            (cid(3), vec![3, 4]),
            (cid(4), vec![1, 4]),
        ];
        let mut union: Vec<u64> = chosen
            .iter()
            .flat_map(|id| {
                features_by_id
                    .iter()
                    .find(|(c, _)| c == id)
                    .map(|(_, f)| f.clone())
                    .unwrap_or_default()
            })
            .collect();
        union.sort_unstable();
        union.dedup();
        assert_eq!(union, vec![1, 2, 3, 4]);
    }

    #[test]
    fn cmin_is_deterministic() {
        let make = || {
            (0..10u8)
                .map(|i| CminCandidate {
                    id: cid(i),
                    features: vec![u64::from(i), u64::from((i + 1) % 10)],
                    size: (i as usize) * 7,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(minimize_corpus(make()), minimize_corpus(make()));
    }
}
