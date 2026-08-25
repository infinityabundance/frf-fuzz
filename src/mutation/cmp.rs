//! Compare-operand substitution.
//!
//! Uses observed comparison operands (from the target's cmp ring) to decide
//! WHERE and WHAT to mutate: find the operand's little-endian byte pattern in
//! the input and replace it with an interesting value for that width. This is
//! the deterministic core of compare-guided fuzzing; the full
//! compare-convergence residual and dictionary-discovery machinery arrives in
//! Phase 2, but the substitution itself is already reproducible from the
//! coordinate alone (the hits are immutable inputs).
//!
//! Deterministic semantics: iterate hits in the fixed order given; for each
//! hit, search for its byte pattern from position 0; on the first match,
//! overwrite with an interesting value drawn from the RNG; stop after
//! `MAX_SUBSTITUTIONS` successful substitutions.

use super::integer::interesting_for_width;
use super::{MutationInput, MutationOutput};
use crate::error::Result;

/// Maximum number of substitutions per mutation.
const MAX_SUBSTITUTIONS: usize = 3;

/// Apply compare-operand substitutions.
pub fn substitute(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    if input.parent.is_empty() || input.cmp_hits.is_empty() {
        return Ok(MutationOutput {
            bytes: input.parent.to_vec(),
            changed: false,
        });
    }
    let mut out = input.parent.to_vec();
    let mut changed = false;
    let mut done = 0usize;
    for hit in input.cmp_hits {
        if done >= MAX_SUBSTITUTIONS {
            break;
        }
        let w = hit.width();
        let pattern = &hit.to_le_bytes()[..w];
        // A parent shorter than the operand width cannot contain the
        // pattern; searching anyway would slice out of bounds (the previous
        // `saturating_sub` loop ran `p = 0` and sliced `out[0..w]` past the
        // end — a runtime-only bug the short-parent regression test locks).
        if out.len() < w {
            continue;
        }
        // Search for the operand pattern from position 0; replace the first
        // occurrence. Overlapping self-matches across hits are possible but
        // deterministic (the hit order is fixed).
        let mut found = None;
        for p in 0..=out.len() - w {
            if &out[p..p + w] == pattern {
                found = Some(p);
                break;
            }
        }
        let Some(p) = found else {
            continue;
        };
        let choices = interesting_for_width(w);
        let nv = choices[input.rng.gen_index(choices.len())];
        if nv.to_le_bytes()[..w] != *pattern {
            out[p..p + w].copy_from_slice(&nv.to_le_bytes()[..w]);
            changed = true;
            done += 1;
        }
    }
    Ok(MutationOutput {
        changed,
        bytes: out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::prng::CounterRng;

    #[test]
    fn short_parent_wider_hit_is_total() {
        // Regression: a 2-byte parent with an 8-byte cmp hit used to slice
        // `out[0..8]` out of bounds (the search loop ran `p = 0` even when
        // `out.len() < w`). Every mutator must be total (never panic) (I2).
        use crate::mutation::CmpHit;
        let parent = [0xABu8, 0xCD];
        let hits = [CmpHit::U64(0x0102_0304_0506_0708)];
        for seed in 0..64u32 {
            let mut rng = CounterRng::from_philox([seed, 1, 0, 0], [0, 0]);
            let mut input = MutationInput {
                parent: &parent,
                rng: &mut rng,
                dictionary: &[],
                cmp_hits: &hits,
                splice_partner: None,
                influence: None,
            };
            let out = substitute(&mut input).unwrap();
            assert_eq!(out.bytes, parent);
            assert!(!out.changed);
        }
    }

    #[test]
    fn substitutes_magic_value() {
        use crate::mutation::CmpHit;
        // Parent contains the LE u32 0xDEADBEEF.
        let parent = [0xEFu8, 0xBE, 0xAD, 0xDE, 0x01, 0x02, 0x03, 0x04];
        let hits = [CmpHit::U32(0xDEAD_BEEF)];
        let mut rng = CounterRng::from_philox([11, 0, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent: &parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &hits,
            splice_partner: None,
            influence: None,
        };
        let out = substitute(&mut input).unwrap();
        assert!(out.changed);
        // The replaced u32 must no longer be 0xDEADBEEF.
        let v = u32::from_le_bytes(out.bytes[0..4].try_into().unwrap());
        assert_ne!(v, 0xDEAD_BEEF);
        // But the interesting table value must appear.
        let choices = interesting_for_width(4);
        assert!(choices.contains(&(v as u64)));
        assert_eq!(out.bytes.len(), parent.len());
    }

    #[test]
    fn no_hits_is_noop() {
        let parent = b"unchanged";
        let mut rng = CounterRng::from_philox([11, 0, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &[],
            splice_partner: None,
            influence: None,
        };
        let out = substitute(&mut input).unwrap();
        assert_eq!(out.bytes, parent);
        assert!(!out.changed);
    }

    #[test]
    fn deterministic() {
        use crate::mutation::CmpHit;
        let parent = [0xEFu8, 0xBE, 0xAD, 0xDE, 0x01, 0x02, 0x03, 0x04];
        let hits = [CmpHit::U32(0xDEAD_BEEF), CmpHit::U16(0x0102)];
        let mut rng = CounterRng::from_philox([11, 7, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent: &parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &hits,
            splice_partner: None,
            influence: None,
        };
        let a = substitute(&mut input).unwrap();
        let mut rng = CounterRng::from_philox([11, 7, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent: &parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &hits,
            splice_partner: None,
            influence: None,
        };
        let b = substitute(&mut input).unwrap();
        assert_eq!(a, b);
    }
}
