//! Splice mutator: overwrite a block of the parent with a block drawn from a
//! partner input (classic cross-over between two corpus entries).

use super::{MutationInput, MutationOutput};
use crate::error::Result;

/// Splice: take a `1..=32`-byte block from `splice_partner` and overwrite a
/// block of the parent with it.
///
/// Deterministic: partner is required (a missing partner is a no-op, not an
/// error — the scheduler simply does not issue splice work orders without a
/// partner). Both blocks are drawn from the same RNG in fixed order: partner
/// block first, then parent block.
pub fn splice(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    let Some(partner) = input.splice_partner else {
        return Ok(MutationOutput {
            bytes: input.parent.to_vec(),
            changed: false,
        });
    };
    if input.parent.is_empty() || partner.is_empty() {
        return Ok(MutationOutput {
            bytes: input.parent.to_vec(),
            changed: false,
        });
    }
    // The block size is bounded by BOTH inputs: `k` must fit in the parent
    // (the destination) and come from the partner (the source). A short
    // parent with a long partner must not overflow `out[dst..dst + k]`.
    let max_k = 32usize.min(partner.len()).min(input.parent.len());
    let k = 1 + input.rng.gen_index(max_k);
    let src = input.rng.gen_index(partner.len().saturating_sub(k).max(1));
    let dst = input
        .rng
        .gen_index(input.parent.len().saturating_sub(k).max(1));
    let mut out = input.parent.to_vec();
    out[dst..dst + k].copy_from_slice(&partner[src..src + k]);
    Ok(MutationOutput {
        changed: true,
        bytes: out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::prng::CounterRng;

    #[test]
    fn splice_copies_partner_bytes() {
        let parent = b"AAAAAAAAAAAAAAAA";
        let partner = b"BBBBBBBBBBBBBBBB";
        let mut rng = CounterRng::from_philox([5, 0, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &[],
            splice_partner: Some(partner),
            influence: None,
        };
        let out = splice(&mut input).unwrap();
        assert_eq!(out.bytes.len(), parent.len());
        assert!(out.changed);
        assert!(out.bytes.contains(&b'B'));
    }

    #[test]
    fn splice_short_parent_never_overflows() {
        // Regression: the block size used to be bounded by the PARTNER only,
        // so a 2-byte parent spliced against a 32-byte partner could slice
        // `out[dst..dst + k]` past the end. Every mutator must be total
        // (never panic) on every input pair (I2).
        let parent = b"AB";
        let partner = b"Z".repeat(32);
        for seed in 0..64u32 {
            let mut rng = CounterRng::from_philox([seed, 1, 0, 0], [0, 0]);
            let mut input = MutationInput {
                parent,
                rng: &mut rng,
                dictionary: &[],
                cmp_hits: &[],
                splice_partner: Some(partner.as_slice()),
                influence: None,
            };
            let out = splice(&mut input).unwrap();
            assert_eq!(out.bytes.len(), parent.len());
        }
    }

    #[test]
    fn splice_without_partner_is_noop() {
        let parent = b"AAAAAAAAAAAAAAAA";
        let mut rng = CounterRng::from_philox([5, 0, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &[],
            splice_partner: None,
            influence: None,
        };
        let out = splice(&mut input).unwrap();
        assert_eq!(out.bytes, parent);
        assert!(!out.changed);
    }
}
