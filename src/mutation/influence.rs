//! Localized influence-region mutation.
//!
//! Restricts byte mutation to an explicit influence mask over the parent
//! (nonzero byte = mutable). This is the deterministic seed of the
//! [`InfluenceSketch`](docs/ARCHITECTURE.md#influence-sketch) hierarchy:
//! mutate chunk -> observe response -> retain implicated chunk -> subdivide.
//! The Phase-0 form is position selection restricted to the mask; Phase 2
//! adds the hierarchical perturbation driver that produces the masks.

use super::bytes;
use super::{MutationInput, MutationOutput};
use crate::error::Result;

/// Mutate a byte at a position restricted to the influence region.
///
/// Semantics: equivalent to [`bytes::byte_flip`] with the position drawn
/// uniformly from the mutable indices. With no mask, behaves exactly like
/// `byte_flip` (uniform over the whole input). An empty mutable region is a
/// deterministic no-op.
pub fn region(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    match bytes::mutable_indices(input.parent, input.influence)? {
        None => bytes::byte_flip(input),
        Some(indices) => {
            if indices.is_empty() {
                return Ok(MutationOutput {
                    bytes: input.parent.to_vec(),
                    changed: false,
                });
            }
            let idx = indices[input.rng.gen_index(indices.len())];
            let mut out = input.parent.to_vec();
            out[idx] = input.rng.gen_byte();
            Ok(MutationOutput {
                changed: true,
                bytes: out,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::prng::CounterRng;

    #[test]
    fn restricted_to_mask() {
        let parent = b"abcdef";
        let mask = [0u8, 0, 1, 1, 0, 0]; // only positions 2,3 mutable
        let mut rng = CounterRng::from_philox([13, 0, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &[],
            splice_partner: None,
            influence: Some(&mask),
        };
        for _ in 0..64 {
            let out = region(&mut input).unwrap();
            assert_eq!(out.bytes.len(), parent.len());
            assert!(out.changed);
            // Only positions 2,3 may differ.
            assert_eq!(&out.bytes[..2], &parent[..2]);
            assert_eq!(&out.bytes[4..], &parent[4..]);
        }
    }

    #[test]
    fn empty_mask_is_noop() {
        let parent = b"abcdef";
        let mask = [0u8; 6];
        let mut rng = CounterRng::from_philox([13, 0, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &[],
            splice_partner: None,
            influence: Some(&mask),
        };
        let out = region(&mut input).unwrap();
        assert_eq!(out.bytes, parent);
        assert!(!out.changed);
    }

    #[test]
    fn no_mask_equals_byte_flip() {
        let parent = b"abcdefghij";
        let mut rng = CounterRng::from_philox([13, 1, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &[],
            splice_partner: None,
            influence: None,
        };
        let a = region(&mut input).unwrap();

        let mut rng = CounterRng::from_philox([13, 1, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &[],
            splice_partner: None,
            influence: None,
        };
        let b = bytes::byte_flip(&mut input).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mask_length_mismatch_is_error() {
        let parent = b"abcdef";
        let mask = [0u8; 3];
        let mut rng = CounterRng::from_philox([13, 0, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &[],
            splice_partner: None,
            influence: Some(&mask),
        };
        assert!(region(&mut input).is_err());
    }
}
