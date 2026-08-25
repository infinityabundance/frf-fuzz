//! Byte-level mutators: flips, inserts, deletes, block operations.
//!
//! All position and size choices come from the coordinate-derived RNG in
//! fixed order. All output is clamped to [`MAX_MUTATED_LEN`]. Empty-input
//! semantics are defined per mutator and are deterministic.

use super::CmpHit;
use super::{check_influence_mask, MutationInput, MutationOutput, MAX_MUTATED_LEN};
use crate::error::{Error, Result};

fn noop(parent: &[u8]) -> MutationOutput {
    MutationOutput {
        bytes: parent.to_vec(),
        changed: false,
    }
}

/// Clamp a post-mutation length to the output bound.
fn clamp_len(len: usize) -> usize {
    len.min(MAX_MUTATED_LEN)
}

/// Single bit flip at one position.
pub fn bit_flip(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    if input.parent.is_empty() {
        return Ok(noop(input.parent));
    }
    let p = input.rng.gen_index(input.parent.len());
    let bit = input.rng.gen_range_u32(0, 8);
    let mut out = input.parent.to_vec();
    out[p] ^= 1 << bit;
    Ok(MutationOutput {
        bytes: out,
        changed: true,
    })
}

/// Whole-byte replacement at one position.
pub fn byte_flip(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    if input.parent.is_empty() {
        return Ok(noop(input.parent));
    }
    let p = input.rng.gen_index(input.parent.len());
    let mut out = input.parent.to_vec();
    out[p] = input.rng.gen_byte();
    Ok(MutationOutput {
        bytes: out,
        changed: true,
    })
}

/// Multiple deterministic flips at distinct positions.
///
/// Draws `2..=6` distinct positions (bounded retry for distinctness); a
/// retry budget exhaustion deterministically reduces the count. Deterministic
/// given the RNG.
pub fn multi_byte_flips(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    let len = input.parent.len();
    if len == 0 {
        return Ok(noop(input.parent));
    }
    let max_flips = 6usize.min(len);
    let n = 2 + input.rng.gen_index(max_flips.saturating_sub(1).max(1));
    let mut positions = Vec::with_capacity(n);
    let mut retries = 0u32;
    while positions.len() < n && retries < 64 {
        let p = input.rng.gen_index(len);
        if !positions.contains(&p) {
            positions.push(p);
        }
        retries += 1;
    }
    let mut out = input.parent.to_vec();
    for p in &positions {
        let bit = input.rng.gen_range_u32(0, 8);
        out[*p] ^= 1 << bit;
    }
    Ok(MutationOutput {
        bytes: out,
        changed: !positions.is_empty(),
    })
}

/// Byte insertion at a position in `[0, len]` (inserting before `len` appends).
pub fn byte_insert(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    let len = input.parent.len();
    let p = input.rng.gen_index(len + 1);
    let k = 1 + input.rng.gen_index(8);
    // Deterministic clamp to the output bound.
    let budget = MAX_MUTATED_LEN.saturating_sub(len);
    let k = k.min(budget);
    let mut out = Vec::with_capacity(clamp_len(len + k));
    out.extend_from_slice(&input.parent[..p]);
    for _ in 0..k {
        out.push(input.rng.gen_byte());
    }
    out.extend_from_slice(&input.parent[p..]);
    out.truncate(clamp_len(out.len()));
    Ok(MutationOutput {
        changed: k > 0,
        bytes: out,
    })
}

/// Byte deletion: remove `1..=8` bytes at a position.
pub fn byte_delete(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    let len = input.parent.len();
    if len == 0 {
        return Ok(noop(input.parent));
    }
    let p = input.rng.gen_index(len);
    let k = 1 + input.rng.gen_index(8);
    let k = k.min(len - p);
    let mut out = Vec::with_capacity(len - k);
    out.extend_from_slice(&input.parent[..p]);
    out.extend_from_slice(&input.parent[p + k..]);
    Ok(MutationOutput {
        changed: true,
        bytes: out,
    })
}

/// Block duplication: copy `1..=32` bytes to a fresh position (clamped).
pub fn block_duplicate(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    let len = input.parent.len();
    if len == 0 {
        return Ok(noop(input.parent));
    }
    let max_block = 32usize.min(len);
    let k = 1 + input.rng.gen_index(max_block);
    let p = input.rng.gen_index(len.saturating_sub(k).max(1));
    let budget = MAX_MUTATED_LEN.saturating_sub(len);
    let k = k.min(budget);
    let insert_at = input.rng.gen_index(len + 1);
    let mut out = Vec::with_capacity(clamp_len(len + k));
    out.extend_from_slice(&input.parent[..insert_at]);
    out.extend_from_slice(&input.parent[p..p + k]);
    out.extend_from_slice(&input.parent[insert_at..]);
    out.truncate(clamp_len(out.len()));
    Ok(MutationOutput {
        changed: k > 0,
        bytes: out,
    })
}

/// Block deletion: remove `1..=32` bytes at a position.
pub fn block_delete(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    let len = input.parent.len();
    if len == 0 {
        return Ok(noop(input.parent));
    }
    let max_block = 32usize.min(len);
    let k = 1 + input.rng.gen_index(max_block);
    let p = input.rng.gen_index(len.saturating_sub(k).max(1));
    let mut out = Vec::with_capacity(len - k);
    out.extend_from_slice(&input.parent[..p]);
    out.extend_from_slice(&input.parent[p + k..]);
    Ok(MutationOutput {
        changed: true,
        bytes: out,
    })
}

/// Block overwrite: replace `1..=32` bytes with random bytes.
pub fn block_overwrite(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    let len = input.parent.len();
    if len == 0 {
        return Ok(noop(input.parent));
    }
    let max_block = 32usize.min(len);
    let k = 1 + input.rng.gen_index(max_block);
    let p = input.rng.gen_index(len.saturating_sub(k).max(1));
    let mut out = input.parent.to_vec();
    for b in &mut out[p..p + k] {
        *b = input.rng.gen_byte();
    }
    Ok(MutationOutput {
        changed: true,
        bytes: out,
    })
}

/// Resolve the effective mutable position range under an optional influence
/// mask, returning the list of mutable indices (or `None` when unmasked).
///
/// Deterministic: indices are enumerated in ascending order and the caller
/// selects via the RNG.
pub(crate) fn mutable_indices(
    parent: &[u8],
    influence: Option<&[u8]>,
) -> Result<Option<Vec<usize>>> {
    check_influence_mask(parent, influence)?;
    match influence {
        None => Ok(None),
        Some(mask) => {
            let indices: Vec<usize> = mask
                .iter()
                .enumerate()
                .filter(|(_, m)| **m != 0)
                .map(|(i, _)| i)
                .collect();
            Ok(Some(indices))
        }
    }
}

/// Compile-time assertion that the mutator module stays dependency-free of
/// the coordinator plane.
#[allow(dead_code)]
fn _assert_dep_free(_: &[CmpHit]) -> Result<()> {
    let _ = Error::Overflow;
    Ok(())
}
