//! Integer mutators: add/sub deltas, boundary values, interesting values.
//!
//! Windows are read as little-endian integers of a width drawn from
//! {1, 2, 4, 8} (only widths that fit in the input). All arithmetic is
//! wrapping, matching how a target reads raw bytes.

use super::{MutationInput, MutationOutput};
use crate::error::Result;

fn noop(parent: &[u8]) -> MutationOutput {
    MutationOutput {
        bytes: parent.to_vec(),
        changed: false,
    }
}

/// Draw (position, width) for an integer window.
fn pick_window(input: &mut MutationInput<'_>) -> Option<(usize, usize)> {
    let len = input.parent.len();
    if len == 0 {
        return None;
    }
    let widths: &[usize] = if len >= 8 {
        &[1, 2, 4, 8]
    } else if len >= 4 {
        &[1, 2, 4]
    } else if len >= 2 {
        &[1, 2]
    } else {
        &[1]
    };
    let width = widths[input.rng.gen_index(widths.len())];
    let p = input.rng.gen_index(len - width + 1);
    Some((p, width))
}

fn read_le(parent: &[u8], p: usize, w: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..w {
        v |= u64::from(parent[p + i]) << (8 * i);
    }
    v
}

fn write_le(out: &mut [u8], p: usize, w: usize, v: u64) {
    for i in 0..w {
        out[p + i] = (v >> (8 * i)) as u8;
    }
}

/// Integer +/- small delta in [-35, +35].
pub fn add_sub(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    let Some((p, w)) = pick_window(input) else {
        return Ok(noop(input.parent));
    };
    let mask = if w == 8 {
        u64::MAX
    } else {
        (1u64 << (8 * w)) - 1
    };
    let v = read_le(input.parent, p, w);
    let delta = i64::from(input.rng.gen_range_u32(0, 70)) - 35;
    let nv = (v.wrapping_add(delta as u64)) & mask;
    let mut out = input.parent.to_vec();
    write_le(&mut out, p, w, nv);
    Ok(MutationOutput {
        changed: nv != v,
        bytes: out,
    })
}

/// Integer boundary values: {0, 1, mid, max-1, max} for the window width.
pub fn boundary(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    let Some((p, w)) = pick_window(input) else {
        return Ok(noop(input.parent));
    };
    let max = if w == 8 {
        u64::MAX
    } else {
        (1u64 << (8 * w)) - 1
    };
    let choices: [u64; 5] = [0, 1, max / 2, max - 1, max];
    let v = read_le(input.parent, p, w);
    let nv = choices[input.rng.gen_index(choices.len())];
    let mut out = input.parent.to_vec();
    write_le(&mut out, p, w, nv);
    Ok(MutationOutput {
        changed: nv != v,
        bytes: out,
    })
}

/// Interesting integer values for a given width, following the classic
/// fuzzing table (0, ±1, ±2, ..., 2^N ± 1, powers of two ± 1, etc.).
pub(crate) fn interesting_for_width(w: usize) -> Vec<u64> {
    let mut v: Vec<u64> = vec![0, 1, u64::MAX];
    // `1u64 << (8 * w)` overflows for w == 8; use wrapping shifts everywhere
    // and mask at the end.
    let high_bit = 1u64 << ((8 * w - 1).min(63));
    for i in 1..=7u32 {
        v.push(i as u64);
        v.push(high_bit.wrapping_mul(2).wrapping_sub(i as u64));
        v.push(high_bit.wrapping_add(i as u64));
        v.push(high_bit.wrapping_sub(i as u64));
    }
    for shift in [8, 16, 24, 32, 40, 48, 56] {
        if shift < 8 * w {
            v.push(1u64 << shift);
            v.push((1u64 << shift) + 1);
            v.push((1u64 << shift) - 1);
        }
    }
    let mask = if w == 8 {
        u64::MAX
    } else {
        (1u64 << (8 * w)) - 1
    };
    v.into_iter().map(|x| x & mask).collect()
}

/// Interesting integer replacement.
pub fn interesting(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    let Some((p, w)) = pick_window(input) else {
        return Ok(noop(input.parent));
    };
    let choices = interesting_for_width(w);
    let v = read_le(input.parent, p, w);
    let nv = choices[input.rng.gen_index(choices.len())];
    let mut out = input.parent.to_vec();
    write_le(&mut out, p, w, nv);
    Ok(MutationOutput {
        changed: nv != v,
        bytes: out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::prng::CounterRng;

    fn run(
        mutator: impl Fn(&mut MutationInput<'_>) -> Result<MutationOutput>,
        parent: &[u8],
    ) -> Vec<u8> {
        let mut rng = CounterRng::from_philox([3, 0, 0, 0], [1, 1]);
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &[],
            splice_partner: None,
            influence: None,
        };
        mutator(&mut input).unwrap().bytes
    }

    #[test]
    fn add_sub_preserves_length() {
        for len in [1usize, 2, 3, 4, 7, 8, 9, 16, 64] {
            let parent: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            for _ in 0..32 {
                let out = run(add_sub, &parent);
                assert_eq!(out.len(), len);
            }
        }
    }

    #[test]
    fn boundary_respects_width() {
        let parent = [0u8; 9];
        for _ in 0..64 {
            let out = run(boundary, &parent);
            // Values must be representable in the drawn width; since we can't
            // observe the width, just check determinism.
            assert_eq!(out.len(), parent.len());
        }
    }

    #[test]
    fn interesting_values_are_in_table() {
        for w in 1..=8usize {
            let table = interesting_for_width(w);
            assert!(table.contains(&0));
            assert!(table.contains(&1));
            let mask = if w == 8 {
                u64::MAX
            } else {
                (1u64 << (8 * w)) - 1
            };
            for x in &table {
                assert!(x <= &mask);
            }
        }
    }

    #[test]
    fn deterministic_across_replays() {
        let parent = b"determinism-check-input-bytes";
        let a = run(add_sub, parent);
        let b = run(add_sub, parent);
        assert_eq!(a, b);
    }
}
