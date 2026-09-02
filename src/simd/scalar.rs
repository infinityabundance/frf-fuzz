//! Normative scalar implementations of the SIMD-friendly operations.
//!
//! These define the semantics. Every accelerated path must be bit-for-bit
//! identical (docs/INVARIANTS.md, I3). Keep this file free of unsafe.

/// Count nonzero bytes.
pub fn count_nonzero(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, b| acc + u32::from(*b != 0))
}

/// Zero every byte.
pub fn clear(data: &mut [u8]) {
    data.fill(0);
}

/// Write indices of nonzero bytes into `out`, returning the count written.
pub fn nonzero_indices(data: &[u8], out: &mut [u32]) -> usize {
    let mut n = 0usize;
    for (i, b) in data.iter().enumerate() {
        if *b != 0 {
            if n >= out.len() {
                break;
            }
            out[n] = i as u32;
            n += 1;
        }
    }
    n
}

/// Zero all nonzero bytes; return the count zeroed.
pub fn clear_nonzero(data: &mut [u8]) -> u32 {
    let mut n = 0u32;
    for b in data.iter_mut() {
        if *b != 0 {
            *b = 0;
            n += 1;
        }
    }
    n
}

/// Scan-and-clear: write the byte offsets of every nonzero byte of `data`
/// (OR-ed with `base`) into `out` in ascending offset order, and CLEAR every
/// nonzero byte. All-zero bytes are left untouched (they are already zero).
///
/// This is the per-execution coverage consume operation (sancov
/// `scan_and_clear`) expressed over one contiguous slice. Returns the number
/// of offsets written and whether the output buffer saturated (a nonzero
/// byte was seen after `out` filled; the data was STILL cleared — a consume
/// never leaks into the next window). Saturation is reported, never silently
/// truncated.
///
/// The scalar implementation is NORMATIVE; the AVX2 path must be bit-for-bit
/// identical (docs/INVARIANTS.md, I3).
pub fn scan_nonzero_clear(data: &mut [u8], base: u64, out: &mut [u64]) -> (u32, bool) {
    let cap = out.len();
    let mut n = 0usize;
    let mut saturated = false;
    for (j, c) in data.iter_mut().enumerate() {
        if *c != 0 {
            if n < cap {
                out[n] = base | (j as u64);
                n += 1;
            } else {
                saturated = true;
            }
            *c = 0;
        }
    }
    (n as u32, saturated)
}

/// Count bits set in `cur` but not in `prev`.
pub fn count_newly_set(prev: &[u8], cur: &[u8]) -> u32 {
    debug_assert_eq!(prev.len(), cur.len());
    prev.iter()
        .zip(cur.iter())
        .fold(0u32, |acc, (p, c)| acc + ((c & !p).count_ones()))
}

/// `dst |= src`.
pub fn merge_into(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d |= s;
    }
}

/// `dst ^= src`.
pub fn xor_into(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

/// Count set bits in a bitmap.
pub fn popcount(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, b| acc + b.count_ones())
}

/// Index of the first differing byte, or `None`.
pub fn first_mismatch(a: &[u8], b: &[u8]) -> Option<usize> {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).position(|(x, y)| x != y)
}

/// Index of the last differing byte, or `None`.
pub fn last_mismatch(a: &[u8], b: &[u8]) -> Option<usize> {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).rposition(|(x, y)| x != y)
}

/// Count differing bytes.
pub fn mismatch_count(a: &[u8], b: &[u8]) -> u32 {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .fold(0u32, |acc, (x, y)| acc + u32::from(x != y))
}

/// Coarse presence mask: `out[i]` bit `j` is set iff any byte in the chunk
/// group starting at `i * 64 + j * 8`... no: each bit of `out[i]` covers one
/// 8-byte mini-chunk (64 mini-chunks per u64 = 512 bytes per u64).
///
/// Contract: `out.len() * 64 * 8 >= data.len()`. Bytes beyond `data.len()`
/// within the last group are treated as zero.
pub fn chunk_present_mask(data: &[u8], out: &mut [u64]) {
    for slot in out.iter_mut() {
        *slot = 0;
    }
    for (i, b) in data.iter().enumerate() {
        if *b != 0 {
            let slot = i / (64 * 8);
            if slot >= out.len() {
                break;
            }
            let bit = (i % (64 * 8)) / 8;
            out[slot] |= 1u64 << bit;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_mask_semantics() {
        let data = [0u8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut out = [0u64; 1];
        chunk_present_mask(&data, &mut out);
        // Byte 3 is in mini-chunk 0 (bits 0..7), byte 15 in mini-chunk 1.
        assert_eq!(out[0], 0b11);
    }
}
