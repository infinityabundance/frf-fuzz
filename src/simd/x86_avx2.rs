//! AVX2 implementations of the SIMD-friendly operations.
//!
//! # Safety policy
//!
//! This is an approved unsafe zone (docs/INVARIANTS.md, "unsafe policy").
//! Every function is `#[target_feature(enable = "avx2")]` (callable only
//! inside an `unsafe` block) and every intrinsic call is wrapped in an
//! explicit `unsafe {}` block with a `// SAFETY:` comment stating the exact
//! invariant. The dominant invariant is: the caller guarantees AVX2 via
//! `is_x86_feature_detected!`, and each function reads/writes only within
//! slice bounds because the tail is always handled by a scalar loop.
//!
//! The scalar implementations in [`super::scalar`] are normative; every
//! function here must be bit-for-bit identical to its scalar counterpart.

#![allow(unsafe_code)]
// `unused_unsafe` fires inside `unsafe fn` bodies for the explicit blocks
// that `deny(unsafe_op_in_unsafe_fn)` requires; its opinion is inverted here.
#![allow(unused_unsafe)]

use core::arch::x86_64::*;

/// Sum of per-byte popcounts of a 32-byte vector, via the nibble-lookup
/// trick (the only portable AVX2 byte-popcount; `_mm256_popcnt_epi8` needs
/// AVX512BITALG).
///
/// # Safety
///
/// Requires AVX2 (caller invariant). Operates only on the vector value; no
/// memory access.
unsafe fn byte_popcount_sum(v: __m256i) -> u32 {
    // SAFETY: caller guarantees AVX2.
    let lookup = unsafe {
        _mm256_setr_epi8(
            0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2,
            3, 3, 4,
        )
    };
    let lo = unsafe { _mm256_and_si256(v, _mm256_set1_epi8(0x0F)) };
    let hi = unsafe { _mm256_and_si256(_mm256_srli_epi16(v, 4), _mm256_set1_epi8(0x0F)) };
    // SAFETY: shuffle with the 16-entry lookup table; indices are masked to
    // 4 bits by construction (lo/hi nibbles).
    let pc = unsafe {
        _mm256_add_epi8(
            _mm256_shuffle_epi8(lookup, lo),
            _mm256_shuffle_epi8(lookup, hi),
        )
    };
    // SAFETY: 4 u64 lanes, each the sum of one 8-byte group (<= 8*8 = 64,
    // no overflow in the byte adds since each byte <= 8).
    let sums = unsafe { _mm256_sad_epu8(pc, _mm256_setzero_si256()) };
    let mut arr = [0u64; 4];
    // SAFETY: `arr` is 4 u64s = 32 bytes, exactly one __m256i.
    unsafe { _mm256_storeu_si256(arr.as_mut_ptr() as *mut __m256i, sums) };
    (arr[0] + arr[1] + arr[2] + arr[3]) as u32
}

/// Count nonzero bytes.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn count_nonzero_avx2(data: &[u8]) -> u32 {
    let mut total = 0u32;
    let mut i = 0usize;
    // SAFETY: we load 32-byte vectors only while `i + 32 <= data.len()`, so
    // every load address is in-bounds. The zero vector is a compile-time
    // constant.
    while i + 32 <= data.len() {
        let v = unsafe { _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i) };
        let eq = unsafe { _mm256_cmpeq_epi8(v, _mm256_setzero_si256()) };
        let mask = unsafe { _mm256_movemask_epi8(eq) } as u32;
        total += 32 - mask.count_ones();
        i += 32;
    }
    // Tail: scalar, so the result is exact for any length.
    for b in &data[i..] {
        total += u32::from(*b != 0);
    }
    total
}

/// Zero every byte.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn clear_avx2(data: &mut [u8]) {
    let mut i = 0usize;
    // SAFETY: we store 32-byte vectors only while `i + 32 <= len`; the tail
    // is zeroed by the scalar loop below. Never writes beyond the slice.
    while i + 32 <= data.len() {
        unsafe {
            _mm256_storeu_si256(
                data.as_mut_ptr().add(i) as *mut __m256i,
                _mm256_setzero_si256(),
            );
        }
        i += 32;
    }
    for b in &mut data[i..] {
        *b = 0;
    }
}

/// Write indices of nonzero bytes into `out`, returning the count written.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn nonzero_indices_avx2(data: &[u8], out: &mut [u32]) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    // SAFETY: 32-byte loads only within `data.len()`; writes to `out` only
    // while `n < out.len()` (we stop and return otherwise).
    while i + 32 <= data.len() {
        let v = unsafe { _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i) };
        let eq = unsafe { _mm256_cmpeq_epi8(v, _mm256_setzero_si256()) };
        let mut mask = !unsafe { _mm256_movemask_epi8(eq) } as u32;
        while mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            if n >= out.len() {
                return n;
            }
            out[n] = (i + bit) as u32;
            n += 1;
            mask &= mask - 1;
        }
        i += 32;
    }
    for (j, b) in data[i..].iter().enumerate() {
        if *b != 0 {
            if n >= out.len() {
                break;
            }
            out[n] = (i + j) as u32;
            n += 1;
        }
    }
    n
}

/// Zero all nonzero bytes; return the count zeroed.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn clear_nonzero_avx2(data: &mut [u8]) -> u32 {
    let mut total = 0u32;
    let mut i = 0usize;
    // SAFETY: 32-byte loads and stores only within `data.len()`; tail below.
    while i + 32 <= data.len() {
        let v = unsafe { _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i) };
        let eq = unsafe { _mm256_cmpeq_epi8(v, _mm256_setzero_si256()) };
        let mask = unsafe { _mm256_movemask_epi8(eq) } as u32;
        total += 32 - mask.count_ones();
        // Zeroing the whole chunk is equivalent to zeroing only the nonzero
        // bytes (zero bytes are already zero).
        unsafe {
            _mm256_storeu_si256(
                data.as_mut_ptr().add(i) as *mut __m256i,
                _mm256_setzero_si256(),
            );
        }
        i += 32;
    }
    for b in &mut data[i..] {
        if *b != 0 {
            *b = 0;
            total += 1;
        }
    }
    total
}

/// Count bits set in `cur` but not in `prev`. **Bit-level** semantics (each
/// byte may contribute 0..=8), matching the scalar reference exactly.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn count_newly_set_avx2(prev: &[u8], cur: &[u8]) -> u32 {
    debug_assert_eq!(prev.len(), cur.len());
    let mut total = 0u32;
    let mut i = 0usize;
    // SAFETY: equal-length slices; 32-byte reads only within bounds.
    while i + 32 <= cur.len() {
        let p = unsafe { _mm256_loadu_si256(prev.as_ptr().add(i) as *const __m256i) };
        let c = unsafe { _mm256_loadu_si256(cur.as_ptr().add(i) as *const __m256i) };
        let new_bits = unsafe { _mm256_andnot_si256(p, c) };
        // SAFETY: byte_popcount_sum requires AVX2 (guaranteed by the caller
        // of this function, which is itself target_feature-gated).
        total += unsafe { byte_popcount_sum(new_bits) };
        i += 32;
    }
    for (p, c) in prev[i..].iter().zip(cur[i..].iter()) {
        total += (c & !p).count_ones();
    }
    total
}

/// `dst |= src`.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn merge_into_avx2(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    let mut i = 0usize;
    // SAFETY: equal-length slices; 32-byte load/store only within bounds.
    while i + 32 <= dst.len() {
        let d = unsafe { _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i) };
        let s = unsafe { _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i) };
        let m = unsafe { _mm256_or_si256(d, s) };
        unsafe { _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, m) };
        i += 32;
    }
    for (d, s) in dst[i..].iter_mut().zip(src[i..].iter()) {
        *d |= s;
    }
}

/// `dst ^= src`.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn xor_into_avx2(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    let mut i = 0usize;
    // SAFETY: equal-length slices; 32-byte load/store only within bounds.
    while i + 32 <= dst.len() {
        let d = unsafe { _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i) };
        let s = unsafe { _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i) };
        let m = unsafe { _mm256_xor_si256(d, s) };
        unsafe { _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, m) };
        i += 32;
    }
    for (d, s) in dst[i..].iter_mut().zip(src[i..].iter()) {
        *d ^= s;
    }
}

/// Count set bits in a bitmap. **Bit-level** semantics (each byte may
/// contribute 0..=8), matching the scalar reference exactly.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn popcount_avx2(data: &[u8]) -> u32 {
    let mut total = 0u32;
    let mut i = 0usize;
    // SAFETY: 32-byte reads only within bounds; tail scalar.
    while i + 32 <= data.len() {
        let v = unsafe { _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i) };
        // SAFETY: byte_popcount_sum requires AVX2 (guaranteed by the caller
        // of this function, which is itself target_feature-gated).
        total += unsafe { byte_popcount_sum(v) };
        i += 32;
    }
    for b in &data[i..] {
        total += b.count_ones();
    }
    total
}

/// Index of the first differing byte, or `None`.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn first_mismatch_avx2(a: &[u8], b: &[u8]) -> Option<usize> {
    debug_assert_eq!(a.len(), b.len());
    let mut i = 0usize;
    // SAFETY: equal-length slices; 32-byte reads only within bounds.
    while i + 32 <= a.len() {
        let x = unsafe { _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i) };
        let y = unsafe { _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i) };
        let diff = unsafe { _mm256_xor_si256(x, y) };
        let eq = unsafe { _mm256_cmpeq_epi8(diff, _mm256_setzero_si256()) };
        let mask = unsafe { _mm256_movemask_epi8(eq) } as u32;
        if mask != 0xFFFF_FFFF {
            let first_diff = (!mask).trailing_zeros() as usize;
            return Some(i + first_diff);
        }
        i += 32;
    }
    for (j, (x, y)) in a[i..].iter().zip(b[i..].iter()).enumerate() {
        if x != y {
            return Some(i + j);
        }
    }
    None
}

/// Index of the last differing byte, or `None`.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn last_mismatch_avx2(a: &[u8], b: &[u8]) -> Option<usize> {
    debug_assert_eq!(a.len(), b.len());
    // Tail first (from the end), then whole 32-byte chunks from the end, so
    // the first mismatch found walking backwards is the last mismatch.
    let mut i = a.len() - (a.len() % 32);
    for (j, (x, y)) in a[i..].iter().zip(b[i..].iter()).enumerate().rev() {
        if x != y {
            return Some(i + j);
        }
    }
    // SAFETY: i is a multiple of 32 and the loop guard keeps i >= 32, so the
    // chunk loads are always in-bounds.
    while i >= 32 {
        i -= 32;
        let x = unsafe { _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i) };
        let y = unsafe { _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i) };
        let diff = unsafe { _mm256_xor_si256(x, y) };
        let eq = unsafe { _mm256_cmpeq_epi8(diff, _mm256_setzero_si256()) };
        let mask = unsafe { _mm256_movemask_epi8(eq) } as u32;
        if mask != 0xFFFF_FFFF {
            let last_diff = 31 - (!mask).leading_zeros() as usize;
            return Some(i + last_diff);
        }
    }
    None
}

/// Count differing bytes.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn mismatch_count_avx2(a: &[u8], b: &[u8]) -> u32 {
    debug_assert_eq!(a.len(), b.len());
    let mut total = 0u32;
    let mut i = 0usize;
    // SAFETY: equal-length slices; 32-byte reads only within bounds.
    while i + 32 <= a.len() {
        let x = unsafe { _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i) };
        let y = unsafe { _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i) };
        let diff = unsafe { _mm256_xor_si256(x, y) };
        let eq = unsafe { _mm256_cmpeq_epi8(diff, _mm256_setzero_si256()) };
        let mask = unsafe { _mm256_movemask_epi8(eq) } as u32;
        total += 32 - mask.count_ones();
        i += 32;
    }
    for (x, y) in a[i..].iter().zip(b[i..].iter()) {
        total += u32::from(x != y);
    }
    total
}

/// Coarse presence mask: `out[i]` bit `j` is set iff any byte in mini-chunk
/// `i*64 + j` (8 bytes each) is nonzero.
///
/// # Safety
///
/// The caller must guarantee AVX2 availability (the public API gates on
/// `is_x86_feature_detected!`) and in-bounds slices (tails are handled by
/// scalar fallbacks).
#[target_feature(enable = "avx2")]
pub unsafe fn chunk_present_mask_avx2(data: &[u8], out: &mut [u64]) {
    for slot in out.iter_mut() {
        *slot = 0;
    }
    let mut i = 0usize;
    // SAFETY: 32-byte reads only within `data.len()`; bit index arithmetic is
    // bounded by the caller contract (out.len()*512 >= data.len()).
    while i + 32 <= data.len() {
        let v = unsafe { _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i) };
        let eq = unsafe { _mm256_cmpeq_epi8(v, _mm256_setzero_si256()) };
        let mask = unsafe { _mm256_movemask_epi8(eq) } as u32;
        let present = !mask;
        if present != 0 {
            for g in 0..4 {
                let group = ((present >> (g * 8)) & 0xFF) as u8;
                if group != 0 {
                    let byte_idx = i + g * 8;
                    let slot = byte_idx / (64 * 8);
                    if slot >= out.len() {
                        break;
                    }
                    let bit = (byte_idx % (64 * 8)) / 8;
                    out[slot] |= 1u64 << bit;
                }
            }
        }
        i += 32;
    }
    for (j, b) in data[i..].iter().enumerate() {
        if *b != 0 {
            let byte_idx = i + j;
            let slot = byte_idx / (64 * 8);
            if slot >= out.len() {
                break;
            }
            let bit = (byte_idx % (64 * 8)) / 8;
            out[slot] |= 1u64 << bit;
        }
    }
}
