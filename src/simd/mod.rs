//! SIMD-accelerated byte/bitmap operations.
//!
//! The scalar implementations in this module are NORMATIVE: every accelerated
//! path must produce bit-for-bit identical results
//! (docs/INVARIANTS.md, I3). AVX2 is an optimization only.
//!
//! The operations here are the ones the engine actually needs (docs §10):
//!
//! * coverage counter scan (nonzero detection + clear)
//! * novelty bitmap comparison and merge
//! * first/last mismatch localization
//! * XOR residual masks
//! * byte equality/difference and fixed-width morphology distance
//! * population-style chunk statistics
//! * fixed-size signature comparison
//!
//! We deliberately do NOT attempt to vectorize arbitrary target execution;
//! these are all bounded, SIMD-friendly, deterministic transformations.
//!
//! # Approved unsafe zone
//!
//! This module is part of the AVX2 unsafe zone: the runtime-dispatch calls
//! into [`x86_avx2`] are `unsafe fn` calls, each guarded by
//! `is_x86_feature_detected!("avx2")` with a `// SAFETY:` comment. The
//! scalar implementations themselves are safe.

#![allow(unsafe_code)]

pub mod scalar;
#[cfg(target_arch = "x86_64")]
pub mod x86_avx2;

use crate::error::Result;

/// Count nonzero bytes. Scalar semantics are normative.
pub fn count_nonzero(data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by the runtime CPUID check; the AVX2 path is only
        // entered when the feature is available, and it never reads beyond
        // `data` (the tail is handled by the scalar fallback inside).
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { x86_avx2::count_nonzero_avx2(data) };
        }
    }
    scalar::count_nonzero(data)
}

/// Zero every byte of `data`.
pub fn clear(data: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by runtime detection; writes exactly `data.len()`
        // bytes (full 32-byte chunks vectorized, remainder scalar).
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { x86_avx2::clear_avx2(data) };
        }
    }
    scalar::clear(data)
}

/// Write the indices of nonzero bytes into `out` (in ascending order),
/// returning the count. The caller must ensure `out` has capacity for at
/// least `count_nonzero(data)` entries; if `out` is too small the scan stops
/// early and returns the number written (the caller can grow and retry).
pub fn nonzero_indices(data: &[u8], out: &mut [u32]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by runtime detection; reads exactly `data.len()`
        // bytes and writes at most `out.len()` entries.
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { x86_avx2::nonzero_indices_avx2(data, out) };
        }
    }
    scalar::nonzero_indices(data, out)
}

/// Zero all nonzero bytes; returns the number zeroed.
pub fn clear_nonzero(data: &mut [u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by runtime detection; reads+writes exactly
        // `data.len()` bytes.
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { x86_avx2::clear_nonzero_avx2(data) };
        }
    }
    scalar::clear_nonzero(data)
}

/// Count bits set in `cur` but not in `prev` (novelty of a bitmap).
pub fn count_newly_set(prev: &[u8], cur: &[u8]) -> Result<u32> {
    check_same_len(prev, cur)?;
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by runtime detection; both slices have equal length.
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { Ok(x86_avx2::count_newly_set_avx2(prev, cur)) };
        }
    }
    Ok(scalar::count_newly_set(prev, cur))
}

/// `dst |= src` (bitwise or) for equal-length slices.
pub fn merge_into(dst: &mut [u8], src: &[u8]) -> Result<()> {
    check_same_len(dst, src)?;
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by the runtime CPUID check above; equal-length
        // slices.
        if std::arch::is_x86_feature_detected!("avx2") {
            unsafe { x86_avx2::merge_into_avx2(dst, src) };
            return Ok(());
        }
    }
    scalar::merge_into(dst, src);
    Ok(())
}

/// `dst ^= src` (bitwise xor) for equal-length slices.
pub fn xor_into(dst: &mut [u8], src: &[u8]) -> Result<()> {
    check_same_len(dst, src)?;
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by the runtime CPUID check above; equal-length
        // slices.
        if std::arch::is_x86_feature_detected!("avx2") {
            unsafe { x86_avx2::xor_into_avx2(dst, src) };
            return Ok(());
        }
    }
    scalar::xor_into(dst, src);
    Ok(())
}

/// Count set bits in a bitmap.
pub fn popcount(data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by runtime detection; reads exactly `data.len()`.
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { x86_avx2::popcount_avx2(data) };
        }
    }
    scalar::popcount(data)
}

/// Index of the first differing byte, or `None` if equal.
pub fn first_mismatch(a: &[u8], b: &[u8]) -> Result<Option<usize>> {
    check_same_len(a, b)?;
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by runtime detection; equal-length slices.
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { Ok(x86_avx2::first_mismatch_avx2(a, b)) };
        }
    }
    Ok(scalar::first_mismatch(a, b))
}

/// Index of the last differing byte, or `None` if equal.
pub fn last_mismatch(a: &[u8], b: &[u8]) -> Result<Option<usize>> {
    check_same_len(a, b)?;
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by runtime detection; equal-length slices.
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { Ok(x86_avx2::last_mismatch_avx2(a, b)) };
        }
    }
    Ok(scalar::last_mismatch(a, b))
}

/// Count differing bytes (fixed-width morphology distance).
pub fn mismatch_count(a: &[u8], b: &[u8]) -> Result<u32> {
    check_same_len(a, b)?;
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by runtime detection; equal-length slices.
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { Ok(x86_avx2::mismatch_count_avx2(a, b)) };
        }
    }
    Ok(scalar::mismatch_count(a, b))
}

/// For each 64-byte-chunk group, set one bit in `out[i]` if any byte in that
/// chunk group is nonzero. `out.len() * 64 >= data.len()` must hold. This is
/// the coarse presence mask used to reject novelty quickly.
pub fn chunk_present_mask(data: &[u8], out: &mut [u64]) {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: guarded by runtime detection; writes exactly `out.len()`
        // u64s, reads only `data.len()` bytes.
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { x86_avx2::chunk_present_mask_avx2(data, out) };
        }
    }
    scalar::chunk_present_mask(data, out)
}

/// Byte-exact equality of two fixed-size signatures.
pub fn signature_eq(a: &[u8], b: &[u8]) -> Result<bool> {
    Ok(first_mismatch(a, b)?.is_none())
}

/// Length of the common prefix (number of equal leading bytes).
pub fn signature_diff_prefix(a: &[u8], b: &[u8]) -> Result<usize> {
    Ok(first_mismatch(a, b)?.unwrap_or(a.len().min(b.len())))
}

fn check_same_len(a: &[u8], b: &[u8]) -> Result<()> {
    if a.len() != b.len() {
        return Err(crate::error::Error::Encoding(
            "simd operation requires equal-length slices",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic LCG for property-test input generation.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn byte(&mut self) -> u8 {
            (self.next() >> 32) as u8
        }
    }

    fn sizes() -> Vec<usize> {
        // Boundary + adversarial sizes: empty, small, chunk-aligned,
        // chunk-aligned +/-1, and large.
        vec![
            0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
            511, 512, 513, 1023, 1024, 1025, 4096, 4097,
        ]
    }

    fn pattern_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut lcg = Lcg(seed);
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push(lcg.byte());
        }
        v
    }

    #[cfg(target_arch = "x86_64")]
    fn avx2_available() -> bool {
        std::arch::is_x86_feature_detected!("avx2")
    }

    #[test]
    fn scalar_matches_avx2_count_nonzero() {
        #[cfg(target_arch = "x86_64")]
        if !avx2_available() {
            return;
        }
        for len in sizes() {
            for seed in [0u64, 1, 0xDEAD, 0xFFFF_FFFF_FFFF_FFFF] {
                let data = pattern_bytes(seed, len);
                let s = scalar::count_nonzero(&data);
                #[cfg(target_arch = "x86_64")]
                let v = unsafe { x86_avx2::count_nonzero_avx2(&data) };
                #[cfg(not(target_arch = "x86_64"))]
                let v = s;
                assert_eq!(s, v, "count_nonzero len={len} seed={seed:#x}");
            }
        }
        // Adversarial: all-zero, all-0xff, alternating.
        for len in sizes() {
            let all0 = vec![0u8; len];
            let allf = vec![0xFFu8; len];
            let alt: Vec<u8> = (0..len)
                .map(|i| if i % 2 == 0 { 0 } else { 0xFF })
                .collect();
            for data in [&all0, &allf, &alt] {
                let s = scalar::count_nonzero(data);
                #[cfg(target_arch = "x86_64")]
                let v = unsafe { x86_avx2::count_nonzero_avx2(data) };
                #[cfg(not(target_arch = "x86_64"))]
                let v = s;
                assert_eq!(s, v);
            }
        }
    }

    #[test]
    fn scalar_matches_avx2_clear_and_nonzero_indices() {
        #[cfg(target_arch = "x86_64")]
        if !avx2_available() {
            return;
        }
        for len in sizes() {
            for seed in [0u64, 7, 0xCAFE] {
                let data = pattern_bytes(seed, len);
                // clear
                let mut a = data.clone();
                let mut b = data.clone();
                scalar::clear(&mut a);
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    x86_avx2::clear_avx2(&mut b)
                };
                #[cfg(not(target_arch = "x86_64"))]
                scalar::clear(&mut b);
                assert_eq!(a, b, "clear len={len}");

                // nonzero_indices
                let mut ia = vec![0u32; len + 1];
                let mut ib = vec![0u32; len + 1];
                let na = scalar::nonzero_indices(&data, &mut ia);
                #[cfg(target_arch = "x86_64")]
                let nb = unsafe { x86_avx2::nonzero_indices_avx2(&data, &mut ib) };
                #[cfg(not(target_arch = "x86_64"))]
                let nb = scalar::nonzero_indices(&data, &mut ib);
                assert_eq!(na, nb, "nonzero_indices count len={len}");
                assert_eq!(&ia[..na], &ib[..nb], "nonzero_indices list len={len}");

                // clear_nonzero returns the same count
                let mut ca = data.clone();
                let mut cb = data.clone();
                let sca = scalar::clear_nonzero(&mut ca);
                #[cfg(target_arch = "x86_64")]
                let scb = unsafe { x86_avx2::clear_nonzero_avx2(&mut cb) };
                #[cfg(not(target_arch = "x86_64"))]
                let scb = scalar::clear_nonzero(&mut cb);
                assert_eq!(sca, scb);
                assert_eq!(ca, cb);
            }
        }
    }

    #[test]
    fn scalar_matches_avx2_bitmap_ops() {
        #[cfg(target_arch = "x86_64")]
        if !avx2_available() {
            return;
        }
        for len in sizes() {
            let a = pattern_bytes(0x1111, len);
            let b = pattern_bytes(0x2222, len);
            let s_new = scalar::count_newly_set(&a, &b);
            #[cfg(target_arch = "x86_64")]
            let v_new = unsafe { x86_avx2::count_newly_set_avx2(&a, &b) };
            #[cfg(not(target_arch = "x86_64"))]
            let v_new = s_new;
            assert_eq!(s_new, v_new);

            let s_pop = scalar::popcount(&a);
            #[cfg(target_arch = "x86_64")]
            let v_pop = unsafe { x86_avx2::popcount_avx2(&a) };
            #[cfg(not(target_arch = "x86_64"))]
            let v_pop = s_pop;
            assert_eq!(s_pop, v_pop);

            let s_mm = scalar::mismatch_count(&a, &b);
            #[cfg(target_arch = "x86_64")]
            let v_mm = unsafe { x86_avx2::mismatch_count_avx2(&a, &b) };
            #[cfg(not(target_arch = "x86_64"))]
            let v_mm = s_mm;
            assert_eq!(s_mm, v_mm);

            let s_fm = scalar::first_mismatch(&a, &b);
            #[cfg(target_arch = "x86_64")]
            let v_fm = unsafe { x86_avx2::first_mismatch_avx2(&a, &b) };
            #[cfg(not(target_arch = "x86_64"))]
            let v_fm = s_fm;
            assert_eq!(s_fm, v_fm);

            let s_lm = scalar::last_mismatch(&a, &b);
            #[cfg(target_arch = "x86_64")]
            let v_lm = unsafe { x86_avx2::last_mismatch_avx2(&a, &b) };
            #[cfg(not(target_arch = "x86_64"))]
            let v_lm = s_lm;
            assert_eq!(s_lm, v_lm);

            // merge and xor
            let mut m1 = a.clone();
            let mut m2 = a.clone();
            scalar::merge_into(&mut m1, &b);
            #[cfg(target_arch = "x86_64")]
            unsafe {
                x86_avx2::merge_into_avx2(&mut m2, &b)
            };
            #[cfg(not(target_arch = "x86_64"))]
            scalar::merge_into(&mut m2, &b);
            assert_eq!(m1, m2);

            let mut x1 = a.clone();
            let mut x2 = a.clone();
            scalar::xor_into(&mut x1, &b);
            #[cfg(target_arch = "x86_64")]
            unsafe {
                x86_avx2::xor_into_avx2(&mut x2, &b)
            };
            #[cfg(not(target_arch = "x86_64"))]
            scalar::xor_into(&mut x2, &b);
            assert_eq!(x1, x2);
        }
    }

    #[test]
    fn scalar_matches_avx2_chunk_present_mask() {
        #[cfg(target_arch = "x86_64")]
        if !avx2_available() {
            return;
        }
        for len in sizes() {
            let data = pattern_bytes(0xABCD, len);
            let mut o1 = vec![0u64; len / 64 + 1];
            let mut o2 = vec![0u64; len / 64 + 1];
            scalar::chunk_present_mask(&data, &mut o1);
            #[cfg(target_arch = "x86_64")]
            unsafe {
                x86_avx2::chunk_present_mask_avx2(&data, &mut o2)
            };
            #[cfg(not(target_arch = "x86_64"))]
            scalar::chunk_present_mask(&data, &mut o2);
            assert_eq!(o1, o2, "chunk_present_mask len={len}");
        }
    }

    #[test]
    fn public_api_dispatch_is_consistent() {
        // The public API must equal the scalar reference regardless of the
        // active acceleration path.
        for len in sizes() {
            let a = pattern_bytes(0x7777, len);
            let b = pattern_bytes(0x8888, len);
            assert_eq!(count_nonzero(&a), scalar::count_nonzero(&a));
            let mut buf = vec![0u32; len + 1];
            assert_eq!(
                nonzero_indices(&a, &mut buf),
                scalar::nonzero_indices(&a, &mut buf.clone())
            );
            if !a.is_empty() {
                assert_eq!(
                    count_newly_set(&a, &b).unwrap(),
                    scalar::count_newly_set(&a, &b)
                );
                assert_eq!(
                    mismatch_count(&a, &b).unwrap(),
                    scalar::mismatch_count(&a, &b)
                );
                assert_eq!(
                    first_mismatch(&a, &b).unwrap(),
                    scalar::first_mismatch(&a, &b)
                );
                assert_eq!(
                    last_mismatch(&a, &b).unwrap(),
                    scalar::last_mismatch(&a, &b)
                );
            }
            let mut c1 = a.clone();
            let mut c2 = a.clone();
            clear(&mut c1);
            scalar::clear(&mut c2);
            assert_eq!(c1, c2);
        }
    }

    #[test]
    fn signature_ops() {
        let a = b"identical-signature";
        let b = b"identical-signature";
        let c = b"identical-signaturE";
        assert!(signature_eq(a, b).unwrap());
        assert!(!signature_eq(a, c).unwrap());
        assert_eq!(signature_diff_prefix(a, b).unwrap(), a.len());
        assert_eq!(signature_diff_prefix(a, c).unwrap(), a.len() - 1);
    }

    #[test]
    fn unequal_lengths_are_refused() {
        assert!(count_newly_set(b"ab", b"abc").is_err());
        assert!(mismatch_count(b"ab", b"abc").is_err());
        assert!(merge_into(&mut [0u8; 2], b"abc").is_err());
    }

    #[test]
    fn count_newly_set_semantics() {
        // prev: bits 0..=7 set; cur: bits 4..=11 set. New: 8..=11 (4 bits).
        let prev = [0b1111_1111u8, 0b0000_0000];
        let cur = [0b1111_0000u8, 0b0000_1111];
        assert_eq!(scalar::count_newly_set(&prev, &cur), 4);
        assert_eq!(count_newly_set(&prev, &cur).unwrap(), 4);
    }
}
