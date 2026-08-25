//! SanitizerCoverage runtime: counter registration, comparison callbacks,
//! and the scan/clear measurement core.
//!
//! # Approved unsafe zone
//!
//! This module is an approved unsafe zone (docs/INVARIANTS.md, "unsafe
//! policy"): it receives raw pointers from LLVM-generated module constructors
//! and scans caller-provided memory. Every unsafe block carries a `// SAFETY:`
//! comment stating the exact invariant.
//!
//! # Callback contract
//!
//! LLVM calls `__sanitizer_cov_8bit_counters_init(start, stop)` once per
//! instrumented module/DSO with the bounds of that module's inline 8-bit
//! counter array. We register at most [`MAX_RANGES`] ranges and refuse
//! impossible lengths (zero or > [`MAX_RANGE_LEN`]).
//!
//! The comparison callbacks (`trace_cmp{1,2,4,8}` / `trace_const_cmp{1,2,4,8}`
//! / `trace_switch`) push into the bounded ring in [`super::cmp`]. They never
//! allocate, never lock (single-threaded worker; atomics only), and never
//! format.
//!
//! # Measurement core
//!
//! The worker protocol (see `docs/ARCHITECTURE.md` §8) is:
//!
//! ```text
//! [calibration]  scan+clear twice; record footprint R (constant index set)
//! [per exec]     clear -> execute target -> scan
//! ```
//!
//! Because the runtime cannot be compile-time excluded on LLVM >= 18 (the
//! `__sanitizer_` name check was removed; rustc cannot emit the
//! `NoSanitizeCoverage` attribute), every scan reports `R | target_edges`.
//! The worker masks `R` (measured once per binary build) and treats the
//! remainder as pure target coverage. The invariant this depends on — that
//! the footprint is identical across scans of the same binary — is verified
//! by [`footprint_calibrate`] and locked by the nightly integration test.
//!
//! Counter semantics: inline 8-bit counters use plain wrapping `i8` adds; a
//! single edge executing >= 256 times wraps to zero in one execution. The
//! scan therefore treats counters as presence (nonzero) bits; counter-value
//! statistics are a Phase-1 sketch concern (documented in
//! docs/ARCHITECTURE.md).

#![allow(unsafe_code)]
// `unused_unsafe` fires inside `unsafe fn` bodies for the explicit blocks
// that `deny(unsafe_op_in_unsafe_fn)` requires; its opinion is inverted here.
#![allow(unused_unsafe)]

use super::cmp::{
    push_cmp1, push_cmp2, push_cmp4, push_cmp8, push_const_cmp1, push_const_cmp2, push_const_cmp4,
    push_const_cmp8, push_switch,
};
// No std atomics in this module: their Ordering match is a switch that
// trace-compares would instrument, recursing inside the target window.

/// Maximum number of counter ranges (one per instrumented module/DSO).
pub const MAX_RANGES: usize = 64;
/// Refuse counter ranges longer than this (hostile/accidental lengths).
pub const MAX_RANGE_LEN: usize = 1 << 30;

/// A registered counter range.
#[derive(Debug, Clone, Copy)]
struct CounterRange {
    start: *const u8,
    len: usize,
}

/// Registration failure latch. The callback cannot panic (a panic inside an
/// `extern "C"` fn aborts, which would be an unhelpful death mid-construction
/// with no way for the worker to report it); instead it records WHY
/// registration was refused and the worker treats any nonzero value as fatal
/// at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegistrationError {
    /// No error.
    None = 0,
    /// A range with zero or impossible length was registered.
    ImpossibleLength = 1,
    /// More than [`MAX_RANGES`] ranges were registered.
    TooManyRanges = 2,
    /// A range longer than [`MAX_RANGE_LEN`] was registered.
    RangeTooLong = 3,
}

// Plain static-mut latch (no std atomics: their Ordering match is a switch
// that trace-compares would instrument, recursing inside the target window).
// Single-threaded module-ctor discipline.
static mut REGISTRATION_ERROR: u8 = 0;

/// The registration error latch value (see [`RegistrationError`]).
pub fn registration_error() -> RegistrationError {
    // SAFETY: single-threaded module ctor; the latch is written once before
    // main. Plain read (no std atomics: their Ordering match is a switch that
    // trace-compares would instrument, recursing inside the target window).
    match unsafe { REGISTRATION_ERROR } {
        0 => RegistrationError::None,
        1 => RegistrationError::ImpossibleLength,
        2 => RegistrationError::TooManyRanges,
        _ => RegistrationError::RangeTooLong,
    }
}

// PC-table bounds (level-4 instrumentation). Registered by the module ctor;
// used in Phase 1 for edge identity. Stored as raw ranges like counters.
static mut PC_TABLE: (usize, usize) = (0, 0);

/// Called by LLVM's module ctor with the bounds of the pc-table section
/// (`-sanitizer-coverage-pc-table`). Recorded for future edge identity;
/// Phase 0 only validates and stores the bounds.
///
/// # Safety
///
/// `start`/`stop` bound a live, static pc-table for the process lifetime
/// (LLVM contract). Nothing is dereferenced here.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_pcs_init(start: *const u8, stop: *const u8) {
    // SAFETY: valid pointer range per the LLVM contract (module ctor).
    let len = unsafe { stop.offset_from(start) } as usize;
    // SAFETY: single-threaded module ctor; the pc-table slot is written once.
    unsafe {
        PC_TABLE = (start as usize, len);
    }
}

/// The registered pc-table length in bytes (0 if pc-table was not enabled).
pub fn pc_table_len() -> usize {
    // SAFETY: single-threaded module ctor; immutable after construction.
    unsafe { PC_TABLE.1 }
}

/// Indirect-call tracing callback (level-4 instrumentation). Counted, never
/// allocates. Runs inside the target window, so the body is icmp-free and
/// uses a plain static-mut counter (std atomic fetch_add routes through an
/// Ordering match that trace-compares would instrument, recursing).
/// (libFuzzer feeds these into its indirect-call coverage; Phase 1 decides
/// whether indirect-call edges earn their cost.)
///
/// # Safety
///
/// Called only by LLVM-generated instrumentation with valid operands per
/// the SanitizerCoverage contract; the body only increments a static-mut
/// counter (single-threaded worker discipline).
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_indir(caller: *const u8, callee: *const u8) {
    let _ = (caller, callee);
    // SAFETY: single-threaded worker discipline; the counter is only
    // incremented here and read by indir_call_count() outside the window.
    unsafe {
        INDIR_CALLS = INDIR_CALLS.wrapping_add(1);
    }
}

/// Number of indirect calls traced since process start.
pub fn indir_call_count() -> u64 {
    // SAFETY: single-threaded worker discipline (module docs).
    unsafe { INDIR_CALLS }
}

static mut INDIR_CALLS: u64 = 0;

// SAFETY: the registry is written only by the module-constructor callback
// (before main, single-threaded) and read by the scan. The worker is
// single-threaded, so no synchronization is required; this invariant is
// documented in the worker contract.
static mut RANGES: [CounterRange; MAX_RANGES] = [CounterRange {
    start: std::ptr::null(),
    len: 0,
}; MAX_RANGES];
static mut RANGE_COUNT: usize = 0;

/// Called by LLVM-generated module constructors with the bounds of a module's
/// inline 8-bit counter array. Registers the range, refusing impossible
/// lengths and range-count overflow.
///
/// # Safety
///
/// `start`/`stop` must be the valid bounds of a live counter array for the
/// lifetime of the process (LLVM guarantees this for instrumented modules).
/// The range is registered by copying the pointers; nothing dereferences
/// them here.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8) {
    // SAFETY: `start`/`stop` form a valid pointer range per the LLVM contract
    // (bounds of a live counter array); offset arithmetic on them is valid.
    let len = unsafe { stop.offset_from(start) } as usize;
    if len == 0 || len > MAX_RANGE_LEN {
        // SAFETY: single-threaded module ctor.
        unsafe {
            REGISTRATION_ERROR = if len == 0 { 1 } else { 3 };
        }
        return;
    }
    // SAFETY: single-threaded module-constructor context (module docs); the
    // registry is read and written only from this callback before main runs.
    if unsafe { RANGE_COUNT } >= MAX_RANGES {
        // SAFETY: single-threaded module ctor.
        unsafe {
            REGISTRATION_ERROR = 2;
        }
        return;
    }
    // SAFETY: single-threaded module-constructor context; registry writes are
    // confined to this callback before main runs (module docs).
    unsafe {
        RANGES[RANGE_COUNT] = CounterRange {
            start: start as *const u8,
            len,
        };
        RANGE_COUNT += 1;
    }
}

// Comparison callbacks. Each is `#[no_mangle] extern "C"` because LLVM emits
// direct calls to these exact symbols. They forward to the bounded ring.
// Never allocate, never lock, never format. ASan-exempt in the instrumented
// target build: an ASan-instrumented callback's shadow checks are themselves
// cmp-instrumented and recurse infinitely (see `cmp` module docs).
//
// The value callbacks are plain `extern "C" fn`s (NOT `unsafe`): they perform
// no unsafe operations, so there is no caller invariant for a Rust caller to
// uphold. "Called by LLVM instrumentation" is a property of the instrumented
// binary, not an invariant these functions enforce.

/// 1-byte comparison callback.
#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_cmp1(a: u8, b: u8) {
    push_cmp1(a, b);
}
/// 2-byte comparison callback.
#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_cmp2(a: u16, b: u16) {
    push_cmp2(a, b);
}
/// 4-byte comparison callback.
#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_cmp4(a: u32, b: u32) {
    push_cmp4(a, b);
}
/// 8-byte comparison callback.
#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_cmp8(a: u64, b: u64) {
    push_cmp8(a, b);
}
/// 1-byte constant comparison callback.
#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_const_cmp1(a: u8, b: u8) {
    push_const_cmp1(a, b);
}
/// 2-byte constant comparison callback.
#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_const_cmp2(a: u16, b: u16) {
    push_const_cmp2(a, b);
}
/// 4-byte constant comparison callback.
#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_const_cmp4(a: u32, b: u32) {
    push_const_cmp4(a, b);
}
/// 8-byte constant comparison callback.
#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_const_cmp8(a: u64, b: u64) {
    push_const_cmp8(a, b);
}

/// `switch` callback: `cases` points to a 2-element header
/// `[num_cases, bitwidth]` followed by `num_cases` case values, all
/// little-endian in `bitwidth` bytes. `val` is the switched value.
///
/// # Safety
///
/// `cases` must point to a live switch table per the LLVM layout above for
/// the duration of the call. The callback only forwards the pointer;
/// [`parse_switch`](super::cmp::parse_switch) validates the header and
/// bounds all reads after the execution window.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_switch(val: u64, cases: *const u64) {
    // SAFETY: the cases pointer contract is validated inside push_switch
    // (header read first, case reads bounded); forwarding preserves it.
    unsafe { push_switch(val, cases) };
}

/// Number of registered counter ranges (for tests and diagnostics).
pub fn range_count() -> usize {
    // SAFETY: single-threaded worker; the registry is immutable after
    // construction.
    unsafe { RANGE_COUNT }
}

/// Total number of counter bytes across all ranges.
pub fn total_counter_bytes() -> usize {
    // SAFETY: single-threaded worker; registry immutable after construction.
    unsafe { (0..RANGE_COUNT).map(|i| RANGES[i].len).sum() }
}

/// Clear all counters. Leaves the constant footprint behind (see module
/// docs); callers that need a pristine array should scan+clear instead.
/// ASan-exempt in the instrumented target build: reading the raw counter
/// pointers must not trigger shadow checks (which would recurse).
pub fn clear_all() {
    // SAFETY: every registered range is a live, valid array (registration
    // contract); we write exactly `len` bytes of each.
    //
    // Index loop (not an iterator): the registry is a `static mut`; the
    // iterator forms either copy the whole array per call (1 KiB of waste in
    // the hot path) or need a reference into static-mut storage. This loop
    // compiles to one 16-byte load per range.
    #[allow(clippy::needless_range_loop)]
    unsafe {
        for i in 0..RANGE_COUNT {
            let r = RANGES[i];
            for j in 0..r.len {
                let c = r.start.add(j) as *mut u8;
                *c = 0;
            }
        }
    }
}

/// Scan all counters, writing the packed indices `(range_index << 32) |
/// offset` of nonzero counters into `out`, and CLEAR every counter
/// unconditionally. Returns the number of nonzero counters seen, or
/// `u32::MAX` if the output buffer was too small (the report was truncated;
/// the counters are STILL all cleared — scan-and-clear is a consume
/// operation, so a saturated report never leaks into the next window).
///
/// Packed-index layout: high 32 bits = range index, low 32 bits = byte
/// offset within the range. Unambiguous for every legal range
/// (`offset < MAX_RANGE_LEN = 1 << 30`); the previous `(i << 20) | j`
/// packing collided for ranges >= 1 MiB.
///
/// The scan itself is instrumented in an instrumented build (see module
/// docs), so its own edges appear in the reported set. They are a constant
/// footprint per build and are masked by the caller. ASan-exempt in the
/// instrumented target build: raw counter reads must not trigger shadow
/// checks.
pub fn scan_and_clear(out: &mut [u64]) -> u32 {
    let cap = out.len();
    let mut n = 0usize;
    let mut saturated = false;
    // SAFETY: every registered range is a live, valid array (registration
    // contract); reads/writes are exactly `len` bytes each. `out` is a
    // caller-owned slice; writes are guarded by `n < cap`.
    //
    // Index loop (not an iterator): see `clear_all` — the registry is a
    // `static mut` and the iterator forms are worse in the hot path.
    #[allow(clippy::needless_range_loop)]
    unsafe {
        for i in 0..RANGE_COUNT {
            let r = RANGES[i];
            for j in 0..r.len {
                let c = r.start.add(j) as *mut u8;
                if *c != 0 {
                    if n < cap {
                        out[n] = ((i as u64) << 32) | (j as u64);
                        n += 1;
                    } else {
                        saturated = true;
                    }
                    *c = 0;
                }
            }
        }
    }
    if saturated {
        u32::MAX
    } else {
        n as u32
    }
}

/// Calibration: run scan+clear cycles back-to-back (nothing but the scan
/// code and its fixed call-site edges may run between measurements), then
/// return the constant footprint set (sorted packed indices).
///
/// The first scan discards startup coverage; scans 2 and 3 must report the
/// same set or calibration fails (an unstable footprint would corrupt
/// masking). The two scans are adjacent so the only edges between them are
/// the fixed return/call-site edges, which are constant across scans.
/// Sorting happens AFTER the last scan so the sort's own edges cannot leak
/// into a measurement.
///
/// `scratch` must have room for every counter index; the caller passes the
/// worker's scan buffer. A `u32::MAX` scan (buffer too small) is an error,
/// never a silent truncation.
///
/// NOTE: this measures only the scan's self-edges. The worker additionally
/// calibrates the FULL window skeleton (clear/reset/execute/snapshot/scan,
/// `target_runtime::worker`) so every constant runtime edge is masked;
/// this function is the scan-only core used by tests and the demo.
pub fn footprint_calibrate(scratch: &mut [u64]) -> Result<Vec<u64>, crate::error::Error> {
    // First scan: discard startup coverage.
    let _ = scan_and_clear(scratch);
    // Scans 2 and 3 back-to-back: the footprint, then its stability check.
    let n2 = scan_and_clear(scratch);
    if n2 == u32::MAX {
        return Err(crate::error::Error::Other(
            "sancov footprint calibration: scan buffer too small".into(),
        ));
    }
    let n3 = scan_and_clear(scratch);
    if n3 == u32::MAX || n3 != n2 {
        return Err(crate::error::Error::Other(
            "sancov footprint calibration: footprint not stable".into(),
        ));
    }
    let mut foot = scratch[..n2 as usize].to_vec();
    foot.sort_unstable();
    let mut foot3 = scratch[..n3 as usize].to_vec();
    foot3.sort_unstable();
    if foot != foot3 {
        return Err(crate::error::Error::Other(
            "sancov footprint calibration: footprint not stable".into(),
        ));
    }
    Ok(foot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The counter registry is process-global and the scan mutates it, so all
    // sancov tests must run serially (test threads run in parallel).
    static LOCK: Mutex<()> = Mutex::new(());

    /// Build a fake counter array, register it as a range (bypassing the
    /// real registry via the callback), and run the scan. Must hold `LOCK`.
    ///
    /// The backing storage is leaked so the registered pointer stays valid
    /// for the process lifetime (the registry is process-global and scans run
    /// after this function returns).
    fn fake_scan(values: &[u8], out: &mut [u64]) -> (u32, Vec<u64>) {
        let backing: &'static mut [u8] = Box::leak(values.to_vec().into_boxed_slice());
        let ptr = backing.as_mut_ptr();
        // SAFETY: `ptr`/`ptr.add(len)` are valid bounds of the leaked storage,
        // which lives for the rest of the process; registration copies the
        // pointers only.
        unsafe { __sanitizer_cov_8bit_counters_init(ptr, ptr.add(backing.len())) };
        let n = scan_and_clear(out);
        // The scan saturates at u32::MAX when the buffer is exceeded; clamp
        // for the slice.
        let count = (n as usize).min(out.len());
        let hits = out[..count].to_vec();
        (n, hits)
    }

    #[test]
    fn scan_reports_and_clears() {
        let _g = LOCK.lock().unwrap();
        let mut out = [0u64; 64];
        let (n, hits) = fake_scan(&[0, 1, 0, 2, 0, 0, 3], &mut out);
        assert_eq!(n, 3);
        // Packed index = (range_index << 32) | offset. The range index is
        // process-global (earlier tests registered ranges), so compare the
        // offsets (low 32 bits).
        let offsets: Vec<u64> = hits.iter().map(|h| h & 0xFFFF_FFFF).collect();
        assert_eq!(offsets, vec![1, 3, 6]);
        // All hits share the same range index (this test's fake range).
        assert!(hits.iter().all(|h| h >> 32 == hits[0] >> 32));
    }

    #[test]
    fn scan_clears_so_second_scan_is_clean() {
        let _g = LOCK.lock().unwrap();
        let mut out = [0u64; 64];
        let values = [5u8; 16];
        let (n1, h1) = fake_scan(&values, &mut out);
        assert_eq!(n1, 16);
        assert_eq!(h1.len(), 16);
        // The bytes were cleared by the first scan; a second scan of the same
        // backing storage must see none of them. The scanner's own footprint
        // in a non-instrumented test binary is empty, so the second scan
        // reports 0.
        let backing: &'static mut [u8] = Box::leak(vec![0u8; 16].into_boxed_slice());
        let ptr = backing.as_mut_ptr();
        // SAFETY: fresh leaked 16-byte fake array; valid for process lifetime.
        unsafe { __sanitizer_cov_8bit_counters_init(ptr, ptr.add(16)) };
        let n2 = scan_and_clear(&mut out);
        assert_eq!(n2, 0);
    }

    #[test]
    fn refuses_zero_length_range() {
        let _g = LOCK.lock().unwrap();
        let x = 0u8;
        // SAFETY: valid pointer pair, but zero length -> must be refused via
        // the registration error latch (a panic inside extern "C" would
        // abort, so the callback never panics).
        unsafe {
            __sanitizer_cov_8bit_counters_init(
                &x as *const u8 as *mut u8,
                &x as *const u8 as *mut u8,
            )
        };
        assert_eq!(registration_error(), RegistrationError::ImpossibleLength);
    }

    #[test]
    fn scan_respects_cap_and_still_clears() {
        let _g = LOCK.lock().unwrap();
        let mut out = [0u64; 2];
        let (n, hits) = fake_scan(&[1u8; 10], &mut out);
        assert_eq!(n, u32::MAX); // saturates, never overflows the buffer
        assert_eq!(hits.len(), 2);
        // Even though the report was truncated, the consume contract holds:
        // the counters were all cleared. A second scan sees nothing. (All
        // ranges registered by earlier tests were consumed by their scans.)
        let mut big = [0u64; 64];
        assert_eq!(scan_and_clear(&mut big), 0);
    }

    #[test]
    fn packed_index_layout() {
        let _g = LOCK.lock().unwrap();
        let mut out = [0u64; 64];
        let (n, hits) = fake_scan(&[0, 9], &mut out);
        assert_eq!(n, 1);
        let idx = hits[0];
        assert_eq!(idx & 0xFFFF_FFFF, 1); // low 32 bits = offset
        assert!(idx >> 32 < MAX_RANGES as u64); // high bits = range index
    }

    #[test]
    fn calibration_returns_stable_footprint() {
        let _g = LOCK.lock().unwrap();
        let mut scratch = [0u64; 4096];
        let foot = footprint_calibrate(&mut scratch).unwrap();
        // Sorted, deduplicated packed index list (may be empty in a
        // non-instrumented test binary).
        assert!(foot.windows(2).all(|w| w[0] < w[1]));
    }
}
