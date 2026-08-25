//! Bounded, allocation-free compare-event ring.
//!
//! Comparison callbacks fire inside the target's execution; they must never
//! allocate, lock, format, or **contain integer comparisons of their own**.
//!
//! # Why the callbacks must be icmp-free (Phase-0 forensic finding)
//!
//! On LLVM >= 18 there is no compile-time way to exclude the runtime from
//! SanitizerCoverage (the `__sanitizer_` name check was removed; rustc cannot
//! emit the `NoSanitizeCoverage` attribute; rustc's `#[sanitize(address =
//! "off")]` does not emit any LLVM attribute — verified empirically). With
//! `-sanitizer-coverage-trace-compares`, every instrumented integer comparison
//! calls back into `__sanitizer_cov_trace_(const_)cmp{1,2,4,8}` — so an
//! instrumented callback that itself compares integers recurses infinitely.
//! LLVM skips only comparisons where BOTH operands are constants.
//!
//! Worse: **AddressSanitizer's own shadow checks are `icmp`s**, and the ASan
//! pass instruments the callback functions like any other code. An
//! ASan-instrumented callback therefore recurses no matter how its Rust body
//! is written. Verified end-to-end: on LLVM 20..22 with rustc, `-Zsanitizer=
//! address` + trace-compares + Rust-defined callbacks cannot coexist in one
//! binary. The architecture consequence (docs/COMPATIBILITY.md):
//!
//! * default instrumented builds use sancov + trace-compares WITHOUT ASan;
//! * `sanitizer = "address"` is an opt-in that disables trace-compares
//!   (ASan memory-error detection instead of compare feedback);
//! * the callback bodies are still written icmp-free and loop-free, both to
//!   minimize the window footprint and because the exclusion could return if
//!   rustc ever wires the sanitize attribute into LLVM.
//!
//! `push` detects overflow with arithmetic only (no branch), and the switch
//! callback records the raw case-table pointer (switch tables live in static
//! constant data, so the pointer stays valid) and defers all parsing to
//! [`parse_switch`], which runs after the execution window where
//! comparisons are fine.
//!
//! # Window discipline
//!
//! The worker's per-execution sequence is:
//!
//! ```text
//! clear coverage counters   (scan_and_clear; its own cmp events are discarded
//!                            by the reset that follows)
//! reset cmp ring
//! execute target
//! scan coverage counters    (constant cmp events land in the ring AFTER the
//!                            target's events)
//! snapshot cmp ring         (outside the coverage window; its edges are
//!                            cleared by the next clear)
//! ```
//!
//! The snapshot's own events are never captured (they land after the
//! captured range) and the next reset discards everything.

#![allow(unsafe_code)]

// No std atomics here: their Ordering match is a switch that trace-compares
// would instrument, recursing inside the target window (module docs).

/// Ring capacity (power of two). Fixed, bounded, documented.
pub const RING_LEN: usize = 1 << 14;

/// Maximum switch cases recorded per parsed event (LLVM switch tables can be
/// huge; we record a bounded prefix).
pub const MAX_SWITCH_CASES: usize = 8;

/// What kind of comparison produced the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CmpKind {
    /// Non-constant comparison.
    Cmp = 1,
    /// Constant comparison (one operand is a compile-time constant).
    ConstCmp = 2,
    /// Switch dispatch.
    Switch = 3,
}

/// One ring event. Fixed size, Copy, no heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmpEvent {
    /// Comparison kind.
    pub kind: CmpKind,
    /// Operand width in bytes (1, 2, 4, 8; 0 for switch).
    pub width: u8,
    /// Operand A (or the switched value for switches).
    pub a: u64,
    /// Operand B (unused for switches).
    pub b: u64,
    /// For [`CmpKind::Switch`]: raw pointer to the LLVM case table
    /// `[num_cases, bitwidth, case0, ...]`. Valid because switch tables are
    /// static constant data; parsed only by [`parse_switch`] after the
    /// execution window. 0 for non-switches.
    pub switch_cases_ptr: u64,
    /// Switch case count (0 until parsed, or for non-switches).
    pub case_count: u16,
    /// Bounded prefix of switch case values (filled by [`parse_switch`]).
    pub cases: [u64; MAX_SWITCH_CASES],
}

/// Compile-time zero cases template. Copied (memcpy, no compare) instead of
/// built with a runtime `[0; N]` repeat, which at opt-level 0 lowers to a
/// compare-loop that would recurse through trace-const-cmp inside the target
/// window.
const ZERO_CASES: [u64; MAX_SWITCH_CASES] = [0; MAX_SWITCH_CASES];

impl CmpEvent {
    /// A plain comparison event. Must not contain integer comparisons or
    /// loops (this is called inside the target window).
    pub const fn cmp(kind: CmpKind, width: u8, a: u64, b: u64) -> CmpEvent {
        CmpEvent {
            kind,
            width,
            a,
            b,
            switch_cases_ptr: 0,
            case_count: 0,
            cases: ZERO_CASES,
        }
    }
}

// Ring state. The producer is the single worker thread; consumers snapshot
// after execution. These are `static mut` u32s accessed ONLY through the raw
// pointer helpers below (no references, no std atomics):
//
// * `std::sync::atomic::AtomicU32::load/store` route through the std
//   `atomic_load`/`atomic_store` wrappers, whose `match order` compiles to a
//   switch at opt-level 0. The switch is cmp-instrumented (trace-switch) and
//   recurses into the callbacks inside the target window — verified
//   end-to-end, at every opt level in the dev profile.
// * creating `&mut` references to a `static mut` emits Rust-2024
//   reference-probe comparisons, which also recurse.
//
// The single-threaded worker discipline makes plain aligned reads/writes
// sound; if a future build ever runs callbacks on multiple threads, replace
// these with intrinsics-based atomics (never the Ordering-matching std
// wrappers), preserving the icmp-free invariant.
static mut HEAD: u32 = 0;
static mut TAIL: u32 = 0;
/// 0xFFFFFFFF once the ring has overflowed since the last reset (stored as a
/// mask so the callback path needs no comparison to set it).
static mut OVERFLOW_MASK: u32 = 0;

/// Raw relaxed-style load; no comparisons, no references.
fn load32(ptr: *const u32) -> u32 {
    // SAFETY: `ptr` must point to a valid, aligned, initialized u32 for the
    // duration of the call (callers pass addr_of_mut! to the statics above).
    // Single-threaded worker discipline (module docs).
    unsafe { ptr.read() }
}

/// Raw store; no comparisons, no references.
fn store32(ptr: *mut u32, v: u32) {
    // SAFETY: `ptr` must point to a valid, aligned u32 (callers pass
    // addr_of_mut! to the statics above). Single-threaded worker discipline.
    unsafe { ptr.write(v) }
}

// SAFETY: `RING` is written only by the single producer (the worker's target
// thread) through the bounded index derived from TAIL, and read only by the
// snapshot after execution. The index arithmetic keeps every access inside
// the array. `CmpEvent` is a plain POD; torn reads cannot occur because the
// producer and consumer are not concurrent (snapshot happens after the
// target returns).
static mut RING: [CmpEvent; RING_LEN] = [CmpEvent {
    kind: CmpKind::Cmp,
    width: 0,
    a: 0,
    b: 0,
    switch_cases_ptr: 0,
    case_count: 0,
    cases: [0; MAX_SWITCH_CASES],
}; RING_LEN];

/// Reset the ring (called by the worker before each execution). Contains no
/// integer comparisons (stores only).
#[inline]
pub fn reset() {
    store32(std::ptr::addr_of_mut!(HEAD), 0);
    store32(std::ptr::addr_of_mut!(TAIL), 0);
    store32(std::ptr::addr_of_mut!(OVERFLOW_MASK), 0);
}

/// True if the ring overflowed since the last reset. Runs outside the
/// execution window (comparisons are fine here).
pub fn overflowed() -> bool {
    load32(std::ptr::addr_of!(OVERFLOW_MASK)) != 0
}

/// Push one event. **Must contain no integer comparisons** (it runs inside
/// the target window): overflow detection is branchless arithmetic.
#[inline]
fn push(e: CmpEvent) {
    let tail = load32(std::ptr::addr_of!(TAIL));
    let head = load32(std::ptr::addr_of!(HEAD));
    // diff = number of live events (wrapping).
    let diff = tail.wrapping_sub(head);
    // full = 0xFFFFFFFF if diff >= RING_LEN else 0. Computed arithmetically:
    // (RING_LEN - diff - 1) is negative exactly when diff >= RING_LEN; the
    // arithmetic shift propagates the sign bit. No icmp, no branch.
    let full = ((RING_LEN as u32).wrapping_sub(diff).wrapping_sub(1) as i32) >> 31;
    store32(std::ptr::addr_of_mut!(OVERFLOW_MASK), full as u32);
    // Advance the head by exactly one slot when full (full & 1 == 1).
    store32(
        std::ptr::addr_of_mut!(HEAD),
        head.wrapping_add((full as u32) & 1),
    );
    let idx = (tail as usize) & (RING_LEN - 1);
    // SAFETY: idx < RING_LEN by the power-of-two mask, so this never reads or
    // writes out of bounds. The write goes through a raw pointer from
    // addr_of_mut! (NOT a reference): creating a `&mut` to a static mut emits
    // Rust-2024 reference-probe comparisons, which would recurse through
    // trace-const-cmp inside the target window (Phase-0 finding; module
    // docs). The producer is the single worker thread.
    unsafe {
        std::ptr::addr_of_mut!(RING)
            .cast::<CmpEvent>()
            .add(idx)
            .write(e);
    }
    store32(std::ptr::addr_of_mut!(TAIL), tail.wrapping_add(1));
}

/// Snapshot the ring contents (oldest first) into `out`; returns the count.
/// Runs after the execution window; comparisons are fine here. The snapshot's
/// own pushed events land after the captured range and are discarded by the
/// next reset.
pub fn snapshot(out: &mut [CmpEvent]) -> usize {
    let head = load32(std::ptr::addr_of!(HEAD));
    let tail = load32(std::ptr::addr_of!(TAIL));
    let count = tail.wrapping_sub(head) as usize;
    let n = count.min(out.len());
    for (i, slot) in out[..n].iter_mut().enumerate() {
        let idx = (head.wrapping_add(i as u32) as usize) & (RING_LEN - 1);
        // SAFETY: idx < RING_LEN by the mask; no concurrent producer (the
        // worker freezes the ring before snapshotting).
        unsafe {
            *slot = std::ptr::addr_of!(RING).cast::<CmpEvent>().add(idx).read();
        }
    }
    n
}

/// Parse a switch event's case table. Runs AFTER the execution window (the
/// callback only recorded the raw pointer; parsing requires comparisons).
///
/// `event.switch_cases_ptr` must point to the LLVM layout
/// `[num_cases: u64, bitwidth: u64, case0, ...]`; reads are bounded by
/// [`MAX_SWITCH_CASES`] and by the declared count. Switch tables are static
/// constant data in the target binary, so the pointer remains valid.
pub fn parse_switch(event: &mut CmpEvent) -> Result<(), crate::error::Error> {
    if event.kind != CmpKind::Switch {
        return Ok(());
    }
    if event.switch_cases_ptr == 0 {
        return Err(crate::error::Error::Encoding(
            "switch event without case table",
        ));
    }
    let header = event.switch_cases_ptr as *const u64;
    // SAFETY: per the LLVM contract the pointer is valid for at least two
    // u64s (num_cases, bitwidth); the callback only records pointers to real
    // switch tables.
    let num_cases = unsafe { *header } as usize;
    let bitwidth = unsafe { *header.add(1) } as usize;
    let bytes = bitwidth.div_ceil(8);
    let to_read = num_cases.min(MAX_SWITCH_CASES);
    for i in 0..to_read {
        // SAFETY: the declared num_cases bounds the table (LLVM contract); we
        // read at most to_read <= num_cases case slots of `bytes` bytes each.
        let base = unsafe { header.add(2 + i) } as *const u8;
        let mut v = 0u64;
        for j in 0..bytes.min(8) {
            // SAFETY: j < bytes <= 8; the case slot is at least `bytes` wide.
            v |= u64::from(unsafe { *base.add(j) }) << (8 * j);
        }
        event.cases[i] = v;
    }
    event.case_count = to_read as u16;
    Ok(())
}

// ---- callback entry points (called by the sancov runtime) ----
// These forward into `push` and must themselves contain no integer
// comparisons.

pub(crate) fn push_cmp1(a: u8, b: u8) {
    push(CmpEvent::cmp(CmpKind::Cmp, 1, u64::from(a), u64::from(b)));
}
pub(crate) fn push_cmp2(a: u16, b: u16) {
    push(CmpEvent::cmp(CmpKind::Cmp, 2, u64::from(a), u64::from(b)));
}
pub(crate) fn push_cmp4(a: u32, b: u32) {
    push(CmpEvent::cmp(CmpKind::Cmp, 4, u64::from(a), u64::from(b)));
}
pub(crate) fn push_cmp8(a: u64, b: u64) {
    push(CmpEvent::cmp(CmpKind::Cmp, 8, a, b));
}
pub(crate) fn push_const_cmp1(a: u8, b: u8) {
    push(CmpEvent::cmp(
        CmpKind::ConstCmp,
        1,
        u64::from(a),
        u64::from(b),
    ));
}
pub(crate) fn push_const_cmp2(a: u16, b: u16) {
    push(CmpEvent::cmp(
        CmpKind::ConstCmp,
        2,
        u64::from(a),
        u64::from(b),
    ));
}
pub(crate) fn push_const_cmp4(a: u32, b: u32) {
    push(CmpEvent::cmp(
        CmpKind::ConstCmp,
        4,
        u64::from(a),
        u64::from(b),
    ));
}
pub(crate) fn push_const_cmp8(a: u64, b: u64) {
    push(CmpEvent::cmp(CmpKind::ConstCmp, 8, a, b));
}

/// Switch callback body: records the value and the raw case-table pointer.
/// **No integer comparisons** (pointer-to-int casts only); all parsing is
/// deferred to [`parse_switch`].
///
/// # Safety
///
/// `cases` must point to a valid LLVM switch case table (static constant
/// data) for the process lifetime; the callback only records the pointer.
pub(crate) unsafe fn push_switch(val: u64, cases: *const u64) {
    push(CmpEvent {
        kind: CmpKind::Switch,
        width: 0,
        a: val,
        b: 0,
        switch_cases_ptr: cases as u64,
        case_count: 0,
        cases: ZERO_CASES,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The ring is a process-global static; test threads run in parallel, so
    // all ring tests must serialize (the runtime's single-producer
    // discipline does not hold across test threads).
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn push_snapshot_roundtrip() {
        let _g = LOCK.lock().unwrap();
        reset();
        push_cmp4(1, 2);
        push_cmp4(3, 4);
        push_const_cmp8(0xDEAD_BEEF, 0);
        let mut out = [CmpEvent::cmp(CmpKind::Cmp, 0, 0, 0); 16];
        let n = snapshot(&mut out);
        assert_eq!(n, 3);
        assert_eq!(out[0], CmpEvent::cmp(CmpKind::Cmp, 4, 1, 2));
        assert_eq!(out[1], CmpEvent::cmp(CmpKind::Cmp, 4, 3, 4));
        assert_eq!(out[2], CmpEvent::cmp(CmpKind::ConstCmp, 8, 0xDEAD_BEEF, 0));
    }

    #[test]
    fn overflow_is_reported() {
        let _g = LOCK.lock().unwrap();
        reset();
        for i in 0..(RING_LEN as u64 + 100) {
            push_cmp8(i, 0);
        }
        assert!(overflowed());
        let mut out = [CmpEvent::cmp(CmpKind::Cmp, 0, 0, 0); 8];
        let n = snapshot(&mut out);
        assert_eq!(n, 8);
        // The oldest surviving event is i = 100 (100 events were dropped).
        assert_eq!(out[0].a, 100);
    }

    #[test]
    fn exact_full_boundary_marks_overflow() {
        let _g = LOCK.lock().unwrap();
        reset();
        for i in 0..RING_LEN as u64 {
            push_cmp8(i, 0);
        }
        // Exactly full: the NEXT push must mark overflow and drop the oldest.
        assert!(!overflowed());
        push_cmp8(9999, 0);
        assert!(overflowed());
        let mut out = [CmpEvent::cmp(CmpKind::Cmp, 0, 0, 0); 4];
        let n = snapshot(&mut out);
        assert_eq!(n, 4);
        assert_eq!(out[0].a, 1); // event 0 dropped
    }

    #[test]
    fn reset_clears() {
        let _g = LOCK.lock().unwrap();
        reset();
        push_cmp1(1, 2);
        reset();
        let mut out = [CmpEvent::cmp(CmpKind::Cmp, 0, 0, 0); 4];
        assert_eq!(snapshot(&mut out), 0);
        assert!(!overflowed());
    }

    #[test]
    fn snapshot_respects_buffer() {
        let _g = LOCK.lock().unwrap();
        reset();
        for i in 0..10u64 {
            push_cmp8(i, 0);
        }
        let mut out = [CmpEvent::cmp(CmpKind::Cmp, 0, 0, 0); 4];
        let n = snapshot(&mut out);
        assert_eq!(n, 4);
        assert_eq!(out[0].a, 0);
        assert_eq!(out[3].a, 3);
    }

    #[test]
    fn switch_parsing() {
        let _g = LOCK.lock().unwrap();
        reset();
        // Header: [num_cases=3, bitwidth=32, 10, 20, 30]
        let header = [3u64, 32, 10, 20, 30];
        // SAFETY: valid 5-element array per the test contract; the callback
        // only records the pointer.
        unsafe { push_switch(20, header.as_ptr()) };
        let mut out = [CmpEvent::cmp(CmpKind::Cmp, 0, 0, 0); 4];
        let n = snapshot(&mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0].kind, CmpKind::Switch);
        assert_eq!(out[0].a, 20);
        parse_switch(&mut out[0]).unwrap();
        assert_eq!(out[0].case_count, 3);
        assert_eq!(&out[0].cases[..3], &[10, 20, 30]);
    }

    #[test]
    fn switch_case_count_is_bounded() {
        let _g = LOCK.lock().unwrap();
        reset();
        // Header claims 1000 cases; only MAX_SWITCH_CASES are parsed.
        let header = [1000u64, 64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        // SAFETY: valid 12-element array per the test contract; parsing must
        // not read beyond element 10 (index 2+8).
        unsafe { push_switch(7, header.as_ptr()) };
        let mut out = [CmpEvent::cmp(CmpKind::Cmp, 0, 0, 0); 4];
        let n = snapshot(&mut out);
        assert_eq!(n, 1);
        parse_switch(&mut out[0]).unwrap();
        assert_eq!(out[0].case_count, 8);
        assert_eq!(out[0].cases[7], 8);
    }
}
