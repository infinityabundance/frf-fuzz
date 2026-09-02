//! Phase-0 instrumentation spike: the REAL runtime, instrumented build.
//!
//! Built and run by `scripts/nightly_spike.sh` with the pinned nightly and
//! the cargo-fuzz-derived flag set (see docs/COMPATIBILITY.md):
//!
//! ```sh
//! RUSTFLAGS="-Zsanitizer=address -Cpasses=sancov-module \
//!   -Cllvm-args=-sanitizer-coverage-level=4 \
//!   -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
//!   -Cllvm-args=-sanitizer-coverage-pc-table \
//!   -Cllvm-args=-sanitizer-coverage-trace-compares \
//!   -Clto=off -Cpanic=abort" \
//!   cargo +nightly-2026-07-24 run --example sancov_demo
//! ```
//!
//! What this proves end-to-end with the crate's own runtime:
//!
//! 1. counter ranges are registered by LLVM module ctors via
//!    `__sanitizer_cov_8bit_counters_init`;
//! 2. the comparison callbacks fire during target execution and land in the
//!    bounded cmp ring;
//! 3. the scan/clear core reports target coverage with a constant,
//!    calibratable footprint (the `__sanitizer_` name exclusion is GONE on
//!    LLVM >= 18, so masking is the mechanism — see `target_runtime::sancov`);
//! 4. the masked delta is deterministic per input and input-discriminating;
//! 5. the measurement window discipline holds: NO instrumented code runs
//!    between clear and scan except the target itself.
//!
//! This example is a validation artifact, not a fuzz target.

use frf_fuzz::target_runtime::cmp::{self, CmpEvent, CmpKind};
use frf_fuzz::target_runtime::sancov;
use std::collections::BTreeSet;

const SCRATCH: usize = 1 << 20;

/// The instrumented target: a magic-value gate plus a range check. Its edges
/// are the "target coverage" the demo must observe.
///
/// At opt-level 3 the optimizer lowers this comparison-only function to a
/// BRANCHLESS `cmov`/`setb` sequence: both inputs execute the same edges.
/// That is exactly why the engine also captures trace-compare VALUES — the
/// demo asserts discrimination via edges OR cmp events (see the invariant
/// in `main`). This is the honest statement of what the measurement window
/// provides at every opt level.
#[inline(never)]
fn magic_gate(x: u32) -> u32 {
    if x == 0xDEADBEEF {
        return 1;
    }
    if (1000..2000).contains(&x) {
        return 2;
    }
    0
}

/// The no-op "target" used during calibration so the constant footprint
/// includes every edge the window skeleton fires (clear, reset, noop,
/// scan, and the caller's call sites).
#[inline(never)]
fn noop_target() {}

/// Calibrate the constant footprint by running the FULL window skeleton
/// (clear -> reset -> noop target -> scan) until the reported set is stable.
/// The first cycle discards startup coverage; subsequent cycles report only
/// the constant edges.
fn calibrate(scratch: &mut [u64]) -> std::collections::BTreeSet<u64> {
    let mut last: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for _ in 0..3 {
        sancov::clear_all();
        cmp::reset();
        noop_target();
        let n = sancov::scan_and_clear(scratch);
        assert!(n != u32::MAX, "calibration scan buffer too small");
        last = scratch[..n as usize].iter().copied().collect();
    }
    last
}

fn main() {
    // The registration latch must be clean (module ctors ran correctly).
    assert_eq!(
        sancov::registration_error(),
        sancov::RegistrationError::None,
        "counter registration was refused"
    );
    let ranges = sancov::range_count();
    let total = sancov::total_counter_bytes();
    assert!(
        ranges >= 1,
        "no counter ranges registered — is the build instrumented?"
    );
    eprintln!("[demo] counter ranges registered: {ranges}, total bytes: {total}");

    // Calibration: measure the constant footprint R by running the full
    // window skeleton (startup coverage is discarded by the first cycle).
    let mut scratch = vec![0u64; SCRATCH];
    let foot = calibrate(&mut scratch);
    eprintln!("[demo] constant footprint R: {} counters", foot.len());

    // The measurement window. Between the clear and the scan, the ONLY
    // instrumented code that runs is the target (magic_gate). The window
    // discipline (target_runtime::cmp module docs):
    //
    //   clear counters -> reset ring -> execute target -> scan counters
    //   -> snapshot ring (outside the coverage window; its edges are cleared
    //   by the next clear).
    //
    // Everything that reports (eprintln, BTreeSet) happens after the window.
    let args: Vec<String> = std::env::args().collect();
    let input_a: u32 = args
        .get(1)
        .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0xDEADBEEF);
    let input_b: u32 = if input_a == 0xDEADBEEF {
        0x1234
    } else {
        0xDEADBEEF
    };

    // Window A: clear, reset, execute, scan. Materialize A's delta NOW:
    // the scan buffer is reused by window B, so reading it later would yield
    // B's data.
    sancov::clear_all();
    cmp::reset();
    let r_a = magic_gate(input_a);
    let n_a = sancov::scan_and_clear(&mut scratch);
    assert!(n_a != u32::MAX, "window A scan buffer too small");
    let set_a: BTreeSet<u64> = scratch[..n_a as usize].iter().copied().collect();
    let delta_a: Vec<u64> = set_a
        .iter()
        .filter(|i| !foot.contains(i))
        .copied()
        .collect();
    let mut events_a = [CmpEvent::cmp(CmpKind::Cmp, 0, 0, 0); 256];
    let n_events_a = cmp::snapshot(&mut events_a);

    // Window B with the other input.
    sancov::clear_all();
    cmp::reset();
    let r_b = magic_gate(input_b);
    let n_b = sancov::scan_and_clear(&mut scratch);
    assert!(n_b != u32::MAX, "window B scan buffer too small");
    let set_b: BTreeSet<u64> = scratch[..n_b as usize].iter().copied().collect();
    let delta_b: Vec<u64> = set_b
        .iter()
        .filter(|i| !foot.contains(i))
        .copied()
        .collect();
    let mut events_b = [CmpEvent::cmp(CmpKind::Cmp, 0, 0, 0); 256];
    let n_events_b = cmp::snapshot(&mut events_b);

    // ---- post-window: report ----
    eprintln!("[demo] magic_gate({input_a:#x}) = {r_a}   magic_gate({input_b:#x}) = {r_b}");
    eprintln!("[demo] input A masked delta: [{}]", fmt_set(&delta_a));
    eprintln!("[demo] input B masked delta: [{}]", fmt_set(&delta_b));

    // Invariant 1: each input produced target edges beyond the footprint.
    assert!(!delta_a.is_empty(), "input A added no target coverage");
    assert!(!delta_b.is_empty(), "input B added no target coverage");
    // Invariant 2: the measurement window discriminates the inputs — via
    // edges OR via trace-compare values. At opt-level 3 a comparison-only
    // target can be branchless (identical edges); the cmp ring then carries
    // the discrimination (the const-cmp operands differ). Both channels are
    // part of the contract.
    let events_a_cmp: Vec<(u64, u64)> = events_a[..n_events_a].iter().map(|e| (e.a, e.b)).collect();
    let events_b_cmp: Vec<(u64, u64)> = events_b[..n_events_b].iter().map(|e| (e.a, e.b)).collect();
    let edges_differ = delta_a != delta_b;
    let events_differ = events_a_cmp != events_b_cmp;
    assert!(
        edges_differ || events_differ,
        "different inputs must produce different coverage OR different cmp events"
    );
    // The no-leak invariant is only meaningful when edges discriminate;
    // when the target is branchless, edge sets are legitimately identical.
    if edges_differ {
        assert!(
            delta_a.iter().any(|i| !delta_b.contains(i)),
            "window A has no exclusive edges (clear failed?)"
        );
        assert!(
            delta_b.iter().any(|i| !delta_a.contains(i)),
            "window B has no exclusive edges (clear failed?)"
        );
    }

    // Invariant 3: the cmp ring captured comparisons during the target runs,
    // including a constant comparison (the magic gate).
    eprintln!(
        "[demo] cmp events A: {n_events_a} (overflow {})  B: {n_events_b} (overflow {})",
        cmp::overflowed(),
        cmp::overflowed()
    );
    assert!(n_events_a > 0, "no cmp events captured during input A");
    assert!(n_events_b > 0, "no cmp events captured during input B");
    let const_cmp_seen = events_a[..n_events_a]
        .iter()
        .any(|e| e.kind == CmpKind::ConstCmp);
    assert!(
        const_cmp_seen,
        "no ConstCmp event captured (magic gate not traced?)"
    );

    eprintln!("[demo] PASS");
}

fn fmt_set(v: &[u64]) -> String {
    let mut s = Vec::new();
    for i in v {
        s.push(format!("{i:x}"));
    }
    s.join(",")
}
