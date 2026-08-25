//! Golden demonstration target (master prompt §34).
//!
//! This is a REAL fuzz target built with `fuzz_target!` and driven by the
//! pinned-nightly instrumented build (`scripts/golden_demo.sh`). It exists
//! to prove, end to end:
//!
//! 1. **Coverage discovery (Path A)** — payload bytes drive deep, nested
//!    dispatch; mutations that reach new branches are admitted to the
//!    corpus by new-edge admission.
//! 2. **Compare-guided substitution** — a planted `u16` magic gate
//!    (`len == 0xBEEF`) is unreachable by blind byte mutation within the
//!    demo budget, but the const-cmp operand lands in the auto-discovered
//!    dictionary and the dictionary/substitution mutators write it,
//!    reaching the crash.
//! 3. **Crash recovery** — reaching the gate panics (panic=abort kills the
//!    worker), the ledger echo reproduces the exact input, the coordinator
//!    records a finding, replays it, and restarts the worker.
//! 4. **Path B (Phase 2): behavior-change-without-new-coverage** — every
//!    input executes the same `marker_gate` edges, but a target-defined
//!    signal (`marker_depth`: the number of `0x42` bytes) changes. A
//!    const-cmp against `0x42` plants that byte into the dictionary, so
//!    dictionary/byte mutations keep adding markers; the residual machinery
//!    (worker persistence filter -> state-feature/morphology admission ->
//!    AMPLIFY) retains the drifting trajectory and follows it until
//!    `depth > 48` panics. A coverage-only run (`--residual=off`) has no
//!    signal along this trajectory and cannot reach the crash within the
//!    demo budget.
//!
//! The deliberate panics are the *only* difference between this target and a
//! real parser harness: everything else is ordinary coverage-driven code.

use frf_fuzz::target_runtime::{FuzzContext, SignalId};

/// The marker-depth signal (Path B).
const SIG_DEPTH: SignalId = SignalId(0);
/// The byte whose count drives Path B. Reaching `depth > DEPTH_LIMIT` panics.
/// Set to 32 so the ladder completes quickly and the demo's OTHER gate (the
/// cmp-driven magic gate) still gets found within the same campaign.
const MARKER: u8 = 0x42;
/// The Path-B crash threshold.
const DEPTH_LIMIT: u64 = 32;
/// Lookup table: 1 at the marker index, 0 elsewhere. Counting via this
/// table avoids a per-byte comparison, so the marker loop does not flood
/// the compare-event ring and drown the length gate's `0xBEEF` const-cmp
/// (a Phase-2 demo finding: an inner-loop `== MARKER` emits one const-cmp
/// per byte, and the bounded 16-event snapshot never sees the magic
/// gate's operand, so the dictionary never learns `0xBEEF`).
const MARKER_TABLE: [u64; 256] = make_marker_table();

const fn make_marker_table() -> [u64; 256] {
    let mut t = [0u64; 256];
    t[MARKER as usize] = 1;
    t
}

/// The magic prefix + length gate. The length compare is a const-cmp that
/// the compare callbacks observe; `0xBEEF` becomes a dictionary token.
#[inline(never)]
fn length_gate(data: &[u8]) -> u32 {
    if data.len() < 8 {
        return 0;
    }
    if &data[0..4] != b"FRFZ" {
        return 1;
    }
    let len = u16::from_le_bytes([data[4], data[5]]);
    if len == 0xBEEF {
        // Deliberate crash: the planted bug. With -Cpanic=abort this kills
        // the worker; the crash ledger reproduces the exact input.
        panic!("golden demo: magic length gate hit (0xBEEF)");
    }
    u32::from(len)
}

/// Deep coverage paths driven by payload content (Path A).
#[inline(never)]
fn payload_paths(payload: &[u8]) -> u32 {
    let mut acc = 0u32;
    if payload.is_empty() {
        return 0x100;
    }
    // Nested dispatch: each distinct first byte opens a distinct deep path.
    match payload[0] {
        0 => {
            if payload.len() > 2 {
                match payload[1] {
                    0 => acc += 1,
                    1 => acc += 2,
                    _ => acc += 3,
                }
            }
        }
        1 => {
            for (i, b) in payload.iter().enumerate() {
                acc = acc.wrapping_add(u32::from(*b)).wrapping_mul(31);
                if i > 512 {
                    break;
                }
            }
        }
        2 => {
            if payload.len() >= 4 {
                let v = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[0]]);
                acc = v.rotate_left(payload.len() as u32 % 31);
            }
        }
        _ => {
            acc = payload.iter().map(|b| u32::from(*b)).sum();
        }
    }
    // A second-stage gate only reachable via path 1 with enough data.
    if acc == 0xDEAD_BEEF {
        panic!("golden demo: second-stage gate hit");
    }
    acc
}

/// Path B (Phase 2): identical coverage for every input; a target-defined
/// signal (marker count) changes. The `0x42` const-cmp feeds the dictionary
/// so the marker byte is writable; the residual machinery follows the
/// drifting trajectory until the depth limit panics.
///
/// The signal is observed BEFORE the panic check: the crashing input's own
/// observation is never recorded (the window dies), but every precursor
/// along the ladder is.
#[inline(never)]
fn marker_gate(data: &[u8], cx: &mut FuzzContext) {
    // The const-cmp that plants 0x42 into the auto-discovered dictionary.
    let mut depth = 0u64;
    if data.len() > 8 && data[8] == MARKER {
        depth += 1;
    }
    for &b in data {
        depth += MARKER_TABLE[b as usize]; // branchless; no cmp events
    }
    let _ = cx.observe_u64(SIG_DEPTH, depth);
    if depth > DEPTH_LIMIT {
        panic!("golden demo: marker depth gate hit (depth {depth} > {DEPTH_LIMIT})");
    }
}

frf_fuzz::fuzz_target!(
    setup = |cx: &mut FuzzContext| {
        cx.register_signal(SIG_DEPTH, "marker_depth", "markers")?;
        Ok(())
    },
    execute = |data: &[u8], cx: &mut FuzzContext| {
        marker_gate(data, cx);
        let _l = length_gate(data);
        let rest = data.get(8..).unwrap_or(&[]);
        let _ = payload_paths(rest);
        Ok(())
    },
);
