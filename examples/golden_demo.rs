//! Golden demonstration target (master prompt §34, Phase-1 subset).
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
//!
//! The Phase-2 extension (Path B: behavior-change-without-new-coverage via
//! target-defined signals) is added when signals/residuals land.
//!
//! The deliberate panic is the *only* difference between this target and a
//! real parser harness: everything else is ordinary coverage-driven code.

use frf_fuzz::target_runtime::FuzzContext;

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

frf_fuzz::fuzz_target!(|data: &[u8], cx: &mut FuzzContext| {
    let _ = cx;
    let _l = length_gate(data);
    let rest = data.get(8..).unwrap_or(&[]);
    let _ = payload_paths(rest);
});
