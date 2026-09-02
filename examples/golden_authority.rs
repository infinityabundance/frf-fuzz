//! Golden-demo FRF authority (Phase 4): the clean reference.
//!
//! The golden demonstration's crash findings are verified by a REAL FRF
//! court whose authority must be an executable that behaves like the
//! *reference* version of the demo parser — the same parsing logic WITHOUT
//! the planted panics. This example is exactly that authority. It honors the
//! same case-harness argv convention an instrumented frf-fuzz target binary
//! implements:
//!
//! ```text
//! golden_authority --frf-fuzz-fixture <path>
//! ```
//!
//! It reads the fixture file, runs the reference parsing logic over its
//! bytes, and exits 0. A crash finding's candidate (the instrumented target,
//! which panics → SIGABRT on the planted gates) therefore diverges from this
//! authority on the exit observable, and FRF emits a receipt.
//!
//! This is a PLAIN Rust program: no `fuzz_target!`, no instrumentation, no
//! frf-fuzz runtime. Build it with the stable coordinator build
//! (`cargo build --example golden_authority`).

use std::io::Read;

/// The marker byte (Path B) and its depth limit — the reference parser
/// observes the same signal but never panics.
const DEPTH_LIMIT: u64 = 32;
const MARKER_TABLE: [u64; 256] = make_marker_table();

const fn make_marker_table() -> [u64; 256] {
    let mut t = [0u64; 256];
    t[0x42] = 1;
    t
}

/// The reference `length_gate`: identical control flow, no planted panic.
#[inline(never)]
fn length_gate(data: &[u8]) -> u32 {
    if data.len() < 8 {
        return 0;
    }
    if &data[0..4] != b"FRFZ" {
        return 1;
    }
    u32::from(u16::from_le_bytes([data[4], data[5]]))
}

/// The reference `payload_paths`: identical control flow, no planted panic.
#[inline(never)]
fn payload_paths(payload: &[u8]) -> u32 {
    let mut acc = 0u32;
    if payload.is_empty() {
        return 0x100;
    }
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
    acc
}

/// The reference `marker_gate`: same counting, no depth panic.
#[inline(never)]
fn marker_gate(data: &[u8]) -> u64 {
    let mut depth = 0u64;
    for &b in data {
        depth += MARKER_TABLE[b as usize];
    }
    let _ = DEPTH_LIMIT; // the limit exists in the candidate, not here
    depth
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("--frf-fuzz-fixture") {
        eprintln!("golden_authority: expected `--frf-fuzz-fixture <path>`");
        std::process::exit(1);
    }
    let path = args.get(2).unwrap_or_else(|| {
        eprintln!("golden_authority: missing fixture path");
        std::process::exit(1)
    });
    let mut file = std::fs::File::open(path).unwrap_or_else(|e| {
        eprintln!("golden_authority: cannot open {path}: {e}");
        std::process::exit(1)
    });
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap_or_else(|e| {
        eprintln!("golden_authority: cannot read {path}: {e}");
        std::process::exit(1)
    });
    // The reference behavior: same functions, no panics. Exits 0.
    let _depth = marker_gate(&data);
    let _len = length_gate(&data);
    let rest = data.get(8..).unwrap_or(&[]);
    let _ = payload_paths(rest);
}
