#!/bin/sh
# Baseline comparison (master prompt §31; docs/EXPERIMENT_PROTOCOL.md §2).
#
# Compares `frf-fuzz` against independent fuzzers "where practical":
#   * cargo-fuzz / libFuzzer (installed here) — a scratch cargo-fuzz harness
#     of the SAME golden-demo gates, run for the same budget;
#   * AFL++ — skipped with a message when `afl-fuzz` is not installed.
#
# Discipline (protocol §2, §9):
#   * baselines are built from their pinned/current upstream (the installed
#     cargo-fuzz version is recorded);
#   * this script is INFORMATIONAL ONLY: single trials, one machine, one
#     budget — never publication evidence. Repeated independent trials at
#     FuzzBench scale are a batch job the protocol prescribes; this script
#     exists so the comparison plumbing is real and runnable, not narrated.
#   * the cargo-fuzz harness is a plain libFuzzer target (no residual
#     machinery exists in libFuzzer); the frf-fuzz side is the `full` arm of
#     `frf-fuzz experiment`, so the comparison is coverage-guided corpus vs
#     residual-guided corpus at equal wall-clock budgets.
#
# Usage: scripts/baseline_compare.sh [nightly] [budget-secs]
set -eu

NIGHTLY="${1:-nightly-2026-07-24}"
BUDGET="${2:-10}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== baseline tool availability ==="
CARGO_FUZZ="$(command -v cargo-fuzz || true)"
AFL="$(command -v afl-fuzz || true)"
echo "cargo-fuzz: ${CARGO_FUZZ:-not installed}"
echo "afl-fuzz:   ${AFL:-not installed}"

SCRATCH="$(mktemp -d /tmp/frf-fuzz-base.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

# ---------------------------------------------------------------------------
# AFL++ (optional; absent toolchains are recorded, never faked)
# ---------------------------------------------------------------------------
if [ -z "$AFL" ]; then
  echo
  echo "=== AFL++ baseline: SKIPPED (afl-fuzz not installed) ==="
  echo "recorded as unavailable in this environment (protocol: 'where practical')."
else
  echo
  echo "=== AFL++ baseline: TODO (afl-clang-fast wrapper harness not shipped; see EXPERIMENT_PROTOCOL.md) ==="
  echo "afl-fuzz is present but an AFL++ harness build for the golden gates is not part of this"
  echo "crate; record the AFL++ version and build one for publication-grade comparisons."
  afl-fuzz -V 2>&1 | head -1 || true
fi

# ---------------------------------------------------------------------------
# cargo-fuzz / libFuzzer baseline
# ---------------------------------------------------------------------------
if [ -z "$CARGO_FUZZ" ]; then
  echo
  echo "=== cargo-fuzz baseline: SKIPPED (cargo-fuzz not installed) ==="
  exit 0
fi

echo
echo "=== cargo-fuzz / libFuzzer baseline (informational, single trial) ==="
CFVER="$(cargo fuzz --version 2>&1 | head -1)"
echo "baseline tool: $CFVER"
echo "budget: ${BUDGET}s per side"

# The scratch cargo-fuzz package: a plain libFuzzer harness with the SAME
# planted gates as examples/golden_demo.rs (no frf-fuzz runtime, no signals).
mkdir -p "$SCRATCH/fuzzproj/src" "$SCRATCH/fuzzproj/fuzz/fuzz_targets"
cat > "$SCRATCH/fuzzproj/Cargo.toml" <<'EOF'
[package]
name = "fuzzproj"
version = "0.1.0"
edition = "2021"

[workspace]
members = ["fuzz"]

[dependencies]
EOF
printf 'pub fn placeholder() {}\n' > "$SCRATCH/fuzzproj/src/lib.rs"
cat > "$SCRATCH/fuzzproj/fuzz/Cargo.toml" <<'EOF'
[package]
name = "fuzzproj-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"

[[bin]]
name = "golden"
path = "fuzz_targets/golden.rs"
test = false
doc = false
EOF
cat > "$SCRATCH/fuzzproj/fuzz/fuzz_targets/golden.rs" <<'EOF'
#![no_main]
// The golden-demo gates as a plain libFuzzer target (baseline comparison).
// Identical planted defects to examples/golden_demo.rs, WITHOUT the
// frf-fuzz target runtime: this is the "ordinary coverage fuzzer" baseline.
use libfuzzer_sys::fuzz_target;

fn marker_depth(data: &[u8]) -> u64 {
    let mut depth = 0u64;
    if data.len() > 8 && data[8] == 0x42 {
        depth += 1;
    }
    for &b in data {
        if b == 0x42 {
            depth += 1;
        }
    }
    depth
}

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
        panic!("golden demo: magic length gate hit (0xBEEF)");
    }
    u32::from(len)
}

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
    if acc == 0xDEAD_BEEF {
        panic!("golden demo: second-stage gate hit");
    }
    acc
}

fuzz_target!(|data: &[u8]| {
    // Path B: the marker-depth panic (residual-guided fuzzers reach this via
    // their drift channel; a plain coverage fuzzer has no such signal).
    if marker_depth(data) > 32 {
        panic!("golden demo: marker depth gate hit");
    }
    let _l = length_gate(data);
    let rest = data.get(8..).unwrap_or(&[]);
    let _ = payload_paths(rest);
});
EOF

# Same seed corpus as the frf-fuzz side.
mkdir -p "$SCRATCH/fuzzproj/corpus"
printf 'FRFZ\x00\x00AAAA' > "$SCRATCH/fuzzproj/corpus/seed-near-gate"
printf 'FRFZ\x01\x00' > "$SCRATCH/fuzzproj/corpus/seed-prefix"
: > "$SCRATCH/fuzzproj/corpus/seed-empty"

cd "$SCRATCH/fuzzproj"
echo "--- building the libFuzzer harness (pinned nightly) ---"
if ! RUSTUP_TOOLCHAIN="$NIGHTLY" cargo fuzz build golden > "$SCRATCH/fuzz-build.log" 2>&1; then
  echo "FAIL: cargo-fuzz build failed — recorded, baseline skipped (environmental):"
  tail -5 "$SCRATCH/fuzz-build.log"
  echo "cargo-fuzz baseline: SKIPPED (build failure; see above)"
  exit 0
fi

echo "--- running libFuzzer (${BUDGET}s, informational single trial) ---"
FUZZBIN="$SCRATCH/fuzzproj/target/x86_64-unknown-linux-gnu/release/golden"
mkdir -p "$SCRATCH/cf-artifacts"
# Run the built fuzzer binary directly (cargo-fuzz forwards the child to the
# terminal, which would bypass the script's capture).
# shellcheck disable=SC2086
"$FUZZBIN" -max_total_time="$BUDGET" -print_final_stats=1 \
  -artifact_prefix="$SCRATCH/cf-artifacts/" "$SCRATCH/fuzzproj/corpus" \
  > "$SCRATCH/libfuzzer.out" 2>&1 || true

echo "--- libFuzzer result summary ---"
grep -E "stat::|#.*(pulse|DONE)|deadly signal|ERROR: libFuzzer" \
  "$SCRATCH/libfuzzer.out" | tail -8 || true
ARTIFACTS="$(ls "$SCRATCH/cf-artifacts/" 2>/dev/null | wc -l)"
echo "libFuzzer crash artifacts: $ARTIFACTS"
if [ "$ARTIFACTS" -gt 0 ]; then
  for f in "$SCRATCH"/cf-artifacts/*; do
    echo "artifact: $(basename "$f")"
  done
fi

echo
echo "BASELINE COMPARE (informational) — record the following side by side:"
echo "  libFuzzer:  single trial, ${BUDGET}s, artifacts=$ARTIFACTS (stats above)"
echo "  frf-fuzz:   run: scripts/phase8_ablation_demo.sh (full-arm trial rows)"
echo "CAVEAT: single trials on one machine are NOT evidence (protocol §9)."
