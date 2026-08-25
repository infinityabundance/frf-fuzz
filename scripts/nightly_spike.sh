#!/bin/sh
# Phase-0 nightly instrumentation spike: build and run the crate's own
# sancov_demo example with the pinned nightly and the verified flag set, and
# verify ASan catches a real fault in the separate ASan-mode build.
#
# Two verified flag sets (docs/COMPATIBILITY.md):
#   mode=default : sancov + trace-compares, NO ASan (the standard instrumented
#                  build; ASan + trace-compares + Rust callbacks cannot
#                  coexist on LLVM >= 18 — Phase-0 finding).
#   mode=asan    : ASan + sancov counters, trace-compares DISABLED (opt-in
#                  for unsafe/native targets; memory-error detection instead
#                  of compare feedback).
#
# Usage: scripts/nightly_spike.sh [nightly]
set -eu

NIGHTLY="${1:-nightly-2026-04-21}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# NOTE: -Cpanic=abort must NOT go into RUSTFLAGS: cargo builds proc-macro
# crates with panic=unwind and RUSTFLAGS is appended last, so a global
# -Cpanic=abort breaks them ("can't find crate for clap_derive"). panic=abort
# is applied to the FINAL target only via `cargo rustc -- ...`.
# The build MUST pass `--target <triple>`: RUSTFLAGS then apply only to
# target-triple crates; HOST crates (proc-macros, build scripts) are built
# without them, which is what keeps `-Zsanitizer` from breaking them.

TARGET="x86_64-unknown-linux-gnu"

COMMON="-Cpasses=sancov-module \
-Cllvm-args=-sanitizer-coverage-level=4 \
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
-Cllvm-args=-sanitizer-coverage-pc-table \
-Copt-level=3 \
-Cdebug-assertions=yes \
-Coverflow-checks=yes \
-Clto=off"

DEFAULT_FLAGS="$COMMON -Cllvm-args=-sanitizer-coverage-trace-compares"
ASAN_FLAGS="-Zsanitizer=address $COMMON"

run_target() {
  local example="$1"; shift
  local flags="$1"; shift
  RUSTFLAGS="$flags" cargo +"$NIGHTLY" rustc --quiet --target "$TARGET" --example "$example" -- -Cpanic=abort
  local bin="target/$TARGET/debug/examples/$example"
  "$bin" "$@"
}

echo "=== nightly identity ==="
rustc +"$NIGHTLY" -vV | grep -E '^(rustc|LLVM|commit-hash)'

echo
echo "=== default mode: sancov_demo (sancov + trace-compares, no ASan) ==="
run_target sancov_demo "$DEFAULT_FLAGS" 0xDEADBEEF
sancov_rc=$?
echo "sancov_demo exit: $sancov_rc"
if [ "$sancov_rc" -ne 0 ]; then
  echo "sancov_demo FAILED (exit $sancov_rc)"
  exit 1
fi

echo
echo "=== asan mode: asan_crash (ASan catches a real OOB; no trace-compares) ==="
run_target asan_crash "$ASAN_FLAGS" > /tmp/asan_demo_out.txt 2>&1 || true
echo "--- ASan output (first 12 lines) ---"
head -12 /tmp/asan_demo_out.txt
if grep -q 'AddressSanitizer' /tmp/asan_demo_out.txt; then
  echo "ASan detected the memory error: PASS"
else
  echo "ASan did NOT detect the memory error: FAIL"
  exit 1
fi
