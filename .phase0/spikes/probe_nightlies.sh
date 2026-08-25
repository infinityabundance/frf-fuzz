#!/bin/sh
# Phase-0 spike: find which installed nightly toolchain supports the
# SanitizerCoverage + ASan flag set used for instrumented fuzz targets.
# Tests BOTH pass names: `sancov` (pre-LLVM-20) and `sancov-module` (current).
# Records exact rustc/LLVM identity of the chosen toolchain.
set -u

SRC=".phase0/spikes/sancov_probe.rs"
OUT_DIR=".phase0/spikes/out"
mkdir -p "$OUT_DIR"

for NIGHTLY in nightly-2026-04-21 nightly-2025-11-25 nightly-2025-11-21 nightly-2025-11-08 nightly-2025-09-14 nightly-2025-09-01 nightly-2025-07-24 nightly-2025-04-01; do
  echo "=== $NIGHTLY ==="
  if ! rustup toolchain list | grep -q "$NIGHTLY"; then
    echo "  (not installed)"
    continue
  fi
  for PASS in sancov sancov-module; do
    BIN="$OUT_DIR/sancov_probe_${NIGHTLY}_${PASS}"
    rm -f "$BIN"
    RUSTC_OUT=$(rustc +"$NIGHTLY" "$SRC" -o "$BIN" \
      -Zsanitizer=address \
      -Cpasses="$PASS" \
      -Cllvm-args=-sanitizer-coverage-level=4 \
      -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
      -Cllvm-args=-sanitizer-coverage-pc-table \
      -Cllvm-args=-sanitizer-coverage-trace-compares \
      -Cpanic=abort 2>&1)
    RC=$?
    if [ $RC -ne 0 ]; then
      ERR=$(echo "$RUSTC_OUT" | grep -E '^error' | head -1)
      echo "  pass=$PASS: COMPILE FAILED (rc=$RC) $ERR"
      continue
    fi
    RUN_OUT=$("$BIN" 0xDEADBEEF 2>&1)
    RUN_RC=$?
    PASSED=$(echo "$RUN_OUT" | grep -c '\[spike\] PASS')
    echo "  pass=$PASS: compile OK, run rc=$RUN_RC, PASS=$PASSED"
    echo "$RUN_OUT" | grep '\[spike\]' | sed 's/^/      /'
  done
  echo "  --- identity ---"
  rustc +"$NIGHTLY" -vV | grep -E '^(rustc|LLVM|commit-hash)' | sed 's/^/    /'
done
