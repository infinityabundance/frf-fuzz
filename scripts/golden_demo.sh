#!/bin/sh
# One-command golden demonstration (master prompt §34; Phase-1 subset).
#
# Proves end-to-end, on this machine, with the pinned nightly:
#   1. a target built with the fuzz_target! macro and the instrumented flags
#   2. multiple persistent workers fuzzing it (coverage-guided admission)
#   3. compare-guided substitution reaching a planted magic gate
#   4. a crash killing only its worker, with the exact candidate reproduced
#      (ledger echo) and a finding recorded + replayed
#   5. fsck validating the store, replay reproducing the finding
#
# Usage: scripts/golden_demo.sh [nightly]
set -eu

NIGHTLY="${1:-nightly-2026-04-21}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET="x86_64-unknown-linux-gnu"
FLAGS="-Cpasses=sancov-module \
-Cllvm-args=-sanitizer-coverage-level=4 \
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
-Cllvm-args=-sanitizer-coverage-pc-table \
-Cllvm-args=-sanitizer-coverage-trace-compares \
-Copt-level=3 \
-Cdebug-assertions=yes \
-Coverflow-checks=yes \
-Clto=off"

# A fresh scratch store (never touch a user's .frf-fuzz).
SCRATCH="$(mktemp -d /tmp/frf-fuzz-demo.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

echo "=== 1. build the instrumented target ==="
RUSTC_ID="$(rustc +"$NIGHTLY" -vV | head -1)"
LLVM_ID="$(rustc +"$NIGHTLY" -vV | grep '^LLVM')"
RUSTFLAGS="$FLAGS" FRF_FUZZ_RUSTC_IDENTITY="$RUSTC_ID" FRF_FUZZ_LLVM_IDENTITY="$LLVM_ID" \
  cargo +"$NIGHTLY" rustc --quiet --target "$TARGET" --example golden_demo -- -Cpanic=abort
BIN="target/$TARGET/debug/examples/golden_demo"
test -x "$BIN" || { echo "FAIL: binary not built"; exit 1; }

echo "=== 2. seed corpus ==="
mkdir -p "$SCRATCH/seeds"
printf 'FRFZ\x00\x00AAAA' > "$SCRATCH/seeds/seed-near-gate.bin"
printf 'FRFZ\x01\x00' > "$SCRATCH/seeds/seed-prefix.bin"
: > "$SCRATCH/seeds/seed-empty.bin"

echo "=== 3. run the campaign (8 workers, 15s) ==="
cargo run --quiet --bin frf-fuzz -- run golden-demo \
  --root "$SCRATCH" \
  --bin "$BIN" \
  --workers 8 \
  --batch-size 1000 \
  --seed 0xC0FFEE \
  --seed-dir "$SCRATCH/seeds" \
  --max-time 15 \
  --nightly "$NIGHTLY" \
  > "$SCRATCH/run.out" 2>&1 || { tail -20 "$SCRATCH/run.out"; echo "FAIL: campaign errored"; exit 1; }
cat "$SCRATCH/run.out"

echo "=== 4. verify the campaign found the magic gate ==="
FINDING_ID="$(cargo run --quiet --bin frf-fuzz -- report --root "$SCRATCH" --json 2>/dev/null | grep -o '"id":"[0-9a-f]\{64\}"' | head -1 | cut -d'"' -f4)"
if [ -z "$FINDING_ID" ]; then
  echo "FAIL: no finding recorded"
  cargo run --quiet --bin frf-fuzz -- report --root "$SCRATCH"
  exit 1
fi
echo "finding: $FINDING_ID"

echo "=== 5. replay the finding ==="
cargo run --quiet --bin frf-fuzz -- replay "$FINDING_ID" --root "$SCRATCH" --bin "$BIN" --nightly "$NIGHTLY" --target golden-demo | tee "$SCRATCH/replay.out"
grep -q 'REPRODUCED' "$SCRATCH/replay.out" || { echo "FAIL: finding did not replay"; exit 1; }

echo "=== 6. fsck the store ==="
cargo run --quiet --bin frf-fuzz -- fsck --root "$SCRATCH" || { echo "FAIL: fsck found defects"; exit 1; }

echo "=== 7. tmin the finding ==="
cargo run --quiet --bin frf-fuzz -- tmin "$FINDING_ID" --root "$SCRATCH" --bin "$BIN" --nightly "$NIGHTLY" --target golden-demo --max-verify 4000 | tee "$SCRATCH/tmin.out"

echo
echo "GOLDEN DEMO PASS"
