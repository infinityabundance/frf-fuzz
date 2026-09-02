#!/bin/sh
# One-command golden demonstration (master prompt §34; Phases 1-4).
#
# Proves end-to-end, on this machine, with the pinned nightly:
#   1. a target built with the fuzz_target! macro and the instrumented flags
#   2. multiple persistent workers fuzzing it (coverage-guided admission)
#   3. compare-guided substitution reaching a planted magic gate
#   4. a crash killing only its worker, with the exact candidate reproduced
#      (ledger echo) and a finding recorded + replayed
#   5. fsck validating the store, replay reproducing the finding
#   6. Path B (Phase 2): a behavior-changing trajectory with NO new coverage
#      is retained via residual signals (state features, morphologies,
#      structured-Unknown), amplified, and followed to a planted depth crash —
#      while a coverage-only run (`--residual=off`) shows no such signal and
#      does NOT reach the depth crash within the same budget.
#   7. Phase 3: the depth-crash lineage forms a durable precedent (DSFB
#      substrate verdicts + FuzzSemanticBank + precedent admission); the
#      store report shows structural verdicts/precedents and `precedent
#      list` renders the bank; fsck validates the precedent revision chain.
#   8. `frf-fuzz boundary` two-sided minimization on a stable/crash pair.
#   9. the engine-level precedent demo (acceptance items 10-12: a known
#      precedent proposes a falsify probe; the probe can support or
#      contradict; contradiction is durably retained and fsck-verified).
#  10. Phase 4 (acceptance items 15-17): a campaign with a real FRF
#      authority court-verifies promoted crash findings and retains the real
#      receipt ids; a real Gemel repository receives durable boundaries
#      (campaign checkpoints + verified-finding evidence/claim bound to the
#      head state); the authority-less control stores stay UNVERIFIED;
#      `verify` is idempotent; revision tape replay persists revision-
#      residual pairs across state artifacts.
#
# Usage: scripts/golden_demo.sh [nightly]
set -eu

NIGHTLY="${1:-nightly-2026-07-24}"
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

# Fresh scratch stores (never touch a user's .frf-fuzz).
SCRATCH="$(mktemp -d /tmp/frf-fuzz-demo.XXXXXX)"
SCRATCH_OFF="$(mktemp -d /tmp/frf-fuzz-demo-off.XXXXXX)"
trap 'rm -rf "$SCRATCH" "$SCRATCH_OFF"' EXIT

echo "=== 1. build the instrumented target ==="
# Touch the example so cargo rebuilds it even when RUSTFLAGS are unchanged
# (a cached stale instrumented binary silently skips new worker logic).
touch examples/golden_demo.rs
RUSTC_ID="$(rustc +"$NIGHTLY" -vV | head -1)"
LLVM_ID="$(rustc +"$NIGHTLY" -vV | grep '^LLVM')"
RUSTFLAGS="$FLAGS" FRF_FUZZ_RUSTC_IDENTITY="$RUSTC_ID" FRF_FUZZ_LLVM_IDENTITY="$LLVM_ID" \
  cargo +"$NIGHTLY" rustc --quiet --target "$TARGET" --example golden_demo -- -Cpanic=abort
BIN="target/$TARGET/debug/examples/golden_demo"
test -x "$BIN" || { echo "FAIL: binary not built"; exit 1; }

echo "=== 2. seed corpus ==="
for D in "$SCRATCH" "$SCRATCH_OFF"; do
  mkdir -p "$D/seeds"
  printf 'FRFZ\x00\x00AAAA' > "$D/seeds/seed-near-gate.bin"
  printf 'FRFZ\x01\x00' > "$D/seeds/seed-prefix.bin"
  : > "$D/seeds/seed-empty.bin"
done

run_campaign() {
  # $1 = store root, $2 = run label, $3 = residual mode
  local store="$1" label="$2" residual="$3"
  echo "=== 3. run the campaign ($label: residual=$residual, 8 workers, 15s) ==="
  cargo run --quiet --bin frf-fuzz -- run golden-demo \
    --root "$store" \
    --bin "$BIN" \
    --workers 8 \
    --batch-size 1000 \
    --seed 0xC0FFEE \
    --seed-dir "$store/seeds" \
    --max-time 15 \
    --nightly "$NIGHTLY" \
    --residual "$residual" \
    > "$store/run.out" 2>&1 || { tail -20 "$store/run.out"; echo "FAIL: campaign errored ($label)"; exit 1; }
  cat "$store/run.out"
}

run_campaign "$SCRATCH" "residual-on" "on"
run_campaign "$SCRATCH_OFF" "coverage-only" "off"

echo "=== 4. verify the residual machinery was active (residual-on) ==="
grep -q 'state features: [1-9]' "$SCRATCH/run.out" || { echo "FAIL: no state features recorded (residual-on)"; exit 1; }
grep -q 'morphologies: [1-9]' "$SCRATCH/run.out" || { echo "FAIL: no morphologies recorded (residual-on)"; exit 1; }
grep -q 'amplify orders: [1-9]' "$SCRATCH/run.out" || { echo "FAIL: no amplify orders (residual-on)"; exit 1; }

echo "=== 5. verify Path B: residual-on reaches the marker-depth crash ==="
DEPTH_FINDINGS="$(grep -l 'marker depth gate' "$SCRATCH"/.frf-fuzz/findings/*.txt 2>/dev/null | wc -l)"
if [ "$DEPTH_FINDINGS" -eq 0 ]; then
  echo "FAIL: residual-on found no marker-depth crash (Path B not demonstrated)"
  exit 1
fi
echo "marker-depth findings (residual-on): $DEPTH_FINDINGS"

# The residual-on campaign's ladder legitimately monopolizes the scheduler,
# so the cmp-driven magic gate is asserted on the coverage-only control
# (both runs share the same target and the same auto-discovered dictionary).
echo "=== 6. verify compare-guided discovery solves the magic gate (coverage-only) ==="
MAGIC_OFF="$(grep -l 'magic length gate' "$SCRATCH_OFF"/.frf-fuzz/findings/*.txt 2>/dev/null | head -1)"
if [ -z "$MAGIC_OFF" ]; then
  echo "FAIL: no magic-gate finding in the coverage-only run"
  cargo run --quiet --bin frf-fuzz -- report --root "$SCRATCH_OFF"
  exit 1
fi
MAGIC_FINDING_ID="$(basename "$MAGIC_OFF" .txt)"
echo "magic-gate finding (coverage-only): $MAGIC_FINDING_ID"

echo "=== 7. verify the coverage-only control does NOT reach the depth crash ==="
DEPTH_OFF="$(grep -l 'marker depth gate' "$SCRATCH_OFF"/.frf-fuzz/findings/*.txt 2>/dev/null | wc -l)"
if [ "$DEPTH_OFF" -ne 0 ]; then
  echo "FAIL: coverage-only unexpectedly found $DEPTH_OFF marker-depth crashes (negative control broke)"
  exit 1
fi
echo "marker-depth findings (coverage-only): $DEPTH_OFF (negative control holds)"

echo "=== 8. replay the magic-gate finding (coverage-only store) ==="
cargo run --quiet --bin frf-fuzz -- replay "$MAGIC_FINDING_ID" --root "$SCRATCH_OFF" --bin "$BIN" --nightly "$NIGHTLY" --target golden-demo | tee "$SCRATCH_OFF/replay.out"
grep -q 'REPRODUCED' "$SCRATCH_OFF/replay.out" || { echo "FAIL: finding did not replay"; exit 1; }

echo "=== 9. fsck the residual-on store ==="
cargo run --quiet --bin frf-fuzz -- fsck --root "$SCRATCH" || { echo "FAIL: fsck found defects"; exit 1; }

echo "=== 9b. verify Phase-3 endoduction objects in the residual store ==="
cargo run --quiet --bin frf-fuzz -- report --root "$SCRATCH" | tee "$SCRATCH/report.out"
grep -q 'structural verdicts: [1-9]' "$SCRATCH/report.out" \
  || { echo "FAIL: no structural verdict objects (Phase 3 substrate inactive)"; exit 1; }
grep -q 'precedent families: [1-9]' "$SCRATCH/report.out" \
  || { echo "FAIL: the depth-crash lineage did not form a durable precedent"; exit 1; }

echo "=== 9c. precedent list renders the bank ==="
cargo run --quiet --bin frf-fuzz -- precedent list --root "$SCRATCH" | tee "$SCRATCH/precedent.out"
grep -q 'status=' "$SCRATCH/precedent.out" || { echo "FAIL: precedent list empty"; exit 1; }

# The coverage-only control must NOT have formed precedents (its residual
# machinery — and therefore its precedent bank — was disabled).
echo "=== 9d. coverage-only control has no precedents ==="
cargo run --quiet --bin frf-fuzz -- report --root "$SCRATCH_OFF" > "$SCRATCH_OFF/report.out"
if grep -q 'precedent families: [1-9]' "$SCRATCH_OFF/report.out"; then
  echo "FAIL: coverage-only store unexpectedly formed precedents"
  exit 1
fi
echo "coverage-only precedents: 0 (control holds)"

echo "=== 9e. engine-level precedent demo (probe support + contradiction retention) ==="
cargo run --quiet --example precedent_engine_demo 2>/dev/null | tee "$SCRATCH/precedent-engine.out"
grep -q 'PRECEDENT ENGINE DEMO PASS' "$SCRATCH/precedent-engine.out" \
  || { echo "FAIL: precedent engine demo"; exit 1; }

echo "=== 10. two-sided boundary minimization on a stable/crash pair ==="
DEPTH_FINDING_ID="$(basename "$(grep -l 'marker depth gate' "$SCRATCH"/.frf-fuzz/findings/*.txt 2>/dev/null | head -1)" .txt)"
cargo run --quiet --bin frf-fuzz -- boundary "$DEPTH_FINDING_ID" \
  --root "$SCRATCH" --bin "$BIN" --nightly "$NIGHTLY" --target golden-demo --max-verify 20000 \
  | tee "$SCRATCH/boundary.out"
grep -q 'minimized: distance' "$SCRATCH/boundary.out" || { echo "FAIL: boundary minimization did not run"; exit 1; }

# ---------------------------------------------------------------------------
# Phase 4: FRF court verification at promotion + Gemel longitudinal memory
# ---------------------------------------------------------------------------
# Acceptance items 15-17:
#   15. with an authority configured, a promoted crash finding is court-
#       verified by the real FRF library and linked by its real receipt id;
#   16. without an authority, the same finding stays explicitly unverified
#       (the two Phase-1/3 stores above ran authority-less: their reports
#       must show zero verifications, never a fabricated one);
#   17. with a Gemel repository present, the promoted/verified result links
#       to the current Gemel state through durable boundaries (checkpoint on
#       campaign create/complete; evidence+claim for the verified finding)
#       with NO per-execution Gemel writes.

echo "=== 11. Phase 4: build the FRF authority (clean reference example) ==="
cargo build --quiet --example golden_authority || { echo "FAIL: authority build"; exit 1; }
AUTH="target/debug/examples/golden_authority"
test -x "$AUTH" || { echo "FAIL: authority not built"; exit 1; }

SCRATCH_P4="$(mktemp -d /tmp/frf-fuzz-demo-p4.XXXXXX)"
trap 'rm -rf "$SCRATCH" "$SCRATCH_OFF" "$SCRATCH_P4"' EXIT

# A real Gemel repository with a head state (evidence can bind a state).
echo "=== 12. Phase 4: initialize the Gemel repository ==="
cargo run --quiet --example phase4_gemel_init -- "$SCRATCH_P4" | tee "$SCRATCH_P4/gemel-init.out"
grep -q 'gemel repo ready' "$SCRATCH_P4/gemel-init.out" || { echo "FAIL: gemel init"; exit 1; }

mkdir -p "$SCRATCH_P4/seeds"
printf 'FRFZ\x00\x00AAAA' > "$SCRATCH_P4/seeds/seed-near-gate.bin"
printf 'FRFZ\x01\x00' > "$SCRATCH_P4/seeds/seed-prefix.bin"
: > "$SCRATCH_P4/seeds/seed-empty.bin"

echo "=== 13. Phase 4: campaign with FRF authority + Gemel (12s) ==="
cargo run --quiet --bin frf-fuzz -- run golden-demo \
  --root "$SCRATCH_P4" \
  --bin "$BIN" \
  --workers 8 \
  --batch-size 1000 \
  --seed 0xD15EA5E \
  --seed-dir "$SCRATCH_P4/seeds" \
  --max-time 12 \
  --nightly "$NIGHTLY" \
  --residual on \
  --authority "$AUTH" \
  --authority-name demo-ref \
  --authority-version 1.0 \
  --gemel on \
  > "$SCRATCH_P4/run.out" 2>&1 || { tail -20 "$SCRATCH_P4/run.out"; echo "FAIL: phase-4 campaign errored"; exit 1; }
cat "$SCRATCH_P4/run.out"

# The run banner must state the authority (and that findings are verified).
grep -q 'FRF authority: demo-ref-1.0' "$SCRATCH_P4/run.out" \
  || { echo "FAIL: campaign did not report the authority"; exit 1; }

# At least one crash finding was court-verified with a REAL receipt.
grep -q 'FRF VERIFIED finding=' "$SCRATCH_P4/run.out" \
  || { echo "FAIL: no FRF-verified finding (court did not reproduce the crash)"; exit 1; }
VERIFIED_ID="$(sed -n 's/.*FRF VERIFIED finding=\([0-9a-f]*\).*/\1/p' "$SCRATCH_P4/run.out" | head -1)"
echo "first FRF-verified finding: $VERIFIED_ID"

# Gemel boundaries were published (created + completed at minimum).
grep -q 'gemel boundary campaign-created' "$SCRATCH_P4/run.out" \
  || { echo "FAIL: no gemel campaign-created boundary"; exit 1; }
grep -q 'gemel boundary campaign-completed' "$SCRATCH_P4/run.out" \
  || { echo "FAIL: no gemel campaign-completed boundary"; exit 1; }
grep -q 'gemel boundaries: [1-9]' "$SCRATCH_P4/run.out" \
  || { echo "FAIL: no gemel boundary records persisted"; exit 1; }

echo "=== 14. Phase 4: report + fsck on the verified store ==="
cargo run --quiet --bin frf-fuzz -- report --root "$SCRATCH_P4" | tee "$SCRATCH_P4/report.out"
grep -q 'FRF verifications: [1-9]' "$SCRATCH_P4/report.out" \
  || { echo "FAIL: report shows no FRF verifications"; exit 1; }
grep -q 'verified: [1-9]' "$SCRATCH_P4/report.out" \
  || { echo "FAIL: report shows no verified findings"; exit 1; }
grep -q 'gemel boundaries: [1-9]' "$SCRATCH_P4/report.out" \
  || { echo "FAIL: report shows no gemel boundaries"; exit 1; }
cargo run --quiet --bin frf-fuzz -- fsck --root "$SCRATCH_P4" \
  || { echo "FAIL: fsck found defects in the verified store"; exit 1; }

# Acceptance item 16: the authority-less stores recorded NO verifications
# (unverified is derived, never fabricated).
echo "=== 15. Phase 4: authority-less control stays unverified ==="
cargo run --quiet --bin frf-fuzz -- report --root "$SCRATCH" > "$SCRATCH/control-report.out"
if grep -q 'FRF verifications: [1-9]' "$SCRATCH/control-report.out"; then
  echo "FAIL: authority-less store fabricated verifications"
  exit 1
fi
cargo run --quiet --bin frf-fuzz -- report --root "$SCRATCH_OFF" > "$SCRATCH_OFF/control-report.out"
if grep -q 'FRF verifications: [1-9]' "$SCRATCH_OFF/control-report.out"; then
  echo "FAIL: coverage-only authority-less store fabricated verifications"
  exit 1
fi
echo "authority-less findings: unverified (control holds)"

echo "=== 16. Phase 4: CLI verify is idempotent with the campaign evidence ==="
cargo run --quiet --bin frf-fuzz -- verify "$VERIFIED_ID" \
  --root "$SCRATCH_P4" \
  --authority "$AUTH" \
  --authority-name demo-ref \
  --authority-version 1.0 \
  --candidate "$BIN" \
  --gemel off 2>/dev/null | tee "$SCRATCH_P4/verify.out"
grep -q 'verification: VERIFIED' "$SCRATCH_P4/verify.out" \
  || { echo "FAIL: CLI verify did not verify the finding"; exit 1; }
grep -q 'frf receipt: receipt-' "$SCRATCH_P4/verify.out" \
  || { echo "FAIL: CLI verify returned no receipt"; exit 1; }

echo "=== 17. Phase 4: revision tape replay across states ==="
cargo run --quiet --bin frf-fuzz -- revision replay "$VERIFIED_ID" \
  --root "$SCRATCH_P4" \
  --target golden-demo \
  --bin "$BIN" \
  --nightly "$NIGHTLY" \
  --state rev-A="$BIN" \
  --state rev-B="$BIN" 2>/dev/null | tee "$SCRATCH_P4/revision.out"
grep -q 'revision pairs: 1' "$SCRATCH_P4/revision.out" \
  || { echo "FAIL: revision replay persisted no pair"; exit 1; }
cargo run --quiet --bin frf-fuzz -- fsck --root "$SCRATCH_P4" \
  || { echo "FAIL: fsck found defects after revision replay"; exit 1; }

# The Gemel repo received durable evidence for the verified finding.
BOUNDARY_REC="$(cargo run --quiet --bin frf-fuzz -- report --root "$SCRATCH_P4" --json 2>/dev/null | sed -n 's/.*\"gemel_boundaries\":\([0-9]*\).*/\1/p')"
echo "gemel boundary records: $BOUNDARY_REC"
[ "${BOUNDARY_REC:-0}" -ge 3 ] || { echo "FAIL: expected >= 3 gemel boundary records"; exit 1; }

echo
echo "GOLDEN DEMO PASS"
