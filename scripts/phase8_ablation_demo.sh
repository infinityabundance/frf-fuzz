#!/bin/sh
# Phase-8 scientific-evaluation demonstration (master prompt §31-§33;
# docs/EXPERIMENT_PROTOCOL.md §2-§5).
#
# Runs `frf-fuzz experiment` over the four code-level ablation arms on the
# golden-demo target (the same planted gates as scripts/golden_demo.sh):
#
#   cov       coverage only                  (cmp off, residual off, precedent off)
#   cov+cmp   coverage + compare operands    (cmp on)
#   residual  + residual sketch + DSFB       (cmp on, residual on)
#   full      + precedent scheduling         (cmp on, residual on, precedent on)
#
# Repeated independent trials per arm (fresh store per trial, deterministic
# per-trial seeds shared across arms), raw-series export, and the
# median/A12/Mann-Whitney comparison table. The assertions are the ablation
# semantics the engine was built for:
#
#   1. arms WITHOUT the residual machinery (cov, cov+cmp) never record a
#      structural trajectory: morphologies = 0, regime episodes = 0,
#      amplify orders = 0, in every trial (deterministic: the machinery is
#      compiled out of the scheduler by the arm switch);
#   2. compare guidance (cov+cmp) reaches the planted magic gate;
#   3. arms WITH the residual machinery (residual, full) retain the
#      behavior-changing Path-B trajectory: morphologies > 0 and a drift
#      state-feature space beyond the seed baseline in every trial, and they
#      reach failures;
#   4. the raw-series export is the recomputation authority: mandatory
#      metadata record + one row per (arm, trial, metric), and the JSON
#      analysis is well-formed and carries the power caveat — the CLI never
#      bakes an unsupported statistical claim.
#
# Honest observation recorded by this demo (Phase 8): at demo budgets the
# magic gate is NOT exclusive to compare guidance — a coverage-only arm can
# occasionally reach it blindly (~340k execs) because the near-gate seed and
# the integer/boundary mutators co-evolve the magic value through the
# corpus. The claim the ablation DOES demonstrate deterministically is the
# engine's core one: no residual machinery, no retained behavioral
# trajectory; residual machinery, the trajectory appears, is retained, and
# failures are reached on the Path-B ladder that coverage alone has no
# signal for. (Closed regime episodes are typically 0 in this demo because
# the ladder's lineages END in crashes while still InEpisode — an episode
# closes on recovery/collapse, which a crash prevents; open trajectories are
# the honest observation. Episode formation/close semantics are pinned at
# engine level in tests/residual_semantics.rs.)
#
# Usage: scripts/phase8_ablation_demo.sh [nightly]
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

SCRATCH="$(mktemp -d /tmp/frf-fuzz-exp.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

echo "=== 1. build the instrumented golden-demo target ==="
touch examples/golden_demo.rs
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

echo "=== 3. run the ablation experiment (4 arms x 2 trials x 10 s) ==="
cargo run --quiet --bin frf-fuzz -- experiment golden-demo \
  --root "$SCRATCH" \
  --bin "$BIN" \
  --nightly "$NIGHTLY" \
  --arms cov,cov+cmp,residual,full \
  --trials 2 \
  --max-time 10 \
  --workers 8 \
  --batch-size 1000 \
  --seed 0xC0FFEE \
  --seed-dir "$SCRATCH/seeds" \
  --out "$SCRATCH/experiments" \
  --json > "$SCRATCH/experiment.out" 2> "$SCRATCH/experiment.err" \
  || { tail -30 "$SCRATCH/experiment.err"; echo "FAIL: experiment run errored"; exit 1; }

# The record lives under the experiments dir; capture its path.
RECORD="$(sed -n 's/.*"record": "\([^"]*\)".*/\1/p' "$SCRATCH/experiment.out" | head -1)"
SERIES="$(sed -n 's/.*"series": "\([^"]*\)".*/\1/p' "$SCRATCH/experiment.out" | head -1)"
test -n "$RECORD" || { echo "FAIL: no record path in output"; exit 1; }
test -f "$SERIES" || { echo "FAIL: series.csv not written"; exit 1; }
test -f "$RECORD/analysis.txt" || { echo "FAIL: analysis.txt not written"; exit 1; }
cat "$RECORD/analysis.txt"

echo "=== 4. verify the JSON analysis is well-formed ==="
grep -q '"metrics"' "$SCRATCH/experiment.out" || { echo "FAIL: JSON missing metrics"; exit 1; }
grep -q '"first_failure_seconds"' "$SCRATCH/experiment.out" || { echo "FAIL: JSON missing censored metric"; exit 1; }
grep -q 'Power caveat' "$RECORD/analysis.txt" || { echo "FAIL: analysis missing the power caveat"; exit 1; }
grep -q 'raw per-trial facts' "$RECORD/analysis.txt" || { echo "FAIL: caveat content missing"; exit 1; }

# Per-arm metric values out of the exported series: `arm,trial,seed,metric,unit,value`.
values_for() {
  # $1 = arm code, $2 = metric code; prints the values (one per line).
  awk -F, -v arm="$1" -v metric="$2" '$1==arm && $4==metric { print $6 }' "$SERIES"
}

echo "=== 5. negative control: no residual machinery, no trajectory ==="
for arm in cov cov+cmp; do
  for metric in morphologies regime_episodes amplify_orders precedent_matches; do
    for v in $(values_for "$arm" "$metric"); do
      [ "$v" = "0.000000" ] || { echo "FAIL: $arm arm recorded $metric=$v (expected 0)"; exit 1; }
    done
  done
done
echo "cov / cov+cmp trajectories: all zero (control holds)"

echo "=== 6. compare guidance reaches the magic gate (cov+cmp findings > 0) ==="
CC=0
for v in $(values_for cov+cmp findings); do
  case "$v" in 0.000000) : ;; *) CC=1 ;; esac
done
[ "$CC" = "1" ] || { echo "FAIL: cov+cmp arm found no crash"; exit 1; }
echo "cov+cmp findings: > 0"

echo "=== 7. residual arms retain the Path-B trajectory ==="
for arm in residual full; do
  # Morphology retention per trial: the first signature appears within the
  # first second of drift. State features: residual arms accumulate drift
  # buckets far beyond the seed-baseline bucket (cov/cov+cmp sit at 1).
  for v in $(values_for "$arm" morphologies); do
    case "$v" in
      0.000000) echo "FAIL: $arm arm trial recorded morphologies=0 (Path B not retained)"; exit 1 ;;
      *) : ;;
    esac
  done
  for v in $(values_for "$arm" state_features); do
    HIGH="$(awk -v x="$v" 'BEGIN{ exit !(x >= 2.0) }' && echo 1 || echo 0)"
    [ "$HIGH" = "1" ] || { echo "FAIL: $arm arm trial recorded state_features=$v (expected drift beyond the seed baseline)"; exit 1; }
  done
done
echo "residual/full morphologies: > 0 and state features beyond baseline in every trial"

echo "=== 8. residual/full reach failures ==="
for arm in residual full; do
  TF=0
  for v in $(values_for "$arm" findings); do
    case "$v" in 0.000000) : ;; *) TF=1 ;; esac
  done
  [ "$TF" = "1" ] || { echo "FAIL: $arm arm found no failure"; exit 1; }
done
echo "residual/full findings: > 0"

echo "=== 9. the series export is the recomputation authority ==="
grep -q '^# target: golden-demo' "$SERIES" || { echo "FAIL: series missing target metadata"; exit 1; }
grep -q '^# nightly:' "$SERIES" || { echo "FAIL: series missing nightly metadata"; exit 1; }
grep -q '^# rustc:' "$SERIES" || { echo "FAIL: series missing rustc metadata"; exit 1; }
grep -q '^# trial_seeds:' "$SERIES" || { echo "FAIL: series missing trial-seed record"; exit 1; }
NROWS="$(grep -cv '^#' "$SERIES")"
# header + 4 arms x 2 trials x 15 metrics = 121 lines (header included).
[ "$NROWS" = "121" ] || { echo "FAIL: unexpected series size ($NROWS rows)"; exit 1; }

echo
echo "PHASE 8 ABLATION DEMO PASS"
