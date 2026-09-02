#!/bin/sh
# End-to-end CLI smoke test: `cargo frf-fuzz init / add / build / run` in a
# scratch Cargo project, plus report/fsck on the resulting store.
#
# This exercises the full user-facing surface (master prompt §4): a normal
# binary target in the user's EXISTING crate, built with the pinned nightly
# and the verified instrumentation flag set.
#
# Usage: scripts/cli_smoke.sh [nightly]
set -eu

NIGHTLY="${1:-nightly-2026-07-24}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="$(mktemp -d /tmp/frf-fuzz-cli.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

FF="cargo run --quiet --manifest-path "$ROOT/Cargo.toml" --bin frf-fuzz --"

# ---- scratch Cargo project with a tiny library ----
mkdir -p "$SCRATCH/myproj/src/bin"
cat > "$SCRATCH/myproj/Cargo.toml" <<EOF
[package]
name = "myproj"
version = "0.1.0"
edition = "2021"

[dependencies]
frf-fuzz = { path = "$ROOT", default-features = false, features = ["target-runtime"] }
EOF
cat > "$SCRATCH/myproj/src/lib.rs" <<'EOF'
pub fn parse(data: &[u8]) -> usize {
    if data.len() > 4 && &data[0..4] == b"FRFZ" { data.len() - 4 } else { 0 }
}
EOF

cd "$SCRATCH/myproj"

echo "=== 1. init ==="
$FF init
test -d .frf-fuzz/objects/blake3

echo "=== 2. add demo ==="
$FF add demo
test -f src/bin/frf_fuzz_demo.rs

echo "=== 3. build (pinned nightly, instrumented) ==="
$FF build demo --nightly "$NIGHTLY"
BIN="target/x86_64-unknown-linux-gnu/debug/frf_fuzz_demo"
test -x "$BIN"

echo "=== 4. run a short campaign ==="
$FF run demo --nightly "$NIGHTLY" --workers 2 --batch-size 500 --max-time 5 | tee run.out
grep -q 'executions:' run.out

echo "=== 5. report + fsck ==="
$FF report | tee report.out
grep -q 'corpus entries:' report.out
$FF fsck | tee fsck.out
grep -q 'fsck: ok' fsck.out

# Phase-4 CLI surface: the authority-less store reports zero FRF
# verifications (derived unverified), and the new commands refuse cleanly
# without their required arguments.
echo "=== 6. phase-4 CLI surface ==="
grep -q 'FRF verifications: 0' report.out || { echo "FAIL: authority-less store fabricated verifications"; exit 1; }
grep -q 'gemel boundaries: 0' report.out || { echo "FAIL: gemel boundaries reported without a repo"; exit 1; }
if $FF verify 0000000000000000000000000000000000000000000000000000000000000000 > verify-noauth.out 2>&1; then
  echo "FAIL: verify without --authority succeeded"
  exit 1
fi
grep -q 'requires .--authority.' verify-noauth.out || { echo "FAIL: verify error not actionable"; exit 1; }
if $FF revision replay 0000000000000000000000000000000000000000000000000000000000000000 > revision-noargs.out 2>&1; then
  echo "FAIL: revision replay without states succeeded"
  exit 1
fi
grep -q 'no object' revision-noargs.out || { echo "FAIL: revision replay error not actionable"; exit 1; }

echo
echo "CLI SMOKE PASS"
