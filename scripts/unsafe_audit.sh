#!/bin/sh
# Unsafe audit for frf-fuzz.
#
# Fails when actual `unsafe` keyword usage appears OUTSIDE the approved
# modules (docs/INVARIANTS.md, "Unsafe policy"). The approved zones are
# exactly:
#
#   src/target_runtime/sancov.rs        (SanitizerCoverage registration/scan)
#   src/target_runtime/cmp.rs           (raw ring; the only alloc-free callback storage)
#   src/target_runtime/worker.rs        (libc FFI boundary: signal/setitimer worker timeout)
#   src/simd/mod.rs                     (AVX2 runtime dispatch)
#   src/simd/x86_avx2.rs                (AVX2 intrinsics)
#   src/execute/crash_ledger.rs         (memmap2 syscall boundary)
#   src/execute/coordinator.rs          (libc SIGINT handler install)
#
# Prose mentions of the word "unsafe" in comments are not violations; only
# keyword usage (`unsafe {`, `unsafe fn`, `unsafe extern`, `unsafe trait`,
# `unsafe impl`) is checked.
#
# Usage: scripts/unsafe_audit.sh   (exit 0 = clean, 1 = violation)
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APPROVED="\
src/target_runtime/sancov.rs \
src/target_runtime/cmp.rs \
src/target_runtime/worker.rs \
src/simd/mod.rs \
src/simd/x86_avx2.rs \
src/execute/crash_ledger.rs \
src/execute/coordinator.rs"

# Actual keyword usage (not the lint name, not prose).
KEYWORD='unsafe[[:space:]]*[{(]|unsafe[[:space:]]+(fn|extern|trait|impl|const[[:space:]]+fn)'

status=0

# 1. src/ outside the approved modules: any keyword usage is a violation.
for f in $(find src -name '*.rs' | sort); do
  case " $APPROVED " in
    *" $f "*) continue ;;
  esac
  if grep -nE "$KEYWORD" "$f" > /dev/null 2>&1; then
    echo "VIOLATION: 'unsafe' keyword in unapproved module: $f"
    grep -nE "$KEYWORD" "$f" | sed 's/^/    /'
    status=1
  fi
done

# 2. In approved modules, every unsafe block/function must carry a SAFETY
#    comment. Per-block proximity is a review gate (noisy to automate for
#    declarations whose contracts live in doc comments); this structural
#    check requires every approved file to contain at least one SAFETY
#    comment and prints the count for the review trail.
for f in $APPROVED; do
  [ -f "$f" ] || continue
  n=$(grep -c 'SAFETY:' "$f" || true)
  if [ "$n" -eq 0 ]; then
    echo "VIOLATION: approved module has no SAFETY comments: $f"
    status=1
  else
    echo "info: $f has $n SAFETY comment(s)"
  fi
done

# 3. No keyword usage outside src/ except the documented asan_crash example.
for f in $(find . -name '*.rs' -not -path './target/*' -not -path './.phase0/*' | sort); do
  [ -f "$f" ] || continue
  case "$f" in
    */examples/asan_crash.rs) continue ;;  # documented deliberate OOB demo
  esac
  case "$f" in
    ./src/*) continue ;;  # handled by checks 1-2
  esac
  if grep -qE "$KEYWORD" "$f" 2>/dev/null; then
    echo "VIOLATION: 'unsafe' keyword in: $f"
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "unsafe audit: clean (approved zones only)"
else
  echo "unsafe audit: FAILED"
fi
exit "$status"
