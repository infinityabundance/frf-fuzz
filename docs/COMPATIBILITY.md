# frf-fuzz Compatibility

Status: Phase 3. This document records the empirically verified toolchain
matrix and the flag sets the instrumented target build uses. The claims were
first reproduced on this machine during Phase 0 and re-verified in Phase 3
after the MSRV raise and nightly re-pin; the commands live in
`.phase0/spikes/` and `scripts/nightly_spike.sh`.

## 1. Coordinator

* Stable Rust >= 1.98 (edition 2021, `rust-version = "1.98"` in
  Cargo.toml), any later stable.
* Verified: `cargo +1.98.0 test` passes with default features AND with
  `--no-default-features --features target-runtime`.
* The coordinator MSRV was raised to 1.98 during Phase 3 by explicit user
  decision (use the latest stable rustc), not by dependency pressure; the
  instrumented nightly was re-pinned and re-verified accordingly (rustc
  1.99.0-nightly satisfies the `rust-version` 1.98 requirement that Cargo
  now enforces).
* The coordinator builds with whatever stable toolchain is installed; the
  `doctor` verifies >= MSRV at runtime.

## 2. Instrumented fuzz target — the pinned nightly

The instrumented target build requires nightly (SanitizerCoverage +
sanitizer flags). The pin is **`nightly-2026-07-24`**:

```
rustc 1.99.0-nightly (89c61a754 2026-07-23)
LLVM version: 22.1.8
```

The pin was re-verified and re-pinned during Phase 3 after the MSRV raise:
the previous pin's rustc sat below 1.98, which Cargo refuses for a crate
with `rust-version = "1.98"`; the instrumented flag set was re-proven
end-to-end on the new pin by `scripts/nightly_spike.sh` and
`scripts/golden_demo.sh`.

`frf-fuzz doctor` verifies the requested nightly against this identity
(`DEFAULT_PINNED_NIGHTLY` / `PINNED_NIGHTLY_*` in `src/lib.rs`) and warns on
mismatch; campaign metadata records the actual identity. A mismatched
nightly is never used silently.

Nightlies verified with the sancov-module + ASan flag set (the Phase-0
probe list; the pinned row re-verified in Phase 3 after the MSRV raise):

| nightly | rustc | LLVM | sancov-module |
|---|---|---|---|
| nightly-2025-04-01 | 1.88.0-nightly | 20.1.1 | works |
| nightly-2025-07-24 | 1.90.0-nightly | 20.1.8 | works |
| nightly-2025-09-01 | 1.91.0-nightly | 21.1.0 | works |
| nightly-2025-09-14 | 1.91.0-nightly | 21.1.1 | works |
| nightly-2025-11-08 | 1.93.0-nightly | 21.1.3 | works |
| nightly-2025-11-21 | 1.93.0-nightly | 21.1.5 | works |
| nightly-2025-11-25 | 1.93.0-nightly | 21.1.5 | works |
| nightly-2026-07-24 | 1.99.0-nightly | 22.1.8 | works (pinned) |

## 3. The instrumented build — flag sets

Two verified modes:

### 3.1 Default mode (safe-Rust targets): sancov + trace-compares, no ASan

```
RUSTFLAGS="-Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares \
  -Copt-level=3 \
  -Cdebug-assertions=yes \
  -Coverflow-checks=yes \
  -Clto=off"
cargo +nightly-2026-07-24 rustc --target <triple> --bin <target> -- -Cpanic=abort
```

Verified end-to-end by `examples/sancov_demo`: counter registration, cmp
callbacks, footprint calibration/masking, input-discriminating coverage.

### 3.2 ASan mode (unsafe/native targets): ASan + sancov counters, NO trace-compares

```
RUSTFLAGS="-Zsanitizer=address \
  -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Copt-level=3 \
  -Cdebug-assertions=yes \
  -Coverflow-checks=yes \
  -Clto=off"
cargo +nightly-2026-07-24 rustc --target <triple> --bin <target> -- -Cpanic=abort
```

Verified: `examples/asan_crash` triggers a real ASan report.

`-Copt-level=3` matches cargo-fuzz's fuzz profile: at dev-profile opt-level
0 the scan/clear loops over the counter array execute tens of thousands of
trace-cmp callbacks per execution (measured: ~1.2k exec/s per worker vs
~10k+ exec/s per worker at opt-level 3 on the golden-demo target). The
icmp-free callback path was re-verified end-to-end at opt-level 3 (no
recursion returns). Debug-assertions and overflow-checks stay ON per the
master prompt's fuzz-target profile.

### 3.3 The three hard build rules (all verified)

1. **`--target <triple>` is mandatory.** Without it, `-Zsanitizer=address`
   instruments host proc-macro crates; rustc then cannot dlopen the
   instrumented `.so` (`error: can't find crate for clap_derive`). With
   `--target`, RUSTFLAGS apply only to target-triple crates (this is also how
   cargo-fuzz builds).
2. **`-Cpanic=abort` must be applied to the FINAL target only** (`cargo
   rustc -- ... -Cpanic=abort`), never in RUSTFLAGS: cargo builds proc-macro
   crates with panic=unwind, and RUSTFLAGS is appended last, so a global
   `-Cpanic=abort` breaks them.
3. **`-Clto=off` is forced** (in RUSTFLAGS; verified to override profile
   `lto = true` because RUSTFLAGS is appended after profile flags). Fat LTO
   + sancov produces linker failures (`undefined symbol: __sancov_gen_.*`,
   the cargo-fuzz #384 hazard class — reproduced directly).

Also: `debug-assertions`/`overflow-checks` on by default for the target
(Phase 1 config; an explicit campaign may request release-equivalent
arithmetic). Every build flag is recorded in campaign metadata.

## 4. Forensic findings that shaped the design

### 4.1 The pass rename
`-Cpasses=sancov` -> **unknown pass name** on all tested LLVM >= 20. The
current name is `-Cpasses=sancov-module` (what cargo-fuzz uses today).
Level 4 + pc-table require `__sanitizer_cov_pcs_init` and
`__sanitizer_cov_trace_pc_indir`; both are implemented in the runtime.

### 4.2 The `__sanitizer_` exclusion is gone
LLVM 16/17 had `if (F.getName().startswith("__sanitizer_")) return false;`
in SanitizerCoverage.cpp. It was removed in LLVM 18. The only remaining
exclusion is the `NoSanitizeCoverage` function attribute (clang's
`no_sanitize("coverage")`), which rustc cannot emit: `#[no_sanitize]` was
removed in 1.91, and the replacement `#[sanitize(...)]` accepts only
address/cfi/memory/... — not coverage. rustc's `#[sanitize(address = "off")]`
emits **no LLVM attribute at all** (verified by IR inspection).

Consequence: the measurement runtime cannot be compile-time excluded. The
engine instead measures the constant self-footprint once during calibration
and masks it permanently. The callback path is additionally written
icmp-free/loop-free so the window footprint is minimal.

### 4.3 The recursion (why the callbacks must be icmp-free)
With trace-compares, every instrumented integer comparison calls back into
the cmp callbacks. Any comparison inside the callback path — including ASan
shadow checks (`icmp` on shadow bytes), Rust-2024 static-mut reference probes,
debug bounds checks, and the std atomic `Ordering` match (a switch) —
recurses infinitely. Each cause was isolated by disassembly and eliminated:
branchless overflow arithmetic, raw-pointer ring writes, pointer-carrying
switch events, `addr_of_mut!` instead of references, and plain static-mut
reads instead of std atomics.

### 4.4 ASan + trace-compares + Rust callbacks: incompatible on LLVM >= 18
Even with an icmp-free callback body, ASan's own shadow checks inside the
callbacks are instrumented icmps. There is no per-function exemption rustc
can emit. => the two-mode design in §3. (libFuzzer avoids this because its
runtime is C++ compiled with `no_sanitize("coverage")`; a pure-Rust runtime
cannot.)

### 4.5 Phase-1 measurement-window findings (all reproduced and fixed)

1. **The scan-only calibration is unstable in an instrumented binary.**
   `footprint_calibrate` used to sort between its second and third scan;
   the sort's own instrumented edges leaked into the third scan. Fixed by
   running the scans back-to-back (nothing but the fixed return/call-site
   edges between them) and sorting after the last scan.
2. **A background watchdog thread cannot coexist with the measurement.**
   The worker's original timeout watchdog was a thread; its wake-path edges
   fire at unpredictable times, and a busy-spin variant increments the
   8-bit edge counters so fast they wrap (presence reads become a coin
   flip). The measurement contract — "only the target runs between clear
   and scan" — forbids background threads in the instrumented binary. The
   timeout is now a one-shot `SIGALRM`/`setitimer` whose handler aborts
   only on a genuine hang (the process dies; no scan ever runs; zero
   contamination). `libc` does not export `setitimer` for linux-gnu, so
   the single stable glibc symbol is declared locally.
3. **Snapshot the cmp ring BEFORE the scan.** The original window scanned
   then snapshotted, so the scan's own cmp events polluted the captured
   tail (requiring a calibrated truncation). Snapshotting first captures
   exactly the target's events; the scan's events land after the captured
   range and are discarded by the next reset. No tail truncation needed.
4. **The worker calibrates the FULL window skeleton**, not the scan alone:
   clear -> reset -> (reset hook) -> noop execute -> snapshot -> scan, run
   until consecutive windows report identical footprints. The masked set
   then covers every constant runtime edge, including the reset hook's.
5. **Two mutation-engine totality bugs found at runtime** (unit tests had
   never covered short parents): `splice` bounded its block size by the
   PARTNER only (a 2-byte parent spliced against a 32-byte partner sliced
   `out[dst..dst+k]` out of bounds), and `compare-operand-substitution`
   sliced `out[0..w]` when the parent was shorter than the operand width.
   Both panics killed workers (panic=abort) and produced "crash" findings
   that did not reproduce on replay — the exact signature of a worker-side
   (non-target) death. Fixed and locked by short-parent regression tests.
   Every mutator must be TOTAL: it must never panic on any input (I2).
6. **Optimization can erase comparison-only edge discrimination.** At
   opt-level 3, `if x == C { a() } else { b() }` lowers to a branchless
   `cmov`/`setcc` sequence — both inputs execute the same edges. This is
   precisely why compare VALUES are part of the feedback contract: the
   demo's discrimination invariant is "edges differ OR cmp events differ".
   Targets that need edge-discriminating coverage at every opt level must
   have side-effecting branches (loops, calls that cannot be speculated).

## 5. Philox4x32-10 provenance

The mutation RNG is Philox4x32-10 per Random123. Verified against the
official Random123 KAT vectors (`philox4x32 10`:
`00000000...` -> `6627e8d5 e169c58d bc57ac4c 9b00dbd8`, plus the max-key and
pi-key vectors) using an independent pure-Python reference
(`.phase0/philox_reference.py`) that must pass the KATs before emitting
anything. Note: numpy's `Philox` state does NOT map 1:1 to Random123
semantics (numpy applies its own state layout); the official vectors are the
authoritative cross-check.

## 6. GPU (Phase 7 gates)

CubeCL will be admitted only if: CPU == CUDA == ROCm bit-for-bit, repeated
GPU runs deterministic, compile/startup cost acceptable, optional feature
does not break the Rust-1.98 default build, no unreasonable dependency
contamination, measured speedup on realistic batch sizes. cudarc (CUDA
11.4..13.x) and rocmrc (younger) are the fallback adapters. The GPU work
itself must not force a further MSRV raise.

## 7. Database (Phase 6 gates)

`dsfb-database = { version = "=0.1.1", default-features = false }`; add
`report` only for JSON/PNG sidecars and `live-postgres` only for the live
tokio+postgres adapter path. The tape lesson is reimplemented locally (the
crate's `Tape` is trapped behind `live-postgres`).

## 8. Non-x86_64

Phase 0 was verified on x86_64-linux. The scalar SIMD path is portable; AVX2
is x86_64-only and runtime-gated. The raw pointer-based ring reads rely on
the single-threaded worker discipline (portable), not on x86 atomicity
(documented in `target_runtime/cmp.rs`).
