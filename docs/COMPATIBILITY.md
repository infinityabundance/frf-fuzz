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

## 6. GPU (Phase 7, gate record)

The admission gates for a device backend are unchanged and now codified in
the code: CPU == CUDA == ROCm bit-for-bit (the `gpu/` CPU kernels are the
equality reference), repeated GPU runs deterministic, acceptable
compile/startup cost, optional feature does not break the Rust-1.98 default
build, no unreasonable dependency contamination, measured speedup on
realistic batch sizes. cudarc (CUDA 11.4..13.x) and rocmrc (younger) are
the fallback adapters. The GPU work itself must not force a further MSRV
raise.

Phase-7 spike record (2026-09-02): CubeCL was inspected from crates.io
(cubecl-core 0.10.0 stable, 0.11.0-pre.3 newest; edition 2024, no declared
rust-version — it would compile on the 1.98 build, so the MSRV gate alone
does not exclude it). The decisive gates (CPU == CUDA == ROCm measured
bit-for-bit, repeated device determinism, measured speedup) require a
CUDA/ROCm device and toolchain; this development machine has none
(`frf-fuzz doctor` records the toolchain state and reports that no device
adapter is admitted). No device backend is therefore admitted: the `cuda`/
`rocm` features stay reserved and dependency-free, `gpu::resolve` always
falls back to the CPU oracle with a recorded note (I14/I15), and the CPU
kernels in `gpu/cpu.rs` are the reference a future adapter must pass before
it can change throughput. CubeCL remains the preferred route; cudarc and
rocmrc remain the documented fallbacks if CubeCL fails its gates on real
hardware.

## 7. Database (Phase 6, verified)

`dsfb-database = { version = "=0.1.1", default-features = false }`. The
`database` feature compiles `dsfb/database_bridge.rs` — the single frf-fuzz
module that links the crate — inside the coordinator `dsfb` tree. With
`default-features = false` the crate pulls no tokio/postgres/otel/plotters
(verified from its manifest); the `report`/`live-postgres` features are NOT
enabled and their machinery is never compiled into frf-fuzz. The tape lesson
was reimplemented locally in Phase 2 (the crate's own `Tape` is trapped
behind `live-postgres`).

## 8. Non-x86_64

Phase 0 was verified on x86_64-linux. The scalar SIMD path is portable; AVX2
is x86_64-only and runtime-gated. The raw pointer-based ring reads rely on
the single-threaded worker discipline (portable), not on x86 atomicity
(documented in `target_runtime/cmp.rs`).

## 9. Phase-4 integration notes (FRF + Gemel)

* FRF courts execute the candidate (and the authority) as real subprocesses
  with hard harness bounds (60 s / 16 MiB per side) under an EMPTY declared
  environment. The verification candidate must therefore be self-contained:
  an instrumented frf-fuzz target binary is, via its `--frf-fuzz-fixture`
  single-shot mode (`target_runtime/fixture.rs`), which requires no
  environment.
* FRF hashes the full candidate binary per court; at promotion (Level 2) a
  court costs on the order of seconds on this machine. This is deliberate:
  crashes are rare, and the per-execution loop never touches FRF. A
  campaign whose crash rate is high pays per distinct crashing input (the
  coordinator dedups identical inputs per campaign).
* FRF executes sides through sealed memfd images; a dynamically-linked Rust
  binary works when its interpreter/loader closure resolves (verified
  end-to-end on x86_64-linux by `scripts/golden_demo.sh` stages 11-17). A
  side that the profile cannot execute produces a REFUSED run, which
  frf-fuzz records as a `Failed` verification — never a fabricated capture.
* ASan-instrumented binaries are not suitable FRF sides (the ASan runtime
  under the sealed/sandboxed profile is not a supported surface); ASan
  campaigns that auto-verify should pass `--verify-candidate` pointing at a
  non-ASan build of the same target.
* Gemel publications require a writable `.gemel` repository discoverable
  from the project root. `workflow::create_checkpoint` takes the repo write
  lock; boundaries are rare (campaign start/end, verified findings,
  precedents), so contention is not a loop concern. rusqlite's bundled
  SQLite needs a C compiler (the `doctor` check covers `cc`).
* FRF run/receipt ids are NOT portable across different frf-fuzz binaries:
  FRF's runner identity is the hash of the embedding executable, so the
  same court observed by two different coordinator builds yields two valid
  evidence chains. Idempotent convergence holds within one binary (tested).

## 10. Phase-5 integration notes (AVX2 hardening)

* The per-execution coverage consume (`sancov::scan_and_clear` + `clear_all`)
  and the cmp ring snapshot (`cmp::snapshot`) now dispatch through the SIMD
  kernels; scalar remains normative (I3) and the property tests assert
  bit-for-bit equality, so an AVX2-disabled CPU observes identical feature
  sets, orderings, and saturation behavior. No instrumented-build flag
  changes were needed: these functions run outside the target window (their
  own edges/events are wiped or land after the captured range), so the
  icmp-free callback discipline is untouched.
* `cmp::snapshot` reads the ring through `copy_nonoverlapping` segments. The
  safety argument is the single-producer discipline plus the power-of-two
  mask: the live region is contiguous except at the RING_LEN wrap, and the
  push discipline keeps the live count <= RING_LEN, so the two segments are
  always inside the array. `snapshot` runs after the window (comparisons are
  fine); it never runs inside a callback.
* The worker keeps cmp events in a fixed `[CmpEvent; 256]` buffer across
  windows; only discovery pushes materialize them. Anything that reads
  `events_buf` must do so before the next window overwrites it (the current
  call sites are `window_with`'s hit extraction and `push_discovery`, both in
  the same loop iteration as the snapshot).
* Phase 5 changed no semantics and no stable record formats: feature packed
  indices, cmp wire encoding, mutation coordinates, and object layouts are
  untouched. The 0.5.0 release is drop-in compatible with 0.4.x stores and
  tapes.

## 11. Phase-6 integration notes (database)

* The bridge lives behind the `database` feature AND the `coordinator`
  feature (the `dsfb/` tree is coordinator-gated). A pure `target-runtime`
  build never compiles it; a database-telemetry fuzz SURFACE (the code under
  test) does not need the feature at all — it decodes its own wire format in
  its own harness. The feature is for the analysis side: replaying declared
  SQL-telemetry rows through the real `dsfb-database` grammar.
* `TelemetryRow` values are the ONLY frf-fuzz input to the crate. There is
  no `From`/`TryFrom` between any frf-fuzz generic type and
  `dsfb_database::residual::{ResidualClass, ResidualSample}`; the module
  never imports the generic fuzz machinery (`no_generic_types_cross_the_
  boundary` source lock + `compile_fail` doctest). This is the Phase-3
  design doc's promised enforcement lock (DESIGN-DSFB.md, I7).
* Rows are validated (finite metrics, class-appropriate ranges, bounded
  channel labels <= 128 bytes, bounded logical time <= 2^40 ms, <= 2^16
  rows/stream) and refused — never coerced — before they reach the crate.
  `Error::Other`/`BoundExceeded` carry the reason; nothing is silently
  dropped.
* `analyze` runs the real `MotifEngine` with the crate's default grammar
  (its `spec/motifs.yaml` numbers). Determinism is the crate's own replay
  fingerprint (`grammar::replay::fingerprint_hex`, SHA-256 over episode
  field LE bytes). The fingerprint is a dsfb-database namespace id — it is
  never reinterpreted as a frf-fuzz object ID or a Gemel Gid.
* Episode `t_start/t_end/peak/ema` are f64 seconds/units from the crate.
  They appear only in analysis VIEWS and prints; frf-fuzz canonical identity
  stays integer-based. No SQL episode object is persisted to the frf-fuzz
  store in Phase 6 (episodes are an analysis artifact of declared rows); a
  durable family would be added only with a real operator workflow.
* f64 arithmetic determinism is the crate's own contract (its test suite
  pins SHA-256 fingerprints). frf-fuzz asserts reproducibility of its own
  analyses on the same build; cross-toolchain float-codegen stability is
  the pinned crate's concern and its pinned version `=0.1.1` protects it.
