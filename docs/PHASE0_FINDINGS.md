# Phase 0 Findings

Status: complete. Every finding below was reproduced on this machine during
Phase 0; the raw commands live in `.phase0/spikes/` and
`scripts/nightly_spike.sh`. Cross-references: `COMPATIBILITY.md` (toolchain),
`ARCHITECTURE.md` (design consequences), `EXPERIMENT_PROTOCOL.md`
(verification record).

## 1. Dependency forensics (from source, not docs.rs)

All four integration crates were downloaded and inspected from source;
`REPORT-frf-0.1.72.md`, `REPORT-gemel-0.11.0.md`,
`REPORT-dsfb-debug-0.1.0.md`, `REPORT-dsfb-database-0.1.1.md` in
`.phase0/forensics/` are the API maps with `file:line` citations.

- frf 0.1.72: no features; filesystem store mandatory; court questions are
  YAML files; IDs must be retained verbatim; compiles on 1.85.
- gemel 0.11.0: no features; `Repo::find` -> `NotARepository` = absent;
  lock-free `insert_object` + journaled `write_refs`; rusqlite bundled needs
  a C compiler; no unsafe in the library.
- dsfb-debug 0.1.0: `default = []` is no_std, zero deps; `std` adds the
  205-detector fusion field; `Unknown` is first-class; BTreeMap only (no
  HashMap); thread-local `LAST_WIN_ALERTS` gotcha; f64 canonical identity.
- dsfb-database 0.1.1: `default-features=false` excludes tokio/postgres/
  otel/plotters; `ResidualClass` is a closed 5-variant SQL enum with explicit
  "not a universal grammar" non-claims; its `Tape` is trapped behind
  `live-postgres` — reimplement locally.

## 2. SanitizerCoverage on current rustc/LLVM

- **Pass rename**: `-Cpasses=sancov` -> `error: unknown pass name 'sancov'`
  on every installed nightly (LLVM 20.1.1 .. 22.1.2). Current name:
  `-Cpasses=sancov-module` (also what cargo-fuzz master uses), plus
  `-Cllvm-args=-sanitizer-coverage-level=4`,
  `-Cllvm-args=-sanitizer-coverage-inline-8bit-counters`,
  `-Cllvm-args=-sanitizer-coverage-pc-table`,
  `-Cllvm-args=-sanitizer-coverage-trace-compares`.
- Level 4 + pc-table require `__sanitizer_cov_pcs_init` and
  `__sanitizer_cov_trace_pc_indir` to be defined (missing-symbol linker
  errors otherwise); both are implemented in `target_runtime/sancov.rs`.
- **`__sanitizer_` name exclusion removed in LLVM 18**: present in LLVM
  16/17 (`if (F.getName().startswith("__sanitizer_")) return false;`), gone
  in 18+; the only remaining exclusion is the `NoSanitizeCoverage` function
  attribute. rustc cannot emit it: `#[no_sanitize]` removed in 1.91;
  `#[sanitize(...)]` accepts only address/cfi/memory/etc.; and rustc's
  `#[sanitize(address = "off")]` emits NO LLVM attribute (verified by IR
  inspection).

## 3. The callback recursion (isolated cause by cause)

With trace-compares, an instrumented comparison callback recurses. Sources
found by disassembly, in order of discovery:

1. ASan shadow checks (`icmp` on shadow bytes before every memory access).
2. ASan fake-stack null checks (`__asan_stack_malloc` result vs 0).
3. Rust-2024 static-mut reference probes (address `!= 0` / `& 1` checks when
   creating references to `static mut`).
4. Debug bounds checks on `RING[idx]` (`idx >= 16384` -> const_cmp8).
5. `[0; N]` array-repeat loops at opt-level 0.
6. std atomic wrappers' `match order` (compiles to a switch ->
   `__sanitizer_cov_trace_switch`).

Eliminations: branchless overflow arithmetic (no branch), raw-pointer ring
writes via `addr_of_mut!` (no reference, no probe), `get_unchecked`-style
bounded writes, compile-time `ZERO_CASES` constant copies, plain static-mut
reads/writes instead of std atomics. The callback path is now icmp-free and
loop-free at any opt level.

**Bottom line**: `-Zsanitizer=address` + trace-compares + Rust-defined
callbacks cannot coexist on LLVM >= 18 (ASan's own shadow checks in the
callbacks are instrumented). Two-mode design: default = sancov + trace-
compares without ASan; opt-in ASan mode disables trace-compares.

## 4. Build architecture

- **`--target <triple>` is mandatory**: without it, `-Zsanitizer=address`
  instruments proc-macro crates and rustc cannot dlopen them
  (`error: can't find crate for clap_derive`). With `--target`, RUSTFLAGS
  apply only to target-triple crates. (cargo-fuzz uses the same mechanism.)
- **`-Cpanic=abort` only on the final target** (`cargo rustc -- ...
  -Cpanic=abort`); never in RUSTFLAGS (proc-macros need unwind and RUSTFLAGS
  is appended last).
- **LTO hazard reproduced**: `-Clto=on` + sancov + ASan -> `undefined
  symbol: __sancov_gen_.*` (the cargo-fuzz #384 class). `-Clto=off` via
  RUSTFLAGS overrides profile `lto = true` (verified flag order: RUSTFLAGS
  comes after profile flags).

## 5. Measurement-window protocol (verified)

```
clear counters -> reset ring -> execute target -> scan counters
-> snapshot ring
```

- The runtime's own edges are a constant footprint R (measured by the full
  window skeleton during calibration) and permanently masked.
- The scan's constant cmp events land after the target's; Phase 1's worker
  truncates the calibrated tail before analysis.
- `examples/sancov_demo` (pinned nightly, default mode) passes: footprint
  stable, masked delta nonempty and input-discriminating, cmp events
  captured. `examples/asan_crash` (ASan mode) triggers a real ASan report.

## 5a. Two latent `scan_and_clear` bugs found during the Phase-0 close-out

Both were found by reading the scan implementation against its documented
contract after the clippy cleanup, and are now fixed and locked by tests:

1. **The "clear with a null buffer" idiom silently did nothing.** The old
   signature `scan_and_clear(out: *mut u32, cap: u32)` returned `u32::MAX`
   at the first nonzero counter when the buffer was full — BEFORE the
   `*c = 0` — and abandoned the remaining ranges. `scan_and_clear(null, 0)`
   (used by the demo as a "clear") therefore never cleared anything, so the
   demo's window B was a confounded superset of window A and its
   "input-discriminating coverage" assertion passed for the wrong reason.
   Fix: `scan_and_clear(out: &mut [u64])` now CLEARS EVERY COUNTER
   unconditionally and reports `u32::MAX` only as a truncation signal;
   scan-and-clear is a consume operation, so a saturated report never leaks
   into the next window. The demo now clears with `clear_all()` and
   materializes each window's delta immediately (the scan buffer is reused).
   New test `scan_respects_cap_and_still_clears` locks the consume contract.
   This is the kind of failure mode the Level-0 hot loop cannot afford:
   a "clear" that doesn't clear is silent cross-window contamination.
2. **The packed index `(range << 20) | offset` collided for ranges >= 1 MiB**
   (`MAX_RANGE_LEN` allows 1 GiB; the offset needs 30 bits, the packing gave
   it 20). Fix: `(range << 32) | offset` in `u64`, unambiguous for every
   legal range. `packed_index_layout` locks the new layout.

Also discovered: the demo built both windows' sets from the same scan
buffer AFTER window B overwrote it; sets are now materialized per window.
The demo's discrimination invariant is now two-sided (each window has
edges the other lacks) instead of the old "deltas differ" check that a
superset leak would also satisfy.

## 6. Philox4x32-10 verification

Official Random123 KAT vectors pass:
`(ctr=0, key=0) -> 6627e8d5 e169c58d bc57ac4c 9b00dbd8`; the max-key and
pi-key vectors also pass. Cross-checked with an independent pure-Python
implementation (`/mnt/1tb_kingston/frf-fuzz/.phase0/philox_reference.py`)
which must pass the KATs before emitting the embedded vector table
(`.phase0/philox_vectors.json`). Note: numpy's Philox state layout does not
map 1:1 to Random123 semantics, so numpy was not used as an oracle.

## 7. Determinism and crash recovery (verified)

- `tests/mutation_determinism.rs`: identical mutation digest across
  independent process runs; digest changes with coordinate fields.
- `tests/crash_recovery.rs`: abort(), panic=abort, worker restart, and
  kill-before-commit all reconstruct the exact coordinate from the ledger.

## 8. IPC batching (measured)

`examples/ipc_bench` (socketpair, framed protocol, 49-byte coordinates, best
of 5 trials):

| k | per-input ns/x | batched ns/x | speedup |
|---|---|---|---|
| 1 | 15108 | 16992 | 0.9x (fixed cost) |
| 10 | 5902 | 1328 | 4.4x |
| 100 | 4906 | 829 | 5.9x |
| 1000 | 5344 | 774 | 6.9x |
| 10000 | 5780 | 796 | 7.3x |

Per-input framing costs ~5-6 µs/execution; batching amortizes it toward
~0.8 µs. A typical target execution costs microseconds, so per-input IPC
would dominate throughput — the work-order architecture is correct.

## 9. MSRV and feature matrix (verified)

`cargo +1.85.0 test` passes with default features and with
`--no-default-features --features target-runtime` (the target-runtime build
links only memmap2). `cargo +1.85.0 build --all-features` also passes, as
does `cargo build --release --all-features` (the optional `dsfb-database`
feature compiles in release). Clippy is clean across all targets and all
features with `-D warnings`; `cargo fmt --check` is clean; rustdoc builds
without warnings; `scripts/unsafe_audit.sh` reports approved zones only.
The doctor reports the full matrix.

## 10. Machine/environment (for reproducibility)

- CPU: x86_64 with AVX2 (verified `avx2` in /proc/cpuinfo).
- OS: linux (kernel per `uname`), 16 cores, 125 GiB RAM.
- Toolchains: stable 1.98.0 (default), 1.85.0/1.85.1 for MSRV, the eight
  nightlies listed in `COMPATIBILITY.md` §2.
- numpy 2.3.5 (used only for the (negative) Philox cross-check), gcc 16.2.1,
  clang 22.1.8 (host), python3.
