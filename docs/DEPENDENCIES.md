# frf-fuzz Dependency Policy and Pin Record

Status: Phase 0. Every dependency exists for a recorded reason. Versions are
pinned (`=`) for integration-sensitive crates. The core default build stays
small enough to audit; the target-runtime build is dependency-tiny.

## Pinned dependencies

| Crate | Version | MSRV | Feature | Why it exists |
|---|---|---|---|---|
| `memmap2` | `=0.9.11` | 1.65 | always | The crash ledger's shared mapping between worker and coordinator. `map_mut` is an `unsafe fn` (mmap syscall boundary); it is the one documented unsafe zone in `execute/crash_ledger.rs`. |
| `libc` | `=0.2.177` | ~1.63 | always | Worker-side Unix process controls: `setrlimit` (memory limits) and the `SIGALRM` timeout (`setitimer` + `signal`; glibc's `setitimer` is NOT exported by the libc crate for linux-gnu, so the single stable symbol is declared locally in `target_runtime/worker.rs`), plus the coordinator's SIGINT handler. Tiny, no transitive deps. |
| `blake3` | `=1.8.7` | compatible within the 1.98 build (resolved by gemel 0.11.0's lock) | `coordinator` | Content identity (BLAKE3-256) for the object store and corpus. Chosen over SHA-256 for speed on the admission path. gated so the target-runtime build never links it. |
| `frf` | `=0.1.72` | 1.85 | `coordinator` | Epistemic authority: court questions, receipts, claims, trajectories for promoted findings. No features exist; pulls clap/serde_yaml/tar/base64/sha2/libc unconditionally — the price of real evidence semantics, kept out of the target-runtime build. Its column value is its own declared MSRV; it compiles within the 1.98 build. |
| `gemel` | `=0.11.0` | 1.85 | `coordinator` | Longitudinal engineering memory: durable boundary objects, state Gids, trajectories, negative knowledge. `rusqlite` bundled requires a C compiler at build time (documented in `doctor`). No features. |
| `dsfb-debug` | `=0.1.0`, `default-features=false, features=["std"]` | 1.75 | `coordinator` | Structural interpretation substrate (residual/sign/drift/slew/grammar/policy/episode + 205-detector fusion field). With this exact feature set it has ZERO transitive deps (verified from its lockfile). Its motif names are never applied to fuzz behavior (I6). |
| `dsfb-database` | `=0.1.1`, `default-features=false` | 1.74 | `database` (optional) | Only for real database telemetry targets. With `default-features=false` it pulls no tokio/postgres/otel/plotters (verified). Generic fuzz residuals never become its `ResidualClass` (I7). |

MSRV contract: the coordinator declares `rust-version = "1.98"` since Phase
3 (raised from 1.85 to the current stable, 1.98.0, by deliberate decision).
The MSRV column keeps each dependency's own declared MSRV where one exists —
frf 0.1.72 and gemel 0.11.0 still declare 1.85 and compile within the 1.98
build. The whole matrix is now verified at 1.98, not at the Phase-0 floor
of 1.85.

## Explicit non-dependencies

* **No libAFL**: its MSRV (>= 1.93 for 0.16.x, per the Phase-0 pin record)
  exceeded the pre-Phase-3 1.85 contract; the crate borrows compositional
  ideas, not the crate.
* **No serde/serde_json in the crate itself**: the protocol is binary; the
  doctor's `--json` is hand-rolled and documented. (frf/gemel/dsfb-database
  bring their own serde internally.)
* **No clap in frf-fuzz's own CLI yet**: the Phase-0 CLI is argv-adapter
  thin; Phase 1 may add clap after this policy is re-reviewed.
* **No thiserror**: the crate error type is hand-rolled so its `Display` is
  part of the public contract.
* **No criterion**: benches are hand-rolled; re-evaluate in Phase 5 when
  measuring hot paths.
* **No GPU dependency yet** (Phase 7): `cuda`/`rocm` features are reserved
  and dependency-free so feature-enabled builds compile without hardware
  (I15).
* **No rand**: determinism is counter-based Philox, our own implementation
  with official KAT vectors.

## Procurement (Phase 0, from source, not docs.rs)

All four integration crates were downloaded from crates.io and inspected from
source (`.phase0/forensics/`); each has a forensic report (`REPORT-*.md`)
with cited `file:line` API maps. Key facts that shaped the pins:

* frf 0.1.72: no `[features]`; filesystem store mandatory; court questions
  are YAML files; IDs are content addresses / `run-`/`receipt-` composites
  that must be retained verbatim.
* gemel 0.11.0: no `[features]`; `Repo::find` -> `NotARepository` is the
  "gemel absent" signal; durable writes are lock-free `insert_object` plus
  journaled `write_refs`; negative knowledge via `close_trajectory
  outcome="rejected"`.
* dsfb-debug 0.1.0: `default = []` is no_std with zero deps; `std` enables
  the detector field/fusion; `SemanticDisposition::Unknown` is first-class
  and never forced; canonical identity is f64 (frf-fuzz derives integer
  identity from enums/masks).
* dsfb-database 0.1.1: features `cli/report/otel/live-postgres/live-mysql/
  full/default`; `default-features=false` keeps the grammar core pure;
  `ResidualClass` is a closed 5-variant SQL enum with explicit
  "not a universal grammar" non-claims; the deterministic tape machinery is
  trapped behind `live-postgres` — reimplemented locally in Phase 2.

## Updating policy

* Integration-sensitive crates are pinned with `=`. Updating is a deliberate
  act: re-run the forensic inspection, re-verify the MSRV matrix
  (`cargo +1.98.0 build`), re-run the full test suite, and update this
  record and the campaign metadata tooling.
* Non-integration crates (memmap2, blake3) may move within their pinned
  minor with the same verification.
