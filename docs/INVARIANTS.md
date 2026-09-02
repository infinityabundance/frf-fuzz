# frf-fuzz Invariants

This is the mechanical contract of the project. Each invariant is stated,
then mapped to the code/tests that pin it. If a change would violate one of
these, the change is wrong.

## I1. A rejected ordinary fuzz execution performs no persistent filesystem write

The hot path (Level 0) never touches the store. Filesystem writes happen only
at admission/promotion/persistence boundaries (Level 2/3).

* Code: `execute/` (protocol is pure IPC; crash ledger is a fixed shared
  mapping, not per-execution I/O), `target_runtime/` (no I/O at all).
* Tests: none needed beyond construction — the hot-path modules contain no
  `std::fs` usage; the crash ledger writes only its two fixed slots, which
  the worker does once per execution *by design* (the ledger is the crash
  reconstruction mechanism, not telemetry).

## I2. A mutation is reproducible from its MutationCoordinate and immutable inputs

No mutable global RNG state. The coordinate encodes (campaign_seed,
parent_short_id, generation, mutator_id, lane_id, mutation_index,
probe_params) and derives a Philox4x32-10 stream.

* Code: `mutation/prng.rs` (KAT-vector-locked), `mutation/coordinate.rs`
  (49-byte canonical encoding), `mutation/*.rs` (pure functions of parent +
  auxiliary data).
* Tests: `mutation_determinism.rs` (identical digest across independent
  process runs), plus per-mutator determinism tests; crash recovery
  reconstructs the exact coordinate.

## I3. The scalar implementation defines semantics; acceleration cannot change them

`simd/scalar.rs` is normative; AVX2 and (later) GPU must be bit-for-bit
identical.

* Code: `simd/mod.rs` runtime dispatch; `simd/x86_avx2.rs`.
* Tests: `simd::tests::scalar_matches_avx2_*` property tests over randomized,
  adversarial, and boundary sizes (0..4097, all-zero, all-0xff, alternating).

## I4. FRF claim/evidence semantics are never recreated inside frf-fuzz

frf-fuzz findings are hypotheses. FRF receipt/claim compilation, residual
dispositions, and trajectory semantics are the `frf` crate's job. We retain
its IDs verbatim and never reinterpret them.

* Code: no FRF reimplementation anywhere; `docs/DESIGN-FRF-BRIDGE.md`
  records the verified call sequence to invoke the real library (Phase 4).
* Enforcement: the frf crate is the only code that constructs FRF IDs.

## I5. Gemel is never mutated for ordinary per-execution telemetry

Gemel receives durable boundaries only (campaign creation/checkpoint,
promoted precedent, FRF-verified finding, falsified precedent, resolved
finding, completion). Reads during the fuzz loop only.

* Code: `docs/DESIGN-GEMEL-BRIDGE.md` (verified read/write API split).
* Test: standalone operation without a `.gemel` repo (the entire Phase-0
  test suite runs without one).

## I6. Unknown DSFB structure is never silently renamed to the closest motif

`Structured + Unknown` is a first-class result. Nearest-label classification
is forbidden; a non-trivial trajectory that matches no bank entry stays
Unknown.

* Code: `dsfb/` (Phase 3) implements `FuzzSemanticBank` with
  `SemanticDisposition::Unknown` propagation.
* Tests (Phase 3): `stable noise -> no invented motif`,
  `Structured+Unknown remains Unknown`.

## I7. Generic fuzz residuals are never represented as SQL motif classes

The generic `RegimeObserver` has its own semantics, documented independently
of SQL. `dsfb-database::residual::ResidualClass` is a closed SQL-specific
enum with no generic variant, and no conversion exists between the two
worlds — the refusal is type-level.

* Code: no `From`/`TryFrom` between fuzz residual types and
  `ResidualClass`; the `database` feature is the only place the dsfb-database
  crate appears.
* Enforcement: the generic fuzz core has no dependency on dsfb-database.

## I8. No GPU result has final semantic authority

CPU is the oracle. GPU output is proposal/ranking evidence only; on
disagreement the GPU backend is quarantined and CPU semantics stand.

* Code: `gpu/` (Phase 7) — `ComputeBackend` trait documented as
  evidence-only.

## I9. No historical precedent is admitted without provenance

Every precedent carries provenance (campaign, tape, build identity, FRF/Gemel
links). Admittance without provenance is a bug.

* Code: `precedent/` (Phase 3) — the `Precedent` model requires provenance
  fields at construction.

## I10. Contradictory/falsifying evidence is never deleted

A contradicted precedent is retained with its counterexample. History is
monotone: a later pass never erases an earlier unresolved residual.

* Code: `precedent/` (Phase 3); the store's immutability model
  (`canon.rs` framing + content-addressed writes) makes deletion impossible
  by construction.
* Tests (Phase 3): `contradictory evidence never deleted`.

## I11. No prediction is represented as probability

Unless a future explicitly validated probabilistic subsystem is separately
introduced, frf-fuzz emits deterministic structural statements only. There is
no "likelihood" field anywhere in the model.

* Enforcement: grep the codebase for probability-flavored language; the
  vocabulary in `NON_CLAIMS.md` is the allowed set.

## I12. A persisted tape replays to the same frf-fuzz structural interpretation

The deterministic contract is `same valid tape -> same interpretation`, not
"OS scheduling is deterministic". Tapes are immutable and content-addressed.

* Code: `tape/` (Phase 2), modeled on DSFB-Database's
  JSONL+sidecar-hash+verify-on-load design (reimplemented locally).
* Tests (Phase 2): `same tape -> same morphology`.

## I13. Same frf-fuzz object ID with different bytes is fatal corruption

Content-addressed store: the ID is the hash of the canonical bytes. A
collision with different bytes is never resolved silently.

* Code: `canon.rs` framing; `id.rs` (BLAKE3-256); store (Phase 1) refuses
  `IdCollision`.
* Tests: `canon::tests` (exact bytes, malformed refusal, version refusal),
  plus store tests in Phase 1.

## I14. Failure of optional FRF/Gemel/GPU integration cannot corrupt standalone campaign state

All optional integrations are additive. A crash or refusal in the FRF court,
a missing Gemel repo, or an unavailable GPU leaves the standalone campaign
fully functional.

* Code: feature gating (`coordinator`/`database`/`cuda`/`rocm`); standalone
  paths return `Unverified`/`Absent` rather than failing.
* Tests: the entire suite runs with default features but no `.gemel`, no
  authority, no GPU.

## I15. Feature-disabled builds contain no hidden dependency on unavailable hardware

`target-runtime` builds contain no GPU/sanitizer/hardware dependency; the
`cuda`/`rocm` features compile and run without the hardware present (they are
reserved and dependency-free in Phase 0).

* Code: Cargo feature matrix; `is_x86_feature_detected!`-guarded AVX2.
* Verified: `cargo build --no-default-features --features target-runtime`
  and `cargo +1.98.0 test` pass (the matrix MSRV was raised to 1.98 during
  Phase 3 by deliberate decision; Phase-0 records of the 1.85 verification
  remain in EXPERIMENT_PROTOCOL.md as historical evidence).

## Unsafe policy

`unsafe` is forbidden everywhere except the approved zones, mechanically
enforced by `#![deny(unsafe_code)]` at the crate root with narrow
`#![allow(unsafe_code)]` in:

1. `target_runtime/sancov.rs` and `target_runtime/cmp.rs` — SanitizerCoverage
   pointer registration/scanning and the raw ring (the only allocation-free
   way to get mutable callback storage; the callback path is additionally
   written icmp-free and loop-free — see `COMPATIBILITY.md` for why).
2. `target_runtime/worker.rs` — the libc FFI boundary (memory limits,
   `setitimer`; declared locally because libc does not export it for
   linux-gnu).
3. `execute/crash_ledger.rs` — the `memmap2` syscall boundary.
4. `execute/coordinator.rs` — the SIGINT handler (async-signal-safe store).
5. `simd/mod.rs` and `simd/x86_avx2.rs` — AVX2 runtime dispatch and
   intrinsics.

Every unsafe block carries a `// SAFETY:` comment stating the exact
invariant. `#![deny(unsafe_op_in_unsafe_fn)]` is enabled crate-wide.
`scripts/unsafe_audit.sh` fails CI when a new unsafe location appears outside
the approved modules.

## Determinism notes

* No wall clock in canonical identity (operational metadata may carry
  timestamps outside the canonical payload).
* No `HashMap` iteration in canonical encoding (BTreeMap only).
* No floating point in canonical identity (morphology signatures use
  integer/fixed-point/bucket fields).
* `f64` may appear in DSFB-Debug's own outputs; frf-fuzz derives its
  integer identity from enums/masks, not from DSFB's floats.
* Lineage/regime/morphology derivation is deterministic given the durable
  corpus: `CorpusMeta` records each entry's observed signals, edge mutator,
  morphology ID, and admission sequence; the coordinator replays edges in
  admission order on rebuild and verifies the re-derived morphology ID
  against the stored one (a mismatch is corruption, I13). Closed regime
  episodes re-derive identically (content-addressed re-writes are
  idempotent).
* `value_bucket` and `magnitude_bucket` are declared normalization laws
  (documented beside the code); the raw values always travel with the
  observation, so bucketing never hides evidence.
* The regime EMA is integer fixed-point in 2^shift units: a raw-unit floor
  EMA gets stuck below 2^shift and recovery never fires (Phase-2 finding,
  locked by the noise/drift/recovery test vectors).
