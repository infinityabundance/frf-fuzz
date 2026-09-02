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
  records the verified call sequence to invoke the real library (implemented
  in Phase 4).
* Enforcement: the frf crate is the only code that constructs FRF IDs.
* Phase 4: a crash finding is `Verified` only when the court observed at
  least one residual divergence; a parity receipt (zero residuals) classifies
  the finding `Failed` with the receipt preserved as evidence of
  non-reproduction. The divergence decision reads FRF's own capture records —
  it never re-derives FRF's comparison semantics.

## I4b. Without a configured authority, verification is DERIVED, never fabricated

A finding with no verification record is `Unverified` by derivation — there is
no "unverified" object to write. `frf-fuzz verify` and campaign auto-verify
refuse when no `--authority` is given (an authority is never invented).

* Code: `frf_bridge::current_verification` returns `None` for unverified
  findings; `cli::cmd_verify` refuses without `--authority`.
* Tests: `tests/phase4_frf_gemel.rs::no_authority_means_derived_unverified`;
  the golden demo asserts the authority-less stores report zero verifications.

## I5. Gemel is never mutated for ordinary per-execution telemetry

Gemel receives durable boundaries only (campaign creation/completion
checkpoints, FRF-verified finding evidence+claim, promoted precedent
evidence, falsified precedent residual). Reads during the fuzz loop only;
no Gemel write happens per execution.

* Code: `docs/DESIGN-GEMEL-BRIDGE.md` (verified read/write API split);
  `gemel_bridge.rs` (implemented in Phase 4) performs reads inside the loop
  and publications only at `publish_boundary` call sites (campaign
  start/end, verified finding, precedent admission/falsification).
* Test: standalone operation without a `.gemel` repo (the entire test suite
  runs without one); `gemel_absent_is_standalone` asserts no writes; the
  golden demo asserts no per-execution Gemel objects (boundary counts only).

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
  `ResidualClass`; `src/dsfb/database_bridge.rs` (feature `database`) is the
  only module where the dsfb-database crate appears.
* Enforcement: the generic fuzz core has no dependency on dsfb-database;
  the bridge imports no generic fuzz machinery (source-lock test
  `no_generic_types_cross_the_boundary` + `compile_fail` doctest, Phase 6).

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
monotone: a later pass never erases an earlier unresolved residual. Phase 4
additions: an FRF `Failed` verification (including a parity receipt) is a
permanent record; a Gemel publication failure is recorded with its failure
class; a falsified precedent publishes a Gemel `Residual` (negative
knowledge) that is never deleted.

* Code: `precedent/` (Phase 3); `frf_bridge.rs` / `gemel_bridge.rs`
  (Phase 4); the store's immutability model (`canon.rs` framing +
  content-addressed writes) makes deletion impossible by construction.
* Tests (Phase 3): `contradictory evidence never deleted`; (Phase 4):
  `non_reproducing_finding_is_failed_and_preserved`,
  `falsified_precedent_publishes_negative_knowledge`.

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
fully functional. Phase 4: campaign verification is best-effort — an FRF
refusal or hard config error is persisted as a `Failed` record, never
fatal to the campaign; a Gemel-side failure writes a local `GemelBoundary`
record with a deterministic failure class and the campaign continues.

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
the approved modules. Two examples are documented exceptions outside `src/`:
`examples/asan_crash.rs` (deliberate OOB demo) and
`examples/phase5_bench.rs` (mirrors the worker's single-symbol `setitimer`
shim to measure the per-window timeout syscall cost).

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
