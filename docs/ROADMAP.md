# frf-fuzz Roadmap

Phase 0 is complete and documented. Phases are executed in order; nothing is
"shipped early" in a way that pretends a later phase exists. Empty
abstractions are not shipped — if a module is not implemented, it is listed
here, not created as a stub.

## Phase 0 — Specification / Forensic Spikes (DONE)

Deliverables, all verified:

- Dependency forensics: frf 0.1.72, gemel 0.11.0, dsfb-debug 0.1.0,
  dsfb-database 0.1.1 inspected from source (`.phase0/forensics/REPORT-*.md`).
- Pinned dependency matrix (`docs/DEPENDENCIES.md`), MSRV 1.85 verified for
  the whole feature matrix.
- Instrumentation spikes: `sancov-module` on LLVM 20..22, trace-cmp
  callbacks, footprint calibration/masking, `--target` rule, LTO-off rule,
  ASan/trace-compares incompatibility — all documented in
  `docs/COMPATIBILITY.md` / `docs/PHASE0_FINDINGS.md`.
- Deterministic MutationCoordinate + Philox4x32-10 (official KAT vectors),
  all 16 mutator families, cross-process determinism tests.
- Scalar/AVX2 SIMD equivalence property tests (bit-for-bit).
- Crash ledger + worker crash/restart reconstruction tests.
- IPC batch-overhead measurement (`examples/ipc_bench`).
- `frf-fuzz doctor` (human + `--json`).
- `docs/ARCHITECTURE.md`, `docs/INVARIANTS.md`, `docs/THREAT_MODEL.md`,
  `docs/EXPERIMENT_PROTOCOL.md` + supporting docs.

## Phase 1 — Minimum Useful Fuzzer (DONE)

- `cargo frf-fuzz init / add / build / run` (+ the `fuzz_target!` macro,
  FuzzContext surface, hooks: setup/reset/execute/teardown).
- Persistent workers (work-order batches), protocol wired end-to-end
  (`scheduler/work_order.rs` wire encoding, `execute/worker_process.rs`,
  `execute/coordinator.rs`).
- Corpus CAS (BLAKE3 content-addressed store under `.frf-fuzz/`),
  admission (coverage-guided), crashes (ledger echo + replay), replay,
  tmin, cmin, inspect, report, fsck.
- Basic scheduler (EXPLORE queue; coverage + cmp + dictionary discovery).
- Campaign metadata (build identities, flag sets, toolchain identity
  embedded at build time).
- Golden demonstration target (`examples/golden_demo`,
  `scripts/golden_demo.sh`: build -> fuzz -> magic-gate crash -> replay ->
  fsck -> tmin in one command) — acceptance items 1-6, 18-19 verified.
- `bin/cargo-frf-fuzz.rs` (thin cargo-subcommand adapter);
  `scripts/cli_smoke.sh` exercises init/add/build/run/report/fsck in a
  scratch project.
- CI: MSRV + stable + nightly instrumentation + golden demo + CLI smoke +
  unsafe audit jobs.
- Measurement-window hardenings (COMPATIBILITY.md §4.5): full-skeleton
  calibration, snapshot-before-scan, SIGALRM timeout (no background
  threads), opt-level-3 fuzz profile, two mutation totality fixes.

Measured on the golden-demo target (8 workers, 15 s): ~1.3M executions,
~88k exec/s aggregate, 40/40 findings reproduced on replay, tmin 12 -> 8 B.

## Phase 2 — Residual-Guided Fuzzing (DONE)

- Target-defined signals: fixed-size `SignalVector` (64 u64 + touched mask),
  schema registration via the setup hook (`cx.register_signal(name, unit)`),
  HELLO carriage, durable `Family::SignalSchema` objects, `--residual on|off`
  ablation switch.
- Worker-side observation: per-execution signal capture in the measurement
  window, `ResidualSketch` (bucketized child-vs-parent comparison), the
  per-order `OrderSignalTracker` (persistence run + cumulative magnitude),
  the `SignalBatchSummary` (the full observation stream in bounded aggregate
  form), and the interest filter (novel features / touched-new / persistent /
  large delta) with a per-result byte budget so discovery floods can never
  overflow the 1 MiB protocol frame (a Phase-2 finding: unbounded discovery
  streams killed workers and produced false crash findings).
- `observe/` (coordinator): `MutationResidual` and `TemporalResidual`
  (separately typed; Authority/Revision arrive with FRF/Gemel in Phase 4),
  `ExecutionObservation`, signal-schema objects, batch-drift detection.
- `dsfb/regime.rs`: `RegimeObserver` — instantaneous + integer fixed-point
  EMA + `Stable -> Drift -> InEpisode -> Recovering` + dwell + deterministic
  episode close (recovery dwell / max dwell), durable `RegimeEpisode`
  objects, deviation-baseline reset at close (second episodes open).
  Semantics documented independently of SQL (I7).
- `dsfb/morphology.rs`: inspectable `MorphologySignature` (axis mask,
  directions, magnitude/slew/persistence bins, coactivation, comparison-
  convergence, state-change, replay stability, structured-Unknown, depth),
  the `LineageAccumulator`, and the `Trivial`/`StructuredUnknown` classifier
  (I6: structured trajectories stay Unknown — the FuzzSemanticBank is Phase
  3). Admission novelty is the structural identity (magnitude/persistence
  bins excluded — a drift trajectory must not flood the corpus; measured
  ~3300 admissions in 12s before the fix).
- Scheduler: EXPLORE/AMPLIFY weighted round-robin (deterministic), the
  bounded amplify queue fed by batch-drift detection, frontier re-anchoring
  with a freshness boost, termination on finding.
- `CorpusMeta` v2: recorded signals, edge mutator, morphology ID, admission
  sequence — lineage/regime/morphology derivation replays deterministically
  on rebuild and verifies stored morphology IDs (I13).
- Counterfactual boundary witnesses: `boundary/witness.rs` (durable pairs,
  relations, verification status) + `minimize.rs` (deterministic two-sided
  minimization) + `frf-fuzz boundary <finding-id>`.
- Run tapes: `tape/model.rs` (build/env digests, candidate, coordinate,
  observation, termination, lineage) written at durable boundaries (seeds,
  findings, residual admissions, boundary pairs); `tape/replay.rs` checks the
  live observation against the recorded one and PRESERVES divergence (I10).
- Golden demonstration: Path B (marker-depth signal drift to a planted
  crash with no new coverage) + the coverage-only negative control + the
  cmp-driven magic gate + boundary minimization, in one command
  (`scripts/golden_demo.sh`). Acceptance items 7-9, 13 verified.

Measured on the golden-demo target (8 workers, 15 s): residual-on retains
~33 state features, forms open regime trajectories, dispatches ~120 amplify
orders and reaches the depth crash; coverage-only shows no depth signal and
cannot reach it within the same budget (negative control holds).

Phase-2 findings locked by tests: the integer EMA floor (recovery never
fires below 2^shift), the morphology admission flood, the worker frame
overflow, the demo cmp-ring flood drowning the magic gate's const-cmp (fixed
with a branchless marker-count lookup table), and the family-15
reconstruction determinism gap (the discovery now carries the exact compare
hits the mutation consumed).

## Phase 3 — DSFB Endoduction

- dsfb-debug integration (verified call sequences in `docs/DESIGN-DSFB.md`),
  FuzzSemanticBank, witness/confuser logic, structural episodes,
  DISCRIMINATE/FALSIFY queues, probe recipes, precedent bank with
  falsifiable relationships, negative controls from `EXPERIMENT_PROTOCOL.md`.

## Phase 4 — FRF + Gemel

- FRF promotion court (verified sequence in `docs/DESIGN-FRF-BRIDGE.md`),
  receipt linkage, refusal preservation.
- Gemel source-state binding, durable checkpoints, negative-knowledge
  publication, revision tape replay, RevisionResidual
  (`docs/DESIGN-GEMEL-BRIDGE.md`).

## Phase 5 — AVX2 Hardening

- Profile the measured hot paths; optimize only measured bottlenecks; no
  semantic changes (property tests stay green).

## Phase 6 — Database Specialization

- Real dsfb-database bridge behind the `database` feature for actual
  database telemetry targets; type-level refusal of generic residuals
  (I7); database historical regression demonstration.

## Phase 7 — GPU

- CubeCL spike against the gates in `COMPATIBILITY.md` §6; `ComputeBackend`
  trait; batch acceleration only after CPU semantics are sealed.

## Phase 8 — Scientific Evaluation

- Ablations (mandatory ladder), historical defects with held-out partition,
  repeated trials, A12 / Mann-Whitney U from exported raw series,
  baselines vs cargo-fuzz/libFuzzer and AFL++.

## Non-goals for V1 (explicit)

Distributed clusters, symbolic execution, SMT, sound taint, GUI, SaaS,
arbitrary languages, Windows sanitizer support, custom kernel schedulers,
VM snapshots, deterministic async schedulers, every CUDA/ROCm feature,
autonomous repair, LLM inference in the hot loop. Extension points are
designed; they are not implemented because they sound impressive.
