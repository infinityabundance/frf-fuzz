# frf-fuzz Roadmap

Phase 0 is complete and documented. Phases are executed in order; nothing is
"shipped early" in a way that pretends a later phase exists. Empty
abstractions are not shipped — if a module is not implemented, it is listed
here, not created as a stub.

## Phase 0 — Specification / Forensic Spikes (DONE)

Deliverables, all verified:

- Dependency forensics: frf 0.1.72, gemel 0.11.0, dsfb-debug 0.1.0,
  dsfb-database 0.1.1 inspected from source (`.phase0/forensics/REPORT-*.md`).
- Pinned dependency matrix (`docs/DEPENDENCIES.md`), MSRV verified for the
  whole feature matrix (the Phase-3 section below records the later raise
  to 1.98).
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

## Phase 3 — DSFB Endoduction (DONE)

- `src/dsfb/debug_bridge.rs`: real dsfb-debug 0.1.0 substrate integration.
  The bridge calls the crate's public free functions
  (`sign::compute_sign_tuple`, `sign::drift_persistence`,
  `grammar::evaluate_raw_grammar`, `grammar::hysteresis_confirm`,
  `dsa::compute_dsa_score`, `dsa::consistency_gate`,
  `policy::apply_policy`) with `SemanticDisposition::Unknown` only — never
  DSFB production motifs (I6). One substrate per ROOT: all mutator families
  of a root share the behavioral stream (earlier per-(root,mutator) wiring
  produced fragmented streams and no calibrated envelope — a Phase-3
  finding). Declared calibration law: the first `calibration_windows` (8)
  axis-event windows fix mean and rho = max(3 sigma, 2 x span); perfectly
  flat axes become "discrete" (no envelope grammar — frf-fuzz state classes
  interpret them). Real boundary density (over the recent raw-grammar ring)
  is fed into the DSA score instead of the crate's hardcoded 0.0. Axis
  verdicts are integer-only, with durable `Family::StructuralVerdict` (0x0D)
  objects and closed structural episodes persisted as
  `Family::StructuralEpisode` (0x0E).
- `src/dsfb/fuzz_bank.rs`: the FuzzSemanticBank — 13 fuzz-specific classes
  (ComparisonConvergence..CrossSignalPropagation; names describe structural
  observations, never causes), per-class
  gates/prerequisites/refusals/confusers/provenance/recommended families,
  deterministic integer scoring with specificity tiers, an ambiguity guard
  (an exact same-score same-tier rival stays Unknown), axis roles derived
  from schema names, and the hard Structured+Unknown discipline (I6).
- `src/precedent/{mod,model,matching,probe,admission}.rs`: durable
  revisioned precedent bank (content-addressed `Family::Precedent` 0x05),
  shape-subsumption matching with a lead window, falsifiable probe recipes
  evaluated on real batch summaries (Support/Contradict/Ambiguous; direct
  contradiction flips status; partial contradictions accumulate x3),
  precedent admission only from real terminal observations (provenance),
  contradictions never deleted (I10), and
  `load_current`/`save_revision`/`verify_links` for fsck.
- Scheduler: DISCRIMINATE and FALSIFY scheduling classes (weighted
  round-robin over 4 weights) with the probe queue and in-flight sets
  bounded in the coordinator; `--precedent on|off`, `--discriminate-weight`
  and `--falsify-weight` CLI flags.
- CLI/report/fsck: `frf-fuzz precedent list|show`; `inspect` decodes
  verdict/episode/precedent payloads; `report` counts structural
  verdicts/episodes, precedent families and revisions; `fsck` verifies
  precedent revision chains, lineage roots (corpus entries) and terminal
  references.
- Demo/tests: `scripts/golden_demo.sh` extended with Phase-3 stages;
  `examples/precedent_engine_demo.rs` demonstrates acceptance items 10-12
  (a precedent proposes a falsify probe; the probe can support or
  contradict; a contradiction is durably retained; the store stays
  fsck-clean); `tests/endoduction.rs` = 7 negative-control + acceptance
  tests (noise-only lineage names nothing, threshold elasticity collapses
  to Unknown, replay determinism/shuffle, match+support+contradiction
  retention, substrate escalation naming, role determinism).
- Coordinator MSRV raised to 1.98 (`rust-version = "1.98"`, edition 2021,
  crate 0.3.0) by explicit user decision to use the latest stable rustc.
  The pinned instrumented nightly was re-verified and re-pinned
  (`nightly-2026-07-24`, rustc 1.99.0-nightly, LLVM 22.1.8) and the
  instrumented flag set re-proven end-to-end via `scripts/nightly_spike.sh`
  and `scripts/golden_demo.sh` (details in `docs/COMPATIBILITY.md`).

Measured on the golden-demo target (8 workers, 15 s per campaign, pinned
nightly): the residual-on store ends with 45 corpus entries, 36 coverage
features, 33 state features, 39 morphology signatures, ~21 structural
verdict objects and 1-3 candidate precedent families (the run that formed 3
held precedents across mutators 9/12/14), fsck-clean including precedent
links. The coverage-only control forms 0 precedents (control holds).
`frf-fuzz precedent list` renders the bank, and
`examples/precedent_engine_demo` prints PRECEDENT ENGINE DEMO PASS.

Throughput on this development machine (8 workers, 10 s, single runs —
§31: no performance conclusion from one run; Phase-1 numbers predate the
Phase-2/3 per-execution observation machinery): ~40k exec/s with
residual+precedent on, ~63k exec/s coverage-only, on the same target and
build. The rate is dominated by the worker's per-execution cmp/sketch work
and coordinator debug builds; Phase-5 (AVX2 hardening) optimizes only
measured hot paths.

## Phase 4 — FRF + Gemel (DONE)

- `src/frf_bridge.rs`: the epistemic-authority plane. Real `frf` 0.1.72
  courts run in-process on promotion: authority admission (once; drift =
  refusal with an actionable message), the court-question manifest (a strict
  YAML emitter with no serde dependency, validated in tests against FRF's
  own parser), `court::run_once(reuse=true)` for FRF-immutability-safe
  idempotent evidence capture, `receipt::run` (the evidence id, retained
  verbatim), and optional claim compilation (`--claim`/`--verify-claim`:
  residuals disposed `Intentional`, baseline claim). Cwd is pinned to the FRF
  store root during the court (stable capture environment identity).
- `Family::FindingVerification` (0x0F): durable verification records
  (finding id, authority, outcome, FRF run/receipt/claim ids, deterministic
  bounded note). No authority => DERIVED `Unverified` — never fabricated
  (acceptance item 16). A crash finding is `Verified` only when the court
  observed >= 1 residual divergence; a parity receipt (0 residuals) is
  `Failed` with the receipt preserved as evidence of non-reproduction (I10).
- Campaign auto-verify: `run --authority <path> [--authority-name/-version]
  [--verify-candidate <path>] [--verify-claim] [--question-id]
  [--fixture-family] [--gemel on|off]`; replay-confirmed crash/timeout
  findings are court-verified at promotion (Level 2) with a per-campaign
  input dedup (a crash flood never re-runs one court per duplicate input).
  Any court/refusal/config failure is persisted as `Failed` and never fails
  the campaign (I14). The verification candidate is the fuzz target binary
  itself via its new single-shot fixture mode.
- `target_runtime/fixture.rs`: `frf_fuzz_<name> --frf-fuzz-fixture <path>`
  runs the registered hooks exactly once over a file's bytes and exits —
  the case-harness interface FRF courts execute (no environment required;
  FRF runs sides with an empty env). Hot path untouched.
- `src/gemel_bridge.rs`: `Repo::find` discovery (absent => standalone,
  broken => recorded failure class), read-only source-state snapshots
  (head-state/change/intent/trajectory/producer Gids verbatim), and durable
  publications: campaign create/complete checkpoints
  (`workflow::create_checkpoint`), verified-finding `Evidence`
  (`court_receipt`) bound to the evaluated state (field 0x11) + `Claim`,
  precedent-admission `Evidence` (`fuzz_result`), falsified-precedent
  `Residual` (`expected_mismatch`) — negative knowledge. Every boundary
  writes a local `Family::GemelBoundary` (0x10) record with the snapshot,
  the published Gids, and the deterministic failure class, so Gemel-side
  failures are observable and never silent (I14). No per-execution Gemel
  writes (I5; verified by test + the golden demo's boundary counts).
- `tape/revision.rs` + `Family::RevisionResidual` (0x11): revision tape
  replay — the same tape's exact candidate re-executed through per-state
  artifact binaries (instrumented targets built from the revisions) with
  durable adjacent-pair objects (tape id, artifact BLAKE3 digests,
  environment digests, termination statuses, signal observations) and the
  typed R_V residual derived at decode. `frf-fuzz revision replay
  <tape-or-finding-id> --state <label>=<binary> ...` (finding ids resolve
  their campaign crash tape deterministically).
- CLI/report/fsck: `verify`, `revision replay`; `run` banner states the
  authority + gemel mode; summary/report count FRF verifications/verified/
  failed and gemel boundaries; `inspect` decodes all three new families;
  `fsck` validates verification-record -> finding links (+ FRF id shape),
  gemel-boundary -> subject links (+ published-Gid presence), and
  revision-pair -> tape links.
- Demo/tests: `tests/phase4_frf_gemel.rs` (8 hermetic integration tests
  running REAL FRF courts with script sides and REAL Gemel repositories
  with head states: verified+idempotent receipts, non-reproduction =
  Failed+preserved, derived-unverified, claim compilation, standalone
  absence, state-bound evidence+claim publication, falsified-precedent
  residual publication, revision-pair roundtrip); `examples/golden_authority.rs`
  (the demo's clean reference) + `examples/phase4_gemel_init.rs` (demo repo
  with a head state); `scripts/golden_demo.sh` stages 11-17 prove acceptance
  items 15-17 live (real FRF-verified receipts at campaign promotion, gemel
  checkpoints + evidence/claim, authority-less controls stay unverified,
  idempotent CLI verify, revision tape replay, fsck-clean at every stage);
  `scripts/cli_smoke.sh` exercises the new CLI surface.

Measured on the golden-demo target (8 workers, 12 s campaign with an
authority + Gemel repo): 1 crash found and FRF-VERIFIED with a real receipt
(`reference=0 candidate=signal(6)` residual), 3 gemel boundary records
(created + completed + finding-verified), store fsck-clean; the two
authority-less control campaigns record zero verifications. FRF courts add
wall-clock time only at crash promotion (Level 2; seconds per court on this
machine) — never in the per-execution loop.

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
