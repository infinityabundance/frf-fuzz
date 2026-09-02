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

## Phase 5 — AVX2 Hardening (DONE)

- `examples/phase5_bench.rs` (`cargo run --release --example phase5_bench`):
  a dependency-free per-execution attribution benchmark. It measures the
  fixed worker costs (coverage scan+clear, cmp snapshot, signal/residual
  machinery, mutations, feature sort, ledger echo, the setitimer arm/disarm
  pair) and compares scalar vs AVX2 kernels. Sizes are grounded: the
  golden-demo target registers 3529 coverage-counter bytes (1 range, read
  from its worker HELLO); 64 KiB and 1 MiB bracket std-inclusive real
  targets. Honest measurement discipline: timed closures re-arm outside the
  clock, the snapshot's copy is forced materialized by an opaque consumer
  (LLVM otherwise forwards it into direct ring reads), and the S2/S8 buffers
  reuse preallocated storage.
- New normative kernel `simd/scalar.rs::scan_nonzero_clear` + AVX2 twin
  `x86_avx2.rs::scan_nonzero_clear_avx2` + runtime dispatch in `simd/mod.rs`:
  the per-window coverage consume (record every nonzero counter's packed
  `base | offset` in ascending order, CLEAR it, report `(written, saturated)`;
  a saturated consume still clears — it never leaks into the next window).
  The AVX2 path tests 32-byte chunks with one compare+movemask, skips
  all-zero chunks without a store, records nonzero offsets bit-by-bit in
  ascending order, then clears the chunk with one zero store.
- `target_runtime/sancov.rs` now walks the registered counter ranges through
  `simd::scan_nonzero_clear` (base = `range_index << 32`) and `simd::clear`;
  `scan_and_clear` returns `u32::MAX` on saturation instead of truncating.
  `target_runtime/cmp.rs::snapshot` copies the live ring as at most two
  contiguous segments (a vectorized memcpy) instead of one masked element at
  a time.
- Worker hot-path allocation removal: the per-execution `to_vec` of the
  saturated ~26 KiB cmp event window is gone. `WindowOutcome` carries
  `n_events`; events live in the fixed `events_buf` and are wired only when a
  discovery is pushed (the estimate and `wire_events` read `events_buf`
  directly). Ordinary executions now allocate nothing for events.
- Measured on this development machine (release; single runs, informational):
  the coverage consume dropped from ~880 ns (scalar) to ~60 ns
  (AVX2-dispatched) on the demo-size 3529-byte counter space, and from ~12 us
  to ~600 ns at 64 KiB (sparse 40-edge window) — the dominant fixed item,
  which had grown linearly with the counter space. `clear_all` was already
  auto-vectorized (~11 ns at demo size). The cmp snapshot is ~185 ns with a
  real materialized copy. Everything else is sub-100 ns scalar work: residual
  deltas ~56 ns, sketch ~29 ns, mutations 25-55 ns, sort+dedup ~12 ns, ledger
  echo ~2 ns, setitimer arm/disarm pair ~127 ns (measured — the timeout
  discipline is NOT a bottleneck on this kernel). The demo-size fixed worker
  floor is ~600 ns against a 15-25 us per-execution target+IPC+coordinator
  budget.
- Why Phase 5 stops here (documented in the bench's Interpretation trailer):
  the remaining items are scalar per-byte decision work or 64-bit saturating
  arithmetic (AVX2 has no 64-bit saturating subtract), each sub-100 ns;
  retrofitting them with vector tricks would risk the scalar==AVX2 invariant
  (I3) for near-zero measured gain. Mutations keep their per-execution
  candidate `Vec` deliberately: the benchmark shows the copy of the parent is
  the cost (unavoidable without in-place mutation, which would break parent
  immutability) and the allocator churn is ~10 ns of a 30-55 ns mutation.
- Verification: property tests assert scalar == AVX2 for every kernel over
  randomized/adversarial/boundary inputs (`simd` suite), the new wrap
  property test pins `cmp::snapshot` against the normative masked reference
  over randomized `(head, tail)` pairs including u32 wraparound, and
  `scripts/golden_demo.sh`/`examples/sancov_demo` re-run the instrumented
  build to confirm the masked delta sets are unchanged after the SIMD wiring
  (I3 regression). `scripts/unsafe_audit.sh` stays clean (unsafe confined to
  the approved zones; every block has a `// SAFETY:` comment).

## Phase 6 — Database Specialization (DONE)

- `src/dsfb/database_bridge.rs` (feature `database`): the ONE place the real
  `dsfb-database` 0.1.1 crate meets frf-fuzz code, for actual SQL-telemetry
  surfaces only. `TelemetryRow` is a CLOSED enum of SQL-telemetry rows
  (query-class latency/baseline, plan change, estimated-vs-actual
  cardinality, lock-wait seconds, chain depth, cache hit ratio, I/O
  amplification, workload JS divergence); each variant dispatches to the
  crate's OWN SQL-semantics constructor (`plan_regression::push_latency`,
  `cardinality::push`, `contention::push_wait`, `cache_io::push_hit_ratio`,
  ...) so a `ResidualClass` can never be chosen from generic fuzz data (I7).
- `build_stream` -> real `dsfb_database::residual::ResidualStream` (sorted;
  the crate's "adapters MUST sort" contract); `analyze` runs the real
  `MotifEngine::new(MotifGrammar::default())` and returns a bounded
  `DbAnalysis` (per-class episode counts, bounded episode views,
  `grammar::replay::fingerprint_hex` — a dsfb-database namespace id, never a
  frf-fuzz object id). Every row is validated (finite metrics,
  class-appropriate ranges, bounded labels/time) before it can reach the
  crate; invalid rows are refused, never coerced.
- Type-level refusal (I7): no `From`/`TryFrom`, no function accepts a
  frf-fuzz generic residual type, and the module never imports the generic
  fuzz machinery. Enforced by a source-level lock test
  (`no_generic_types_cross_the_boundary`) plus a `compile_fail` doctest;
  `error.rs::Error::Refused` documents the I7 boundary. This ships the
  Phase-3 design doc's promised "Phase 6 enforcement test"
  (docs/DESIGN-DSFB.md).
- `examples/db_regression_demo.rs` — the database historical regression
  demonstration (run: `cargo run --features database --example
  db_regression_demo`). One telemetry surface over an IDENTICAL 90 s raw
  tape under two program states: revision A (clean, previous-sample
  baseline) vs revision B (baseline frozen at process start — a documented
  calibration regression). Same parse surface (coverage-blind difference),
  but the real SQL grammar sees revision B develop a
  `plan_regression_onset` episode that A never forms, while a genuine
  LockRow wait ramp is read identically by both (the divergence is specific
  to the regressed channel). Deterministic fingerprints; 225 raw rows
  collapse to <= 2 bounded episodes per revision.
- `tests/phase6_database.rs` (feature `database`): hermetic integration
  tests over the REAL crate — determinism of the clean/frozen revisions,
  per-channel episode scoping (two wait events -> two channel-scoped
  episodes), empty-tape fingerprint lock (SHA-256 of the empty list),
  hostile-row refusal (NaN/out-of-range/over-long/bounded-count), row-order
  invariance after sort.
- Measured on this machine (informational): the demo asserts clean=0 /
  frozen=1 plan-regression episodes, contention=1 in both, fingerprints
  differ, and each revision reproduces its own fingerprint exactly across
  repeated analyses.
- Docs: `ARCHITECTURE.md` §12, `COMPATIBILITY.md` §7 + §11, `DESIGN-DSFB.md`
  (Phase-6 enforcement now shipped), `DEPENDENCIES.md` status.

## Phase 7 — GPU (DONE)

- `src/gpu/` (coordinator feature, zero new dependencies): the batch-compute
  architecture with the CPU implementation as the semantic oracle.
  - `gpu/backend.rs`: `ComputeBackend` trait (five batch ops:
    `generate_mutation_plans`, `morphology_distance`, `precedent_rank`,
    `influence_masks`, `compact_descriptors`), backend kinds + `probe` +
    `resolve`, the shared validation/bounds contract, and deterministic
    `rank_desc`. All ops are integer-only (no floats in any output that
    could enter a ranking/identity decision), bounded before allocation,
    and defined to accept empty batches (empty in -> empty out).
  - `gpu/cpu.rs`: `CpuBackend` — the normative oracle. Plans allocate the
    order budget across candidates by u64 largest-remainder over
    priorities (ties by index) with seeded mutator rotation (Philox);
    distances are xor-popcounts; ranks are integer fixed-point proximity
    scores; masks and compact descriptors are seeded counter-stream
    folds. Every op is a plain bounded loop a device kernel must
    replicate bit-for-bit.
  - I8 discipline: every op's output is proposal/ranking evidence only;
    nothing decides "bug"/"precedent true"/"FRF claim passes".
    I14/I15: `resolve(Some(Cuda|Rocm))` falls back to the CPU oracle and
    records the reason — never a silent substitute.
  - `doctor` reports the CUDA/ROCm TOOLCHAIN and states that no device
    adapter is admitted (toolchain presence is not an active backend),
    plus the in-effect `ComputeBackend` (CPU oracle).
- CubeCL spike (recorded 2026-09-02): cubecl-core 0.10.0 stable /
  0.11.0-pre.3 inspected from crates.io — edition 2024, no declared MSRV
  (compiles on the 1.98 build), so the MSRV gate alone does NOT exclude it.
  The DECISIVE gates (CPU == CUDA == ROCm bit-for-bit, repeated device
  determinism, acceptable compile/startup cost, measured speedup on
  realistic batch sizes) require a CUDA/ROCm device + toolchain, which this
  development machine does not have (doctor records the absence). No device
  backend is therefore admitted; `cuda`/`rocm` features stay reserved and
  dependency-free; the CPU kernels above are the equality reference a
  future adapter must pass (docs/COMPATIBILITY.md §6). cudarc/rocmrc remain
  the documented fallback adapters if CubeCL fails its gates later.
- Demo: `examples/gpu_backend_demo.rs` + `scripts/gpu_demo.sh`
  (`cargo run --example gpu_backend_demo`): deterministic proposals
  (priority shares 12/6/2 over a 20-order budget), bit-exact morphology
  distances, integer precedent ranking with deterministic ordering,
  deterministic masks/descriptors, and the recorded CUDA/ROCm fallback to
  the CPU oracle — prints GPU BACKEND DEMO PASS.
- Tests: unit tests across `gpu/` (determinism, priority allocation,
  zero-priority equal split, validation/bounds refusal, exact + symmetric
  distances incl. max-distance, rank ordering and tie-breaking, mask
  coverage + seed sensitivity, descriptor distinctness, compact-batch
  validation, empty-batch validity, fallback resolution with recorded
  notes, stable kind codes). No semantic change to any earlier phase: the
  worker/coordinator hot paths are untouched.
- Docs: `ARCHITECTURE.md` §3 + §17 + §18, `COMPATIBILITY.md` §6,
  `DEPENDENCIES.md`, `INVARIANTS.md` I8/I15, `README.md` status.

## Phase 8 — Scientific Evaluation (DONE)

- The experiment instrument (`frf-fuzz experiment`, `src/experiment/`):
  repeated independent trials over the four code-level ablation arms, raw
  series export, and non-parametric comparison.
  - Arms = frozen deltas over the campaign's three feedback switches
    (protocol §2 ladder rungs 1-5): `cov` (cmp off, residual off, precedent
    off) -> `cov+cmp` -> `residual` -> `full`. Rungs 6-9 are orthogonal
    axes, documented, not switches: Gemel revision memory (durable
    boundaries, Phase 4), AVX2 (measured constant, I3), GPU (unadmitted,
    Phase 7), full system = `full` + a configured FRF authority.
  - **New honest ablation switch `--cmp on|off`**: with cmp off the
    const-compare dictionary discovery is gated, the dictionary/compare
    mutation families leave the Explore rotation (`MutatorId::
    WITHOUT_CMP_GUIDED`, locked by test), and the worker skips cmp-ring
    reset/snapshot/substitution (env `FRF_FUZZ_CMP`). `--residual off` was
    already coverage-only in spirit but still carried the Phase-2
    morphology/state-feature persistence: those are now residual-gated too
    (a coverage-only corpus stores no morphology objects, counts no state
    features, feeds no regime/lineage machinery — the ablation arms are
    semantically clean, not just scheduler-degenerate).
  - Trial hygiene: fresh store per trial, deterministic per-trial seeds
    (splitmix64 over base seed + trial; shared across arms so arms differ
    only in their feedback channels), budget-mandated (`--max-time` /
    `--max-execs` required: trials are right-censored by design).
  - Censoring discipline: time/executions-to-first-failure trials that find
    nothing are exported as `NA` rows and reported as found/censored counts
    per arm — never silently dropped; arm-pair A12/MWU on censored metrics
    uses the labeled complete-case subset.
  - `experiment/stats.rs`: dependency-free median/quartiles, Vargha-Delaney
    A12, Mann-Whitney U (normal approximation, continuity + tie correction,
    self-contained `erfc`). Property-locked against hand values, identical
    samples (A12 = 0.5, p = 1), full separation (A12 = 0/1), ties, and the
    direction reversal.
  - `experiment/mod.rs`: `AblationArm`/`Metric` tables (codes locked by
    test), series CSV export with the protocol §3 mandatory metadata in
    `#` comment lines + `read_series` re-import (malformed/non-finite rows
    refused), deterministic experiment id (excludes paths and wall clocks),
    host/environment record, JSON + human analysis with the fixed power
    caveat (I11: the CLI never bakes an unsupported statistical claim).
  - Held-out partition (`held_out_split`): deterministic Fisher-Yates over
    a splitmix64 stream; disjoint, recorded, reproducible development/blind
    splits for the protocol §4 benchmark-leakage control.
- Executable demonstrations:
  - `scripts/phase8_ablation_demo.sh` (run via the pinned nightly): builds
    the golden-demo target and runs `frf-fuzz experiment golden-demo
    --arms cov,cov+cmp,residual,full --trials 2 --max-time 10`.
    Assertions: cov/cov+cmp record zero morphologies/regime
    episodes/amplify orders/precedent matches in every trial (negative
    control: no residual machinery, no trajectory); cov+cmp reaches the
    magic gate; residual/full retain the Path-B trajectory (morphologies >
    0 and a state-feature space beyond the seed baseline in every trial)
    and reach failures; the exported series is the recomputation authority
    (metadata record, row count, JSON well-formedness, power caveat).
  - `scripts/baseline_compare.sh`: cargo-fuzz/libFuzzer baseline of the
    same golden gates (scratch `fuzz/` package built outside this crate,
    `#![no_main]` harness, pinned nightly, ASan); AFL++ skipped with a
    recorded message when not installed. Informational single trials only,
    labeled as such (protocol §9: never publication evidence).
  - `scripts/cli_smoke.sh` now exercises the experiment CLI surface
    (budget/arm-switch argument guards + a 2-arm smoke with JSON + record
    checks).
- Measured on this machine (informational; demo trial counts — the analysis
  output says so and so does this record): 4 arms x 2 trials x 10 s on the
  golden-demo target, 8 workers. Coverage-only runs ~143k exec/s and
  reaches the magic gate only blindly (~340k execs, 1/2 trials); cov+cmp
  runs ~108k exec/s, finds the gate in 2/2 trials at ~472k execs; the
  residual arms run ~53k exec/s (residual analysis + crash restarts cost
  throughput) but reach the Path-B failure at ~84k execs / ~1.24 s in 2/2
  trials — about 6x fewer executions and ~3.5x less wall time than cov+cmp
  — and are the only arms with a retained trajectory (33 drift state
  features vs the 1-bucket seed baseline, 5.5 morphology identities, ~108
  amplify orders, 12 boundary witnesses). Honest observations recorded:
  closed regime episodes are 0 even in the residual arms because the
  ladder's lineages END in crashes while still InEpisode (an episode closes
  on recovery/collapse; open trajectories are the live observation —
  episode formation/close semantics stay pinned at engine level in
  `tests/residual_semantics.rs`), and precedent/probe activity needs longer
  campaigns than 10 s (the 15 s+ golden-demo campaign demonstrates it). At
  demo budgets the magic gate is not cmp-exclusive: the near-gate seed +
  classic integer/boundary mutators can co-evolve `0xBEEF` blind in ~340k
  execs — compare guidance is a reliability/speed channel here, and the
  load-bearing claim is the trajectory one. Publication-grade conclusions
  need the FuzzBench-scale repeated-trial protocol; the machinery is real
  and the exports preserve every raw series.
- Tests: `tests/phase8_experiment.rs` (export -> import -> recompute
  identity, censoring survival, held-out disjointness/leakage guard,
  identical-arms negative control A12 = 0.5/p = 1, hostile export refusal,
  caveat presence) + `experiment` unit tests (arm/metric table locks, seed
  derivation, CSV round trip, complete-case comparisons, experiment-id
  path/time exclusion).
- Docs: `EXPERIMENT_PROTOCOL.md` §2-§5 implementation record,
  `ARCHITECTURE.md` §22, `README.md` status.

## Non-goals for V1 (explicit)

Distributed clusters, symbolic execution, SMT, sound taint, GUI, SaaS,
arbitrary languages, Windows sanitizer support, custom kernel schedulers,
VM snapshots, deterministic async schedulers, every CUDA/ROCm feature,
autonomous repair, LLM inference in the hot loop. Extension points are
designed; they are not implemented because they sound impressive.
