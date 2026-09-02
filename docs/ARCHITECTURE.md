# frf-fuzz Architecture

Status: **Phase 0 complete** (see `ROADMAP.md`). This document is the
architectural contract for the whole project; later phases extend it without
violating it.

## 0. Mission

frf-fuzz is a heterogeneous residual-guided fuzzing engine and deterministic
endoductive software-experimentation system. It is one Cargo package, one
crate, two planes.

```
Coverage tells us where execution went.
Residual structure tells us how behavior is changing.
Historical residual trajectories tell us where to interrogate next.
FRF determines whether promoted discoveries are evidence.
Gemel remembers what those discoveries meant across software evolution.
```

The loop:

```
Observe -> Characterize -> Compare -> Form bounded structural hypothesis
-> Select next experiment -> Execute -> Attempt falsification
-> Promote meaningful discoveries -> FRF verification -> Gemel memory
```

frf-fuzz never converts this into probabilistic bug prediction. It emits
deterministic structural statements ("current trajectory matches prefix
SIG-…", "required witness X has not appeared", "status: candidate precursor",
"FRF verification: absent / failed / admitted") and falsifiable proposed
continuation experiments — never "87% likely to be a bug".

## 1. Two planes (load-bearing)

```
EXPLORATION PLANE                        EVIDENCE PLANE
high throughput                          deliberate
disposable intermediate state            replayable
heuristic scheduling allowed             deterministic
GPU proposals allowed                    immutable
approximate influence inference allowed  FRF-backed (when configured)
coverage + morphology guide              Gemel-backed (when present)
```

The escalation ladder:

| Level | Runs on | Work |
|---|---|---|
| 0 | every execution | coverage counters, compact compare observations, target-defined signals, timing/resource sketch, cheap residual sketch, crash/timeout status |
| 1 | interesting/sampled | structural residual analysis, drift/slew, regime update, morphology signature, DSFB fuzz-bank interrogation |
| 2 | promotion | deterministic replay, stability measurement, counterfactual/boundary reduction, optional FRF court |
| 3 | durable memory | precedent admission/update, Gemel checkpoint/evidence/residual linkage, campaign summary |

Hard rule: no full FRF court, no Gemel write, no complete DSFB detector field
on the ordinary per-execution path. This separation is enforced by the module
structure (see §8): the `target-runtime` feature tree has no dependency on the
coordinator tree.

## 2. Toolchain and compatibility

* Coordinator: stable Rust >= 1.98 (`rust-version = "1.98"`, edition 2021;
  `pub const MSRV: &str = "1.98"` in `src/lib.rs`). The MSRV was raised from
  1.85 to the current stable (1.98.0) by deliberate decision at the end of
  Phase 3 ("use the latest rust version").
* Instrumented fuzz target: pinned nightly (`DEFAULT_PINNED_NIGHTLY`,
  currently `nightly-2026-07-24`, rustc 1.99.0-nightly
  `89c61a7545da48b06116675b888398d02a4064c7`, LLVM 22.1.8). The previous pin
  (`nightly-2026-04-21`, rustc 1.97.0-nightly) was rustc 1.97 — below the
  raised MSRV, so Cargo refused the instrumented build — and the pin was
  re-pinned/re-verified: same LLVM-22 generation as the verified 22.1.2 flag
  set, with `scripts/nightly_spike.sh` + `scripts/golden_demo.sh` re-proven
  end-to-end on it. The identity is verified by `frf-fuzz doctor` and
  recorded in campaign metadata; a mismatched nightly is reported, never
  silently used.

See `COMPATIBILITY.md` for the verified flag sets, the `--target` requirement,
and the ASan/trace-compares incompatibility (Phase-0 findings).

## 3. Feature architecture (one crate)

```toml
default = ["coordinator"]
coordinator = ["dep:blake3", "dep:frf", "dep:gemel", "dep:dsfb-debug"]
target-runtime = []
database = ["dep:dsfb-database"]
cuda = []          # reserved: no device adapter admitted (Phase-7 gates)
rocm = []          # reserved: no device adapter admitted (Phase-7 gates)
dangerous-inprocess = []   # reserved
```

The coordinator `gpu/` module (batch-compute contract + CPU oracle) is part
of the `coordinator` feature and adds no dependencies. Enabling `cuda` or
`rocm` changes nothing yet: `gpu::resolve(Some(Cuda|Rocm))` falls back to
the CPU oracle and records the reason (I14/I15).

The user's fuzz harness depends on `frf-fuzz` with
`default-features = false, features = ["target-runtime"]`. The coordinator
dependency tree (frf, gemel, dsfb-debug, blake3) is never compiled into the
instrumented target. Verified: `cargo build --no-default-features --features
target-runtime` compiles only `memmap2` plus the crate itself.

## 4. User experience (target)

```
cargo install frf-fuzz
cd my-project
cargo frf-fuzz init | add parser | build parser | run parser
```

A generated target is a normal binary in the user's existing crate
(`src/bin/frf_fuzz_parser.rs`), built with the pinned nightly + the verified
flag set and `--target <triple>` (see `COMPATIBILITY.md`). The target closure
surface is `fuzz_target!(|data: &[u8], cx: &mut FuzzContext| …)` with
pre-registered numeric signal IDs; no signal strings in the hot loop.

## 5. Execution architecture (work orders, not per-input IPC)

The coordinator spawns N persistent instrumented worker processes. They speak
a bounded versioned binary protocol (`execute/protocol.rs`): framing
`FRFZ | major u16 | minor u16 | kind u8 | len u32 | payload | crc32`,
1 MiB frame bound, unknown major fails closed, hostile lengths rejected before
allocation. Messages: Hello, Capabilities, WorkOrder, WorkResult, Discovery,
Heartbeat, Shutdown, Error.

**The coordinator dispatches WORK ORDERS** — parent input, mutation coordinate
range, mutator family, energy/budget, probe recipe, campaign seed, dictionary
generation, signal schema — and the worker executes hundreds/thousands of
local deterministic mutations before returning. IPC cost is amortized toward
zero (measured: ~5.3µs/execution per-input vs ~0.8µs/execution batched at
k=1000; see `PHASE0_FINDINGS.md`).

Every mutation is reconstructible from: campaign seed, parent content ID,
generation, mutator ID, lane ID, mutation index, probe parameters. No mutable
global RNG state.

## 6. Deterministic mutation coordinates

`MutationCoordinate` (49-byte canonical encoding) maps to a Philox4x32-10
stream (Random123; official KAT vectors locked in `mutation/prng.rs`):

```
counter = [generation, mutator<<16|lane, index_lo, index_hi]
key     = [seed_lo, seed_hi]
```

The same coordinate produces identical decisions on scalar CPU, AVX2, CUDA,
ROCm. `probe_params` are carried for provenance but intentionally do not
enter the stream (they parameterize which experiment runs, not the draw).

Mutator families have stable numeric IDs 1..16 (see `mutation/mod.rs`; the
table is locked by a test). Fifteen families are implemented; the ID table
must never be renumbered.

## 7. Crash recovery without per-execution IPC

Per-worker shared crash ledger (`execute/crash_ledger.rs`): two self-
validating 128-byte slots (magic + seq + 49-byte coordinate + CRC-32) in a
memory-mapped file. The worker commits immediately before executing the
target; if it dies (panic=abort, ASan finding, signal, OOM, abort), the
coordinator reads the newest valid slot, reconstructs the exact candidate,
records crash metadata, and restarts the worker.

Crash consistency argument (no atomics needed): the CRC is written last and
covers magic+seq+coordinate; the reader only reads after the worker died, so
every observed state is a complete commit or a prefix of one — any torn state
fails CRC. Residual risk ≈ 2⁻³² per torn byte (see `THREAT_MODEL.md`).

Proven end-to-end by `tests/crash_recovery.rs`: abort(), panic=abort, restart,
and kill-before-commit cases.

## 8. Instrumentation and the measurement window

The runtime (`target_runtime/`) implements the SanitizerCoverage consumer:
counter-range registration (bounded, refusal latched), all comparison
callbacks (cmp1/2/4/8, const_cmp1/2/4/8, switch), pc-table registration, and
indirect-call counting.

### Phase-0 instrumentation findings (see `COMPATIBILITY.md` / `PHASE0_FINDINGS.md`)

1. `-Cpasses=sancov-module` is the current pass name (`sancov` is dead on
   LLVM >= 20); verified on LLVM 20.1.1 .. 22.1.2. The Phase-3 pin
   (`nightly-2026-07-24`) runs LLVM 22.1.8 — the same LLVM-22 generation —
   and the flag set was re-proven end-to-end on it (see §2).
2. The `__sanitizer_` name-prefix exclusion was **removed in LLVM 18**;
   the only remaining exclusion is the `NoSanitizeCoverage` attribute, which
   rustc cannot emit. rustc's `#[sanitize(address = "off")]` emits **no**
   LLVM attribute (verified). => the runtime cannot be compile-time excluded.
3. An instrumented comparison callback recurses: its own comparisons, its
   ASan shadow checks, its static-mut reference probes, and the std atomic
   `Ordering` match are all themselves cmp/switch-instrumented. Verified
   recursively, each cause isolated and eliminated.
4. `-Zsanitizer=address` + trace-compares + Rust-defined callbacks **cannot
   coexist** on LLVM >= 18. Default builds therefore use sancov +
   trace-compares WITHOUT ASan; `sanitizer = "address"` is an opt-in that
   disables trace-compares.

### The measurement window (worker invariant)

```
[per execution]
  write crash ledger coordinate + input echo   (edges/events wiped by the
                                                clear below)
  arm one-shot SIGALRM timeout                 (fires only on a genuine hang;
                                                the process dies, no scan runs)
  clear coverage counters
  reset cmp ring
  (reset hook, then execute hook)
  snapshot cmp ring                            (captures EXACTLY the target's
                                                events — the scan has not run
                                                yet; no tail truncation)
  scan coverage counters                       (its own cmp events land after
                                                the captured range and are
                                                discarded by the next reset)
  disarm timeout
```

Only the target runs between clear and scan. The runtime's own edges are a
constant footprint R, measured once during campaign calibration (the FULL
window skeleton: clear/reset/(reset hook)/noop-execute/snapshot/scan) and
permanently masked. Verified by `examples/sancov_demo` (built with the
pinned nightly): footprint stable, masked delta = pure target edges,
input-discriminating, cmp events captured.

The runtime's callback path is written icmp-free and loop-free (branchless
overflow, raw-pointer ring writes, pointer-carrying switch events parsed
after the window) so that the recursion cannot return if rustc ever wires
the sanitize attribute, and so the window footprint stays minimal. At
opt-level 3 the callback path was re-verified end-to-end (no recursion).

There are deliberately NO background threads in the instrumented binary: a
thread's instrumented edges fire at unpredictable times inside the window
and cannot be calibrated out (COMPATIBILITY.md §4.5.2). The per-execution
timeout is a one-shot `SIGALRM` (`setitimer`), whose handler aborts the
process only when the target hangs; the crash ledger already holds the
coordinate, so the coordinator records a timeout finding.

## 9. Compare feedback

Callbacks feed a bounded allocation-free ring (`target_runtime/cmp.rs`,
16 384 events, overflow latched as a mask). Phase-1 policy: compare operands
drive magic-value discovery, dictionary discovery, compare-convergence
residuals, and cmp-guided substitution (the `CompareOperandSubstitution`
mutator is already implemented). No heap, no mutex, no formatting in the
callback path; operand width + values are sufficient (precise call-site PCs
deferred until a measured implementation exists; never stack unwinding).

## 10. SIMD

`simd/` provides coverage-scan, novelty-bitmap, mismatch, popcount, chunk-
presence and signature operations. Scalar implementations are normative
(`simd/scalar.rs`, which stays unsafe-free); AVX2 (`simd/x86_avx2.rs`) is
runtime-dispatched via `is_x86_feature_detected!` and must be bit-for-bit
identical (property tests cover randomized, adversarial, and boundary sizes;
the byte-popcount uses the AVX2 nibble-lookup trick, bit-level semantics
matched to scalar). Unsafe is confined to the approved zones (see
`INVARIANTS.md`).

Phase 5 wired the three measured per-window costs through these kernels:

* `scan_nonzero_clear` (`simd/{scalar,x86_avx2,mod}.rs`) is the per-execution
  coverage consume expressed over one contiguous slice: it records the packed
  `base | byte_offset` of every nonzero counter into the output (ascending
  order) and CLEARS it, reporting `(written, saturated)` — a saturated
  consume still clears everything, so a report overflow never leaks into the
  next window. `target_runtime/sancov.rs::scan_and_clear` walks the registered
  counter ranges and feeds each range slice to the dispatched kernel with
  `base = range_index << 32`; `clear_all` likewise dispatches `simd::clear`
  per range (LLVM already auto-vectorized the old byte loop, so clearing was
  never the bottleneck — the scan was: ~880 ns -> ~60 ns scalar vs AVX2 on
  the demo-size 3529-byte counter space). The kernel returns saturation
  (`u32::MAX`) instead of truncating silently.
* `cmp::snapshot` copies the live ring region as at most two contiguous
  segments (head/tail are power-of-two masked; the live count is <= RING_LEN
  by the push discipline) instead of one masked element at a time, so the
  copy lowers to a vectorized memcpy (~226 ns -> ~185 ns measured with a real
  materialized copy; the masked loop could not vectorize across the wrap).
  The wrap correctness is property-tested against the normative masked
  reference over randomized (head, tail) pairs covering u32 wraparound.
* The worker no longer heap-copies the cmp event window on every execution:
  `window_with` snapshots into the fixed `events_buf` and records
  `n_events`; the events are wired into a discovery only when one is pushed.
  Previously every execution paid a `to_vec` of the saturated ~26 KiB event
  window (a per-execution allocation + copy, violating the performance
  contract); ordinary executions now allocate nothing for events.

The remaining per-execution items (residual deltas ~56 ns, sketch ~29 ns,
mutations 25-55 ns, feature sort ~12 ns, ledger echo ~2 ns, setitimer
arm/disarm pair ~127 ns on this kernel) are scalar by nature — the deltas
are 64-bit saturating arithmetic and AVX2 has no 64-bit saturating
subtract — and sub-100 ns each, so Phase 5 stops at the measured items
(`examples/phase5_bench`, `cargo run --release --example phase5_bench`).
The demo-size fixed worker floor is ~600 ns against a 15-25 us per-execution
target+IPC+coordinator budget.

## 11. Observation frame and residuals

`ExecutionObservation` (Phase 2, `observe/frame.rs`) is compact and
fixed-size: coordinate, outcome, feature set, compare summary, compare hits
used (family-15 exact reconstruction), signal vector, residual sketch, time
bucket. The hot representation is bounded and heap-free on the worker side
(the `SignalVector` + `ResidualSketch` are fixed-size arrays).

The four residual families are separately typed and never flattened into one
score. Phase 2 implements the two that exist in Phase 2:

* Mutation residual `R_M(child, parent)` — `observe/residual.rs::
  MutationResidual`: exact saturating per-signal deltas of a corpus edge, the
  child-vs-parent residual sketch, and the touched-new/lost masks. Computed
  from the parent's RECORDED observation (carried in the work order), so
  residuals are lineage-consistent.
* Temporal residual `R_T(k)` — `TemporalResidual`: observation vs the
  lineage nominal + instantaneous delta; feeds the regime observer.

Authority residual (FRF, Phase 4) and revision residual (Gemel, Phase 4) are
NOT stubbed; they arrive with their bridges (docs/ROADMAP.md).

The cheap Level-0 sketch (`target_runtime/signals.rs::ResidualSketch`) is
computed in the worker per execution against the order's parent signals:
per-signal magnitude buckets, 2-bit directions, touched-new/lost masks — all
fixed-size, heap-free, deterministic. The worker folds sketches into a
per-order `OrderSignalTracker` (consecutive same-direction runs + cumulative
magnitude) and a `SignalBatchSummary` (the full observation stream in
bounded aggregate form — how the coordinator sees rejected executions
without per-execution IPC).

## 12. DSFB integration

The `dsfb/` module takes the architectural lessons and reimplements them
locally, with semantics documented independently of SQL (I7):

* `dsfb/regime.rs::RegimeObserver` — the DSFB-Database lesson: instantaneous
  residual + integer fixed-point EMA (2^shift units; a raw-unit floor EMA
  gets stuck below 2^shift and recovery never fires — a Phase-2 finding) +
  `Stable -> Drift -> InEpisode -> Recovering` + dwell counts + a
  deterministic episode close (recovery dwell or max-dwell cap — never
  wall-clock). Episodes reset their deviation baseline at close so a later
  regime opens its own bounded episode. Closed episodes are durable
  `Family::RegimeEpisode` objects. The real `dsfb-database` crate (feature
  `database`) is used only for real database telemetry targets;
  generic fuzz residuals can never be coerced into its `ResidualClass` —
  no conversion exists (I7).
* `dsfb/database_bridge.rs` (Phase 6, feature `database`) — the ONE place
  the real `dsfb-database` crate meets frf-fuzz code. `TelemetryRow` is a
  closed enum of SQL-telemetry rows (query-class latency/baseline, plan
  change, cardinality estimate-vs-actual, lock-wait seconds/chain depth,
  cache hit ratio, I/O amplification, workload JS divergence). Each variant
  pushes through the crate's OWN SQL-semantics constructor, so a
  `ResidualClass` value is chosen only by the constructor the variant
  dispatches to — never from a bare value and a tag (I7). `analyze` runs
  the real `MotifEngine` over the sorted real `ResidualStream` and returns
  bounded episodes + the crate's deterministic replay fingerprint
  (`grammar::replay`; dsfb-database namespace). Rows are validated before
  they can reach the crate (finite, class-ranged, bounded labels/time);
  hostile rows are refused, never coerced. The generic fuzz machinery is
  never imported here (source-level lock test + `compile_fail` doctest).
  Demonstration: `examples/db_regression_demo.rs` (same raw tape, clean vs
  frozen-baseline distiller revision -> the real grammar sees a
  `plan_regression_onset` episode appear in the regressed revision only).
* `dsfb/morphology.rs::MorphologySignature` — an inspectable deterministic
  shape (axis mask, direction bits, magnitude/slew/persistence bins,
  coactivation, comparison-convergence class, state-change class, replay
  stability, structured-Unknown marker, depth). The canonical encoding is
  hashed for the ID, but every field is retained. `LineageAccumulator`
  derives successive signatures from a lineage's edge residuals; replaying
  the same edges yields identical signatures (I12 spirit). The classifier
  distinguishes `Trivial` from `StructuredUnknown`; naming is deferred to
  the Phase-3 FuzzSemanticBank, and a structured signature that matches no
  named class stays `StructuredUnknown` — it is NEVER renamed to a nearest
  label (I6). **Admission novelty is the *structural identity*** (shape fields;
  magnitude/persistence bins excluded — otherwise a drifting trajectory
  floods the corpus, a Phase-2 finding measured at ~3300 admissions in 12s
  on the golden demo).

Phase 3 shipped the real dsfb-debug substrate and the bank.
`dsfb/debug_bridge.rs` calls dsfb-debug 0.1.0's public free functions only
(`sign`, `grammar`, `dsa`, `policy`); its production motif machinery and
`evaluate_signal` bank lookup are bypassed, so production-debugging motif
names never appear on fuzz behavior (I6). The substrate is one
`LineageSubstrate` per ROOT — all mutator families of a root share the
admitted-edge behavioral stream (the per-(root, mutator) variant was a
Phase-3 finding: fragmented streams never calibrated an envelope). The
declared calibration law: the first `calibration_windows` (8) axis windows
fix the mean and rho = max(3 sigma, 2 * span); an axis that stays exactly
flat through the extended segment becomes a discrete/step axis — no
envelope grammar, interpreted by frf-fuzz's discrete state classes
instead. Real boundary density from a raw-grammar ring feeds the DSA score
(dsfb-debug's own `evaluate_signal` hardcodes 0.0 there with a comment; the
free-function chain does not). Axis verdicts are integer-only and durable
per structural edge as `Family::StructuralVerdict` (0x0D); closed
structural episodes persist as `Family::StructuralEpisode` (0x0E).
`dsfb/fuzz_bank.rs` is the FuzzSemanticBank: 13 named fuzz classes with
reason-code/grammar prerequisites, context predicates, confusers,
provenance, and recommended experiment families, scored deterministically
with small integers, specificity tiers, and an ambiguity guard (a
same-score same-tier rival keeps `Structured + Unknown`).

## 13. Scheduler

Explicit scheduling classes (`scheduler/policy.rs`): EXPLORE (code 1,
uniform parents, rotated families) and AMPLIFY (code 2, re-mutate a
drifting lineage's frontier with the exact drifting family, continuing its
index space), plus the Phase-3 probe classes DISCRIMINATE (code 3, separate
two or more plausible precedents/confusers) and FALSIFY (code 4,
aggressively test a strong precursor hypothesis). A configurable
deterministic weighted round-robin (a pure function of the campaign seed
and a per-planner counter) picks among the classes that are currently
available: four weights, one per class (zero disables the class; default
[4, 1, 1, 1]). Probe classes schedule matched-lineage probe batches and
fire only while residual guidance AND the precedent switch are on. The
probe queue is bounded (`MAX_PROBE_ENTRIES`, 256) with a bounded in-flight
set. The amplify queue is bounded
(`MAX_AMPLIFY_ENTRIES`), populated by batch-drift detection over the worker's
signal summaries (persistence run + cumulative magnitude), re-anchored to
advance the frontier when a new descendant is admitted (with a one-shot
freshness boost so the ladder climbs one rung per order), and dropped when a
finding terminates the lineage (the boundary was reached). Integer
priorities only; all ties break deterministically (entry ID order).

## 14. Tapes, precedents, boundaries, influence

* `RunTape` (`tape/model.rs`): immutable, content-addressed, with build and
  environment digests, the exact candidate (or its coordinate), the
  scheduler mode, the recorded observation, termination status, lineage
  context, and source (seed/finding/admission/boundary/replay). Written at
  durable boundaries only: seeds, findings, residual admissions, boundary
  witnesses. The deterministic contract is `same valid tape -> same frf-fuzz
  structural interpretation` (the interpretation is a pure function of the
  recorded fields); `tape/replay.rs` additionally checks that a live
  re-execution reproduces the recorded observation, and a divergence is
  PRESERVED as instability (I10) — never resolved by overwriting.
* Precedent bank (Phase 3; `precedent/{mod,model,matching,probe,admission}`):
  durable, revisioned, content-addressed trajectories
  (`Family::Precedent`, 0x05) with structural prefix, context predicates,
  known continuations, counterexamples, confusers, discriminating probes,
  FRF receipt IDs, Gemel IDs, provenance. Every precedent carries >= 1
  falsifiable experimental relationship. Matching is deterministic shape-
  subsumption inside a lead window (`precedent/matching.rs`); falsifiable
  probe recipes yield Support / Contradict / Ambiguous (`precedent/probe.rs`)
  — the first support confirms a Candidate, and a direct contradiction (or
  three partials) flips the status to Contradicted. Admission happens only
  from real terminal observations (`precedent/admission.rs`); contradictions
  are never deleted (I10), and contradicted precedents are never scheduled
  again.
* Boundary witnesses (`boundary/`): passing/failing pairs are first-class
  objects (`BoundaryWitness` with the preserved relation and verification
  status); `minimize.rs` implements deterministic two-sided minimization
  (greedy coordinate descent + length trimming, byte index ascending, left
  before right) shrinking the distance while preserving the distinction.
  `frf-fuzz boundary <finding-id>` forms the stable/crash pair of a finding
  vs its corpus parent, minimizes it, and persists the verified witness +
  tapes.
* InfluenceSketch (Phase 2.5+): hierarchical perturbation (mutate chunk ->
  observe -> retain -> subdivide). Explicitly NOT sound taint analysis; false
  positives/negatives documented.

## 15. FRF bridge (Phase 4, implemented in 0.4.0)

frf-fuzz findings are hypotheses, never FRF claims/receipts. On promotion
with a configured authority: build the exact FRF court question (authority,
candidate, fixture, observable axes), invoke the `frf` library in-process,
retain the real run/receipt/claim IDs verbatim (opaque, FRF's namespace).

Implementation (`src/frf_bridge.rs`):

- `Family::FindingVerification` (0x0F) objects are durable verification
  records: finding id + authority name/version + outcome + FRF run/receipt/
  claim ids + a deterministic bounded note. Absence of a record = derived
  `Unverified` (never fabricated).
- The court is run through `frf::commands::court::run_once` with
  `reuse = true`, so identical evidence is captured once and reused (FRF
  immutability); the working directory is pinned to the FRF store root for
  the duration so the capture's environment identity (which records cwd) is
  stable. The manifest is emitted by a strict YAML writer (no serde in
  frf-fuzz) validated in tests against FRF's own parser.
- **A crash finding is `Verified` only when the court observed at least one
  residual divergence** (candidate differed from the reference over the
  declared observables). FRF also emits receipts for parity runs (zero
  residuals); those classify the finding as `Failed` — the crash did not
  reproduce as a differential — and the parity receipt is PRESERVED as
  evidence of that non-reproduction (I10).
- FRF refusal (court refused, receipt refused, claim blocked) is a `Failed`
  record with the reason; never deleted or downgraded. Claim compilation is
  an explicit opt-in (`--claim` / `--verify-claim`): residuals are disposed
  `Intentional` (a non-blocking closure) and a baseline claim is compiled.
- The FRF store lives at `<store-root>/frf-root/` and is the source of
  truth for FRF IDs (level-2 durable boundary writes only).
- In campaigns, `run --authority <path>` auto-verifies each replay-confirmed
  crash finding at promotion (Level 2) with a per-campaign input dedup so a
  crash flood never re-runs the same court per duplicate input. The
  verification candidate is the fuzz-target binary itself (its single-shot
  `--frf-fuzz-fixture` fixture mode, see `target_runtime::fixture`); ASan
  campaigns should point `--verify-candidate` at a non-ASan build.
- `frf-fuzz verify <finding-id>` verifies an existing finding standalone
  (idempotent: same binary + authority + question converge on one record).

## 16. Gemel bridge (Phase 4, implemented in 0.4.0)

Gemel is longitudinal memory. No `.gemel` repo => standalone mode (verified:
`Repo::find` -> `NotARepository`); with a repo, the fuzz loop is read-only
w.r.t. Gemel (I5) and durable boundaries publish at Level 3.

Implementation (`src/gemel_bridge.rs`):

- `Family::GemelBoundary` (0x10) objects record every durable boundary: kind
  (campaign created/completed, finding verified, precedent admitted,
  falsified precedent), the frf-fuzz subject id, the Gemel source-state
  snapshot (head-state/change/intent/trajectory/producer Gids, verbatim),
  the published outcome Gids, and a deterministic failure class when the
  Gemel-side publication failed — failures are observable and never fatal
  (I14).
- Campaign creation/completion publish Gemel checkpoints
  (`workflow::create_checkpoint`). An FRF-verified finding publishes an
  `Evidence` (kind `court_receipt`) bound to the current state Gid (field
  0x11) plus a `Claim`; a promoted precedent publishes an `Evidence` (kind
  `fuzz_result`); a falsified precedent publishes a `Residual`
  (classification `expected_mismatch`) — negative knowledge, never deleted
  (I10). No head state => the record says `no-head-state`; no fabricated
  binding.
- `frf-fuzz revision replay <tape-or-finding-id> --state <label>=<binary>`
  replays one tape's exact candidate through per-state artifacts and
  persists `Family::RevisionResidual` (0x11) pairs: the tape id, both
  artifact digests (BLAKE3 of the exact binaries), both environment
  digests, both termination statuses, and both signal observations; the
  typed residual R_V is derived at decode time ([`RevisionResidual::of`]).

## 17. GPU (Phase 7, implemented)

`gpu/` ships the batch-compute architecture: [`ComputeBackend`](crate::gpu::ComputeBackend)
with five batch operations — `generate_mutation_plans`, `morphology_distance`,
`precedent_rank`, `influence_masks`, `compact_descriptors` — plus backend
resolution ([`resolve`](crate::gpu::resolve)/[`probe`](crate::gpu::probe)).
CPU is the semantic oracle ([`CpuBackend`](crate::gpu::CpuBackend), always
available, normative). GPU output is proposal/ranking evidence only (I8).
All kernels are integer-only and bounded; empty batches are valid
(empty in -> empty out); every output is deterministic and repeated-run
tested.

Device backends are NOT admitted yet: CubeCL (one kernel -> CUDA + HIP/ROCm)
remains the preferred route but its admission gates (CPU == CUDA == ROCm
bit-for-bit, repeated device determinism, acceptable compile/startup cost,
measured speedup on realistic batch sizes) can only be verified on real
hardware, which this development machine does not have (doctor records the
toolchain state; `cuda`/`rocm` features stay dependency-free and reserved,
I15). cudarc/rocmrc remain the documented fallback adapters. No MSRV raise,
no per-input kernels; when an accelerator is admitted, workloads stay
batched with the CPU kernels above as the equality reference.

## 18. Module layout

See `src/lib.rs` for the current tree. Ungated modules (shared with the
instrumented target): `error`, `canon`, `mutation/{mod,prng,coordinate,
bytes,integer,splice,dictionary,cmp,influence}`, `simd/{mod,scalar,
x86_avx2}`, `scheduler/work_order`, `execute/{protocol,crash_ledger}`,
`target_runtime/{sancov,cmp,signals,target,worker,fixture}`.
Coordinator-gated: `id`, `store/{object,refs,fsck}`, `corpus/{entry,
admission,minimize}`, `observe/{frame,residual,signals,sketch}`,
`dsfb/{regime,morphology,debug_bridge,fuzz_bank}`,
`precedent/{mod,model,matching,probe,admission}`, `scheduler/policy`,
`execute/{finding,worker_process,coordinator}`, `boundary/{witness,
minimize}`, `tape/{model,replay,revision}`, `gpu/{backend,cpu}`,
`frf_bridge`, `gemel_bridge`, `experiment/{mod,stats}` (Phase 8),
`report`, `cli`, `bin/{frf-fuzz,cargo-frf-fuzz}`.
`dsfb/database_bridge` (Phase 6) is compiled only when the `database`
feature is enabled; it is the sole frf-fuzz module that links
`dsfb-database`.

`bin/frf-fuzz.rs` and `bin/cargo-frf-fuzz.rs` are thin argv adapters to
`frf_fuzz::cli` — no duplicated command logic.

`execute/coordinator.rs` keeps one per-root DSFB substrate per campaign
(`CampaignState::root_dsfb`) plus the verdict/episode and probe counters.
Phase 4 families: `canon::Family::{FindingVerification=0x0F,
GemelBoundary=0x10, RevisionResidual=0x11}`; `report` counts them, `fsck`
validates their links (verification records -> findings with FRF-id shape
checks; gemel boundaries -> their subjects + published-Gid presence;
revision pairs -> their tapes), and `inspect` decodes all three. The CLI has
`verify` and `revision replay`; `run` takes `--authority*`,
`--verify-candidate`, `--verify-claim`, `--question-id`,
`--fixture-family`, `--cmp on|off` (Phase 8, default on), and
`--gemel on|off`. `experiment` (Phase 8) takes a target plus `--arms`,
`--trials`, `--max-time`/`--max-execs`, `--out`, and `--json` (§22).

## 19. Performance contract (Phase-1 hot path targets)

After warmup: no heap allocation per ordinary execution, no filesystem I/O,
no FRF call, no Gemel write, no full input hash for rejected candidates, no
full detector field, no GPU launch; bounded compare/event buffers;
preallocated mutation buffers; deterministic backpressure. Hash only on
admit/promote/persist. Batch aggressively.

## 20. Backpressure

All channels bounded. When a downstream queue fills: skip low-value deep
analysis, retain compact candidate metadata, keep fuzzing — never block
workers indefinitely on slow FRF/disk/reporting. Crash findings exert
stronger backpressure than ordinary candidates.

## 21. Security posture

Hostile: target output, corpus, stored objects, tapes, config, worker frames,
FRF evidence, Gemel data, dictionaries. No shell string construction
(`Command` + argv); every length bounded before allocation; checked
arithmetic; target timeouts; Unix memory limits; target output never rendered
uninterpreted. See `THREAT_MODEL.md`.

## 22. Experiment instrument (Phase 8, implemented)

`frf-fuzz experiment` (`src/experiment/{mod,stats}.rs`, coordinator feature)
runs the ablation ladder of `EXPERIMENT_PROTOCOL.md` §2 as repeated
independent trials. The design stays two-plane-compliant: every trial is a
fresh store with a deterministic per-trial seed (splitmix64 over the base
seed + trial; arms share the seed schedule, so trials differ only in their
feedback channels), and comparison uses per-trial summaries plus the
exported raw series — no per-execution observation is elevated to the
evidence plane.

The arms are frozen deltas over the campaign's three feedback switches:
`cov` (cmp off, residual off, precedent off) -> `cov+cmp` -> `residual` ->
`full` (protocol ladder rungs 1-5). The new `--cmp on|off` switch (on
`run`, default on) gates const-compare dictionary seeding, the
dictionary/compare mutation families — excluded from the Explore rotation
via `MutatorId::WITHOUT_CMP_GUIDED` when off — and worker-side cmp-ring
collection (env `FRF_FUZZ_CMP`). Residual-off campaigns additionally keep
no morphology objects and count no state features (morphology persistence
and state-feature insertion are residual-gated in the coordinator admission
path), so regime/lineage/amplify machinery observes nothing: the `cov` arm
is semantically coverage-only, not a scheduler-degenerate residual build.

Budgets are mandatory (`--max-time` / `--max-execs`): trials are
right-censored by design. Raw series export to
`<out>/<expid>/<ts>/series.csv` (default out root
`<root>/.frf-fuzz/experiments`) with the protocol §3 metadata in `#`
comment lines, plus `analysis.txt` and `meta.json` (human and `--json`
output). The export is the recomputation authority: statistics
(median/quartiles, Vargha-Delaney A12, Mann-Whitney U two-sided) recompute
from the raw series, and the CLI never bakes an unsupported claim (I11).
Censored first-failure trials export `NA` rows and report found/censored
per arm; arm-pair A12/Mann-Whitney U on censored metrics compares only the
labeled complete-case subset. `experiment::held_out_split(defect_ids,
blind_fraction, seed)` derives the deterministic development/blind
partition for the protocol §4 benchmark-leakage control.

Where it lives: `src/experiment/` (stats dependency-free), the
`experiment` CLI subcommand, `scripts/phase8_ablation_demo.sh` (golden-demo
target built on the pinned nightly; asserts the trajectory negative control,
retention, and export authority), `scripts/baseline_compare.sh`
(cargo-fuzz/libFuzzer baseline of the same gates; AFL++ recorded skip when
absent), and `tests/phase8_experiment.rs` (export -> import -> recompute,
censoring survival, held-out disjointness, identical-arms negative control).
