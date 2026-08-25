# frf-fuzz Experiment Protocol

This is the scientific discipline of the project. frf-fuzz is an experimental
instrument whose claims must survive falsification; this document fixes the
methodology for every evaluation claim it may ever make. Phase 0 records the
verification evidence for the fundamental assumptions; later phases fill in
the ablation and benchmark tables under this protocol.

## 0. Epistemic boundary (fixed)

frf-fuzz prediction is exactly:

> A current deterministic structural trajectory shares a declared prefix with
> one or more historical evidence-backed trajectories, and those historical
> trajectories imply one or more falsifiable next experiments.

It is NOT a guarantee of future failure, causal attribution, a probability of
vulnerability, or proof from pattern similarity. The system's usefulness is
measured by whether it chooses BETTER NEXT EXPERIMENTS — that is the core
scientific claim to test, and nothing else is claimed.

## 1. Phase-0 verification record (this phase)

The following were verified empirically during Phase 0; the evidence and
commands are in `PHASE0_FINDINGS.md` and `COMPATIBILITY.md`.

| Assumption | Verdict | Evidence |
|---|---|---|
| `-Cpasses=sancov-module` instruments on LLVM 20..22 | PASS | probe on 8 nightlies |
| `-Cpasses=sancov` (old name) is dead | CONFIRMED | "unknown pass name" on all |
| `__sanitizer_` name exclusion exists on LLVM >= 18 | REFUTED | removed in LLVM 18 |
| trace-cmp callbacks fire in an instrumented build | PASS | probe + sancov_demo |
| scanner self-contamination is a constant, calibratable footprint | PASS | footprint stability + masking |
| masked coverage delta is input-discriminating | PASS | sancov_demo |
| ASan + trace-compares + Rust callbacks coexist | REFUTED | recursion, cause isolated |
| `-Clto=off` via RUSTFLAGS overrides profile `lto = true` | PASS | flag-order verified |
| fat LTO + sancov can fail to link | CONFIRMED | `__sancov_gen_*` undefined |
| `--target` keeps proc-macro crates uninstrumented | PASS | clap builds with ASan flags |
| Philox4x32-10 KAT vectors | PASS | official Random123 vectors |
| same coordinate -> same mutation across processes | PASS | `tests/mutation_determinism.rs` |
| crash ledger reconstructs exact coordinate | PASS | `tests/crash_recovery.rs` |
| scalar == AVX2 bit-for-bit | PASS | property tests, sizes 0..4097 |
| IPC batching beats per-input framing | PASS | ipc_bench: 4.4x..7.3x |
| MSRV 1.85 matrix (default + target-runtime) | PASS | `cargo +1.85.0 test` |
| whole feature matrix compiles on 1.85 | PASS | coordinator build + tests |

## 2. Mandatory ablations (Phase 8)

Never publish a performance or effectiveness conclusion from one run or one
configuration. The ablation ladder (each step ADDs one feedback channel):

1. coverage only
2. coverage + cmp
3. coverage + cmp + residual sketch
4. coverage + residual + DSFB structural analysis
5. + precedent scheduling
6. + Gemel revision memory
7. + AVX2
8. + GPU
9. full system

Baselines where practical: cargo-fuzz / libFuzzer, AFL++, and any relevant
modern fuzzer available in the environment. Baselines must be built from
their pinned/current upstream with documented versions.

## 3. Benchmark hygiene

For every experiment record (this is the required metadata set):

* seeds (exact seed corpus identity + RNG seeds)
* build identities (rustc/LLVM for coordinator AND instrumented target,
  feature sets, flag sets — the campaign metadata must be self-contained)
* CPU model, core count, clock governor if controllable
* GPU model + driver (GPU trials only)
* OS/kernel version
* toolchain identity (pinned nightly + stable)
* campaign config (scheduling classes and weights, corpus bounds, timeouts)
* corpus origin (from seeds, from previous campaigns, held-out separation)
* dictionary (if any; content hash)
* time budget and trial number

Metrics (per trial, logged as time series, not just endpoints):

* executions/sec
* time and executions to first failure
* time to first FRF-verified residual (when an authority is configured)
* unique verified residual lineages
* coverage (edges) and unique state features
* unique morphology signatures
* structured-Unknown yield
* precursor lead executions and lead time (precursor detection -> failure)
* false precursor rate, falsification rate, promotion acceptance rate
* corpus size, CPU overhead, memory overhead
* GPU transfer/kernel time and speedup (GPU trials)

Publication-grade comparison uses repeated independent trials (FuzzBench-style
practice: ~20 trials / 24h per configuration in the reference methodology).
Report medians, dispersion/confidence intervals, Vargha-Delaney A12, and
Mann-Whitney U. Export formats must preserve the raw time series so these
statistics can be recomputed; the CLI never bakes unsupported statistical
claims into its output (it reports raw facts; analysis is the analyst's job).

## 4. Benchmark leakage controls

* Held-out defects: a historical failure used to CREATE a precursor
  signature must never also be used as a blind test of prediction. Precursor
  bank construction and blind evaluation use disjoint defect sets; the
  partition is recorded.
* Seed hygiene: seeds derived from the target's own test suite are recorded
  as such and treated separately from independent seeds.
* Configuration leakage: hyperparameters (thresholds, weights) tuned on a
  development split are frozen before evaluation; the frozen values are
  recorded.
* No mid-campaign changes: an evaluation campaign's config is immutable once
  started; `frf-fuzz fsck` and campaign records make this auditable.

## 5. Negative controls (required, Phase 2+)

Residual systems can hallucinate structure in noise. Mandatory controls:

* shuffled execution order (same observations, random order — any "trajectory"
  must vanish)
* randomized unrelated residual channel (a synthetic noise channel must not
  produce regimes)
* stable/noise-only target (the demo target's known-benign paths must never
  yield motifs)
* repeated known-benign corpus (run twice; regimes must be identical or
  absent)
* threshold elasticity (a motif that collapses under tiny parameter movement
  is not strong evidence)
* replay perturbation (replay the same tape with unrelated ambient changes;
  the interpretation must be stable)
* precedent confuser challenges (a confuser signature must be
  distinguishable by its discriminating probe)

Failure to reproduce is PRESERVED, not discarded.

## 6. The golden demonstration target (Phase 1 acceptance; spec §34)

The demo target (executable, one command) must contain:

* Path A: new coverage leads to ordinary coverage discovery.
* Path B: multiple inputs execute the SAME relevant coverage while a
  target-defined signal changes gradually; a residual becomes persistent; a
  boundary is approached; eventually a terminal failure/divergence. The
  coverage-only scheduler has no special signal during the early Path-B
  trajectory; the residual scheduler detects and retains the precursor.
* A compare/magic-value gate proving cmp-guided substitution works.

The one-command demonstration is wired in Phase 1 (`cargo frf-fuzz run demo`).

## 7. Determinism protocol

* Same coordinate + same parent -> same mutation: verified across process
  runs (Phase 0).
* Same valid tape -> same structural interpretation: verified in Phase 2.
* Live observation vs replay disagreement: preserve BOTH and report
  instability (never silently prefer one).
* GPU vs CPU disagreement: CPU wins; the GPU backend is quarantined.

## 8. FRF/Gemel experimental roles

* FRF is the authority layer: a promoted differential finding is
  court-verified and linked by its real FRF evidence ID (Phase 4 acceptance
  item 15); without an authority, the same finding is explicitly
  `Unverified`, never fabricated (item 16).
* Gemel: revision studies replay identical tapes across Gemel states,
  yielding revision residuals; a branch of development is a controlled
  experiment; failed branches/fixes are negative knowledge.

## 9. Reporting rules

* Never publish performance conclusions from a single run.
* Every reported number carries its trial count, environment, and campaign
  metadata reference.
* Statistical analysis is reproducible from the exported raw series.
* Claims are phrased in the fixed epistemic vocabulary
  (`NON_CLAIMS.md`); probabilistic phrasing is prohibited (I11).
