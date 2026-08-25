# DSFB Integration Design (Phase 3)

Verified against `dsfb-debug 0.1.0` and `dsfb-database 0.1.1` source
(`.phase0/forensics/REPORT-dsfb-debug-0.1.0.md`,
`.phase0/forensics/REPORT-dsfb-database-0.1.1.md`). This document fixes the
integration contract; Phase 3 implements it.

## DSFB-Debug: structural substrate

Dependency: `dsfb-debug = { version = "=0.1.0", default-features = false,
features = ["std"] }` — zero transitive deps (verified from its lockfile).
`std` is required for the detector field and fusion layer; the no_std core
(residual/sign/grammar/policy/episode) is available without it.

### Level split (matches the escalation ladder)

- **Level 0/1 (cheap, per interesting execution)**: the structural engine
  without detectors — `sign::compute_sign_tuple`, `sign::drift_persistence`,
  `grammar::evaluate_raw_grammar`, `grammar::hysteresis_confirm`,
  `policy::apply_policy`. This is the no_std path.
- **Level 1 full (promoted executions)**: `fusion::run_fusion_evaluation`
  with `FusionConfig::ALL_DEFAULT` (205 detectors, `min_consensus = 3`) or a
  subset via `detector_weight_overrides` (weight 0 removes a detector).
  Cheaper tier: `FusionConfig::ALL_FOUR_DEFAULT` (scalar + cusum + ewma +
  dsfb_structural). NOTE: `run_fusion_evaluation` runs the field twice
  (replay self-check); if that 2x cost is unacceptable, call the individual
  `incumbent_baselines::*` functions directly (all pub, uniform shape) and
  read the thread-local `LAST_WIN_ALERTS` immediately after each call, same
  thread.

### Unknown handling (the load-bearing discipline)

- `SemanticDisposition::Unknown` is first-class and every anti-hallucination
  gate (margin, confuser-boundary, tier-witness, named-witness) passes it
  through untouched.
- Structured vs trivial Unknown is read from companion fields: structured =
  episode-level `matched_motif == Unknown` with `policy_state >= Review`
  (and `confirmed_grammar_state >= Boundary` cells); trivial = Admissible +
  Silent + no episode.
- frf-fuzz NEVER calls a nearest-label classifier on Unknown (I6).

### Integer identity

DSFB-Debug's canonical outputs are f64; frf-fuzz derives its integer
morphology identity from the enums/masks (`GrammarState`, `ReasonCode`,
`PolicyState`, tier masks), never from the f64 values.

### Gotchas

- `LAST_WIN_ALERTS` is thread-local and must be read immediately after the
  detector call on the same thread.
- BTreeMap only — no HashMap iteration-order hazards.
- `run_evaluation` caps at 8192 cells; batch sizes must respect that.

## FuzzSemanticBank (frf-fuzz-owned)

frf-fuzz implements its own fuzz-specific semantic bank rather than reusing
DSFB-Debug's production-debugging motif names:

- Candidate structural classes (descriptions, not causes):
  ComparisonConvergence, ResidualLocalization, AllocationCreep,
  StateDepthExpansion, ParserStateInstability, OutputTopologyShift,
  ErrorVariantMigration, RetryEscalation, ScheduleSensitivity,
  BoundaryGrazing, AbruptBehavioralSlew, PersistentBehavioralDrift,
  CrossSignalPropagation.
- Every named fuzz motif requires: reason-code/grammar prerequisites,
  required detector/witness families, context predicates, confusers,
  deterministic thresholds/bins, provenance, recommended experiment
  families, and refusal conditions.
- The bank reuses DSFB-Debug's deterministic tie-break discipline (provenance
  rank, then lower index) and gate structure (zero-tier filter, witness-tier
  gate, margin gate, confuser gate, named-witness gate) with its own motif
  table.
- `Structured + Unknown` remains a valid terminal state throughout.

## DSFB-Database: the architectural lesson only

Dependency: `dsfb-database = { version = "=0.1.1", default-features = false }`
behind the `database` feature, used ONLY for real database telemetry targets.

The generic `RegimeObserver` (Phase 2, in frf-fuzz) reimplements the
DSFB-Database state machine with its own types and its own documentation:

- instantaneous residual = raw sample
- smoothed residual = `s_k = rho*s_{k-1} + (1-rho)*|r_k|`
- envelope: `|instant| >= slew -> Boundary; |ema| >= drift -> Drift; else
  Stable`
- states: `Stable | InEpisode{t_open} | Recovering{t_open, t_recover_start}`
- deterministic close: emit when recovery holds for `min_dwell`; end-of-
  stream flush with dwell guard
- sample-time is caller-supplied logical time (never wall clock);
  channels sorted; episodes sorted by t_start with `partial_cmp
  .unwrap_or(Ordering::Equal)`.

### Type-level refusal (I7)

- `ResidualClass` is a closed 5-variant SQL enum with no generic variant;
  constructing a `ResidualSample` requires choosing one of the five.
- frf-fuzz defines NO conversion between its fuzz residual types and
  `ResidualClass`; the generic fuzz core has no dependency on dsfb-database,
  so the two types cannot meet in generic code.
- In the `database` integration, `ResidualClass` is constructed only through
  the crate's SQL-semantics constructors (`push_latency`, `push_plan_change`,
  `push_wait`, `push_chain_depth`, `push_hit_ratio`, `push_io_amplification`,
  `push_jsd`).
- Enforcement test (Phase 6): a compile-fail / non-conversion lock, mirroring
  the crate's own `non_claim_lock.rs` discipline.

### Tape lesson

The crate's deterministic tape (`live/tape.rs`) is trapped behind
`live-postgres` (tokio+postgres). frf-fuzz reimplements the
JSONL + sidecar-hash + verify-on-load design locally (Phase 2 `tape/`),
including the asymmetry: `tape -> episodes` is byte-stable; `engine -> tape`
is not.
