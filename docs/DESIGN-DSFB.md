# DSFB Integration Design (Phase 3)

Status: **implemented** — Phase 3 shipped the design below in
`dsfb/debug_bridge.rs`, `dsfb/fuzz_bank.rs`, `scheduler/policy.rs`, and
`precedent/` (see `ROADMAP.md`). Verified against `dsfb-debug 0.1.0` and
`dsfb-database 0.1.1` source
(`.phase0/forensics/REPORT-dsfb-debug-0.1.0.md`,
`.phase0/forensics/REPORT-dsfb-database-0.1.1.md`). This document fixed the
integration contract; the implemented deviations are recorded inline below.

## DSFB-Debug: structural substrate

Dependency: `dsfb-debug = { version = "=0.1.0", default-features = false,
features = ["std"] }` — zero transitive deps (verified from its lockfile).
`std` is required for the detector field and fusion layer; the no_std core
(residual/sign/grammar/policy/episode) is available without it.

### Level split (matches the escalation ladder)

- **Level 0/1 (cheap, per interesting execution)**: the structural engine
  without detectors — `sign::compute_sign_tuple`, `sign::drift_persistence`,
  `grammar::evaluate_raw_grammar`, `grammar::hysteresis_confirm`,
  `dsa::compute_dsa_score`, `dsa::consistency_gate`, `policy::apply_policy`.
  This is the no_std path, and the one Phase 3 implemented:
  `dsfb/debug_bridge.rs` runs exactly this chain per admitted edge with
  `SemanticDisposition::Unknown` only (I6), so DSFB's `Review` means
  "structure present but unnamed".
- **Level 1 full (promoted executions; NOT implemented)**: the design
  offered `fusion::run_fusion_evaluation` with `FusionConfig::ALL_DEFAULT`
  (205 detectors, `min_consensus = 3`) or a subset via
  `detector_weight_overrides` (weight 0 removes a detector). Cheaper tier:
  `FusionConfig::ALL_FOUR_DEFAULT` (scalar + cusum + ewma + dsfb_structural).
  NOTE: `run_fusion_evaluation` runs the field twice (replay self-check);
  if that 2x cost is unacceptable, call the individual
  `incumbent_baselines::*` functions directly (all pub, uniform shape) and
  read the thread-local `LAST_WIN_ALERTS` immediately after each call, same
  thread. Phase 3 calls the free functions directly and bypasses DSFB-
  Debug's `evaluate_signal` bank lookup, so production-debugging motif
  names never appear (I6).

### Implemented substrate (Phase 3 deviations)

- One `LineageSubstrate` per ROOT: all mutator families of a root share one
  admitted-edge behavioral stream (admission order). The per-(root,
  mutator) variant was a Phase-3 finding and was dropped — fragmented
  streams never calibrated an envelope.
- Declared calibration law: the first `calibration_windows` (8) axis
  windows fix the axis mean and rho = max(3 sigma, 2 * span), so values
  inside the already-observed span can never be misread as structural.
- An axis whose calibration segment never moves is a discrete/step axis:
  envelope grammar is unavailable (`calibrated = false`), verdicts stay
  Silent, and frf-fuzz's discrete state-change classes interpret it
  instead — DSFB never hallucinates envelope violations on step axes.
- Boundary density is real: computed over the recent raw-grammar ring
  (`drift_window` windows) and fed to `dsa::compute_dsa_score`. DSFB-
  Debug's own `evaluate_signal` hardcodes boundary density 0.0 there, with
  a comment; the free-function chain does not.
- Axis verdicts are integer-only (enum codes, direction class, magnitude
  bucket; no f64 in canonical payloads). They are durable per structural
  edge as `Family::StructuralVerdict` (0x0D); closed structural episodes
  persist as `Family::StructuralEpisode` (0x0E).

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

## FuzzSemanticBank (frf-fuzz-owned; implemented in `dsfb/fuzz_bank.rs`)

frf-fuzz implements its own fuzz-specific semantic bank rather than reusing
DSFB-Debug's production-debugging motif names. The implemented bank
classifies substrate axis verdicts plus the morphology signature from
deterministic integer evidence (no floats, no probabilities):

- Named structural classes (descriptions, not causes; the 13 shipped
  classes): ComparisonConvergence, ResidualLocalization, AllocationCreep,
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
- Scoring is deterministic integer + specificity tier, with an ambiguity
  guard: a same-score same-tier rival keeps the result `Structured +
  Unknown` instead of picking an arbitrary winner.
- Axis roles are assigned from the registered signal schema (name/unit
  keywords, `role_of`); a class whose context predicate demands a role
  refuses when the involved axes carry no declared role.
- `Structured + Unknown` remains a valid terminal state throughout.

## Precedent probes (implemented, Phase 3)

Precedent semantics shipped in `precedent/` (`model`, `matching`, `probe`,
`admission`); see `ARCHITECTURE.md` §14 for the durable object.

- Matching is deterministic shape-subsumption inside a lead window: the live
  signature must carry every profile axis with the same direction, agree on
  the comparison-convergence / state-change classes, and belong to the same
  mutator family, at a depth past the profile but inside the lead window.
- Falsifiable probe recipes evaluate to Support / Contradict / Ambiguous; a
  direct contradiction (the axis never moved at all) flips the precedent's
  status, and so do three partial contradictions.
- The first support confirms a Candidate; contradicted precedents are never
  scheduled again and are never deleted (I10).
- Admission happens only from real terminal observations; nothing is
  admitted from interpretation alone.
- Matched lineages are scheduled as DISCRIMINATE (the precedent declares a
  confuser) or FALSIFY (no confuser) probe batches through the bounded
  probe queue (`scheduler/policy.rs`).

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
