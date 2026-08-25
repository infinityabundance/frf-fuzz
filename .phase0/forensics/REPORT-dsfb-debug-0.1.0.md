# Forensic API Report — `dsfb-debug` v0.1.0

Source inspected: `/mnt/1tb_kingston/frf-fuzz/.phase0/forensics/dsfb-debug-0.1.0/` (extracted crate root).
All citations are `file:line` into that tree. Facts only — nothing from docs.rs or memory.

---

## 1. Package facts

### Manifest (`Cargo.toml`, normalized) and original (`Cargo.toml.orig`)

| Field | Value | Source |
|---|---|---|
| name | `dsfb-debug` | `Cargo.toml:15` |
| version | `0.1.0` | `Cargo.toml:16` |
| edition | `2021` | `Cargo.toml:13` |
| rust-version (MSRV) | `1.75.0` | `Cargo.toml:14` |
| license | `Apache-2.0` | `Cargo.toml:63` |
| authors | `Riaan de Beer <riaan@invariantforge.net>` | `Cargo.toml:17` |
| repository | `https://github.com/infinityabundance/dsfb` | `Cargo.toml:64` |
| description | "DSFB-Debug — Structural Semiotics Engine for Software Debugging. A deterministic, read-only, observer-only augmentation layer…" | `Cargo.toml:44-49` |
| toolchain pin | `rust-toolchain.toml:10-12` — `channel = "1.75.0"`, components `clippy`, `rustfmt` | `rust-toolchain.toml` |

### Dependencies (`Cargo.toml:71-88`; original `Cargo.toml.orig:62-68`)

```toml
[dependencies.plotters]
version = "0.3"
features = ["bitmap_backend", "bitmap_encoder", "ttf", "all_series", "all_elements", "full_palette"]
optional = true
default-features = false

[dependencies.zip]
version = "0.6"
features = ["deflate"]
optional = true
default-features = false
```

- **Both dependencies are `optional` and only reachable through the `demo` feature.** The core has **zero required runtime dependencies** (stated `Cargo.toml.orig:63-64`; confirmed by the lockfile — the only `dsfb-debug` dependencies listed are `plotters` and `zip`, `Cargo.lock:163-168`).
- `[dev-dependencies]` is **empty** (`Cargo.toml:90`, `Cargo.toml.orig:75`).
- Lockfile pins: `plotters 0.3.7`, `zip 0.6.6` (`Cargo.lock:454,815`).

### Features (`Cargo.toml:92-101`, original `Cargo.toml.orig:44-60`)

```toml
[features]
default = []
demo = ["std", "paper-lock", "dep:plotters", "dep:zip"]
paper-lock = ["std"]
std = []
```

- `default = []` — **no features on by default; the default build is `no_std` with zero dependencies.**
- `std` — empty feature list (`["std"]`); opts in the std-only adapter layer, `Vec`-based buffers, fusion, audit, render, calibration, incumbent baselines (`lib.rs:95-133`).
- `paper-lock` — implies `std`; gates the real-dataset evaluation API (`real_data` module: `lib.rs:121-122`).
- `demo` — implies `std` + `paper-lock` + `dep:plotters` + `dep:zip`; gates the demo module (`lib.rs:135-136`) and the demo binary.

### `[lib]` config

- **No explicit `[lib]` section** in either manifest — defaults apply (lib name `dsfb_debug`, target `src/lib.rs`).
- The crate is `#![no_std]` (`lib.rs:91`), `#![forbid(unsafe_code)]` (`lib.rs:92`), `#![deny(clippy::unwrap_used)]` (`lib.rs:93`).

### Bins

```toml
[[bin]]
name = "dsfb-debug-demo"
path = "src/bin/dsfb_debug_demo.rs"
required-features = ["demo"]
```
(`Cargo.toml:66-69`, `Cargo.toml.orig:70-73`)

The binary is **physically unbuildable without `--features demo`** (`required-features`). A lib-only build (`cargo build` / `cargo build --features std`) never compiles it.

### Workspace

`Cargo.toml.orig:77-81` contains an **empty `[workspace]`** ("Detached from the parent workspace… so the crate can be built / tested standalone").

---

## 2. Public library surface

### `src/lib.rs` — complete list of public items

Module declarations (in order, `lib.rs:101-136`):

```rust
pub mod types;          // L101
pub mod error;          // L102
pub mod config;         // L103
pub mod residual;       // L104
pub mod sign;           // L105
pub mod envelope;       // L106
pub mod grammar;        // L107
pub mod heuristics_bank;// L108
pub mod dsa;            // L109
pub mod policy;         // L110
pub mod episode;        // L111
pub mod baseline;       // L112
pub mod causality;      // L113
pub mod graph_inference;// L114
pub mod episode_catalog;// L115
#[cfg(feature = "std")] pub mod adapters;            // L119-120
#[cfg(feature = "paper-lock")] pub mod real_data;    // L121-122
#[cfg(feature = "std")] pub mod calibration;         // L123-124
#[cfg(feature = "std")] pub mod incumbent_baselines; // L125-126
#[cfg(feature = "std")] pub mod render;              // L127-128
#[cfg(feature = "std")] pub mod fusion;              // L129-130
#[cfg(feature = "std")] pub mod audit;               // L132-133
#[cfg(feature = "demo")] pub mod demo;               // L135-136
```

Top-level struct (the engine) and its full impl:

```rust
pub struct DsfbDebugEngine<const MAX_SIGNALS: usize, const MAX_MOTIFS: usize> {
    config: EngineConfig,
    heuristics_bank: HeuristicsBank<MAX_MOTIFS>,
}                                                       // lib.rs:157-163

impl<const S: usize, const M: usize> DsfbDebugEngine<S, M> {
    pub fn new(config: EngineConfig) -> Result<Self>                         // L167-173
    pub fn paper_lock() -> Result<Self>                                      // L176-178
    pub fn config(&self) -> &EngineConfig                                    // L181-183
    pub fn heuristics_bank(&self) -> &HeuristicsBank<M>                      // L189-191
    pub fn evaluate_signal(&self, residual_norms: &[f64], k: usize, rho: f64,
        signal_index: u16, window_index: u64, was_imputed: bool,
        recent_raw_states: &[GrammarState], persistence_count: usize)
        -> SignalEvaluation                                                  // L208-218
    pub fn run_evaluation(&self, data: &[f64], num_signals: usize,
        num_windows: usize, fault_labels: &[bool], healthy_window_end: usize,
        eval_out: &mut [SignalEvaluation], episodes_out: &mut [DebugEpisode],
        dataset_name: &'static str) -> Result<(usize, BenchmarkMetrics)>     // L329-339
    pub fn run_evaluation_with_graph(&self, data: &[f64], num_signals: usize,
        num_windows: usize, fault_labels: &[bool], healthy_window_end: usize,
        eval_out: &mut [SignalEvaluation], episodes_out: &mut [DebugEpisode],
        dataset_name: &'static str, service_graph: &[(u16, u16)])
        -> Result<(usize, BenchmarkMetrics)>                                 // L588-599
    pub fn verify_deterministic_replay(&self, data: &[f64], num_signals: usize,
        num_windows: usize, fault_labels: &[bool], healthy_window_end: usize)
        -> Result<bool>                                                      // L619-626
}
impl DsfbDebugEngine<256, 64> {
    pub fn default_size() -> Result<Self>   // = paper_lock(); L697-706
}
```

### Per-module public surface (key items, exact signatures)

**`types`** (`src/types.rs`) — all types are `Copy + Clone + Debug + PartialEq` (no heap):

```rust
pub struct SignTuple { pub norm: f64, pub drift: f64, pub slew: f64 }   // L51-59
impl SignTuple { pub const ZERO: Self = Self { norm: 0.0, drift: 0.0, slew: 0.0 }; } // L61-63

pub enum GrammarState { Admissible = 0, Boundary = 1, Violation = 2 }   // L66-74
pub enum ReasonCode { Admissible, BoundaryApproach, SustainedOutwardDrift,
    AbruptSlewViolation, RecurrentBoundaryGrazing, EnvelopeViolation,
    DriftWithRecovery, SingleCrossing }                                  // L77-95
pub enum PolicyState { Silent = 0, Watch = 1, Review = 2, Escalate = 3 } // L99-109
pub enum MotifClass { /* 32 variants, L118-258 — see §5 */ }            // L117-258
pub enum SemanticDisposition { Named(MotifClass), Unknown }              // L261-267
pub struct MatchConfidence { pub disposition: SemanticDisposition,
    pub top_score: f64, pub runner_up_score: f64, pub runner_up_motif: Option<MotifClass>,
    pub margin: f64, pub tier_consensus_factor: f64, pub confuser_motif: Option<MotifClass>,
    pub confuser_score: f64, pub margin_vs_confuser: f64 }               // L279-311
pub enum Provenance { FrameworkDesign, DatasetObserved, FieldValidated } // L314-322
pub struct HeuristicEntry { /* 23 fields, L338-451 — see §5 */ }
pub struct SignalEvaluation { pub window_index: u64, pub signal_index: u16,
    pub residual_value: f64, pub sign_tuple: SignTuple,
    pub raw_grammar_state: GrammarState, pub confirmed_grammar_state: GrammarState,
    pub reason_code: ReasonCode, pub motif: Option<MotifClass>,
    pub semantic_disposition: SemanticDisposition, pub dsa_score: f64,
    pub policy_state: PolicyState, pub was_imputed: bool,
    pub drift_persistence: f64 }                                         // L455-476
pub enum DriftDirection { Positive, Negative, Oscillatory, None }        // L479-485
pub struct StructuralSignature { pub dominant_drift_direction: DriftDirection,
    pub peak_slew_magnitude: f64, pub duration_windows: u64, pub signal_correlation: f64 } // L488-494
pub struct DebugEpisode { pub episode_id: u32, pub start_window: u64, pub end_window: u64,
    pub peak_grammar_state: GrammarState, pub primary_reason_code: ReasonCode,
    pub matched_motif: SemanticDisposition, pub policy_state: PolicyState,
    pub contributing_signal_count: u16, pub structural_signature: StructuralSignature,
    pub root_cause_signal_index: Option<u16> }                           // L498-514
pub struct AuditRecord { pub event_type: AuditEventType, pub window_index: u64,
    pub signal_index: u16, pub source: AuditSource, pub outcome: PolicyState } // L519-526
pub enum AuditEventType { GrammarStateTransition, EpisodeOpened, EpisodeClosed,
    PolicyEscalation, MotifMatched, EndoductiveUnknown }                 // L528-536
pub enum AuditSource { GrammarEvaluator, EpisodeAggregator, PolicyEngine, HeuristicsBank } // L538-544
pub struct BenchmarkMetrics { pub dataset_name: &'static str, pub total_windows: u64,
    pub total_signals: u16, pub raw_anomaly_count: u64, pub dsfb_episode_count: u64,
    pub rscr: f64, pub episode_precision: f64, pub fault_recall: f64,
    pub investigation_load_raw: u64, pub investigation_load_dsfb: u64,
    pub investigation_load_reduction_pct: f64,
    pub clean_window_false_episode_rate: f64 }                           // L547-565
```

**`error`** (`src/error.rs`):

```rust
pub enum DsfbError { /* 14 variants, all Copy, L29-62:
    DimensionMismatch{expected,got}, BaselineNotEstablished,
    InvalidEnvelopeRadius{signal_index}, WindowOutOfRange{index},
    EpisodeBufferFull, SignalBufferFull, HistoryBufferFull, HeuristicsBankFull,
    InvalidConfig(&'static str), ParseError{record,field},
    InsufficientBaselineData{available,required},
    BufferTooSmall{needed,available}, MissingRealData, HashMismatch */ }
pub type Result<T> = core::result::Result<T, DsfbError>;                 // L97
```

**`config`** (`src/config.rs`): `EngineConfig` (11 fields), `PAPER_LOCK_CONFIG` const, `EngineConfig::validate() -> Result<()>`, `impl Default` (→ `PAPER_LOCK_CONFIG`). See §7.

**`heuristics_bank`** — see §4/§5.

**`episode`** (`src/episode.rs`): `pub fn aggregate_episodes(...) -> usize` (L75-84), `pub fn compute_metrics(...) -> BenchmarkMetrics` (L267-275). See §6.

**`baseline`** (`src/baseline.rs`): `pub fn compute_baseline_mean(healthy_data: &[f64], num_signals: usize, num_windows: usize, mean_out: &mut [f64])` (L38-43); `pub fn compute_baseline_envelope(healthy_data: &[f64], baseline_mean: &[f64], num_signals: usize, num_windows: usize, rho_out: &mut [f64])` (L74-80).

**`envelope`** (`src/envelope.rs`): `pub fn is_admissible(norm: f64, rho: f64) -> bool` (L27-30); `pub fn is_boundary_zone(norm: f64, rho: f64, boundary_fraction: f64) -> bool` (L33-36); `pub fn is_violation(norm: f64, rho: f64) -> bool` (L39-42); `pub fn compute_envelope_radius(healthy_residuals: &[f64]) -> f64` (L51-52); `pub fn sqrt_approx_pub(x: f64) -> f64` (L86-89).

**`residual`** (`src/residual.rs`): `pub fn compute_residuals(observation: &[f64], baseline: &[f64], missing_mask: &[bool], output: &mut [f64]) -> Result<()>` (L35-41); `pub fn residual_norm(r: f64) -> f64` (L65-68).

**`sign`** (`src/sign.rs`): `pub fn compute_sign_tuple(norms: &[f64], k: usize) -> SignTuple` (L35-36); `pub fn drift_persistence(norms: &[f64], k: usize, window: usize) -> f64` (L62-63); `pub fn boundary_density(states: &[u8], k: usize, window: usize) -> f64` (L84-85); `pub fn slew_density(norms: &[f64], k: usize, window: usize, delta_s: f64) -> f64` (L104-105).

**`grammar`** (`src/grammar.rs`): `pub fn evaluate_raw_grammar(sign: &SignTuple, rho: f64, config: &EngineConfig, drift_persistence: f64) -> (GrammarState, ReasonCode)` (L32-38); `pub fn hysteresis_confirm(recent_raw_states: &[GrammarState], n_confirm: usize) -> GrammarState` (L70-74).

**`dsa`** (`src/dsa.rs`): `pub fn compute_dsa_score(boundary_density: f64, drift_persistence: f64, slew_density: f64) -> f64` (L25-30); `pub fn consistency_gate(dsa_score: f64, tau: f64) -> bool` (L37-39).

**`policy`** (`src/policy.rs`): `pub fn apply_policy(confirmed_grammar: GrammarState, dsa_score: f64, consistency_gate_passed: bool, semantic: SemanticDisposition, persistence_count: usize, persistence_threshold: usize) -> PolicyState` (L30-38).

**`causality`** (`src/causality.rs`): `pub fn attribute_root_causes(episodes_out: &mut [DebugEpisode], episode_count: usize, eval_out: &[SignalEvaluation], num_signals: usize, num_windows: usize, service_graph: &[(u16, u16)], slew_delta: f64)` (L53-61).

**`graph_inference`** (`src/graph_inference.rs`): `pub struct ServiceEdge { pub parent: u16, pub child: u16 }` (L44-48); `pub fn infer_service_graph_from_observed(observed: &[ServiceEdge], num_services: usize, out_edges: &mut [(u16, u16)]) -> usize` (L63-67); `pub fn tarjan_scc(edges: &[(u16, u16)], num_services: usize, scc_id_out: &mut [u16]) -> usize` (L125-129).

**`episode_catalog`** (`src/episode_catalog.rs`): `pub struct EpisodeCatalog<const N: usize>` (L42-46) with `new()`, `record(&mut self, ep: DebugEpisode)`, `total_recorded() -> u64`, `len()`, `is_empty()`, `find_similar(&self, query: &DebugEpisode) -> Option<SimilarEpisode>` (L63-129); `pub struct SimilarEpisode { catalog_index: usize, past_episode: DebugEpisode, similarity: f64 }` (L49-61).

**std-gated modules** (absent from `no_std` build):

- `adapters` (`src/adapters/mod.rs:33-36`): `pub mod sha256; pub mod residual_projection; pub use residual_projection::{parse_residual_projection, OwnedResidualMatrix};`
- `adapters::residual_projection` (`src/adapters/residual_projection.rs`): `pub struct OwnedResidualMatrix { data: Vec<f64>, num_signals: usize, num_windows: usize, healthy_window_end: usize, fault_labels: Vec<bool>, is_sentinel: bool, header_provenance: String, channels: Vec<String> }` (L69-93); `pub fn parse_residual_projection(bytes: &[u8]) -> Result<OwnedResidualMatrix>` (L95).
- `adapters::sha256`: `pub fn sha256(data: &[u8]) -> [u8; 32]` (L52); `pub fn sha256_hex(data: &[u8]) -> [u8; 64]` (L137).
- `incumbent_baselines` — the 205-detector library. See §4.
- `fusion` — see §4/§6.
- `render` (`src/render.rs`): `pub struct RenderedEpisodeSummary { … }` (L57-67); `pub fn render_episode_summary<const M: usize>(episode: &DebugEpisode, signal_names: &[String], bank: &HeuristicsBank<M>, match_confidence: Option<MatchConfidence>) -> RenderedEpisodeSummary` (L88-98); `pub fn render_episodes_summary<const M: usize>(episodes: &[DebugEpisode], count: usize, signal_names: &[String], bank: &HeuristicsBank<M>) -> Vec<RenderedEpisodeSummary>` (L150-160).
- `calibration` (`src/calibration.rs`): `pub struct MotifThresholdRecommendation { … }` (L56-62); `pub struct CalibrationReport { config: EngineConfig, motif_recommendations: Vec<MotifThresholdRecommendation>, healthy_stats: HealthyStats }` (L66-76); `pub struct HealthyStats { … }` (L81-91); `pub fn recommend_config_from_healthy(healthy_data: &[f64], num_signals: usize, num_windows: usize, percentile: f64) -> CalibrationReport` (L104-114).
- `real_data` (`src/real_data.rs`): `pub struct RealDatasetManifest { … }` (L72-82); `pub struct RealDatasetEvaluation { manifest_name: &'static str, metrics: BenchmarkMetrics, deterministic_replay_holds: bool, episode_count: usize, fixture_header: String }` (L100-109); `pub fn verify_fixture_integrity(manifest: &RealDatasetManifest, fixture_bytes: &[u8]) -> Result<()>` (L112-122); `pub fn evaluate_real_dataset<const S: usize, const M: usize>(engine: &DsfbDebugEngine<S, M>, manifest: &RealDatasetManifest, fixture_bytes: &[u8]) -> Result<RealDatasetEvaluation>` (L152-162); plus 12 `pub const MANIFEST_*` entries (e.g. `MANIFEST_TADBENCH_F11` L310-320).
- `audit` (`src/audit/mod.rs:40-100`): re-exports `compute_detector_selectivity_per_fixture`, `aggregate_detector_audit`, `render_detector_selectivity_md`, `DetectorSelectivity`, `CrossFixtureDetectorEntry`, `CrossFixtureDetectorReport`; `compute_axis_discrimination`, `render_axis_discrimination_md`, `AxisDiscriminationEntry`, `AxisDiscriminationReport`; `audit_confuser_pairs`, `render_confuser_audit_md`, `ConfuserPairAuditEntry`, `ConfuserAuditReport`; `run_loo_cv`, `aggregate_loo_cv`, `aggregate_kfold_cv`, `render_loo_cv_baseline_md`, `render_kfold_cv_md`, `refinement_passes_gate`, `LooCvFixtureRecord`, `LooCvAggregate`, `KFoldCvAggregate`, `KFoldFoldRecord`, `RefinementGateVerdict`; `build_motif_refinement`, `build_motif_refinement_from_observations`, `render_motif_refinement_md`, `EpisodeMotifObservation`, `MotifRefinementEntry`, `MotifRefinementReport`, `AffinityDivergence`; `canonical_calibrated_weight_overrides`, `TOP_DETECTORS_BY_SELECTIVITY`; `bootstrap_ci`, `bootstrap_ci_with_seed`, `render_bootstrap_md`, `BootstrapAggregate`, `BootstrapCi`, `DEFAULT_BOOTSTRAP_ITERATIONS`, `DEFAULT_BOOTSTRAP_SEED`.
- `demo` (`src/demo/mod.rs:49-56`): `pub mod figures; pub mod infrastructure; pub mod pdf_report; pub mod runner; pub use runner::run_demo;` — `run_demo() -> Result<PathBuf>` (`src/demo/runner.rs:65-75`).

---

## 3. The residual pipeline

Documented architecture (`lib.rs:43-63`): `Residual → SignTuple → Grammar → Hysteresis → ReasonCode → Bank lookup → Episode`.

### Chain inside `run_evaluation` (`lib.rs:360-578`), with exact call sites

1. **Baseline mean** — `baseline::compute_baseline_mean(healthy_slice, num_signals, healthy_window_end, &mut baseline_mean[..num_signals])` (`lib.rs:369-371`; def `baseline.rs:38-43`). Two-pass mean over the first `healthy_window_end` windows; NaN values skipped (`baseline.rs:54`).
2. **Envelope radius ρ** — `baseline::compute_baseline_envelope(healthy_slice, &baseline_mean[..num_signals], num_signals, healthy_window_end, &mut rho[..num_signals])` (`lib.rs:372-375`; def `baseline.rs:74-80`). ρ = 3σ per signal with Bessel correction, floor `1e-10` (`baseline.rs:102-107`), σ via `envelope::sqrt_approx_pub` (Newton, 8 iterations, `envelope.rs:93-109`).
3. **Residual + norm** — inline in `run_evaluation`:
   ```rust
   let is_nan = obs.is_nan(); // NaN check
   let residual = if is_nan { 0.0 } else { obs - baseline_mean[s] };
   let norm = residual::residual_norm(residual);            // lib.rs:406-408
   ```
   (NaN observation ⇒ residual 0, then `evaluate_signal` receives `was_imputed = is_nan` and zeroes everything — `lib.rs:220-236`.)
   Standalone form: `residual::compute_residuals(&obs, &base, &missing_mask, &mut out) -> Result<()>` (`residual.rs:35-41`); `residual::residual_norm(r) = |r|` (`residual.rs:65-68`).
4. **Sign tuple** — `sign::compute_sign_tuple(&norm_histories[s][..nh], k)` (`lib.rs:239`; def `sign.rs:35-59`): `norm = |norms[k]|`; `drift = norms[k] - norms[k-1]` (first finite difference); `slew = drift(k) - drift(k-1)` (second difference). `k == 0` or empty ⇒ `SignTuple::ZERO`.
5. **Drift persistence** — `sign::drift_persistence(&norms, k, self.config.drift_window)` (`lib.rs:242-244`; def `sign.rs:62-80`): fraction of last W window-to-window drifts that are > 0. Also `sign::boundary_density(&[u8], k, window) -> f64` (`sign.rs:84-101`) and `sign::slew_density(&[f64], k, window, delta_s) -> f64` (`sign.rs:104-125`).
6. **Raw grammar + reason code** — `grammar::evaluate_raw_grammar(&sign_tuple, rho, &self.config, drift_pers)` (`lib.rs:247-249`; def `grammar.rs:32-63`):
   - Violation if `norm > ρ` (reason `AbruptSlewViolation` if `|slew| > config.slew_delta`, else `EnvelopeViolation`);
   - Boundary if in `(boundary_fraction·ρ, ρ]` with (`drift > 0 && persistence > 0.5` ⇒ `SustainedOutwardDrift`) or `|slew| > slew_delta` ⇒ `AbruptSlewViolation`) else `BoundaryApproach`;
   - else `(Admissible, Admissible)`.
7. **Hysteresis** — `grammar::hysteresis_confirm(recent_raw_states, self.config.hysteresis_confirm)` (`lib.rs:252-254`; def `grammar.rs:70-103`): requires n_confirm consecutive Boundary-or-higher; Violation bypasses hysteresis. The engine takes the max of raw and confirmed, so **Violation always confirms** (`lib.rs:256-260`).
8. **DSA + consistency gate** — `dsa::compute_dsa_score(0.0 /*boundary density — hardcoded 0*/, drift_pers, if |slew| > slew_delta {1.0} else {0.0})` (`lib.rs:264-269`; def `dsa.rs:25-33`, unit weights `= boundary_density + drift_persistence + slew_density`); `dsa::consistency_gate(dsa_score, self.config.consistency_gate)` = `dsa_score >= tau` (`lib.rs:270`; def `dsa.rs:37-39`).
9. **Semantics (per-signal)** — `self.heuristics_bank.lookup(reason_code, drift_pers, slew_mag)` (`lib.rs:273`; def `heuristics_bank.rs:1143-1184`). `motif = Some(m) | None` follows `Named | Unknown` (`lib.rs:276-279`).
10. **Policy** — `policy::apply_policy(confirmed_grammar, dsa_score, gate_passed, semantic, persistence_count, self.config.persistence_threshold)` (`lib.rs:282-289`; def `policy.rs:30-79`).
11. **Episode aggregation** — `episode::aggregate_episodes(&policy_states_flat[..], num_signals, num_windows, &reason_codes_flat[..], &drift_dirs_flat[..], &slew_mags_flat[..], self.config.episode_correlation_window, episodes_out)` (`lib.rs:501-510`; def `episode.rs:74-249`). See §6.
12. **Episode-level bank match** — `self.heuristics_bank.match_episode(&ep, avg_drift, avg_boundary)` written back into `episodes_out[ep_idx].matched_motif` (`lib.rs:546-548`), with a policy escalation if the bank recommends `Escalate` for a `Review` episode (`lib.rs:554-561`).
13. **Metrics** — `episode::compute_metrics(episodes_out, episode_count, fault_labels, raw_anomaly_count, self.config.episode_precision_window, dataset_name, num_signals as u16)` (`lib.rs:567-575`; def `episode.rs:266-374`).

The per-signal version of steps 4-10 is the public `DsfbDebugEngine::evaluate_signal` (`lib.rs:208-218`), documented as the single-signal, single-window entry point. Its `recent_raw_states`/`persistence_count` arguments are the caller-maintained hysteresis state (managed inside `run_evaluation` via `recent_raw[[GrammarState::Admissible; 4]; S]` circular buffers, `lib.rs:383-384, 428-456`).

**Slew/drift flat-stream quantization** used by the episode aggregator: `drift_dirs_flat` = Positive/Negative/None by threshold ±0.1 on `sign_tuple.drift`; `slew_mags_flat` = `|sign_tuple.slew|` (`lib.rs:469-481`).

---

## 4. The detector field

### The 205 detectors / 27 axes claim

- `incumbent_baselines.rs:1-9`: "**205 deterministic detectors organised across 27 mathematical axes** (Tiers A–U + EXTRA + V/X/Y/Z/AA)".
- `fusion.rs:10-14` repeats the claim; the module doc table (`incumbent_baselines.rs:14-42`) gives per-tier counts.
- The 27 axis constants are the `TIER_BIT_*` consts in `heuristics_bank.rs:116-149` (`TIER_BIT_A` … `TIER_BIT_AA`, 32 bits total; bits 0-21 A-U + EXTRA, bits 22-31 V/X/Y/Z/AA/B..).
- Verifiable enumeration: with all `FusionConfig` flags on, `FusionConfig::detectors_used()` returns **205** — 24 individual flags (23 flat detectors + `use_dsfb_structural`) plus `tier_detector_count() == 181` family detectors (`fusion.rs:494-519, 523-545`). Family dispatch enumerations are visible in `run_inner` (`fusion.rs:1038-1286`).
- Each detector is a standalone `pub fn` in `incumbent_baselines.rs` with the uniform shape `(data: &[f64], num_signals: usize, num_windows: usize, healthy_window_end: usize, fault_labels: &[bool], pred_window: u64, <hyperparams>) -> DetectorOutput`. Example (`incumbent_baselines.rs:173-180`):

```rust
pub fn scalar_threshold(
    data: &[f64],
    num_signals: usize,
    num_windows: usize,
    healthy_window_end: usize,
    fault_labels: &[bool],
    pred_window: u64,
) -> DetectorOutput
```

### Detector output / witness record

```rust
pub struct DetectorOutput {                                  // incumbent_baselines.rs:124-144
    pub detector_name: &'static str,
    pub raw_alert_count: u64,
    pub alerts_per_signal: [u64; 32],   // up to 32 signals; truncated otherwise
    pub alert_windows: u64,
    pub episode_count: u64,
    pub captured_faults: u64,
    pub total_faults: u64,
    pub clean_window_false_alerts: u64,
    pub clean_windows: u64,
}
impl DetectorOutput {
    pub fn rscr(&self) -> f64            // 1.0 or 0.0   (L150-152)
    pub fn fault_recall(&self) -> f64    // captured/total (L154-160)
    pub fn clean_window_fp_rate(&self) -> f64  // (L162-168)
}
```

### Per-window alert side channel (witness field)

`incumbent_baselines.rs:108-119` — a **thread-local** buffer each detector fills just before returning:

```rust
std::thread_local! {
    pub static LAST_WIN_ALERTS: std::cell::RefCell<Vec<bool>> = std::cell::RefCell::new(Vec::new());
}
```

The fusion harness reads it immediately after each family-level detector call and ORs the bits into `window_tier_mask[w]` keyed by the detector's tier (`fusion.rs:1002-1031`, the `push_tier!` macro: "forces evaluation BEFORE LAST_WIN_ALERTS read"). This is the mechanism that turns flat detectors into tier/witness evidence without changing detector signatures. **Caveat for frf-fuzz:** it is a single shared thread-local; correct usage is strictly call-detector-then-read, same thread, sequentially.

### API to run the full detector field on an observation

```rust
pub fn run_fusion_evaluation<const S: usize, const M: usize>(
    engine: &DsfbDebugEngine<S, M>,
    data: &[f64],
    num_signals: usize,
    num_windows: usize,
    healthy_window_end: usize,
    fault_labels: &[bool],
    config: &FusionConfig,
    fixture_name: &'static str,
) -> Result<FusionMetrics>                                       // fusion.rs:627-636
```

This is the **full-field entry point**. Important operational facts:

- It runs `run_inner` **twice** — once for metrics, once for replay verification — and sets `FusionMetrics.deterministic_replay_holds` from equality of counts + per-episode tier masks + top witnesses (`fusion.rs:637-657`). Cost = 2 × full field.
- Inside `run_inner` (`fusion.rs:660-1641`): per-cell consensus grid `cell_consensus` (u8 per (w,s)), per-window `window_boost`, per-cell + per-window tier bitmasks (`cell_tier_mask`, `window_tier_mask`, `fusion.rs:676-706`); consensus arithmetic `total = cell_consensus[idx] + window_boost[w]`, fire iff `>= config.min_consensus` (`fusion.rs:1316-1327`).
- The DSFB structural meta-layer runs `engine.run_evaluation(...)` inside `run_inner` when `config.use_dsfb_structural` (`fusion.rs:1293-1309`), then types each closed episode through the bank (`fusion.rs:1394-1606`).

### Is there a way to run a SUBSET? — Yes, three mechanisms

1. **`FusionConfig` per-detector / per-family boolean flags** (`fusion.rs:121-180`). `FusionConfig::ALL_FOUR_DEFAULT` (`fusion.rs:429-472`) is the shipped minimal config: `min_consensus: 2`, only `use_scalar`, `use_cusum`, `use_ewma`, `use_dsfb_structural` true; every other flag false. `FusionConfig::ALL_DEFAULT` (`fusion.rs:324-427`) enables everything (min_consensus 3, all 24 individual flags + all 20 family flags true). Any combination is constructible with struct-update syntax: `FusionConfig { use_tier_l_multivariate: false, ..FusionConfig::ALL_DEFAULT }`.
2. **`detector_weight_overrides: Option<&'static [(&'static str, u8)]>`** (`fusion.rs:302-320`; lookup `weight_for(&self, name: &str) -> u8` at `fusion.rs:485-492`): weight 0 **fully suppresses** a detector's contribution to `cell_consensus`, both tier bitmasks, and `all_detector_alerts` (the standalone `DetectorOutput` is still pushed to `per_detector` for audit). The shipped subset-optimization harness (`tests/detector_subset_opt.rs:143-154`) uses exactly this to keep only the top-K selectivity-ranked detectors:

```rust
fn build_top_k_overrides(ranked: &[&'static str], k: usize) -> &'static [(&'static str, u8)] {
    let mut overrides: Vec<(&'static str, u8)> = Vec::with_capacity(total - k);
    for (i, name) in ranked.iter().enumerate() {
        if i >= k { overrides.push((*name, 0)); }
    }
    Box::leak(overrides.into_boxed_slice())
}
```

3. **Direct per-detector calls** — every detector is a public free function in `incumbent_baselines` (e.g. `scalar_threshold`, `cusum`, `ewma`, `mann_kendall`, `poisson_burst`, `pettitt_test`, …), so frf-fuzz can invoke an arbitrary subset itself and get `DetectorOutput` per detector without touching fusion.

**And the structural side is already cheap and separable**: `run_evaluation`/`evaluate_signal` do **not** run any of the 205 detectors — the grammar/DSA/policy pipeline is self-contained no_std code. That is the natural frf-fuzz Level-0 gate.

### Axes (tiers) mapping for subset selection

`affinity_tiers_for(reason_code: ReasonCode, min_correlation_count: u16) -> u32` (`heuristics_bank.rs:157-195`) maps reason codes to the tier bits that are predictive for them (e.g. `SustainedOutwardDrift ⇒ TIER_BIT_I|J|M|S|U|T`; `AbruptSlewViolation ⇒ A|B|I|N|O|EXTRA`), with `u32::MAX` ("all tiers") for `Admissible`. Each `HeuristicEntry` carries a hand-curated `affinity_tiers` mask that overrides the derived mask when non-zero (`heuristics_bank.rs:1699-1701, 1747-1751`).

---

## 5. Motif bank: 32 motifs, matching, anti-hallucination gates, Unknown

### The bank type

```rust
pub struct HeuristicsBank<const MAX: usize> {
    entries: [Option<HeuristicEntry>; MAX],
    count: usize,
}                                                        // heuristics_bank.rs:199-202
```

- `pub fn with_canonical_motifs() -> Self` (`heuristics_bank.rs:204-207`) loads **32 canonical `HeuristicEntry` records** (verified by test `count_after_canonical_init` asserting `bank.count() == 32`, `heuristics_bank.rs:2149-2155`; the module doc and figure titles also say "32-motif": `heuristics_bank.rs:1`, `demo/infrastructure.rs:201`). Note: the `lib.rs:700` doc comment ("29 canonical motifs as of v0.2") is stale — actual count is 32.
- If `MAX < 32`, the canonical bank is **truncated** to `MAX` entries (`heuristics_bank.rs:1129-1134`).
- `impl Default` → `with_canonical_motifs()` (`heuristics_bank.rs:1972-1976`).
- `pub fn entries_iter(&self) -> impl Iterator<Item = &HeuristicEntry>` (`heuristics_bank.rs:1545-1547`), `pub fn entry_for(&self, motif: MotifClass) -> Option<&HeuristicEntry>` (`heuristics_bank.rs:1551-1562`), `pub fn count(&self) -> usize` (`heuristics_bank.rs:1531-1534`).

`MotifClass` has exactly **32 variants** (`types.rs:117-258`): Tier-1 `MemoryLeakDrift, CascadingTimeoutSlew, DeploymentRegressionSlew, CacheDegradationGrazing, ConnectionPoolExhaustionDrift, GcPressureOscillation, ErrorRateEscalation, DependencySlowdown, ResourceSaturation, QueueBackpressure`; Tier-2 `RetryStormCascade, CircuitBreakerOpenShift, DatabaseLockContention, AuthenticationFailureSpike, ConfigDriftRegression`; Tier-3 `PacketLossErrorEscalation, NetworkDelayDependencyInflation, DiskIoSaturation, CpuSaturation, JvmHeapPressure, JvmGcPause`; Tier-4 `ServiceGraphDriftPropagation, HighDimAnomalyCluster, MetricCorrelationCollapse`; Tier-5 `LogVolumeAnomaly, LogTraceTemporalDecorrelation, LogSeverityEscalation`; Tier-6 `SaturationTrending, EpisodicTransientSpike, RegressiveDriftWithRecovery, EnvelopeBoundaryApproach, EnvelopeBreach`.

`HeuristicEntry` (all 23 fields, `types.rs:338-451`):

```rust
pub struct HeuristicEntry {
    pub motif_class: MotifClass,
    pub reason_code: ReasonCode,
    pub candidate_interpretation: &'static str,
    pub provenance: Provenance,
    pub recommended_action: PolicyState,
    pub drift_threshold: f64,
    pub slew_threshold: f64,
    pub boundary_density_threshold: f64,
    pub min_correlation_count: u16,
    pub max_correlation_count: u16,
    pub min_duration_windows: u16,
    pub max_duration_windows: u16,
    pub weight_drift: f64, pub weight_slew: f64, pub weight_boundary: f64,
    pub weight_correlation: f64, pub weight_duration: f64,
    pub evidence_dataset: &'static str,
    pub evidence_dataset_doi: &'static str,
    pub dashboard_hint: &'static str,
    pub taxonomy_ref: &'static str,
    pub affinity_tiers: u32,
    pub confuser_motif: Option<MotifClass>,
    pub margin_vs_confuser_threshold: f64,
    pub primary_witness_tiers: u32,
    pub primary_witness_detectors: &'static [&'static str],
}
```

### Matching paths

- **Per-signal** `lookup(reason_code, drift_persistence, slew_magnitude) -> SemanticDisposition` (`heuristics_bank.rs:1143-1184`): filters on reason-code equality, score = `1.0 + drift_pers (if ≥ drift_threshold) + slew_mag (if ≥ slew_threshold)`; argmax over score, tie-break by provenance rank (`FieldValidated 3 > DatasetObserved 2 > FrameworkDesign 1`, `provenance_rank` at `heuristics_bank.rs:1980-1986`) then lowest index. No match ⇒ `Unknown`.
- **Per-episode** `match_episode(&self, episode: &DebugEpisode, avg_drift_persistence: f64, avg_boundary_density: f64) -> SemanticDisposition` (`heuristics_bank.rs:1200-1277`): gates on reason-code equality **plus** correlation-count and duration ranges; score = `1.0 + Σ weight_f·feature_f` (drift, slew, boundary) + `weight_correlation·count·0.1` + `weight_duration·windows·0.05`; same deterministic tie-breaks.
- `match_episode_with_confidence(...) -> MatchConfidence` (`heuristics_bank.rs:1285-1387`) — adds runner-up tracking and `margin = (top - runner_up)/top` clamped [0,1]; `top_score == 0.0` ⇒ Unknown.
- `match_episode_with_consensus(episode, avg_drift, avg_boundary, episode_max_consensus: u8, max_detectors: u8) -> MatchConfidence` (`heuristics_bank.rs:1407-1515`) — same plus additive `consensus_factor = episode_max_consensus / max_detectors` boost.
- `match_episode_with_tier_affinity(...)` (`heuristics_bank.rs:1628-1646`) and `match_episode_with_tier_affinity_axes(episode, avg_drift, avg_boundary, cell_tier_mask: &[u32], window_tier_mask: &[u32], num_signals: usize, max_active_tiers: u8, episode_max_consensus: u8, use_zero_tier_filter: bool, use_disambiguator_boost: bool, use_primary_witness_tier_gate: bool) -> MatchConfidence` (`heuristics_bank.rs:1663-1676`) — tier-affinity-restricted consensus scoring, multiplicative consensus boost (`score *= 1.0 + 0.5·consensus_factor`, L1850), confuser disambiguator boost (`*= 1.0 + 0.3·disambig_factor`, L1884), and **confuser-pair adjudication** filling `confuser_motif/confuser_score/margin_vs_confuser` (L1929-1953).

### Anti-hallucination gates (the ladder)

1. **Zero-tier-firing filter** (axis 4): motifs whose curated `affinity_tiers != 0` and `!= u32::MAX` but had **no affinity tier fire** in the episode range are skipped (`heuristics_bank.rs:1784-1791`).
2. **Primary-witness-tier gate** (axis 8): `entry.primary_witness_tiers != 0` must have at least one bit fired in the episode range, else the motif is hard-disqualified (`heuristics_bank.rs:1801-1826`).
3. **Margin gate** (axis 2): fusion rejects typing when `MatchConfidence.margin < config.margin_gate` (default 0.30; adaptive halving when `tier_consensus_factor > 0.5`, `fusion.rs:1470-1485`).
4. **Confuser-boundary gate** (axis 6): a Named motif must beat its declared confuser: `confidence.margin_vs_confuser >= entry.margin_vs_confuser_threshold` (default 0.10), else the episode is routed to `confuser_ambiguous` (`fusion.rs:1495-1507`).
5. **Per-detector named-witness gate** (axis 9): `entry.primary_witness_detectors` — at least one named detector must have fired in the episode range per `all_detector_alerts`; empty witness list or no captured witnesses vacuously passes (`fusion.rs:1515-1546`).

### CRUCIALLY — Unknown handling

- **There is an explicit `Unknown` variant**: `pub enum SemanticDisposition { Named(MotifClass), Unknown }` (`types.rs:261-267`), documented "Endoductive mode — structure characterized but no named match". It is deliberately **not** `Named` + low-confidence; it is a distinct first-class outcome.
- **No forced nearest-label**: every match path returns `None ⇒ SemanticDisposition::Unknown` when no entry passes the gates (`heuristics_bank.rs:1180-1183, 1273-1276, 1367-1370, 1497-1500, 1918-1921`). In fusion, `Unknown` dispositions **bypass** the margin gate, confuser gate, and witness gate — they are never promoted or demoted, they stay Unknown (`fusion.rs:1480-1484` "Unknown ⇒ true", `1498-1506`, `1517-1545`). The bank has a documented "endoductive discipline": LO2-style anomalies that no motif covers are validated to stay `Unknown` (`heuristics_bank.rs:67-74`, test `eval_lo2.rs`).
- **Trivial-Unknown vs Structured-Unknown is distinguished by the surrounding structural fields, not by Unknown alone**:
  - Signal level: `SignalEvaluation.semantic_disposition == Unknown` **plus** `confirmed_grammar_state == Admissible` + `policy_state == Silent` ⇒ trivial (nothing detected). The same `Unknown` with `confirmed_grammar_state >= Boundary` + `policy_state == Review` ⇒ structured-but-unmatched. `policy::apply_policy` encodes this exactly: `Admissible && dsa < 0.5 ⇒ Silent` (`policy.rs:40-42`), while `Unknown` after the persistence gate ⇒ `Review` with the comment "Endoductive: structure present but unnamed → Review" (`policy.rs:74-77`).
  - Episode level: `DebugEpisode.matched_motif == Unknown` with `policy_state == Review`/`Escalate` is the structured-unknown episode; `aggregate_episodes` only opens episodes on `>= Review` (`episode.rs:107-110`), so a `Silent`/`Watch` stream produces **zero** episodes.
  - Audit trail: `AuditEventType::EndoductiveUnknown` exists specifically for this outcome (`types.rs:535`).
  - The endoductive Unknown also gets partial credit in the episode catalog: Unknown↔Unknown pairs score motif weight 0.5 in `signature_similarity` (`episode_catalog.rs:148-154`).

---

## 6. Episodes

### Structural episode types

- `DebugEpisode` (`types.rs:498-514`) — see §2. `matched_motif: SemanticDisposition` (starts `Unknown`, filled by the caller).
- `StructuralSignature { dominant_drift_direction, peak_slew_magnitude, duration_windows, signal_correlation }` (`types.rs:488-494`).
- `SimilarEpisode` + `EpisodeCatalog<N>` for cross-episode recall (`episode_catalog.rs:42-61`).

### Episode opening / closing — `aggregate_episodes`

```rust
pub fn aggregate_episodes(
    policy_states: &[PolicyState],
    num_signals: usize,
    num_windows: usize,
    reason_codes: &[ReasonCode],
    drift_directions: &[DriftDirection],
    slew_magnitudes: &[f64],
    correlation_window: u64,
    episodes_out: &mut [DebugEpisode],
) -> usize                                                          // episode.rs:74-84
```

Semantics (`episode.rs:15-32, 98-249`): an episode **opens** when any signal in a window is `>= PolicyState::Review`; it **closes** when all signals are below Review for `correlation_window` consecutive windows (or at end of data). Per-episode fields: `peak_grammar_state` = max (Escalate→Violation, Review→Boundary); `primary_reason_code` = max by `reason_severity` (`episode.rs:251-262`); `peak_slew` = max |slew|; `contributing_signal_count` = max concurrent contributing signals; `dominant_drift_direction` = first signal's drift at the close window (proxy; `episode.rs:182-186`); `signal_correlation = contributing / num_signals`. `episode_id` sequential from 0. Deterministic row-major scan.

### Fusion outputs

`FusionMetrics` (`fusion.rs:548-625`) — the full-field output packet:

```rust
pub struct FusionMetrics {
    pub fixture_name: &'static str,
    pub min_consensus: u8,
    pub detectors_used: u8,
    pub raw_alert_count: u64,
    pub consensus_alert_count: u64,
    pub consensus_alert_windows: u64,
    pub fusion_episode_count: u64,
    pub fusion_rscr: f64,
    pub fusion_fault_recall: f64,
    pub fusion_clean_window_fp_rate: f64,
    pub consensus_confirmed_typed_episodes: u64,
    pub consensus_filtered_out_episodes: u64,
    pub consensus_confirmed_clean_fp_rate: f64,
    pub ambiguous_typed_episodes: u64,
    pub bank_aware_filtered_out: u64,
    pub confuser_ambiguous_episodes: u64,
    pub operator_score: f64,
    pub deterministic_replay_holds: bool,
    pub per_detector: Vec<DetectorOutput>,
    pub dsfb_structural: Option<BenchmarkMetrics>,
    pub per_episode_confidence: Vec<MatchConfidence>,
    pub per_episode_tier_mask: Vec<u32>,
    pub per_episode_top_witnesses: Vec<Vec<(&'static str, u64)>>,
}
```

- `per_detector` — one `DetectorOutput` per enabled detector (the raw witness field).
- `per_episode_confidence` — per typed episode `MatchConfidence` (top motif, runner-up, margin, confuser fields).
- `per_episode_tier_mask` — OR of observed tier bits over the episode range.
- `per_episode_top_witnesses` — top-5 firing detectors in the episode range, sorted by fired-window count then name (deterministic, `fusion.rs:1602-1604`).
- Episode counters distinguish: typed-confirmed / filtered (no consensus at all) / bank-aware-filtered (consensus exists but below per-motif threshold) / margin-ambiguous / confuser-ambiguous (`fusion.rs:1385-1389, 1449-1568`).

---

## 7. Config

### `EngineConfig` (`config.rs:23-48`) — the structural engine's config

```rust
pub struct EngineConfig {
    pub drift_window: usize,          // W (paper: 5)
    pub dsa_window: usize,            // 10 (note: unused by compute_dsa_score)
    pub persistence_threshold: usize, // K (4)
    pub consistency_gate: f64,        // τ (2.0)
    pub corroboration_count: usize,   // m (1)
    pub hysteresis_confirm: usize,    // n_confirm (2)
    pub boundary_fraction: f64,       // 0.5
    pub episode_correlation_window: u64,   // 5
    pub episode_precision_window: u64,     // 5
    pub min_healthy_windows: usize,   // 100
    pub slew_delta: f64,              // δ_s (0.1)
}
```

`pub const PAPER_LOCK_CONFIG: EngineConfig` (`config.rs:52-64`); `EngineConfig::validate() -> Result<()>` (`config.rs:66-91`); `Default` → paper-lock values (`config.rs:93-96`). **The detector field is configured/scaled separately via `FusionConfig`** (`fusion.rs:120-321` — see §4), not via `EngineConfig`. `EngineConfig` only tunes the structural grammar/DSA/policy/episode pipeline; the fusion side has its own ~100-field `FusionConfig` with per-detector, per-family, and 9-axis gate toggles, plus `detector_weight_overrides` for per-detector scaling.

Advisory site calibration exists: `calibration::recommend_config_from_healthy(healthy_data, num_signals, num_windows, percentile) -> CalibrationReport` (`calibration.rs:104-114`) — advisory only, never auto-applied ("No automatic apply", `calibration.rs:33-41`).

---

## 8. Transitive dependencies; heavy-deps question

- **Direct deps: `plotters` (0.3, optional) and `zip` (0.6, optional)** — both gated behind `demo` (`Cargo.toml:71-88`). Nothing else.
- **`serde`, `clap`, `rayon`, `rand`, `chrono`, `sha2`: NOT present anywhere** in `Cargo.lock` (verified by full lockfile read: the only packages are plotters' and zip's closure — `image`, `png`, `font-kit`, `freetype-sys`, `flate2`, `crc32fast`, `miniz_oxide`, `walkdir`, `thiserror`, `wasm-bindgen`, … all under `demo`).
- The `no_std` core (everything except the `std`-gated modules) pulls **zero** dependencies; SHA-256, DFT, and matrix algebra are hand-rolled (`Cargo.toml.orig:63-64`, `lib.rs:29-30`, `adapters/mod.rs:9-13`).
- **Lib-only build avoiding the demo binary**: `cargo build` (default, no features) or `cargo build --features std` compiles the lib with zero external deps and never builds `dsfb-debug-demo` (its `required-features = ["demo"]` makes it unbuildable otherwise; `Cargo.toml:66-69`). The 205-detector field + fusion need `--features std`; `real_data` needs `std,paper-lock`.
- `deny.toml` exists at the crate root (advisory policy for `cargo deny`, not a build gate).

---

## 9. Integration gotchas for frf-fuzz

1. **Unsafe**: `#![forbid(unsafe_code)]` (`lib.rs:92`) — zero `unsafe` in crate code. (Only reachable `unsafe` would be inside the optional `demo`-only dep closure, e.g. font rendering, never compiled in a lib-only build.)
2. **Global state**: exactly one piece — `incumbent_baselines::LAST_WIN_ALERTS`, a `thread_local!` `RefCell<Vec<bool>>` (`incumbent_baselines.rs:108-119`). It is written by every detector just before returning and read immediately after by `run_inner`'s `push_tier!` (`fusion.rs:1002-1031`). Safe only under sequential same-thread call-then-read discipline; **do not call two detectors in parallel** and read the side channel afterward, and do not interleave other work between a detector call and the read. It is std-only and unused by the no_std core.
3. **f64 in canonical identity**: the whole structural identity is `f64` — `SignTuple { norm, drift, slew }`, ρ, DSA, drift persistence, thresholds, `MatchConfidence` scores/margins all `f64` (`types.rs:52-59, 280-311`; `config.rs`; `dsa.rs`). frf-fuzz's "no floats in canonical identity" requirement means frf-fuzz must derive its own integer canonical identity **from** these outputs (e.g. from `GrammarState`/`ReasonCode`/`PolicyState`/`DriftDirection` enums and the `u32` tier masks), not by hashing f64 values. Note `run_evaluation` already quantizes drift direction at ±0.1 (`lib.rs:474-480`) and the aggregator stores `peak_slew` as f64.
4. **NaN / missingness**: NaN observations are treated as imputed: residual forced to 0.0 and `evaluate_signal` zeroes everything (`lib.rs:406-407, 220-236`); `was_imputed: true` is stamped on the `SignalEvaluation` for audit. `baseline` skips NaN values (`baseline.rs:54, 94`). No panic paths (`#![deny(clippy::unwrap_used)]`).
5. **Read-only guarantee**: all public engine/bank/detector APIs take `&self`/`&[T]`; the only writes are to **caller-owned** output buffers (`eval_out`, `episodes_out`, `mean_out`, `rho_out`, `out_edges`, `scc_id_out`). `EpisodeCatalog::record` is the sole stateful API (`&mut self`) and is separate from the engine.
6. **Determinism**:
   - No `HashMap` anywhere in `src/` (verified by grep). The std paths use `BTreeMap` for deterministic iteration: `all_detector_alerts` (`fusion.rs:684-685`), audit maps (`audit/detector_firing.rs:125`, `audit/axis_discrimination.rs:152-156`).
   - All iteration is fixed-order loops; no rayon/parallelism.
   - The only "random" sources are seeded/LCG: `isolation_forest`'s `iso_seed` is a fixed const `0x9E3779B97F4A7C15` (`fusion.rs:359`); bootstrap uses a fixed LCG seed `DEFAULT_BOOTSTRAP_SEED` (`audit/bootstrap.rs:48-52`).
   - Sort with `partial_cmp` fallback `Ordering::Equal` is deterministic given fixed inputs (`audit/detector_firing.rs:147-149, 167-169`).
   - The only wall-clock use is `demo/runner.rs` timestamps (`demo` feature only).
   - `run_fusion_evaluation` self-verifies by double-running and setting `deterministic_replay_holds` (`fusion.rs:637-657`) — but note the replay check compares counts, tier masks, and witness lists, **not** f64 score equality of `MatchConfidence` (episode scores are assumed deterministic, not re-compared bit-wise at the fusion layer; `engine.verify_deterministic_replay` does compare `DebugEpisode` PartialEq including f64 fields, `lib.rs:688`).
7. **Buffer/limit gotchas**:
   - `run_evaluation` refuses `num_signals > S` (const generic) and `num_signals * num_windows > 8192` (`FLAT_CAP`, `lib.rs:340-358`) — the per-signal flat streams are fixed `[T; 8192]` arrays. frf-fuzz promotion runs must respect the 8192-cell cap or chunk.
   - `eval_out`/`episodes_out` are caller-sized; overflow silently stops writing (`lib.rs:460-462`) — size them `num_signals*num_windows` and `256` respectively.
   - `alerts_per_signal: [u64; 32]` truncates beyond 32 signals (`incumbent_baselines.rs:129`).
   - `HeuristicsBank<MAX>` truncates the canonical 32 motifs if `MAX < 32`.
   - `causality` supports up to 512 signals (`causality.rs:105`); `graph_inference` up to 256 nodes (`graph_inference.rs:52`).
8. **Two-tier cost model already exists**: the crate itself ships the "subset optimization" evidence that a small top-K detector set reaches the 95%-recall plateau on its 12-fixture surface (`tests/detector_subset_opt.rs:176-286`), and `FusionConfig::ALL_FOUR_DEFAULT` is the minimal 4-input config. frf-fuzz's Level-0/Level-1 split maps onto: structural `run_evaluation` (Level 0) → `run_fusion_evaluation` with a custom subset `FusionConfig` (Level 1).
9. **`run_fusion_evaluation` doubles the field cost** (two `run_inner` passes for replay). For per-promoted-execution Level-1 runs in a fuzzer loop this is 2× — either accept it, or note that `run_inner` is private and the only public full-field entry is the replay-verifying one; for strict cost control call individual `incumbent_baselines::*` detectors directly (all `pub`) and read `LAST_WIN_ALERTS` yourself.
10. **fault labels are required** by every detector signature (`fault_labels: &[bool]`); for fuzz executions without ground-truth labels, pass an all-`false` mask — detectors still compute `raw_alert_count`/`alerts_per_signal`/`alert_windows`, but `captured_faults`/`fault_recall` become vacuous (fault_recall returns 1.0 when total_faults == 0, `incumbent_baselines.rs:154-160`).
11. `default_size()` hardcodes `<256, 64>` and equals `paper_lock()` (`lib.rs:697-706`) — frf-fuzz should prefer `DsfbDebugEngine::<S, M>::new(EngineConfig{...})` with its own config rather than inheriting paper-lock values wholesale.

---

## 10. Concrete recommendation for frf-fuzz

**Feature set (minimal, lib-only):**

```toml
dsfb-debug = { version = "0.1", default-features = false, features = ["std"] }
```

- `std` is required for the detector field (`incumbent_baselines`, `fusion`, `audit`) and the TSV adapter. The no_std core (residual/sign/grammar/policy/episode/causality/graph_inference/episode_catalog) works with `default-features = false` alone if frf-fuzz ever needs to run structural Level-0 without std.
- Do **not** enable `demo` (pulls plotters+zip). `paper-lock` only if frf-fuzz wants `real_data::evaluate_real_dataset` + SHA-256-gated fixtures (not needed for a fuzzer's own executions).
- Cargo will resolve **zero transitive deps** for this feature set (verified against `Cargo.lock`).

**Call sequence:**

**(a) Residual + sign tuple + drift/slew for one execution pair (Level 1, per promoted execution):**

Use the structural engine — no detectors involved. Either per-signal streaming:

```rust
let engine = DsfbDebugEngine::<256, 64>::new(EngineConfig { ..EngineConfig::default() })?; // or custom

// per signal s, per window k, with a per-signal norm history `norms: &[f64]`:
let st = sign::compute_sign_tuple(norms, k);                 // SignTuple { norm, drift, slew }
let dp  = sign::drift_persistence(norms, k, cfg.drift_window);
let (raw_state, reason) = grammar::evaluate_raw_grammar(&st, rho[s], &cfg, dp);
let confirmed = grammar::hysteresis_confirm(recent_states, cfg.hysteresis_confirm);
// ... or, batched over the whole windowed matrix:
let (episode_count, metrics) = engine.run_evaluation(
    &data, num_signals, num_windows, &fault_labels,
    healthy_window_end, &mut eval_out, &mut episodes_out, "frf_exec")?;
```

Level-0 (every execution) = `run_evaluation`'s structural pass only (baseline → residual → sign → grammar → policy), which is the cheap no_std path; keep `run_evaluation` output `SignalEvaluation.sign_tuple` and `drift_persistence` as the canonical structural residue for the frf-fuzz identity.

**(b) Run the detector field on a promoted execution:**

```rust
let cfg = FusionConfig { detector_weight_overrides: Some(FRF_LEVEL1_OVERRIDES), ..FusionConfig::ALL_DEFAULT };
let m = fusion::run_fusion_evaluation(&engine, &data, num_signals, num_windows,
    healthy_window_end, &fault_labels, &cfg, "frf_promoted")?;
```

- Level-0 cheap detector tier: start from `FusionConfig::ALL_FOUR_DEFAULT` (scalar + cusum + ewma + dsfb_structural, `min_consensus = 2`) or a custom struct with the handful of detectors frf-fuzz deems cheap (e.g. scalar, cusum, ewma, mann_kendall, monotone_leak).
- Level-1 full field: `FusionConfig::ALL_DEFAULT` (205 detectors, `min_consensus = 3`).
- To suppress detectors by name (cheap/full blend), build a `detector_weight_overrides: &[("name", 0_u8)]` list per the subset-opt pattern (`tests/detector_subset_opt.rs:143-154`); weight 0 removes the detector from consensus + tier masks + witness capture while retaining its `DetectorOutput` in `m.per_detector` for audit.
- Budget note: `run_fusion_evaluation` executes the field twice (replay self-check). If that 2× is unacceptable in the fuzz loop, call the individual `incumbent_baselines::*` functions directly (all `pub`, uniform `(data, num_signals, num_windows, healthy_window_end, fault_labels, pred_window, …) -> DetectorOutput` shape) and read `LAST_WIN_ALERTS` immediately after each call to build `window_tier_mask` yourself.

**(c) Structured/Unknown classification (never forced):**

```rust
// Episode level — the promotion decision:
let disposition = m.per_episode_confidence[ep_idx].disposition; // Named(MotifClass) | Unknown
match disposition {
    SemanticDisposition::Named(motif) => { /* use motif + margin + margin_vs_confuser */ }
    SemanticDisposition::Unknown => {
        // STRUCTURED Unknown iff the episode is real structure:
        let structured = episodes_out[ep_idx].policy_state >= PolicyState::Review; // or check
        // confirmed_grammar_state >= Boundary on the eval grid; trivial Unknown never
        // produces an episode (aggregate_episodes opens only on >= Review).
    }
}
```

Rules of thumb grounded in source: (i) `Unknown` is a first-class result at both signal and episode level; the bank and every fusion gate pass it through untouched (`heuristics_bank.rs:1180-1183`, `fusion.rs:1480-1545`). (ii) Trivial-vs-structured is read from the accompanying fields: trivial = `GrammarState::Admissible` + `PolicyState::Silent` + no episode; structured-unknown = episode-level `matched_motif == Unknown` with `policy_state >= Review` (policy.rs:74-77 "Endoductive: structure present but unnamed → Review") and `confirmed_grammar_state >= Boundary` cells. (iii) When using the fusion layer, do not treat `ambiguous_typed_episodes` / `confuser_ambiguous_episodes` as forced labels — they are "needs review" queues distinct from `consensus_confirmed_typed_episodes` (`fusion.rs:1556-1568`).

**(d) Feed detector outputs into frf-fuzz's own `FuzzSemanticBank`:**

Use DSFB-Debug strictly as the structural/witness substrate; keep frf-fuzz's own motif names:

1. Consume `m.per_detector: Vec<DetectorOutput>` — the per-detector witness counts (`detector_name`, `raw_alert_count`, `alerts_per_signal`, `alert_windows`), one record per enabled detector; this is the domain-independent evidence feed.
2. Consume `m.per_episode_confidence: Vec<MatchConfidence>` — scores, margins, runner-up, confuser fields — as *evidence routing* inputs, but map `MotifClass` only through frf-fuzz's own taxonomy (do not reuse DSFB's `MotifClass` names for classification).
3. Consume `m.per_episode_tier_mask: Vec<u32>` and `m.per_episode_top_witnesses: Vec<Vec<(&'static str, u64)>>` for per-episode witness routing, and `engine.heuristics_bank().entries_iter()` / `entry_for(motif)` if frf-fuzz wants the `HeuristicEntry` shape (thresholds, weights, witness lists) as a template for its own bank records — note `HeuristicEntry` and `HeuristicsBank<M>` are public and `entries` are `Copy`, so frf-fuzz can clone the *machinery* (scoring/gating) while substituting its own motif table.
4. For per-window signal-level evidence without the fusion layer, call individual detectors directly and use `DetectorOutput` + `LAST_WIN_ALERTS`; the engine's `SignalEvaluation` grid (from `run_evaluation`) supplies the structural side (`sign_tuple`, `drift_persistence`, `reason_code`, `confirmed_grammar_state`).
5. frf-fuzz's own semantic bank can reuse the deterministic tie-break discipline (provenance rank then lower index — `heuristics_bank.rs:1196-1199, 1259-1262`) and the anti-hallucination gate structure (zero-tier filter, witness-tier gate, margin gate, confuser gate, named-witness gate) without adopting DSFB-Debug's motif names, keeping `Structured+Unknown` as a valid terminal state throughout.
