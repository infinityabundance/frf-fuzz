# Forensic API Report — `frf` 0.1.72

Source read: `/mnt/1tb_kingston/frf-fuzz/.phase0/forensics/frf-0.1.72/` (extracted crate; `Cargo.toml` is the cargo-normalized form, `Cargo.toml.orig` the original). All facts below are from that source, cited `file:line`. Compiled and verified on `rustc 1.85.0` and `1.98.0` during this inspection (see §5).

---

## 1. Package facts

From `Cargo.toml` (normalized) and `Cargo.toml.orig`:

| fact | value | source |
|---|---|---|
| name | `frf` | `Cargo.toml:15` |
| version | `0.1.72` | `Cargo.toml:16` |
| edition | `2021` | `Cargo.toml:13` |
| rust-version (MSRV) | `1.85` | `Cargo.toml:14`, `Cargo.toml.orig:11` |
| license | `MIT OR Apache-2.0` | `Cargo.toml:42` |
| build script | none (`build = false`) | `Cargo.toml:17` |
| `[lib]` | `name = "frf"`, `path = "src/lib.rs"` (no crate-type → default `lib`/rlib) | `Cargo.toml:45-47` |
| `[[bin]]` | `name = "frf"`, `path = "src/main.rs"` | `Cargo.toml:49-51` |
| `[profile.release]` | `lto = true`, `overflow-checks = true`, `strip = true` | `Cargo.toml:233-236`, `Cargo.toml.orig:64-71` |

**Features: NONE.** There is no `[features]` section in `Cargo.toml` or `Cargo.toml.orig` (verified by grep over `**/*.toml`). The crate has no optional dependencies, no feature-gated modules, and no way to disable the CLI/extension dependencies via features. "Default features" = the empty set.

**`[dependencies]` — all non-optional** (`Cargo.toml:201-231`, `Cargo.toml.orig:35-49`):

| crate | version | optional | notes |
|---|---|---|---|
| `base64` | `0.22` | no | comparator/normalizer side-stream base64 |
| `clap` | `4` | no | features `["derive", "env"]` — used by `src/cli.rs`, which is part of the **lib** |
| `serde` | `1` | no | features `["derive"]` |
| `serde_json` | `1` | no | |
| `serde_yaml` | `0.9` | no | (resolves to `0.9.34+deprecated`) |
| `sha2` | `0.10` | no | |
| `tar` | `0.4` | no | used by `commands/bundle.rs` single-file bundles |
| `libc` | `0.2` | no | `[target.'cfg(unix)'.dependencies]` only |

Dev-dependencies: `tar 0.4` (`Cargo.toml:227-228`). 39 integration tests are declared (`Cargo.toml:53-199`), incl. `tests/fuzz.rs` (the crate's own deterministic fuzz harness) and `tests/noncli_courts.rs`.

---

## 2. Public library surface

`src/lib.rs` (29 lines) re-exports nothing; it declares 21 public modules verbatim (`src/lib.rs:9-29`):

```rust
pub mod canon;        // canonical JSON (RFC 8785 subset)
pub mod cli;          // clap CLI types — PUBLISHED (part of the lib)
pub mod commands;     // dispatch + every verb implementation
pub mod comparators;  // built-in comparator registry + evaluation
pub mod error;        // FrfError, Result
pub mod ext;          // external-program extension machinery
pub mod host;         // process execution, environment, hashing, ExecImage/ExecProfile
pub mod kappa;        // endoduction κ table
pub mod model;        // the whole canonical object model (all evidence types)
pub mod mutation;     // built-in mutation operators (court challenge)
pub mod native;       // ELF native runtime closure binding
pub mod normalizers;  // external normalizer protocol
pub mod produced;     // produced-artifact tree capture
pub mod render;       // claim renderers (prose/json/sarif/ci/badge)
pub mod sandbox;      // Landlock+seccomp I/O-closed profile
pub mod scope;        // claim scope algebra (K, P regions)
pub mod semantics;    // all content-identity functions (FRF/<KIND>/vN preimages)
pub mod sentences;    // claim sentence assembly
pub mod store;        // Store: filesystem evidence store
pub mod trajectory;   // drift/slew/localization/bands/trend classification
pub mod verify;       // verified loaders (identity re-derivation)
```

There are no macros and no top-level re-exports; consumers use fully-qualified paths (`frf::store::Store`, `frf::commands::court::run`, …).

### 2.1 `frf::error` (`src/error.rs`, 32 lines)

```rust
#[derive(Debug, Clone)]
pub struct FrfError(pub String);                                  // error.rs:7-8
impl FrfError {
    pub fn new(msg: impl Into<String>) -> Self                    // error.rs:11
    pub fn is_append_conflict(&self) -> bool                      // error.rs:19
}
impl fmt::Display for FrfError { … }                              // error.rs:24
impl std::error::Error for FrfError {}                            // error.rs:30
pub type Result<T> = std::result::Result<T, FrfError>;            // error.rs:32
```
Every library call returns `Result<T>`; the binary prints `frf: {e}` on stderr and exits non-zero (`src/main.rs:13-21`).

### 2.2 `frf::model` — the canonical object model (`src/model.rs`, 6281 lines)

Schema/version constants (all `pub const …: &str`):
`SCHEMA_AUTHORITY = "frf-authority-v1"` (`model.rs:71`), `SCHEMA_CAPTURE = "frf-capture-v15"` (`model.rs:115`), `SCHEMA_RESIDUAL = "frf-residual-v1"` (`model.rs:116`), `SCHEMA_DISPOSITION = "frf-disposition-v3"` (`model.rs:128`), `SCHEMA_RECEIPT = "frf-receipt-v20"` (`model.rs:171`), `SCHEMA_CLAIM = "frf-claim-v11"` (`model.rs:222`), `SCHEMA_RUNNER = "frf-runner-v1"` (`model.rs:224`), `SCHEMA_SERIES = "frf-series-v4"` (`model.rs:712`), `SCHEMA_TRAJECTORY = "frf-trajectory-v6"` (`model.rs:697`), `SCHEMA_CHALLENGE = "frf-challenge-v1"` (`model.rs:449`), `SCHEMA_ENVIRONMENT = "frf-environment-v3"` (`model.rs:266`), `SCHEMA_PROVENANCE = "frf-provenance-v3"` (`model.rs:270`), `SCHEMA_EXECUTION_CONTEXT = "frf-execution-context-v1"` (`model.rs:78`), `SCHEMA_RUNTIME_CLOSURE = "frf-runtime-closure-v1"` (`model.rs:461`), `SCHEMA_BUNDLE = "frf-bundle-v3"` (`model.rs:672`), plus extension-protocol schemas at `model.rs:456-459, 725-726, 737-740, 748-751, 761-764, 772-779`.

Claim policies (`model.rs:247-256`): `CLAIM_POLICY_BASELINE="baseline"`, `CLAIM_POLICY_SENSITIVITY_BACKED`, `CLAIM_POLICY_INDEPENDENTLY_WITNESSED`, `CLAIM_POLICY_HIGH_ASSURANCE`; `CLAIM_POLICIES: &[&str]`.

Execution profiles (`model.rs:281-326`): `EXECUTION_PROFILE_LINUX="frf-exec-linux-v1"`, `_LINUX_V2`, `_LINUX_V3`, `EXECUTION_PROFILE_OCI="frf-exec-oci"`. Capability vocabulary + `profile_capabilities(profile: &str) -> Option<&'static [&'static str]>` (`model.rs:342-423`), `HIGH_ASSURANCE_CAPABILITIES` (`model.rs:429-433`).

**Authority:**
```rust
pub struct AuthorityRecord {                                      // model.rs:2417-2431
    pub schema_version: String,
    pub id: String,          // "{name}-{version}"
    pub name: String,
    pub kind: String,        // v0 admits "executable_reference" only
    pub version: String,
    pub executable_sha256: String,
    pub path: String,
    pub platform: String,    // "{arch}-{os}"
}
```

**Court question (hand-authored YAML manifest):**
```rust
pub struct CourtManifest {                                        // model.rs:2439-2477
    pub court: CourtSpec,
    #[serde(default)] pub comparators: Vec<ComparatorDeclaration>,
    #[serde(default)] pub normalizers: Vec<NormalizerDeclaration>,
    #[serde(default)] pub minimizers: Vec<MinimizerDeclaration>,
    #[serde(default)] pub capture_adapters: Vec<CaptureAdapterDeclaration>,
    #[serde(default)] pub mutations: Vec<MutationDeclaration>,
    #[serde(default)] pub capture_surface: Vec<CaptureSurfacePolicy>,
}
pub struct CourtSpec {                                            // model.rs:2743-2801
    pub id: String,
    pub question: String,
    pub falsifier: String,
    pub authority: String,          // admitted authority id
    pub candidate: CandidateSpec,
    pub fixture: FixtureSpec,
    pub admissibility_envelope: AdmissibilityEnvelope,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub produce: Option<ProduceSpec>,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub execution_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub environment: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub environment_points: Option<BTreeMap<String, BTreeMap<String, String>>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_context: Option<ExecutionContextDeclaration>,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub execution_image: Option<String>,
}
pub struct CandidateSpec { name, version_or_commit, build_profile, path: String }   // model.rs:2818-2824
pub struct FixtureSpec   { id, path: String, arguments: Vec<String> }               // model.rs:2828-2834
pub struct AdmissibilityEnvelope { fixture_family, platforms, observables, normalizers: Vec<String>, replay_scope: String } // model.rs:2838-2844
```
`CourtSpec` fields are all `pub`, so a manifest can be constructed in memory; but the court runner reads it from a **YAML file on disk** via `Store::parse_yaml` (see §3).

**Capture:**
```rust
pub struct CaptureManifest {                                      // model.rs:2882-2979
    pub schema_version: String,
    pub run: String,
    pub court: String,
    pub authority: String,
    pub manifest: String,
    pub fixture: String,
    pub fixture_sha256: String,
    pub arguments: Vec<String>,
    pub environment: EnvironmentIdentity,
    pub court_spec: CourtSpec,
    pub comparator_semantics: Vec<ComparatorSemantic>,
    #[serde(default)] pub normalizer_semantics: Vec<NormalizerSemantic>,
    #[serde(default)] pub adapter_semantics: Vec<CaptureAdapterSemantic>,
    #[serde(default)] pub minimizer_semantics: Vec<MinimizerSemantic>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_surface: Option<Vec<CaptureSurfacePolicy>>,
    pub provenance: ObservationProvenance,
    pub authority_artifact: ArtifactIdentity,
    pub candidate_artifact: ArtifactIdentity,
    pub court_semantic_identity: String,
    pub execution_profile: String,
    pub capture_bounds: CaptureBounds,
    pub observation_identity: String,
    pub execution_identity: String,
    pub reference: SideCapture,
    pub candidate: SideCapture,
    pub residuals: Vec<String>,          // residual ids
    #[serde(default, skip_serializing_if = "Vec::is_empty")] pub harness_events: Vec<String>,
    #[serde(default)] pub evidence_refs: Vec<EvidenceRef>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_context: Option<ExecutionContextClosure>,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub container_image: Option<OciImage>,
}
pub struct SideCapture {                                          // model.rs:3460-3497
    pub exit: String, pub exit_sha256: String,
    pub stderr_first_line: String, pub stderr_first_line_sha256: String,
    pub stdout_first_line: String, pub stdout_first_line_sha256: String,
    pub stdout_sha256: String, pub stderr_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub produced: Option<ProducedSide>,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub adapted: Option<AdaptedObservation>,
    #[serde(skip_serializing, default)] pub stdout_bytes: Vec<u8>,   // memory-only
    #[serde(skip_serializing, default)] pub stderr_bytes: Vec<u8>,   // memory-only
}
impl SideCapture { pub fn stdout(&self) -> &[u8] }                // model.rs:3522-3524
pub struct RunnerIdentity { schema_version, frf_version, frf_executable_hash: String }  // model.rs:2987-2991
pub struct CaptureBounds {                                        // model.rs:484-523
    pub timeout_ms: String, pub max_stream_bytes: String,
    pub produced_max_files: String, pub produced_max_bytes: String, pub produced_max_file_bytes: String,
    pub rlimit_as_mb: String, pub rlimit_cpu_s: String, pub rlimit_nofile: String, pub rlimit_nproc: String,
    #[serde(skip_serializing_if = "Option::is_none")] pub cgroup_pids_max: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub cgroup_memory_max: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub cgroup_cpu_max: Option<String>,
}
pub fn validate_capture_bounds(b: &CaptureBounds) -> crate::error::Result<()>   // model.rs:545
pub struct EvidenceRef { role, object_kind, cid: String }         // model.rs:2858-2867
pub struct ArtifactIdentity {                                     // model.rs:3196-3207
    pub path: String, pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")] pub interpreter: Option<InterpreterIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")] pub native_runtime: Option<NativeRuntimeClosure>,
}
```

**Observables / residual kinds — open protocol identifiers (not closed enums):**
```rust
pub struct ObservableId(String);                                  // model.rs:1729
impl ObservableId {
    pub fn exit() -> Self                                         // model.rs:1733
    pub fn stderr() -> Self                                       // model.rs:1737
    pub fn stdout() -> Self                                       // model.rs:1741
    pub fn parse(s: &str) -> crate::error::Result<Self>           // model.rs:1749
    pub fn as_str(&self) -> &str                                  // model.rs:1754
    pub fn is_builtin(&self) -> bool                              // model.rs:1759
}
pub struct ResidualKind(String);                                  // model.rs:1799
impl ResidualKind {
    pub fn exit() -> Self                                         // model.rs:1803
    pub fn text() -> Self                                         // model.rs:1808
    pub fn parse(s: &str) -> crate::error::Result<Self>           // model.rs:1814
    pub fn as_str(&self) -> &str                                  // model.rs:1819
    pub fn schema(&self) -> Option<&'static KindSchema>           // model.rs:1827
}
pub struct KindSchema { pub id: &'static str, pub meaning: &'static str,
                        pub surface_grammar: &'static str, pub comparator_family: &'static str }  // model.rs:1841-1846
pub const KIND_SCHEMAS: &[KindSchema]                             // model.rs:1854-1879 (exit, text, wire, latency)
```

**Residual + disposition:**
```rust
pub struct ResidualRecord {                                       // model.rs:3573-3594
    pub schema_version: String, pub id: String, pub court: String, pub run: String,
    pub axis: ObservableId, pub kind: ResidualKind,
    #[serde(skip_serializing_if = "Option::is_none")] pub surface: Option<String>,
    pub authority: String, pub scope: String, pub candidate_sha256: String,
    pub raw_reference: String, pub raw_candidate: String,
    pub raw_reference_sha256: String, pub raw_candidate_sha256: String,
}
pub enum ClosureKind { Intentional, Environmental, OracleVersion, Harness, Unknown }  // model.rs:1924-1930
impl ClosureKind { pub const ALL: [ClosureKind; 5]; pub const fn as_str(self) -> &'static str;
                   pub fn parse(s: &str) -> Option<Self>; pub const fn blocks_claim(self) -> bool } // model.rs:1932-1960
pub enum Disposition {                                            // model.rs:2004-2025
    Open,
    Closed { kind: ClosureKind, reason: String },
    Fixed   { reason: String, resolution_run_id: String, closure_predicate: String },
    Nonreproduced { reason: String, observation_run_id: String },
    Stabilized { reason: String, trajectory_id: String, consecutive_passes: String, stabilization_bound: String },
}
impl Disposition {                                                // model.rs:2027-2092
    pub fn as_str(&self) -> &'static str
    pub fn reason(&self) -> Option<&str>
    pub fn resolution_run_id(&self) -> Option<&str>
    pub fn observation_run_id(&self) -> Option<&str>
    pub fn trajectory_id(&self) -> Option<&str>
    pub fn is_blocking(&self) -> bool
}
pub struct DispositionEvent {                                     // model.rs:3609-3627
    pub schema_version: String,
    pub event_id: String,                // content address, filled by Store::append_disposition_event
    pub residual_id: String,
    pub parent_event_id: Option<String>,
    #[serde(flatten)] pub disposition: Disposition,
    pub evidence_refs: Vec<String>,
}
impl DispositionEvent {                                           // model.rs:3839-3967
    pub fn closed(residual_id: &str, kind: ClosureKind, reason: String) -> crate::error::Result<Self>
    pub fn fixed(residual_id: &str, reason: String, resolution_run_id: String, closure_predicate: String) -> crate::error::Result<Self>
    pub fn nonreproduced(residual_id: &str, reason: String, observation_run_id: String) -> crate::error::Result<Self>
    pub fn stabilized(residual_id: &str, reason: String, trajectory_id: String, consecutive_passes: String, stabilization_bound: String) -> crate::error::Result<Self>
}
pub const CLOSURE_PREDICATE_FIX_COURT: &str = "fix-court: same court, authority, fixture, arguments, observables, normalizers, environment; candidate artifact identity changed; axis equality"; // model.rs:1967
pub const STABILIZATION_MIN_CONSECUTIVE_PASSES: u32 = 2;         // model.rs:1973
```

**Endoduction token (κ):**
```rust
pub struct TokenRecord {                                          // model.rs:3992-4005
    pub schema_version: String, pub residual_id: String,
    pub token: String,     // "{kind}/{surface}/{magnitude}/{disposition}"
    pub kind: ResidualKind, pub surface: String, pub authority: String,
    pub magnitude: String, pub scope: String, pub disposition: String,
    pub next_court: String, pub blocks_claims: Vec<String>,
}
```
Pure functions in `frf::kappa` (`src/kappa.rs`): `pub struct TokenShape { surface, magnitude, next_court: String }` (`kappa.rs:29-33`); `pub fn token_shape(axis: &ObservableId) -> TokenShape` (`kappa.rs:39`); `pub fn blocks_claims(axis: &ObservableId, scope: &str) -> Vec<String>` (`kappa.rs:96`); `pub fn kappa(r: &ResidualRecord, disposition: &Disposition) -> TokenRecord` (`kappa.rs:111`); `pub fn grammar_state(disposition: &Disposition) -> &'static str` (`kappa.rs:148`).

**Receipt:**
```rust
pub struct Receipt {                                              // model.rs:5377-5418
    #[serde(deserialize_with = "expect_receipt_schema")] pub schema_version: String,
    pub run: String,                        // the reproduction target (run id)
    pub court: ReceiptCourt,
    pub provenance: ObservationProvenance,
    pub comparator_semantics: Vec<ComparatorSemantic>,
    #[serde(default)] pub normalizer_semantics: Vec<NormalizerSemantic>,
    #[serde(default)] pub adapter_semantics: Vec<CaptureAdapterSemantic>,
    pub execution_profile: String,
    pub capture_bounds: CaptureBounds,
    pub authority: ReceiptAuthority,
    pub candidate: ReceiptCandidate,
    pub environment: EnvironmentIdentity,
    pub fixtures: Vec<ReceiptFixture>,
    pub observables: Vec<ReceiptObservable>,
    pub residuals: Vec<ReceiptResidual>,
    pub endoduction: ReceiptEndoduction,
    pub claims: ReceiptClaims,
    pub replay: ReceiptReplay,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_context: Option<ExecutionContextClosure>,
}
pub struct ReceiptResidual {                                      // model.rs:5605-5651
    pub id: String, pub axis: String, pub kind: ResidualKind,
    pub sign: ResidualSign,
    pub grammar_state: String,
    pub raw_reference_hash: String, pub raw_candidate_hash: String,
    #[serde(deserialize_with = "expect_disposition_str")] pub disposition: String,
    pub disposition_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub resolution_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub closure_predicate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub observation_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub trajectory_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub consecutive_passes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub stabilization_bound: Option<String>,
    pub reproducer: String, pub invariant: String, pub residual_fingerprint: String,
}
pub struct ReceiptObservable { axis, raw_reference_hash, raw_candidate_hash, comparator, normalization_rules: Vec<String>, verdict: ObservableVerdict, comparator_request: Option<String>, comparator_result: Option<String> }  // model.rs:5543-5560
pub enum ObservableVerdict { Pass, Residual }                     // model.rs:5564-5567
pub struct ReceiptEndoduction { schema_version: String, tokens: Vec<ReceiptToken> }   // model.rs:5655-5658
pub struct ReceiptToken { residual_id: String, token: String, next_court: String, blocks_claims: Vec<String> }  // model.rs:5662-5667
pub struct ReceiptClaims { positive: Vec<String>, non_claims: Vec<String>, blocked_by_open_residuals: Vec<String> }  // model.rs:5674-5678
pub struct ReceiptReplay { program: String, evidence_root: String, argv: Vec<String>, expected_run_identity: String }  // model.rs:5685-5694
pub struct TrajectoryEvidence { coordinate_system: String, series: String, drift: String, slew: String }  // model.rs:5576-5585
pub struct ResidualSign { #[serde(default)] pub trajectory_evidence: Vec<TrajectoryEvidence> }  // model.rs:5598-5601
```

**Claim IR:**
```rust
pub struct ClaimScope {                                           // model.rs:5710-5735
    pub authority: Vec<String>, pub candidate: Vec<String>, pub fixtures: Vec<String>,
    pub fixture_family: String, pub observables: Vec<String>,
    pub environments: Vec<String>, pub versions: Vec<String>, pub temporal: Vec<String>,
}
impl ClaimScope { pub fn intersects(&self, other: &ClaimScope) -> bool; pub fn contains(&self, other: &ClaimScope) -> bool }  // model.rs:5752-5775
pub struct EvidenceRegion { pub cells: Vec<ClaimScope> }          // model.rs:5791
impl EvidenceRegion { pub fn empty() -> Self; pub fn cell(scope: ClaimScope) -> Self;
                      pub fn push(&mut self, cell: ClaimScope); pub fn contains(&self, k: &ClaimScope) -> bool;
                      pub fn intersects(&self, surface: &ClaimScope) -> bool }  // model.rs:5799-5831
pub struct ClaimRecord {                                          // model.rs:5908-6009
    pub id: String, pub schema_version: String, pub receipt: String, pub authority: String,
    pub candidate: ClaimCandidate, pub court: String, pub fixture_family: String,
    pub environment: String, pub relation: String, pub proposition: String,
    pub scope: EvidenceRegion, pub observable_scope: Vec<String>,
    pub blockers: Vec<String>, pub excluded_evidence: Vec<String>, pub requires: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")] pub trajectory_premises: Vec<TrajectoryPremise>,
    pub transform: EvidenceTransform, pub knowledge_snapshot: KnowledgeSnapshot,
    pub policy: String, #[serde(default)] pub mutation_profile: Vec<String>,
    #[serde(default)] pub capability: Vec<ClaimCapability>,
    #[serde(default)] pub witness_statements: Vec<String>,
    #[serde(default)] pub independence_evidence: Vec<String>,
    pub replay_profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")] pub required_capabilities: Vec<String>,
}
pub struct KnowledgeSnapshot { schema_version: String, cid: String, residual_heads: Vec<SnapshotResidualHead>, objects: Vec<SnapshotObject> }  // model.rs:6107-6116
pub struct TrajectoryPremise { lineage, axis, coordinate_system, series, trajectory, drift, slew, localization, bands: String, onset: Option<String>, cessation: Option<String> }  // model.rs:6024-6049
```

**Trajectory / series (see §4 for the API):**
```rust
pub struct ExecutionSeries { schema_version, id, experiment_id, parent_series_id: Option<String>, court, coordinate_system: String, points: Vec<SeriesPoint> }  // model.rs:4564-4579
pub struct SeriesPoint { point_index: String, coordinate: String, coordinate_identity: String, run: String }  // model.rs:4583-4599
pub struct TrajectoryRecord { schema_version, id, subject, axis, coordinate_system, series: String, observations: Vec<TrajectoryObservation>, derivation: TrajectoryDerivation, transform: EvidenceTransform }  // model.rs:4279-4300
pub struct TrajectoryObservation { point_index, coordinate, coordinate_identity, run: String, observed: bool, residual: Option<String>, fingerprint: Option<String>, magnitude: Option<String> }  // model.rs:4241-4266
pub struct TrajectoryDerivation { drift: TrajectoryDrift, slew: TrajectorySlew, localization: TrajectoryLocalization, bands: String, trend: TrajectoryTrend, magnitude_kind: String }  // model.rs:4217-4233
pub enum TrajectoryDrift { Persistent, Transient, Recurrent, BoundaryLocalized, VersionStratified }   // model.rs:4019-4038
pub enum TrajectorySlew { Stable, Abrupt, Burst, Recurrent, Gradual }                                  // model.rs:4070-4082
pub enum TrajectoryLocalization { None_, Start, End, Both, Interior }                                  // model.rs:4117-4129
pub enum TrajectoryTrend { Flat, Increasing, Decreasing, NonMonotonic, Unknown }                       // model.rs:4167-4179
```
Each of the four enums has `pub const ALL: [T; N]`, `pub const fn as_str(self) -> &'static str`, `pub fn parse(s: &str) -> Option<Self>` (e.g. `model.rs:4041-4065`).

```rust
pub struct EvidenceTransform { kind, source: String, varying_dimensions: Vec<String>, invariant_dimensions: Vec<String>, observation_relation: String, success_predicate: String }  // model.rs:4434-4453
impl EvidenceTransform { pub fn observation(run: &str, relation: &str) -> Self;
    pub fn resolution(run: &str, relation: &str) -> Self; pub fn replay(run: &str, relation: &str) -> Self;
    pub fn reduction(residual: &str, relation: &str) -> Self; pub fn trajectory(series: &str, relation: &str) -> Self;
    pub fn claim(receipt: &str, relation: &str) -> Self }        // model.rs:4457-4553
```

**Witness / mutation / comparator / normalizer extension types** (all `pub struct`, serde `deny_unknown_fields`): `WitnessSemantic`, `WitnessImplementation`, `WitnessSubject {kind, id, cid}`, `WitnessRequest<'a>`, `WitnessContext<'a> {evidence_root}`, `WitnessResponse`, `WitnessAuthority`, `WitnessAttestation {statement, outcome, detail}`, `WitnessIdentity`, `WitnessStatement` (`model.rs:1485-1624`); `IndependenceEvidence` (`model.rs:1636-1660`), `INDEPENDENCE_RELATIONS: &[&str] = ["different-implementation", "separate-party", "unaffiliated-channel", "adversarial-review"]` (`model.rs:786-791`). `MutationSemantic`, `MutationRequest<'a>`, `MutationResponse`, `MutationInvocation`, `MutationResult`, `MutationEvidence` (`model.rs:2730-3368`). `ComparatorSemantic` (`model.rs:3012-3031`, with `relation_label()` at `model.rs:3036`), `ComparatorImplementation` (`model.rs:3051-3061`), `ComparatorRequest<'a>`/`ComparatorObservation<'a>`/`ComparatorContext<'a>`/`ComparatorResponse`/`ComparatorResidual` (`model.rs:5069-5168`), `ComparatorInvocation`/`ComparatorResult`/`ComparatorEvidence` (`model.rs:5187-5240`). `NormalizerSemantic`/`NormalizerImplementation`/`NormalizerRequest`/`NormalizerResponse`/`NormalizerInvocation`/`NormalizerResult` (`model.rs:811-902`). `CourtChallenge` (`model.rs:5017-5058`). `Minimizer*` (`model.rs:912-1376`), `ReductionRecord` (`model.rs:4761-4819`), `ReductionAttempt`/`ReductionDerivation`/`ReductionMinimality` (`model.rs:4665-4747`). `Unverified<T>` marker (`model.rs:49-69`).

### 2.3 `frf::store` — `Store` (`src/store.rs`, 3125 lines)

```rust
pub struct Store { pub root: PathBuf }                            // store.rs:102-104
impl Store {
    pub fn new(root: PathBuf) -> Self                             // store.rs:107
    pub fn ensure_tree(&self) -> Result<()>                       // store.rs:114  (creates authorities/ captures/ objects/ residuals/ series/ trajectories/ reductions/ receipts/ claims/ witnesses/ independence/ harness — NOT courts/)
    // path builders (validate id → root-relative path):
    pub fn authority_path(&self, id: &str) -> Result<PathBuf>     // store.rs:143
    pub fn run_dir(&self, run: &str) -> Result<PathBuf>           // store.rs:148
    pub fn residual_path(&self, id: &str) -> Result<PathBuf>      // store.rs:687
    pub fn residual_leaf_path(&self, run: &str, id: &str) -> Result<PathBuf>  // store.rs:694
    pub fn receipt_path(&self, id: &str) -> Result<PathBuf>       // store.rs:714
    pub fn claim_path(&self, id: &str) -> Result<PathBuf>         // store.rs:729
    pub fn object_path(&self, sha256: &str) -> Result<PathBuf>    // store.rs:1829
    pub fn trajectory_path(&self, lineage: &str, coordinate_system: &str, series: &str) -> Result<PathBuf>  // store.rs:1599
    pub fn series_path(&self, id: &str) -> Result<PathBuf>        // store.rs:1635
    // loaders (raw parse; identity NOT yet re-derived — see §2.8):
    pub fn load_authority(&self, id: &str) -> Result<AuthorityRecord>                  // store.rs:2289
    pub fn load_residual(&self, id: &str) -> Result<Unverified<ResidualRecord>>        // store.rs:2312
    pub fn load_capture(&self, run: &str) -> Result<Unverified<CaptureManifest>>       // store.rs:2467
    pub fn load_receipt(&self, id: &str) -> Result<Unverified<Receipt>>                // store.rs:2481
    pub fn load_series(&self, id: &str) -> Result<ExecutionSeries>                     // store.rs:1641
    pub fn load_trajectory(&self, lineage: &str, coordinate_system: &str, series: &str) -> Result<TrajectoryRecord>  // store.rs:1615
    pub fn load_claim(&self, id: &str) -> Result<ClaimRecord>                          // store.rs:772
    pub fn load_challenge(&self, id: &str) -> Result<CourtChallenge>                   // store.rs:1428
    pub fn load_reduction(&self, id: &str) -> Result<ReductionRecord>                  // store.rs:1490
    pub fn load_witness_statement(&self, id: &str) -> Result<WitnessStatement>         // store.rs:1229
    pub fn load_independence(&self, id: &str) -> Result<IndependenceEvidence>          // store.rs:1357
    // dispositions:
    pub fn disposition_events(&self, id: &str) -> Result<Vec<DispositionEvent>>        // store.rs:2126
    pub fn current_disposition(&self, id: &str) -> Result<Disposition>                 // store.rs:2175
    pub fn append_disposition_event(&self, partial: &DispositionEvent) -> Result<DispositionEvent>  // store.rs:2197
    pub fn append_disposition_event_cas(&self, residual_id: &str, partial: &DispositionEvent) -> Result<DispositionEvent>  // store.rs:2265
    pub fn write_token(&self, record: &ResidualRecord, disposition: &Disposition) -> Result<()>  // store.rs:2107
    // claims / universe:
    pub fn write_claim(&self, claim: &ClaimRecord) -> Result<()>                       // store.rs:804
    pub fn claim_ids_for_receipt(&self, receipt_id: &str) -> Result<Vec<String>>       // store.rs:753
    pub fn knowledge_snapshot(&self) -> Result<KnowledgeSnapshot>                      // store.rs:854
    // series helpers:
    pub fn write_series(&self, series: &ExecutionSeries) -> Result<()>                 // store.rs:1672
    pub fn experiment_ids(&self) -> Result<Vec<String>>                                // store.rs:1701
    pub fn experiment_heads(&self, experiment_id: &str) -> Result<Vec<ExecutionSeries>>  // store.rs:1730
    pub fn series_depth(&self, id: &str) -> Result<u32>                                // store.rs:1763
    pub fn series_is_descendant_of(&self, descendant: &str, ancestor: &str) -> Result<bool>  // store.rs:1781
    pub fn series_containing_run(&self, run: &str) -> Result<Vec<ExecutionSeries>>     // store.rs:1803
    // objects:
    pub fn materialize_object(&self, bytes: &[u8], executable: bool) -> Result<PathBuf>  // store.rs:1926
    pub fn verified_object_bytes(&self, sha256: &str) -> Result<Vec<u8>>               // store.rs:1840
    pub fn object_availability(&self, sha256: &str) -> Result<ObjectAvailability>      // store.rs:1895
    // serialization:
    pub fn to_evidence<T: serde::Serialize>(&self, value: &T) -> Result<String>        // store.rs:1992 (canonical JSON)
    pub fn parse_evidence<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<T>  // store.rs:2001
    pub fn parse_yaml<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<T> // store.rs:2012
    pub fn write_once(&self, path: &Path, contents: &str) -> Result<()>                // store.rs:2023 (fails if exists)
    pub fn write_derived(&self, path: &Path, contents: &str) -> Result<()>             // store.rs:2101 (may overwrite)
    pub fn commit_content_addressed(&self, path: &Path, contents: &str) -> Result<()>  // store.rs:2060
}
pub fn is_valid_id(id: &str) -> bool; pub fn validate_id(what: &str, id: &str) -> Result<()>  // store.rs:55-73
```
`pub(crate) fn derive_lineage_trajectory(store: &Store, series: &ExecutionSeries, lineage: &str) -> Result<TrajectoryRecord>` — **not public** (`store.rs:2834`); trajectories are produced through `commands::court::run` series mode.

### 2.4 `frf::commands` — every verb, callable in-process (`src/commands/mod.rs:19`)

```rust
pub fn dispatch(store: &Store, command: Command) -> Result<()>    // commands/mod.rs:19
```
`pub mod`s: `admit, bundle, claim, court, dispose, evidence, receipt, replay, witness` (`commands/mod.rs:4-12`).

- `admit::run(store: &Store, path: &Path, name: &str, version: &str, kind: &str) -> Result<String>` — returns the authority id `{name}-{version}` (`commands/admit.rs:23`, id built at `commands/admit.rs:53`). Refuses non-`executable_reference` kind (`admit.rs:24-28`), non-executable files on unix (`admit.rs:45-50, 84-89`), and re-admission (`admit.rs:55-60`).
- `court::run(store: &Store, manifest_path: &Path, opts: &SeriesOptions) -> Result<String>` — returns the **run id** (`commands/court.rs:284`).
- `court::run_once(store: &Store, manifest_path: &Path, candidate_override: Option<&str>, authority_version_override: Option<&str>, reuse: bool, point_environment: Option<&BTreeMap<String, String>>) -> Result<String>` (`commands/court.rs:1619`).
- `court::minimize(store: &Store, residual_id: &str) -> Result<String>` (`commands/court.rs:628`); `court::challenge(store: &Store, manifest_path: &Path, operators_arg: Option<&str>) -> Result<Vec<String>>` (`commands/court.rs:3357`).
- `receipt::run(store: &Store, run: &str) -> Result<String>` — returns the **receipt id** (`commands/receipt.rs:25`).
- `dispose::run(store: &Store, id: &str, disposition: ClosureArg, reason: &str, resolution_run: Option<String>, observation_run: Option<String>, trajectory: Option<String>, consecutive_passes: Option<u32>) -> Result<()>` (`commands/dispose.rs:48`).
- `claim::run(store: &Store, receipt_ids: &[String], json: bool, policy: &str, mutation_profile: &str, trajectory_keys: &[String]) -> Result<()>` — writes the claim, prints `claim {id}` on stdout (`commands/claim.rs:417`, `commands/claim.rs:950`).
- `replay::run(store: &Store, id: &str, policy_str: &str, side_cwd: &Path) -> Result<()>` (`commands/replay.rs:318`); `ReplayPolicy::{Exact, Semantic}` + `parse` (`commands/replay.rs:45-67`).
- `bundle::export(store: &Store, receipt_id: &str, output: &Path, container: Container) -> Result<PathBuf>` (`commands/bundle.rs:1145`), `bundle::verify(bundle_root: &Path) -> Result<()>` (`commands/bundle.rs:1247`), `bundle::replay_bundle(bundle_path: &Path, policy: &str) -> Result<()>` (`commands/bundle.rs:1382`).
- `witness::attest(store: &Store, subject_kind: &str, subject_id: &str, id: &str, relation: &str, relation_version: &str, program: &str, statement: &str) -> Result<String>` (`commands/witness.rs:29`), `witness::declare_independence(store: &Store, statement_id: &str, relation: &str, relation_version: &str, basis: &str, detail: Option<&str>) -> Result<String>` (`commands/witness.rs:317`).
- `evidence::status(store: &Store) -> Result<()>` (`commands/evidence.rs:39`), `evidence::publish_detached(source: &Store, policy: &Path, output: &Path) -> Result<PathBuf>` (`commands/evidence.rs:188`).

### 2.5 `frf::host` — execution harness (`src/host.rs`, 3195 lines)

```rust
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(60);       // host.rs:40
pub const EXEC_MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;        // host.rs:45
pub const EXEC_PRODUCED_MAX_FILES: u64 = 4096;                    // host.rs:51
pub const EXEC_RLIMIT_AS_MB: u64 = 2048; pub const EXEC_RLIMIT_CPU_S: u64 = 30;
pub const EXEC_RLIMIT_NOFILE: u64 = 1024; pub const EXEC_RLIMIT_NPROC: u64 = 4096;  // host.rs:66-76
pub enum ExecProfile { LinuxV1, LinuxV2, LinuxV3, Oci }           // host.rs:96-106
impl ExecProfile { pub fn parse(s: &str) -> crate::error::Result<Self>; pub fn as_str(self) -> &'static str }  // host.rs:107-135
pub struct ExecImage { … }                                        // host.rs:194-204 (sealed memfd image)
impl ExecImage { pub fn seal(bytes: &[u8], expected_sha256: &str, argv0: &Path) -> Result<ExecImage>;
                 pub fn from_path(path: &Path) -> ExecImage; pub fn path(&self) -> &Path;
                 pub fn argv0(&self) -> &Path }                   // host.rs:205-285
pub struct ProcessOutcome { pub stdout: Vec<u8>, pub stderr: Vec<u8>, pub exit: String, pub violation: Option<Box<HarnessViolation>> }  // host.rs:1053-1059
pub struct HarnessViolation { event_kind: &'static str, target, cap, observed, detail: String }  // host.rs:1003-1013
pub struct RunError { pub message: String, pub violation: Option<Box<HarnessViolation>> }        // host.rs:1022-1038
pub fn run_process(image: &ExecImage, args: &[String], profile: ExecProfile, env: &BTreeMap<String, String>, container: Option<&OciImage>) -> std::result::Result<ProcessOutcome, RunError>  // host.rs:1070
pub fn run_process_in(image: &ExecImage, args: &[String], cwd: &Path, profile: ExecProfile, env: &BTreeMap<String, String>, container: Option<&OciImage>) -> …  // host.rs:1081
pub fn run_process_with_stdin(image: &ExecImage, args: &[String], stdin: &[u8], profile: ExecProfile, env: &BTreeMap<String, String>, container: Option<&OciImage>) -> …  // host.rs:1093
pub fn run_process_with_stdin_in(image: &ExecImage, args: &[String], stdin: &[u8], cwd: &Path, profile: ExecProfile, env: &BTreeMap<String, String>, container: Option<&OciImage>) -> …  // host.rs:1115
pub fn run_process_closed(image: &ExecImage, args: &[String], cwd: Option<&Path>, profile: ExecProfile, env: &BTreeMap<String, String>, sandbox: &crate::sandbox::IoClosedSandbox) -> …  // host.rs:1142
pub fn extension_profile(side_profile: ExecProfile) -> ExecProfile  // host.rs:1159 (OCI/v3 side → v1 for extension programs)
pub fn reference_capture_bounds() -> CaptureBounds                 // host.rs:904
pub fn capture_bounds(profile: ExecProfile) -> CaptureBounds       // host.rs:931 (reads FRF_EXEC_* env overrides)
pub fn environment_identity(environment: &BTreeMap<String, String>) -> EnvironmentIdentity  // host.rs:2049
pub fn sha256_bytes(bytes: &[u8]) -> String; pub fn sha256_file(path: &Path) -> Result<String>;
pub fn current_exe_hash() -> Result<String>; pub fn is_sha256_hex(s: &str) -> bool; pub fn read_file(path: &Path) -> Result<Vec<u8>>  // host.rs:955-984
pub fn interpreter_identity(artifact: &[u8]) -> Result<Option<InterpreterIdentity>>  // host.rs:2094
```
Env-var overrides read at runtime: `FRF_EXEC_TIMEOUT_MS`, `FRF_EXEC_MAX_BYTES`, `FRF_EXEC_PRODUCED_MAX_FILES/BYTES/FILE_BYTES`, `FRF_EXEC_RLIMIT_*` (`host.rs:790-894`), plus `FRF_ROOT` (cli) and `FRF_PRINT_SELF_CPU` (commands/mod.rs:73).

### 2.6 `frf::comparators`, `frf::normalizers`, `frf::mutation`, `frf::trajectory`

`frf::comparators` (`src/comparators.rs`):
```rust
pub struct ComparatorSpec { pub id: &'static str, pub relation: &'static str, pub extractor: &'static str, pub residual_classifier: &'static str }  // comparators.rs:44-57
pub const SPECS: &[ComparatorSpec]                                 // comparators.rs:58+ (exit, stderr, stdout, filesystem.tree, bytes.wire, structured.state)
pub fn spec_for(id: &str) -> Option<&'static ComparatorSpec>       // comparators.rs:95
pub fn magnitude_kind(axis: &str) -> String                        // comparators.rs:131
pub fn divergence_magnitude(axis: &str, raw_reference: &str, raw_candidate: &str) -> Option<String>  // comparators.rs:145
pub fn specification_hash(id: &str, relation: &str, extractor: &str, residual_classifier: &str, relation_version: &str) -> Result<String>  // comparators.rs:201
pub fn semantic(id: &str) -> Result<ComparatorSemantic>            // comparators.rs:219
pub fn declared_semantic(decl: &ComparatorDeclaration) -> Result<ComparatorSemantic>  // comparators.rs:247
pub enum ComparatorOutcome { Equivalent, Divergent(Vec<(Option<String>, String, String)>), Indeterminate }  // comparators.rs:286-296
pub fn interpret(response: &ComparatorResponse, expected_request_id: &str) -> Result<ComparatorOutcome>  // comparators.rs:312
pub enum BuiltinKind { Exit, Stderr, Stdout, Tree, Bytes, Json }   // comparators.rs:429-439
impl BuiltinKind { pub fn from_id(id: &str) -> Option<Self>; pub fn as_str(self) -> &'static str;
                   pub fn surface(self) -> Option<&'static str>; pub fn capture_requirements(self) -> Vec<CaptureRequirement>;
                   pub fn project(self, side: &SideCapture) -> String; pub fn compare(self, reference: &SideCapture, candidate: &SideCapture, …) -> Result<…> }  // comparators.rs:444-520
pub fn build_request<'a>(axis: &'a str, semantic: &'a ComparatorSemantic, reference: &'a ProcessOutcome, candidate: &'a ProcessOutcome, reference_adapted: Option<&'a AdaptedObservation>, candidate_adapted: Option<&'a AdaptedObservation>, fixture_sha256: &'a str, arguments: &'a [String], environment_digest: &'a str, produced: Option<(...)>) -> …  // comparators.rs:757
pub fn canonical_request(request: &ComparatorRequest) -> Result<(Vec<u8>, String)>  // comparators.rs:810
pub fn run_external(image: &host::ExecImage, axis: &ObservableId, request_bytes: &[u8], request_cid: &str, cwd: &Path, profile: host::ExecProfile, env: &BTreeMap<String, String>) -> Result<(ComparatorOutcome, Vec<u8>)>  // comparators.rs:823
pub struct EvaluationPlan { pub axis: ObservableId, pub semantic: ComparatorSemantic, pub implementation: ComparatorImplementation }  // comparators.rs:905-921
impl EvaluationPlan { pub fn from_capture(capture: &CaptureManifest, axis: &ObservableId) -> Result<EvaluationPlan>; pub fn capture_requirements(&self) -> Vec<CaptureRequirement> }  // comparators.rs:922-959
pub struct EvaluationContext<'a> { pub fixture_sha256: &'a str, pub arguments: &'a [String], pub environment_digest: &'a str, pub produced: Option<(&'a ProducedSide, &'a ProducedSide)>, pub cwd: &'a Path, pub raw: Option<…> }  // comparators.rs:974-984
pub enum EvaluationResult { Pass, Divergent(Vec<(Option<String>, String, String)>) }  // comparators.rs:1006-1012
pub struct Evaluation { pub result: EvaluationResult, pub evidence: Option<EvaluationEvidence> }  // comparators.rs:1029-1032
pub fn evaluate(store: &Store, plan: &EvaluationPlan, reference: &SideCapture, candidate: &SideCapture, context: &EvaluationContext) -> Result<Evaluation>  // comparators.rs:1051
pub fn runner_identity() -> Result<RunnerIdentity>                // comparators.rs:1154
```

`frf::normalizers` (`src/normalizers.rs`): `declared_semantic(decl: &NormalizerDeclaration) -> Result<NormalizerSemantic>` (`normalizers.rs:32`), `build_request<'a>(semantic, side, stdout, stderr, fixture_sha256, arguments, environment_digest) -> NormalizerRequest<'a>` (`normalizers.rs:52`), `canonical_request(request) -> Result<(Vec<u8>, String)>` (`normalizers.rs:76`), `interpret(response, expected_request_id, applies_to, raw_stdout, raw_stderr) -> Result<(Vec<u8>, Vec<u8>)>` (`normalizers.rs:85`), `run_side(...) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)>` (`normalizers.rs:145`), `record_evidence(...) -> Result<(NormalizerInvocation, NormalizerResult)>` (`normalizers.rs:178`), `apply_capture_normalizers(store, capture, side, raw_outcome, verify_request_cids, cwd, profile, env) -> Result<host::ProcessOutcome>` (`normalizers.rs:244`).

`frf::mutation` (`src/mutation.rs`): `pub enum MutationOperator { ExitClass, StderrFirstLine, StdoutFirstLine }` (`mutation.rs:45-67`) with `target_axis()`, `from_axis(axis) -> Option<Self>`, `as_str()`, `parse(id) -> Result<Self>`, `wrapper(reference_sha256) -> String` (`mutation.rs:68-113`).

`frf::trajectory` (`src/trajectory.rs`): `pub const STRATIFIED_AXES: &[&str] = &["authority_version", "candidate_revision"]` (`trajectory.rs:55`) and:
```rust
pub fn classify(observed: &[bool], coordinate_system: &str, magnitudes: &[Option<String>], magnitude_kind: &str) -> Result<TrajectoryDerivation>  // trajectory.rs:66
```

`frf::scope` (`src/scope.rs`): `premise_scope(r: &Receipt) -> ClaimScope` (`scope.rs:24`), `claim_scope(r: &Receipt) -> ClaimScope` (`scope.rs:52`), `residual_scope(record: &ResidualRecord, capture: &CaptureManifest, authority_version: &str) -> ClaimScope` (`scope.rs:70`), `claim_region(receipts: &[&Receipt]) -> EvidenceRegion` (`scope.rs:99`), `premise_region(receipts: &[&Receipt]) -> EvidenceRegion` (`scope.rs:110`), `region_observables(region: &EvidenceRegion) -> Vec<String>` (`scope.rs:119`).

`frf::canon` (`src/canon.rs`): `pub fn canonical<T: Serialize>(value: &T) -> Result<String>` (`canon.rs:41`), `pub fn encode(value: &Value) -> Result<String>` (`canon.rs:49`), `pub fn parse_strict(bytes: &[u8]) -> Result<Value>` (`canon.rs:199`), `pub fn require_canonical_bytes(bytes: &[u8], what: &str) -> Result<()>` (`canon.rs:212`).

`frf::ext` (`src/ext.rs`): `pub struct ProgramSnapshot { pub impl_hash: String, pub snapshot: PathBuf, pub image: host::ExecImage, pub artifact: ArtifactIdentity }` (`ext.rs:30-40`), `pub fn snapshot_program(store: &Store, path: &Path, profile: host::ExecProfile) -> Result<ProgramSnapshot>` (`ext.rs:50`), `pub fn run_program(image: &host::ExecImage, request_bytes: &[u8], cwd: &Path, profile: host::ExecProfile, env: &BTreeMap<String, String>) -> Result<Vec<u8>>` (`ext.rs:92`), `pub fn write_evidence(store: &Store, dir: &Path, request_bytes: &[u8], response_bytes: &[u8], invocation: &serde_json::Value, result: &serde_json::Value) -> Result<()>` (`ext.rs:157`).

`frf::produced` (`src/produced.rs`): `pub struct ProducedLimits { pub max_files: u64, pub max_bytes: u64, pub max_file_bytes: u64 }` (`produced.rs:36-40`), `pub struct ProducedStaging { pub dir: PathBuf }` + `new(tag: &str)` (`produced.rs:46-60`), `pub fn capture_produced_tree(root: &Path, staging: &Path, limits: ProducedLimits) -> std::result::Result<Vec<ProducedFile>, RunError>` (`produced.rs:79`), `pub fn produced_side(files: Vec<ProducedFile>) -> Result<ProducedSide>` (`produced.rs:266`).

`frf::native` (`src/native.rs`): `pub fn is_elf(bytes: &[u8]) -> bool` (`native.rs:39`), `pub fn runtime_closure(exec_path: &Path, bytes: &[u8], profile: host::ExecProfile) -> Result<Option<NativeRuntimeClosure>>` (`native.rs:270`).

`frf::sandbox` (`src/sandbox.rs`): `pub struct IoClosedSandbox { pub read: Vec<PathBuf>, pub read_exec: Vec<PathBuf>, pub write_dir: Option<PathBuf> }` (`sandbox.rs:100-115`), `pub fn landlock_abi() -> Option<i64>` (`sandbox.rs:147`), `pub fn enforceability_error() -> Option<FrfError>` (`sandbox.rs:175`), `pub fn install(sandbox: &IoClosedSandbox) -> std::io::Result<()>` (`sandbox.rs:265`; non-Linux → error).

### 2.7 `frf::semantics` — every content identity (`src/semantics.rs`, 2111 lines)

```rust
pub fn hash_preimage(kind: &str, doc: &Value) -> Result<String>    // semantics.rs:41  (SHA-256 of "{kind}\n{canonical json}")
pub fn fixture_identity(semantic_id: &str, content_sha256: &str, declared_arguments: &[String]) -> Result<String>   // semantics.rs:54  (FRF/FIXTURE/v1)
pub fn court_semantic_identity(spec: &CourtSpec, authority_sha256: &str, fixture_sha256: &str, comparator_semantics: &[ComparatorSemantic], normalizer_semantics: &[NormalizerSemantic], adapter_semantics: &[CaptureAdapterSemantic]) -> Result<String>  // semantics.rs:294  (FRF/COURT/v2)
pub struct RunPreimage<'a> { court, authority, authority_interpreter: Option<&str>, candidate_sha256, candidate_interpreter: Option<&str>, fixture_sha256, arguments: &[String], environment_digest, runner_hash, court_semantic_identity: &'a str, reference: &'a SideCapture, candidate: &'a SideCapture, residuals: &'a [String], execution_profile: &'a str, capture_bounds: &'a CaptureBounds, comparator_implementations: &'a [ComparatorImplementation], normalizer_implementations, adapter_implementations, minimizer_implementations: &'a [...], container_image: Option<&'a OciImage>, publication_surface: Option<&'a [CaptureSurfacePolicy]> }  // semantics.rs:436-446
pub fn observation_identity(p: &RunPreimage) -> Result<String>     // semantics.rs:518  (FRF/OBSERVATION/v1)
pub fn execution_identity(p: &RunPreimage) -> Result<String>       // semantics.rs:574  (FRF/EXECUTION/v1)
pub fn run_identity(p: &RunPreimage) -> Result<String>             // semantics.rs:633  (FRF/RUN/v2)
pub fn residual_fingerprint(r: &ResidualRecord) -> Result<String>  // semantics.rs:651
pub fn residual_identity(run: &str, kind: &ResidualKind, axis: &ObservableId, surface: Option<&str>, raw_reference_sha256: &str, raw_candidate_sha256: &str) -> Result<String>  // semantics.rs:670  (FRF/RESIDUAL/v1)
pub fn residual_record_identity(r: &ResidualRecord) -> Result<String>  // semantics.rs:691
pub fn fingerprint_from_projections(kind: &ResidualKind, axis: &ObservableId, surface: Option<&str>, raw_reference: &str, raw_candidate: &str) -> Result<String>  // semantics.rs:704
pub fn residual_lineage(kind: &ResidualKind, axis: &ObservableId, surface: Option<&str>, fixture_family: &str, authority_name: &str, fixture: &str) -> Result<String>  // semantics.rs:748  (FRF/RESIDUAL-LINEAGE/v1)
pub fn residual_lineage_of_record(store: &Store, record: &ResidualRecord) -> Result<String>  // semantics.rs:771
pub fn coordinate_identity(coordinate_system: &str, value: &serde_json::Value) -> Result<String>  // semantics.rs:792  (FRF/COORDINATE/v1)
pub fn series_identity(experiment_id: &str, parent_series_id: Option<&str>, court: &str, coordinate_system: &str, points: &[SeriesPoint]) -> Result<String>  // semantics.rs:809  (FRF/SERIES/v2)
pub fn claim_identity(claim: &ClaimRecord) -> Result<String>       // semantics.rs:991  (FRF/CLAIM/v1 over doc minus id)
pub fn trajectory_identity(trajectory: &TrajectoryRecord) -> Result<String>  // semantics.rs:1010 (FRF/TRAJECTORY/v1)
pub fn record_content_identity<T: serde::Serialize>(record: &T) -> Result<String>  // semantics.rs:1029
pub fn challenge_identity(court: &str, operator: &str, target_axis: &str, reference_sha256: &str, mutant_candidate_sha256: &str, run: &str) -> Result<String>  // semantics.rs:1044 (FRF/CHALLENGE/v1)
pub fn disposition_event_identity(c: &DispositionEventContent) -> Result<String>   // semantics.rs:1080 (FRF/DISPOSITION-EVENT/v1)
pub fn knowledge_snapshot_identity(snapshot: &KnowledgeSnapshot) -> Result<String>  // semantics.rs:959 (FRF/KNOWLEDGE/v2)
pub fn witness_identity(semantic: &WitnessSemantic, implementation: &WitnessImplementation) -> Result<String>  // semantics.rs:1431 (FRF/WITNESS-IDENTITY/v1)
pub fn witness_statement_identity(c: &WitnessStatementContent) -> Result<String>    // semantics.rs:1453 (FRF/WITNESS-STATEMENT/v1)
pub fn independence_identity(c: &IndependenceContent) -> Result<String>             // semantics.rs:1497 (FRF/INDEPENDENCE/v1)
pub fn semantic_diff(a: &CaptureManifest, b: &CaptureManifest) -> Option<String>    // semantics.rs:1518
```
Plus per-extension specification hashes: `normalizer_specification_hash` (`semantics.rs:227`), `minimizer_specification_hash` (`semantics.rs:240`), `capture_adapter_specification_hash` (`semantics.rs:252`), `witness_specification_hash` (`semantics.rs:264`), `mutation_specification_hash` (`semantics.rs:1215`), `independence_specification_hash` (`semantics.rs:1474`), and identity functions for every extension record (`comparator_invocation_identity` `semantics.rs:1177`, `comparator_result_identity` `:1202`, `mutation_invocation_identity` `:1238`, `mutation_result_identity` `:1265`, `normalizer_invocation_identity` `:1288`, `normalizer_result_identity` `:1313`, `minimizer_invocation_identity` `:1334`, `minimizer_result_identity` `:1359`, `capture_adapter_invocation_identity` `:1380`, `capture_adapter_result_identity` `:1404`).

### 2.8 `frf::verify` — verified loaders (identity re-derived before use) (`src/verify.rs`, 4931 lines)

```rust
pub struct CaptureVerified { pub run: String, pub capture: CaptureManifest, pub detached: Vec<DetachedObjectRef> }  // verify.rs:87-95
impl CaptureVerified { pub fn digest(&self, residuals: &[ResidualRecord]) -> Result<String> }  // verify.rs:204
pub fn load_capture_verified(store: &Store, run: &str) -> Result<CaptureVerified>      // verify.rs:319
pub fn capture_digest(capture: &CaptureManifest, residuals: &[ResidualRecord]) -> Result<String>  // verify.rs:218
pub fn capture_identities(capture: &CaptureManifest, residuals: &[ResidualRecord]) -> Result<(String, String)>  // verify.rs:255
pub struct ResidualVerified { … }                                 // verify.rs:818-834 (private fields)
impl ResidualVerified { pub fn id(&self) -> &str; pub fn record(&self) -> &ResidualRecord; pub fn capture(&self) -> &CaptureVerified }  // verify.rs:835-841
pub fn load_residual_verified(store: &Store, id: &str) -> Result<ResidualVerified>      // verify.rs:842
pub struct ReceiptVerified { … }                                 // verify.rs:1199-1221 (private fields)
impl ReceiptVerified { pub fn id(&self) -> &str; pub fn body(&self) -> &Receipt; pub fn detached(&self) -> &[DetachedObjectRef] }  // verify.rs:1222-1238
pub fn load_receipt_verified(store: &Store, id: &str) -> Result<ReceiptVerified>        // verify.rs:1465
pub fn sign_for(store: &Store, _capture: &CaptureManifest, record: &ResidualRecord) -> Result<ResidualSign>  // verify.rs:1240
pub fn verify_sign(store: &Store, record: &ResidualRecord, sign: &ResidualSign) -> Result<()>  // verify.rs:1340
pub fn verify_trajectory_document(store: &Store, subject: &str, coordinate_system: &str, series: &str) -> Result<()>  // verify.rs:1298
pub struct ClaimVerified { … }                                   // verify.rs:2020-2040
impl ClaimVerified { pub fn id(&self) -> &str; pub fn claim(&self) -> &ClaimRecord; pub fn premises(&self) -> &[ReceiptVerified] }  // verify.rs:2041-2056
pub fn load_claim_verified(store: &Store, id: &str) -> Result<ClaimVerified>            // verify.rs:2302
pub fn verify_knowledge_universe(store: &Store, universe: &KnowledgeSnapshot) -> Result<()>  // verify.rs:2151
pub struct WholeStoreReport { pub counts: Vec<(String, usize)>, pub errors: Vec<String>, pub detached: Vec<DetachedObjectRef>, pub surface_declared: usize, pub surface_withheld: usize }  // verify.rs:3727-3744
pub fn verify_whole_store(store: &Store) -> Result<WholeStoreReport>                    // verify.rs:3783
```
`impl Receipt { pub fn validate_semantics(&self) -> Result<()> }` — document-level OpenReceipt conformance (`verify.rs:2707-2711`).

---

## 3. The precise API to run a court programmatically

All of these are plain synchronous `fn`s; the flow is: **admit → manifest file → `court::run` → `receipt::run` → (optionally dispose) → `claim::run`**.

**(a) Define an authority** — `frf::commands::admit::run` (`commands/admit.rs:23`):
```rust
pub fn run(store: &Store, path: &Path, name: &str, version: &str, kind: &str) -> Result<String>
// returns the authority id "{name}-{version}"
```
Prerequisites: `store.ensure_tree()` (`store.rs:114`); the file at `path` must exist and be executable on unix (`admit.rs:39-50`); `kind` must be `"executable_reference"` (`admit.rs:24`). Admission is once — re-admitting an existing id refuses (`admit.rs:55-60`). `Store::new(root)` (`store.rs:107`) + `ensure_tree()` is the only store setup needed.

**(b) Create a court question** — a `CourtManifest` YAML document on disk. There is no in-memory runner entry point: `court::run` / `run_once` parse the manifest from a path via `store.parse_yaml(manifest_path)` (`commands/court.rs:1627`, `store.rs:2012`). Construct `CourtManifest` in memory, serialize with `serde_yaml::to_string`, write to a file (e.g. under `courts/<id>/manifest.yaml`), and pass the path. Required shape (example at `frf/courts/cli-malformed-input/manifest.yaml`):
```yaml
court:
  id: <court-id>                # validated as a path-safe id (commands/court.rs:1653)
  question: <string>
  falsifier: <string>
  authority: <admitted-id>      # e.g. ref-cli-1.8.2
  candidate: { name, version_or_commit, build_profile, path }
  fixture:   { id, path, arguments: [..., "{fixture}", ...] }
  admissibility_envelope:
    fixture_family: <string>
    platforms: ["<arch>-<os>"]   # must contain the current platform (commands/court.rs:1876-1882)
    observables: [exit, stderr]  # any protocol id; must be served by a built-in or declared comparator
    normalizers: []
    replay_scope: single-run     # the only accepted value (commands/court.rs:1870-1875)
```
All paths inside resolve relative to the process working directory (`README.md:69-70`); the authority must be admitted for the current platform (`commands/court.rs:1883-1888`); candidate/fixture files are read + hashed before execution (`commands/court.rs:1939-1945`).

**(c) Run a court / capture on two artifacts** — `frf::commands::court::run` (`commands/court.rs:284`):
```rust
pub struct SeriesOptions {                                        // commands/court.rs:231-250
    pub repeat: Option<u32>,
    pub candidate_revisions: Option<Vec<String>>,
    pub authority_versions: Option<Vec<String>>,
    pub environment_point: Option<String>,
    pub time_point: Option<String>,
    pub series_parent: Option<String>,
}
pub fn run(store: &Store, manifest_path: &Path, opts: &SeriesOptions) -> Result<String>  // returns the run id
pub fn run_once(store: &Store, manifest_path: &Path,
                candidate_override: Option<&str>, authority_version_override: Option<&str>,
                reuse: bool, point_environment: Option<&BTreeMap<String, String>>) -> Result<String>  // commands/court.rs:1619
```
For a single run pass `&SeriesOptions::default()` (`SeriesOptions` derives `Default`, `commands/court.rs:230`). The side programs run through `host::run_process`/`run_process_closed` under the declared `ExecProfile` (`commands/court.rs:2388-2405`, `host.rs:1070/1142`), each in its own process group with resource limits; output overflow/timeout **refuses** the run (harness events + `ExecutionAttemptRecord` written as evidence, `commands/court.rs:2406-2438`). The run is committed atomically (`captures/.staging-*` → one rename, `commands/court.rs:3009, 3325`); an identical re-run is refused (immutability) unless `reuse=true` (series mode) (`commands/court.rs:2965-2996`).

Run id format (`commands/court.rs:2963`): `run-{court_id}-{run_identity_hash}` where the hash is `semantics::run_identity` (`FRF/RUN/v2`, `semantics.rs:633`), a 64-hex SHA-256. E.g. `run-cli-malformed-input-<64hex>`. Residual ids are pure 64-hex content addresses (`FRF/RESIDUAL/v1`, `semantics.rs:670-687`, assigned at `commands/court.rs:3021-3028`). Residuals + their `open` κ tokens are written during the run (`commands/court.rs:3017-3043`); the capture records the residual id list (`CaptureManifest.residuals`, `commands/court.rs:3277`).

**(d) Obtain a receipt / evidence ID** — `frf::commands::receipt::run` (`commands/receipt.rs:25`):
```rust
pub fn run(store: &Store, run: &str) -> Result<String>   // returns the receipt id
```
Emits the OpenReceipt only from **verified** evidence (`load_capture_verified` + per-residual `load_residual_verified`, `commands/receipt.rs:31-44`). Receipt id format (`commands/receipt.rs:316`):
```rust
let id = format!("receipt-{run}-{}", host::sha256_bytes(json.as_bytes()));
// i.e.  "receipt-run-<court>-<runhash>-<64-hex sha256 of the canonical receipt bytes>"
```
The receipt is written once (`receipts/<id>.json`, canonical JSON); an existing id must hash to its own id (`commands/receipt.rs:317-338`). The residual fingerprints, κ tokens, and disposition events bound at emit time are embedded (`commands/receipt.rs:160-213, 280-297`). To read a receipt back safely, use `frf::verify::load_receipt_verified` (`verify.rs:1465`).

**(e) Record a disposition** — either the command wrapper or the store API:
```rust
pub fn run(store: &Store, id: &str, disposition: ClosureArg, reason: &str,
           resolution_run: Option<String>, observation_run: Option<String>,
           trajectory: Option<String>, consecutive_passes: Option<u32>) -> Result<()>   // commands/dispose.rs:48
```
`ClosureArg` (from `frf::cli`, `cli.rs:411-428`): `Fixed | Nonreproduced | Stabilized | Intentional | Environmental | OracleVersion | Harness | Unknown`. Rules enforced: `fixed` requires `resolution_run` + a changed candidate + axis-closing compatibility (`dispose.rs:82-97`, `store.rs:2518, 2695`); `nonreproduced` requires `observation_run` + same candidate (`dispose.rs:112-120`, `store.rs:2715`); `stabilized` requires `trajectory` + `consecutive_passes ≥ 2` (`dispose.rs:143-157`, `store.rs:2743`); other kinds take a reason only (`dispose.rs:166-172`). The event is appended hash-chained with CAS (`append_disposition_event_cas`, `dispose.rs:179`, `store.rs:2265`) and the derived token rewritten (`store.rs:2107`). Lower-level alternative: build `DispositionEvent::closed/fixed/nonreproduced/stabilized` (`model.rs:3839-3967`) and call `store.append_disposition_event(&partial)` (`store.rs:2197`). `open` is not settable.

**(f) Compile a claim** — `frf::commands::claim::run` (`commands/claim.rs:417`):
```rust
pub fn run(store: &Store, receipt_ids: &[String], json: bool, policy: &str,
           mutation_profile: &str, trajectory_keys: &[String]) -> Result<()>
```
`policy` ∈ `CLAIM_POLICIES` (`claim.rs:428`); `mutation_profile` is `AXIS:FAMILY,…` (requires a sensitivity-bearing policy, `claim.rs:586-599`); `trajectory_keys` are `{lineage}.{coordinate-system}.{series}` document keys (`claim.rs:791-802`). Only verified receipts are accepted (`load_receipt_verified`, `claim.rs:446-459`); all premises must bind the same authority + candidate (`claim.rs:467-485`); admission checks harness invalidation, per-premise clean axes, `Scope(K) ⊆ Scope(P₁∪…∪Pₙ)` via `scope::claim_region`/`premise_region` (`claim.rs:534-543`), store-wide blockers over the committed `knowledge_snapshot` (`claim.rs:551-567`), and the policy tier's capability evidence. Claim id: `semantics::claim_identity` = 64-hex SHA-256 of `"FRF/CLAIM/v1\n" + canonical(document minus id)` (`semantics.rs:991-1001`, assigned `claim.rs:930`); written to `claims/<id>.json` + by-receipt index via `store.write_claim` (`claim.rs:938`, `store.rs:804`); stdout prints `claim {id}` (`claim.rs:950`). The compiled claim's `requires` = the premise receipt ids, so frf-fuzz can retain the claim id + receipt ids verbatim.

---

## 4. Trajectory API (multi-version residual trajectories)

Trajectories are **derived** from `ExecutionSeries` records; runs never know their series (`model.rs:4274-4276`, `commands/court.rs:567-608`).

To *create* series/trajectories programmatically, call `court::run` with exactly one `SeriesOptions` field set (`commands/court.rs:301-305`): `repeat: Some(n)` (n≥2), `candidate_revisions: Some(vec![...])`, `authority_versions: Some(vec![...])` (each must be admitted, `commands/court.rs:406-408`), `environment_point: Some(label)` (must be declared in `court.environment_points`), or `time_point: Some(label)` (`commands/court.rs:326-337`). The series court then:
1. runs each point via `run_once` (`commands/court.rs:349-521`),
2. writes a content-addressed, parent-linked `ExecutionSeries` snapshot via `store.write_series` (`commands/court.rs:530-546`, `store.rs:1672`; id = `FRF/SERIES/v2`, `semantics.rs:809`),
3. derives one `TrajectoryRecord` per observed lineage and writes it to `trajectories/<lineage>.<coordinate-system>.<series-id>.yaml` (`commands/court.rs:577-608`, `store.rs:1599`) — this calls the `pub(crate)` `store::derive_lineage_trajectory` (`store.rs:2834`), so in-process users get trajectories via `court::run`, not by calling it directly.

Reading/consuming trajectories (all public):
```rust
pub fn load_trajectory(&self, lineage: &str, coordinate_system: &str, series: &str) -> Result<TrajectoryRecord>  // store.rs:1615
pub fn load_series(&self, id: &str) -> Result<ExecutionSeries>                // store.rs:1641
pub fn experiment_ids(&self) -> Result<Vec<String>>                           // store.rs:1701
pub fn experiment_heads(&self, experiment_id: &str) -> Result<Vec<ExecutionSeries>>  // store.rs:1730
pub fn series_depth(&self, id: &str) -> Result<u32>                           // store.rs:1763
pub fn series_is_descendant_of(&self, descendant: &str, ancestor: &str) -> Result<bool>  // store.rs:1781
pub fn series_containing_run(&self, run: &str) -> Result<Vec<ExecutionSeries>>  // store.rs:1803
pub fn verify_trajectory_document(store: &Store, subject: &str, coordinate_system: &str, series: &str) -> Result<()>  // verify.rs:1298
pub fn verify_sign(store: &Store, record: &ResidualRecord, sign: &ResidualSign) -> Result<()>  // verify.rs:1340
pub fn sign_for(store: &Store, _capture: &CaptureManifest, record: &ResidualRecord) -> Result<ResidualSign>  // verify.rs:1240 (receipt sign per coordinate system)
pub fn classify(observed: &[bool], coordinate_system: &str, magnitudes: &[Option<String>], magnitude_kind: &str) -> Result<TrajectoryDerivation>  // trajectory.rs:66
pub fn trajectory_identity(trajectory: &TrajectoryRecord) -> Result<String>  // semantics.rs:1010
pub fn series_identity(experiment_id: &str, parent_series_id: Option<&str>, court: &str, coordinate_system: &str, points: &[SeriesPoint]) -> Result<String>  // semantics.rs:809
pub fn coordinate_identity(coordinate_system: &str, value: &serde_json::Value) -> Result<String>  // semantics.rs:792
pub fn residual_lineage_of_record(store: &Store, record: &ResidualRecord) -> Result<String>  // semantics.rs:771
```
Trajectories enter receipts as `ResidualSign.trajectory_evidence: Vec<TrajectoryEvidence>` (`model.rs:5598-5601, 5576-5585`) and can enter claims as `trajectory_premises: Vec<TrajectoryPremise>` via `claim::run`'s `trajectory_keys` (`commands/claim.rs:790-851`, `model.rs:6024-6049`). Coordinate systems: `repeat_index | candidate_revision | authority_version | environment | time` (`model.rs:4289-4290`); stratification axes `authority_version`, `candidate_revision` (`trajectory.rs:55`).

---

## 5. Compile status on stable Rust 1.85, and bin/lib split

**Verified during this inspection:** `cargo +1.85.0 check --lib` and `cargo +1.85.0 check --all-targets` both finish cleanly (offline, fresh target dirs), and `cargo check --lib` on 1.98.0 also passes. The declared MSRV (`rust-version = "1.85"`, `Cargo.toml:14`) is real.

**Pure-library question:** the lib compiles standalone, but it is **not** a "pure" library in the sense of excluding the CLI: `cli.rs` and `commands/` are `pub mod`s of the lib (`lib.rs:10-11`), and the lib depends on `clap` (with derive) unconditionally. There are no features to strip this. The only bin-only code is `src/main.rs` (23 lines): it parses `Cli`, builds `Store::new(cli.root)`, calls `store.ensure_tree()`, and dispatches (`main.rs:9-22`). Everything testable lives in the lib (`lib.rs:3-7`).

**Error type:** yes — `frf::error::FrfError(String)` + `Result<T>` (`error.rs:7-32`). Errors surface as `Err(FrfError)` from every API; the binary maps them to `frf: <message>` on stderr + `ExitCode::FAILURE` (`main.rs:18-21`). `FrfError::is_append_conflict()` (`error.rs:19`) distinguishes disposition-CAS conflicts.

---

## 6. Transitive dependencies and embedding weight

Direct (all non-optional, from `Cargo.toml:201-231`): `base64 0.22`, `clap 4` (derive+env), `serde 1` (derive), `serde_json 1`, `serde_yaml 0.9`, `sha2 0.10`, `tar 0.4`, `libc 0.2` (unix only).

Resolved graph from `Cargo.lock` (all versions listed there): `base64 0.22.1`; `clap 4.6.6` → `clap_builder 4.6.6` → `anstream 1.0.0`, `anstyle 1.0.14`, `anstyle-parse 1.0.0`, `anstyle-query 1.1.5`, `anstyle-wincon 3.0.11` (windows), `clap_lex 1.1.0`, `colorchoice 1.0.5`, `is_terminal_polyfill 1.70.2`, `strsim 0.11.1`, `utf8parse 0.2.2`, `windows-sys 0.61.2` (windows), `once_cell_polyfill`; `clap_derive 4.6.4` → `heck 0.5.0`, `proc-macro2 1.0.107`, `quote 1.0.47`, `syn 3.0.3`, `unicode-ident 1.0.24`; `libc 0.2.189`; `serde 1.0.229` → `serde_core`, `serde_derive`; `serde_json 1.0.151` → `itoa 1.0.18`, `memchr 2.8.3`, `zmij 1.0.23`; `serde_yaml 0.9.34+deprecated` → `indexmap 2.14.0`, `ryu 1.0.23`, `unsafe-libyaml 0.2.11`; `sha2 0.10.9` → `cfg-if`, `cpufeatures 0.2.17`, `digest 0.10.7` → `block-buffer 0.10.4`, `crypto-common 0.1.7` → `generic-array 0.14.7` → `typenum 1.20.1`, `version_check 0.9.5`; `tar 0.4.46` → `filetime 0.2.29`, `xattr 1.6.1` → `rustix 1.1.4` → `bitflags 2.13.1`, `errno 0.3.14`, `linux-raw-sys 0.12.1`.

**No heavy async/runtime deps:** no `tokio`, `async-std`, `rayon`, `regex`, `reqwest`, `anyhow`, `thiserror`. The crate is fully synchronous. The heaviest items are `clap` (proc-macro at build time) and `serde_yaml` (vendored `unsafe-libyaml`), both always compiled because there are **no features to disable them** — embedding `frf` in a fuzzer binary adds the full set above unconditionally. `tar` is likewise non-optional (bundle export). `serde_yaml` is deprecated upstream (`0.9.34+deprecated`) — a maintenance signal, not a break.

---

## 7. Integration gotchas

- **Not `no_std`** — the lib uses `std::fs`, `std::process`, `std::env`, `std::os::unix` everywhere (e.g. `store.rs`, `host.rs`, `sandbox.rs`).
- **`unsafe`** is confined to `host.rs` (22 occurrences) and `sandbox.rs` (10): `libc` syscalls for memfd sealing (`ExecImage::seal`, `host.rs:205`), `prctl(PR_SET_CHILD_SUBREAPER)` (`host.rs:599-609`), cgroup v2 (`host.rs:407+`), Landlock rulesets (`sandbox.rs:147`), seccomp filters, `getrusage` (`host.rs:840`), `umask` (`host.rs:2012`). All other modules are safe Rust. On non-Linux targets the sealing path falls back to a private temp file (`host.rs:247-307`) and the I/O-closed profile refuses (`sandbox.rs:265-277`); cgroup v2 is Linux-only.
- **Global state:** `static CGROUP_COUNTER: AtomicU64` (`host.rs:150`) and a `std::sync::Once` subreaper flag (`host.rs:599-609`); no `lazy_static`/`thread_local`/`static mut` outside tests. Ambient behavior comes from env vars read at runtime: `FRF_ROOT` (cli root override, `cli.rs:18`), `FRF_EXEC_*` harness overrides (`host.rs:790-894` — note these make `capture_bounds` differ from the reference bounds and are recorded as part of the execution identity, `host.rs:931`), `FRF_PRINT_SELF_CPU` (`commands/mod.rs:73`).
- **Filesystem store is mandatory.** The whole model is directory-based: `Store::new(root)` + `store.ensure_tree()` (`store.rs:107, 114`). There is **no in-memory mode**; receipts, captures, objects, claims, series, and trajectories are files under the root (`store.rs:3-18`). Default root is `.frf` (`cli.rs:18`) — the crate's own test tree is literally a directory named `frf/` at the repo root (`tests/common/mod.rs:10`). Every write is guarded: `write_once` refuses overwrites (`store.rs:2023`), runs are staged + atomically renamed (`commands/court.rs:3009, 3325`), dispositions are CAS-appended (`store.rs:2265`), claims/objects are content-addressed writes (`store.rs:804, 2060`). frf-fuzz must supply a writable root directory and must treat the store as the source of truth for IDs.
- **Working-directory coupling.** Manifest paths, authority record paths, candidate/fixture paths, and the `produce` path resolve relative to the **process cwd** (`commands/court.rs:1627, 1928-1945, 2352-2364`; `README.md:69-70`), and the environment identity records `cwd` (`host.rs:2049`). A library caller embedding frf must `chdir` or write absolute paths into the manifest/authority record — but note authority records store the path at admission time and the court re-reads it (`commands/court.rs:1928`), so paths must remain valid at run time. `replay`/`bundle replay` re-execute from an invocation root derived from the receipt (`commands/replay.rs:965-973`).
- **Executability + platform checks:** admission requires the executable bit on unix (`admit.rs:84-89`); courts refuse to run if the current platform is outside `envelope.platforms` or differs from the authority's admitted platform (`commands/court.rs:1876-1888`). frf-fuzz must generate executable candidates/fixtures and declare `platforms: ["<arch>-<os>"]`.
- **The court question must come from a file** (YAML) — there is no function taking an in-memory `CourtManifest`; `court::run`/`run_once` call `store.parse_yaml` (`commands/court.rs:1627`). Construct + serialize the manifest, write it to disk, then pass the path.
- **Observed-side resource contract:** sides are executed with hard bounds (60 s timeout, 16 MiB stream caps, rlimits; overflow **refuses** the run and writes harness/attempt evidence, `host.rs:40-76`, `commands/court.rs:2406-2438`) — a fuzzer's target must fit those bounds or the run is a recorded refusal, not a capture.
- **Determinism/caching:** identical re-observation is refused (immutability) unless `reuse=true` (series mode) (`commands/court.rs:2965-2996`); series appends to a branched experiment refuse without `series_parent` (`commands/court.rs:452-476`); disposition appends are CAS with bounded retries (`model.rs:1978`).
- **No `.frf/` requirement in the library** — the `.frf` default is only the CLI's `--root` default (`cli.rs:18`). The library takes any `root: PathBuf`. But the library **does** require a filesystem store (see above); nothing works without one.
- **Receipt/run/residual/claim IDs are the identity** — retain them verbatim. They are content addresses (SHA-256 hex) or `run-{court}-{hash}` / `receipt-{run}-{hash}` composites (§3d); a verifier re-derives every one of them from the evidence bytes, so any rewriting breaks verification.

---

## 8. Recommendation for frf-fuzz

**Feature set:** use **default features** — there is nothing to choose (no `[features]` exist). Accept that embedding pulls `clap`, `serde_yaml`, `tar`, `base64`, `sha2`, `libc` unconditionally (§6). Add `frf = "0.1.72"` (or a path dependency on the extracted source) to frf-fuzz's manifest; gate it behind the `coordinator` feature as planned.

**Call sequence to promote a finding and obtain an FRF evidence ID** (all `frf::` items, fully in-process, no subprocess):

```rust
use frf::store::Store;
use frf::commands::{admit, court, receipt, claim, dispose};
use frf::cli::ClosureArg;
use frf::model::CourtManifest;

// 1. Store (filesystem-backed; any writable root).
let store = Store::new(root.into());
store.ensure_tree()?;

// 2. Define the authority (the reference/oracle executable).
//    Returns "{name}-{version}" e.g. "ref-cli-1.8.2".
let authority_id = admit::run(&store, &authority_path, "ref-cli", "1.8.2", "executable_reference")?;

// 3. Court question: build the manifest, serialize to YAML, write to disk.
//    (court::run only accepts a manifest PATH.)
let manifest = CourtManifest { court: /* CourtSpec { id, question, falsifier,
    authority: authority_id, candidate, fixture, admissibility_envelope { … } } */, ..Default::default() };
let yaml = serde_yaml::to_string(&manifest)?;
std::fs::write(&manifest_path, yaml)?;

// 4. Run the court: executes reference vs candidate, writes capture +
//    residuals + κ tokens; returns the RUN ID.
let run_id = court::run(&store, &manifest_path, &court::SeriesOptions::default())?;
// run_id == "run-{court}-{64-hex}"  (commands/court.rs:2963)

// (optional) dispose residuals so the receipt binds the wanted state:
//   for each residual id (read from captures/<run>/capture.json ["residuals"]):
//   dispose::run(&store, &residual_id, ClosureArg::Intentional, "reason", None, None, None, None)?;

// 5. Emit the OpenReceipt; THE evidence ID frf-fuzz retains verbatim.
let receipt_id = receipt::run(&store, &run_id)?;
// receipt_id == "receipt-{run_id}-{64-hex}"  (commands/receipt.rs:316)

// 6. (optional) compile a claim (baseline policy; refuses on blockers).
claim::run(&store, &[receipt_id.clone()], false, frf::model::CLAIM_POLICY_BASELINE, "", &[])?;
// prints "claim {64-hex}"; claim id derivable via frf::semantics::claim_identity
```

Notes for the fuzzer integration:
- Retain `receipt_id` (and, if useful, `run_id` + residual ids) **verbatim**; they are the portable evidence handles. Never reimplement receipt/claim semantics — re-derivation is the library's job (`frf::verify::load_receipt_verified`, `verify.rs:1465`).
- For "bind candidate artifacts/authorities/tapes": authorities come from `admit::run`; candidates/fixtures are just files the manifest names (hashed + snapshotted into `objects/sha256/` at run time, `commands/court.rs:1950-1952`); "tapes" map naturally to `series` + `trajectories` via `court::run` with `SeriesOptions{ repeat: Some(n), .. }` (§4).
- The manifest, authority, candidate, and fixture must be on disk with working-directory-relative or absolute paths that resolve at run time, and the target binaries must be executable; declare `platforms` matching `{arch}-{os}` (e.g. `x86_64-linux`).
- Everything is synchronous and blocking; there is no async runtime. Harness bounds (60 s / 16 MiB) apply to every executed side, so a fuzzer's promoted finding must reproduce within those bounds or the run is a recorded refusal (`ExecutionAttemptRecord`), not a capture.
