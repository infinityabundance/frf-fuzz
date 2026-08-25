# Forensic API Report — `gemel` 0.11.0

Source read: `.phase0/forensics/gemel-0.11.0/` (all `src/` files, `Cargo.toml`, `Cargo.toml.orig`, `Cargo.lock`, `.cargo_vcs_info.json`). VCS commit `4914c18b8178b572cb342338f065664f5ec2d97e` (`.cargo_vcs_info.json:3`). All citations are `file:line` relative to that directory. Nothing below is from docs.rs or memory.

---

## 1. Package facts

Source: `Cargo.toml` (normalized; `Cargo.toml.orig` identical except it omits the normalized `[test]` list).

| Item | Value | Citation |
|---|---|---|
| name | `gemel` | Cargo.toml:15 |
| version | `0.11.0` | Cargo.toml:16 |
| edition | `2021` | Cargo.toml:13 |
| rust-version (MSRV) | `1.85` | Cargo.toml:14 |
| license | `MIT OR Apache-2.0` | Cargo.toml:34 |
| `[lib]` | `name = "gemel"`, `path = "src/lib.rs"` | Cargo.toml:37-39 |
| `[[bin]]` | `gemel` (`src/bin/gemel.rs`), `golden-gen` (`src/bin/golden_gen.rs`) | Cargo.toml:41-47 |
| `[[test]]` | `derived_consistency`, `exchange_tests`, `git_interop_tests`, `golden_tests`, `phase1_tests` … `phase8_tests` (no `phase4`) | Cargo.toml:49-91 |

**[features] — there is none.** No `[features]` section exists in either `Cargo.toml` or `Cargo.toml.orig`. There are **no feature flags at all** in this crate; nothing switches storage backends.

**Direct dependencies (all unconditional, all non-optional)** — `Cargo.toml:93-114`:

| crate | version req | optional | features |
|---|---|---|---|
| `blake3` | `1.5` | no | — |
| `clap` | `4.6.6` | no | `derive` |
| `fd-lock` | `4.0.4` | no | — |
| `flate2` | `1.0` | no | — |
| `rusqlite` | `0.40.2` | no | `bundled` |
| `serde_json` | `1.0` | no | — |
| `sha1` | `0.10` | no | — |

Locked versions (`Cargo.lock`): blake3 1.8.7, clap 4.6.6, fd-lock 4.0.4, flate2 1.1.9, rusqlite 0.40.2, serde_json 1.0.151, sha1 0.10.7.

---

## 2. Public library surface

`src/lib.rs` declares **30 public modules** and 4 re-exports (lib.rs:24-56):

```rust
pub mod consts; pub mod content; pub mod court; pub mod decode; pub mod defaults;
pub mod encode; pub mod error; pub mod exchange; pub mod family; pub mod gid;
pub mod git_adapter; pub mod git_interop; pub mod git_io; pub mod golden;
pub mod hash; pub mod hex; pub mod ignore; pub mod json; pub mod limits;
pub mod protocol; pub mod query; pub mod reconcile; pub mod semantic;
pub mod spec; pub mod store; pub mod sync; pub mod validate; pub mod value;
pub mod varint; pub mod workflow;

pub use error::ObjectError;
pub use value::{Body, Field, Object, Value};
```

Submodules: `exchange::{export, ingest}` (exchange/mod.rs:10-11), `store::{fsck, index, lock, objects, refs, retention, tombstone}` (store/mod.rs:7-13), `sync::{gemlpack, session, transports}` (sync/mod.rs:9-11), `semantic::{rust}` (semantic/mod.rs:19).

### Per-module public API (signatures pasted exactly)

**`gid`** (src/gid.rs):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Gid { family: Family, digest: [u8; 32] }              // fields PRIVATE (gid.rs:12-16)
pub enum ParseGidError { MissingSeparator, UnknownFamily, MalformedDigest }  // gid.rs:19-27
impl Gid {
    pub const fn new(family: Family, digest: [u8; 32]) -> Gid    // gid.rs:43
    pub const fn family(self) -> Family                          // gid.rs:48
    pub const fn digest(&self) -> &[u8; 32]                      // gid.rs:53
    pub fn to_bytes(self) -> [u8; 33]                            // gid.rs:58
    pub fn from_bytes(bytes: &[u8; 33]) -> Option<Gid>           // gid.rs:66
}
impl fmt::Display for Gid                                        // gid.rs:74
impl std::str::FromStr for Gid { type Err = ParseGidError; }     // gid.rs:80
```

**`hash`** (src/hash.rs):
```rust
pub fn blake3_256(bytes: &[u8]) -> [u8; 32]                     // hash.rs:12
pub fn object_id_bytes(bytes: &[u8]) -> [u8; 32]                // hash.rs:17
pub fn gid_from_envelope(bytes: &[u8]) -> Option<Gid>           // hash.rs:22 (family read from envelope byte 5)
pub fn object_id(obj: &Object, limits: &crate::limits::Limits) -> Result<Gid, ObjectError>  // hash.rs:28 (encodes first)
```

**`value`** (src/value.rs):
```rust
pub enum Value { U(u64), I(i64), B(bool), Bytes(Vec<u8>), Str(String), Gid(Gid),
                 Record(Vec<Field>), Array(Vec<Value>), Raw(Vec<u8>) }   // value.rs:13-32
pub struct Field { pub tag: u8, pub value: Value }                        // value.rs:36-39
impl Field { pub const fn new(tag: u8, value: Value) -> Field }           // value.rs:42
pub enum Body { Blob(Vec<u8>), Fields(Vec<Field>) }                       // value.rs:49-54
pub struct Object { pub family: Family, pub schemever: u8, pub body: Body }  // value.rs:58-62
impl Object {
    pub fn blob(bytes: Vec<u8>) -> Object                                  // value.rs:66
    pub fn fields(family: Family, body: Vec<Field>) -> Object              // value.rs:75
    pub fn blob_bytes(&self) -> Option<&[u8]>                              // value.rs:84
    pub fn field_sequence(&self) -> Option<&[Field]>                       // value.rs:92
}
```

**`varint`** (src/varint.rs): `encode_u64(u64, &mut Vec<u8>)`, `encode_i64(i64, &mut Vec<u8>)`, `decode_u64(&[u8], &mut usize) -> Result<u64, VarintError>`, `decode_i64(&[u8], &mut usize) -> Result<i64, VarintError>`; `enum VarintError { UnexpectedEof, Overflow, TooLong, NonCanonical }` (varint.rs:45-105).

**`hex`** (src/hex.rs): `pub fn encode(bytes: &[u8]) -> String` (lowercase), `pub fn decode(s: &str) -> Result<Vec<u8>, HexError>`; `enum HexError { OddLength, InvalidChar }` (hex.rs:15-39).

**`family`** (src/family.rs): `#[repr(u8)] pub enum Family` — 24 families, code bytes:
Blob=0x01, Tree=0x02, State=0x03, Operation=0x04, Episode=0x05, Intent=0x06, Change=0x07, Case=0x08, Trajectory=0x09, Claim=0x0A, Evidence=0x0B, Residual=0x0C, Verification=0x0D, Producer=0x0E, AgentRun=0x0F, Environment=0x10, Reconciliation=0x11, Release=0x12, ContextManifest=0x13, Checkpoint=0x14, Config=0x15, Mapping=0x16, SemanticEntity=0x17, SemanticIndex=0x18 (family.rs:11-39).
```rust
impl Family {
    pub const ALL: [Family; 24]                                   // family.rs:43
    pub fn code(self) -> u8                                       // family.rs:71
    pub fn from_code(code: u8) -> Option<Family>                  // family.rs:76
    pub fn short(self) -> &'static str                            // family.rs:81 ("change", "context-manifest", …)
    pub fn parse_short(name: &str) -> Option<Family>              // family.rs:111
    pub fn human(self) -> &'static str                            // family.rs:116
    pub fn allows_extensions(self) -> bool                        // family.rs:147 (false only for Blob)
    pub fn max_schemever(self) -> u8                              // family.rs:152 (1)
    pub fn supports_schemever(self, schemever: u8) -> bool        // family.rs:157
}
impl fmt::Display for Family                                      // family.rs:162 (short name)
```

**`limits`** (src/limits.rs):
```rust
pub struct Limits {
    pub max_object_bytes: u64,        // default 1<<30 (1 GiB)
    pub max_record_depth: usize,      // 64
    pub max_array_elements: usize,    // 1_000_000
    pub max_string_bytes: usize,      // 16<<20 (16 MiB)
    pub max_refs_per_object: usize,   // 100_000
}
impl Default for Limits               // limits.rs:19-28
```

**`consts`** (src/consts.rs): `MAGIC: [u8;4] = *b"GEML"`, `ENC_VERSION: u8 = 1`, `FLAGS_ZERO: u8 = 0x00`, `TAG_MAX_SCHEMA: u8 = 0x7F`, `TAG_MIN_EXTENSION: u8 = 0x80`, `TAG_MAX_EXTENSION: u8 = 0xEF`, `MAX_FIELDS_PER_RECORD: usize = 0xEF`.

**`error`** (src/error.rs): `pub enum ObjectError` — 32 variants, all canonical-layer failures (BadMagic, UnknownEncodingVersion{found}, UnknownFamily{code}, UnknownSchemaVersion{family,found}, ReservedFlags{found}, LengthMismatch, TrailingBytes, NonCanonicalInteger, IntegerOverflow, InvalidBoolean{byte}, InvalidUtf8, InvalidGid{len}, UnsortedFields{tag,prev}, DuplicateField{tag}, ReservedTag{tag}, UnknownMandatoryField{family,tag}, ExtensionNotPermitted{family,tag}, ValueLengthMismatch, MissingRequiredField{family,tag,name}, LimitExceeded{kind,limit,found}, InvalidPath{path}, InvalidEnumValue{field,found}, FamilyMismatch{expected,found}, TypeMismatch{tag,expected}, BodyKindMismatch{family}, UnexpectedRawValue{tag}, ExtensionMustBeRaw{tag}, InvalidTreeMode{mode}, InvalidTreeTargetFamily{name,mode}, InvalidTreeOrder{name}, InvalidTreeName{name}, UndeclaredOperationTag{op_type,tag}, EmptyPredicate, MappingFabricatedNonEmpty, RefCountExceeded{limit,found}, UnknownFieldName{tag}, Varint(VarintError), Hex(HexError), GidParse(String), DigestLength{len}) (error.rs:11-100). `From<VarintError|HexError|ParseGidError>` impls (error.rs:198-219). Not boxed (`#![allow(clippy::result_large_err)]`, lib.rs:22).

**`encode`** (src/encode.rs): `pub fn encode_object(obj: &Object, limits: &Limits) -> Result<Vec<u8>, ObjectError>` (encode.rs:16), `pub fn type_name(ty: &Type) -> &'static str` (encode.rs:250).

**`decode`** (src/decode.rs): `pub fn decode_object(bytes: &[u8], limits: &Limits) -> Result<Object, ObjectError>` (decode.rs:20).

**`spec`** (src/spec.rs): `pub enum Type { U64, I64, Bool, Bytes, Str, Path, Enum(&'static [&'static str]), Gid(Family), GidAny, Record(&'static [FieldSpec]), Array(&'static Type) }` (spec.rs:11-34); `pub struct FieldSpec { pub tag: u8, pub name: &'static str, pub ty: Type, pub required: bool }` + `FieldSpec::new` (spec.rs:38-54); `pub struct FamilySchema { pub family, pub schemever, pub extensions_allowed, pub fields: &'static [FieldSpec] }` + `field(tag)`, `field_by_name(name)` (spec.rs:58-75); `pub fn schema_for(family: Family) -> &'static FamilySchema` (spec.rs:1199); `pub fn all_schemas() -> [&'static FamilySchema; 24]` (spec.rs:1229); `pub fn op_kind_tags(op_type: &str) -> Option<&'static [u8]>` (spec.rs:1262); plus ~40 `pub static` schema tables (ENUM_*, TY_*, *_SPEC) at spec.rs:81-1047 — the normative field layout per family (see §5).

**`validate`** (src/validate.rs): `pub const MODE_FILE: u64 = 0o100644; MODE_EXEC = 0o100755; MODE_SYMLINK = 0o120000; MODE_DIR = 0o040000` (validate.rs:11-14); `pub fn is_valid_canonical_path(p: &str) -> bool` (validate.rs:16); `pub fn is_valid_tree_name(name: &str) -> bool` (validate.rs:35); `pub fn validate_family(obj: &Object, limits: &Limits) -> Result<(), ObjectError>` (validate.rs:48); `pub fn is_known_family(family: Family) -> bool` (validate.rs:237).

**`json`** (src/json.rs): `pub fn object_to_json(obj: &Object) -> Result<Json, ObjectError>` (json.rs:16; `Json = serde_json::Value`), `pub fn field_to_json(field: &Field, schema: &FamilySchema) -> Result<Json, ObjectError>` (json.rs:35), `pub fn value_to_json(value: &Value, ty: Option<Type>) -> Json` (json.rs:48).

**`ignore`** (src/ignore.rs): `pub struct Ignore`; `Ignore::parse(text: &str) -> Ignore` (ignore.rs:40), `Ignore::from_root(root: &Path) -> Ignore` (reads `root/.gitignore`, ignore.rs:81), `pub fn is_ignored(&self, rel_path: &str, is_dir: bool) -> bool` (ignore.rs:94).

**`store`** — see §3 for `Repo`; submodules:
- `store::objects` (src/store/objects.rs): `object_path(meta,&Gid)`, `tombstone_path`, `write_atomic(path,&[u8])`, `insert(meta, id, bytes, limits)`, `read(meta, id, limits)` (re-hashes every read), `exists`, `scan(meta)`, `enum ObjectError { NotFound, Corrupt{id,detail}, HashCollision{id}, Io, Limit{limit,found} }`.
- `store::refs` (src/store/refs.rs): `pub struct RefOp { pub name: String, pub new: Option<Gid> }` + `RefOp::set(name, gid)` / `RefOp::delete(name)` (refs.rs:17-38); `pub struct RefTransaction { pub ops: Vec<RefOp> }` (refs.rs:42-44); `validate_name`, `ref_path`, `read(meta,name) -> Result<Option<Gid>, Error>`, `all(meta)`, `journal_path`, `apply(meta,txn)`, `apply_unlocked(meta,txn)` (journaled, refs.rs:143), `recover`, `recover_unlocked`.
- `store::lock` (src/store/lock.rs): `pub fn with_write_lock<T>(lock_path: &Path, f: impl FnOnce() -> Result<T, crate::store::Error>) -> Result<T, crate::store::Error>` (lock.rs:15, blocking, advisory flock via fd-lock), `pub fn try_with_write_lock<T>(...) -> Option<Result<T, Error>>` (lock.rs:31, non-blocking). Non-reentrant (lock.rs:7-9).
- `store::index` (src/store/index.rs): `INDEX_SCHEMA_VERSION: i64 = 1`, `db_path(meta)`, `note_insert`, `note_refs`, `mark_stale`, `open_for_query(repo) -> Result<Connection, Error>`, `is_stale`, `is_fresh(repo) -> bool`, `scan_canonical(repo) -> Vec<(Gid, Object)>`, `refs_mirror`, `indexed_objects`, `edges_of(obj)`, `rebuild(repo)`, `remove(repo)`. SQLite DB at `.gemel/index/gemel.db`, WAL mode, auto-created on first use (index.rs:30-40); **derived, disposable, never source of truth** (index.rs:1-7).
- `store::tombstone` (src/store/tombstone.rs): `pub struct Tombstone { pub id: Gid, pub family: Family, pub size: u64, pub pruned_at: i64, pub policy_tier: u8, pub policy_rule: String, pub archive_remote: Option<String> }`; `write`, `read`, `exists`, `remove` (tombstone.rs:28-92).
- `store::retention` (src/store/retention.rs): `TIER_0_CANONICAL=0 … TIER_3_FORENSIC=3`, `default_tier(family) -> u8`, `adjusted_blob_tier(evidence_referenced) -> u8`, `default_retention_record() -> serde_json::Value`. GC pruning itself is not implemented (retention.rs:1-16).
- `store::fsck` (src/store/fsck.rs): `pub struct FsckOptions { pub repair: bool, pub rebuild_index: bool, pub verbose: bool }`, `pub struct FsckReport { … }` with `exit_code() -> u8`, `is_clean() -> bool`, `pub fn run(repo, opts) -> Result<FsckReport, Error>`.

**`content`** (src/content.rs): `pub struct Snapshot { pub state: Gid, pub files: usize, pub symlinks: usize, pub bytes: u64, pub coherent: bool, pub attempts: u32 }` (content.rs:17-30); `MAX_CAPTURE_ATTEMPTS: u32 = 3`; `build_state(repo, root, ignore) -> Result<Snapshot, Error>` (content.rs:63 — snapshots + inserts blobs/trees/state, adds extension 0x80 `Raw` capture record); `object_identity(repo, obj) -> Result<Gid, Error>` (in-memory identity, no publish, content.rs:122); `object_identity_with_limits`; `state_identity_from_files(repo, files) -> Result<(Gid, Gid), Error>` (tree,state; no inserts, content.rs:139); `state_identity_from_files_with_limits`; `build_state_from_files(repo, files) -> Result<Gid, Error>` (inserts, content.rs:161); `state_files(repo, state) -> Result<BTreeMap<String,(u64,Gid)>, Error>` (content.rs:403); `materialize_overlay(repo, state, target)` (content.rs:437); `materialize_exact(repo, state, target, ignore) -> Result<Vec<String>, Error>` (content.rs:457); `exact_removals(...)`; `pub enum DeltaKind { Created, Deleted, Modified, Renamed { from: String } }` (content.rs:678); `pub struct FileDelta { pub path: String, pub kind: DeltaKind, pub old_blob: Option<Gid>, pub new_blob: Option<Gid> }` (content.rs:687); `diff_states(repo, a, b) -> Result<Vec<FileDelta>, Error>` (content.rs:695); `synthesize_operations(repo, deltas, producer) -> Result<Vec<Gid>, Error>` (content.rs:797); `synthesize_operations_ts(...)` (content.rs:808); `flatten_tree(repo, tree) -> Result<HashMap<String,(u64,Gid)>, Error>` (content.rs:874); `pub enum PathStatus { Added, Modified, Deleted, TypeChanged }` (content.rs:932); `working_tree_delta(repo, base, ignore)` (content.rs:941); `pure_working_tree_files(root, ignore, limits)` (content.rs:1054); `blob_identity(content: &[u8]) -> Gid` (content.rs:1146); `pub enum Edit { Equal(usize), Delete(usize), Insert(usize) }` (content.rs:1172); `myers_diff(a,b) -> Vec<Edit>` (content.rs:1180); `pub struct Hunk { a_start, a_count, b_start, b_count, lines }` (content.rs:1415); `to_hunks(edits, a, b, context) -> Vec<Hunk>`; `unified_diff(a_label, b_label, a, b, context) -> String` (content.rs:1512); `split_lines(content) -> Vec<&str>` (content.rs:1540).

**`workflow`** — see §3e/f/h.

**`query`** (src/query.rs): `pub struct LogEntry { pub change: Gid, pub name: Option<String>, pub summary: String, pub input_state: Option<Gid>, pub resulting_state: Option<Gid>, pub trajectory: Option<String>, pub created_at: Option<i64>, pub operations: Vec<Gid>, pub claims: Vec<Gid>, pub evidence: Vec<Gid>, pub residuals: Vec<Gid> }` (query.rs:16-29); `pub fn log(repo, limit: usize) -> Result<Vec<LogEntry>, Error>` (query.rs:32); `current_trajectory_name(repo) -> Result<Option<String>, Error>` (query.rs:83); `show(repo, name_or_id) -> Result<(Gid, Object, Option<String>), Error>` (query.rs:91); `pub enum ClaimStatus { Superseded, Contradicted, PartiallySupported, Supported, Unverified, Stale }` + `as_str` (query.rs:104-123); `claim_status(repo, claim) -> Result<(ClaimStatus, Vec<Gid>, Vec<Gid>), Error>` (query.rs:129); `residuals_affecting_claim`, `evidence_outcome`, `residual_disposition(repo, residual) -> Result<String, Error>` (query.rs:261), `residual_persistence(repo, residual) -> Result<usize, Error>` (query.rs:277); `pub struct ClaimSummary`, `pub struct ResidualSummary`, `pub struct Status { trajectory, intent, state, changed, claims, residuals, evidence_count, semantic_entity_count }` (query.rs:337-347); `pub enum Readiness { Ready, ReadyWithResiduals, NotReady }` (query.rs:354); `status(repo) -> Result<Status, Error>` (query.rs:372); field helpers `str_field`, `gid_field`, `int_field`, `gid_list`, `record_field`, `value_at`, `u64_field` (query.rs:472-528); `head_state(repo) -> Result<Option<Gid>, Error>` (query.rs:531); `resolve_state(repo, name_or_id) -> Result<Gid, Error>` (query.rs:536); `chain_latest(repo, gid) -> Result<Gid, Error>` (query.rs:576, guard 4096); `all_trajectories(repo) -> Result<Vec<(String, Gid)>, Error>` (query.rs:636); `trajectory_versions(repo, latest) -> Result<Vec<(Gid, Object)>, Error>` (query.rs:651); `change_touches`, `change_touches_subjects`, `pub struct SubjectHit`, `changes_touching(subject)`, `changes_touching_subjects(subjects)` (query.rs:683-782); `page_by_time<T>(...)` (query.rs:873); `pub struct ClaimRow`, `pub struct ClaimsFilter { subject, status, limit, cursor }`, `claims(repo, filter) -> Result<(Vec<ClaimRow>, Option<String>), Error>` (query.rs:918-953); `pub enum Freshness { Current, MayRequireRefresh }` (query.rs:1020); `evidence_freshness(repo, evidence)` (query.rs:1049); `pub struct EvidenceRow { gid, kind, subject, outcome, evaluated_state, freshness, reproduction_replayable, producer, created_at }` (query.rs:1036-1046); `evidence_show(repo, name_or_id)` (query.rs:1062); `evidence_for_subject(repo, subject)` (query.rs:1090); `pub struct ResidualRow`, `pub struct ResidualsFilter`, `residuals(repo, filter)` (query.rs:1151-1185); `subject_affects_residual`; `pub struct AttemptSummary { trajectory, name, intent, outcome, termination_reason, evidence, residuals, handoff_summary, touched_subject, created_at }` (query.rs:1267-1277); `attempts(repo, subject) -> Result<Vec<AttemptSummary>, Error>` (query.rs:1284); `pub struct TrajectoryChange { change, summary, state, created_at }` (query.rs:1371); `pub struct TrajectoryDetail { gid, name, intent, base_state, outcome, termination_reason, sequence, evidence, residuals, handoff }` (query.rs:1380); `pub struct HandoffDetail` (query.rs:1396); `trajectory_detail(repo, name_or_id)` (query.rs:1408); `pub struct WhyEvidence`, `WhyResidual`, `WhyNode`, `WhyClaim`, `pub struct WhyReport { subject, semantic, introduced_by, last_modified, previous_approaches, uncertainty }` (query.rs:1511-1560); `why(repo, subject) -> Result<WhyReport, Error>` (query.rs:1567); `pub struct CheckpointPlan` (used by workflow; query.rs — see `checkpoint_plan`).

**`defaults`** (src/defaults.rs): `human_producer_object(name, email) -> Object`, `human_producer_object_at(name, email, created_at)`, `automation_producer_object(name)`, `automation_producer_object_at(name, created_at)`, `git_import_producer_object()`, `unknown_producer_object()`, `default_config_object() -> Object` (defaults.rs:33-157).

**`court`** (src/court.rs): `COURT_PRODUCER_NAME: &str = "court-runner"`; `pub struct CourtOutcome { pub evidence: Gid, pub outcome: String, pub exit_code: Option<i64>, pub stdout_digest: Option<String>, pub stderr_digest: Option<String>, pub detail: String }` (court.rs:25-32); `pub fn run_court(repo, evidence: &Gid, allow: bool, timeout_secs: u64) -> Result<CourtOutcome, Error>` (court.rs:36 — executes the evidence's reproduction command, court.rs:36-46); `allowlist_path(repo)`, `write_allowlist(repo, patterns: &[&str])` (court.rs:266-278).

**`protocol`** (src/protocol.rs): `AGENT_SCHEMA = "gemel.agent.v1"`, `MAX_REQUEST_LINE = 64*1024`, `MAX_RESPONSE_BYTES = 4*1024*1024`; `pub struct AgentRequest { pub id: u64, pub query: String, pub params: serde_json::Map<String, Value> }` (protocol.rs:46-50); `pub fn parse_request(line: &str) -> Result<AgentRequest, String>` (protocol.rs:54); `pub fn route(repo: &Repo, req: &AgentRequest) -> Result<Value, String>` (protocol.rs:88, queries: status/next/why/semantic); `pub fn run_session(repo: &Repo) -> Result<(), Error>` (protocol.rs:118).

**`reconcile`** (src/reconcile.rs): `pub struct ReconcileInput { pub name: String, pub gid: Gid }` (reconcile.rs:39); `pub struct TextualConflict { pub path: String, pub changes: Vec<Gid> }` (reconcile.rs:46); `pub struct Interaction { kind, certainty, subjects, severity, detail }` (reconcile.rs:53); `pub struct ReconcilePlan { inputs, base_state, intent, adopted, rejected, textual_conflicts, interactions, claims_retained, claims_invalidated, evidence_retained, … }` (reconcile.rs:64); `pub struct ReconcileOutcome { reconciliation: Gid, reconciliation_name: String, change: Gid, change_name: String, state: Gid, state_name: String, plan: ReconcilePlan }` (reconcile.rs:85); `pub struct ReconcileOptions { pub apply: bool, pub producer: Option<Gid> }` (reconcile.rs:97); `pub fn analyze(repo, inputs) -> Result<ReconcilePlan, Error>` (reconcile.rs:158); `pub fn reconcile(repo, inputs, opts) -> Result<ReconcileOutcome, Error>` (reconcile.rs:457).

**`git_adapter`** (src/git_adapter.rs, shells out to the `git` binary): `pub type StagedEntry = (String, u64, Vec<u8>)` (git_adapter.rs:33); `pub struct GitCommit { tree, parents, author, committer, message }` (git_adapter.rs:36); `pub struct GitTreeEntry { mode, kind, oid, path }` (git_adapter.rs:46); `rev_list_topo_reverse(root, head)`, `cat_commit(root, oid)`, `ls_tree_recursive(root, tree)`, `cat_blob(root, oid)`, `parse_commit(raw)`, `person_timestamp(line)`, `person_name(line)`, `person_email(line)`, `clone_repo(url, dir)`, `staged_files(root)` (git_adapter.rs:55-222). All `git` invocations are `git -C <cwd> …` (git_adapter.rs:13-23).

**`git_io`** (src/git_io.rs, self-contained loose-object writer, no git binary): `pub struct Oid(pub [u8; 20])` with `Oid::parse(s) -> Result<Oid, Error>` (git_io.rs:14-33); `hash_object(kind, content) -> Oid` (SHA-1, git_io.rs:45); `EMPTY_TREE`; `loose_path(git_dir, oid)`; `write_loose(git_dir, oid, kind, content)` (zlib via flate2); `read_loose`; `read_loose_all`; `pub struct TreeEntry { mode: u32, name: String, oid: Oid }` (git_io.rs:162); `encode_tree(entries) -> Vec<u8>`, `decode_tree(bytes) -> Result<Vec<TreeEntry>, Error>`; `pub struct Commit { tree: Oid, parents: Vec<Oid>, author, committer, message }` (git_io.rs:238); `encode_commit(c) -> Vec<u8>`, `decode_commit(content) -> Result<Commit, Error>`; `read_ref(git_dir, name)`, `list_branches(git_dir)`, `write_branch(git_dir, name, oid)`, `write_head(git_dir, branch)`.

**`git_interop`** (src/git_interop.rs): `EXPORT_VERSION = "1"`, `GEMEL_COMMITTER = "gemel <gemel@local>"`, `GEMEL_PRODUCER_AUTHOR = "Gemel Producer <gemel@local>"` (git_interop.rs:27-40); `pub struct ExportGitOptions { pub git_dir: PathBuf, pub branch: String, pub include_claims: bool }`; `pub struct ExportOutcome { commits, trees, mappings, head_oid, branch }`; `pub struct ImportGitOptions { pub git_dir: PathBuf, pub head: String }`; `pub struct ImportOutcome { commits, changes, trajectories, mappings, relinked, ignored_trailers, unknown_producers }`; `pub fn head_closure(repo: &Repo) -> Result<Vec<Gid>, Error>` (git_interop.rs:271 — head-reachable change closure, topological); `pub fn export_git(repo, opts) -> Result<ExportOutcome, Error>` (git_interop.rs:302, uses git_io only); `pub fn import_git(repo, opts) -> Result<ImportOutcome, Error>` (git_interop.rs:532, uses git_adapter → requires `git`).

**`sync`** (src/sync/mod.rs): `REF_REMOTES = "refs/remotes"`, `REMOTES_FILE = "remotes.json"` (sync/mod.rs:39-44); `is_public_ref(name) -> bool` (sync/mod.rs:48); `public_refs(repo)` (sync/mod.rs:63); `reachable_ids(repo, seeds)` (sync/mod.rs:76); `missing_ids(repo, ids)` (sync/mod.rs:101); `ensure_reachable(repo, refs)` (sync/mod.rs:113); `pub trait Transport { fn describe(&self) -> String; fn list_refs(&mut self) -> Result<Vec<(String, Gid)>, Error>; fn reachable_ids(&mut self, seeds: &[Gid]) -> Result<Vec<Gid>, Error>; fn missing_ids(&mut self, ids: &[Gid]) -> Result<Vec<Gid>, Error>; fn fetch_objects(&mut self, ids: &[Gid]) -> Result<Vec<(Gid, Vec<u8>)>, Error>; … }` (sync/mod.rs:133-143); `pub struct FileTransport` with `FileTransport::open(path, init) -> Result<FileTransport, Error>` (sync/mod.rs:158) and `path()`; `pub struct RemotesConfig { pub remotes: Vec<(String, String)> }`, `read_remotes(repo)`, `write_remotes(repo, cfg)`, `add_remote(repo, name, path)`; `pub struct FetchOutcome`, `tracked_refs(repo, remote)`, `pub fn fetch(repo, remote, transport)` (sync/mod.rs:360), `pub struct PushOutcome`, `pub fn push(repo, remote, transport)` (sync/mod.rs:416), `pub struct PullOutcome`, `pub fn pull(repo, remote, transport)` (sync/mod.rs:479).
- `sync::gemlpack` (src/sync/gemlpack.rs): `MAGIC = b"GMLP"`, `FORMAT_VERSION = 1`; `pub struct PackRecord { pub id: Gid, pub envelope: Vec<u8> }`; `pack_id(bytes) -> [u8;32]`; `encode_pack(records) -> Result<Vec<u8>, Error>`; `pub struct PackLimits { max_pack_bytes, max_objects, max_object_bytes }`; `decode_pack(bytes, limits) -> Result<Vec<PackRecord>, Error>`.
- `sync::session` (src/sync/session.rs): `MAX_LINE = 64*1024`, `MAX_PACK_BYTES = 4<<30`, `MAX_IDS = 10_000_000`; `pub struct ServeOptions { pub read_only: bool }`; `handle_json(repo, op, params, read_only)`, `handle_fetch(repo, ids)`, `handle_push(repo, pack_bytes, read_only)`, `serve_session(repo, opts)`, `send_json<W: Write, R: BufRead>(out, inp, req)`.
- `sync::transports` (src/sync/transports.rs): `pub enum RemoteUrl { Ssh { user, host, port, path }, Http { host, port, path }, Local(PathBuf) }` (transports.rs:30-40); `pub fn parse_remote(arg: &str) -> Result<RemoteUrl, Error>` (transports.rs:51; `https://` fails closed, transports.rs:70); `pub enum RemoteTarget { Native(Box<dyn Transport>), Git(PathBuf) }` (transports.rs:146); `resolve_target(repo, arg)`; `pub struct SshTransport` with `SshTransport::ssh(host, user, port, path)` (spawns `ssh`), `SshTransport::spawn(program, args, describe)`; `pub struct HttpTransport` with `HttpTransport::new(host, port, path, token)`; `pub struct ServeHttpOptions { root, read_only, tokens }` (transports.rs:778); `pub fn serve_http(server_root, addr, opts)` (transports.rs:834; refuses non-loopback without tokens).

**`exchange`** (src/exchange/mod.rs): `PROTOCOL_VERSION = "v1"`, `EXCHANGE_ROOT = "exchange"`, `FRONTIER_SCHEMA = "gemel.exchange.frontier.v1"`, `PACK_SCHEMA = "gemel.exchange.pack.v1"`, `TARGET_PACK_BYTES = 262_144` (exchange/mod.rs:23-34); `pub struct ExchangeLimits { max_descriptor_bytes, max_pack_bytes, max_objects_per_pack, max_packs_per_frontier, max_automatic_ingest_bytes, max_reference_depth }` (exchange/mod.rs:37-44); `exchange_dir(meta)`, `pack_dir(meta)`, `frontier_dir(meta)`, `pack_path(meta, id)`, `frontier_path(meta, id)`, `read_pack_file(path)`, `read_frontier_file(path)`; `pub struct PackObject { pub id: Gid, pub envelope: Vec<u8> }`; `encode_pack(objects) -> Result<(Vec<u8>, [u8;32]), Error>`, `decode_pack(bytes, limits) -> Result<Vec<PackObject>, Error>`; `pack_id(bytes)`, `frontier_id(bytes)`; `pub struct Coverage { canonical_metadata, source_content, evidence_receipts, evidence_payloads, conversations, forensic_traces }` (exchange/mod.rs:280); `pub struct Frontier { schema, source_state: Gid, head_change: Gid, trajectory: Option<Gid>, intent: Option<Gid>, parent_frontiers: Vec<String>, packs: Vec<String>, profile: String, coverage: Coverage, required_schemas: Vec<u8> }` (exchange/mod.rs:304-315); `encode_frontier(f) -> Result<Vec<u8>, Error>` (sorted-key JSON, no timestamps; exchange/mod.rs:319); `parse_frontier(bytes, limits)`; `pub type DiscoveredFrontier = (Frontier, [u8; 32], Vec<u8>)` (exchange/mod.rs:473); `discover_frontiers(meta) -> Result<Vec<DiscoveredFrontier>, Error>` (exchange/mod.rs:476); `hex_to_digest(hex) -> Option<[u8;32]>`.
- `exchange::export` (src/exchange/export.rs): `pub enum Profile { Frontier, Portable }` + `Profile::parse(s)`, `Profile::as_str()` (export.rs:16-31); `pub struct ExportOutcome { packs_written, packs_reused, objects, frontier: String, frontier_id: [u8;32], source_state: Gid }` (export.rs:41-48); `collect_export_objects(repo, profile) -> Result<Vec<(Gid, Vec<u8>)>, Error>` (export.rs:54); `pub type PackArtifact = (Vec<u8>, [u8; 32])`; `build_packs(objects)`; `write_atomic_fsync(path, bytes)`; `content_state_identity(repo, files) -> Result<Gid, Error>` (export.rs:164); `content_state_identity_with_limits(files, limits)` (export.rs:173); `content_identity_of_state(repo, state) -> Result<Gid, Error>` (export.rs:190); `LOCAL_GITIGNORE` + `install_local_gitignore(meta)` (export.rs:196-202); `pub fn export(repo, profile) -> Result<ExportOutcome, Error>` (export.rs:255); `read_active_frontier(meta) -> Result<Option<[u8;32]>, Error>` (export.rs:335); `mark_imported(meta, id) -> Result<bool, Error>` (export.rs:359); `is_imported(meta, id) -> bool`; `clean_temporaries(meta)`; `working_tree_files(repo)` (export.rs:412).
- `exchange::ingest` (src/exchange/ingest.rs): `REF_EXCHANGE = "refs/exchange"`, `REF_EXCHANGE_FRONTIERS = "refs/exchange/frontiers"` (ingest.rs:17-23); `pub enum SourceBinding { Matched, Diverged }` (ingest.rs:25-30); `pub struct IngestOutcome { frontiers_found, frontiers_imported, frontiers_already_imported, packs_processed, objects_promoted, current_source_state: Option<Gid>, matching: Vec<String>, diverged: Vec<String>, activated: Option<String>, … }` (ingest.rs:34-44); `pub fn ingest(repo) -> Result<IngestOutcome, Error>` (ingest.rs:193); `ingest_with_limits(repo, limits)` (ingest.rs:199); `pub struct ExchangeStatus`, `pub struct FrontierSummary { id, source_state, head_change, profile, imported, binding }` (ingest.rs:443-461); `pub fn status(repo: Option<&Repo>, root: &Path) -> Result<ExchangeStatus, Error>` (ingest.rs:464); `pub fn bootstrap(root: &Path) -> Result<IngestOutcome, Error>` (ingest.rs:513 — init + ingest); `pub enum VerifyMode { WorkingTree, GitIndex }` (ingest.rs:521); `pub fn verify(root, mode) -> Result<VerifyOutcome, Error>` (ingest.rs:529); `pub struct VerifyOutcome { frontiers_validated, packs_validated, source_state, staged, matched, diverged }` (ingest.rs:669).

**`semantic`** (src/semantic/mod.rs): `REF_SEMANTIC = "refs/semantic"`, `REF_SEMANTIC_CURRENT = "refs/semantic/current"`, `REF_SEMANTIC_HEAD = "refs/semantic/head"`, `INDEXER_PRODUCER_NAME = "semantic-indexer"` (semantic/mod.rs:28-39); `entity_kind_of(scan_kind)`; `pub struct EntityRecord { kind, name, module_path, file_path, start_line, end_line, signature, visibility, parent_name, impl_target, impl_trait, state: Gid, uses: Vec<String> }` (semantic/mod.rs:46-61); `pub struct IndexOutcome { entities, files, new_entities, modified_entities, moved_entities, lineage_links, index: Gid }`; `pub fn index_state(repo, state: &Gid, producer: &Gid) -> Result<IndexOutcome, Error>` (semantic/mod.rs:79); `records_for_state(repo, state)`; `index_for_state(repo, state) -> Result<Option<Gid>, Error>` (semantic/mod.rs:418); `entities_for_state(repo, state)`; `current_entities(repo)`; `resolve_entity(repo, subject)`; `pub struct EntityInfo { … }` (semantic/mod.rs:484); `pub fn resolve_subject(repo, subject) -> Result<ResolvedSubject, Error>` (semantic/mod.rs:612).

**`golden`** (src/golden/mod.rs): `pub struct Fixture { pub name: &'static str, pub description: &'static str, pub build: fn(&mut FixtureCtx) -> Object }` (golden/mod.rs:18); `pub struct FixtureCtx` with `gid(&mut self, name) -> Gid` and `take_refs()`; `pub struct BuiltFixture { fixture, object, gid, refs }`; `pub fn build_all(limits: &Limits) -> Result<Vec<BuiltFixture>, ObjectError>` (golden/mod.rs:68); `pub fn all_fixtures() -> &'static [Fixture]` (golden/mod.rs:88).

---

## 3. Precise API for frf-fuzz's needs

### (a) Open / discover a repository

```rust
pub fn init(root: &Path, opts: &InitOptions) -> Result<Repo, Error>        // store/mod.rs:174
pub fn open(root: &Path) -> Result<Repo, Error>                            // store/mod.rs:241
pub fn find(start: &Path) -> Result<Repo, Error>                           // store/mod.rs:255
pub struct InitOptions { pub author_name: Option<String>, pub author_email: Option<String> }  // store/mod.rs:158-164
pub const META_DIR: &str = ".gemel";                                       // store/mod.rs:27
```

- Repository = a directory containing `.gemel/` **with `meta.json`**. `open` fails with `Error::NotARepository(root)` unless `meta/.gemel` is a dir **and** `meta.json` is a file (store/mod.rs:242-245). A `.gemel/` carrying only exchange material is *not* a repo and open fails cleanly (store/mod.rs:237-240).
- `find` walks parent directories from `start` until a dir with `.gemel/` is found, then `open`s it (store/mod.rs:255-264).
- `Repo::open` runs **opportunistic journal recovery** (may acquire the write lock and roll back interrupted ref transactions + rebuild the derived index; store/mod.rs:250, 347-354). This is the only "write on read" path.
- `Repo` is `#[derive(Debug, Clone)]` with private `root`/`meta` (store/mod.rs:151-155); `root() -> &Path`, `meta_dir() -> &Path` (store/mod.rs:267-274).

### (b) Current state Gid / head

```rust
pub fn read_ref(&self, name: &str) -> Result<Option<Gid>, Error>           // store/mod.rs:424
pub const REF_HEAD: &str        = "refs/head";                             // store/mod.rs:30
pub const REF_STATE_HEAD: &str  = "refs/state/head";                       // store/mod.rs:31
pub fn head_state(repo: &Repo) -> Result<Option<Gid>, Error>               // query.rs:531 (= read_ref(REF_STATE_HEAD))
```
- `refs/state/head` is the current state Gid (written by `finish_change`, workflow.rs:649). `refs/head` is the current Change Gid.
- Workspace-materialized state (per workspace): `workflow::workspace_state(repo) -> Result<Option<Gid>, Error>` (workflow.rs:67, reads `.gemel/worktrees/<ws>/state.ref`), `workspace_named_state(repo, workspace)` (workflow.rs:72).
- Human names for any object: `repo.name_of(&gid) -> Result<Option<String>, Error>` (store/mod.rs:453); `repo.resolve(name_or_id) -> Result<Gid, Error>` (store/mod.rs:287 — exact Gid parse first, then `refs/names/*`, `refs/trajectories/*`, `refs/cases/*`, `refs/releases/*`, `refs/reconciliations/*`, `refs/checkpoints/*`, `refs/mappings/*`).

### (c) Active intent / change / trajectory state (read-only)

```rust
pub fn read_pending(repo: &Repo) -> Result<Option<serde_json::Value>, Error>          // workflow.rs:107
pub fn read_pending_named(repo: &Repo, workspace: &str) -> Result<Option<serde_json::Value>, Error>  // workflow.rs:112
pub const PENDING_SCHEMA: &str = "gemel.pending.v1";                                  // workflow.rs:25
pub fn current_trajectory_name(repo: &Repo) -> Result<Option<String>, Error>          // query.rs:83
```
- Pending record lives at `.gemel/worktrees/<ws>/pending.json` (workflow.rs:116) with keys: `schema`, `input_state`, `intent`, `producer`, `workspace`, `worktree`, `started_at` (workflow.rs:257-265). **The active intent Gid is `pending["intent"]` when a change is in progress.**
- Current trajectory: ref `refs/trajectories/current` (workflow.rs:653) + named `refs/trajectories/T<n>`; `query::current_trajectory_name` resolves the name via `name_in_namespace` (query.rs:83-89).
- Counters and default producer: `repo.read_meta() -> Result<serde_json::Value, Error>` (store/mod.rs:308) — `meta.json` has `default_producer` (Gid string) and `counters.{intent,trajectory,change,state,checkpoint,reconciliation}` (store/mod.rs:211-222).
- Active intent object content: `Family::Intent` fields 0x01 `summary` (required), 0x0B `producer`, 0x0C `created_at` (spec.rs:611-624; created at workflow.rs:242-249).
- `workflow::name_in_namespace(repo, namespace, gid) -> Result<Option<String>, Error>` (workflow.rs:169).

### (d) Create durable objects (canonical encoding, identity, immutable store)

```rust
pub fn insert_object(&self, obj: &Object) -> Result<Gid, Error>           // store/mod.rs:357 — encode → validate → hash → atomic publish → index
pub fn insert_bytes(&self, bytes: &[u8]) -> Result<Gid, Error>            // store/mod.rs:363 — decode-validates first
pub fn read_object(&self, id: &Gid) -> Result<ReadOutcome, Error>         // store/mod.rs:377
pub fn read_bytes(&self, id: &Gid) -> Result<Vec<u8>, Error>              // store/mod.rs:398 — re-hashes, verifies identity
pub fn load(&self, id: &Gid) -> Result<Object, Error>                     // store/mod.rs:406
pub fn has_object(&self, id: &Gid) -> Result<bool, Error>                 // store/mod.rs:417
pub enum ReadOutcome { Object(Object), Pruned(tombstone::Tombstone) }     // store/mod.rs:524-529
```
- **Identity = BLAKE3-256 of the canonical envelope bytes**, family byte is part of the Gid (hash.rs:3, gid.rs:3-5). `hash::object_id(obj, limits)` computes it without a store; `content::object_identity(repo, obj)` likewise (content.rs:122); `insert_object` uses the same machinery (store/mod.rs:357-360).
- Storage layout: `.gemel/objects/<2-hex>/<64-hex>.gce` (objects.rs:57-62). Insert = write temp → `fsync` → atomic rename → dir fsync (objects.rs:72-91); dedup on identical bytes, `HashCollision` error otherwise (objects.rs:95-114). Every read re-hashes and rejects corrupted bytes (objects.rs:117-138).
- **Inserts are lock-free** — object files are immutable once published; the writer lock is only for ref transactions/GC/repair (lock.rs:1-9).
- Blob objects: `Object::blob(bytes)`; blobs of raw working-tree files are the *only* way to store raw payloads (blob family has no fields, spec.rs:533).
- Working-tree → State without per-file churn: `content::build_state(repo, root, ignore) -> Result<Snapshot, Error>` inserts blobs/trees/state in one call (content.rs:63-99) — suitable for durable boundaries, not per-execution. For a pure in-memory identity (no writes): `content::state_identity_from_files(repo, &files) -> Result<(Gid, Gid), Error>` (content.rs:139; tree,state) / `state_identity_from_files_with_limits(files, limits)`.
- State object = fields `{0x01: Gid(Tree)}` + optional `0x80 Raw` capture record (content.rs:88-94); State schema: only 0x01 `root_tree` required (spec.rs:544-549).

### (e) Write a change / intent

Full workflow entry points (both take the writer lock internally):

```rust
pub fn begin_change(repo: &Repo, opts: &BeginOptions) -> Result<BeginOutcome, Error>     // workflow.rs:214
pub struct BeginOptions { pub from_state: Option<Gid>, pub intent: Option<Gid>,
    pub intent_summary: Option<String>, pub producer: Option<Gid>,
    pub workspace: Option<String>, pub worktree: Option<PathBuf> }                       // workflow.rs:186-201
pub struct BeginOutcome { pub input_state: Option<Gid>, pub intent: Option<Gid>,
    pub intent_name: Option<String>, pub producer: Gid, pub started_at: i64 }            // workflow.rs:204-211

pub fn finish_change(repo: &Repo, opts: &FinishOptions) -> Result<FinishOutcome, Error>  // workflow.rs:348
pub struct FinishOptions { pub summary: String, pub claims: Vec<ClaimSpec>,
    pub evidence: Vec<EvidenceSpec>, pub residuals: Vec<ResidualSpec>,
    pub workspace: Option<String>, pub worktree: Option<PathBuf> }                       // workflow.rs:317-328
pub struct FinishOutcome { pub change: Gid, pub change_name: String, pub trajectory: Gid,
    pub trajectory_name: String, pub state: Gid, pub state_name: String,
    pub operations: Vec<Gid>, pub claims: Vec<Gid>, pub evidence: Vec<Gid>,
    pub residuals: Vec<Gid>, pub is_new_trajectory: bool }                               // workflow.rs:330-344
```

**Warning for frf-fuzz:** `finish_change` **snapshots the entire working tree** (`content::build_state`, workflow.rs:361-367), synthesizes an Operation per file delta (workflow.rs:388-409), and writes pending.json + intent + Change + Trajectory + names + refs (workflow.rs:639-666). That is exactly the "per-execution writes" frf-fuzz must avoid. For durable boundaries only, it is fine.

Lower-level (preferred for boundary-only publishing):
- Build an Intent object directly: `Object::fields(Family::Intent, [f(0x01, Str(summary)), f(0x0B, Gid(producer)), f(0x0C, I(now_ms()))])` then `repo.insert_object(&obj)` (exact construction at workflow.rs:242-253).
- Build a Change object directly with the schema fields: `summary` 0x01 (required), `intent` 0x02, `input_state` 0x03, `operations` 0x04, `resulting_state` 0x05, `producer` 0x06 (required), `claims` 0x0C, `evidence` 0x0D, `residuals` 0x0E, `causal_parents` 0x11, `created_at` 0x15 (spec.rs:627-654; exact tag-order pattern at workflow.rs:563-607).
- Publish refs atomically: `repo.write_refs(&RefTransaction { ops: vec![RefOp::set(name, gid)] })` (store/mod.rs:429; refs.rs:24-38). Refs are plain files `<gid>\n` under `.gemel/refs/...`, journaled + fsynced (refs.rs:143-195). Multi-ref txns are atomic (journal rollback, refs.rs:197-262).

### (f) Link evidence / residuals to a state

No separate "attach" API — linkage is by **Gid reference fields inside the objects**, all schema-typed:
- Evidence (spec.rs:713-731): 0x01 `producer` (req), 0x02 `kind` (req, enum `ENUM_EVIDENCE_KIND` incl. `"fuzz_result"`, `"replay"`, `"artifact_hash"`, `"court_receipt"`, spec.rs:123-138), 0x03 `subject` (Str), 0x04 `subject_refs`, 0x05 `command`, 0x06 `command_ref` (Operation), 0x07 `input_refs`, 0x08 `environment`, 0x09 `tools`, 0x0A `fixtures`, 0x0B `normalizers`, 0x0C `comparators`, 0x0D `result` (record: 0x01 outcome enum `pass|fail|mismatch|inconclusive|error|skipped`, 0x02 detail, 0x03 exit_code, 0x04 counts), 0x0E `output_refs`, 0x0F `reproduction` (record: replayable/inputs_present/inputs_remote/policy_required), 0x10 `created_at`, **0x11 `evaluated_state` (Gid(State)) — the state-binding field**.
- **State binding for evidence** = field 0x11 `evaluated_state` (spec.rs:730); freshness checks compare it to `refs/state/head` (query.rs:1049-1059). Minimal valid Evidence construction used by the workflow: `f(0x01 producer), f(0x02 kind), [f(0x03 subject)], f(0x0D Record[f(0x01 outcome)]), f(0x10 created_at)` (workflow.rs:414-424).
- Residual (spec.rs:734-757): 0x01 `previous`, 0x02 `summary` (req), 0x03 `classification` (enum: `semantic_divergence|expected_mismatch|platform_divergence|performance_divergence|unexplained_divergence|contract_mismatch|verification_gap|other`, spec.rs:147-156), 0x04 `severity` (`low|medium|high|blocking`), 0x05 `scope`, 0x06 `affected_claims` (Array(Claim)), 0x07 `affected_changes` (Array(Change)), 0x08 `origin_evidence`, 0x09 `first_observed_at`, 0x0A `disposition_event` (record: 0x01 disposition enum `open|acknowledged|resolved|superseded|irrelevant`, 0x02 by Producer, 0x03 evidence, 0x04 reconciliation, 0x05 reason, 0x06 at), 0x0B `recurrence`, 0x0C `created_at`. Construction pattern: workflow.rs:454-500.
- Claim (spec.rs:695-710): 0x01 `subject`, 0x03 `predicate` (req), 0x04 `predicate_kind` (enum incl. `correctness`, `behavior`, `safety`, …), 0x07 `producer` (req), 0x08 `evidence` (Array(Evidence)), 0x0B `supersedes` (Gid(Claim)), 0x0C `change`, 0x0E `created_at`. Construction pattern: workflow.rs:425-452.
- The Change/Trajectory objects then reference them: Change 0x0C/0x0D/0x0E (workflow.rs:585-602); Trajectory 0x08 `added_evidence` / 0x09 `added_residuals` / 0x06 `added_changes` (workflow.rs:622-636, spec.rs:677-692).
- Versioned resolution of residuals (disposition): `workflow::resolve_residual(repo, &ResolveResidualOptions) -> Result<ResolveResidualOutcome, Error>` (workflow.rs:941) — appends a disposition event to a new chain version. `ResolveResidualOptions { residual: String, disposition: String, reason: Option<String>, producer: Option<Gid> }` (workflow.rs:919-929). `query::residual_disposition` reads it (query.rs:261).

### (g) Traverse history / trajectories

```rust
pub fn log(repo: &Repo, limit: usize) -> Result<Vec<LogEntry>, Error>                 // query.rs:32
pub fn all_trajectories(repo: &Repo) -> Result<Vec<(String, Gid)>, Error>             // query.rs:636
pub fn trajectory_versions(repo: &Repo, latest: &Gid) -> Result<Vec<(Gid, Object)>, Error>  // query.rs:651
pub fn trajectory_detail(repo: &Repo, name_or_id: &str) -> Result<TrajectoryDetail, Error>   // query.rs:1408
pub fn chain_latest(repo: &Repo, gid: &Gid) -> Result<Gid, Error>                     // query.rs:576
pub fn show(repo: &Repo, name_or_id: &str) -> Result<(Gid, Object, Option<String>), Error>    // query.rs:91
pub fn head_closure(repo: &Repo) -> Result<Vec<Gid>, Error>                           // git_interop.rs:271
pub fn state_files(repo: &Repo, state: &Gid) -> Result<BTreeMap<String, (u64, Gid)>, Error>   // content.rs:403
pub fn flatten_tree(repo: &Repo, tree: &Gid) -> Result<HashMap<String, (u64, Gid)>, Error>    // content.rs:874
pub fn all_refs(&self) -> Result<Vec<(String, Gid)>, Error>                           // store/mod.rs:446
```
- History walk: `refs/head` → Change → `causal_parents` 0x11 array (workflow.rs:502-516, spec.rs:649). `head_closure` yields the head-reachable change set in topological order (git_interop.rs:271-279).
- Trajectory chain: Trajectory 0x01 `previous` links versions; `trajectory_versions` walks it with a 4096 guard (query.rs:651-661).
- States: every `refs/names/S<n>` points at a State Gid (workflow.rs:651); `refs/state/head` is current. A full tape-replay enumeration = `repo.all_refs()` filtered to `refs/names/S*` + `state_files` per state (or `content::materialize_overlay(repo, &state, &target)` to lay files out, content.rs:437).

### (h) Negative knowledge / failed attempts

No dedicated "failure" family. Three canonical mechanisms, all first-class:
1. **Trajectory close with `outcome = "rejected"`** (or `abandoned|superseded|inconclusive|interrupted`, spec.rs:105-112): `workflow::close_trajectory(repo, &CloseTrajectoryOptions) -> Result<CloseTrajectoryOutcome, Error>` (workflow.rs:867); `CloseTrajectoryOptions { trajectory: String, outcome: String, reason: Option<String>, producer: Option<Gid> }` (workflow.rs:843-854). Closed trajectories are terminal; new work on the same intent starts a fresh attempt — "rejected attempts are preserved, not extended" (workflow.rs:518-521). `query::attempts(repo, subject)` surfaces prior attempts incl. outcome + termination_reason (query.rs:1284).
2. **Residuals** = the "unresolved problem / divergence" record (classification enum explicitly includes `unexplained_divergence`, `expected_mismatch`, `verification_gap`, spec.rs:147-156). Dispositions `acknowledged|resolved|superseded|irrelevant` record the negative outcome of follow-up (spec.rs:158-164).
3. **Reconciliation invalidation**: `reconcile::reconcile` records `rejected_changes` (Reconciliation 0x06) and `claims_invalidated` (0x0B) (spec.rs:837-876; reconcile.rs:457-467). Claim supersession: Claim 0x0B `supersedes` (spec.rs:706); `query::claim_status` returns `Contradicted`/`Superseded` (query.rs:104-139).

---

## 4. Gid type — opaque?

**Treat it as opaque.** Facts (src/gid.rs):
- Binary form: **33 bytes** = 1 family-code byte + 32-byte BLAKE3-256 digest (gid.rs:3-5, 58-63). Textual form: `<family-short>.<64 lowercase hex>` (gid.rs:5, 74-78).
- Creation: `Gid::new(family, [u8;32])` (gid.rs:43); from bytes: `Gid::from_bytes(&[u8;33]) -> Option<Gid>` (rejects unknown family, gid.rs:66-71); parse text: `s.parse::<Gid>()` (FromStr, gid.rs:80-101) — **strictly lowercase hex, exactly 64 chars**, rejects uppercase; errors: `ParseGidError { MissingSeparator, UnknownFamily, MalformedDigest }` (gid.rs:19-27).
- Accessors: `family()`, `digest() -> &[u8;32]`, `to_bytes()` (gid.rs:48-63). Fields are private; no reinterpretation API exists beyond `to_bytes`/`from_bytes`. `Display` prints `<short>.<hex>`.
- In canonical objects, a Gid reference is encoded as `varint(33) || 33 bytes` (encode.rs:232-236; decode.rs:315-340).
- Derivation: `ObjectId = BLAKE3-256(canonical envelope bytes)` (hash.rs:3). frf-fuzz must not compute identities itself except through gemel's `encode_object` + `object_id_bytes`/`object_id`, or `insert_object`.

---

## 5. Canonical object encoding (GCE)

- **Envelope** (encode.rs:27-31; consts.rs:3-16): `"GEML"` (4 bytes) | `ENC_VERSION` (1 byte = 0x01) | family code | schemever (1) | flags (0x00) | `varint(body_len)` | body. Envelope ≤ 9 bytes minimum (decode.rs:21).
- **Body**: blob family → raw bytes; all other families → strict-ascending tagged field sequence. Each field: `varint(tag) | varint(value_len) | value bytes` (encode.rs:133-135). Tags 0x01..=0x7F are schema-mandatory (unknown → fail closed); 0x80..=0xEF extension tags carry opaque `Raw` bytes where `extensions_allowed`; 0x00 and 0xF0..=0xFF reserved (consts.rs:13-17, encode.rs:87-111).
- **Determinism**: field tags strictly ascending, no duplicates, required fields present, enum/path/Gid-family checks, limits enforced (encode.rs:3-4, 83-147). Encoding always validates (encode.rs:1-4); decoding fails closed on any non-canonical input (decode.rs:1-4).
- **API**:
  ```rust
  pub fn encode_object(obj: &Object, limits: &Limits) -> Result<Vec<u8>, ObjectError>   // encode.rs:16
  pub fn decode_object(bytes: &[u8], limits: &Limits) -> Result<Object, ObjectError>     // decode.rs:20
  pub fn object_id(obj: &Object, limits: &Limits) -> Result<Gid, ObjectError>            // hash.rs:28
  pub fn object_id_bytes(bytes: &[u8]) -> [u8; 32]                                        // hash.rs:17
  pub fn gid_from_envelope(bytes: &[u8]) -> Option<Gid>                                   // hash.rs:22
  ```
- Values: `Value` enum above; integers = canonical LEB128 / zigzag (varint.rs:1-14); bool = 0x00/0x01; strings byte-identical, never normalized (value.rs:23); Gid refs = 33 raw bytes (encode.rs:232-236).
- **There is no serde impl for `Object`** — the crate does not depend on `serde` directly (only `serde_json`), and `Object` carries no `Serialize`/`Deserialize` derives (value.rs). frf-fuzz must build objects via `Object::fields`/`Object::blob` + `Field::new` and let gemel encode; or store raw envelopes via `insert_bytes`.
- Machine-readable field schemas: `spec::schema_for(family)` / `all_schemas()` (spec.rs:1199, 1229); `FamilySchema::field(tag)` / `field_by_name(name)` (spec.rs:67-74). Deterministic JSON projection: `json::object_to_json` (json.rs:16).

---

## 6. Transitive dependencies; backend requirements

**Full lock-file tree** (Cargo.lock): gemel direct deps as in §1, plus:
`adler2 2.0.1`, `anstream 1.0.0`, `anstyle 1.0.14`, `anstyle-parse 1.0.0`, `anstyle-query 1.1.5`, `anstyle-wincon 3.0.11`, `arrayvec 0.7.8`, `bitflags 2.13.1`, `block-buffer 0.10.4`, `bumpalo 3.20.3`, `cc 1.4.4`, `cfg-if 1.0.4`, `clap_builder 4.6.6`, `clap_derive 4.6.4`, `clap_lex 1.1.0`, `colorchoice 1.0.5`, `constant_time_eq 0.4.2`, `cpufeatures 0.2.17 / 0.3.0`, `crc32fast 1.5.1`, `crypto-common 0.1.7`, `digest 0.10.7`, `errno 0.3.14`, `fallible-iterator 0.3.0`, `fallible-streaming-iterator 0.1.9`, `find-msvc-tools 0.1.11`, `foldhash 0.2.0`, `generic-array 0.14.7`, `hashbrown 0.16.1/0.17.1`, `hashlink 0.12.1`, `heck 0.5.0`, `is_terminal_polyfill 1.70.2`, `itoa 1.0.18`, `js-sys 0.3.104`, `libc 0.2.189`, `libsqlite3-sys 0.38.2` (via rusqlite `bundled` → compiles SQLite with `cc`), `linux-raw-sys 0.12.1`, `memchr 2.8.3`, `miniz_oxide 0.8.9`, `once_cell 1.21.4`, `once_cell_polyfill 1.70.2`, `pkg-config 0.3.34`, `proc-macro2 1.0.107`, `quote 1.0.47`, `rsqlite-vfs 0.1.1` (wasm-target), `rustix 1.1.4`, `rustversion 1.0.23`, `serde 1.0.229`, `serde_core`, `serde_derive`, `shlex 2.0.1`, `simd-adler32 0.3.10`, `smallvec 1.15.2`, `sqlite-wasm-rs 0.5.5` (wasm-target), `strsim 0.11.1`, `syn 2.0.119 / 3.0.4`, `thiserror 2.0.20`, `typenum`, `unicode-ident`, `utf8parse 0.2.2`, `vcpkg 0.2.15`, `version_check`, `wasm-bindgen*` (wasm-target), `windows-*` (windows-target), `zmij` (serde_json dep).

**Backend requirements for the library API:**
- The core (repo store, encode/decode, workflow, query, content, exchange, sync-file) is **pure local filesystem** — no network, no git binary, no daemon. `Repo::init/open/find`, `insert_object`, refs, queries all operate on `<root>/.gemel/`.
- **`git` binary is NOT required** for the core. It is required only by `git_adapter` (used by `git_interop::import_git`, `clone_repo`; git_adapter.rs:13-23, 171-181). `git_interop::export_git` writes loose Git objects itself (sha1 + flate2 zlib; git_io.rs) without invoking git.
- **Network**: only in `sync::transports` — `SshTransport` spawns the system `ssh` binary (transports.rs:256-266); `HttpTransport`/`serve_http` use `std::net::TcpStream`/`TcpListener` (transports.rs:26, 834). None are touched by discovery/store/workflow/query.
- **SQLite index** (rusqlite `bundled`) is created lazily on first object insert or query (index.rs:30-40) and is *derived/disposable* (index.rs:1-7); index failures are swallowed (store marks it stale; store/mod.rs:482-496). It is an accelerator, not required for correctness (`scan_canonical` is the always-correct slow path, store/mod.rs:503-508).
- **Build-time note**: rusqlite `bundled` compiles SQLite from source → a C compiler (`cc`) is needed at build time; there is no system-sqlite linkage requirement (Cargo.toml:108, libsqlite3-sys via cc).

---

## 7. Integration gotchas

1. **No `unsafe` in the library.** The only `unsafe` in the crate is `reset_sigpipe` in the CLI binary `src/bin/gemel.rs:511-520`. The other "unsafe" match is a string in a golden fixture (golden/mod.rs:347).
2. **Locking is advisory, non-reentrant, flock-based** (`fd-lock`): nested `with_write_lock` on the same repo deadlocks; store code uses `*_unlocked` helpers inside one outer lock scope (lock.rs:7-9). `workflow::{begin_change, finish_change, create_checkpoint, close_trajectory, resolve_residual}` and `reconcile::reconcile` acquire the lock themselves — do not wrap them in `repo.with_write_lock`. Readers never lock (lock.rs:3-5).
3. **Object inserts are lock-free; ref transactions take the lock.** `insert_object`/`insert_bytes` do not lock (store/mod.rs:357-373); `write_refs` acquires the writer lock (store/mod.rs:429-435); `apply_refs_unlocked` requires the caller to hold it (store/mod.rs:439-443).
4. **`Repo::open` may write**: opportunistic journal recovery takes the write lock if free and can roll back interrupted ref transactions + rebuild the derived index (store/mod.rs:250, 347-354). Fine at durable boundaries; be aware it is not strictly read-only.
5. **Global state**: `objects::TEMP_SEQ` (static `AtomicU64`) uniquifies temp filenames for atomic writes (objects.rs:54, 78-79); test-only `testing::COUNTER` (store/mod.rs:545). No other statics in the library.
6. **MSRV 1.85 / edition 2021**: code uses `let else` (store/mod.rs:424-426 etc.), `Option::is_none_or`-style patterns are avoided, `#[derive(Default)]` on options. No nightly features. Building needs a C toolchain (bundled SQLite).
7. **No feature flags exist** (§1). Nothing switches storage backends; storage is always the filesystem store. (The only "backends" are the *transports* for sync, selected by which `Transport` impl you construct — file/ssh/http.)
8. **`workspace_named_dir` panics** on invalid workspace names (`""`, `.`, `..`, or containing `/`, `\`, NUL) — workflow.rs:53-64. Validate workspace strings yourself.
9. **`finish_change` snapshots the whole working tree** (content.rs:63; workflow.rs:361-367) and writes a pending.json — per-execution use would violate frf-fuzz's "no per-execution writes" constraint. Use direct object construction + `insert_object` + one ref transaction for boundary events.
10. **Name counters are single-writer**: `workflow::next_name` reads/writes `meta.json` under the writer lock (workflow.rs:145-160). Concurrent name allocation outside the lock corrupts counters.
11. **Canonical strictness**: field tags must be pushed in strict ascending order or the encoder rejects (`UnsortedFields`, encode.rs:93-96; workflow comments at workflow.rs:414-417, 560-562). Gid text parse rejects uppercase hex (gid.rs:86-92). Object sizes/limits default as in §2 `Limits`.
12. **`insert_object` decodes its own bytes to re-validate** (store/mod.rs:365) — a second full parse per insert; fine at boundary frequency.
13. **Trajectory/chain loops are guarded at 4096** (`chain_latest`, `trajectory_versions`, query.rs:576-586, 651-661).
14. **Error types are large, unboxed** (store `Error` has 20 variants, store/mod.rs:44-98; `ObjectError` 40+, error.rs:11-100) — the crate allows `result_large_err` (lib.rs:22). Match exhaustively or use `?`; do not `size_of`-optimize them.
15. **Index writes are best-effort** — object insert/ref txn succeed even if the SQLite note fails; the index is marked stale and rebuilt later (store/mod.rs:482-496; index.rs:1-7). Never treat index absence as data loss.
16. **Exchange auto-ingest is CLI behavior, not `Repo::open`**: the CLI calls `exchange::ingest::ingest` after opening when frontiers exist (bin/gemel.rs:580-588). The library `Repo::open` does not ingest exchange material.
17. **fsck exit codes**: 0 clean, 1 repairs/recovery, 2 errors (store/fsck.rs:70-85).

---

## 8. Concrete recommendation for frf-fuzz

**Feature set**: none — gemel has no features; depend on `gemel = "0.11.0"` (MSRV 1.85; C toolchain needed for bundled SQLite at build time). Only the following modules are needed at runtime: `gemel::store`, `gemel::workflow` (read helpers + boundary ops), `gemel::query`, `gemel::content`, `gemel::value`, `gemel::family`, `gemel::gid`, `gemel::hash`, `gemel::encode`, `gemel::limits`, `gemel::defaults`, `gemel::ignore`, `gemel::spec` (for field tables). No `sync`, `exchange`, `git_*`, `protocol`, `court`, `semantic` needed.

**Work perfectly without gemel**: gate on detection — `Repo::find(dir)`/`Repo::open(dir)` returning `Err(Error::NotARepository(_))` (store/mod.rs:255-264, 241-252) means "no gemel repo": run frf-fuzz's own bookkeeping. Never make gemel writes required for execution.

**No per-execution writes**: reads only during the fuzz loop — `repo.read_ref(REF_STATE_HEAD)`, `read_ref(REF_HEAD)`, `workflow::read_pending`, `read_ref("refs/trajectories/current")`, `repo.read_meta()` (all pure reads; refs/objects are immutable, readers never lock, lock.rs:3-5). All writes happen at durable boundaries only.

### Exact call sequence

**(a) Discover repo + capture current state Gid + active intent/change/trajectory (boundary-time, read-only):**
```rust
use gemel::store::{Repo, REF_HEAD, REF_STATE_HEAD};
use gemel::workflow;

let repo = match Repo::find(start_dir) {          // store/mod.rs:255; walks up parents
    Ok(r) => r,
    Err(gemel::store::Error::NotARepository(_)) => { /* gemel absent: frf-fuzz standalone path */ }
};
let head_state: Option<Gid> = repo.read_ref(REF_STATE_HEAD)?;      // store/mod.rs:424; current state Gid
let head_change: Option<Gid> = repo.read_ref(REF_HEAD)?;           // current Change Gid
let pending = workflow::read_pending(&repo)?;                      // workflow.rs:107; active intent = pending["intent"]
let meta = repo.read_meta()?;                                      // store/mod.rs:308; default_producer Gid
let cur_traj = repo.read_ref("refs/trajectories/current")?;        // current Trajectory Gid
```

**(b) Record a promoted finding (FRF-verified) bound to the current state Gid** — at a durable boundary, with one lock-free object publish + one journaled ref transaction:
```rust
use gemel::value::{Object, Field, Value};
use gemel::family::Family;
use gemel::store::{now_ms, refs::{RefOp, RefTransaction}};   // now_ms store/mod.rs:532

let producer: Gid = meta["default_producer"].as_str().unwrap().parse()?;
let state_gid = head_state.ok_or(/* no head state: repo empty */)?;

// Evidence bound to the exact state via field 0x11 (spec.rs:730)
let evidence = Object::fields(Family::Evidence, vec![
    Field::new(0x01, Value::Gid(producer)),                                  // producer (required)
    Field::new(0x02, Value::Str("fuzz_result".into())),                      // kind ∈ ENUM_EVIDENCE_KIND
    Field::new(0x03, Value::Str(subject.clone())),                           // subject
    Field::new(0x0D, Value::Record(vec![Field::new(0x01, Value::Str("pass".into()))])), // result.outcome
    Field::new(0x11, Value::Gid(state_gid)),                                 // evaluated_state binding
    Field::new(0x10, Value::I(now_ms())),                                    // created_at
]);
let evidence_id = repo.insert_object(&evidence)?;        // store/mod.rs:357 — lock-free, dedup

let claim = Object::fields(Family::Claim, vec![
    Field::new(0x01, Value::Str(subject.clone())),                            // 0x01 subject
    Field::new(0x03, Value::Str(predicate)),                                  // 0x03 predicate (required)
    Field::new(0x04, Value::Str("correctness".into())),                       // 0x04 predicate_kind
    Field::new(0x07, Value::Gid(producer)),                                   // 0x07 producer (required)
    Field::new(0x08, Value::Array(vec![Value::Gid(evidence_id)])),            // 0x08 evidence link
    Field::new(0x0E, Value::I(now_ms())),                                     // 0x0E created_at
]);                                                                           // tags strictly ascending
let claim_id = repo.insert_object(&claim)?;
repo.write_refs(&RefTransaction {                                             // store/mod.rs:429; journaled, atomic
    ops: vec![
        RefOp::set(&format!("refs/names/P{}", next), claim_id),               // human name (optional)
        // or bind into a durable boundary: workflow::create_checkpoint, or a Change object
    ],
})?;
```
For a **campaign/checkpoint boundary**, prefer `workflow::create_checkpoint(&repo, &CheckpointOptions { summary, producer })` (workflow.rs:735) which publishes a Checkpoint object + `refs/checkpoints/K<n>`/`current` under one transaction — designed as a continuation boundary. For a **promoted precedent as a Change**, construct the Change object directly with `input_state`/`resulting_state`/`evidence`/`claims` fields (tags 0x01,0x03,0x05,0x06,0x0C,0x0D,0x15, workflow.rs:563-607) and set `refs/head` + `refs/state/head` + `refs/names/C<n>`/`S<n>` in one `RefTransaction`.

**(c) Record a falsified precedent (negative knowledge)** — `workflow::close_trajectory` with outcome `"rejected"` (workflow.rs:867; outcomes spec.rs:105-112) at the boundary, plus a Residual for the divergence:
```rust
use gemel::workflow::{close_trajectory, CloseTrajectoryOptions, resolve_residual, ResolveResidualOptions};
let closed = close_trajectory(&repo, &CloseTrajectoryOptions {
    trajectory: "T3".into(),            // name or identity (resolve() order, store/mod.rs:287)
    outcome: "rejected".into(),         // rejected attempts are preserved, never extended (workflow.rs:518-521)
    reason: Some("FRF falsified precedent".into()),
    producer: None,                     // defaults to repo default producer
})?;
// Optionally record the divergence as a Residual bound to the same state:
let residual = Object::fields(Family::Residual, vec![
    Field::new(0x02, Value::Str("falsified precedent".into())),
    Field::new(0x03, Value::Str("unexplained_divergence".into())),   // enum, spec.rs:147-156
    Field::new(0x04, Value::Str("medium".into())),
    Field::new(0x08, Value::Gid(evidence_id)),                       // origin evidence
    Field::new(0x0C, Value::I(now_ms())),
]);
let residual_id = repo.insert_object(&residual)?;
// later disposition:
let _ = resolve_residual(&repo, &ResolveResidualOptions {
    residual: residual_id.to_string(),
    disposition: "resolved".into(),    // open|acknowledged|resolved|superseded|irrelevant
    reason: Some("FRF verification completed".into()),
    producer: None,
})?;
```

**(d) Enumerate revision states for future tape replay** (read-only; do at boundary):
```rust
use gemel::query;
let entries = query::log(&repo, usize::MAX)?;                 // query.rs:32 — all changes, oldest→newest
for e in &entries {
    if let Some(state) = e.resulting_state {
        let files = gemel::content::state_files(&repo, &state)?;   // content.rs:403 — (path, (mode, blob Gid))
        // stash (state Gid, files map) into the tape; replay later with:
        // gemel::content::materialize_overlay(&repo, &state, &target_dir)  // content.rs:437
    }
}
// Alternative raw walk: head_closure (git_interop.rs:271) + Change field 0x05 resulting_state / 0x11 causal_parents.
```

**Guarantees for the "no per-execution writes" contract**: all reads above touch only immutable object files and ref files; readers never take the writer lock (lock.rs:3-5); the single caveat is `Repo::find`→`Repo::open`'s opportunistic journal recovery (store/mod.rs:250, 347-354), which only runs when a previous transaction was interrupted — acceptable, and it only ever restores canonical state. Every durable write is either a lock-free immutable object publish (`insert_object`) or a journaled, atomic, fsynced ref transaction (`write_refs`), so any crash leaves either the old or the new boundary, never a partial one.
