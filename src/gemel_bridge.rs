//! Gemel bridge (Phase 4): longitudinal engineering memory.
//!
//! frf-fuzz works perfectly without Gemel: when no `.gemel` repository is
//! discoverable from the project root, every boundary is standalone (I14).
//! When one IS present:
//!
//! * the fuzz loop itself stays read-only w.r.t. Gemel — never a per-
//!   execution Gemel write (I5); reads never take the writer lock;
//! * durable boundaries publish into the repo: campaign creation/completion
//!   become Gemel checkpoints; an FRF-verified finding publishes an
//!   `Evidence` (kind `court_receipt`, bound to the current state Gid via
//!   field 0x11) plus a `Claim`; a promoted structural precedent publishes
//!   an `Evidence` (kind `fuzz_result`) of the terminal observation; a
//!   falsified precedent publishes a `Residual` (classification
//!   `expected_mismatch`) — negative knowledge that is never deleted (I10);
//! * every boundary also writes a LOCAL `Family::GemelBoundary` (0x10)
//!   object recording the Gemel source-state snapshot (head-state/change/
//!   intent/trajectory/producer Gids, verbatim), the published outcome
//!   Gids, and — when Gemel refused — a deterministic failure class. The
//!   local record makes a Gemel-side failure observable and never silent,
//!   and `fsck` can validate the recorded links.
//!
//! Gemel Gids are opaque identities (`<family>.<64-hex>`); they are retained
//! verbatim and never reinterpreted or merged with frf-fuzz `ContentId`s or
//! FRF ids (three separate namespaces, docs/INVARIANTS.md).
//!
//! This module is coordinator-gated.

use crate::canon::Family;
use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::store::Store as FrfFuzzStore;

/// Version of the gemel-boundary payload encoding.
pub const GEMEL_BOUNDARY_VERSION: u8 = 1;
/// Maximum length of a retained Gemel id string (Gids are 66 chars; bound
/// generously for future identity forms, before allocation).
pub const MAX_GEMEL_ID_LEN: usize = 512;

/// The durable frf-fuzz boundary kinds that publish into Gemel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BoundaryKind {
    /// A campaign was created.
    CampaignCreated = 1,
    /// A campaign completed (all exit paths).
    CampaignCompleted = 2,
    /// A promoted finding was FRF-verified (receipt emitted).
    FindingVerified = 3,
    /// A structural precedent was admitted from a terminal observation.
    PrecedentAdmitted = 4,
    /// A precedent was falsified by a contradicting probe.
    FalsifiedPrecedent = 5,
}

impl BoundaryKind {
    /// The wire byte.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<BoundaryKind> {
        match b {
            1 => Some(BoundaryKind::CampaignCreated),
            2 => Some(BoundaryKind::CampaignCompleted),
            3 => Some(BoundaryKind::FindingVerified),
            4 => Some(BoundaryKind::PrecedentAdmitted),
            5 => Some(BoundaryKind::FalsifiedPrecedent),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            BoundaryKind::CampaignCreated => "campaign-created",
            BoundaryKind::CampaignCompleted => "campaign-completed",
            BoundaryKind::FindingVerified => "finding-verified",
            BoundaryKind::PrecedentAdmitted => "precedent-admitted",
            BoundaryKind::FalsifiedPrecedent => "falsified-precedent",
        }
    }
}

/// Whether the Gemel-side publication of a boundary completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PublishState {
    /// The Gemel objects were published (checkpoint/evidence/claim/residual).
    Published = 0,
    /// Gemel refused or failed; the failure class records why.
    Failed = 1,
}

impl PublishState {
    /// The wire byte.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<PublishState> {
        match b {
            0 => Some(PublishState::Published),
            1 => Some(PublishState::Failed),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            PublishState::Published => "published",
            PublishState::Failed => "failed",
        }
    }
}

/// Deterministic failure classes for a Gemel publication (codes, not free
/// text — the local record stays canonical).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GemelFailure {
    /// No failure (published).
    None = 0,
    /// The boundary needs a state binding but the repo has no head state.
    NoHeadState = 1,
    /// Gemel could not be opened/discovered cleanly (corrupt repo etc.).
    RepoBroken = 2,
    /// The checkpoint publication was refused.
    CheckpointFailed = 3,
    /// An object insert was refused.
    InsertFailed = 4,
    /// The read-only snapshot failed.
    SnapshotFailed = 5,
}

impl GemelFailure {
    /// The wire byte.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<GemelFailure> {
        match b {
            0 => Some(GemelFailure::None),
            1 => Some(GemelFailure::NoHeadState),
            2 => Some(GemelFailure::RepoBroken),
            3 => Some(GemelFailure::CheckpointFailed),
            4 => Some(GemelFailure::InsertFailed),
            5 => Some(GemelFailure::SnapshotFailed),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            GemelFailure::None => "none",
            GemelFailure::NoHeadState => "no-head-state",
            GemelFailure::RepoBroken => "repo-broken",
            GemelFailure::CheckpointFailed => "checkpoint-failed",
            GemelFailure::InsertFailed => "insert-failed",
            GemelFailure::SnapshotFailed => "snapshot-failed",
        }
    }
}

/// The durable local record of one Gemel boundary (Family::GemelBoundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryRecord {
    /// The boundary kind.
    pub kind: BoundaryKind,
    /// The frf-fuzz subject (campaign/finding/precedent content id).
    pub subject: ContentId,
    /// Whether the Gemel-side publication completed.
    pub state: PublishState,
    /// The deterministic failure class (None when published).
    pub failure: GemelFailure,
    /// Gemel head-state Gid text at the boundary (verbatim; absent on an
    /// empty repo).
    pub head_state: Option<String>,
    /// Gemel head-change Gid text at the boundary (verbatim).
    pub head_change: Option<String>,
    /// The active intent Gid text at the boundary (verbatim), when a change
    /// was in progress.
    pub intent: Option<String>,
    /// The current trajectory Gid text at the boundary (verbatim).
    pub trajectory: Option<String>,
    /// The repository default producer Gid text (verbatim).
    pub producer: Option<String>,
    /// The published checkpoint Gid (campaign boundaries).
    pub checkpoint: Option<String>,
    /// The published evidence Gid (finding-verified / precedent-admitted).
    pub evidence: Option<String>,
    /// The published claim Gid (finding-verified).
    pub claim: Option<String>,
    /// The published residual Gid (falsified precedent — negative knowledge).
    pub residual: Option<String>,
}

/// The read-only Gemel source-state snapshot captured at a boundary.
#[derive(Debug, Clone, Default)]
pub struct GemelSnapshot {
    /// `refs/state/head` Gid text.
    pub head_state: Option<String>,
    /// `refs/head` (current Change) Gid text.
    pub head_change: Option<String>,
    /// The active intent Gid text (`worktree pending.json`), when present.
    pub intent: Option<String>,
    /// `refs/trajectories/current` Gid text.
    pub trajectory: Option<String>,
    /// The repo default producer Gid text.
    pub producer: Option<String>,
}

/// Encode a boundary record to its canonical payload.
pub fn encode_boundary(b: &BoundaryRecord) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 1 + 32 + 1 + 1);
    out.push(GEMEL_BOUNDARY_VERSION);
    out.push(b.kind.code());
    out.extend_from_slice(b.subject.as_bytes());
    out.push(b.state.code());
    out.push(b.failure.code());
    push_opt(&mut out, b.head_state.as_deref())?;
    push_opt(&mut out, b.head_change.as_deref())?;
    push_opt(&mut out, b.intent.as_deref())?;
    push_opt(&mut out, b.trajectory.as_deref())?;
    push_opt(&mut out, b.producer.as_deref())?;
    push_opt(&mut out, b.checkpoint.as_deref())?;
    push_opt(&mut out, b.evidence.as_deref())?;
    push_opt(&mut out, b.claim.as_deref())?;
    push_opt(&mut out, b.residual.as_deref())?;
    Ok(out)
}

/// Decode a boundary record from its canonical payload.
pub fn decode_boundary(bytes: &[u8]) -> Result<BoundaryRecord> {
    let mut r = GReader { bytes, pos: 0 };
    let version = r.take(1)?[0];
    if version != GEMEL_BOUNDARY_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "gemel-boundary",
            version: version as u32,
        });
    }
    let kind = BoundaryKind::from_byte(r.take(1)?[0])
        .ok_or(Error::Encoding("unknown gemel boundary kind"))?;
    let subject: [u8; 32] = r.take(32)?.try_into().unwrap();
    let state = PublishState::from_byte(r.take(1)?[0])
        .ok_or(Error::Encoding("unknown gemel publish state"))?;
    let failure = GemelFailure::from_byte(r.take(1)?[0])
        .ok_or(Error::Encoding("unknown gemel failure class"))?;
    let head_state = r.take_opt()?;
    let head_change = r.take_opt()?;
    let intent = r.take_opt()?;
    let trajectory = r.take_opt()?;
    let producer = r.take_opt()?;
    let checkpoint = r.take_opt()?;
    let evidence = r.take_opt()?;
    let claim = r.take_opt()?;
    let residual = r.take_opt()?;
    if r.pos != bytes.len() {
        return Err(Error::Encoding("gemel boundary has trailing bytes"));
    }
    Ok(BoundaryRecord {
        kind,
        subject: ContentId::from_array(subject),
        state,
        failure,
        head_state,
        head_change,
        intent,
        trajectory,
        producer,
        checkpoint,
        evidence,
        claim,
        residual,
    })
}

struct GReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> GReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > self.bytes.len() {
            return Err(Error::Encoding("gemel boundary truncated"));
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn take_opt(&mut self) -> Result<Option<String>> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => {
                let len = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
                if len > MAX_GEMEL_ID_LEN {
                    return Err(Error::BoundExceeded {
                        what: "gemel id field",
                        limit: MAX_GEMEL_ID_LEN as u64,
                        got: len as u64,
                    });
                }
                let s = std::str::from_utf8(self.take(len)?)
                    .map_err(|_| Error::Encoding("gemel id field is not utf-8"))?;
                Ok(Some(s.to_string()))
            }
            _ => Err(Error::Encoding("invalid gemel optional field flag")),
        }
    }
}

fn push_opt(out: &mut Vec<u8>, s: Option<&str>) -> Result<()> {
    match s {
        Some(s) => {
            if s.len() > MAX_GEMEL_ID_LEN {
                return Err(Error::BoundExceeded {
                    what: "gemel id field",
                    limit: MAX_GEMEL_ID_LEN as u64,
                    got: s.len() as u64,
                });
            }
            out.push(1u8);
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        None => out.push(0u8),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Discovery + snapshot (read-only)
// ---------------------------------------------------------------------------

/// The discovery result for a Gemel repository at a project root.
#[derive(Debug)]
pub enum GemelDiscovery {
    /// No repository (standalone mode; no boundary records are written).
    Absent,
    /// A repository was found and opened.
    Present(gemel::store::Repo),
    /// A `.gemel` directory exists but could not be opened cleanly.
    /// Boundaries record `Failure::RepoBroken`; the campaign never fails.
    Broken(String),
}

/// Discover a Gemel repository by walking up from `start`.
pub fn discover(start: &std::path::Path) -> GemelDiscovery {
    match gemel::store::Repo::find(start) {
        Ok(repo) => GemelDiscovery::Present(repo),
        Err(gemel::store::Error::NotARepository(_)) => GemelDiscovery::Absent,
        Err(e) => GemelDiscovery::Broken(e.to_string()),
    }
}

/// Capture the read-only source-state snapshot of a repository.
pub fn snapshot(repo: &gemel::store::Repo) -> Result<GemelSnapshot> {
    use gemel::store::{REF_HEAD, REF_STATE_HEAD};
    let head_state = repo
        .read_ref(REF_STATE_HEAD)
        .map_err(|e| Error::Other(format!("gemel read_ref(state/head): {e}")))?
        .map(|g| g.to_string());
    let head_change = repo
        .read_ref(REF_HEAD)
        .map_err(|e| Error::Other(format!("gemel read_ref(head): {e}")))?
        .map(|g| g.to_string());
    let trajectory = repo
        .read_ref("refs/trajectories/current")
        .map_err(|e| Error::Other(format!("gemel read_ref(trajectories/current): {e}")))?
        .map(|g| g.to_string());
    let intent = match gemel::workflow::read_pending(repo)
        .map_err(|e| Error::Other(format!("gemel read_pending: {e}")))?
    {
        Some(pending) => pending
            .get("intent")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        None => None,
    };
    let producer = repo
        .read_meta()
        .map_err(|e| Error::Other(format!("gemel read_meta: {e}")))?
        .get("default_producer")
        .cloned()
        .and_then(|v| v.as_str().map(|s| s.to_string()));
    Ok(GemelSnapshot {
        head_state,
        head_change,
        intent,
        trajectory,
        producer,
    })
}

// ---------------------------------------------------------------------------
// Boundary publication
// ---------------------------------------------------------------------------

/// Publish one durable boundary into Gemel (when a repository is present)
/// and persist the local `GemelBoundary` record.
///
/// Returns `Ok(None)` in standalone mode (no repository); `Ok(Some(id))` —
/// the local record's content id — when a repository is present (whether the
/// Gemel-side publication succeeded or failed, so failures are observable).
///
/// `evidence_detail` is an optional human detail bound into published
/// evidence result records (e.g. the FRF receipt id for verified findings).
pub fn publish_boundary(
    store: &FrfFuzzStore,
    project_root: &std::path::Path,
    kind: BoundaryKind,
    subject: ContentId,
    evidence_detail: Option<&str>,
) -> Result<Option<ContentId>> {
    let repo = match discover(project_root) {
        GemelDiscovery::Absent => return Ok(None),
        GemelDiscovery::Broken(msg) => {
            eprintln!("[frf-fuzz] gemel repository present but broken: {msg}");
            return persist_local_record(
                store,
                &empty_record(kind, subject, GemelFailure::RepoBroken),
            );
        }
        GemelDiscovery::Present(repo) => repo,
    };

    let snap = match snapshot(&repo) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[frf-fuzz] gemel snapshot failed: {e}");
            return persist_local_record(
                store,
                &empty_record(kind, subject, GemelFailure::SnapshotFailed),
            );
        }
    };

    let mut record = BoundaryRecord {
        kind,
        subject,
        state: PublishState::Failed,
        failure: GemelFailure::None,
        head_state: snap.head_state.clone(),
        head_change: snap.head_change.clone(),
        intent: snap.intent.clone(),
        trajectory: snap.trajectory.clone(),
        producer: snap.producer.clone(),
        checkpoint: None,
        evidence: None,
        claim: None,
        residual: None,
    };

    let published = match kind {
        BoundaryKind::CampaignCreated | BoundaryKind::CampaignCompleted => {
            publish_checkpoint(&repo, kind, subject)
        }
        BoundaryKind::FindingVerified => {
            publish_verified_finding(&repo, &snap, subject, evidence_detail)
        }
        BoundaryKind::PrecedentAdmitted => publish_precedent(&repo, &snap, subject),
        BoundaryKind::FalsifiedPrecedent => publish_falsified(&repo, subject),
    };

    match published {
        Ok(out) => {
            record.state = PublishState::Published;
            record.failure = GemelFailure::None;
            record.checkpoint = out.checkpoint;
            record.evidence = out.evidence;
            record.claim = out.claim;
            record.residual = out.residual;
        }
        Err((code, msg)) => {
            record.state = PublishState::Failed;
            record.failure = code;
            eprintln!(
                "[frf-fuzz] gemel boundary {} ({}) failed: {}",
                kind.name(),
                subject,
                msg
            );
        }
    }
    persist_local_record(store, &record)
}

/// What a publication produced (Gid texts, verbatim).
#[derive(Debug, Default)]
struct PublishOutcome {
    checkpoint: Option<String>,
    evidence: Option<String>,
    claim: Option<String>,
    residual: Option<String>,
}

fn empty_record(kind: BoundaryKind, subject: ContentId, failure: GemelFailure) -> BoundaryRecord {
    BoundaryRecord {
        kind,
        subject,
        state: PublishState::Failed,
        failure,
        head_state: None,
        head_change: None,
        intent: None,
        trajectory: None,
        producer: None,
        checkpoint: None,
        evidence: None,
        claim: None,
        residual: None,
    }
}

fn persist_local_record(
    store: &FrfFuzzStore,
    record: &BoundaryRecord,
) -> Result<Option<ContentId>> {
    let payload = encode_boundary(record)?;
    Ok(Some(store.put(Family::GemelBoundary, &payload)?))
}

/// Campaign boundaries become Gemel checkpoints (a continuation boundary).
fn publish_checkpoint(
    repo: &gemel::store::Repo,
    kind: BoundaryKind,
    subject: ContentId,
) -> std::result::Result<PublishOutcome, (GemelFailure, String)> {
    let summary = format!(
        "frf-fuzz {} boundary: subject {}",
        kind.name(),
        subject.to_hex()
    );
    let opts = gemel::workflow::CheckpointOptions {
        summary: Some(summary),
        producer: None, // repository default producer
    };
    let outcome = gemel::workflow::create_checkpoint(repo, &opts)
        .map_err(|e| (GemelFailure::CheckpointFailed, e.to_string()))?;
    Ok(PublishOutcome {
        checkpoint: Some(outcome.checkpoint.to_string()),
        ..PublishOutcome::default()
    })
}

/// An FRF-verified finding publishes Evidence (kind `court_receipt`, bound
/// to the current state Gid) plus a Claim (kind `behavior`).
fn publish_verified_finding(
    repo: &gemel::store::Repo,
    snap: &GemelSnapshot,
    subject: ContentId,
    evidence_detail: Option<&str>,
) -> std::result::Result<PublishOutcome, (GemelFailure, String)> {
    use gemel::family::Family as GFamily;
    use gemel::store::now_ms;
    use gemel::value::{Field, Object, Value};

    let state_gid = snap
        .head_state
        .as_ref()
        .ok_or((
            GemelFailure::NoHeadState,
            "no head state to bind evidence to".into(),
        ))?
        .parse::<gemel::gid::Gid>()
        .map_err(|e| (GemelFailure::NoHeadState, e.to_string()))?;
    let producer = snap
        .producer
        .as_ref()
        .ok_or((
            GemelFailure::NoHeadState,
            "repo has no default producer".into(),
        ))?
        .parse::<gemel::gid::Gid>()
        .map_err(|e| (GemelFailure::NoHeadState, e.to_string()))?;

    // Evidence: kind court_receipt, subject = the finding, bound to the
    // evaluated state (field 0x11). The FRF receipt/run ids ride in the
    // result detail (verbatim, bounded).
    let detail = match evidence_detail {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => "frf-verified".to_string(),
    };
    let evidence = Object::fields(
        GFamily::Evidence,
        vec![
            Field::new(0x01, Value::Gid(producer)),
            Field::new(0x02, Value::Str("court_receipt".into())),
            Field::new(
                0x03,
                Value::Str(format!("frf-fuzz finding {}", subject.to_hex())),
            ),
            Field::new(
                0x0D,
                Value::Record(vec![
                    Field::new(0x01, Value::Str("pass".into())),
                    Field::new(0x02, Value::Str(detail)),
                ]),
            ),
            Field::new(0x10, Value::I(now_ms())),
            Field::new(0x11, Value::Gid(state_gid)),
        ],
    );
    let evidence_gid = repo
        .insert_object(&evidence)
        .map_err(|e| (GemelFailure::InsertFailed, e.to_string()))?;

    // Claim: the durable statement that the finding is FRF-verified on the
    // current state.
    let claim = Object::fields(
        GFamily::Claim,
        vec![
            Field::new(0x01, Value::Str(format!("frf-fuzz finding {}", subject.to_hex()))),
            Field::new(
                0x03,
                Value::Str(format!(
                    "finding {} is FRF-verified: the candidate diverges from the authority over the declared observables on the finding's input",
                    subject.to_hex()
                )),
            ),
            Field::new(0x04, Value::Str("behavior".into())),
            Field::new(0x07, Value::Gid(producer)),
            Field::new(0x08, Value::Array(vec![Value::Gid(evidence_gid)])),
            Field::new(0x0E, Value::I(now_ms())),
        ],
    );
    let claim_gid = repo
        .insert_object(&claim)
        .map_err(|e| (GemelFailure::InsertFailed, e.to_string()))?;
    Ok(PublishOutcome {
        evidence: Some(evidence_gid.to_string()),
        claim: Some(claim_gid.to_string()),
        ..PublishOutcome::default()
    })
}

/// A promoted structural precedent publishes an Evidence (kind `fuzz_result`)
/// of the terminal observation, bound to the current state when one exists.
fn publish_precedent(
    repo: &gemel::store::Repo,
    snap: &GemelSnapshot,
    subject: ContentId,
) -> std::result::Result<PublishOutcome, (GemelFailure, String)> {
    use gemel::family::Family as GFamily;
    use gemel::store::now_ms;
    use gemel::value::{Field, Object, Value};

    let producer = snap
        .producer
        .as_ref()
        .ok_or((
            GemelFailure::NoHeadState,
            "repo has no default producer".into(),
        ))?
        .parse::<gemel::gid::Gid>()
        .map_err(|e| (GemelFailure::NoHeadState, e.to_string()))?;

    let mut fields = vec![
        Field::new(0x01, Value::Gid(producer)),
        Field::new(0x02, Value::Str("fuzz_result".into())),
        Field::new(0x03, Value::Str(format!("frf-fuzz precedent {}", subject.to_hex()))),
        Field::new(0x0D, Value::Record(vec![
            Field::new(0x01, Value::Str("fail".into())),
            Field::new(
                0x02,
                Value::Str("the lineage reached its terminal event; promoted to a durable precedent with a falsifiable probe relationship".into()),
            ),
        ])),
        Field::new(0x10, Value::I(now_ms())),
    ];
    // Bind to the current state when one exists; without a head state the
    // evidence still records the observation (no fabricated binding).
    if let Some(state_text) = &snap.head_state {
        if let Ok(state_gid) = state_text.parse::<gemel::gid::Gid>() {
            fields.push(Field::new(0x11, Value::Gid(state_gid)));
        }
    }
    let evidence_gid = repo
        .insert_object(&Object::fields(GFamily::Evidence, fields))
        .map_err(|e| (GemelFailure::InsertFailed, e.to_string()))?;
    Ok(PublishOutcome {
        evidence: Some(evidence_gid.to_string()),
        ..PublishOutcome::default()
    })
}

/// A falsified precedent publishes a Residual (classification
/// `expected_mismatch`) — negative knowledge, never deleted (I10).
fn publish_falsified(
    repo: &gemel::store::Repo,
    subject: ContentId,
) -> std::result::Result<PublishOutcome, (GemelFailure, String)> {
    use gemel::family::Family as GFamily;
    use gemel::store::now_ms;
    use gemel::value::{Field, Object, Value};

    let residual = Object::fields(
        GFamily::Residual,
        vec![
            Field::new(
                0x02,
                Value::Str(format!(
                    "frf-fuzz falsified precedent {}: a probe contradicted the precedent's continuation",
                    subject.to_hex()
                )),
            ),
            Field::new(0x03, Value::Str("expected_mismatch".into())),
            Field::new(0x04, Value::Str("medium".into())),
            Field::new(0x0C, Value::I(now_ms())),
        ],
    );
    let gid = repo
        .insert_object(&residual)
        .map_err(|e| (GemelFailure::InsertFailed, e.to_string()))?;
    Ok(PublishOutcome {
        residual: Some(gid.to_string()),
        ..PublishOutcome::default()
    })
}

/// Verify gemel-boundary link closure for `fsck`: every stored record
/// decodes and its subject reference resolves to an object of the family the
/// kind declares. Returns human-readable defects (empty = clean).
pub fn verify_links(store: &FrfFuzzStore) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    for id in store.list_object_ids()? {
        let Ok(Some((Family::GemelBoundary, payload))) = store.get_typed(&id) else {
            continue;
        };
        let rec = match decode_boundary(&payload) {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("{id}: corrupt gemel-boundary payload: {e}"));
                continue;
            }
        };
        let want = match rec.kind {
            BoundaryKind::CampaignCreated | BoundaryKind::CampaignCompleted => {
                Some(Family::Campaign)
            }
            BoundaryKind::FindingVerified => Some(Family::Finding),
            BoundaryKind::PrecedentAdmitted | BoundaryKind::FalsifiedPrecedent => {
                Some(Family::Precedent)
            }
        };
        match store.get_typed(&rec.subject) {
            Ok(Some((f, _))) => {
                if let Some(want) = want {
                    if f != want {
                        errors.push(format!(
                            "{id}: subject {} is family {} not {} for a {} boundary",
                            rec.subject,
                            f.name(),
                            want.name(),
                            rec.kind.name()
                        ));
                    }
                }
            }
            _ => errors.push(format!(
                "{id}: subject {} is missing for a {} boundary",
                rec.subject,
                rec.kind.name()
            )),
        }
        // A published record must carry at least one published Gid.
        if rec.state == PublishState::Published
            && rec.checkpoint.is_none()
            && rec.evidence.is_none()
            && rec.claim.is_none()
            && rec.residual.is_none()
        {
            errors.push(format!(
                "{id}: record is published but carries no published Gemel Gid"
            ));
        }
    }
    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BoundaryRecord {
        BoundaryRecord {
            kind: BoundaryKind::FindingVerified,
            subject: ContentId::new(b"finding"),
            state: PublishState::Published,
            failure: GemelFailure::None,
            head_state: Some("st.abc".to_string()),
            head_change: Some("ch.abc".to_string()),
            intent: None,
            trajectory: None,
            producer: Some("pr.def".to_string()),
            checkpoint: None,
            evidence: Some("ev.123".to_string()),
            claim: Some("cl.456".to_string()),
            residual: None,
        }
    }

    #[test]
    fn record_roundtrip() {
        let r = sample();
        let dec = decode_boundary(&encode_boundary(&r).unwrap()).unwrap();
        assert_eq!(dec, r);
    }

    #[test]
    fn failed_record_roundtrip() {
        let mut r = sample();
        r.state = PublishState::Failed;
        r.failure = GemelFailure::NoHeadState;
        r.evidence = None;
        r.claim = None;
        let dec = decode_boundary(&encode_boundary(&r).unwrap()).unwrap();
        assert_eq!(dec, r);
        assert_eq!(dec.failure, GemelFailure::NoHeadState);
    }

    #[test]
    fn decoder_rejects_corruption() {
        let enc = encode_boundary(&sample()).unwrap();
        assert!(decode_boundary(&enc[..enc.len() - 1]).is_err());
        let mut bad = enc.clone();
        bad[0] = 99;
        assert!(decode_boundary(&bad).is_err());
        let mut bad2 = enc.clone();
        bad2[1] = 0xEE; // unknown kind
        assert!(decode_boundary(&bad2).is_err());
    }

    #[test]
    fn kinds_and_failures_encode_stably() {
        // Lock the codes.
        assert_eq!(BoundaryKind::CampaignCreated.code(), 1);
        assert_eq!(BoundaryKind::FindingVerified.code(), 3);
        assert_eq!(BoundaryKind::FalsifiedPrecedent.code(), 5);
        assert_eq!(GemelFailure::NoHeadState.code(), 1);
        assert_eq!(PublishState::Published.code(), 0);
        assert_eq!(PublishState::Failed.code(), 1);
        for k in [
            BoundaryKind::CampaignCreated,
            BoundaryKind::CampaignCompleted,
            BoundaryKind::FindingVerified,
            BoundaryKind::PrecedentAdmitted,
            BoundaryKind::FalsifiedPrecedent,
        ] {
            assert_eq!(BoundaryKind::from_byte(k.code()), Some(k));
        }
    }

    #[test]
    fn discovery_is_absent_outside_a_repo() {
        // A scratch directory with no .gemel must discover Absent.
        let dir =
            std::env::temp_dir().join(format!("frf-fuzz-gemel-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(matches!(discover(&dir), GemelDiscovery::Absent));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovery_and_checkpoint_on_a_fresh_repo() {
        // A freshly initialized repo is Present; a campaign boundary
        // publishes a checkpoint; the local record is durable + verifies.
        let dir = std::env::temp_dir().join(format!("frf-fuzz-gemel-repo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = gemel::store::Repo::init(
            &dir,
            &gemel::store::InitOptions {
                author_name: Some("frf-fuzz tests".to_string()),
                author_email: None,
            },
        )
        .expect("gemel init");
        drop(repo);

        // Discovery from the repo directory and from a child directory.
        assert!(matches!(discover(&dir), GemelDiscovery::Present(_)));
        let child = dir.join("src");
        std::fs::create_dir_all(&child).unwrap();
        assert!(matches!(discover(&child), GemelDiscovery::Present(_)));

        // Publish a campaign boundary into a local frf-fuzz store.
        let store_dir = dir.join(".frf-fuzz");
        let store = FrfFuzzStore::open(store_dir).unwrap();
        let subject = store.put(Family::Campaign, b"campaign-payload").unwrap();
        let rec_id = publish_boundary(&store, &dir, BoundaryKind::CampaignCreated, subject, None)
            .unwrap()
            .expect("a repo is present, so a local record must exist");
        let (fam, payload) = store.get_typed(&rec_id).unwrap().unwrap();
        assert_eq!(fam, Family::GemelBoundary);
        let rec = decode_boundary(&payload).unwrap();
        assert_eq!(rec.state, PublishState::Published, "fresh repo checkpoints");
        assert_eq!(rec.kind, BoundaryKind::CampaignCreated);
        assert!(rec.checkpoint.is_some(), "checkpoint gid published");
        assert_eq!(rec.subject, subject);
        assert!(rec.head_state.is_none(), "empty repo has no head state");

        // The repo now contains the checkpoint.
        let repo = match discover(&dir) {
            GemelDiscovery::Present(r) => r,
            _ => panic!("repo must be present"),
        };
        let cps = repo.read_ref("refs/checkpoints/current").unwrap();
        assert!(cps.is_some(), "checkpoint ref must exist");

        // fsck-style link validation is clean.
        let errors = verify_links(&store).unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verified_finding_needs_a_head_state() {
        // On a fresh (headless) repo a finding-verified boundary cannot bind
        // an evaluated state: the local record says Failed(NoHeadState).
        let dir =
            std::env::temp_dir().join(format!("frf-fuzz-gemel-headless-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _repo = gemel::store::Repo::init(
            &dir,
            &gemel::store::InitOptions {
                author_name: Some("frf-fuzz tests".to_string()),
                author_email: None,
            },
        )
        .expect("gemel init");
        let store_dir = dir.join(".frf-fuzz");
        let store = FrfFuzzStore::open(store_dir).unwrap();
        let finding_payload =
            crate::execute::finding::encode_finding(&crate::execute::finding::Finding {
                kind: crate::execute::finding::FindingKind::Crash,
                parent_short: [0; 8],
                coordinate: [0; 49],
                replay: crate::execute::finding::ReplayStatus::NotReplayed,
                input: b"x".to_vec(),
            })
            .unwrap();
        let finding_id = store.put(Family::Finding, &finding_payload).unwrap();
        let rec_id = publish_boundary(
            &store,
            &dir,
            BoundaryKind::FindingVerified,
            finding_id,
            Some("receipt-run-f-abc"),
        )
        .unwrap()
        .expect("local record");
        let (_, payload) = store.get_typed(&rec_id).unwrap().unwrap();
        let rec = decode_boundary(&payload).unwrap();
        assert_eq!(rec.state, PublishState::Failed);
        assert_eq!(rec.failure, GemelFailure::NoHeadState);
        let errors = verify_links(&store).unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn absent_repo_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("frf-fuzz-gemel-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = FrfFuzzStore::open(dir.join(".frf-fuzz")).unwrap();
        let subject = store.put(Family::Campaign, b"c").unwrap();
        let rec =
            publish_boundary(&store, &dir, BoundaryKind::CampaignCreated, subject, None).unwrap();
        assert!(
            rec.is_none(),
            "standalone mode: no records, no gemel writes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
