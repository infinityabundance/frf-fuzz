//! FRF bridge (Phase 4): the epistemic-authority plane.
//!
//! frf-fuzz discoveries are HYPOTHESES/findings; they are never FRF receipts
//! or claims (I4). FRF is the authority: when an authority/reference is
//! configured and a finding is promoted, this bridge:
//!
//! 1. admits the authority executable into FRF's own store (once; a drifted
//!    oracle is refused, never silently replaced);
//! 2. binds the exact candidate artifact, the exact input (as the court
//!    fixture), the declared observables, and the court question into an
//!    FRF `CourtManifest` (written to disk — `court::run` accepts only a
//!    manifest path);
//! 3. runs the court through `frf::commands::court::run_once` with
//!    `reuse = true` so identical evidence is captured once and reused
//!    (FRF immutability), never re-captured;
//! 4. emits the OpenReceipt via `frf::commands::receipt::run` — the
//!    evidence ID frf-fuzz retains VERBATIM;
//! 5. optionally (explicit `--claim`) disposes the run's residuals as
//!    `Intentional` and compiles a baseline claim.
//!
//! FRF refusal is evidence: a refused or non-divergent run is recorded as
//! `VerificationOutcome::Failed` with a deterministic note and is never
//! deleted or downgraded (I10). When no authority is configured, a finding
//! is UNVERIFIED by derivation (absence of a verification record) — never
//! fabricated (acceptance item 16).
//!
//! ## IDs
//!
//! FRF run/receipt/claim ids are FRF's content-addresses (`run-{court}-{sha}`,
//! `receipt-{run}-{sha}`, 64-hex claims). They live in their own namespace,
//! are never merged with frf-fuzz `ContentId`s (BLAKE3) or Gemel Gids, and
//! are never reinterpreted (docs/INVARIANTS.md).
//!
//! ## Store
//!
//! FRF requires a filesystem store; frf-fuzz supplies `<store-root>/frf-root/`
//! and treats it as the source of truth for FRF IDs. FRF objects written here
//! are Level-2 durable boundaries only — never per-execution (I1).
//!
//! This module is coordinator-gated.

use crate::canon::Family;
use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::store::Store as FrfFuzzStore;

/// The FRF store root relative to a frf-fuzz store root.
pub const FRF_ROOT_DIR: &str = "frf-root";
/// Version of the verification-record payload encoding.
pub const VERIFICATION_VERSION: u8 = 1;
/// Maximum length of an authority name/version (bounded before allocation;
/// FRF additionally restricts the character set).
pub const MAX_AUTHORITY_NAME_LEN: usize = 128;
/// Maximum length of a retained FRF id (run/receipt/claim, verbatim).
pub const MAX_FRF_ID_LEN: usize = 512;
/// Maximum length of a deterministic record note (refusals, claim blocks).
pub const MAX_NOTE_LEN: usize = 2048;

/// The outcome of one court verification. Only `Verified` and `Failed` are
/// persisted; `Unverified` is the DERIVED state when no record exists for a
/// finding (never fabricated as an object).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationOutcome {
    /// FRF emitted an OpenReceipt (verified evidence).
    Verified,
    /// The court ran but FRF refused or found no divergence (the finding did
    /// not reproduce as a differential under the FRF harness, the run was
    /// refused, or the receipt was refused). The note preserves why.
    Failed,
}

impl VerificationOutcome {
    /// The wire byte.
    pub fn code(self) -> u8 {
        match self {
            VerificationOutcome::Verified => 1,
            VerificationOutcome::Failed => 0,
        }
    }

    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<VerificationOutcome> {
        match b {
            1 => Some(VerificationOutcome::Verified),
            0 => Some(VerificationOutcome::Failed),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            VerificationOutcome::Verified => "verified",
            VerificationOutcome::Failed => "failed",
        }
    }
}

/// The authority (reference/oracle) configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySpec {
    /// Authority name (`[A-Za-z0-9._-]`, FRF-validated at admission).
    pub name: String,
    /// Authority version (`[A-Za-z0-9._-]`); the authority id is
    /// `{name}-{version}`. Bump the version when the oracle changes.
    pub version: String,
    /// Path to the executable reference (must exist and be executable).
    pub path: std::path::PathBuf,
}

/// The court-question binding (config, campaign-constant per question).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CourtQuestion {
    /// Court id (path-safe; part of the run id).
    pub id: String,
    /// The question text.
    pub question: String,
    /// The falsifier text.
    pub falsifier: String,
    /// The fixture family (envelope; the input class the question is about).
    pub fixture_family: String,
}

impl Default for CourtQuestion {
    fn default() -> CourtQuestion {
        CourtQuestion {
            id: "frf-fuzz".to_string(),
            question: "For the same input, does the candidate terminate exactly as the reference terminates, over the declared observables?".to_string(),
            falsifier: "The candidate's observable behavior diverges from the reference on some input in the family.".to_string(),
            fixture_family: "fuzz-input".to_string(),
        }
    }
}

/// The durable verification record (Family::FindingVerification, 0x0F).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRecord {
    /// The finding this record verifies.
    pub finding: ContentId,
    /// The FRF authority name (verbatim; `{name}-{version}` is FRF's id).
    pub authority_name: String,
    /// The FRF authority version (verbatim).
    pub authority_version: String,
    /// The outcome.
    pub outcome: VerificationOutcome,
    /// The FRF run id (`run-{court}-{sha}`), verbatim, when the court ran.
    pub run: Option<String>,
    /// The FRF receipt id — THE evidence id — verbatim, when emitted.
    pub receipt: Option<String>,
    /// The FRF claim id (64-hex), verbatim, when a claim was compiled.
    pub claim: Option<String>,
    /// Deterministic note (refusal/claim-block/divergence-absence reason),
    /// bounded and content-tailed so distinct long texts stay distinct.
    pub note: Option<String>,
}

/// The result of running one court (before binding to a finding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CourtOutcome {
    /// Verified iff a receipt was emitted.
    pub outcome: VerificationOutcome,
    /// The FRF run id when the court executed.
    pub run: Option<String>,
    /// The receipt id when emitted.
    pub receipt: Option<String>,
    /// The claim id when compiled (only with explicit `--claim`).
    pub claim: Option<String>,
    /// Deterministic note when not fully verified.
    pub note: Option<String>,
}

/// Run a court for one finding and persist the durable verification record.
///
/// Returns the record object id and the decoded record. The record's
/// identity is a pure function of its content, so re-verifying the same
/// finding against the same authority converges on one object (idempotent).
#[allow(clippy::too_many_arguments)]
pub fn verify_and_persist(
    store: &FrfFuzzStore,
    finding: &ContentId,
    authority: &AuthoritySpec,
    question: &CourtQuestion,
    candidate_path: &std::path::Path,
    fixture_bytes: &[u8],
    with_claim: bool,
) -> Result<(ContentId, VerificationRecord)> {
    let outcome = run_court(
        store.root(),
        authority,
        question,
        candidate_path,
        fixture_bytes,
        with_claim,
    )?;
    let record = VerificationRecord {
        finding: *finding,
        authority_name: authority.name.clone(),
        authority_version: authority.version.clone(),
        outcome: outcome.outcome,
        run: outcome.run,
        receipt: outcome.receipt,
        claim: outcome.claim,
        note: outcome.note,
    };
    let payload = encode_verification(&record)?;
    let id = store.put(Family::FindingVerification, &payload)?;
    Ok((id, record))
}

// ---------------------------------------------------------------------------
// Verification record helpers
// ---------------------------------------------------------------------------

/// Encode a verification record to its canonical payload.
///
/// Layout: version(1) | finding(32) | outcome(1) | authority-name |
/// authority-version | optional note | optional run | optional receipt |
/// optional claim, each optional/string as u32-len + utf-8 bytes.
pub fn encode_verification(v: &VerificationRecord) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 32 + 1 + 200);
    out.push(VERIFICATION_VERSION);
    out.extend_from_slice(v.finding.as_bytes());
    out.push(v.outcome.code());
    push_str(&mut out, &v.authority_name, MAX_AUTHORITY_NAME_LEN)?;
    push_str(&mut out, &v.authority_version, MAX_AUTHORITY_NAME_LEN)?;
    push_opt_str(&mut out, v.note.as_deref(), MAX_NOTE_LEN)?;
    push_opt_str(&mut out, v.run.as_deref(), MAX_FRF_ID_LEN)?;
    push_opt_str(&mut out, v.receipt.as_deref(), MAX_FRF_ID_LEN)?;
    push_opt_str(&mut out, v.claim.as_deref(), MAX_FRF_ID_LEN)?;
    Ok(out)
}

/// Decode a verification record from its canonical payload.
pub fn decode_verification(bytes: &[u8]) -> Result<VerificationRecord> {
    let mut r = VReader { bytes, pos: 0 };
    let version = r.take(1)?[0];
    if version != VERIFICATION_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "finding-verification",
            version: version as u32,
        });
    }
    let finding: [u8; 32] = r.take(32)?.try_into().unwrap();
    let outcome = VerificationOutcome::from_byte(r.take(1)?[0])
        .ok_or(Error::Encoding("unknown verification outcome"))?;
    let authority_name = r.take_str(MAX_AUTHORITY_NAME_LEN)?;
    let authority_version = r.take_str(MAX_AUTHORITY_NAME_LEN)?;
    let note = r.take_opt_str(MAX_NOTE_LEN)?;
    let run = r.take_opt_str(MAX_FRF_ID_LEN)?;
    let receipt = r.take_opt_str(MAX_FRF_ID_LEN)?;
    let claim = r.take_opt_str(MAX_FRF_ID_LEN)?;
    if r.pos != bytes.len() {
        return Err(Error::Encoding("verification record has trailing bytes"));
    }
    Ok(VerificationRecord {
        finding: ContentId::from_array(finding),
        authority_name,
        authority_version,
        outcome,
        run,
        receipt,
        claim,
        note,
    })
}

/// Bounded cursor over the canonical payload.
struct VReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> VReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > self.bytes.len() {
            return Err(Error::Encoding("verification record truncated"));
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn take_str(&mut self, limit: usize) -> Result<String> {
        let len = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        if len > limit {
            return Err(Error::BoundExceeded {
                what: "string field",
                limit: limit as u64,
                got: len as u64,
            });
        }
        let s = std::str::from_utf8(self.take(len)?)
            .map_err(|_| Error::Encoding("string field is not utf-8"))?;
        Ok(s.to_string())
    }

    fn take_opt_str(&mut self, limit: usize) -> Result<Option<String>> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => Ok(Some(self.take_str(limit)?)),
            _ => Err(Error::Encoding("invalid optional-string flag")),
        }
    }
}

/// Deterministically bound a free text: keep the head up to `limit` bytes
/// (utf-8 safe) and, when truncated, append a digest tail of the full text
/// so two distinct long texts never collapse into one record (I10).
pub fn bound_text(s: &str, limit: usize) -> String {
    if s.len() <= limit {
        return s.to_string();
    }
    let tail = crate::id::ContentId::new(s.as_bytes()).to_hex();
    let tail = &tail[..16];
    // Reserve room for the marker + tail.
    let cut = limit.saturating_sub(tail.len() + 3);
    let mut head = s.as_bytes()[..cut.min(s.len())].to_vec();
    // Never split a utf-8 sequence at the boundary.
    while !head.is_empty() && !std::str::from_utf8(&head).is_ok() {
        head.pop();
    }
    let mut out = String::from_utf8(head).unwrap_or_default();
    out.push('…');
    out.push_str(tail);
    debug_assert!(out.len() <= limit + 8);
    out
}

fn push_str(out: &mut Vec<u8>, s: &str, limit: usize) -> Result<()> {
    if s.len() > limit {
        return Err(Error::BoundExceeded {
            what: "string field",
            limit: limit as u64,
            got: s.len() as u64,
        });
    }
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn push_opt_str(out: &mut Vec<u8>, s: Option<&str>, limit: usize) -> Result<()> {
    match s {
        Some(s) => {
            out.push(1u8);
            push_str(out, s, limit)?;
        }
        None => out.push(0u8),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Store layout
// ---------------------------------------------------------------------------

/// The FRF store root under a frf-fuzz store root.
pub fn frf_root_path(store_root: &std::path::Path) -> std::path::PathBuf {
    store_root.join(FRF_ROOT_DIR)
}

/// Open (creating if needed) the FRF store under a frf-fuzz store root.
pub fn open_frf_store(store_root: &std::path::Path) -> Result<frf::store::Store> {
    let root = std::path::absolute(frf_root_path(store_root))
        .map_err(|e| Error::Other(format!("cannot resolve the FRF store root: {e}")))?;
    std::fs::create_dir_all(&root)?;
    let store = frf::store::Store::new(root);
    store
        .ensure_tree()
        .map_err(|e| Error::Other(format!("FRF store setup failed: {e}")))?;
    Ok(store)
}

/// The current verification of a finding: the strongest record present
/// (`Verified` > `Failed`; ties resolve to the lowest object id, a
/// deterministic total order). `Ok(None)` = derived `Unverified`.
pub fn current_verification(
    store: &FrfFuzzStore,
    finding: &ContentId,
) -> Result<Option<VerificationRecord>> {
    let mut best: Option<(u8, ContentId, VerificationRecord)> = None;
    for id in store.list_object_ids()? {
        let Ok(Some((Family::FindingVerification, payload))) = store.get_typed(&id) else {
            continue;
        };
        let Ok(rec) = decode_verification(&payload) else {
            continue; // corruption is fsck's job
        };
        if &rec.finding != finding {
            continue;
        }
        let rank = if rec.outcome == VerificationOutcome::Verified {
            2
        } else {
            1
        };
        let replace = match &best {
            None => true,
            Some((br, bid, _)) => rank > *br || (rank == *br && id < *bid),
        };
        if replace {
            best = Some((rank, id, rec));
        }
    }
    Ok(best.map(|(_, _, rec)| rec))
}

// ---------------------------------------------------------------------------
// Manifest emission (no serde in frf-fuzz; a strict YAML emitter validated
// against FRF's own deserializer in tests)
// ---------------------------------------------------------------------------

/// Emit the court manifest YAML for a verification court.
///
/// All free-text fields are double-quoted with the documented escapes, so
/// hostile or unusual question/falsifier text cannot corrupt the document.
/// Paths are emitted as-is inside double quotes; the caller must pass
/// ABSOLUTE paths (they resolve from the process cwd otherwise).
#[allow(clippy::too_many_arguments)]
pub fn emit_manifest(
    question: &CourtQuestion,
    authority_id: &str,
    candidate_path: &std::path::Path,
    fixture_path: &std::path::Path,
    platform: &str,
) -> String {
    let mut out = String::new();
    out.push_str("court:\n");
    out.push_str(&format!("  id: {}\n", yaml_q(&question.id)));
    out.push_str(&format!("  question: {}\n", yaml_q(&question.question)));
    out.push_str(&format!("  falsifier: {}\n", yaml_q(&question.falsifier)));
    out.push_str(&format!("  authority: {}\n", yaml_q(authority_id)));
    out.push_str("  candidate:\n");
    out.push_str("    name: candidate\n");
    out.push_str("    version_or_commit: \"1.0\"\n");
    out.push_str("    build_profile: release\n");
    out.push_str(&format!(
        "    path: {}\n",
        yaml_q(&candidate_path.to_string_lossy())
    ));
    out.push_str("  fixture:\n");
    out.push_str("    id: fuzz-input\n");
    out.push_str(&format!(
        "    path: {}\n",
        yaml_q(&fixture_path.to_string_lossy())
    ));
    out.push_str("    arguments:\n");
    out.push_str(&format!(
        "      - {}\n",
        yaml_q(crate::target_runtime::fixture::FIXTURE_ARG)
    ));
    out.push_str("      - \"{fixture}\"\n");
    out.push_str("  admissibility_envelope:\n");
    out.push_str(&format!(
        "    fixture_family: {}\n",
        yaml_q(&question.fixture_family)
    ));
    out.push_str("    platforms:\n");
    out.push_str(&format!("      - {}\n", yaml_q(platform)));
    out.push_str("    observables:\n");
    out.push_str("      - exit\n");
    out.push_str("      - stderr\n");
    out.push_str("    normalizers: []\n");
    out.push_str("    replay_scope: single-run\n");
    out
}

/// Quote a string as a YAML double-quoted scalar with the documented
/// escapes. Control characters (< 0x20 and DEL) use `\uXXXX`; `"` and `\`
/// are escaped; everything else (including UTF-8) is emitted verbatim.
pub fn yaml_q(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The current platform string FRF expects (`<arch>-<os>`).
pub fn platform_string() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

// ---------------------------------------------------------------------------
// Court driver
// ---------------------------------------------------------------------------

/// A guard that pins the process working directory for the duration of an
/// FRF court and restores it afterwards. FRF's capture environment identity
/// records the cwd, so the run identity is only reproducible when the cwd is
/// stable; the FRF store root is the natural constant.
struct CwdGuard {
    original: std::path::PathBuf,
}

impl CwdGuard {
    fn pin_to(root: &std::path::Path) -> Result<CwdGuard> {
        let original = std::env::current_dir()?;
        std::env::set_current_dir(root)?;
        Ok(CwdGuard { original })
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}

/// Validate the court question fields before any file is staged: the court
/// id becomes a directory component under the FRF store root (path safety)
/// and every text field is bounded before the manifest is written.
fn validate_question(question: &CourtQuestion) -> Result<()> {
    if question.id.is_empty()
        || question.id.len() > 128
        || question.id == "."
        || question.id == ".."
        || !question
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') || c == ':')
    {
        return Err(Error::Refused(
            "question id must be 1..=128 chars of [A-Za-z0-9._:-]",
        ));
    }
    if question.id.contains("::") {
        return Err(Error::Refused("question id must not contain '::'"));
    }
    if question.question.len() > 8192 || question.falsifier.len() > 8192 {
        return Err(Error::Refused(
            "question/falsifier text too long (max 8192)",
        ));
    }
    if question.fixture_family.len() > 512 || question.fixture_family.is_empty() {
        return Err(Error::Refused("fixture family must be 1..=512 chars"));
    }
    Ok(())
}

/// Run one verification court against FRF and return the evidence chain.
///
/// `fixture_bytes` are the exact finding input (hashed and snapshotted by
/// FRF at run time). `candidate_path` must be an executable that honors the
/// `--frf-fuzz-fixture <path>` single-shot interface (an instrumented
/// frf-fuzz target binary does). `with_claim` additionally disposes the
/// run's residuals as `Intentional` and compiles a baseline claim.
///
/// A promoted crash finding is `Verified` ONLY when the court observed at
/// least one residual divergence (the candidate differed from the reference
/// over the declared observables). A parity run — both sides identical, zero
/// residuals — still emits an FRF receipt, but that receipt is evidence of
/// NON-reproduction; the outcome is `Failed` and the parity receipt is
/// preserved in the record.
#[allow(clippy::too_many_arguments)]
pub fn run_court(
    store_root: &std::path::Path,
    authority: &AuthoritySpec,
    question: &CourtQuestion,
    candidate_path: &std::path::Path,
    fixture_bytes: &[u8],
    with_claim: bool,
) -> Result<CourtOutcome> {
    // ---- resolve + validate the artifacts (before any FRF write) ----
    let candidate = std::path::absolute(candidate_path)
        .map_err(|e| Error::Other(format!("cannot resolve candidate path: {e}")))?;
    if !candidate.is_file() {
        return Err(Error::Refused("candidate is not a file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&candidate)
            .map_err(|e| Error::Other(format!("cannot stat candidate: {e}")))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(Error::Refused(
                "candidate is not executable (set the executable bit)",
            ));
        }
    }
    let authority_path = std::path::absolute(&authority.path)
        .map_err(|e| Error::Other(format!("cannot resolve authority path: {e}")))?;
    if !authority_path.is_file() {
        return Err(Error::Refused("authority is not a file"));
    }
    validate_id_component(&authority.name)?;
    validate_id_component(&authority.version)?;
    validate_question(question)?;
    let authority_id = format!("{}-{}", authority.name, authority.version);

    // ---- FRF store + admission (idempotent) ----
    let frf_store = open_frf_store(store_root)?;
    let _admitted = admit_or_verify(
        &frf_store,
        &authority_path,
        &authority.name,
        &authority.version,
        &authority_id,
    )?;

    // ---- stage the fixture + manifest under the FRF store root ----
    // The court id must be path-safe (FRF validates it again at run time).
    let court_dir = frf_root_path(store_root)
        .join("frf-fuzz-courts")
        .join(&question.id);
    std::fs::create_dir_all(&court_dir)?;
    let fixture_path = court_dir.join("fixture.bin");
    std::fs::write(&fixture_path, fixture_bytes)?;
    let manifest_path = court_dir.join("manifest.yaml");
    let manifest = emit_manifest(
        question,
        &authority_id,
        &candidate,
        &fixture_path,
        &platform_string(),
    );
    std::fs::write(&manifest_path, manifest)?;

    // ---- run the court with a pinned cwd (stable environment identity) ----
    let _guard = CwdGuard::pin_to(&frf_root_path(store_root))?;
    let run = match frf::commands::court::run_once(
        &frf_store,
        &manifest_path,
        None,
        None,
        true, // reuse identical verified evidence (FRF immutability)
        None,
    ) {
        Ok(run) => run,
        Err(e) => {
            // The court itself refused (harness bounds, artifact drift, a
            // sandbox refusal, ...). That refusal is evidence: record it.
            return Ok(CourtOutcome {
                outcome: VerificationOutcome::Failed,
                run: None,
                receipt: None,
                claim: None,
                note: Some(bound_text(&format!("FRF court refused: {e}"), MAX_NOTE_LEN)),
            });
        }
    };

    // ---- emit the receipt (the evidence id) ----
    let receipt = match frf::commands::receipt::run(&frf_store, &run) {
        Ok(r) => r,
        Err(e) => {
            // The run captured, but no receipt was emitted (no verified
            // divergence — e.g. the finding did not reproduce under the FRF
            // harness, or the residuals did not verify). Preserve the run id
            // and the refusal; the outcome is Failed.
            return Ok(CourtOutcome {
                outcome: VerificationOutcome::Failed,
                run: Some(run),
                receipt: None,
                claim: None,
                note: Some(bound_text(
                    &format!("FRF receipt refused: {e}"),
                    MAX_NOTE_LEN,
                )),
            });
        }
    };

    // A receipt alone is NOT a verification of a crash finding: FRF emits a
    // receipt from any verified run, including a PARITY run with zero
    // residuals (both sides behaved identically). A promoted crash finding
    // is verified only when the candidate DIVERGED from the reference — at
    // least one residual — on the declared observables. Zero residuals means
    // the crash did not reproduce under the FRF harness; the outcome is
    // Failed and the parity receipt is PRESERVED as evidence of that
    // non-reproduction (I10).
    let capture = frf_store
        .load_capture(&run)
        .map_err(|e| Error::Other(format!("cannot read FRF capture: {e}")))?
        .into_inner();
    let divergence_count = capture.residuals.len();
    if divergence_count == 0 {
        return Ok(CourtOutcome {
            outcome: VerificationOutcome::Failed,
            run: Some(run),
            receipt: Some(receipt),
            claim: None,
            note: Some(bound_text(
                "no divergence under the FRF harness: the candidate behaved like the reference on this input (the crash did not reproduce as a differential); the parity receipt is preserved as evidence",
                MAX_NOTE_LEN,
            )),
        });
    }

    // ---- optional claim compilation ----
    let mut claim = None;
    if with_claim {
        match compile_baseline_claim(&frf_store, &run, &receipt) {
            Ok(Some(c)) => claim = Some(c),
            Ok(None) => {}
            Err(e) => {
                // A refused claim is preserved in the note; the receipt (the
                // evidence) already stands.
                return Ok(CourtOutcome {
                    outcome: VerificationOutcome::Verified,
                    run: Some(run),
                    receipt: Some(receipt),
                    claim: None,
                    note: Some(bound_text(
                        &format!("claim not compiled: {e}"),
                        MAX_NOTE_LEN,
                    )),
                });
            }
        }
    }

    Ok(CourtOutcome {
        outcome: VerificationOutcome::Verified,
        run: Some(run),
        receipt: Some(receipt),
        claim,
        note: None,
    })
}

/// Admit the authority, or verify that an existing admission is identical.
fn admit_or_verify(
    frf_store: &frf::store::Store,
    authority_path: &std::path::Path,
    name: &str,
    version: &str,
    authority_id: &str,
) -> Result<String> {
    let record_path = frf_store
        .authority_path(authority_id)
        .map_err(|e| Error::Other(format!("FRF authority path error: {e}")))?;
    if !record_path.exists() {
        let id = frf::commands::admit::run(
            frf_store,
            authority_path,
            name,
            version,
            "executable_reference",
        )
        .map_err(|e| Error::Other(format!("FRF admission failed: {e}")))?;
        return Ok(id);
    }
    let rec = frf_store
        .load_authority(authority_id)
        .map_err(|e| Error::Other(format!("FRF authority load failed: {e}")))?;
    let sha = frf::host::sha256_file(authority_path)
        .map_err(|e| Error::Other(format!("cannot hash authority: {e}")))?;
    if rec.executable_sha256 != sha {
        return Err(Error::Refused(
            "authority bytes changed since admission; admission is once — admit the changed oracle as a new version",
        ));
    }
    if rec.path != authority_path.to_string_lossy() {
        return Err(Error::Refused(
            "authority path changed since admission; re-admit with the original path or bump the authority version",
        ));
    }
    Ok(authority_id.to_string())
}

/// Dispose the run's residuals as `Intentional` and compile a baseline
/// claim over the receipt. Returns the claim id. `Err` when FRF refuses.
fn compile_baseline_claim(
    frf_store: &frf::store::Store,
    run: &str,
    receipt: &str,
) -> Result<Option<String>> {
    use frf::cli::ClosureArg;
    use frf::commands::{claim, dispose};
    // The capture records the residual ids; dispose each as Intentional (an
    // explicit, reason-bearing closure that does NOT block claims) so the
    // claim can bind clean evidence.
    let capture = frf_store
        .load_capture(run)
        .map_err(|e| Error::Other(format!("cannot read FRF capture: {e}")))?
        .into_inner();
    for rid in &capture.residuals {
        dispose::run(
            frf_store,
            rid,
            ClosureArg::Intentional,
            "frf-fuzz verification: the divergence is the promoted finding (candidate crashes where the reference passes); disposed to compile the baseline claim",
            None,
            None,
            None,
            None,
        )
        .map_err(|e| Error::Other(format!("FRF disposition failed for {rid}: {e}")))?;
    }
    claim::run(
        frf_store,
        std::slice::from_ref(&receipt.to_string()),
        false,
        frf::model::CLAIM_POLICY_BASELINE,
        "",
        &[],
    )
    .map_err(|e| Error::Other(format!("FRF claim refused: {e}")))?;
    // claim::run compiles the claim; resolve its id from the by-receipt
    // index (the newest claim for this receipt).
    Ok(frf_store
        .claim_ids_for_receipt(receipt)
        .map_err(|e| Error::Other(format!("FRF claim index error: {e}")))?
        .first()
        .cloned())
}

fn validate_id_component(s: &str) -> Result<()> {
    if s.is_empty() || s == "." || s == ".." {
        return Err(Error::Encoding("authority name/version must be non-empty"));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(Error::Encoding(
            "authority name/version must match [A-Za-z0-9._-]",
        ));
    }
    Ok(())
}

/// Verify verification-record link closure for `fsck`: every stored record
/// decodes and its finding reference resolves to a stored `Finding`. Returns
/// human-readable defects (empty = clean).
pub fn verify_links(store: &FrfFuzzStore) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    for id in store.list_object_ids()? {
        let Ok(Some((Family::FindingVerification, payload))) = store.get_typed(&id) else {
            continue;
        };
        let rec = match decode_verification(&payload) {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("{id}: corrupt finding-verification payload: {e}"));
                continue;
            }
        };
        match store.get_typed(&rec.finding) {
            Ok(Some((Family::Finding, _))) => {}
            _ => errors.push(format!(
                "{id}: finding reference {} is missing or not a finding",
                rec.finding
            )),
        }
        // FRF ids must look like FRF ids (they are opaque, but a malformed
        // reference is a corruption signal).
        if let Some(run) = &rec.run {
            if !run.starts_with("run-") {
                errors.push(format!("{id}: run id {run:?} is not an FRF run id"));
            }
        }
        if let Some(receipt) = &rec.receipt {
            if !receipt.starts_with("receipt-") {
                errors.push(format!(
                    "{id}: receipt id {receipt:?} is not an FRF receipt id"
                ));
            }
        }
    }
    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VerificationRecord {
        VerificationRecord {
            finding: ContentId::new(b"finding"),
            authority_name: "reference".to_string(),
            authority_version: "1.0".to_string(),
            outcome: VerificationOutcome::Verified,
            run: Some("run-frf-fuzz-abcdef".to_string()),
            receipt: Some("receipt-run-frf-fuzz-abcdef-1234".to_string()),
            claim: None,
            note: None,
        }
    }

    #[test]
    fn record_roundtrip() {
        let v = sample();
        let dec = decode_verification(&encode_verification(&v).unwrap()).unwrap();
        assert_eq!(dec, v);
        assert_eq!(
            dec.receipt.as_deref(),
            Some("receipt-run-frf-fuzz-abcdef-1234")
        );
    }

    #[test]
    fn failed_record_roundtrip_with_note() {
        let mut v = sample();
        v.outcome = VerificationOutcome::Failed;
        v.receipt = None;
        v.note = Some("FRF court refused: boom".to_string());
        let dec = decode_verification(&encode_verification(&v).unwrap()).unwrap();
        assert_eq!(dec, v);
    }

    #[test]
    fn decoder_rejects_truncation_and_bad_outcome() {
        let enc = encode_verification(&sample()).unwrap();
        assert!(decode_verification(&enc[..enc.len() - 1]).is_err());
        let mut bad = enc.clone();
        bad[33] = 0xEE;
        assert!(decode_verification(&bad).is_err());
        let mut bad2 = enc.clone();
        bad2[0] = 99;
        assert!(decode_verification(&bad2).is_err());
    }

    #[test]
    fn bound_text_is_deterministic_and_distinct() {
        let a = "x".repeat(5000);
        let b = format!("{}y", "x".repeat(4999));
        let ba = bound_text(&a, 1000);
        let bb = bound_text(&b, 1000);
        assert_ne!(ba, bb); // distinct tails keep distinct records (I10)
        assert_eq!(ba, bound_text(&a, 1000)); // deterministic
        assert_eq!(bound_text("short", 1000), "short");
        // utf-8 safe: multibyte content is never split mid-character.
        let m = "é".repeat(3000);
        let bm = bound_text(&m, 100);
        assert!(std::str::from_utf8(bm.as_bytes()).is_ok());
    }

    #[test]
    fn yaml_quoting_escapes_hostile_text() {
        assert_eq!(yaml_q("plain"), "\"plain\"");
        assert_eq!(yaml_q("a\"b\\c\nd\te\rf"), "\"a\\\"b\\\\c\\nd\\te\\rf\"");
        assert_eq!(yaml_q("\u{1}"), "\"\\u0001\"");
        assert_eq!(yaml_q("\u{7f}"), "\"\\u007f\"");
        // The fixture placeholder must survive quoting verbatim.
        assert_eq!(yaml_q("{fixture}"), "\"{fixture}\"");
    }

    #[test]
    fn manifest_emits_expected_shape() {
        let q = CourtQuestion::default();
        let yaml = emit_manifest(
            &q,
            "reference-1.0",
            std::path::Path::new("/abs/candidate"),
            std::path::Path::new("/abs/fixture.bin"),
            "x86_64-linux",
        );
        assert!(yaml.contains("  id: \"frf-fuzz\"\n"));
        assert!(yaml.contains("  authority: \"reference-1.0\"\n"));
        assert!(yaml.contains("    path: \"/abs/candidate\"\n"));
        assert!(yaml.contains("      - \"{fixture}\"\n"));
        assert!(yaml.contains("    platforms:\n      - \"x86_64-linux\"\n"));
        assert!(yaml.contains("    replay_scope: single-run\n"));
    }

    #[test]
    fn manifest_parses_with_frfs_own_deserializer() {
        // The real contract: frf's serde_yaml parser must accept the emitted
        // document as a CourtManifest. This test runs FRF's own parser.
        let q = CourtQuestion {
            id: "frf-fuzz-test".to_string(),
            question: "line one\nline two: with \"quotes\" and \\ backslashes".to_string(),
            falsifier: "diverges \u{1b}".to_string(),
            fixture_family: "fuzz-input".to_string(),
        };
        let yaml = emit_manifest(
            &q,
            "reference-1.0",
            std::path::Path::new("/abs/candidate"),
            std::path::Path::new("/abs/fixture.bin"),
            "x86_64-linux",
        );
        let dir =
            std::env::temp_dir().join(format!("frf-fuzz-manifest-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fs = frf::store::Store::new(dir.clone());
        fs.ensure_tree().unwrap();
        let path = dir.join("manifest.yaml");
        std::fs::write(&path, &yaml).unwrap();
        let m: frf::model::CourtManifest = fs.parse_yaml(&path).unwrap();
        assert_eq!(m.court.id, "frf-fuzz-test");
        assert_eq!(m.court.authority, "reference-1.0");
        assert_eq!(m.court.candidate.name, "candidate");
        assert_eq!(
            m.court.fixture.arguments,
            vec!["--frf-fuzz-fixture", "{fixture}"]
        );
        assert_eq!(m.court.admissibility_envelope.replay_scope, "single-run");
        assert_eq!(
            m.court.admissibility_envelope.platforms,
            vec!["x86_64-linux"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
