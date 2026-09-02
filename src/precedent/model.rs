//! The durable precedent model (master prompt §17; Phase 3).
//!
//! A precedent is NOT `fingerprint -> bug name`. It records one observed
//! structural trajectory family that led to a terminal event, together with
//! the context it occurred in, a falsifiable probe relationship, and the
//! evidence accumulated for and against it (I9: no precedent is admitted
//! without provenance; I10: contradictory evidence is never deleted).
//!
//! # Immutability and revisions
//!
//! Precedents are stored as immutable content-addressed objects
//! (`Family::Precedent`). Every update (probe outcome, terminal
//! confirmation, contradiction) writes a NEW revision whose
//! `prev_revision` points at the previous one; the full chain is retained.
//! The "current" precedent for a lineage is the revision with the highest
//! `updated_seq` (deterministic resolution on load).
//!
//! # Status transitions (documented, deterministic)
//!
//! ```text
//! create -> Candidate
//! Candidate + probe Support or terminal confirmation -> Confirmed
//! Confirmed + probe Support               -> Confirmed (supports += 1)
//! (Candidate|Confirmed) + Direct contradiction -> Contradicted
//! (Candidate|Confirmed) + Partial contradictions x3 -> Contradicted
//! Contradicted -> terminal (no further probes are scheduled from it)
//! ```
//!
//! A contradicted precedent is preserved with its counterexample evidence;
//! it is never deleted and never silently overwritten.
//!
//! This module is coordinator-gated.

use crate::dsfb::fuzz_bank::FuzzMotif;
use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::precedent::probe::{
    decode_evidence, encode_evidence, ProbeEvidence, ProbeOutcome, ProbeRecipe,
};
use crate::target_runtime::signals::MAX_SIGNALS;

/// Version of the precedent payload encoding.
pub const PRECEDENT_VERSION: u8 = 1;
/// Maximum probe-evidence records retained in the newest revision.
pub const MAX_PRECEDENT_EVIDENCE: usize = 32;
/// Maximum evidence bytes inside one precedent payload.
pub const MAX_PRECEDENT_PAYLOAD: usize = 1 << 16;

/// The status of a precedent (see module docs for the transitions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PrecedentStatus {
    /// Created from a real terminal observation; not yet corroborated.
    Candidate = 1,
    /// Corroborated by at least one probe support or terminal confirmation.
    Confirmed = 2,
    /// Refuted by direct (or 3x partial) contradictory probe evidence. It is
    /// retained as negative knowledge and never scheduled again.
    Contradicted = 3,
}

impl PrecedentStatus {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<PrecedentStatus> {
        match b {
            1 => Some(PrecedentStatus::Candidate),
            2 => Some(PrecedentStatus::Confirmed),
            3 => Some(PrecedentStatus::Contradicted),
            _ => None,
        }
    }

    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            PrecedentStatus::Candidate => "candidate",
            PrecedentStatus::Confirmed => "confirmed",
            PrecedentStatus::Contradicted => "contradicted",
        }
    }
}

/// The kind of terminal event a precedent's lineage reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TerminalKind {
    /// The lineage reached a crash finding.
    CrashFinding = 1,
    /// The lineage reached a timeout finding.
    TimeoutFinding = 2,
    /// The lineage produced a retained counterfactual boundary witness.
    BoundaryWitness = 3,
    /// The lineage closed a DSFB structural episode at Escalate.
    EscalatedEpisode = 4,
}

impl TerminalKind {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<TerminalKind> {
        match b {
            1 => Some(TerminalKind::CrashFinding),
            2 => Some(TerminalKind::TimeoutFinding),
            3 => Some(TerminalKind::BoundaryWitness),
            4 => Some(TerminalKind::EscalatedEpisode),
            _ => None,
        }
    }

    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            TerminalKind::CrashFinding => "crash-finding",
            TerminalKind::TimeoutFinding => "timeout-finding",
            TerminalKind::BoundaryWitness => "boundary-witness",
            TerminalKind::EscalatedEpisode => "escalated-episode",
        }
    }
}

/// The *likely confuser* the creation context declares for the family. A
/// non-None confuser makes probes DISCRIMINATE (separate family from
/// confuser); None makes probes FALSIFY (aggressively test the family).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfuserKind {
    /// No declared confuser.
    None = 0,
    /// The confuser settles after an initial climb (warm-up/saturation).
    SaturationWarmup = 1,
    /// The confuser scales with input length (benign proportionality).
    LengthProportional = 2,
    /// The confuser alternates branches per input flag.
    BranchAlternation = 3,
    /// The confuser is a shared input region driving dependent counters.
    SharedRegionCascade = 4,
}

impl ConfuserKind {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<ConfuserKind> {
        match b {
            0 => Some(ConfuserKind::None),
            1 => Some(ConfuserKind::SaturationWarmup),
            2 => Some(ConfuserKind::LengthProportional),
            3 => Some(ConfuserKind::BranchAlternation),
            4 => Some(ConfuserKind::SharedRegionCascade),
            _ => None,
        }
    }

    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            ConfuserKind::None => "none",
            ConfuserKind::SaturationWarmup => "saturation-warmup",
            ConfuserKind::LengthProportional => "length-proportional",
            ConfuserKind::BranchAlternation => "branch-alternation",
            ConfuserKind::SharedRegionCascade => "shared-region-cascade",
        }
    }
}

/// The structural prefix profile: the reduced shape fields of the signature
/// captured BEFORE the terminal escalation. Matching requires a live
/// signature whose shape subsumes this profile (same axes, same directions
/// on those axes, same comparison-convergence and state-change classes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixProfile {
    /// The lineage depth (generation) at which the profile was captured.
    pub depth: u32,
    /// Bitmask of structurally involved signal axes.
    pub axis_mask: u64,
    /// Two bits per axis: cumulative direction (0 none, 1 up, 2 down).
    pub dir_bits: u128,
    /// `CmpConvergence` code at capture.
    pub cmp_convergence: u8,
    /// `StateChange` code at capture.
    pub state_change: u8,
    /// Whether the captured signature was structured-Unknown.
    pub structured_unknown: bool,
}

impl PrefixProfile {
    /// Build a profile from a morphology signature captured at `depth`.
    pub fn from_signature(
        sig: &crate::dsfb::morphology::MorphologySignature,
        depth: u32,
    ) -> PrefixProfile {
        PrefixProfile {
            depth,
            axis_mask: sig.axis_mask,
            dir_bits: sig.dir_bits,
            cmp_convergence: sig.cmp_convergence,
            state_change: sig.state_change,
            structured_unknown: sig.structured_unknown,
        }
    }

    /// The deterministic profile identity (FNV-1a over the canonical fields).
    /// Used as the precedent-grouping key.
    pub fn profile_identity(&self) -> u64 {
        let mut h: u64 = 0xCBF2_9CE4_8422_2325;
        for &b in &self.axis_mask.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        for &b in &self.dir_bits.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        for &b in &[
            self.cmp_convergence,
            self.state_change,
            u8::from(self.structured_unknown),
        ] {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        h
    }

    /// Whether a live signature's shape subsumes this profile: every profile
    /// axis is present in the signature with the SAME direction, and the
    /// comparison-convergence and state-change classes agree. Direction
    /// equality on the profile axes is the load-bearing precursor condition
    /// (the trajectory must still be heading the same way).
    pub fn subsumed_by(&self, sig: &crate::dsfb::morphology::MorphologySignature) -> bool {
        if sig.axis_mask & self.axis_mask != self.axis_mask {
            return false;
        }
        for i in 0..MAX_SIGNALS {
            if self.axis_mask & (1u64 << i) == 0 {
                continue;
            }
            let want = (self.dir_bits >> (2 * i)) & 0b11;
            if sig.dir(i) as u128 != want {
                return false;
            }
        }
        sig.cmp_convergence == self.cmp_convergence && sig.state_change == self.state_change
    }

    /// Encode the profile (canonical).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4 + 8 + 16 + 1 + 1 + 1);
        out.extend_from_slice(&self.depth.to_le_bytes());
        out.extend_from_slice(&self.axis_mask.to_le_bytes());
        out.extend_from_slice(&self.dir_bits.to_le_bytes());
        out.push(self.cmp_convergence);
        out.push(self.state_change);
        out.push(u8::from(self.structured_unknown));
        Ok(out)
    }

    /// Decode a profile payload (bounded fields).
    pub fn decode(bytes: &[u8]) -> Result<PrefixProfile> {
        if bytes.len() != 31 {
            return Err(Error::Encoding("prefix-profile length is not 31"));
        }
        let mut pos = 0usize;
        let mut take = |n: usize| -> Result<&[u8]> {
            let end = pos.checked_add(n).ok_or(Error::Overflow)?;
            if end > bytes.len() {
                return Err(Error::Encoding("prefix-profile truncated"));
            }
            let out = &bytes[pos..end];
            pos = end;
            Ok(out)
        };
        let depth = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let axis_mask = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let dir_bits = u128::from_le_bytes(take(16)?.try_into().unwrap());
        let cmp_convergence = take(1)?[0];
        let state_change = take(1)?[0];
        let structured_unknown = take(1)?[0] != 0;
        Ok(PrefixProfile {
            depth,
            axis_mask,
            dir_bits,
            cmp_convergence,
            state_change,
            structured_unknown,
        })
    }
}

/// The continuation the precedent's lineage actually reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Continuation {
    /// The terminal event kind.
    pub kind: TerminalKind,
    /// The bank class named along the trajectory at/just before the terminal
    /// event (0 = none / structured-Unknown).
    pub class: u8,
    /// The leading axis of the trajectory (the one that dominated).
    pub axis: u16,
    /// The lineage depth at the terminal event (the frontier generation).
    pub depth: u32,
    /// The DSFB reason code of the leading axis at the last structured edge.
    pub reason: u8,
    /// The durable terminal object (finding / boundary witness / episode).
    pub terminal_ref: Option<ContentId>,
}

/// A durable precedent (one revision of the lineage's precedent chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Precedent {
    /// The lineage root entry the trajectory descended from (provenance).
    pub lineage_root: ContentId,
    /// The lineage mutator family id.
    pub mutator: u16,
    /// The structural prefix profile (the precursor shape).
    pub profile: PrefixProfile,
    /// Union of the declared schema roles on the profile axes (context
    /// predicate; matching across lineages requires compatible roles).
    pub role_mask: u16,
    /// What the trajectory led to.
    pub continuation: Continuation,
    /// The declared confuser kind.
    pub confuser: ConfuserKind,
    /// Admission-sequence of creation (provenance ordering).
    pub created_seq: u64,
    /// Admission-sequence of the latest update (revision ordering).
    pub updated_seq: u64,
    /// Status.
    pub status: PrecedentStatus,
    /// The previous revision (chain; None for the first).
    pub prev_revision: Option<ContentId>,
    /// Cumulative probe supports.
    pub supports: u32,
    /// Cumulative probe contradictions.
    pub contradictions: u32,
    /// Cumulative ambiguous probe outcomes.
    pub ambiguous_probes: u32,
    /// The falsifiable probe relationship (required before scheduling).
    pub recipe: ProbeRecipe,
    /// Recent evidence tail (newest first; older records live in earlier
    /// revisions of the chain).
    pub evidence: Vec<ProbeEvidence>,
}

impl Precedent {
    /// The grouping key: (lineage root, mutator, profile identity).
    pub fn group_key(&self) -> (ContentId, u16, u64) {
        (
            self.lineage_root,
            self.mutator,
            self.profile.profile_identity(),
        )
    }

    /// Whether this revision is schedulable (guides probes).
    pub fn schedulable(&self) -> bool {
        self.status == PrecedentStatus::Candidate || self.status == PrecedentStatus::Confirmed
    }

    /// Whether the confuser demands DISCRIMINATE rather than FALSIFY probes.
    pub fn discriminates(&self) -> bool {
        self.confuser != ConfuserKind::None
    }

    /// Apply one probe outcome, producing the next revision's fields.
    /// `direct_contradiction` is true when the axis never moved at all (the
    /// family expectation was directly refuted). Returns the updated
    /// (status, supports, contradictions, ambiguous). Deterministic; the
    /// caller persists the new revision and sets `prev_revision`/
    /// `updated_seq`.
    pub fn apply_probe(
        &self,
        outcome: ProbeOutcome,
        evidence: ProbeEvidence,
        direct_contradiction: bool,
    ) -> (PrecedentStatus, u32, u32, u32) {
        let mut supports = self.supports;
        let mut contradictions = self.contradictions;
        let mut ambiguous = self.ambiguous_probes;
        let mut status = self.status;
        match outcome {
            ProbeOutcome::Support => {
                supports = supports.saturating_add(1);
                if status == PrecedentStatus::Candidate {
                    status = PrecedentStatus::Confirmed;
                }
            }
            ProbeOutcome::Contradict => {
                contradictions = contradictions.saturating_add(1);
                if direct_contradiction || contradictions >= 3 {
                    // A direct refutation (the axis never moved) defeats the
                    // family expectation immediately; three partial
                    // contradictions accumulate to the same conclusion.
                    status = PrecedentStatus::Contradicted;
                }
            }
            ProbeOutcome::Ambiguous => {
                ambiguous = ambiguous.saturating_add(1);
            }
        }
        let _ = evidence;
        (status, supports, contradictions, ambiguous)
    }
}

/// Canonical payload of one precedent revision.
pub fn encode_precedent(p: &Precedent) -> Result<Vec<u8>> {
    if p.evidence.len() > MAX_PRECEDENT_EVIDENCE {
        return Err(Error::BoundExceeded {
            what: "precedent evidence records",
            limit: MAX_PRECEDENT_EVIDENCE as u64,
            got: p.evidence.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(512);
    out.push(PRECEDENT_VERSION);
    out.extend_from_slice(p.lineage_root.as_bytes());
    out.extend_from_slice(&p.mutator.to_le_bytes());
    let profile = p.profile.encode()?;
    out.extend_from_slice(&(profile.len() as u32).to_le_bytes());
    out.extend_from_slice(&profile);
    out.extend_from_slice(&p.role_mask.to_le_bytes());
    out.push(p.continuation.kind.code());
    out.push(p.continuation.class);
    out.extend_from_slice(&p.continuation.axis.to_le_bytes());
    out.extend_from_slice(&p.continuation.depth.to_le_bytes());
    out.push(p.continuation.reason);
    match p.continuation.terminal_ref {
        Some(id) => out.extend_from_slice(id.as_bytes()),
        None => out.extend_from_slice(&[0u8; 32]),
    }
    out.push(p.confuser.code());
    out.extend_from_slice(&p.created_seq.to_le_bytes());
    out.extend_from_slice(&p.updated_seq.to_le_bytes());
    out.push(p.status.code());
    match p.prev_revision {
        Some(id) => out.extend_from_slice(id.as_bytes()),
        None => out.extend_from_slice(&[0u8; 32]),
    }
    out.extend_from_slice(&p.supports.to_le_bytes());
    out.extend_from_slice(&p.contradictions.to_le_bytes());
    out.extend_from_slice(&p.ambiguous_probes.to_le_bytes());
    let recipe = p.recipe.encode()?;
    out.extend_from_slice(&(recipe.len() as u32).to_le_bytes());
    out.extend_from_slice(&recipe);
    out.extend_from_slice(&(p.evidence.len() as u32).to_le_bytes());
    for ev in &p.evidence {
        let enc = encode_evidence(ev)?;
        out.extend_from_slice(&(enc.len() as u16).to_le_bytes());
        out.extend_from_slice(&enc);
    }
    if out.len() > MAX_PRECEDENT_PAYLOAD {
        return Err(Error::BoundExceeded {
            what: "precedent payload",
            limit: MAX_PRECEDENT_PAYLOAD as u64,
            got: out.len() as u64,
        });
    }
    Ok(out)
}

/// Decode a precedent payload (all bounds enforced before allocation).
pub fn decode_precedent(bytes: &[u8]) -> Result<Precedent> {
    if bytes.len() > MAX_PRECEDENT_PAYLOAD {
        return Err(Error::BoundExceeded {
            what: "precedent payload",
            limit: MAX_PRECEDENT_PAYLOAD as u64,
            got: bytes.len() as u64,
        });
    }
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > bytes.len() {
            return Err(Error::Encoding("precedent truncated"));
        }
        let out = &bytes[pos..end];
        pos = end;
        Ok(out)
    };
    let version = take(1)?[0];
    if version != PRECEDENT_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "precedent",
            version: version as u32,
        });
    }
    let lineage_root = ContentId::from_array(take(32)?.try_into().unwrap());
    let mutator = u16::from_le_bytes(take(2)?.try_into().unwrap());
    let profile_len = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
    if profile_len != 31 {
        return Err(Error::Encoding("precedent profile length must be 31"));
    }
    let profile = PrefixProfile::decode(take(profile_len)?)?;
    let role_mask = u16::from_le_bytes(take(2)?.try_into().unwrap());
    let kind =
        TerminalKind::from_byte(take(1)?[0]).ok_or(Error::Encoding("unknown terminal kind"))?;
    let class = take(1)?[0];
    if class != 0 && FuzzMotif::from_code(class).is_none() {
        return Err(Error::Encoding("unknown continuation class"));
    }
    let axis = u16::from_le_bytes(take(2)?.try_into().unwrap());
    let depth = u32::from_le_bytes(take(4)?.try_into().unwrap());
    let reason = take(1)?[0];
    let terminal_raw = take(32)?;
    let terminal_ref = if terminal_raw.iter().all(|b| *b == 0) {
        None
    } else {
        Some(ContentId::from_array(terminal_raw.try_into().unwrap()))
    };
    let confuser =
        ConfuserKind::from_byte(take(1)?[0]).ok_or(Error::Encoding("unknown confuser kind"))?;
    let created_seq = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let updated_seq = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let status = PrecedentStatus::from_byte(take(1)?[0])
        .ok_or(Error::Encoding("unknown precedent status"))?;
    let prev_raw = take(32)?;
    let prev_revision = if prev_raw.iter().all(|b| *b == 0) {
        None
    } else {
        Some(ContentId::from_array(prev_raw.try_into().unwrap()))
    };
    let supports = u32::from_le_bytes(take(4)?.try_into().unwrap());
    let contradictions = u32::from_le_bytes(take(4)?.try_into().unwrap());
    let ambiguous_probes = u32::from_le_bytes(take(4)?.try_into().unwrap());
    let recipe_len = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
    if recipe_len == 0 || recipe_len > 32 {
        return Err(Error::Encoding("precedent recipe length out of range"));
    }
    let recipe = ProbeRecipe::decode(take(recipe_len)?)?;
    let evidence_count = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
    if evidence_count > MAX_PRECEDENT_EVIDENCE {
        return Err(Error::BoundExceeded {
            what: "precedent evidence records",
            limit: MAX_PRECEDENT_EVIDENCE as u64,
            got: evidence_count as u64,
        });
    }
    let mut evidence = Vec::with_capacity(evidence_count);
    for _ in 0..evidence_count {
        let elen = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        if elen == 0 || elen > 128 {
            return Err(Error::Encoding("precedent evidence length out of range"));
        }
        evidence.push(decode_evidence(take(elen)?)?);
    }
    if pos != bytes.len() {
        return Err(Error::Encoding("precedent has trailing bytes"));
    }
    Ok(Precedent {
        lineage_root,
        mutator,
        profile,
        role_mask,
        continuation: Continuation {
            kind,
            class,
            axis,
            depth,
            reason,
            terminal_ref,
        },
        confuser,
        created_seq,
        updated_seq,
        status,
        prev_revision,
        supports,
        contradictions,
        ambiguous_probes,
        recipe,
        evidence,
    })
}

/// Human-readable rendering of one precedent revision (for `inspect`).
pub fn render_precedent(p: &Precedent, id: Option<&ContentId>) -> String {
    let mut s = String::new();
    if let Some(id) = id {
        s.push_str(&format!("precedent revision: {id}\n"));
    }
    s.push_str(&format!(
        "lineage: root={} mutator={} profile_depth={} axes={:#x}\n",
        p.lineage_root, p.mutator, p.profile.depth, p.profile.axis_mask
    ));
    s.push_str(&format!(
        "status: {} (supports {} contradictions {} ambiguous {})\n",
        p.status.name(),
        p.supports,
        p.contradictions,
        p.ambiguous_probes
    ));
    s.push_str(&format!(
        "continuation: {} class={} axis={} reason={} depth={}\n",
        p.continuation.kind.name(),
        if p.continuation.class == 0 {
            "none/structured-unknown".to_string()
        } else {
            FuzzMotif::from_code(p.continuation.class)
                .map(|m| m.name().to_string())
                .unwrap_or_else(|| format!("code#{}", p.continuation.class))
        },
        p.continuation.axis,
        p.continuation.reason,
        p.continuation.depth
    ));
    if let Some(t) = p.continuation.terminal_ref {
        s.push_str(&format!("terminal object: {t}\n"));
    }
    if let Some(prev) = p.prev_revision {
        s.push_str(&format!("previous revision: {prev}\n"));
    }
    s.push_str(&format!(
        "recipe: family={} axis={} expectation={} (min_count={}, min_run={}, min_bucket={})\n",
        p.recipe.family,
        p.recipe.axis,
        p.recipe.expectation.name(),
        p.recipe.min_count,
        p.recipe.min_run,
        p.recipe.min_sum_bucket
    ));
    s.push_str(&format!(
        "confuser: {}\ncreated_seq: {}\n",
        p.confuser.name(),
        p.created_seq
    ));
    if !p.evidence.is_empty() {
        s.push_str("recent evidence (newest first):\n");
        for e in &p.evidence {
            s.push_str(&format!(
                "  seq={} {} axis={} moved={} run={} bucket={}\n",
                e.seq,
                e.outcome.name(),
                e.axis,
                e.moved,
                e.run,
                e.sum_bucket
            ));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsfb::morphology::{LineageAccumulator, MorphologySignature};
    use crate::observe::residual::MutationResidual;
    use crate::precedent::probe::ProbeRecipe;
    use crate::target_runtime::signals::{SignalId, SignalVector};

    fn vec_with(id: u16, v: u64) -> SignalVector {
        let mut s = SignalVector::new();
        s.observe(SignalId(id), v).unwrap();
        s
    }

    fn drifting_sig(steps: u32) -> MorphologySignature {
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&vec_with(0, 0));
        let mut parent = vec_with(0, 0);
        let mut sig = acc.push(&MutationResidual::of(&parent, &parent), 0);
        for d in 1..=steps {
            let child = vec_with(0, d as u64);
            sig = acc.push(&MutationResidual::of(&child, &parent), d);
            parent = child;
        }
        sig
    }

    fn sample_precedent() -> Precedent {
        let sig = drifting_sig(6);
        let profile = PrefixProfile::from_signature(&sig, 6);
        Precedent {
            lineage_root: ContentId::new(b"rootA"),
            mutator: crate::mutation::MutatorId::DictionaryInsert.id(),
            profile,
            role_mask: 1,
            continuation: Continuation {
                kind: TerminalKind::CrashFinding,
                class: FuzzMotif::StateDepthExpansion.code(),
                axis: 0,
                depth: 24,
                reason: 5,
                terminal_ref: Some(ContentId::new(b"finding")),
            },
            confuser: ConfuserKind::SaturationWarmup,
            created_seq: 10,
            updated_seq: 10,
            status: PrecedentStatus::Candidate,
            prev_revision: None,
            supports: 0,
            contradictions: 0,
            ambiguous_probes: 0,
            recipe: ProbeRecipe::persists(
                crate::mutation::MutatorId::DictionaryInsert,
                0,
                20,
                4,
                3,
            ),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn precedent_roundtrip() {
        let p = sample_precedent();
        let enc = encode_precedent(&p).unwrap();
        let dec = decode_precedent(&enc).unwrap();
        assert_eq!(dec, p);
        assert!(decode_precedent(&enc[..enc.len() - 1]).is_err());
        let mut bad = enc.clone();
        bad[0] = 99;
        assert!(decode_precedent(&bad).is_err());
        let mut extra = enc.clone();
        extra.push(0);
        assert!(decode_precedent(&extra).is_err());
    }

    #[test]
    fn precedent_with_evidence_roundtrip() {
        let mut p = sample_precedent();
        p.evidence = vec![
            crate::precedent::probe::ProbeEvidence {
                outcome: ProbeOutcome::Contradict,
                seq: 42,
                axis: 0,
                moved: 0,
                run: 0,
                sum_bucket: 0,
                batch_execs: 500,
            },
            crate::precedent::probe::ProbeEvidence {
                outcome: ProbeOutcome::Support,
                seq: 41,
                axis: 0,
                moved: 300,
                run: 9,
                sum_bucket: 11,
                batch_execs: 500,
            },
        ];
        let enc = encode_precedent(&p).unwrap();
        assert_eq!(decode_precedent(&enc).unwrap(), p);
    }

    #[test]
    fn profile_subsumption_is_deterministic() {
        let sig = drifting_sig(10);
        let profile = PrefixProfile::from_signature(&drifting_sig(4), 4);
        // The deeper signature subsumes the shallower profile (same axes,
        // same directions, same classes).
        assert!(profile.subsumed_by(&sig));
        // A reversed-direction signature must NOT subsume the profile.
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&vec_with(0, 20));
        let mut parent = vec_with(0, 20);
        let mut rev = acc.push(&MutationResidual::of(&parent, &parent), 0);
        for d in 1..=6u32 {
            let child = vec_with(0, 20u64.saturating_sub(d as u64));
            rev = acc.push(&MutationResidual::of(&child, &parent), d);
            parent = child;
        }
        assert!(!profile.subsumed_by(&rev));
    }

    #[test]
    fn status_transitions_are_documented() {
        let p = sample_precedent();
        let ev = crate::precedent::probe::ProbeEvidence {
            outcome: ProbeOutcome::Support,
            seq: 1,
            axis: 0,
            moved: 300,
            run: 10,
            sum_bucket: 12,
            batch_execs: 500,
        };
        // Support on a Candidate -> Confirmed.
        let (s1, sup, _, _) = p.apply_probe(ProbeOutcome::Support, ev, false);
        assert_eq!(s1, PrecedentStatus::Confirmed);
        assert_eq!(sup, 1);
        // A DIRECT contradiction flips to Contradicted immediately.
        let cev = crate::precedent::probe::ProbeEvidence {
            outcome: ProbeOutcome::Contradict,
            seq: 2,
            axis: 0,
            moved: 0,
            run: 0,
            sum_bucket: 0,
            batch_execs: 500,
        };
        let (s2, _, c2, _) = sample_precedent().apply_probe(ProbeOutcome::Contradict, cev, true);
        assert_eq!(s2, PrecedentStatus::Contradicted);
        assert_eq!(c2, 1);
        // Three PARTIAL contradictions also flip (accumulated rule).
        let pev = crate::precedent::probe::ProbeEvidence {
            outcome: ProbeOutcome::Contradict,
            seq: 3,
            axis: 0,
            moved: 2,
            run: 1,
            sum_bucket: 1,
            batch_execs: 500,
        };
        let mut cur = sample_precedent();
        let status0 = cur.status;
        for _ in 0..3 {
            let (s, _, c, _) = cur.apply_probe(ProbeOutcome::Contradict, pev, false);
            cur.contradictions = c;
            cur.status = s;
        }
        assert_eq!(cur.contradictions, 3);
        assert_eq!(status0, PrecedentStatus::Candidate);
        assert_eq!(cur.status, PrecedentStatus::Contradicted);
        // Ambiguous outcomes never change the status.
        let aev = crate::precedent::probe::ProbeEvidence {
            outcome: ProbeOutcome::Ambiguous,
            seq: 4,
            axis: 0,
            moved: 5,
            run: 1,
            sum_bucket: 2,
            batch_execs: 500,
        };
        let (s3, _, _, am) = sample_precedent().apply_probe(ProbeOutcome::Ambiguous, aev, false);
        assert_eq!(s3, PrecedentStatus::Candidate);
        assert_eq!(am, 1);
    }

    #[test]
    fn identity_and_render_are_stable() {
        let p = sample_precedent();
        let enc = encode_precedent(&p).unwrap();
        let id = ContentId::new(
            &crate::canon::frame(
                crate::canon::Family::Precedent,
                crate::canon::MAJOR,
                crate::canon::MINOR,
                &enc,
            )
            .unwrap(),
        );
        let text = render_precedent(&p, Some(&id));
        assert!(text.contains("status: candidate"));
        assert!(text.contains("recipe:"));
        // Rendering must not change across identical revisions.
        assert_eq!(render_precedent(&p, Some(&id)), text);
    }
}
