//! Canonical object framing for the local store.
//!
//! Every persisted object in `.frf-fuzz/objects/` is framed as:
//!
//! ```text
//! magic   [u8; 4]  = b"FRFZ"
//! family  u8       (see Family)
//! major   u8       (framing major version; bump = breaking)
//! minor   u8       (framing minor version; bump = additive)
//! length  u64 LE   (payload length, bounded)
//! payload [u8; length]
//! ```
//!
//! The canonical identity is the BLAKE3-256 hash of exactly these bytes
//! (magic through payload); it must never contain host pathnames, wall-clock
//! timestamps, process IDs, memory addresses, or nondeterministic map
//! iteration (see docs/INVARIANTS.md, I13). Operational metadata lives in
//! sidecar files, outside the canonical payload.
//!
//! This module is dependency-free so the target-runtime plane can share the
//! framing. The hashing half (ContentId) lives in [`crate::id`], which is
//! coordinator-gated.
//!
//! All lengths are checked before allocation; every length is bounded by
//! [`MAX_OBJECT_LEN`].

use crate::error::{Error, Result};

/// Framing magic.
pub const MAGIC: [u8; 4] = *b"FRFZ";

/// Current framing major version. Bump only on breaking layout changes.
pub const MAJOR: u8 = 0;
/// Current framing minor version. Bump on additive changes.
pub const MINOR: u8 = 1;

/// Absolute ceiling for a single object payload. Kept far below any
/// plausibly-useful corpus object so hostile lengths fail before allocation.
pub const MAX_OBJECT_LEN: u64 = 1 << 30; // 1 GiB

/// Fixed header length: magic(4) + family(1) + major(1) + minor(1) + len(8).
pub const HEADER_LEN: usize = 15;

/// Maximum number of bytes in a single object (header + payload).
pub const MAX_TOTAL_LEN: u64 = MAX_OBJECT_LEN + HEADER_LEN as u64;

/// frf-fuzz internal object families.
///
/// These codes are frf-fuzz-internal. FRF IDs (SHA-256 content addresses and
/// `run-`/`receipt-` composites) and Gemel Gids live in their own namespaces
/// and are never reinterpreted through this table (docs/INVARIANTS.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Family {
    /// A corpus entry (input bytes + admission metadata).
    CorpusEntry = 0x01,
    /// A promoted finding (hypothesis, never an FRF receipt).
    Finding = 0x02,
    /// A deterministic run tape.
    RunTape = 0x03,
    /// A morphology signature (inspectable fields, not just a hash).
    MorphologySignature = 0x04,
    /// A structural precedent (prefix + context + probes + counterexamples).
    Precedent = 0x05,
    /// A campaign record.
    Campaign = 0x06,
    /// A durable campaign checkpoint.
    Checkpoint = 0x07,
    /// A counterfactual boundary witness pair.
    BoundaryWitness = 0x08,
    /// A closed regime episode.
    RegimeEpisode = 0x09,
    /// Configuration.
    Config = 0x0A,
    /// Corpus-entry metadata (features, parent, admission reason). The
    /// corpus entry object itself carries only the input bytes so its
    /// identity is a pure function of the input; this object carries the
    /// durable, non-rebuildable observation metadata (features cannot be
    /// re-derived without re-execution).
    CorpusMeta = 0x0B,
    /// The target's registered signal schema (name/unit per signal ID).
    /// Content-addressed: identical schemas share one object.
    SignalSchema = 0x0C,
    /// A DSFB structural verdict (Phase 3): the integer-reduced structural
    /// reading of one admitted lineage edge (axes, grammar/reason/policy
    /// codes, direction, deviation magnitudes) plus its bank nomination.
    StructuralVerdict = 0x0D,
    /// A closed DSFB-flavored structural episode (Phase 3): the lineage
    /// segment during which at least one axis sustained policy ≥ Review.
    StructuralEpisode = 0x0E,
    /// An FRF court-verification record (Phase 4): one promoted finding
    /// bound to one FRF evidence chain (run/receipt/claim ids, retained
    /// verbatim). Absence of a record for a finding = Unverified (derived,
    /// never fabricated). The record's identity is a pure function of its
    /// own content, so re-verification converges on one object.
    FindingVerification = 0x0F,
    /// A durable Gemel boundary record (Phase 4): one frf-fuzz durable
    /// boundary (campaign created/completed, finding verified, precedent
    /// admitted or falsified) with the Gemel source-state binding captured
    /// at that moment (head-state/change/intent/trajectory/producer Gids,
    /// retained verbatim) plus the outcome Gids Gemel published. Records
    /// the publication result class so a Gemel-side failure is observable
    /// and never silent (I14). No Gemel ID is ever reinterpreted.
    GemelBoundary = 0x10,
    /// A revision residual R_V(Vn, Vn-1, tape) (Phase 4): the typed
    /// behavioral difference between two artifact observations of the SAME
    /// tape candidate. Computed by revision tape replay; the scalar
    /// semantics are the MutationResidual semantics applied across the
    /// revision axis (never flattened).
    RevisionResidual = 0x11,
}

impl Family {
    /// All defined families.
    pub const ALL: [Family; 17] = [
        Family::CorpusEntry,
        Family::Finding,
        Family::RunTape,
        Family::MorphologySignature,
        Family::Precedent,
        Family::Campaign,
        Family::Checkpoint,
        Family::BoundaryWitness,
        Family::RegimeEpisode,
        Family::Config,
        Family::CorpusMeta,
        Family::SignalSchema,
        Family::StructuralVerdict,
        Family::StructuralEpisode,
        Family::FindingVerification,
        Family::GemelBoundary,
        Family::RevisionResidual,
    ];

    /// The one-byte family code.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Decode a family from its one-byte code.
    pub fn from_code(code: u8) -> Option<Family> {
        Self::ALL.iter().copied().find(|f| f.code() == code)
    }

    /// Human-readable family name.
    pub fn name(self) -> &'static str {
        match self {
            Family::CorpusEntry => "corpus-entry",
            Family::Finding => "finding",
            Family::RunTape => "run-tape",
            Family::MorphologySignature => "morphology-signature",
            Family::Precedent => "precedent",
            Family::Campaign => "campaign",
            Family::Checkpoint => "checkpoint",
            Family::BoundaryWitness => "boundary-witness",
            Family::RegimeEpisode => "regime-episode",
            Family::Config => "config",
            Family::CorpusMeta => "corpus-meta",
            Family::SignalSchema => "signal-schema",
            Family::StructuralVerdict => "structural-verdict",
            Family::StructuralEpisode => "structural-episode",
            Family::FindingVerification => "finding-verification",
            Family::GemelBoundary => "gemel-boundary",
            Family::RevisionResidual => "revision-residual",
        }
    }
}

/// A decoded object header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectHeader {
    /// The object family.
    pub family: Family,
    /// Framing major version.
    pub major: u8,
    /// Framing minor version.
    pub minor: u8,
    /// Payload length in bytes (bounded by [`MAX_OBJECT_LEN`]).
    pub length: u64,
}

impl ObjectHeader {
    /// Encode the 15-byte header for `payload_len` payload bytes.
    ///
    /// Rejects payload lengths above [`MAX_OBJECT_LEN`] (checked before any
    /// allocation or write).
    pub fn encode(
        family: Family,
        major: u8,
        minor: u8,
        payload_len: u64,
    ) -> Result<[u8; HEADER_LEN]> {
        if payload_len > MAX_OBJECT_LEN {
            return Err(Error::BoundExceeded {
                what: "object payload length",
                limit: MAX_OBJECT_LEN,
                got: payload_len,
            });
        }
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(&MAGIC);
        h[4] = family.code();
        h[5] = major;
        h[6] = minor;
        h[7..15].copy_from_slice(&payload_len.to_le_bytes());
        Ok(h)
    }

    /// Decode and validate a 15-byte header.
    ///
    /// Fails on: bad magic, unknown family, unsupported major version, or an
    /// impossible payload length.
    pub fn decode(bytes: &[u8]) -> Result<ObjectHeader> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Encoding("header shorter than HEADER_LEN"));
        }
        if bytes[0..4] != MAGIC {
            return Err(Error::BadMagic {
                expected: hex(&MAGIC),
                got: hex(&bytes[0..4]),
            });
        }
        let family = Family::from_code(bytes[4])
            .ok_or(Error::Encoding("unknown family code in object header"))?;
        let major = bytes[5];
        if major != MAJOR {
            return Err(Error::UnsupportedVersion {
                family: family.name(),
                version: major as u32,
            });
        }
        let minor = bytes[6];
        let length = u64::from_le_bytes(bytes[7..15].try_into().unwrap());
        if length > MAX_OBJECT_LEN {
            return Err(Error::BoundExceeded {
                what: "object payload length",
                limit: MAX_OBJECT_LEN,
                got: length,
            });
        }
        Ok(ObjectHeader {
            family,
            major,
            minor,
            length,
        })
    }

    /// Total framed length for this header (header + payload).
    pub fn total_len(&self) -> Result<u64> {
        HEADER_LEN
            .checked_add(self.length as usize)
            .map(|t| t as u64)
            .ok_or(Error::Overflow)
    }
}

/// Build the full canonical framed object (header + payload) in a fresh
/// buffer. The returned bytes are the canonical identity input.
pub fn frame(family: Family, major: u8, minor: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let header = ObjectHeader::encode(family, major, minor, payload.len() as u64)?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode a full framed object, returning the validated header and the
/// payload slice. Rejects malformed framing and unknown versions before
/// touching the payload.
pub fn unframe(bytes: &[u8]) -> Result<(ObjectHeader, &[u8])> {
    let header = ObjectHeader::decode(bytes)?;
    let total = header.total_len()? as usize;
    if bytes.len() < total {
        return Err(Error::Encoding("object truncated"));
    }
    // Reject trailing bytes: canonical encoding is exact.
    if bytes.len() != total {
        return Err(Error::Encoding("object has trailing bytes"));
    }
    Ok((header, &bytes[HEADER_LEN..total]))
}

fn hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        for family in Family::ALL {
            let h = ObjectHeader::encode(family, MAJOR, MINOR, 42).unwrap();
            let d = ObjectHeader::decode(&h).unwrap();
            assert_eq!(d.family, family);
            assert_eq!(d.length, 42);
            assert_eq!(d.major, MAJOR);
            assert_eq!(d.minor, MINOR);
        }
    }

    #[test]
    fn frame_unframe_roundtrip() {
        let payload = b"the canonical deterministic payload";
        let framed = frame(Family::Finding, MAJOR, MINOR, payload).unwrap();
        let (h, p) = unframe(&framed).unwrap();
        assert_eq!(h.family, Family::Finding);
        assert_eq!(p, payload);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut framed = frame(Family::Finding, MAJOR, MINOR, b"x").unwrap();
        framed[0] = b'X';
        assert!(matches!(unframe(&framed), Err(Error::BadMagic { .. })));
    }

    #[test]
    fn rejects_unknown_family() {
        let mut framed = frame(Family::Finding, MAJOR, MINOR, b"x").unwrap();
        framed[4] = 0xFF;
        assert!(matches!(unframe(&framed), Err(Error::Encoding(_))));
    }

    #[test]
    fn rejects_unknown_major_version() {
        let framed = frame(Family::Finding, 99, MINOR, b"x").unwrap();
        assert!(matches!(
            unframe(&framed),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn rejects_impossible_length() {
        let mut framed = frame(Family::Finding, MAJOR, MINOR, b"x").unwrap();
        // length field = 2^40 (LE)
        framed[7..15].copy_from_slice(&(1u64 << 40).to_le_bytes());
        assert!(matches!(unframe(&framed), Err(Error::BoundExceeded { .. })));
    }

    #[test]
    fn rejects_truncation_and_trailing_bytes() {
        let payload = b"payload-payload-payload";
        let framed = frame(Family::Finding, MAJOR, MINOR, payload).unwrap();
        assert!(matches!(
            unframe(&framed[..framed.len() - 3]),
            Err(Error::Encoding(_))
        ));
        let mut extra = framed.clone();
        extra.push(0);
        assert!(matches!(unframe(&extra), Err(Error::Encoding(_))));
    }

    #[test]
    fn encode_rejects_oversized_length() {
        assert!(matches!(
            ObjectHeader::encode(Family::Finding, MAJOR, MINOR, MAX_OBJECT_LEN + 1),
            Err(Error::BoundExceeded { .. })
        ));
    }

    #[test]
    fn header_layout_is_exact() {
        // Lock the framing layout: magic(4) family(1) major(1) minor(1) len(8).
        let h = ObjectHeader::encode(Family::CorpusEntry, MAJOR, MINOR, 0x0102_0304).unwrap();
        assert_eq!(&h[0..4], b"FRFZ");
        assert_eq!(h[4], 0x01); // CorpusEntry
        assert_eq!(h[5], 0);
        assert_eq!(h[6], 1);
        assert_eq!(&h[7..15], &0x0102_0304u64.to_le_bytes());
        assert_eq!(h.len(), HEADER_LEN);
    }
}
