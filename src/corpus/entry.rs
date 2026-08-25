//! Corpus entry objects and metadata.
//!
//! # Two-object design (why)
//!
//! A corpus entry is TWO store objects:
//!
//! * `CorpusEntry` — payload is the input bytes ONLY. Its content ID is a
//!   pure function of the input, so re-discovering the same input never
//!   duplicates storage and the input can be looked up by hashing.
//! * `CorpusMeta` — the durable observation metadata: entry ID, parent,
//!   generation, the footprint-masked feature set, the recorded signal
//!   observation, the admission reason, the edge mutator, the morphology
//!   signature ID, and the admission sequence number. Features/signals
//!   CANNOT be re-derived without re-execution, so this metadata is durable;
//!   it is what lets the in-memory corpus index be rebuilt by scanning
//!   (fsck/campaign start) instead of being treated as authoritative.
//!
//! # Version 2 (Phase 2)
//!
//! `signals` records the observed signal vector of the input (the
//! mutation-residual baseline for its children); `mutator_id` records the
//! edge mutator that produced the entry (lineage identity); `morphology_id`
//! references the durable morphology signature; `admission_seq` is the
//! coordinator's admission counter so lineage/regime replay on rebuild is
//! exactly the recorded processing order.
//!
//! The wire encoding below is fixed and bounded; see
//! [`crate::scheduler::work_order`] for the feature-set representation
//! (sorted `u64` packed indices `(range << 32) | offset`).
//!
//! This module is coordinator-gated.

use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::target_runtime::signals::SignalVector;

/// Version of the corpus-meta payload encoding.
pub const CORPUS_META_VERSION: u8 = 2;

/// Max features recorded per entry (an execution cannot exceed this).
pub const MAX_FEATURES_PER_ENTRY: usize = 1 << 16;

/// Why an input was admitted to the corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdmissionReason {
    /// A seed input (corpus seeding).
    Seed = 1,
    /// Discovered new coverage (new packed feature).
    NewCoverage = 2,
    /// A smaller representative of an existing feature set (cmin).
    SmallerRepresentative = 3,
    /// A crashing / timeout input (also stored as a finding).
    Crash = 4,
    /// A new (signal, value-bucket) state feature appeared (Phase 2).
    NewStateFeature = 5,
    /// A new morphology signature appeared and matched a named class
    /// (Phase 3+; Phase 2 has no named classes yet).
    NewMorphology = 6,
    /// A new non-trivial morphology that matches no named class — retained
    /// as a first-class Structured-Unknown trajectory (I6).
    StructuredUnknown = 7,
    /// A counterfactual boundary pair (regime-A/regime-B) was retained.
    BoundaryWitness = 8,
}

impl AdmissionReason {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<AdmissionReason> {
        match b {
            1 => Some(AdmissionReason::Seed),
            2 => Some(AdmissionReason::NewCoverage),
            3 => Some(AdmissionReason::SmallerRepresentative),
            4 => Some(AdmissionReason::Crash),
            5 => Some(AdmissionReason::NewStateFeature),
            6 => Some(AdmissionReason::NewMorphology),
            7 => Some(AdmissionReason::StructuredUnknown),
            8 => Some(AdmissionReason::BoundaryWitness),
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
            AdmissionReason::Seed => "seed",
            AdmissionReason::NewCoverage => "new-coverage",
            AdmissionReason::SmallerRepresentative => "smaller-representative",
            AdmissionReason::Crash => "crash",
            AdmissionReason::NewStateFeature => "new-state-feature",
            AdmissionReason::NewMorphology => "new-morphology",
            AdmissionReason::StructuredUnknown => "structured-unknown",
            AdmissionReason::BoundaryWitness => "boundary-witness",
        }
    }
}

/// Durable metadata for one corpus entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusMeta {
    /// The `CorpusEntry` object ID (the input).
    pub entry_id: ContentId,
    /// The parent entry's content ID, or `None` for seeds.
    pub parent_id: Option<ContentId>,
    /// Mutation generation / depth (0 for seeds).
    pub generation: u32,
    /// Footprint-masked feature set (sorted, deduplicated packed indices).
    pub features: Vec<u64>,
    /// Admission reason.
    pub reason: AdmissionReason,
    /// The recorded signal observation of this input (Phase 2; the
    /// mutation-residual baseline for its children).
    pub signals: SignalVector,
    /// The mutator family that produced this entry from its parent (None
    /// for seeds). Lineage identity (Phase 2).
    pub mutator_id: Option<u16>,
    /// The durable morphology signature of this entry's lineage position
    /// (None when the entry is a trivial baseline). Phase 2.
    pub morphology_id: Option<ContentId>,
    /// The coordinator's admission sequence number (rebuild/regime replay
    /// order). Phase 2.
    pub admission_seq: u64,
}

/// Encode corpus metadata to its canonical payload.
pub fn encode_meta(meta: &CorpusMeta) -> Result<Vec<u8>> {
    if meta.features.len() > MAX_FEATURES_PER_ENTRY {
        return Err(Error::BoundExceeded {
            what: "features per corpus entry",
            limit: MAX_FEATURES_PER_ENTRY as u64,
            got: meta.features.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(
        1 + 32 + 32 + 4 + 1 + 4 + meta.features.len() * 8 + 8 + 520 + 1 + 1 + 32 + 8,
    );
    out.push(CORPUS_META_VERSION);
    out.extend_from_slice(meta.entry_id.as_bytes());
    match meta.parent_id {
        Some(p) => out.extend_from_slice(p.as_bytes()),
        None => out.extend_from_slice(&[0u8; 32]),
    }
    out.extend_from_slice(&meta.generation.to_le_bytes());
    out.push(meta.reason.code());
    out.extend_from_slice(&(meta.features.len() as u32).to_le_bytes());
    for f in &meta.features {
        out.extend_from_slice(&f.to_le_bytes());
    }
    // Signal vector: touched mask + 64 × u64 (fixed 520 B).
    out.extend_from_slice(&meta.signals.touched_mask().to_le_bytes());
    for i in 0..crate::target_runtime::signals::MAX_SIGNALS {
        out.extend_from_slice(
            &meta
                .signals
                .value(crate::target_runtime::signals::SignalId(i as u16))
                .to_le_bytes(),
        );
    }
    match meta.mutator_id {
        Some(m) => out.extend_from_slice(&m.to_le_bytes()),
        None => out.extend_from_slice(&0u16.to_le_bytes()),
    }
    match meta.morphology_id {
        Some(id) => out.extend_from_slice(id.as_bytes()),
        None => out.extend_from_slice(&[0u8; 32]),
    }
    out.extend_from_slice(&meta.admission_seq.to_le_bytes());
    Ok(out)
}

/// Decode corpus metadata from its canonical payload.
pub fn decode_meta(bytes: &[u8]) -> Result<CorpusMeta> {
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > bytes.len() {
            return Err(Error::Encoding("corpus-meta truncated"));
        }
        let out = &bytes[pos..end];
        pos = end;
        Ok(out)
    };
    let version = take(1)?[0];
    if version != CORPUS_META_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "corpus-meta",
            version: version as u32,
        });
    }
    let entry_id = ContentId::from_array(take(32)?.try_into().unwrap());
    let parent_raw = take(32)?;
    let parent_id = if parent_raw.iter().all(|b| *b == 0) {
        None
    } else {
        Some(ContentId::from_array(parent_raw.try_into().unwrap()))
    };
    let generation = u32::from_le_bytes(take(4)?.try_into().unwrap());
    let reason = AdmissionReason::from_byte(take(1)?[0])
        .ok_or(Error::Encoding("unknown admission reason"))?;
    let feature_count = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
    if feature_count > MAX_FEATURES_PER_ENTRY {
        return Err(Error::BoundExceeded {
            what: "features per corpus entry",
            limit: MAX_FEATURES_PER_ENTRY as u64,
            got: feature_count as u64,
        });
    }
    let mut features = Vec::with_capacity(feature_count);
    for _ in 0..feature_count {
        features.push(u64::from_le_bytes(take(8)?.try_into().unwrap()));
    }
    // Signal vector (fixed 520 B).
    let touched = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let mut signals = SignalVector::new();
    for i in 0..crate::target_runtime::signals::MAX_SIGNALS {
        let v = u64::from_le_bytes(take(8)?.try_into().unwrap());
        if touched & (1u64 << i) != 0 {
            signals
                .observe(crate::target_runtime::signals::SignalId(i as u16), v)
                .map_err(|_| Error::Encoding("signal id out of range"))?;
        }
    }
    let mutator_raw = u16::from_le_bytes(take(2)?.try_into().unwrap());
    let mutator_id = if mutator_raw == 0 {
        None
    } else {
        Some(mutator_raw)
    };
    let morph_raw = take(32)?;
    let morphology_id = if morph_raw.iter().all(|b| *b == 0) {
        None
    } else {
        Some(ContentId::from_array(morph_raw.try_into().unwrap()))
    };
    let admission_seq = u64::from_le_bytes(take(8)?.try_into().unwrap());
    if pos != bytes.len() {
        return Err(Error::Encoding("corpus-meta has trailing bytes"));
    }
    Ok(CorpusMeta {
        entry_id,
        parent_id,
        generation,
        features,
        reason,
        signals,
        mutator_id,
        morphology_id,
        admission_seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_meta() -> CorpusMeta {
        let mut signals = SignalVector::new();
        signals
            .observe(crate::target_runtime::signals::SignalId(0), 42)
            .unwrap();
        CorpusMeta {
            entry_id: ContentId::new(b"input bytes"),
            parent_id: Some(ContentId::new(b"parent")),
            generation: 3,
            features: vec![1, 2, 0xFFFF_FFFF_0000_0000],
            reason: AdmissionReason::NewCoverage,
            signals,
            mutator_id: Some(7),
            morphology_id: Some(ContentId::new(b"morph")),
            admission_seq: 99,
        }
    }

    #[test]
    fn meta_roundtrip() {
        let m = sample_meta();
        let enc = encode_meta(&m).unwrap();
        let dec = decode_meta(&enc).unwrap();
        assert_eq!(dec, m);
    }

    #[test]
    fn seed_meta_roundtrip() {
        let m = CorpusMeta {
            parent_id: None,
            generation: 0,
            features: vec![],
            reason: AdmissionReason::Seed,
            mutator_id: None,
            morphology_id: None,
            admission_seq: 0,
            ..sample_meta()
        };
        let dec = decode_meta(&encode_meta(&m).unwrap()).unwrap();
        assert_eq!(dec, m);
        assert_eq!(dec.parent_id, None);
        assert_eq!(dec.mutator_id, None);
        assert_eq!(dec.morphology_id, None);
    }

    #[test]
    fn meta_rejects_truncation_and_trailing() {
        let enc = encode_meta(&sample_meta()).unwrap();
        assert!(decode_meta(&enc[..enc.len() - 1]).is_err());
        let mut extra = enc.clone();
        extra.push(0);
        assert!(decode_meta(&extra).is_err());
    }

    #[test]
    fn meta_rejects_unknown_version() {
        let mut enc = encode_meta(&sample_meta()).unwrap();
        enc[0] = 99;
        assert!(matches!(
            decode_meta(&enc),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn admission_reason_codes_are_stable() {
        assert_eq!(AdmissionReason::Seed.code(), 1);
        assert_eq!(AdmissionReason::NewCoverage.code(), 2);
        assert_eq!(AdmissionReason::SmallerRepresentative.code(), 3);
        assert_eq!(AdmissionReason::Crash.code(), 4);
        assert_eq!(AdmissionReason::NewStateFeature.code(), 5);
        assert_eq!(AdmissionReason::NewMorphology.code(), 6);
        assert_eq!(AdmissionReason::StructuredUnknown.code(), 7);
        assert_eq!(AdmissionReason::BoundaryWitness.code(), 8);
        assert_eq!(AdmissionReason::from_byte(1), Some(AdmissionReason::Seed));
        assert_eq!(AdmissionReason::from_byte(9), None);
    }
}
