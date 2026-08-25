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
//!   generation, the footprint-masked feature set, and the admission
//!   reason. Features CANNOT be re-derived without re-execution, so this
//!   metadata is durable; it is what lets the in-memory
//!   [`CorpusIndex`] be rebuilt by scanning (fsck/campaign start) instead
//!   of being treated as authoritative.
//!
//! The wire encoding below is fixed and bounded; see
//! [`crate::scheduler::work_order`] for the feature-set representation
//! (sorted `u64` packed indices `(range << 32) | offset`).
//!
//! This module is coordinator-gated.

use crate::error::{Error, Result};
use crate::id::ContentId;

/// Version of the corpus-meta payload encoding.
pub const CORPUS_META_VERSION: u8 = 1;

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
}

impl AdmissionReason {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<AdmissionReason> {
        match b {
            1 => Some(AdmissionReason::Seed),
            2 => Some(AdmissionReason::NewCoverage),
            3 => Some(AdmissionReason::SmallerRepresentative),
            4 => Some(AdmissionReason::Crash),
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
    let mut out = Vec::with_capacity(1 + 32 + 32 + 4 + 1 + 4 + meta.features.len() * 8);
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
    if pos != bytes.len() {
        return Err(Error::Encoding("corpus-meta has trailing bytes"));
    }
    Ok(CorpusMeta {
        entry_id,
        parent_id,
        generation,
        features,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_meta() -> CorpusMeta {
        CorpusMeta {
            entry_id: ContentId::new(b"input bytes"),
            parent_id: Some(ContentId::new(b"parent")),
            generation: 3,
            features: vec![1, 2, 0xFFFF_FFFF_0000_0000],
            reason: AdmissionReason::NewCoverage,
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
            ..sample_meta()
        };
        let dec = decode_meta(&encode_meta(&m).unwrap()).unwrap();
        assert_eq!(dec, m);
        assert_eq!(dec.parent_id, None);
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
        assert_eq!(AdmissionReason::from_byte(1), Some(AdmissionReason::Seed));
        assert_eq!(AdmissionReason::from_byte(9), None);
    }
}
