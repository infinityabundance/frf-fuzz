//! The boundary-witness object model.
//!
//! A [`BoundaryWitness`] records a passing/failing (or regime-A/regime-B)
//! pair with the preserved behavioral relation, the current byte distance,
//! and the verification status. The canonical encoding is deterministic and
//! bounded; the object is immutable (Family::BoundaryWitness). When an FRF
//! authority exists (Phase 4), both sides are court-verified; until then the
//! verification status stays `Unverified` unless a deliberate replay
//! confirmed it.

use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::scheduler::work_order::MAX_INPUT_LEN;

/// Version of the witness payload encoding.
pub const WITNESS_VERSION: u8 = 1;

/// Which side of a boundary a stored object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BoundarySide {
    /// The left (regime-A / passing / admissible) side.
    Left = 1,
    /// The right (regime-B / failing / violating) side.
    Right = 2,
}

impl BoundarySide {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<BoundarySide> {
        match b {
            1 => Some(BoundarySide::Left),
            2 => Some(BoundarySide::Right),
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
            BoundarySide::Left => "left",
            BoundarySide::Right => "right",
        }
    }
}

/// What behavioral relation the pair preserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BoundaryRelation {
    /// Parity/divergence (two regimes diverge).
    ParityDivergence = 1,
    /// Admissible vs Boundary (one side still admissible, the other at the
    /// boundary).
    AdmissibleBoundary = 2,
    /// Boundary vs Violation.
    BoundaryViolation = 3,
    /// Stable vs Crash (the right side terminates the process).
    StableCrash = 4,
    /// Morphology A vs Morphology B (distinct structural shapes).
    #[allow(non_camel_case_types)]
    MorphologyA_MorphologyB = 5,
}

impl BoundaryRelation {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<BoundaryRelation> {
        match b {
            1 => Some(BoundaryRelation::ParityDivergence),
            2 => Some(BoundaryRelation::AdmissibleBoundary),
            3 => Some(BoundaryRelation::BoundaryViolation),
            4 => Some(BoundaryRelation::StableCrash),
            5 => Some(BoundaryRelation::MorphologyA_MorphologyB),
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
            BoundaryRelation::ParityDivergence => "parity-divergence",
            BoundaryRelation::AdmissibleBoundary => "admissible-boundary",
            BoundaryRelation::BoundaryViolation => "boundary-violation",
            BoundaryRelation::StableCrash => "stable-crash",
            BoundaryRelation::MorphologyA_MorphologyB => "morphology-a-b",
        }
    }
}

/// The verification status of a boundary witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WitnessVerification {
    /// Both sides were observed once; not yet deliberately verified.
    Unverified = 1,
    /// A deliberate re-execution confirmed both sides preserve the relation.
    Verified = 2,
    /// A deliberate re-execution contradicted the relation (both sides are
    /// retained; the contradiction is valuable knowledge, I10).
    Contradicted = 3,
}

impl WitnessVerification {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<WitnessVerification> {
        match b {
            1 => Some(WitnessVerification::Unverified),
            2 => Some(WitnessVerification::Verified),
            3 => Some(WitnessVerification::Contradicted),
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
            WitnessVerification::Unverified => "unverified",
            WitnessVerification::Verified => "verified",
            WitnessVerification::Contradicted => "contradicted",
        }
    }
}

/// A counterfactual boundary witness pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryWitness {
    /// The left (regime-A / passing) side object.
    pub left: ContentId,
    /// The right (regime-B / failing) side object.
    pub right: ContentId,
    /// The left side's input bytes (exact; the pair must minimize *these*).
    pub left_input: Vec<u8>,
    /// The right side's input bytes.
    pub right_input: Vec<u8>,
    /// The preserved behavioral relation.
    pub relation: BoundaryRelation,
    /// Current deterministic byte distance between the two inputs.
    pub distance: u64,
    /// Verification status.
    pub verification: WitnessVerification,
    /// The run tape of the minimized pair (Phase 2: written after a
    /// deliberate `boundary` session; None for auto-formed witnesses).
    pub tape: Option<ContentId>,
}

/// Encode a witness to its canonical payload.
pub fn encode_witness(w: &BoundaryWitness) -> Result<Vec<u8>> {
    if w.left_input.len() > MAX_INPUT_LEN || w.right_input.len() > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "witness input length",
            limit: MAX_INPUT_LEN as u64,
            got: w.left_input.len().max(w.right_input.len()) as u64,
        });
    }
    let mut out = Vec::with_capacity(1 + 64 + 8 + 1 + 1 + 1 + 4 + 8 + 4 + 33);
    out.push(WITNESS_VERSION);
    out.extend_from_slice(w.left.as_bytes());
    out.extend_from_slice(w.right.as_bytes());
    out.extend_from_slice(&(w.left_input.len() as u32).to_le_bytes());
    out.extend_from_slice(&w.left_input);
    out.extend_from_slice(&(w.right_input.len() as u32).to_le_bytes());
    out.extend_from_slice(&w.right_input);
    out.push(w.relation.code());
    out.extend_from_slice(&w.distance.to_le_bytes());
    out.push(w.verification.code());
    match w.tape {
        Some(t) => {
            out.push(1);
            out.extend_from_slice(t.as_bytes());
        }
        None => out.push(0),
    }
    Ok(out)
}

/// Decode a witness payload.
pub fn decode_witness(bytes: &[u8]) -> Result<BoundaryWitness> {
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > bytes.len() {
            return Err(Error::Encoding("witness truncated"));
        }
        let out = &bytes[pos..end];
        pos = end;
        Ok(out)
    };
    let version = take(1)?[0];
    if version != WITNESS_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "boundary-witness",
            version: version as u32,
        });
    }
    let left = ContentId::from_array(take(32)?.try_into().unwrap());
    let right = ContentId::from_array(take(32)?.try_into().unwrap());
    let llen = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
    if llen > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "witness input length",
            limit: MAX_INPUT_LEN as u64,
            got: llen as u64,
        });
    }
    let left_input = take(llen)?.to_vec();
    let rlen = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
    if rlen > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "witness input length",
            limit: MAX_INPUT_LEN as u64,
            got: rlen as u64,
        });
    }
    let right_input = take(rlen)?.to_vec();
    let relation = BoundaryRelation::from_byte(take(1)?[0])
        .ok_or(Error::Encoding("unknown boundary relation"))?;
    let distance = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let verification = WitnessVerification::from_byte(take(1)?[0])
        .ok_or(Error::Encoding("unknown witness verification"))?;
    let tape = match take(1)?[0] {
        0 => None,
        1 => Some(ContentId::from_array(take(32)?.try_into().unwrap())),
        _ => return Err(Error::Encoding("witness tape flag invalid")),
    };
    if pos != bytes.len() {
        return Err(Error::Encoding("witness has trailing bytes"));
    }
    Ok(BoundaryWitness {
        left,
        right,
        left_input,
        right_input,
        relation,
        distance,
        verification,
        tape,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_witness() -> BoundaryWitness {
        BoundaryWitness {
            left: ContentId::new(b"left"),
            right: ContentId::new(b"right"),
            left_input: b"aaaa".to_vec(),
            right_input: b"bbbb".to_vec(),
            relation: BoundaryRelation::StableCrash,
            distance: 4,
            verification: WitnessVerification::Unverified,
            tape: None,
        }
    }

    #[test]
    fn witness_roundtrip() {
        let w = sample_witness();
        let dec = decode_witness(&encode_witness(&w).unwrap()).unwrap();
        assert_eq!(dec, w);
    }

    #[test]
    fn witness_rejects_malformed() {
        let enc = encode_witness(&sample_witness()).unwrap();
        assert!(decode_witness(&enc[..enc.len() - 1]).is_err());
        let mut bad = enc.clone();
        bad[0] = 9;
        assert!(matches!(
            decode_witness(&bad),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn codes_are_stable() {
        assert_eq!(BoundaryRelation::StableCrash.code(), 4);
        assert_eq!(BoundaryRelation::MorphologyA_MorphologyB.code(), 5);
        assert_eq!(WitnessVerification::Unverified.code(), 1);
        assert_eq!(WitnessVerification::Verified.code(), 2);
        assert_eq!(WitnessVerification::Contradicted.code(), 3);
        assert_eq!(BoundarySide::Left.code(), 1);
        assert_eq!(BoundarySide::Right.code(), 2);
        assert_eq!(BoundaryRelation::from_byte(9), None);
        assert_eq!(WitnessVerification::from_byte(9), None);
    }
}
