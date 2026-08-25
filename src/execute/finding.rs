//! Finding objects (Family::Finding).
//!
//! A finding is a HYPOTHESIS: "this exact input reproduces this outcome
//! class on this build". It is never an FRF receipt or claim (I4; Phase 4
//! adds the FRF court on promotion). The finding is self-contained: it
//! embeds the exact input bytes, so `replay` and `fsck` never depend on the
//! corpus index to re-verify it.
//!
//! The canonical payload contains NO wall-clock timestamps, process IDs, or
//! host paths (docs/INVARIANTS.md): those live in the campaign record and
//! the human-readable sidecar the CLI writes next to the finding.
//!
//! This module is coordinator-gated.

use crate::error::{Error, Result};
use crate::mutation::coordinate::{COORDINATE_ENCODED_LEN, COORDINATE_VERSION};
use crate::mutation::MutationCoordinate;
use crate::scheduler::work_order::MAX_INPUT_LEN;

/// Version of the finding payload encoding.
pub const FINDING_VERSION: u8 = 1;

/// The observed outcome class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FindingKind {
    /// The process died (ASan finding, panic=abort, signal, abort, OOM).
    Crash = 1,
    /// The watchdog aborted the execution (hang).
    Timeout = 2,
    /// The worker died but the ledger could not attribute it to a specific
    /// candidate (e.g. death between executions, or replay did not
    /// reproduce). Recorded, never deleted (I10).
    Unattributed = 3,
}

impl FindingKind {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<FindingKind> {
        match b {
            1 => Some(FindingKind::Crash),
            2 => Some(FindingKind::Timeout),
            3 => Some(FindingKind::Unattributed),
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
            FindingKind::Crash => "crash",
            FindingKind::Timeout => "timeout",
            FindingKind::Unattributed => "unattributed",
        }
    }
}

/// Whether a deliberate replay reproduced the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplayStatus {
    /// Not yet replayed.
    NotReplayed = 0,
    /// The deliberate replay reproduced the same outcome class.
    Reproduced = 1,
    /// The deliberate replay did NOT reproduce it (live/replay divergence —
    /// preserved and reported, never silently resolved).
    NotReproduced = 2,
}

impl ReplayStatus {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<ReplayStatus> {
        match b {
            0 => Some(ReplayStatus::NotReplayed),
            1 => Some(ReplayStatus::Reproduced),
            2 => Some(ReplayStatus::NotReproduced),
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
            ReplayStatus::NotReplayed => "not-replayed",
            ReplayStatus::Reproduced => "reproduced",
            ReplayStatus::NotReproduced => "not-reproduced",
        }
    }
}

/// The durable finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Outcome class.
    pub kind: FindingKind,
    /// Parent corpus entry short key (zeros for seeds/overrides).
    pub parent_short: [u8; 8],
    /// The mutation coordinate (or the override marker for inputs that were
    /// not produced by mutation).
    pub coordinate: [u8; COORDINATE_ENCODED_LEN],
    /// Deliberate-replay status.
    pub replay: ReplayStatus,
    /// The exact input bytes.
    pub input: Vec<u8>,
}

impl Finding {
    /// A typed-coordinate accessor (None for override markers, whose
    /// mutator id 0 the typed decoder refuses).
    pub fn coordinate_typed(&self) -> Option<MutationCoordinate> {
        MutationCoordinate::decode(&self.coordinate).ok()
    }
}

/// Encode a finding to its canonical payload.
pub fn encode_finding(f: &Finding) -> Result<Vec<u8>> {
    if f.input.len() > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "finding input length",
            limit: MAX_INPUT_LEN as u64,
            got: f.input.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(1 + 1 + 8 + COORDINATE_ENCODED_LEN + 1 + 4 + f.input.len());
    out.push(FINDING_VERSION);
    out.push(f.kind.code());
    out.extend_from_slice(&f.parent_short);
    out.extend_from_slice(&f.coordinate);
    out.push(f.replay.code());
    out.extend_from_slice(&(f.input.len() as u32).to_le_bytes());
    out.extend_from_slice(&f.input);
    Ok(out)
}

/// Decode a finding from its canonical payload.
pub fn decode_finding(bytes: &[u8]) -> Result<Finding> {
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > bytes.len() {
            return Err(Error::Encoding("finding truncated"));
        }
        let out = &bytes[pos..end];
        pos = end;
        Ok(out)
    };
    let version = take(1)?[0];
    if version != FINDING_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "finding",
            version: version as u32,
        });
    }
    let kind =
        FindingKind::from_byte(take(1)?[0]).ok_or(Error::Encoding("unknown finding kind"))?;
    let parent_short = take(8)?.try_into().unwrap();
    let coordinate = take(COORDINATE_ENCODED_LEN)?.try_into().unwrap();
    let replay =
        ReplayStatus::from_byte(take(1)?[0]).ok_or(Error::Encoding("unknown replay status"))?;
    let input_len = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
    if input_len > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "finding input length",
            limit: MAX_INPUT_LEN as u64,
            got: input_len as u64,
        });
    }
    let input = take(input_len)?.to_vec();
    if pos != bytes.len() {
        return Err(Error::Encoding("finding has trailing bytes"));
    }
    Ok(Finding {
        kind,
        parent_short,
        coordinate,
        replay,
        input,
    })
}

/// The zero coordinate (used for seeds and un-mutated inputs).
pub const ZERO_COORDINATE: [u8; COORDINATE_ENCODED_LEN] = {
    let mut c = [0u8; COORDINATE_ENCODED_LEN];
    c[0] = COORDINATE_VERSION;
    c
};

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Finding {
        Finding {
            kind: FindingKind::Crash,
            parent_short: [1, 2, 3, 4, 5, 6, 7, 8],
            coordinate: {
                let c = MutationCoordinate {
                    campaign_seed: 7,
                    parent_short_id: [9; 8],
                    generation: 1,
                    mutator_id: crate::mutation::MutatorId::ByteFlip,
                    lane_id: 2,
                    mutation_index: 3,
                    probe_params: [0; 4],
                };
                c.encode()
            },
            replay: ReplayStatus::Reproduced,
            input: b"crashing input".to_vec(),
        }
    }

    #[test]
    fn finding_roundtrip() {
        let f = sample();
        let dec = decode_finding(&encode_finding(&f).unwrap()).unwrap();
        assert_eq!(dec, f);
        assert_eq!(
            dec.coordinate_typed().unwrap(),
            f.coordinate_typed().unwrap()
        );
    }

    #[test]
    fn override_marker_coordinate_is_recognized() {
        let mut f = sample();
        // The override marker: mutator id 0 (unused by the stable table).
        f.coordinate = {
            let mut c = ZERO_COORDINATE;
            c[21..23].copy_from_slice(&0u16.to_le_bytes());
            c
        };
        let dec = decode_finding(&encode_finding(&f).unwrap()).unwrap();
        assert!(dec.coordinate_typed().is_none());
    }

    #[test]
    fn finding_rejects_truncation_and_bad_kind() {
        let enc = encode_finding(&sample()).unwrap();
        assert!(decode_finding(&enc[..enc.len() - 1]).is_err());
        let mut bad = enc.clone();
        bad[1] = 0xEE;
        assert!(decode_finding(&bad).is_err());
    }

    #[test]
    fn kind_codes_are_stable() {
        assert_eq!(FindingKind::Crash.code(), 1);
        assert_eq!(FindingKind::Timeout.code(), 2);
        assert_eq!(FindingKind::Unattributed.code(), 3);
        assert_eq!(ReplayStatus::NotReplayed.code(), 0);
        assert_eq!(ReplayStatus::Reproduced.code(), 1);
        assert_eq!(ReplayStatus::NotReproduced.code(), 2);
    }
}
