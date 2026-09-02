//! Revision tape replay (Phase 4): identical tapes across software states.
//!
//! The same `RunTape` candidate is replayed through N *artifact* probes —
//! instrumented fuzz-target binaries built from N software revisions (Gemel
//! states or any user labels) — and the same-tape observations are compared
//! across consecutive states. A difference between two states on the SAME
//! tape, SAME input, SAME observation surface is a program-side perturbation
//! between those revisions (a branch of development is a natural controlled
//! experiment; docs/DESIGN-GEMEL-BRIDGE.md).
//!
//! Durable objects (`Family::RevisionResidual`, 0x11) persist each adjacent
//! pair: the tape id, the two artifact digests (BLAKE3-256 of the exact
//! binary bytes that executed), the two environment digests (toolchain
//! identity from each probe's HELLO), the two termination statuses, and both
//! signal observations when the side survived. The residual itself is
//! DERIVED at decode time ([`RevisionResidual::of`]) — same bytes, same
//! residual (I12) — but the object family keeps R_V separate from R_M and
//! R_T (master prompt §12; never flattened).
//!
//! Canonical identity contains no host pathnames or timestamps: labels are
//! caller-chosen identifiers (Gemel state Gids, commit ids, ...) and artifact
//! digests are content.
//!
//! This module is coordinator-gated.

use crate::canon::Family;
use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::observe::residual::RevisionResidual;
use crate::store::Store;
use crate::tape::model::TerminationStatus;
use crate::target_runtime::signals::{SignalId, SignalVector, MAX_SIGNALS};

/// Version of the revision-residual payload encoding.
pub const REVISION_RESIDUAL_VERSION: u8 = 1;

/// Maximum label length (bounded before allocation).
pub const MAX_REVISION_LABEL_LEN: usize = 256;

/// One artifact's observation of the tape candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionStateObservation {
    /// Caller-chosen revision identifier (e.g. a Gemel state Gid string).
    pub label: String,
    /// BLAKE3-256 of the exact binary bytes that executed.
    pub artifact: [u8; 32],
    /// Canonical environment digest (toolchain identity of the probe).
    pub environment: [u8; 32],
    /// How the candidate terminated on this artifact.
    pub termination: TerminationStatus,
    /// The recorded signal observation (present iff `termination == Ok`).
    pub signals: Option<SignalVector>,
}

/// The durable revision-residual pair object (R_V across one revision edge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionPair {
    /// The tape whose candidate both artifacts executed.
    pub tape: ContentId,
    /// The earlier revision's observation.
    pub earlier: RevisionStateObservation,
    /// The later revision's observation.
    pub later: RevisionStateObservation,
}

impl RevisionPair {
    /// Derive the typed residual (None unless both sides survived with
    /// observations — a termination change is itself a program-side
    /// perturbation, reported through the statuses instead).
    pub fn residual(&self) -> Option<RevisionResidual> {
        match (&self.earlier.signals, &self.later.signals) {
            (Some(e), Some(l)) => Some(RevisionResidual::of(l, e)),
            _ => None,
        }
    }
}

/// Encode a revision pair to its canonical payload.
///
/// Layout: version(1) | tape-id(32) | earlier-state | later-state, where each
/// state is label(u32 len + utf-8) | artifact(32) | environment(32) |
/// termination(1) | signals-flag(1) | [signals: touched(8) + 64*value(8)].
/// The signal layout mirrors the wire encoding of the worker observation
/// (fixed 520 bytes), kept self-contained so this module has no private
/// dependency on the scheduler codec.
pub fn encode_revision_pair(p: &RevisionPair) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 32 + 2 * (4 + 64 + 32 + 32 + 1 + 1 + 520));
    out.push(REVISION_RESIDUAL_VERSION);
    out.extend_from_slice(p.tape.as_bytes());
    push_state(&mut out, &p.earlier)?;
    push_state(&mut out, &p.later)?;
    Ok(out)
}

/// Decode a revision pair from its canonical payload.
pub fn decode_revision_pair(bytes: &[u8]) -> Result<RevisionPair> {
    let mut r = Reader { bytes, pos: 0 };
    let version = r.take(1)?[0];
    if version != REVISION_RESIDUAL_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "revision-residual",
            version: version as u32,
        });
    }
    let tape: [u8; 32] = r.take(32)?.try_into().unwrap();
    let earlier = take_state(&mut r)?;
    let later = take_state(&mut r)?;
    if r.pos != bytes.len() {
        return Err(Error::Encoding("revision pair has trailing bytes"));
    }
    Ok(RevisionPair {
        tape: ContentId::from_array(tape),
        earlier,
        later,
    })
}

/// Bounded cursor over the canonical payload.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > self.bytes.len() {
            return Err(Error::Encoding("revision pair truncated"));
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }
}

fn push_state(out: &mut Vec<u8>, s: &RevisionStateObservation) -> Result<()> {
    push_str(out, &s.label, MAX_REVISION_LABEL_LEN)?;
    out.extend_from_slice(&s.artifact);
    out.extend_from_slice(&s.environment);
    out.push(s.termination.code());
    match &s.signals {
        Some(v) => {
            out.push(1u8);
            out.extend_from_slice(&v.touched_mask().to_le_bytes());
            for i in 0..MAX_SIGNALS {
                out.extend_from_slice(&v.value(SignalId(i as u16)).to_le_bytes());
            }
        }
        None => out.push(0u8),
    }
    Ok(())
}

fn take_state(r: &mut Reader<'_>) -> Result<RevisionStateObservation> {
    let label = take_str(r, MAX_REVISION_LABEL_LEN)?;
    let artifact: [u8; 32] = r.take(32)?.try_into().unwrap();
    let environment: [u8; 32] = r.take(32)?.try_into().unwrap();
    let termination = TerminationStatus::from_byte(r.take(1)?[0])
        .ok_or(Error::Encoding("unknown revision termination status"))?;
    let signals = match r.take(1)?[0] {
        0 => None,
        1 => {
            let touched = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
            let mut v = SignalVector::new();
            for i in 0..MAX_SIGNALS {
                let val = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
                if touched & (1u64 << i) != 0 {
                    v.observe(SignalId(i as u16), val)
                        .map_err(|_| Error::Encoding("revision signal id out of range"))?;
                }
            }
            Some(v)
        }
        _ => return Err(Error::Encoding("invalid revision signals flag")),
    };
    Ok(RevisionStateObservation {
        label,
        artifact,
        environment,
        termination,
        signals,
    })
}

fn push_str(out: &mut Vec<u8>, s: &str, limit: usize) -> Result<()> {
    if s.len() > limit {
        return Err(Error::BoundExceeded {
            what: "revision label",
            limit: limit as u64,
            got: s.len() as u64,
        });
    }
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn take_str(r: &mut Reader<'_>, limit: usize) -> Result<String> {
    let len = u32::from_le_bytes(r.take(4)?.try_into().unwrap()) as usize;
    if len > limit {
        return Err(Error::BoundExceeded {
            what: "revision label",
            limit: limit as u64,
            got: len as u64,
        });
    }
    let s = std::str::from_utf8(r.take(len)?)
        .map_err(|_| Error::Encoding("revision label is not utf-8"))?;
    Ok(s.to_string())
}

// ---------------------------------------------------------------------------
// Replay driver
// ---------------------------------------------------------------------------

/// A per-state probe: how to execute one input on one artifact and observe
/// the outcome. `verify` runs the candidate and returns `(died, signals,
/// features)` — the same shape [`crate::tape::replay::replay_tape_payload`]
/// consumes.
pub struct StateProbe<'a> {
    /// Caller-chosen revision identifier (Gemel state Gid, commit id, ...).
    pub label: String,
    /// BLAKE3-256 of the artifact bytes that will execute.
    pub artifact: [u8; 32],
    /// Canonical environment digest of the artifact's toolchain.
    pub environment: [u8; 32],
    /// The execution probe (spawns/uses the artifact's instrumented binary).
    #[allow(clippy::type_complexity)]
    pub verify: &'a mut dyn FnMut(&[u8]) -> Result<(bool, SignalVector, Vec<u64>)>,
}

/// Replay one tape's candidate through every state probe, in order.
///
/// Each state's observation is measured exactly once per probe. The state
/// order is the caller's (usually chronological); adjacent pairs form the
/// revision edges. A probe whose process died records the tape's recorded
/// termination class (Crash/Timeout) with no signal observation — a
/// termination change across states is itself a program-side perturbation
/// and is preserved in the pair statuses (I10).
pub fn replay_across_states(
    tape: &crate::tape::model::RunTape,
    probes: &mut [StateProbe<'_>],
) -> Result<Vec<RevisionStateObservation>> {
    let mut out = Vec::with_capacity(probes.len());
    for p in probes.iter_mut() {
        let (died, signals, _features) = (p.verify)(&tape.candidate)?;
        let termination = if died {
            // The probe process did not survive. The recorded tape class is
            // the best attribution: a replay that times out keeps Timeout;
            // any other death keeps the tape's own termination class (for an
            // Ok tape, a death is Crash). The live/recorded divergence is
            // preserved by the caller through the pair statuses.
            match tape.termination {
                TerminationStatus::Ok => TerminationStatus::Crash,
                other => other,
            }
        } else {
            TerminationStatus::Ok
        };
        let observation = if termination == TerminationStatus::Ok {
            Some(signals)
        } else {
            None
        };
        out.push(RevisionStateObservation {
            label: p.label.clone(),
            artifact: p.artifact,
            environment: p.environment,
            termination,
            signals: observation,
        });
    }
    Ok(out)
}

/// Compare one state's observation against the tape's recorded observation
/// (revision replay report; signals + termination only).
///
/// Features are deliberately NOT compared across revisions: a different
/// build has different edges, so coverage features legitimately differ; the
/// pre-registered signal surface is the stable cross-revision observation
/// (the schema defines it). A termination tape is reproduced only by a
/// death.
pub fn compare_state_to_tape(
    tape: &crate::tape::model::RunTape,
    state: &RevisionStateObservation,
) -> crate::tape::replay::TapeReplayOutcome {
    use crate::tape::replay::TapeReplayOutcome;
    let survived = state.termination == TerminationStatus::Ok;
    match tape.termination {
        TerminationStatus::Crash | TerminationStatus::Timeout => {
            if survived {
                TapeReplayOutcome::Diverged {
                    reason: "the state's artifact survived although the tape records a termination"
                        .into(),
                }
            } else {
                TapeReplayOutcome::TerminationReproduced
            }
        }
        TerminationStatus::Ok => {
            if !survived {
                return TapeReplayOutcome::Diverged {
                    reason: "the state's artifact died although the tape records Ok".into(),
                };
            }
            match (&tape.observation, &state.signals) {
                (None, _) => TapeReplayOutcome::Matches,
                (Some(recorded), Some(live)) => {
                    for i in 0..crate::target_runtime::signals::MAX_SIGNALS {
                        let id = SignalId(i as u16);
                        let rt = recorded.signals.was_touched(id);
                        let lt = live.was_touched(id);
                        if rt != lt {
                            return TapeReplayOutcome::Diverged {
                                reason: format!(
                                    "signal {i} touched-set differs: tape {rt} vs live {lt}"
                                ),
                            };
                        }
                        if rt && recorded.signals.value(id) != live.value(id) {
                            return TapeReplayOutcome::Diverged {
                                reason: format!(
                                    "signal {i} value differs: tape {} vs live {}",
                                    recorded.signals.value(id),
                                    live.value(id)
                                ),
                            };
                        }
                    }
                    TapeReplayOutcome::Matches
                }
                (Some(_), None) => TapeReplayOutcome::Diverged {
                    reason: "the state's artifact survived but recorded no signals".into(),
                },
            }
        }
    }
}

/// Persist every adjacent pair of a state replay as a durable revision
/// residual object. Returns the object ids in replay order (n-1 for n
/// states; empty for fewer than two states).
pub fn persist_pairs(
    store: &Store,
    tape: &ContentId,
    states: &[RevisionStateObservation],
) -> Result<Vec<ContentId>> {
    let mut ids = Vec::new();
    for w in states.windows(2) {
        let pair = RevisionPair {
            tape: *tape,
            earlier: w[0].clone(),
            later: w[1].clone(),
        };
        let payload = encode_revision_pair(&pair)?;
        ids.push(store.put(Family::RevisionResidual, &payload)?);
    }
    Ok(ids)
}

/// Verify revision-residual link closure for `fsck`: every stored object
/// decodes and its tape reference resolves to a stored `RunTape`. Returns
/// human-readable defects (empty = clean).
pub fn verify_links(store: &Store) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    for id in store.list_object_ids()? {
        let Ok(Some((Family::RevisionResidual, payload))) = store.get_typed(&id) else {
            continue;
        };
        let pair = match decode_revision_pair(&payload) {
            Ok(p) => p,
            Err(e) => {
                errors.push(format!("{id}: corrupt revision-residual payload: {e}"));
                continue;
            }
        };
        match store.get_typed(&pair.tape) {
            Ok(Some((Family::RunTape, _))) => {}
            _ => errors.push(format!(
                "{id}: tape reference {} is missing or not a run-tape",
                pair.tape
            )),
        }
    }
    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tape::model::RunTape;

    fn observation(label: &str, v: Option<u64>, artifact_seed: u8) -> RevisionStateObservation {
        let mut signals = SignalVector::new();
        let termination = match v {
            Some(val) => {
                signals.observe(SignalId(0), val).unwrap();
                TerminationStatus::Ok
            }
            None => TerminationStatus::Crash,
        };
        RevisionStateObservation {
            label: label.to_string(),
            artifact: [artifact_seed; 32],
            environment: [0; 32],
            termination,
            signals: if termination == TerminationStatus::Ok {
                Some(signals)
            } else {
                None
            },
        }
    }

    #[test]
    fn pair_roundtrip_and_delta_derivation() {
        let earlier = observation("state-a", Some(10), 1);
        let later = observation("state-b", Some(14), 2);
        let pair = RevisionPair {
            tape: ContentId::new(b"tape"),
            earlier,
            later,
        };
        let dec = decode_revision_pair(&encode_revision_pair(&pair).unwrap()).unwrap();
        assert_eq!(dec, pair);
        let r = dec.residual().unwrap();
        assert_eq!(r.delta(0), 4);
        assert_eq!(r.moved(), 1);
    }

    #[test]
    fn pair_with_termination_change_has_no_residual() {
        let earlier = observation("state-a", Some(10), 1);
        let died = observation("state-b", None, 2);
        let pair = RevisionPair {
            tape: ContentId::new(b"tape"),
            earlier,
            later: died,
        };
        assert!(pair.residual().is_none());
        assert_eq!(pair.later.termination, TerminationStatus::Crash);
    }

    #[test]
    fn decoder_rejects_bad_version_and_truncation() {
        let pair = RevisionPair {
            tape: ContentId::new(b"tape"),
            earlier: observation("a", Some(1), 1),
            later: observation("b", Some(2), 2),
        };
        let enc = encode_revision_pair(&pair).unwrap();
        assert!(decode_revision_pair(&enc[..enc.len() - 1]).is_err());
        let mut bad = enc.clone();
        bad[0] = 0xEE;
        assert!(decode_revision_pair(&bad).is_err());
    }

    #[test]
    fn replay_across_states_orders_observations() {
        let tape = RunTape {
            build_digest: [0; 32],
            environment_digest: [0; 32],
            candidate: b"input".to_vec(),
            coordinate: None,
            scheduler_mode: 0,
            observation: None,
            termination: TerminationStatus::Ok,
            lineage: None,
            source: crate::tape::model::TapeSource::Replay,
        };
        let p1 = StateProbe {
            label: "s1".into(),
            artifact: [1; 32],
            environment: [0; 32],
            verify: &mut |_: &[u8]| -> Result<(bool, SignalVector, Vec<u64>)> {
                let mut s = SignalVector::new();
                s.observe(SignalId(0), 3).unwrap();
                Ok((false, s, vec![]))
            },
        };
        let p2 = StateProbe {
            label: "s2".into(),
            artifact: [2; 32],
            environment: [0; 32],
            verify: &mut |_: &[u8]| -> Result<(bool, SignalVector, Vec<u64>)> {
                Ok((true, SignalVector::new(), vec![]))
            },
        };
        let mut probes = [p1, p2];
        let obs = replay_across_states(&tape, &mut probes).unwrap();
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].label, "s1");
        assert_eq!(obs[0].termination, TerminationStatus::Ok);
        assert_eq!(obs[0].signals.as_ref().unwrap().value(SignalId(0)), 3);
        assert_eq!(obs[1].label, "s2");
        assert_eq!(obs[1].termination, TerminationStatus::Crash);
        assert!(obs[1].signals.is_none());
    }

    #[test]
    fn persist_pairs_writes_adjacent_edges_and_verifies() {
        let store_dir =
            std::env::temp_dir().join(format!("frf-fuzz-revision-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&store_dir);
        let store = Store::open(store_dir.clone()).unwrap();
        let tape_id = store.put(Family::RunTape, b"fake-tape-bytes").unwrap();
        let states = vec![
            observation("a", Some(1), 1),
            observation("b", Some(2), 2),
            observation("c", Some(3), 3),
        ];
        let ids = persist_pairs(&store, &tape_id, &states).unwrap();
        assert_eq!(ids.len(), 2);
        let errors = verify_links(&store).unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        // A dangling tape reference is reported.
        let pair = RevisionPair {
            tape: ContentId::new(b"missing-tape"),
            earlier: observation("a", Some(1), 1),
            later: observation("b", Some(2), 2),
        };
        store
            .put(
                Family::RevisionResidual,
                &encode_revision_pair(&pair).unwrap(),
            )
            .unwrap();
        let errors = verify_links(&store).unwrap();
        assert!(
            errors.iter().any(|e| e.contains("tape reference")),
            "{errors:?}"
        );
        let _ = std::fs::remove_dir_all(&store_dir);
    }
}
