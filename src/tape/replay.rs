//! Tape replay: re-execute a tape's candidate and compare the live
//! observation against the recorded one.
//!
//! The structural interpretation of a tape is a pure function of its
//! recorded fields (I12 holds by construction). Replay checks the *live*
//! side of the contract: does a fresh execution reproduce the recorded
//! observation? A divergence is preserved as instability (I10) — it is
//! never resolved by overwriting the tape.

use crate::error::Result;
use crate::id::ContentId;
use crate::store::Store;
use crate::tape::model::{RunTape, TapeObservation};
use crate::target_runtime::signals::{SignalId, SignalVector, MAX_SIGNALS};

/// The result of re-executing a tape's candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapeReplayOutcome {
    /// The live execution reproduced the recorded observation exactly
    /// (signals + features + termination).
    Matches,
    /// The candidate terminated as the tape recorded (crash reproduced),
    /// but the observation could not be compared (the tape has none).
    TerminationReproduced,
    /// The live execution diverged from the recorded observation (or the
    /// tape's termination was not reproduced). Both are preserved.
    Diverged {
        /// Why: the process survived a crash tape, died an ok tape, or the
        /// signals/features differed.
        reason: String,
    },
}

/// Execute a tape's candidate through `verify` and compare.
///
/// `verify` runs the candidate and returns `(died, signals, features)`:
/// whether the process died, and the observed signals/features when it
/// survived.
#[allow(clippy::type_complexity)]
pub fn replay_tape(
    store: &Store,
    tape_id: &ContentId,
    verify: &mut dyn FnMut(&[u8]) -> Result<(bool, SignalVector, Vec<u64>)>,
) -> Result<TapeReplayOutcome> {
    let payload = store
        .get(tape_id)?
        .ok_or_else(|| crate::error::Error::Other(format!("no tape {tape_id}")))?;
    let tape = crate::tape::model::decode_tape(&payload)?;
    replay_tape_payload(&tape, verify)
}

/// Replay against an already-decoded tape (testable without a store).
#[allow(clippy::type_complexity)]
pub fn replay_tape_payload(
    tape: &RunTape,
    verify: &mut dyn FnMut(&[u8]) -> Result<(bool, SignalVector, Vec<u64>)>,
) -> Result<TapeReplayOutcome> {
    let (died, live_signals, live_features) = verify(&tape.candidate)?;
    match tape.termination {
        crate::tape::model::TerminationStatus::Crash
        | crate::tape::model::TerminationStatus::Timeout => {
            if died {
                Ok(TapeReplayOutcome::TerminationReproduced)
            } else {
                Ok(TapeReplayOutcome::Diverged {
                    reason: "the candidate survived although the tape records a termination".into(),
                })
            }
        }
        crate::tape::model::TerminationStatus::Ok => {
            if died {
                return Ok(TapeReplayOutcome::Diverged {
                    reason: "the candidate died although the tape records Ok".into(),
                });
            }
            let recorded = match &tape.observation {
                Some(o) => o,
                None => return Ok(TapeReplayOutcome::Matches),
            };
            compare_observation(recorded, &live_signals, &live_features)
        }
    }
}

fn compare_observation(
    recorded: &TapeObservation,
    live_signals: &SignalVector,
    live_features: &[u64],
) -> Result<TapeReplayOutcome> {
    // Features must match exactly (sorted/deduped on both sides).
    let mut lf = live_features.to_vec();
    lf.sort_unstable();
    lf.dedup();
    if lf != recorded.features {
        return Ok(TapeReplayOutcome::Diverged {
            reason: format!(
                "features differ: tape {} vs live {}",
                recorded.features.len(),
                lf.len()
            ),
        });
    }
    // Signals must match on every axis (including the touched set: an axis
    // the tape recorded as touched must be touched live, and an axis the
    // tape recorded as absent must be absent live).
    for i in 0..MAX_SIGNALS {
        let id = SignalId(i as u16);
        let rt = recorded.signals.was_touched(id);
        let lt = live_signals.was_touched(id);
        if rt != lt {
            return Ok(TapeReplayOutcome::Diverged {
                reason: format!("signal {i} touched-set differs: tape {rt} vs live {lt}"),
            });
        }
        if rt && recorded.signals.value(id) != live_signals.value(id) {
            return Ok(TapeReplayOutcome::Diverged {
                reason: format!(
                    "signal {i} value differs: tape {} vs live {}",
                    recorded.signals.value(id),
                    live_signals.value(id)
                ),
            });
        }
    }
    Ok(TapeReplayOutcome::Matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tape::model::{TapeObservation, TerminationStatus};

    fn ok_tape(signal_value: u64) -> RunTape {
        let mut signals = SignalVector::new();
        signals.observe(SignalId(0), signal_value).unwrap();
        RunTape {
            build_digest: [0; 32],
            environment_digest: [0; 32],
            candidate: b"abc".to_vec(),
            coordinate: None,
            scheduler_mode: 0,
            observation: Some(TapeObservation {
                features: vec![1, 2],
                signals: signals.clone(),
                sketch: crate::target_runtime::signals::ResidualSketch::of(
                    &SignalVector::new(),
                    &signals,
                ),
                cmp_events: vec![],
                time_bucket: 0,
            }),
            termination: TerminationStatus::Ok,
            lineage: None,
            source: crate::tape::model::TapeSource::Admission,
        }
    }

    #[test]
    fn matching_observation_returns_matches() {
        let tape = ok_tape(7);
        let mut verify = |_: &[u8]| -> Result<(bool, SignalVector, Vec<u64>)> {
            let mut s = SignalVector::new();
            s.observe(SignalId(0), 7).unwrap();
            Ok((false, s, vec![2, 1]))
        };
        let outcome = replay_tape_payload(&tape, &mut verify).unwrap();
        assert_eq!(outcome, TapeReplayOutcome::Matches);
    }

    #[test]
    fn differing_signal_diverges_and_is_preserved() {
        let tape = ok_tape(7);
        let mut verify = |_: &[u8]| -> Result<(bool, SignalVector, Vec<u64>)> {
            let mut s = SignalVector::new();
            s.observe(SignalId(0), 9).unwrap();
            Ok((false, s, vec![1, 2]))
        };
        let outcome = replay_tape_payload(&tape, &mut verify).unwrap();
        assert!(matches!(outcome, TapeReplayOutcome::Diverged { .. }));
    }

    #[test]
    fn touched_set_divergence_is_caught() {
        let tape = ok_tape(7);
        let mut verify = |_: &[u8]| -> Result<(bool, SignalVector, Vec<u64>)> {
            Ok((false, SignalVector::new(), vec![1, 2])) // nothing touched live
        };
        let outcome = replay_tape_payload(&tape, &mut verify).unwrap();
        assert!(matches!(outcome, TapeReplayOutcome::Diverged { .. }));
    }

    #[test]
    fn crash_tape_checks_termination() {
        let mut tape = ok_tape(0);
        tape.termination = TerminationStatus::Crash;
        tape.observation = None;
        let mut died = |_: &[u8]| -> Result<(bool, SignalVector, Vec<u64>)> {
            Ok((true, SignalVector::new(), vec![]))
        };
        assert_eq!(
            replay_tape_payload(&tape, &mut died).unwrap(),
            TapeReplayOutcome::TerminationReproduced
        );
        let mut survived = |_: &[u8]| -> Result<(bool, SignalVector, Vec<u64>)> {
            Ok((false, SignalVector::new(), vec![]))
        };
        assert!(matches!(
            replay_tape_payload(&tape, &mut survived).unwrap(),
            TapeReplayOutcome::Diverged { .. }
        ));
    }
}
