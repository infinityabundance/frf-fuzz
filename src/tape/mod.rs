//! Deterministic run tapes (master prompt §20).
//!
//! Live execution is not necessarily deterministic; a tape makes an
//! observation deterministic by persisting its coordinate: target build
//! identity, the exact candidate (or its reconstructible coordinate), the
//! scheduler mode, the environment digest, the signal schema, the recorded
//! observation, and the termination status.
//!
//! A tape is immutable and content-addressed. The deterministic contract
//! (I12): *same valid tape → same frf-fuzz structural interpretation* —
//! the structural interpretation (morphology/regime classification) is a
//! pure function of the recorded fields, so it is identical by
//! construction; replay additionally checks that a live re-execution
//! reproduces the recorded observation, and a divergence is PRESERVED as
//! instability (I10) rather than resolved.
//!
//! Phase 2 writes tapes at durable boundaries only (seeds, findings,
//! residual admissions, boundary witnesses) — never per ordinary execution
//! (I1). Phase 4 replays identical tapes across Gemel revision states to
//! form revision residuals.
//!
//! This module is coordinator-gated.

pub mod model;
pub mod replay;

pub use model::{
    build_digest, decode_tape, encode_tape, environment_digest, RunTape, TapeObservation,
    TapeSource, TerminationStatus, TAPE_VERSION,
};
pub use replay::{replay_tape, TapeReplayOutcome};
