//! Counterfactual boundary witnesses (master prompt §23).
//!
//! Passing/failing — or regime-A/regime-B — pairs are first-class objects.
//! When two nearby inputs straddle a meaningful behavioral boundary, both
//! are retained as a [`BoundaryWitness`], and deterministic two-sided
//! minimization shrinks the distance between them while preserving their
//! behavioral distinction.
//!
//! This module is coordinator-gated.

pub mod minimize;
pub mod witness;

pub use minimize::{byte_distance, minimize_pair};
pub use witness::{
    decode_witness, encode_witness, BoundaryRelation, BoundarySide, BoundaryWitness,
    WitnessVerification, WITNESS_VERSION,
};
