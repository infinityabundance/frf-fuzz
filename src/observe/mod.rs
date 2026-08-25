//! Coordinator-side observation interpretation: [`ExecutionObservation`],
//! the residual families, signal-schema store objects, sketch aggregation,
//! and the lineage accumulator.
//!
//! The worker computes the cheap Level-0 sketch and signal vector; this
//! module turns those into the structural Level-1/2 objects the scheduler
//! and regime/morphology machinery consume. Everything here is deterministic
//! integer arithmetic over fixed-size fields (docs/ARCHITECTURE.md §11-12,
//! §16).
//!
//! This module is coordinator-gated.

pub mod frame;
pub mod residual;
pub mod signals;
pub mod sketch;

pub use frame::ExecutionObservation;
pub use residual::{MutationResidual, TemporalResidual};
pub use signals::{decode_signal_schema, encode_signal_schema};
