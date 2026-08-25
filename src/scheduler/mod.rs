//! Scheduling: how the coordinator chooses experiments.
//!
//! The [`WorkOrder`] wire encoding is ungated (the worker decodes it);
//! the policy that *builds* orders is coordinator-gated ([`policy`]).
//! Phase 1 ships a single EXPLORE queue (coverage + cmp guidance) with
//! deterministic mutation-family rotation and corpus selection; the
//! AMPLIFY / DISCRIMINATE / FALSIFY classes arrive in Phases 2-3
//! (docs/ARCHITECTURE.md §13).

pub mod work_order;

#[cfg(feature = "coordinator")]
pub mod policy;

pub use work_order::{
    decode_discovery, decode_hello, decode_work_order, decode_work_result, encode_discovery,
    encode_hello, encode_work_order, encode_work_result, CmpEventWire, DiscoveryRecord,
    ExecutionStatus, Hello, WorkOrder, WorkResult,
};
