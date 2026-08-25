//! Execution plane: coordinator/worker protocol and crash ledger.
//!
//! The exploration plane never sends one candidate per execution over IPC.
//! The coordinator dispatches WORK ORDERS (parent input + mutation coordinate
//! ranges + energy + probe recipe), and the worker executes hundreds or
//! thousands of local deterministic mutations before returning. This module
//! provides the bounded versioned binary framing ([`protocol`]) and the
//! per-worker shared crash ledger ([`crash_ledger`]) that lets the
//! coordinator reconstruct an exact crashing candidate after a worker dies —
//! with no per-execution IPC round-trip.

pub mod crash_ledger;
pub mod protocol;

#[cfg(feature = "coordinator")]
pub mod coordinator;
#[cfg(feature = "coordinator")]
pub mod finding;
#[cfg(feature = "coordinator")]
pub mod worker_process;
