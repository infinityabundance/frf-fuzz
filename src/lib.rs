//! frf-fuzz — heterogeneous residual-guided fuzzing engine.
//!
//! Central thesis:
//!
//! ```text
//! Coverage tells us where execution went.
//! Residual structure tells us how behavior is changing.
//! Historical residual trajectories tell us where to interrogate next.
//! FRF determines whether promoted discoveries are evidence.
//! Gemel remembers what those discoveries meant across software evolution.
//! ```
//!
//! This crate is ONE Cargo package serving two planes:
//!
//! * **Exploration plane** — high-throughput coverage + compare + residual
//!   guided fuzzing. Disposable intermediate state, heuristic scheduling,
//!   GPU proposals allowed. This is the `target-runtime` feature.
//! * **Evidence plane** — deliberate, replayable, deterministic, immutable,
//!   FRF-backed when an authority is configured, Gemel-backed when a Gemel
//!   repository is present. This is the `coordinator` feature.
//!
//! The escalation ladder (Level 0 → Level 3) keeps the hot loop fast: only
//! promoted discoveries reach FRF courts, Gemel boundaries, or the full DSFB
//! detector field.
//!
//! # Features
//!
//! * `default = ["coordinator"]` — full coordinator.
//! * `target-runtime` — tiny runtime for instrumented fuzz targets.
//! * `database` — real dsfb-database bridge for database telemetry targets.
//! * `cuda` / `rocm` — reserved GPU backends (Phase 7).
//! * `dangerous-inprocess` — reserved in-process execution opt-in.
//!
//! # Safety policy
//!
//! `unsafe` is forbidden crate-wide except in tightly isolated low-level
//! modules (target-runtime SanitizerCoverage scanning, AVX2 intrinsics, future
//! GPU FFI). Each unsafe block carries a `// SAFETY:` comment stating the exact
//! invariant, and `scripts/unsafe_audit.sh` fails CI when a new unsafe
//! location appears outside the approved modules.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![forbid(ambiguous_glob_reexports)]
// Only the instrumented fuzz-target build (nightly) enables the `sanitize`
// attribute, used to make the measurement runtime ASan-exempt (see
// target_runtime::cmp module docs: an ASan-instrumented comparison callback
// recurses infinitely on LLVM >= 18). The coordinator build never enables
// this feature.

// ---------------------------------------------------------------------------
// Module tree. Ungated modules are shared by both planes and must stay
// dependency-free (or depend only on memmap2). Coordinator-gated modules may
// use blake3 and the optional evidence crates.
// ---------------------------------------------------------------------------

pub mod canon;
pub mod error;
pub mod execute;
pub mod macros;
pub mod mutation;
pub mod scheduler;
pub mod simd;
pub mod target_runtime;

#[cfg(feature = "coordinator")]
pub mod corpus;

#[cfg(feature = "coordinator")]
pub mod id;

#[cfg(feature = "coordinator")]
pub mod observe;

#[cfg(feature = "coordinator")]
pub mod frf_bridge;

#[cfg(feature = "coordinator")]
pub mod gemel_bridge;

#[cfg(feature = "coordinator")]
pub mod dsfb;

#[cfg(feature = "coordinator")]
pub mod precedent;

#[cfg(feature = "coordinator")]
pub mod store;

#[cfg(feature = "coordinator")]
pub mod boundary;

#[cfg(feature = "coordinator")]
pub mod tape;

#[cfg(feature = "coordinator")]
pub mod report;

#[cfg(feature = "coordinator")]
pub mod cli;

/// The pinned nightly toolchain for instrumented fuzz-target builds.
///
/// The coordinator itself compiles on stable Rust >= 1.98 (the declared
/// MSRV); only the instrumented target build requires nightly (LLVM
/// SanitizerCoverage + sanitizer flags). `frf-fuzz doctor` verifies this exact
/// toolchain and its rustc/LLVM identity; campaign metadata records the same
/// identity.
///
/// Pinned in Phase 0 after empirical verification across every installed
/// nightly (LLVM 20.1.1 .. 22.1.2); re-verified on Phase-3 MSRV raise to
/// `nightly-2026-07-24` (rustc 1.99.0-nightly, LLVM 22.1.8 — the same LLVM
/// 22 generation, so the cargo-fuzz-derived flag set
/// (`-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4
/// -Cllvm-args=-sanitizer-coverage-inline-8bit-counters
/// -Cllvm-args=-sanitizer-coverage-pc-table
/// -Cllvm-args=-sanitizer-coverage-trace-compares -Zsanitizer=address`) was
/// proven end-to-end. The coordinator MSRV was raised to 1.98 (the current
/// stable) by explicit decision during Phase 3, so the pinned nightly (rustc
/// 1.99.0-nightly) now also satisfies the crate's `rust-version`. See
/// docs/COMPATIBILITY.md.
pub const DEFAULT_PINNED_NIGHTLY: &str = "nightly-2026-07-24";

/// The exact rustc identity of [`DEFAULT_PINNED_NIGHTLY`] at pin time
/// (`rustc -vV`), so a mismatched nightly can be detected instead of silently
/// used.
pub const PINNED_NIGHTLY_RUSTC: &str = "rustc 1.99.0-nightly (89c61a754 2026-07-23)";
/// The exact LLVM identity of [`DEFAULT_PINNED_NIGHTLY`].
pub const PINNED_NIGHTLY_LLVM: &str = "LLVM version: 22.1.8";
/// The exact rustc commit hash of [`DEFAULT_PINNED_NIGHTLY`].
pub const PINNED_NIGHTLY_COMMIT: &str = "89c61a7545da48b06116675b888398d02a4064c7";

/// The minimum supported Rust version for the coordinator build.
///
/// Raised from 1.85 to 1.98 (the current stable) by explicit user decision
/// during Phase 3: the coordinator and target-runtime are written against the
/// current stable toolchain, not an artificial older floor. The instrumented
/// fuzz-target build remains pinned to [`DEFAULT_PINNED_NIGHTLY`] — that is a
/// separate, recorded toolchain identity, never "whatever nightly is
/// installed" (docs/COMPATIBILITY.md).
pub const MSRV: &str = "1.98";
