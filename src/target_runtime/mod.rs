//! Target-side runtime: the measurement core that lives in the instrumented
//! fuzz target binary.
//!
//! This is the `target-runtime` plane. It must stay tiny and dependency-free
//! (only `memmap2` is shared with the coordinator, for the crash ledger). The
//! coordinator dependency tree is never compiled into the instrumented target
//! (docs/INVARIANTS.md, I15).
//!
//! The runtime provides:
//!
//! * [`sancov`] — SanitizerCoverage callback registration, comparison
//!   callbacks, and the scan/clear measurement core with the calibration
//!   footprint invariant.
//! * [`cmp`] — the bounded, allocation-free compare-event ring.
//! * [`signals`] — the pre-registered semantic signal vector and
//!   [`FuzzContext`], the surface exposed to fuzz targets.
//!
//! # Instrumentation findings (Phase 0, verified empirically)
//!
//! LLVM >= 18 removed the `__sanitizer_` name-prefix exclusion from
//! SanitizerCoverage.cpp (present in 16/17); the only remaining exclusion is
//! the `NoSanitizeCoverage` function attribute, which rustc cannot emit.
//! Therefore the runtime's own edges ARE instrumented in an instrumented
//! build. Their self-contamination is a **deterministic constant footprint**
//! (same edges every execution), which the worker measures once during
//! campaign calibration and permanently masks. See
//! [`sancov::footprint_calibrate`] and docs/COMPATIBILITY.md.

pub mod cmp;
pub mod fixture;
pub mod sancov;
pub mod signals;
pub mod target;
pub mod worker;

pub use signals::{FuzzContext, SignalId};
