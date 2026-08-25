//! Build script for frf-fuzz.
//!
//! Detects the instrumented fuzz-target build (set by `cargo frf-fuzz build`
//! / the nightly spike via the `FRF_TARGET_BUILD` environment variable) and
//! emits `cargo:rustc-cfg=frf_target_build`.
//!
//! Why: on LLVM >= 18 there is no compile-time way to exclude the measurement
//! runtime from SanitizerCoverage, and an ASan-instrumented comparison
//! callback recurses infinitely (its own ASan shadow checks and comparisons
//! are themselves cmp-instrumented; see `target_runtime::cmp` module docs).
//! The runtime therefore needs the nightly-only `#[sanitize(address = "off")]`
//! attribute — which requires `#![feature(sanitize)]`. The coordinator build
//! must stay stable-1.85-clean, so the feature gate and the attribute are both
//! gated on `frf_target_build`, which only the instrumented target build sets.

fn main() {
    // Reserved: the instrumented fuzz-target build may later need a per-crate
    // cfg (e.g. if rustc ever wires `sanitize(address="off")` into LLVM
    // attributes). Today it does not, so nothing is emitted.
}
