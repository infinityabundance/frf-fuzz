//! DSFB-inspired structural interpretation (coordinator feature).
//!
//! This module applies the architectural lessons of DSFB-Debug and
//! DSFB-Database to generic fuzz observations. It does NOT reuse their
//! ontology:
//!
//! * `regime` — the DSFB-Database lesson: instantaneous residual + smoothed
//!   residual + `Stable → Drift → InEpisode → Recovering` + dwell +
//!   deterministic episode close. Semantics are documented independently of
//!   SQL telemetry and generic fuzz residuals are never coerced into a SQL
//!   `ResidualClass` (I7 — enforced in types; see `database_bridge` below).
//! * `morphology` — inspectable, deterministic morphology signatures with a
//!   `Trivial` / `StructuredUnknown` classifier. The `Unknown` discipline is
//!   DSFB's: a structurally non-trivial observation that matches no named
//!   class REMAINS `Unknown`; it is never force-labelled (I6).
//! * `debug_bridge` (Phase 3) — the real dsfb-debug substrate: the DSFB
//!   envelope grammar is driven by the crate's public free functions over a
//!   per-root behavioral stream, with frf-fuzz's own declared calibration
//!   law. Only `SemanticDisposition::Unknown` is ever passed to the policy
//!   engine; DSFB production motifs are never used to label fuzz behavior.
//! * `fuzz_bank` (Phase 3) — the FuzzSemanticBank: 13 fuzz-specific
//!   structural classes with gates, refusals, confusers, deterministic
//!   integer scoring, and the Structured+Unknown discipline as a first-class
//!   result.
//! * `database_bridge` (Phase 6, feature `database`) — the ONE place the
//!   real `dsfb-database` crate meets frf-fuzz code, for actual SQL-
//!   telemetry surfaces only. Declared SQL-telemetry rows are pushed through
//!   the crate's own SQL-semantics constructors and interpreted by its real
//!   `MotifEngine`; generic fuzz residuals can never name a SQL class (I7,
//!   enforced in types + a source-level lock test).

pub mod debug_bridge;
pub mod fuzz_bank;
pub mod morphology;
pub mod regime;

#[cfg(feature = "database")]
pub mod database_bridge;

pub use debug_bridge::{
    AxisVerdict, BridgeConfig, DriftDir, EdgeStructural, LineageSubstrate, StructuralEpisode,
};
pub use fuzz_bank::{
    AxisRole, BankEvidence, BankVerdict, FuzzMotif, FuzzMotifDef, MotifProvenance,
};
pub use morphology::{
    classify, LineageAccumulator, MorphologySignature, StructuralClass, Triviality,
};
pub use regime::{EpisodeClose, RegimeConfig, RegimeEpisode, RegimeObserver, RegimeState};

#[cfg(feature = "database")]
pub use database_bridge::{analyze, build_stream, DbAnalysis, DbEpisodeView, TelemetryRow};
