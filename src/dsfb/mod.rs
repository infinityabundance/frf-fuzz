//! DSFB-inspired structural interpretation (coordinator feature).
//!
//! This module takes the *architectural lessons* of DSFB-Debug and
//! DSFB-Database and applies them to generic fuzz observations. It does NOT
//! reuse their ontology:
//!
//! * `regime` — the DSFB-Database lesson: instantaneous residual + smoothed
//!   residual + `Stable → Drift → InEpisode → Recovering` + dwell +
//!   deterministic episode close. Semantics are documented independently of
//!   SQL telemetry and generic fuzz residuals are never coerced into a SQL
//!   `ResidualClass` (I7 — enforced in types; the `database` feature bridge
//!   is Phase 6).
//! * `morphology` — inspectable, deterministic morphology signatures with a
//!   `Trivial` / `StructuredUnknown` classifier. The `Unknown` discipline is
//!   DSFB's: a structurally non-trivial observation that matches no named
//!   class REMAINS `Unknown`; it is never force-labelled (I6). Phase 2 has
//!   no named fuzz motifs yet — the FuzzSemanticBank is Phase 3 — so every
//!   non-trivial morphology is `StructuredUnknown` by construction.
//!
//! Phase 3 adds `debug_bridge` (real dsfb-debug substrate) and `fuzz_bank`;
//! Phase 6 adds `database_bridge`. They are NOT stubbed here
//! (docs/ROADMAP.md).

pub mod debug_bridge;
pub mod fuzz_bank;
pub mod morphology;
pub mod regime;

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
