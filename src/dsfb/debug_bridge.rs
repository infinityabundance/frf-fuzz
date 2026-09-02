//! Real DSFB-Debug structural substrate (master prompt §13; Phase 3).
//!
//! This module is the frf-fuzz bridge to the *domain-independent machinery*
//! of `dsfb-debug 0.1.0` — residual norm, sign tuple, drift persistence,
//! grammar, hysteresis, DSA consistency gate, and policy — implemented by
//! calling the crate's public free functions
//! (`dsfb_debug::sign`, `dsfb_debug::grammar`, `dsfb_debug::dsa`,
//! `dsfb_debug::policy`).
//!
//! It deliberately does NOT touch `dsfb_debug`'s motif machinery
//! (`HeuristicsBank` / `MotifClass` / `SemanticDisposition::Named`):
//! those names are production-debugging motifs and reusing them to label
//! fuzz behavior would be semantically dishonest (docs/DESIGN-DSFB.md §9,
//! invariant I6). The only disposition this bridge ever passes to the
//! policy engine is [`dsfb_debug::types::SemanticDisposition::Unknown`] —
//! DSFB's "endoductive" path — so `Review` means exactly "structure present
//! "structure present but unnamed" and naming is deferred to frf-fuzz's own
//! FuzzSemanticBank (`crate::dsfb::fuzz_bank`, the next Phase-3 module).
//!
//! # What the bridge interprets
//!
//! A per-(root, mutator) *lineage* emits, at each admitted edge, the child
//! observation of every signal axis that moved. Each axis gets an *axis
//! event stream*: the sequence of values it exhibited when it moved, in
//! admission order. This is the same sample stream the Phase-2
//! [`crate::dsfb::regime::RegimeObserver`] consumes, so both interpreters
//! see identical evidence and both replay deterministically from the durable
//! corpus (`CorpusMeta` signals, admission order).
//!
//! # The declared calibration law (documented, deterministic)
//!
//! DSFB's grammar compares a residual norm `‖r‖ = |value − mean|` against an
//! envelope radius ρ. In telemetry, ρ is 3σ of a *healthy* window. A fuzz
//! lineage has no external "healthy" window, so frf-fuzz declares one:
//!
//! 1. The first `calibration_windows` windows of an axis stream form its
//!    calibration segment (the lineage's own observed behavior near the
//!    nominal). If the segment is perfectly flat (span == 0), collection
//!    extends to `calibration_windows × 2` in search of the axis's first
//!    movement.
//! 2. `mean` = arithmetic mean of the segment; `σ` = Bessel-corrected
//!    sample standard deviation (0 when fewer than 2 samples).
//! 3. ρ = max(3σ, 2·span) where `span` = max − min of the segment. The
//!    span term is deliberate: DSFB's Boundary zone opens at `0.5·ρ`, so
//!    requiring `2·span` means *grazing only begins outside the span the
//!    lineage has already exhibited*. Values inside the observed span can
//!    never be misread as structural (the primary negative-control risk,
//!    master prompt §32).
//! 4. If ρ == 0 (the axis stayed exactly constant through the extended
//!    segment) the axis is treated as a *discrete/step axis*: envelope
//!    grammar is unavailable (`calibrated = false`), verdicts stay Silent,
//!    and the axis is interpreted by frf-fuzz's own discrete state-change
//!    classes instead. This keeps DSFB from hallucinating envelope
//!    violations on axes whose natural behavior is a step change.
//!
//! After calibration, every subsequent window is evaluated through the real
//! DSFB chain: norm → [`sign::compute_sign_tuple`] → drift persistence →
//! [`grammar::evaluate_raw_grammar`] → hysteresis confirmation →
//! DSA consistency gate → [`policy::apply_policy`] with the caller-side
//! persistence counter maintained exactly as `dsfb_debug`'s own
//! `run_evaluation` maintains it (consecutive confirmed-Boundary windows,
//! reset on a non-Boundary window).
//!
//! # Integer canonical identity
//!
//! DSFB's canonical values are f64; frf-fuzz's canonical identity is
//! integer-only (docs/ARCHITECTURE.md §16). The bridge therefore reduces
//! every evaluation to the *enum* outputs (`GrammarState`, `ReasonCode`,
//! `PolicyState`) and integer classes (direction class, deviation magnitude
//! bucket). No f64 enters a canonical payload.
//!
//! # Escalation-ladder placement
//!
//! The cheap structural pass runs per *admitted* execution (Level 1), never
//! per ordinary execution. Verdict objects are persisted only when the edge
//! produced structural activity (any axis policy ≥ Watch or a bank
//! nomination); episodes persist on deterministic close. Everything the
//! bridge computes for a rejected execution is nothing — rejected
//! executions never reach this module (I1).
//!
//! This module is coordinator-gated (its dependency `dsfb-debug` is enabled
//! by the `coordinator` feature).

use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::observe::residual::MutationResidual;
use crate::target_runtime::signals::{magnitude_bucket, SignalId, MAX_SIGNALS};
use dsfb_debug::config::EngineConfig;
use dsfb_debug::dsa;
use dsfb_debug::grammar;
use dsfb_debug::policy;
use dsfb_debug::sign;
use dsfb_debug::types::{GrammarState, PolicyState, ReasonCode, SemanticDisposition};

/// Version of the structural-verdict payload encoding.
pub const STRUCTURAL_VERDICT_VERSION: u8 = 1;
/// Version of the structural-episode payload encoding.
pub const STRUCTURAL_EPISODE_VERSION: u8 = 1;
/// Maximum verdict records in one durable verdict object.
pub const MAX_VERDICTS_PER_OBJECT: usize = 64;

/// Maximum norm-history length kept per axis (mirrors `dsfb-debug`'s own
/// `NORM_HIST` rolling buffer of 32; enough for any paper-lock
/// `drift_window`).
pub const MAX_NORM_HIST: usize = 32;

/// The bridge configuration. Defaults reproduce the DSFB paper-lock
/// `EngineConfig` where the crate has a paper-lock value (drift window,
/// persistence threshold, hysteresis, boundary fraction, slew delta,
/// consistency gate); the calibration law is frf-fuzz's own declared law
/// above.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BridgeConfig {
    /// Windows of the per-axis calibration segment (default 8).
    pub calibration_windows: usize,
    /// Envelope-law multiplier on the calibration span (default 2).
    pub span_envelope_multiplier: f64,
    /// DSFB drift window W (paper lock: 5).
    pub drift_window: usize,
    /// DSFB persistence threshold K (paper lock: 4).
    pub persistence_threshold: usize,
    /// DSFB hysteresis confirmation count (paper lock: 2).
    pub hysteresis_confirm: usize,
    /// DSFB boundary fraction (paper lock: 0.5).
    pub boundary_fraction: f64,
    /// DSFB slew delta (paper lock: 0.1).
    pub slew_delta: f64,
    /// DSFB DSA consistency gate τ (paper lock: 2.0).
    pub consistency_gate: f64,
}

impl BridgeConfig {
    /// The default bridge configuration.
    pub const fn default_config() -> BridgeConfig {
        BridgeConfig {
            calibration_windows: 8,
            span_envelope_multiplier: 2.0,
            drift_window: 5,
            persistence_threshold: 4,
            hysteresis_confirm: 2,
            boundary_fraction: 0.5,
            slew_delta: 0.1,
            consistency_gate: 2.0,
        }
    }

    /// Build the DSFB `EngineConfig` this bridge drives. The bridge owns a
    /// single validated instance per lineage substrate.
    pub fn engine_config(&self) -> Result<EngineConfig> {
        let cfg = EngineConfig {
            drift_window: self.drift_window,
            persistence_threshold: self.persistence_threshold,
            hysteresis_confirm: self.hysteresis_confirm,
            boundary_fraction: self.boundary_fraction,
            slew_delta: self.slew_delta,
            consistency_gate: self.consistency_gate,
            ..EngineConfig::default()
        };
        cfg.validate()
            .map_err(|e| Error::Other(format!("dsfb-debug bridge config refused: {e}")))?;
        Ok(cfg)
    }
}

impl Default for BridgeConfig {
    fn default() -> BridgeConfig {
        BridgeConfig::default_config()
    }
}

/// Drift direction class of one axis at one window (integer; part of
/// canonical identity). The quantization law: the DSFB drift is the finite
/// difference of consecutive residual norms; a drift magnitude at or below
/// `slew_delta` is `None`; otherwise the sign of the drift. `Oscillatory`
/// means the drift sign flipped against the previous evaluated window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DriftDir {
    /// No measurable drift (|drift| ≤ slew_delta or no prior window).
    None = 0,
    /// Outward: the residual norm grew (value moved away from the nominal).
    Outward = 1,
    /// Inward: the residual norm shrank (value moved back toward the nominal).
    Inward = 2,
    /// The drift sign flipped vs the previous window.
    Oscillatory = 3,
}

impl DriftDir {
    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            DriftDir::None => "none",
            DriftDir::Outward => "outward",
            DriftDir::Inward => "inward",
            DriftDir::Oscillatory => "oscillatory",
        }
    }
}

/// The integer-reduced structural verdict of ONE axis at ONE lineage edge
/// (the canonical form of a DSFB signal evaluation; no floats).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxisVerdict {
    /// The signal axis.
    pub axis: u16,
    /// `dsfb_debug::types::GrammarState` discriminant (0..=2).
    pub grammar: u8,
    /// Confirmed grammar state after hysteresis (0..=2).
    pub confirmed: u8,
    /// `dsfb_debug::types::ReasonCode` discriminant (0..=7).
    pub reason: u8,
    /// `dsfb_debug::types::PolicyState` discriminant (0..=3).
    pub policy: u8,
    /// Drift direction class.
    pub dir: u8,
    /// Whether an envelope was calibrated for this axis (false = discrete
    /// axis; grammar fields are then all zero/Silent by construction).
    pub calibrated: bool,
    /// Magnitude bucket of |value − mean| (the deviation magnitude).
    pub dev_mag_bin: u8,
    /// Consecutive confirmed-Boundary-or-higher windows counted so far.
    pub persistence: u8,
}

impl AxisVerdict {
    /// A zero verdict (used for uncalibrated/discrete axes and as the
    /// nominal baseline of an axis before its first post-calibration
    /// movement).
    pub const fn silent(axis: u16, calibrated: bool) -> AxisVerdict {
        AxisVerdict {
            axis,
            grammar: GrammarState::Admissible as u8,
            confirmed: GrammarState::Admissible as u8,
            reason: ReasonCode::Admissible as u8,
            policy: PolicyState::Silent as u8,
            dir: DriftDir::None.code(),
            calibrated,
            dev_mag_bin: 0,
            persistence: 0,
        }
    }

    /// Whether the verdict shows structural activity at or above the DSFB
    /// `Watch` level.
    pub fn is_active(&self) -> bool {
        self.policy >= PolicyState::Watch as u8
    }
}

/// One lineage edge's structural result: the moved axes' verdicts plus the
/// per-lineage episode transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeStructural {
    /// Per-axis verdicts for the axes that moved on this edge (empty for a
    /// fully trivial edge).
    pub verdicts: Vec<AxisVerdict>,
    /// Whether the verdict set triggered the frf-fuzz bank (the caller runs
    /// the bank; this carries the edge summary it needs).
    pub any_active: bool,
}

impl EdgeStructural {
    /// The maximum policy level among the edge's verdicts.
    pub fn max_policy(&self) -> u8 {
        self.verdicts
            .iter()
            .map(|v| v.policy)
            .max()
            .unwrap_or(PolicyState::Silent as u8)
    }

    /// Bitmask of axes with any structural activity (policy ≥ Watch).
    pub fn active_axes(&self) -> u64 {
        let mut m = 0u64;
        for v in &self.verdicts {
            if v.is_active() {
                m |= 1u64 << v.axis;
            }
        }
        m
    }
}

/// The reason codes that appeared on the axes of a lineage during one
/// closed structural episode (bitset over the 0..=7 reason discriminants).
pub type ReasonBits = u8;

/// A closed DSFB-flavored structural episode (Phase 3 "structural
/// episodes"): the lineage segment during which at least one axis
/// sustained policy ≥ Review, closed when all axes stayed below Review for
/// `correlation_window` consecutive lineage edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralEpisode {
    /// The lineage root entry (full content id).
    pub root: ContentId,
    /// The lineage mutator family id.
    pub mutator: u16,
    /// First lineage ordinal (admission edge) at which any axis reached
    /// policy ≥ Review.
    pub t_open: u64,
    /// Last lineage ordinal of the episode (the edge that completed the
    /// quiet-run close).
    pub t_close: u64,
    /// Ordinal of the peak (highest-policy) edge.
    pub peak_ordinal: u64,
    /// Peak policy level observed (3 = Escalate).
    pub peak_policy: u8,
    /// Bitmask of axes that reached policy ≥ Review during the episode.
    pub axes: u64,
    /// Reason codes seen on episode axes (bitset).
    pub reasons: ReasonBits,
    /// Number of lineage edges inside the episode (t_close − t_open + 1).
    pub dwell: u64,
    /// The frf-fuzz bank nomination for the episode if the bank named one
    /// (0 = none / structured-Unknown). Set by the caller from the bank.
    pub class: u8,
    /// Lineage depth at t_open (for provenance).
    pub open_generation: u32,
}

/// Canonical payload of a [`StructuralEpisode`].
pub fn encode_episode_payload(ep: &StructuralEpisode) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 32 + 2 + 8 * 5 + 1 + 8 + 1 + 8 + 1 + 4);
    out.push(STRUCTURAL_EPISODE_VERSION);
    out.extend_from_slice(ep.root.as_bytes());
    out.extend_from_slice(&ep.mutator.to_le_bytes());
    out.extend_from_slice(&ep.t_open.to_le_bytes());
    out.extend_from_slice(&ep.t_close.to_le_bytes());
    out.extend_from_slice(&ep.peak_ordinal.to_le_bytes());
    out.push(ep.peak_policy);
    out.extend_from_slice(&ep.axes.to_le_bytes());
    out.push(ep.reasons);
    out.extend_from_slice(&ep.dwell.to_le_bytes());
    out.push(ep.class);
    out.extend_from_slice(&ep.open_generation.to_le_bytes());
    Ok(out)
}

/// Decode a [`StructuralEpisode`] payload.
pub fn decode_episode_payload(bytes: &[u8]) -> Result<StructuralEpisode> {
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > bytes.len() {
            return Err(Error::Encoding("structural-episode truncated"));
        }
        let out = &bytes[pos..end];
        pos = end;
        Ok(out)
    };
    let version = take(1)?[0];
    if version != STRUCTURAL_EPISODE_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "structural-episode",
            version: version as u32,
        });
    }
    let root = ContentId::from_array(take(32)?.try_into().unwrap());
    let mutator = u16::from_le_bytes(take(2)?.try_into().unwrap());
    let t_open = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let t_close = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let peak_ordinal = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let peak_policy = take(1)?[0];
    if peak_policy > PolicyState::Escalate as u8 {
        return Err(Error::Encoding(
            "structural-episode peak policy out of range",
        ));
    }
    let axes = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let reasons = take(1)?[0];
    let dwell = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let class = take(1)?[0];
    let open_generation = u32::from_le_bytes(take(4)?.try_into().unwrap());
    if pos != bytes.len() {
        return Err(Error::Encoding("structural-episode has trailing bytes"));
    }
    Ok(StructuralEpisode {
        root,
        mutator,
        t_open,
        t_close,
        peak_ordinal,
        peak_policy,
        axes,
        reasons,
        dwell,
        class,
        open_generation,
    })
}

/// A durable per-edge structural reading (one `Family::StructuralVerdict`
/// object): the lineage edge's integer-reduced verdicts plus its bank
/// nomination. Written only when the edge produced structural activity
/// (any axis policy ≥ Watch or a bank nomination).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableVerdict {
    /// The lineage root entry.
    pub root: ContentId,
    /// The lineage mutator family.
    pub mutator: u16,
    /// The lineage depth (generation) of this edge.
    pub depth: u32,
    /// Per-axis verdicts of the moved axes.
    pub axes: Vec<AxisVerdict>,
    /// The bank nomination class (0 = none / structured-Unknown).
    pub class: u8,
    /// The structural identity of the edge's morphology signature.
    pub morph_identity: u64,
}

/// Encode a durable verdict payload.
pub fn encode_verdict_payload(v: &DurableVerdict) -> Result<Vec<u8>> {
    if v.axes.len() > MAX_VERDICTS_PER_OBJECT {
        return Err(Error::BoundExceeded {
            what: "verdict axes",
            limit: MAX_VERDICTS_PER_OBJECT as u64,
            got: v.axes.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(1 + 32 + 2 + 4 + 1 + 1 + 8 + 64 * 11);
    out.push(STRUCTURAL_VERDICT_VERSION);
    out.extend_from_slice(v.root.as_bytes());
    out.extend_from_slice(&v.mutator.to_le_bytes());
    out.extend_from_slice(&v.depth.to_le_bytes());
    out.push(v.class);
    out.extend_from_slice(&v.morph_identity.to_le_bytes());
    out.push(v.axes.len() as u8);
    for a in &v.axes {
        out.extend_from_slice(&a.axis.to_le_bytes());
        out.push(a.grammar);
        out.push(a.confirmed);
        out.push(a.reason);
        out.push(a.policy);
        out.push(a.dir);
        out.push(u8::from(a.calibrated));
        out.push(a.dev_mag_bin);
        out.push(a.persistence);
    }
    Ok(out)
}

/// Decode a durable verdict payload.
pub fn decode_verdict_payload(bytes: &[u8]) -> Result<DurableVerdict> {
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > bytes.len() {
            return Err(Error::Encoding("structural-verdict truncated"));
        }
        let out = &bytes[pos..end];
        pos = end;
        Ok(out)
    };
    let version = take(1)?[0];
    if version != STRUCTURAL_VERDICT_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "structural-verdict",
            version: version as u32,
        });
    }
    let root = ContentId::from_array(take(32)?.try_into().unwrap());
    let mutator = u16::from_le_bytes(take(2)?.try_into().unwrap());
    let depth = u32::from_le_bytes(take(4)?.try_into().unwrap());
    let class = take(1)?[0];
    let morph_identity = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let axis_count = take(1)?[0] as usize;
    if axis_count > MAX_VERDICTS_PER_OBJECT {
        return Err(Error::BoundExceeded {
            what: "verdict axes",
            limit: MAX_VERDICTS_PER_OBJECT as u64,
            got: axis_count as u64,
        });
    }
    let mut axes = Vec::with_capacity(axis_count);
    for _ in 0..axis_count {
        let axis = u16::from_le_bytes(take(2)?.try_into().unwrap());
        let grammar = take(1)?[0];
        let confirmed = take(1)?[0];
        let reason = take(1)?[0];
        let policy = take(1)?[0];
        let dir = take(1)?[0];
        let calibrated = take(1)?[0] != 0;
        let dev_mag_bin = take(1)?[0];
        let persistence = take(1)?[0];
        axes.push(AxisVerdict {
            axis,
            grammar,
            confirmed,
            reason,
            policy,
            dir,
            calibrated,
            dev_mag_bin,
            persistence,
        });
    }
    if pos != bytes.len() {
        return Err(Error::Encoding("structural-verdict has trailing bytes"));
    }
    Ok(DurableVerdict {
        root,
        mutator,
        depth,
        axes,
        class,
        morph_identity,
    })
}

/// One axis's streaming structural state (per (root, mutator, signal)).
#[derive(Debug, Clone)]
struct AxisStream {
    /// Calibration values collected so far (bounded by max_calibration).
    calib: Vec<u64>,
    /// Rolling residual-norm history (bounded by [`MAX_NORM_HIST`]).
    norms: Vec<f64>,
    /// Recent raw grammar states (chronological, most recent last; bounded
    /// by `hysteresis_confirm`).
    recent_raw: Vec<GrammarState>,
    /// Raw grammar-state *codes* over the last `drift_window` windows, for
    /// the crate's own `sign::boundary_density` (DSFB's `evaluate_signal`
    /// hardcodes boundary density 0.0 with the comment "would need state
    /// history — simplified"; we have the state history, so we supply the
    /// real density the DSA score is defined over).
    raw_codes: Vec<u8>,
    /// Consecutive confirmed-Boundary windows (DSFB caller-side counter).
    persistence: usize,
    /// The calibration segment's mean.
    mean: f64,
    /// The envelope radius (ρ).
    rho: f64,
    /// Calibration is complete and an envelope was calibrated (ρ > 0).
    calibrated: bool,
    /// Whether the extended calibration exhausted without any movement
    /// (discrete axis).
    discrete: bool,
    /// The last drift sign (−1 / 0 / +1 from the DSFB drift, ±δ deadband).
    last_drift_sign: i8,
    /// The latest sticky verdict (recomputed each window; held for the
    /// episode machine and for the *current* edge's activity checks).
    sticky: AxisVerdict,
    /// Windows evaluated so far (post-calibration count).
    eval_windows: u64,
}

impl AxisStream {
    fn new() -> AxisStream {
        AxisStream {
            calib: Vec::new(),
            norms: Vec::new(),
            recent_raw: Vec::new(),
            raw_codes: Vec::new(),
            persistence: 0,
            mean: 0.0,
            rho: 0.0,
            calibrated: false,
            discrete: false,
            last_drift_sign: 0,
            sticky: AxisVerdict::silent(0, false),
            eval_windows: 0,
        }
    }

    /// Try to finish calibration. Calibration is only attempted once the
    /// segment has at least `calibration_windows` samples (the declared
    /// law); a perfectly flat segment extends to the doubled cap before the
    /// axis is declared discrete.
    fn maybe_finalize(&mut self, cfg: &BridgeConfig) {
        if self.calib.len() < cfg.calibration_windows {
            return;
        }
        let Some((mean, sigma)) = mean_sigma(&self.calib) else {
            return;
        };
        let span = self
            .calib
            .iter()
            .max()
            .copied()
            .unwrap_or(0)
            .saturating_sub(self.calib.iter().min().copied().unwrap_or(0));
        let rho = (3.0 * sigma).max(cfg.span_envelope_multiplier * span as f64);
        if rho > 0.0 {
            self.mean = mean;
            self.rho = rho;
            self.calibrated = true;
            self.discrete = false;
            self.sticky = AxisVerdict::silent(self.sticky.axis, true);
        } else if self.calib.len() >= max_calibration(cfg) {
            // The axis never varied through the extended segment: discrete.
            self.discrete = true;
            self.calibrated = false;
            self.sticky = AxisVerdict::silent(self.sticky.axis, false);
        }
    }

    /// Push one observed value (one window of this axis's event stream).
    /// Returns the evaluated verdict, or `None` while the window is part of
    /// the calibration segment.
    fn push(
        &mut self,
        axis: u16,
        value: u64,
        cfg: &BridgeConfig,
        ecfg: &EngineConfig,
    ) -> Option<AxisVerdict> {
        self.sticky.axis = axis;
        if !self.calibrated && !self.discrete {
            self.calib.push(value);
            self.maybe_finalize(cfg);
            if !self.calibrated {
                return None;
            }
        }
        if self.discrete {
            // Discrete axis: no envelope grammar; the frf-fuzz discrete
            // state classes interpret it. Emit the silent verdict.
            return Some(AxisVerdict::silent(axis, false));
        }
        // Post-calibration evaluation through the real DSFB chain.
        let norm = (value as f64 - self.mean).abs();
        self.norms.push(norm);
        if self.norms.len() > MAX_NORM_HIST {
            let excess = self.norms.len() - MAX_NORM_HIST;
            self.norms.drain(0..excess);
        }
        let k = self.norms.len() - 1;
        let st = sign::compute_sign_tuple(&self.norms, k);
        let drift_pers = sign::drift_persistence(&self.norms, k, cfg.drift_window);

        let (raw, reason) = grammar::evaluate_raw_grammar(&st, self.rho, ecfg, drift_pers);
        self.recent_raw.push(raw);
        if self.recent_raw.len() > cfg.hysteresis_confirm {
            let excess = self.recent_raw.len() - cfg.hysteresis_confirm;
            self.recent_raw.drain(0..excess);
        }
        self.raw_codes.push(raw as u8);
        if self.raw_codes.len() > cfg.drift_window.max(1) {
            let excess = self.raw_codes.len() - cfg.drift_window.max(1);
            self.raw_codes.drain(0..excess);
        }
        let mut confirmed = grammar::hysteresis_confirm(&self.recent_raw, cfg.hysteresis_confirm);
        if raw == GrammarState::Violation {
            // DSFB's rule: a raw violation bypasses hysteresis.
            confirmed = GrammarState::Violation;
        }
        let slew_mag = st.slew.abs();
        let slew_flag = if slew_mag > cfg.slew_delta { 1.0 } else { 0.0 };
        // Real boundary density over the recent raw grammar codes (see the
        // field doc; this is the crate's own `sign::boundary_density`).
        let k_bd = self.raw_codes.len().saturating_sub(1);
        let boundary_density =
            sign::boundary_density(&self.raw_codes, k_bd, cfg.drift_window.max(1));
        let dsa_score = dsa::compute_dsa_score(boundary_density, drift_pers, slew_flag);
        let gate = dsa::consistency_gate(dsa_score, cfg.consistency_gate);
        let policy_state = policy::apply_policy(
            confirmed,
            dsa_score,
            gate,
            SemanticDisposition::Unknown,
            self.persistence,
            cfg.persistence_threshold,
        );

        // DSFB caller-side persistence counter (identical to the crate's
        // run_evaluation update rule).
        if confirmed >= GrammarState::Boundary {
            self.persistence = self.persistence.saturating_add(1);
        } else {
            self.persistence = 0;
        }

        // Drift direction class (declared quantization law, module docs).
        let dir = if st.drift > cfg.slew_delta {
            if self.last_drift_sign == -1 {
                DriftDir::Oscillatory
            } else {
                DriftDir::Outward
            }
        } else if st.drift < -cfg.slew_delta {
            if self.last_drift_sign == 1 {
                DriftDir::Oscillatory
            } else {
                DriftDir::Inward
            }
        } else {
            DriftDir::None
        };
        self.last_drift_sign = if st.drift > cfg.slew_delta {
            1
        } else if st.drift < -cfg.slew_delta {
            -1
        } else {
            0
        };

        let dev = (value as f64 - self.mean).abs().round() as u64;
        let verdict = AxisVerdict {
            axis,
            grammar: raw as u8,
            confirmed: confirmed as u8,
            reason: reason as u8,
            policy: policy_state as u8,
            dir: dir.code(),
            calibrated: true,
            dev_mag_bin: magnitude_bucket(dev),
            persistence: self.persistence.min(u8::MAX as usize) as u8,
        };
        self.sticky = verdict;
        self.eval_windows = self.eval_windows.saturating_add(1);
        Some(verdict)
    }
}

/// The extended calibration cap (span extension in search of movement).
fn max_calibration(cfg: &BridgeConfig) -> usize {
    cfg.calibration_windows.saturating_mul(2).max(3)
}

/// Mean and Bessel-corrected sample standard deviation of a slice.
fn mean_sigma(values: &[u64]) -> Option<(f64, f64)> {
    if values.is_empty() {
        return None;
    }
    let n = values.len() as f64;
    let mean = values.iter().map(|v| *v as f64).sum::<f64>() / n;
    if values.len() < 2 {
        return Some((mean, 0.0));
    }
    let var = values
        .iter()
        .map(|v| {
            let d = *v as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / (n - 1.0);
    Some((mean, var.sqrt()))
}

/// The per-(root, mutator) structural substrate: per-axis streams plus the
/// episode machine that turns axis verdicts into closed structural
/// episodes. Pure deterministic state; replaying the same edges in the same
/// order reproduces identical verdicts and episodes.
#[derive(Debug, Clone)]
pub struct LineageSubstrate {
    /// The lineage key (root, mutator) this substrate belongs to.
    root: ContentId,
    mutator: u16,
    /// The bridge configuration (immutable after construction).
    cfg: BridgeConfig,
    /// The validated DSFB engine config.
    ecfg: EngineConfig,
    /// Per-axis streams (created lazily on first movement).
    streams: Vec<Option<AxisStream>>,
    /// The open structural episode, if any.
    open: Option<OpenEpisode>,
    /// Edges below Review on all axes since the last active edge.
    quiet_run: u64,
}

/// An open (not yet closed) structural episode.
#[derive(Debug, Clone)]
struct OpenEpisode {
    t_open: u64,
    peak_ordinal: u64,
    peak_policy: u8,
    axes: u64,
    reasons: ReasonBits,
    open_generation: u32,
}

impl LineageSubstrate {
    /// A fresh substrate for a (root, mutator) lineage.
    pub fn new(root: ContentId, mutator: u16, cfg: &BridgeConfig) -> Result<LineageSubstrate> {
        let ecfg = cfg.engine_config()?;
        Ok(LineageSubstrate {
            root,
            mutator,
            cfg: *cfg,
            ecfg,
            streams: vec![None; MAX_SIGNALS],
            open: None,
            quiet_run: 0,
        })
    }

    /// The lineage root.
    pub fn root(&self) -> &ContentId {
        &self.root
    }

    /// The lineage mutator family.
    pub fn mutator(&self) -> u16 {
        self.mutator
    }

    /// The bridge configuration.
    pub fn config(&self) -> &BridgeConfig {
        &self.cfg
    }

    /// The number of axes with an active (policy ≥ Watch) sticky verdict.
    pub fn active_axis_count(&self) -> usize {
        self.streams
            .iter()
            .flatten()
            .filter(|s| s.sticky.is_active())
            .count()
    }

    /// Whether a structural episode is currently open.
    pub fn episode_open(&self) -> bool {
        self.open.is_some()
    }

    /// Feed one admitted lineage edge at lineage ordinal `ordinal` (the
    /// per-lineage edge counter). Only axes the edge moved are fed (their
    /// child values read from the residual); the episode machine advances
    /// on every edge. Returns the edge's structural summary and, when the
    /// edge closed an episode, that episode.
    pub fn feed_edge(
        &mut self,
        ordinal: u64,
        edge: &MutationResidual,
        generation: u32,
    ) -> Result<(EdgeStructural, Option<StructuralEpisode>)> {
        let mut verdicts = Vec::new();
        for i in 0..MAX_SIGNALS {
            if edge.moved() & (1u64 << i) == 0 {
                continue;
            }
            let stream = self.streams[i].get_or_insert_with(|| {
                let mut s = AxisStream::new();
                s.sticky.axis = i as u16;
                s
            });
            if let Some(v) = stream.push(
                i as u16,
                edge.child.value(SignalId(i as u16)),
                &self.cfg,
                &self.ecfg,
            ) {
                verdicts.push(v);
            }
        }
        let mut axes = 0u64;
        let mut reasons: ReasonBits = 0;
        let mut peak = 0u8;
        for v in &verdicts {
            if v.policy >= PolicyState::Review as u8 {
                axes |= 1u64 << v.axis;
                reasons |= 1u8 << (v.reason & 7);
                peak = peak.max(v.policy);
            }
        }
        // DSFB's episode semantics evaluate every signal every window; an
        // axis whose value is unchanged keeps its prior evaluation (identical
        // inputs -> identical DSFB outputs). A sticky Review-or-higher verdict
        // therefore keeps an episode active across edges where the axis did
        // not move.
        let sticky_active = self
            .streams
            .iter()
            .flatten()
            .any(|s| s.sticky.policy >= PolicyState::Review as u8);
        let active = axes != 0 || sticky_active;
        let closed = self.advance_episode(ordinal, generation, active, axes, reasons, peak);
        Ok((
            EdgeStructural {
                verdicts,
                any_active: active,
            },
            closed,
        ))
    }

    /// Advance the episode machine after an edge. `active` says whether any
    /// axis is at policy ≥ Review (freshly evaluated OR sticky);
    /// `ep_axes`/`ep_reasons`/`ep_peak` summarize the fresh Review-or-higher
    /// verdicts of this edge.
    fn advance_episode(
        &mut self,
        ordinal: u64,
        generation: u32,
        active: bool,
        ep_axes: u64,
        ep_reasons: ReasonBits,
        ep_peak: u8,
    ) -> Option<StructuralEpisode> {
        let correlation = self.cfg.drift_window.max(1) as u64; // quiet-run length (W)
        match &mut self.open {
            None => {
                if active {
                    self.open = Some(OpenEpisode {
                        t_open: ordinal,
                        peak_ordinal: ordinal,
                        peak_policy: ep_peak.max(PolicyState::Review as u8),
                        axes: ep_axes,
                        reasons: ep_reasons,
                        open_generation: generation,
                    });
                }
                self.quiet_run = 0;
                None
            }
            Some(open) => {
                if active {
                    open.peak_ordinal = ordinal;
                    open.peak_policy = open.peak_policy.max(ep_peak);
                    open.axes |= ep_axes;
                    open.reasons |= ep_reasons;
                    self.quiet_run = 0;
                    None
                } else {
                    self.quiet_run += 1;
                    if self.quiet_run >= correlation {
                        let closed = self.open.take().map(|o| StructuralEpisode {
                            root: self.root,
                            mutator: self.mutator,
                            t_open: o.t_open,
                            t_close: ordinal,
                            peak_ordinal: o.peak_ordinal,
                            peak_policy: o.peak_policy,
                            axes: o.axes,
                            reasons: o.reasons,
                            dwell: ordinal.saturating_sub(o.t_open).saturating_add(1),
                            class: 0,
                            open_generation: o.open_generation,
                        });
                        self.quiet_run = 0;
                        closed
                    } else {
                        None
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target_runtime::signals::SignalVector;

    fn vec_with(id: u16, v: u64) -> SignalVector {
        let mut s = SignalVector::new();
        s.observe(SignalId(id), v).unwrap();
        s
    }

    fn edge(parent: &SignalVector, child: &SignalVector) -> MutationResidual {
        MutationResidual::of(child, parent)
    }

    fn cfg() -> BridgeConfig {
        BridgeConfig::default_config()
    }

    fn substrate() -> LineageSubstrate {
        LineageSubstrate::new(ContentId::new(b"root"), 7, &cfg()).unwrap()
    }

    #[test]
    fn flat_series_never_escalates() {
        // A series that never moves has no windows and must never fabricate
        // structure: every edge is trivial, the episode machine stays quiet,
        // and no verdict is ever emitted.
        let mut sub = substrate();
        let mut parent = vec_with(0, 5);
        for i in 1..=24u64 {
            let child = vec_with(0, 5);
            let (es, ep) = sub.feed_edge(i, &edge(&parent, &child), i as u32).unwrap();
            assert!(ep.is_none());
            assert!(!es.any_active);
            assert!(es.verdicts.is_empty());
            parent = child;
        }
        assert!(!sub.episode_open());
    }

    #[test]
    fn noise_within_calibration_span_stays_silent() {
        // Jitter that stays inside the observed calibration span must never
        // enter the boundary zone (the span multiplier is 2).
        let mut sub = substrate();
        let values = [
            10u64, 12, 9, 11, 10, 12, 11, 10, // calibration (span 3)
            9, 12, 10, 11, 9, 12, 10, 11, 9, 10, 12, 9, 11, 10, 11, 10, 9, 12, // inside span
        ];
        let mut parent = vec_with(0, values[0]);
        let mut any_active = false;
        for (i, v) in values.iter().enumerate().skip(1) {
            let child = vec_with(0, *v);
            let (es, _ep) = sub
                .feed_edge(i as u64, &edge(&parent, &child), i as u32)
                .unwrap();
            any_active |= es.verdicts.iter().any(|v| v.is_active());
            parent = child;
        }
        assert!(!any_active, "in-span jitter must stay Silent");
    }

    #[test]
    fn monotone_outward_drift_escalates_and_forms_an_episode() {
        let mut sub = substrate();
        // Depth axis climbs 0..=24; calibration windows 1..=8 (values
        // 1..=8: mean 4.5, span 7, so rho = max(3 sigma, 2*7) = 14). The
        // climb beyond the calibration span produces Review once the DSFB
        // persistence gate K=4 passes (window 17), Escalate once the norm
        // exceeds rho (window 19), and an episode that stays open while the
        // axis is out of envelope and closes after a quiet run once it
        // returns.
        let mut parent = vec_with(0, 0);
        let mut peak_policy = 0u8;
        for d in 1..=24u64 {
            let child = vec_with(0, d);
            let (es, ep) = sub.feed_edge(d, &edge(&parent, &child), d as u32).unwrap();
            peak_policy = peak_policy.max(es.max_policy());
            assert!(ep.is_none(), "episode must stay open while climbing");
            parent = child;
        }
        assert_eq!(peak_policy, PolicyState::Escalate as u8);

        // Return to the nominal: value 5 (inside the envelope). The episode
        // must close after `drift_window` quiet edges.
        let child = vec_with(0, 5);
        let (es, _ep) = sub.feed_edge(25, &edge(&parent, &child), 25).unwrap();
        assert!(!es.verdicts.iter().any(|v| v.is_active()));
        parent = child;
        let quiet_target = cfg().drift_window as u64;
        let mut closed = None;
        for i in 26..=26 + quiet_target + 1 {
            let c = vec_with(0, 5);
            let (_, ep) = sub.feed_edge(i, &edge(&parent, &c), i as u32).unwrap();
            if ep.is_some() {
                closed = ep;
                break;
            }
            parent = c;
        }
        let closed = closed.expect("episode must close after quiet run");
        assert_eq!(closed.t_open, 17); // first edge at which any axis is Review
        assert_eq!(closed.t_close, 29); // 5 quiet edges after the return
        assert_eq!(closed.peak_policy, PolicyState::Escalate as u8);
        assert!(closed.axes & 1 != 0);
        assert!(closed.reasons & (1 << (ReasonCode::EnvelopeViolation as u8)) != 0);
    }

    #[test]
    fn frozen_review_axis_keeps_episode_open() {
        // Once an axis has reached Review, an episode must NOT close merely
        // because the axis stopped moving while other axes keep changing:
        // DSFB would keep evaluating the unchanged signal and it would stay
        // in the boundary zone. Only a real return below Review starts the
        // quiet run.
        let mut sub = substrate();
        let mut parent = vec_with(0, 0);
        // Climb to Escalate (windows 19+; earlier windows are calibration
        // and boundary-approach).
        for d in 1..=20u64 {
            let child = vec_with(0, d);
            let (es, _) = sub.feed_edge(d, &edge(&parent, &child), d as u32).unwrap();
            if d >= 19 {
                assert_eq!(es.max_policy(), PolicyState::Escalate as u8);
            }
            parent = child;
        }
        assert!(sub.episode_open());
        // The axis freezes at 20 while a second axis wanders benignly inside
        // its own envelope. The episode must stay open (sticky Review).
        let mut parent2 = vec_with(0, 20);
        parent2.observe(SignalId(1), 0).unwrap();
        for i in 21..=30u64 {
            let mut child = vec_with(0, 20);
            child.observe(SignalId(1), i % 5).unwrap();
            let (es, ep) = sub.feed_edge(i, &edge(&parent2, &child), i as u32).unwrap();
            assert!(
                ep.is_none(),
                "frozen Review axis must keep the episode open"
            );
            assert!(es.any_active);
            parent2 = child;
        }
    }

    #[test]
    fn verdict_and_episode_payloads_roundtrip() {
        let ep = StructuralEpisode {
            root: ContentId::new(b"root"),
            mutator: 7,
            t_open: 3,
            t_close: 19,
            peak_ordinal: 17,
            peak_policy: PolicyState::Escalate as u8,
            axes: 0b101,
            reasons: 0b100_0101,
            dwell: 17,
            class: 0,
            open_generation: 4,
        };
        let enc = encode_episode_payload(&ep).unwrap();
        let dec = decode_episode_payload(&enc).unwrap();
        assert_eq!(dec, ep);
        assert!(decode_episode_payload(&enc[..enc.len() - 1]).is_err());
        let mut bad = enc.clone();
        bad[0] = 99;
        assert!(decode_episode_payload(&bad).is_err());
    }

    #[test]
    fn replay_is_deterministic() {
        let mut a = substrate();
        let mut b = substrate();
        let mut pa = vec_with(0, 0);
        let mut pb = vec_with(0, 0);
        let mut verdicts_a = Vec::new();
        let mut verdicts_b = Vec::new();
        let mut ep_a = Vec::new();
        let mut ep_b = Vec::new();
        for d in 1..=40u64 {
            let ca = vec_with(0, d);
            let cb = vec_with(0, d);
            let (ea, e1) = a.feed_edge(d, &edge(&pa, &ca), d as u32).unwrap();
            let (eb, e2) = b.feed_edge(d, &edge(&pb, &cb), d as u32).unwrap();
            verdicts_a.extend(ea.verdicts);
            verdicts_b.extend(eb.verdicts);
            ep_a.extend(e1);
            ep_b.extend(e2);
            pa = ca;
            pb = cb;
        }
        assert_eq!(verdicts_a, verdicts_b);
        assert_eq!(ep_a, ep_b);
        assert_eq!(a.episode_open(), b.episode_open());
    }

    #[test]
    fn discrete_axis_first_movement_is_silent_not_violation() {
        // A clamping axis (every movement lands on the same value 1) is flat
        // through the extended calibration and is declared discrete; its
        // later movement must NOT fabricate an envelope violation.
        let mut sub = substrate();
        let mut parent = vec_with(0, 0);
        // Windows 1..=16: parents 0,2,3,4,... all clamp to child value 1.
        for i in 1..=16u64 {
            let child = vec_with(0, 1);
            let (es, _ep) = sub.feed_edge(i, &edge(&parent, &child), i as u32).unwrap();
            assert!(!es.verdicts.iter().any(|v| v.is_active()));
            parent = child;
        }
        // A real departure now: value 3. The axis is discrete, so the
        // verdict must be silent (never a grammar violation).
        let child = vec_with(0, 3);
        let (es, _ep) = sub.feed_edge(17, &edge(&parent, &child), 17).unwrap();
        assert!(!es.verdicts.iter().any(|v| v.is_active()));
        assert!(es.verdicts.iter().all(|v| !v.calibrated));
        assert!(es
            .verdicts
            .iter()
            .all(|v| v.policy == PolicyState::Silent as u8));
    }

    #[test]
    fn recovery_from_drift_is_inward_direction() {
        // After an outward climb, a return toward the mean must read as
        // Inward direction (norm shrinking), which is real structure (the
        // axis recovered) — distinct from the initial Outward class.
        let mut sub = substrate();
        let mut parent = vec_with(0, 0);
        let mut saw_outward = false;
        for d in 1..=14u64 {
            let child = vec_with(0, d);
            let (es, _) = sub.feed_edge(d, &edge(&parent, &child), d as u32).unwrap();
            if let Some(v) = es.verdicts.iter().find(|v| v.axis == 0) {
                if v.dir == DriftDir::Outward.code() {
                    saw_outward = true;
                }
            }
            parent = child;
        }
        assert!(saw_outward);
        // Drift back toward the mean: 14 -> 13 -> 12 ...
        let mut saw_inward = false;
        for d in (1u64..=13).rev() {
            let child = vec_with(0, d);
            let (es, _) = sub
                .feed_edge(40 - d, &edge(&parent, &child), (40 - d) as u32)
                .unwrap();
            if let Some(v) = es.verdicts.iter().find(|v| v.axis == 0) {
                if v.dir == DriftDir::Inward.code() {
                    saw_inward = true;
                }
            }
            parent = child;
        }
        assert!(saw_inward);
    }
}
