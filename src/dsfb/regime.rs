//! The regime observer (the DSFB-Database lesson, re-documented
//! independently; invariant I7).
//!
//! DSFB-Database demonstrates that sustained raw crossings collapse into a
//! very small number of bounded episodes rather than hundreds of individual
//! alerts. frf-fuzz applies that architecture to *mutation lineages*: the
//! noisy per-execution observation stream of one signal becomes a bounded
//! structural episode with an onset, a peak, persistence and a recovery.
//!
//! # Semantics (documented independently of SQL telemetry)
//!
//! The observer consumes a stream of `(ordinal, value)` observations for ONE
//! signal and maintains:
//!
//! * **instantaneous residual** `r(t) = value(t) - value(t-1)` (0 for the
//!   first sample);
//! * **smoothed residual** — an integer fixed-point EMA
//!   `ema(t) = ema(t-1) - (ema(t-1) >> shift) + r(t)`, i.e. α = 1/2^shift;
//! * **cumulative deviation** from the current nominal — the first observed
//!   value, or the recovery point after the previous episode closed (exact
//!   `i128`);
//! * a state machine `Stable → Drift → InEpisode → Recovering → Stable`
//!   with deterministic dwell counts and a deterministic episode close.
//!
//! State transitions:
//!
//! * `Stable → Drift`: `|ema| ≥ drift_threshold` for `drift_dwell`
//!   consecutive samples.
//! * `Drift → InEpisode`: `|cumulative| ≥ episode_threshold` (a boundary
//!   crossing in deviation space).
//! * `InEpisode → Recovering`: `|ema| < recovery_threshold` for
//!   `recovery_dwell` consecutive samples (the episode has settled), or the
//!   deterministic `max_dwell` cap is hit.
//! * `Recovering → Stable`: `|ema| < drift_threshold` for `drift_dwell`
//!   consecutive samples.
//!
//! An episode CLOSES only by a deterministic rule — recovery dwell or max
//! dwell — never by wall-clock time. Same series + same config ⇒ same
//! episode sequence (I12 spirit).
//!
//! All arithmetic is integer; there are no floats in identity or state.

use crate::error::{Error, Result};

/// Version of the episode payload encoding.
pub const REGIME_EPISODE_VERSION: u8 = 1;

/// Why an episode closed (deterministic rules only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EpisodeClose {
    /// The smoothed residual settled below the recovery threshold for
    /// `recovery_dwell` consecutive samples.
    RecoveryDwell = 1,
    /// The episode reached `max_dwell` samples and was closed by the cap
    /// (prevents unbounded episodes; a cap close is itself informative).
    MaxDwell = 2,
}

impl EpisodeClose {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<EpisodeClose> {
        match b {
            1 => Some(EpisodeClose::RecoveryDwell),
            2 => Some(EpisodeClose::MaxDwell),
            _ => None,
        }
    }

    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            EpisodeClose::RecoveryDwell => "recovery-dwell",
            EpisodeClose::MaxDwell => "max-dwell",
        }
    }
}

/// The observer's current regime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegimeState {
    /// No sustained smoothed residual; no episode.
    Stable = 0,
    /// The smoothed residual has exceeded the drift threshold for the dwell.
    Drift = 1,
    /// The cumulative deviation crossed the episode threshold.
    InEpisode = 2,
    /// An episode closed and the stream is settling back toward Stable.
    Recovering = 3,
}

impl RegimeState {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<RegimeState> {
        match b {
            0 => Some(RegimeState::Stable),
            1 => Some(RegimeState::Drift),
            2 => Some(RegimeState::InEpisode),
            3 => Some(RegimeState::Recovering),
            _ => None,
        }
    }

    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            RegimeState::Stable => "stable",
            RegimeState::Drift => "drift",
            RegimeState::InEpisode => "in-episode",
            RegimeState::Recovering => "recovering",
        }
    }
}

/// The observer's configuration. Campaign-constant; encoded into every
/// closed episode so episodes are self-describing and re-derivation uses
/// the same thresholds.
///
/// Thresholds are in RAW units of the observed signal; the internal EMA
/// state is kept in fixed-point units (× 2^ema_shift) so the integer
/// arithmetic never floors to zero while the signal is still settling
/// (a Phase-2 finding: a raw-unit floor EMA gets stuck below 2^shift and
/// recovery never fires).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegimeConfig {
    /// EMA shift: α = 1/2^shift (the fixed-point scale).
    pub ema_shift: u8,
    /// Drift threshold in raw units (|smoothed| >= this to be Drift).
    pub drift_threshold: i64,
    /// Consecutive drift samples required to enter Drift.
    pub drift_dwell: u32,
    /// Cumulative |deviation from baseline| required to open an episode.
    pub episode_threshold: u64,
    /// Recovery threshold in raw units.
    pub recovery_threshold: i64,
    /// Consecutive recovering samples required to close an episode.
    pub recovery_dwell: u32,
    /// Deterministic cap on episode length in samples.
    pub max_dwell: u32,
}

impl RegimeConfig {
    /// The default configuration (documented, tunable per campaign).
    pub const fn default_config() -> RegimeConfig {
        RegimeConfig {
            ema_shift: 4,
            drift_threshold: 8,
            drift_dwell: 3,
            episode_threshold: 32,
            recovery_threshold: 2,
            recovery_dwell: 3,
            max_dwell: 4096,
        }
    }
}

/// A closed, durable regime episode (Family::RegimeEpisode payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegimeEpisode {
    /// The signal this episode is about.
    pub signal: u16,
    /// The configuration the episode ran under.
    pub cfg: RegimeConfig,
    /// Ordinal of the first InEpisode sample.
    pub onset_ordinal: u64,
    /// Ordinal of the peak |deviation| sample.
    pub peak_ordinal: u64,
    /// The signal value at the peak.
    pub peak_value: u64,
    /// Maximum |cumulative deviation| reached inside the episode.
    pub peak_deviation: u64,
    /// Ordinal of the closing sample.
    pub close_ordinal: u64,
    /// Samples spent in InEpisode.
    pub dwell: u32,
    /// Why the episode closed.
    pub closed_by: EpisodeClose,
    /// Extreme smoothed residual (fixed-point) reached inside the episode.
    pub peak_ema_fixed: i64,
}

/// Encode a closed episode to its canonical payload.
pub fn encode_episode(e: &RegimeEpisode) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 2 + 1 + 4 * 8 + 4 + 1 + 8 + 8);
    out.push(REGIME_EPISODE_VERSION);
    out.extend_from_slice(&e.signal.to_le_bytes());
    out.push(e.cfg.ema_shift);
    out.extend_from_slice(&e.cfg.drift_threshold.to_le_bytes());
    out.extend_from_slice(&e.cfg.drift_dwell.to_le_bytes());
    out.extend_from_slice(&e.cfg.episode_threshold.to_le_bytes());
    out.extend_from_slice(&e.cfg.recovery_threshold.to_le_bytes());
    out.extend_from_slice(&e.cfg.recovery_dwell.to_le_bytes());
    out.extend_from_slice(&e.cfg.max_dwell.to_le_bytes());
    out.extend_from_slice(&e.onset_ordinal.to_le_bytes());
    out.extend_from_slice(&e.peak_ordinal.to_le_bytes());
    out.extend_from_slice(&e.peak_value.to_le_bytes());
    out.extend_from_slice(&e.peak_deviation.to_le_bytes());
    out.extend_from_slice(&e.close_ordinal.to_le_bytes());
    out.extend_from_slice(&e.dwell.to_le_bytes());
    out.push(e.closed_by.code());
    out.extend_from_slice(&e.peak_ema_fixed.to_le_bytes());
    Ok(out)
}

/// Decode a closed episode payload.
pub fn decode_episode(bytes: &[u8]) -> Result<RegimeEpisode> {
    if bytes.len() < 1 + 2 + 1 + 4 * 8 + 4 + 1 + 8 * 4 + 4 + 1 + 8 {
        return Err(Error::Encoding("regime-episode truncated"));
    }
    let version = bytes[0];
    if version != REGIME_EPISODE_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "regime-episode",
            version: version as u32,
        });
    }
    let mut pos = 1usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > bytes.len() {
            return Err(Error::Encoding("regime-episode truncated"));
        }
        let out = &bytes[pos..end];
        pos = end;
        Ok(out)
    };
    let signal = u16::from_le_bytes(take(2)?.try_into().unwrap());
    let cfg = RegimeConfig {
        ema_shift: take(1)?[0],
        drift_threshold: i64::from_le_bytes(take(8)?.try_into().unwrap()),
        drift_dwell: u32::from_le_bytes(take(4)?.try_into().unwrap()),
        episode_threshold: u64::from_le_bytes(take(8)?.try_into().unwrap()),
        recovery_threshold: i64::from_le_bytes(take(8)?.try_into().unwrap()),
        recovery_dwell: u32::from_le_bytes(take(4)?.try_into().unwrap()),
        max_dwell: u32::from_le_bytes(take(4)?.try_into().unwrap()),
    };
    let e = RegimeEpisode {
        signal,
        cfg,
        onset_ordinal: u64::from_le_bytes(take(8)?.try_into().unwrap()),
        peak_ordinal: u64::from_le_bytes(take(8)?.try_into().unwrap()),
        peak_value: u64::from_le_bytes(take(8)?.try_into().unwrap()),
        peak_deviation: u64::from_le_bytes(take(8)?.try_into().unwrap()),
        close_ordinal: u64::from_le_bytes(take(8)?.try_into().unwrap()),
        dwell: u32::from_le_bytes(take(4)?.try_into().unwrap()),
        closed_by: EpisodeClose::from_byte(take(1)?[0])
            .ok_or(Error::Encoding("unknown episode close reason"))?,
        peak_ema_fixed: i64::from_le_bytes(take(8)?.try_into().unwrap()),
    };
    if pos != bytes.len() {
        return Err(Error::Encoding("regime-episode has trailing bytes"));
    }
    Ok(e)
}

/// The per-(lineage, signal) regime observer.
#[derive(Debug, Clone)]
pub struct RegimeObserver {
    cfg: RegimeConfig,
    state: RegimeState,
    /// Fixed-point smoothed residual (units of 2^ema_shift).
    ema_fixed: i64,
    /// Exact cumulative deviation from baseline.
    cumulative: i128,
    baseline: Option<u64>,
    prev_value: Option<u64>,
    drift_run: u32,
    recover_run: u32,
    dwell: u32,
    onset_ordinal: u64,
    peak_ordinal: u64,
    peak_value: u64,
    peak_deviation: u64,
    peak_ema_fixed: i64,
    episode_open: bool,
}

impl RegimeObserver {
    /// A fresh observer with the given configuration.
    pub fn new(cfg: RegimeConfig) -> RegimeObserver {
        RegimeObserver {
            cfg,
            state: RegimeState::Stable,
            ema_fixed: 0,
            cumulative: 0,
            baseline: None,
            prev_value: None,
            drift_run: 0,
            recover_run: 0,
            dwell: 0,
            onset_ordinal: 0,
            peak_ordinal: 0,
            peak_value: 0,
            peak_deviation: 0,
            peak_ema_fixed: 0,
            episode_open: false,
        }
    }

    /// The current state.
    pub fn state(&self) -> RegimeState {
        self.state
    }

    /// The smoothed residual (fixed-point).
    pub fn ema_fixed(&self) -> i64 {
        self.ema_fixed
    }

    /// The exact cumulative deviation from baseline.
    pub fn cumulative(&self) -> i128 {
        self.cumulative
    }

    /// The baseline (first observed value), if any.
    pub fn baseline(&self) -> Option<u64> {
        self.baseline
    }

    /// Whether an episode is currently open.
    pub fn episode_open(&self) -> bool {
        self.episode_open
    }

    /// Feed one observation. Returns the closed episode when this sample
    /// closed one (at most one per sample).
    pub fn feed(&mut self, ordinal: u64, value: u64) -> Option<RegimeEpisode> {
        if self.baseline.is_none() {
            self.baseline = Some(value);
        }
        let r = match self.prev_value {
            Some(p) => (value as i128 - p as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64,
            None => 0,
        };
        self.prev_value = Some(value);
        // Fixed-point EMA in 2^shift units: ema = ema - (ema >> shift) +
        // (r << shift). Scaling r keeps the state above the integer floor
        // while it settles, so a flat tail genuinely decays to recovery
        // instead of getting stuck below 2^shift (Phase-2 finding).
        let scale = 1i64 << self.cfg.ema_shift;
        let r_fixed = r.saturating_mul(scale);
        self.ema_fixed = self
            .ema_fixed
            .saturating_sub(self.ema_fixed >> self.cfg.ema_shift)
            .saturating_add(r_fixed);
        self.cumulative = self.cumulative.saturating_add(r as i128);

        let drift_fixed = self
            .cfg
            .drift_threshold
            .saturating_mul(scale)
            .unsigned_abs();
        let recovery_fixed = self
            .cfg
            .recovery_threshold
            .saturating_mul(scale)
            .unsigned_abs();
        let mut closed: Option<RegimeEpisode> = None;
        match self.state {
            RegimeState::Stable => {
                if self.ema_fixed.unsigned_abs() >= drift_fixed {
                    self.drift_run += 1;
                    if self.drift_run >= self.cfg.drift_dwell {
                        self.state = RegimeState::Drift;
                        self.drift_run = 0;
                    }
                } else {
                    self.drift_run = 0;
                }
            }
            RegimeState::Drift => {
                if self.ema_fixed.unsigned_abs() < drift_fixed {
                    self.drift_run += 1;
                    if self.drift_run >= self.cfg.drift_dwell {
                        self.state = RegimeState::Stable;
                        self.drift_run = 0;
                    }
                } else {
                    self.drift_run = 0;
                }
                if self.state == RegimeState::Drift {
                    self.maybe_open_episode(ordinal, value);
                }
            }
            RegimeState::InEpisode => {
                self.dwell = self.dwell.saturating_add(1);
                self.update_peak(ordinal, value);
                if self.ema_fixed.unsigned_abs() < recovery_fixed {
                    self.recover_run += 1;
                    if self.recover_run >= self.cfg.recovery_dwell {
                        closed = Some(self.close(EpisodeClose::RecoveryDwell, ordinal, value));
                    }
                } else {
                    self.recover_run = 0;
                }
                if closed.is_none() && self.dwell >= self.cfg.max_dwell {
                    closed = Some(self.close(EpisodeClose::MaxDwell, ordinal, value));
                }
            }
            RegimeState::Recovering => {
                if self.ema_fixed.unsigned_abs() < drift_fixed {
                    self.drift_run += 1;
                    if self.drift_run >= self.cfg.drift_dwell {
                        self.state = RegimeState::Stable;
                        self.drift_run = 0;
                        self.recover_run = 0;
                    }
                } else {
                    self.drift_run = 0;
                }
            }
        }
        closed
    }

    /// Reset the observer (fresh lineage root): back to Stable, drop the
    /// baseline and any open episode state. An open episode is NOT closed by
    /// a reset — the coordinator decides how to record it (a reset with an
    /// open episode is a campaign-boundary situation, not a deterministic
    /// close).
    pub fn reset(&mut self) {
        self.state = RegimeState::Stable;
        self.ema_fixed = 0;
        self.cumulative = 0;
        self.baseline = None;
        self.prev_value = None;
        self.drift_run = 0;
        self.recover_run = 0;
        self.dwell = 0;
        self.episode_open = false;
    }

    fn maybe_open_episode(&mut self, ordinal: u64, value: u64) {
        if self.episode_open {
            return;
        }
        let dev = self.cumulative.unsigned_abs();
        if dev >= self.cfg.episode_threshold as u128 {
            self.episode_open = true;
            self.state = RegimeState::InEpisode;
            self.dwell = 1;
            self.recover_run = 0;
            self.onset_ordinal = ordinal;
            self.peak_ordinal = ordinal;
            self.peak_value = value;
            self.peak_deviation = dev as u64;
            self.peak_ema_fixed = self.ema_fixed;
        }
    }

    fn update_peak(&mut self, ordinal: u64, value: u64) {
        let dev = self.cumulative.unsigned_abs();
        // Strict `>`: the peak is the FIRST sample reaching the maximum
        // deviation (a flat tail must not re-anchor the peak onto its own
        // closing sample).
        if (dev as u64) > self.peak_deviation {
            self.peak_deviation = dev as u64;
            self.peak_ordinal = ordinal;
            self.peak_value = value;
        }
        if self.ema_fixed.unsigned_abs() > self.peak_ema_fixed.unsigned_abs() {
            self.peak_ema_fixed = self.ema_fixed;
        }
    }

    fn close(&mut self, reason: EpisodeClose, ordinal: u64, value: u64) -> RegimeEpisode {
        let episode = RegimeEpisode {
            signal: 0, // filled by the caller (the observer is per-signal)
            cfg: self.cfg,
            onset_ordinal: self.onset_ordinal,
            peak_ordinal: self.peak_ordinal,
            peak_value: self.peak_value,
            peak_deviation: self.peak_deviation,
            close_ordinal: ordinal,
            dwell: self.dwell,
            closed_by: reason,
            peak_ema_fixed: self.peak_ema_fixed,
        };
        self.episode_open = false;
        self.state = RegimeState::Recovering;
        self.recover_run = 0;
        self.drift_run = 0;
        self.dwell = 0;
        // The recovery point becomes the new nominal for the NEXT episode:
        // the deviation baseline resets so a later regime can open its own
        // bounded episode (deterministic close + reset).
        self.cumulative = 0;
        self.baseline = Some(value);
        episode
    }
}

/// A convenience test driver: feed a whole series and collect the episodes.
pub fn run_series(cfg: RegimeConfig, series: &[(u64, u64)]) -> (RegimeState, Vec<RegimeEpisode>) {
    let mut obs = RegimeObserver::new(cfg);
    let mut episodes = Vec::new();
    for (ordinal, value) in series {
        if let Some(ep) = obs.feed(*ordinal, *value) {
            episodes.push(ep);
        }
    }
    (obs.state(), episodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: RegimeConfig = RegimeConfig::default_config();

    #[test]
    fn episode_encoding_roundtrip() {
        let e = RegimeEpisode {
            signal: 3,
            cfg: CFG,
            onset_ordinal: 10,
            peak_ordinal: 50,
            peak_value: 100,
            peak_deviation: 90,
            close_ordinal: 80,
            dwell: 71,
            closed_by: EpisodeClose::RecoveryDwell,
            peak_ema_fixed: 123,
        };
        let enc = encode_episode(&e).unwrap();
        let dec = decode_episode(&enc).unwrap();
        assert_eq!(dec, e);
        // Locked wire size: version(1) signal(2) ema_shift(1) + cfg fields
        // (8+4+8+8+4+4) + onset(8) peak_ordinal(8) peak_value(8)
        // peak_deviation(8) close(8) dwell(4) close_reason(1) peak_ema(8).
        assert_eq!(enc.len(), 1 + 2 + 1 + 36 + 8 * 5 + 4 + 1 + 8);
    }

    #[test]
    fn flat_series_stays_stable_no_episode() {
        let series: Vec<(u64, u64)> = (0..100).map(|i| (i, 42)).collect();
        let (state, episodes) = run_series(CFG, &series);
        assert_eq!(state, RegimeState::Stable);
        assert!(episodes.is_empty());
    }

    #[test]
    fn noise_around_constant_stays_stable() {
        // Negative control (§32): jitter must not invent a drift.
        let mut series = Vec::new();
        for i in 0..256u64 {
            let v = if i % 2 == 0 { 100 } else { 101 };
            series.push((i, v));
        }
        let (state, episodes) = run_series(CFG, &series);
        assert_eq!(state, RegimeState::Stable);
        assert!(episodes.is_empty());
    }

    #[test]
    fn monotonic_ramp_opens_and_closes_episode() {
        // A ramp up to 200 then flat: drift, episode, recovery close.
        let mut series = Vec::new();
        for i in 0..200u64 {
            series.push((i, i)); // value == ordinal
        }
        for i in 200..400u64 {
            series.push((i, 200)); // flat recovery tail
        }
        let (state, episodes) = run_series(CFG, &series);
        assert_eq!(episodes.len(), 1);
        let ep = &episodes[0];
        assert_eq!(ep.closed_by, EpisodeClose::RecoveryDwell);
        assert!(ep.onset_ordinal > 0);
        assert!(ep.peak_deviation >= CFG.episode_threshold);
        assert!(ep.close_ordinal > ep.peak_ordinal);
        assert_eq!(ep.dwell, (ep.close_ordinal - ep.onset_ordinal + 1) as u32);
        assert!(state == RegimeState::Recovering || state == RegimeState::Stable);
    }

    #[test]
    fn long_episode_closes_by_max_dwell() {
        // A strong sustained drift held past max_dwell closes by the cap.
        let cfg = RegimeConfig {
            max_dwell: 32,
            ..CFG
        };
        let mut series = Vec::new();
        for i in 0..300u64 {
            series.push((i, i.saturating_mul(2)));
        }
        let (_, episodes) = run_series(cfg, &series);
        assert!(!episodes.is_empty());
        assert_eq!(episodes[0].closed_by, EpisodeClose::MaxDwell);
        assert_eq!(episodes[0].dwell, 32);
    }

    #[test]
    fn slew_direction_reversal_recovers() {
        // Ramp up, ramp back down, then flat: the episode stays open through
        // the reversed slope (a sustained opposite drift is still drift) and
        // closes only when the signal settles.
        let mut series = Vec::new();
        for i in 0..200u64 {
            series.push((i, i));
        }
        for i in 200..400u64 {
            series.push((i, 400 - i));
        }
        for i in 400..600u64 {
            series.push((i, 0)); // settle
        }
        let (state, episodes) = run_series(CFG, &series);
        assert!(!episodes.is_empty());
        assert!(state == RegimeState::Recovering || state == RegimeState::Stable);
    }

    #[test]
    fn deterministic_replay_of_series() {
        let series: Vec<(u64, u64)> = (0..500).map(|i| (i, (i * 7) % 130)).collect();
        let (s1, e1) = run_series(CFG, &series);
        let (s2, e2) = run_series(CFG, &series);
        assert_eq!(s1, s2);
        assert_eq!(e1, e2);
    }

    #[test]
    fn second_episode_can_open_after_recovery() {
        // Two separate ramps with a flat stretch between them: two episodes.
        let mut series = Vec::new();
        let mut i = 0u64;
        for _ in 0..150 {
            series.push((i, i));
            i += 1;
        }
        for _ in 0..200 {
            series.push((i, 150));
            i += 1;
        }
        for k in 0..150u64 {
            series.push((i, 150 + k));
            i += 1;
        }
        for _ in 0..200 {
            series.push((i, 300)); // flat tail so episode 2 closes
            i += 1;
        }
        let (state, episodes) = run_series(CFG, &series);
        assert_eq!(episodes.len(), 2);
        assert!(state == RegimeState::Recovering || state == RegimeState::Stable);
    }

    #[test]
    fn observer_exposes_state_machine() {
        let mut obs = RegimeObserver::new(CFG);
        assert_eq!(obs.state(), RegimeState::Stable);
        for v in 0..100u64 {
            obs.feed(v, v);
        }
        // By value 100 the cumulative deviation is 100 >= 32 and the EMA is
        // well above the drift threshold.
        assert!(obs.episode_open());
        assert!(obs.cumulative() >= 32);
    }

    #[test]
    fn state_and_close_codes_are_stable() {
        assert_eq!(RegimeState::Stable.code(), 0);
        assert_eq!(RegimeState::Drift.code(), 1);
        assert_eq!(RegimeState::InEpisode.code(), 2);
        assert_eq!(RegimeState::Recovering.code(), 3);
        assert_eq!(EpisodeClose::RecoveryDwell.code(), 1);
        assert_eq!(EpisodeClose::MaxDwell.code(), 2);
        assert_eq!(RegimeState::from_byte(9), None);
        assert_eq!(EpisodeClose::from_byte(9), None);
    }
}
