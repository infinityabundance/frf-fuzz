//! Phase-8 scientific evaluation machinery (master prompt §31-§33).
//!
//! This module is the experiment instrument: repeated independent trials over
//! the four code-level ablation arms, raw-series export that preserves every
//! per-trial measurement, and non-parametric comparison (median/quartiles,
//! Vargha-Delaney A12, Mann-Whitney U) that never bakes a conclusion into the
//! CLI. The full methodology is fixed in `docs/EXPERIMENT_PROTOCOL.md`; the
//! numbers this module prints are raw facts plus the protocol's power caveat.
//!
//! # The ablation arms
//!
//! The mandatory ablation ladder (protocol §2) is implemented here as four
//! code-level arms over the campaign's three feedback switches. Each arm is a
//! frozen delta applied to one base policy, so the ONLY difference between
//! arms is the feedback channel under test:
//!
//! | arm | cmp | residual | precedent | ladder rung |
//! |---|---|---|---|---|
//! | `cov` | off | off | off | 1. coverage only |
//! | `cov+cmp` | on | off | off | 2. + compare operands |
//! | `residual` | on | on | off | 3.-4. + residual sketch + DSFB structure |
//! | `full` | on | on | on | 5. + precedent scheduling |
//!
//! Rungs 6-9 of the ladder are separate orthogonal axes, not switches on one
//! campaign: Gemel revision memory is a revision-study axis (durable
//! boundaries, Phase 4), AVX2 is a constant measured optimization that cannot
//! change semantics (I3), GPU acceleration is not admitted on any device
//! (Phase 7 record), and "full system" = `full` + an FRF authority when one
//! is configured.
//!
//! # Trial hygiene
//!
//! Every trial runs in its own fresh store with its own seed, so trials are
//! independent; arm *i* trials share their seed sequence with arm *j* trials
//! (paired structure — the only difference is the arm). The raw per-trial
//! series is exported as CSV with the protocol's mandatory environment
//! metadata in comment lines, so every statistic is recomputable from the
//! export (`read_series` + [`analyze`]).
//!
//! # Censoring
//!
//! Time/executions-to-first-failure are right-censored: a trial that never
//! fails records no value. Censored trials are never silently dropped — they
//! appear as `found`/`censored` counts per arm, and arm-pair statistics on
//! censored metrics use the complete-case subset (both arms found a failure)
//! and say so. The CLI never prints an unsupported statistical claim.

pub mod stats;

use crate::error::{Error, Result};
use crate::execute::coordinator::{run_campaign, CampaignConfig, CampaignSummary};
use crate::scheduler::policy::SchedulePolicy;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Upper bound on trials per arm (protects the export and the wall clock
/// from absurd requests; a FuzzBench-scale campaign is a batch job, not a
/// single CLI invocation).
pub const MAX_TRIALS: u32 = 1000;

// ---------------------------------------------------------------------------
// Ablation arms
// ---------------------------------------------------------------------------

/// The four code-level ablation arms (docs/EXPERIMENT_PROTOCOL.md §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AblationArm {
    /// Coverage only: no compare guidance, no residual machinery, no
    /// precedent scheduling (ladder rung 1).
    Cov,
    /// Coverage + compare operands (ladder rung 2).
    CovCmp,
    /// Coverage + cmp + residual sketch + DSFB structural analysis (ladder
    /// rungs 3-4; `precedent` stays off).
    Residual,
    /// The full code-level system: residual + DSFB + precedent scheduling
    /// (ladder rung 5).
    Full,
}

impl AblationArm {
    /// All arms in fixed order (also the export sort order).
    pub const ALL: [AblationArm; 4] = [
        AblationArm::Cov,
        AblationArm::CovCmp,
        AblationArm::Residual,
        AblationArm::Full,
    ];

    /// Parse an arm code (`cov`, `cov+cmp`, `residual`, `full`).
    pub fn parse(s: &str) -> Option<AblationArm> {
        match s.trim() {
            "cov" => Some(AblationArm::Cov),
            "cov+cmp" => Some(AblationArm::CovCmp),
            "residual" => Some(AblationArm::Residual),
            "full" => Some(AblationArm::Full),
            _ => None,
        }
    }

    /// The stable export code.
    pub const fn code(self) -> &'static str {
        match self {
            AblationArm::Cov => "cov",
            AblationArm::CovCmp => "cov+cmp",
            AblationArm::Residual => "residual",
            AblationArm::Full => "full",
        }
    }

    /// Human-readable label.
    pub const fn name(self) -> &'static str {
        match self {
            AblationArm::Cov => "coverage only",
            AblationArm::CovCmp => "coverage + cmp",
            AblationArm::Residual => "coverage + cmp + residual",
            AblationArm::Full => "full system",
        }
    }

    /// Whether the arm enables compare guidance.
    pub const fn cmp(self) -> bool {
        !matches!(self, AblationArm::Cov)
    }

    /// Whether the arm enables the residual machinery.
    pub const fn residual(self) -> bool {
        matches!(self, AblationArm::Residual | AblationArm::Full)
    }

    /// Whether the arm enables precedent scheduling (requires residual).
    pub const fn precedent(self) -> bool {
        matches!(self, AblationArm::Full)
    }

    /// Apply the arm's frozen feedback-channel deltas to a policy. All other
    /// fields (workers, batch size, weights, bounds, timeouts) are inherited
    /// from the caller's base policy untouched.
    pub fn apply(self, p: &mut SchedulePolicy) {
        p.cmp = self.cmp();
        p.residual = self.residual();
        p.precedent = self.precedent();
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// One per-trial measurement (a subset of the protocol §3 metric list that a
/// single local campaign can observe without an external authority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Metric {
    /// Executions attempted.
    Executions,
    /// Executions per second of wall time.
    ExecsPerSec,
    /// Corpus entries at campaign end.
    CorpusEntries,
    /// Distinct coverage features at campaign end.
    CoverageFeatures,
    /// Distinct (signal, value-bucket) state features.
    StateFeatures,
    /// Distinct morphology structural identities.
    Morphologies,
    /// Closed regime episodes.
    RegimeEpisodes,
    /// Boundary witnesses written.
    Boundaries,
    /// Findings recorded.
    Findings,
    /// AMPLIFY orders dispatched.
    AmplifyOrders,
    /// Precedent families matched.
    PrecedentMatches,
    /// Probe orders dispatched.
    ProbesDispatched,
    /// Probe contradictions recorded (negative knowledge).
    ProbeContradictions,
    /// Executions before the first failure finding (right-censored).
    FirstFailureExec,
    /// Seconds before the first failure finding (right-censored).
    FirstFailureSeconds,
}

impl Metric {
    /// All metrics in fixed order (the export sort order).
    pub const ALL: [Metric; 15] = [
        Metric::Executions,
        Metric::ExecsPerSec,
        Metric::CorpusEntries,
        Metric::CoverageFeatures,
        Metric::StateFeatures,
        Metric::Morphologies,
        Metric::RegimeEpisodes,
        Metric::Boundaries,
        Metric::Findings,
        Metric::AmplifyOrders,
        Metric::PrecedentMatches,
        Metric::ProbesDispatched,
        Metric::ProbeContradictions,
        Metric::FirstFailureExec,
        Metric::FirstFailureSeconds,
    ];

    /// Parse a metric code (the stable export code).
    pub fn parse(s: &str) -> Option<Metric> {
        Metric::ALL.iter().copied().find(|m| m.code() == s)
    }

    /// The stable export code.
    pub const fn code(self) -> &'static str {
        match self {
            Metric::Executions => "executions",
            Metric::ExecsPerSec => "execs_per_sec",
            Metric::CorpusEntries => "corpus_entries",
            Metric::CoverageFeatures => "coverage_features",
            Metric::StateFeatures => "state_features",
            Metric::Morphologies => "morphologies",
            Metric::RegimeEpisodes => "regime_episodes",
            Metric::Boundaries => "boundaries",
            Metric::Findings => "findings",
            Metric::AmplifyOrders => "amplify_orders",
            Metric::PrecedentMatches => "precedent_matches",
            Metric::ProbesDispatched => "probes_dispatched",
            Metric::ProbeContradictions => "probe_contradictions",
            Metric::FirstFailureExec => "first_failure_exec",
            Metric::FirstFailureSeconds => "first_failure_seconds",
        }
    }

    /// The measurement unit (for the export and human tables).
    pub const fn unit(self) -> &'static str {
        match self {
            Metric::Executions => "exec",
            Metric::ExecsPerSec => "exec/s",
            Metric::CorpusEntries => "entries",
            Metric::CoverageFeatures => "features",
            Metric::StateFeatures => "features",
            Metric::Morphologies => "signatures",
            Metric::RegimeEpisodes => "episodes",
            Metric::Boundaries => "witnesses",
            Metric::Findings => "findings",
            Metric::AmplifyOrders => "orders",
            Metric::PrecedentMatches => "matches",
            Metric::ProbesDispatched => "orders",
            Metric::ProbeContradictions => "records",
            Metric::FirstFailureExec => "exec",
            Metric::FirstFailureSeconds => "s",
        }
    }

    /// A short human label.
    pub const fn label(self) -> &'static str {
        match self {
            Metric::Executions => "executions",
            Metric::ExecsPerSec => "exec/s",
            Metric::CorpusEntries => "corpus",
            Metric::CoverageFeatures => "coverage features",
            Metric::StateFeatures => "state features",
            Metric::Morphologies => "morphologies",
            Metric::RegimeEpisodes => "regime episodes",
            Metric::Boundaries => "boundary witnesses",
            Metric::Findings => "findings",
            Metric::AmplifyOrders => "amplify orders",
            Metric::PrecedentMatches => "precedent matches",
            Metric::ProbesDispatched => "probe orders",
            Metric::ProbeContradictions => "probe contradictions",
            Metric::FirstFailureExec => "exec to first failure",
            Metric::FirstFailureSeconds => "seconds to first failure",
        }
    }

    /// Whether the metric is right-censored: a trial that never produced a
    /// failure records no value, and that absence is itself information
    /// (never silently dropped, never treated as a number).
    pub const fn censored(self) -> bool {
        matches!(self, Metric::FirstFailureExec | Metric::FirstFailureSeconds)
    }

    /// The value of a metric for one campaign summary. Censored metrics
    /// return `None` when the trial found no failure.
    pub fn value_of(self, s: &CampaignSummary) -> Option<f64> {
        match self {
            Metric::Executions => Some(s.executions as f64),
            Metric::ExecsPerSec => {
                let secs = s.duration.as_secs_f64();
                if secs > 0.0 {
                    Some(s.executions as f64 / secs)
                } else {
                    None
                }
            }
            Metric::CorpusEntries => Some(s.corpus_entries as f64),
            Metric::CoverageFeatures => Some(s.features as f64),
            Metric::StateFeatures => Some(s.state_features as f64),
            Metric::Morphologies => Some(s.morphologies as f64),
            Metric::RegimeEpisodes => Some(s.regimes as f64),
            Metric::Boundaries => Some(s.boundaries as f64),
            Metric::Findings => Some(s.findings as f64),
            Metric::AmplifyOrders => Some(s.amplify_orders as f64),
            Metric::PrecedentMatches => Some(s.precedent_matches as f64),
            Metric::ProbesDispatched => Some(s.probes_dispatched as f64),
            Metric::ProbeContradictions => Some(s.probe_contradictions as f64),
            Metric::FirstFailureExec => s.first_failure_exec.map(|v| v as f64),
            Metric::FirstFailureSeconds => s.first_failure_elapsed.map(|d| d.as_secs_f64()),
        }
    }
}

// ---------------------------------------------------------------------------
// The raw series
// ---------------------------------------------------------------------------

/// One recorded trial measurement: one (arm, trial, metric) observation.
///
/// `value` is `None` exactly when the metric is right-censored for that
/// trial (a failure metric with no failure); a censored observation is
/// preserved as a row, never dropped.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrialRow {
    /// The arm.
    pub arm: AblationArm,
    /// Trial ordinal within the arm (0-based).
    pub trial: u32,
    /// The trial's campaign seed (independent per trial, shared across
    /// arms — see module docs).
    pub seed: u64,
    /// The metric.
    pub metric: Metric,
    /// The measured value; `None` = censored (no failure in budget).
    pub value: Option<f64>,
}

/// Deterministic per-trial seed derivation (splitmix64 over the base seed
/// and the trial ordinal). Trials are independent; arm *i* trial *t* uses the
/// same seed as arm *j* trial *t*, so the arms differ only in their frozen
/// feedback-channel config.
pub fn trial_seed(base: u64, trial: u32) -> u64 {
    let mut x = base
        .wrapping_add(u64::from(trial).wrapping_mul(0x9E37_79B9_7F4A_7C15))
        .wrapping_add(0xD1B5_4A32_D192_ED03);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// The `#` metadata lines of a series export (key -> value).
pub type SeriesMeta = Vec<(String, String)>;

/// Write the raw series to a CSV file. The first lines are `#`-prefixed
/// metadata (operational: host identity, toolchain, config — the protocol's
/// mandatory record); data rows follow the documented header. The file is
/// the authoritative export: every statistic is recomputable from it.
pub fn write_series(path: &Path, metadata: &[(&str, String)], rows: &[TrialRow]) -> Result<()> {
    let mut out = String::new();
    out.push_str("# frf-fuzz experiment series\n");
    for (k, v) in metadata {
        out.push_str(&format!("# {}: {}\n", k, v.replace('\n', " ")));
    }
    out.push_str("arm,trial,seed,metric,unit,value\n");
    for r in rows {
        let value = match r.value {
            Some(v) => format!("{v:.6}"),
            None => "NA".to_string(), // censored
        };
        out.push_str(&format!(
            "{},{},{},{},{},{}\n",
            r.arm.code(),
            r.trial,
            r.seed,
            r.metric.code(),
            r.metric.unit(),
            value
        ));
    }
    crate::store::atomic_write(path, out.as_bytes())?;
    Ok(())
}

/// Parse a series CSV written by [`write_series`]. Returns the `#` metadata
/// lines (key -> value) plus the data rows in file order.
pub fn read_series(path: &Path) -> Result<(SeriesMeta, Vec<TrialRow>)> {
    let content = std::fs::read_to_string(path)?;
    let mut meta = Vec::new();
    let mut rows = Vec::new();
    let mut in_header = true;
    for (line_no, line) in content.lines().enumerate() {
        if in_header {
            if let Some(rest) = line.strip_prefix("# ") {
                if let Some((k, v)) = rest.split_once(": ") {
                    meta.push((k.to_string(), v.to_string()));
                }
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            // The first non-comment line must be the column header.
            if line != "arm,trial,seed,metric,unit,value" {
                return Err(Error::Other(format!(
                    "series CSV line {}: unexpected header {line:?}",
                    line_no + 1
                )));
            }
            in_header = false;
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() != 6 {
            return Err(Error::Other(format!(
                "series CSV line {}: expected 6 columns, got {}",
                line_no + 1,
                cols.len()
            )));
        }
        let arm = AblationArm::parse(cols[0]).ok_or_else(|| {
            Error::Other(format!(
                "series CSV line {}: unknown arm {:?}",
                line_no + 1,
                cols[0]
            ))
        })?;
        let trial: u32 = cols[1].parse().map_err(|_| {
            Error::Other(format!(
                "series CSV line {}: bad trial {:?}",
                line_no + 1,
                cols[1]
            ))
        })?;
        let seed: u64 = cols[2].parse().map_err(|_| {
            Error::Other(format!(
                "series CSV line {}: bad seed {:?}",
                line_no + 1,
                cols[2]
            ))
        })?;
        let metric = Metric::parse(cols[3]).ok_or_else(|| {
            Error::Other(format!(
                "series CSV line {}: unknown metric {:?}",
                line_no + 1,
                cols[3]
            ))
        })?;
        let value = match cols[5] {
            "NA" => None,
            v => {
                let parsed: f64 = v.parse().map_err(|_| {
                    Error::Other(format!(
                        "series CSV line {}: bad value {:?}",
                        line_no + 1,
                        v
                    ))
                })?;
                // Export always writes finite values; a non-finite value in
                // an export is hostile or corrupt and is refused (it would
                // silently poison every statistic).
                if !parsed.is_finite() {
                    return Err(Error::Other(format!(
                        "series CSV line {}: non-finite value {:?}",
                        line_no + 1,
                        v
                    )));
                }
                Some(parsed)
            }
        };
        rows.push(TrialRow {
            arm,
            trial,
            seed,
            metric,
            value,
        });
    }
    if in_header {
        return Err(Error::Other(
            "series CSV has no data (header missing)".into(),
        ));
    }
    Ok((meta, rows))
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// Per-arm statistics for one metric.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetricStats {
    /// Total trials in the arm.
    pub n: usize,
    /// Trials with an observed (uncensored) value.
    pub found: usize,
    /// Trials with a censored value (failure metric, no failure in budget).
    pub censored: usize,
    /// Median over observed values (`None` when none).
    pub median: Option<f64>,
    /// Lower quartile over observed values.
    pub q1: Option<f64>,
    /// Upper quartile over observed values.
    pub q3: Option<f64>,
}

/// One arm-pair comparison for one metric.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArmComparison {
    /// The left arm (A12 reads: probability a left observation exceeds a
    /// right observation; > 0.5 favors left).
    pub left: AblationArm,
    /// The right arm.
    pub right: AblationArm,
    /// Number of trial pairs used (`n` for uncensored metrics; the
    /// complete-case subset for censored metrics — trials where BOTH arms
    /// observed a value).
    pub n_pairs: usize,
    /// Whether this comparison used the complete-case subset (censored
    /// metric only). Censored trials are excluded because a censored value
    /// cannot enter A12/MWU; the per-arm `found`/`censored` counts carry the
    /// full information.
    pub complete_case: bool,
    /// Vargha-Delaney A12 over the used trials (`None` when no pair is
    /// usable).
    pub a12: Option<f64>,
    /// Mann-Whitney U (two-sided, normal approximation) over the used
    /// trials (`None` when fewer than 2 usable pairs).
    pub mwu: Option<stats::Mwu>,
}

/// Full analysis of one metric across the arms present in a series.
#[derive(Debug, Clone, PartialEq)]
pub struct SeriesAnalysis {
    /// The metric.
    pub metric: Metric,
    /// Per-arm statistics, keyed by arm.
    pub by_arm: BTreeMap<AblationArm, MetricStats>,
    /// The requested arm-pair comparisons.
    pub comparisons: Vec<ArmComparison>,
}

/// Observed (uncensored) values per (arm, trial) for one metric.
fn observed_pairs(rows: &[TrialRow], metric: Metric, arm: AblationArm) -> Vec<(u32, f64)> {
    let mut v: Vec<(u32, f64)> = rows
        .iter()
        .filter(|r| r.metric == metric && r.arm == arm)
        .filter_map(|r| r.value.map(|v| (r.trial, v)))
        .collect();
    v.sort_by_key(|a| a.0);
    v
}

fn stats_of(values: &[f64], n_total: usize) -> MetricStats {
    let found = values.len();
    let (q1, q3) = match stats::quartiles(values) {
        Some((a, _m, b)) => (Some(a), Some(b)),
        None => (None, None),
    };
    MetricStats {
        n: n_total,
        found,
        censored: n_total.saturating_sub(found),
        median: stats::median(values),
        q1,
        q3,
    }
}

/// Analyze a raw series: per-arm statistics for every metric present, plus
/// the requested arm-pair comparisons. Pure and deterministic — this is the
/// function the CLI renders and the tests recompute from exports.
pub fn analyze(rows: &[TrialRow], pairs: &[(AblationArm, AblationArm)]) -> Vec<SeriesAnalysis> {
    let mut out = Vec::new();
    for metric in Metric::ALL {
        if !rows.iter().any(|r| r.metric == metric) {
            continue;
        }
        let mut by_arm = BTreeMap::new();
        for arm in AblationArm::ALL {
            // Row presence (not observed-value presence) defines arm
            // participation: a fully-censored arm still reports n/censored
            // (failure to reproduce is preserved, protocol §5).
            let n_total = rows
                .iter()
                .filter(|r| r.metric == metric && r.arm == arm)
                .count();
            if n_total == 0 {
                continue;
            }
            let values: Vec<f64> = observed_pairs(rows, metric, arm)
                .iter()
                .map(|(_, v)| *v)
                .collect();
            by_arm.insert(arm, stats_of(&values, n_total));
        }
        let comparisons = pairs
            .iter()
            .copied()
            .filter(|(a, b)| by_arm.contains_key(a) && by_arm.contains_key(b) && *a != *b)
            .map(|(left, right)| compare_arms(rows, metric, left, right))
            .collect();
        out.push(SeriesAnalysis {
            metric,
            by_arm,
            comparisons,
        });
    }
    out
}

fn compare_arms(
    rows: &[TrialRow],
    metric: Metric,
    left: AblationArm,
    right: AblationArm,
) -> ArmComparison {
    let lv = observed_pairs(rows, metric, left);
    let rv = observed_pairs(rows, metric, right);
    let (lvals, rvals, complete_case) = if metric.censored() {
        // Complete-case subset: trials where BOTH arms observed a value.
        let lmap: BTreeMap<u32, f64> = lv.iter().copied().collect();
        let rmap: BTreeMap<u32, f64> = rv.iter().copied().collect();
        let trials: Vec<u32> = lmap
            .keys()
            .copied()
            .filter(|t| rmap.contains_key(t))
            .collect();
        let lv: Vec<f64> = trials.iter().map(|t| lmap[t]).collect();
        let rv: Vec<f64> = trials.iter().map(|t| rmap[t]).collect();
        (lv, rv, true)
    } else {
        (
            lv.iter().map(|(_, v)| *v).collect(),
            rv.iter().map(|(_, v)| *v).collect(),
            false,
        )
    };
    let n_pairs = lvals.len().min(rvals.len());
    let (a12, mwu) = if n_pairs == 0 {
        (None, None)
    } else {
        let a12 = stats::a12(&lvals, &rvals);
        // Mann-Whitney needs a usable variance; below 2 pairs per sample the
        // normal approximation is not defined (z would be vacuous).
        let mwu = if n_pairs >= 2 {
            stats::mann_whitney_u(&lvals, &rvals)
        } else {
            None
        };
        (a12, mwu)
    };
    ArmComparison {
        left,
        right,
        n_pairs,
        complete_case,
        a12,
        mwu,
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// Everything an experiment run needs (the campaign-constant subset of a
/// [`CampaignConfig`] plus the experiment dimensions). The base policy's
/// feedback switches are overridden per arm by [`AblationArm::apply`]; its
/// other fields are the frozen hyperparameters shared by every trial.
#[derive(Debug, Clone)]
pub struct ExperimentSpec {
    /// Target name (campaign metadata).
    pub target_name: String,
    /// The instrumented target binary path.
    pub target_bin: PathBuf,
    /// Arms to run (non-empty, deduplicated in [`AblationArm::ALL`] order).
    pub arms: Vec<AblationArm>,
    /// Trials per arm (1..=[`MAX_TRIALS`]).
    pub trials: u32,
    /// Base scheduling policy (workers, batch size, weights, bounds). The
    /// feedback switches are forced per arm.
    pub base_policy: SchedulePolicy,
    /// Base campaign seed; trial seeds derive from it deterministically
    /// ([`trial_seed`]).
    pub base_seed: u64,
    /// Seed inputs directory (shared, read-only across trials).
    pub seed_dir: Option<PathBuf>,
    /// Per-trial wall-clock budget.
    pub max_time: std::time::Duration,
    /// Optional per-trial execution cap.
    pub max_execs: Option<u64>,
    /// Sanitizer mode for worker spawns.
    pub sanitizer: crate::execute::worker_process::SanitizerMode,
    /// Optional RLIMIT_AS per worker in MiB.
    pub memory_limit_mb: u64,
    /// Initial user dictionary (empty for ablations).
    pub initial_dictionary: Vec<Vec<u8>>,
    /// rustc release line of the instrumented build (metadata).
    pub rustc_release: String,
    /// LLVM version line of the instrumented build (metadata).
    pub llvm_version: String,
    /// The exact instrumented-build flags (metadata).
    pub instrument_flags: Vec<String>,
    /// The nightly toolchain used for the instrumented build (metadata).
    pub nightly: String,
    /// Output root; the record directory `<root>/<expid>/<run-ts>/` is
    /// created under it.
    pub out_root: PathBuf,
}

/// The durable record of one experiment run.
#[derive(Debug, Clone)]
pub struct ExperimentRecord {
    /// The record directory (series, metadata and analysis live here).
    pub dir: PathBuf,
    /// The raw-series CSV path.
    pub series_path: PathBuf,
    /// All trial rows (sorted: arm order, trial, metric order).
    pub series: Vec<TrialRow>,
    /// The analysis (per metric present).
    pub analysis: Vec<SeriesAnalysis>,
    /// The metadata JSON (operational sidecar).
    pub meta_json: String,
    /// The human analysis table.
    pub analysis_text: String,
}

/// The experiment identity: BLAKE3 over the canonical descriptor (target
/// identity, arms, trials, base seed, policy knobs, budget). Paths and wall
/// clocks are excluded so identical experiments group under one id; the
/// run-ts subdirectory keeps repeated runs distinct.
fn experiment_id(spec: &ExperimentSpec) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"frf-fuzz-experiment-v1\0");
    h.update(spec.target_name.as_bytes());
    h.update(&[0]);
    for a in &spec.arms {
        h.update(a.code().as_bytes());
        h.update(&[0]);
    }
    h.update(&spec.trials.to_le_bytes());
    h.update(&spec.base_seed.to_le_bytes());
    h.update(&spec.base_policy.workers.to_le_bytes());
    h.update(&spec.base_policy.batch_size.to_le_bytes());
    h.update(&spec.base_policy.timeout_ms.to_le_bytes());
    h.update(&spec.base_policy.max_corpus_entries.to_le_bytes());
    h.update(&spec.base_policy.max_features_per_order.to_le_bytes());
    for w in spec.base_policy.class_weights {
        h.update(&w.to_le_bytes());
    }
    h.update(&spec.base_policy.amplify_min_count.to_le_bytes());
    h.update(&spec.base_policy.amplify_min_run.to_le_bytes());
    h.update(&spec.base_policy.amplify_min_sum_bucket.to_le_bytes());
    h.update(&spec.max_time.as_nanos().to_le_bytes());
    h.update(&spec.max_execs.unwrap_or(0).to_le_bytes());
    for d in &spec.initial_dictionary {
        h.update(d);
        h.update(&[0]);
    }
    *h.finalize().as_bytes()
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Minimal JSON string escaping (no serde dependency; the sidecar is
/// operational, not canonical).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Best-effort host metadata (operational; every field falls back to
/// "unknown" — the record must never fail because the environment is odd).
fn host_metadata() -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    v.push(("os", std::env::consts::OS.to_string()));
    v.push(("arch", std::env::consts::ARCH.to_string()));
    let cores = std::thread::available_parallelism()
        .map(|n| n.get().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    v.push(("cores", cores));
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    v.push(("kernel", kernel));
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, rest)| rest.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    v.push(("cpu", cpu));
    v
}

/// Run one trial of one arm in a fresh store. Returns the trial's rows
/// (every metric) plus the summary.
fn run_trial(
    spec: &ExperimentSpec,
    arm: AblationArm,
    trial: u32,
    seed: u64,
    store_root: &Path,
) -> Result<(Vec<TrialRow>, CampaignSummary)> {
    let mut policy = spec.base_policy.clone();
    arm.apply(&mut policy);
    policy.seed = seed;
    let cfg = CampaignConfig {
        target_bin: spec.target_bin.clone(),
        store_root: store_root.to_path_buf(),
        policy,
        sanitizer: spec.sanitizer,
        memory_limit_mb: spec.memory_limit_mb,
        seed_dir: spec.seed_dir.clone(),
        target_name: spec.target_name.clone(),
        max_time: Some(spec.max_time),
        max_execs: spec.max_execs,
        initial_dictionary: spec.initial_dictionary.clone(),
        rustc_release: spec.rustc_release.clone(),
        llvm_version: spec.llvm_version.clone(),
        instrument_flags: spec.instrument_flags.clone(),
        // Ablation trials are authority-less by design: FRF/Gemel are
        // orthogonal axes (protocol §2 rungs 6-9), and an experiment must
        // not fabricate an authority.
        authority: None,
        question: crate::frf_bridge::CourtQuestion::default(),
        verification_candidate: None,
        verify_claim: false,
        gemel: false,
    };
    let summary = run_campaign(&cfg)?;
    let mut rows = Vec::new();
    for metric in Metric::ALL {
        if let Some(v) = metric.value_of(&summary) {
            rows.push(TrialRow {
                arm,
                trial,
                seed,
                metric,
                value: Some(v),
            });
        } else {
            // Censored (failure metric, no failure): preserve as a row with
            // no value — the absence is information (protocol §5: failure
            // to reproduce is preserved, never discarded).
            rows.push(TrialRow {
                arm,
                trial,
                seed,
                metric,
                value: None,
            });
        }
    }
    Ok((rows, summary))
}

/// Run the full experiment: every trial of every arm in independent fresh
/// stores, export the raw series + metadata, compute the analysis, and
/// return the durable record. Never raises the process's own SIGINT handler
/// expectations: callers install it once (the coordinator's handler is
/// process-global and idempotent).
pub fn run_experiment(spec: &ExperimentSpec) -> Result<ExperimentRecord> {
    if spec.arms.is_empty() {
        return Err(Error::Other(
            "experiment: at least one arm is required".into(),
        ));
    }
    let mut arms: Vec<AblationArm> = Vec::new();
    for a in AblationArm::ALL {
        if spec.arms.contains(&a) && !arms.contains(&a) {
            arms.push(a);
        }
    }
    if arms.is_empty() {
        return Err(Error::Other("experiment: no valid arms".into()));
    }
    if spec.trials == 0 || spec.trials > MAX_TRIALS {
        return Err(Error::Other(format!(
            "experiment: trials must be in 1..={MAX_TRIALS}"
        )));
    }

    // The run timestamp is operational metadata (never part of any canonical
    // identity); it keeps repeated runs of one experiment distinct while the
    // deterministic experiment id groups them.
    let id = hex32(&experiment_id(spec));
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dir = spec.out_root.join(&id).join(ts.to_string());
    crate::store::ensure_dir(&dir)?;
    let trials_dir = dir.join("trials");

    eprintln!(
        "[experiment] id={id} target={} arms={} trials={} budget={:.0}s base-seed={:#x}",
        spec.target_name,
        arms.len(),
        spec.trials,
        spec.max_time.as_secs_f64(),
        spec.base_seed
    );

    let mut rows: Vec<TrialRow> = Vec::new();
    for arm in &arms {
        for trial in 0..spec.trials {
            let seed = trial_seed(spec.base_seed, trial);
            let store_root = trials_dir.join(arm.code()).join(format!("trial-{trial}"));
            crate::store::ensure_dir(&store_root)?;
            let (trows, summary) = run_trial(spec, *arm, trial, seed, &store_root)?;
            let found = summary.findings;
            eprintln!(
                "[experiment] arm={:<8} trial={}/{} seed={:#016x} execs={} corpus={} findings={} duration={:.1}s",
                arm.code(),
                trial + 1,
                spec.trials,
                seed,
                summary.executions,
                summary.corpus_entries,
                found,
                summary.duration.as_secs_f64()
            );
            rows.extend(trows);
        }
    }
    rows.sort_by(|a, b| {
        arm_index(a.arm)
            .cmp(&arm_index(b.arm))
            .then(a.trial.cmp(&b.trial))
            .then(metric_index(a.metric).cmp(&metric_index(b.metric)))
    });

    // ---- metadata sidecar ----
    let mut meta: Vec<(&'static str, String)> = Vec::new();
    meta.push(("experiment_id", id.clone()));
    meta.push(("target", spec.target_name.clone()));
    meta.push(("target_bin", spec.target_bin.display().to_string()));
    meta.push((
        "arms",
        arms.iter().map(|a| a.code()).collect::<Vec<_>>().join(","),
    ));
    meta.push(("trials", spec.trials.to_string()));
    meta.push(("base_seed", format!("{:#x}", spec.base_seed)));
    let trial_seeds: Vec<String> = (0..spec.trials)
        .map(|t| format!("{:#x}", trial_seed(spec.base_seed, t)))
        .collect();
    meta.push(("trial_seeds", trial_seeds.join(",")));
    meta.push(("budget_secs", format!("{:.3}", spec.max_time.as_secs_f64())));
    meta.push((
        "policy",
        format!(
            "workers={} batch={} timeout_ms={} weights={:?} max_corpus={}",
            spec.base_policy.workers,
            spec.base_policy.batch_size,
            spec.base_policy.timeout_ms,
            spec.base_policy.class_weights,
            spec.base_policy.max_corpus_entries
        ),
    ));
    meta.push(("nightly", spec.nightly.clone()));
    meta.push(("rustc", spec.rustc_release.clone()));
    meta.push(("llvm", spec.llvm_version.clone()));
    meta.push(("instrument_flags", spec.instrument_flags.join(" ")));
    meta.push(("dictionary", spec.initial_dictionary.len().to_string()));
    meta.push(("sanitizer", spec.sanitizer.env_value().to_string()));
    meta.push(("memory_limit_mb", spec.memory_limit_mb.to_string()));
    meta.extend(host_metadata());
    meta.push((
        "created_unix_secs",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
    ));

    let series_path = dir.join("series.csv");
    let meta_refs: Vec<(&str, String)> = meta.iter().map(|(k, v)| (*k, v.clone())).collect();
    write_series(&series_path, &meta_refs, &rows)?;

    // ---- analysis ----
    let adjacent: Vec<(AblationArm, AblationArm)> = arms.windows(2).map(|w| (w[0], w[1])).collect();
    let analysis = analyze(&rows, &adjacent);

    // Human table.
    let mut text = String::new();
    text.push_str(&format!(
        "frf-fuzz experiment {} — {} trials per arm, {:.0}s budget per trial\n",
        id,
        spec.trials,
        spec.max_time.as_secs_f64()
    ));
    text.push_str(&format!(
        "target: {} | nightly: {} | rustc: {}\n",
        spec.target_name, spec.nightly, spec.rustc_release
    ));
    for a in &analysis {
        render_metric(&mut text, a);
    }
    text.push_str(&protocol_caveat());
    let analysis_path = dir.join("analysis.txt");
    crate::store::atomic_write(&analysis_path, text.as_bytes())?;

    // JSON sidecar (flat, documented shape).
    let mut j = String::from("{\n");
    for (k, v) in &meta {
        j.push_str(&format!("  {}: {},\n", json_str(k), json_str(v)));
    }
    j.push_str(&format!(
        "  {}: {}\n}}\n",
        json_str("analysis_series"),
        json_str(&series_path.display().to_string())
    ));
    let meta_json = j;
    let meta_path = dir.join("meta.json");
    crate::store::atomic_write(&meta_path, meta_json.as_bytes())?;

    Ok(ExperimentRecord {
        dir,
        series_path,
        series: rows,
        analysis,
        meta_json,
        analysis_text: text,
    })
}

fn arm_index(a: AblationArm) -> usize {
    AblationArm::ALL
        .iter()
        .position(|x| *x == a)
        .unwrap_or(usize::MAX)
}

fn metric_index(m: Metric) -> usize {
    Metric::ALL
        .iter()
        .position(|x| *x == m)
        .unwrap_or(usize::MAX)
}

/// Render one metric's analysis block into the human table.
fn render_metric(out: &mut String, a: &SeriesAnalysis) {
    out.push_str(&format!("\n{} ({})\n", a.metric.label(), a.metric.unit()));
    for arm in AblationArm::ALL {
        let Some(st) = a.by_arm.get(&arm) else {
            continue;
        };
        let med = fmt_opt(st.median);
        let q = match (st.q1, st.q3) {
            (Some(q1), Some(q3)) => format!(" [{q1:.3}, {q3:.3}]"),
            _ => String::new(),
        };
        let cens = if a.metric.censored() {
            format!(" found={}/{} censored={}", st.found, st.n, st.censored)
        } else {
            format!(" n={}", st.n)
        };
        out.push_str(&format!(
            "  {:<22} median={:<12}  {}{}\n",
            arm.code(),
            med,
            q.trim_start(),
            cens
        ));
    }
    for c in &a.comparisons {
        let a12 = match c.a12 {
            Some(v) => format!("{v:.3}"),
            None => "n/a".to_string(),
        };
        let p = match c.mwu {
            Some(m) => format!("{:.4}", m.p_two_sided),
            None => "n/a".to_string(),
        };
        let z = match c.mwu {
            Some(m) => format!("{:.2}", m.z),
            None => "n/a".to_string(),
        };
        let cc = if c.complete_case {
            " (complete-case: censored trials excluded)"
        } else {
            ""
        };
        out.push_str(&format!(
            "  compare {:<8} vs {:<8}: A12(left>right)={} n={}{}  MWU z={} p={}\n",
            c.left.code(),
            c.right.code(),
            a12,
            c.n_pairs,
            cc,
            z,
            p
        ));
    }
}

fn fmt_opt(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:.3}"),
        None => "n/a".to_string(),
    }
}

/// The fixed power caveat printed with every analysis (protocol §3: the CLI
/// reports raw facts; publication-grade conclusions need the repeated-trial
/// minimums and baselines of docs/EXPERIMENT_PROTOCOL.md).
pub fn protocol_caveat() -> String {
    "\nPower caveat (docs/EXPERIMENT_PROTOCOL.md §3): these are raw per-trial \
     facts for THIS machine, toolchain, budget and seed set. Median/A12/MWU at \
     demo trial counts are directional hints, not evidence. Publication-grade \
     claims require the documented repeated-trials minimums, frozen \
     hyperparameters, held-out defects, and cargo-fuzz/AFL++ baselines.\n"
        .to_string()
}

// ---------------------------------------------------------------------------
// Held-out partition (benchmark-leakage control, docs/EXPERIMENT_PROTOCOL.md
// §4)
// ---------------------------------------------------------------------------

/// A deterministic held-out partition of a defect set.
///
/// Benchmark hygiene requires that a historical failure used to CREATE a
/// precursor signature is never also used as a blind test of prediction.
/// This split partitions a set of defect identifiers into a `development`
/// set (allowed to build signatures / tune thresholds) and a `blind` set
/// (reserved for evaluation), with the membership recorded so the partition
/// is auditable. The split is a pure function of the inputs: same ids +
/// same fraction + same seed => same partition.
#[derive(Debug, Clone, PartialEq)]
pub struct HeldOutSplit {
    /// Defect identifiers usable for signature/development work.
    pub development: Vec<u64>,
    /// Defect identifiers reserved for blind evaluation (never used during
    /// development).
    pub blind: Vec<u64>,
    /// The requested blind fraction.
    pub blind_fraction: f64,
    /// The partition seed (recorded for auditability).
    pub seed: u64,
}

/// Split `defect_ids` into development and blind sets (protocol §4).
///
/// Deterministic: ids are sorted, then a Fisher-Yates shuffle is driven by a
/// splitmix64 counter stream derived from (`seed`, count) — no global state,
/// no wall clock. `blind` receives the first `blind_n` shuffled ids where
/// `blind_n` is `(len * blind_fraction).round()` clamped to `1..len-1` (both
/// sides need at least one member, so the partition is meaningful). Returns
/// `Err` for fewer than 2 ids or a fraction outside `(0,1)`.
pub fn held_out_split(defect_ids: &[u64], blind_fraction: f64, seed: u64) -> Result<HeldOutSplit> {
    if !(0.0 < blind_fraction && blind_fraction < 1.0) {
        return Err(Error::Other(
            "held-out blind fraction must be strictly inside (0, 1)".into(),
        ));
    }
    if defect_ids.len() < 2 {
        return Err(Error::Other(
            "held-out split needs at least 2 defect ids".into(),
        ));
    }
    let mut ids: Vec<u64> = defect_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    let len = ids.len();
    let blind_n = ((len as f64) * blind_fraction)
        .round()
        .clamp(1.0, (len - 1) as f64) as usize;
    // Deterministic Fisher-Yates over splitmix64 stream (the same counter
    // discipline as trial seeds — never a global RNG).
    let mut stream = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut next = move || {
        let mut x = stream;
        stream = stream.wrapping_add(0x9E37_79B9_7F4A_7C15);
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^ (x >> 31)
    };
    for i in (1..len).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        ids.swap(i, j);
    }
    let mut blind = ids[..blind_n].to_vec();
    let mut development = ids[blind_n..].to_vec();
    blind.sort_unstable();
    development.sort_unstable();
    Ok(HeldOutSplit {
        development,
        blind,
        blind_fraction,
        seed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(arm: AblationArm, trial: u32, metric: Metric, value: Option<f64>) -> TrialRow {
        TrialRow {
            arm,
            trial,
            seed: trial_seed(0xC0FFEE, trial),
            metric,
            value,
        }
    }

    #[test]
    fn arm_table_is_stable_and_frozen() {
        // Lock the four arms' feedback-channel deltas (module docs table).
        assert_eq!(AblationArm::ALL.len(), 4);
        for arm in AblationArm::ALL {
            let mut p = SchedulePolicy::default();
            arm.apply(&mut p);
            assert_eq!(p.cmp, arm.cmp());
            assert_eq!(p.residual, arm.residual());
            assert_eq!(p.precedent, arm.precedent());
            // The arm must never touch the frozen hyperparameters.
            assert_eq!(p.workers, SchedulePolicy::default().workers);
            assert_eq!(p.batch_size, SchedulePolicy::default().batch_size);
            assert_eq!(p.class_weights, SchedulePolicy::default().class_weights);
        }
        assert!(!AblationArm::Cov.cmp() && !AblationArm::Cov.residual());
        assert!(AblationArm::CovCmp.cmp() && !AblationArm::CovCmp.residual());
        assert!(AblationArm::Residual.cmp() && AblationArm::Residual.residual());
        assert!(!AblationArm::Residual.precedent());
        assert!(AblationArm::Full.cmp() && AblationArm::Full.precedent());
        for code in ["cov", "cov+cmp", "residual", "full"] {
            assert_eq!(AblationArm::parse(code).unwrap().code(), code);
        }
        assert_eq!(AblationArm::parse("bogus"), None);
    }

    #[test]
    fn metric_codes_are_stable_and_unique() {
        let mut codes = std::collections::BTreeSet::new();
        for m in Metric::ALL {
            assert!(codes.insert(m.code()), "duplicate metric code {}", m.code());
            assert_eq!(Metric::parse(m.code()), Some(m));
            assert_eq!(m.censored(), m.code().starts_with("first_failure"));
        }
        assert_eq!(Metric::parse("nope"), None);
    }

    #[test]
    fn trial_seeds_are_distinct_and_deterministic() {
        let s0 = trial_seed(0xABCD, 0);
        let mut seen = std::collections::BTreeSet::new();
        for t in 0..64u32 {
            let s = trial_seed(0xABCD, t);
            assert!(seen.insert(s), "trial seeds must be distinct");
            assert_eq!(s, trial_seed(0xABCD, t), "trial seeds must be pure");
        }
        assert_ne!(s0, trial_seed(0xABCE, 0), "base seed must matter");
    }

    #[test]
    fn analyze_separates_arms_and_reports_medians() {
        // Arm A: no failures (all censored). Arm B: failures at 100..109.
        let mut rows = Vec::new();
        for t in 0..10u32 {
            rows.push(row(AblationArm::Cov, t, Metric::FirstFailureSeconds, None));
            rows.push(row(
                AblationArm::CovCmp,
                t,
                Metric::FirstFailureSeconds,
                Some(100.0 + f64::from(t)),
            ));
            rows.push(row(AblationArm::Cov, t, Metric::ExecsPerSec, Some(1000.0)));
            rows.push(row(
                AblationArm::CovCmp,
                t,
                Metric::ExecsPerSec,
                Some(2000.0),
            ));
        }
        let analysis = analyze(&rows, &[(AblationArm::Cov, AblationArm::CovCmp)]);
        assert_eq!(analysis.len(), 2);
        for a in &analysis {
            assert_eq!(a.comparisons.len(), 1);
            let c = a.comparisons[0];
            match a.metric {
                Metric::ExecsPerSec => {
                    let cov = a.by_arm[&AblationArm::Cov];
                    let cc = a.by_arm[&AblationArm::CovCmp];
                    assert_eq!(cov.n, 10);
                    assert_eq!(cov.median, Some(1000.0));
                    assert_eq!(cc.median, Some(2000.0));
                    assert!(!c.complete_case);
                    assert_eq!(c.n_pairs, 10);
                    // cov (1000) is below cov+cmp (2000) on every pair, so
                    // P(left > right) = 0; the reversal is 1.
                    assert_eq!(c.a12, Some(0.0));
                    let p = c.mwu.unwrap().p_two_sided;
                    assert!(p < 0.01);
                    let rev = compare_arms(
                        &rows,
                        Metric::ExecsPerSec,
                        AblationArm::CovCmp,
                        AblationArm::Cov,
                    );
                    assert_eq!(rev.a12, Some(1.0));
                }
                Metric::FirstFailureSeconds => {
                    let cov = a.by_arm[&AblationArm::Cov];
                    let cc = a.by_arm[&AblationArm::CovCmp];
                    // Cov censored everywhere; the median is over FOUND
                    // trials only (none) — the count carries the truth.
                    assert_eq!(cov.found, 0);
                    assert_eq!(cov.censored, 10);
                    assert_eq!(cov.median, None);
                    assert_eq!(cc.found, 10);
                    assert_eq!(cc.censored, 0);
                    assert_eq!(cc.median, Some(104.5));
                    // Complete-case: zero common trials -> no comparison.
                    assert!(c.complete_case);
                    assert_eq!(c.n_pairs, 0);
                    assert_eq!(c.a12, None);
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn series_csv_round_trips_exactly() {
        let dir =
            std::env::temp_dir().join(format!("frf-fuzz-experiment-csv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::store::ensure_dir(&dir).unwrap();
        let path = dir.join("series.csv");
        let rows = vec![
            row(AblationArm::Cov, 0, Metric::Executions, Some(1000.0)),
            row(AblationArm::Cov, 0, Metric::FirstFailureSeconds, None),
            row(AblationArm::Full, 3, Metric::Findings, Some(2.0)),
            row(AblationArm::Residual, 1, Metric::ExecsPerSec, Some(1234.5)),
        ];
        let meta = vec![
            ("target", "demo".to_string()),
            ("arms", "cov,full".to_string()),
        ];
        write_series(&path, &meta, &rows).unwrap();
        let (got_meta, got_rows) = read_series(&path).unwrap();
        assert_eq!(got_meta.len(), 2);
        assert_eq!(got_meta[0], ("target".to_string(), "demo".to_string()));
        assert_eq!(got_rows, rows);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn series_csv_refuses_malformed_rows() {
        let dir = std::env::temp_dir().join(format!(
            "frf-fuzz-experiment-csv-bad-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        crate::store::ensure_dir(&dir).unwrap();
        let path = dir.join("bad.csv");
        std::fs::write(&path, b"arm,trial,seed,metric,unit,value\ncov,0,1,executions,count,1.0\nbogus,0,1,findings,count,1\n").unwrap();
        assert!(read_series(&path).is_err());
        let path2 = dir.join("bad2.csv");
        std::fs::write(&path2, b"# only comments\n").unwrap();
        assert!(read_series(&path2).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn analyze_is_pure_and_censoring_is_preserved() {
        // Re-running analysis on the same rows is byte-identical, and a
        // trial with no failure is never silently dropped from the counts.
        let mut rows = Vec::new();
        for t in 0..3u32 {
            rows.push(row(AblationArm::Residual, t, Metric::Findings, Some(1.0)));
            rows.push(row(
                AblationArm::Residual,
                t,
                Metric::FirstFailureExec,
                if t == 2 { None } else { Some(500.0) },
            ));
        }
        let a1 = analyze(&rows, &[]);
        let a2 = analyze(&rows, &[]);
        assert_eq!(a1, a2);
        let ff = a1
            .iter()
            .find(|a| a.metric == Metric::FirstFailureExec)
            .unwrap();
        let st = ff.by_arm[&AblationArm::Residual];
        assert_eq!(st.n, 3);
        assert_eq!(st.found, 2);
        assert_eq!(st.censored, 1);
        assert_eq!(st.median, Some(500.0));
    }

    #[test]
    fn held_out_split_is_disjoint_deterministic_and_recorded() {
        let ids: Vec<u64> = (0..20).collect();
        let a = held_out_split(&ids, 0.25, 42).unwrap();
        // Disjoint + covering, both sides non-empty.
        let mut all = a.development.clone();
        all.extend(a.blind.iter().copied());
        all.sort_unstable();
        assert_eq!(all, ids, "partitions must be disjoint and covering");
        assert!(!a.development.is_empty() && !a.blind.is_empty());
        // 25% of 20 = 5 blind.
        assert_eq!(a.blind.len(), 5);
        assert_eq!(a.development.len(), 15);
        // Pure: same inputs -> same partition.
        assert_eq!(a, held_out_split(&ids, 0.25, 42).unwrap());
        // The seed must matter (over many seeds, not all partitions agree).
        let mut distinct = std::collections::BTreeSet::new();
        for s in 0..64u64 {
            let p = held_out_split(&ids, 0.25, s).unwrap();
            distinct.insert((p.development.clone(), p.blind.clone()));
        }
        assert!(
            distinct.len() > 1,
            "different seeds should usually produce different partitions"
        );
        // Guards.
        assert!(held_out_split(&[1], 0.5, 0).is_err());
        assert!(held_out_split(&ids, 0.0, 0).is_err());
        assert!(held_out_split(&ids, 1.0, 0).is_err());
    }

    #[test]
    fn experiment_id_excludes_paths_and_time() {
        let base = ExperimentSpec {
            target_name: "demo".into(),
            target_bin: PathBuf::from("/tmp/whatever/golden_demo"),
            arms: vec![AblationArm::Cov, AblationArm::Full],
            trials: 3,
            base_policy: SchedulePolicy::default(),
            base_seed: 7,
            seed_dir: None,
            max_time: std::time::Duration::from_secs(10),
            max_execs: None,
            sanitizer: crate::execute::worker_process::SanitizerMode::None,
            memory_limit_mb: 0,
            initial_dictionary: Vec::new(),
            rustc_release: "r1".into(),
            llvm_version: "l1".into(),
            instrument_flags: vec!["-x".into()],
            nightly: "n1".into(),
            out_root: PathBuf::from("/a"),
        };
        let mut moved = base.clone();
        moved.target_bin = PathBuf::from("/elsewhere/golden_demo");
        moved.out_root = PathBuf::from("/b");
        assert_eq!(experiment_id(&base), experiment_id(&moved));
        let mut changed = base.clone();
        changed.base_seed = 8;
        assert_ne!(experiment_id(&base), experiment_id(&changed));
    }
}
