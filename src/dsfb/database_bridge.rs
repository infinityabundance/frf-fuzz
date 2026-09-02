//! Real `dsfb-database` integration for **actual SQL-telemetry surfaces**
//! (feature `database`; master prompt §14, §35 Phase 6).
//!
//! # What this module is
//!
//! frf-fuzz's *generic* structural machinery (`regime`, `morphology`,
//! `debug_bridge`, `fuzz_bank`) deliberately never touches SQL semantics.
//! This module is the ONE place the real `dsfb-database` crate is allowed to
//! meet frf-fuzz code, and it exists for one audience: a campaign whose fuzz
//! target IS a database telemetry surface (a distiller/decoder whose
//! telemetry output is genuinely SQL-shaped — query-class latencies,
//! estimated-vs-actual row counts, lock-wait events, cache hit ratios,
//! workload JS divergence).
//!
//! It converts *declared SQL telemetry rows* into the real crate's
//! `ResidualStream` (via the crate's own SQL-semantics constructor
//! functions), runs the real `MotifEngine` grammar over the stream, and
//! returns bounded structural episodes plus the crate's deterministic replay
//! fingerprint. The output is an evidence-plane artifact: deterministic,
//! replayable, and comparable across revisions of the telemetry surface
//! ("same tape, two states -> different SQL residual morphology" is a
//! program-side perturbation; docs/INVARIANTS.md I12).
//!
//! # The type-level refusal (invariant I7)
//!
//! Generic fuzz residuals are NEVER represented as SQL `ResidualClass`
//! values. The refusal is structural:
//!
//! 1. This module has no `From`/`TryFrom` impls and no function that accepts
//!    a frf-fuzz generic residual type. The generic fuzz core (`observe`,
//!    `target_runtime::signals`, `regime`, `morphology`) is never imported
//!    here, so its types cannot meet `ResidualClass` in any code path.
//! 2. [`TelemetryRow`] is a closed enum of SQL-telemetry rows. Each variant
//!    carries the exact fields one of the crate's SQL-semantics constructors
//!    requires (a query class / wait event / cache id / workload bucket plus
//!    the metric's raw values). A `ResidualClass` value is chosen ONLY by
//!    the constructor the variant dispatches to — never from a bare value
//!    and a tag.
//! 3. Every row is validated before it can reach the crate: finite metrics,
//!    class-appropriate ranges, bounded labels, bounded logical time. A row
//!    that is not genuine SQL telemetry is refused, never silently coerced.
//!
//! A source-level lock test (`no_generic_types_cross_the_boundary`) greps
//! this file for the generic fuzz type names and conversion impls; the
//! `compile_fail` doctest on [`TelemetryRow`] documents the boundary.
//! `dsfb-database`'s own five `ResidualClass`es are a closed SQL enum with
//! an explicit "not a universal grammar" non-claim; frf-fuzz's generic
//! observer has its own independently documented semantics (`regime.rs`)
//! and no conversion between the two worlds exists
//! (docs/DESIGN-DSFB.md "Type-level refusal (I7)").
//!
//! # Determinism
//!
//! All rows carry an integer logical time (`t_ms`). The stream is sorted by
//! `t` before the grammar runs, and [`analyze`] returns the crate's own
//! deterministic episode fingerprint (`grammar::replay::fingerprint_hex`,
//! SHA-256 over the episode fields' little-endian bytes). The SAME rows in
//! the SAME order always produce the SAME analysis on the same build; the
//! grammar's per-channel state machines are fed in sorted `t` order.
//!
//! # How a telemetry surface uses it
//!
//! The fuzz target's harness decodes whatever wire format the real surface
//! speaks into [`TelemetryRow`]s (the decode is the target's job — this
//! module never guesses a format). The analysis runs at promotion/offline
//! time (never per-execution): replay the recorded telemetry rows through
//! [`analyze`] and compare fingerprints across revisions. The episode
//! structure is an observation about the SURFACE, never a claim about a bug.

use crate::error::{Error, Result};
use dsfb_database::grammar::{replay, MotifClass, MotifEngine, MotifGrammar};
use dsfb_database::residual::{
    cache_io, cardinality, contention, plan_regression, workload_phase, ResidualClass,
    ResidualStream,
};

/// Version of the telemetry-row contract.
pub const DB_BRIDGE_VERSION: u8 = 1;

/// Maximum rows in one analyzed stream (bounded before allocation).
pub const MAX_ROWS_PER_STREAM: usize = 1 << 16;

/// Maximum encoded length of a channel label (query class, wait event,
/// cache id, workload bucket). Bounded before allocation.
pub const MAX_LABEL_BYTES: usize = 128;

/// Maximum logical time, in milliseconds. ~34 years at 1 ms resolution.
pub const MAX_T_MS: u64 = 1 << 40;

/// Maximum absolute value of any SQL metric in a row (finite, bounded).
pub const MAX_METRIC_ABS: f64 = 1e15;

/// Maximum number of episodes retained in an analysis view.
pub const MAX_EPISODE_VIEWS: usize = 64;

/// The five SQL telemetry classes, in `MotifClass::ALL` order. Names are
/// frf-fuzz's declared semantics for REPORTING; the authoritative class of a
/// pushed sample is decided by the crate constructor the row dispatches to.
pub const SQL_CLASS_NAMES: [&str; 5] = [
    "plan_regression",
    "cardinality",
    "contention",
    "cache_io",
    "workload_phase",
];

/// A declared SQL-telemetry row.
///
/// Each variant carries exactly the raw fields the corresponding
/// `dsfb-database` SQL-semantics constructor requires. There is deliberately
/// NO generic variant: a bare value plus a tag cannot name a SQL class.
///
/// ```compile_fail
/// // I7 refusal (types): there is no way to coerce a bare signal value into
/// // SQL telemetry. The only constructors are the SQL-typed variants below,
/// // and no conversion from generic fuzz data exists. If this block ever
/// // compiles, a coercion was added — that is a violation.
/// use frf_fuzz::dsfb::database_bridge::TelemetryRow;
/// fn coerce(v: u64) -> TelemetryRow {
///     TelemetryRow::from_bare_signal(v) // no such constructor (I7)
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum TelemetryRow {
    /// Query-class latency against its baseline (ms).
    /// -> `plan_regression::push_latency` (`ResidualClass::PlanRegression`).
    PlanLatency {
        /// Logical time, milliseconds since stream start (bounded).
        t_ms: u64,
        /// The query class the latency belongs to (channel discriminator).
        query_class: String,
        /// Observed latency, ms (finite, >= 0).
        latency_ms: f64,
        /// The declared baseline the surface compares against, ms.
        baseline_ms: f64,
    },
    /// A plan-hash change for a query class.
    /// -> `plan_regression::push_plan_change` (`ResidualClass::PlanRegression`).
    PlanChange {
        /// Logical time, milliseconds since stream start.
        t_ms: u64,
        /// The query class whose plan changed.
        query_class: String,
    },
    /// Estimated vs actual rows returned for a query class.
    /// -> `cardinality::push` (`ResidualClass::Cardinality`).
    Cardinality {
        /// Logical time, milliseconds since stream start.
        t_ms: u64,
        /// The query class (or subplan) identifier.
        query_class: String,
        /// Optimizer row estimate (finite, >= 0).
        estimated_rows: f64,
        /// Actual rows returned (finite, >= 0).
        actual_rows: f64,
    },
    /// Lock-wait seconds observed for a wait event.
    /// -> `contention::push_wait` (`ResidualClass::Contention`).
    ContentionWait {
        /// Logical time, milliseconds since stream start.
        t_ms: u64,
        /// The wait event name (channel discriminator).
        wait_event: String,
        /// Wait seconds (finite, >= 0).
        wait_seconds: f64,
    },
    /// Blocked-by chain depth for a wait event.
    /// -> `contention::push_chain_depth` (`ResidualClass::Contention`).
    ContentionChain {
        /// Logical time, milliseconds since stream start.
        t_ms: u64,
        /// The wait event name.
        wait_event: String,
        /// Chain depth (1 = isolated wait; bounded <= 1e9).
        depth: u64,
    },
    /// Expected vs observed buffer/cache hit ratio for a cache.
    /// -> `cache_io::push_hit_ratio` (`ResidualClass::CacheIo`).
    CacheHitRatio {
        /// Logical time, milliseconds since stream start.
        t_ms: u64,
        /// The cache identifier (channel discriminator).
        cache_id: String,
        /// Expected hit ratio in [0, 1].
        expected: f64,
        /// Observed hit ratio in [0, 1].
        observed: f64,
    },
    /// Observed vs baseline I/O seconds for a file.
    /// -> `cache_io::push_io_amplification` (`ResidualClass::CacheIo`).
    CacheIoAmplification {
        /// Logical time, milliseconds since stream start.
        t_ms: u64,
        /// The file identifier (channel discriminator).
        file_id: String,
        /// Observed I/O seconds (finite, >= 0).
        observed_seconds: f64,
        /// Baseline I/O seconds (finite, >= 0).
        baseline_seconds: f64,
    },
    /// Workload JS-divergence for a workload bucket.
    /// -> `workload_phase::push_jsd` (`ResidualClass::WorkloadPhase`).
    WorkloadJsd {
        /// Logical time, milliseconds since stream start.
        t_ms: u64,
        /// The workload bucket identifier (channel discriminator).
        bucket_id: String,
        /// Jensen-Shannon divergence in [0, 1].
        jsd: f64,
    },
}

impl TelemetryRow {
    /// The channel label this row feeds (the discriminator dsfb-database
    /// scopes episodes by: query class, wait event, cache id, bucket id).
    pub fn channel_label(&self) -> &str {
        match self {
            TelemetryRow::PlanLatency { query_class, .. }
            | TelemetryRow::PlanChange { query_class, .. }
            | TelemetryRow::Cardinality { query_class, .. } => query_class,
            TelemetryRow::ContentionWait { wait_event, .. }
            | TelemetryRow::ContentionChain { wait_event, .. } => wait_event,
            TelemetryRow::CacheHitRatio { cache_id, .. } => cache_id,
            TelemetryRow::CacheIoAmplification { file_id, .. } => file_id,
            TelemetryRow::WorkloadJsd { bucket_id, .. } => bucket_id,
        }
    }

    /// The declared SQL class this row's constructor pushes. Reporting only:
    /// the authoritative class is decided by the crate constructor this
    /// variant dispatches to; this accessor mirrors that closed match so
    /// callers never guess.
    pub fn residual_class(&self) -> ResidualClass {
        match self {
            TelemetryRow::PlanLatency { .. } | TelemetryRow::PlanChange { .. } => {
                ResidualClass::PlanRegression
            }
            TelemetryRow::Cardinality { .. } => ResidualClass::Cardinality,
            TelemetryRow::ContentionWait { .. } | TelemetryRow::ContentionChain { .. } => {
                ResidualClass::Contention
            }
            TelemetryRow::CacheHitRatio { .. } | TelemetryRow::CacheIoAmplification { .. } => {
                ResidualClass::CacheIo
            }
            TelemetryRow::WorkloadJsd { .. } => ResidualClass::WorkloadPhase,
        }
    }

    /// Logical time in milliseconds (the row's own field, common to every
    /// variant).
    fn t_ms(&self) -> u64 {
        match self {
            TelemetryRow::PlanLatency { t_ms, .. }
            | TelemetryRow::PlanChange { t_ms, .. }
            | TelemetryRow::Cardinality { t_ms, .. }
            | TelemetryRow::ContentionWait { t_ms, .. }
            | TelemetryRow::ContentionChain { t_ms, .. }
            | TelemetryRow::CacheHitRatio { t_ms, .. }
            | TelemetryRow::CacheIoAmplification { t_ms, .. }
            | TelemetryRow::WorkloadJsd { t_ms, .. } => *t_ms,
        }
    }

    /// Validate the row's fields and push it into `stream` through the crate's
    /// own SQL-semantics constructor. This is the ONLY path from frf-fuzz
    /// code into a `ResidualStream`. Invalid rows are refused, never coerced.
    pub fn push_into(&self, stream: &mut ResidualStream) -> Result<()> {
        let t_ms = self.t_ms();
        if t_ms > MAX_T_MS {
            return Err(Error::Other(format!(
                "telemetry time {t_ms} ms exceeds MAX_T_MS {MAX_T_MS}"
            )));
        }
        // Integer ms -> seconds is a single deterministic division (exact
        // for t_ms < 2^53, i.e. ~285k years).
        let t = t_ms as f64 / 1000.0;
        match self {
            TelemetryRow::PlanLatency {
                query_class,
                latency_ms,
                baseline_ms,
                ..
            } => {
                finite_nonneg(*latency_ms, "plan latency_ms")?;
                finite_nonneg(*baseline_ms, "plan baseline_ms")?;
                plan_regression::push_latency(
                    stream,
                    t,
                    check_label(query_class)?,
                    *latency_ms,
                    *baseline_ms,
                );
            }
            TelemetryRow::PlanChange { query_class, .. } => {
                plan_regression::push_plan_change(stream, t, check_label(query_class)?);
            }
            TelemetryRow::Cardinality {
                query_class,
                estimated_rows,
                actual_rows,
                ..
            } => {
                finite_nonneg(*estimated_rows, "cardinality estimated_rows")?;
                finite_nonneg(*actual_rows, "cardinality actual_rows")?;
                cardinality::push(
                    stream,
                    t,
                    check_label(query_class)?,
                    *estimated_rows,
                    *actual_rows,
                );
            }
            TelemetryRow::ContentionWait {
                wait_event,
                wait_seconds,
                ..
            } => {
                finite_nonneg(*wait_seconds, "contention wait_seconds")?;
                contention::push_wait(stream, t, check_label(wait_event)?, *wait_seconds);
            }
            TelemetryRow::ContentionChain {
                wait_event, depth, ..
            } => {
                if *depth > 1_000_000_000 {
                    return Err(Error::Other(format!(
                        "contention chain depth {depth} exceeds 1e9"
                    )));
                }
                contention::push_chain_depth(stream, t, check_label(wait_event)?, *depth as usize);
            }
            TelemetryRow::CacheHitRatio {
                cache_id,
                expected,
                observed,
                ..
            } => {
                finite_range(*expected, 0.0, 1.0, "cache hit ratio expected")?;
                finite_range(*observed, 0.0, 1.0, "cache hit ratio observed")?;
                cache_io::push_hit_ratio(stream, t, check_label(cache_id)?, *expected, *observed);
            }
            TelemetryRow::CacheIoAmplification {
                file_id,
                observed_seconds,
                baseline_seconds,
                ..
            } => {
                finite_nonneg(*observed_seconds, "cache io observed_seconds")?;
                finite_nonneg(*baseline_seconds, "cache io baseline_seconds")?;
                cache_io::push_io_amplification(
                    stream,
                    t,
                    check_label(file_id)?,
                    *observed_seconds,
                    *baseline_seconds,
                );
            }
            TelemetryRow::WorkloadJsd { bucket_id, jsd, .. } => {
                finite_range(*jsd, 0.0, 1.0, "workload jsd")?;
                workload_phase::push_jsd(stream, t, check_label(bucket_id)?, *jsd);
            }
        }
        Ok(())
    }
}

/// Validate a channel label: non-empty and bounded.
fn check_label(label: &str) -> Result<&str> {
    if label.is_empty() {
        return Err(Error::Other("telemetry channel label is empty".to_string()));
    }
    if label.len() > MAX_LABEL_BYTES {
        return Err(Error::Other(format!(
            "telemetry channel label exceeds MAX_LABEL_BYTES {MAX_LABEL_BYTES}"
        )));
    }
    Ok(label)
}

/// Validate a finite, non-negative metric with a bounded magnitude.
fn finite_nonneg(v: f64, what: &str) -> Result<()> {
    if !v.is_finite() || v < 0.0 {
        return Err(Error::Other(format!(
            "{what} must be finite and non-negative"
        )));
    }
    if v > MAX_METRIC_ABS {
        return Err(Error::Other(format!(
            "{what} exceeds MAX_METRIC_ABS {MAX_METRIC_ABS}"
        )));
    }
    Ok(())
}

/// Validate a finite metric inside a closed range.
fn finite_range(v: f64, lo: f64, hi: f64, what: &str) -> Result<()> {
    if !v.is_finite() || v < lo || v > hi {
        return Err(Error::Other(format!(
            "{what} must be finite and in [{lo}, {hi}]"
        )));
    }
    Ok(())
}

/// Build a sorted `ResidualStream` from declared rows. The only frf-fuzz
/// entry point into the crate's stream type.
pub fn build_stream(source: &str, rows: &[TelemetryRow]) -> Result<ResidualStream> {
    if rows.len() > MAX_ROWS_PER_STREAM {
        return Err(Error::BoundExceeded {
            what: "telemetry rows per stream",
            limit: MAX_ROWS_PER_STREAM as u64,
            got: rows.len() as u64,
        });
    }
    let mut stream = ResidualStream::new(source);
    for row in rows {
        row.push_into(&mut stream)?;
    }
    // The crate's contract: adapters MUST sort before the grammar runs.
    stream.sort();
    Ok(stream)
}

/// One bounded episode view (reporting only; floats never enter frf-fuzz
/// canonical identity).
#[derive(Debug, Clone)]
pub struct DbEpisodeView {
    /// The SQL motif class name (`MotifClass::name`).
    pub motif: &'static str,
    /// The channel discriminator the episode was scoped to.
    pub channel: String,
    /// Episode open time, seconds (crate units).
    pub t_start_s: f64,
    /// Episode close time, seconds.
    pub t_end_s: f64,
    /// Peak |residual| inside the episode.
    pub peak: f64,
    /// EMA residual at the boundary.
    pub ema_at_boundary: f64,
}

/// The deterministic result of running the real grammar over declared rows.
#[derive(Debug, Clone)]
pub struct DbAnalysis {
    /// Stream source label.
    pub source: String,
    /// Number of raw samples pushed (post-sort).
    pub sample_count: usize,
    /// Number of episodes the real grammar closed.
    pub episode_count: usize,
    /// Per-class episode counts in `SQL_CLASS_NAMES` order.
    pub per_class: [u32; 5],
    /// Deterministic episode fingerprint (dsfb-database `replay` SHA-256 hex).
    /// dsfb-database namespace: never reinterpreted as a frf-fuzz object ID.
    pub fingerprint_hex: String,
    /// Bounded episode views (reporting only).
    pub episodes: Vec<DbEpisodeView>,
}

impl DbAnalysis {
    /// Episode count for one motif class.
    pub fn count_for(&self, class: MotifClass) -> u32 {
        MotifClass::ALL
            .iter()
            .position(|c| *c == class)
            .map(|i| self.per_class[i])
            .unwrap_or(0)
    }

    /// Plan-regression episode count (index into [`SQL_CLASS_NAMES`]).
    pub fn plan_regression_count(&self) -> u32 {
        self.per_class[0]
    }

    /// Cardinality-mismatch episode count.
    pub fn cardinality_count(&self) -> u32 {
        self.per_class[1]
    }

    /// Contention episode count.
    pub fn contention_count(&self) -> u32 {
        self.per_class[2]
    }

    /// Cache-io episode count.
    pub fn cache_io_count(&self) -> u32 {
        self.per_class[3]
    }

    /// Workload-phase episode count.
    pub fn workload_phase_count(&self) -> u32 {
        self.per_class[4]
    }
}

/// Run the real `dsfb-database` `MotifEngine` (default grammar) over declared
/// SQL-telemetry rows. Deterministic: the same rows in the same order always
/// produce the same analysis on the same build (unit-tested here and in
/// `tests/phase6_database.rs`).
pub fn analyze(source: &str, rows: &[TelemetryRow]) -> Result<DbAnalysis> {
    let stream = build_stream(source, rows)?;
    let engine = MotifEngine::new(MotifGrammar::default());
    let episodes = engine.run(&stream);
    let mut per_class = [0u32; 5];
    let mut views: Vec<DbEpisodeView> = Vec::new();
    for ep in episodes.iter() {
        if let Some(i) = MotifClass::ALL.iter().position(|c| *c == ep.motif) {
            per_class[i] = per_class[i].saturating_add(1);
        }
        if views.len() < MAX_EPISODE_VIEWS {
            views.push(DbEpisodeView {
                motif: ep.motif.name(),
                channel: ep
                    .channel
                    .clone()
                    .unwrap_or_else(|| "_anonymous_".to_string()),
                t_start_s: ep.t_start,
                t_end_s: ep.t_end,
                peak: ep.peak,
                ema_at_boundary: ep.ema_at_boundary,
            });
        }
    }
    Ok(DbAnalysis {
        source: stream.source.clone(),
        sample_count: stream.samples.len(),
        episode_count: episodes.len(),
        per_class,
        fingerprint_hex: replay::fingerprint_hex(&episodes),
        episodes: views,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn latency_row(t_ms: u64, qclass: &str, latency_ms: f64, baseline_ms: f64) -> TelemetryRow {
        TelemetryRow::PlanLatency {
            t_ms,
            query_class: qclass.to_string(),
            latency_ms,
            baseline_ms,
        }
    }

    fn quiet_stream(class: ResidualClass) -> Vec<TelemetryRow> {
        // 100 near-zero samples in the given class, no channel drift.
        (0..100)
            .map(|i| match class {
                ResidualClass::PlanRegression => {
                    latency_row(i * 1000, "q1", 100.0 + (i % 3) as f64, 100.0)
                }
                ResidualClass::Cardinality => TelemetryRow::Cardinality {
                    t_ms: i * 1000,
                    query_class: "q1".into(),
                    estimated_rows: 1000.0,
                    actual_rows: 1001.0,
                },
                ResidualClass::Contention => TelemetryRow::ContentionWait {
                    t_ms: i * 1000,
                    wait_event: "LockRow".into(),
                    wait_seconds: 0.001,
                },
                ResidualClass::CacheIo => TelemetryRow::CacheHitRatio {
                    t_ms: i * 1000,
                    cache_id: "shared".into(),
                    expected: 0.99,
                    observed: 0.99,
                },
                ResidualClass::WorkloadPhase => TelemetryRow::WorkloadJsd {
                    t_ms: i * 1000,
                    bucket_id: "bucket_a".into(),
                    jsd: 0.01,
                },
            })
            .collect()
    }

    #[test]
    fn rows_dispatch_to_the_declared_sql_class() {
        // Every variant must push exactly the class its constructor targets —
        // the type-level mapping is a closed match, never data-driven.
        let cases: &[(TelemetryRow, ResidualClass)] = &[
            (
                TelemetryRow::PlanLatency {
                    t_ms: 0,
                    query_class: "q".into(),
                    latency_ms: 1.0,
                    baseline_ms: 1.0,
                },
                ResidualClass::PlanRegression,
            ),
            (
                TelemetryRow::PlanChange {
                    t_ms: 0,
                    query_class: "q".into(),
                },
                ResidualClass::PlanRegression,
            ),
            (
                TelemetryRow::Cardinality {
                    t_ms: 0,
                    query_class: "q".into(),
                    estimated_rows: 1.0,
                    actual_rows: 1.0,
                },
                ResidualClass::Cardinality,
            ),
            (
                TelemetryRow::ContentionWait {
                    t_ms: 0,
                    wait_event: "w".into(),
                    wait_seconds: 0.0,
                },
                ResidualClass::Contention,
            ),
            (
                TelemetryRow::ContentionChain {
                    t_ms: 0,
                    wait_event: "w".into(),
                    depth: 1,
                },
                ResidualClass::Contention,
            ),
            (
                TelemetryRow::CacheHitRatio {
                    t_ms: 0,
                    cache_id: "c".into(),
                    expected: 1.0,
                    observed: 1.0,
                },
                ResidualClass::CacheIo,
            ),
            (
                TelemetryRow::CacheIoAmplification {
                    t_ms: 0,
                    file_id: "f".into(),
                    observed_seconds: 1.0,
                    baseline_seconds: 1.0,
                },
                ResidualClass::CacheIo,
            ),
            (
                TelemetryRow::WorkloadJsd {
                    t_ms: 0,
                    bucket_id: "b".into(),
                    jsd: 0.0,
                },
                ResidualClass::WorkloadPhase,
            ),
        ];
        for (row, want) in cases {
            let mut stream = ResidualStream::new("dispatch-test");
            row.push_into(&mut stream).unwrap();
            assert_eq!(stream.samples.len(), 1);
            assert_eq!(stream.samples[0].class, *want, "variant dispatched wrong");
            assert_eq!(row.residual_class(), *want);
            assert!(!row.channel_label().is_empty());
        }
    }

    #[test]
    fn quiet_streams_produce_no_episodes() {
        for class in ResidualClass::ALL {
            let rows = quiet_stream(class);
            let a = analyze("quiet", &rows).unwrap();
            assert_eq!(
                a.episode_count,
                0,
                "{}: quiet stream invented an episode",
                class.name()
            );
            assert_eq!(a.sample_count, 100);
        }
    }

    #[test]
    fn sustained_drift_forms_an_episode_in_its_class_only() {
        // A sustained contention ramp must produce exactly a contention
        // episode — nothing in the other four classes.
        let mut rows: Vec<TelemetryRow> = Vec::new();
        for i in 0..40 {
            let wait = if (10..30).contains(&i) { 0.5 } else { 0.001 };
            rows.push(TelemetryRow::ContentionWait {
                t_ms: i * 1000,
                wait_event: "LockRow".into(),
                wait_seconds: wait,
            });
        }
        let a = analyze("ramp", &rows).unwrap();
        assert_eq!(
            a.episode_count, 1,
            "expected exactly one contention episode"
        );
        assert_eq!(a.count_for(MotifClass::ContentionRamp), 1);
        assert_eq!(a.count_for(MotifClass::PlanRegressionOnset), 0);
        assert_eq!(a.count_for(MotifClass::CardinalityMismatchRegime), 0);
        assert_eq!(a.count_for(MotifClass::CacheCollapse), 0);
        assert_eq!(a.count_for(MotifClass::WorkloadPhaseTransition), 0);
        assert_eq!(a.episodes[0].channel, "LockRow");
        assert!(a.episodes[0].peak >= 0.5);
    }

    #[test]
    fn analysis_is_deterministic() {
        let mut rows: Vec<TelemetryRow> = Vec::new();
        for i in 0..90 {
            let wait = if (30..50).contains(&i) { 1.0 } else { 0.0 };
            rows.push(TelemetryRow::ContentionWait {
                t_ms: i * 1000,
                wait_event: "LockRow".into(),
                wait_seconds: wait,
            });
            if i < 60 {
                rows.push(latency_row(
                    i * 1000,
                    "q_scan",
                    100.0 + 3.0 * i as f64,
                    100.0,
                ));
            }
        }
        let a1 = analyze("det", &rows).unwrap();
        let a2 = analyze("det", &rows).unwrap();
        assert_eq!(a1.fingerprint_hex, a2.fingerprint_hex);
        assert_eq!(a1.episode_count, a2.episode_count);
        assert_eq!(a1.per_class, a2.per_class);
        // Fingerprint is not the empty hash (episodes exist).
        assert_ne!(a1.fingerprint_hex, replay::fingerprint_hex(&[]));
    }

    #[test]
    fn row_ordering_does_not_change_the_analysis() {
        // The stream is sorted by t before the grammar runs: shuffled rows
        // must produce the same analysis as sorted rows.
        let mut rows: Vec<TelemetryRow> = Vec::new();
        for i in 0..60 {
            let wait = if (20..40).contains(&i) { 0.8 } else { 0.0 };
            rows.push(TelemetryRow::ContentionWait {
                t_ms: i * 1000,
                wait_event: "LockRow".into(),
                wait_seconds: wait,
            });
        }
        let sorted = analyze("order", &rows).unwrap();
        // Deterministic permutation: take indices in a coprime stride order
        // (37 is coprime with 60, so this is a true reordering).
        let n = rows.len();
        let permuted: Vec<TelemetryRow> = (0..n).map(|i| rows[(i * 37) % n].clone()).collect();
        assert_ne!(permuted, rows, "permutation must reorder");
        let scrambled = analyze("order", &permuted).unwrap();
        assert_eq!(sorted.fingerprint_hex, scrambled.fingerprint_hex);
        assert_eq!(sorted.episode_count, scrambled.episode_count);
    }

    #[test]
    fn invalid_rows_are_refused() {
        let bad: &[TelemetryRow] = &[
            latency_row(0, "q", f64::NAN, 100.0),
            latency_row(0, "q", 100.0, f64::INFINITY),
            latency_row(0, "q", -1.0, 100.0),
            TelemetryRow::Cardinality {
                t_ms: 0,
                query_class: "q".into(),
                estimated_rows: f64::NEG_INFINITY,
                actual_rows: 1.0,
            },
            TelemetryRow::ContentionWait {
                t_ms: 0,
                wait_event: "w".into(),
                wait_seconds: -0.5,
            },
            TelemetryRow::CacheHitRatio {
                t_ms: 0,
                cache_id: "c".into(),
                expected: 1.5,
                observed: 0.9,
            },
            TelemetryRow::WorkloadJsd {
                t_ms: 0,
                bucket_id: "b".into(),
                jsd: 2.0,
            },
            TelemetryRow::PlanLatency {
                t_ms: MAX_T_MS + 1,
                query_class: "q".into(),
                latency_ms: 1.0,
                baseline_ms: 1.0,
            },
        ];
        for row in bad {
            let mut stream = ResidualStream::new("bad");
            assert!(
                row.push_into(&mut stream).is_err(),
                "invalid row was not refused: {row:?}"
            );
        }
        // Empty channel labels are refused too.
        assert!(TelemetryRow::PlanChange {
            t_ms: 0,
            query_class: String::new(),
        }
        .push_into(&mut ResidualStream::new("bad"))
        .is_err());
        // Over-long labels are refused.
        let long = "x".repeat(MAX_LABEL_BYTES + 1);
        assert!(TelemetryRow::ContentionChain {
            t_ms: 0,
            wait_event: long,
            depth: 1,
        }
        .push_into(&mut ResidualStream::new("bad"))
        .is_err());
    }

    #[test]
    fn row_count_is_bounded() {
        let mut rows = Vec::new();
        for _ in 0..=MAX_ROWS_PER_STREAM {
            rows.push(latency_row(0, "q", 1.0, 1.0));
        }
        assert!(build_stream("big", &rows).is_err());
        rows.pop();
        assert!(build_stream("big", &rows).is_ok());
    }

    /// I7 source lock: this module must never import the generic fuzz
    /// machinery or define a conversion into SQL types. Needle strings are
    /// assembled from halves so the test cannot match its own source text.
    #[test]
    fn no_generic_types_cross_the_boundary() {
        let src = include_str!("database_bridge.rs");
        let needles = [
            concat!("impl ", "From<"),
            concat!("impl ", "TryFrom<"),
            concat!("use crate::", "observe"),
            concat!("use crate::target_", "runtime::signals"),
            concat!("Residual", "Sketch"),
            concat!("Mutation", "Residual"),
            concat!("Temporal", "Residual"),
            concat!("Regime", "Observer"),
            concat!("Signal", "Vector"),
            concat!("Lineage", "Accumulator"),
            concat!("Morphology", "Signature"),
            concat!("crate::", "regime"),
        ];
        for n in needles {
            assert!(
                !src.contains(n),
                "I7 violation: database_bridge references generic machinery (`{n}`)"
            );
        }
        // The refusal must be documented in the module contract.
        assert!(src.contains("type-level refusal"));
        assert!(src.contains("compile_fail"));
    }
}
