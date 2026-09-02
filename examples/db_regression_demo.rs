//! Database historical-regression demonstration (Phase 6; master prompt §35
//! Phase 6, §14 DSFB-Database integration).
//!
//! A deterministic, executable demonstration of why the REAL `dsfb-database`
//! grammar (feature `database`) exists in frf-fuzz, using the SAME library
//! code a campaign analysis runs (`dsfb::database_bridge::analyze`).
//!
//! Scenario: one telemetry surface — a distiller that turns raw query-class
//! latency observations into SQL telemetry residual rows — is exercised over
//! an IDENTICAL 90-second tape of raw observations under two program states:
//!
//! * revision A (clean): the latency normalizer compares each observation to
//!   the PREVIOUS observation (an instantaneous-delta law);
//! * revision B (regressed): the same normalizer was changed to compare
//!   against a BASELINE FROZEN AT PROCESS START (a documented calibration
//!   regression — the classic "calibration froze" bug class).
//!
//! Both revisions parse the same raw tape with the same code shape (only the
//! arithmetic law differs), so a coverage-only scheduler sees NO difference
//! between them. The real SQL grammar, fed through the bridge's typed
//! constructors, sees a different structural reading: revision B develops a
//! `plan_regression_onset` episode that revision A never forms, while an
//! injected genuine lock-wait ramp is seen identically by both (the
//! divergence is specific to the regressed channel, not a global artifact).
//!
//! Everything is deterministic: fixed rows, the crate's default grammar, and
//! the crate's own replay fingerprint. Printed claims are structural
//! observations only — never a bug probability.
//!
//! Run: `cargo run --features database --example db_regression_demo`

#[cfg(all(feature = "coordinator", feature = "database"))]
mod demo {
    use frf_fuzz::dsfb::database_bridge::{analyze, DbAnalysis, TelemetryRow};

    /// The two program states of the telemetry distiller under study.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Revision {
        /// Clean: instantaneous-delta normalizer (previous-sample baseline).
        Clean,
        /// Regressed: baseline frozen at process start.
        FrozenBaseline,
    }

    /// Deterministic per-second latency jitter in [-2, 2] ms (whole ms so
    /// every row value is exact in f64; signed arithmetic — u64 would
    /// underflow when the modulo is 0 or 1 in debug builds).
    fn jitter_ms(i: u64) -> f64 {
        (((i * 7) % 5) as i64 - 2) as f64
    }

    /// The raw tape, distilled by `revision` into declared SQL telemetry rows.
    ///
    /// * Plan-latency rows for query class `q_scan`, one per second: 100 ms
    ///   nominal, ramping +3 ms/s for 60 s, then a plateau — plus ±2 ms
    ///   jitter. Baseline per the revision's calibration law.
    /// * Cardinality rows (est == act, control channel: must stay quiet in
    ///   BOTH revisions).
    /// * A genuine lock-wait ramp on wait event `LockRow` (both revisions
    ///   decode it identically; the grammar must form the SAME contention
    ///   episode in both — the regression is specific to the plan channel).
    fn rows_for(revision: Revision) -> Vec<TelemetryRow> {
        const SECONDS: u64 = 90;
        const NOMINAL_MS: f64 = 100.0;
        let mut lat: Vec<f64> = Vec::with_capacity(SECONDS as usize);
        for i in 1..=SECONDS {
            let ramp = i.min(60) as f64 * 3.0;
            lat.push(NOMINAL_MS + ramp + jitter_ms(i));
        }

        let mut rows = Vec::new();
        for i in 1..=SECONDS {
            let lat_now = lat[(i - 1) as usize];
            let baseline = match revision {
                Revision::Clean => {
                    if i == 1 {
                        lat_now
                    } else {
                        lat[(i - 2) as usize] // previous sample
                    }
                }
                Revision::FrozenBaseline => NOMINAL_MS,
            };
            rows.push(TelemetryRow::PlanLatency {
                t_ms: i * 1000,
                query_class: "q_scan".to_string(),
                latency_ms: lat_now,
                baseline_ms: baseline,
            });
            // Cardinality control: estimates match actuals exactly.
            if i % 2 == 0 {
                rows.push(TelemetryRow::Cardinality {
                    t_ms: i * 1000,
                    query_class: "q_card".to_string(),
                    estimated_rows: 1000.0,
                    actual_rows: 1000.0,
                });
            }
            // Genuine lock-wait ramp, seconds 40..44 (identical in both).
            let wait = match i {
                40 => 0.08,
                41 => 0.35,
                42 => 0.9,
                43 => 1.4,
                44 => 0.7,
                _ => 0.0,
            };
            rows.push(TelemetryRow::ContentionWait {
                t_ms: i * 1000,
                wait_event: "LockRow".to_string(),
                wait_seconds: wait,
            });
        }
        rows
    }

    fn view(rows: &[TelemetryRow], tag: &str) -> DbAnalysis {
        let a = analyze(tag, rows).expect("bridge analysis must succeed on valid rows");
        println!();
        println!(
            "[{tag}] {} raw rows -> {} bounded episode(s)",
            rows.len(),
            a.episode_count
        );
        for (i, name) in frf_fuzz::dsfb::database_bridge::SQL_CLASS_NAMES
            .iter()
            .enumerate()
        {
            if a.per_class[i] != 0 {
                println!("  {name}: {} episode(s)", a.per_class[i]);
            }
        }
        for e in &a.episodes {
            println!(
                "  episode [{}] {} {:.1}s..{:.1}s peak {:.3}",
                e.motif, e.channel, e.t_start_s, e.t_end_s, e.peak
            );
        }
        println!("  fingerprint: {}", a.fingerprint_hex);
        a
    }

    pub fn run() -> Result<(), String> {
        println!("frf-fuzz phase-6 database historical-regression demonstration");
        println!();
        println!(concat!(
            "Raw tape: 90 s of q_scan plan latency (100 ms nominal, +3 ms/s ramp, \n",
            "  then plateau; +/-2 ms jitter), est==act cardinality rows, and a \n",
            "  genuine lock-wait ramp (LockRow, s 40-44). Both revisions parse the \n",
            "  SAME bytes; only the latency baseline law differs between them."
        ));

        // Determinism: analyze each revision twice, fingerprints must match.
        let clean = rows_for(Revision::Clean);
        let regressed = rows_for(Revision::FrozenBaseline);
        let a1 = view(&clean, "revision-A clean (rolling baseline)");
        let a1b = analyze("revision-A clean", &clean).expect("re-analyze A");
        assert_eq!(
            a1.fingerprint_hex, a1b.fingerprint_hex,
            "FAIL: revision A is not deterministic across runs"
        );
        let b1 = view(&regressed, "revision-B regressed (frozen baseline)");
        let b1b = analyze("revision-B regressed", &regressed).expect("re-analyze B");
        assert_eq!(
            b1.fingerprint_hex, b1b.fingerprint_hex,
            "FAIL: revision B is not deterministic across runs"
        );
        println!("determinism: each revision reproduces its fingerprint");

        // The structural claims.
        assert_eq!(
            a1.plan_regression_count(),
            0,
            "FAIL: clean revision formed a plan-regression episode"
        );
        assert_eq!(
            b1.plan_regression_count(),
            1,
            "FAIL: regressed revision did not form the expected plan-regression episode"
        );
        // The genuine contention ramp is seen identically by both revisions.
        for (tag, a) in [("revision A", &a1), ("revision B", &b1)] {
            assert_eq!(
                a.contention_count(),
                1,
                "FAIL: {tag} lost the genuine contention episode"
            );
            let contention = a
                .episodes
                .iter()
                .find(|e| e.motif == "contention_ramp")
                .expect("contention episode view");
            assert_eq!(contention.channel, "LockRow");
            assert!(contention.peak >= 1.0, "contention peak too small");
        }
        // Control channels stay quiet in both.
        for (tag, a) in [("revision A", &a1), ("revision B", &b1)] {
            assert_eq!(
                a.cardinality_count(),
                0,
                "FAIL: {tag}: cardinality control channel formed an episode"
            );
            assert_eq!(
                a.cache_io_count(),
                0,
                "FAIL: {tag}: cache control channel formed an episode"
            );
        }
        assert_ne!(
            a1.fingerprint_hex, b1.fingerprint_hex,
            "FAIL: clean and regressed revisions produced the same episode fingerprint"
        );

        println!();
        println!("Interpretation:");
        println!("  - both revisions execute the same parse surface; only the baseline");
        println!("    arithmetic differs, so coverage-only scheduling sees no signal here.");
        println!("  - the real SQL grammar sees the frozen-baseline revision develop a");
        println!("    plan_regression_onset episode that the clean revision never forms,");
        println!("    while the genuine LockRow ramp is read identically by both.");
        println!(
            "  - {} raw telemetry rows collapse into <= 2 bounded structural episodes",
            clean.len()
        );
        println!("    per revision (the DSFB-Database episode lesson).");
        println!();
        println!("DB REGRESSION DEMO PASS");
        Ok(())
    }
}

#[cfg(all(feature = "coordinator", feature = "database"))]
fn main() {
    if let Err(e) = demo::run() {
        eprintln!("db regression demo: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(all(feature = "coordinator", feature = "database")))]
fn main() {}
