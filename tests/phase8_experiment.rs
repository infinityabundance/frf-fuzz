//! Phase-8 scientific-evaluation integration tests (master prompt §31-§33;
//! docs/EXPERIMENT_PROTOCOL.md).
//!
//! The full ablation *campaigns* need the pinned-nightly instrumented build
//! and are exercised by `scripts/phase8_ablation_demo.sh` (like
//! `scripts/golden_demo.sh`). What belongs in the hermetic suite is the
//! experiment instrument itself: raw-series export/import, median/A12/MWU
//! recomputation from the export, censoring preservation, the held-out
//! partition (benchmark-leakage control), and the negative control that the
//! statistics never invent a difference between identical arms.
//!
//! Requires the `coordinator` feature (the default build).

#![cfg(feature = "coordinator")]

use frf_fuzz::experiment::stats;
use frf_fuzz::experiment::{
    analyze, held_out_split, read_series, write_series, AblationArm, Metric, TrialRow,
};
use std::path::Path;

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "frf-fuzz-phase8-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn seed_of(base: u64, trial: u32) -> u64 {
    frf_fuzz::experiment::trial_seed(base, trial)
}

fn row(arm: AblationArm, trial: u32, metric: Metric, value: Option<f64>) -> TrialRow {
    TrialRow {
        arm,
        trial,
        seed: seed_of(0xABC, trial),
        metric,
        value,
    }
}

/// The raw series must be the recomputation authority: export, re-import,
/// and re-derive every reported statistic from the file.
#[test]
fn exported_series_recomputes_identical_statistics() {
    let dir = tmp_dir("export");
    let path = dir.join("series.csv");

    // A realistic two-arm series: cov never fails in budget (censored);
    // cov+cmp finds failures at 50..65s; residual finds them earlier.
    let mut rows = Vec::new();
    for t in 0..8u32 {
        let base: f64 = 60.0 - f64::from(t);
        rows.push(row(AblationArm::Cov, t, Metric::FirstFailureSeconds, None));
        rows.push(row(
            AblationArm::CovCmp,
            t,
            Metric::FirstFailureSeconds,
            Some(base),
        ));
        rows.push(row(
            AblationArm::Residual,
            t,
            Metric::FirstFailureSeconds,
            Some(base * 0.5),
        ));
        rows.push(row(AblationArm::Cov, t, Metric::ExecsPerSec, Some(1000.0)));
        rows.push(row(
            AblationArm::CovCmp,
            t,
            Metric::ExecsPerSec,
            Some(1200.0),
        ));
        rows.push(row(AblationArm::Cov, t, Metric::Findings, Some(0.0)));
        rows.push(row(AblationArm::CovCmp, t, Metric::Findings, Some(1.0)));
    }

    let meta = vec![
        ("target", "golden-demo".to_string()),
        ("trials", "8".to_string()),
    ];
    write_series(&path, &meta, &rows).unwrap();
    let (meta_back, rows_back) = read_series(&path).unwrap();
    assert_eq!(meta_back.len(), 2);
    assert_eq!(rows, rows_back);

    // All statistics must reproduce from the imported rows.
    let pairs = [
        (AblationArm::Cov, AblationArm::CovCmp),
        (AblationArm::CovCmp, AblationArm::Residual),
    ];
    let analysis = analyze(&rows_back, &pairs);
    for a in &analysis {
        match a.metric {
            Metric::FirstFailureSeconds => {
                let cov = a.by_arm[&AblationArm::Cov];
                assert_eq!((cov.found, cov.censored), (0, 8));
                assert_eq!(cov.median, None);
                let cc = a.by_arm[&AblationArm::CovCmp];
                assert_eq!(cc.found, 8);
                assert_eq!(cc.median, Some(56.5)); // 60..53 median
                let r = a.by_arm[&AblationArm::Residual];
                assert_eq!(r.found, 8);
                assert_eq!(r.median, Some(28.25));
                // Complete-case cov vs cov+cmp: no common trials.
                let c0 = &a.comparisons[0];
                assert!(c0.complete_case);
                assert_eq!(c0.n_pairs, 0);
                assert_eq!(c0.a12, None);
                // cov+cmp vs residual: every residual observation is below
                // every cov+cmp observation -> P(left > right) = 1.
                let c1 = &a.comparisons[1];
                assert_eq!(c1.n_pairs, 8);
                assert_eq!(c1.a12, Some(1.0));
                assert!(c1.mwu.unwrap().p_two_sided < 0.01);
            }
            Metric::ExecsPerSec => {
                let c0 = &a.comparisons[0];
                assert!(!c0.complete_case);
                assert_eq!(c0.n_pairs, 8);
                assert_eq!(c0.a12, Some(0.0));
            }
            _ => {}
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Benchmark-leakage control (protocol §4): the development partition and
/// the blind partition are disjoint and recorded; a defect used to build a
/// signature can never be its own blind test.
#[test]
fn held_out_partition_prevents_leakage() {
    // 40 recorded defect ids from a hypothetical historical-defect corpus.
    let defect_ids: Vec<u64> = (100..140).collect();
    let split = held_out_split(&defect_ids, 0.2, 0x5EED).unwrap();

    // Auditable record: the partition is reproducible from (ids, fraction,
    // seed) alone.
    assert_eq!(split, held_out_split(&defect_ids, 0.2, 0x5EED).unwrap());

    // Disjoint + covering.
    for d in &split.blind {
        assert!(
            !split.development.contains(d),
            "blind defect {d} leaked into the development set"
        );
    }
    let mut merged = split.development.clone();
    merged.extend(split.blind.iter().copied());
    merged.sort_unstable();
    assert_eq!(merged, defect_ids);

    // 20% of 40 = 8 blind; development = 32.
    assert_eq!(split.blind.len(), 8);
    assert_eq!(split.development.len(), 32);

    // The blind set is a strict, recorded subset — simulating "signature
    // built from development, evaluated on blind" cannot overlap by
    // construction.
    let signature_sources: Vec<u64> = split.development.clone();
    for source in &signature_sources {
        assert!(
            !split.blind.contains(source),
            "a signature source must never be in the blind evaluation set"
        );
    }
}

/// Negative control for the statistics machinery: identical arms must
/// produce stochastic equality (A12 = 0.5, p = 1) — the analysis never
/// invents a difference between identical distributions.
#[test]
fn identical_arms_never_invent_a_difference() {
    let mut rows = Vec::new();
    for t in 0..12u32 {
        // Deterministic jitter (same splitmix stream for both arms, so the
        // two samples are identical — every pair ties).
        let x = frf_fuzz::experiment::trial_seed(0x7, t) % 20;
        let v = 1000.0 + x as f64;
        rows.push(row(AblationArm::Cov, t, Metric::ExecsPerSec, Some(v)));
        rows.push(row(AblationArm::CovCmp, t, Metric::ExecsPerSec, Some(v)));
    }
    let analysis = analyze(&rows, &[(AblationArm::Cov, AblationArm::CovCmp)]);
    let a = analysis
        .iter()
        .find(|a| a.metric == Metric::ExecsPerSec)
        .unwrap();
    let c = &a.comparisons[0];
    assert!((c.a12.unwrap() - 0.5).abs() < 1e-12);
    let p = c.mwu.unwrap().p_two_sided;
    assert!(
        (p - 1.0).abs() < 1e-9,
        "identical arms must not look different"
    );
}

/// Censoring survives the export: `NA` rows round-trip as censored and the
/// found/censored counts stay exact.
#[test]
fn censoring_survives_export_and_recount() {
    let dir = tmp_dir("censored");
    let path = dir.join("series.csv");
    let mut rows = Vec::new();
    for t in 0..5u32 {
        rows.push(row(
            AblationArm::Full,
            t,
            Metric::FirstFailureExec,
            if t == 4 {
                None
            } else {
                Some(10_000.0 + 100.0 * f64::from(t))
            },
        ));
    }
    write_series(&path, &[], &rows).unwrap();
    let (_, back) = read_series(&path).unwrap();
    assert_eq!(rows, back);
    let analysis = analyze(&back, &[]);
    let a = analysis
        .iter()
        .find(|a| a.metric == Metric::FirstFailureExec)
        .unwrap();
    let st = a.by_arm[&AblationArm::Full];
    assert_eq!((st.n, st.found, st.censored), (5, 4, 1));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stats module agrees with hand-computed values on a recorded series (the
/// recomputation path the protocol's export format exists for).
#[test]
fn stats_recompute_known_values() {
    let x = [1.0, 2.0, 3.0, 4.0, 5.0];
    let y = [3.0, 4.0, 5.0, 6.0, 7.0];
    assert_eq!(stats::median(&x), Some(3.0));
    assert!((stats::a12(&x, &y).unwrap() - 0.18).abs() < 1e-12);
    assert_eq!(stats::median(&[]), None);

    // The A12 estimator is the probability P(X > Y) with ties at 0.5:
    // hand-computed for the series above in the module docs.
    let m = stats::mann_whitney_u(&x, &y).unwrap();
    assert!(m.u > 0.0 && m.p_two_sided > 0.0 && m.p_two_sided <= 1.0);
}

/// Malformed exports are refused, never partially trusted.
#[test]
fn hostile_exports_are_refused() {
    let dir = tmp_dir("hostile");
    let cases: &[(&str, &[u8])] = &[
        ("no-header", b"cov,0,1,executions,count,1.0\n"),
        (
            "bad-arm",
            b"arm,trial,seed,metric,unit,value\nnope,0,1,executions,count,1.0\n",
        ),
        (
            "bad-metric",
            b"arm,trial,seed,metric,unit,value\ncov,0,1,wat,count,1.0\n",
        ),
        (
            "bad-value",
            b"arm,trial,seed,metric,unit,value\ncov,0,1,executions,count,1e999\n",
        ),
        ("short-row", b"arm,trial,seed,metric,unit,value\ncov,0\n"),
        (
            "huge-trial",
            b"arm,trial,seed,metric,unit,value\ncov,4294967296,1,executions,count,1.0\n".as_ref(),
        ),
    ];
    for (name, content) in cases {
        let path = dir.join(format!("{name}.csv"));
        std::fs::write(&path, content).unwrap();
        assert!(
            read_series(&path).is_err(),
            "hostile export {name} must be refused"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Deterministic seed derivation drives independent trials; identical seeds
/// reproduce identical trials (the reproducibility contract of the export).
#[test]
fn trial_seeds_drive_reproducible_trials() {
    assert_eq!(
        frf_fuzz::experiment::trial_seed(0xDEAD, 3),
        frf_fuzz::experiment::trial_seed(0xDEAD, 3)
    );
    assert_ne!(
        frf_fuzz::experiment::trial_seed(0xDEAD, 3),
        frf_fuzz::experiment::trial_seed(0xDEAD, 4)
    );
}

/// The demo/analysis renderer never emits a probability-style claim: check
/// the fixed caveat ships with every analysis text (I11: no unsupported
/// statistical claims in the CLI).
#[test]
fn analysis_carries_the_power_caveat() {
    let text = frf_fuzz::experiment::protocol_caveat();
    assert!(text.contains("raw per-trial facts"));
    assert!(text.contains("not evidence"));
    // And the exported series file is the recomputation authority.
    assert!(Path::new("docs/EXPERIMENT_PROTOCOL.md").exists());
}
