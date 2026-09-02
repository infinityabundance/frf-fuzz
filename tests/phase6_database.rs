//! Phase 6 integration tests: the real `dsfb-database` bridge
//! (`dsfb::database_bridge`, feature `database`).
//!
//! These exercise the REAL `dsfb-database` crate — its typed SQL-semantics
//! residual constructors and its `MotifEngine` grammar — through frf-fuzz's
//! bridge, with the type-level refusal (I7) intact: rows are the only input,
//! and the declared channel semantics decide everything. No mocks, no
//! reimplementation: the grammar that closes these episodes is the crate's
//! own.
//!
//! Determinism is the contract under test: the same declared rows must
//! produce the same analysis and the same replay fingerprint every time.

#![cfg(all(feature = "coordinator", feature = "database"))]

use frf_fuzz::dsfb::database_bridge::{
    analyze, TelemetryRow, MAX_LABEL_BYTES, MAX_ROWS_PER_STREAM,
};

/// A 90 s query-class latency tape distilled by two baseline laws (the same
/// two "revisions" the db regression demo studies, built here hermetically
/// with different arithmetic so the test does not depend on the example).
fn latency_at(i: u64) -> f64 {
    let ramp = i.min(60) as f64 * 3.0;
    // Deterministic whole-ms jitter in [-2, 2]: signed arithmetic (u64 would
    // underflow when the modulo is 0 or 1 in debug builds).
    let jitter = (((i * 7) % 5) as i64 - 2) as f64;
    100.0 + ramp + jitter
}

fn latency_tape(frozen_baseline: bool) -> Vec<TelemetryRow> {
    let mut rows = Vec::new();
    for i in 1..=90u64 {
        let latency = latency_at(i);
        let baseline = if frozen_baseline {
            100.0
        } else if i == 1 {
            latency // clean: previous-sample baseline
        } else {
            latency_at(i - 1)
        };
        rows.push(TelemetryRow::PlanLatency {
            t_ms: i * 1000,
            query_class: "q_scan".to_string(),
            latency_ms: latency,
            baseline_ms: baseline,
        });
    }
    rows
}

#[test]
fn determinism_clean_and_frozen_revisions() {
    let clean = latency_tape(false);
    let frozen = latency_tape(true);
    let a1 = analyze("p6-clean", &clean).expect("clean analysis");
    let a2 = analyze("p6-clean", &clean).expect("clean re-analysis");
    let b1 = analyze("p6-frozen", &frozen).expect("frozen analysis");
    let b2 = analyze("p6-frozen", &frozen).expect("frozen re-analysis");

    assert_eq!(a1.fingerprint_hex, a2.fingerprint_hex);
    assert_eq!(b1.fingerprint_hex, b2.fingerprint_hex);
    assert_eq!(a1.episode_count, a2.episode_count);
    assert_eq!(b1.episode_count, b2.episode_count);
    assert_eq!(a1.sample_count, clean.len());
    assert_eq!(b1.sample_count, frozen.len());
    assert_eq!(a1.source, "p6-clean");

    // The two revisions must read DIFFERENTLY: the frozen baseline develops
    // plan-regression structure the clean one never forms.
    assert_eq!(
        a1.plan_regression_count(),
        0,
        "clean revision invented a plan episode"
    );
    assert_eq!(
        b1.plan_regression_count(),
        1,
        "frozen revision lost its plan episode"
    );
    assert_ne!(a1.fingerprint_hex, b1.fingerprint_hex);
}

#[test]
fn episode_structure_tracks_declared_channels() {
    // Two wait events with independent ramps must yield two contention
    // episodes, each scoped to its own channel.
    let mut rows = Vec::new();
    for i in 0..60u64 {
        let wait_a = if (10..25).contains(&i) { 0.8 } else { 0.0 };
        let wait_b = if (35..50).contains(&i) { 0.6 } else { 0.0 };
        rows.push(TelemetryRow::ContentionWait {
            t_ms: i * 1000,
            wait_event: "LockRow".into(),
            wait_seconds: wait_a,
        });
        rows.push(TelemetryRow::ContentionWait {
            t_ms: i * 1000,
            wait_event: "LockTable".into(),
            wait_seconds: wait_b,
        });
    }
    let a = analyze("p6-channels", &rows).unwrap();
    assert_eq!(a.contention_count(), 2);
    let mut channels: Vec<&str> = a
        .episodes
        .iter()
        .filter(|e| e.motif == "contention_ramp")
        .map(|e| e.channel.as_str())
        .collect();
    channels.sort_unstable();
    assert_eq!(channels, ["LockRow", "LockTable"]);
    assert_eq!(a.plan_regression_count(), 0);
    assert_eq!(a.cardinality_count(), 0);
    assert_eq!(a.cache_io_count(), 0);
    assert_eq!(a.workload_phase_count(), 0);
}

#[test]
fn empty_tape_analyzes_to_no_episodes() {
    let a = analyze("p6-empty", &[]).unwrap();
    assert_eq!(a.episode_count, 0);
    assert_eq!(a.sample_count, 0);
    // dsfb-database's replay fingerprint of the empty episode list is the
    // SHA-256 of the empty byte string (the crate's own determinism lock).
    assert_eq!(
        a.fingerprint_hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn hostile_rows_are_refused_not_coerced() {
    // Non-finite metric.
    let nan = vec![TelemetryRow::PlanLatency {
        t_ms: 0,
        query_class: "q".into(),
        latency_ms: f64::NAN,
        baseline_ms: 100.0,
    }];
    assert!(analyze("p6-nan", &nan).is_err());

    // Out-of-range ratio.
    let hit = vec![TelemetryRow::CacheHitRatio {
        t_ms: 0,
        cache_id: "c".into(),
        expected: 0.9,
        observed: 1.5,
    }];
    assert!(analyze("p6-ratio", &hit).is_err());

    // Over-long label.
    let long = vec![TelemetryRow::ContentionWait {
        t_ms: 0,
        wait_event: "x".repeat(MAX_LABEL_BYTES + 1),
        wait_seconds: 0.1,
    }];
    assert!(analyze("p6-long", &long).is_err());

    // Row-count bound.
    let mut flood = Vec::new();
    for _ in 0..=MAX_ROWS_PER_STREAM {
        flood.push(TelemetryRow::PlanChange {
            t_ms: 0,
            query_class: "q".into(),
        });
    }
    assert!(analyze("p6-flood", &flood).is_err());
}

#[test]
fn row_order_is_irrelevant_after_sort() {
    let rows = latency_tape(true);
    // Deterministic permutation: take indices in a coprime stride order.
    let n = rows.len();
    let permuted: Vec<TelemetryRow> = (0..n).map(|i| rows[(i * 37) % n].clone()).collect();
    let sorted = analyze("p6-order", &rows).unwrap();
    let scrambled = analyze("p6-order", &permuted).unwrap();
    assert_eq!(sorted.fingerprint_hex, scrambled.fingerprint_hex);
    assert_eq!(sorted.episode_count, scrambled.episode_count);
}
