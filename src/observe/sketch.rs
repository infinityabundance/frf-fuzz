//! Sketch and batch-summary interpretation (coordinator side).
//!
//! Pure deterministic functions over the worker's cheap Level-0 forms:
//! state-feature buckets for the bounded global state set, and batch-drift
//! detection that decides when a (parent, mutator) lineage deserves an
//! AMPLIFY order. No mutable state; everything is derived from immutable
//! inputs so rebuilds are exact.

use crate::target_runtime::signals::{
    magnitude_bucket, value_bucket, SignalBatchSummary, SignalVector, MAX_SIGNALS,
};

/// The state-feature pairs (signal, value bucket) an observation covers.
///
/// The global state-feature set is bounded by construction: at most
/// `MAX_SIGNALS × 180` pairs.
pub fn state_buckets(v: &SignalVector) -> Vec<(u16, u8)> {
    let mut out = Vec::with_capacity(MAX_SIGNALS);
    for i in 0..MAX_SIGNALS {
        let id = crate::target_runtime::signals::SignalId(i as u16);
        if v.was_touched(id) {
            out.push((i as u16, value_bucket(v.value(id))));
        }
    }
    out
}

/// A batch-drift observation: one signal moved persistently across a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchDrift {
    /// The signal.
    pub signal: u16,
    /// Executions touching it (>= min_count by construction).
    pub count: u32,
    /// Maximum same-direction run observed.
    pub max_run: u8,
    /// Exact sum of |delta| across the batch.
    pub sum_abs_delta: u64,
}

/// Detect persistent drift in a batch summary: a signal whose executions
/// (count >= `min_count`) accumulated a total magnitude bucket
/// (`magnitude_bucket(sum_abs_delta) >= min_sum_bucket`) AND showed a
/// same-direction run of at least `min_run`.
///
/// The direction is deliberately NOT part of the result: the regime observer
/// determines direction persistence; this detector only says "this signal
/// moved a lot and consistently within this batch".
pub fn batch_drifts(
    summary: &SignalBatchSummary,
    min_count: u32,
    min_run: u8,
    min_sum_bucket: u8,
) -> Vec<BatchDrift> {
    let mut out = Vec::new();
    for i in 0..MAX_SIGNALS {
        if summary.touched & (1u64 << i) == 0 {
            continue;
        }
        if summary.count[i] < min_count {
            continue;
        }
        if summary.max_run[i] < min_run {
            continue;
        }
        if magnitude_bucket(summary.sum_abs_delta[i]) < min_sum_bucket {
            continue;
        }
        out.push(BatchDrift {
            signal: i as u16,
            count: summary.count[i],
            max_run: summary.max_run[i],
            sum_abs_delta: summary.sum_abs_delta[i],
        });
    }
    out
}

/// A deterministic fixed-point AMPLIFY priority for a drifting lineage.
///
/// Integer only; higher = more urgent. Combines the dominant drift's
/// magnitude bucket (high bits) with its persistence run and count. Ties
/// are broken by the caller (entry ID order).
pub fn drift_priority(drifts: &[BatchDrift]) -> u64 {
    let mut best: Option<(u64, u16)> = None;
    for d in drifts {
        let mag = u64::from(magnitude_bucket(d.sum_abs_delta));
        let p = (mag << 32) | (u64::from(d.max_run) << 16) | (u64::from(d.count) & 0xFFFF);
        if best.map(|(b, _)| p > b).unwrap_or(true) {
            best = Some((p, d.signal));
        }
    }
    let (p, _) = best.unwrap_or((0, 0));
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target_runtime::signals::{ResidualSketch, SignalId};

    #[test]
    fn state_buckets_of_observation() {
        let mut v = SignalVector::new();
        v.observe(SignalId(0), 5).unwrap();
        v.observe(SignalId(2), 100).unwrap();
        let mut pairs = state_buckets(&v);
        pairs.sort();
        assert_eq!(pairs, vec![(0, 5), (2, 65)]);
    }

    #[test]
    fn batch_drifts_fires_on_persistent_batch() {
        let mut summary = SignalBatchSummary::new();
        let mut tracker = crate::target_runtime::signals::OrderSignalTracker::new();
        // 10 consecutive +1 steps on signal 0.
        let mut cur = SignalVector::new();
        cur.observe(SignalId(0), 0).unwrap();
        for _ in 0..10 {
            let mut next = SignalVector::new();
            next.observe(SignalId(0), cur.value(SignalId(0)) + 1)
                .unwrap();
            let d = crate::target_runtime::signals::deltas(&cur, &next);
            let sketch = ResidualSketch::of(&cur, &next);
            summary.push_deltas(&next, &d);
            summary.max_run[0] = summary.max_run[0].max(tracker.run[0]);
            tracker.push(&d, &sketch, 4, 4);
            summary.max_run[0] = summary.max_run[0].max(tracker.run[0]);
            cur = next;
        }
        let drifts = batch_drifts(&summary, 4, 4, 4);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].signal, 0);
        assert_eq!(drifts[0].sum_abs_delta, 10);
        assert!(drifts[0].max_run >= 4);
        assert!(drift_priority(&drifts) > 0);
    }

    #[test]
    fn batch_drifts_stays_silent_on_noise() {
        // Values oscillating around a constant produce short runs and
        // canceling deltas; the detector must stay silent (negative
        // control: no invented drift in noise, §32).
        let mut summary = SignalBatchSummary::new();
        let mut tracker = crate::target_runtime::signals::OrderSignalTracker::new();
        let mut cur = SignalVector::new();
        cur.observe(SignalId(0), 100).unwrap();
        let mut v = 100u64;
        for _ in 0..64 {
            v = if v == 100 { 101 } else { 100 };
            let mut next = SignalVector::new();
            next.observe(SignalId(0), v).unwrap();
            let d = crate::target_runtime::signals::deltas(&cur, &next);
            let sketch = ResidualSketch::of(&cur, &next);
            summary.push_deltas(&next, &d);
            tracker.push(&d, &sketch, 4, 4);
            summary.max_run[0] = summary.max_run[0].max(tracker.run[0]);
            cur = next;
        }
        // max_run never reaches 4 (direction flips every sample).
        let drifts = batch_drifts(&summary, 4, 4, 4);
        assert!(drifts.is_empty());
    }
}
