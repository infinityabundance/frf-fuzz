//! Corpus admission policy (Phase 1: coverage-guided).
//!
//! An execution is admitted when:
//!
//! * it crashed or timed out (a finding input is always retained), or
//! * it produced at least one packed feature absent from the global
//!   feature set.
//!
//! Phase-2 extends this ladder with state features, morphology signatures,
//! structured-Unknown trajectories, counterfactual boundary pairs, smaller
//! representatives, and higher-stability representatives (docs/ARCHITECTURE
//! .md §21). The refusal path is explicit: a rejected execution performs no
//! persistent filesystem write (I1).
//!
//! This module is coordinator-gated.

use crate::corpus::entry::AdmissionReason;
use crate::corpus::CorpusIndex;

/// The admission decision for one execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    /// Why this input is admitted.
    pub reason: AdmissionReason,
    /// The features that were new (empty for crash-only admissions).
    pub novel: Vec<u64>,
}

/// Decide whether an execution is admitted, and why. `features` must be
/// sorted/deduped packed indices (as produced by the worker).
pub fn decide(index: &CorpusIndex, features: &[u64], is_finding: bool) -> Option<Admission> {
    if is_finding {
        return Some(Admission {
            reason: AdmissionReason::Crash,
            novel: Vec::new(),
        });
    }
    let novel = index.novel_features(features);
    if novel.is_empty() {
        None
    } else {
        Some(Admission {
            reason: AdmissionReason::NewCoverage,
            novel,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::entry::CorpusMeta;
    use crate::id::ContentId;

    fn index_with(features: &[u64]) -> CorpusIndex {
        let mut index = CorpusIndex::new();
        let id = ContentId::new(b"seed");
        index
            .insert_meta(CorpusMeta {
                entry_id: id,
                parent_id: None,
                generation: 0,
                features: features.to_vec(),
                reason: AdmissionReason::Seed,
            })
            .unwrap();
        index
    }

    #[test]
    fn novel_feature_admits() {
        let index = index_with(&[1, 2]);
        let a = decide(&index, &[1, 3], false).unwrap();
        assert_eq!(a.reason, AdmissionReason::NewCoverage);
        assert_eq!(a.novel, vec![3]);
    }

    #[test]
    fn no_novel_feature_rejects() {
        let index = index_with(&[1, 2]);
        assert_eq!(decide(&index, &[1, 2], false), None);
        assert_eq!(decide(&index, &[], false), None);
    }

    #[test]
    fn finding_always_admits() {
        let index = index_with(&[1, 2]);
        let a = decide(&index, &[1, 2], true).unwrap();
        assert_eq!(a.reason, AdmissionReason::Crash);
        assert!(a.novel.is_empty());
    }
}
