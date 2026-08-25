//! Corpus admission policy.
//!
//! An execution is admitted when (in priority order):
//!
//! * it crashed or timed out (a finding input is always retained), or
//! * it produced at least one packed feature absent from the global feature
//!   set (coverage-guided admission), or
//! * (residual-guided, Phase 2) it produced a globally-new (signal, value
//!   bucket) state feature, or
//! * (residual-guided) its lineage position produced a new morphology
//!   signature — retained as `StructuredUnknown` when no named class
//!   matches (I6; the FuzzSemanticBank is Phase 3) or `NewMorphology` when
//!   a named class applies.
//!
//! The refusal path is explicit: a rejected execution performs no
//! persistent filesystem write (I1). Every corpus dimension is bounded:
//! features are bounded by the counter space, state features by
//! (signal × bucket) pairs, morphologies and entries by hard caps
//! (docs/ARCHITECTURE.md §21).
//!
//! This module is coordinator-gated.

use crate::corpus::entry::AdmissionReason;
use crate::corpus::CorpusIndex;
use crate::dsfb::morphology::StructuralClass;
use crate::observe::residual::MutationResidual;

/// The admission decision for one execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    /// Why this input is admitted.
    pub reason: AdmissionReason,
    /// The features that were new (empty for crash/residual-only admissions).
    pub novel: Vec<u64>,
}

/// The residual-guided inputs to the admission decision.
#[derive(Debug, Clone, Default)]
pub struct ResidualInput {
    /// The child-vs-parent edge residual (Phase 2).
    pub edge: Option<MutationResidual>,
    /// Globally-new (signal, value bucket) state features.
    pub new_state: Vec<(u16, u8)>,
    /// Whether the lineage position produced a new morphology signature.
    pub new_morphology: bool,
    /// The morphology's structural class (Trivial / StructuredUnknown).
    pub morph_class: Option<StructuralClass>,
}

impl ResidualInput {
    /// Whether residual-guided admission is engaged at all for this
    /// execution.
    pub fn engaged(&self) -> bool {
        self.edge.is_some()
    }
}

/// Decide whether an execution is admitted, and why. `features` must be
/// sorted/deduped packed indices (as produced by the worker).
///
/// `residual_enabled` gates the Phase-2 admission reasons; with it off the
/// decision degenerates to Phase-1 coverage-only admission (the ablation
/// switch).
pub fn decide(
    index: &CorpusIndex,
    features: &[u64],
    is_finding: bool,
    residual: Option<&ResidualInput>,
    residual_enabled: bool,
) -> Option<Admission> {
    if is_finding {
        return Some(Admission {
            reason: AdmissionReason::Crash,
            novel: Vec::new(),
        });
    }
    let novel = index.novel_features(features);
    if !novel.is_empty() {
        return Some(Admission {
            reason: AdmissionReason::NewCoverage,
            novel,
        });
    }
    if !residual_enabled {
        return None;
    }
    let r = residual?;
    if !r.new_state.is_empty() {
        return Some(Admission {
            reason: AdmissionReason::NewStateFeature,
            novel: Vec::new(),
        });
    }
    if r.new_morphology {
        return match r.morph_class {
            Some(StructuralClass::StructuredUnknown) => Some(Admission {
                reason: AdmissionReason::StructuredUnknown,
                novel: Vec::new(),
            }),
            Some(StructuralClass::Trivial) => None,
            None => Some(Admission {
                reason: AdmissionReason::NewMorphology,
                novel: Vec::new(),
            }),
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::entry::CorpusMeta;
    use crate::id::ContentId;
    use crate::target_runtime::signals::SignalVector;

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
                signals: SignalVector::new(),
                mutator_id: None,
                morphology_id: None,
                admission_seq: 0,
            })
            .unwrap();
        index
    }

    #[test]
    fn novel_feature_admits() {
        let index = index_with(&[1, 2]);
        let a = decide(&index, &[1, 3], false, None, true).unwrap();
        assert_eq!(a.reason, AdmissionReason::NewCoverage);
        assert_eq!(a.novel, vec![3]);
    }

    #[test]
    fn no_novel_feature_rejects() {
        let index = index_with(&[1, 2]);
        assert_eq!(decide(&index, &[1, 2], false, None, true), None);
        assert_eq!(decide(&index, &[], false, None, true), None);
    }

    #[test]
    fn state_feature_admits() {
        let index = index_with(&[1, 2]);
        let r = ResidualInput {
            edge: None,
            new_state: vec![(0, 5)],
            new_morphology: false,
            morph_class: None,
        };
        let a = decide(&index, &[1, 2], false, Some(&r), true).unwrap();
        assert_eq!(a.reason, AdmissionReason::NewStateFeature);
    }

    #[test]
    fn structured_unknown_admits_as_unknown() {
        let index = index_with(&[1, 2]);
        let r = ResidualInput {
            edge: None,
            new_state: vec![],
            new_morphology: true,
            morph_class: Some(StructuralClass::StructuredUnknown),
        };
        let a = decide(&index, &[1, 2], false, Some(&r), true).unwrap();
        assert_eq!(a.reason, AdmissionReason::StructuredUnknown);
        // I6: never force a nearest label; the class stays StructuredUnknown.
        assert_eq!(r.morph_class.unwrap(), StructuralClass::StructuredUnknown);
    }

    #[test]
    fn trivial_morphology_does_not_admit() {
        let index = index_with(&[1, 2]);
        let r = ResidualInput {
            edge: None,
            new_state: vec![],
            new_morphology: true,
            morph_class: Some(StructuralClass::Trivial),
        };
        assert_eq!(decide(&index, &[1, 2], false, Some(&r), true), None);
    }

    #[test]
    fn residual_off_is_coverage_only() {
        let index = index_with(&[1, 2]);
        let r = ResidualInput {
            edge: None,
            new_state: vec![(0, 5)],
            new_morphology: true,
            morph_class: Some(StructuralClass::StructuredUnknown),
        };
        // With residual off, none of the Phase-2 reasons admit.
        assert_eq!(decide(&index, &[1, 2], false, Some(&r), false), None);
        assert_eq!(
            decide(&index, &[1, 3], false, Some(&r), false)
                .unwrap()
                .reason,
            AdmissionReason::NewCoverage
        );
    }

    #[test]
    fn finding_always_admits() {
        let index = index_with(&[1, 2]);
        let a = decide(&index, &[1, 2], true, None, true).unwrap();
        assert_eq!(a.reason, AdmissionReason::Crash);
        assert!(a.novel.is_empty());
    }
}
