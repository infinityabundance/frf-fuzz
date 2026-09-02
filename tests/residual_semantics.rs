//! Phase-2 integration semantics (residual-guided fuzzing): lineage replay
//! determinism, morphology stability across rebuilds, regime episodes on
//! synthetic series (with the noise negative control), residual admission,
//! two-sided boundary minimization, and the deterministic tape contract.
//!
//! These tests exercise the public library surface end-to-end (store +
//! corpus + observation + dsfb + boundary + tape); the process-level worker
//! paths are covered by `scripts/golden_demo.sh`.

#![cfg(feature = "coordinator")]

use frf_fuzz::canon::Family;
use frf_fuzz::corpus::admission::{decide, ResidualInput};
use frf_fuzz::corpus::entry::{self, AdmissionReason, CorpusMeta};
use frf_fuzz::corpus::CorpusIndex;
use frf_fuzz::dsfb::morphology::{
    classify, LineageAccumulator, MorphologySignature, StructuralClass,
};
use frf_fuzz::dsfb::regime::{RegimeConfig, RegimeObserver, RegimeState};
use frf_fuzz::id::ContentId;
use frf_fuzz::observe::residual::MutationResidual;
use frf_fuzz::store::Store;
use frf_fuzz::target_runtime::signals::{SignalId, SignalVector};

fn tmp_store(tag: &str) -> Store {
    let dir = std::env::temp_dir().join(format!(
        "frf-fuzz-residual-test-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    Store::open(dir).unwrap()
}

fn vec_with(id: u16, v: u64) -> SignalVector {
    let mut s = SignalVector::new();
    s.observe(SignalId(id), v).unwrap();
    s
}

/// Build a synthetic corpus: a seed (signal 0) plus a drifting lineage of
/// children whose signal value climbs by one per generation (all via the
/// same mutator family). Returns the store and the index.
fn build_drifting_corpus(tag: &str, generations: u32) -> (Store, CorpusIndex) {
    let store = tmp_store(tag);
    let mut index = CorpusIndex::new();

    // Seed (baseline observation).
    let seed_id = store.put(Family::CorpusEntry, b"seed").unwrap();
    let seed_meta = CorpusMeta {
        entry_id: seed_id,
        parent_id: None,
        generation: 0,
        features: vec![1],
        reason: AdmissionReason::Seed,
        signals: vec_with(0, 0),
        mutator_id: None,
        morphology_id: None,
        admission_seq: 0,
    };
    store
        .put(Family::CorpusMeta, &entry::encode_meta(&seed_meta).unwrap())
        .unwrap();
    index.insert_meta(seed_meta).unwrap();

    // Children: value climbs by one per generation, always via ByteInsert
    // (mutator 7). All execute the same coverage (feature set {1}).
    let mut parent = seed_id;
    for gen in 1..=generations {
        let input = format!("child-{gen}").into_bytes();
        let id = store.put(Family::CorpusEntry, &input).unwrap();
        let meta = CorpusMeta {
            entry_id: id,
            parent_id: Some(parent),
            generation: gen,
            features: vec![1],
            reason: AdmissionReason::NewStateFeature,
            signals: vec_with(0, u64::from(gen)),
            mutator_id: Some(7),
            morphology_id: None, // filled after morphology computation below
            admission_seq: u64::from(gen),
        };
        store
            .put(Family::CorpusMeta, &entry::encode_meta(&meta).unwrap())
            .unwrap();
        index.insert_meta(meta.clone()).unwrap();
        parent = id;
    }
    (store, index)
}

#[test]
fn lineage_replay_is_deterministic_and_morphology_is_stable() {
    let (_store, index) = build_drifting_corpus("lineage", 20);
    let seed = index.root_of(index.iter().next().unwrap().0).unwrap();
    let seed_signals = index.meta(&seed).unwrap().signals.clone();
    // The deepest child = the last by admission order (deterministic).
    let last_entry_id = index.by_admission_order().last().unwrap().entry_id;

    // Replay the lineage twice, independently: identical signatures.
    let replay = |index: &CorpusIndex| -> (Vec<ContentId>, Vec<MorphologySignature>) {
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&seed_signals);
        let mut ids = Vec::new();
        let mut sigs = Vec::new();
        for meta in index.lineage_chain(&last_entry_id, 7) {
            let parent_signals = meta
                .parent_id
                .and_then(|p| index.meta(&p))
                .map(|m| m.signals.clone())
                .unwrap_or_default();
            let edge = MutationResidual::of(&meta.signals, &parent_signals);
            let sig = acc.push(&edge, meta.generation);
            let enc = sig.encode().unwrap();
            let framed = frf_fuzz::canon::frame(Family::MorphologySignature, 0, 1, &enc).unwrap();
            ids.push(ContentId::new(&framed));
            sigs.push(sig);
        }
        (ids, sigs)
    };
    let (ids_a, sigs_a) = replay(&index);
    let (ids_b, sigs_b) = replay(&index);
    assert_eq!(ids_a, ids_b);
    assert_eq!(sigs_a, sigs_b);

    // The drifting lineage is structurally active and (Phase 2) unnamed.
    let last = sigs_a.last().unwrap();
    assert_eq!(classify(last), StructuralClass::StructuredUnknown);
    assert!(last.structured_unknown);
    // Every intermediate signature is distinct (the trajectory is retained
    // step by step, not collapsed).
    let mut distinct: std::collections::BTreeSet<ContentId> = std::collections::BTreeSet::new();
    distinct.extend(ids_a.iter());
    assert_eq!(distinct.len(), 20);
}

#[test]
fn regime_episode_forms_on_drift_and_noise_stays_stable() {
    let cfg = RegimeConfig::default_config();
    // Drift series: value == ordinal, then flat.
    let mut series = Vec::new();
    for i in 0..200u64 {
        series.push((i, i));
    }
    for i in 200..400u64 {
        series.push((i, 200));
    }
    let mut obs = RegimeObserver::new(cfg);
    let mut episodes = 0usize;
    for (o, v) in &series {
        if obs.feed(*o, *v).is_some() {
            episodes += 1;
        }
    }
    assert_eq!(
        episodes, 1,
        "a sustained drift must form exactly one episode"
    );
    // The episode closed deterministically (recovery dwell); the observer
    // may already be back to Stable by the end of the flat tail.
    assert!(!obs.episode_open());
    assert!(matches!(
        obs.state(),
        RegimeState::Recovering | RegimeState::Stable
    ));

    // Negative control: noise around a constant must stay Stable.
    let mut obs = RegimeObserver::new(cfg);
    for i in 0..256u64 {
        let v = if i % 2 == 0 { 100 } else { 101 };
        obs.feed(i, v);
    }
    assert_eq!(obs.state(), RegimeState::Stable);
    assert!(!obs.episode_open());
}

#[test]
fn residual_admission_ladder() {
    let store = tmp_store("admission");
    let mut index = CorpusIndex::new();
    let seed_id = store.put(Family::CorpusEntry, b"seed").unwrap();
    let seed_meta = CorpusMeta {
        entry_id: seed_id,
        parent_id: None,
        generation: 0,
        features: vec![1],
        reason: AdmissionReason::Seed,
        signals: SignalVector::new(),
        mutator_id: None,
        morphology_id: None,
        admission_seq: 0,
    };
    store
        .put(Family::CorpusMeta, &entry::encode_meta(&seed_meta).unwrap())
        .unwrap();
    index.insert_meta(seed_meta).unwrap();

    // No new coverage, but a new state bucket: NewStateFeature.
    let r = ResidualInput {
        edge: None,
        new_state: vec![(0, 5)],
        new_morphology: false,
        morph_class: None,
    };
    let a = decide(&index, &[1], false, Some(&r), true).unwrap();
    assert_eq!(a.reason, AdmissionReason::NewStateFeature);

    // A new structured morphology (unnamed): StructuredUnknown, not a label.
    let r = ResidualInput {
        edge: None,
        new_state: vec![],
        new_morphology: true,
        morph_class: Some(StructuralClass::StructuredUnknown),
    };
    let a = decide(&index, &[1], false, Some(&r), true).unwrap();
    assert_eq!(a.reason, AdmissionReason::StructuredUnknown);

    // With residual disabled: coverage only (the ablation switch).
    assert_eq!(decide(&index, &[1], false, Some(&r), false), None);

    // Nothing new: rejected (I1: no admission).
    let r = ResidualInput::default();
    assert_eq!(decide(&index, &[1], false, Some(&r), true), None);
}

#[test]
fn two_sided_minimization_preserves_the_distinction() {
    use frf_fuzz::boundary::minimize::{byte_distance, minimize_pair, PairSide};

    let left = vec![0u8; 64];
    let right = vec![0xFFu8; 64];
    let mut verify = |input: &[u8]| -> Result<PairSide, frf_fuzz::error::Error> {
        if input.iter().any(|b| *b >= 0x80) {
            Ok(PairSide::Right)
        } else {
            Ok(PairSide::Left)
        }
    };
    let outcome = minimize_pair(&left, &right, 1_000_000, &mut verify).unwrap();
    assert!(outcome.end_distance < outcome.start_distance);
    assert_eq!(outcome.end_distance, 255);
    assert!(verify(&outcome.left).unwrap() == PairSide::Left);
    assert!(verify(&outcome.right).unwrap() == PairSide::Right);
    assert_eq!(
        byte_distance(&outcome.left, &outcome.right),
        outcome.end_distance
    );
}

#[test]
fn tape_contract_matches_and_diverges() {
    use frf_fuzz::tape::model::{RunTape, TapeObservation, TerminationStatus};
    use frf_fuzz::tape::replay::replay_tape_payload;
    use frf_fuzz::tape::replay::TapeReplayOutcome;

    let mut signals = SignalVector::new();
    signals.observe(SignalId(0), 7).unwrap();
    let tape = RunTape {
        build_digest: [0; 32],
        environment_digest: [0; 32],
        candidate: b"candidate".to_vec(),
        coordinate: None,
        scheduler_mode: 0,
        observation: Some(TapeObservation {
            features: vec![1, 2],
            signals: signals.clone(),
            sketch: frf_fuzz::target_runtime::signals::ResidualSketch::of(
                &SignalVector::new(),
                &signals,
            ),
            cmp_events: vec![],
            time_bucket: 0,
        }),
        termination: TerminationStatus::Ok,
        lineage: None,
        source: frf_fuzz::tape::model::TapeSource::Admission,
    };

    // A live execution that reproduces the observation matches (I12).
    let mut ok = |_: &[u8]| -> Result<(bool, SignalVector, Vec<u64>), frf_fuzz::error::Error> {
        let mut s = SignalVector::new();
        s.observe(SignalId(0), 7).unwrap();
        Ok((false, s, vec![1, 2]))
    };
    assert_eq!(
        replay_tape_payload(&tape, &mut ok).unwrap(),
        TapeReplayOutcome::Matches
    );

    // A divergent observation is preserved as instability (I10), not fixed.
    let mut bad = |_: &[u8]| -> Result<(bool, SignalVector, Vec<u64>), frf_fuzz::error::Error> {
        let mut s = SignalVector::new();
        s.observe(SignalId(0), 999).unwrap();
        Ok((false, s, vec![1, 2]))
    };
    assert!(matches!(
        replay_tape_payload(&tape, &mut bad).unwrap(),
        TapeReplayOutcome::Diverged { .. }
    ));
}

#[test]
fn store_roundtrips_all_phase2_families() {
    use frf_fuzz::tape::model::TapeSource;
    use frf_fuzz::tape::model::{RunTape, TerminationStatus};
    let store = tmp_store("families");
    // Morphology object.
    let sig = MorphologySignature::trivial(0);
    let mid = store
        .put(Family::MorphologySignature, &sig.encode().unwrap())
        .unwrap();
    // Corpus meta referencing it.
    let mut signals = SignalVector::new();
    signals.observe(SignalId(0), 3).unwrap();
    let meta = CorpusMeta {
        entry_id: store.put(Family::CorpusEntry, b"in").unwrap(),
        parent_id: None,
        generation: 0,
        features: vec![1],
        reason: AdmissionReason::Seed,
        signals,
        mutator_id: None,
        morphology_id: Some(mid),
        admission_seq: 0,
    };
    store
        .put(Family::CorpusMeta, &entry::encode_meta(&meta).unwrap())
        .unwrap();
    // Regime episode object.
    let mut obs = RegimeObserver::new(RegimeConfig::default_config());
    let mut closed = None;
    for i in 0..300u64 {
        let v = if i < 200 { i } else { 200 };
        if let Some(ep) = obs.feed(i, v) {
            closed = Some(ep);
        }
    }
    let ep = closed.expect("the drift series must close an episode");
    store
        .put(
            Family::RegimeEpisode,
            &frf_fuzz::dsfb::regime::encode_episode(&ep).unwrap(),
        )
        .unwrap();
    // Boundary witness object.
    let witness = frf_fuzz::boundary::witness::BoundaryWitness {
        left: meta.entry_id,
        right: ContentId::new(b"right"),
        left_input: b"aa".to_vec(),
        right_input: b"bb".to_vec(),
        relation: frf_fuzz::boundary::witness::BoundaryRelation::StableCrash,
        distance: 2,
        verification: frf_fuzz::boundary::witness::WitnessVerification::Verified,
        tape: None,
    };
    store
        .put(
            Family::BoundaryWitness,
            &frf_fuzz::boundary::witness::encode_witness(&witness).unwrap(),
        )
        .unwrap();
    // Tape object.
    let tape = RunTape {
        build_digest: [1; 32],
        environment_digest: [2; 32],
        candidate: b"t".to_vec(),
        coordinate: None,
        scheduler_mode: 0,
        observation: None,
        termination: TerminationStatus::Ok,
        lineage: None,
        source: TapeSource::Replay,
    };
    store
        .put(
            Family::RunTape,
            &frf_fuzz::tape::model::encode_tape(&tape).unwrap(),
        )
        .unwrap();

    // Rebuild the index and run the fsck link checks: everything resolves.
    let index = CorpusIndex::rebuild(&store).unwrap();
    assert_eq!(index.len(), 1);
    assert!(index.meta(&meta.entry_id).is_some());
    let errors = frf_fuzz::report::corpus_link_check(store.root()).unwrap();
    assert!(errors.is_empty(), "fsck errors: {errors:?}");
    // The morphology object round-trips to the identical signature.
    let payload = store.get(&mid).unwrap().unwrap();
    assert_eq!(MorphologySignature::decode(&payload).unwrap(), sig);
}
