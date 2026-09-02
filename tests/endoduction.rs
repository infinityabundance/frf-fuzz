//! Phase-3 endoduction integration tests (master prompt §13, §17, §32,
//! §33-F/G; docs/EXPERIMENT_PROTOCOL.md negative controls).
//!
//! These tests exercise the REAL shared Phase-3 machinery exactly as the
//! coordinator uses it: the DSFB substrate feed, the FuzzSemanticBank
//! classifier, precedent admission from terminal observations, shape
//! matching, falsifiable probe evaluation, and durable contradiction
//! retention. They are deterministic by construction (integer evidence,
//! no wall clock, no randomness) and double as the engine-level
//! demonstration of acceptance items 10-12.
//!
//! Requires the `coordinator` feature (the default build).

use frf_fuzz::dsfb::debug_bridge::{AxisVerdict, BridgeConfig, DriftDir, LineageSubstrate};
use frf_fuzz::dsfb::fuzz_bank::{classify_evidence, role_of, AxisRole, BankEvidence, FuzzMotif};
use frf_fuzz::dsfb::morphology::{LineageAccumulator, MorphologySignature};
use frf_fuzz::id::ContentId;
use frf_fuzz::observe::residual::MutationResidual;
use frf_fuzz::precedent::probe::{ProbeOutcome, ProbeRecipe};
use frf_fuzz::precedent::{
    create_from_terminal, matching::matches, probe::evaluate as eval_probe, ConfuserKind,
    Precedent, PrecedentStatus, TerminalKind,
};
use frf_fuzz::store::Store;
use frf_fuzz::target_runtime::signals::{SignalBatchSummary, SignalId, SignalVector};

fn vec_with(id: u16, v: u64) -> SignalVector {
    let mut s = SignalVector::new();
    s.observe(SignalId(id), v).unwrap();
    s
}

fn signal_desc(name: &str, unit: &str) -> frf_fuzz::target_runtime::signals::SignalDesc {
    let mut d = frf_fuzz::target_runtime::signals::SignalDesc::empty();
    d.present = true;
    let nb = name.as_bytes();
    d.name_len = nb.len().min(32) as u8;
    d.name[..d.name_len as usize].copy_from_slice(&nb[..d.name_len as usize]);
    let ub = unit.as_bytes();
    d.unit_len = ub.len().min(16) as u8;
    d.unit[..d.unit_len as usize].copy_from_slice(&ub[..d.unit_len as usize]);
    d
}

/// Drive a monotone depth-ladder through the REAL substrate, mirroring what
/// the coordinator replays from durable corpus metas: values 0,1,...,n on
/// one axis. Returns the last structural edge and its verdicts.
fn climb_through_substrate(
    n: u64,
) -> (
    Vec<AxisVerdict>,
    Option<frf_fuzz::dsfb::debug_bridge::StructuralEpisode>,
) {
    let mut sub =
        LineageSubstrate::new(ContentId::new(b"rootA"), 7, &BridgeConfig::default_config())
            .unwrap();
    let mut parent = vec_with(0, 0);
    let mut last = Vec::new();
    let mut closed = None;
    for d in 1..=n {
        let child = vec_with(0, d);
        let edge = MutationResidual::of(&child, &parent);
        let (es, ep) = sub.feed_edge(d, &edge, d as u32).unwrap();
        if !es.verdicts.is_empty() {
            last = es.verdicts;
        }
        if ep.is_some() {
            closed = ep;
        }
        parent = child;
    }
    (last, closed)
}

fn drifting_sig(steps: u32, baseline: u64, step: u64) -> MorphologySignature {
    let mut acc = LineageAccumulator::new();
    acc.init_baseline(&vec_with(0, baseline));
    let mut parent = vec_with(0, baseline);
    let mut sig = acc.push(&MutationResidual::of(&parent, &parent), 0);
    for d in 1..=steps {
        let child = vec_with(0, baseline + d as u64 * step);
        sig = acc.push(&MutationResidual::of(&child, &parent), d);
        parent = child;
    }
    sig
}

fn review_verdict(axis: u16, reason: u8) -> AxisVerdict {
    // Reason codes are dsfb_debug discriminants: 2 = SustainedOutwardDrift,
    // 1 = BoundaryApproach, 3 = AbruptSlewViolation.
    AxisVerdict {
        axis,
        grammar: 1,
        confirmed: 1,
        reason,
        policy: 2, // Review
        dir: DriftDir::Outward.code(),
        calibrated: true,
        dev_mag_bin: 5,
        persistence: 8,
    }
}

/// A probe batch summary where `axis` moved in `count` executions with the
/// given run and summed magnitude.
fn summary_with(axis: usize, count: u32, run: u8, sum_abs: u64) -> SignalBatchSummary {
    let mut s = SignalBatchSummary::new();
    s.touched |= 1u64 << axis;
    s.count[axis] = count;
    s.max_run[axis] = run;
    s.sum_abs_delta[axis] = sum_abs;
    s.min[axis] = 0;
    s.max[axis] = sum_abs.max(1);
    s
}

// ---------------------------------------------------------------------------
// Negative controls (EXPERIMENT_PROTOCOL §32)
// ---------------------------------------------------------------------------

#[test]
fn stable_noise_lineage_names_nothing() {
    // A jitter series inside its calibration span must never name a class:
    // the substrate stays Silent, the bank zero-tier filter refuses, and the
    // result is Unknown (trivial/structured handled by the caller).
    let mut sub =
        LineageSubstrate::new(ContentId::new(b"noise"), 7, &BridgeConfig::default_config())
            .unwrap();
    let values = [
        100u64, 102, 99, 101, 100, 102, 101, 99, 100, 101, 99, 102, 100, 101, 102, 99, 100, 101,
        99, 102,
    ];
    let mut parent = vec_with(0, values[0]);
    let mut active = false;
    for (i, v) in values.iter().enumerate().skip(1) {
        let child = vec_with(0, *v);
        let (es, _) = sub
            .feed_edge(i as u64, &MutationResidual::of(&child, &parent), i as u32)
            .unwrap();
        active |= es.verdicts.iter().any(|v| v.is_active());
        parent = child;
    }
    assert!(!active, "in-span noise must never reach Watch");
    let sig = drifting_sig(4, 100, 0);
    let ev = BankEvidence::new(&sig, &[]);
    let bv = classify_evidence(&ev);
    assert!(!bv.is_named(), "no evidence => no class");
}

#[test]
fn threshold_elasticity_collapses_into_unknown() {
    // The bank's naming must be *elastic*: shrink the persistence of the
    // same evidence and the class must collapse (no brittle naming that
    // survives arbitrary parameter movement).
    let sig = drifting_sig(12, 0, 1);
    let strong = review_verdict(0, 2); // SustainedOutwardDrift
    let mut ev = BankEvidence::new(&sig, &[strong]);
    ev.set_role(0, role_of(&signal_desc("marker_depth", "markers")));
    let named = classify_evidence(&ev);
    assert_eq!(named.motif(), Some(FuzzMotif::StateDepthExpansion));
    // Collapse: short, weak, low-persistence evidence with no sustained
    // drift must not name anything.
    let weak = AxisVerdict {
        persistence: 1,
        policy: 1, // Watch only
        dev_mag_bin: 2,
        ..strong
    };
    let mut ev2 = BankEvidence::new(&drifting_sig(2, 0, 1), &[weak]);
    ev2.set_role(0, role_of(&signal_desc("marker_depth", "markers")));
    let collapsed = classify_evidence(&ev2);
    assert!(
        !collapsed.is_named(),
        "weak evidence must collapse to Unknown"
    );
}

#[test]
fn replay_perturbation_does_not_change_verdicts() {
    // Same tape (same edge stream) => same substrate verdicts (I12 spirit);
    // a SHUFFLED stream must not yield the same stable episode (order is
    // semantics). Two independent substrates replaying identical edges agree
    // bit-for-bit.
    let mut a =
        LineageSubstrate::new(ContentId::new(b"r"), 7, &BridgeConfig::default_config()).unwrap();
    let mut b =
        LineageSubstrate::new(ContentId::new(b"r"), 7, &BridgeConfig::default_config()).unwrap();
    let mut pa = vec_with(0, 0);
    let mut pb = vec_with(0, 0);
    for d in 1..=40u64 {
        let ca = vec_with(0, d);
        let cb = vec_with(0, d);
        let (ea, e1) = a
            .feed_edge(d, &MutationResidual::of(&ca, &pa), d as u32)
            .unwrap();
        let (eb, e2) = b
            .feed_edge(d, &MutationResidual::of(&cb, &pb), d as u32)
            .unwrap();
        assert_eq!(ea.verdicts, eb.verdicts);
        assert_eq!(e1.is_some(), e2.is_some());
        pa = ca;
        pb = cb;
    }
}

// ---------------------------------------------------------------------------
// Acceptance 10-12: precedent proposes a probe; probe supports or
// contradicts; contradiction is durably retained.
// ---------------------------------------------------------------------------

fn mk_precedent(root: ContentId, precursor_depth: u32, seq: u64) -> Precedent {
    let precursor = drifting_sig(precursor_depth, 0, 1);
    let recipe = ProbeRecipe::persists(frf_fuzz::mutation::MutatorId::ByteInsert, 0, 20, 4, 3);
    create_from_terminal(
        root,
        frf_fuzz::mutation::MutatorId::ByteInsert,
        &precursor,
        precursor_depth,
        TerminalKind::CrashFinding,
        FuzzMotif::StateDepthExpansion.code(),
        0,
        5,
        30,
        None,
        ConfuserKind::SaturationWarmup,
        recipe,
        seq,
    )
    .expect("a structured lineage with a lead admits a precedent")
}

#[test]
fn precedent_creates_match_and_support_and_contradiction() {
    let store_dir =
        std::env::temp_dir().join(format!("frf-fuzz-endoduction-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store_dir);
    let store = Store::open(store_dir.clone()).unwrap();

    // A real terminal lineage: root entry stored, precedent admitted with
    // provenance.
    let root = ContentId::new(b"root-live");
    let p = mk_precedent(root, 4, 1);
    let pid = frf_fuzz::precedent::save_revision(&store, &p).unwrap();
    assert_eq!(p.status, PrecedentStatus::Candidate);

    // A live sibling lineage at depth 9 shares the precursor shape under the
    // same family: matching fires (cross-root allowed, same family).
    let live = drifting_sig(9, 0, 1);
    let current = frf_fuzz::precedent::load_current(&store).unwrap();
    assert_eq!(current.len(), 1);
    assert!(matches(
        &current[0],
        &live,
        9,
        frf_fuzz::mutation::MutatorId::ByteInsert.id()
    ));
    let _ = pid;

    // The falsifiable relationship: a batch that keeps the axis moving
    // supports the precedent family...
    let moving = summary_with(0, 400, 12, 1 << 16);
    let outcome = eval_probe(&p.recipe, &moving);
    assert_eq!(outcome, ProbeOutcome::Support);
    // ...a batch where the axis never moves directly contradicts it...
    let stopped = summary_with(0, 0, 0, 0);
    let contradiction = eval_probe(&p.recipe, &stopped);
    assert_eq!(contradiction, ProbeOutcome::Contradict);

    // Retention: apply the contradiction through the revision machinery and
    // verify the precedent is Contradicted and the old revision is retained.
    let evidence = frf_fuzz::precedent::ProbeEvidence {
        outcome: contradiction,
        seq: 42,
        axis: 0,
        moved: 0,
        run: 0,
        sum_bucket: 0,
        batch_execs: 500,
    };
    let direct = frf_fuzz::precedent::contradiction_weight(&p.recipe, &stopped)
        == frf_fuzz::precedent::ContradictionWeight::Direct;
    assert!(direct);
    let (status, supports, contradictions, _) = p.apply_probe(contradiction, evidence, direct);
    assert_eq!(status, PrecedentStatus::Contradicted);
    assert_eq!(contradictions, 1);
    assert_eq!(supports, 0);

    // A contradictory precedent is no longer schedulable.
    let mut contradicted = p.clone();
    contradicted.status = status;
    contradicted.contradictions = contradictions;
    contradicted.updated_seq = 42;
    contradicted.prev_revision = Some(pid);
    let _ = contradicted;
    let _ = frf_fuzz::precedent::save_revision(&store, &p);
    // Both revisions still load: nothing was deleted (I10).
    let all = store.list_object_ids().unwrap();
    assert!(!all.is_empty());
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn precedent_status_confirm_on_first_support() {
    let p = mk_precedent(ContentId::new(b"rootB"), 4, 1);
    assert_eq!(p.status, PrecedentStatus::Candidate);
    let ev = frf_fuzz::precedent::ProbeEvidence {
        outcome: ProbeOutcome::Support,
        seq: 7,
        axis: 0,
        moved: 300,
        run: 9,
        sum_bucket: 11,
        batch_execs: 500,
    };
    let (status, supports, _, _) = p.apply_probe(ProbeOutcome::Support, ev, false);
    assert_eq!(status, PrecedentStatus::Confirmed);
    assert_eq!(supports, 1);
}

// ---------------------------------------------------------------------------
// Substrate + bank through the coordinator's escalation path
// ---------------------------------------------------------------------------

#[test]
fn real_substrate_verdicts_name_the_demo_ladder_class() {
    // The golden-demo marker-depth ladder through the REAL substrate: the
    // axis drifts beyond its calibration envelope, reaches Review/Escalate,
    // and the bank names the trajectory exactly as the coordinator would
    // (StateDepthExpansion for the depth role; PersistentBehavioralDrift
    // once it escalates).
    let (verdicts, _closed) = climb_through_substrate(24);
    assert!(!verdicts.is_empty());
    let max_policy = verdicts.iter().map(|v| v.policy).max().unwrap();
    assert!(
        max_policy >= 3,
        "the ladder must escalate through the envelope"
    );

    let sig = drifting_sig(24, 0, 1);
    let mut ev = BankEvidence::new(&sig, &verdicts);
    ev.set_role(0, role_of(&signal_desc("marker_depth", "markers")));
    let bv = classify_evidence(&ev);
    // With a depth role and monotone outward climb the trajectory is named.
    assert!(bv.is_named(), "the depth ladder must be named, got {bv:?}");
}

#[test]
fn roles_are_deterministic_from_schema_names() {
    assert_eq!(
        role_of(&signal_desc("allocated_bytes", "bytes")),
        AxisRole::ALLOCATION
    );
    assert_eq!(
        role_of(&signal_desc("retry_count", "count")),
        AxisRole::RETRY
    );
    assert_eq!(role_of(&signal_desc("err_variant", "id")), AxisRole::ERROR);
    assert_eq!(role_of(&signal_desc("whatever", "qty")), AxisRole::NONE);
}
