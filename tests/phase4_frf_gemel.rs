//! Phase 4 integration tests: FRF court verification + Gemel boundaries.
//!
//! These tests exercise the REAL `frf` and `gemel` crates:
//!
//! * an FRF court runs actual side processes (admission, capture, residuals,
//!   receipts) through `frf-fuzz`'s bridge — no mocks;
//! * a Gemel repository is initialized, given a head state, and receives
//!   durable boundary publications (evidence/claim/residual/checkpoint);
//! * the local store stays fsck-clean after every boundary.
//!
//! The court sides are POSIX-shell scripts (pure builtins — no external
//! binaries), matching the `--frf-fuzz-fixture <path>` argv convention an
//! instrumented target binary implements. This keeps the wiring tests fast
//! and hermetic while exercising the exact same FRF code path a real
//! campaign verification uses.

#![cfg(feature = "coordinator")]

use frf_fuzz::canon::Family;
use frf_fuzz::error::Result;
use frf_fuzz::frf_bridge::{self, AuthoritySpec, CourtQuestion, VerificationOutcome};
use frf_fuzz::gemel_bridge::{self, BoundaryKind, PublishState};
use frf_fuzz::id::ContentId;
use frf_fuzz::store::Store;

fn tmp_project(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "frf-fuzz-phase4-{tag}-{}-{}",
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

fn write_script(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let content = format!("#!/bin/sh\n{body}\n");
    std::fs::write(path, content).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

fn authority_script(path: &std::path::Path) {
    // The reference: accepts every input (exit 0).
    write_script(path, "exit 0");
}

fn crashing_candidate_script(path: &std::path::Path) {
    // The candidate: diverges (exit 1) exactly when the fixture carries the
    // crash marker; otherwise behaves like the reference (exit 0).
    write_script(
        path,
        "IFS= read -r line < \"$2\"\nif [ \"$line\" = \"crash-marker\" ]; then\n  exit 1\nfi\nexit 0",
    );
}

fn benign_candidate_script(path: &std::path::Path) {
    // A candidate that never diverges from the reference.
    write_script(path, "exit 0");
}

fn store_a_finding(project: &std::path::Path, input: &[u8]) -> (Store, ContentId) {
    let store = Store::open(project.join(".frf-fuzz")).unwrap();
    let finding = frf_fuzz::execute::finding::Finding {
        kind: frf_fuzz::execute::finding::FindingKind::Crash,
        parent_short: [0; 8],
        coordinate: [0; 49],
        replay: frf_fuzz::execute::finding::ReplayStatus::Reproduced,
        input: input.to_vec(),
    };
    let id = store
        .put(
            Family::Finding,
            &frf_fuzz::execute::finding::encode_finding(&finding).unwrap(),
        )
        .unwrap();
    (store, id)
}

#[test]
fn verified_finding_receives_a_real_receipt_and_is_idempotent() {
    let project = tmp_project("verified");
    let store_root = project.join(".frf-fuzz");
    let (store, finding_id) = store_a_finding(&project, b"crash-marker");
    let auth = AuthoritySpec {
        name: "ref".into(),
        version: "1.0".into(),
        path: {
            let p = project.join("authority.sh");
            authority_script(&p);
            p
        },
    };
    let candidate = {
        let p = project.join("candidate.sh");
        crashing_candidate_script(&p);
        p
    };
    let question = CourtQuestion {
        id: "verify-idem".into(),
        ..CourtQuestion::default()
    };

    let (rec_id, rec) = frf_bridge::verify_and_persist(
        &store,
        &finding_id,
        &auth,
        &question,
        &candidate,
        b"crash-marker",
        false,
    )
    .unwrap();
    assert_eq!(rec.outcome, VerificationOutcome::Verified);
    let run = rec.run.as_deref().expect("run id");
    let receipt = rec.receipt.as_deref().expect("receipt id");
    assert!(run.starts_with("run-"), "frf run id: {run}");
    assert!(receipt.starts_with("receipt-"), "frf receipt id: {receipt}");

    // The record round-trips and resolves as the current verification.
    let payload = store.get(&rec_id).unwrap().unwrap();
    let dec = frf_bridge::decode_verification(&payload).unwrap();
    assert_eq!(dec, rec);
    let current = frf_bridge::current_verification(&store, &finding_id)
        .unwrap()
        .unwrap();
    assert_eq!(current.receipt, rec.receipt);

    // Re-verifying the identical finding + authority converges on the SAME
    // record object (FRF immutability + content addressing) and reuses the
    // identical FRF evidence.
    let (rec_id2, rec2) = frf_bridge::verify_and_persist(
        &store,
        &finding_id,
        &auth,
        &question,
        &candidate,
        b"crash-marker",
        false,
    )
    .unwrap();
    assert_eq!(rec_id2, rec_id, "repeat verification converges");
    assert_eq!(rec2, rec);

    // The FRF store really contains the receipt (source of truth).
    let frf_store = frf_bridge::open_frf_store(&store_root).unwrap();
    let verified = frf::verify::load_receipt_verified(&frf_store, receipt).unwrap();
    assert_eq!(verified.id(), receipt);

    // fsck link validation is clean.
    assert!(frf_bridge::verify_links(&store).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn non_reproducing_finding_is_failed_and_preserved() {
    let project = tmp_project("failed");
    let (store, finding_id) = store_a_finding(&project, b"crash-marker");
    let auth = AuthoritySpec {
        name: "ref".into(),
        version: "1.1".into(),
        path: {
            let p = project.join("authority.sh");
            authority_script(&p);
            p
        },
    };
    // The candidate does NOT diverge on this input: no differential.
    let candidate = {
        let p = project.join("candidate.sh");
        benign_candidate_script(&p);
        p
    };
    let question = CourtQuestion {
        id: "verify-failed".into(),
        ..CourtQuestion::default()
    };
    let (rec_id, rec) = frf_bridge::verify_and_persist(
        &store,
        &finding_id,
        &auth,
        &question,
        &candidate,
        b"crash-marker",
        false,
    )
    .unwrap();
    assert_eq!(rec.outcome, VerificationOutcome::Failed);
    // The parity receipt is PRESERVED as evidence of non-reproduction (I10).
    let receipt = rec.receipt.as_deref();
    let note = rec.note.as_deref().expect("failure note preserved");
    assert!(
        receipt.is_some() && receipt.unwrap().starts_with("receipt-"),
        "parity receipt preserved: {receipt:?}"
    );
    assert!(note.contains("no divergence"), "note explains why: {note}");
    // The failed record is durable + current for that finding.
    assert!(frf_bridge::current_verification(&store, &finding_id)
        .unwrap()
        .is_some());
    let payload = store.get(&rec_id).unwrap().unwrap();
    assert_eq!(frf_bridge::decode_verification(&payload).unwrap(), rec);
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn no_authority_means_derived_unverified() {
    // Without any verification record, a finding is Unverified by derivation
    // (never fabricated as an object).
    let project = tmp_project("unverified");
    let (store, finding_id) = store_a_finding(&project, b"x");
    assert!(frf_bridge::current_verification(&store, &finding_id)
        .unwrap()
        .is_none());
    // And the store contains no verification objects at all.
    for id in store.list_object_ids().unwrap() {
        let (family, _) = store.get_typed(&id).unwrap().unwrap();
        assert_ne!(family, Family::FindingVerification);
    }
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn claim_compilation_is_an_explicit_opt_in() {
    let project = tmp_project("claim");
    let (store, finding_id) = store_a_finding(&project, b"crash-marker");
    let auth = AuthoritySpec {
        name: "ref".into(),
        version: "1.2".into(),
        path: {
            let p = project.join("authority.sh");
            authority_script(&p);
            p
        },
    };
    let candidate = {
        let p = project.join("candidate.sh");
        crashing_candidate_script(&p);
        p
    };
    let question = CourtQuestion {
        id: "verify-claim".into(),
        ..CourtQuestion::default()
    };
    let (_, rec) = frf_bridge::verify_and_persist(
        &store,
        &finding_id,
        &auth,
        &question,
        &candidate,
        b"crash-marker",
        true, // with_claim
    )
    .unwrap();
    assert_eq!(rec.outcome, VerificationOutcome::Verified);
    match &rec.claim {
        Some(claim) => {
            assert_eq!(claim.len(), 64, "claim id is a 64-hex content address");
            // The claim is really in the FRF store.
            let frf_store = frf_bridge::open_frf_store(&project.join(".frf-fuzz")).unwrap();
            assert!(frf::verify::load_claim_verified(&frf_store, claim).is_ok());
        }
        None => {
            // A claim refusal is preserved in the note (the receipt — the
            // evidence — stands regardless).
            let note = rec.note.as_deref().unwrap_or("");
            assert!(
                note.contains("claim not compiled"),
                "claim refusal must be recorded: {note}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn gemel_absent_is_standalone() {
    let project = tmp_project("gemel-absent");
    let store = Store::open(project.join(".frf-fuzz")).unwrap();
    let subject = store.put(Family::Campaign, b"c").unwrap();
    let rec = gemel_bridge::publish_boundary(
        &store,
        &project,
        BoundaryKind::CampaignCreated,
        subject,
        None,
    )
    .unwrap();
    assert!(rec.is_none(), "standalone mode writes nothing");
    // The store contains no gemel-boundary objects.
    for id in store.list_object_ids().unwrap() {
        let (family, _) = store.get_typed(&id).unwrap().unwrap();
        assert_ne!(family, Family::GemelBoundary);
    }
    let _ = std::fs::remove_dir_all(&project);
}

/// Initialize a gemel repo with a real head state (one tracked file).
fn init_repo_with_state(project: &std::path::Path) {
    use gemel::store::refs::{RefOp, RefTransaction};
    let repo = gemel::store::Repo::init(
        project,
        &gemel::store::InitOptions {
            author_name: Some("frf-fuzz phase4".to_string()),
            author_email: None,
        },
    )
    .unwrap();
    // A working tree with one file -> blob -> tree -> state.
    let blob = gemel::Object::blob(b"fn main() {}".to_vec());
    let blob_gid = repo.insert_object(&blob).unwrap();
    let mut files = std::collections::BTreeMap::new();
    files.insert("src/lib.rs".to_string(), (0o100644u64, blob_gid));
    let state_gid = gemel::content::build_state_from_files(&repo, &files).unwrap();
    repo.write_refs(&RefTransaction {
        ops: vec![RefOp::set(gemel::store::REF_STATE_HEAD, state_gid)],
    })
    .unwrap();
}

#[test]
fn verified_finding_publishes_evidence_and_claim_bound_to_state() {
    let project = tmp_project("gemel-bound");
    init_repo_with_state(&project);

    let store = Store::open(project.join(".frf-fuzz")).unwrap();
    let finding_payload =
        frf_fuzz::execute::finding::encode_finding(&frf_fuzz::execute::finding::Finding {
            kind: frf_fuzz::execute::finding::FindingKind::Crash,
            parent_short: [0; 8],
            coordinate: [0; 49],
            replay: frf_fuzz::execute::finding::ReplayStatus::Reproduced,
            input: b"crash-marker".to_vec(),
        })
        .unwrap();
    let finding_id = store.put(Family::Finding, &finding_payload).unwrap();

    // Publish the durable boundary (as a campaign verification would).
    let rec_id = gemel_bridge::publish_boundary(
        &store,
        &project,
        BoundaryKind::FindingVerified,
        finding_id,
        Some("frf run run-x receipt receipt-x"),
    )
    .unwrap()
    .expect("repo present => local record");
    let payload = store.get(&rec_id).unwrap().unwrap();
    let rec = gemel_bridge::decode_boundary(&payload).unwrap();
    assert_eq!(rec.state, PublishState::Published);
    assert_eq!(rec.kind, BoundaryKind::FindingVerified);
    assert_eq!(rec.subject, finding_id);
    let evidence = rec.evidence.as_deref().expect("evidence gid published");
    let claim = rec.claim.as_deref().expect("claim gid published");
    assert!(rec.head_state.is_some(), "head state bound");

    // The objects really exist in the gemel repo with the right families and
    // the evidence is bound to the head state (field 0x11).
    let repo = match gemel_bridge::discover(&project) {
        gemel_bridge::GemelDiscovery::Present(r) => r,
        other => panic!("repo must be present: {other:?}"),
    };
    let head_state = repo
        .read_ref(gemel::store::REF_STATE_HEAD)
        .unwrap()
        .unwrap();
    let ev = repo.load(&evidence.parse().unwrap()).unwrap();
    assert_eq!(ev.family, gemel::family::Family::Evidence);
    let bound = ev
        .field_sequence()
        .unwrap()
        .iter()
        .find(|f| f.tag == 0x11)
        .expect("evaluated_state field")
        .clone();
    match bound.value {
        gemel::value::Value::Gid(g) => assert_eq!(g, head_state, "evidence bound to head state"),
        other => panic!("0x11 is not a Gid: {other:?}"),
    }
    let cl = repo.load(&claim.parse().unwrap()).unwrap();
    assert_eq!(cl.family, gemel::family::Family::Claim);

    // Local fsck stays clean.
    assert!(gemel_bridge::verify_links(&store).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn falsified_precedent_publishes_negative_knowledge() {
    let project = tmp_project("gemel-falsified");
    init_repo_with_state(&project);
    let store = Store::open(project.join(".frf-fuzz")).unwrap();
    // The subject: a stored precedent object (needed for fsck link checks).
    let entry_id = store.put(Family::CorpusEntry, b"root-input").unwrap();
    let finding_payload =
        frf_fuzz::execute::finding::encode_finding(&frf_fuzz::execute::finding::Finding {
            kind: frf_fuzz::execute::finding::FindingKind::Crash,
            parent_short: [0; 8],
            coordinate: [0; 49],
            replay: frf_fuzz::execute::finding::ReplayStatus::Reproduced,
            input: b"x".to_vec(),
        })
        .unwrap();
    let finding_id = store.put(Family::Finding, &finding_payload).unwrap();
    let precedent = frf_fuzz::precedent::model::Precedent {
        lineage_root: entry_id,
        mutator: 1,
        profile: frf_fuzz::precedent::PrefixProfile {
            depth: 1,
            axis_mask: 1,
            dir_bits: 1,
            cmp_convergence: 0,
            state_change: 0,
            structured_unknown: false,
        },
        role_mask: 1,
        continuation: frf_fuzz::precedent::Continuation {
            kind: frf_fuzz::precedent::TerminalKind::CrashFinding,
            class: 0,
            axis: 0,
            depth: 2,
            reason: 0,
            terminal_ref: Some(finding_id),
        },
        confuser: frf_fuzz::precedent::ConfuserKind::None,
        created_seq: 1,
        updated_seq: 1,
        status: frf_fuzz::precedent::PrecedentStatus::Candidate,
        prev_revision: None,
        supports: 0,
        contradictions: 1,
        ambiguous_probes: 0,
        recipe: frf_fuzz::precedent::ProbeRecipe::persists(
            frf_fuzz::mutation::MutatorId::ByteFlip,
            0,
            8,
            4,
            3,
        ),
        evidence: vec![],
    };
    let precedent_id = store
        .put(
            Family::Precedent,
            &frf_fuzz::precedent::encode_precedent(&precedent).unwrap(),
        )
        .unwrap();

    let rec_id = gemel_bridge::publish_boundary(
        &store,
        &project,
        BoundaryKind::FalsifiedPrecedent,
        precedent_id,
        None,
    )
    .unwrap()
    .expect("local record");
    let payload = store.get(&rec_id).unwrap().unwrap();
    let rec = gemel_bridge::decode_boundary(&payload).unwrap();
    assert_eq!(rec.state, PublishState::Published);
    let residual = rec.residual.as_deref().expect("residual gid published");
    let repo = match gemel_bridge::discover(&project) {
        gemel_bridge::GemelDiscovery::Present(r) => r,
        _ => panic!("repo present"),
    };
    let res = repo.load(&residual.parse().unwrap()).unwrap();
    assert_eq!(res.family, gemel::family::Family::Residual);
    assert!(gemel_bridge::verify_links(&store).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn revision_pairs_roundtrip_and_verify() -> Result<()> {
    use frf_fuzz::tape::revision;
    let project = tmp_project("revision");
    let store = Store::open(project.join(".frf-fuzz"))?;
    let tape_id = store.put(Family::RunTape, b"tape-bytes")?;
    let mut a = revision::RevisionStateObservation {
        label: "state-a".into(),
        artifact: [1; 32],
        environment: [0; 32],
        termination: frf_fuzz::tape::model::TerminationStatus::Ok,
        signals: Some(frf_fuzz::target_runtime::signals::SignalVector::new()),
    };
    let b = revision::RevisionStateObservation {
        label: "state-b".into(),
        artifact: [2; 32],
        environment: [0; 32],
        termination: frf_fuzz::tape::model::TerminationStatus::Ok,
        signals: Some(frf_fuzz::target_runtime::signals::SignalVector::new()),
    };
    let _ = &mut a;
    let pair = revision::RevisionPair {
        tape: tape_id,
        earlier: a.clone(),
        later: b,
    };
    let enc = revision::encode_revision_pair(&pair)?;
    assert_eq!(revision::decode_revision_pair(&enc)?, pair);
    let _ = std::fs::remove_dir_all(&project);
    Ok(())
}
