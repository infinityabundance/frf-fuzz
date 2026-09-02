//! Precedent-engine demonstration (master prompt §34 / acceptance 10-12,
//! engine level; Phase 3).
//!
//! A deterministic, executable demonstration of the precedent bank's
//! falsifiable loop using the SAME library code the campaign coordinator
//! runs: a real structural lineage is observed, a terminal crash admits a
//! precedent with provenance, a live sibling lineage matches its precursor
//! shape, a falsify probe is evaluated against a real batch summary, and a
//! direct contradiction flips the precedent to `Contradicted` — retained as
//! negative knowledge, never deleted. The scratch store is fsck-validated
//! at the end (revision chain, corpus-entry lineage root, terminal finding).
//!
//! Run: `cargo run --example precedent_engine_demo`
//!
//! Everything here is deterministic: no randomness, no wall clock inside any
//! canonical payload, and every printed statement is a structural claim —
//! never a probability.

#[cfg(feature = "coordinator")]
mod demo {
    use frf_fuzz::canon::Family;
    use frf_fuzz::dsfb::fuzz_bank::FuzzMotif;
    use frf_fuzz::dsfb::morphology::{LineageAccumulator, MorphologySignature};
    use frf_fuzz::execute::finding::{Finding, FindingKind, ReplayStatus};
    use frf_fuzz::observe::residual::MutationResidual;
    use frf_fuzz::precedent::probe::{ProbeOutcome, ProbeRecipe};
    use frf_fuzz::precedent::{
        choose_precursor, contradiction_weight, create_from_terminal, load_current, save_revision,
        verify_links, ConfuserKind, PrecedentStatus, TerminalKind,
    };
    use frf_fuzz::store::Store;
    use frf_fuzz::target_runtime::signals::{SignalBatchSummary, SignalId, SignalVector};

    fn vec_with(id: u16, v: u64) -> SignalVector {
        let mut s = SignalVector::new();
        s.observe(SignalId(id), v).unwrap();
        s
    }

    /// Rebuild a monotone climbing lineage history (oldest first), mirroring
    /// what the coordinator keeps from durable corpus metas.
    fn climbing_history(root_value: u64, steps: u32) -> Vec<(u32, MorphologySignature)> {
        let mut acc = LineageAccumulator::new();
        acc.init_baseline(&vec_with(0, root_value));
        let mut parent = vec_with(0, root_value);
        let mut out = Vec::new();
        acc.push(&MutationResidual::of(&parent, &parent), 0);
        for d in 1..=steps {
            let child = vec_with(0, root_value + d as u64);
            let sig = acc.push(&MutationResidual::of(&child, &parent), d);
            out.push((d, sig));
            parent = child;
        }
        out
    }

    /// A deterministic "probe batch summary": `axis` moved in `count` executions
    /// with the given run length and total movement (the shape of a real
    /// `SignalBatchSummary` the coordinator reads from a WorkResult).
    fn probe_batch(axis: usize, count: u32, run: u8, sum_abs: u64) -> SignalBatchSummary {
        let mut s = SignalBatchSummary::new();
        s.touched |= 1u64 << axis;
        s.count[axis] = count;
        s.max_run[axis] = run;
        s.sum_abs_delta[axis] = sum_abs;
        s.min[axis] = 0;
        s.max[axis] = sum_abs.max(1);
        s
    }

    fn store_dir() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("frf-fuzz-precedent-demo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        let dir = store_dir();
        let store = Store::open(dir.clone())?;

        // ---- 1. a real terminal lineage: root entry + the depth crash ----
        let root_input = b"FRFZ\x00\x00AAAA".to_vec();
        let root = store.put(Family::CorpusEntry, &root_input)?;
        let crash_input = b"FRFZ\x00\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec();
        let finding_payload = frf_fuzz::execute::finding::encode_finding(&Finding {
            kind: FindingKind::Crash,
            parent_short: root.short(),
            coordinate: [0; 49],
            replay: ReplayStatus::Reproduced,
            input: crash_input.clone(),
        })?;
        let finding_id = store.put(Family::Finding, &finding_payload)?;

        // The lineage's durable shape history (as recorded by the coordinator).
        let history = climbing_history(0, 24);
        let terminal_depth = 25; // the crashed child's generation
        let (precursor, precursor_depth) = choose_precursor(&history, terminal_depth).unwrap();
        let recipe = ProbeRecipe::persists(frf_fuzz::mutation::MutatorId::ByteInsert, 0, 20, 4, 3);
        let precedent = create_from_terminal(
            root,
            frf_fuzz::mutation::MutatorId::ByteInsert,
            &precursor,
            precursor_depth,
            TerminalKind::CrashFinding,
            FuzzMotif::PersistentBehavioralDrift.code(),
            0,
            5,
            terminal_depth,
            Some(finding_id),
            ConfuserKind::None,
            recipe,
            1,
        )
        .expect("a structured lineage with a lead admits a precedent");
        let pid = save_revision(&store, &precedent)?;
        println!("1. terminal lineage: depth crash at gen {terminal_depth}");
        println!(
            "   precedent admitted: profile_depth={} axes={:#x} status={} (provenance: root {}, finding {})",
            precedent.profile.depth,
            precedent.profile.axis_mask,
            precedent.status.name(),
            &root.to_hex()[..8],
            &finding_id.to_hex()[..8]
        );

        // ---- 2. a live sibling lineage shares the precursor shape ----
        let live_history = climbing_history(0, 9);
        let live_sig = live_history.last().unwrap().1.clone();
        let live_depth = 9;
        let mut matched = false;
        let current = load_current(&store)?;
        for p in &current {
            if frf_fuzz::precedent::matches(
                p,
                &live_sig,
                live_depth,
                frf_fuzz::mutation::MutatorId::ByteInsert.id(),
            ) {
                matched = true;
                println!(
                    "2. live sibling lineage (gen {live_depth}) matches precedent profile depth {}: structural prefix recognized",
                    p.profile.depth
                );
                break;
            }
        }
        assert!(matched, "the live lineage must match the precedent");

        // ---- 3. the falsify probe SUPPORTS the family ----
        let moving = probe_batch(0, 400, 12, 1 << 16);
        let outcome = frf_fuzz::precedent::probe::evaluate(&precedent.recipe, &moving);
        assert_eq!(outcome, ProbeOutcome::Support);
        let evidence = frf_fuzz::precedent::ProbeEvidence {
            outcome,
            seq: 2,
            axis: 0,
            moved: 400,
            run: 12,
            sum_bucket: 16,
            batch_execs: 500,
        };
        let (status, supports, contradictions, _) = precedent.apply_probe(outcome, evidence, false);
        println!(
            "3. falsify probe (continue ByteInsert on the frontier): axis kept moving -> {}; precedent now {} (supports {})",
            outcome.name(),
            status.name(),
            supports
        );
        let mut supported = precedent.clone();
        supported.status = status;
        supported.supports = supports;
        supported.contradictions = contradictions;
        supported.updated_seq = 2;
        supported.prev_revision = Some(pid);
        let sid = save_revision(&store, &supported)?;

        // ---- 4. a DIRECT contradiction flips and is retained ----
        let stopped = probe_batch(0, 0, 0, 0);
        let outcome2 = frf_fuzz::precedent::probe::evaluate(&supported.recipe, &stopped);
        assert_eq!(outcome2, ProbeOutcome::Contradict);
        let direct = contradiction_weight(&supported.recipe, &stopped)
            == frf_fuzz::precedent::ContradictionWeight::Direct;
        assert!(direct);
        let evidence2 = frf_fuzz::precedent::ProbeEvidence {
            outcome: outcome2,
            seq: 3,
            axis: 0,
            moved: 0,
            run: 0,
            sum_bucket: 0,
            batch_execs: 500,
        };
        let (status2, _, contradictions2, _) = supported.apply_probe(outcome2, evidence2, direct);
        assert_eq!(status2, PrecedentStatus::Contradicted);
        println!(
            "4. discriminator probe: the axis never moved -> {} (direct). Precedent now {} (contradictions {}).",
            outcome2.name(),
            status2.name(),
            contradictions2
        );
        let mut contradicted = supported;
        contradicted.status = status2;
        contradicted.contradictions = contradictions2;
        contradicted.updated_seq = 3;
        contradicted.prev_revision = Some(sid);
        let _cid = save_revision(&store, &contradicted)?;

        // ---- 5. nothing was deleted: three revisions, one contradicted ----
        let revisions: Vec<_> = store
            .list_object_ids()?
            .into_iter()
            .filter(|id| {
                store
                    .get_typed(id)
                    .ok()
                    .flatten()
                    .map(|(f, _)| f == Family::Precedent)
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(revisions.len(), 3, "all revisions must be retained (I10)");
        let current_after = load_current(&store)?;
        assert_eq!(current_after.len(), 1);
        assert_eq!(current_after[0].status, PrecedentStatus::Contradicted);
        println!(
            "5. contradiction durably retained: {} precedent revision(s) stored; current status {} (never overwritten, never deleted)",
            revisions.len(),
            current_after[0].status.name()
        );

        // ---- 6. fsck validates the store: objects, revision chain, refs ----
        let errors = verify_links(&store)?;
        assert!(errors.is_empty(), "fsck must be clean: {errors:?}");
        println!("6. store verification: clean (revision chain, lineage root, terminal finding)");
        println!();
        println!("PRECEDENT ENGINE DEMO PASS");
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}

#[cfg(feature = "coordinator")]
fn main() {
    if let Err(e) = demo::main() {
        eprintln!("precedent engine demo: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "coordinator"))]
fn main() {}
