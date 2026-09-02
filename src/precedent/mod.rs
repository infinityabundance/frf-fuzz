//! The durable precedent bank (master prompt §17; Phase 3).
//!
//! A precedent is a durable, content-addressed record of one structural
//! trajectory family that led to a terminal event, with its context, its
//! falsifiable probe relationship, and the accumulated confirming/falsifying
//! evidence. Precedents are the *historical residual trajectories* the
//! engine consults when a live lineage starts to share a shape with the
//! past (matching), so it can propose the next discriminating or falsifying
//! experiment instead of guessing.
//!
//! Submodules:
//!
//! * `model` — the revisioned precedent object and its canonical encoding;
//! * `matching` — deterministic shape-subsumption matching;
//! * `probe` — the falsifiable probe recipes and outcome evaluation;
//! * `admission` — creation of precedents from real terminal observations.
//!
//! Revision discipline: every update writes a new immutable object; the
//! "current" revision of a (root, mutator, profile) family is the one with
//! the highest `updated_seq`. Contradictions are never deleted (I10).
//!
//! This module is coordinator-gated.

pub mod admission;
pub mod matching;
pub mod model;
pub mod probe;

pub use admission::{choose_precursor, create_from_terminal, derive_recipe};
pub use matching::{matches, matching_precedents};
pub use model::{
    decode_precedent, encode_precedent, render_precedent, ConfuserKind, Continuation, Precedent,
    PrecedentStatus, PrefixProfile, TerminalKind,
};
pub use probe::{
    contradiction_weight, decode_evidence, encode_evidence, evaluate, ContradictionWeight,
    Expectation, ProbeEvidence, ProbeOutcome, ProbeRecipe,
};

use crate::canon::Family;
use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::store::Store;

/// Hard cap on precedents the bank will load (defense against unbounded
/// store growth from hostile or accidental precedent floods).
pub const MAX_LOADED_PRECEDENTS: usize = 4096;

/// Resolve the CURRENT revision of every (root, mutator, profile) precedent
/// family in the store, deterministically. Older revisions remain stored
/// (immutable history; I10). Bounded by [`MAX_LOADED_PRECEDENTS`].
pub fn load_current(store: &Store) -> Result<Vec<Precedent>> {
    let mut by_group: std::collections::BTreeMap<(ContentId, u16, u64), Precedent> =
        std::collections::BTreeMap::new();
    let mut count = 0usize;
    for id in store.list_object_ids()? {
        let Ok(Some((Family::Precedent, payload))) = store.get_typed(&id) else {
            continue;
        };
        count += 1;
        if count > MAX_LOADED_PRECEDENTS {
            return Err(Error::BoundExceeded {
                what: "stored precedent objects",
                limit: MAX_LOADED_PRECEDENTS as u64,
                got: count as u64,
            });
        }
        let Ok(p) = decode_precedent(&payload) else {
            // Corruption is reported by fsck; loading skips unreadable
            // revisions rather than failing the whole campaign (I14 spirit).
            continue;
        };
        let key = p.group_key();
        // Deterministic resolution: ids are visited in sorted order, so an
        // equal-seq revision keeps the first (lowest-id) as current.
        let replace = by_group
            .get(&key)
            .map(|cur| p.updated_seq > cur.updated_seq)
            .unwrap_or(true);
        if replace {
            by_group.insert(key, p);
        }
    }
    Ok(by_group.into_values().collect())
}

/// Persist a new precedent revision (content-addressed; returns its ID).
pub fn save_revision(store: &Store, p: &Precedent) -> Result<ContentId> {
    let payload = encode_precedent(p)?;
    store.put(Family::Precedent, &payload)
}

/// Verify precedent link closure for `fsck`: every stored precedent's
/// revision chain resolves, its lineage root is a stored corpus entry, and
/// its terminal reference (when set) exists with an appropriate family.
/// Returns human-readable defects (empty = clean).
pub fn verify_links(store: &Store) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    for id in store.list_object_ids()? {
        let Ok(Some((Family::Precedent, payload))) = store.get_typed(&id) else {
            continue;
        };
        let p = match decode_precedent(&payload) {
            Ok(p) => p,
            Err(e) => {
                errors.push(format!("{id}: corrupt precedent payload: {e}"));
                continue;
            }
        };
        // Lineage root must be a stored corpus entry (provenance I9).
        match store.get_typed(&p.lineage_root) {
            Ok(Some((Family::CorpusEntry, _))) => {}
            Ok(Some((other, _))) => errors.push(format!(
                "{id}: lineage root {} is family {} not corpus-entry",
                p.lineage_root,
                other.name()
            )),
            _ => errors.push(format!("{id}: lineage root {} is missing", p.lineage_root)),
        }
        // Revision chain must resolve.
        if let Some(prev) = p.prev_revision {
            match store.get_typed(&prev) {
                Ok(Some((Family::Precedent, _))) => {}
                _ => errors.push(format!(
                    "{id}: previous revision {prev} is missing or not a precedent"
                )),
            }
        }
        // Terminal reference must exist with the family its kind declares.
        if let Some(t) = p.continuation.terminal_ref {
            let want_family = match p.continuation.kind {
                model::TerminalKind::CrashFinding | model::TerminalKind::TimeoutFinding => {
                    Some(Family::Finding)
                }
                model::TerminalKind::BoundaryWitness => Some(Family::BoundaryWitness),
                // Escalated episodes may be either regime or structural
                // episodes (the coordinator writes whichever closed).
                model::TerminalKind::EscalatedEpisode => None,
            };
            match store.get_typed(&t) {
                Ok(Some((f, _))) => {
                    if let Some(want) = want_family {
                        if f != want {
                            errors.push(format!(
                                "{id}: terminal {} is family {} not {}",
                                t,
                                f.name(),
                                want.name()
                            ));
                        }
                    } else if f != Family::RegimeEpisode
                        && f != Family::StructuralEpisode
                        && f != Family::BoundaryWitness
                    {
                        errors.push(format!(
                            "{id}: terminal {t} has unexpected family {} for an escalated-episode precedent",
                            f.name()
                        ));
                    }
                }
                _ => errors.push(format!("{id}: terminal {t} is missing")),
            }
        }
    }
    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precedent::model::{ConfuserKind, Continuation, PrefixProfile, TerminalKind};
    use crate::precedent::probe::ProbeRecipe;

    fn tmp_store(tag: &str) -> Store {
        let dir = std::env::temp_dir().join(format!(
            "frf-fuzz-precedent-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Store::open(dir).unwrap()
    }

    fn sample() -> Precedent {
        Precedent {
            lineage_root: ContentId::new(b"entry"),
            mutator: 7,
            profile: PrefixProfile {
                depth: 2,
                axis_mask: 1,
                dir_bits: 1,
                cmp_convergence: 1,
                state_change: 0,
                structured_unknown: true,
            },
            role_mask: 1,
            continuation: Continuation {
                kind: TerminalKind::CrashFinding,
                class: 0,
                axis: 0,
                depth: 20,
                reason: 5,
                terminal_ref: Some(ContentId::new(b"finding")),
            },
            confuser: ConfuserKind::None,
            created_seq: 1,
            updated_seq: 1,
            status: model::PrecedentStatus::Candidate,
            prev_revision: None,
            supports: 0,
            contradictions: 0,
            ambiguous_probes: 0,
            recipe: ProbeRecipe::persists(crate::mutation::MutatorId::ByteInsert, 0, 20, 4, 3),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn current_revision_resolution_picks_highest_updated_seq() {
        let store = tmp_store("current");
        // Store the corpus entry + terminal the sample references so the
        // links verify cleanly.
        let entry_id = store.put(Family::CorpusEntry, b"input").unwrap();
        let finding_payload =
            crate::execute::finding::encode_finding(&crate::execute::finding::Finding {
                kind: crate::execute::finding::FindingKind::Crash,
                parent_short: [0; 8],
                coordinate: [0; 49],
                replay: crate::execute::finding::ReplayStatus::NotReplayed,
                input: b"crash input".to_vec(),
            })
            .unwrap();
        let finding_id = store.put(Family::Finding, &finding_payload).unwrap();

        let mut p1 = sample();
        p1.lineage_root = entry_id;
        p1.continuation.terminal_ref = Some(finding_id);
        let id1 = save_revision(&store, &p1).unwrap();
        // A newer revision of the same family with updated evidence.
        let mut p2 = p1.clone();
        p2.updated_seq = 5;
        p2.supports = 1;
        p2.prev_revision = Some(id1);
        let id2 = save_revision(&store, &p2).unwrap();
        assert_ne!(id1, id2);

        let current = load_current(&store).unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].updated_seq, 5);
        assert_eq!(current[0].supports, 1);

        // Links verify: both revisions present; root is a corpus entry; the
        // terminal finding exists.
        let errors = verify_links(&store).unwrap();
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn verify_links_reports_missing_terminal() {
        let store = tmp_store("links");
        let entry_id = store.put(Family::CorpusEntry, b"input").unwrap();
        let mut p = sample();
        p.lineage_root = entry_id;
        // terminal_ref points at an object that is never stored.
        save_revision(&store, &p).unwrap();
        let errors = verify_links(&store).unwrap();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("terminal") && e.contains("missing")),
            "{errors:?}"
        );
    }
}
