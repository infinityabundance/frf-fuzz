//! Corpus: admission, the rebuildable in-memory index, and minimization.
//!
//! The durable truth is the object store: `CorpusEntry` objects (input
//! bytes) + `CorpusMeta` objects (features, parent, reason). The in-memory
//! [`CorpusIndex`] is a derived structure — it is rebuilt at campaign start
//! and by `fsck` by scanning `CorpusMeta` objects, so it is never
//! authoritative and can always be regenerated.
//!
//! # Admission (Phase 1 policy)
//!
//! An execution is admitted when it is a crash/timeout or when it produced
//! at least one packed feature not present in the global feature set
//! (coverage-guided admission). Smaller-representative admission is the
//! job of `cmin`, not the live loop.
//!
//! This module is coordinator-gated.

pub mod admission;
pub mod entry;
pub mod minimize;

pub use entry::{AdmissionReason, CorpusMeta};

use crate::canon::Family;
use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::mutation::CounterRng;
use crate::store::Store;
use std::collections::BTreeMap;

/// Hard bound on corpus size (admission refuses beyond this; the campaign
/// reports the refusal rather than growing without limit).
pub const MAX_CORPUS_ENTRIES: usize = 1 << 20;

/// The in-memory corpus index, derived from `CorpusMeta` objects.
#[derive(Debug, Default)]
pub struct CorpusIndex {
    /// entry_id -> metadata (deterministic iteration).
    entries: BTreeMap<ContentId, CorpusMeta>,
    /// packed feature -> entries covering it.
    feature_to_entries: BTreeMap<u64, Vec<ContentId>>,
}

impl CorpusIndex {
    /// An empty index.
    pub fn new() -> CorpusIndex {
        CorpusIndex::default()
    }

    /// Rebuild the index by scanning the store's `CorpusMeta` objects.
    /// Corrupt metadata is an error (fsck territory), never silently
    /// skipped.
    pub fn rebuild(store: &Store) -> Result<CorpusIndex> {
        let mut index = CorpusIndex::new();
        for id in store.list_object_ids()? {
            let Some((family, payload)) = store.get_typed(&id)? else {
                continue;
            };
            if family != Family::CorpusMeta {
                continue;
            }
            let meta = entry::decode_meta(&payload)?;
            index.insert_meta(meta)?;
        }
        Ok(index)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Global feature count (distinct packed features covered).
    pub fn feature_count(&self) -> usize {
        self.feature_to_entries.len()
    }

    /// The metadata for an entry.
    pub fn meta(&self, id: &ContentId) -> Option<&CorpusMeta> {
        self.entries.get(id)
    }

    /// Iterate entries in deterministic (ID) order.
    pub fn iter(&self) -> impl Iterator<Item = (&ContentId, &CorpusMeta)> {
        self.entries.iter()
    }

    /// All features an entry covers (from its metadata).
    pub fn features_of(&self, id: &ContentId) -> Option<&[u64]> {
        self.entries.get(id).map(|m| m.features.as_slice())
    }

    /// The entries covering a feature (deterministic order).
    pub fn entries_for_feature(&self, feature: u64) -> &[ContentId] {
        self.feature_to_entries
            .get(&feature)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// True when every feature is already covered globally.
    pub fn all_known(&self, features: &[u64]) -> bool {
        features
            .iter()
            .all(|f| self.feature_to_entries.contains_key(f))
    }

    /// The subset of `features` NOT yet covered globally (sorted).
    pub fn novel_features(&self, features: &[u64]) -> Vec<u64> {
        let mut out: Vec<u64> = features
            .iter()
            .copied()
            .filter(|f| !self.feature_to_entries.contains_key(f))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The global feature set (sorted).
    pub fn global_features(&self) -> Vec<u64> {
        self.feature_to_entries.keys().copied().collect()
    }

    /// Insert metadata into the index. Refuses duplicate entry IDs (the
    /// store already guarantees unique content, so a duplicate means two
    /// different metadata objects for one input — corruption, I13 spirit).
    pub fn insert_meta(&mut self, meta: CorpusMeta) -> Result<()> {
        if self.entries.contains_key(&meta.entry_id) {
            return Err(Error::IdCollision);
        }
        for f in &meta.features {
            self.feature_to_entries
                .entry(*f)
                .or_default()
                .push(meta.entry_id);
        }
        self.entries.insert(meta.entry_id, meta);
        Ok(())
    }

    /// Deterministic parent selection: weighted round-robin over entries in
    /// ID order, weights derived from a stable per-campaign stream (the
    /// campaign seed). Phase 1 keeps the weighting flat (uniform over
    /// entries); rarity/novelty weighting arrives with the Phase-2
    /// scheduler.
    pub fn pick_parent(&self, rng: &mut CounterRng) -> Option<ContentId> {
        if self.entries.is_empty() {
            return None;
        }
        let idx = rng.gen_index(self.entries.len());
        Some(*self.entries.keys().nth(idx).unwrap())
    }

    /// Walk the parent chain to the seed ancestor of an entry.
    pub fn root_of(&self, id: &ContentId) -> Option<ContentId> {
        let mut cur = *id;
        for _ in 0..=self.entries.len() {
            let meta = self.entries.get(&cur)?;
            match meta.parent_id {
                Some(p) => cur = p,
                None => return Some(cur),
            }
        }
        None // cycle (corrupt metadata; fsck territory)
    }

    /// Resolve an 8-byte short key to a full content ID (deterministic: the
    /// lowest full ID with that prefix — a lookup hint, not identity).
    pub fn entry_by_short(&self, short: [u8; 8]) -> Option<ContentId> {
        self.entries.keys().find(|id| id.short() == short).copied()
    }

    /// The lineage chain of an entry: the parent-first path from its seed
    /// ancestor, including only edges whose mutator matches `mutator`
    /// (deterministic; used by lineage/regime rebuild replay).
    pub fn lineage_chain(&self, id: &ContentId, mutator: u16) -> Vec<&CorpusMeta> {
        let mut chain = Vec::new();
        let mut cur = Some(*id);
        while let Some(c) = cur {
            let Some(meta) = self.entries.get(&c) else {
                break;
            };
            if meta.mutator_id == Some(mutator) {
                chain.push(meta);
            }
            cur = meta.parent_id;
        }
        chain.reverse(); // parent-first
        chain
    }

    /// All entries sorted by admission sequence (deterministic rebuild
    /// order for lineage/regime replay).
    pub fn by_admission_order(&self) -> Vec<&CorpusMeta> {
        let mut v: Vec<&CorpusMeta> = self.entries.values().collect();
        v.sort_by_key(|m| (m.admission_seq, m.entry_id));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(tag: &str) -> Store {
        let dir =
            std::env::temp_dir().join(format!("frf-fuzz-corpus-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Store::open(dir).unwrap()
    }

    #[test]
    fn index_rebuilds_from_store() {
        let s = tmp_store("rebuild");
        // Seed entry: input + meta.
        let input_id = s.put(Family::CorpusEntry, b"seed input").unwrap();
        let meta = CorpusMeta {
            entry_id: input_id,
            parent_id: None,
            generation: 0,
            features: vec![1, 2, 3],
            reason: AdmissionReason::Seed,
            signals: crate::target_runtime::signals::SignalVector::new(),
            mutator_id: None,
            morphology_id: None,
            admission_seq: 0,
        };
        s.put(Family::CorpusMeta, &entry::encode_meta(&meta).unwrap())
            .unwrap();

        let index = CorpusIndex::rebuild(&s).unwrap();
        assert_eq!(index.len(), 1);
        assert_eq!(index.feature_count(), 3);
        assert_eq!(index.features_of(&input_id), Some([1u64, 2, 3].as_slice()));
        assert!(index.all_known(&[1, 3]));
        assert!(!index.all_known(&[1, 99]));
        assert_eq!(index.novel_features(&[2, 99]), vec![99]);
    }

    #[test]
    fn pick_parent_is_deterministic() {
        let mut index = CorpusIndex::new();
        for i in 0..5u8 {
            let id = ContentId::new(&[i; 32]);
            index
                .insert_meta(CorpusMeta {
                    entry_id: id,
                    parent_id: None,
                    generation: 0,
                    features: vec![u64::from(i)],
                    reason: AdmissionReason::Seed,
                    signals: crate::target_runtime::signals::SignalVector::new(),
                    mutator_id: None,
                    morphology_id: None,
                    admission_seq: 0,
                })
                .unwrap();
        }
        let mut r1 = CounterRng::from_philox([1, 0, 0, 0], [7, 0]);
        let mut r2 = CounterRng::from_philox([1, 0, 0, 0], [7, 0]);
        for _ in 0..100 {
            assert_eq!(index.pick_parent(&mut r1), index.pick_parent(&mut r2));
        }
        assert!(index.pick_parent(&mut r1).is_some());
    }

    #[test]
    fn duplicate_entry_meta_is_refused() {
        let mut index = CorpusIndex::new();
        let id = ContentId::new(b"x");
        let meta = CorpusMeta {
            entry_id: id,
            parent_id: None,
            generation: 0,
            features: vec![],
            reason: AdmissionReason::Seed,
            signals: crate::target_runtime::signals::SignalVector::new(),
            mutator_id: None,
            morphology_id: None,
            admission_seq: 0,
        };
        index.insert_meta(meta.clone()).unwrap();
        assert!(index.insert_meta(meta).is_err());
    }
}
