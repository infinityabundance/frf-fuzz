//! Campaign/store reporting: `frf-fuzz report`.
//!
//! Aggregates the durable store into a human and `--json` report: campaign
//! objects, the latest checkpoint, corpus size/feature counts, findings,
//! and refs. Everything is read from immutable objects; nothing here
//! mutates the store.
//!
//! This module is coordinator-gated.

use crate::canon::Family;
use crate::corpus::entry;
use crate::corpus::CorpusIndex;
use crate::error::Result;
use crate::execute::finding;
use crate::id::ContentId;
use crate::store::fsck;
use crate::store::refs;
use crate::store::Store;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One finding in the report.
#[derive(Debug, Clone)]
pub struct FindingInfo {
    /// The finding object id.
    pub id: ContentId,
    /// Outcome class.
    pub kind: finding::FindingKind,
    /// Deliberate-replay status.
    pub replay: finding::ReplayStatus,
    /// Input length in bytes.
    pub input_len: usize,
}

/// The full report.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Store root.
    pub store_root: PathBuf,
    /// Campaign object ids.
    pub campaign_ids: Vec<ContentId>,
    /// Latest checkpoint id.
    pub checkpoint: Option<ContentId>,
    /// Corpus stats (from a rebuilt index).
    pub corpus_entries: usize,
    /// Distinct coverage features covered by the corpus.
    pub corpus_features: usize,
    /// All findings (deterministic order).
    pub findings: Vec<FindingInfo>,
    /// Refs (name -> id hex), sorted.
    pub refs: Vec<(String, String)>,
    /// Per-family object counts.
    pub object_counts: BTreeMap<String, usize>,
}

impl Report {
    /// Number of distinct findings.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}

/// Generate a report from the store.
pub fn generate(store_root: &std::path::Path) -> Result<Report> {
    let store = Store::open(store_root.to_path_buf())?;
    let mut report = Report {
        store_root: store_root.to_path_buf(),
        ..Report::default()
    };

    // Refs (deterministic order).
    for name in refs::list_refs(store_root)? {
        if let Ok(Some(id)) = refs::get_ref(store_root, &name) {
            report.refs.push((name, id.to_hex()));
        }
    }
    if let Ok(Some(id)) = refs::get_ref(store_root, "checkpoint-current") {
        report.checkpoint = Some(id);
    }

    // Object inventory + findings.
    for id in store.list_object_ids()? {
        let Ok(Some((family, payload))) = store.get_typed(&id) else {
            continue;
        };
        let name = family.name().to_string();
        *report.object_counts.entry(name).or_insert(0) += 1;
        match family {
            Family::Campaign => report.campaign_ids.push(id),
            Family::Finding => {
                if let Ok(f) = finding::decode_finding(&payload) {
                    report.findings.push(FindingInfo {
                        id,
                        kind: f.kind,
                        replay: f.replay,
                        input_len: f.input.len(),
                    });
                }
            }
            _ => {}
        }
    }
    report.campaign_ids.sort();
    report.findings.sort_by_key(|f| f.id.to_hex());

    // Corpus stats (rebuild the disposable index from durable metadata).
    let index = CorpusIndex::rebuild(&store)?;
    report.corpus_entries = index.len();
    report.corpus_features = index.feature_count();

    Ok(report)
}

/// Human-readable rendering.
pub fn render_human(r: &Report) -> String {
    let mut s = String::new();
    s.push_str(&format!("frf-fuzz store: {}\n", r.store_root.display()));
    s.push_str(&format!("campaigns: {}\n", r.campaign_ids.len()));
    if let Some(c) = &r.checkpoint {
        s.push_str(&format!("checkpoint: {}\n", c));
    }
    s.push_str(&format!("corpus entries: {}\n", r.corpus_entries));
    s.push_str(&format!(
        "distinct coverage features: {}\n",
        r.corpus_features
    ));
    s.push_str(&format!("findings: {}\n", r.findings.len()));
    for f in &r.findings {
        s.push_str(&format!(
            "  {} kind={} replay={} input={}B\n",
            f.id,
            f.kind.name(),
            f.replay.name(),
            f.input_len
        ));
    }
    s.push_str("objects by family:\n");
    for (name, count) in &r.object_counts {
        s.push_str(&format!("  {name}: {count}\n"));
    }
    s.push_str("refs:\n");
    for (name, id) in &r.refs {
        s.push_str(&format!("  {name} -> {id}\n"));
    }
    s
}

/// JSON rendering (stable key order; valid JSON for `report --json`).
pub fn render_json(r: &Report) -> String {
    let mut s = String::new();
    s.push('{');
    s.push_str(&format!(
        "\"store_root\":{},\"campaigns\":{},\"checkpoint\":{},",
        json_str(&r.store_root.display().to_string()),
        r.campaign_ids.len(),
        r.checkpoint
            .as_ref()
            .map(|c| json_str(&c.to_hex()))
            .unwrap_or_else(|| "null".to_string())
    ));
    s.push_str(&format!(
        "\"corpus_entries\":{},\"corpus_features\":{},\"findings\":[",
        r.corpus_entries, r.corpus_features
    ));
    for (i, f) in r.findings.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"id\":{},\"kind\":{},\"replay\":{},\"input_len\":{}}}",
            json_str(&f.id.to_hex()),
            json_str(f.kind.name()),
            json_str(f.replay.name()),
            f.input_len
        ));
    }
    s.push_str("],\"objects\":{");
    for (i, (name, count)) in r.object_counts.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{}:{count}", json_str(name)));
    }
    s.push_str("},\"refs\":{");
    for (i, (name, id)) in r.refs.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{}:{}", json_str(name), json_str(id)));
    }
    s.push_str("}}");
    s
}

/// fsck-derived store health for the report.
pub fn store_health(store_root: &std::path::Path) -> Result<fsck::FsckReport> {
    let store = Store::open(store_root.to_path_buf())?;
    fsck::fsck(&store)
}

/// Corpus-link validation: every corpus-meta's entry exists, is a
/// CorpusEntry object, and its parent (when set) resolves.
pub fn corpus_link_check(store_root: &std::path::Path) -> Result<Vec<String>> {
    let store = Store::open(store_root.to_path_buf())?;
    let mut errors = Vec::new();
    for id in store.list_object_ids()? {
        let Ok(Some((Family::CorpusMeta, payload))) = store.get_typed(&id) else {
            continue;
        };
        let Ok(meta) = entry::decode_meta(&payload) else {
            errors.push(format!("{id}: corrupt corpus-meta payload"));
            continue;
        };
        // The entry object must exist with the CorpusEntry family.
        match store.get_typed(&meta.entry_id) {
            Ok(Some((Family::CorpusEntry, _))) => {}
            Ok(Some((other, _))) => {
                errors.push(format!(
                    "{id}: entry {} is family {} not corpus-entry",
                    meta.entry_id,
                    other.name()
                ));
            }
            _ => {
                errors.push(format!("{id}: entry {} is missing", meta.entry_id));
            }
        }
        // Parent link (when present) must resolve to a corpus entry.
        if let Some(parent) = meta.parent_id {
            match store.get_typed(&parent) {
                Ok(Some((Family::CorpusEntry, _))) => {}
                _ => {
                    errors.push(format!(
                        "{id}: parent {} is missing or not a corpus entry",
                        parent
                    ));
                }
            }
        }
        // Features must be sorted and deduplicated (worker contract).
        if !meta.features.windows(2).all(|w| w[0] < w[1]) {
            errors.push(format!("{id}: features are not strictly sorted"));
        }
    }
    Ok(errors)
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
