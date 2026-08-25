//! Store verification: `frf-fuzz fsck`.
//!
//! Verifies, for every stored object:
//!
//! * the filename is the lowercase hex content ID and the file content
//!   hashes to that ID (I13);
//! * the framing is valid (magic, known family, supported version, exact
//!   length, no trailing bytes);
//! * every ref points to an existing, valid object.
//!
//! fsck NEVER repairs objects (immutable; a damaged object is reported and
//! left for the operator). Disposable indexes can be rebuilt, but the store
//! module does not own them; callers (the CLI `fsck` command) compose this
//! store check with the corpus link check (`crate::corpus`).
//!
//! This module is coordinator-gated.

use crate::canon::{self, Family};
use crate::error::Result;
use crate::id::ContentId;
use crate::store::refs::list_refs;
use crate::store::{Store, OBJECTS_DIR, REFS_DIR};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// One verified object.
#[derive(Debug, Clone)]
pub struct ObjectReport {
    /// The object's content ID.
    pub id: ContentId,
    /// The object family (from the validated framing).
    pub family: Family,
    /// Framed length in bytes.
    pub framed_len: usize,
}

/// The fsck result.
#[derive(Debug, Clone, Default)]
pub struct FsckReport {
    /// Objects that passed verification, grouped by family (deterministic
    /// iteration).
    pub by_family: BTreeMap<String, Vec<ObjectReport>>,
    /// Errors: human-readable descriptions of every defect found.
    pub errors: Vec<String>,
    /// Refs that point at missing or corrupt objects.
    pub dangling_refs: Vec<String>,
}

impl FsckReport {
    /// True when no defects were found.
    pub fn clean(&self) -> bool {
        self.errors.is_empty() && self.dangling_refs.is_empty()
    }

    /// Total objects verified.
    pub fn object_count(&self) -> usize {
        self.by_family.values().map(Vec::len).sum()
    }

    /// Object count per family (deterministic, sorted by family name).
    pub fn per_family_counts(&self) -> Vec<(&str, usize)> {
        self.by_family
            .iter()
            .map(|(name, v)| (name.as_str(), v.len()))
            .collect()
    }
}

/// Run the store-level fsck.
pub fn fsck(store: &Store) -> Result<FsckReport> {
    let mut report = FsckReport::default();
    let objects_dir = store.root().join(OBJECTS_DIR);

    // ---- objects ----
    if objects_dir.exists() {
        for entry in walk_dir(&objects_dir) {
            if !entry.is_file() {
                continue;
            }
            let fname = entry
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if fname.len() != 64 {
                report.errors.push(format!(
                    "{}: filename is not a 64-hex content id",
                    entry.display()
                ));
                continue;
            }
            let id = match ContentId::from_hex(&fname) {
                Ok(id) => id,
                Err(_) => {
                    report.errors.push(format!(
                        "{}: filename is not a valid content id",
                        entry.display()
                    ));
                    continue;
                }
            };
            // Path must be objects/blake3/<2-hex>/<64-hex>.
            let parent_ok = entry
                .parent()
                .and_then(Path::file_name)
                .map(|d| d.to_string_lossy() == fname[..2])
                .unwrap_or(false);
            if !parent_ok {
                report.errors.push(format!(
                    "{}: object not in the <first-two-hex>/ directory layout",
                    entry.display()
                ));
            }
            let bytes = match fs::read(&entry) {
                Ok(b) => b,
                Err(e) => {
                    report
                        .errors
                        .push(format!("{}: unreadable: {e}", entry.display()));
                    continue;
                }
            };
            let actual = ContentId::new(&bytes);
            if actual != id {
                report.errors.push(format!(
                    "{}: content hashes to {} (I13 violation)",
                    entry.display(),
                    actual.to_hex()
                ));
                continue;
            }
            match canon::unframe(&bytes) {
                Ok((header, _)) => {
                    let name = header.family.name().to_string();
                    report
                        .by_family
                        .entry(name)
                        .or_default()
                        .push(ObjectReport {
                            id,
                            family: header.family,
                            framed_len: bytes.len(),
                        });
                }
                Err(e) => {
                    report
                        .errors
                        .push(format!("{}: bad framing: {e}", entry.display()));
                }
            }
        }
    }

    // ---- refs ----
    let refs_dir = store.root().join(REFS_DIR);
    if refs_dir.exists() {
        for name in list_refs(store.root())? {
            match crate::store::refs::get_ref(store.root(), &name) {
                Ok(Some(id)) => {
                    if !store.contains(&id) {
                        report
                            .dangling_refs
                            .push(format!("{name} -> {id} (missing)"));
                    }
                }
                Ok(None) => {
                    report.dangling_refs.push(format!("{name} -> (unreadable)"));
                }
                Err(e) => {
                    report.dangling_refs.push(format!("{name}: {e}"));
                }
            }
        }
    }

    Ok(report)
}

/// Deterministic recursive walk (sorted, no symlink following).
fn walk_dir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| !is_symlink(p))
        .collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            out.extend(walk_dir(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn is_symlink(p: &Path) -> bool {
    fs::symlink_metadata(p)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::object::Store;

    fn tmp_store(tag: &str) -> Store {
        let dir =
            std::env::temp_dir().join(format!("frf-fuzz-fsck-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Store::open(dir).unwrap()
    }

    #[test]
    fn empty_store_is_clean() {
        let s = tmp_store("empty");
        let r = fsck(&s).unwrap();
        assert!(r.clean());
        assert_eq!(r.object_count(), 0);
    }

    #[test]
    fn valid_objects_and_refs_are_clean() {
        let s = tmp_store("valid");
        let id = s.put(Family::CorpusEntry, b"input").unwrap();
        crate::store::refs::set_ref(s.root(), "corpus-head", &id).unwrap();
        let r = fsck(&s).unwrap();
        assert!(r.clean(), "{:?}", r.errors);
        assert_eq!(r.object_count(), 1);
        assert_eq!(r.per_family_counts(), vec![("corpus-entry", 1)]);
    }

    #[test]
    fn dangling_ref_is_reported() {
        let s = tmp_store("dangling");
        let id = ContentId::new(b"never stored");
        crate::store::refs::set_ref(s.root(), "campaign-current", &id).unwrap();
        let r = fsck(&s).unwrap();
        assert!(!r.clean());
        assert_eq!(r.dangling_refs.len(), 1);
    }

    #[test]
    fn tampered_object_is_reported() {
        let s = tmp_store("tamper");
        let id = s.put(Family::Finding, b"payload").unwrap();
        let path = s
            .root()
            .join(OBJECTS_DIR)
            .join(&id.to_hex()[..2])
            .join(id.to_hex());
        let mut bytes = fs::read(&path).unwrap();
        bytes[5] ^= 0x01; // corrupt the family byte
        fs::write(&path, bytes).unwrap();
        let r = fsck(&s).unwrap();
        assert!(!r.clean());
        assert_eq!(r.errors.len(), 1);
    }
}
