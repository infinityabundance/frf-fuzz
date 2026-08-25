//! The immutable object store: atomic writes, content addressing, collision
//! detection.
//!
//! # Atomic-write protocol (documented in docs/ARCHITECTURE.md §24)
//!
//! ```text
//! create temp file in tmp/ -> write all bytes -> fsync file
//! -> rename onto final path (same filesystem, atomic) -> fsync directory
//! ```
//!
//! `put` is idempotent: writing the same framed bytes twice is a no-op that
//! returns the same ID. Writing *different* bytes under an existing ID is
//! `Error::IdCollision` — fatal corruption (I13), never silently resolved.
//!
//! This module is coordinator-gated (requires `blake3`).

use crate::canon::{self, Family};
use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::store::{OBJECTS_DIR, TMP_DIR};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The object store rooted at `root` (the `.frf-fuzz/` directory).
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Open (creating if needed) the store at `root`.
    pub fn open(root: PathBuf) -> Result<Store> {
        for dir in [&root, &root.join(OBJECTS_DIR), &root.join(TMP_DIR)] {
            fs::create_dir_all(dir).map_err(|e| {
                Error::Other(format!(
                    "cannot create store directory {}: {e}",
                    dir.display()
                ))
            })?;
        }
        Ok(Store { root })
    }

    /// The store root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The on-disk path for an object ID.
    fn path_for(&self, id: &ContentId) -> PathBuf {
        let hex = id.to_hex();
        self.root.join(OBJECTS_DIR).join(&hex[..2]).join(&hex)
    }

    /// Frame `payload` as a `family` object, hash it, and store it
    /// atomically. Returns the content ID. Idempotent; `IdCollision` on
    /// same-ID-different-bytes.
    pub fn put(&self, family: Family, payload: &[u8]) -> Result<ContentId> {
        let framed = canon::frame(family, canon::MAJOR, canon::MINOR, payload)?;
        let id = ContentId::new(&framed);
        let path = self.path_for(&id);
        if path.exists() {
            let existing = fs::read(&path)?;
            if existing == framed {
                return Ok(id);
            }
            return Err(Error::IdCollision);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.tmp_path();
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&framed)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        // Best-effort directory fsync (EINVAL/unsupported on some filesystems).
        if let Some(dir) = path.parent() {
            if let Ok(d) = fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(id)
    }

    /// Fetch a stored object's *payload* (framing validated). `None` when
    /// the object does not exist; `Err` on corruption (hash mismatch,
    /// malformed framing).
    pub fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>> {
        Ok(self.get_typed(id)?.map(|(_, payload)| payload))
    }

    /// Fetch an object's validated family and payload.
    pub fn get_typed(&self, id: &ContentId) -> Result<Option<(Family, Vec<u8>)>> {
        match self.get_raw(id)? {
            None => Ok(None),
            Some(framed) => {
                let (header, payload) = canon::unframe(&framed)?;
                Ok(Some((header.family, payload.to_vec())))
            }
        }
    }

    /// Fetch the raw framed bytes of an object (for fsck/verification).
    pub fn get_raw(&self, id: &ContentId) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)?;
        // Verify the address: the file at `id` must hash to `id`. A mismatch
        // is corruption, never silently served (I13).
        let actual = ContentId::new(&bytes);
        if &actual != id {
            return Err(Error::Other(format!(
                "object {} hashes to {} (corruption)",
                id,
                actual.to_hex()
            )));
        }
        Ok(Some(bytes))
    }

    /// True if the object exists and is valid.
    pub fn contains(&self, id: &ContentId) -> bool {
        self.get_raw(id).map(|o| o.is_some()).unwrap_or(false)
    }

    /// List every stored object ID in deterministic (sorted) order. Used by
    /// index rebuilds (`fsck`, campaign start). Content is NOT verified here
    /// (that is `get`/`fsck`'s job); the filename is parsed as the ID.
    pub fn list_object_ids(&self) -> Result<Vec<ContentId>> {
        let objects_dir = self.root.join(OBJECTS_DIR);
        let mut ids = Vec::new();
        if !objects_dir.exists() {
            return Ok(ids);
        }
        for entry in walk_dir(&objects_dir) {
            if !entry.is_file() {
                continue;
            }
            let fname = entry
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if fname.len() == 64 {
                if let Ok(id) = ContentId::from_hex(&fname) {
                    ids.push(id);
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// A fresh temp path in `tmp/` (unique per call via a monotonic
    /// counter; `tmp/` is disposable and excluded from canonical identity).
    fn tmp_path(&self) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
        let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        self.root.join(TMP_DIR).join(format!("write-{n}.tmp"))
    }
}

/// Deterministic recursive walk (sorted, no symlink following).
fn walk_dir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            fs::symlink_metadata(p)
                .map(|m| !m.file_type().is_symlink())
                .unwrap_or(false)
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(tag: &str) -> Store {
        let dir =
            std::env::temp_dir().join(format!("frf-fuzz-store-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Store::open(dir).unwrap()
    }

    #[test]
    fn put_get_roundtrip() {
        let s = tmp_store("roundtrip");
        let id = s.put(Family::CorpusEntry, b"hello corpus").unwrap();
        assert_eq!(s.get(&id).unwrap(), Some(b"hello corpus".to_vec()));
        assert!(s.contains(&id));
    }

    #[test]
    fn put_is_idempotent_and_collision_is_fatal() {
        let s = tmp_store("collision");
        let id1 = s.put(Family::CorpusEntry, b"same bytes").unwrap();
        let id2 = s.put(Family::CorpusEntry, b"same bytes").unwrap();
        assert_eq!(id1, id2);
        // Same ID + different bytes is fatal (I13). The only way to reach it
        // is corruption: the on-disk object was tampered (a legit write of
        // the same ID is byte-identical by construction).
        let path = s.path_for(&id1);
        let mut bytes = fs::read(&path).unwrap();
        bytes[15] ^= 0xFF; // corrupt one payload byte
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            s.put(Family::CorpusEntry, b"same bytes"),
            Err(Error::IdCollision)
        ));
    }

    #[test]
    fn identity_is_content_only() {
        let s = tmp_store("content");
        let id = s.put(Family::CorpusEntry, b"deterministic").unwrap();
        // Independent store, same bytes -> same ID.
        let other = tmp_store("content-other");
        assert_eq!(
            other.put(Family::CorpusEntry, b"deterministic").unwrap(),
            id
        );
        // Different family -> different ID.
        assert_ne!(s.put(Family::Finding, b"deterministic").unwrap(), id);
    }

    #[test]
    fn missing_object_is_none() {
        let s = tmp_store("missing");
        let id = ContentId::new(b"never written");
        assert_eq!(s.get(&id).unwrap(), None);
        assert!(!s.contains(&id));
    }

    #[test]
    fn list_object_ids_is_sorted() {
        let s = tmp_store("list");
        let id = s.put(Family::CorpusEntry, b"a").unwrap();
        let id2 = s.put(Family::Finding, b"b").unwrap();
        let ids = s.list_object_ids().unwrap();
        let mut expect = vec![id, id2];
        expect.sort();
        assert_eq!(ids, expect);
    }

    #[test]
    fn tampered_object_is_corruption() {
        let s = tmp_store("tamper");
        let id = s.put(Family::CorpusEntry, b"tamper me").unwrap();
        let path = s.path_for(&id);
        let mut bytes = fs::read(&path).unwrap();
        bytes[15] ^= 0xFF; // flip one payload byte
        fs::write(&path, bytes).unwrap();
        assert!(s.get(&id).is_err());
        assert!(!s.contains(&id));
    }
}
