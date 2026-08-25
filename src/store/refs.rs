//! Named references: `refs/<name>` -> content ID.
//!
//! Refs are the durable pointers between objects (e.g. `campaigns/current`
//! -> the campaign object, `corpus/head` -> the latest corpus snapshot).
//! They use the same atomic-write protocol as objects. Refs are validated by
//! `fsck` (a ref to a missing object is corruption, reportable but not
//! auto-repaired: the ref is the durable intent).
//!
//! This module is coordinator-gated.

use crate::error::{Error, Result};
use crate::id::ContentId;
use crate::store::REFS_DIR;
use std::fs;
use std::path::{Path, PathBuf};

/// The refs root.
pub fn refs_dir(root: &Path) -> PathBuf {
    root.join(REFS_DIR)
}

/// Set `name` -> `id`, atomically.
pub fn set_ref(root: &Path, name: &str, id: &ContentId) -> Result<()> {
    validate_ref_name(name)?;
    let dir = refs_dir(root);
    fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    fs::write(&tmp, id.to_hex().as_bytes())?;
    // fsync the temp before rename.
    {
        let f = fs::File::open(&tmp)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    if let Ok(d) = fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Resolve `name` -> content ID. `None` when the ref does not exist; `Err`
/// on malformed ref content (corruption).
pub fn get_ref(root: &Path, name: &str) -> Result<Option<ContentId>> {
    validate_ref_name(name)?;
    let path = refs_dir(root).join(name);
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    let id = ContentId::from_hex(content.trim()).map_err(|_| {
        Error::Other(format!(
            "ref `{name}` does not contain a valid content id (corruption)"
        ))
    })?;
    Ok(Some(id))
}

/// List ref names in deterministic (sorted) order.
pub fn list_refs(root: &Path) -> Result<Vec<String>> {
    let dir = refs_dir(root);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names: Vec<String> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.ends_with(".tmp"))
        .collect();
    names.sort();
    Ok(names)
}

/// Ref names are constrained to a safe character set (no path separators,
/// no traversal).
fn validate_ref_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
    {
        return Err(Error::Encoding("invalid ref name"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("frf-fuzz-refs-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn ref_roundtrip() {
        let root = tmp_root("roundtrip");
        let id = ContentId::new(b"ref target");
        set_ref(&root, "campaign-current", &id).unwrap();
        assert_eq!(get_ref(&root, "campaign-current").unwrap(), Some(id));
        assert_eq!(list_refs(&root).unwrap(), vec!["campaign-current"]);
    }

    #[test]
    fn missing_ref_is_none() {
        let root = tmp_root("missing");
        assert_eq!(get_ref(&root, "nope").unwrap(), None);
    }

    #[test]
    fn bad_ref_name_is_refused() {
        let root = tmp_root("badname");
        let id = ContentId::new(b"x");
        assert!(set_ref(&root, "../escape", &id).is_err());
        assert!(set_ref(&root, "a/b", &id).is_err());
        assert!(set_ref(&root, "", &id).is_err());
    }

    #[test]
    fn corrupt_ref_content_is_error() {
        let root = tmp_root("corrupt");
        fs::create_dir_all(refs_dir(&root)).unwrap();
        fs::write(refs_dir(&root).join("bad"), "not-a-hex-id").unwrap();
        assert!(get_ref(&root, "bad").is_err());
    }
}
