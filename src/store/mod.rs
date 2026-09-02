//! The `.frf-fuzz/` content-addressed object store.
//!
//! Layout (docs/ARCHITECTURE.md §24):
//!
//! ```text
//! .frf-fuzz/
//!   config.toml
//!   objects/blake3/<first-two-hex>/<full-hex-id>   (framed objects)
//!   refs/<name>                                    (name -> content id)
//!   corpus/                                       (indexes; disposable)
//!   findings/
//!   tmp/                                          (atomic-write staging)
//! ```
//!
//! Every object is immutable and content-addressed by BLAKE3-256 over its
//! canonical framed bytes ([`crate::canon`]). Same ID + different bytes is
//! fatal corruption (I13), never silently resolved. Writes follow the
//! documented atomic protocol: temp file, write all, fsync, rename, dir
//! fsync where supported.
//!
//! The corpus/feature/finding indexes are disposable: they are rebuilt from
//! the durable objects by `fsck`/campaign start (features come from the
//! durable `CorpusMeta` objects, so nothing observation-derived is lost).
//!
//! This module is coordinator-gated (requires `blake3` for identity).

use crate::error::{Error, Result};

pub mod fsck;
pub mod object;
pub mod refs;

pub use object::Store;
pub use refs::{get_ref, list_refs, set_ref};

/// Create a directory (and parents) if missing.
pub fn ensure_dir(path: &std::path::Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(path)
        .map_err(|e| Error::Other(format!("cannot create directory {}: {e}", path.display())))
}

/// Atomically write an operational sidecar file: temp file in the same
/// directory, write all, fsync, rename onto the final path, best-effort
/// directory fsync. This is the store's write discipline applied to files
/// that are NOT canonical store objects (experiment exports, reports).
/// The staging file carries a process-unique suffix so concurrent writers
/// never collide.
pub fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| {
        Error::Other(format!(
            "atomic write {}: no parent directory",
            path.display()
        ))
    })?;
    ensure_dir(dir)?;
    let tmp = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "out".to_string())
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The default store root relative to a project directory.
pub const DEFAULT_STORE_DIR: &str = ".frf-fuzz";

/// The object subtree root (relative to the store root).
pub const OBJECTS_DIR: &str = "objects/blake3";
/// The refs subtree root.
pub const REFS_DIR: &str = "refs";
/// The atomic-write staging directory.
pub const TMP_DIR: &str = "tmp";
