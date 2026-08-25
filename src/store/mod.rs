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

pub mod fsck;
pub mod object;
pub mod refs;

pub use object::Store;
pub use refs::{get_ref, list_refs, set_ref};

/// The default store root relative to a project directory.
pub const DEFAULT_STORE_DIR: &str = ".frf-fuzz";

/// The object subtree root (relative to the store root).
pub const OBJECTS_DIR: &str = "objects/blake3";
/// The refs subtree root.
pub const REFS_DIR: &str = "refs";
/// The atomic-write staging directory.
pub const TMP_DIR: &str = "tmp";
