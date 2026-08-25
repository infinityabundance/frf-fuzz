//! Central error type.
//!
//! Deliberately dependency-free (no thiserror): the error type is part of the
//! crate's narrow public API and its `Display` output is itself part of the
//! user-facing contract (`frf-fuzz report`, `frf-fuzz doctor --json`).
//!
//! Every variant carries enough context to be actionable without a stack
//! trace: what was bounded, what the bound was, and what was actually seen.

use std::fmt;

/// Result alias for the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The crate-wide error type.
//
// Deliberately not Clone/Eq/PartialEq: it contains `std::io::Error`, which is
// none of those. Tests compare via `matches!` on variants.
#[derive(Debug)]
pub enum Error {
    /// A length or count exceeded a configured bound.
    BoundExceeded {
        /// The name of the bounded quantity.
        what: &'static str,
        /// The configured limit.
        limit: u64,
        /// The offending value.
        got: u64,
    },

    /// A magic/header mismatch: wrong object family, wrong framing, or
    /// corrupt bytes.
    BadMagic {
        /// Expected magic bytes (hex).
        expected: String,
        /// Observed bytes (hex).
        got: String,
    },

    /// An unsupported or unknown version in a versioned encoding.
    UnsupportedVersion {
        /// The versioned artifact family.
        family: &'static str,
        /// The version that was refused.
        version: u32,
    },

    /// Canonical encoding or decoding failure.
    Encoding(&'static str),

    /// Arithmetic overflow in a length/count computation on hostile input.
    Overflow,

    /// A checksum mismatch (torn write, corruption, or hostile input).
    ChecksumMismatch,

    /// An object with this ID already exists with different bytes. This is
    /// fatal corruption, never silently resolved (invariant I13).
    IdCollision,

    /// An I/O error.
    Io(std::io::Error),

    /// A worker process died unexpectedly.
    WorkerDied {
        /// The exit status observed.
        status: std::process::ExitStatus,
        /// Which stage the worker was in, if known.
        stage: &'static str,
    },

    /// The instrumented toolchain probe failed.
    Toolchain(String),

    /// A structural/regime observation was refused (e.g. generic fuzz
    /// residual passed where a SQL ResidualClass is required — invariant I7).
    Refused(&'static str),

    /// Anything else; the message is the contract.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BoundExceeded { what, limit, got } => {
                write!(f, "{what} exceeds bound {limit}: got {got}")
            }
            Error::BadMagic { expected, got } => {
                write!(f, "bad magic: expected {expected}, got {got}")
            }
            Error::UnsupportedVersion { family, version } => {
                write!(f, "unsupported {family} version {version}")
            }
            Error::Encoding(what) => write!(f, "encoding error: {what}"),
            Error::Overflow => write!(f, "arithmetic overflow in length computation"),
            Error::ChecksumMismatch => write!(f, "checksum mismatch"),
            Error::IdCollision => write!(f, "object ID collision: same ID, different bytes"),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::WorkerDied { status, stage } => {
                write!(f, "worker died at {stage}: {status}")
            }
            Error::Toolchain(what) => write!(f, "toolchain error: {what}"),
            Error::Refused(what) => write!(f, "refused: {what}"),
            Error::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
