//! Content identity for the coordinator-side object store.
//!
//! frf-fuzz internal identity is BLAKE3-256 over canonical framed bytes
//! ([`crate::canon`]). This namespace is deliberately separate from FRF IDs
//! (SHA-256 content addresses / `run-`/`receipt-` composites) and Gemel Gids;
//! none of these namespaces are ever merged or reinterpreted
//! (docs/INVARIANTS.md).
//!
//! A [`ContentId`] is 32 raw bytes; the canonical textual form is lowercase
//! hex. The [`ContentId::short`] form (first 8 bytes) is used inside
//! [`crate::mutation::coordinate::MutationCoordinate`] as the parent short key
//! for the crash ledger: the full ID is resolved by the coordinator through
//! the corpus index.
//!
//! This module is coordinator-gated (requires `blake3`).

use crate::error::{Error, Result};

/// A BLAKE3-256 content address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentId([u8; 32]);

impl ContentId {
    /// Hash `bytes` into a content ID.
    pub fn new(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Wrap an existing 32-byte digest.
    pub const fn from_array(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The raw digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The first 8 bytes: the short key used in mutation coordinates and the
    /// crash ledger. Collisions are resolved by the coordinator through the
    /// corpus index (an 8-byte prefix is a lookup hint, not identity).
    pub const fn short(&self) -> [u8; 8] {
        let mut s = [0u8; 8];
        let mut i = 0;
        while i < 8 {
            s[i] = self.0[i];
            i += 1;
        }
        s
    }

    /// Lowercase hex form.
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for &b in &self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }

    /// Parse a 64-char lowercase hex string.
    pub fn from_hex(s: &str) -> Result<ContentId> {
        if s.len() != 64 {
            return Err(Error::Encoding("content id must be 64 hex chars"));
        }
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        for i in 0..32 {
            let hi = hexval(bytes[2 * i]).ok_or(Error::Encoding("invalid hex digit"))?;
            let lo = hexval(bytes[2 * i + 1]).ok_or(Error::Encoding("invalid hex digit"))?;
            out[i] = (hi << 4) | lo;
        }
        Ok(ContentId(out))
    }
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::str::FromStr for ContentId {
    type Err = Error;
    fn from_str(s: &str) -> Result<ContentId> {
        ContentId::from_hex(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BLAKE3-256 of the empty input (well-known vector).
    const BLAKE3_EMPTY: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

    #[test]
    fn known_vector_empty() {
        let id = ContentId::new(b"");
        assert_eq!(id.to_hex(), BLAKE3_EMPTY);
    }

    #[test]
    fn hex_roundtrip() {
        let id = ContentId::new(b"some canonical bytes");
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        let back = ContentId::from_hex(&hex).unwrap();
        assert_eq!(back, id);
        assert_eq!(back.to_hex(), hex);
    }

    #[test]
    fn short_is_first_eight_bytes() {
        let id = ContentId::new(b"abcdefghijklmnopqrstuvwxyz");
        let mut expect = [0u8; 8];
        expect.copy_from_slice(&id.as_bytes()[..8]);
        assert_eq!(id.short(), expect);
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(ContentId::from_hex("").is_err());
        assert!(ContentId::from_hex("abc").is_err());
        assert!(ContentId::from_hex(&"g".repeat(64)).is_err());
        assert!(ContentId::from_hex(&"A".repeat(64)).is_err()); // uppercase refused
        assert!(ContentId::from_hex(&"a".repeat(63)).is_err());
    }
}
