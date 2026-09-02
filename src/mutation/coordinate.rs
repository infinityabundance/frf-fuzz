//! The canonical mutation coordinate.
//!
//! A [`MutationCoordinate`] fully specifies one mutation:
//!
//! ```text
//! campaign_seed      u64   (deterministic campaign identity)
//! parent_short_id    [u8; 8]  (first 8 bytes of the parent content ID)
//! generation         u32   (mutation generation / depth)
//! mutator_id         MutatorId (stable numeric family ID, see mutation::MutatorId)
//! lane_id            u16   (worker lane)
//! mutation_index     u64   (ordinal within the lane's batch)
//! probe_params       [u32; 4]  (probe recipe parameters; 0 = none)
//! ```
//!
//! The encoded form is fixed-size (49 bytes) and canonical: version byte
//! first, then all fields little-endian. It is small enough to sit in the
//! per-worker crash ledger, which is what lets the coordinator reconstruct an
//! exact crashing candidate after a worker dies (docs/INVARIANTS.md, I2).
//!
//! The parent short ID is a lookup hint: the full parent content ID lives in
//! the corpus index. Mutation is reproducible from the coordinate plus the
//! immutable parent bytes and any dictionaries; it never depends on mutable
//! global RNG state.

use crate::error::{Error, Result};
use crate::mutation::prng::CounterRng;
use crate::mutation::MutatorId;

/// Version of the coordinate encoding. Bump on any layout change.
pub const COORDINATE_VERSION: u8 = 1;

/// Fixed encoded length: version(1) + seed(8) + parent(8) + gen(4) +
/// mutator(2) + lane(2) + index(8) + probe(16) = 49 bytes.
pub const COORDINATE_ENCODED_LEN: usize = 49;

/// A fully-specified deterministic mutation coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MutationCoordinate {
    /// Campaign seed; the deterministic identity of the campaign's random
    /// stream.
    pub campaign_seed: u64,
    /// First 8 bytes of the parent content ID (corpus lookup hint).
    pub parent_short_id: [u8; 8],
    /// Mutation generation / depth.
    pub generation: u32,
    /// The mutator family (stable numeric ID).
    pub mutator_id: MutatorId,
    /// Worker lane ID.
    pub lane_id: u16,
    /// Mutation ordinal within the lane's work order.
    pub mutation_index: u64,
    /// Probe recipe parameters (0 when not probing). Carried for provenance;
    /// see `prng` docs for why they do not enter the random stream.
    pub probe_params: [u32; 4],
}

impl MutationCoordinate {
    /// Encode to the canonical 49-byte form.
    pub fn encode(&self) -> [u8; COORDINATE_ENCODED_LEN] {
        let mut out = [0u8; COORDINATE_ENCODED_LEN];
        out[0] = COORDINATE_VERSION;
        out[1..9].copy_from_slice(&self.campaign_seed.to_le_bytes());
        out[9..17].copy_from_slice(&self.parent_short_id);
        out[17..21].copy_from_slice(&self.generation.to_le_bytes());
        out[21..23].copy_from_slice(&(self.mutator_id.id()).to_le_bytes());
        out[23..25].copy_from_slice(&self.lane_id.to_le_bytes());
        out[25..33].copy_from_slice(&self.mutation_index.to_le_bytes());
        for (i, p) in self.probe_params.iter().enumerate() {
            out[33 + i * 4..33 + i * 4 + 4].copy_from_slice(&p.to_le_bytes());
        }
        out
    }

    /// Decode from the canonical 49-byte form, validating the version byte
    /// and the mutator ID. Rejects unknown versions and unknown mutator IDs.
    pub fn decode(bytes: &[u8]) -> Result<MutationCoordinate> {
        if bytes.len() != COORDINATE_ENCODED_LEN {
            return Err(Error::Encoding("coordinate must be exactly 49 bytes"));
        }
        if bytes[0] != COORDINATE_VERSION {
            return Err(Error::UnsupportedVersion {
                family: "mutation-coordinate",
                version: bytes[0] as u32,
            });
        }
        let campaign_seed = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
        let mut parent_short_id = [0u8; 8];
        parent_short_id.copy_from_slice(&bytes[9..17]);
        let generation = u32::from_le_bytes(bytes[17..21].try_into().unwrap());
        let mutator_raw = u16::from_le_bytes(bytes[21..23].try_into().unwrap());
        let mutator_id = MutatorId::from_id(mutator_raw)
            .ok_or(Error::Encoding("unknown mutator id in coordinate"))?;
        let lane_id = u16::from_le_bytes(bytes[23..25].try_into().unwrap());
        let mutation_index = u64::from_le_bytes(bytes[25..33].try_into().unwrap());
        let mut probe_params = [0u32; 4];
        for (i, p) in probe_params.iter_mut().enumerate() {
            *p = u32::from_le_bytes(bytes[33 + i * 4..33 + i * 4 + 4].try_into().unwrap());
        }
        Ok(MutationCoordinate {
            campaign_seed,
            parent_short_id,
            generation,
            mutator_id,
            lane_id,
            mutation_index,
            probe_params,
        })
    }

    /// Derive the deterministic random stream for this coordinate.
    pub fn derive_prng(&self) -> CounterRng {
        CounterRng::from_coordinate_fields(
            self.campaign_seed,
            self.generation,
            self.mutator_id.id(),
            self.lane_id,
            self.mutation_index,
        )
    }

    /// The coordinate as a hex string (for the crash ledger / CLI display).
    pub fn to_hex(&self) -> String {
        let bytes = self.encode();
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(COORDINATE_ENCODED_LEN * 2);
        for &b in &bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }

    /// Parse from hex produced by [`Self::to_hex`].
    pub fn from_hex(s: &str) -> Result<MutationCoordinate> {
        let bytes = hex_decode(s).ok_or(Error::Encoding("invalid coordinate hex"))?;
        MutationCoordinate::decode(&bytes)
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..s.len() / 2 {
        let hi = hexval(b[2 * i])?;
        let lo = hexval(b[2 * i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MutationCoordinate {
        MutationCoordinate {
            campaign_seed: 0xDEAD_BEEF_CAFE_F00D,
            parent_short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            generation: 7,
            mutator_id: MutatorId::ByteFlip,
            lane_id: 3,
            mutation_index: 0x1234_5678_9ABC_DEF0,
            probe_params: [9, 8, 7, 6],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let c = sample();
        let bytes = c.encode();
        assert_eq!(bytes.len(), COORDINATE_ENCODED_LEN);
        let d = MutationCoordinate::decode(&bytes).unwrap();
        assert_eq!(d, c);
    }

    #[test]
    fn hex_roundtrip() {
        let c = sample();
        let h = c.to_hex();
        assert_eq!(h.len(), COORDINATE_ENCODED_LEN * 2);
        assert_eq!(MutationCoordinate::from_hex(&h).unwrap(), c);
    }

    #[test]
    fn rejects_unknown_version() {
        let c = sample();
        let mut bytes = c.encode();
        bytes[0] = 99;
        assert!(matches!(
            MutationCoordinate::decode(&bytes),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn rejects_bad_length_and_unknown_mutator() {
        let c = sample();
        assert!(MutationCoordinate::decode(&c.encode()[..48]).is_err());
        let mut bytes = c.encode();
        bytes[21] = 0xFF;
        bytes[22] = 0xFF;
        assert!(MutationCoordinate::decode(&bytes).is_err());
    }

    #[test]
    fn deterministic_encoding() {
        let c = sample();
        let e1 = c.encode();
        let e2 = sample().encode();
        assert_eq!(e1, e2);
    }

    #[test]
    fn derived_stream_depends_on_mutator_id() {
        let a = sample();
        let mut b = sample();
        b.mutator_id = MutatorId::BitFlip;
        assert_ne!(a.derive_prng().next_u64(), b.derive_prng().next_u64());
    }
}
