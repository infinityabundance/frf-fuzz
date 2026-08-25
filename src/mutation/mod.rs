//! Deterministic mutation engine.
//!
//! Every mutation is a pure function of a [`MutationCoordinate`]
//! (coordinate module), the immutable parent bytes, and immutable auxiliary
//! data (dictionary entries, compare-operand hits, splice partners). There is
//! no mutable global RNG state anywhere in this module
//! (docs/INVARIANTS.md, I2).
//!
//! Mutator family IDs are STABLE: 1..15 are assigned in docs/ARCHITECTURE.md
//! and must never be renumbered. A mutation recorded as family 7 must mean
//! byte-insert forever, on every backend and every future version that reads
//! old tapes.

pub mod bytes;
pub mod cmp;
pub mod coordinate;
pub mod dictionary;
pub mod influence;
pub mod integer;
pub mod prng;
pub mod splice;

pub use coordinate::MutationCoordinate;
pub use prng::CounterRng;

use crate::error::{Error, Result};

/// Ceiling for mutated output length. Insert/duplicate/splice operations
/// clamp deterministically to this bound rather than growing without limit.
pub const MAX_MUTATED_LEN: usize = 1 << 20; // 1 MiB

/// Stable mutator family IDs.
///
/// These IDs are part of the persisted record format. Do NOT renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum MutatorId {
    /// Single bit flip at one position.
    BitFlip = 1,
    /// Whole-byte replacement at one position.
    ByteFlip = 2,
    /// Multiple deterministic flips at distinct positions.
    MultiByteFlips = 3,
    /// Integer +/- small delta.
    IntegerAddSub = 4,
    /// Integer boundary values.
    IntegerBoundary = 5,
    /// Interesting integer replacement.
    InterestingInteger = 6,
    /// Byte insertion.
    ByteInsert = 7,
    /// Byte deletion.
    ByteDelete = 8,
    /// Block duplication.
    BlockDuplicate = 9,
    /// Block deletion.
    BlockDelete = 10,
    /// Block overwrite with random bytes.
    BlockOverwrite = 11,
    /// Splice a block from a partner input.
    Splice = 12,
    /// Dictionary entry insertion.
    DictionaryInsert = 13,
    /// Dictionary entry overwrite.
    DictionaryOverwrite = 14,
    /// Compare-operand substitution.
    CompareOperandSubstitution = 15,
    /// Localized influence-region mutation.
    InfluenceRegionMutation = 16,
}

impl MutatorId {
    /// All mutator families in ID order.
    pub const ALL: [MutatorId; 16] = [
        MutatorId::BitFlip,
        MutatorId::ByteFlip,
        MutatorId::MultiByteFlips,
        MutatorId::IntegerAddSub,
        MutatorId::IntegerBoundary,
        MutatorId::InterestingInteger,
        MutatorId::ByteInsert,
        MutatorId::ByteDelete,
        MutatorId::BlockDuplicate,
        MutatorId::BlockDelete,
        MutatorId::BlockOverwrite,
        MutatorId::Splice,
        MutatorId::DictionaryInsert,
        MutatorId::DictionaryOverwrite,
        MutatorId::CompareOperandSubstitution,
        MutatorId::InfluenceRegionMutation,
    ];

    /// The stable numeric ID.
    pub const fn id(self) -> u16 {
        self as u16
    }

    /// Resolve a numeric ID to a mutator family.
    pub const fn from_id(id: u16) -> Option<MutatorId> {
        match id {
            1 => Some(MutatorId::BitFlip),
            2 => Some(MutatorId::ByteFlip),
            3 => Some(MutatorId::MultiByteFlips),
            4 => Some(MutatorId::IntegerAddSub),
            5 => Some(MutatorId::IntegerBoundary),
            6 => Some(MutatorId::InterestingInteger),
            7 => Some(MutatorId::ByteInsert),
            8 => Some(MutatorId::ByteDelete),
            9 => Some(MutatorId::BlockDuplicate),
            10 => Some(MutatorId::BlockDelete),
            11 => Some(MutatorId::BlockOverwrite),
            12 => Some(MutatorId::Splice),
            13 => Some(MutatorId::DictionaryInsert),
            14 => Some(MutatorId::DictionaryOverwrite),
            15 => Some(MutatorId::CompareOperandSubstitution),
            16 => Some(MutatorId::InfluenceRegionMutation),
            _ => None,
        }
    }

    /// Human-readable family name.
    pub const fn name(self) -> &'static str {
        match self {
            MutatorId::BitFlip => "bit-flip",
            MutatorId::ByteFlip => "byte-flip",
            MutatorId::MultiByteFlips => "multi-byte-flips",
            MutatorId::IntegerAddSub => "integer-add-sub",
            MutatorId::IntegerBoundary => "integer-boundary",
            MutatorId::InterestingInteger => "interesting-integer",
            MutatorId::ByteInsert => "byte-insert",
            MutatorId::ByteDelete => "byte-delete",
            MutatorId::BlockDuplicate => "block-duplicate",
            MutatorId::BlockDelete => "block-delete",
            MutatorId::BlockOverwrite => "block-overwrite",
            MutatorId::Splice => "splice",
            MutatorId::DictionaryInsert => "dictionary-insert",
            MutatorId::DictionaryOverwrite => "dictionary-overwrite",
            MutatorId::CompareOperandSubstitution => "compare-operand-substitution",
            MutatorId::InfluenceRegionMutation => "influence-region-mutation",
        }
    }
}

/// A compare-operand observation (from the target runtime's cmp ring).
///
/// Width is explicit so substitution can match the operand's byte pattern
/// exactly. Values are interpreted as little-endian in the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpHit {
    /// 1-byte operand.
    U8(u8),
    /// 2-byte operand.
    U16(u16),
    /// 4-byte operand.
    U32(u32),
    /// 8-byte operand.
    U64(u64),
}

impl CmpHit {
    /// Operand width in bytes.
    pub const fn width(&self) -> usize {
        match self {
            CmpHit::U8(_) => 1,
            CmpHit::U16(_) => 2,
            CmpHit::U32(_) => 4,
            CmpHit::U64(_) => 8,
        }
    }

    /// The operand value.
    pub const fn value(&self) -> u64 {
        match self {
            CmpHit::U8(v) => *v as u64,
            CmpHit::U16(v) => *v as u64,
            CmpHit::U32(v) => *v as u64,
            CmpHit::U64(v) => *v,
        }
    }

    /// Little-endian byte pattern of the operand, zero-padded to 8 bytes.
    pub const fn to_le_bytes(&self) -> [u8; 8] {
        let v = self.value().to_le_bytes();
        match self.width() {
            1 => [v[0], 0, 0, 0, 0, 0, 0, 0],
            2 => [v[0], v[1], 0, 0, 0, 0, 0, 0],
            4 => [v[0], v[1], v[2], v[3], 0, 0, 0, 0],
            _ => v,
        }
    }
}

/// Immutable inputs to a mutation. Everything here is either a `&` reference
/// to immutable data or the per-mutation RNG derived from the coordinate.
pub struct MutationInput<'a> {
    /// The parent bytes being mutated.
    pub parent: &'a [u8],
    /// The coordinate-derived random stream (mutable, per-mutation).
    pub rng: &'a mut CounterRng,
    /// Dictionary entries (empty for no dictionary).
    pub dictionary: &'a [&'a [u8]],
    /// Compare-operand observations (empty for no cmp guidance).
    pub cmp_hits: &'a [CmpHit],
    /// Optional splice partner input.
    pub splice_partner: Option<&'a [u8]>,
    /// Optional influence mask over `parent` (same length; nonzero byte =
    /// mutable). `None` means every byte is mutable.
    pub influence: Option<&'a [u8]>,
}

/// Result of one mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationOutput {
    /// The mutated bytes.
    pub bytes: Vec<u8>,
    /// True if the output differs from the parent (the worker skips no-op
    /// mutations without executing the target).
    pub changed: bool,
}

/// Apply one mutator family to the input, deterministically.
pub fn apply(mutator: MutatorId, input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    match mutator {
        MutatorId::BitFlip => bytes::bit_flip(input),
        MutatorId::ByteFlip => bytes::byte_flip(input),
        MutatorId::MultiByteFlips => bytes::multi_byte_flips(input),
        MutatorId::IntegerAddSub => integer::add_sub(input),
        MutatorId::IntegerBoundary => integer::boundary(input),
        MutatorId::InterestingInteger => integer::interesting(input),
        MutatorId::ByteInsert => bytes::byte_insert(input),
        MutatorId::ByteDelete => bytes::byte_delete(input),
        MutatorId::BlockDuplicate => bytes::block_duplicate(input),
        MutatorId::BlockDelete => bytes::block_delete(input),
        MutatorId::BlockOverwrite => bytes::block_overwrite(input),
        MutatorId::Splice => splice::splice(input),
        MutatorId::DictionaryInsert => dictionary::insert(input),
        MutatorId::DictionaryOverwrite => dictionary::overwrite(input),
        MutatorId::CompareOperandSubstitution => cmp::substitute(input),
        MutatorId::InfluenceRegionMutation => influence::region(input),
    }
}

/// Uniform mutator-family selection (equal weight; Phase 1 introduces
/// scheduling weights). Deterministic given the RNG.
pub fn select_mutator(rng: &mut CounterRng) -> MutatorId {
    let idx = rng.gen_index(MutatorId::ALL.len());
    MutatorId::ALL[idx]
}

/// Resolve an influence mask against the parent length.
///
/// Returns `Err` when a mask is present with a length mismatch (a programming
/// error, never silently ignored).
pub(crate) fn check_influence_mask(parent: &[u8], influence: Option<&[u8]>) -> Result<()> {
    if let Some(mask) = influence {
        if mask.len() != parent.len() {
            return Err(Error::Encoding(
                "influence mask length must equal parent length",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutator_id_table_is_stable() {
        // Lock the stable ID table (docs: do not renumber).
        let expect: &[(u16, &str)] = &[
            (1, "bit-flip"),
            (2, "byte-flip"),
            (3, "multi-byte-flips"),
            (4, "integer-add-sub"),
            (5, "integer-boundary"),
            (6, "interesting-integer"),
            (7, "byte-insert"),
            (8, "byte-delete"),
            (9, "block-duplicate"),
            (10, "block-delete"),
            (11, "block-overwrite"),
            (12, "splice"),
            (13, "dictionary-insert"),
            (14, "dictionary-overwrite"),
            (15, "compare-operand-substitution"),
            (16, "influence-region-mutation"),
        ];
        for (id, name) in expect {
            let m = MutatorId::from_id(*id).unwrap();
            assert_eq!(m.id(), *id);
            assert_eq!(m.name(), *name);
        }
        assert_eq!(MutatorId::ALL.len(), expect.len());
        for (i, m) in MutatorId::ALL.iter().enumerate() {
            assert_eq!(m.id(), expect[i].0);
        }
    }

    #[test]
    fn cmp_hit_bytes() {
        assert_eq!(CmpHit::U8(0xAB).to_le_bytes(), [0xAB, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            CmpHit::U16(0xABCD).to_le_bytes(),
            [0xCD, 0xAB, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            CmpHit::U32(0xDEADBEEF).to_le_bytes(),
            [0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]
        );
        assert_eq!(CmpHit::U64(0x0102030405060708).to_le_bytes()[0], 0x08);
        assert_eq!(CmpHit::U32(0).width(), 4);
        assert_eq!(CmpHit::U64(u64::MAX).value(), u64::MAX);
    }

    #[test]
    fn noop_on_empty_input_is_deterministic() {
        // Every mutator must be deterministic on empty input. Mutators that
        // can legitimately grow an empty input (byte-insert, dictionary
        // insert) produce bytes; everything else is a no-op. The invariant
        // under test: no panics, and repeated application is identical.
        for m in MutatorId::ALL {
            let mut rng = CounterRng::from_philox([0, 0, 0, 0], [0, 0]);
            let mut input = MutationInput {
                parent: b"",
                rng: &mut rng,
                dictionary: &[],
                cmp_hits: &[],
                splice_partner: Some(b"partner"),
                influence: Some(b""),
            };
            let out = apply(m, &mut input).unwrap();
            // Deterministic: replaying with a fresh RNG gives the same bytes.
            let mut rng2 = CounterRng::from_philox([0, 0, 0, 0], [0, 0]);
            let mut input2 = MutationInput {
                parent: b"",
                rng: &mut rng2,
                dictionary: &[],
                cmp_hits: &[],
                splice_partner: Some(b"partner"),
                influence: Some(b""),
            };
            let out2 = apply(m, &mut input2).unwrap();
            assert_eq!(out.bytes, out2.bytes, "{} must be deterministic", m.name());
        }
    }
}
