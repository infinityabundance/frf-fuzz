//! Dictionary mutators: insert or overwrite with dictionary entries.

use super::{MutationInput, MutationOutput, MAX_MUTATED_LEN};
use crate::error::Result;

fn noop(parent: &[u8]) -> MutationOutput {
    MutationOutput {
        bytes: parent.to_vec(),
        changed: false,
    }
}

/// Dictionary entry insertion: insert a chosen entry's bytes at a position.
///
/// Deterministic: entry chosen by RNG index first, position second. Missing
/// dictionary is a no-op.
pub fn insert(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    if input.dictionary.is_empty() {
        return Ok(noop(input.parent));
    }
    let entry = input.dictionary[input.rng.gen_index(input.dictionary.len())];
    let len = input.parent.len();
    let p = input.rng.gen_index(len + 1);
    let budget = MAX_MUTATED_LEN.saturating_sub(len);
    let k = entry.len().min(budget);
    let mut out = Vec::with_capacity((len + k).min(MAX_MUTATED_LEN));
    out.extend_from_slice(&input.parent[..p]);
    out.extend_from_slice(&entry[..k]);
    out.extend_from_slice(&input.parent[p..]);
    out.truncate(MAX_MUTATED_LEN);
    Ok(MutationOutput {
        changed: k > 0,
        bytes: out,
    })
}

/// Dictionary entry overwrite: replace `entry.len()` bytes at a position.
pub fn overwrite(input: &mut MutationInput<'_>) -> Result<MutationOutput> {
    if input.dictionary.is_empty() || input.parent.is_empty() {
        return Ok(noop(input.parent));
    }
    let entry = input.dictionary[input.rng.gen_index(input.dictionary.len())];
    let k = entry.len().min(input.parent.len());
    if k == 0 {
        return Ok(noop(input.parent));
    }
    let p = input
        .rng
        .gen_index(input.parent.len().saturating_sub(k).max(1));
    let mut out = input.parent.to_vec();
    out[p..p + k].copy_from_slice(&entry[..k]);
    Ok(MutationOutput {
        changed: true,
        bytes: out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::prng::CounterRng;

    fn dict() -> Vec<&'static [u8]> {
        vec![b"magic", b"\x00\x00\x00\x01", b"fizzbuzz", b"\xff"]
    }

    #[test]
    fn insert_grows_input() {
        let parent = b"prefix-suffix";
        let mut rng = CounterRng::from_philox([9, 0, 0, 0], [0, 0]);
        let d = dict();
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &d,
            cmp_hits: &[],
            splice_partner: None,
            influence: None,
        };
        let out = insert(&mut input).unwrap();
        assert!(out.bytes.len() > parent.len());
        assert!(out.changed);
    }

    #[test]
    fn overwrite_uses_entry_bytes() {
        let parent = b"0123456789abcdef";
        let mut rng = CounterRng::from_philox([9, 1, 0, 0], [0, 0]);
        let d = dict();
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &d,
            cmp_hits: &[],
            splice_partner: None,
            influence: None,
        };
        let out = overwrite(&mut input).unwrap();
        assert_eq!(out.bytes.len(), parent.len());
        assert!(out.changed);
        // Some dictionary entry's bytes must appear in the output (the entry
        // is chosen by the RNG, so check all of them).
        let used = d.iter().any(|entry| {
            let k = entry.len().min(parent.len());
            k > 0 && out.bytes.windows(k).any(|w| w == &entry[..k])
        });
        assert!(used, "no dictionary entry appeared in the output");
    }

    #[test]
    fn empty_dictionary_is_noop() {
        let parent = b"data";
        let mut rng = CounterRng::from_philox([9, 0, 0, 0], [0, 0]);
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &[],
            cmp_hits: &[],
            splice_partner: None,
            influence: None,
        };
        for f in [insert, overwrite] {
            let out = f(&mut input).unwrap();
            assert_eq!(out.bytes, parent);
            assert!(!out.changed);
        }
    }
}
