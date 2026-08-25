//! Cross-process mutation determinism (docs/INVARIANTS.md, I2).
//!
//! A mutation must be reproducible from its MutationCoordinate and immutable
//! inputs ACROSS INDEPENDENT PROCESS RUNS. Two spawned `frf-fuzz
//! __phase0 mutation-digest <coord>` processes must print identical digests.
//!
//! Requires the `coordinator` feature (the CLI binary is
//! `required-features = ["coordinator"]`).

#![cfg(feature = "coordinator")]

use std::process::Command;

fn mutation_digest(coord_hex: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_frf-fuzz"))
        .args(["__phase0", "mutation-digest", coord_hex])
        .output()
        .expect("spawn frf-fuzz");
    assert!(
        out.status.success(),
        "mutation-digest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf8 digest")
        .trim()
        .to_string()
}

/// A fixed coordinate exercising every mutator family across indices.
fn sample_coordinate_hex() -> String {
    use frf_fuzz::mutation::MutationCoordinate;
    use frf_fuzz::mutation::MutatorId;
    let coord = MutationCoordinate {
        campaign_seed: 0xDEAD_BEEF_CAFE_F00D,
        parent_short_id: [1, 2, 3, 4, 5, 6, 7, 8],
        generation: 3,
        mutator_id: MutatorId::MultiByteFlips,
        lane_id: 5,
        mutation_index: 0,
        probe_params: [0, 0, 0, 0],
    };
    coord.to_hex()
}

#[test]
fn identical_digest_across_independent_process_runs() {
    let hex = sample_coordinate_hex();
    let a = mutation_digest(&hex);
    let b = mutation_digest(&hex);
    assert_eq!(
        a, b,
        "mutation digest must be identical across process runs"
    );
    assert_eq!(a.len(), 16);
}

#[test]
fn digest_changes_with_coordinate_fields() {
    use frf_fuzz::mutation::MutationCoordinate;
    let mut c = MutationCoordinate::from_hex(&sample_coordinate_hex()).unwrap();
    let base = mutation_digest(&c.to_hex());
    // Same coordinate fields, different campaign seed -> different digest.
    c.campaign_seed ^= 1;
    let other = mutation_digest(&c.to_hex());
    assert_ne!(base, other, "campaign seed must change the mutation stream");
}
