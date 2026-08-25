//! Worker crash recovery without per-execution IPC
//! (docs/ARCHITECTURE.md §7, docs/INVARIANTS.md I2).
//!
//! Proves the full loop: spawn a worker process that commits its current
//! MutationCoordinate to the shared crash ledger and then dies (SIGABRT via
//! `abort()`, or panic under panic=abort); the coordinator-side reader
//! reconstructs the EXACT coordinate; the worker restarts cleanly.
//!
//! Requires the `coordinator` feature (the CLI binary is
//! `required-features = ["coordinator"]`).

#![cfg(feature = "coordinator")]

use frf_fuzz::execute::crash_ledger::CrashLedgerReader;
use frf_fuzz::mutation::{MutationCoordinate, MutatorId};
use std::path::PathBuf;
use std::process::Command;

fn coord(seed: u64, index: u64, mutator: MutatorId) -> MutationCoordinate {
    MutationCoordinate {
        campaign_seed: seed,
        parent_short_id: [9, 8, 7, 6, 5, 4, 3, 2],
        generation: 1,
        mutator_id: mutator,
        lane_id: 2,
        mutation_index: index,
        probe_params: [0; 4],
    }
}

fn ledger_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("frf-fuzz-crash-recovery-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    let _ = std::fs::remove_file(&p);
    p
}

fn spawn_worker(
    ledger: &std::path::Path,
    c: &MutationCoordinate,
    kind: &str,
) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_frf-fuzz"))
        .args([
            "__phase0",
            "worker-crash-probe",
            ledger.to_str().unwrap(),
            &c.to_hex(),
            "--crash-kind",
            kind,
        ])
        .spawn()
        .expect("spawn worker-crash-probe")
}

#[test]
fn abort_crash_is_reconstructed_exactly() {
    let ledger = ledger_path("abort.ledger");
    let expected = coord(0xAB, 77, MutatorId::BitFlip);

    let mut child = spawn_worker(&ledger, &expected, "abort");
    let status = child.wait().unwrap();
    assert!(!status.success(), "worker must die on abort()");

    // Coordinator side: read the ledger and reconstruct the exact candidate.
    let reader = CrashLedgerReader::open(&ledger).unwrap();
    let got = reader.latest().unwrap().expect("ledger must have a commit");
    assert_eq!(
        got, expected,
        "crash coordinate must be reconstructed exactly"
    );
}

#[test]
fn panic_crash_is_reconstructed_exactly() {
    let ledger = ledger_path("panic.ledger");
    let expected = coord(0xCD, 9, MutatorId::ByteFlip);

    let mut child = spawn_worker(&ledger, &expected, "panic");
    let status = child.wait().unwrap();
    assert!(!status.success(), "worker must die on panic (panic=abort)");

    let reader = CrashLedgerReader::open(&ledger).unwrap();
    let got = reader.latest().unwrap().expect("ledger must have a commit");
    assert_eq!(got, expected);
}

#[test]
fn worker_restarts_and_commits_again() {
    // After a crash, a fresh worker must start cleanly on the same ledger
    // (the ping-pong slots never confuse a new worker).
    let ledger = ledger_path("restart.ledger");
    let first = coord(1, 1, MutatorId::ByteDelete);

    // Crash once.
    let status = spawn_worker(&ledger, &first, "abort").wait().unwrap();
    assert!(!status.success());
    let reader = CrashLedgerReader::open(&ledger).unwrap();
    assert_eq!(reader.latest().unwrap(), Some(first));

    // Restart: a healthy worker commits a new coordinate and exits 0.
    let second = coord(2, 2, MutatorId::BlockOverwrite);
    let status = Command::new(env!("CARGO_BIN_EXE_frf-fuzz"))
        .args([
            "__phase0",
            "worker-ok",
            ledger.to_str().unwrap(),
            &second.to_hex(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "restarted worker must exit cleanly");
    let reader = CrashLedgerReader::open(&ledger).unwrap();
    assert_eq!(reader.latest().unwrap(), Some(second));
}

#[test]
fn ledger_on_unstarted_worker_is_empty() {
    let ledger = ledger_path("unstarted.ledger");
    let _ = std::fs::remove_file(&ledger);
    // A worker that dies before its first execution leaves no commit. The
    // worker sleeps 500ms BEFORE committing; we kill it after 50ms, so it
    // cannot have committed.
    let mut child = Command::new(env!("CARGO_BIN_EXE_frf-fuzz"))
        .args([
            "__phase0",
            "worker-crash-probe",
            ledger.to_str().unwrap(),
            &coord(0, 0, MutatorId::BitFlip).to_hex(),
            "--crash-kind",
            "abort",
            "--delay-ms",
            "500",
        ])
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    let _ = child.kill();
    let status = child.wait().unwrap();
    assert!(!status.success());
    // The worker never committed, so the ledger has no valid slot.
    if ledger.exists() {
        let reader = CrashLedgerReader::open(&ledger).unwrap();
        assert_eq!(reader.latest().unwrap(), None);
    }
}
