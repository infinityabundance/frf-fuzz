//! Phase-0 IPC batch-overhead measurement.
//!
//! The exploration plane's performance contract (docs/ARCHITECTURE.md §5, §26)
//! says: DO NOT send one candidate per execution over IPC; dispatch WORK
//! ORDERS carrying hundreds/thousands of deterministic mutation coordinates,
//! and let the worker execute locally. This example measures why, using the
//! crate's own framed protocol over a socketpair:
//!
//! * "per-input": K individual WorkOrder frames, each acknowledged (the
//!   naive model);
//! * "batched": ONE WorkOrder frame carrying K mutation coordinates, ONE
//!   WorkResult frame back.
//!
//! Reported: total wall time and ns/execution for K in {1, 10, 100, 1000,
//! 10000}. The batching win is the framing+syscall amortization; a typical
//! target execution costs microseconds, so per-input IPC would dominate.
//!
//! This is a Phase-0 measurement artifact, not a benchmark of the final
//! worker (which also has mutation + coverage costs). Results are recorded in
//! docs/PHASE0_FINDINGS.md.

use frf_fuzz::execute::protocol::{read_frame, write_frame, MsgKind};
use frf_fuzz::mutation::MutationCoordinate;
use std::os::unix::net::UnixStream;
use std::time::Instant;

/// Number of trials per size (measurement noise reduction).
const TRIALS: usize = 5;

fn coord(i: u64) -> MutationCoordinate {
    MutationCoordinate {
        campaign_seed: 0x1234_5678_9ABC_DEF0,
        parent_short_id: [1, 2, 3, 4, 5, 6, 7, 8],
        generation: 1,
        mutator_id: frf_fuzz::mutation::MutatorId::ByteFlip,
        lane_id: 0,
        mutation_index: i,
        probe_params: [0; 4],
    }
}

/// A work-order payload: the batch size followed by K encoded coordinates.
fn work_order_payload(k: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + k * frf_fuzz::mutation::coordinate::COORDINATE_ENCODED_LEN);
    p.extend_from_slice(&(k as u32).to_le_bytes());
    for i in 0..k as u64 {
        p.extend_from_slice(&coord(i).encode());
    }
    p
}

fn run_trial(k: usize, batch: bool) -> std::time::Duration {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let reader = std::thread::spawn(move || {
        // Worker side: echo results back.
        let mut buf = Vec::with_capacity(65536);
        loop {
            buf.clear();
            let frame = match read_frame(&mut b, &mut buf) {
                Ok(f) => f,
                Err(_) => break, // stream closed by the sender
            };
            match frame.kind {
                MsgKind::Shutdown => break,
                MsgKind::WorkOrder => {
                    if batch {
                        // Batched: one result frame for the whole batch.
                        let n = u32::from_le_bytes(frame.payload[..4].try_into().unwrap());
                        let payload = n.to_le_bytes();
                        write_frame(&mut b, MsgKind::WorkResult, &payload).unwrap();
                    } else {
                        // Per-input: one result frame per coordinate.
                        let n = u32::from_le_bytes(frame.payload[..4].try_into().unwrap());
                        for _ in 0..n {
                            let payload = 1u32.to_le_bytes();
                            write_frame(&mut b, MsgKind::WorkResult, &payload).unwrap();
                        }
                    }
                }
                _ => {}
            }
        }
    });

    let start = Instant::now();
    let mut buf = Vec::with_capacity(65536);
    if batch {
        // One WorkOrder + one WorkResult.
        write_frame(&mut a, MsgKind::WorkOrder, &work_order_payload(k)).unwrap();
        buf.clear();
        let _ = read_frame(&mut a, &mut buf).unwrap();
    } else {
        // K WorkOrders + K WorkResults.
        for _ in 0..k {
            write_frame(&mut a, MsgKind::WorkOrder, &work_order_payload(1)).unwrap();
            buf.clear();
            let _ = read_frame(&mut a, &mut buf).unwrap();
        }
    }
    write_frame(&mut a, MsgKind::Shutdown, &[]).unwrap();
    let elapsed = start.elapsed();
    reader.join().unwrap();
    elapsed
}

fn best_of(k: usize, batch: bool) -> std::time::Duration {
    let mut best = std::time::Duration::MAX;
    for _ in 0..TRIALS {
        best = best.min(run_trial(k, batch));
    }
    best
}

fn main() {
    println!(
        "{:>8} | {:>14} | {:>14} | {:>12} | {:>10}",
        "batch k", "per-input (ns/x)", "batched (ns/x)", "speedup", "saved ns/x"
    );
    for k in [1usize, 10, 100, 1_000, 10_000] {
        let per = best_of(k, false).as_nanos() as f64 / k as f64;
        let bat = best_of(k, true).as_nanos() as f64 / k as f64;
        let speedup = per / bat;
        println!(
            "{k:>8} | {per:>14.0} | {bat:>14.0} | {speedup:>11.1}x | {:.0}",
            per - bat
        );
    }
    println!(
        "\nModel: socketpair, framed protocol, 49-byte coordinates; best of {} trials.\n\
         Interpretation: per-input IPC costs ~10^2-10^3 ns/execution of pure framing;\n\
         batching amortizes it toward zero. A typical target execution costs\n\
         microseconds, so per-input IPC would dominate throughput. See\n\
         docs/PHASE0_FINDINGS.md.",
        TRIALS
    );
}
