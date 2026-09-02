//! Phase-5 hot-path benchmark: where does the per-execution time go?
//!
//! Phase 5 (AVX2 hardening) optimizes only MEASURED bottlenecks — no
//! semantics change (I3). This example attributes the worker's fixed
//! per-execution costs and compares the scalar (normative) SIMD kernels
//! against their AVX2 paths.
//!
//! It is a hand-rolled benchmark (the dependency policy forbids criterion):
//! each section runs an operation enough times to be stable and reports
//! ns/op. Timed loops reuse buffers (no per-iteration allocation unless the
//! real path allocates) and re-arm inputs outside the timed section.
//!
//! ```sh
//! cargo run --release --example phase5_bench
//! ```
//!
//! Sizes are grounded in measurement: the golden-demo target registers 3529
//! coverage-counter bytes (1 range; read from its worker HELLO). 64 KiB and
//! 1 MiB bracket real targets whose instrumented binaries (std included)
//! have much larger counter spaces. The compare ring captures at most 256
//! events (104 B each: kind/width + three u64s + u16 + 8 case u64s) per
//! execution (~26 KiB saturated) and converts at most 16 into hits.

use frf_fuzz::mutation::{apply, CounterRng, MutationInput, MutatorId};
use frf_fuzz::target_runtime::cmp::{self, CmpEvent};
use frf_fuzz::target_runtime::signals::{
    deltas, magnitude_bucket, OrderSignalTracker, ResidualSketch, SignalBatchSummary, SignalId,
    SignalVector, MAX_SIGNALS,
};
use std::hint::black_box;
use std::time::Instant;

/// The golden-demo target's measured counter space (from its worker HELLO).
const DEMO_COUNTERS: usize = 3529;
/// Larger real-target counter spaces (std-inclusive instrumented binaries).
const SIZES: [usize; 3] = [DEMO_COUNTERS, 64 * 1024, 1024 * 1024];

/// Time a closure, returning ns/op. `iterations` scales with op cost.
///
/// `black_box(f())` is a deliberate call barrier so the optimizer cannot
/// hoist or fuse the timed calls; the lint allowance exists only because the
/// closures return `()`, which is otherwise a clippy `unit_arg`.
#[allow(clippy::unit_arg)]
fn ns_per(iters: u64, mut f: impl FnMut()) -> f64 {
    for _ in 0..iters / 10 {
        black_box(f());
    }
    let start = Instant::now();
    for _ in 0..iters {
        black_box(f());
    }
    start.elapsed().as_nanos() as f64 / iters as f64
}

fn fmt_ns(n: f64) -> String {
    if n >= 1_000.0 {
        format!("{:9.1} us", n / 1_000.0)
    } else {
        format!("{:9.1} ns ", n)
    }
}

/// The demo scan/clear inner-loop pattern over one contiguous buffer
/// (`range_index` provides the packed high bits). Mirrors sancov's scalar
/// `scan_and_clear` loop exactly; the real function walks a static registry
/// that only exists in an instrumented binary, so the bench reproduces the
/// loop over an owned buffer.
fn pattern_scan_clear(buf: &mut [u8], range_index: u64, out: &mut [u64]) -> u32 {
    let cap = out.len();
    let mut n = 0usize;
    let mut saturated = false;
    for (j, c) in buf.iter_mut().enumerate() {
        if *c != 0 {
            if n < cap {
                out[n] = (range_index << 32) | (j as u64);
                n += 1;
            } else {
                saturated = true;
            }
            *c = 0;
        }
    }
    if saturated {
        u32::MAX
    } else {
        n as u32
    }
}

/// Deterministic pseudo-random positions of `k` nonzero bytes in `buf`.
fn seed_nonzero(buf: &mut [u8], k: usize, salt: u64) -> Vec<usize> {
    let mut positions = Vec::with_capacity(k);
    let mut x = salt.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
    let mut placed = 0usize;
    let mut guard = 0usize;
    while placed < k && guard < buf.len() * 4 + 1024 {
        guard += 1;
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let p = (x as usize) % buf.len();
        if buf[p] == 0 {
            buf[p] = 1 + ((x >> 33) as u8 % 250);
            positions.push(p);
            placed += 1;
        }
    }
    positions
}

/// Opaque event consumer (never inlined): forces the snapshot's copy to
/// actually materialize into `events` instead of being forwarded by the
/// optimizer into direct `RING` reads, which would under-measure the real
/// per-execution cost (the worker's `events_buf` escapes through later reads
/// and `push_discovery`, so the copy is real there).
#[inline(never)]
fn consume_events(events: &[CmpEvent], sink: &mut u64) {
    for e in events {
        *sink = sink.wrapping_add(e.a.wrapping_add(e.b));
    }
}

fn main() {
    println!("frf-fuzz phase-5 hot-path benchmark (release build; ns/op)");
    println!();

    // ---- S1: coverage scan + clear patterns (per execution) ----
    println!("-- S1 coverage scan+clear pattern (scalar baseline; sparse window: 40 edges) --");
    for &size in &SIZES {
        let mut buf = vec![0u8; size];
        let mut out = vec![0u64; 65536];
        let positions = seed_nonzero(&mut buf, 40, 0xC0FFEE + size as u64);
        // Realistic steady state: previous window cleared everything, the
        // target re-set ~40 edges. Re-arm the same 40 positions per
        // iteration (scan+clear consumes them), then scan.
        let scan_ns = ns_per(if size >= 1 << 20 { 20_000 } else { 100_000 }, || {
            for &p in &positions {
                buf[p] = 0x42;
            }
            black_box(pattern_scan_clear(&mut buf, 0, &mut out));
        });
        let clear_ns = ns_per(if size >= 1 << 20 { 20_000 } else { 100_000 }, || {
            for b in buf.iter_mut() {
                *b = 0;
            }
            black_box(buf.len());
        });
        println!(
            "{size:>8} B  scan+clear(sparse) {}   clear-all {}",
            fmt_ns(scan_ns),
            fmt_ns(clear_ns)
        );
    }

    // ---- S2: compare-ring snapshot (per execution, saturated window) ----
    println!();
    println!("-- S2 compare-ring snapshot (saturated 256-event window) --");
    cmp::reset();
    for _ in 0..256 {
        frf_fuzz::target_runtime::sancov::__sanitizer_cov_trace_cmp4(0xABCD_1234, 0xABCD_1235);
    }
    let mut events = [CmpEvent::cmp(frf_fuzz::target_runtime::cmp::CmpKind::Cmp, 4, 0, 0); 256];
    let mut snap_sink = 0u64;
    let snap_ns = ns_per(200_000, || {
        let n = cmp::snapshot(&mut events);
        consume_events(&events[..n], &mut snap_sink);
        black_box(snap_sink);
    });
    println!("snapshot+consume(256, 26 KiB): {}", fmt_ns(snap_ns));

    // ---- S3: signal capture + residual machinery (fixed 64-axis) ----
    println!();
    println!("-- S3 signal capture + residual machinery (fixed 64 axes) --");
    let mut parent = SignalVector::new();
    parent.observe(SignalId(0), 0x20).unwrap();
    let mut child = parent.clone();
    child.observe(SignalId(0), 0x80).unwrap(); // marker-depth drift pattern

    let copy_ns = ns_per(200_000, || {
        let c = black_box(child.clone());
        black_box(c.value(SignalId(0)));
    });
    println!("signal vector clone (520 B):  {}", fmt_ns(copy_ns));

    let (mut d, mut s) = ([0i64; MAX_SIGNALS], ResidualSketch::zeroed());
    let d_ns = ns_per(200_000, || {
        d = deltas(black_box(&parent), black_box(&child));
    });
    println!("deltas (64 axes):             {}", fmt_ns(d_ns));
    let s_ns = ns_per(200_000, || {
        s = ResidualSketch::of(black_box(&parent), black_box(&child));
    });
    println!("ResidualSketch::of (64):      {}", fmt_ns(s_ns));

    // Fresh tracker per fold keeps a steady state (no saturation drift).
    let fold_ns = ns_per(200_000, || {
        let mut t = OrderSignalTracker::new();
        black_box(t.push(black_box(&d), black_box(&s), 4, 3));
    });
    println!("tracker.push (fresh):         {}", fmt_ns(fold_ns));
    let mut summary = SignalBatchSummary::new();
    let sum_ns = ns_per(200_000, || {
        summary.push_deltas(black_box(&child), black_box(&d));
        black_box(summary.touched);
    });
    println!("batch push_deltas:            {}", fmt_ns(sum_ns));
    let mag_ns = ns_per(1_000_000, || {
        black_box(magnitude_bucket(black_box(0x12345)));
    });
    println!("magnitude_bucket:             {}", fmt_ns(mag_ns));

    // ---- S4: deterministic mutation (per execution) ----
    println!();
    println!("-- S4 mutation apply (188 B parent, 16 dict tokens, splice 64 B) --");
    let parent_bytes: Vec<u8> = (0..188u8)
        .map(|i| i.wrapping_mul(31).wrapping_add(7))
        .collect();
    let dict: Vec<Vec<u8>> = (0..16)
        .map(|i| vec![0x42u8, i, 0xBE, 0xEF, i.wrapping_add(1)])
        .collect();
    let dict_refs: Vec<&[u8]> = dict.iter().map(|d| d.as_slice()).collect();
    let partner: &[u8] = &parent_bytes[..64];
    for mutator in [
        MutatorId::BitFlip,
        MutatorId::ByteFlip,
        MutatorId::ByteInsert,
        MutatorId::ByteDelete,
        MutatorId::DictionaryInsert,
        MutatorId::CompareOperandSubstitution,
        MutatorId::Splice,
    ] {
        let m = mutator;
        let mut sink = 0usize;
        let n = ns_per(100_000, || {
            let mut r = CounterRng::from_coordinate_fields(0xC0FFEE, 3, m.id(), 0, 9);
            let mut input = MutationInput {
                parent: &parent_bytes,
                rng: &mut r,
                dictionary: &dict_refs,
                cmp_hits: &[],
                splice_partner: Some(partner),
                influence: None,
            };
            sink = sink.wrapping_add(apply(m, &mut input).unwrap().bytes.len());
            black_box(sink);
        });
        println!("mutator {:>28}: {}", mutator.name(), fmt_ns(n));
    }

    // ---- S5: feature post-processing (per execution) ----
    println!();
    println!("-- S5 feature sort+dedup (30 features) --");
    let mut feats: Vec<u64> = (0..30).map(|i| 0x1_0000_0000u64 + (i as u64) * 7).collect();
    let feat_ns = ns_per(200_000, || {
        feats.sort_unstable();
        feats.dedup();
        black_box(feats.len());
    });
    println!("sort+dedup (30):              {}", fmt_ns(feat_ns));

    // ---- S6: ledger echo (per execution) ----
    println!();
    println!("-- S6 crash-ledger echo (49 B coordinate + 188 B input) --");
    let mut echo = vec![0u8; 188 + 64];
    let echo_ns = ns_per(200_000, || {
        echo[..49].copy_from_slice(&[7u8; 49]);
        echo[64..].copy_from_slice(&parent_bytes);
        black_box(&echo[64]);
    });
    println!("echo write (237 B):           {}", fmt_ns(echo_ns));

    // ---- S6b: per-window timeout arm/disarm (2 real syscalls/exec) ----
    println!();
    println!("-- S6b setitimer arm+disarm pair (per-window timeout discipline) --");
    let itv = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 1000, // armed far ahead; disarmed microseconds later
            tv_usec: 0,
        },
    };
    let zero = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    // glibc does not export setitimer in the libc crate on linux-gnu (the
    // worker declares its own extern; see target_runtime/worker.rs), so the
    // bench mirrors that single-symbol declaration.
    extern "C" {
        fn setitimer(
            which: libc::c_int,
            new_value: *const libc::itimerval,
            old_value: *mut libc::itimerval,
        ) -> libc::c_int;
    }
    let timer_ns = ns_per(100_000, || {
        // SAFETY: valid pointers to stack locals; the timer is disarmed a
        // few microseconds after arming with a 1000 s deadline, so it can
        // never fire inside the loop.
        unsafe {
            setitimer(libc::ITIMER_REAL, &itv, std::ptr::null_mut());
            setitimer(libc::ITIMER_REAL, &zero, std::ptr::null_mut());
        }
    });
    println!("setitimer pair (2 syscalls):  {}", fmt_ns(timer_ns));

    // ---- S7: simd kernels: scalar (normative) vs AVX2 dispatch ----
    println!();
    println!("-- S7 simd kernel dispatch (scalar fallback == AVX2 semantics) --");
    let avx2 = std::arch::is_x86_feature_detected!("avx2");
    println!("avx2 available: {avx2}");
    for &size in &SIZES {
        let mut a = vec![0u8; size];
        let _positions = seed_nonzero(&mut a, size / 64, 0x5EED + size as u64); // ~1.5% set
        let mut scratch = vec![0u32; size];
        let mut zeros = vec![0u8; size];
        let cnt_ns = ns_per(100_000, || {
            black_box(frf_fuzz::simd::count_nonzero(black_box(&a)));
        });
        let nz_ns = ns_per(100_000, || {
            let n = frf_fuzz::simd::nonzero_indices(&a, &mut scratch);
            black_box(n);
        });
        // clear steady-state: repeated zeroing of an already-zero buffer is
        // exactly what clear_all does per window (the range is written every
        // time, whether or not edges fired).
        let clear_ns = ns_per(100_000, || {
            frf_fuzz::simd::clear(&mut zeros);
            black_box(zeros.len());
        });
        println!(
            "{size:>8} B  count_nonzero {}  nonzero_indices {}  clear(steady) {}",
            fmt_ns(cnt_ns),
            fmt_ns(nz_ns),
            fmt_ns(clear_ns)
        );
    }

    // ---- S8: the per-window coverage consume: scalar vs AVX2 dispatch ----
    println!();
    println!("-- S8 scan_nonzero_clear (the per-window coverage consume) --");
    for &size in &SIZES {
        // Sparse window (~40 edges), the realistic steady state. The consume
        // clears only the armed bytes, so each iteration re-arms them in
        // place (no per-iteration allocation or full copy).
        let mut sparse = vec![0u8; size];
        let pos = seed_nonzero(&mut sparse, 40, 0xF00D + size as u64);
        let cap = size + 1;
        let mut bs = sparse.clone();
        let mut bv = sparse.clone();
        let mut out_s = vec![0u64; cap];
        let mut out_v = vec![0u64; cap];
        // Scalar reference.
        let scalar_ns = ns_per(if size >= 1 << 20 { 10_000 } else { 60_000 }, || {
            for &p in &pos {
                bs[p] = 0x42;
            }
            black_box(frf_fuzz::simd::scalar::scan_nonzero_clear(
                &mut bs, 0, &mut out_s,
            ));
        });
        // Dispatched (AVX2 when available, scalar otherwise).
        let disp_ns = ns_per(if size >= 1 << 20 { 10_000 } else { 60_000 }, || {
            for &p in &pos {
                bv[p] = 0x42;
            }
            black_box(frf_fuzz::simd::scan_nonzero_clear(&mut bv, 0, &mut out_v));
        });
        println!(
            "{size:>8} B  sparse-scan scalar {}  dispatched {}",
            fmt_ns(scalar_ns),
            fmt_ns(disp_ns)
        );
        // Adversarial: every byte nonzero (worst case for chunk skipping).
        // The per-iteration fill re-arms the consume; this is an upper bound
        // that includes the memset.
        let mut dense = vec![0u8; size];
        let dense_ns = ns_per(10_000, || {
            dense.fill(0x7F);
            black_box(frf_fuzz::simd::scan_nonzero_clear(
                &mut dense, 0, &mut out_v,
            ));
        });
        println!(
            "{size:>8} B  dense-scan dispatched     {}",
            fmt_ns(dense_ns)
        );
    }

    println!();
    println!("Interpretation (demo-size 3529-B counter space):");
    println!("  the per-window coverage consume (S8) was the dominant fixed item:");
    println!("  scalar ~880 ns -> AVX2-dispatched ~60 ns. cmp snapshot (S2, two-");
    println!("  segment contiguous copy) ~185 ns with a real materialized copy.");
    println!("  The worker ALSO no longer heap-copies the event window per");
    println!("  execution (was a ~26 KiB alloc+copy; events now stay in the fixed");
    println!("  buffer and are wired only on discovery push). Everything else");
    println!("  (S3 residual machinery ~170 ns total, S4 mutations 25-55 ns,");
    println!("  S5 12 ns, S6 2 ns, S6b timeout pair 127 ns) is scalar, sub-100 ns,");
    println!("  and either per-byte decision work or saturating 64-bit arithmetic");
    println!("  with no AVX2 64-bit saturating-sub instruction: not vectorizable at");
    println!("  these sizes without risk. Fixed worker floor ~600 ns vs the 15-25 us");
    println!("  target+IPC+coordinator budget; Phase 5 stops here by measurement.");
}
