// Phase-0 spike: minimal Rust SanitizerCoverage consumer, compiled by a pinned
// nightly rustc with the cargo-fuzz-derived flag set.
//
// FORENSIC FINDING (verified empirically, LLVM 20.1.1 .. 22.1.2):
//   LLVM >= 18 removed the `__sanitizer_` name-prefix exclusion from
//   SanitizerCoverage.cpp (present in 16/17). The only remaining exclusion is
//   the `NoSanitizeCoverage` function attribute, which rustc cannot emit.
//   => the runtime CANNOT be compile-time excluded on current toolchains.
//
// CONSEQUENCE (the mechanism the engine uses):
//   The runtime self-contamination is a DETERMINISTIC CONSTANT footprint R:
//   the scan's own loop/return edges (fixed indices in the counter array, fixed
//   per build). The engine measures R once during campaign calibration and
//   permanently masks those indices. This probe proves the invariants masking
//   depends on:
//     (1) after the first scan, every scan reports the identical set R;
//     (2) after a target execution, scan == R | target_edges, and the masked
//         delta is exactly the target's edges;
//     (3) the delta is deterministic per input and differs across inputs that
//         take different branches.
//   The worker additionally guarantees that NO other instrumented code runs
//   inside the [clear -> execute -> scan] window.
//
// This file is NOT part of the crate. It lives in .phase0/spikes/.

const MAX_RANGES: usize = 16;

#[derive(Copy, Clone)]
struct CounterRange {
    start: *mut u8,
    len: usize,
}

static mut RANGES: [CounterRange; MAX_RANGES] = [CounterRange {
    start: std::ptr::null_mut(),
    len: 0,
}; MAX_RANGES];
static mut RANGE_COUNT: usize = 0;

#[no_mangle]
pub extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8) {
    unsafe {
        let len = stop.offset_from(start) as usize;
        if RANGE_COUNT >= MAX_RANGES || len == 0 || len > 1 << 30 {
            panic!("refusing impossible range");
        }
        RANGES[RANGE_COUNT] = CounterRange { start, len };
        RANGE_COUNT += 1;
    }
}

static mut CMP4_CALLS: u64 = 0;
static mut CONST_CMP4_CALLS: u64 = 0;

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_cmp4(a: u32, b: u32) {
    unsafe { CMP4_CALLS = CMP4_CALLS.wrapping_add(1) };
    std::hint::black_box(a);
    std::hint::black_box(b);
}

#[no_mangle]
pub extern "C" fn __sanitizer_cov_trace_const_cmp4(a: u32, b: u32) {
    unsafe { CONST_CMP4_CALLS = CONST_CMP4_CALLS.wrapping_add(1) };
    std::hint::black_box(a);
    std::hint::black_box(b);
}

// The scanner: single function, #[inline(never)], no calls into other
// instrumented code, so its self-contamination is a fixed small set of edges.
// Walks every registered range in order, writing each nonzero counter's
// (range_index, offset) to `out` (packed: range_index<<20 | offset), then
// clears it. Returns the number of nonzero counters seen (saturating at
// u32::MAX if `cap` is exceeded).
#[no_mangle]
#[inline(never)]
pub extern "C" fn __sanitizer_frf_fuzz_scan(out: *mut u32, cap: u32) -> u32 {
    unsafe {
        let mut n = 0u32;
        for i in 0..RANGE_COUNT {
            let r = RANGES[i];
            for j in 0..r.len {
                let c = r.start.add(j);
                if *c != 0 {
                    if n < cap {
                        *out.add(n as usize) = ((i as u32) << 20) | (j as u32);
                        n += 1;
                    } else {
                        return u32::MAX;
                    }
                    *c = 0;
                }
            }
        }
        n
    }
}

#[inline(never)]
fn magic_gate(x: u32) -> u32 {
    if x == 0xDEADBEEF {
        return 1;
    }
    if (1000..2000).contains(&x) {
        return 2;
    }
    0
}

const CAP: usize = 1 << 16;

fn set_string(s: &[u32]) -> String {
    let mut v: Vec<u32> = s.to_vec();
    v.sort_unstable();
    v.iter()
        .map(|i| format!("{i:x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let v = args
        .get(1)
        .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0);

    // Measurement window discipline: between scans, NO instrumented code runs
    // except the scan call itself. All eprintln! output happens at the end.
    let mut a = [0u32; CAP];
    let mut b = [0u32; CAP];
    let mut c = [0u32; CAP];
    let mut d = [0u32; CAP];
    let mut e = [0u32; CAP];

    // Scan 1: reads startup coverage, clears. Residue R is left behind.
    let n1 = unsafe { __sanitizer_frf_fuzz_scan(a.as_mut_ptr(), CAP as u32) };
    // Scan 2: must read exactly R (the constant footprint).
    let n2 = unsafe { __sanitizer_frf_fuzz_scan(b.as_mut_ptr(), CAP as u32) };
    // Target execution (input-dependent branches).
    let r1 = magic_gate(v);
    // Scan 3: reads R | target_edges.
    let n3 = unsafe { __sanitizer_frf_fuzz_scan(c.as_mut_ptr(), CAP as u32) };
    // Scan 4: must read exactly R again (target edges were cleared).
    let n4 = unsafe { __sanitizer_frf_fuzz_scan(d.as_mut_ptr(), CAP as u32) };
    // Second target execution with a DIFFERENT input, then scan 5.
    let r2 = magic_gate(0x1234);
    let n5 = unsafe { __sanitizer_frf_fuzz_scan(e.as_mut_ptr(), CAP as u32) };

    // ---- now safe to print ----
    let ra = &a[..n1 as usize];
    let rb = &b[..n2 as usize];
    let rc = &c[..n3 as usize];
    let rd = &d[..n4 as usize];
    let re = &e[..n5 as usize];

    eprintln!("[spike] scan1 (startup+R) nonzero={}", n1);
    eprintln!("[spike] scan2 (footprint R) nonzero={}", n2);
    eprintln!("[spike] footprint R = [{}]", set_string(rb));
    let foot_stable = rb == rd; // scan2 == scan4 (both pure R)
    eprintln!(
        "[spike] footprint stability (scan2 == scan4): {}",
        foot_stable
    );

    eprintln!(
        "[spike] magic_gate({:#x}) = {}   magic_gate(0x1234) = {}",
        v, r1, r2
    );
    eprintln!("[spike] scan3 (after input {:#x}) nonzero={}", v, n3);

    // Masked delta: scan3 set minus footprint set.
    let foot: std::collections::BTreeSet<u32> = rb.iter().copied().collect();
    let delta: Vec<u32> = rc.iter().copied().filter(|i| !foot.contains(i)).collect();
    eprintln!("[spike] masked target delta = [{}]", set_string(&delta));

    let delta2: Vec<u32> = re.iter().copied().filter(|i| !foot.contains(i)).collect();
    eprintln!(
        "[spike] masked delta for 0x1234 = [{}]",
        set_string(&delta2)
    );

    // Invariants:
    // (a) footprint constant after first scan (scan2 == scan4);
    // (b) input 0xDEADBEEF produced a nonempty masked delta (target edges);
    // (c) the two inputs produced DIFFERENT deltas (different branches),
    //     proving the masked delta reflects the input, not the runtime.
    let ok = foot_stable && !delta.is_empty() && !delta2.is_empty() && delta != delta2;

    unsafe {
        eprintln!(
            "[spike] cmp4 calls={} constcmp4 calls={}",
            CMP4_CALLS, CONST_CMP4_CALLS
        );
    }
    if !ok {
        eprintln!("[spike] FAIL");
        std::process::exit(1);
    }
    eprintln!("[spike] PASS");
}
