//! Phase-0 ASan spike: a deliberate heap out-of-bounds write that
//! AddressSanitizer must catch in the instrumented build.
//!
//! This example intentionally contains a memory error. It exists ONLY to
//! prove that `-Zsanitizer=address` catches real faults in the instrumented
//! fuzz-target build. The unsafe block is deliberate and documented; this
//! file is a validation artifact, not part of the engine.
//!
//! The single unsafe write is outside `src/` (examples are separate crates),
//! so it does not affect the crate's unsafe policy or the unsafe audit.

fn main() {
    let mut buf = vec![0u8; 8];
    // SAFETY: this is DELIBERATELY out of bounds (index 8_000_000 on an
    // 8-byte buffer). ASan must report a heap-buffer-overflow and the process
    // must die with a nonzero exit. This line is the entire point of the
    // example.
    unsafe {
        *buf.as_mut_ptr().add(8_000_000) = 0xAA;
    }
    // Never reached when ASan is active.
    println!("no crash (ASan not active?)");
}
