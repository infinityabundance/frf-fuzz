// Minimal crate with a sancov-instrumentable function, used to verify that
// RUSTFLAGS="-Clto=off" overrides `[profile.release] lto = true`.
#[no_mangle]
pub extern "C" fn frf_fuzz_lto_spike_magic(x: u32) -> u32 {
    if x == 0xDEADBEEF {
        1
    } else {
        0
    }
}

fn main() {
    let r = frf_fuzz_lto_spike_magic(0xDEADBEEF);
    std::process::exit(if r == 1 { 0 } else { 1 });
}
