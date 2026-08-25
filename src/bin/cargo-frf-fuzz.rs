//! The `cargo frf-fuzz` subcommand adapter.
//!
//! Cargo invokes `cargo-frf-fuzz frf-fuzz <args...>` for `cargo frf-fuzz
//! <args...>`; this binary strips the `frf-fuzz` token and forwards the
//! rest to the SAME library implementation as `bin/frf-fuzz.rs`
//! (`frf_fuzz::cli::run`). There is no duplicated command logic
//! (docs/ARCHITECTURE.md §18).
//!
//! The adapter also normalizes cargo's working-directory behavior: cargo
//! subcommands run in the workspace root, which is exactly where the
//! `.frf-fuzz/` store lives.

fn main() {
    // argv[0] = "cargo-frf-fuzz", argv[1] = "frf-fuzz", argv[2..] = the real args.
    let mut args: Vec<String> = std::env::args().skip(2).collect();
    if args.is_empty() {
        args.push("help".to_string());
    }
    let code = frf_fuzz::cli::run(&args);
    std::process::exit(code);
}
