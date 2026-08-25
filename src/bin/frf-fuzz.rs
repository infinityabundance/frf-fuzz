//! The `frf-fuzz` binary: a thin argv adapter to `frf_fuzz::cli`.
//! No command logic lives here.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(frf_fuzz::cli::run(&args));
}
