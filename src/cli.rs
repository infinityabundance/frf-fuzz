//! Command-line surface (coordinator feature).
//!
//! Phase 0 ships `doctor` (toolchain verification, §2 of the master prompt)
//! plus two hidden test seams used by the integration tests. The full
//! init/add/build/run/replay/tmin/cmin/inspect/report/fsck surface arrives in
//! Phase 1.
//!
//! Everything is implemented here in the library; the `bin/frf-fuzz.rs`
//! binary is a thin argv adapter and `bin/cargo-frf-fuzz.rs` (Phase 1) will
//! be a thin cargo-subcommand adapter to the same code — no duplicated
//! command logic.

use crate::error::Result;
use crate::mutation::MutationCoordinate;
use crate::scheduler::WorkOrder;
use crate::{
    DEFAULT_PINNED_NIGHTLY, MSRV, PINNED_NIGHTLY_COMMIT, PINNED_NIGHTLY_LLVM, PINNED_NIGHTLY_RUSTC,
};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The instrumented-build flag set, derived from current cargo-fuzz practice
/// and verified empirically in Phase 0 (docs/COMPATIBILITY.md). `-Cpasses=
/// sancov-module` is the post-LLVM-20 pass name; the old `sancov` name is
/// dead. `-Clto=off` is forced because fat LTO + sancov + ASan produces
/// linker failures (verified; the known cargo-fuzz #384 hazard class).
///
/// `-Copt-level=3` matches cargo-fuzz's fuzz profile (dev-profile opt-level
/// 0 makes the scan/clear loops execute tens of thousands of trace-cmp
/// callbacks per execution); debug-assertions and overflow-checks stay ON
/// per the master prompt's fuzz-target profile.
pub const INSTRUMENT_FLAGS: &[&str] = &[
    "-Cpasses=sancov-module",
    "-Cllvm-args=-sanitizer-coverage-level=4",
    "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
    "-Cllvm-args=-sanitizer-coverage-pc-table",
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
    "-Copt-level=3",
    "-Cdebug-assertions=yes",
    "-Coverflow-checks=yes",
    "-Clto=off",
];

/// Run the CLI; returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let Some(sub) = args.first() else {
        print_usage();
        return 2;
    };
    match sub.as_str() {
        "version" => {
            println!("frf-fuzz {}", env!("CARGO_PKG_VERSION"));
            println!("MSRV (coordinator): {}", MSRV);
            println!("default pinned nightly: {}", DEFAULT_PINNED_NIGHTLY);
            0
        }
        "init" => finish("init", cmd_init(&args[1..])),
        "add" => finish("add", cmd_add(&args[1..])),
        "build" => finish("build", cmd_build(&args[1..])),
        "run" => finish("run", cmd_run(&args[1..])),
        "replay" => finish("replay", cmd_replay(&args[1..])),
        "tmin" => finish("tmin", cmd_tmin(&args[1..])),
        "cmin" => finish("cmin", cmd_cmin(&args[1..])),
        "boundary" => finish("boundary", cmd_boundary(&args[1..])),
        "inspect" => finish("inspect", cmd_inspect(&args[1..])),
        "report" => finish("report", cmd_report(&args[1..])),
        "fsck" => finish("fsck", cmd_fsck(&args[1..])),
        "doctor" => match doctor(&args[1..]) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("frf-fuzz doctor: {e}");
                1
            }
        },
        "__phase0" => run_phase0_seams(&args[1..]),
        "help" | "--help" | "-h" => {
            print_usage();
            0
        }
        _ => {
            eprintln!("frf-fuzz: unknown subcommand `{sub}`");
            print_usage();
            2
        }
    }
}

/// Run a command and map the error to an exit code.
fn finish(cmd: &str, r: crate::error::Result<i32>) -> i32 {
    match r {
        Ok(code) => code,
        Err(e) => {
            eprintln!("frf-fuzz {cmd}: {e}");
            1
        }
    }
}

fn print_usage() {
    println!(
        "frf-fuzz {} — heterogeneous residual-guided fuzzing engine\n\
         \n\
         USAGE:\n\
         \x20 frf-fuzz init [--root <path>]\n\
         \x20 frf-fuzz add <name> [--root <path>] [--force]\n\
         \x20 frf-fuzz build <name> [--nightly <tc>] [--sanitizer none|address]\n\
         \x20 frf-fuzz run <name> [--workers N] [--batch-size N] [--seed <dir>]\n\
         \x20                 [--max-time <secs>] [--max-execs N] [--sanitizer none|address]\n\
         \x20                 [--nightly <tc>] [--memory-limit-mb N] [--root <path>] [--rebuild]\n\
         \x20                 [--residual on|off] [--explore-weight N] [--amplify-weight N]\n\
         \x20 frf-fuzz replay <finding-id> [--root <path>] [--target <name>]\n\
         \x20 frf-fuzz tmin <finding-id> [--root <path>] [--target <name>] [--max-verify N]\n\
         \x20 frf-fuzz cmin <name> [--root <path>]\n\
         \x20 frf-fuzz boundary <finding-id> [--root <path>] [--target <name>] [--max-verify N]\n\
         \x20 frf-fuzz inspect <id> [--root <path>]\n\
         \x20 frf-fuzz report [--root <path>] [--json]\n\
         \x20 frf-fuzz fsck [--root <path>]\n\
         \x20 frf-fuzz doctor [--json] [--nightly <toolchain>] [--root <path>]\n\
         \x20 frf-fuzz version\n\
         \n\
         Hidden Phase-0 seams: __phase0 mutation-digest <coord-hex>,\n\
         __phase0 worker-crash-probe <ledger> <coord-hex> [--crash-kind abort|panic]\n\
         __phase0 worker-ok <ledger> <coord-hex>",
        env!("CARGO_PKG_VERSION")
    );
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

/// A single doctor check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// The check passed.
    Ok,
    /// The check passed with a caveat (does not fail the build).
    Warn,
    /// The check failed.
    Fail,
}

impl CheckStatus {
    fn as_str(self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
        }
    }
}

/// One check: name, status, detail.
#[derive(Debug, Clone)]
pub struct Check {
    /// The check name.
    pub name: &'static str,
    /// The check status.
    pub status: CheckStatus,
    /// Human-readable detail.
    pub detail: String,
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Check {
        Check {
            name,
            status: CheckStatus::Ok,
            detail: detail.into(),
        }
    }
    fn warn(name: &'static str, detail: impl Into<String>) -> Check {
        Check {
            name,
            status: CheckStatus::Warn,
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Check {
        Check {
            name,
            status: CheckStatus::Fail,
            detail: detail.into(),
        }
    }
}

/// Doctor result: ordered checks plus the overall verdict.
pub struct DoctorReport {
    /// The ordered checks.
    pub checks: Vec<Check>,
}

impl DoctorReport {
    /// Overall status: fail if any Fail, else warn if any Warn, else ok.
    pub fn verdict(&self) -> CheckStatus {
        if self.checks.iter().any(|c| c.status == CheckStatus::Fail) {
            CheckStatus::Fail
        } else if self.checks.iter().any(|c| c.status == CheckStatus::Warn) {
            CheckStatus::Warn
        } else {
            CheckStatus::Ok
        }
    }

    /// Human-readable report.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for c in &self.checks {
            out.push_str(&format!(
                "[{:4}] {:<28} {}\n",
                c.status.as_str(),
                c.name,
                c.detail
            ));
        }
        out.push_str(&format!("\nverdict: {}\n", self.verdict().as_str()));
        out
    }

    /// Minimal structured JSON (no serde dependency; the shape is a flat,
    /// documented array).
    pub fn render_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\"frf-fuzz\":\"doctor\",\"version\":\"");
        out.push_str(env!("CARGO_PKG_VERSION"));
        out.push_str("\",\"checks\":[");
        for (i, c) in self.checks.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":\"");
            out.push_str(c.name);
            out.push_str("\",\"status\":\"");
            out.push_str(c.status.as_str());
            out.push_str("\",\"detail\":\"");
            out.push_str(&json_escape(&c.detail));
            out.push_str("\"}");
        }
        out.push_str("],\"verdict\":\"");
        out.push_str(self.verdict().as_str());
        out.push_str("\"}");
        out
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn doctor(args: &[String]) -> Result<i32> {
    let mut json = false;
    let mut nightly = DEFAULT_PINNED_NIGHTLY.to_string();
    let mut root = PathBuf::from(".frf-fuzz");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--nightly" => {
                i += 1;
                nightly = args.get(i).cloned().unwrap_or_default();
            }
            "--root" => {
                i += 1;
                root = PathBuf::from(args.get(i).cloned().unwrap_or_default());
            }
            other => {
                eprintln!("frf-fuzz doctor: unknown option `{other}`");
                return Ok(2);
            }
        }
        i += 1;
    }

    let report = run_doctor(&nightly, &root)?;
    if json {
        println!("{}", report.render_json());
    } else {
        print!("{}", report.render());
    }
    Ok(match report.verdict() {
        CheckStatus::Ok => 0,
        CheckStatus::Warn => 0,
        CheckStatus::Fail => 1,
    })
}

fn run_doctor(nightly: &str, root: &Path) -> Result<DoctorReport> {
    let mut checks = Vec::new();

    // ---- 1. stable rustc ----
    match rustc_version(&["-vV"]) {
        Ok(info) => {
            let release = info.get("release").cloned().unwrap_or_default();
            let ok = version_at_least(&release, MSRV);
            checks.push(if ok {
                Check::ok("stable rustc", format!("{release} (>= {MSRV} required)"))
            } else {
                Check::fail("stable rustc", format!("{release} < {MSRV} required"))
            });
        }
        Err(e) => checks.push(Check::fail("stable rustc", format!("unavailable: {e}"))),
    }

    // ---- 2. requested nightly ----
    let nightly_info = match rustc_version(&[&format!("+{nightly}"), "-vV"]) {
        Ok(info) => Some(info),
        Err(e) => {
            checks.push(Check::fail(
                "requested nightly",
                format!("`{nightly}` unavailable: {e}"),
            ));
            None
        }
    };
    if let Some(info) = &nightly_info {
        let release = info.get("release").cloned().unwrap_or_default();
        let commit = info.get("commit-hash").cloned().unwrap_or_default();
        let llvm = info.get("llvm_version").cloned().unwrap_or_default();
        // The pinned identity is recorded as the full `rustc -vV` first line
        // ("rustc <release> (<short-commit> <date>)"). The `release:` line
        // in -vV carries the FULL commit hash, so compare the release
        // prefix (before the parenthesis) and the commit via the
        // `commit-hash` key.
        let pinned_release = PINNED_NIGHTLY_RUSTC
            .strip_prefix("rustc ")
            .unwrap_or(PINNED_NIGHTLY_RUSTC);
        fn release_prefix(s: &str) -> &str {
            s.split('(').next().unwrap_or(s).trim()
        }
        let pinned = release_prefix(&release) == release_prefix(pinned_release)
            && commit == PINNED_NIGHTLY_COMMIT;
        checks.push(Check::ok(
            "requested nightly",
            format!("{release} ({commit}) — LLVM {llvm}"),
        ));
        checks.push(if pinned {
            Check::ok(
                "nightly identity",
                format!("matches the pinned Phase-0 identity ({PINNED_NIGHTLY_LLVM})"),
            )
        } else {
            Check::warn(
                "nightly identity",
                format!(
                    "differs from pinned (expected {PINNED_NIGHTLY_RUSTC} / {PINNED_NIGHTLY_COMMIT}); \
                     campaign metadata will record the actual identity"
                ),
            )
        });
        checks.push(if llvm_ge_20(&llvm) {
            Check::ok(
                "LLVM compatibility",
                format!("LLVM {llvm} >= 20 (sancov-module pass name supported)"),
            )
        } else {
            Check::fail(
                "LLVM compatibility",
                format!("LLVM {llvm} < 20: the `sancov` pass name is dead; `sancov-module` requires LLVM >= 20"),
            )
        });
    }

    // ---- 3. sanitizer availability (compile probe) ----
    if nightly_info.is_some() {
        match sanitizer_probe(nightly) {
            Ok(()) => checks.push(Check::ok(
                "sanitizer + sancov probe",
                "compiled a minimal instrumented binary with ASan + sancov-module",
            )),
            Err(e) => checks.push(Check::fail("sanitizer + sancov probe", e)),
        }
    } else {
        checks.push(Check::fail(
            "sanitizer + sancov probe",
            "skipped (nightly unavailable)",
        ));
    }

    // ---- 4. target architecture ----
    checks.push(Check::ok(
        "target architecture",
        format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
    ));

    // ---- 5. AVX2 ----
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            checks.push(Check::ok("AVX2", "available (acceleration enabled)"));
        } else {
            checks.push(Check::warn(
                "AVX2",
                "not available (scalar path only; semantics unchanged)",
            ));
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        checks.push(Check::ok("AVX2", "not applicable (non-x86_64)"));
    }

    // ---- 6. GPU availability (when requested) ----
    let cuda = tool_on_path("nvcc") || tool_on_path("nvidia-smi");
    let rocm = tool_on_path("hipcc") || tool_on_path("rocminfo");
    if cfg!(feature = "cuda") {
        checks.push(if cuda {
            Check::ok("CUDA", "toolchain present")
        } else {
            Check::fail("CUDA", "feature enabled but no CUDA toolchain found")
        });
    } else {
        checks.push(if cuda {
            Check::ok("CUDA", "toolchain present (feature disabled)")
        } else {
            Check::ok("CUDA", "not requested / not detected")
        });
    }
    if cfg!(feature = "rocm") {
        checks.push(if rocm {
            Check::ok("ROCm", "toolchain present")
        } else {
            Check::fail("ROCm", "feature enabled but no ROCm toolchain found")
        });
    } else {
        checks.push(if rocm {
            Check::ok("ROCm", "toolchain present (feature disabled)")
        } else {
            Check::ok("ROCm", "not requested / not detected")
        });
    }

    // ---- 7. FRF dependency compatibility ----
    checks.push(Check::ok(
        "FRF dependency compatibility",
        format!(
            "frf {}, gemel {}, dsfb-debug {} (MSRVs 1.85/1.85/1.75; linked into this binary, so the pin compiles)",
            pinned_dep_version("frf"),
            pinned_dep_version("gemel"),
            pinned_dep_version("dsfb-debug")
        ),
    ));
    // gemel builds bundled SQLite, needing a C compiler.
    if tool_on_path("cc") {
        checks.push(Check::ok("C compiler", "present (gemel bundled sqlite)"));
    } else {
        checks.push(Check::warn(
            "C compiler",
            "`cc` not found: building the coordinator (gemel bundled sqlite) may fail",
        ));
    }

    // ---- 8. Gemel repository presence ----
    match gemel_repo_at(root) {
        RepoCheck::Present(path) => checks.push(Check::ok(
            "gemel repository",
            format!("present at {}", path.display()),
        )),
        RepoCheck::Absent => checks.push(Check::ok("gemel repository", "absent — standalone mode")),
    }

    // ---- 9. target build settings ----
    let features: Vec<&str> = {
        let mut v = Vec::new();
        if cfg!(feature = "coordinator") {
            v.push("coordinator");
        }
        if cfg!(feature = "target-runtime") {
            v.push("target-runtime");
        }
        if cfg!(feature = "database") {
            v.push("database");
        }
        if cfg!(feature = "cuda") {
            v.push("cuda");
        }
        if cfg!(feature = "rocm") {
            v.push("rocm");
        }
        v
    };
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    checks.push(Check::ok(
        "target build settings",
        format!("features: [{}], profile: {profile}", features.join(", ")),
    ));

    // ---- 10. LTO hazards ----
    match find_lto_hazard(root) {
        Some(desc) => checks.push(Check::warn(
            "LTO hazard",
            format!("{desc} — instrumented builds force `-Clto=off` via RUSTFLAGS (verified to override)"),
        )),
        None => checks.push(Check::ok(
            "LTO hazard",
            "no `lto = true` profile found near the store root",
        )),
    }

    // ---- 11. writable store paths ----
    match probe_writable(root) {
        Ok(()) => checks.push(Check::ok(
            "writable store paths",
            format!("{} is writable", root.display()),
        )),
        Err(e) => checks.push(Check::fail("writable store paths", e)),
    }

    Ok(DoctorReport { checks })
}

/// Rustc `-vV` output parsed into key/value lines.
fn rustc_version(prefix_args: &[&str]) -> Result<std::collections::BTreeMap<String, String>> {
    let out = Command::new("rustc")
        .args(prefix_args)
        .output()
        .map_err(|e| crate::error::Error::Toolchain(format!("rustc unavailable: {e}")))?;
    if !out.status.success() {
        return Err(crate::error::Error::Toolchain(
            "rustc -vV failed (toolchain not installed?)".into(),
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            // Normalize keys: "LLVM version" -> "llvm_version".
            map.insert(
                k.trim().to_lowercase().replace(' ', "_"),
                v.trim().to_string(),
            );
        }
    }
    Ok(map)
}

fn version_at_least(version: &str, min: &str) -> bool {
    // version like "1.85.0" or "1.85.0-nightly (hash date)"; min like "1.85".
    let parse = |s: &str| -> Option<(u64, u64, u64)> {
        let mut it = s
            .trim()
            .split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<u64>().ok());
        let major = it.next()??;
        let minor = it.next().unwrap_or(Some(0))?;
        let patch = it.next().unwrap_or(Some(0))?;
        Some((major, minor, patch))
    };
    let (vmaj, vmin, _) = parse(version).unwrap_or((0, 0, 0));
    let (mmaj, mmin, _) = parse(min).unwrap_or((0, 0, 0));
    (vmaj, vmin) >= (mmaj, mmin)
}

fn llvm_ge_20(llvm: &str) -> bool {
    llvm.trim()
        .split('.')
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|major| major >= 20)
        .unwrap_or(false)
}

/// Compile a minimal instrumented binary with the pinned flag set.
fn sanitizer_probe(nightly: &str) -> std::result::Result<(), String> {
    let dir = std::env::temp_dir().join(format!("frf-fuzz-doctor-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let src = dir.join("probe.rs");
    let bin = dir.join("probe");
    std::fs::write(
        &src,
        "fn main() {\n    let x: u32 = std::env::args().count() as u32;\n    if x == 0xDEADBEEF { std::process::exit(1); }\n}\n",
    )
    .map_err(|e| e.to_string())?;
    let mut cmd = Command::new("rustc");
    cmd.arg(format!("+{nightly}"))
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .arg("-Zsanitizer=address")
        .arg("-Cpanic=abort");
    for f in INSTRUMENT_FLAGS {
        cmd.arg(f);
    }
    let out = cmd.output().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&dir);
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first_err = stderr
            .lines()
            .find(|l| l.starts_with("error"))
            .unwrap_or("unknown error");
        Err(format!("compile probe failed: {first_err}"))
    }
}

fn tool_on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .any(|dir| dir.join(tool).is_file() || dir.join(format!("{tool}.exe")).is_file())
        })
        .unwrap_or(false)
}

enum RepoCheck {
    Present(PathBuf),
    Absent,
}

fn gemel_repo_at(root: &Path) -> RepoCheck {
    // Walk up from `root` looking for a `.gemel` directory (gemel's META_DIR).
    let mut dir: &Path = root;
    loop {
        if dir.join(".gemel").is_dir() {
            return RepoCheck::Present(dir.to_path_buf());
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
    RepoCheck::Absent
}

/// Scan for `[profile.*] lto = true` in the nearest Cargo.toml files.
fn find_lto_hazard(root: &Path) -> Option<String> {
    let mut dir: &Path = root;
    loop {
        let toml = dir.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&toml) {
            if lto_profile_in(&text) {
                return Some(format!("{} declares LTO in a profile", toml.display()));
            }
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
    None
}

fn lto_profile_in(toml: &str) -> bool {
    // Crude but safe: any `lto = true` line inside a `[profile.*]` section.
    let mut in_profile = false;
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_profile = t.starts_with("[profile");
            continue;
        }
        if in_profile && t.starts_with("lto") && t.contains("true") {
            return true;
        }
    }
    false
}

fn probe_writable(root: &Path) -> std::result::Result<(), String> {
    std::fs::create_dir_all(root).map_err(|e| format!("cannot create {}: {e}", root.display()))?;
    let probe = root.join(".doctor-write-probe");
    std::fs::write(&probe, b"probe").map_err(|e| e.to_string())?;
    std::fs::remove_file(&probe).map_err(|e| e.to_string())?;
    Ok(())
}

fn pinned_dep_version(dep: &str) -> &'static str {
    // Pinned by `=` in Cargo.toml (docs/DEPENDENCIES.md); the versions are
    // part of the pin record and are verified to compile by the very act of
    // linking this binary.
    match dep {
        "frf" => "0.1.72",
        "gemel" => "0.11.0",
        "dsfb-debug" => "0.1.0",
        _ => "?",
    }
}

// ---------------------------------------------------------------------------
// Phase-0 hidden seams (used by integration tests; not user-facing)
// ---------------------------------------------------------------------------

fn run_phase0_seams(args: &[String]) -> i32 {
    let Some(sub) = args.first() else {
        eprintln!("frf-fuzz __phase0: missing seam name");
        return 2;
    };
    match sub.as_str() {
        // Print the canonical hex of the mutation produced by a coordinate at
        // mutation_index 0..N, hashed with FNV-1a 64. Used by the
        // cross-process determinism test: two independent process runs must
        // print the identical digest.
        "mutation-digest" => {
            let coord_hex = match args.get(1) {
                Some(h) => h,
                None => {
                    eprintln!("frf-fuzz __phase0 mutation-digest <coord-hex>");
                    return 2;
                }
            };
            match mutation_digest(coord_hex) {
                Ok(d) => {
                    println!("{d}");
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        // Worker crash probe: open the ledger, commit the coordinate, then
        // die in the requested way. Proves the coordinator can reconstruct
        // the exact candidate after a worker death.
        "worker-crash-probe" => {
            let ledger = match args.get(1) {
                Some(p) => PathBuf::from(p),
                None => {
                    eprintln!("frf-fuzz __phase0 worker-crash-probe <ledger> <coord-hex> [--crash-kind abort|panic]");
                    return 2;
                }
            };
            let coord_hex = match args.get(2) {
                Some(h) => h,
                None => {
                    eprintln!("frf-fuzz __phase0 worker-crash-probe <ledger> <coord-hex>");
                    return 2;
                }
            };
            let mut crash_kind = "abort";
            let mut delay_ms: u64 = 0;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--crash-kind" => {
                        i += 1;
                        crash_kind = args.get(i).map(|s| s.as_str()).unwrap_or("abort");
                    }
                    "--delay-ms" => {
                        i += 1;
                        delay_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
                    }
                    _ => {}
                }
                i += 1;
            }
            match worker_crash_probe(&ledger, coord_hex, crash_kind, delay_ms) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        // Worker ok probe: commit, then exit 0 (used to prove restart works).
        "worker-ok" => {
            let ledger = match args.get(1) {
                Some(p) => PathBuf::from(p),
                None => {
                    eprintln!("frf-fuzz __phase0 worker-ok <ledger> <coord-hex>");
                    return 2;
                }
            };
            let coord_hex = match args.get(2) {
                Some(h) => h,
                None => {
                    eprintln!("frf-fuzz __phase0 worker-ok <ledger> <coord-hex>");
                    return 2;
                }
            };
            match worker_ok(&ledger, coord_hex) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        other => {
            eprintln!("frf-fuzz __phase0: unknown seam `{other}`");
            2
        }
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = 0xCBF2_9CE4_8422_2325u64;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

fn mutation_digest(coord_hex: &str) -> Result<String> {
    let coord = MutationCoordinate::from_hex(coord_hex)?;
    let parent = b"deterministic parent bytes for the cross-process test";
    let dict: [&[u8]; 2] = [b"MAGIC", b"\x00\x00\x00\x01"];
    let hits = [crate::mutation::CmpHit::U32(0xDEAD_BEEF)];
    let mut digest = fnv1a64(b"frf-fuzz mutation-digest v1");
    for index in 0..16u64 {
        let mut c = coord;
        c.mutation_index = index;
        let mut rng = c.derive_prng();
        let mut input = crate::mutation::MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &dict,
            cmp_hits: &hits,
            splice_partner: Some(parent),
            influence: None,
        };
        let out = crate::mutation::apply(c.mutator_id, &mut input)?;
        // Mix both the index and the mutation bytes into the digest so two
        // identical byte outputs at different indices still differ.
        digest = fnv1a64(&out.bytes) ^ digest.rotate_left(17) ^ index;
    }
    Ok(format!("{digest:016x}"))
}

fn worker_crash_probe(
    ledger: &Path,
    coord_hex: &str,
    crash_kind: &str,
    delay_ms: u64,
) -> Result<i32> {
    let coord = MutationCoordinate::from_hex(coord_hex)?;
    // Optional delay BEFORE committing: lets tests kill the worker while it is
    // still "before its first execution" deterministically.
    if delay_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
    }
    let mut w = crate::execute::crash_ledger::CrashLedgerWriter::open(ledger)?;
    w.commit(&coord);
    // Give the coordinator a moment to observe the committed ledger before
    // we die (the coordinator waits on process exit; this is purely to make
    // the test deterministic under scheduling).
    std::thread::sleep(std::time::Duration::from_millis(50));
    match crash_kind {
        "abort" => std::process::abort(),
        "panic" => panic!("frf-fuzz worker-crash-probe: deliberate panic (panic=abort)"),
        other => {
            eprintln!("unknown crash kind `{other}`");
            Ok(1)
        }
    }
}

fn worker_ok(ledger: &Path, coord_hex: &str) -> Result<i32> {
    let coord = MutationCoordinate::from_hex(coord_hex)?;
    let mut w = crate::execute::crash_ledger::CrashLedgerWriter::open(ledger)?;
    w.commit(&coord);
    std::thread::sleep(std::time::Duration::from_millis(20));
    Ok(0)
}

// ---------------------------------------------------------------------------
// Phase 1: init / add / build / run / replay / tmin / cmin / inspect /
// report / fsck
// ---------------------------------------------------------------------------

/// Common argument helpers.
fn flag_value(args: &[String], name: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == name {
            return iter.next().cloned();
        }
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// The project root: `--root <path>` or the current directory.
fn project_root(args: &[String]) -> PathBuf {
    flag_value(args, "--root")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
}

/// The store root: `<project>/.frf-fuzz`.
fn store_root_of(project: &Path) -> PathBuf {
    project.join(crate::store::DEFAULT_STORE_DIR)
}

fn nightly_from(args: &[String]) -> String {
    flag_value(args, "--nightly").unwrap_or_else(|| DEFAULT_PINNED_NIGHTLY.to_string())
}

fn sanitizer_from(args: &[String]) -> Result<crate::execute::worker_process::SanitizerMode> {
    match flag_value(args, "--sanitizer").as_deref() {
        None | Some("none") => Ok(crate::execute::worker_process::SanitizerMode::None),
        Some("address") => Ok(crate::execute::worker_process::SanitizerMode::Address),
        Some(other) => Err(crate::error::Error::Other(format!(
            "unknown --sanitizer value `{other}` (expected none|address)"
        ))),
    }
}

/// Require that the project has a Cargo manifest.
fn require_cargo_project(root: &Path) -> Result<()> {
    if !root.join("Cargo.toml").is_file() {
        return Err(crate::error::Error::Other(format!(
            "{} is not a Cargo project (no Cargo.toml)",
            root.display()
        )));
    }
    Ok(())
}

/// The instrumented-build flag set for a sanitizer mode.
fn build_flags(sanitizer: crate::execute::worker_process::SanitizerMode) -> String {
    let common: Vec<&str> = INSTRUMENT_FLAGS
        .iter()
        .filter(|f| !f.contains("trace-compares"))
        .copied()
        .collect();
    match sanitizer {
        crate::execute::worker_process::SanitizerMode::None => {
            let mut f = common.join(" ");
            f.push_str(" -Cllvm-args=-sanitizer-coverage-trace-compares");
            f
        }
        crate::execute::worker_process::SanitizerMode::Address => {
            let mut f = "-Zsanitizer=address".to_string();
            f.push(' ');
            f.push_str(&common.join(" "));
            f
        }
    }
}

/// The host triple (e.g. x86_64-unknown-linux-gnu) from `rustc -vV`.
fn host_triple() -> Result<String> {
    let out = Command::new("rustc").arg("-vV").output()?;
    if !out.status.success() {
        return Err(crate::error::Error::Toolchain("rustc -vV failed".into()));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(|h| h.trim().to_string())
        .ok_or_else(|| crate::error::Error::Toolchain("no host line in rustc -vV".into()))
}

/// (rustc release line, LLVM line) for a toolchain.
fn toolchain_identity(nightly: &str) -> Result<(String, String)> {
    let out = Command::new("rustc")
        .arg(format!("+{nightly}"))
        .arg("-vV")
        .output()?;
    if !out.status.success() {
        return Err(crate::error::Error::Toolchain(format!(
            "`{nightly}` unavailable ({})",
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("no stderr")
        )));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let release = s.lines().next().unwrap_or("unknown").to_string();
    let llvm = s
        .lines()
        .find(|l| l.starts_with("LLVM"))
        .unwrap_or("unknown")
        .to_string();
    Ok((release, llvm))
}

/// The instrumented binary path for a target name.
fn target_bin_path(triple: &str, name: &str) -> PathBuf {
    PathBuf::from("target")
        .join(triple)
        .join("debug")
        .join(format!("frf_fuzz_{name}"))
}

/// Resolve the target binary, building it if missing (or `--rebuild`).
/// With `--bin <path>`, the given binary is used directly (no build).
fn resolve_target_bin(name: &str, args: &[String]) -> Result<PathBuf> {
    if let Some(bin) = flag_value(args, "--bin") {
        let p = PathBuf::from(bin);
        if !p.is_file() {
            return Err(crate::error::Error::Other(format!(
                "--bin {} does not exist",
                p.display()
            )));
        }
        return Ok(p);
    }
    let triple = host_triple()?;
    let bin = target_bin_path(&triple, name);
    if bin.is_file() && !has_flag(args, "--rebuild") {
        return Ok(bin);
    }
    let nightly = nightly_from(args);
    let sanitizer = sanitizer_from(args)?;
    build_target(name, &nightly, &triple, sanitizer)?;
    Ok(bin)
}

/// Run the pinned-nightly instrumented build of one target.
fn build_target(
    name: &str,
    nightly: &str,
    triple: &str,
    sanitizer: crate::execute::worker_process::SanitizerMode,
) -> Result<()> {
    require_cargo_project(&std::env::current_dir().unwrap_or_default())?;
    let file = std::env::current_dir()
        .unwrap_or_default()
        .join("src/bin")
        .join(format!("frf_fuzz_{name}.rs"));
    if !file.is_file() {
        return Err(crate::error::Error::Other(format!(
            "target file {} does not exist (run `frf-fuzz add {name}` first)",
            file.display()
        )));
    }
    let flags = build_flags(sanitizer);
    eprintln!("[build] {nightly} --target {triple} --bin frf_fuzz_{name}");
    eprintln!("[build] RUSTFLAGS={flags}");
    // Embed the toolchain identity into the worker binary (env! at compile
    // time) so its Hello records what it was BUILT with, not what rustc
    // happens to be on PATH at runtime.
    let (release, llvm) = toolchain_identity(nightly)?;
    let status = Command::new("cargo")
        .arg(format!("+{nightly}"))
        .arg("rustc")
        .arg("--quiet")
        .arg("--target")
        .arg(triple)
        .arg("--bin")
        .arg(format!("frf_fuzz_{name}"))
        .arg("--")
        .arg("-Cpanic=abort")
        .env("RUSTFLAGS", &flags)
        .env("FRF_FUZZ_RUSTC_IDENTITY", &release)
        .env("FRF_FUZZ_LLVM_IDENTITY", &llvm)
        .status()?;
    if !status.success() {
        return Err(crate::error::Error::Other(format!(
            "instrumented build failed (status {status}) — see the compiler output above"
        )));
    }
    eprintln!(
        "[build] ok: {} ({}, {})",
        target_bin_path(triple, name).display(),
        release,
        llvm
    );
    Ok(())
}

/// `frf-fuzz init`
fn cmd_init(args: &[String]) -> Result<i32> {
    let root = project_root(args);
    require_cargo_project(&root)?;
    let store = store_root_of(&root);
    let _s = crate::store::Store::open(store.clone())?;
    for sub in [
        "corpus",
        "findings",
        "tapes",
        "signatures",
        "precedents",
        "campaigns",
        "checkpoints",
        "refs",
        "tmp",
    ] {
        std::fs::create_dir_all(store.join(sub))?;
    }
    let config_path = store.join("config.toml");
    if !config_path.is_file() {
        std::fs::write(&config_path, INIT_CONFIG)?;
    }
    // Dependency hint: the user's crate must depend on frf-fuzz with the
    // target-runtime feature for generated targets to compile.
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))?;
    if !manifest.contains("frf-fuzz") {
        eprintln!(
            "[init] add this to {} and then `cargo build`:",
            root.join("Cargo.toml").display()
        );
        eprintln!(
            "  [dependencies]\n  frf-fuzz = {{ version = \"0.1\", default-features = false, features = [\"target-runtime\"] }}"
        );
        eprintln!("  (or `frf-fuzz = {{ path = \"<frf-fuzz checkout>\", default-features = false, features = [\"target-runtime\"] }}` for a local checkout)");
    }
    println!("frf-fuzz store initialized at {}", store.display());
    Ok(0)
}

const INIT_CONFIG: &str = "# frf-fuzz store configuration (Phase 2)\n# Defaults shown; a campaign overrides these per invocation.\n\n[campaign]\n# Mutation batches per work order (<= 4096).\n# batch_size = 1000\n# Per-execution watchdog timeout in milliseconds.\n# timeout_ms = 5000\n# Residual-guided admission + EXPLORE/AMPLIFY scheduling (ablation switch).\n# residual = true\n# Weighted round-robin between scheduling classes (EXPLORE, AMPLIFY).\n# explore_weight = 4\n# amplify_weight = 1\n\n[worker]\n# Optional RLIMIT_AS per worker in MiB (0 = no limit). ASan builds need\n# generous limits (shadow memory), so this defaults to off.\n# memory_limit_mb = 0\n";

/// `frf-fuzz add <name>`
fn cmd_add(args: &[String]) -> Result<i32> {
    let name = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| crate::error::Error::Other("usage: frf-fuzz add <name>".into()))?;
    validate_target_name(name)?;
    let root = project_root(args);
    require_cargo_project(&root)?;
    let dir = root.join("src/bin");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("frf_fuzz_{name}.rs"));
    if path.is_file() && !has_flag(args, "--force") {
        return Err(crate::error::Error::Other(format!(
            "{} already exists (use --force to overwrite)",
            path.display()
        )));
    }
    let body = target_template(name);
    std::fs::write(&path, body)?;
    println!("created {}", path.display());
    println!("next: `cargo frf-fuzz build {name}` then `cargo frf-fuzz run {name}`");
    Ok(0)
}

fn validate_target_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || name.starts_with(|c: char| c.is_ascii_digit())
    {
        return Err(crate::error::Error::Other(
            "target name must be 1..=64 [a-zA-Z0-9_] chars and not start with a digit".into(),
        ));
    }
    Ok(())
}

fn target_template(name: &str) -> String {
    format!(
        "//! frf-fuzz target: {name}.\n\
         //!\n\
         //! Build: `cargo frf-fuzz build {name}`   Run: `cargo frf-fuzz run {name}`\n\
         //!\n\
         //! The closure receives the candidate input and a [`FuzzContext`].\n\
         //! Semantic signals (Phase 2) are registered once in `setup` and\n\
         //! observed per execution via `cx.observe_u64`.\n\
         \n\
         use frf_fuzz::target_runtime::{{FuzzContext, SignalId}};\n\
         \n\
         frf_fuzz::fuzz_target!(\n\
         \x20   setup = |cx: &mut FuzzContext| {{\n\
         \x20       // Register the semantic signals this target observes (once).\n\
         \x20       cx.register_signal(SignalId(0), \"parsed_items\", \"count\")?;\n\
         \x20       Ok(())\n\
         \x20   }},\n\
         \x20   execute = |data: &[u8], cx: &mut FuzzContext| {{\n\
         \x20       let _ = data;\n\
         \x20       // TODO: drive the code under test. For example:\n\
         \x20       //   let parsed = mycrate::parse(data)?;\n\
         \x20       //   cx.observe_u64(SignalId(0), parsed.len() as u64)?;\n\
         \x20       Ok(())\n\
         \x20   }},\n\
         );\n"
    )
}

/// `frf-fuzz build <name>`
fn cmd_build(args: &[String]) -> Result<i32> {
    let name = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| crate::error::Error::Other("usage: frf-fuzz build <name>".into()))?;
    validate_target_name(name)?;
    let nightly = nightly_from(args);
    let sanitizer = sanitizer_from(args)?;
    let triple = host_triple()?;
    build_target(name, &nightly, &triple, sanitizer)?;
    Ok(0)
}

/// `frf-fuzz run <name>`
fn cmd_run(args: &[String]) -> Result<i32> {
    let name = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| crate::error::Error::Other("usage: frf-fuzz run <name>".into()))?;
    // With an explicit --bin the name is campaign metadata only; otherwise
    // it must be a valid target identifier (binary name frf_fuzz_<name>).
    if flag_value(args, "--bin").is_none() {
        validate_target_name(name)?;
    }
    let root = project_root(args);
    let store_root = store_root_of(&root);
    let _s = crate::store::Store::open(store_root.clone())?;
    // With an explicit --bin, the store can live in a non-Cargo directory
    // (e.g. a scratch directory for demos).
    if flag_value(args, "--bin").is_none() {
        require_cargo_project(&root)?;
    }

    let bin = resolve_target_bin(name, args)?;
    let nightly = nightly_from(args);
    let sanitizer = sanitizer_from(args)?;
    let (release, llvm) = toolchain_identity(&nightly)?;

    let mut policy = crate::scheduler::policy::SchedulePolicy::default();
    if let Some(w) = flag_value(args, "--workers") {
        policy.workers = w.parse().map_err(|_| {
            crate::error::Error::Other("--workers must be a positive integer".into())
        })?;
    }
    if let Some(b) = flag_value(args, "--batch-size") {
        policy.batch_size = b.parse().map_err(|_| {
            crate::error::Error::Other("--batch-size must be an integer >= 1".into())
        })?;
        if policy.batch_size == 0
            || policy.batch_size > crate::scheduler::work_order::MAX_DISCOVERIES_PER_RESULT as u64
        {
            return Err(crate::error::Error::Other(format!(
                "--batch-size must be in 1..={}",
                crate::scheduler::work_order::MAX_DISCOVERIES_PER_RESULT
            )));
        }
    }
    if let Some(s) = flag_value(args, "--seed") {
        policy.seed = parse_u64(&s, "--seed")?;
    }
    if let Some(r) = flag_value(args, "--residual") {
        policy.residual = match r.as_str() {
            "on" | "1" | "true" => true,
            "off" | "0" | "false" => false,
            other => {
                return Err(crate::error::Error::Other(format!(
                    "--residual must be on|off (got `{other}`)"
                )));
            }
        };
    }
    if let Some(w) = flag_value(args, "--explore-weight") {
        policy.class_weights[0] = parse_u64(&w, "--explore-weight")?;
    }
    if let Some(w) = flag_value(args, "--amplify-weight") {
        policy.class_weights[1] = parse_u64(&w, "--amplify-weight")?;
    }
    let seed_dir = flag_value(args, "--seed-dir").map(PathBuf::from);
    let max_time = flag_value(args, "--max-time").map(|s| {
        let secs: u64 = parse_u64(&s, "--max-time").unwrap_or(0);
        std::time::Duration::from_secs(secs)
    });
    let max_execs = flag_value(args, "--max-execs")
        .map(|s| parse_u64(&s, "--max-execs"))
        .transpose()?;
    let memory_limit_mb = flag_value(args, "--memory-limit-mb")
        .map(|s| parse_u64(&s, "--memory-limit-mb"))
        .transpose()?
        .unwrap_or(0);

    let initial_dictionary = read_user_dictionary(&root, name)?;

    let cfg = crate::execute::coordinator::CampaignConfig {
        target_bin: bin,
        store_root,
        policy,
        sanitizer,
        memory_limit_mb,
        seed_dir,
        target_name: name.clone(),
        max_time,
        max_execs,
        initial_dictionary,
        rustc_release: release,
        llvm_version: llvm,
        instrument_flags: build_flags(sanitizer)
            .split_whitespace()
            .map(|s| s.to_string())
            .collect(),
    };
    crate::execute::coordinator::install_sigint_handler();
    eprintln!("[run] target: {}", cfg.target_bin.display());
    eprintln!(
        "[run] workers: {} batch: {} seed: {:#x} residual: {}",
        cfg.policy.workers, cfg.policy.batch_size, cfg.policy.seed, cfg.policy.residual
    );
    let summary = crate::execute::coordinator::run_campaign(&cfg)?;
    println!(
        "\ncampaign {} ({})",
        summary.campaign_id,
        if summary.graceful {
            "graceful"
        } else {
            "interrupted"
        }
    );
    println!("  executions: {}", summary.executions);
    println!("  corpus entries: {}", summary.corpus_entries);
    println!("  coverage features: {}", summary.features);
    println!("  state features: {}", summary.state_features);
    println!("  morphologies: {}", summary.morphologies);
    println!("  regime episodes (closed): {}", summary.regimes);
    println!("  regime trajectories (open): {}", summary.open_episodes);
    println!("  boundary witnesses: {}", summary.boundaries);
    println!("  run tapes: {}", summary.tapes);
    println!("  amplify orders: {}", summary.amplify_orders);
    println!("  findings: {}", summary.findings);
    println!("  duration: {:.1}s", summary.duration.as_secs_f64());
    Ok(0)
}

fn parse_u64(s: &str, what: &str) -> Result<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .map_err(|_| crate::error::Error::Other(format!("{what} must be an integer")))
    } else {
        t.parse()
            .map_err(|_| crate::error::Error::Other(format!("{what} must be an integer")))
    }
}

/// Read the optional user dictionary for a target: `.frf-fuzz/dict/<name>.dict`
/// (one token per line, whitespace-trimmed, `#` comments).
fn read_user_dictionary(root: &Path, name: &str) -> Result<Vec<Vec<u8>>> {
    let path = store_root_of(root)
        .join("dict")
        .join(format!("{name}.dict"));
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bytes = line.as_bytes().to_vec();
        if !bytes.is_empty() && bytes.len() <= crate::scheduler::work_order::MAX_DICT_ENTRY_LEN {
            out.push(bytes);
        }
    }
    if out.len() > crate::scheduler::work_order::MAX_DICT_ENTRIES {
        out.truncate(crate::scheduler::work_order::MAX_DICT_ENTRIES);
    }
    Ok(out)
}

/// A reusable verification session (spawns a worker on demand, respawns on
/// death). Used by replay/tmin.
struct Session {
    cfg: Box<crate::execute::coordinator::CampaignConfig>,
    worker: Option<crate::execute::worker_process::WorkerHandle>,
    next_seq: u64,
}

impl Session {
    fn new(cfg: crate::execute::coordinator::CampaignConfig) -> Session {
        Session {
            cfg: Box::new(cfg),
            worker: None,
            next_seq: 0,
        }
    }

    /// Verify one input: `Ok((died, signals, features))` where `died` means
    /// the worker DIED executing it (crash or watchdog timeout — both are
    /// "the process does not survive"), and `signals`/`features` are the
    /// recorded observation when it survived (empty when it died).
    fn verify(
        &mut self,
        input: &[u8],
    ) -> Result<(bool, crate::target_runtime::signals::SignalVector, Vec<u64>)> {
        if self.worker.is_none() {
            self.worker = Some(crate::execute::worker_process::WorkerHandle::spawn(
                &self.cfg.target_bin,
                &self.cfg.store_root,
                0,
                &self.cfg.policy,
                self.cfg.sanitizer,
                self.cfg.memory_limit_mb,
            )?);
        }
        let w = self.worker.as_mut().unwrap();
        let seq = self.next_seq;
        self.next_seq += 1;
        let order = override_order_for(&self.cfg.policy, seq, input.to_vec());
        w.send_order(&order)?;
        match w.recv_result() {
            Ok(r) => Ok((false, r.override_signals, r.override_features)),
            Err(_) => {
                // The worker died; drop it (a fresh one is spawned next).
                let mut dead = self.worker.take().unwrap();
                let _ = dead.wait();
                Ok((
                    true,
                    crate::target_runtime::signals::SignalVector::new(),
                    Vec::new(),
                ))
            }
        }
    }
}

/// An override order (same shape the coordinator uses for replay).
fn override_order_for(
    policy: &crate::scheduler::policy::SchedulePolicy,
    seq: u64,
    input: Vec<u8>,
) -> WorkOrder {
    WorkOrder {
        campaign_seed: policy.seed,
        generation: 0,
        mutator_id: crate::mutation::MutatorId::BitFlip.id(),
        lane_id: 0,
        start_index: seq,
        index_count: 1,
        parent: Vec::new(),
        parent_short: [0; 8],
        parent_signals: crate::target_runtime::signals::SignalVector::new(),
        partner: Vec::new(),
        dictionary: Vec::new(),
        new_features: Vec::new(),
        input_override: input,
    }
}

/// Resolve a target name + args to a CampaignConfig (shared by replay/tmin).
fn session_config(
    name: &str,
    args: &[String],
) -> Result<crate::execute::coordinator::CampaignConfig> {
    let root = project_root(args);
    let store_root = store_root_of(&root);
    let _s = crate::store::Store::open(store_root.clone())?;
    let bin = resolve_target_bin(name, args)?;
    let nightly = nightly_from(args);
    let sanitizer = sanitizer_from(args)?;
    let (release, llvm) = toolchain_identity(&nightly)?;
    Ok(crate::execute::coordinator::CampaignConfig {
        target_bin: bin,
        store_root,
        policy: crate::scheduler::policy::SchedulePolicy::default(),
        sanitizer,
        memory_limit_mb: 0,
        seed_dir: None,
        target_name: name.to_string(),
        max_time: None,
        max_execs: None,
        initial_dictionary: Vec::new(),
        rustc_release: release,
        llvm_version: llvm,
        instrument_flags: Vec::new(),
    })
}

/// `frf-fuzz replay <finding-id>`
fn cmd_replay(args: &[String]) -> Result<i32> {
    let id = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| crate::error::Error::Other("usage: frf-fuzz replay <finding-id>".into()))?;
    let root = project_root(args);
    let store_root = store_root_of(&root);
    let store = crate::store::Store::open(store_root.clone())?;
    let id = crate::id::ContentId::from_hex(id)?;
    let payload = store
        .get(&id)?
        .ok_or_else(|| crate::error::Error::Other(format!("no object {id}")))?;
    let (header, _) = crate::canon::unframe(&store.get_raw(&id)?.unwrap())?;
    if header.family != crate::canon::Family::Finding {
        return Err(crate::error::Error::Other(format!(
            "object {id} is {}, not a finding",
            header.family.name()
        )));
    }
    let finding = crate::execute::finding::decode_finding(&payload)?;
    println!(
        "finding {} kind={} replay={} input={}B",
        id,
        finding.kind.name(),
        finding.replay.name(),
        finding.input.len()
    );
    println!("input hex: {}", hex_dump(&finding.input));

    // The replay needs a target to run: reuse the finding's campaign.
    // Phase 1 resolves the target name from `--target <name>` (or the
    // campaign ref, when present).
    let name = flag_value(args, "--target").ok_or_else(|| {
        crate::error::Error::Other(
            "replay needs `--target <name>` to know which instrumented binary to run".into(),
        )
    })?;
    let cfg = session_config(&name, args)?;
    let mut session = Session::new(cfg);
    let (died, _, _) = session.verify(&finding.input)?;
    if died {
        println!("result: REPRODUCED (the worker dies on this input)");
    } else {
        println!("result: NOT REPRODUCED (the input runs to completion)");
    }
    // Persist a new finding revision with the replay status (immutable
    // objects: the original is retained, I10).
    let mut updated = finding.clone();
    updated.replay = if died {
        crate::execute::finding::ReplayStatus::Reproduced
    } else {
        crate::execute::finding::ReplayStatus::NotReproduced
    };
    let payload = crate::execute::finding::encode_finding(&updated)?;
    let new_id = store.put(crate::canon::Family::Finding, &payload)?;
    println!("replay revision: {new_id}");
    Ok(0)
}

/// `frf-fuzz tmin <finding-id>`
fn cmd_tmin(args: &[String]) -> Result<i32> {
    let id = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| crate::error::Error::Other("usage: frf-fuzz tmin <finding-id>".into()))?;
    let root = project_root(args);
    let store_root = store_root_of(&root);
    let store = crate::store::Store::open(store_root.clone())?;
    let id = crate::id::ContentId::from_hex(id)?;
    let payload = store
        .get(&id)?
        .ok_or_else(|| crate::error::Error::Other(format!("no object {id}")))?;
    let finding = crate::execute::finding::decode_finding(&payload)?;
    let name = flag_value(args, "--target").ok_or_else(|| {
        crate::error::Error::Other(
            "tmin needs `--target <name>` to know which instrumented binary to run".into(),
        )
    })?;
    let cfg = session_config(&name, args)?;
    let max_verify: u64 = flag_value(args, "--max-verify")
        .map(|s| parse_u64(&s, "--max-verify"))
        .transpose()?
        .unwrap_or(200_000);

    println!(
        "tmin: minimizing {} ({} bytes) preserving worker death",
        id,
        finding.input.len()
    );
    let mut session = Session::new(cfg);
    let mut verifications = 0u64;
    let mut verify = |input: &[u8]| -> bool {
        if verifications >= max_verify {
            return false;
        }
        verifications += 1;
        session
            .verify(input)
            .map(|(died, _, _)| died)
            .unwrap_or(false)
    };
    let minimized = crate::corpus::minimize::minimize_input(&finding.input, &mut verify);
    println!(
        "tmin: {} -> {} bytes ({} verifications)",
        finding.input.len(),
        minimized.len(),
        verifications
    );
    println!("minimized input hex: {}", hex_dump(&minimized));
    // Persist the minimized input as a new finding revision (kind preserved;
    // replay status unknown until replayed).
    let mut updated = finding.clone();
    updated.input = minimized;
    updated.coordinate = crate::execute::finding::ZERO_COORDINATE;
    updated.replay = crate::execute::finding::ReplayStatus::NotReplayed;
    let payload = crate::execute::finding::encode_finding(&updated)?;
    let new_id = store.put(crate::canon::Family::Finding, &payload)?;
    println!("tmin revision: {new_id} (verify with `frf-fuzz replay {new_id} --target {name}`)");
    Ok(0)
}

/// `frf-fuzz cmin <name>`
fn cmd_cmin(args: &[String]) -> Result<i32> {
    let name = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| crate::error::Error::Other("usage: frf-fuzz cmin <name>".into()))?;
    validate_target_name(name)?;
    let root = project_root(args);
    let store_root = store_root_of(&root);
    let store = crate::store::Store::open(store_root.clone())?;
    let index = crate::corpus::CorpusIndex::rebuild(&store)?;
    if index.is_empty() {
        return Err(crate::error::Error::Other(
            "corpus is empty — run a campaign first".into(),
        ));
    }
    let mut candidates = Vec::new();
    for (id, meta) in index.iter() {
        let input = store.get(id)?.unwrap_or_default();
        candidates.push(crate::corpus::minimize::CminCandidate {
            id: *id,
            features: meta.features.clone(),
            size: input.len(),
        });
    }
    let total_inputs = candidates.len();
    let total_bytes: usize = candidates.iter().map(|c| c.size).sum();
    let chosen = crate::corpus::minimize::minimize_corpus(candidates);
    let chosen_bytes: usize = chosen
        .iter()
        .filter_map(|id| index.meta(id))
        .filter_map(|m| store.get(&m.entry_id).ok().flatten())
        .map(|v| v.len())
        .sum();
    println!(
        "cmin {}: {} entries / {}B -> {} entries / {}B (preserving {} features)",
        name,
        total_inputs,
        total_bytes,
        chosen.len(),
        chosen_bytes,
        index.feature_count()
    );
    // Persist the selection (a disposable index; objects are immutable and
    // never deleted by cmin).
    let dir = store_root.join("corpus");
    std::fs::create_dir_all(&dir)?;
    let selection: Vec<String> = chosen.iter().map(|id| id.to_hex()).collect();
    std::fs::write(dir.join("cmin-selection.txt"), selection.join("\n"))?;
    println!(
        "selection written to {}",
        dir.join("cmin-selection.txt").display()
    );
    Ok(0)
}

/// `frf-fuzz boundary <finding-id>` — two-sided minimization of a
/// counterfactual boundary pair (acceptance item 13).
///
/// Forms (or reuses) the StableCrash pair of a crash finding vs its corpus
/// parent, then deterministically shrinks the byte distance between the two
/// sides while preserving the distinction (left survives, right dies),
/// verifies the result deliberately, and persists the minimized witness +
/// a run tape.
fn cmd_boundary(args: &[String]) -> Result<i32> {
    let id = args.iter().find(|a| !a.starts_with('-')).ok_or_else(|| {
        crate::error::Error::Other("usage: frf-fuzz boundary <finding-id>".into())
    })?;
    let root = project_root(args);
    let store_root = store_root_of(&root);
    let store = crate::store::Store::open(store_root.clone())?;
    let id = crate::id::ContentId::from_hex(id)?;
    let payload = store
        .get(&id)?
        .ok_or_else(|| crate::error::Error::Other(format!("no object {id}")))?;
    let finding = crate::execute::finding::decode_finding(&payload)?;
    let name = flag_value(args, "--target").ok_or_else(|| {
        crate::error::Error::Other(
            "boundary needs `--target <name>` to know which instrumented binary to run".into(),
        )
    })?;
    let cfg = session_config(&name, args)?;

    // The left side: the corpus entry matching the finding's parent short
    // key (a crash finding's parent is the input whose mutation crossed the
    // boundary).
    let index = crate::corpus::CorpusIndex::rebuild(&store)?;
    let left_id = index.entry_by_short(finding.parent_short).ok_or_else(|| {
        crate::error::Error::Other(
            "finding parent is not in the corpus (it was admitted in an earlier campaign?); \
                 pass `--left <corpus-id>` to choose the left side explicitly"
                .into(),
        )
    })?;
    let left_input = store
        .get(&left_id)?
        .ok_or_else(|| crate::error::Error::Other("left corpus entry missing".into()))?;
    let right_input = finding.input.clone();

    println!(
        "boundary: pair {} ({}B, corpus) vs {} ({}B, crash)",
        left_id,
        left_input.len(),
        id,
        right_input.len()
    );
    println!(
        "  relation: stable-crash, distance: {}",
        crate::boundary::minimize::byte_distance(&left_input, &right_input)
    );

    let max_verify: u64 = flag_value(args, "--max-verify")
        .map(|s| parse_u64(&s, "--max-verify"))
        .transpose()?
        .unwrap_or(200_000);
    let mut session = Session::new(cfg);
    let verifications = std::cell::Cell::new(0u64);
    let mut classify = |input: &[u8]| -> crate::error::Result<crate::boundary::minimize::PairSide> {
        if verifications.get() >= max_verify {
            return Err(crate::error::Error::Other(
                "boundary verification budget exhausted".into(),
            ));
        }
        verifications.set(verifications.get() + 1);
        let (died, _, _) = session.verify(input)?;
        Ok(if died {
            crate::boundary::minimize::PairSide::Right
        } else {
            crate::boundary::minimize::PairSide::Left
        })
    };

    // The pair must already be a valid boundary (left survives, right dies).
    if classify(&left_input)? != crate::boundary::minimize::PairSide::Left
        || classify(&right_input)? != crate::boundary::minimize::PairSide::Right
    {
        return Err(crate::error::Error::Other(
            "the pair does not preserve a stable-crash distinction (left must survive, right must die)"
                .into(),
        ));
    }

    let outcome = crate::boundary::minimize::minimize_pair(
        &left_input,
        &right_input,
        max_verify.saturating_sub(verifications.get()),
        &mut classify,
    )?;
    println!(
        "  minimized: distance {} -> {} ({} verifications)",
        outcome.start_distance,
        outcome.end_distance,
        verifications.get()
    );
    println!(
        "  left  ({}B): {}",
        outcome.left.len(),
        hex_dump(&outcome.left)
    );
    println!(
        "  right ({}B): {}",
        outcome.right.len(),
        hex_dump(&outcome.right)
    );

    // Persist the minimized witness + a boundary tape (durable, I10/I12).
    let witness = crate::boundary::witness::BoundaryWitness {
        left: left_id,
        right: id,
        left_input: outcome.left.clone(),
        right_input: outcome.right.clone(),
        relation: crate::boundary::witness::BoundaryRelation::StableCrash,
        distance: outcome.end_distance,
        verification: crate::boundary::witness::WitnessVerification::Verified,
        tape: None,
    };
    let payload = crate::boundary::witness::encode_witness(&witness)?;
    let witness_id = store.put(crate::canon::Family::BoundaryWitness, &payload)?;

    // A boundary tape recording both sides (deterministic replay contract).
    let env = crate::tape::model::environment_digest(
        &name,
        "",
        "",
        crate::execute::worker_process::SanitizerMode::None.wire_mode(),
    );
    let build = crate::tape::model::build_digest(&name, "", "", &[]);
    for (side_input, is_right) in [(&outcome.left, false), (&outcome.right, true)] {
        let tape = crate::tape::model::RunTape {
            build_digest: build,
            environment_digest: env,
            candidate: side_input.clone(),
            coordinate: None,
            scheduler_mode: 0,
            observation: None,
            termination: if is_right {
                crate::tape::model::TerminationStatus::Crash
            } else {
                crate::tape::model::TerminationStatus::Ok
            },
            lineage: None,
            source: crate::tape::model::TapeSource::Boundary,
        };
        let payload = crate::tape::model::encode_tape(&tape)?;
        store.put(crate::canon::Family::RunTape, &payload)?;
    }
    println!("  boundary witness: {witness_id}");
    println!("  next: `frf-fuzz inspect {witness_id}`");
    Ok(0)
}

/// `frf-fuzz inspect <id>`
fn cmd_inspect(args: &[String]) -> Result<i32> {
    let id = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| crate::error::Error::Other("usage: frf-fuzz inspect <id>".into()))?;
    let root = project_root(args);
    let store_root = store_root_of(&root);
    let store = crate::store::Store::open(store_root.clone())?;
    let id = crate::id::ContentId::from_hex(id)?;
    let framed = store
        .get_raw(&id)?
        .ok_or_else(|| crate::error::Error::Other(format!("no object {id}")))?;
    let (header, payload) = crate::canon::unframe(&framed)?;
    println!("id: {}", id.to_hex());
    println!("family: {}", header.family.name());
    println!("framing: v{}.{}", header.major, header.minor);
    println!("payload: {} bytes", payload.len());
    match header.family {
        crate::canon::Family::CorpusEntry => {
            println!("corpus input ({}B): {}", payload.len(), hex_dump(payload));
        }
        crate::canon::Family::Finding => {
            if let Ok(f) = crate::execute::finding::decode_finding(payload) {
                println!("kind: {}", f.kind.name());
                println!("replay: {}", f.replay.name());
                println!("input ({}B): {}", f.input.len(), hex_dump(&f.input));
            }
        }
        crate::canon::Family::CorpusMeta => {
            if let Ok(m) = crate::corpus::entry::decode_meta(payload) {
                println!("entry: {}", m.entry_id);
                println!(
                    "parent: {}",
                    m.parent_id
                        .map(|p| p.to_hex())
                        .unwrap_or_else(|| "(seed)".into())
                );
                println!("generation: {}", m.generation);
                println!("reason: {}", m.reason.name());
                println!(
                    "features ({}): {:?}",
                    m.features.len(),
                    &m.features[..m.features.len().min(16)]
                );
                println!(
                    "signals: touched={:016x} values={:?}",
                    m.signals.touched_mask(),
                    &m.signals.as_slice()[..crate::target_runtime::signals::MAX_SIGNALS.min(8)]
                );
                println!(
                    "mutator: {}",
                    m.mutator_id
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "(seed)".into())
                );
                println!(
                    "morphology: {}",
                    m.morphology_id
                        .map(|x| x.to_hex())
                        .unwrap_or_else(|| "(none)".into())
                );
                println!("admission_seq: {}", m.admission_seq);
            }
        }
        crate::canon::Family::MorphologySignature => {
            if let Ok(sig) = crate::dsfb::morphology::MorphologySignature::decode(payload) {
                let class = crate::dsfb::morphology::classify(&sig);
                println!("class: {}", class.name());
                println!("axis_mask: {:016x}", sig.axis_mask);
                if let Some(axis) = sig.dominant_axis() {
                    println!("dominant_axis: {axis}");
                    println!("  dir: {}", sig.dir(axis as usize));
                    println!("  mag_bin: {}", sig.mag_bin(axis as usize));
                    println!("  slew: {}", sig.slew_bins[axis as usize]);
                    println!("  persistence: {}", sig.persistence[axis as usize]);
                }
                println!("cmp_convergence: {}", sig.cmp_convergence);
                println!("state_change: {}", sig.state_change);
                println!("replay_stability: {}", sig.replay_stability);
                println!("structured_unknown: {}", sig.structured_unknown);
                println!("depth: {}", sig.depth);
            }
        }
        crate::canon::Family::RunTape => {
            if let Ok(t) = crate::tape::model::decode_tape(payload) {
                println!("termination: {}", t.termination.name());
                println!("source: {}", t.source.name());
                println!(
                    "candidate ({}B): {}",
                    t.candidate.len(),
                    hex_dump(&t.candidate)
                );
                println!("coordinate: {:?}", t.coordinate);
                println!(
                    "observation: {}",
                    t.observation
                        .map(|o| format!(
                            "{} features, {:?} signals",
                            o.features.len(),
                            o.signals.touched_mask()
                        ))
                        .unwrap_or_else(|| "(none — window never completed)".into())
                );
                println!(
                    "lineage: {}",
                    t.lineage
                        .map(|l| format!("root {} mutator {}", l.root, l.mutator))
                        .unwrap_or_else(|| "(none)".into())
                );
            }
        }
        crate::canon::Family::BoundaryWitness => {
            if let Ok(w) = crate::boundary::witness::decode_witness(payload) {
                println!("left: {} ({}B)", w.left, w.left_input.len());
                println!("right: {} ({}B)", w.right, w.right_input.len());
                println!("relation: {}", w.relation.name());
                println!("distance: {}", w.distance);
                println!("verification: {}", w.verification.name());
                println!(
                    "tape: {}",
                    w.tape
                        .map(|t| t.to_hex())
                        .unwrap_or_else(|| "(none)".into())
                );
            }
        }
        crate::canon::Family::RegimeEpisode => {
            if let Ok(e) = crate::dsfb::regime::decode_episode(payload) {
                println!("signal: {}", e.signal);
                println!(
                    "state path: stable -> drift -> in-episode (onset {}) -> peak {} -> close {}",
                    e.onset_ordinal, e.peak_ordinal, e.close_ordinal
                );
                println!("peak deviation: {}", e.peak_deviation);
                println!("dwell: {}", e.dwell);
                println!("closed by: {}", e.closed_by.name());
            }
        }
        crate::canon::Family::SignalSchema => {
            if let Ok(s) = crate::observe::signals::decode_signal_schema(payload) {
                println!("registered signals ({}):", s.count);
                for (id, d) in s.iter() {
                    println!("  #{} {} ({})", id.id(), d.name_str(), d.unit_str());
                }
            }
        }
        _ => {
            println!(
                "payload head: {}",
                hex_dump(&payload[..payload.len().min(64)])
            );
        }
    }
    Ok(0)
}

/// `frf-fuzz report`
fn cmd_report(args: &[String]) -> Result<i32> {
    let root = project_root(args);
    let store_root = store_root_of(&root);
    let report = crate::report::generate(&store_root)?;
    if has_flag(args, "--json") {
        println!("{}", crate::report::render_json(&report));
    } else {
        print!("{}", crate::report::render_human(&report));
    }
    Ok(0)
}

/// `frf-fuzz fsck`
fn cmd_fsck(args: &[String]) -> Result<i32> {
    let root = project_root(args);
    let store_root = store_root_of(&root);
    let health = crate::report::store_health(&store_root)?;
    let corpus_errors = crate::report::corpus_link_check(&store_root)?;
    println!("frf-fuzz fsck {}", store_root.display());
    let per_family = health.per_family_counts();
    println!(
        "objects: {} ({} families)",
        health.object_count(),
        per_family.len()
    );
    for (name, count) in &per_family {
        println!("  {name}: {count}");
    }
    let mut failed = false;
    if !health.errors.is_empty() {
        failed = true;
        println!("object errors: {}", health.errors.len());
        for e in &health.errors {
            println!("  ERROR: {e}");
        }
    }
    if !health.dangling_refs.is_empty() {
        failed = true;
        println!("dangling refs: {}", health.dangling_refs.len());
        for r in &health.dangling_refs {
            println!("  ERROR: {r}");
        }
    }
    if !corpus_errors.is_empty() {
        failed = true;
        println!("corpus link errors: {}", corpus_errors.len());
        for e in &corpus_errors {
            println!("  ERROR: {e}");
        }
    }
    if failed {
        eprintln!(
            "fsck: FAILED — see errors above (objects are immutable and are never auto-repaired)"
        );
        Ok(1)
    } else {
        println!("fsck: ok");
        Ok(0)
    }
}

/// Compact hex dump for diagnostics.
fn hex_dump(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let show = &bytes[..bytes.len().min(64)];
    let mut s = String::with_capacity(show.len() * 2);
    for &b in show {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    if bytes.len() > show.len() {
        s.push('…');
    }
    s
}
