//! Single-shot fixture execution (Phase 4: FRF courts + revision harnesses).
//!
//! An instrumented fuzz-target binary doubles as a *case harness*: when
//! invoked as
//!
//! ```text
//! frf_fuzz_<name> --frf-fuzz-fixture <path>
//! ```
//!
//! it reads exactly the file at `<path>` (bounded by the worker input limit)
//! and runs the registered target hooks ONCE over those bytes in a fresh
//! process, exactly like one deliberate replay execution:
//!
//! ```text
//! setup (once) -> context reset -> reset hook -> execute hook -> teardown
//! ```
//!
//! Process exit semantics are the crash contract, deliberately identical to
//! the persistent worker's override path:
//!
//! * `execute` returns `Ok(())` — exit code 0 (the input was accepted);
//! * the process dies (panic=abort, `abort()`, a signal, an ASan finding) —
//!   death by signal, which is exactly how a crash finding reproduces;
//! * the fixture cannot be read or exceeds the input bound — a message on
//!   stderr and exit code 1 (a harness error, never a false "crash").
//!
//! No environment variables are required and none are consulted: FRF
//! executes both sides of a court with an empty environment and the fixture
//! snapshot path in argv, so this mode must be self-contained. It is only
//! entered from `argv[1] == "--frf-fuzz-fixture"`; the persistent worker
//! protocol is untouched (no hot-path impact).
//!
//! This module is part of `target-runtime`; it must stay dependency-free.

use crate::error::Result;
use crate::scheduler::work_order::MAX_INPUT_LEN;
use crate::target_runtime::target::{hooks, TargetHooks};
use crate::target_runtime::FuzzContext;

/// The argv token that selects fixture mode.
pub const FIXTURE_ARG: &str = "--frf-fuzz-fixture";

/// True when `argv` selects fixture mode (`argv[1] == FIXTURE_ARG`).
pub fn is_fixture_invocation() -> bool {
    std::env::args().nth(1).as_deref() == Some(FIXTURE_ARG)
}

/// Run one fixture execution and exit the process (never returns).
///
/// The exit code is 0 when the target accepted the input; a crash (panic=
/// abort, `abort()`, signal, sanitizer finding) propagates as the process
/// death it is — the same death the crash ledger records during fuzzing.
pub fn run_fixture_and_exit() -> ! {
    let code = match run_fixture() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("frf-fuzz fixture: {e}");
            1
        }
    };
    std::process::exit(code);
}

/// Load and run one fixture through the registered hooks.
fn run_fixture() -> Result<()> {
    let h = hooks();
    // argv[0] is the program; argv[1] is FIXTURE_ARG; argv[2] is the path.
    let path = std::env::args()
        .nth(2)
        .ok_or_else(|| crate::error::Error::Other("missing fixture path argument".into()))?;
    let meta = std::fs::metadata(&path)
        .map_err(|e| crate::error::Error::Other(format!("cannot stat fixture {path}: {e}")))?;
    if meta.len() > MAX_INPUT_LEN as u64 {
        return Err(crate::error::Error::BoundExceeded {
            what: "fixture input length",
            limit: MAX_INPUT_LEN as u64,
            got: meta.len(),
        });
    }
    let data = std::fs::read(&path)
        .map_err(|e| crate::error::Error::Other(format!("cannot read fixture {path}: {e}")))?;
    execute_once(h, &data)
}

/// Run the hooks exactly once over `data` (the single-shot execution
/// contract; mirrors the worker's per-execution reset semantics).
fn execute_once(h: &TargetHooks, data: &[u8]) -> Result<()> {
    let mut cx = FuzzContext::new();
    if let Some(setup) = h.setup {
        setup(&mut cx)?;
    }
    cx.reset();
    if let Some(reset) = h.reset {
        reset(&mut cx)?;
    }
    (h.execute)(data, &mut cx)?;
    if let Some(teardown) = h.teardown {
        teardown()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target_runtime::target::{HooksBuilder, TargetHooks};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RUNS: AtomicUsize = AtomicUsize::new(0);
    static RESETS: AtomicUsize = AtomicUsize::new(0);
    static SETUPS: AtomicUsize = AtomicUsize::new(0);
    static TEARDOWNS: AtomicUsize = AtomicUsize::new(0);

    fn counting_hooks() -> TargetHooks {
        HooksBuilder::new()
            .setup(|cx: &mut FuzzContext| {
                SETUPS.fetch_add(1, Ordering::SeqCst);
                let _ = cx;
                Ok(())
            })
            .execute(|data: &[u8], cx: &mut FuzzContext| {
                RUNS.fetch_add(1, Ordering::SeqCst);
                let _ = (data, cx);
                Ok(())
            })
            .reset(|cx: &mut FuzzContext| {
                RESETS.fetch_add(1, Ordering::SeqCst);
                let _ = cx;
                Ok(())
            })
            .teardown(|| {
                TEARDOWNS.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .finish()
    }

    #[test]
    fn fixture_flag_detection() {
        // Can't mutate argv in a unit test; the detection helper is a pure
        // function of argv[1] which we cannot set here. Assert the constant
        // contract instead (the flag string is the wiring contract).
        assert_eq!(FIXTURE_ARG, "--frf-fuzz-fixture");
    }

    #[test]
    fn execute_once_runs_full_hook_sequence() {
        RUNS.store(0, Ordering::SeqCst);
        RESETS.store(0, Ordering::SeqCst);
        SETUPS.store(0, Ordering::SeqCst);
        TEARDOWNS.store(0, Ordering::SeqCst);
        let h = counting_hooks();
        execute_once(&h, b"fixture bytes").unwrap();
        assert_eq!(RUNS.load(Ordering::SeqCst), 1);
        assert_eq!(RESETS.load(Ordering::SeqCst), 1);
        assert_eq!(SETUPS.load(Ordering::SeqCst), 1);
        assert_eq!(TEARDOWNS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn execute_once_propagates_hook_errors() {
        let h = HooksBuilder::new()
            .execute(|_: &[u8], _: &mut FuzzContext| Err(crate::error::Error::Other("boom".into())))
            .finish();
        assert!(execute_once(&h, b"x").is_err());
    }
}
