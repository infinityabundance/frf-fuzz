//! The fuzz-target hook registry and the [`fuzz_target!`](crate::fuzz_target)
//! builder surface.
//!
//! A fuzz target is a normal binary in the user's crate
//! (`src/bin/frf_fuzz_<name>.rs`) whose entire content is one invocation of
//! the `fuzz_target!` macro. The macro builds a [`TargetHooks`] via
//! [`HooksBuilder`] and hands it to [`run`], which installs it and enters
//! the worker main loop ([`super::worker`]).
//!
//! # Hooks
//!
//! * `setup` — once, before the worker loop.
//! * `execute` — required, per execution, with `&[u8]` input and the
//!   [`FuzzContext`].
//! * `reset` — optional, per execution before `execute`; required for
//!   stateful targets (persistent fuzzing needs explicit reset semantics).
//! * `teardown` — once, after the worker loop (on graceful shutdown).
//!
//! A hook error is a target-side programming error: the worker reports it
//! and exits (fail-fast, actionable). The process-level crash path (panic=
//! abort, ASan, signals) is handled by the crash ledger, not by hooks.
//!
//! This module is part of `target-runtime`; it must stay dependency-free.

use crate::error::Result;
use crate::target_runtime::FuzzContext;

/// The type of the target execute hook.
pub type ExecuteFn = fn(&[u8], &mut FuzzContext) -> Result<()>;
/// The type of the optional setup hook: receives the context so the target
/// can register its signal schema (`cx.register_signal(...)`) once, before
/// the loop (Phase 2; strings never flow through the per-execution path).
pub type SetupFn = Option<fn(&mut FuzzContext) -> Result<()>>;
/// The type of the optional teardown hook.
pub type OptionalHook = Option<fn() -> Result<()>>;
/// The type of the optional per-execution reset hook.
pub type ResetFn = Option<fn(&mut FuzzContext) -> Result<()>>;

/// The four target hooks. `execute` is mandatory; the rest are optional.
#[derive(Debug, Clone, Copy)]
pub struct TargetHooks {
    /// Runs once before the worker loop (with the context, so the target
    /// can register its signal schema).
    pub setup: SetupFn,
    /// The per-execution target function.
    pub execute: ExecuteFn,
    /// Optional per-execution state reset (before `execute`).
    pub reset: ResetFn,
    /// Runs once on graceful shutdown.
    pub teardown: OptionalHook,
}

/// Builder for [`TargetHooks`]; the `fuzz_target!` macro expands to method
/// calls on this. Optional hooks may be set at most once (a second `setup`
/// is a macro-level programming error, refused).
#[derive(Debug, Default)]
pub struct HooksBuilder {
    setup: SetupFn,
    execute: Option<ExecuteFn>,
    reset: ResetFn,
    teardown: OptionalHook,
}

impl HooksBuilder {
    /// A fresh builder.
    pub fn new() -> HooksBuilder {
        HooksBuilder::default()
    }

    /// Set the setup hook (once, before the loop). The hook receives the
    /// context so the target can register its signal schema.
    pub fn setup(mut self, f: fn(&mut FuzzContext) -> Result<()>) -> HooksBuilder {
        assert!(self.setup.is_none(), "fuzz_target!: setup registered twice");
        self.setup = Some(f);
        self
    }

    /// Set the required execute hook.
    pub fn execute(mut self, f: fn(&[u8], &mut FuzzContext) -> Result<()>) -> HooksBuilder {
        assert!(
            self.execute.is_none(),
            "fuzz_target!: execute registered twice"
        );
        self.execute = Some(f);
        self
    }

    /// Set the per-execution reset hook.
    pub fn reset(mut self, f: fn(&mut FuzzContext) -> Result<()>) -> HooksBuilder {
        assert!(self.reset.is_none(), "fuzz_target!: reset registered twice");
        self.reset = Some(f);
        self
    }

    /// Set the teardown hook.
    pub fn teardown(mut self, f: fn() -> Result<()>) -> HooksBuilder {
        assert!(
            self.teardown.is_none(),
            "fuzz_target!: teardown registered twice"
        );
        self.teardown = Some(f);
        self
    }

    /// Finish building. Panics with an actionable message when `execute` is
    /// missing (a target without an execute hook is a configuration error).
    pub fn finish(self) -> TargetHooks {
        TargetHooks {
            setup: self.setup,
            execute: self.execute.expect(
                "fuzz_target! requires an `execute` hook: `execute = |data: &[u8], cx: &mut FuzzContext| { .. }`",
            ),
            reset: self.reset,
            teardown: self.teardown,
        }
    }
}

/// The process-global target. Set exactly once by `run` (from the macro
/// expansion) before the worker loop starts; read by the loop. `OnceLock`
/// (std atomics) is fine here: this is startup/loop machinery, never the
/// callback path.
static TARGET: std::sync::OnceLock<TargetHooks> = std::sync::OnceLock::new();

/// Install the hooks and enter the worker loop. Never returns (exits the
/// process with the worker's exit code).
pub fn run(hooks: TargetHooks) -> ! {
    // The macro generates one `run` call per binary; a second install is a
    // build-level mistake (two `fuzz_target!` invocations).
    let _ = TARGET.set(hooks).map_err(|_| {
        eprintln!("frf-fuzz worker: fuzz_target! registered twice (two macros in one binary)");
        std::process::exit(2)
    });
    let code = super::worker::run_main();
    std::process::exit(code);
}

/// The installed hooks (worker loop; panics when not installed — the loop
/// only runs after `run`).
pub fn hooks() -> &'static TargetHooks {
    TARGET
        .get()
        .expect("frf-fuzz worker: no fuzz target installed")
}
