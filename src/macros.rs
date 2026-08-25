//! The `fuzz_target!` macro — the entire surface a fuzz target author sees.
//!
//! Two forms:
//!
//! ```ignore
//! frf_fuzz::fuzz_target!(|data: &[u8], cx: &mut FuzzContext| {
//!     let _ = mycrate::parse(data);
//!     // optional semantic signals (Phase 2):
//!     // cx.observe_u64(signal::PARSED_ITEMS, n)?;
//! });
//! ```
//!
//! ```ignore
//! frf_fuzz::fuzz_target!(
//!     setup    = || { init_state(); Ok(()) },
//!     reset    = |cx: &mut FuzzContext| { reset_state(); Ok(()) },
//!     execute  = |data: &[u8], cx: &mut FuzzContext| { run(data) },
//!     teardown = || { flush_state(); Ok(()) },
//! );
//! ```
//!
//! The expansion installs the hooks and enters the worker main loop, which
//! speaks the coordinator protocol on stdio and executes candidates in the
//! instrumented measurement window. Only `execute` is required; `setup` /
//! `reset` / `teardown` are optional and may appear in any order. Hooks are
//! plain `fn` pointers (no captures).
//!
//! The macro references the crate as `$crate`, so the expansion works in any
//! crate that depends on `frf-fuzz` with the `target-runtime` feature.

/// The fuzz-target entry point.
#[macro_export]
macro_rules! fuzz_target {
    // ---- hook form: any order, execute required at build time ----
    (@mk setup $e:expr) => { .setup($e) };
    (@mk execute $e:expr) => { .execute($e) };
    (@mk reset $e:expr) => { .reset($e) };
    (@mk teardown $e:expr) => { .teardown($e) };
    ($($hook:ident = $closure:expr),+ $(,)?) => {
        fn main() {
            $crate::target_runtime::target::run(
                $crate::target_runtime::target::HooksBuilder::new()
                    $($crate::fuzz_target!(@mk $hook $closure))*
                    .finish(),
            );
        }
    };
    // ---- simple closure form: sugar for `execute = ...` ----
    // The closure type annotation is the user's own; the body is wrapped so
    // a plain `{ ... }` body (which evaluates to ()) still satisfies the
    // `Result<()>` hook contract. `?` inside the body propagates through the
    // wrapper (the wrapper returns `Result`), and a body that already
    // returns `Ok(())` is harmless.
    (|$data:ident: &[u8], $cx:ident: &mut $ty:ty| $body:expr) => {
        fn main() {
            $crate::target_runtime::target::run(
                $crate::target_runtime::target::HooksBuilder::new()
                    .execute(|$data: &[u8], $cx: &mut $ty| { $body; Ok(()) })
                    .finish(),
            );
        }
    };
}

#[cfg(test)]
mod tests {
    // The macro is compile-tested through `examples/` and the golden demo;
    // here we only verify the builder surface.
    use crate::target_runtime::target::HooksBuilder;

    #[test]
    fn builder_defaults_and_requirements() {
        let b = HooksBuilder::new();
        assert!(std::panic::catch_unwind(|| b.finish()).is_err()); // execute missing
        let hooks = HooksBuilder::new().execute(|_data, _cx| Ok(())).finish();
        assert!(hooks.setup.is_none());
        assert!(hooks.reset.is_none());
        assert!(hooks.teardown.is_none());
    }

    #[test]
    fn duplicate_optional_hook_is_refused() {
        let b = HooksBuilder::new().setup(|| Ok(()));
        assert!(std::panic::catch_unwind(|| b.setup(|| Ok(()))).is_err());
    }
}
