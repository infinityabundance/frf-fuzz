# frf-fuzz

Heterogeneous residual-guided fuzzing engine and deterministic endoductive
software-experimentation system. One crate, two planes.

```
Coverage tells us where execution went.
Residual structure tells us how behavior is changing.
Historical residual trajectories tell us where to interrogate next.
FRF determines whether promoted discoveries are evidence.
Gemel remembers what those discoveries meant across software evolution.
```

Status: **Phases 0-3 complete** — a usable, deterministic fuzzer with
coverage + compare guidance AND residual-guided fuzzing: target-defined
semantic signals, mutation residuals, regime episodes (Stable → Drift →
InEpisode → Recovering with deterministic close), inspectable morphology
signatures with a Structured-Unknown discipline, EXPLORE/AMPLIFY
scheduling, counterfactual boundary witnesses with two-sided minimization,
and deterministic run tapes. Phase 3 adds DSFB endoduction: the real
`dsfb-debug` 0.1.0 substrate (structural verdicts and episodes), the
FuzzSemanticBank's fuzz-specific classes, a durable precedent bank with
falsifiable probes, and DISCRIMINATE/FALSIFY scheduling. Persistent
instrumented workers, a content-addressed corpus, crash recovery without
per-execution IPC, and the
`init/add/build/run/replay/tmin/cmin/boundary/inspect/report/fsck/precedent`
surface. See `docs/ROADMAP.md` for the phase plan.

## The idea in one paragraph

Ordinary fuzzers remember inputs that reach new code. frf-fuzz also watches
*how behavior changes* — coverage, compare operands, target-defined signals,
mutation residuals, structural drift/slew/regimes — and when a behavioral
trajectory starts to look like a historically evidence-backed precursor, it
proposes a falsifiable next experiment instead of guessing. FRF (the
Forensic Residual Framework) independently verifies promoted discoveries;
Gemel remembers what they meant across software evolution. It never converts
any of this into probabilistic bug prediction.

## Using it

```sh
cargo install frf-fuzz

cd my-project
# add the dependency (the fuzz target links only the tiny target-runtime):
#   [dependencies]
#   frf-fuzz = { version = "0.4", default-features = false, features = ["target-runtime"] }

cargo frf-fuzz init
cargo frf-fuzz add parser      # creates src/bin/frf_fuzz_parser.rs
cargo frf-fuzz build parser    # pinned-nightly instrumented build
cargo frf-fuzz run parser      # spawns N persistent workers and fuzzes

# residual-guided / endoductive tools:
cargo frf-fuzz run parser --residual off      # coverage-only ablation
cargo frf-fuzz run parser --precedent on --discriminate-weight <w> --falsify-weight <w>
cargo frf-fuzz boundary <finding-id>          # two-sided minimization
cargo frf-fuzz precedent list                 # renders the precedent bank
cargo frf-fuzz precedent show <id>            # detail for one precedent

# FRF verification + Gemel longitudinal memory (Phase 4):
# run a campaign that court-verifies every replay-confirmed crash finding
# against a reference executable and publishes durable Gemel boundaries
# (a .gemel repository must exist for the Gemel side):
cargo frf-fuzz run parser --authority ./reference-cli \
    --authority-name my-ref --authority-version 1.0 \
    --verify-candidate target/debug/frf_fuzz_parser
cargo frf-fuzz verify <finding-id> --authority ./reference-cli --candidate <harness>
cargo frf-fuzz revision replay <finding-id> \
    --state v1=<bin-from-v1> --state v2=<bin-from-v2>   # revision residual
```

A generated target is a normal binary in your existing crate:

```rust
use frf_fuzz::target_runtime::FuzzContext;

frf_fuzz::fuzz_target!(|data: &[u8], cx: &mut FuzzContext| {
    let _ = mycrate::parse(data);
});
```

Optional hooks (`setup` / `reset` / `execute` / `teardown`, any order) are
supported; persistent fuzzing of stateful targets needs an explicit `reset`.

Post-campaign tooling: `cargo frf-fuzz replay <finding-id>`,
`tmin <finding-id>`, `cmin <target>`, `verify <finding-id>`,
`revision replay <id>`, `inspect <id>`, `report [--json]`, `fsck`, `doctor`.

The FRF authority is an executable that honors the case-harness interface
(`--frf-fuzz-fixture <path>` — the instrumented fuzz-target binary itself
does); it models the REFERENCE behavior of the software under test. Without
an authority, findings stay explicitly unverified. Gemel boundaries are
published only when a `.gemel` repository is present.

One-command end-to-end demonstration (build -> fuzz -> compare-guided
magic-gate crash -> replay -> fsck -> tmin -> FRF-verified finding -> Gemel
boundaries -> revision replay):

```sh
sh scripts/golden_demo.sh
```

## Requirements

* Coordinator: stable Rust >= 1.98 (MSRV), a C compiler (gemel's bundled
  sqlite).
* Instrumented fuzz target: the pinned nightly
  (`nightly-2026-07-24`; `rustup toolchain install nightly-2026-07-24`) —
  LLVM SanitizerCoverage and sanitizer flags require nightly. The exact
  nightly identity is verified by `frf-fuzz doctor` and recorded in campaign
  metadata; a mismatched nightly is never silently used.
* x86_64 with AVX2 for the accelerated SIMD path (the scalar path is
  portable and normative).

## Status by phase

| Phase | Content | Status |
|---|---|---|
| 0 | Specification / forensic spikes | **DONE** |
| 1 | Minimum useful fuzzer (init/add/build/run, workers, corpus, crashes, replay, tmin, cmin, inspect, report, fsck) | **DONE** |
| 2 | Residual-guided fuzzing (signals, residuals, regimes, morphology, boundaries, tapes) | **DONE** |
| 3 | DSFB endoduction (FuzzSemanticBank, precedents, probes) | **DONE** |
| 4 | FRF courts (real receipts at promotion) + Gemel durable boundaries + revision tape replay | **DONE** |
| 5-8 | AVX2 hardening, database specialization, GPU, scientific evaluation | planned |

## The two planes

* **Exploration plane** (fast, disposable): coverage + compare + residual
  guided mutation in persistent workers; the `target-runtime` feature.
* **Evidence plane** (deliberate, immutable): promotion, replay, FRF courts,
  Gemel boundaries; the `coordinator` feature.

Only promoted discoveries reach FRF, Gemel, or the full DSFB detector field.
The hot loop stays fast; the memory stays trustworthy.

## Non-claims (the short version)

frf-fuzz does not predict bugs. It recognizes deterministic structural
prefixes and proposes falsifiable experiments. It never emits probabilities,
never forces an unknown structure into a label, never reimplements FRF
semantics, and never writes per-execution Gemel telemetry. See
`docs/NON_CLAIMS.md`.
