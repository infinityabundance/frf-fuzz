# FRF Bridge Design (Phase 4)

Verified against `frf 0.1.72` source (`.phase0/forensics/REPORT-frf-0.1.72.md`).
This document fixes the integration contract; **Phase 4 (crate 0.4.0)
implements it in `src/frf_bridge.rs`** — see `docs/ARCHITECTURE.md` §15 for
what shipped.

## Roles

- frf-fuzz discoveries are **hypotheses/findings**, never FRF receipts or
  claims (I4).
- FRF is the epistemic authority: it decides whether a promoted differential
  finding is evidence, and it produces the evidence IDs frf-fuzz retains
  verbatim.
- No configured authority => `FindingVerification::Unverified`. Crashes and
  sanitizer failures remain valid fuzz findings without an authority, but are
  never represented as FRF parity/differential claims.

## Verified call sequence (library, in-process, no subprocess)

```rust
use frf::store::Store;
use frf::commands::{admit, court, receipt, claim, dispose};
use frf::cli::ClosureArg;
use frf::model::CourtManifest;

// 1. Store (filesystem-backed; any writable root; the library has no
//    in-memory mode and no features).
let store = Store::new(root.into());
store.ensure_tree()?;

// 2. Authority: an executable reference/oracle. Returns "{name}-{version}".
//    Requires the file to exist and be executable; admission is once.
let authority_id = admit::run(&store, &authority_path, "ref-cli", "1.8.2",
                              "executable_reference")?;

// 3. Court question: CourtManifest -> YAML -> file (court::run accepts only
//    a manifest PATH). Envelope must declare the current platform
//    ("<arch>-<os>"), observables (exit, stderr, ...), normalizers, and
//    replay_scope: single-run. All paths resolve relative to cwd.
let manifest = CourtManifest { /* court: CourtSpec { id, question, falsifier,
    authority, candidate, fixture, admissibility_envelope { ... } } */ };
let yaml = serde_yaml::to_string(&manifest)?;
std::fs::write(&manifest_path, yaml)?;

// 4. Run the court (executes reference vs candidate with hard bounds:
//    60s timeout, 16 MiB stream caps, rlimits; overflow REFUSES the run and
//    writes ExecutionAttemptRecord evidence). Returns the run id
//    "run-{court}-{64-hex sha256}". Identical re-runs are refused
//    (immutability) unless reuse=true (series mode).
let run_id = court::run(&store, &manifest_path,
                        &court::SeriesOptions::default())?;

// 5. (optional) dispose residuals so the receipt binds the wanted state.
for residual_id in capture_residuals(&store, &run_id)? {
    dispose::run(&store, &residual_id, ClosureArg::Intentional,
                 "reason", None, None, None, None)?;
}

// 6. OpenReceipt — THE evidence ID frf-fuzz retains verbatim.
//    "receipt-{run_id}-{64-hex sha256 of canonical receipt bytes}".
//    Emitted only from VERIFIED evidence.
let receipt_id = receipt::run(&store, &run_id)?;

// 7. (optional) compile a claim from verified receipts (baseline policy).
//    The claim id is a 64-hex content address; `requires` = receipt ids.
claim::run(&store, &[receipt_id.clone()], false,
           frf::model::CLAIM_POLICY_BASELINE, "", &[])?;
```

## Trajectory support

Trajectories are derived from `ExecutionSeries`; create them via
`court::run` with exactly one `SeriesOptions` field set
(`repeat: Some(n)` for n >= 2, `candidate_revisions`, `authority_versions`,
`environment_point`, or `time_point`). Read back with `store::load_trajectory`
/ `load_series`; verify with `frf::verify::verify_trajectory_document`.
Coordinate systems: `repeat_index | candidate_revision | authority_version |
environment | time`.

## Contract details

- **IDs are the identity**: `run-{court}-{sha256}`, `receipt-{run}-{sha256}`,
  residual/claim ids are content addresses. Any rewriting breaks
  verification; frf-fuzz stores them opaque and verbatim.
- Harness bounds (60s / 16 MiB) apply to every executed side: a promoted
  finding must reproduce within those bounds or the run is a recorded
  refusal, not a capture.
- The store is directory-based; frf-fuzz supplies a writable root under
  `.frf-fuzz/` (e.g. `.frf-fuzz/frf-root/`) and treats FRF's store as the
  source of truth for FRF IDs.
- Embedding weight: frf pulls clap + serde_yaml + tar + base64 + sha2 +
  libc unconditionally (no features). That is the documented price of real
  evidence semantics; it stays out of the instrumented target build.

## Refusals

- FRF refusal (run refused, receipt refused, claim blocked) is preserved:
  the finding records `FindingVerification::Failed` with the FRF refusal
  evidence; the finding is never deleted or downgraded silently.
