# Gemel Bridge Design (Phase 4)

Verified against `gemel 0.11.0` source (`.phase0/forensics/REPORT-gemel-0.11.0.md`).
This document fixes the integration contract; Phase 4 implements it.

## Roles

- Gemel is longitudinal engineering memory. frf-fuzz works perfectly without
  it: no `.gemel` repository => standalone mode (I14).
- With a repo: **read-only during the fuzz loop**; durable boundaries only
  (I5). Never write a Gemel object per execution.
- Gemel IDs (`Gid`) are opaque; never reinterpreted or replaced. frf-fuzz
  internal IDs (BLAKE3) and FRF IDs (SHA-256) are separate namespaces.

## Verified read-only loop API

```rust
use gemel::store::{Repo, REF_HEAD, REF_STATE_HEAD};
use gemel::workflow;

// Absence signal: Repo::find walks up parents; NotARepository => standalone.
let repo = match Repo::find(start_dir) {
    Ok(r) => r,
    Err(gemel::store::Error::NotARepository(_)) => { /* standalone */ }
};

// Reads only (readers never take the writer lock):
let head_state: Option<Gid> = repo.read_ref(REF_STATE_HEAD)?;  // current state
let head_change: Option<Gid> = repo.read_ref(REF_HEAD)?;       // current Change
let pending = workflow::read_pending(&repo)?;                  // active intent
let meta = repo.read_meta()?;                                  // default_producer
let cur_traj = repo.read_ref("refs/trajectories/current")?;    // current trajectory
```

## Verified durable boundary API

**Promoted finding bound to the current state** (one lock-free object publish
+ one journaled ref transaction):

```rust
let producer: Gid = meta["default_producer"].as_str().unwrap().parse()?;
let state_gid = head_state.ok_or(...)?;
let evidence = Object::fields(Family::Evidence, vec![
    Field::new(0x01, Value::Gid(producer)),
    Field::new(0x02, Value::Str("fuzz_result".into())),
    Field::new(0x03, Value::Str(subject.clone())),
    Field::new(0x0D, Value::Record(vec![Field::new(0x01, Value::Str("pass".into()))])),
    Field::new(0x11, Value::Gid(state_gid)),   // evaluated_state binding
    Field::new(0x10, Value::I(now_ms())),
]);
let evidence_id = repo.insert_object(&evidence)?;   // lock-free, dedup, fail-closed collision
let claim = Object::fields(Family::Claim, vec![ /* 0x01 subject, 0x03 predicate,
    0x04 predicate_kind, 0x07 producer, 0x08 evidence links, 0x0E created_at */ ]);
let claim_id = repo.insert_object(&claim)?;
repo.write_refs(&RefTransaction { ops: vec![/* e.g. RefOp::set("refs/names/P<n>", claim_id) */] })?;
```

**Campaign/checkpoint boundary**: prefer `workflow::create_checkpoint(&repo,
&CheckpointOptions { summary, producer })` (publishes a Checkpoint object +
`refs/checkpoints/K<n>`/`current` under one transaction).

**Falsified precedent (negative knowledge)**: `workflow::close_trajectory`
with outcome `"rejected"` (rejected attempts are preserved, never extended),
optionally plus a Residual object for the divergence.

**Enumerate revision states for tape replay** (read-only, at boundary):
`query::log(&repo, usize::MAX)` -> for each entry, `content::state_files` /
`content::materialize_overlay`; or walk the head closure.

## Contract details

- `Repo::find`->`Repo::open` may opportunistically recover an interrupted
  journal (the only read-path write; restores canonical state only).
- `finish_change` snapshots the whole working tree — a boundary-only API,
  never used in the loop.
- gemel builds bundled SQLite (needs a C compiler at build time; the doctor
  checks `cc`).
- No features to strip; the library is safe Rust (no unsafe).
- Writers: lock-free immutable `insert_object` + journaled atomic `write_refs`
  => a crash leaves either the old or the new boundary, never a partial one.

## Refusals

- No head state (empty repo): boundaries that need a state binding are
  refused with a clear error, or the finding is recorded with
  `gemel_binding: None` — never a fabricated Gid.
- Falsified precedents are published as negative knowledge, never deleted.
