# frf-fuzz Threat Model

Status: Phase 0. The attack surface is treated as hostile by default: target
output, corpus files, stored objects, tape files, config files, worker
frames, FRF external evidence, Gemel data, and dictionaries. This document
enumerates the adversarial inputs, the failure modes, and the controls.
Controls marked *(Phase N)* land in that phase.

## 1. Assets

* Integrity of the fuzz loop: no adversarial input may corrupt campaign
  state, mutate the corpus incorrectly, or forge evidence.
* Determinism: adversarial inputs must not be able to break the
  coordinate->mutation->replay contract.
* Boundedness: memory, CPU, disk, and IPC must stay bounded.
* Evidence integrity: promoted findings must be reproducible and their FRF/
  Gemel linkages valid.
* Availability: one bad target execution or one hostile object must not take
  down the coordinator or wedge the workers.

## 2. Adversarial inputs and controls

### 2.1 Target output
The target (fuzzed code) is fully adversarial: it may emit arbitrary bytes,
huge streams, or terminal control sequences.

Controls:
- Target output is never interpreted as prose; the coordinator escapes or
  discards it.
- Stream caps and timeouts at the worker boundary (Phase 1; the FRF side
  already enforces 60s / 16 MiB bounds on its executed sides).
- No shell construction: all subprocess invocation is `Command` + argv.

### 2.2 Corpus and stored objects
Corpus files and store objects are hostile: wrong magic, lying lengths,
checksum mismatches, duplicate IDs with different bytes.

Controls:
- Object framing (`canon.rs`): magic + family + major/minor + bounded length;
  unknown major versions fail closed; lengths checked before allocation.
- Content identity (`id.rs`): BLAKE3-256 over canonical bytes; same ID +
  different bytes is fatal corruption (I13) — never silently resolved.
- Store writes: temp file -> write -> fsync -> atomic rename -> directory
  fsync (Phase 1); indexes are disposable/rebuildable; no authoritative
  SQLite.
- `frf-fuzz fsck` verifies hashes, encodings, ref targets, parent links,
  tape closure, precedent refs, FRF ID formatting/reachability, Gemel link
  validity (Phase 1).

### 2.3 Worker frames
The worker/coordinator protocol is hostile: truncation, hostile lengths,
unknown versions/kinds, bad checksums, frame floods.

Controls (`execute/protocol.rs`):
- 1 MiB frame bound checked before allocation; `u32::MAX` length fields are
  refused without allocation.
- Unknown major versions fail closed; unknown kinds refused.
- CRC-32 validated on every frame.
- Tested: truncation at every byte offset, hostile length, version skew,
  checksum corruption, multi-frame streams.

### 2.4 Config files
Configuration is hostile (Phase 1): malformed TOML, absurd bounds, path
traversal in configured paths.

Controls: strict parsing, bounded numeric fields, refusal on invalid
combinations, no silent fallback that changes semantics.

### 2.5 Crash ledger
The ledger file could be tampered (it lives on shared disk).

Controls:
- Two self-validating slots: magic + CRC cover seq + coordinate; a torn or
  tampered slot is rejected; the newest valid slot wins; both-invalid with
  magic present is reported as damage (never silently empty).
- Residual risk: a torn byte that preserves the CRC ≈ 2⁻³² per torn byte;
  accepted and documented.
- The ledger is per-worker and small (256 bytes); it is never a trusted
  evidence source, only a crash-reconstruction aid — the finding is always
  replayed deliberately before promotion.

### 2.6 FRF external evidence and Gemel data
FRF receipts and Gemel objects are external authoritative data.

Controls:
- FRF IDs and Gemel Gids are opaque; never reinterpreted or rewritten.
- FRF receipt loading goes through the crate's own verified loader
  (`frf::verify::load_receipt_verified`); refuse states are preserved.
- Gemel is read-only during the fuzz loop; boundaries only on promotion.
- Both integrations are optional (I14): failure cannot corrupt standalone
  campaign state.

### 2.7 Dictionaries
Dictionary files (Phase 1) may contain hostile byte sequences.

Controls: bounded entry count and entry length; entries are data, never
interpreted; mutation only copies bytes.

## 3. Robustness limits (accepted and documented)

* **CRC-32 collision**: framing and ledger integrity rely on CRC-32
  (2⁻³² per corrupted byte). Content integrity relies on BLAKE3-256 (no
  practical collision). The ledger is a crash aid, not evidence.
* **8-bit counter wraparound**: an edge executing >= 256 times in one
  execution wraps its inline counter to zero; the scan treats counters as
  presence bits (same practical limitation as libFuzzer). Counter-value
  statistics are a Phase-1 sketch concern.
* **ASan/trace-compares incompatibility**: see `COMPATIBILITY.md`. The
  default instrumented build (no ASan) detects crashes via panic=abort,
  signals, timeouts, and the ledger; memory-safety checking is available in
  the ASan opt-in mode (which disables trace-compares).
* **Switch tables**: the switch callback records a raw pointer into static
  constant data; parsing is deferred until after the execution window. The
  pointer validity contract is LLVM's (case tables are static constants).

## 4. Bounds (current values)

| Quantity | Bound | Where |
|---|---|---|
| frame payload | 1 MiB | `execute/protocol.rs` |
| object payload | 1 GiB | `canon.rs` |
| counter ranges | 64 | `target_runtime/sancov.rs` |
| range length | 1 GiB | `target_runtime/sancov.rs` |
| cmp ring | 16384 events | `target_runtime/cmp.rs` |
| switch cases parsed | 8 | `target_runtime/cmp.rs` |
| signals | 64 | `target_runtime/signals.rs` |
| mutated length | 1 MiB | `mutation/mod.rs` |
| coordinate | 49 bytes fixed | `mutation/coordinate.rs` |
| crash ledger | 256 bytes fixed | `execute/crash_ledger.rs` |

All bounds are checked before allocation; arithmetic on hostile lengths uses
`checked_add`/`checked_mul` where applicable.

## 5. Attack scenarios (worked examples)

1. **Hostile frame length `0xFFFFFFFF`**: refused at the header check before
   any allocation; the connection is torn down; the worker is restarted.
2. **Corpus file with ID X but modified bytes**: content-address check fails;
   `fsck` reports `IdCollision`-class corruption; the object is never loaded.
3. **Target floods stdout with escape sequences**: output is captured with a
   cap, never rendered raw; the finding's output is escaped in reports.
4. **Tape file with truncated tail**: the sidecar hash verification fails on
   load; the tape is refused (never partially interpreted).
5. **Worker dies mid-commit**: the ledger's CRC-last discipline means the
   reader sees either the previous complete commit or an invalid slot; the
   coordinator replays the candidate deliberately before promotion.

## 6. Memory limits (Unix)

Phase 1: workers are spawned with rlimits where practical (address space,
file size, core dumps disabled). FRF's own executed sides already enforce
resource limits via its host/sandbox machinery.
