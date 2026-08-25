//! The instrumented worker main loop.
//!
//! The worker IS the fuzz target binary (built with the pinned nightly and
//! the instrumentation flag set; see docs/COMPATIBILITY.md). The
//! coordinator spawns it with a set of environment variables and speaks the
//! bounded binary protocol on stdio ([`crate::execute::protocol`],
//! [`crate::scheduler::work_order`]).
//!
//! # The measurement window (worker invariant, docs/ARCHITECTURE.md §8)
//!
//! ```text
//! ledger.commit(coord)       (crash reconstructability; events discarded
//!                             by the reset below)
//! clear coverage counters
//! reset cmp ring
//! cx.reset()                 (clear the signal vector; NOT execution_ordinal)
//! (reset hook, then execute hook)
//! capture signal vector      (a fixed-size memcpy; constant edges)
//! snapshot cmp ring          (captures exactly the target's events: the
//!                             scan has not run yet — no tail truncation)
//! scan coverage counters     (its own cmp events land after the captured
//!                             range; discarded by the next reset)
//! ```
//!
//! The worker's own edges are a constant footprint, measured once at
//! calibration and permanently masked. The snapshot-before-scan ordering
//! removes the "calibrated cmp tail" problem entirely: the captured range
//! contains only target events.
//!
//! # Phase 2: residual observation
//!
//! Every execution's signal vector is compared against the ORDER's parent
//! signals (sent by the coordinator) into a fixed-size [`ResidualSketch`].
//! A per-order [`OrderSignalTracker`] folds sketches into the
//! persistent-drift rule, and a [`SignalBatchSummary`] aggregates the whole
//! batch. The worker pushes a discovery when an execution is interesting:
//! new local coverage, a newly-touched signal, a persistent same-direction
//! drift, or a large single delta. The coordinator decides admission; the
//! worker never writes anything per execution (I1).
//!
//! # Crash recovery contract
//!
//! The ledger is written BEFORE execution; if the process dies (panic=
//! abort, ASan, signal, watchdog timeout, OOM), the coordinator reads the
//! ledger, reconstructs the exact candidate from the coordinate + the
//! parent bytes it sent, and replays it deliberately.
//!
//! This module is part of `target-runtime`.

#![allow(unsafe_code)]
// Approved unsafe zone: the libc FFI boundary (worker memory limits). The
// only unsafe operation is the `setrlimit` syscall call itself, which is
// async-signal-safe and cannot touch Rust state; see `apply_memory_limit`.

use crate::error::{Error, Result};
use crate::execute::crash_ledger::CrashLedgerWriter;
use crate::execute::protocol::{self, MsgKind};
use crate::mutation::{self, CmpHit, CounterRng, MutationCoordinate, MutationInput, MutatorId};
use crate::scheduler::work_order::{
    self, CmpEventWire, CmpHitWire, DiscoveryRecord, ExecutionStatus, Hello, WorkOrder, WorkResult,
    MAX_CMP_EVENTS_PER_EXEC, MAX_CMP_HITS_PER_EXEC, MAX_DISCOVERIES_PER_RESULT,
};
use crate::target_runtime::cmp::{self, CmpEvent, CmpKind};
use crate::target_runtime::sancov;
use crate::target_runtime::signals::{
    OrderSignalTracker, ResidualSketch, SignalBatchSummary, SignalVector,
};
use crate::target_runtime::target::{self, TargetHooks};
use crate::target_runtime::FuzzContext;
use std::collections::BTreeSet;
use std::io::{BufReader, BufWriter, Write};
use std::process;
use std::time::SystemTime;

/// Environment variables the coordinator sets on every worker.
pub const ENV_LEDGER: &str = "FRF_FUZZ_LEDGER";
/// Worker lane id (u16).
pub const ENV_LANE: &str = "FRF_FUZZ_LANE";
/// Sanitizer mode: "none" (sancov+tracecmp) or "address" (ASan).
pub const ENV_SANITIZER: &str = "FRF_FUZZ_SANITIZER";
/// Per-execution timeout in milliseconds.
pub const ENV_TIMEOUT_MS: &str = "FRF_FUZZ_TIMEOUT_MS";
/// Worker ordinal (diagnostics).
pub const ENV_WORKER_ID: &str = "FRF_FUZZ_WORKER_ID";
/// Optional RLIMIT_AS in MiB (0 = no limit).
pub const ENV_MEMORY_LIMIT_MB: &str = "FRF_FUZZ_MEMORY_LIMIT_MB";

/// Marker for input-override executions in the crash ledger: mutator id 0
/// is unused by the stable table (1..=16), so the coordinator recognizes
/// `(parent_short == [0;8], mutator == 0)` as "override execution whose
/// ordinal is `mutation_index` of the current override session".
pub const OVERRIDE_MARKER_MUTATOR: u16 = 0;

/// Worker-side persistence rule: an execution is "persistently drifting" on
/// a signal when at least this many consecutive same-direction nonzero
/// deltas have accumulated ...
pub const PERSIST_MIN_RUN: u8 = 4;
/// ... AND the cumulative magnitude bucket is at least this (|delta| >= 16).
pub const PERSIST_MIN_CUM_BUCKET: u8 = 4;
/// A single delta at or above this magnitude bucket (|delta| >= 2^15) is
/// treated as a potential boundary crossing and pushed on its own.
pub const LARGE_DELTA_BUCKET: u8 = 16;
/// Byte budget for one encoded work result. The worker stops pushing
/// discoveries when the estimated encoded payload would exceed this, so a
/// discovery flood can never produce a frame that violates the protocol's
/// 1 MiB bound (a Phase-2 finding: unbounded discovery streams killed
/// workers with "frame length exceeds bound" and produced false crash
/// findings). The estimate tracks the dominant per-record fields and stays
/// well below the 1 MiB frame ceiling.
pub const RESULT_BYTE_BUDGET: usize = 700 * 1024;

/// The worker main loop. Returns the process exit code.
pub fn run_main() -> i32 {
    match run_inner() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("frf-fuzz worker: {e}");
            // Report the error to the coordinator if we still can, then
            // fail with a nonzero exit so the coordinator never mistakes
            // a broken worker for a clean shutdown.
            1
        }
    }
}

fn run_inner() -> Result<i32> {
    let hooks = target::hooks();
    let cfg = WorkerConfig::from_env()?;
    if cfg.memory_limit_mb > 0 {
        apply_memory_limit(cfg.memory_limit_mb)?;
    }

    let ledger = CrashLedgerWriter::open(&cfg.ledger_path)?;
    let cx = FuzzContext::new();
    // One-shot SIGALRM timeout: the handler fires only on a genuine hang,
    // aborting the process (the ledger already has the coordinate). There is
    // NO background thread: a background thread's instrumented edges would
    // contaminate the measurement window (timing-dependent, uncalibratable).
    install_alarm_handler()?;

    let total = sancov::total_counter_bytes();
    if total == 0 {
        return Err(Error::Other(
            "no sanitizer-coverage counters registered — is this binary instrumented?".into(),
        ));
    }
    let scan_buf = vec![0u64; total];
    let events_buf = [CmpEvent::cmp(CmpKind::Cmp, 0, 0, 0); 256];
    let mut worker = Worker {
        hooks,
        ledger,
        cx,
        timeout_ms: cfg.timeout_ms,
        footprint_set: BTreeSet::new(),
        scan_buf,
        events_buf,
        local_baseline: BTreeSet::new(),
        last_cmp_hits: Vec::new(),
        tracker: OrderSignalTracker::new(),
        batch_summary: SignalBatchSummary::new(),
    };

    // ---- setup hook (target init + signal schema registration; its edges
    // are wiped by the first calibration window's clear) ----
    if let Some(setup) = hooks.setup {
        setup(&mut worker.cx)
            .map_err(|e| Error::Other(format!("target setup hook failed: {e}")))?;
    }
    let schema_wire = work_order::schema_to_wire(worker.cx.schema())?;

    // ---- calibration ----
    // The footprint must cover the FULL window skeleton (clear, reset,
    // execute-call, snapshot, scan) so the loop masks every constant runtime
    // edge. With no background threads, the skeleton is the only code that
    // runs between clear and scan.
    let footprint = worker.calibrate_window()?;
    worker.footprint_set = footprint.iter().copied().collect();
    eprintln!(
        "[worker] calibrated footprint: {} constant counters ({} total)",
        footprint.len(),
        total
    );

    // ---- hello ----
    let hello = Hello {
        mode: cfg.mode,
        range_count: sancov::range_count() as u32,
        total_counter_bytes: total as u64,
        pid: process::id(),
        rustc_release: rustc_release_line().unwrap_or_else(|| "unknown".into()),
        llvm_version: rustc_llvm_line().unwrap_or_else(|| "unknown".into()),
        schema: schema_wire,
    };
    let mut out = BufWriter::new(std::io::stdout().lock());
    let mut input = BufReader::new(std::io::stdin().lock());
    protocol::write_frame(&mut out, MsgKind::Hello, &work_order::encode_hello(&hello)?)?;
    out.flush()?;

    // ---- main loop ----
    let mut frame_buf: Vec<u8> = Vec::new();
    loop {
        let frame = protocol::read_frame(&mut input, &mut frame_buf)?;
        match frame.kind {
            MsgKind::WorkOrder => {
                let order = work_order::decode_work_order(frame.payload)?;
                let result = if order.input_override.is_empty() {
                    worker.execute_batch(&order)?
                } else {
                    worker.execute_override(&order)?
                };
                let payload = work_order::encode_work_result(&result)?;
                protocol::write_frame(&mut out, MsgKind::WorkResult, &payload)?;
                out.flush()?;
            }
            MsgKind::Heartbeat => {
                protocol::write_frame(&mut out, MsgKind::Heartbeat, b"")?;
                out.flush()?;
            }
            MsgKind::Shutdown => break,
            MsgKind::Error => {
                return Err(Error::Other(
                    "coordinator reported an error; shutting down".into(),
                ));
            }
            other => {
                return Err(Error::Other(format!(
                    "unexpected message kind {other:?} from coordinator (fail closed)"
                )));
            }
        }
    }

    // ---- teardown ----
    if let Some(teardown) = hooks.teardown {
        teardown().map_err(|e| Error::Other(format!("target teardown hook failed: {e}")))?;
    }
    Ok(0)
}

/// Worker configuration from the environment (the coordinator sets these).
#[derive(Debug, Clone)]
struct WorkerConfig {
    ledger_path: std::path::PathBuf,
    mode: u8,
    timeout_ms: u64,
    memory_limit_mb: u64,
}

impl WorkerConfig {
    fn from_env() -> Result<WorkerConfig> {
        let ledger_path = env_path(ENV_LEDGER)?;
        // The lane is set by the coordinator for diagnostics; the actual
        // lane used per execution comes from the work order's coordinate.
        let _lane = env_u64(ENV_LANE)?.unwrap_or(0);
        let mode = match env_str(ENV_SANITIZER)?.as_deref() {
            Some("address") => work_order::mode::ASAN,
            _ => work_order::mode::SANCOV_TRACECMP,
        };
        let timeout_ms = env_u64(ENV_TIMEOUT_MS)?.unwrap_or(5000);
        if timeout_ms == 0 {
            return Err(Error::Encoding("FRF_FUZZ_TIMEOUT_MS must be > 0"));
        }
        let memory_limit_mb = env_u64(ENV_MEMORY_LIMIT_MB)?.unwrap_or(0);
        Ok(WorkerConfig {
            ledger_path,
            mode,
            timeout_ms,
            memory_limit_mb,
        })
    }
}

fn env_path(name: &str) -> Result<std::path::PathBuf> {
    match std::env::var_os(name) {
        Some(v) if !v.is_empty() => Ok(v.into()),
        _ => Err(Error::Other(format!(
            "frf-fuzz worker: environment variable {name} is not set (run me through `frf-fuzz run`, not directly)"
        ))),
    }
}

fn env_str(name: &str) -> Result<Option<String>> {
    Ok(std::env::var(name).ok())
}

fn env_u64(name: &str) -> Result<Option<u64>> {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .map(Some)
            .map_err(|_| Error::Encoding("invalid u64 in environment variable")),
        Err(_) => Ok(None),
    }
}

/// Apply RLIMIT_AS (virtual address space) via libc. Off by default; the
/// coordinator enables it through config. ASan builds need generous limits
/// (shadow memory), so the default config keeps it off and documents it.
fn apply_memory_limit(mib: u64) -> Result<()> {
    let bytes = mib.saturating_mul(1024 * 1024);
    let rlim = libc::rlimit {
        rlim_cur: bytes,
        rlim_max: bytes,
    };
    // SAFETY: setrlimit with a fully-initialized rlimit struct; the call
    // itself is async-signal-safe and cannot touch Rust state.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_AS, &rlim) };
    if rc != 0 {
        return Err(Error::Other(format!(
            "setrlimit(RLIMIT_AS, {mib} MiB) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// rustc release line: the build embeds the toolchain identity via
/// `FRF_FUZZ_RUSTC_IDENTITY` (set by the coordinator's build command); a
/// direct/manual run falls back to probing `rustc -vV` (best-effort).
fn rustc_release_line() -> Option<String> {
    if let Some(v) = option_env!("FRF_FUZZ_RUSTC_IDENTITY") {
        return Some(v.to_string());
    }
    rustc_vv().and_then(|lines| lines.first().cloned())
}

fn rustc_llvm_line() -> Option<String> {
    if let Some(v) = option_env!("FRF_FUZZ_LLVM_IDENTITY") {
        return Some(v.to_string());
    }
    rustc_vv().and_then(|lines| lines.iter().find(|l| l.starts_with("LLVM")).cloned())
}

fn rustc_vv() -> Option<Vec<String>> {
    let out = process::Command::new("rustc").arg("-vV").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.to_string())
            .collect(),
    )
}

/// The per-worker execution state.
struct Worker {
    hooks: &'static TargetHooks,
    ledger: CrashLedgerWriter,
    cx: FuzzContext,
    /// Per-execution timeout in milliseconds (the SIGALRM deadline).
    timeout_ms: u64,
    /// Sorted footprint packed indices (permanently masked).
    footprint_set: BTreeSet<u64>,
    /// Scan scratch (one slot per counter byte).
    scan_buf: Vec<u64>,
    /// Cmp snapshot scratch.
    events_buf: [CmpEvent; 256],
    /// Locally-seen features (worker-side novelty baseline).
    local_baseline: BTreeSet<u64>,
    /// Cmp hits from the previous window (cmp-guided substitution).
    last_cmp_hits: Vec<CmpHit>,
    /// Per-order persistent-drift tracker (reset per work order).
    tracker: OrderSignalTracker,
    /// Per-order batch signal summary (reset per work order).
    batch_summary: SignalBatchSummary,
}

/// One executed window's observation (worker-internal).
struct WindowOutcome {
    /// Footprint-masked, sorted, deduplicated feature set.
    features: Vec<u64>,
    /// Target cmp events (already separated from the scan by ordering).
    events: Vec<CmpEvent>,
    /// The observed signal vector (Phase 2).
    signals: SignalVector,
    /// Execution time bucket (logarithmic).
    time_bucket: u8,
}

/// Why an execution is worth reporting to the coordinator.
struct InterestFlags(u8);

impl InterestFlags {
    const NOVEL_FEATURES: u8 = 1 << 0;
    const NEW_SIGNAL: u8 = 1 << 1;
    const PERSISTENT: u8 = 1 << 2;
    const LARGE_DELTA: u8 = 1 << 3;

    fn any(&self) -> bool {
        self.0 != 0
    }
}

impl Worker {
    fn execute_batch(&mut self, order: &WorkOrder) -> Result<WorkResult> {
        for f in &order.new_features {
            self.local_baseline.insert(*f);
        }
        let mutator = MutatorId::from_id(order.mutator_id)
            .ok_or(Error::Encoding("unknown mutator id in work order"))?;
        let dict_refs: Vec<&[u8]> = order.dictionary.iter().map(|d| d.as_slice()).collect();
        let partner: Option<&[u8]> = if order.partner.is_empty() {
            None
        } else {
            Some(order.partner.as_slice())
        };
        // Fresh per-order residual state.
        self.tracker = OrderSignalTracker::new();
        self.batch_summary = SignalBatchSummary::new();
        let mut result = WorkResult::default();
        let mut result_bytes = 0usize;
        for i in 0..order.index_count {
            let index = order.start_index.wrapping_add(i);
            let coord = MutationCoordinate {
                campaign_seed: order.campaign_seed,
                parent_short_id: order.parent_short,
                generation: order.generation,
                mutator_id: mutator,
                lane_id: order.lane_id,
                mutation_index: index,
                probe_params: [0; 4],
            };
            let (candidate, hits_used) =
                self.mutate(order, &coord, mutator, &dict_refs, partner)?;
            result.exec_count += 1;
            let outcome = self.window_execute(&coord, &candidate)?;
            // Phase 2: residual observation (fixed-size, heap-free). The
            // exact saturating deltas feed the drift tracker and the batch
            // summary; the bucketized sketch travels with the discovery.
            let deltas =
                crate::target_runtime::signals::deltas(&order.parent_signals, &outcome.signals);
            let sketch = ResidualSketch::of(&order.parent_signals, &outcome.signals);
            self.batch_summary.push_deltas(&outcome.signals, &deltas);
            let persistent =
                self.tracker
                    .push(&deltas, &sketch, PERSIST_MIN_RUN, PERSIST_MIN_CUM_BUCKET);
            // Update the local baseline and decide whether this execution
            // is locally novel.
            let novel: Vec<u64> = outcome
                .features
                .iter()
                .copied()
                .filter(|f| !self.local_baseline.contains(f))
                .collect();
            for f in &outcome.features {
                self.local_baseline.insert(*f);
            }
            let interest = InterestFlags(
                (if novel.is_empty() {
                    0
                } else {
                    InterestFlags::NOVEL_FEATURES
                }) | (if sketch.touched_new != 0 {
                    InterestFlags::NEW_SIGNAL
                } else {
                    0
                }) | (if persistent != 0 {
                    InterestFlags::PERSISTENT
                } else {
                    0
                }) | (if sketch.at_or_above(LARGE_DELTA_BUCKET) != 0 {
                    InterestFlags::LARGE_DELTA
                } else {
                    0
                }),
            );
            if interest.any() {
                self.push_discovery(
                    &mut result,
                    &mut result_bytes,
                    coord,
                    outcome,
                    sketch,
                    hits_used,
                    interest,
                )?;
            }
        }
        // Copy the tracker's persistence runs into the summary (the summary
        // cannot derive them from per-execution sketches alone).
        for i in 0..crate::target_runtime::signals::MAX_SIGNALS {
            self.batch_summary.max_run[i] = self.batch_summary.max_run[i].max(self.tracker.run[i]);
        }
        result.signal_summary = self.batch_summary;
        Ok(result)
    }

    /// Execute the exact bytes of an input-override order (seed/replay/tmin
    /// sessions). Status is always Ok from a live worker; a crash kills
    /// the process and the coordinator resolves it via the ledger's
    /// override marker (mutator 0, ordinal in `mutation_index`). Override
    /// executions are status-only: they never feed corpus admission.
    fn execute_override(&mut self, order: &WorkOrder) -> Result<WorkResult> {
        // Marker coordinate: version byte, parent_short = [0; 8], mutator
        // id 0 (unused by the stable table), lane, ordinal. Committed raw
        // because the typed coordinate cannot represent mutator 0.
        let mut marker = [0u8; crate::mutation::coordinate::COORDINATE_ENCODED_LEN];
        marker[0] = crate::mutation::coordinate::COORDINATE_VERSION;
        marker[21..23].copy_from_slice(&OVERRIDE_MARKER_MUTATOR.to_le_bytes());
        marker[23..25].copy_from_slice(&order.lane_id.to_le_bytes());
        marker[25..33].copy_from_slice(&order.start_index.to_le_bytes());
        self.ledger.commit_raw(&marker);
        self.ledger.commit_echo(&order.input_override)?;
        let outcome = self.window_execute_raw(&order.input_override)?;
        Ok(WorkResult {
            exec_count: 1,
            timeout_count: 0,
            discoveries: Vec::new(),
            truncated: false,
            signal_summary: SignalBatchSummary::new(),
            override_features: outcome.features,
            override_signals: outcome.signals,
        })
    }

    /// Deterministically mutate `parent` at `coord` (I2). Returns the
    /// candidate bytes and the compare hits the mutation actually consumed
    /// (so the coordinator can reconstruct family-15 candidates bit-exactly).
    fn mutate<'a>(
        &'a mut self,
        order: &'a WorkOrder,
        coord: &MutationCoordinate,
        mutator: MutatorId,
        dictionary: &'a [&'a [u8]],
        partner: Option<&'a [u8]>,
    ) -> Result<(Vec<u8>, Vec<CmpHitWire>)> {
        let mut rng = CounterRng::from_coordinate_fields(
            coord.campaign_seed,
            coord.generation,
            coord.mutator_id.id(),
            coord.lane_id,
            coord.mutation_index,
        );
        let mut input = MutationInput {
            parent: &order.parent,
            rng: &mut rng,
            dictionary,
            cmp_hits: &self.last_cmp_hits,
            splice_partner: partner,
            influence: None,
        };
        let hits_used: Vec<CmpHitWire> = self
            .last_cmp_hits
            .iter()
            .take(MAX_CMP_HITS_PER_EXEC)
            .map(|h| CmpHitWire {
                width: h.width() as u8,
                value: h.value(),
            })
            .collect();
        let out = mutation::apply(mutator, &mut input)?;
        if out.changed {
            Ok((out.bytes, hits_used))
        } else {
            // Deterministic no-op (e.g. empty parent with a delete
            // mutator): still counts as an execution but with the parent
            // bytes unchanged.
            Ok((order.parent.clone(), hits_used))
        }
    }

    /// The measurement window (module docs).
    fn window_execute(&mut self, coord: &MutationCoordinate, data: &[u8]) -> Result<WindowOutcome> {
        // 1. Crash reconstructability FIRST: coordinate, then the exact
        //    input echo (both before the window, so their edges/events are
        //    cleared/discarded by the window sequence below).
        self.ledger.commit(coord);
        self.ledger.commit_echo(data)?;
        self.window_execute_raw(data)
    }

    /// The measurement window body (after the ledger commit). Arms the
    /// one-shot timeout, runs the window, disarms.
    fn window_execute_raw(&mut self, data: &[u8]) -> Result<WindowOutcome> {
        // 2. Arm the timeout (aborts the process on a hang; the ledger
        //    already has the coordinate). Armed BEFORE the window; its edges
        //    are wiped by the clear below.
        arm_timeout(self.timeout_ms)?;
        let outcome = self.window_with(self.hooks.execute, data);
        let _ = disarm_timeout();
        outcome
    }

    /// The window skeleton with an arbitrary execute function (the real
    /// hook in the loop, `noop_execute` during calibration).
    fn window_with(
        &mut self,
        exec: fn(&[u8], &mut FuzzContext) -> Result<()>,
        data: &[u8],
    ) -> Result<WindowOutcome> {
        sancov::clear_all();
        cmp::reset();
        let t0 = SystemTime::now();
        // Clear the per-execution signal vector (NOT execution_ordinal or
        // the schema) BEFORE the target's reset hook, so a target that
        // observes in its reset hook starts from a fresh vector.
        self.cx.reset();
        if let Some(reset) = self.hooks.reset {
            reset(&mut self.cx)
                .map_err(|e| Error::Other(format!("target reset hook failed: {e}")))?;
        }
        self.cx.execution_ordinal = self.cx.execution_ordinal.wrapping_add(1);
        exec(data, &mut self.cx)
            .map_err(|e| Error::Other(format!("target execute hook failed: {e}")))?;
        // Capture the signal vector: a fixed-size memcpy with constant
        // edges, so it cannot contaminate the observation.
        let signals = self.cx.take_signals();
        let dt_ms = t0.elapsed().map(|d| d.as_millis() as u64).unwrap_or(0);
        // 4. Snapshot the ring BEFORE the scan: the captured range is
        //    exactly the target's events (the scan's own events land after
        //    and are discarded by the next reset).
        let n_events = cmp::snapshot(&mut self.events_buf);
        let events: Vec<CmpEvent> = self.events_buf[..n_events.min(self.events_buf.len())].to_vec();
        // 5. Scan (clears). Saturating return is impossible here: the scan
        //    buffer has one slot per counter byte.
        let n = sancov::scan_and_clear(&mut self.scan_buf);
        let n = (n as usize).min(self.scan_buf.len());
        // 6. Mask the constant footprint; sort + dedup.
        let mut features: Vec<u64> = self.scan_buf[..n]
            .iter()
            .copied()
            .filter(|f| !self.footprint_set.contains(f))
            .collect();
        features.sort_unstable();
        features.dedup();
        // 7. Remember cmp hits for cmp-guided substitution in the NEXT
        //    mutation (bounded).
        self.last_cmp_hits.clear();
        for e in events.iter().take(MAX_CMP_EVENTS_PER_EXEC) {
            if let Some(hit) = event_to_hit(e) {
                self.last_cmp_hits.push(hit);
            }
        }
        Ok(WindowOutcome {
            features,
            events,
            signals,
            time_bucket: time_bucket(dt_ms),
        })
    }

    /// Calibrate the full window skeleton's constant footprint. Consecutive
    /// windows must report identical footprints or the worker refuses to
    /// start (an unstable footprint would corrupt masking). With no
    /// background threads, the skeleton is the only code between clear and
    /// scan, so the footprint is stable by construction.
    fn calibrate_window(&mut self) -> Result<Vec<u64>> {
        let mut last: Vec<u64> = Vec::new();
        for _ in 0..4 {
            let report = self.window_with(noop_execute, &[])?;
            if report.features == last {
                return Ok(last);
            }
            if !last.is_empty() {
                let diff: Vec<u64> = report
                    .features
                    .iter()
                    .copied()
                    .filter(|f| !last.contains(f))
                    .collect();
                eprintln!(
                    "[worker] calibration mismatch: {} vs {} (new in this window: {:?})",
                    last.len(),
                    report.features.len(),
                    diff.iter().take(8).collect::<Vec<_>>()
                );
            }
            last = report.features;
        }
        Err(Error::Other(
            "worker footprint calibration: window footprint not stable \
             (is background code writing counters inside the window?)"
                .into(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn push_discovery(
        &mut self,
        result: &mut WorkResult,
        result_bytes: &mut usize,
        coord: MutationCoordinate,
        outcome: WindowOutcome,
        sketch: ResidualSketch,
        hits_used: Vec<CmpHitWire>,
        interest: InterestFlags,
    ) -> Result<()> {
        let _ = interest;
        if result.discoveries.len() >= MAX_DISCOVERIES_PER_RESULT {
            result.truncated = true;
            return Ok(());
        }
        // Byte budget: stop pushing once the encoded result would approach
        // the protocol frame bound (the count cap alone is not enough for
        // discovery floods — a Phase-2 finding: an unbounded stream killed
        // workers with "frame length exceeds bound" and produced false
        // crash findings). The estimate mirrors the encode sizes of the
        // dominant fields; the real encode enforces the hard frame bound.
        let estimate = 49
            + 1
            + 4
            + outcome.features.len() * 8
            + 2
            + outcome.events.len().min(MAX_CMP_EVENTS_PER_EXEC) * 17
            + 2
            + hits_used.len() * 9
            + 520
            + 96
            + 1;
        if result_bytes.saturating_add(estimate) > RESULT_BYTE_BUDGET {
            result.truncated = true;
            return Ok(());
        }
        *result_bytes += estimate;
        result.discoveries.push(DiscoveryRecord {
            coordinate: coord,
            status: ExecutionStatus::Ok,
            features: outcome.features,
            cmp_events: wire_events(&outcome.events),
            cmp_hits_used: hits_used,
            signals: outcome.signals,
            sketch,
            time_bucket: outcome.time_bucket,
        });
        Ok(())
    }
}

/// Convert captured ring events to the compact wire form (bounded).
fn wire_events(events: &[CmpEvent]) -> Vec<CmpEventWire> {
    events
        .iter()
        .take(MAX_CMP_EVENTS_PER_EXEC)
        .map(|e| CmpEventWire {
            kind: e.kind as u8,
            width: e.width,
            a: e.a,
            b: e.b,
        })
        .collect()
}

/// Convert a ring event to a substitution hit (width-gated).
fn event_to_hit(e: &CmpEvent) -> Option<CmpHit> {
    if e.kind == CmpKind::Switch {
        return None;
    }
    match e.width {
        1 => Some(CmpHit::U8(e.a as u8)),
        2 => Some(CmpHit::U16(e.a as u16)),
        4 => Some(CmpHit::U32(e.a as u32)),
        8 => Some(CmpHit::U64(e.a)),
        _ => None,
    }
}

/// Logarithmic time bucket (0 = fastest; sub-ms executions are bucket 0).
fn time_bucket(ms: u64) -> u8 {
    if ms == 0 {
        0
    } else {
        ms.ilog2().min(255) as u8
    }
}

/// The calibration/loop no-op execute: the window skeleton's target slot
/// during calibration. Its edges are constant and become part of the masked
/// footprint; the real execute hook's edges are target features and are
/// never masked.
fn noop_execute(_data: &[u8], _cx: &mut FuzzContext) -> Result<()> {
    Ok(())
}

/// Install the SIGALRM handler: a one-shot per-execution timeout. The
/// handler aborts the process (the crash ledger already holds the
/// coordinate), and the coordinator attributes the death to a timeout.
/// There is deliberately NO background watchdog thread: a thread's
/// instrumented edges would fire at unpredictable times inside the
/// measurement window and could not be calibrated out (Phase-1 finding;
/// see module docs).
fn install_alarm_handler() -> Result<()> {
    // SAFETY: signal() with a static extern "C" fn pointer; the handler
    // only calls abort() (async-signal-safe). Installed once at startup on
    // the main thread.
    #[allow(unsafe_code)]
    unsafe {
        let handler: extern "C" fn(libc::c_int) = alarm_handler;
        let prev = libc::signal(libc::SIGALRM, handler as usize);
        if prev == libc::SIG_ERR {
            return Err(Error::Other(format!(
                "signal(SIGALRM) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

extern "C" fn alarm_handler(_sig: libc::c_int) {
    // The ledger has the in-flight coordinate; abort so the coordinator
    // treats the death as a timeout finding. abort() is async-signal-safe.
    std::process::abort();
}

/// Arm the one-shot real-time timeout (`ms` from now).
fn arm_timeout(ms: u64) -> Result<()> {
    set_itimer(ms)
}

/// Disarm the timeout.
fn disarm_timeout() -> Result<()> {
    set_itimer(0)
}

// glibc `setitimer(2)`: the libc crate does not export it for linux-gnu
// (it does for android/musl), so the single stable symbol is declared
// here. This is the only place the worker calls it.
extern "C" {
    fn setitimer(
        which: libc::c_int,
        new_value: *const libc::itimerval,
        old_value: *mut libc::itimerval,
    ) -> libc::c_int;
}

fn set_itimer(ms: u64) -> Result<()> {
    let tv = libc::timeval {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_usec: ((ms % 1000) * 1000) as libc::suseconds_t,
    };
    let itv = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: tv,
    };
    // SAFETY: fully initialized itimerval, null old-value out-param; the
    // syscall cannot touch Rust state.
    #[allow(unsafe_code)]
    let rc = unsafe { setitimer(libc::ITIMER_REAL, &itv, std::ptr::null_mut()) };
    if rc != 0 {
        return Err(Error::Other(format!(
            "setitimer failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}
