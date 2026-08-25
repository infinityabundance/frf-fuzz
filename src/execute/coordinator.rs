//! The fuzzing coordinator: campaign loop, admission, crash recovery.
//!
//! The coordinator is the Evidence-plane authority over the Exploration
//! plane: it decides what is admitted to the corpus, what becomes a
//! finding, and what the workers learn next. It never executes the target
//! itself — workers do — and every decision is deterministic given the
//! campaign seed and the corpus.
//!
//! # Loop
//!
//! ```text
//! open store, rebuild corpus index
//! write campaign object
//! spawn N persistent workers
//! seed the corpus (override orders) if empty
//! loop:
//!   dispatch work orders to idle lanes
//!   await results (bounded channel, heartbeat timeout)
//!   process results: admission, findings, dictionary discovery
//!   handle worker deaths: ledger -> echo input -> replay -> finding
//! until: max_time / max_execs / SIGINT
//! graceful shutdown: shutdown workers, checkpoint, summary
//! ```
//!
//! This module is coordinator-gated.

use crate::canon::Family;
use crate::corpus::admission;
use crate::corpus::entry::{self, AdmissionReason, CorpusMeta};
use crate::corpus::CorpusIndex;
use crate::error::{Error, Result};
use crate::execute::finding::{self, Finding, FindingKind, ReplayStatus};
use crate::execute::worker_process::{SanitizerMode, WorkerEvent, WorkerHandle};
use crate::id::ContentId;
use crate::mutation::{CounterRng, MutationCoordinate};
use crate::scheduler::policy::{OrderPlanner, SchedulePolicy};
use crate::scheduler::work_order::{self, ExecutionStatus, WorkOrder, WorkResult};
use crate::store::object::Store;
use crate::store::refs;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

/// Per-lane consecutive startup deaths before the campaign aborts (a worker
/// that dies before its first execution repeatedly is a broken binary).
const MAX_STARTUP_DEATHS: u32 = 3;
/// Heartbeat interval: if no worker produced an event within this, the
/// coordinator pings all workers.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Per-lane poll granularity in the await loop (short so idle lanes never
/// block the loop; adds latency only when everything is idle).
const AWAIT_POLL: Duration = Duration::from_millis(25);
/// Grace period for workers to finish after Shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Campaign configuration.
#[derive(Debug, Clone)]
pub struct CampaignConfig {
    /// The instrumented fuzz-target binary.
    pub target_bin: PathBuf,
    /// The `.frf-fuzz/` store root.
    pub store_root: PathBuf,
    /// Scheduling policy.
    pub policy: SchedulePolicy,
    /// Sanitizer mode.
    pub sanitizer: SanitizerMode,
    /// Worker memory limit in MiB (0 = none).
    pub memory_limit_mb: u64,
    /// Seed corpus directory (regular files become seeds). `None` seeds
    /// with the empty input.
    pub seed_dir: Option<PathBuf>,
    /// Target name (campaign metadata).
    pub target_name: String,
    /// Wall-clock budget (`None` = until Ctrl-C or `max_execs`).
    pub max_time: Option<Duration>,
    /// Execution budget.
    pub max_execs: Option<u64>,
    /// Initial dictionary entries.
    pub initial_dictionary: Vec<Vec<u8>>,
    /// rustc release line of the instrumented build (campaign metadata).
    pub rustc_release: String,
    /// LLVM version line of the instrumented build.
    pub llvm_version: String,
    /// The exact instrumented-build flag set (campaign metadata).
    pub instrument_flags: Vec<String>,
}

/// The campaign outcome.
#[derive(Debug, Clone)]
pub struct CampaignSummary {
    /// Campaign object id.
    pub campaign_id: ContentId,
    /// Executions completed.
    pub executions: u64,
    /// Corpus entries after the run.
    pub corpus_entries: usize,
    /// Distinct features covered.
    pub features: usize,
    /// Findings recorded.
    pub findings: u64,
    /// Duration.
    pub duration: Duration,
    /// Whether the campaign ended gracefully (shutdown path).
    pub graceful: bool,
}

/// The SIGINT latch (set by a signal handler; checked by the loop).
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Install the SIGINT handler (best-effort; a missing handler just means
/// Ctrl-C kills the coordinator without a checkpoint).
pub fn install_sigint_handler() {
    // SAFETY: `signal()` with a static function pointer; the handler only
    // stores an AtomicBool (lock-free, async-signal-safe in practice).
    // The coordinator is single-threaded at install time.
    #[allow(unsafe_code)]
    unsafe {
        // Cast through an `extern "C" fn` pointer so the signal ABI is
        // explicit; `sighandler_t` is `usize` on Linux.
        let handler: extern "C" fn(libc::c_int) = sigint_handler;
        libc::signal(libc::SIGINT, handler as usize);
    }
}

extern "C" fn sigint_handler(_sig: libc::c_int) {
    INTERRUPTED.store(true, AtomicOrdering::Relaxed);
}

/// Run a campaign to completion. The caller has already installed the
/// SIGINT handler if desired.
pub fn run_campaign(cfg: &CampaignConfig) -> Result<CampaignSummary> {
    let store = Store::open(cfg.store_root.clone())?;
    let mut index = CorpusIndex::rebuild(&store)?;

    // ---- campaign object ----
    let campaign_payload = encode_campaign(cfg)?;
    let campaign_id = store.put(Family::Campaign, &campaign_payload)?;
    refs::set_ref(&cfg.store_root, "campaign-current", &campaign_id)?;

    // ---- dictionary ----
    let mut dictionary = cfg.initial_dictionary.clone();
    let mut dict_consts: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut dict_const_count = 0usize;

    // ---- workers ----
    let mut workers: Vec<Option<WorkerHandle>> = Vec::new();
    for lane in 0..cfg.policy.workers as u16 {
        workers.push(Some(spawn_worker(cfg, &store, lane)?));
    }

    // ---- scheduler state ----
    let mut planner = OrderPlanner::new(&cfg.policy);
    let mut next_index: BTreeMap<[u8; 8], u64> =
        load_checkpoint_next_index(&store, &cfg.store_root)?;
    let mut pending: BTreeMap<u16, PendingOrder> = BTreeMap::new();
    let mut deltas: Vec<u64> = Vec::new();
    let mut startup_deaths: BTreeMap<u16, u32> = BTreeMap::new();
    let mut executions = 0u64;
    let mut findings = 0u64;
    let start = Instant::now();
    let mut override_seq: BTreeMap<u16, u64> = BTreeMap::new();

    // ---- seed the corpus if empty ----
    if index.is_empty() {
        let seeds = read_seeds(cfg)?;
        for seed in &seeds {
            let lane = 0u16;
            let seq = override_seq.entry(lane).or_insert(0);
            let order = override_order(&cfg.policy, lane, *seq, seed.clone());
            *seq += 1;
            let w = workers[0]
                .as_mut()
                .ok_or(Error::Other("worker 0 missing".into()))?;
            w.send_order(&order)?;
            let result = w
                .recv_result()
                .map_err(|e| Error::Other(format!("seeding worker died: {e}")))?;
            let features = result.override_features;
            if features.is_empty() {
                // The seed executes zero novel edges (e.g. empty input on an
                // empty-function target); still admit it so the corpus is
                // non-empty and the loop has a parent.
                admit_seed(&store, &mut index, seed, &features)?;
            } else {
                admit_seed(&store, &mut index, seed, &features)?;
            }
        }
        eprintln!("[campaign] seeded corpus: {} entries", index.len());
    }

    // ---- main loop ----
    let mut graceful = false;
    'outer: loop {
        // 1. dispatch to idle lanes.
        for lane in 0..cfg.policy.workers as u16 {
            if pending.contains_key(&lane) {
                continue;
            }
            let Some(w) = workers[lane as usize].as_mut() else {
                continue;
            };
            // Parent selection (deterministic from the campaign seed).
            let mut rng = CounterRng::from_philox(
                [executions as u32, (executions >> 32) as u32, lane as u32, 0],
                [cfg.policy.seed as u32, (cfg.policy.seed >> 32) as u32],
            );
            let Some(parent_id) = index.pick_parent(&mut rng) else {
                // No corpus (all entries somehow gone): nothing to do.
                break 'outer;
            };
            let parent_meta = index.meta(&parent_id).expect("picked parent must exist");
            let parent_bytes = store.get(&parent_id)?.unwrap_or_default();
            let start = *next_index.entry(parent_id.short()).or_insert(0);
            let mut plan =
                planner.plan_for(lane, parent_id.short(), parent_meta.generation + 1, start);
            plan.count = plan
                .count
                .min(work_order::MAX_DISCOVERIES_PER_RESULT as u64);
            *next_index.entry(parent_id.short()).or_insert(0) = start.wrapping_add(plan.count);
            // Splice partner: a second parent (never self).
            let mut parents: Vec<[u8; 8]> = index.iter().map(|(id, _)| id.short()).collect();
            parents.sort_unstable();
            let partner_short = planner.pick_partner(&mut rng, &parents, parent_id.short());
            let partner_bytes = match partner_short {
                Some(short) => index
                    .iter()
                    .find(|(id, _)| id.short() == short)
                    .and_then(|(id, _)| store.get(id).ok().flatten())
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            // Dictionary: carry a bounded slice (the worker's bound).
            let dict_slice: Vec<Vec<u8>> = dictionary
                .iter()
                .take(work_order::MAX_DICT_ENTRIES)
                .cloned()
                .collect();
            let order = planner.build_order(
                &plan,
                parent_bytes,
                parent_id.short(),
                partner_bytes,
                &dict_slice,
                &deltas,
            );
            let pend = PendingOrder {
                order: order.clone(),
                parent_id,
                parent_generation: parent_meta.generation,
                is_override: false,
            };
            w.send_order(&order)?;
            pending.insert(lane, pend);
        }
        deltas.clear();

        // 2. await one event with a bounded poll. Each lane is polled with a
        //    short timeout so a lane without a pending result can never block
        //    the loop (the per-lane channels are independent); the heartbeat
        //    fires when nothing has arrived for HEARTBEAT_INTERVAL.
        let mut heartbeat_at = Instant::now() + HEARTBEAT_INTERVAL;
        'poll: loop {
            for lane in 0..cfg.policy.workers as u16 {
                let Some(w) = workers[lane as usize].as_mut() else {
                    continue;
                };
                match w.poll_event(AWAIT_POLL)? {
                    Some(WorkerEvent::Frame(payload)) => {
                        if let Some(pend) = pending.remove(&lane) {
                            let result = work_order::decode_work_result(&payload)?;
                            let (_admitted, new_deltas) = process_result(
                                &store,
                                &mut index,
                                &pend,
                                &result,
                                &mut dictionary,
                                &mut dict_consts,
                                &mut dict_const_count,
                            )?;
                            for f in new_deltas {
                                if !deltas.contains(&f) {
                                    deltas.push(f);
                                }
                            }
                            executions = executions.saturating_add(result.exec_count);
                            // Log progress periodically.
                            if executions % (cfg.policy.batch_size * 8) < cfg.policy.batch_size {
                                eprintln!(
                                    "[campaign] execs={} corpus={} features={} findings={}",
                                    executions,
                                    index.len(),
                                    index.feature_count(),
                                    findings
                                );
                            }
                        }
                        // else: a frame from a lane with no pending order
                        // (e.g. a heartbeat reply) — ignore.
                        break 'poll;
                    }
                    Some(WorkerEvent::Eof) => {
                        handle_worker_death(
                            cfg,
                            &store,
                            &mut workers,
                            lane,
                            &mut pending,
                            &mut startup_deaths,
                            &mut findings,
                            &mut override_seq,
                        )?;
                        break 'poll;
                    }
                    None => {}
                }
            }
            // Heartbeat ping when nothing has arrived for a while.
            if Instant::now() >= heartbeat_at {
                for lane in 0..cfg.policy.workers as u16 {
                    if let Some(w) = workers[lane as usize].as_mut() {
                        let _ = w.send_heartbeat();
                    }
                }
                heartbeat_at = Instant::now() + HEARTBEAT_INTERVAL;
            }
        }

        // 4. termination checks.
        if INTERRUPTED.load(AtomicOrdering::Relaxed) {
            graceful = true;
            break;
        }
        if let Some(t) = cfg.max_time {
            if start.elapsed() >= t {
                graceful = true;
                break;
            }
        }
        if let Some(m) = cfg.max_execs {
            if executions >= m {
                graceful = true;
                break;
            }
        }
    }

    // ---- graceful shutdown ----
    for lane in 0..cfg.policy.workers as u16 {
        if let Some(w) = workers[lane as usize].as_mut() {
            let _ = w.send_shutdown();
        }
    }
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    for w in workers.iter_mut().flatten() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let _ = w.kill();
        } else {
            let _ = w.wait_timeout(remaining);
        }
    }

    // ---- checkpoint + summary ----
    let checkpoint_payload =
        encode_checkpoint(&campaign_id, &index, executions, findings, &next_index)?;
    let checkpoint_id = store.put(Family::Checkpoint, &checkpoint_payload)?;
    refs::set_ref(&cfg.store_root, "checkpoint-current", &checkpoint_id)?;

    Ok(CampaignSummary {
        campaign_id,
        executions,
        corpus_entries: index.len(),
        features: index.feature_count(),
        findings,
        duration: start.elapsed(),
        graceful,
    })
}

/// A work order we sent and have not yet processed a result for.
struct PendingOrder {
    order: WorkOrder,
    parent_id: ContentId,
    parent_generation: u32,
    is_override: bool,
}

/// Build an input-override order (seed / replay / tmin candidate).
fn override_order(policy: &SchedulePolicy, lane: u16, seq: u64, input: Vec<u8>) -> WorkOrder {
    WorkOrder {
        campaign_seed: policy.seed,
        generation: 0,
        mutator_id: crate::mutation::MutatorId::BitFlip.id(),
        lane_id: lane,
        start_index: seq,
        index_count: 1,
        parent: Vec::new(),
        parent_short: [0; 8],
        partner: Vec::new(),
        dictionary: Vec::new(),
        new_features: Vec::new(),
        input_override: input,
    }
}

fn spawn_worker(cfg: &CampaignConfig, _store: &Store, lane: u16) -> Result<WorkerHandle> {
    WorkerHandle::spawn(
        &cfg.target_bin,
        &cfg.store_root,
        lane,
        &cfg.policy,
        cfg.sanitizer,
        cfg.memory_limit_mb,
    )
}

/// Read seed inputs from the seed directory (or the empty-input default).
fn read_seeds(cfg: &CampaignConfig) -> Result<Vec<Vec<u8>>> {
    let Some(dir) = &cfg.seed_dir else {
        return Ok(vec![Vec::new()]);
    };
    let mut seeds = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    entries.sort();
    let mut total = 0usize;
    for p in entries {
        let data = std::fs::read(&p)?;
        if data.len() > work_order::MAX_INPUT_LEN {
            return Err(Error::BoundExceeded {
                what: "seed input length",
                limit: work_order::MAX_INPUT_LEN as u64,
                got: data.len() as u64,
            });
        }
        total = total.saturating_add(data.len());
        if seeds.len() >= 4096 || total > (1 << 26) {
            return Err(Error::Other(
                "seed corpus exceeds the 4096-entry / 64 MiB bound".into(),
            ));
        }
        seeds.push(data);
    }
    if seeds.is_empty() {
        seeds.push(Vec::new());
    }
    Ok(seeds)
}

/// Admit one seed: entry object + metadata + index insert.
fn admit_seed(
    store: &Store,
    index: &mut CorpusIndex,
    input: &[u8],
    features: &[u64],
) -> Result<()> {
    let entry_id = store.put(Family::CorpusEntry, input)?;
    if index.meta(&entry_id).is_some() {
        return Ok(()); // already admitted
    }
    let mut feat = features.to_vec();
    feat.sort_unstable();
    feat.dedup();
    let meta = CorpusMeta {
        entry_id,
        parent_id: None,
        generation: 0,
        features: feat,
        reason: AdmissionReason::Seed,
    };
    let payload = entry::encode_meta(&meta)?;
    store.put(Family::CorpusMeta, &payload)?;
    index.insert_meta(meta)
}

/// Process one work result: admissions and dictionary growth.
/// Returns (new_corpus_entries, newly-global features).
#[allow(clippy::too_many_arguments)]
fn process_result(
    store: &Store,
    index: &mut CorpusIndex,
    pend: &PendingOrder,
    result: &WorkResult,
    dictionary: &mut Vec<Vec<u8>>,
    dict_consts: &mut std::collections::BTreeSet<Vec<u8>>,
    dict_const_count: &mut usize,
) -> Result<(u64, Vec<u64>)> {
    let mut admitted = 0u64;
    let mut new_global: Vec<u64> = Vec::new();

    // Dictionary discovery: const-cmp operands become tokens.
    for d in &result.discoveries {
        for e in &d.cmp_events {
            if e.kind == 2 && e.width >= 1 && e.width <= 8 {
                for val in [e.a, e.b] {
                    let bytes = value_bytes(val, e.width);
                    if is_interesting_token(&bytes) && dict_consts.insert(bytes.clone()) {
                        *dict_const_count += 1;
                    }
                }
            }
        }
        if *dict_const_count > work_order::MAX_DICT_ENTRIES {
            break;
        }
    }
    // Materialize new const tokens into the dictionary (bounded).
    if *dict_const_count > dictionary.len() {
        let mut all = dict_consts.iter().cloned().collect::<Vec<_>>();
        all.sort();
        all.dedup();
        all.truncate(work_order::MAX_DICT_ENTRIES);
        // Deterministic merge: prefer the user dictionary first.
        let mut merged = pend.order.dictionary.clone();
        for t in all {
            if merged.len() >= work_order::MAX_DICT_ENTRIES {
                break;
            }
            if !merged.contains(&t) {
                merged.push(t);
            }
        }
        merged.sort();
        merged.dedup();
        *dictionary = merged;
    }

    for d in &result.discoveries {
        if d.status != ExecutionStatus::Ok {
            // Live worker statuses are always Ok; non-Ok here is a protocol
            // anomaly. Defensive: record it, don't crash.
            continue;
        }
        // Reconstruct the candidate input from the coordinate (I2).
        let input = reconstruct_candidate(pend, d)?;
        let admission = admission::decide(index, &d.features, false);
        let Some(admission) = admission else {
            continue;
        };
        let entry_id = store.put(Family::CorpusEntry, &input)?;
        if index.meta(&entry_id).is_some() {
            continue; // already known
        }
        let mut feat = d.features.clone();
        feat.sort_unstable();
        feat.dedup();
        let meta = CorpusMeta {
            entry_id,
            parent_id: Some(pend.parent_id),
            generation: pend.parent_generation + 1,
            features: feat,
            reason: admission.reason,
        };
        let payload = entry::encode_meta(&meta)?;
        store.put(Family::CorpusMeta, &payload)?;
        index.insert_meta(meta)?;
        admitted += 1;
        for f in &admission.novel {
            if !new_global.contains(f) {
                new_global.push(*f);
            }
        }
    }
    Ok((admitted, new_global))
}

/// Reconstruct the candidate bytes for a discovery from the pending order's
/// parent and the coordinate (I2; the mutation engine is shared code).
fn reconstruct_candidate(pend: &PendingOrder, d: &work_order::DiscoveryRecord) -> Result<Vec<u8>> {
    if pend.order.input_override.is_empty() {
        let parent = &pend.order.parent;
        let mut rng = CounterRng::from_coordinate_fields(
            d.coordinate.campaign_seed,
            d.coordinate.generation,
            d.coordinate.mutator_id.id(),
            d.coordinate.lane_id,
            d.coordinate.mutation_index,
        );
        let dict_refs: Vec<&[u8]> = pend.order.dictionary.iter().map(|e| e.as_slice()).collect();
        let partner: Option<&[u8]> = if pend.order.partner.is_empty() {
            None
        } else {
            Some(pend.order.partner.as_slice())
        };
        let mut input = crate::mutation::MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &dict_refs,
            cmp_hits: &[],
            splice_partner: partner,
            influence: None,
        };
        let out = crate::mutation::apply(d.coordinate.mutator_id, &mut input)?;
        if out.changed {
            Ok(out.bytes)
        } else {
            Ok(parent.to_vec())
        }
    } else {
        Ok(pend.order.input_override.clone())
    }
}

/// Handle a worker death: read the ledger, record a finding, restart.
#[allow(clippy::too_many_arguments)]
fn handle_worker_death(
    cfg: &CampaignConfig,
    store: &Store,
    workers: &mut [Option<WorkerHandle>],
    lane: u16,
    pending: &mut BTreeMap<u16, PendingOrder>,
    startup_deaths: &mut BTreeMap<u16, u32>,
    findings: &mut u64,
    override_seq: &mut BTreeMap<u16, u64>,
) -> Result<()> {
    let mut worker = workers[lane as usize]
        .take()
        .ok_or(Error::Other("worker already dead".into()))?;
    // Reap the process.
    let _status = worker.wait()?;
    let stderr = worker.stderr_tail();

    let pend = pending.remove(&lane);
    let (seq, coord_bytes) = worker.new_crash_commit()?.unwrap_or((0, [0; 49]));
    let echo = worker.ledger_echo();

    let is_override_marker = coord_bytes[0] == crate::mutation::coordinate::COORDINATE_VERSION
        && coord_bytes[21..23] == 0u16.to_le_bytes()
        && coord_bytes[9..17] == [0u8; 8];

    // Build the finding.
    let (input, kind) = if seq != 0 && !echo.is_empty() {
        // Exact crashing input from the echo.
        (echo, FindingKind::Crash)
    } else if seq != 0 {
        // Echo empty (e.g. died between commit and echo): reconstruct from
        // the coordinate when possible.
        match MutationCoordinate::decode(&coord_bytes) {
            Ok(coord) if !is_override_marker => {
                let pend_for_recon = pending_for_recon(pend.as_ref(), &coord)?;
                let input = reconstruct_candidate(&pend_for_recon, &coord_to_discovery(&coord))?;
                (input, FindingKind::Crash)
            }
            _ => (Vec::new(), FindingKind::Unattributed),
        }
    } else {
        (Vec::new(), FindingKind::Unattributed)
    };

    // Startup-death accounting: a worker that dies before producing any
    // result repeatedly is a broken binary.
    let d = startup_deaths.entry(lane).or_insert(0);
    if input.is_empty() && pend.is_none() {
        *d += 1;
        if *d >= MAX_STARTUP_DEATHS {
            return Err(Error::Other(format!(
                "worker lane {lane} died {MAX_STARTUP_DEATHS} times before producing any result — is the target binary instrumented and runnable?"
            )));
        }
    } else {
        *d = 0;
    }

    // Record the finding when we have an input.
    if !input.is_empty() {
        let coord_hex = hex(&coord_bytes);
        let finding = Finding {
            kind,
            parent_short: coord_bytes[9..17].try_into().unwrap_or([0; 8]),
            coordinate: coord_bytes,
            replay: ReplayStatus::NotReplayed,
            input: input.clone(),
        };
        let payload = finding::encode_finding(&finding)?;
        let id = store.put(Family::Finding, &payload)?;
        // Sidecar: human-readable diagnostics (never part of identity).
        write_finding_sidecar(store, &id, &finding, &stderr, &coord_hex, seq)?;
        *findings += 1;
        eprintln!(
            "[campaign] FINDING lane={lane} kind={} id={} input={}B (seq {seq})",
            kind.name(),
            id,
            input.len()
        );
        // Deliberate replay to classify and confirm. Crash inputs are NOT
        // admitted to the corpus (their feature sets were never measured —
        // the worker died mid-window — so they are useless mutation parents;
        // the Finding object already retains the input, I10).
        classify_and_replay(cfg, store, lane, &input, &id, override_seq)?;
    } else {
        eprintln!(
            "[campaign] worker lane {lane} died without an attributable candidate (seq {seq})"
        );
    }

    // Restart the worker.
    workers[lane as usize] = Some(spawn_worker(cfg, store, lane)?);
    Ok(())
}

/// Find the pending-order stand-in needed to reconstruct a coordinate whose
/// order has already been removed from `pending`.
fn pending_for_recon(
    pend: Option<&PendingOrder>,
    _coord: &MutationCoordinate,
) -> Result<PendingOrder> {
    match pend {
        Some(p) => Ok(PendingOrder {
            order: p.order.clone(),
            parent_id: p.parent_id,
            parent_generation: p.parent_generation,
            is_override: p.is_override,
        }),
        None => Err(Error::Other(
            "worker died with a ledger coordinate but no pending order to reconstruct from".into(),
        )),
    }
}

/// Adapt a coordinate to the discovery shape reconstruction needs.
fn coord_to_discovery(coord: &MutationCoordinate) -> work_order::DiscoveryRecord {
    work_order::DiscoveryRecord {
        coordinate: *coord,
        status: ExecutionStatus::Ok,
        features: Vec::new(),
        cmp_events: Vec::new(),
        time_bucket: 0,
    }
}

/// Deliberately replay the finding input through a fresh worker to classify
/// (crash vs timeout by replay timing) and confirm reproduction.
fn classify_and_replay(
    cfg: &CampaignConfig,
    store: &Store,
    lane: u16,
    input: &[u8],
    finding_id: &ContentId,
    override_seq: &mut BTreeMap<u16, u64>,
) -> Result<()> {
    let mut w = spawn_worker(cfg, store, lane)?;
    let seq = override_seq.entry(lane).or_insert(0);
    let order = override_order(&cfg.policy, lane, *seq, input.to_vec());
    *seq += 1;
    w.send_order(&order)?;
    let outcome = match w.recv_result() {
        Ok(_) => ReplayStatus::NotReproduced, // ran to completion
        Err(_) => {
            // Worker died during replay: the input reproduced the death. The
            // watchdog aborts a hang at `timeout_ms`, so a death is
            // Reproduced regardless of timing; the KIND (crash vs timeout)
            // is preserved from the original observation.
            let _ = w.wait();
            ReplayStatus::Reproduced
        }
    };
    // Update the finding object's replay status. Objects are immutable, so
    // the replayed finding is a NEW revision (both are retained; I10).
    let payload = store
        .get(finding_id)?
        .ok_or(Error::Other("finding vanished".into()))?;
    let mut finding = finding::decode_finding(&payload)?;
    finding.replay = outcome;
    let new_payload = finding::encode_finding(&finding)?;
    let new_id = store.put(Family::Finding, &new_payload)?;
    let _ = new_id;
    let _ = w.send_shutdown();
    let _ = w.wait();
    Ok(())
}

/// Write the human-readable diagnostics sidecar next to a finding.
fn write_finding_sidecar(
    store: &Store,
    id: &ContentId,
    finding: &Finding,
    stderr: &str,
    coord_hex: &str,
    seq: u64,
) -> Result<()> {
    let dir = store.root().join("findings");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.txt", id.to_hex()));
    let mut note = String::new();
    note.push_str(&format!("finding: {}\n", id.to_hex()));
    note.push_str(&format!("kind: {}\n", finding.kind.name()));
    note.push_str(&format!("replay: {}\n", finding.replay.name()));
    note.push_str(&format!("ledger seq: {seq}\n"));
    note.push_str(&format!("coordinate: {coord_hex}\n"));
    note.push_str(&format!("input bytes: {}\n", finding.input.len()));
    if !stderr.is_empty() {
        note.push_str("---- worker stderr tail ----\n");
        note.push_str(stderr);
        if !stderr.ends_with('\n') {
            note.push('\n');
        }
    }
    std::fs::write(&path, note)?;
    Ok(())
}

/// Extract little-endian `width`-byte value bytes.
fn value_bytes(v: u64, width: u8) -> Vec<u8> {
    let le = v.to_le_bytes();
    le[..(width as usize).min(8)].to_vec()
}

/// A token is interesting if it is nonzero and not all-FF (magic-ish).
fn is_interesting_token(bytes: &[u8]) -> bool {
    bytes.iter().any(|b| *b != 0) && !bytes.iter().all(|b| *b == 0xFF)
}

/// Campaign object payload (deterministic; no timestamps/paths).
fn encode_campaign(cfg: &CampaignConfig) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(1u8); // version
    out.extend_from_slice(&cfg.policy.seed.to_le_bytes());
    push_str(&mut out, &cfg.target_name, 256)?;
    push_str(&mut out, &cfg.rustc_release, 512)?;
    push_str(&mut out, &cfg.llvm_version, 512)?;
    out.push(cfg.sanitizer.wire_mode());
    out.extend_from_slice(&(cfg.policy.workers as u32).to_le_bytes());
    out.extend_from_slice(&cfg.policy.batch_size.to_le_bytes());
    out.extend_from_slice(&cfg.policy.timeout_ms.to_le_bytes());
    let flags = cfg.instrument_flags.join(" ");
    push_str(&mut out, &flags, 4096)?;
    Ok(out)
}

fn push_str(out: &mut Vec<u8>, s: &str, limit: usize) -> Result<()> {
    if s.len() > limit {
        return Err(Error::BoundExceeded {
            what: "campaign metadata string",
            limit: limit as u64,
            got: s.len() as u64,
        });
    }
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Checkpoint payload: campaign id + counts + per-parent next indices.
fn encode_checkpoint(
    campaign_id: &ContentId,
    index: &CorpusIndex,
    executions: u64,
    findings: u64,
    next_index: &BTreeMap<[u8; 8], u64>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(1u8); // version
    out.extend_from_slice(campaign_id.as_bytes());
    out.extend_from_slice(&executions.to_le_bytes());
    out.extend_from_slice(&findings.to_le_bytes());
    out.extend_from_slice(&(index.len() as u64).to_le_bytes());
    out.extend_from_slice(&(next_index.len() as u64).to_le_bytes());
    for (short, idx) in next_index {
        out.extend_from_slice(short);
        out.extend_from_slice(&idx.to_le_bytes());
    }
    Ok(out)
}

/// Load per-parent next indices from the latest checkpoint (resume support).
fn load_checkpoint_next_index(
    store: &Store,
    root: &std::path::Path,
) -> Result<BTreeMap<[u8; 8], u64>> {
    let Some(id) = refs::get_ref(root, "checkpoint-current")? else {
        return Ok(BTreeMap::new());
    };
    let Some(payload) = store.get(&id)? else {
        return Ok(BTreeMap::new());
    };
    // Bounded manual cursor over the payload.
    let mut pos = 0usize;
    let take = |n: usize, pos: &mut usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > payload.len() {
            return Err(Error::Encoding("checkpoint truncated"));
        }
        let out = &payload[*pos..end];
        *pos = end;
        Ok(out)
    };
    let version = take(1, &mut pos)?[0];
    if version != 1 {
        return Err(Error::UnsupportedVersion {
            family: "checkpoint",
            version: version as u32,
        });
    }
    let _campaign = take(32, &mut pos)?;
    let _execs = u64::from_le_bytes(take(8, &mut pos)?.try_into().unwrap());
    let _findings = u64::from_le_bytes(take(8, &mut pos)?.try_into().unwrap());
    let _entries = u64::from_le_bytes(take(8, &mut pos)?.try_into().unwrap());
    let count = u64::from_le_bytes(take(8, &mut pos)?.try_into().unwrap());
    if count > (1 << 24) {
        return Err(Error::BoundExceeded {
            what: "checkpoint next-index entries",
            limit: 1 << 24,
            got: count,
        });
    }
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let short: [u8; 8] = take(8, &mut pos)?.try_into().unwrap();
        let idx = u64::from_le_bytes(take(8, &mut pos)?.try_into().unwrap());
        map.insert(short, idx);
    }
    Ok(map)
}

fn hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0xf) as usize] as char);
    }
    s
}
