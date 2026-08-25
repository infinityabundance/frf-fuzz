//! The campaign coordinator (coordinator feature).
//!
//! Owns the escalation ladder's coordinator side: seeds the corpus, rebuilds
//! the durable observation state (lineages, regime observers, morphology
//! signatures, state features), dispatches EXPLORE/AMPLIFY work orders,
//! processes results into admissions, writes durable boundaries (tapes,
//! regime episodes, boundary witnesses), and handles worker deaths via the
//! crash ledger.
//!
//! # Phase-2 determinism contract
//!
//! Every admitted entry advances exactly one lineage (root, edge mutator).
//! The lineage accumulator and regime observers are replayed from durable
//! `CorpusMeta` signals (in `admission_seq` order) at rebuild; the
//! recomputed morphology ID must equal the stored one (corruption fails
//! closed, I13). Closed regime episodes are re-derived identically
//! (content-addressed, so re-writing them is idempotent).

use crate::boundary::minimize::byte_distance;
use crate::boundary::witness::{BoundaryRelation, BoundaryWitness, WitnessVerification};
use crate::canon::Family;
use crate::corpus::admission::{decide as admission_decide, ResidualInput};
use crate::corpus::entry::{self, AdmissionReason, CorpusMeta};
use crate::corpus::CorpusIndex;
use crate::dsfb::morphology::{classify, LineageAccumulator, MorphologySignature};
use crate::dsfb::regime::{RegimeConfig, RegimeEpisode, RegimeObserver};
use crate::error::{Error, Result};
use crate::execute::finding::{self, Finding, FindingKind, ReplayStatus};
use crate::execute::worker_process::{SanitizerMode, WorkerEvent, WorkerHandle};
use crate::id::ContentId;
use crate::mutation::{CmpHit, CounterRng, MutationCoordinate, MutationInput};
use crate::observe::residual::MutationResidual;
use crate::observe::signals::encode_signal_schema;
use crate::observe::sketch::{batch_drifts, drift_priority, state_buckets};
use crate::scheduler::policy::{AmplifyEntry, OrderPlanner, SchedulePolicy, SchedulingClass};
use crate::scheduler::work_order::{self, ExecutionStatus, WorkOrder, WorkResult};
use crate::store::refs;
use crate::store::Store;
use crate::tape::model::{
    build_digest, encode_tape, environment_digest, RunTape, TapeLineage, TapeObservation,
    TapeSource, TerminationStatus,
};
use crate::target_runtime::signals::{ResidualSketch, SignalId, SignalVector};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A worker that dies before producing any result this many times in a row
/// is a broken binary, not a fuzzing artifact.
const MAX_STARTUP_DEATHS: u32 = 8;
/// Heartbeat interval when nothing has arrived.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Per-lane event poll timeout (bounds the coordinator's idle wait).
const AWAIT_POLL: Duration = Duration::from_millis(25);
/// Shutdown grace for workers.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Hard cap on live amplify-queue entries (bounded scheduling; §21).
const MAX_AMPLIFY_ENTRIES: usize = 4096;
/// One-shot freshness boost applied when an amplify frontier advances (the
/// next batch's drift recomputes the priority, so the boost is ephemeral).
const AMPLIFY_HOT_BOOST: u64 = 1 << 32;

/// Campaign configuration.
#[derive(Debug, Clone)]
pub struct CampaignConfig {
    /// The instrumented target binary path.
    pub target_bin: PathBuf,
    /// The store root.
    pub store_root: PathBuf,
    /// Scheduling policy (workers, batch size, seed, residual flags).
    pub policy: SchedulePolicy,
    /// Sanitizer mode.
    pub sanitizer: SanitizerMode,
    /// Optional RLIMIT_AS per worker in MiB.
    pub memory_limit_mb: u64,
    /// Seed inputs directory (None = empty-input default).
    pub seed_dir: Option<PathBuf>,
    /// Target name (campaign metadata + tape digests).
    pub target_name: String,
    /// Maximum campaign wall-clock time.
    pub max_time: Option<Duration>,
    /// Maximum executions.
    pub max_execs: Option<u64>,
    /// Initial user dictionary.
    pub initial_dictionary: Vec<Vec<u8>>,
    /// rustc release line (metadata + tape digests).
    pub rustc_release: String,
    /// LLVM version line (metadata + tape digests).
    pub llvm_version: String,
    /// The exact instrumented-build flags.
    pub instrument_flags: Vec<String>,
}

/// Campaign summary (reported by the CLI).
#[derive(Debug, Clone)]
pub struct CampaignSummary {
    /// Campaign object id.
    pub campaign_id: ContentId,
    /// Executions attempted.
    pub executions: u64,
    /// Corpus entries.
    pub corpus_entries: usize,
    /// Distinct coverage features.
    pub features: usize,
    /// Findings recorded.
    pub findings: u64,
    /// Duration.
    pub duration: Duration,
    /// Whether the campaign ended gracefully (interrupt/time/max-execs).
    pub graceful: bool,
    /// Distinct (signal, value bucket) state features.
    pub state_features: usize,
    /// Distinct morphology signatures.
    pub morphologies: usize,
    /// Closed regime episodes.
    pub regimes: u64,
    /// Regime trajectories still open at campaign end (re-derivable).
    pub open_episodes: usize,
    /// Boundary witnesses written.
    pub boundaries: u64,
    /// Run tapes written.
    pub tapes: u64,
    /// AMPLIFY orders dispatched.
    pub amplify_orders: u64,
}

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
    INTERRUPTED.store(true, Ordering::Relaxed);
}

/// The coordinator's durable-state bookkeeping (Phase 2).
struct CampaignState {
    cfg: CampaignConfig,
    /// Global (signal, value-bucket) state-feature set (bounded).
    state_features: std::collections::BTreeSet<(u16, u8)>,
    /// Global morphology *structural identities* (admission novelty is a
    /// new shape, not a new magnitude/persistence bin — otherwise a drifting
    /// trajectory floods the corpus, a Phase-2 finding).
    morph_identities: std::collections::BTreeSet<u64>,
    /// Per-(root, mutator) lineage state.
    lineages: BTreeMap<(ContentId, u16), LineageState>,
    /// Live amplify queue: (frontier, mutator) -> entry.
    amplify: BTreeMap<(ContentId, u16), AmplifyEntry>,
    /// Global admission sequence (checkpointed).
    admission_seq: u64,
    /// The regime configuration (campaign-constant).
    regime_cfg: RegimeConfig,
    /// Counters.
    closed_episodes: u64,
    boundaries: u64,
    tapes: u64,
    amplify_orders: u64,
    /// Schema digest already stored (content-addressed; ref recorded).
    schema_ref: Option<ContentId>,
    /// The target's signal schema (for inspection names).
    schema: Option<crate::target_runtime::signals::SignalSchema>,
    /// Canonical build/env digests for tapes.
    build: [u8; 32],
    env: [u8; 32],
}

/// One lineage's coordinator-side state.
struct LineageState {
    acc: LineageAccumulator,
    /// Per-signal regime observers (created lazily on first movement).
    observers: BTreeMap<u16, RegimeObserver>,
    /// The frontier entry (latest admitted descendant).
    frontier: ContentId,
    /// Edge counter (regime ordinal; deterministic).
    ordinal: u64,
}

impl LineageState {
    fn new() -> LineageState {
        LineageState {
            acc: LineageAccumulator::new(),
            observers: BTreeMap::new(),
            frontier: ContentId::new(b""),
            ordinal: 0,
        }
    }
}

impl CampaignState {
    fn new(cfg: &CampaignConfig) -> CampaignState {
        CampaignState {
            cfg: cfg.clone(),
            state_features: std::collections::BTreeSet::new(),
            morph_identities: std::collections::BTreeSet::new(),
            lineages: BTreeMap::new(),
            amplify: BTreeMap::new(),
            admission_seq: 0,
            regime_cfg: RegimeConfig::default_config(),
            closed_episodes: 0,
            boundaries: 0,
            tapes: 0,
            amplify_orders: 0,
            schema_ref: None,
            schema: None,
            build: build_digest(
                &cfg.target_name,
                &cfg.rustc_release,
                &cfg.llvm_version,
                &cfg.instrument_flags,
            ),
            env: environment_digest(
                &cfg.target_name,
                &cfg.rustc_release,
                &cfg.llvm_version,
                cfg.sanitizer.wire_mode(),
            ),
        }
    }

    /// The seed ancestor of an entry (deterministic walk; no cache — the
    /// walk is O(depth) and lineages are shallow).
    fn root_of(&self, index: &CorpusIndex, id: &ContentId) -> Option<ContentId> {
        index.root_of(id)
    }

    /// Rebuild all derived state from the durable corpus (deterministic
    /// replay in admission order; verifies stored morphology IDs — a
    /// mismatch is corruption, I13).
    fn rebuild(&mut self, store: &Store, index: &CorpusIndex) -> Result<()> {
        for meta in index.by_admission_order() {
            self.admission_seq = self.admission_seq.max(meta.admission_seq.saturating_add(1));
            for (s, b) in state_buckets(&meta.signals) {
                self.state_features.insert((s, b));
            }
            let Some(mutator) = meta.mutator_id else {
                continue; // seeds are baselines, not lineage edges
            };
            let root = index
                .root_of(&meta.entry_id)
                .ok_or_else(|| Error::Other("corrupt lineage root".into()))?;
            let key = (root, mutator);
            let parent_signals = meta
                .parent_id
                .and_then(|p| index.meta(&p))
                .map(|m| m.signals.clone())
                .unwrap_or_default();
            let edge = MutationResidual::of(&meta.signals, &parent_signals);
            let ls = self.lineages.entry(key).or_insert_with(|| {
                let mut ls = LineageState::new();
                if let Some(root_meta) = index.meta(&root) {
                    ls.acc.init_baseline(&root_meta.signals);
                }
                ls
            });
            let mut acc_clone = ls.acc.clone();
            let morph = acc_clone.push(&edge, meta.generation);
            let computed_id = morphology_obj_id(&morph.encode()?)?;
            if let Some(stored) = meta.morphology_id {
                if stored != computed_id {
                    return Err(Error::Other(format!(
                        "corpus-meta {} morphology {} disagrees with replayed derivation {} (corruption or version drift)",
                        meta.entry_id,
                        stored,
                        computed_id
                    )));
                }
            }
            ls.acc = acc_clone;
            ls.frontier = meta.entry_id;
            ls.ordinal = ls.ordinal.saturating_add(1);
            self.morph_identities.insert(morph.structural_identity());
            // Regime feeds on the moved axes. Episodes are collected and
            // written after the observer loop (borrow discipline).
            let mut closed: Vec<(u16, RegimeEpisode)> = Vec::new();
            for i in 0..crate::target_runtime::signals::MAX_SIGNALS {
                if edge.moved() & (1u64 << i) != 0 {
                    let obs = ls
                        .observers
                        .entry(i as u16)
                        .or_insert_with(|| RegimeObserver::new(self.regime_cfg));
                    if let Some(ep) = obs.feed(ls.ordinal, edge.child.value(SignalId(i as u16))) {
                        closed.push((i as u16, ep));
                    }
                }
            }
            for (signal, ep) in closed {
                self.write_episode(store, signal, ep)?;
            }
        }
        Ok(())
    }

    /// Persist a closed regime episode (content-addressed; idempotent).
    fn write_episode(&mut self, store: &Store, signal: u16, mut ep: RegimeEpisode) -> Result<()> {
        ep.signal = signal;
        let payload = crate::dsfb::regime::encode_episode(&ep)?;
        store.put(Family::RegimeEpisode, &payload)?;
        self.closed_episodes = self.closed_episodes.saturating_add(1);
        Ok(())
    }

    /// Persist the signal schema (content-addressed) and record its ref.
    fn store_schema(
        &mut self,
        store: &Store,
        schema: &crate::target_runtime::signals::SignalSchema,
    ) -> Result<ContentId> {
        let payload = encode_signal_schema(schema)?;
        let id = store.put(Family::SignalSchema, &payload)?;
        self.schema_ref = Some(id);
        self.schema = Some(*schema);
        Ok(id)
    }

    /// The regime observers that are currently InEpisode (for the summary).
    fn open_episode_count(&self) -> usize {
        self.lineages
            .values()
            .flat_map(|ls| ls.observers.values())
            .filter(|o| o.episode_open())
            .count()
    }
}

/// The morphology object ID for a canonical payload (the store's identity
/// rule: BLAKE3 over the framed object).
fn morphology_obj_id(payload: &[u8]) -> Result<ContentId> {
    let framed = crate::canon::frame(
        Family::MorphologySignature,
        crate::canon::MAJOR,
        crate::canon::MINOR,
        payload,
    )?;
    Ok(ContentId::new(&framed))
}

/// Run a campaign to completion. The caller has already installed the
/// SIGINT handler if desired.
pub fn run_campaign(cfg: &CampaignConfig) -> Result<CampaignSummary> {
    let store = Store::open(cfg.store_root.clone())?;
    let mut index = CorpusIndex::rebuild(&store)?;
    let mut state = CampaignState::new(cfg);

    // ---- campaign object ----
    let campaign_payload = encode_campaign(cfg)?;
    let campaign_id = store.put(Family::Campaign, &campaign_payload)?;
    refs::set_ref(&cfg.store_root, "campaign-current", &campaign_id)?;

    // ---- dictionary ----
    let mut dictionary = cfg.initial_dictionary.clone();
    let mut dict_consts: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    let mut dict_const_count = 0usize;

    // ---- workers ----
    let mut workers: Vec<Option<WorkerHandle>> = Vec::new();
    for lane in 0..cfg.policy.workers as u16 {
        workers.push(Some(spawn_worker(cfg, &store, lane)?));
    }
    // Record the schema from the first worker's hello (content-addressed).
    if let Some(w) = workers.first().and_then(|w| w.as_ref()) {
        if !w.hello.schema.is_empty() {
            let schema = work_order::wire_to_schema(&w.hello.schema)?;
            let id = state.store_schema(&store, &schema)?;
            refs::set_ref(&cfg.store_root, "signal-schema-current", &id)?;
        }
    }

    // ---- rebuild derived state from the durable corpus ----
    state.rebuild(&store, &index)?;

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
            // Phase 2: the seed's recorded observation (signals).
            let signals = result.override_signals;
            admit_seed(&store, &mut index, seed, &features, &signals, &mut state)?;
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
            // Scheduling class: EXPLORE vs AMPLIFY (WRR, deterministic).
            let class = planner.pick_class(!state.amplify.is_empty());
            let mut is_amplify = false;
            let (parent_id, plan) = if class == SchedulingClass::Amplify {
                // Highest-priority drifting lineage (ties: lowest key).
                let entry = state
                    .amplify
                    .iter()
                    .max_by(|a, b| a.1.priority.cmp(&b.1.priority).then_with(|| b.0.cmp(a.0)))
                    .map(|(_, e)| e.clone());
                let Some(entry) = entry else {
                    break 'outer; // queue drained between pick and use
                };
                let parent_meta = index
                    .meta(&entry.parent)
                    .expect("amplify frontier must exist");
                let start = *next_index.entry(parent_meta.entry_id.short()).or_insert(0);
                let plan = planner.plan_amplify(
                    lane,
                    &entry,
                    parent_meta.generation.saturating_add(1),
                    start,
                );
                state.amplify_orders = state.amplify_orders.saturating_add(1);
                is_amplify = true;
                (entry.parent, plan)
            } else {
                let Some(parent_id) = index.pick_parent(&mut rng) else {
                    break 'outer; // no corpus
                };
                let parent_meta = index.meta(&parent_id).expect("picked parent must exist");
                let start = *next_index.entry(parent_id.short()).or_insert(0);
                let plan =
                    planner.plan_for(lane, parent_id.short(), parent_meta.generation + 1, start);
                (parent_id, plan)
            };
            let parent_meta = index.meta(&parent_id).expect("parent must exist");
            let parent_bytes = store.get(&parent_id)?.unwrap_or_default();
            let parent_signals = parent_meta.signals.clone();
            let mut plan = plan;
            plan.count = plan
                .count
                .min(work_order::MAX_DISCOVERIES_PER_RESULT as u64);
            *next_index.entry(parent_id.short()).or_insert(0) =
                start_of(&plan, &next_index, parent_id.short());
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
                parent_signals,
                partner_bytes,
                &dict_slice,
                &deltas,
            );
            let pend = PendingOrder {
                order: order.clone(),
                parent_id,
                parent_generation: parent_meta.generation,
                is_override: false,
                is_amplify,
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
                                &mut state,
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
                                    "[campaign] execs={} corpus={} features={} state={} morph={} episodes={} amplify={} findings={}",
                                    executions,
                                    index.len(),
                                    index.feature_count(),
                                    state.state_features.len(),
                                    state.morph_identities.len(),
                                    state.closed_episodes,
                                    state.amplify.len(),
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
                            &mut index,
                            &mut state,
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
        if INTERRUPTED.load(Ordering::Relaxed) {
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
    let checkpoint_payload = encode_checkpoint(
        &campaign_id,
        &index,
        executions,
        findings,
        &next_index,
        state.admission_seq,
    )?;
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
        state_features: state.state_features.len(),
        morphologies: state.morph_identities.len(),
        regimes: state.closed_episodes,
        open_episodes: state.open_episode_count(),
        boundaries: state.boundaries,
        tapes: state.tapes,
        amplify_orders: state.amplify_orders,
    })
}

/// The planned start index of a plan (the coordinator already advanced
/// `next_index` when building the plan; this helper recomputes it).
fn start_of(
    plan: &crate::scheduler::policy::OrderPlan,
    next: &BTreeMap<[u8; 8], u64>,
    parent: [u8; 8],
) -> u64 {
    let cur = next.get(&parent).copied().unwrap_or(0);
    cur.wrapping_add(plan.count)
}

/// A work order we sent and have not yet processed a result for.
struct PendingOrder {
    order: WorkOrder,
    parent_id: ContentId,
    parent_generation: u32,
    is_override: bool,
    is_amplify: bool,
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
        parent_signals: SignalVector::new(),
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

/// Admit one seed: entry object + metadata + index insert + seed tape.
fn admit_seed(
    store: &Store,
    index: &mut CorpusIndex,
    input: &[u8],
    features: &[u64],
    signals: &SignalVector,
    state: &mut CampaignState,
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
        signals: signals.clone(),
        mutator_id: None,
        morphology_id: None,
        admission_seq: state.admission_seq,
    };
    state.admission_seq = state.admission_seq.saturating_add(1);
    let payload = entry::encode_meta(&meta)?;
    store.put(Family::CorpusMeta, &payload)?;
    index.insert_meta(meta)?;
    for (s, b) in state_buckets(signals) {
        state.state_features.insert((s, b));
    }
    // Seed tape (the baseline observation is a durable boundary).
    let tape = RunTape {
        build_digest: state.build,
        environment_digest: state.env,
        candidate: input.to_vec(),
        coordinate: None,
        scheduler_mode: 2,
        observation: Some(TapeObservation {
            features: features.to_vec(),
            signals: signals.clone(),
            sketch: ResidualSketch::zeroed(),
            cmp_events: Vec::new(),
            time_bucket: 0,
        }),
        termination: TerminationStatus::Ok,
        lineage: None,
        source: TapeSource::Seed,
    };
    let payload = encode_tape(&tape)?;
    store.put(Family::RunTape, &payload)?;
    state.tapes = state.tapes.saturating_add(1);
    Ok(())
}

/// Process one work result: admissions, lineage/regime/morphology updates,
/// amplify-queue updates, and dictionary growth.
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
    state: &mut CampaignState,
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

    // ---- Phase 2: batch-drift -> amplify queue ----
    if state.cfg.policy.residual && result.signal_summary.touched != 0 {
        let drifts = batch_drifts(
            &result.signal_summary,
            state.cfg.policy.amplify_min_count,
            state.cfg.policy.amplify_min_run,
            state.cfg.policy.amplify_min_sum_bucket,
        );
        let key = (pend.parent_id, pend.order.mutator_id);
        if drifts.is_empty() {
            state.amplify.remove(&key);
        } else {
            let priority = drift_priority(&drifts);
            state.amplify.insert(
                key,
                AmplifyEntry {
                    parent: pend.parent_id,
                    mutator: pend.order.mutator_id,
                    priority,
                },
            );
            // Bound the queue: drop the lowest-priority entries beyond the
            // cap (deterministic: iterate in key order, keep highest).
            if state.amplify.len() > MAX_AMPLIFY_ENTRIES {
                let mut entries: Vec<(crate::id::ContentId, u16, u64)> = state
                    .amplify
                    .iter()
                    .map(|((p, m), e)| (*p, *m, e.priority))
                    .collect();
                entries.sort_by(|a, b| {
                    b.2.cmp(&a.2)
                        .then_with(|| a.0.cmp(&b.0))
                        .then_with(|| a.1.cmp(&b.1))
                });
                let mut kept = std::collections::BTreeSet::new();
                for (p, m, _) in entries.into_iter().take(MAX_AMPLIFY_ENTRIES) {
                    kept.insert((p, m));
                }
                state.amplify.retain(|k, _| kept.contains(k));
            }
        }
    }

    for d in &result.discoveries {
        if d.status != ExecutionStatus::Ok {
            // Live worker statuses are always Ok; non-Ok here is a protocol
            // anomaly. Defensive: record it, don't crash.
            continue;
        }
        // Reconstruct the candidate input from the coordinate (I2; the
        // discovery now carries the exact cmp hits the mutation used).
        let input = reconstruct_candidate(pend, d)?;

        // ---- Phase 2 residual observation ----
        let edge = MutationResidual::of(&d.signals, &pend.order.parent_signals);
        let mut residual = ResidualInput::default();
        if state.cfg.policy.residual {
            // Candidate state features (globally new buckets; inserted only
            // on admission so the corpus stays the memory).
            let mut new_state = Vec::new();
            for (s, b) in state_buckets(&d.signals) {
                if !state.state_features.contains(&(s, b)) {
                    new_state.push((s, b));
                }
            }
            // Lineage position: compute the tentative morphology on a clone
            // (only committed if the entry is admitted).
            let (morph, morph_id, is_new_morph) =
                tentative_morphology(state, index, pend, &edge, d)?;
            residual = ResidualInput {
                edge: Some(edge.clone()),
                new_state,
                new_morphology: is_new_morph,
                morph_class: Some(classify(&morph)),
            };
            let _ = morph_id;
        }

        let admission = admission_decide(
            index,
            &d.features,
            false,
            if state.cfg.policy.residual {
                Some(&residual)
            } else {
                None
            },
            state.cfg.policy.residual,
        );
        let Some(admission) = admission else {
            continue;
        };
        let entry_id = store.put(Family::CorpusEntry, &input)?;
        if index.meta(&entry_id).is_some() {
            continue; // already known
        }
        // Commit the lineage accumulator clone (the entry is admitted).
        let (morph, morph_id) = commit_morphology(state, index, pend, &edge, d)?;
        if let Some(_mid) = morph_id {
            let payload = morph.encode()?;
            store.put(Family::MorphologySignature, &payload)?;
            state.morph_identities.insert(morph.structural_identity());
        }
        // Insert the new state features (admission commits them).
        for (s, b) in state_buckets(&d.signals) {
            state.state_features.insert((s, b));
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
            signals: d.signals.clone(),
            mutator_id: Some(d.coordinate.mutator_id.id()),
            morphology_id: morph_id,
            admission_seq: state.admission_seq,
        };
        state.admission_seq = state.admission_seq.saturating_add(1);
        let payload = entry::encode_meta(&meta)?;
        store.put(Family::CorpusMeta, &payload)?;
        index.insert_meta(meta)?;
        admitted += 1;
        for f in &admission.novel {
            if !new_global.contains(f) {
                new_global.push(*f);
            }
        }

        // ---- lineage / regime / amplify updates ----
        let root = state
            .root_of(index, &pend.parent_id)
            .unwrap_or(pend.parent_id);
        let mutator = d.coordinate.mutator_id.id();
        let key = (root, mutator);
        let ls = state.lineages.entry(key).or_insert_with(|| {
            let mut ls = LineageState::new();
            if let Some(root_meta) = index.meta(&root) {
                ls.acc.init_baseline(&root_meta.signals);
            }
            ls
        });
        ls.frontier = entry_id;
        ls.ordinal = ls.ordinal.saturating_add(1);
        // Regime feeds on the moved axes. Episodes are collected and
        // written after the observer loop (borrow discipline).
        let mut closed: Vec<(u16, RegimeEpisode)> = Vec::new();
        for i in 0..crate::target_runtime::signals::MAX_SIGNALS {
            if edge.moved() & (1u64 << i) != 0 {
                let obs = ls
                    .observers
                    .entry(i as u16)
                    .or_insert_with(|| RegimeObserver::new(state.regime_cfg));
                if let Some(ep) = obs.feed(ls.ordinal, edge.child.value(SignalId(i as u16))) {
                    closed.push((i as u16, ep));
                }
            }
        }
        for (signal, ep) in closed {
            state.write_episode(store, signal, ep)?;
        }
        // Frontier advance in the amplify queue: the new child continues the
        // drifting lineage (same mutator). The priority gets a one-shot
        // freshness boost so the just-advanced frontier is re-probed next
        // (the next batch's drift recomputes the priority and the boost
        // decays): this is what lets a ladder climb one rung per order
        // instead of waiting for the uniform queue.
        if let Some(entry) = state.amplify.get(&(pend.parent_id, mutator)).cloned() {
            state.amplify.remove(&(pend.parent_id, mutator));
            state.amplify.insert(
                (entry_id, mutator),
                AmplifyEntry {
                    parent: entry_id,
                    mutator,
                    priority: entry.priority.saturating_add(AMPLIFY_HOT_BOOST),
                },
            );
        }

        // ---- durable tape for residual-interest admissions ----
        let is_residual_admission = matches!(
            admission.reason,
            AdmissionReason::NewStateFeature
                | AdmissionReason::NewMorphology
                | AdmissionReason::StructuredUnknown
        );
        if is_residual_admission {
            let tape = RunTape {
                build_digest: state.build,
                environment_digest: state.env,
                candidate: input,
                coordinate: Some(d.coordinate),
                scheduler_mode: if pend.is_amplify { 1 } else { 0 },
                observation: Some(TapeObservation {
                    features: d.features.clone(),
                    signals: d.signals.clone(),
                    sketch: d.sketch,
                    cmp_events: d.cmp_events.clone(),
                    time_bucket: d.time_bucket,
                }),
                termination: TerminationStatus::Ok,
                lineage: Some(TapeLineage { root, mutator }),
                source: TapeSource::Admission,
            };
            let payload = encode_tape(&tape)?;
            store.put(Family::RunTape, &payload)?;
            state.tapes = state.tapes.saturating_add(1);
        }
    }
    Ok((admitted, new_global))
}

/// Compute the tentative morphology for a discovery WITHOUT committing the
/// lineage accumulator (a rejected execution must not advance lineage
/// state). Returns (signature, id, is_new).
fn tentative_morphology(
    state: &CampaignState,
    index: &CorpusIndex,
    pend: &PendingOrder,
    edge: &MutationResidual,
    d: &work_order::DiscoveryRecord,
) -> Result<(MorphologySignature, Option<ContentId>, bool)> {
    let mutator = d.coordinate.mutator_id.id();
    let root = state
        .root_of(index, &pend.parent_id)
        .unwrap_or(pend.parent_id);
    let key = (root, mutator);
    let mut acc = match state.lineages.get(&key) {
        Some(ls) => ls.acc.clone(),
        None => {
            let mut acc = LineageAccumulator::new();
            if let Some(root_meta) = index.meta(&root) {
                acc.init_baseline(&root_meta.signals);
            }
            acc
        }
    };
    let morph = acc.push(edge, pend.parent_generation + 1);
    let id = morphology_obj_id(&morph.encode()?)?;
    let is_new = !state
        .morph_identities
        .contains(&morph.structural_identity());
    Ok((morph, Some(id), is_new))
}

/// Commit the lineage accumulator for an admitted entry (the counterpart of
/// `tentative_morphology`; the accumulator's clone is stored).
fn commit_morphology(
    state: &mut CampaignState,
    index: &CorpusIndex,
    pend: &PendingOrder,
    edge: &MutationResidual,
    d: &work_order::DiscoveryRecord,
) -> Result<(MorphologySignature, Option<ContentId>)> {
    let mutator = d.coordinate.mutator_id.id();
    let root = state
        .root_of(index, &pend.parent_id)
        .unwrap_or(pend.parent_id);
    let key = (root, mutator);
    let ls = state.lineages.entry(key).or_insert_with(|| {
        let mut ls = LineageState::new();
        if let Some(root_meta) = index.meta(&root) {
            ls.acc.init_baseline(&root_meta.signals);
        }
        ls
    });
    let mut acc_clone = ls.acc.clone();
    let morph = acc_clone.push(edge, pend.parent_generation + 1);
    let id = morphology_obj_id(&morph.encode()?)?;
    ls.acc = acc_clone;
    Ok((morph, Some(id)))
}

/// Reconstruct the candidate bytes for a discovery from the pending order's
/// parent and the coordinate (I2; the mutation engine is shared code, and
/// the discovery carries the exact compare hits the mutation consumed).
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
        let cmp_hits: Vec<CmpHit> = d.cmp_hits_used.iter().map(|h| h.to_hit()).collect();
        let mut input = MutationInput {
            parent,
            rng: &mut rng,
            dictionary: &dict_refs,
            cmp_hits: &cmp_hits,
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

/// Handle a worker death: read the ledger, record a finding, write the
/// crash tape + boundary witness, restart.
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
    index: &mut CorpusIndex,
    state: &mut CampaignState,
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

        // ---- Phase 2: crash tape + boundary witness ----
        let crash_lineage = pend.as_ref().and_then(|p| {
            if p.is_override {
                None
            } else {
                state.root_of(index, &p.parent_id).map(|root| TapeLineage {
                    root,
                    mutator: p.order.mutator_id,
                })
            }
        });
        write_crash_tape(store, state, &finding, crash_lineage)?;
        if let Some(p) = pend.as_ref() {
            if !p.is_override {
                if let Some(parent_id) = index.entry_by_short(finding.parent_short) {
                    if let Some(parent_input) = store.get(&parent_id)? {
                        let distance = byte_distance(&parent_input, &input);
                        let witness = BoundaryWitness {
                            left: parent_id,
                            right: id,
                            left_input: parent_input,
                            right_input: input.clone(),
                            relation: BoundaryRelation::StableCrash,
                            distance,
                            verification: WitnessVerification::Unverified,
                            tape: None,
                        };
                        let payload = crate::boundary::witness::encode_witness(&witness)?;
                        store.put(Family::BoundaryWitness, &payload)?;
                        state.boundaries = state.boundaries.saturating_add(1);
                    }
                }
            }
            // The drifting lineage reached its terminal boundary: stop
            // amplifying it (the finding + witness are the durable result).
            if p.is_amplify {
                state.amplify.remove(&(p.parent_id, p.order.mutator_id));
            }
        }
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

/// Write the crash finding's run tape (durable boundary; I12).
fn write_crash_tape(
    store: &Store,
    state: &mut CampaignState,
    finding: &Finding,
    lineage: Option<TapeLineage>,
) -> Result<()> {
    let tape = RunTape {
        build_digest: state.build,
        environment_digest: state.env,
        candidate: finding.input.clone(),
        coordinate: MutationCoordinate::decode(&finding.coordinate).ok(),
        scheduler_mode: 0,
        observation: None, // the window never completed
        termination: if finding.kind == FindingKind::Crash {
            TerminationStatus::Crash
        } else {
            TerminationStatus::Timeout
        },
        lineage,
        source: TapeSource::Finding,
    };
    let payload = encode_tape(&tape)?;
    store.put(Family::RunTape, &payload)?;
    state.tapes = state.tapes.saturating_add(1);
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
            is_amplify: p.is_amplify,
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
        cmp_hits_used: Vec::new(),
        signals: SignalVector::new(),
        sketch: ResidualSketch::zeroed(),
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
    out.push(2u8); // version
    out.extend_from_slice(&cfg.policy.seed.to_le_bytes());
    push_str(&mut out, &cfg.target_name, 256)?;
    push_str(&mut out, &cfg.rustc_release, 512)?;
    push_str(&mut out, &cfg.llvm_version, 512)?;
    out.push(cfg.sanitizer.wire_mode());
    out.extend_from_slice(&(cfg.policy.workers as u32).to_le_bytes());
    out.extend_from_slice(&cfg.policy.batch_size.to_le_bytes());
    out.extend_from_slice(&cfg.policy.timeout_ms.to_le_bytes());
    out.push(u8::from(cfg.policy.residual));
    out.extend_from_slice(&cfg.policy.class_weights[0].to_le_bytes());
    out.extend_from_slice(&cfg.policy.class_weights[1].to_le_bytes());
    let flags = cfg.instrument_flags.join(" ");
    push_str(&mut out, &flags, 4096)?;
    Ok(out)
}

fn push_str(out: &mut Vec<u8>, s: &str, limit: usize) -> Result<()> {
    if s.len() > limit {
        return Err(Error::BoundExceeded {
            what: "string field",
            limit: limit as u64,
            got: s.len() as u64,
        });
    }
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Checkpoint payload: campaign id + counters + per-parent next index +
/// the admission sequence (Phase 2).
fn encode_checkpoint(
    campaign_id: &ContentId,
    index: &CorpusIndex,
    executions: u64,
    findings: u64,
    next_index: &BTreeMap<[u8; 8], u64>,
    admission_seq: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(2u8); // version
    out.extend_from_slice(campaign_id.as_bytes());
    out.extend_from_slice(&executions.to_le_bytes());
    out.extend_from_slice(&findings.to_le_bytes());
    out.extend_from_slice(&admission_seq.to_le_bytes());
    out.extend_from_slice(&(index.len() as u64).to_le_bytes());
    out.extend_from_slice(&(next_index.len() as u32).to_le_bytes());
    for (short, idx) in next_index {
        out.extend_from_slice(short);
        out.extend_from_slice(&idx.to_le_bytes());
    }
    Ok(out)
}

/// Load the per-parent next-index map from the checkpoint (deterministic
/// resume of mutation index spaces).
fn load_checkpoint_next_index(
    store: &Store,
    root: &std::path::Path,
) -> Result<BTreeMap<[u8; 8], u64>> {
    let mut out = BTreeMap::new();
    let Some(id) = refs::get_ref(root, "checkpoint-current")? else {
        return Ok(out);
    };
    let Some(payload) = store.get(&id)? else {
        return Ok(out);
    };
    if payload.is_empty() || payload[0] != 2 {
        return Ok(out); // v1 checkpoints predate next_index (or empty)
    }
    let mut pos = 1usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let end = pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > payload.len() {
            return Err(Error::Encoding("checkpoint truncated"));
        }
        let out = &payload[pos..end];
        pos = end;
        Ok(out)
    };
    let _campaign = take(32)?;
    let _executions = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let _findings = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let _admission_seq = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let _entries = u64::from_le_bytes(take(8)?.try_into().unwrap());
    let count = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
    if count > 1 << 24 {
        return Err(Error::BoundExceeded {
            what: "checkpoint parent count",
            limit: 1 << 24,
            got: count as u64,
        });
    }
    for _ in 0..count {
        let short: [u8; 8] = take(8)?.try_into().unwrap();
        let idx = u64::from_le_bytes(take(8)?.try_into().unwrap());
        out.insert(short, idx);
    }
    Ok(out)
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
