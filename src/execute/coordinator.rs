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
use crate::dsfb::debug_bridge::{
    encode_episode_payload, encode_verdict_payload, AxisVerdict, BridgeConfig, DurableVerdict,
    EdgeStructural, LineageSubstrate, StructuralEpisode,
};
use crate::dsfb::fuzz_bank::{classify_evidence, role_of, AxisRole, BankEvidence, FuzzMotif};
use crate::dsfb::morphology::{classify, LineageAccumulator, MorphologySignature};
use crate::dsfb::regime::{RegimeConfig, RegimeEpisode, RegimeObserver};
use crate::error::{Error, Result};
use crate::execute::finding::{self, Finding, FindingKind, ReplayStatus};
use crate::execute::worker_process::{SanitizerMode, WorkerEvent, WorkerHandle};
use crate::frf_bridge::{
    self, AuthoritySpec, CourtQuestion, VerificationOutcome, VerificationRecord,
};
use crate::gemel_bridge::{self, BoundaryKind};
use crate::id::ContentId;
use crate::mutation::{CmpHit, CounterRng, MutationCoordinate, MutationInput};
use crate::observe::residual::MutationResidual;
use crate::observe::signals::encode_signal_schema;
use crate::observe::sketch::{batch_drifts, drift_priority, state_buckets};
use crate::precedent::probe::{evaluate as eval_probe, ProbeOutcome};
use crate::precedent::{
    choose_precursor, create_from_terminal, load_current as load_precedents,
    save_revision as save_precedent_revision, ConfuserKind, Precedent, PrefixProfile, TerminalKind,
};
use crate::scheduler::policy::{
    AmplifyEntry, ClassAvail, OrderPlanner, ProbeEntry, SchedulePolicy, SchedulingClass,
};
use crate::scheduler::work_order::{self, ExecutionStatus, WorkOrder, WorkResult};
use crate::store::refs;
use crate::store::Store;
use crate::tape::model::{
    build_digest, encode_tape, environment_digest, RunTape, TapeLineage, TapeObservation,
    TapeSource, TerminationStatus,
};
use crate::target_runtime::signals::{
    ResidualSketch, SignalId, SignalSchema, SignalVector, MAX_SIGNALS,
};
use std::collections::{BTreeMap, VecDeque};
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
/// Hard cap on the live probe queue (bounded scheduling; §21).
const MAX_PROBE_ENTRIES: usize = 256;
/// Max precedent matches honored per admitted edge (a bounded match storm
/// guard; only the most specific matches get probes).
const MAX_MATCHES_PER_EDGE: usize = 2;
/// How many structured signatures each lineage keeps for precedent
/// creation (bounded memory; oldest dropped).
const LINEAGE_HISTORY_CAP: usize = 8;
/// Default probe recipe thresholds (the falsifiable relationship derived at
/// precedent creation: the axis that historically drifted must keep moving
/// across at least a quarter of the batch, with a persistent run).
const PROBE_MIN_RUN: u8 = 4;
const PROBE_MIN_BUCKET: u8 = 3;

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
    /// Optional FRF authority: when configured, promoted (replay-confirmed)
    /// crash/timeout findings are court-verified at promotion (Level 2) and
    /// the real FRF receipt id is retained verbatim (Phase 4).
    pub authority: Option<AuthoritySpec>,
    /// The court-question binding used for every verification court.
    pub question: CourtQuestion,
    /// The verification candidate executable (must honor the
    /// `--frf-fuzz-fixture <path>` interface; an instrumented frf-fuzz
    /// target binary does). Default: the fuzz target binary itself — for
    /// ASan campaigns, point this at a non-ASan build of the same target.
    pub verification_candidate: Option<PathBuf>,
    /// Compile an FRF baseline claim after verification (explicit opt-in;
    /// disposes the run's residuals as Intentional first).
    pub verify_claim: bool,
    /// Publish durable boundaries into a Gemel repository when one is
    /// present (campaign checkpoints, verified findings, precedents).
    pub gemel: bool,
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
    /// Executions attempted before the first failure finding (crash or
    /// timeout) was recorded, if any occurred.
    pub first_failure_exec: Option<u64>,
    /// Wall time from campaign start to the first failure finding.
    pub first_failure_elapsed: Option<Duration>,
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
    /// Structural verdict objects persisted (Phase 3).
    pub structural_verdicts: u64,
    /// Structural episodes closed + persisted (Phase 3).
    pub structural_episodes: u64,
    /// Precedent revisions persisted (Phase 3).
    pub precedent_revisions: u64,
    /// Precedent families matched against live lineages.
    pub precedent_matches: u64,
    /// Probe orders dispatched.
    pub probes_dispatched: u64,
    /// Probe outcomes (Phase 3).
    pub probe_supports: u64,
    /// Probe contradictions recorded (negative knowledge).
    pub probe_contradictions: u64,
    /// Ambiguous probe outcomes.
    pub probe_ambiguous: u64,
    /// FRF verification records persisted (Phase 4).
    pub frf_verifications: u64,
    /// FRF-verified findings (receipts emitted; Phase 4).
    pub frf_verified: u64,
    /// FRF verification attempts that failed/refused (preserved, Phase 4).
    pub frf_failed: u64,
    /// Local Gemel boundary records written (Phase 4).
    pub gemel_boundaries: u64,
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

/// The coordinator's durable-state bookkeeping (Phase 2 + Phase 3).
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
    /// The DSFB structural substrate per ROOT (all mutator families of a
    /// root share one behavioral stream: the root's admitted evolution in
    /// admission order — Phase 3). Created lazily once a root shows
    /// structure.
    root_dsfb: BTreeMap<ContentId, LineageSubstrate>,
    /// Per-root edge ordinal for the substrate (deterministic).
    root_ordinals: BTreeMap<ContentId, u64>,
    /// Live amplify queue: (frontier, mutator) -> entry.
    amplify: BTreeMap<(ContentId, u16), AmplifyEntry>,
    /// The precedent bank: current revisions keyed by (root, mutator,
    /// profile identity) (Phase 3).
    precedents: BTreeMap<(ContentId, u16, u64), (ContentId, Precedent)>,
    /// The live probe queue: seq -> probe order (Phase 3).
    probes: BTreeMap<u64, ProbeEntry>,
    /// Deterministic probe ordinal counter.
    probe_seq: u64,
    /// Probes currently executing, keyed by the matched lineage
    /// (root, mutator, profile identity) — never by revision id (revisions
    /// change on every update; the key must stay stable or the set would
    /// accumulate stale entries).
    probe_inflight: std::collections::BTreeSet<(ContentId, u16, u64)>,
    /// Global admission sequence (checkpointed).
    admission_seq: u64,
    /// The regime configuration (campaign-constant).
    regime_cfg: RegimeConfig,
    /// The DSFB bridge configuration (campaign-constant; Phase 3).
    bridge_cfg: BridgeConfig,
    /// Per-axis declared roles (filled from the target schema; Phase 3).
    roles: [AxisRole; MAX_SIGNALS],
    /// Counters.
    closed_episodes: u64,
    boundaries: u64,
    tapes: u64,
    amplify_orders: u64,
    structural_verdicts: u64,
    structural_episodes: u64,
    precedent_revisions: u64,
    precedent_matches: u64,
    probes_dispatched: u64,
    probe_supports: u64,
    probe_contradictions: u64,
    probe_ambiguous: u64,
    /// FRF verification records persisted (Phase 4).
    frf_verifications: u64,
    /// FRF-verified findings (receipts emitted).
    frf_verified: u64,
    /// FRF verification attempts that failed (preserved).
    frf_failed: u64,
    /// Local Gemel boundary records written.
    gemel_boundaries: u64,
    /// Executions attempted when the FIRST failure finding was recorded
    /// (crash or timeout; None = no failure occurred).
    first_failure_exec: Option<u64>,
    /// Wall time from campaign start to the first failure finding.
    first_failure_elapsed: Option<std::time::Duration>,
    /// Inputs already court-verified THIS campaign (BLAKE3 over the input
    /// bytes). FRF courts are expensive (they hash the full candidate and
    /// run both sides); a crash flood of identical inputs must not re-run
    /// the same court per finding — the first attempt's durable record
    /// covers every later occurrence (same input + same authority + same
    /// question = same court).
    verified_inputs: std::collections::BTreeSet<[u8; 32]>,
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
    /// Bounded structured-signature history for precedent creation
    /// (oldest first; Phase 3).
    shape_history: VecDeque<(u32, MorphologySignature)>,
    /// The bank nomination of the latest edge (0 = none).
    last_class: u8,
    /// The latest edge's structural verdict summary (for continuation data).
    last_verdict_axis: Option<u16>,
    /// The frontier entry (latest admitted descendant).
    frontier: ContentId,
    /// Lineage edge counter (regime ordinal; deterministic).
    ordinal: u64,
}

impl LineageState {
    fn new() -> LineageState {
        LineageState {
            acc: LineageAccumulator::new(),
            observers: BTreeMap::new(),
            shape_history: VecDeque::new(),
            last_class: 0,
            last_verdict_axis: None,
            frontier: ContentId::new(b""),
            ordinal: 0,
        }
    }

    /// Record a structured signature in the bounded creation history.
    fn push_history(&mut self, depth: u32, sig: &MorphologySignature) {
        if sig.is_trivial() {
            return;
        }
        self.shape_history.push_back((depth, sig.clone()));
        if self.shape_history.len() > LINEAGE_HISTORY_CAP {
            self.shape_history.pop_front();
        }
    }

    /// Record the latest bank nomination and its dominant axis.
    fn record_nomination(&mut self, class: u8, verdicts: &[AxisVerdict]) {
        self.last_class = class;
        if let Some(v) = verdicts.iter().max_by_key(|v| v.policy) {
            self.last_verdict_axis = Some(v.axis);
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
            root_dsfb: BTreeMap::new(),
            root_ordinals: BTreeMap::new(),
            amplify: BTreeMap::new(),
            precedents: BTreeMap::new(),
            probes: BTreeMap::new(),
            probe_seq: 0,
            probe_inflight: std::collections::BTreeSet::new(),
            admission_seq: 0,
            regime_cfg: RegimeConfig::default_config(),
            bridge_cfg: BridgeConfig::default_config(),
            roles: [AxisRole::NONE; MAX_SIGNALS],
            closed_episodes: 0,
            boundaries: 0,
            tapes: 0,
            amplify_orders: 0,
            structural_verdicts: 0,
            structural_episodes: 0,
            precedent_revisions: 0,
            precedent_matches: 0,
            probes_dispatched: 0,
            probe_supports: 0,
            probe_contradictions: 0,
            probe_ambiguous: 0,
            frf_verifications: 0,
            frf_verified: 0,
            frf_failed: 0,
            gemel_boundaries: 0,
            first_failure_exec: None,
            first_failure_elapsed: None,
            verified_inputs: std::collections::BTreeSet::new(),
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

    /// Load the durable precedent bank (Phase 3). Only the current revision
    /// of each family is held in memory; older revisions stay stored.
    fn load_bank(&mut self, store: &Store) -> Result<()> {
        if !self.cfg.policy.residual || !self.cfg.policy.precedent {
            return Ok(());
        }
        // Resolve the object id of each current revision by re-encoding
        // (content addressing is deterministic, so the id of a decoded
        // revision is recomputable).
        for p in load_precedents(store)? {
            let payload = crate::precedent::encode_precedent(&p)?;
            let framed = crate::canon::frame(
                Family::Precedent,
                crate::canon::MAJOR,
                crate::canon::MINOR,
                &payload,
            )?;
            let id = ContentId::new(&framed);
            let key = p.group_key();
            self.precedents.insert(key, (id, p));
        }
        Ok(())
    }

    /// Fill the per-axis role table from the target's registered schema
    /// (Phase 3). Axes without a schema keep [`AxisRole::NONE`].
    fn fill_roles(&mut self, schema: &SignalSchema) {
        for (id, desc) in schema.iter() {
            if let Some(slot) = self.roles.get_mut(id.id() as usize) {
                *slot = role_of(desc);
            }
        }
    }

    /// Feed one admitted edge into its root's DSFB substrate (per-root
    /// behavioral stream; the mutator families of one root share it).
    /// Deterministic; returns the edge's structural summary and the closed
    /// structural episode when this edge completed one.
    fn feed_root_structural(
        &mut self,
        root: &ContentId,
        edge: &MutationResidual,
        generation: u32,
    ) -> Result<(EdgeStructural, Option<StructuralEpisode>)> {
        if !self.root_dsfb.contains_key(root) {
            if edge.moved() == 0 {
                return Ok((
                    EdgeStructural {
                        verdicts: Vec::new(),
                        any_active: false,
                    },
                    None,
                ));
            }
            let sub = LineageSubstrate::new(*root, 0, &self.bridge_cfg)?;
            self.root_dsfb.insert(*root, sub);
            self.root_ordinals.insert(*root, 0);
        }
        let ordinal = self
            .root_ordinals
            .get_mut(root)
            .expect("ordinal just created");
        *ordinal = ordinal.wrapping_add(1);
        let sub = self
            .root_dsfb
            .get_mut(root)
            .expect("substrate just created");
        sub.feed_edge(*ordinal, edge, generation)
    }

    /// The seed ancestor of an entry (deterministic walk; no cache — the
    /// walk is O(depth) and lineages are shallow).
    fn root_of(&self, index: &CorpusIndex, id: &ContentId) -> Option<ContentId> {
        index.root_of(id)
    }

    /// Rebuild all derived state from the durable corpus (deterministic
    /// replay in admission order; verifies stored morphology IDs — a
    /// mismatch is corruption, I13). The DSFB substrate and precedent
    /// history are re-derived in memory so a resumed campaign continues
    /// from the same structural state; nothing new is persisted here.
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
            // Phase 3: re-derive the root substrate + lineage history in
            // memory. The returned verdicts/episodes are dropped (their
            // durable objects were written when the admissions originally
            // happened); only the machine state must be identical for the
            // resume.
            if !morph.is_trivial() {
                ls.push_history(meta.generation, &morph);
            }
            for (signal, ep) in closed {
                self.write_episode(store, signal, ep)?;
            }
            if self.cfg.policy.residual {
                let _ = self.feed_root_structural(&root, &edge, meta.generation)?;
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

    // ---- Phase 4: Gemel campaign-created boundary ----
    // Level-3 durable boundary only; standalone mode writes nothing. A
    // Gemel-side failure is recorded locally, never fatal (I14).
    if cfg.gemel {
        if let Some(id) = gemel_bridge::publish_boundary(
            &store,
            &gemel_project_root(cfg),
            BoundaryKind::CampaignCreated,
            campaign_id,
            None,
        )? {
            state.gemel_boundaries = state.gemel_boundaries.saturating_add(1);
            eprintln!(
                "[campaign] gemel boundary campaign-created -> {}",
                id.to_hex()
            );
        }
    }

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
            state.fill_roles(&schema);
        }
    }

    // ---- load the durable precedent bank (Phase 3) ----
    state.load_bank(&store)?;

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
            // Scheduling class: EXPLORE / AMPLIFY / DISCRIMINATE / FALSIFY
            // (WRR, deterministic over the currently available classes).
            let avail = ClassAvail {
                amplify: !state.amplify.is_empty(),
                discriminate: state
                    .probes
                    .values()
                    .any(|e| e.class == SchedulingClass::Discriminate),
                falsify: state
                    .probes
                    .values()
                    .any(|e| e.class == SchedulingClass::Falsify),
            };
            let class = planner.pick_class(&avail);
            let mut is_amplify = false;
            let mut probe_entry: Option<ProbeEntry> = None;
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
            } else if class == SchedulingClass::Discriminate || class == SchedulingClass::Falsify {
                // The earliest-queued probe of the picked class (deterministic
                // FIFO by queue key).
                let entry = state
                    .probes
                    .iter()
                    .find(|(_, e)| e.class == class)
                    .map(|(seq, e)| (*seq, e.clone()));
                let Some((seq, entry)) = entry else {
                    break 'outer; // queue drained between pick and use
                };
                state.probes.remove(&seq);
                let parent_meta = index
                    .meta(&entry.frontier)
                    .expect("probe frontier must exist");
                let start = *next_index.entry(parent_meta.entry_id.short()).or_insert(0);
                let plan = planner.plan_probe(
                    lane,
                    &entry,
                    parent_meta.generation.saturating_add(1),
                    start,
                    entry.seq,
                );
                state.probes_dispatched = state.probes_dispatched.saturating_add(1);
                state.probe_inflight.insert(probe_key(&entry));
                probe_entry = Some(entry);
                (probe_entry.as_ref().unwrap().frontier, plan)
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
                probe: probe_entry,
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
                            let probe = pend.probe.clone();
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
                            // Phase 3: a probe order's batch result is
                            // evaluated against the precedent's falsifiable
                            // relationship.
                            if let Some(entry) = &probe {
                                record_probe_result(&store, &mut state, entry, &result)?;
                            }
                            for f in new_deltas {
                                if !deltas.contains(&f) {
                                    deltas.push(f);
                                }
                            }
                            executions = executions.saturating_add(result.exec_count);
                            // Log progress periodically.
                            if executions % (cfg.policy.batch_size * 8) < cfg.policy.batch_size {
                                eprintln!(
                                    "[campaign] execs={} corpus={} features={} state={} morph={} episodes={} verdicts={} precedents={} probes={} amplify={} findings={}",
                                    executions,
                                    index.len(),
                                    index.feature_count(),
                                    state.state_features.len(),
                                    state.morph_identities.len(),
                                    state.closed_episodes,
                                    state.structural_verdicts,
                                    state.precedents.len(),
                                    state.probes_dispatched,
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
                        let findings_before = findings;
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
                        if findings > findings_before && state.first_failure_exec.is_none() {
                            state.first_failure_exec = Some(executions);
                            state.first_failure_elapsed = Some(start.elapsed());
                        }
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

    // ---- Phase 4: Gemel campaign-completed boundary ----
    // Level-3 durable boundary on every exit path (graceful or not); the
    // local checkpoint above is always the durable continuation record.
    if cfg.gemel {
        if let Some(id) = gemel_bridge::publish_boundary(
            &store,
            &gemel_project_root(cfg),
            BoundaryKind::CampaignCompleted,
            campaign_id,
            None,
        )? {
            state.gemel_boundaries = state.gemel_boundaries.saturating_add(1);
            eprintln!(
                "[campaign] gemel boundary campaign-completed -> {}",
                id.to_hex()
            );
        }
    }

    Ok(CampaignSummary {
        campaign_id,
        executions,
        corpus_entries: index.len(),
        features: index.feature_count(),
        findings,
        first_failure_exec: state.first_failure_exec,
        first_failure_elapsed: state.first_failure_elapsed,
        duration: start.elapsed(),
        graceful,
        state_features: state.state_features.len(),
        morphologies: state.morph_identities.len(),
        regimes: state.closed_episodes,
        open_episodes: state.open_episode_count(),
        boundaries: state.boundaries,
        tapes: state.tapes,
        amplify_orders: state.amplify_orders,
        structural_verdicts: state.structural_verdicts,
        structural_episodes: state.structural_episodes,
        precedent_revisions: state.precedent_revisions,
        precedent_matches: state.precedent_matches,
        probes_dispatched: state.probes_dispatched,
        probe_supports: state.probe_supports,
        probe_contradictions: state.probe_contradictions,
        probe_ambiguous: state.probe_ambiguous,
        frf_verifications: state.frf_verifications,
        frf_verified: state.frf_verified,
        frf_failed: state.frf_failed,
        gemel_boundaries: state.gemel_boundaries,
    })
}

/// The Gemel discovery root for a campaign: the project directory holding
/// the store (the store root's parent), where the developer's `.gemel`
/// repository lives.
fn gemel_project_root(cfg: &CampaignConfig) -> std::path::PathBuf {
    cfg.store_root
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| cfg.store_root.clone())
}

/// Publish one durable boundary into Gemel when the campaign has it enabled
/// and a repository is present. Standalone mode writes nothing; a Gemel-side
/// failure is recorded locally and counted, never fatal (I14).
fn gemel_publish(
    state: &mut CampaignState,
    store: &Store,
    kind: BoundaryKind,
    subject: ContentId,
    detail: Option<&str>,
) -> Result<()> {
    if !state.cfg.gemel {
        return Ok(());
    }
    if let Some(rec_id) = gemel_bridge::publish_boundary(
        store,
        &gemel_project_root(&state.cfg),
        kind,
        subject,
        detail,
    )? {
        state.gemel_boundaries = state.gemel_boundaries.saturating_add(1);
        eprintln!(
            "[campaign] gemel boundary {} subject={} record={}",
            kind.name(),
            subject,
            rec_id.to_hex()
        );
    }
    Ok(())
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
    /// The probe relationship this order tests (Phase 3), when it was
    /// dispatched from the probe queue.
    probe: Option<ProbeEntry>,
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

    // Dictionary discovery: const-cmp operands become tokens. Gated on the
    // compare channel (Phase 8): with `cmp = off` the campaign is genuinely
    // coverage-only and no compare observation may influence later mutations.
    if state.cfg.policy.cmp {
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
        // Under the residual switch the committed morphology is persisted as
        // a signature object, counted, and linked from the corpus meta; a
        // residual-off campaign keeps NO structural memory (no lineage
        // accumulator, no signature objects, no state-feature buckets — the
        // Phase-8 ablation semantics: coverage-only corpora must show zero
        // morphologies/state-features/regimes). The entry is still admitted
        // by coverage below and its signals remain in the meta (they are
        // needed for a later residual-on resume to re-derive everything).
        let residual_on = state.cfg.policy.residual;
        let (morph, morph_id) = if residual_on {
            commit_morphology(state, index, pend, &edge, d)?
        } else {
            (
                MorphologySignature::trivial(pend.parent_generation + 1),
                None,
            )
        };
        if residual_on {
            if let Some(_mid) = morph_id {
                let payload = morph.encode()?;
                store.put(Family::MorphologySignature, &payload)?;
                state.morph_identities.insert(morph.structural_identity());
            }
            // Insert the new state features (admission commits them).
            for (s, b) in state_buckets(&d.signals) {
                state.state_features.insert((s, b));
            }
        }
        let generation = pend.parent_generation + 1;
        let mut feat = d.features.clone();
        feat.sort_unstable();
        feat.dedup();
        let meta = CorpusMeta {
            entry_id,
            parent_id: Some(pend.parent_id),
            generation,
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

        // ---- lineage / regime / amplify / DSFB updates ----
        // All of this is residual-channel memory: lineage accumulators,
        // regime observers, structured-signature history, amplify/precedent
        // queues. A residual-off campaign skips it entirely (the arm keeps
        // no structural state — Phase-8 ablation semantics).
        let root = state
            .root_of(index, &pend.parent_id)
            .unwrap_or(pend.parent_id);
        let mutator = d.coordinate.mutator_id.id();
        let key = (root, mutator);
        let precedent_on = state.cfg.policy.precedent;
        let regime_cfg = state.regime_cfg;
        // Outputs gathered while the lineage entry is mutably borrowed.
        let mut closed_regime: Vec<(u16, RegimeEpisode)> = Vec::new();
        if residual_on {
            let ls = state.lineages.entry(key).or_insert_with(|| {
                let mut ls = LineageState::new();
                if let Some(root_meta) = index.meta(&root) {
                    ls.acc.init_baseline(&root_meta.signals);
                }
                ls
            });
            ls.frontier = entry_id;
            ls.ordinal = ls.ordinal.saturating_add(1);
            // Regime feeds on the moved axes. Episodes are collected here
            // and persisted after the lineage borrow ends.
            for i in 0..crate::target_runtime::signals::MAX_SIGNALS {
                if edge.moved() & (1u64 << i) != 0 {
                    let obs = ls
                        .observers
                        .entry(i as u16)
                        .or_insert_with(|| RegimeObserver::new(regime_cfg));
                    if let Some(ep) = obs.feed(ls.ordinal, edge.child.value(SignalId(i as u16))) {
                        closed_regime.push((i as u16, ep));
                    }
                }
            }
            // Phase 3: structured-signature history (kept per (root,
            // mutator) lineage for precedent family identity).
            if !morph.is_trivial() {
                ls.push_history(generation, &morph);
            }
        }
        // Phase 3: feed the ROOT's DSFB substrate — one shared stream per
        // root, spanning all mutator families: the root's behavioral
        // evolution in admission order. This is the stream the DSFB
        // envelope/grammar semantics are calibrated on.
        let mut structural_verdicts_this_edge = 0u64;
        let mut closed_structural: Option<StructuralEpisode> = None;
        if residual_on {
            let (es, closed_ep) = state.feed_root_structural(&root, &edge, generation)?;
            closed_structural = closed_ep;
            // The bank names only structurally active edges; the durable
            // verdict object records the edge's integer-reduced verdicts
            // and the nomination.
            let class = if es.verdicts.iter().any(|v| v.is_active()) {
                let mut ev = BankEvidence::new(&morph, &es.verdicts);
                for v in &es.verdicts {
                    ev.set_role(v.axis, state.roles[v.axis as usize]);
                }
                let bv = classify_evidence(&ev);
                let code = bv.motif().map(|m| m.code()).unwrap_or(0);
                // Log only class CHANGES (the trajectory entered a new
                // named regime), never every edge of a sustained regime.
                let prev = state
                    .lineages
                    .get(&key)
                    .map(|ls| ls.last_class)
                    .unwrap_or(0);
                if code != 0 && code != prev {
                    eprintln!(
                        "[campaign] bank: depth={} class={} axes={:#x}",
                        generation,
                        FuzzMotif::from_code(code).map(|m| m.name()).unwrap_or("?"),
                        morph.axis_mask
                    );
                }
                code
            } else {
                0
            };
            if let Some(ls) = state.lineages.get_mut(&key) {
                ls.record_nomination(class, &es.verdicts);
            }
            // Persist a durable verdict when there is structural activity or
            // a nomination (Level 1/2 boundary).
            let persist = es.verdicts.iter().any(|v| v.is_active()) || class != 0;
            if persist {
                let dv = DurableVerdict {
                    root,
                    mutator,
                    depth: generation,
                    axes: es.verdicts.clone(),
                    class,
                    morph_identity: morph.structural_identity(),
                };
                let payload = encode_verdict_payload(&dv)?;
                store.put(Family::StructuralVerdict, &payload)?;
                structural_verdicts_this_edge = 1;
            }
        }
        for (signal, ep) in closed_regime {
            state.write_episode(store, signal, ep)?;
        }
        if let Some(ep) = closed_structural {
            let payload = encode_episode_payload(&ep)?;
            store.put(Family::StructuralEpisode, &payload)?;
            state.structural_episodes = state.structural_episodes.saturating_add(1);
            eprintln!(
                "[campaign] structural episode closed: root={} axes={:#x} peak_policy={} t=[{},{}]",
                short_hex8(&ep.root),
                ep.axes,
                ep.peak_policy,
                ep.t_open,
                ep.t_close
            );
        }
        if structural_verdicts_this_edge > 0 {
            state.structural_verdicts = state
                .structural_verdicts
                .saturating_add(structural_verdicts_this_edge);
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
        // Phase 3: precedent matching against the live lineage shape. Only
        // structured signatures match (a trivial shape has no profile).
        if residual_on && precedent_on && !morph.is_trivial() {
            enqueue_precedent_probes(state, &morph, &root, mutator, entry_id);
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

// ---------------------------------------------------------------------------
// Phase 3: precedent matching, probe execution/records, and precedent
// admission from terminal observations.
// ---------------------------------------------------------------------------

/// Match a live lineage signature against the loaded precedent bank and
/// enqueue probe orders (bounded). Never writes to the store; all queue
/// state is in-memory (a probe queue is disposable campaign state — lost on
/// restart, unlike precedent revisions).
/// The stable in-flight key of a probe: (matched root, mutator, profile
/// identity). Revision ids are NOT used (they change on every precedent
/// update, which would leak stale keys into the in-flight set).
fn probe_key(entry: &ProbeEntry) -> (ContentId, u16, u64) {
    (
        entry.root,
        entry.precedent.mutator,
        entry.precedent.profile.profile_identity(),
    )
}

fn enqueue_precedent_probes(
    state: &mut CampaignState,
    sig: &MorphologySignature,
    root: &ContentId,
    mutator: u16,
    frontier: ContentId,
) {
    if state.precedents.is_empty() {
        return;
    }
    let matched: Vec<Precedent> = crate::precedent::matching_precedents(
        state.precedents.values().map(|(_, p)| p),
        sig,
        sig.depth,
        mutator,
    )
    .into_iter()
    .cloned()
    .collect();
    for p in matched.into_iter().take(MAX_MATCHES_PER_EDGE) {
        let gk = p.group_key();
        let Some(&(pid, _)) = state.precedents.get(&gk) else {
            continue;
        };
        state.precedent_matches = state.precedent_matches.saturating_add(1);
        // One probe per (matched lineage, precedent family): bounded by the
        // in-flight set and one queued entry per family+root.
        if state
            .probe_inflight
            .contains(&(*root, p.mutator, p.profile.profile_identity()))
        {
            continue;
        }
        if state
            .probes
            .values()
            .any(|e| e.root == *root && e.mutator == p.mutator)
        {
            continue;
        }
        if state.probes.len() >= MAX_PROBE_ENTRIES {
            break;
        }
        let class = if p.discriminates() {
            SchedulingClass::Discriminate
        } else {
            SchedulingClass::Falsify
        };
        let seq = state.probe_seq;
        state.probe_seq = state.probe_seq.wrapping_add(1);
        eprintln!(
            "[campaign] precedent match: status={} profile_depth={} axes={:#x} -> {} probe seq={}",
            p.status.name(),
            p.profile.depth,
            p.profile.axis_mask,
            class.name(),
            seq
        );
        state.probes.insert(
            seq,
            ProbeEntry {
                seq,
                class,
                precedent: p,
                precedent_id: pid,
                root: *root,
                mutator,
                frontier,
                priority: u64::MAX - seq,
            },
        );
    }
}

/// Evaluate a completed probe batch against the precedent's falsifiable
/// relationship and record the outcome as a new precedent revision. A
/// contradiction is retained as negative knowledge (I10); a precedent is
/// never deleted.
fn record_probe_result(
    store: &Store,
    state: &mut CampaignState,
    entry: &ProbeEntry,
    result: &WorkResult,
) -> Result<()> {
    let gk = entry.precedent.group_key();
    let Some((pid, current)) = state.precedents.get(&gk).map(|(id, p)| (*id, p.clone())) else {
        return Ok(()); // the family is gone; nothing to record against
    };
    let recipe = current.recipe;
    let outcome = eval_probe(&recipe, &result.signal_summary);
    let axis = recipe.axis as usize;
    let moved = if axis < MAX_SIGNALS {
        result.signal_summary.count[axis]
    } else {
        0
    };
    let run = if axis < MAX_SIGNALS {
        result.signal_summary.max_run[axis]
    } else {
        0
    };
    let sum_abs = if axis < MAX_SIGNALS {
        result.signal_summary.sum_abs_delta[axis]
    } else {
        0
    };
    let evidence = crate::precedent::ProbeEvidence {
        outcome,
        seq: state.admission_seq,
        axis: recipe.axis,
        moved,
        run,
        sum_bucket: crate::target_runtime::signals::magnitude_bucket(sum_abs),
        batch_execs: result.exec_count,
    };
    let direct = crate::precedent::contradiction_weight(&recipe, &result.signal_summary)
        == crate::precedent::ContradictionWeight::Direct;
    persist_probe_update(store, state, &current, pid, outcome, evidence, direct)?;
    state.probe_inflight.remove(&probe_key(entry));
    eprintln!(
        "[campaign] probe outcome: {} axis={} moved={} run={} execs={}",
        outcome.name(),
        recipe.axis,
        moved,
        run,
        result.exec_count
    );
    Ok(())
}

/// A worker died while a probe order was executing: the probe batch reached
/// the terminal event itself. That is the strongest form of confirmation
/// (the continuation recurred under the falsify order).
fn record_probe_crash(store: &Store, state: &mut CampaignState, entry: &ProbeEntry) -> Result<()> {
    let gk = entry.precedent.group_key();
    let Some((pid, current)) = state.precedents.get(&gk).map(|(id, p)| (*id, p.clone())) else {
        return Ok(());
    };
    let evidence = crate::precedent::ProbeEvidence {
        outcome: ProbeOutcome::Support,
        seq: state.admission_seq,
        axis: current.recipe.axis,
        moved: 0,
        run: 0,
        sum_bucket: 0,
        batch_execs: 0,
    };
    persist_probe_update(
        store,
        state,
        &current,
        pid,
        ProbeOutcome::Support,
        evidence,
        false,
    )?;
    state.probe_inflight.remove(&probe_key(entry));
    eprintln!(
        "[campaign] probe order crashed: continuation confirmed for precedent {}",
        short_hex8(&pid)
    );
    Ok(())
}

/// Persist one probe outcome as a new precedent revision and refresh the
/// in-memory current revision.
fn persist_probe_update(
    store: &Store,
    state: &mut CampaignState,
    current: &Precedent,
    pid: ContentId,
    outcome: ProbeOutcome,
    evidence: crate::precedent::ProbeEvidence,
    direct: bool,
) -> Result<()> {
    let (status, supports, contradictions, ambiguous) =
        current.apply_probe(outcome, evidence, direct);
    let mut rev = current.clone();
    rev.status = status;
    rev.supports = supports;
    rev.contradictions = contradictions;
    rev.ambiguous_probes = ambiguous;
    rev.prev_revision = Some(pid);
    rev.updated_seq = state.admission_seq;
    rev.evidence.insert(0, evidence);
    if rev.evidence.len() > crate::precedent::model::MAX_PRECEDENT_EVIDENCE {
        rev.evidence
            .truncate(crate::precedent::model::MAX_PRECEDENT_EVIDENCE);
    }
    let new_id = save_precedent_revision(store, &rev)?;
    state.precedent_revisions = state.precedent_revisions.saturating_add(1);
    let gk = rev.group_key();
    state.precedents.insert(gk, (new_id, rev));
    match outcome {
        ProbeOutcome::Support => state.probe_supports = state.probe_supports.saturating_add(1),
        ProbeOutcome::Contradict => {
            state.probe_contradictions = state.probe_contradictions.saturating_add(1);
            // Phase 4: a falsified precedent is negative knowledge. Publish
            // it to Gemel as a Residual (best-effort; the local record
            // makes failures observable) — I10: never deleted.
            if state.cfg.gemel {
                gemel_publish(state, store, BoundaryKind::FalsifiedPrecedent, new_id, None)?;
            }
        }
        ProbeOutcome::Ambiguous => state.probe_ambiguous = state.probe_ambiguous.saturating_add(1),
    }
    eprintln!(
        "[campaign] precedent {} -> {} (supports {} contradictions {})",
        short_hex8(&new_id),
        status.name(),
        supports,
        contradictions
    );
    Ok(())
}

/// Admit (or confirm) a precedent from a real terminal observation: the
/// lineage that just crashed with a structured precursor history becomes a
/// durable precedent with a falsifiable probe relationship (I9: provenance;
/// §17: every precedent carries ≥ 1 falsifiable relationship).
fn maybe_admit_precedent(
    store: &Store,
    state: &mut CampaignState,
    index: &CorpusIndex,
    pend: &PendingOrder,
    kind: FindingKind,
    finding_id: &ContentId,
) -> Result<()> {
    if !state.cfg.policy.residual || !state.cfg.policy.precedent || pend.is_override {
        return Ok(());
    }
    let terminal_kind = match kind {
        FindingKind::Crash => TerminalKind::CrashFinding,
        FindingKind::Timeout => TerminalKind::TimeoutFinding,
        FindingKind::Unattributed => return Ok(()),
    };
    let Some(root) = state.root_of(index, &pend.parent_id) else {
        return Ok(());
    };
    let mutator = pend.order.mutator_id;
    let key = (root, mutator);
    let Some(ls) = state.lineages.get(&key) else {
        return Ok(());
    };
    if ls.shape_history.is_empty() {
        return Ok(());
    }
    let terminal_depth = pend.parent_generation.saturating_add(1);
    let history: Vec<(u32, MorphologySignature)> = ls.shape_history.iter().cloned().collect();
    let Some((precursor, precursor_depth)) = choose_precursor(&history, terminal_depth) else {
        return Ok(());
    };
    let axis = ls
        .last_verdict_axis
        .or_else(|| precursor.dominant_axis())
        .unwrap_or(0);
    let class = ls.last_class;
    let gk = (
        root,
        mutator,
        PrefixProfile::from_signature(&precursor, precursor_depth).profile_identity(),
    );
    // A repeated terminal event on the same family confirms the existing
    // precedent rather than duplicating it.
    if state.precedents.contains_key(&gk) {
        let _ = (class, terminal_kind, axis);
        return Ok(());
    }
    let recipe = crate::precedent::derive_recipe(
        crate::mutation::MutatorId::from_id(mutator).unwrap_or(crate::mutation::MutatorId::BitFlip),
        axis,
        (state.cfg.policy.batch_size / 8).max(4) as u32,
        PROBE_MIN_RUN,
        PROBE_MIN_BUCKET,
    );
    let Some(p) = create_from_terminal(
        root,
        crate::mutation::MutatorId::from_id(mutator).unwrap_or(crate::mutation::MutatorId::BitFlip),
        &precursor,
        precursor_depth,
        terminal_kind,
        class,
        axis,
        0,
        terminal_depth,
        Some(*finding_id),
        ConfuserKind::None,
        recipe,
        state.admission_seq,
    ) else {
        return Ok(());
    };
    let id = save_precedent_revision(store, &p)?;
    state.precedent_revisions = state.precedent_revisions.saturating_add(1);
    state.precedents.insert(gk, (id, p));
    eprintln!(
        "[campaign] precedent admitted: root={} mutator={} profile_depth={} axes={:#x} -> {} (depth {})",
        short_hex8(&root),
        mutator,
        precursor_depth,
        precursor.axis_mask,
        terminal_kind.name(),
        terminal_depth
    );
    // Phase 4: a promoted structural precedent is a durable boundary
    // (Level 3). Best-effort; the local record makes failures observable.
    if state.cfg.gemel {
        gemel_publish(state, store, BoundaryKind::PrecedentAdmitted, id, None)?;
    }
    Ok(())
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
            // Phase 3: a probe order that crashed confirms the precedent's
            // continuation (the falsify order reached the terminal event).
            if let Some(entry) = &p.probe {
                record_probe_crash(store, state, entry)?;
            }
        }
        // Phase 3: a structured lineage that reached a terminal event
        // becomes (or confirms) a durable precedent with a falsifiable
        // relationship.
        if let Some(p) = pend.as_ref() {
            maybe_admit_precedent(store, state, index, p, kind, &id)?;
        }
        // Deliberate replay to classify and confirm. Crash inputs are NOT
        // admitted to the corpus (their feature sets were never measured —
        // the worker died mid-window — so they are useless mutation parents;
        // the Finding object already retains the input, I10).
        let (replay, final_id) = classify_and_replay(cfg, store, lane, &input, &id, override_seq)?;

        // ---- Phase 4: FRF verification at promotion (Level 2) ----
        // Only replay-confirmed findings are court-verified: a finding that
        // does not reproduce standalone would show no differential under
        // the FRF harness, which replay already recorded. With no authority
        // configured the finding stays Unverified (derived, never
        // fabricated — acceptance item 16).
        if replay == ReplayStatus::Reproduced {
            if let Some(authority) = cfg.authority.as_ref() {
                let candidate = cfg
                    .verification_candidate
                    .clone()
                    .unwrap_or_else(|| cfg.target_bin.clone());
                let detail = attempt_frf_verification(
                    store,
                    state,
                    &final_id,
                    &finding.input,
                    authority,
                    &candidate,
                )?;
                // Gemel: a VERIFIED finding is a durable boundary bound to
                // the current state (best-effort; recorded locally). A
                // failed/refused verification publishes nothing to Gemel —
                // the durable Failed record in the local store is the
                // evidence (I10, I14).
                if let Some(detail) = detail {
                    if cfg.gemel
                        && gemel_bridge::publish_boundary(
                            store,
                            &gemel_project_root(cfg),
                            BoundaryKind::FindingVerified,
                            final_id,
                            Some(&detail),
                        )?
                        .is_some()
                    {
                        state.gemel_boundaries = state.gemel_boundaries.saturating_add(1);
                    }
                }
            }
        }
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
            probe: p.probe.clone(),
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
/// Deliberately re-execute a finding's input on a fresh worker to classify
/// it (crash/timeout reproduce as a death; a surviving run is a
/// non-reproduction, preserved). Returns the replay status and the NEW
/// finding revision id (objects are immutable; both revisions are retained,
/// I10). The returned revision is the one FRF verification binds.
fn classify_and_replay(
    cfg: &CampaignConfig,
    store: &Store,
    lane: u16,
    input: &[u8],
    finding_id: &ContentId,
    override_seq: &mut BTreeMap<u16, u64>,
) -> Result<(ReplayStatus, ContentId)> {
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
    let _ = w.send_shutdown();
    let _ = w.wait();
    Ok((outcome, new_id))
}

/// Run the FRF verification court for one promoted finding and persist the
/// durable verification record. Any failure — FRF refusal OR a hard
/// configuration error (missing candidate, bad authority id) — becomes a
/// `Failed` record with a deterministic note; the campaign never fails on
/// verification (I14). Returns an evidence detail string for the Gemel
/// boundary (the FRF run/receipt ids when present).
fn attempt_frf_verification(
    store: &Store,
    state: &mut CampaignState,
    finding_id: &ContentId,
    input: &[u8],
    authority: &AuthoritySpec,
    candidate: &std::path::Path,
) -> Result<Option<String>> {
    // Crash-flood dedup: the same input (same authority + question, which
    // are campaign-constant) produces the same court; the first attempt's
    // durable record already covers it. Re-running the court per duplicate
    // crash would serialize the campaign on FRF hashing/execution.
    let input_digest: [u8; 32] = *ContentId::new(input).as_bytes();
    if !state.verified_inputs.insert(input_digest) {
        eprintln!(
            "[campaign] FRF verification skipped for finding={} (input already court-verified this campaign)",
            finding_id
        );
        return Ok(None);
    }
    let (ver_id, record) = match frf_bridge::verify_and_persist(
        store,
        finding_id,
        authority,
        &state.cfg.question,
        candidate,
        input,
        state.cfg.verify_claim,
    ) {
        Ok(r) => r,
        Err(e) => {
            // A hard configuration error is still a durable (failed)
            // verification attempt: the reason is preserved, never silent.
            let rec = VerificationRecord {
                finding: *finding_id,
                authority_name: authority.name.clone(),
                authority_version: authority.version.clone(),
                outcome: VerificationOutcome::Failed,
                run: None,
                receipt: None,
                claim: None,
                note: Some(frf_bridge::bound_text(
                    &format!("verification failed: {e}"),
                    frf_bridge::MAX_NOTE_LEN,
                )),
            };
            let payload = frf_bridge::encode_verification(&rec)?;
            let id = store.put(Family::FindingVerification, &payload)?;
            (id, rec)
        }
    };
    state.frf_verifications = state.frf_verifications.saturating_add(1);
    match record.outcome {
        VerificationOutcome::Verified => {
            state.frf_verified = state.frf_verified.saturating_add(1);
            let receipt = record.receipt.clone().unwrap_or_default();
            eprintln!(
                "[campaign] FRF VERIFIED finding={} receipt={} record={}",
                finding_id,
                receipt,
                ver_id.to_hex()
            );
            Ok(Some(format!(
                "frf run {} receipt {}",
                record.run.as_deref().unwrap_or(""),
                receipt
            )))
        }
        VerificationOutcome::Failed => {
            state.frf_failed = state.frf_failed.saturating_add(1);
            eprintln!(
                "[campaign] FRF verification failed finding={} record={} note={}",
                finding_id,
                ver_id.to_hex(),
                record.note.as_deref().unwrap_or("")
            );
            Ok(None)
        }
    }
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
    out.push(u8::from(cfg.policy.precedent));
    for w in cfg.policy.class_weights {
        out.extend_from_slice(&w.to_le_bytes());
    }
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

fn short_hex8(id: &ContentId) -> String {
    let h = id.to_hex();
    h[..8].to_string()
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
