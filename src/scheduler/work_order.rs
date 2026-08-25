//! Wire encoding for coordinator <-> worker payloads.
//!
//! The protocol framing lives in [`crate::execute::protocol`]; this module
//! defines the *payload* layouts carried inside frames. Everything is a
//! fixed, bounded, little-endian binary encoding with explicit version
//! bytes — no JSON, no serde, no allocation before a length is checked.
//!
//! The worker (a fuzz target built with `target-runtime`) and the
//! coordinator both link this module, so encode/decode are symmetric and
//! every bound is enforced on both sides.
//!
//! # Bounds (all enforced before allocation)
//!
//! | quantity | bound | rationale |
//! |---|---|---|
//! | parent input | 1 MiB | matches `mutation::MAX_MUTATED_LEN` |
//! | splice partner | 1 MiB | same |
//! | dictionary entries | 4096 | corpus dictionaries are small |
//! | dictionary entry | 4 KiB | a single interesting token |
//! | features per work order | 65536 | fits the 1 MiB frame |
//! | features per execution | 65536 | an execution cannot touch more counters |
//! | discoveries per result | 4096 | bounded batch reporting |
//! | cmp events per execution | 16 | a compact summary is enough |
//! | signals | 64 | fixed-size `SignalVector` (520 B) |
//! | residual sketch | 96 B | fixed-size `ResidualSketch` |
//! | batch signal summary | 64 × 29 B | per-order aggregates |
//! | schema entries | 64 | one per signal ID |
//!
//! # Determinism
//!
//! Encodings are canonical: identical payloads encode to identical bytes.
//! There is no map iteration, no wall clock, no process ID in any payload
//! (operational metadata lives in campaign sidecars, not here).
//!
//! # Phase 2 (version 2)
//!
//! * [`WorkOrder`] carries the parent's recorded signal observation
//!   (`parent_signals`), so the worker can compute the child-vs-parent
//!   residual sketch locally and the coordinator's mutation residual is
//!   lineage-consistent.
//! * [`DiscoveryRecord`] carries the child's signal vector, its residual
//!   sketch, and the compare hits the mutation actually used (`cmp_hits_used`
//!   — this closes a Phase-1 determinism gap where the coordinator
//!   reconstructed compare-operand-substitution candidates with an empty hit
//!   list and silently lost the admission, I2).
//! * [`WorkResult`] carries the per-order [`SignalBatchSummary`] (the full
//!   observation stream in bounded aggregate form) and the override
//!   execution's signals.
//! * [`Hello`] carries the target's registered signal schema.

use crate::error::{Error, Result};
use crate::mutation::{CmpHit, MutationCoordinate};
use crate::target_runtime::signals::{
    ResidualSketch, SignalBatchSummary, SignalDesc, SignalId, SignalSchema, SignalVector,
    MAX_SIGNALS,
};

/// Version of the work-order encoding. Bump on any layout change.
pub const WORK_ORDER_VERSION: u8 = 2;
/// Version of the work-result encoding. Bump on any layout change.
pub const WORK_RESULT_VERSION: u8 = 2;
/// Version of the hello encoding. Bump on any layout change.
pub const HELLO_VERSION: u8 = 2;

/// Worker execution modes, negotiated via the `FRF_FUZZ_SANITIZER` env var
/// the coordinator sets at spawn.
pub mod mode {
    /// SanitizerCoverage + trace-compares, no ASan (default build).
    pub const SANCOV_TRACECMP: u8 = 1;
    /// ASan build; trace-compares disabled (see docs/COMPATIBILITY.md).
    pub const ASAN: u8 = 2;
}

/// Max parent/partner input length (== `mutation::MAX_MUTATED_LEN`).
pub const MAX_INPUT_LEN: usize = 1 << 20;
/// Max dictionary entries per work order.
pub const MAX_DICT_ENTRIES: usize = 4096;
/// Max length of a single dictionary entry.
pub const MAX_DICT_ENTRY_LEN: usize = 4096;
/// Max new features carried in a work order.
pub const MAX_FEATURES_PER_ORDER: usize = 1 << 16;
/// Max features reported for one execution.
pub const MAX_FEATURES_PER_EXEC: usize = 1 << 16;
/// Max discovery records per work result.
pub const MAX_DISCOVERIES_PER_RESULT: usize = 4096;
/// Max cmp events summarized per execution.
pub const MAX_CMP_EVENTS_PER_EXEC: usize = 16;
/// Max cmp hits a mutation may have used (same bound).
pub const MAX_CMP_HITS_PER_EXEC: usize = MAX_CMP_EVENTS_PER_EXEC;
/// Max bytes of an error message.
pub const MAX_ERROR_MSG_LEN: usize = 4096;

/// Per-execution outcome as recorded in a [`DiscoveryRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecutionStatus {
    /// The target returned normally.
    Ok = 1,
    /// The worker died while executing this coordinate (ASan finding,
    /// panic=abort, signal, abort, OOM). Reconstructed via the crash ledger.
    Crash = 2,
    /// The watchdog aborted the worker while executing this coordinate.
    Timeout = 3,
}

impl ExecutionStatus {
    /// Decode from the wire byte.
    pub fn from_byte(b: u8) -> Option<ExecutionStatus> {
        match b {
            1 => Some(ExecutionStatus::Ok),
            2 => Some(ExecutionStatus::Crash),
            3 => Some(ExecutionStatus::Timeout),
            _ => None,
        }
    }

    /// The wire byte.
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// A compact comparison event for the wire (kind: 1 cmp, 2 const-cmp,
/// 3 switch; width in bytes). See `target_runtime::cmp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmpEventWire {
    /// Comparison kind (1 cmp, 2 const-cmp, 3 switch).
    pub kind: u8,
    /// Operand width in bytes (1, 2, 4, 8; 0 for switch).
    pub width: u8,
    /// Operand A (or the switched value for switches).
    pub a: u64,
    /// Operand B (unused for switches).
    pub b: u64,
}

/// A compare hit the worker fed into a mutation (the exact operand values
/// `CompareOperandSubstitution` used). Wire form of [`CmpHit`]; required so
/// the coordinator reconstructs family-15 candidates bit-exactly (I2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmpHitWire {
    /// Operand width in bytes (1, 2, 4, 8).
    pub width: u8,
    /// Operand value (little-endian, truncated to `width`).
    pub value: u64,
}

impl CmpHitWire {
    /// Convert to the mutation-engine hit.
    pub fn to_hit(self) -> CmpHit {
        match self.width {
            1 => CmpHit::U8(self.value as u8),
            2 => CmpHit::U16(self.value as u16),
            4 => CmpHit::U32(self.value as u32),
            _ => CmpHit::U64(self.value),
        }
    }
}

/// A work order: one batch of deterministic mutations the worker executes
/// locally before returning. The coordinator never sends one candidate per
/// execution over IPC (docs/ARCHITECTURE.md §5).
#[derive(Debug, Clone)]
pub struct WorkOrder {
    /// Campaign seed (deterministic campaign identity).
    pub campaign_seed: u64,
    /// Mutation generation / depth.
    pub generation: u32,
    /// Mutator family (stable `MutatorId` numeric ID).
    pub mutator_id: u16,
    /// Worker lane ID.
    pub lane_id: u16,
    /// First `mutation_index` of the batch.
    pub start_index: u64,
    /// Number of mutations in the batch (>= 1).
    pub index_count: u64,
    /// Parent input bytes (the corpus entry being mutated).
    pub parent: Vec<u8>,
    /// First 8 bytes of the parent content ID (provenance: the worker
    /// cannot hash, and the crash ledger's coordinate must carry the same
    /// short key the coordinator uses to resolve the parent).
    pub parent_short: [u8; 8],
    /// The parent's recorded signal observation (from its `CorpusMeta`).
    /// The worker computes every child's residual sketch against this, so
    /// mutation residuals are lineage-consistent (Phase 2).
    pub parent_signals: SignalVector,
    /// Optional splice partner (empty = none).
    pub partner: Vec<u8>,
    /// Dictionary entries (interesting tokens).
    pub dictionary: Vec<Vec<u8>>,
    /// Packed feature indices the coordinator admitted since the last order;
    /// the worker merges them into its local baseline so it can suppress
    /// redundant discoveries.
    pub new_features: Vec<u64>,
    /// When non-empty, the worker executes exactly these bytes once
    /// (`index_count` is ignored, 1 execution, status-only result). Used by
    /// replay/tmin/cmin verification — deliberate per-candidate tools, not
    /// the hot loop.
    pub input_override: Vec<u8>,
}

/// One interesting execution reported by the worker.
#[derive(Debug, Clone)]
pub struct DiscoveryRecord {
    /// The exact mutation coordinate that produced this candidate.
    pub coordinate: MutationCoordinate,
    /// Outcome.
    pub status: ExecutionStatus,
    /// Full footprint-masked feature set of the execution (sorted,
    /// deduplicated packed indices).
    pub features: Vec<u64>,
    /// Compact comparison summary.
    pub cmp_events: Vec<CmpEventWire>,
    /// The compare hits this mutation was built from (family-15 exact
    /// reconstruction; empty for all other families).
    pub cmp_hits_used: Vec<CmpHitWire>,
    /// The child's observed signal vector (Phase 2).
    pub signals: SignalVector,
    /// The child-vs-parent residual sketch (Phase 2).
    pub sketch: ResidualSketch,
    /// Logarithmic execution-time bucket (0 = fastest).
    pub time_bucket: u8,
}

/// The worker's reply to one work order.
#[derive(Debug, Clone, Default)]
pub struct WorkResult {
    /// Executions attempted in this batch.
    pub exec_count: u64,
    /// Executions the watchdog aborted (timeouts; the ledger made the
    /// coordinate reconstructable; the coordinator records a finding).
    pub timeout_count: u64,
    /// Interesting executions (novel local features, persistent drift,
    /// state expansion, large deltas).
    pub discoveries: Vec<DiscoveryRecord>,
    /// True when the discovery list hit [`MAX_DISCOVERIES_PER_RESULT`] and
    /// was truncated (the worker's local baseline was still updated, so
    /// the coordinator's next delta re-synchronizes; the batch is small
    /// enough that this should never happen with the default policy).
    pub truncated: bool,
    /// Per-signal aggregates over the whole batch (the full observation
    /// stream in bounded form; Phase 2 drift detection).
    pub signal_summary: SignalBatchSummary,
    /// When the order was an input-override (seed/replay/tmin), the
    /// footprint-masked feature set of that single execution. Empty for
    /// batch orders.
    pub override_features: Vec<u64>,
    /// When the order was an input-override, the observed signal vector of
    /// that single execution (so seeds carry a recorded observation).
    pub override_signals: SignalVector,
}

/// The worker's greeting, sent immediately after startup.
#[derive(Debug, Clone)]
pub struct Hello {
    /// Execution mode (see `mode`).
    pub mode: u8,
    /// Registered sancov counter ranges.
    pub range_count: u32,
    /// Total counter bytes across all ranges.
    pub total_counter_bytes: u64,
    /// Worker process ID (diagnostics only; never part of identity).
    pub pid: u32,
    /// `rustc -vV` release line, e.g. "1.97.0-nightly".
    pub rustc_release: String,
    /// `rustc -vV` LLVM line.
    pub llvm_version: String,
    /// The target's registered signal schema (name/unit per ID).
    pub schema: Vec<SignalDescWire>,
}

/// A wire schema entry (id + name + unit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalDescWire {
    /// Signal ID.
    pub id: u16,
    /// Name (ASCII, bounded).
    pub name: String,
    /// Unit (ASCII, bounded; may be empty).
    pub unit: String,
}

// ---------------------------------------------------------------------------
// Bounded wire reader/writer
// ---------------------------------------------------------------------------

struct WireWriter {
    buf: Vec<u8>,
}

impl WireWriter {
    fn new() -> Self {
        WireWriter { buf: Vec::new() }
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    fn len_u32_bytes(&mut self, len: usize, limit: u64) -> Result<()> {
        if len as u64 > limit {
            return Err(Error::BoundExceeded {
                what: "wire field length",
                limit,
                got: len as u64,
            });
        }
        self.u32(len as u32);
        Ok(())
    }
    fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

struct WireReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        WireReader { bytes, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > self.bytes.len() {
            return Err(Error::Encoding("wire payload truncated"));
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes_of_len(&mut self, limit: u64) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if len as u64 > limit {
            return Err(Error::BoundExceeded {
                what: "wire field length",
                limit,
                got: len as u64,
            });
        }
        self.take(len)
    }
    fn done(&self) -> Result<()> {
        if self.pos != self.bytes.len() {
            return Err(Error::Encoding("wire payload has trailing bytes"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Signal vector / sketch / batch summary wire forms
// ---------------------------------------------------------------------------

/// Fixed wire length of a [`SignalVector`]: touched mask (8) + 64 × u64.
pub const SIGNAL_VECTOR_WIRE_LEN: usize = 8 + MAX_SIGNALS * 8;
/// Fixed wire length of a [`ResidualSketch`]: 64 buckets + 16 dir bits +
/// 8 touched_new + 8 touched_lost.
pub const SKETCH_WIRE_LEN: usize = MAX_SIGNALS + 16 + 8 + 8;

fn encode_signal_vector(w: &mut WireWriter, v: &SignalVector) {
    w.u64(v.touched_mask());
    for i in 0..MAX_SIGNALS {
        w.u64(v.value(SignalId(i as u16)));
    }
}

fn decode_signal_vector(r: &mut WireReader<'_>) -> Result<SignalVector> {
    let touched = r.u64()?;
    let mut v = SignalVector::new();
    for i in 0..MAX_SIGNALS {
        let val = r.u64()?;
        if touched & (1u64 << i) != 0 {
            v.observe(SignalId(i as u16), val)
                .map_err(|_| Error::Encoding("signal id out of range"))?;
        }
    }
    Ok(v)
}

fn encode_sketch(w: &mut WireWriter, s: &ResidualSketch) {
    w.bytes(&s.mag_buckets);
    w.bytes(&s.dir_bits.to_le_bytes());
    w.u64(s.touched_new);
    w.u64(s.touched_lost);
}

fn decode_sketch(r: &mut WireReader<'_>) -> Result<ResidualSketch> {
    let mut s = ResidualSketch::default();
    s.mag_buckets.copy_from_slice(r.take(MAX_SIGNALS)?);
    let dir_raw: [u8; 16] = r.take(16)?.try_into().unwrap();
    s.dir_bits = u128::from_le_bytes(dir_raw);
    s.touched_new = r.u64()?;
    s.touched_lost = r.u64()?;
    Ok(s)
}

/// Encode a batch summary: touched mask + per-touched-signal aggregates.
/// The number of encoded signals is bounded by the mask (≤ 64).
pub fn encode_batch_summary(summary: &SignalBatchSummary) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u64(summary.touched);
    for i in 0..MAX_SIGNALS {
        if summary.touched & (1u64 << i) != 0 {
            w.u32(summary.count[i]);
            w.u64(summary.min[i]);
            w.u64(summary.max[i]);
            w.u64(summary.sum_abs_delta[i]);
            w.u8(summary.max_run[i]);
        }
    }
    w.into_vec()
}

/// Decode a batch summary (bounded by the mask).
pub fn decode_batch_summary(bytes: &[u8]) -> Result<SignalBatchSummary> {
    let mut r = WireReader::new(bytes);
    let mut summary = SignalBatchSummary::new();
    summary.touched = r.u64()?;
    for i in 0..MAX_SIGNALS {
        if summary.touched & (1u64 << i) != 0 {
            summary.count[i] = r.u32()?;
            summary.min[i] = r.u64()?;
            summary.max[i] = r.u64()?;
            summary.sum_abs_delta[i] = r.u64()?;
            summary.max_run[i] = r.u8()?;
        }
    }
    r.done()?;
    Ok(summary)
}

/// Encode a signal schema into wire entries (registered signals only, ID
/// order). Bounded: at most [`MAX_SIGNALS`] entries.
pub fn schema_to_wire(schema: &SignalSchema) -> Result<Vec<SignalDescWire>> {
    let mut out = Vec::with_capacity(schema.count as usize);
    for (id, d) in schema.iter() {
        out.push(SignalDescWire {
            id: id.id(),
            name: d.name_str().to_string(),
            unit: d.unit_str().to_string(),
        });
    }
    Ok(out)
}

/// Rebuild a `SignalSchema` from wire entries (for HELLO decode).
pub fn wire_to_schema(entries: &[SignalDescWire]) -> Result<SignalSchema> {
    if entries.len() > MAX_SIGNALS {
        return Err(Error::BoundExceeded {
            what: "schema entries",
            limit: MAX_SIGNALS as u64,
            got: entries.len() as u64,
        });
    }
    let mut schema = SignalSchema::empty();
    for e in entries {
        let id = SignalId::new(e.id).ok_or(Error::Encoding("schema signal id out of range"))?;
        // Reuse the same validation the target-side registration enforces.
        SignalSchema::validate(&e.name, &e.unit)?;
        let mut desc = SignalDesc::empty();
        desc.present = true;
        desc.name_len = e.name.len() as u8;
        desc.name[..e.name.len()].copy_from_slice(e.name.as_bytes());
        desc.unit_len = e.unit.len() as u8;
        desc.unit[..e.unit.len()].copy_from_slice(e.unit.as_bytes());
        // The wire cannot be trusted: a duplicate ID is refused.
        if schema.desc(id).is_some() {
            return Err(Error::Encoding("schema contains a duplicate signal id"));
        }
        schema.set_desc(id, desc);
    }
    Ok(schema)
}

// ---------------------------------------------------------------------------
// Work order
// ---------------------------------------------------------------------------

/// Encode a work order.
pub fn encode_work_order(order: &WorkOrder) -> Result<Vec<u8>> {
    if order.parent.len() > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "parent input length",
            limit: MAX_INPUT_LEN as u64,
            got: order.parent.len() as u64,
        });
    }
    if order.partner.len() > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "splice partner length",
            limit: MAX_INPUT_LEN as u64,
            got: order.partner.len() as u64,
        });
    }
    if order.dictionary.len() > MAX_DICT_ENTRIES {
        return Err(Error::BoundExceeded {
            what: "dictionary entries",
            limit: MAX_DICT_ENTRIES as u64,
            got: order.dictionary.len() as u64,
        });
    }
    if order.new_features.len() > MAX_FEATURES_PER_ORDER {
        return Err(Error::BoundExceeded {
            what: "new features in work order",
            limit: MAX_FEATURES_PER_ORDER as u64,
            got: order.new_features.len() as u64,
        });
    }
    if order.index_count == 0 && order.input_override.is_empty() {
        return Err(Error::Encoding(
            "work order must have index_count >= 1 or an input override",
        ));
    }
    if order.input_override.len() > MAX_INPUT_LEN {
        return Err(Error::BoundExceeded {
            what: "input override length",
            limit: MAX_INPUT_LEN as u64,
            got: order.input_override.len() as u64,
        });
    }
    let mut w = WireWriter::new();
    w.u8(WORK_ORDER_VERSION);
    w.u64(order.campaign_seed);
    w.u32(order.generation);
    w.u16(order.mutator_id);
    w.u16(order.lane_id);
    w.u64(order.start_index);
    w.u64(order.index_count);
    w.len_u32_bytes(order.parent.len(), MAX_INPUT_LEN as u64)?;
    w.bytes(&order.parent);
    w.bytes(&order.parent_short);
    encode_signal_vector(&mut w, &order.parent_signals);
    w.len_u32_bytes(order.partner.len(), MAX_INPUT_LEN as u64)?;
    w.bytes(&order.partner);
    w.u32(order.dictionary.len() as u32);
    for entry in &order.dictionary {
        if entry.len() > MAX_DICT_ENTRY_LEN {
            return Err(Error::BoundExceeded {
                what: "dictionary entry length",
                limit: MAX_DICT_ENTRY_LEN as u64,
                got: entry.len() as u64,
            });
        }
        w.len_u32_bytes(entry.len(), MAX_DICT_ENTRY_LEN as u64)?;
        w.bytes(entry);
    }
    w.u32(order.new_features.len() as u32);
    for f in &order.new_features {
        w.u64(*f);
    }
    w.len_u32_bytes(order.input_override.len(), MAX_INPUT_LEN as u64)?;
    w.bytes(&order.input_override);
    Ok(w.into_vec())
}

/// Decode a work order, enforcing every bound before allocation.
pub fn decode_work_order(bytes: &[u8]) -> Result<WorkOrder> {
    let mut r = WireReader::new(bytes);
    let version = r.u8()?;
    if version != WORK_ORDER_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "work-order",
            version: version as u32,
        });
    }
    let campaign_seed = r.u64()?;
    let generation = r.u32()?;
    let mutator_id = r.u16()?;
    let lane_id = r.u16()?;
    let start_index = r.u64()?;
    let index_count = r.u64()?;
    if index_count == 0 {
        return Err(Error::Encoding("work order index_count must be >= 1"));
    }
    let parent = r.bytes_of_len(MAX_INPUT_LEN as u64)?.to_vec();
    let parent_short = r.take(8)?.try_into().unwrap();
    let parent_signals = decode_signal_vector(&mut r)?;
    let partner = r.bytes_of_len(MAX_INPUT_LEN as u64)?.to_vec();
    let dict_count = r.u32()? as usize;
    if dict_count > MAX_DICT_ENTRIES {
        return Err(Error::BoundExceeded {
            what: "dictionary entries",
            limit: MAX_DICT_ENTRIES as u64,
            got: dict_count as u64,
        });
    }
    let mut dictionary = Vec::with_capacity(dict_count);
    for _ in 0..dict_count {
        let entry = r.bytes_of_len(MAX_DICT_ENTRY_LEN as u64)?.to_vec();
        dictionary.push(entry);
    }
    let feature_count = r.u32()? as usize;
    if feature_count > MAX_FEATURES_PER_ORDER {
        return Err(Error::BoundExceeded {
            what: "new features in work order",
            limit: MAX_FEATURES_PER_ORDER as u64,
            got: feature_count as u64,
        });
    }
    let mut new_features = Vec::with_capacity(feature_count);
    for _ in 0..feature_count {
        new_features.push(r.u64()?);
    }
    let input_override = r.bytes_of_len(MAX_INPUT_LEN as u64)?.to_vec();
    r.done()?;
    Ok(WorkOrder {
        campaign_seed,
        generation,
        mutator_id,
        lane_id,
        start_index,
        index_count,
        parent,
        parent_short,
        parent_signals,
        partner,
        dictionary,
        new_features,
        input_override,
    })
}

// ---------------------------------------------------------------------------
// Discovery / work result
// ---------------------------------------------------------------------------

/// Encode a discovery record.
pub fn encode_discovery(d: &DiscoveryRecord) -> Result<Vec<u8>> {
    if d.features.len() > MAX_FEATURES_PER_EXEC {
        return Err(Error::BoundExceeded {
            what: "features per execution",
            limit: MAX_FEATURES_PER_EXEC as u64,
            got: d.features.len() as u64,
        });
    }
    if d.cmp_events.len() > MAX_CMP_EVENTS_PER_EXEC {
        return Err(Error::BoundExceeded {
            what: "cmp events per execution",
            limit: MAX_CMP_EVENTS_PER_EXEC as u64,
            got: d.cmp_events.len() as u64,
        });
    }
    if d.cmp_hits_used.len() > MAX_CMP_HITS_PER_EXEC {
        return Err(Error::BoundExceeded {
            what: "cmp hits used per execution",
            limit: MAX_CMP_HITS_PER_EXEC as u64,
            got: d.cmp_hits_used.len() as u64,
        });
    }
    let mut w = WireWriter::new();
    w.bytes(&d.coordinate.encode());
    w.u8(d.status.code());
    w.u32(d.features.len() as u32);
    for f in &d.features {
        w.u64(*f);
    }
    w.u16(d.cmp_events.len() as u16);
    for e in &d.cmp_events {
        w.u8(e.kind);
        w.u8(e.width);
        w.u64(e.a);
        w.u64(e.b);
    }
    w.u16(d.cmp_hits_used.len() as u16);
    for h in &d.cmp_hits_used {
        w.u8(h.width);
        w.u64(h.value);
    }
    encode_signal_vector(&mut w, &d.signals);
    encode_sketch(&mut w, &d.sketch);
    w.u8(d.time_bucket);
    Ok(w.into_vec())
}

/// Decode a discovery record.
pub fn decode_discovery(bytes: &[u8]) -> Result<DiscoveryRecord> {
    let mut r = WireReader::new(bytes);
    let coord_bytes = r.take(crate::mutation::coordinate::COORDINATE_ENCODED_LEN)?;
    let coordinate = MutationCoordinate::decode(coord_bytes)?;
    let status =
        ExecutionStatus::from_byte(r.u8()?).ok_or(Error::Encoding("unknown execution status"))?;
    let feature_count = r.u32()? as usize;
    if feature_count > MAX_FEATURES_PER_EXEC {
        return Err(Error::BoundExceeded {
            what: "features per execution",
            limit: MAX_FEATURES_PER_EXEC as u64,
            got: feature_count as u64,
        });
    }
    let mut features = Vec::with_capacity(feature_count);
    for _ in 0..feature_count {
        features.push(r.u64()?);
    }
    let cmp_count = r.u16()? as usize;
    if cmp_count > MAX_CMP_EVENTS_PER_EXEC {
        return Err(Error::BoundExceeded {
            what: "cmp events per execution",
            limit: MAX_CMP_EVENTS_PER_EXEC as u64,
            got: cmp_count as u64,
        });
    }
    let mut cmp_events = Vec::with_capacity(cmp_count);
    for _ in 0..cmp_count {
        let kind = r.u8()?;
        let width = r.u8()?;
        let a = r.u64()?;
        let b = r.u64()?;
        cmp_events.push(CmpEventWire { kind, width, a, b });
    }
    let hit_count = r.u16()? as usize;
    if hit_count > MAX_CMP_HITS_PER_EXEC {
        return Err(Error::BoundExceeded {
            what: "cmp hits used per execution",
            limit: MAX_CMP_HITS_PER_EXEC as u64,
            got: hit_count as u64,
        });
    }
    let mut cmp_hits_used = Vec::with_capacity(hit_count);
    for _ in 0..hit_count {
        let width = r.u8()?;
        let value = r.u64()?;
        cmp_hits_used.push(CmpHitWire { width, value });
    }
    let signals = decode_signal_vector(&mut r)?;
    let sketch = decode_sketch(&mut r)?;
    let time_bucket = r.u8()?;
    r.done()?;
    Ok(DiscoveryRecord {
        coordinate,
        status,
        features,
        cmp_events,
        cmp_hits_used,
        signals,
        sketch,
        time_bucket,
    })
}

/// Max payload a single encoded discovery record may claim inside a result.
const MAX_DISCOVERY_RECORD_LEN: u32 = 1 << 20;

/// Encode a work result.
pub fn encode_work_result(result: &WorkResult) -> Result<Vec<u8>> {
    if result.discoveries.len() > MAX_DISCOVERIES_PER_RESULT {
        return Err(Error::BoundExceeded {
            what: "discoveries per result",
            limit: MAX_DISCOVERIES_PER_RESULT as u64,
            got: result.discoveries.len() as u64,
        });
    }
    let mut w = WireWriter::new();
    w.u8(WORK_RESULT_VERSION);
    w.u64(result.exec_count);
    w.u64(result.timeout_count);
    w.u8(u8::from(result.truncated));
    w.u32(result.discoveries.len() as u32);
    for d in &result.discoveries {
        let enc = encode_discovery(d)?;
        w.len_u32_bytes(enc.len(), u64::from(MAX_DISCOVERY_RECORD_LEN))?;
        w.bytes(&enc);
    }
    let summary = encode_batch_summary(&result.signal_summary);
    w.len_u32_bytes(summary.len(), 4096)?;
    w.bytes(&summary);
    w.u32(result.override_features.len() as u32);
    for f in &result.override_features {
        w.u64(*f);
    }
    encode_signal_vector(&mut w, &result.override_signals);
    Ok(w.into_vec())
}

/// Decode a work result.
pub fn decode_work_result(bytes: &[u8]) -> Result<WorkResult> {
    let mut r = WireReader::new(bytes);
    let version = r.u8()?;
    if version != WORK_RESULT_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "work-result",
            version: version as u32,
        });
    }
    let exec_count = r.u64()?;
    let timeout_count = r.u64()?;
    let truncated = r.u8()? != 0;
    let disc_count = r.u32()? as usize;
    if disc_count > MAX_DISCOVERIES_PER_RESULT {
        return Err(Error::BoundExceeded {
            what: "discoveries per result",
            limit: MAX_DISCOVERIES_PER_RESULT as u64,
            got: disc_count as u64,
        });
    }
    let mut discoveries = Vec::with_capacity(disc_count);
    for _ in 0..disc_count {
        let dlen = r.u32()?;
        if dlen > MAX_DISCOVERY_RECORD_LEN {
            return Err(Error::BoundExceeded {
                what: "discovery record length",
                limit: u64::from(MAX_DISCOVERY_RECORD_LEN),
                got: u64::from(dlen),
            });
        }
        let dbytes = r.take(dlen as usize)?;
        discoveries.push(decode_discovery(dbytes)?);
    }
    let summary_bytes = r.bytes_of_len(4096)?;
    let signal_summary = decode_batch_summary(summary_bytes)?;
    let ov_count = r.u32()? as usize;
    if ov_count > MAX_FEATURES_PER_ORDER {
        return Err(Error::BoundExceeded {
            what: "override features",
            limit: MAX_FEATURES_PER_ORDER as u64,
            got: ov_count as u64,
        });
    }
    let mut override_features = Vec::with_capacity(ov_count);
    for _ in 0..ov_count {
        override_features.push(r.u64()?);
    }
    let override_signals = decode_signal_vector(&mut r)?;
    r.done()?;
    Ok(WorkResult {
        exec_count,
        timeout_count,
        discoveries,
        truncated,
        signal_summary,
        override_features,
        override_signals,
    })
}

// ---------------------------------------------------------------------------
// Hello
// ---------------------------------------------------------------------------

/// Encode a hello message.
pub fn encode_hello(hello: &Hello) -> Result<Vec<u8>> {
    if hello.rustc_release.len() > 256 || hello.llvm_version.len() > 256 {
        return Err(Error::Encoding("hello identity strings too long"));
    }
    if hello.schema.len() > MAX_SIGNALS {
        return Err(Error::BoundExceeded {
            what: "schema entries",
            limit: MAX_SIGNALS as u64,
            got: hello.schema.len() as u64,
        });
    }
    let mut w = WireWriter::new();
    w.u8(HELLO_VERSION);
    w.u8(hello.mode);
    w.u32(hello.range_count);
    w.u64(hello.total_counter_bytes);
    w.u32(hello.pid);
    w.len_u32_bytes(hello.rustc_release.len(), 256)?;
    w.bytes(hello.rustc_release.as_bytes());
    w.len_u32_bytes(hello.llvm_version.len(), 256)?;
    w.bytes(hello.llvm_version.as_bytes());
    w.u8(hello.schema.len() as u8);
    for e in &hello.schema {
        if e.name.len() > crate::target_runtime::signals::MAX_SIGNAL_NAME_LEN
            || e.unit.len() > crate::target_runtime::signals::MAX_SIGNAL_UNIT_LEN
        {
            return Err(Error::Encoding("schema entry too long"));
        }
        w.u16(e.id);
        w.u8(e.name.len() as u8);
        w.bytes(e.name.as_bytes());
        w.u8(e.unit.len() as u8);
        w.bytes(e.unit.as_bytes());
    }
    Ok(w.into_vec())
}

/// Decode a hello message.
pub fn decode_hello(bytes: &[u8]) -> Result<Hello> {
    let mut r = WireReader::new(bytes);
    let version = r.u8()?;
    if version != HELLO_VERSION {
        return Err(Error::UnsupportedVersion {
            family: "hello",
            version: version as u32,
        });
    }
    let mode = r.u8()?;
    let range_count = r.u32()?;
    let total_counter_bytes = r.u64()?;
    let pid = r.u32()?;
    let rustc_release = String::from_utf8(r.bytes_of_len(256)?.to_vec())
        .map_err(|_| Error::Encoding("hello rustc_release is not UTF-8"))?;
    let llvm_version = String::from_utf8(r.bytes_of_len(256)?.to_vec())
        .map_err(|_| Error::Encoding("hello llvm_version is not UTF-8"))?;
    let schema_count = r.u8()? as usize;
    if schema_count > MAX_SIGNALS {
        return Err(Error::BoundExceeded {
            what: "schema entries",
            limit: MAX_SIGNALS as u64,
            got: schema_count as u64,
        });
    }
    let mut schema = Vec::with_capacity(schema_count);
    for _ in 0..schema_count {
        let id = r.u16()?;
        let name_len = r.u8()? as usize;
        if name_len > crate::target_runtime::signals::MAX_SIGNAL_NAME_LEN {
            return Err(Error::BoundExceeded {
                what: "schema name length",
                limit: crate::target_runtime::signals::MAX_SIGNAL_NAME_LEN as u64,
                got: name_len as u64,
            });
        }
        let name = String::from_utf8(r.take(name_len)?.to_vec())
            .map_err(|_| Error::Encoding("schema name is not UTF-8"))?;
        let unit_len = r.u8()? as usize;
        if unit_len > crate::target_runtime::signals::MAX_SIGNAL_UNIT_LEN {
            return Err(Error::BoundExceeded {
                what: "schema unit length",
                limit: crate::target_runtime::signals::MAX_SIGNAL_UNIT_LEN as u64,
                got: unit_len as u64,
            });
        }
        let unit = String::from_utf8(r.take(unit_len)?.to_vec())
            .map_err(|_| Error::Encoding("schema unit is not UTF-8"))?;
        schema.push(SignalDescWire { id, name, unit });
    }
    r.done()?;
    Ok(Hello {
        mode,
        range_count,
        total_counter_bytes,
        pid,
        rustc_release,
        llvm_version,
        schema,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_order() -> WorkOrder {
        let mut signals = SignalVector::new();
        signals.observe(SignalId(0), 7).unwrap();
        WorkOrder {
            campaign_seed: 0xDEADBEEF,
            generation: 7,
            mutator_id: 12,
            lane_id: 3,
            start_index: 100,
            index_count: 500,
            parent: b"parent input bytes".to_vec(),
            parent_short: [0xAB; 8],
            parent_signals: signals,
            partner: b"partner".to_vec(),
            dictionary: vec![b"FIZZ".to_vec(), b"BUZZ".to_vec(), vec![0, 1, 2, 255]],
            new_features: vec![1, 2, 3, 0xFFFF_FFFF_0000_0000],
            input_override: Vec::new(),
        }
    }

    fn sample_discovery() -> DiscoveryRecord {
        let parent = SignalVector::new();
        let mut child = SignalVector::new();
        child.observe(SignalId(1), 42).unwrap();
        DiscoveryRecord {
            coordinate: crate::mutation::MutationCoordinate {
                campaign_seed: 1,
                parent_short_id: [2; 8],
                generation: 3,
                mutator_id: crate::mutation::MutatorId::ByteFlip,
                lane_id: 4,
                mutation_index: 5,
                probe_params: [0; 4],
            },
            status: ExecutionStatus::Ok,
            features: vec![1, 2, 3],
            cmp_events: vec![CmpEventWire {
                kind: 2,
                width: 4,
                a: 0xBEEF,
                b: 0,
            }],
            cmp_hits_used: vec![CmpHitWire {
                width: 4,
                value: 0xBEEF,
            }],
            signals: child.clone(),
            sketch: ResidualSketch::of(&parent, &child),
            time_bucket: 2,
        }
    }

    #[test]
    fn work_order_roundtrip() {
        let order = sample_order();
        let enc = encode_work_order(&order).unwrap();
        let dec = decode_work_order(&enc).unwrap();
        assert_eq!(dec.campaign_seed, order.campaign_seed);
        assert_eq!(dec.generation, order.generation);
        assert_eq!(dec.mutator_id, order.mutator_id);
        assert_eq!(dec.lane_id, order.lane_id);
        assert_eq!(dec.start_index, order.start_index);
        assert_eq!(dec.index_count, order.index_count);
        assert_eq!(dec.parent, order.parent);
        assert_eq!(dec.parent_short, order.parent_short);
        assert_eq!(dec.parent_signals, order.parent_signals);
        assert_eq!(dec.partner, order.partner);
        assert_eq!(dec.dictionary, order.dictionary);
        assert_eq!(dec.new_features, order.new_features);
        assert_eq!(dec.input_override, order.input_override);
    }

    #[test]
    fn work_order_encoding_is_canonical() {
        let order = sample_order();
        assert_eq!(
            encode_work_order(&order).unwrap(),
            encode_work_order(&order).unwrap()
        );
    }

    #[test]
    fn work_order_rejects_oversize_parent() {
        let mut order = sample_order();
        order.parent = vec![0; MAX_INPUT_LEN + 1];
        assert!(encode_work_order(&order).is_err());
    }

    #[test]
    fn work_order_rejects_oversize_dictionary_entry() {
        let mut order = sample_order();
        order.dictionary = vec![vec![0; MAX_DICT_ENTRY_LEN + 1]];
        assert!(encode_work_order(&order).is_err());
    }

    #[test]
    fn work_order_rejects_zero_count_without_override() {
        let mut order = sample_order();
        order.index_count = 0;
        assert!(encode_work_order(&order).is_err());
    }

    #[test]
    fn work_order_rejects_trailing_bytes() {
        let mut enc = encode_work_order(&sample_order()).unwrap();
        enc.push(0);
        assert!(decode_work_order(&enc).is_err());
    }

    #[test]
    fn work_order_rejects_truncation() {
        let enc = encode_work_order(&sample_order()).unwrap();
        assert!(decode_work_order(&enc[..enc.len() - 3]).is_err());
    }

    #[test]
    fn work_order_rejects_unknown_version() {
        let mut enc = encode_work_order(&sample_order()).unwrap();
        enc[0] = 1; // the old v1 byte layout
        assert!(matches!(
            decode_work_order(&enc),
            Err(Error::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn discovery_roundtrip() {
        let d = sample_discovery();
        let enc = encode_discovery(&d).unwrap();
        let dec = decode_discovery(&enc).unwrap();
        assert_eq!(dec.coordinate, d.coordinate);
        assert_eq!(dec.status, d.status);
        assert_eq!(dec.features, d.features);
        assert_eq!(dec.cmp_events, d.cmp_events);
        assert_eq!(dec.cmp_hits_used, d.cmp_hits_used);
        assert_eq!(dec.signals, d.signals);
        assert_eq!(dec.sketch, d.sketch);
        assert_eq!(dec.time_bucket, d.time_bucket);
    }

    #[test]
    fn discovery_rejects_bad_status() {
        let mut enc = encode_discovery(&sample_discovery()).unwrap();
        // status byte sits right after the fixed coordinate block.
        let status_at = crate::mutation::coordinate::COORDINATE_ENCODED_LEN;
        enc[status_at] = 99;
        assert!(decode_discovery(&enc).is_err());
    }

    #[test]
    fn work_result_roundtrip() {
        let parent = SignalVector::new();
        let mut summary = SignalBatchSummary::new();
        let mut child = SignalVector::new();
        child.observe(SignalId(0), 3).unwrap();
        let d = crate::target_runtime::signals::deltas(&parent, &child);
        summary.push_deltas(&child, &d);
        summary.max_run[0] = 4;
        let result = WorkResult {
            exec_count: 1000,
            timeout_count: 0,
            discoveries: vec![sample_discovery()],
            truncated: false,
            signal_summary: summary,
            override_features: vec![9, 10],
            override_signals: child.clone(),
        };
        let enc = encode_work_result(&result).unwrap();
        let dec = decode_work_result(&enc).unwrap();
        assert_eq!(dec.exec_count, 1000);
        assert_eq!(dec.discoveries.len(), 1);
        assert_eq!(dec.signal_summary, summary);
        assert_eq!(dec.override_features, vec![9, 10]);
        assert_eq!(dec.override_signals, child);
    }

    #[test]
    fn batch_summary_roundtrip_with_max_run() {
        let mut summary = SignalBatchSummary::new();
        summary.touched = 0b101;
        summary.count[0] = 5;
        summary.min[0] = 1;
        summary.max[0] = 9;
        summary.sum_abs_delta[0] = 31;
        summary.max_run[0] = 4;
        summary.count[2] = 2;
        summary.min[2] = 3;
        summary.max[2] = 4;
        summary.sum_abs_delta[2] = 5;
        summary.max_run[2] = 2;
        let enc = encode_batch_summary(&summary);
        let dec = decode_batch_summary(&enc).unwrap();
        assert_eq!(dec, summary);
    }

    #[test]
    fn batch_summary_wire_is_bounded() {
        let mut summary = SignalBatchSummary::new();
        summary.touched = u64::MAX; // all 64 signals
        for i in 0..MAX_SIGNALS {
            summary.count[i] = 1;
            summary.min[i] = 0;
            summary.max[i] = 1;
            summary.sum_abs_delta[i] = 1;
            summary.max_run[i] = 1;
        }
        let enc = encode_batch_summary(&summary);
        assert!(enc.len() <= 4096);
        assert_eq!(decode_batch_summary(&enc).unwrap(), summary);
    }

    #[test]
    fn hello_roundtrip_with_schema() {
        let hello = Hello {
            mode: mode::SANCOV_TRACECMP,
            range_count: 2,
            total_counter_bytes: 1024,
            pid: 42,
            rustc_release: "1.97.0-nightly".into(),
            llvm_version: "LLVM version: 22.1.2".into(),
            schema: vec![
                SignalDescWire {
                    id: 0,
                    name: "parsed_items".into(),
                    unit: "count".into(),
                },
                SignalDescWire {
                    id: 3,
                    name: "depth".into(),
                    unit: "".into(),
                },
            ],
        };
        let enc = encode_hello(&hello).unwrap();
        let dec = decode_hello(&enc).unwrap();
        assert_eq!(dec.mode, hello.mode);
        assert_eq!(dec.range_count, hello.range_count);
        assert_eq!(dec.total_counter_bytes, hello.total_counter_bytes);
        assert_eq!(dec.pid, hello.pid);
        assert_eq!(dec.rustc_release, hello.rustc_release);
        assert_eq!(dec.llvm_version, hello.llvm_version);
        assert_eq!(dec.schema.len(), 2);
        assert_eq!(dec.schema[0].id, 0);
        assert_eq!(dec.schema[0].name, "parsed_items");
        assert_eq!(dec.schema[1].unit, "");
    }

    #[test]
    fn schema_wire_conversion_roundtrip() {
        let mut schema = SignalSchema::empty();
        schema.set_desc(SignalId(1), {
            let mut d = SignalDesc::empty();
            d.present = true;
            d.name_len = 4;
            d.name[..4].copy_from_slice(b"deep");
            d.unit_len = 5;
            d.unit[..5].copy_from_slice(b"level");
            d
        });
        let wire = schema_to_wire(&schema).unwrap();
        assert_eq!(wire.len(), 1);
        assert_eq!(wire[0].id, 1);
        assert_eq!(wire[0].name, "deep");
        let back = wire_to_schema(&wire).unwrap();
        assert_eq!(back.count, 1);
        assert_eq!(back.desc(SignalId(1)).unwrap().name_str(), "deep");
        assert_eq!(back.desc(SignalId(1)).unwrap().unit_str(), "level");
    }

    #[test]
    fn wire_to_schema_refuses_duplicates_and_bad_ids() {
        let dup = vec![
            SignalDescWire {
                id: 0,
                name: "a".into(),
                unit: "".into(),
            },
            SignalDescWire {
                id: 0,
                name: "b".into(),
                unit: "".into(),
            },
        ];
        assert!(wire_to_schema(&dup).is_err());
        let bad = vec![SignalDescWire {
            id: MAX_SIGNALS as u16,
            name: "a".into(),
            unit: "".into(),
        }];
        assert!(wire_to_schema(&bad).is_err());
    }

    #[test]
    fn cmp_hit_wire_converts() {
        let h = CmpHitWire {
            width: 4,
            value: 0xDEAD_BEEF,
        };
        assert_eq!(h.to_hit(), CmpHit::U32(0xDEAD_BEEF));
        let h8 = CmpHitWire {
            width: 8,
            value: u64::MAX,
        };
        assert_eq!(h8.to_hit(), CmpHit::U64(u64::MAX));
    }

    #[test]
    fn signal_vector_wire_is_fixed_size() {
        let mut v = SignalVector::new();
        v.observe(SignalId(63), 1).unwrap();
        let mut w = WireWriter::new();
        encode_signal_vector(&mut w, &v);
        assert_eq!(w.into_vec().len(), SIGNAL_VECTOR_WIRE_LEN);
        let mut r = WireReader::new(&[0u8; SIGNAL_VECTOR_WIRE_LEN]);
        let zero = decode_signal_vector(&mut r).unwrap();
        assert_eq!(zero, SignalVector::new());
    }

    #[test]
    fn execution_status_codes_are_stable() {
        assert_eq!(ExecutionStatus::Ok.code(), 1);
        assert_eq!(ExecutionStatus::Crash.code(), 2);
        assert_eq!(ExecutionStatus::Timeout.code(), 3);
        assert_eq!(ExecutionStatus::from_byte(1), Some(ExecutionStatus::Ok));
        assert_eq!(ExecutionStatus::from_byte(9), None);
    }

    #[test]
    fn input_override_roundtrip() {
        let mut order = sample_order();
        order.input_override = b"exact candidate bytes".to_vec();
        let dec = decode_work_order(&encode_work_order(&order).unwrap()).unwrap();
        assert_eq!(dec.input_override, order.input_override);
    }
}
