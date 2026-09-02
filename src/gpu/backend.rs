//! Batch compute-backend contract (master prompt §25, §35 Phase 7).
//!
//! GPU acceleration is OPTIONAL and never changes semantics: the CPU
//! implementation is the semantic oracle, and every accelerated path must be
//! bit-for-bit identical (the same discipline as `simd`, docs/INVARIANTS.md
//! I3). This module defines the batch operations a device backend would
//! accelerate and the availability/fallback machinery that keeps an absent
//! accelerator from ever corrupting a campaign (I14, I15).
//!
//! # Evidence discipline (I8)
//!
//! Every operation in [`ComputeBackend`] produces *proposals, rankings,
//! distances, masks, or compact descriptors* — scheduling evidence only.
//! Nothing here decides "this is a bug", "this precedent is true", or "this
//! FRF claim passes". Those decisions belong to the CPU-side evidence plane.
//! A future device backend is quarantined on any disagreement with the CPU
//! oracle; the CPU result stands.
//!
//! # Integer-only kernels
//!
//! All canonical outputs are integers: distances are popcount sums, ranks are
//! integer fixed-point scores, masks are byte arrays, descriptors are 16-byte
//! integer folds. There are no floats in any output that could enter a
//! ranking or identity decision (docs/ARCHITECTURE.md §16 discipline). Every
//! op is a plain bounded loop over integer words — the exact shape a CUDA or
//! ROCm kernel must replicate.
//!
//! # Availability
//!
//! [`resolve`] selects a backend for a campaign: the CPU oracle by default;
//! a requested CUDA/ROCm backend is admitted ONLY when a probe passes. No
//! device adapter has been admitted yet (Phase-7 gate record,
//! docs/COMPATIBILITY.md §6), so [`probe`] reports CUDA/ROCm unavailable
//! with an actionable reason and [`resolve`] falls back to the CPU oracle —
//! semantics unchanged.

use crate::error::{Error, Result};
use crate::mutation::prng::CounterRng;

/// Fixed width of one signature row, in u64 words (16 words = 128 bytes of
/// canonical integer signature words).
pub const SIGNATURE_WORDS: usize = 16;

/// Maximum signature rows in one batch (each `SIGNATURE_WORDS` u64s).
pub const MAX_SIGNATURE_ROWS: usize = 1 << 14;

/// Maximum precedent rows in one rank batch.
pub const MAX_PRECEDENT_ROWS: usize = 1 << 12;

/// Maximum candidate entries in one plan request.
pub const MAX_CANDIDATES: usize = 1 << 16;

/// Maximum total orders a plan request may produce.
pub const MAX_TOTAL_ORDERS: u32 = 1 << 22;

/// Maximum executions attributed to one order.
pub const MAX_EXECUTIONS_PER_ORDER: u32 = 1 << 20;

/// Maximum inputs in one mask batch.
pub const MAX_MASK_INPUTS: usize = 1 << 12;

/// Maximum total mask bytes across one batch (bounded before allocation).
pub const MAX_MASK_TOTAL_BYTES: usize = 1 << 26;

/// Maximum total bytes compacted in one descriptor batch.
pub const MAX_COMPACT_TOTAL_BYTES: usize = 1 << 26;

/// Maximum length of one compacted input.
pub const MAX_COMPACT_INPUT_LEN: usize = 1 << 20;

/// Maximum fixed-point weight on one precedent row.
pub const MAX_WEIGHT: u32 = 1 << 20;

/// A device/backend kind. Stable codes for reporting; never persisted as
/// semantic identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BackendKind {
    /// The CPU oracle (normative semantics; always available).
    Cpu = 0,
    /// A CUDA device backend (not yet admitted; see module docs).
    Cuda = 1,
    /// A ROCm/HIP device backend (not yet admitted).
    Rocm = 2,
}

impl BackendKind {
    /// The stable wire code.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            BackendKind::Cpu => "cpu",
            BackendKind::Cuda => "cuda",
            BackendKind::Rocm => "rocm",
        }
    }
}

/// Result of probing one backend kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// The probed kind.
    pub kind: BackendKind,
    /// True if the backend can be used right now.
    pub available: bool,
    /// Why it is or is not available (actionable, static).
    pub reason: &'static str,
}

/// Probe a backend kind. The CPU oracle is always available. Device backends
/// are admitted only when an adapter exists AND the Phase-7 parity gates have
/// been verified on real hardware (docs/COMPATIBILITY.md §6) — none has been
/// yet, so CUDA/ROCm probe unavailable with the reason recorded here.
pub fn probe(kind: BackendKind) -> Probe {
    match kind {
        BackendKind::Cpu => Probe {
            kind,
            available: true,
            reason: "cpu oracle (normative semantics)",
        },
        BackendKind::Cuda => Probe {
            kind,
            available: false,
            reason: if cfg!(feature = "cuda") {
                "cuda feature enabled but no adapter admitted: the Phase-7 parity gates \
                 (CPU == CUDA bit-for-bit, repeated device determinism, measured speedup) \
                 are unverified on this machine"
            } else {
                "cuda feature disabled"
            },
        },
        BackendKind::Rocm => Probe {
            kind,
            available: false,
            reason: if cfg!(feature = "rocm") {
                "rocm feature enabled but no adapter admitted: the Phase-7 parity gates \
                 (CPU == ROCm bit-for-bit, repeated device determinism, measured speedup) \
                 are unverified on this machine"
            } else {
                "rocm feature disabled"
            },
        },
    }
}

/// The resolved compute configuration for a campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeConfig {
    /// The backend that will run batch proposals.
    pub backend: BackendKind,
    /// Set when a requested accelerator was NOT admitted and the campaign
    /// fell back to the CPU oracle (I14/I15): the reason is recorded, never
    /// silent.
    pub fallback_note: Option<&'static str>,
}

/// Resolve a campaign's requested backend. `None` (the default) or `Cpu`
/// selects the CPU oracle. A requested `Cuda`/`Rocm` backend is admitted only
/// if [`probe`] passes; otherwise the CPU oracle is used and the refusal is
/// reported in [`ComputeConfig::fallback_note`] — an unavailable accelerator
/// never changes campaign semantics.
pub fn resolve(requested: Option<BackendKind>) -> ComputeConfig {
    match requested {
        None | Some(BackendKind::Cpu) => ComputeConfig {
            backend: BackendKind::Cpu,
            fallback_note: None,
        },
        Some(kind) => {
            let p = probe(kind);
            if p.available {
                ComputeConfig {
                    backend: kind,
                    fallback_note: None,
                }
            } else {
                ComputeConfig {
                    backend: BackendKind::Cpu,
                    fallback_note: Some(p.reason),
                }
            }
        }
    }
}

/// Metadata of one candidate for mutation-plan proposals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateMeta {
    /// The corpus entry's short content id (parent for the proposed orders).
    pub parent_short: [u8; 8],
    /// Integer scheduling priority (higher = more of the plan budget).
    pub priority: u32,
}

/// One proposed work order: which parent, which mutator family, how many
/// executions, and the deterministic mutation-index base.
///
/// A proposal is evidence for SCHEDULING only: nothing here executes the
/// target or admits anything. The coordinator that turns a proposal into real
/// `WorkOrder`s derives exact mutation coordinates from its own rules; every
/// mutation remains reconstructible from its `MutationCoordinate` (I2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationPlanProposal {
    /// Parent corpus-entry short id.
    pub parent_short: [u8; 8],
    /// Mutator family id (stable table; `mutation::MutatorId`).
    pub mutator: u16,
    /// Lane id (bounded to 16 bits of the proposal index).
    pub lane: u32,
    /// Executions this order should run.
    pub count: u32,
    /// Deterministic mutation-index base for this order.
    pub start_index: u64,
}

/// A batch plan request.
#[derive(Debug, Clone)]
pub struct PlanBatchRequest<'a> {
    /// Candidate parents, in input order (indices are the tie-break key).
    pub candidates: &'a [CandidateMeta],
    /// Total number of orders to propose across the batch.
    pub total_orders: u32,
    /// Executions per proposed order.
    pub executions_per_order: u32,
    /// Deterministic batch seed (part of every proposal's provenance).
    pub seed: u64,
    /// Allowed mutator family ids (subset of the stable table, non-empty).
    pub mutators: &'a [u16],
}

/// One mask batch: per-input influence masks over the input's byte range,
/// laid out contiguously. `offsets[i]` is the start of input `i`'s mask in
/// `data`; input `i` has length `lens[i]`, so its mask is
/// `data[offsets[i] .. offsets[i] + lens[i]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskBatch {
    /// Input lengths, in order.
    pub lens: Vec<u32>,
    /// Start offset of each input's mask within `data`.
    pub offsets: Vec<u32>,
    /// Flattened masks (1 = region mutable for the hierarchical
    /// perturbation step).
    pub data: Vec<u8>,
}

/// One compact descriptor batch input view: flattened `data` plus `offsets`,
/// where `offsets[i]` is the start of input `i` and input `i` ends where
/// input `i + 1` begins (the last ends at `data.len()`).
#[derive(Debug, Clone, Copy)]
pub struct CompactBatch<'a> {
    /// Flattened candidate bytes.
    pub data: &'a [u8],
    /// Per-input start offsets (must be ascending; the first must be 0;
    /// equal consecutive offsets denote a zero-length input).
    pub offsets: &'a [u32],
}

/// Sort scores descending, ties by ascending index. Deterministic (stable).
pub fn rank_desc(scores: &[i64]) -> Vec<u32> {
    let mut order: Vec<u32> = (0..scores.len() as u32).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(scores[i as usize]));
    order
}

/// A batch accelerator. The CPU oracle ([`crate::gpu::cpu::CpuBackend`])
/// implements every operation with plain integer loops; a future device
/// backend must be bit-for-bit identical and is admitted only after the
/// Phase-7 parity gates pass (module docs). No operation has final semantic
/// authority (I8): outputs are proposals/rankings/descriptors only.
pub trait ComputeBackend {
    /// The kind of this backend.
    fn kind(&self) -> BackendKind;

    /// Deterministically propose `total_orders` mutation orders across the
    /// candidate batch: each candidate receives a share of the budget
    /// proportional to its priority (u64 largest-remainder allocation), and
    /// its orders rotate through the allowed mutator families seeded by the
    /// batch seed. Output is proposal evidence only.
    fn generate_mutation_plans(
        &self,
        req: &PlanBatchRequest<'_>,
    ) -> Result<Vec<MutationPlanProposal>>;

    /// Fixed-width morphology distance between two equal-length batches of
    /// signature rows (both flattened `row_count * SIGNATURE_WORDS` u64s):
    /// per row, the sum of xor-popcounts over its words — an integer
    /// in `[0, SIGNATURE_WORDS * 64]` per row.
    fn morphology_distance(&self, left: &[u64], right: &[u64]) -> Result<Vec<u32>>;

    /// Rank `candidate_rows` (flattened `n * SIGNATURE_WORDS`) against
    /// `precedent_rows` (flattened `m * SIGNATURE_WORDS`) with integer
    /// fixed-point weights: `score_i = sum_p w_p * (max_dist -
    /// dist(row_i, precedent_p))`. Integer scores only; ordering is derived
    /// with [`rank_desc`] by the caller. Ranking evidence only (I8).
    fn precedent_rank(
        &self,
        candidate_rows: &[u64],
        precedent_rows: &[u64],
        weights: &[u32],
    ) -> Result<Vec<i64>>;

    /// Deterministic per-input influence masks: for input `j` of length `L`,
    /// mask byte `k` is 1 iff the seeded stream bit is set (a coded
    /// group-perturbation mask over the input's byte range, §22). Masks are
    /// integer, deterministic, and bounded.
    fn influence_masks(&self, lens: &[u32], seed: u64) -> Result<MaskBatch>;

    /// Deterministic 16-byte compact descriptors over the batch (integer
    /// fold, seed-mixed). NOT canonical identity (BLAKE3-256 is): compact
    /// descriptors are for device-resident bookkeeping/ranking only, and a
    /// collision is possible — documented, never used for store identity.
    fn compact_descriptors(&self, batch: &CompactBatch<'_>) -> Result<Vec<[u8; 16]>>;
}

// ---------------------------------------------------------------------------
// Shared validation helpers (integer-only; used by every backend so the
// contract is enforced identically before any kernel runs).
// ---------------------------------------------------------------------------

/// Validate a flattened signature-row batch length; returns the row count.
/// An empty batch is valid (empty in -> empty out); a non-multiple or
/// over-bounded batch is refused.
pub(crate) fn check_signature_rows(words: &[u64], what: &'static str) -> Result<usize> {
    if !words.len().is_multiple_of(SIGNATURE_WORDS) {
        return Err(Error::Other(format!(
            "{what} length {} is not a multiple of SIGNATURE_WORDS {SIGNATURE_WORDS}",
            words.len()
        )));
    }
    let rows = words.len() / SIGNATURE_WORDS;
    if rows > MAX_SIGNATURE_ROWS {
        return Err(Error::BoundExceeded {
            what,
            limit: MAX_SIGNATURE_ROWS as u64,
            got: rows as u64,
        });
    }
    Ok(rows)
}

/// Validate a flattened mask-batch input list and its total byte budget.
/// An empty batch is valid (empty in -> empty out).
pub(crate) fn check_mask_inputs(lens: &[u32]) -> Result<()> {
    if lens.len() > MAX_MASK_INPUTS {
        return Err(Error::BoundExceeded {
            what: "mask batch inputs",
            limit: MAX_MASK_INPUTS as u64,
            got: lens.len() as u64,
        });
    }
    let total: u64 = lens.iter().map(|l| u64::from(*l)).sum();
    if total > MAX_MASK_TOTAL_BYTES as u64 {
        return Err(Error::BoundExceeded {
            what: "mask batch total bytes",
            limit: MAX_MASK_TOTAL_BYTES as u64,
            got: total,
        });
    }
    Ok(())
}

/// Validate a compact-batch view (ascending offsets starting at 0, bounded).
/// An empty batch is valid (empty in -> empty out). Returns the input count.
pub(crate) fn check_compact_batch(batch: &CompactBatch<'_>) -> Result<usize> {
    if batch.offsets.len() > MAX_MASK_INPUTS {
        return Err(Error::BoundExceeded {
            what: "compact batch inputs",
            limit: MAX_MASK_INPUTS as u64,
            got: batch.offsets.len() as u64,
        });
    }
    if !batch.offsets.is_empty() && batch.offsets[0] != 0 {
        return Err(Error::Encoding("compact batch first offset must be 0"));
    }
    for (i, o) in batch.offsets.iter().enumerate() {
        if i + 1 < batch.offsets.len() && batch.offsets[i + 1] < *o {
            return Err(Error::Encoding("compact batch offsets must be ascending"));
        }
        let end = if i + 1 < batch.offsets.len() {
            batch.offsets[i + 1]
        } else {
            batch.data.len() as u32
        };
        let len = end.saturating_sub(*o) as usize;
        if len > MAX_COMPACT_INPUT_LEN {
            return Err(Error::BoundExceeded {
                what: "compact input length",
                limit: MAX_COMPACT_INPUT_LEN as u64,
                got: len as u64,
            });
        }
        if end as usize > batch.data.len() {
            return Err(Error::Encoding("compact batch offsets exceed data length"));
        }
    }
    if batch.data.len() > MAX_COMPACT_TOTAL_BYTES {
        return Err(Error::BoundExceeded {
            what: "compact batch total bytes",
            limit: MAX_COMPACT_TOTAL_BYTES as u64,
            got: batch.data.len() as u64,
        });
    }
    Ok(batch.offsets.len())
}

/// Per-candidate seeded stream (Philox; the same counter-based RNG as the
/// mutation engine, so a device kernel can reproduce it exactly).
pub(crate) fn seeded_rng(seed: u64, index: u32, salt: u32) -> CounterRng {
    CounterRng::from_philox(
        [seed as u32, (seed >> 32) as u32, index, salt],
        [0xD1CE_5EED, 0xF00D_CAFE],
    )
}
