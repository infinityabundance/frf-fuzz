//! Semantic signal vector, target signal schema, and the cheap per-execution
//! residual sketch.
//!
//! # Two planes, one representation
//!
//! Targets observe program-state quantities (parsed item count, allocation
//! high-water, retry count, ...) through a pre-registered schema of compact
//! numeric IDs. No signal strings in the hot loop: registration happens once
//! (setup hook), and the worker exchanges fixed-size [`SignalVector`]s.
//!
//! Signal values are `u64` and saturation-free (wrapping): a target that
//! observes a negative quantity as `i64` casts it. The *units* and *meaning*
//! of each ID live in the schema (sent to the coordinator in HELLO and
//! persisted as a `SignalSchema` store object), not in the runtime.
//!
//! # The residual sketch
//!
//! The per-execution [`ResidualSketch`] is the Level-0 "cheap residual
//! sketch" (master prompt §1): a fixed-size, heap-free, fully deterministic
//! bucketized comparison of the child's signal vector against the parent's
//! recorded observation. It is what lets the worker decide "interesting"
//! (drift/persistence/state-expansion) locally without any history beyond a
//! per-order accumulator, and what the coordinator aggregates into batch
//! summaries. Scalar semantics are normative; the sketch is pure integer
//! arithmetic over fixed arrays (docs/ARCHITECTURE.md §10).

/// Maximum number of semantic signals per target. Bounded so the per-execution
/// vector is a fixed-size array.
pub const MAX_SIGNALS: usize = 64;

/// Maximum length of a registered signal name (bytes).
pub const MAX_SIGNAL_NAME_LEN: usize = 32;
/// Maximum length of a registered signal unit (bytes).
pub const MAX_SIGNAL_UNIT_LEN: usize = 16;

/// A compact, pre-registered signal ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignalId(pub u16);

impl SignalId {
    /// The raw numeric ID.
    pub const fn id(self) -> u16 {
        self.0
    }

    /// Bounds-checked construction; `None` beyond [`MAX_SIGNALS`].
    pub const fn new(id: u16) -> Option<SignalId> {
        if (id as usize) < MAX_SIGNALS {
            Some(SignalId(id))
        } else {
            None
        }
    }
}

/// The fixed-size per-execution signal vector. Pre-zeroed; the worker resets
/// it before each execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalVector {
    values: [u64; MAX_SIGNALS],
    touched: u64, // bitmask: which signal IDs were observed this execution
}

impl SignalVector {
    /// A fresh, all-zero vector.
    pub const fn new() -> SignalVector {
        SignalVector {
            values: [0; MAX_SIGNALS],
            touched: 0,
        }
    }

    /// Reset for a new execution.
    pub fn reset(&mut self) {
        self.values = [0; MAX_SIGNALS];
        self.touched = 0;
    }

    /// Record an observation. Out-of-schema IDs are refused (a programming
    /// error in the target, not silent truncation).
    pub fn observe(&mut self, id: SignalId, value: u64) -> Result<(), crate::error::Error> {
        let idx = id.0 as usize;
        if idx >= MAX_SIGNALS {
            return Err(crate::error::Error::BoundExceeded {
                what: "signal id",
                limit: MAX_SIGNALS as u64,
                got: id.0 as u64,
            });
        }
        self.values[idx] = value;
        self.touched |= 1u64 << idx;
        Ok(())
    }

    /// The value of a signal (0 if never observed this execution).
    pub fn value(&self, id: SignalId) -> u64 {
        self.values[id.0 as usize]
    }

    /// Whether the signal was observed this execution.
    pub fn was_touched(&self, id: SignalId) -> bool {
        self.touched & (1u64 << id.0) != 0
    }

    /// Bitmask of observed signals.
    pub fn touched_mask(&self) -> u64 {
        self.touched
    }

    /// Borrow the raw values (for the execution sketch).
    pub fn as_slice(&self) -> &[u64; MAX_SIGNALS] {
        &self.values
    }
}

impl Default for SignalVector {
    fn default() -> Self {
        SignalVector::new()
    }
}

/// One registered signal's schema entry: a bounded name and unit.
///
/// Fixed-size byte arrays keep the schema heap-free in the worker; the
/// canonical wire/store encoding lives in the coordinator's
/// [`crate::observe::signals`] module. Names and units are ASCII, bounded,
/// and never flow through the per-execution hot path (they are captured once
/// after setup and sent in HELLO).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalDesc {
    /// The signal is registered.
    pub present: bool,
    /// Signal name bytes (ASCII, right-padded with NULs).
    pub name: [u8; MAX_SIGNAL_NAME_LEN],
    /// Name length in bytes (1..=MAX_SIGNAL_NAME_LEN).
    pub name_len: u8,
    /// Unit bytes (ASCII, right-padded with NULs).
    pub unit: [u8; MAX_SIGNAL_UNIT_LEN],
    /// Unit length in bytes (0..=MAX_SIGNAL_UNIT_LEN; empty unit allowed).
    pub unit_len: u8,
}

impl SignalDesc {
    /// The name as a `&str` (validated at registration; ASCII only).
    pub fn name_str(&self) -> &str {
        let n = (self.name_len as usize).min(MAX_SIGNAL_NAME_LEN);
        // SAFETY-free: the bytes were validated ASCII at registration.
        std::str::from_utf8(&self.name[..n]).unwrap_or("")
    }

    /// The unit as a `&str`.
    pub fn unit_str(&self) -> &str {
        let n = (self.unit_len as usize).min(MAX_SIGNAL_UNIT_LEN);
        std::str::from_utf8(&self.unit[..n]).unwrap_or("")
    }

    /// An empty (unregistered) descriptor.
    pub const fn empty() -> SignalDesc {
        SignalDesc {
            present: false,
            name: [0; MAX_SIGNAL_NAME_LEN],
            name_len: 0,
            unit: [0; MAX_SIGNAL_UNIT_LEN],
            unit_len: 0,
        }
    }
}

/// The fixed-size target signal schema (one descriptor per ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalSchema {
    descs: [SignalDesc; MAX_SIGNALS],
    /// Number of registered signals.
    pub count: u8,
}

impl SignalSchema {
    /// An empty schema.
    pub const fn empty() -> SignalSchema {
        SignalSchema {
            descs: [SignalDesc::empty(); MAX_SIGNALS],
            count: 0,
        }
    }

    /// The descriptor for a signal, or `None` when unregistered.
    pub fn desc(&self, id: SignalId) -> Option<&SignalDesc> {
        let d = &self.descs[id.0 as usize];
        if d.present {
            Some(d)
        } else {
            None
        }
    }

    /// Iterate registered descriptors in ID order.
    pub fn iter(&self) -> impl Iterator<Item = (SignalId, &SignalDesc)> {
        self.descs
            .iter()
            .enumerate()
            .filter(|(_, d)| d.present)
            .map(|(i, d)| (SignalId(i as u16), d))
    }

    /// Validate an ASCII name/unit pair for registration.
    pub fn validate(name: &str, unit: &str) -> Result<(), crate::error::Error> {
        if name.is_empty() || name.len() > MAX_SIGNAL_NAME_LEN {
            return Err(crate::error::Error::BoundExceeded {
                what: "signal name length",
                limit: MAX_SIGNAL_NAME_LEN as u64,
                got: name.len() as u64,
            });
        }
        if unit.len() > MAX_SIGNAL_UNIT_LEN {
            return Err(crate::error::Error::BoundExceeded {
                what: "signal unit length",
                limit: MAX_SIGNAL_UNIT_LEN as u64,
                got: unit.len() as u64,
            });
        }
        if !name.is_ascii() || !unit.is_ascii() {
            return Err(crate::error::Error::Encoding(
                "signal names and units must be ASCII",
            ));
        }
        if name.chars().any(|c| c.is_control()) || unit.chars().any(|c| c.is_control()) {
            return Err(crate::error::Error::Encoding(
                "signal names and units must not contain control characters",
            ));
        }
        Ok(())
    }

    /// Insert a validated descriptor (wire decode helper). Maintains the
    /// registered count (a previously-present slot is a caller error; the
    /// wire path refuses duplicates before calling).
    pub(crate) fn set_desc(&mut self, id: SignalId, desc: SignalDesc) {
        if !self.descs[id.0 as usize].present {
            self.count = self.count.saturating_add(1);
        }
        self.descs[id.0 as usize] = desc;
    }
}

impl Default for SignalSchema {
    fn default() -> Self {
        SignalSchema::empty()
    }
}

/// Bucket a signal *value* (not a delta) into a bounded integer class.
///
/// Exact for small values (0..=63 — the region where fine structure matters),
/// then linear, then logarithmic. The output range is 0..=179 (u8; the
/// function never saturates for u64 inputs), so a global state-feature set
/// of (signal, bucket) pairs is bounded at 64 × 180 = 11520 entries
/// (§21 "Bound every corpus dimension").
///
/// This is a *normalization with a declared law* (docs/INVARIANTS.md): the
/// bucket is derived deterministically from the value and the law is
/// documented here, so no evidence is hidden — the raw value always travels
/// with the observation.
pub fn value_bucket(v: u64) -> u8 {
    if v < 64 {
        v as u8
    } else if v < 4096 {
        // 64 + (v / 64): 64..=127 for v in 64..=4095.
        64u8.saturating_add((v / 64) as u8)
    } else {
        // 128 + ilog2(v >> 12): 128..=179 for v in 4096..=u64::MAX.
        128u8.saturating_add((v >> 12).ilog2() as u8)
    }
}

/// Bucket a *magnitude* (a delta's absolute value) into a bounded class.
///
/// 0 stays 0; otherwise 1 + ilog2(m), capped at 63. Bucket 1 = 1,
/// bucket 2 = 2..=3, bucket 3 = 4..=7, ... — logarithmic, monotone,
/// deterministic. Used by the residual sketch and morphology magnitude bins.
pub fn magnitude_bucket(m: u64) -> u8 {
    if m == 0 {
        0
    } else {
        m.ilog2().saturating_add(1).min(63) as u8
    }
}

/// The cheap fixed-size per-execution residual sketch: child observation
/// bucketized against the parent's recorded observation.
/// Fields (all deterministic integer classes):
///
/// * `mag_buckets[s]` — [`magnitude_bucket`] of |child - parent| per signal
///   (0 when the child did not touch the signal);
/// * `dir_bits` — 2 bits per signal: 0 = no movement, 1 = child > parent,
///   2 = child < parent;
/// * `touched_new` — signals the child touched that the parent did not;
/// * `touched_lost` — signals the parent touched that the child did not.
///
/// The sketch is a *lossy* view by design (buckets, not raw deltas); the raw
/// child signal vector always travels alongside it in the discovery record,
/// so the coordinator can compute exact residuals when it needs them. The
/// sketch exists to keep the worker's per-execution filtering and the batch
/// aggregation bounded and heap-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidualSketch {
    /// Per-signal magnitude buckets (0 = no delta).
    pub mag_buckets: [u8; MAX_SIGNALS],
    /// Two bits per signal (see module docs).
    pub dir_bits: u128,
    /// Child-touched-but-parent-untouched bitmask.
    pub touched_new: u64,
    /// Parent-touched-but-child-untouched bitmask.
    pub touched_lost: u64,
}

impl ResidualSketch {
    /// A zeroed sketch (no movement on any axis).
    pub const fn zeroed() -> ResidualSketch {
        ResidualSketch {
            mag_buckets: [0; MAX_SIGNALS],
            dir_bits: 0,
            touched_new: 0,
            touched_lost: 0,
        }
    }

    /// Compute the sketch of `child` against `parent`.
    ///
    /// An untouchd parent signal is treated as baseline 0 (the child
    /// "introduced" the signal). Deltas are saturated i64 differences
    /// (checked arithmetic; a wrapped u64 difference would be a wrong sign).
    pub fn of(parent: &SignalVector, child: &SignalVector) -> ResidualSketch {
        let mut s = ResidualSketch::default();
        let mut dir_bits: u128 = 0;
        for i in 0..MAX_SIGNALS {
            let id = SignalId(i as u16);
            let ct = child.was_touched(id);
            let pt = parent.was_touched(id);
            if ct && !pt {
                s.touched_new |= 1u64 << i;
            }
            if pt && !ct {
                s.touched_lost |= 1u64 << i;
            }
            if ct {
                let pv = if pt { parent.value(id) } else { 0 };
                let cv = child.value(id);
                let delta =
                    (cv as i128 - pv as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64;
                s.mag_buckets[i] = magnitude_bucket(delta.unsigned_abs());
                let dir: u128 = if delta > 0 {
                    1
                } else if delta < 0 {
                    2
                } else {
                    0
                };
                dir_bits |= dir << (2 * i);
            }
        }
        s.dir_bits = dir_bits;
        s
    }

    /// The 2-bit direction of signal `i` (0 none, 1 up, 2 down).
    pub fn dir(&self, i: usize) -> u8 {
        ((self.dir_bits >> (2 * i)) & 0b11) as u8
    }

    /// The set of signals with any nonzero movement (bitmask).
    pub fn moved(&self) -> u64 {
        let mut m = 0u64;
        for i in 0..MAX_SIGNALS {
            if self.mag_buckets[i] != 0 {
                m |= 1u64 << i;
            }
        }
        m
    }

    /// Bitmask of signals with a magnitude at or above `bucket`.
    pub fn at_or_above(&self, bucket: u8) -> u64 {
        let mut m = 0u64;
        for i in 0..MAX_SIGNALS {
            if self.mag_buckets[i] >= bucket {
                m |= 1u64 << i;
            }
        }
        m
    }
}

/// The bounded per-signal tracker a worker keeps for ONE work order (one
/// parent, one mutator family). It turns a batch of per-execution sketches
/// into a persistent-drift decision without any history beyond these fields.
///
/// `run`/`last_dir` implement the "consecutive same-direction" persistence
/// rule; `cum_abs` accumulates |delta| vs the parent across the batch so a
/// weak-but-consistent effect is distinguishable from noise (the master
/// prompt's AMPLIFY signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderSignalTracker {
    /// Current consecutive same-direction run length (capped).
    pub run: [u8; MAX_SIGNALS],
    /// Last nonzero direction per signal (0 none, 1 up, 2 down).
    pub last_dir: [u8; MAX_SIGNALS],
    /// Saturating cumulative |delta| vs parent across the batch.
    pub cum_abs: [u64; MAX_SIGNALS],
}

impl OrderSignalTracker {
    /// A fresh tracker.
    pub const fn new() -> OrderSignalTracker {
        OrderSignalTracker {
            run: [0; MAX_SIGNALS],
            last_dir: [0; MAX_SIGNALS],
            cum_abs: [0; MAX_SIGNALS],
        }
    }

    /// Fold one execution into the tracker. Returns the mask of signals
    /// currently satisfying the persistence rule (same-direction run at
    /// least `min_run`, or cumulative magnitude bucket at least
    /// `min_cum_bucket`). The OR keeps a weak-but-consistent effect visible
    /// even when consecutive same-sign deltas are rare — the AND form was
    /// too sparse and starved the coordinator of trajectory points (a
    /// Phase-2 finding). The worker pushes every persistent execution,
    /// bounded by the per-result byte budget, so the coordinator sees the
    /// full trajectory stream.
    pub fn push(
        &mut self,
        deltas: &[i64; MAX_SIGNALS],
        sketch: &ResidualSketch,
        min_run: u8,
        min_cum_bucket: u8,
    ) -> u64 {
        let mut persistent = 0u64;
        // Parallel fixed-size arrays indexed by signal id: the range form is
        // intentional (the index also feeds `1u64 << i` masks).
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_SIGNALS {
            let dir = sketch.dir(i);
            if dir == 0 {
                continue;
            }
            self.cum_abs[i] = self.cum_abs[i].saturating_add(deltas[i].unsigned_abs());
            if dir == self.last_dir[i] {
                self.run[i] = self.run[i].saturating_add(1);
            } else {
                self.run[i] = 1;
            }
            self.last_dir[i] = dir;
            let cum_bucket = magnitude_bucket(self.cum_abs[i]);
            if self.run[i] >= min_run || cum_bucket >= min_cum_bucket {
                persistent |= 1u64 << i;
            }
        }
        persistent
    }
}

/// The bounded per-order batch summary: per-signal aggregates over every
/// execution in a work order (not just the discoveries). This is how the
/// full observation stream — including executions the coordinator never
/// admits — reaches the coordinator without per-execution IPC (§26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalBatchSummary {
    /// Signals touched by at least one execution.
    pub touched: u64,
    /// Executions touching the signal.
    pub count: [u32; MAX_SIGNALS],
    /// Minimum observed value (over touched executions).
    pub min: [u64; MAX_SIGNALS],
    /// Maximum observed value.
    pub max: [u64; MAX_SIGNALS],
    /// Saturating sum of |delta| vs the order's parent (over all execs).
    pub sum_abs_delta: [u64; MAX_SIGNALS],
    /// Maximum same-direction run observed in the batch (persistence).
    pub max_run: [u8; MAX_SIGNALS],
}

impl SignalBatchSummary {
    /// A fresh summary.
    pub const fn new() -> SignalBatchSummary {
        SignalBatchSummary {
            touched: 0,
            count: [0; MAX_SIGNALS],
            min: [u64::MAX; MAX_SIGNALS],
            max: [0; MAX_SIGNALS],
            sum_abs_delta: [0; MAX_SIGNALS],
            max_run: [0; MAX_SIGNALS],
        }
    }

    /// Fold one execution's exact deltas into the summary (the worker passes
    /// the per-signal saturating delta it already computed).
    pub fn push_deltas(&mut self, child: &SignalVector, deltas: &[i64; MAX_SIGNALS]) {
        // Parallel fixed-size arrays indexed by signal id.
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_SIGNALS {
            if child.was_touched(SignalId(i as u16)) {
                self.touched |= 1u64 << i;
                self.count[i] = self.count[i].saturating_add(1);
                let v = child.value(SignalId(i as u16));
                self.min[i] = self.min[i].min(v);
                self.max[i] = self.max[i].max(v);
            }
            self.sum_abs_delta[i] = self.sum_abs_delta[i].saturating_add(deltas[i].unsigned_abs());
        }
    }
}

impl Default for OrderSignalTracker {
    fn default() -> Self {
        OrderSignalTracker::new()
    }
}

impl Default for SignalBatchSummary {
    fn default() -> Self {
        SignalBatchSummary::new()
    }
}

impl Default for ResidualSketch {
    fn default() -> Self {
        ResidualSketch::zeroed()
    }
}

/// Compute the exact saturating child-vs-parent delta for one signal.
/// Untouched signals contribute 0 on both sides (a child that introduces a
/// signal is compared against a parent baseline of 0).
pub fn delta(parent: &SignalVector, child: &SignalVector, i: usize) -> i64 {
    let id = SignalId(i as u16);
    let pv = if parent.was_touched(id) {
        parent.value(id)
    } else {
        0
    };
    let cv = if child.was_touched(id) {
        child.value(id)
    } else {
        0
    };
    (cv as i128 - pv as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Per-signal exact saturating deltas (child - parent).
pub fn deltas(parent: &SignalVector, child: &SignalVector) -> [i64; MAX_SIGNALS] {
    let mut out = [0i64; MAX_SIGNALS];
    #[allow(clippy::needless_range_loop)]
    for i in 0..MAX_SIGNALS {
        out[i] = delta(parent, child, i);
    }
    out
}

/// The handle handed to a fuzz target's closure.
///
/// `fuzz_target!` provides this as `cx`; targets call `cx.observe_u64(...)`
/// for semantic signals and `cx.register_signal(...)` (setup hook) for the
/// schema. The context also carries the mutable per-execution input buffer
/// for the `execute` hook contract.
#[derive(Debug)]
pub struct FuzzContext {
    signals: SignalVector,
    schema: SignalSchema,
    /// Execution ordinal (worker-maintained; targets may read it).
    pub execution_ordinal: u64,
}

impl FuzzContext {
    /// A fresh context.
    pub fn new() -> FuzzContext {
        FuzzContext {
            signals: SignalVector::new(),
            schema: SignalSchema::empty(),
            execution_ordinal: 0,
        }
    }

    /// Reset per-execution state (the schema is NOT reset: it is registered
    /// once in setup and must survive every execution).
    pub fn reset(&mut self) {
        self.signals.reset();
    }

    /// Register a signal's name/unit (setup hook; once per signal).
    ///
    /// Registration is idempotent for identical name/unit pairs; a
    /// conflicting re-registration is an error (a target programming error,
    /// not silent truncation).
    pub fn register_signal(
        &mut self,
        id: SignalId,
        name: &str,
        unit: &str,
    ) -> Result<(), crate::error::Error> {
        SignalSchema::validate(name, unit)?;
        let idx = id.0 as usize;
        if idx >= MAX_SIGNALS {
            return Err(crate::error::Error::BoundExceeded {
                what: "signal id",
                limit: MAX_SIGNALS as u64,
                got: id.0 as u64,
            });
        }
        let existing = &self.schema.descs[idx];
        if existing.present {
            if existing.name_str() == name && existing.unit_str() == unit {
                return Ok(()); // idempotent
            }
            return Err(crate::error::Error::Other(format!(
                "signal {} registered twice with conflicting metadata",
                id.0
            )));
        }
        let mut desc = SignalDesc::empty();
        desc.present = true;
        desc.name_len = name.len() as u8;
        desc.name[..name.len()].copy_from_slice(name.as_bytes());
        desc.unit_len = unit.len() as u8;
        desc.unit[..unit.len()].copy_from_slice(unit.as_bytes());
        self.schema.descs[idx] = desc;
        self.schema.count = self.schema.count.saturating_add(1);
        Ok(())
    }

    /// The registered schema (worker reads it once after setup).
    pub fn schema(&self) -> &SignalSchema {
        &self.schema
    }

    /// Observe a u64 semantic signal.
    pub fn observe_u64(&mut self, id: SignalId, value: u64) -> Result<(), crate::error::Error> {
        self.signals.observe(id, value)
    }

    /// Observe a u32 semantic signal (widened).
    pub fn observe_u32(&mut self, id: SignalId, value: u32) -> Result<(), crate::error::Error> {
        self.signals.observe(id, u64::from(value))
    }

    /// Observe an i64 semantic signal (bit-cast; meaning is schema-defined).
    pub fn observe_i64(&mut self, id: SignalId, value: i64) -> Result<(), crate::error::Error> {
        self.signals.observe(id, value as u64)
    }

    /// The accumulated signal vector (read by the worker after execution).
    pub fn signals(&self) -> &SignalVector {
        &self.signals
    }

    /// Take the signal vector (worker-side, after execution).
    pub fn take_signals(&mut self) -> SignalVector {
        std::mem::take(&mut self.signals)
    }
}

impl Default for FuzzContext {
    fn default() -> Self {
        FuzzContext::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S0: SignalId = SignalId(0);
    const S1: SignalId = SignalId(1);

    #[test]
    fn observe_and_read() {
        let mut v = SignalVector::new();
        v.observe(S0, 42).unwrap();
        assert_eq!(v.value(S0), 42);
        assert!(v.was_touched(S0));
        assert!(!v.was_touched(S1));
        assert_eq!(v.touched_mask(), 1);
    }

    #[test]
    fn reset_clears() {
        let mut v = SignalVector::new();
        v.observe(S0, 7).unwrap();
        v.reset();
        assert_eq!(v.value(S0), 0);
        assert!(!v.was_touched(S0));
    }

    #[test]
    fn out_of_schema_id_is_refused() {
        let mut v = SignalVector::new();
        assert!(v.observe(SignalId(MAX_SIGNALS as u16), 1).is_err());
        assert!(SignalId::new(MAX_SIGNALS as u16).is_none());
        assert!(SignalId::new(3).is_some());
    }

    #[test]
    fn context_roundtrip() {
        let mut cx = FuzzContext::new();
        cx.observe_u64(S0, 100).unwrap();
        cx.observe_u32(S1, 5).unwrap();
        let sig = cx.take_signals();
        assert_eq!(sig.value(S0), 100);
        assert_eq!(sig.value(S1), 5);
        assert_eq!(sig.touched_mask(), 0b11);
    }

    #[test]
    fn schema_registration_is_idempotent_and_conflict_refused() {
        let mut cx = FuzzContext::new();
        cx.register_signal(S0, "parsed_items", "count").unwrap();
        cx.register_signal(S0, "parsed_items", "count").unwrap(); // idempotent
        assert!(cx.register_signal(S0, "other", "count").is_err()); // conflict
        assert!(cx.register_signal(S0, "bad name", "count").is_err()); // space ok...
                                                                       // ...but control chars are refused
        assert!(cx.register_signal(S0, "bad\nname", "count").is_err());
        let s = cx.schema();
        assert_eq!(s.count, 1);
        assert_eq!(s.desc(S0).unwrap().name_str(), "parsed_items");
        assert_eq!(s.desc(S0).unwrap().unit_str(), "count");
        assert!(s.desc(S1).is_none());
    }

    #[test]
    fn schema_validates_bounds() {
        assert!(SignalSchema::validate("", "u").is_err());
        let long = "x".repeat(MAX_SIGNAL_NAME_LEN + 1);
        assert!(SignalSchema::validate(&long, "u").is_err());
        let long_unit = "x".repeat(MAX_SIGNAL_UNIT_LEN + 1);
        assert!(SignalSchema::validate("name", &long_unit).is_err());
        assert!(SignalSchema::validate("name", "μ").is_err()); // non-ASCII
    }

    #[test]
    fn value_bucket_law() {
        // Exact for small values.
        for v in 0..64u64 {
            assert_eq!(value_bucket(v), v as u8);
        }
        // Linear region.
        assert_eq!(value_bucket(64), 65);
        assert_eq!(value_bucket(127), 65);
        assert_eq!(value_bucket(128), 66);
        assert_eq!(value_bucket(4095), 127);
        // Logarithmic region.
        assert_eq!(value_bucket(4096), 128);
        assert_eq!(value_bucket(8191), 128);
        assert_eq!(value_bucket(8192), 129);
        // Monotone and bounded.
        let mut prev = 0u8;
        for v in (0..10_000_000u64).step_by(97) {
            let b = value_bucket(v);
            assert!(b >= prev);
            prev = b;
        }
        assert_eq!(value_bucket(u64::MAX), 179);
    }

    #[test]
    fn magnitude_bucket_law() {
        assert_eq!(magnitude_bucket(0), 0);
        assert_eq!(magnitude_bucket(1), 1);
        assert_eq!(magnitude_bucket(2), 2);
        assert_eq!(magnitude_bucket(3), 2);
        assert_eq!(magnitude_bucket(4), 3);
        assert_eq!(magnitude_bucket(7), 3);
        assert_eq!(magnitude_bucket(8), 4);
        assert_eq!(magnitude_bucket(16), 5);
        assert_eq!(magnitude_bucket(u64::MAX), 63);
    }

    #[test]
    fn sketch_computes_buckets_dirs_and_touched() {
        let mut parent = SignalVector::new();
        parent.observe(S0, 100).unwrap();
        let mut child = SignalVector::new();
        child.observe(S0, 105).unwrap(); // delta +5
        child.observe(S1, 7).unwrap(); // introduced
        let s = ResidualSketch::of(&parent, &child);
        assert_eq!(s.mag_buckets[0], magnitude_bucket(5));
        assert_eq!(s.dir(0), 1);
        assert_eq!(s.mag_buckets[1], magnitude_bucket(7));
        assert_eq!(s.dir(1), 1);
        assert_eq!(s.touched_new, 1 << 1);
        assert_eq!(s.touched_lost, 0);
        assert_eq!(s.moved(), 0b11);
    }

    #[test]
    fn sketch_direction_signs() {
        let mut parent = SignalVector::new();
        parent.observe(S0, 10).unwrap();
        let mut child = SignalVector::new();
        child.observe(S0, 3).unwrap();
        let s = ResidualSketch::of(&parent, &child);
        assert_eq!(s.dir(0), 2); // down
        assert_eq!(s.mag_buckets[0], magnitude_bucket(7));
    }

    #[test]
    fn sketch_untouched_parent_baseline_is_zero() {
        let parent = SignalVector::new(); // nothing touched
        let mut child = SignalVector::new();
        child.observe(S0, 9).unwrap();
        let s = ResidualSketch::of(&parent, &child);
        assert_eq!(s.dir(0), 1);
        assert_eq!(s.touched_new, 1);
        assert_eq!(s.mag_buckets[0], magnitude_bucket(9));
    }

    #[test]
    fn tracker_persists_same_direction_and_resets_on_flip() {
        let mut tracker = OrderSignalTracker::new();
        let mut newly = 0u64;
        // Eight consecutive +1 steps (each child = parent + 1): run reaches
        // 8, cum_abs reaches 8 (bucket 4), so the persistence rule
        // (run >= 4, bucket >= 4) fires.
        let mut parent = SignalVector::new();
        parent.observe(S0, 0).unwrap();
        for v in 1u64..=8 {
            let mut child = SignalVector::new();
            child.observe(S0, v).unwrap();
            let sketch = ResidualSketch::of(&parent, &child);
            let d = deltas(&parent, &child);
            newly |= tracker.push(&d, &sketch, 4, 4);
            parent = child;
        }
        assert_eq!(tracker.run[0], 8);
        assert_eq!(tracker.cum_abs[0], 8);
        assert!(newly & 1 != 0);
        // A direction flip resets the run.
        let mut child = SignalVector::new();
        child.observe(S0, 7).unwrap();
        let sketch = ResidualSketch::of(&parent, &child);
        let d = deltas(&parent, &child);
        tracker.push(&d, &sketch, 4, 4);
        assert_eq!(tracker.run[0], 1);
        assert_eq!(tracker.last_dir[0], 2);
    }

    #[test]
    fn batch_summary_aggregates() {
        let mut parent = SignalVector::new();
        parent.observe(S0, 0).unwrap();
        let mut summary = SignalBatchSummary::new();
        for v in [1u64, 3, 5] {
            let mut child = SignalVector::new();
            child.observe(S0, v).unwrap();
            let d = deltas(&parent, &child);
            summary.push_deltas(&child, &d);
        }
        assert_eq!(summary.count[0], 3);
        assert_eq!(summary.min[0], 1);
        assert_eq!(summary.max[0], 5);
        // Exact deltas: 1 + 3 + 5 = 9.
        assert_eq!(summary.sum_abs_delta[0], 9);
        assert_eq!(summary.touched, 1);
    }
}
