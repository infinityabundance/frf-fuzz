//! Semantic signal vector and the [`FuzzContext`] target surface.
//!
//! Targets observe program-state quantities (parsed item count, allocation
//! high-water, retry count, ...) through a pre-registered schema of compact
//! numeric IDs. No signal strings in the hot loop: registration happens once
//! (Phase 1's `cargo frf-fuzz add` writes the schema), and the worker
//! exchanges fixed-size [`SignalVector`]s.
//!
//! Signal values are `u64` and saturation-free (wrapping): a target that
//! observes a negative quantity as `i64` casts it. The *units* and *meaning*
//! of each ID live in the target schema (a Phase-1 store artifact), not in
//! the runtime.

/// Maximum number of semantic signals per target. Bounded so the per-execution
/// vector is a fixed-size array.
pub const MAX_SIGNALS: usize = 64;

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

/// The handle handed to a fuzz target's closure.
///
/// Phase 1's `fuzz_target!` macro provides this as `cx`; targets call
/// `cx.observe_u64(...)` (or the typed helpers) for semantic signals. The
/// context also carries the mutable per-execution input buffer for the
/// `execute` hook contract.
#[derive(Debug)]
pub struct FuzzContext {
    signals: SignalVector,
    /// Execution ordinal (worker-maintained; targets may read it).
    pub execution_ordinal: u64,
}

impl FuzzContext {
    /// A fresh context.
    pub fn new() -> FuzzContext {
        FuzzContext {
            signals: SignalVector::new(),
            execution_ordinal: 0,
        }
    }

    /// Reset per-execution state.
    pub fn reset(&mut self) {
        self.signals.reset();
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
}
