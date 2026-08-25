//! The coordinator-side execution observation (master prompt §11).
//!
//! The worker never sends a heavyweight object per execution: the wire
//! carries bounded fixed-size fields (features, cmp summary, signal vector,
//! residual sketch, time bucket) only for *interesting* executions. This
//! module assembles those into the compact [`ExecutionObservation`] the
//! scheduler, residual, regime, and morphology machinery read. Rejected
//! executions never reach here (I1).
//!
//! The observation is deliberately small and fixed-shape; it is the unit of
//! mutation-residual computation and the durable `RunTape` observation
//! record.

use crate::mutation::MutationCoordinate;
use crate::scheduler::work_order::{CmpEventWire, ExecutionStatus};
use crate::target_runtime::signals::{ResidualSketch, SignalVector};

/// The compact per-execution observation assembled by the coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionObservation {
    /// The exact mutation coordinate (I2 reconstruction key).
    pub coordinate: MutationCoordinate,
    /// Outcome.
    pub status: ExecutionStatus,
    /// Sorted, deduplicated packed feature indices.
    pub features: Vec<u64>,
    /// Compact comparison summary (bounded).
    pub cmp_events: Vec<CmpEventWire>,
    /// The compare hits the mutation consumed (family-15 exactness).
    pub cmp_hits_used: Vec<CmpEventWire>,
    /// The child's observed signal vector.
    pub signals: SignalVector,
    /// The child-vs-parent residual sketch (Level-0 cheap form).
    pub sketch: ResidualSketch,
    /// Logarithmic execution-time bucket.
    pub time_bucket: u8,
}

impl ExecutionObservation {
    /// Number of features observed (bounded by the wire).
    pub fn feature_count(&self) -> usize {
        self.features.len()
    }

    /// Whether any feature is present.
    pub fn has_features(&self) -> bool {
        !self.features.is_empty()
    }

    /// The signals the child touched but the parent did not.
    pub fn touched_new(&self) -> u64 {
        self.sketch.touched_new
    }
}
