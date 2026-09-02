//! Batch GPU-compute architecture (master prompt §25; Phase 7).
//!
//! Two-plane rule applied to compute: the CPU oracle in [`cpu`] defines every
//! batch operation's semantics; a device backend (CUDA/ROCm) would be an
//! *acceleration of the same integer kernels* and is admitted only when the
//! Phase-7 parity gates pass on real hardware (CPU == CUDA == ROCm
//! bit-for-bit, repeated device determinism, measured speedup;
//! docs/COMPATIBILITY.md §6). No device backend has been admitted yet, so
//! [`backend::resolve`] always yields the CPU oracle and records a
//! fallback note when an accelerator was requested (I14, I15).
//!
//! Batch ops are proposal/ranking evidence only — never final semantic
//! authority (I8). All kernels are integer-only and bounded.

pub mod backend;
pub mod cpu;

pub use backend::{
    probe, rank_desc, resolve, BackendKind, CandidateMeta, CompactBatch, ComputeBackend,
    ComputeConfig, MaskBatch, MutationPlanProposal, PlanBatchRequest, Probe, MAX_CANDIDATES,
    MAX_COMPACT_INPUT_LEN, MAX_COMPACT_TOTAL_BYTES, MAX_EXECUTIONS_PER_ORDER, MAX_MASK_INPUTS,
    MAX_MASK_TOTAL_BYTES, MAX_PRECEDENT_ROWS, MAX_SIGNATURE_ROWS, MAX_TOTAL_ORDERS, MAX_WEIGHT,
    SIGNATURE_WORDS,
};
pub use cpu::CpuBackend;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_kind_codes_are_stable() {
        assert_eq!(BackendKind::Cpu.code(), 0);
        assert_eq!(BackendKind::Cuda.code(), 1);
        assert_eq!(BackendKind::Rocm.code(), 2);
        assert_eq!(BackendKind::Cpu.name(), "cpu");
        assert_eq!(BackendKind::Cuda.name(), "cuda");
        assert_eq!(BackendKind::Rocm.name(), "rocm");
    }

    #[test]
    fn cpu_probes_available_and_resolve_defaults_to_it() {
        let p = probe(BackendKind::Cpu);
        assert!(p.available);
        assert_eq!(p.kind, BackendKind::Cpu);

        let cfg = resolve(None);
        assert_eq!(cfg.backend, BackendKind::Cpu);
        assert!(cfg.fallback_note.is_none());

        let cfg = resolve(Some(BackendKind::Cpu));
        assert_eq!(cfg.backend, BackendKind::Cpu);
        assert!(cfg.fallback_note.is_none());
    }

    #[test]
    fn unavailable_accelerators_fall_back_to_the_cpu_oracle_with_a_note() {
        // No device adapter is admitted anywhere yet, so a requested CUDA or
        // ROCm backend must never silently become something else: it resolves
        // to the CPU oracle and the refusal is recorded (I14/I15).
        for kind in [BackendKind::Cuda, BackendKind::Rocm] {
            let p = probe(kind);
            assert!(!p.available, "{} must probe unavailable", kind.name());
            assert!(!p.reason.is_empty());

            let cfg = resolve(Some(kind));
            assert_eq!(cfg.backend, BackendKind::Cpu, "fallback to CPU oracle");
            let note = cfg
                .fallback_note
                .expect("fallback must be recorded, never silent");
            assert!(!note.is_empty());
        }
    }

    #[test]
    fn rank_desc_sorts_scores_descending_with_deterministic_ties() {
        let scores = [5i64, 5, 1, 9, 0, 5];
        let order = rank_desc(&scores);
        // 9 first; the three 5s keep ascending index order (stable); then 1, 0.
        assert_eq!(order, vec![3, 0, 1, 5, 2, 4]);
        // Deterministic.
        assert_eq!(order, rank_desc(&scores));
        // Empty input -> empty order.
        assert!(rank_desc(&[]).is_empty());
    }

    #[test]
    fn cpu_backend_is_a_valid_compute_backend() {
        let b = CpuBackend;
        let dyn_b: &dyn ComputeBackend = &b;
        assert_eq!(dyn_b.kind(), BackendKind::Cpu);
    }
}
