//! Batch compute-backend demonstration (Phase 7; master prompt §25).
//!
//! A deterministic, executable demonstration of the `gpu/` batch-compute
//! contract using the SAME library code a campaign would use
//! (`gpu::backend::ComputeBackend` with the CPU oracle):
//!
//! * deterministic mutation-plan proposals over a candidate batch
//!   (priority-proportional, largest-remainder, seeded mutator rotation);
//! * fixed-width morphology distance over signature rows (integer
//!   xor-popcount, bit-for-bit exact);
//! * precedent ranking with integer fixed-point weights (ranking evidence
//!   only — never a verdict);
//! * deterministic influence masks and compact descriptors;
//! * backend resolution: the CPU oracle by default, and a requested but
//!   unadmitted accelerator falls back to the CPU oracle WITH a recorded
//!   note (I14/I15) — never a silent substitute.
//!
//! Everything printed is a structural/proposal statement, never a bug claim.
//! GPU output — when a device backend is eventually admitted after the
//! Phase-7 parity gates pass on hardware — is proposal evidence only (I8).
//!
//! Run: `cargo run --example gpu_backend_demo`

#[cfg(feature = "coordinator")]
mod demo {
    use frf_fuzz::gpu::{
        rank_desc, resolve, BackendKind, CandidateMeta, CompactBatch, ComputeBackend, CpuBackend,
        PlanBatchRequest, Probe, SIGNATURE_WORDS,
    };

    fn row(byte: u8) -> Vec<u64> {
        // A signature row carrying one 8-bit pattern in its first word; the
        // rest is zero, so distance between two such rows is the popcount of
        // their xor — small, readable integers for the demo.
        let mut w = vec![0u64; SIGNATURE_WORDS];
        w[0] = u64::from(byte);
        w
    }

    pub fn run() -> Result<(), String> {
        println!("frf-fuzz phase-7 batch compute-backend demonstration (CPU oracle)");
        println!();

        let b = CpuBackend;

        // 1. Mutation-plan proposals.
        let req = PlanBatchRequest {
            candidates: &[
                CandidateMeta {
                    parent_short: [1; 8],
                    priority: 60,
                },
                CandidateMeta {
                    parent_short: [2; 8],
                    priority: 30,
                },
                CandidateMeta {
                    parent_short: [3; 8],
                    priority: 10,
                },
            ],
            total_orders: 20,
            executions_per_order: 8,
            seed: 0xF00D,
            mutators: &[1, 4, 7, 12],
        };
        let plans = b.generate_mutation_plans(&req).map_err(|e| e.to_string())?;
        let plans_again = b.generate_mutation_plans(&req).map_err(|e| e.to_string())?;
        assert_eq!(plans, plans_again, "plans must be deterministic");
        let per_parent = |id: u8| plans.iter().filter(|p| p.parent_short[0] == id).count();
        println!("mutation plans: 20 orders (exec x8) -> parent shares 60/30/10:");
        println!(
            "  parent 1: {}, parent 2: {}, parent 3: {} (deterministic)",
            per_parent(1),
            per_parent(2),
            per_parent(3)
        );
        assert_eq!(per_parent(1), 12);
        assert_eq!(per_parent(2), 6);
        assert_eq!(per_parent(3), 2);

        // 2. Morphology distance (integer xor-popcount).
        let left: Vec<u64> = [row(0xA5), row(0x00), row(0xFF)].concat();
        let right: Vec<u64> = [row(0xA5), row(0xFF), row(0x00)].concat();
        let dist = b
            .morphology_distance(&left, &right)
            .map_err(|e| e.to_string())?;
        println!("morphology distance (rows x3): {dist:?} (bit-exact integers)");
        assert_eq!(dist, vec![0, 8, 8]); // one differing word = 8 bits on this row

        // 3. Precedent ranking: candidate 0 close to the precedent.
        let precedent: Vec<u64> = row(0x5A);
        let candidates: Vec<u64> = [row(0x5A), row(0x00)].concat();
        let scores = b
            .precedent_rank(&candidates, &precedent, &[2048])
            .map_err(|e| e.to_string())?;
        let order = rank_desc(&scores);
        println!("precedent rank scores: {scores:?} -> order {order:?} (evidence only)");
        assert_eq!(order, vec![0, 1]);
        assert!(scores[0] > scores[1]);

        // 4. Influence masks + compact descriptors.
        let masks = b
            .influence_masks(&[4, 9], 0x5EED)
            .map_err(|e| e.to_string())?;
        let masks2 = b
            .influence_masks(&[4, 9], 0x5EED)
            .map_err(|e| e.to_string())?;
        assert_eq!(masks, masks2, "masks must be deterministic");
        println!(
            "influence masks: 2 inputs (4+9 bytes), offsets {:?} (deterministic 0/1)",
            masks.offsets
        );
        let data: Vec<u8> = (0..24u8).collect();
        let batch = CompactBatch {
            data: &data,
            offsets: &[0, 8, 16],
        };
        let desc = b.compact_descriptors(&batch).map_err(|e| e.to_string())?;
        println!(
            "compact descriptors: {} x 16 bytes (not identity)",
            desc.len()
        );
        assert_eq!(desc.len(), 3);
        assert_ne!(desc[0], desc[1]);
        assert_ne!(desc[1], desc[2]);

        // 5. Backend resolution + probes (I14/I15: fallback is recorded).
        let cpu_cfg = resolve(None);
        assert_eq!(cpu_cfg.backend, BackendKind::Cpu);
        println!("backend resolve(None)      -> {}", cpu_cfg.backend.name());
        for kind in [BackendKind::Cuda, BackendKind::Rocm] {
            let p: Probe = frf_fuzz::gpu::probe(kind);
            let cfg = resolve(Some(kind));
            println!(
                "backend resolve(Some({})) -> {} (note: {})",
                kind.name(),
                cfg.backend.name(),
                cfg.fallback_note.unwrap_or("")
            );
            assert_eq!(cfg.backend, BackendKind::Cpu, "must fall back to CPU");
            assert!(!p.available);
            assert!(cfg.fallback_note.is_some(), "fallback must be recorded");
        }

        println!();
        println!("GPU BACKEND DEMO PASS");
        Ok(())
    }
}

#[cfg(feature = "coordinator")]
fn main() {
    if let Err(e) = demo::run() {
        eprintln!("gpu backend demo: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "coordinator"))]
fn main() {}
