//! The CPU oracle backend (normative semantics for every batch op).
//!
//! Every operation here is a plain, bounded, integer-only loop — the exact
//! shape a CUDA/ROCm kernel must replicate bit-for-bit before it can be
//! admitted (docs/COMPATIBILITY.md §6). The CPU backend is always available,
//! never quarantined, and its outputs are the reference every accelerated
//! path is tested against. No output has final semantic authority (I8).
//!
//! # Determinism
//!
//! All randomness comes from the counter-based Philox stream
//! (`mutation::prng`), seeded per input from the batch seed — the same
//! generator family a device kernel can reproduce with a counter/key pair.
//! Nothing here depends on iteration order of a `HashMap` or on wall clock.

use super::backend::{
    check_compact_batch, check_mask_inputs, check_signature_rows, seeded_rng, BackendKind,
    CandidateMeta, CompactBatch, ComputeBackend, MaskBatch, MutationPlanProposal, PlanBatchRequest,
    MAX_CANDIDATES, MAX_EXECUTIONS_PER_ORDER, MAX_PRECEDENT_ROWS, MAX_TOTAL_ORDERS, MAX_WEIGHT,
    SIGNATURE_WORDS,
};
use crate::error::{Error, Result};
use crate::mutation::MutatorId;

/// Maximum distance between two rows of `SIGNATURE_WORDS` u64s.
const MAX_ROW_DISTANCE: i64 = (SIGNATURE_WORDS * 64) as i64;

/// The CPU oracle backend. Unit struct: stateless, always available.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuBackend;

impl ComputeBackend for CpuBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Cpu
    }

    fn generate_mutation_plans(
        &self,
        req: &PlanBatchRequest<'_>,
    ) -> Result<Vec<MutationPlanProposal>> {
        let n = req.candidates.len();
        if n > MAX_CANDIDATES {
            return Err(Error::BoundExceeded {
                what: "plan request candidates",
                limit: MAX_CANDIDATES as u64,
                got: n as u64,
            });
        }
        if req.total_orders > MAX_TOTAL_ORDERS {
            return Err(Error::BoundExceeded {
                what: "plan request total orders",
                limit: MAX_TOTAL_ORDERS as u64,
                got: u64::from(req.total_orders),
            });
        }
        if req.executions_per_order == 0 || req.executions_per_order > MAX_EXECUTIONS_PER_ORDER {
            return Err(Error::BoundExceeded {
                what: "plan request executions per order",
                limit: MAX_EXECUTIONS_PER_ORDER as u64,
                got: u64::from(req.executions_per_order),
            });
        }
        if req.mutators.is_empty() {
            return Err(Error::Other(
                "plan request requires at least one allowed mutator".to_string(),
            ));
        }
        for m in req.mutators {
            if MutatorId::from_id(*m).is_none() {
                return Err(Error::UnsupportedVersion {
                    family: "mutator family",
                    version: u32::from(*m),
                });
            }
        }
        if req.total_orders == 0 {
            return Ok(Vec::new());
        }
        if n == 0 {
            return Err(Error::Other(
                "plan request has orders but no candidates".to_string(),
            ));
        }

        let total = u64::from(req.total_orders);
        // u64 largest-remainder allocation of the order budget by priority.
        // Sum of u32 priorities over <= 2^16 candidates fits u64 easily.
        let sum: u64 = req.candidates.iter().map(|c| u64::from(c.priority)).sum();
        let shares = if sum == 0 {
            allocate_equal(total, n)
        } else {
            allocate_by_priority(total, req.candidates)
        };

        let mut out: Vec<MutationPlanProposal> = Vec::new();
        let mut order_index: u64 = 0;
        for (ci, candidate) in req.candidates.iter().enumerate() {
            let share = shares[ci];
            if share == 0 {
                continue;
            }
            // Per-candidate mutator rotation from the batch seed.
            let mut rng = seeded_rng(req.seed, ci as u32, 1);
            let rotate = rng.next_u32() as usize % req.mutators.len();
            let mlen = req.mutators.len() as u64;
            for k in 0..share {
                let mutator = req.mutators[((rotate as u64 + k) % mlen) as usize];
                out.push(MutationPlanProposal {
                    parent_short: candidate.parent_short,
                    mutator,
                    lane: (order_index as u32) & 0xFFFF,
                    count: req.executions_per_order,
                    start_index: order_index.saturating_mul(u64::from(req.executions_per_order)),
                });
                order_index = order_index.saturating_add(1);
            }
        }
        Ok(out)
    }

    fn morphology_distance(&self, left: &[u64], right: &[u64]) -> Result<Vec<u32>> {
        if left.len() != right.len() {
            return Err(Error::Encoding(
                "morphology distance requires equal-length batches",
            ));
        }
        let rows = check_signature_rows(left, "morphology batch")?;
        if rows == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(rows);
        for r in 0..rows {
            let mut acc = 0u32;
            for w in 0..SIGNATURE_WORDS {
                acc = acc.saturating_add(
                    (left[r * SIGNATURE_WORDS + w] ^ right[r * SIGNATURE_WORDS + w]).count_ones(),
                );
            }
            out.push(acc);
        }
        Ok(out)
    }

    fn precedent_rank(
        &self,
        candidate_rows: &[u64],
        precedent_rows: &[u64],
        weights: &[u32],
    ) -> Result<Vec<i64>> {
        let rows = check_signature_rows(candidate_rows, "rank candidate batch")?;
        let precedents = check_signature_rows(precedent_rows, "rank precedent batch")?;
        if precedents > MAX_PRECEDENT_ROWS {
            return Err(Error::BoundExceeded {
                what: "rank precedent rows",
                limit: MAX_PRECEDENT_ROWS as u64,
                got: precedents as u64,
            });
        }
        if weights.len() != precedents {
            return Err(Error::Encoding(
                "rank weights length must equal precedent row count",
            ));
        }
        for w in weights {
            if *w > MAX_WEIGHT {
                return Err(Error::BoundExceeded {
                    what: "precedent rank weight",
                    limit: u64::from(MAX_WEIGHT),
                    got: u64::from(*w),
                });
            }
        }
        if rows == 0 {
            return Ok(Vec::new());
        }
        // score_i = sum_p w_p * (max_dist - dist(row_i, precedent_p)); every
        // term is non-negative and the sum fits i64 (bounds in module docs).
        let mut scores = vec![0i64; rows];
        let precedents = precedent_rows.as_chunks::<SIGNATURE_WORDS>().0;
        let candidates = candidate_rows.as_chunks::<SIGNATURE_WORDS>().0;
        for (pi, p) in precedents.iter().enumerate() {
            let w = i64::from(weights[pi]);
            if w == 0 {
                continue;
            }
            for (ri, r) in candidates.iter().enumerate() {
                let mut dist = 0u32;
                for wd in 0..SIGNATURE_WORDS {
                    dist = dist.saturating_add((r[wd] ^ p[wd]).count_ones());
                }
                let term = w * (MAX_ROW_DISTANCE - i64::from(dist));
                scores[ri] = scores[ri].saturating_add(term);
            }
        }
        Ok(scores)
    }

    fn influence_masks(&self, lens: &[u32], seed: u64) -> Result<MaskBatch> {
        check_mask_inputs(lens)?;
        if lens.is_empty() {
            return Ok(MaskBatch {
                lens: Vec::new(),
                offsets: Vec::new(),
                data: Vec::new(),
            });
        }
        let mut offsets = Vec::with_capacity(lens.len());
        let mut data = Vec::new();
        let mut cursor: u32 = 0;
        for (j, l) in lens.iter().enumerate() {
            offsets.push(cursor);
            let mut rng = seeded_rng(seed, j as u32, 2);
            for _ in 0..*l {
                // Deterministic bit: one stream word per mask byte, bit 0.
                data.push((rng.next_u32() & 1) as u8);
            }
            cursor = cursor.saturating_add(*l);
        }
        Ok(MaskBatch {
            lens: lens.to_vec(),
            offsets,
            data,
        })
    }

    fn compact_descriptors(&self, batch: &CompactBatch<'_>) -> Result<Vec<[u8; 16]>> {
        let n = check_compact_batch(batch)?;
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut out: Vec<[u8; 16]> = Vec::with_capacity(n);
        let seed64: u64 = 0x6A09_E667_F3BC_C909; // fixed mixing seed for the fold
        for (i, o) in batch.offsets.iter().enumerate() {
            let end = if i + 1 < batch.offsets.len() {
                batch.offsets[i + 1] as usize
            } else {
                batch.data.len()
            };
            let input = &batch.data[*o as usize..end];
            let mut lanes = [
                seed64.wrapping_add(i as u64),
                seed64.rotate_left(17) ^ (i as u64).wrapping_mul(0x9E37_79B9),
                seed64.rotate_left(31) ^ (i as u64).wrapping_mul(0x85EB_CA6B),
                seed64.rotate_left(47),
            ];
            for (k, chunk) in input.chunks(8).enumerate() {
                let mut word = 0u64;
                for (b, byte) in chunk.iter().enumerate() {
                    word |= u64::from(*byte) << (8 * b);
                }
                let mix = word
                    .rotate_left((k as u32 * 7) & 63)
                    .wrapping_mul(0xD6E8_FEB8_6659_FD93)
                    ^ 0xA5A5_5A5A_5A5A_A5A5;
                for lane in lanes.iter_mut() {
                    *lane ^= mix;
                    *lane = lane
                        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                        .rotate_left(29)
                        .wrapping_add(0xBF58_476D_1CE4_E5B9);
                }
            }
            let mut desc = [0u8; 16];
            for (lane, chunk) in lanes.iter().zip(desc.chunks_mut(4)) {
                chunk.copy_from_slice(&lane.to_le_bytes()[..4]);
            }
            out.push(desc);
        }
        Ok(out)
    }
}

/// Split `total` equally over `n` candidates; the largest remainder goes to
/// the lowest indices (deterministic). `n >= 1` (caller guarantees).
fn allocate_equal(total: u64, n: usize) -> Vec<u64> {
    let base = total / n as u64;
    let rem = (total % n as u64) as usize;
    (0..n).map(|i| base + u64::from(i < rem)).collect()
}

/// Split `total` over candidates by priority (u64 largest remainder). Sum of
/// u32 priorities over <= 2^16 candidates fits u64; `sum > 0` (caller
/// guarantees). The leftover remainder goes to the highest-priority
/// candidates, ties broken by ascending index (deterministic).
fn allocate_by_priority(total: u64, candidates: &[CandidateMeta]) -> Vec<u64> {
    let sum: u64 = candidates.iter().map(|c| u64::from(c.priority)).sum();
    let mut shares: Vec<u64> = candidates
        .iter()
        .map(|c| total * u64::from(c.priority) / sum)
        .collect();
    let floor_sum: u64 = shares.iter().sum();
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by(|&a, &b| {
        let pa = candidates[a].priority;
        let pb = candidates[b].priority;
        pb.cmp(&pa).then(a.cmp(&b))
    });
    let mut left = total.saturating_sub(floor_sum);
    for idx in order {
        if left == 0 {
            break;
        }
        shares[idx] += 1;
        left -= 1;
    }
    shares
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::backend::{rank_desc, MAX_COMPACT_INPUT_LEN};

    fn row(words: [u64; SIGNATURE_WORDS]) -> Vec<u64> {
        words.to_vec()
    }

    fn meta(parent: u8, priority: u32) -> CandidateMeta {
        CandidateMeta {
            parent_short: [parent; 8],
            priority,
        }
    }

    #[test]
    fn kind_is_cpu() {
        let b = CpuBackend;
        assert_eq!(b.kind(), BackendKind::Cpu);
    }

    #[test]
    fn plans_respect_priority_shares_deterministically() {
        let b = CpuBackend;
        let req = PlanBatchRequest {
            candidates: &[meta(1, 300), meta(2, 100), meta(3, 0), meta(4, 100)],
            total_orders: 100,
            executions_per_order: 8,
            seed: 0xC0FFEE,
            mutators: &[1, 7, 13],
        };
        let plans = b.generate_mutation_plans(&req).unwrap();
        assert_eq!(plans.len(), 100);
        // Sum of priorities 500: candidate 1 (300) gets ~60, candidates 2/4
        // (100 each) get ~20, candidate 3 gets 0.
        let count = |id: u8| plans.iter().filter(|p| p.parent_short[0] == id).count();
        assert_eq!(count(1), 60);
        assert_eq!(count(2), 20);
        assert_eq!(count(3), 0);
        assert_eq!(count(4), 20);
        // Every plan carries the requested execution count, and start indexes
        // are non-overlapping.
        for (i, p) in plans.iter().enumerate() {
            assert_eq!(p.count, 8);
            assert_eq!(p.start_index, (i as u64) * 8);
        }
        // All proposed mutators are from the allowed set.
        for p in &plans {
            assert!([1u16, 7, 13].contains(&p.mutator));
        }
        // Deterministic: repeat gives the identical vector.
        let again = b.generate_mutation_plans(&req).unwrap();
        assert_eq!(plans, again);
    }

    #[test]
    fn plans_with_zero_priorities_split_evenly() {
        let b = CpuBackend;
        let req = PlanBatchRequest {
            candidates: &[meta(1, 0), meta(2, 0), meta(3, 0)],
            total_orders: 10,
            executions_per_order: 1,
            seed: 7,
            mutators: &[2],
        };
        let plans = b.generate_mutation_plans(&req).unwrap();
        assert_eq!(plans.len(), 10);
        let count = |id: u8| plans.iter().filter(|p| p.parent_short[0] == id).count();
        assert_eq!(count(1), 4); // largest remainder: 10 / 3 -> 3,3,3 + 1 extra
        assert_eq!(count(2), 3);
        assert_eq!(count(3), 3);
    }

    #[test]
    fn plan_requests_are_validated() {
        let b = CpuBackend;
        // Empty candidate set with zero budget is a valid empty plan.
        let empty = PlanBatchRequest {
            candidates: &[],
            total_orders: 0,
            executions_per_order: 1,
            seed: 0,
            mutators: &[1],
        };
        assert!(b.generate_mutation_plans(&empty).unwrap().is_empty());
        // Unknown mutator family refused.
        let bad_mut = PlanBatchRequest {
            candidates: &[meta(1, 1)],
            total_orders: 1,
            executions_per_order: 1,
            seed: 0,
            mutators: &[99],
        };
        assert!(b.generate_mutation_plans(&bad_mut).is_err());
        // No allowed mutators refused.
        let no_mut = PlanBatchRequest {
            candidates: &[meta(1, 1)],
            total_orders: 1,
            executions_per_order: 1,
            seed: 0,
            mutators: &[],
        };
        assert!(b.generate_mutation_plans(&no_mut).is_err());
        // Zero executions per order refused.
        let zero_ex = PlanBatchRequest {
            candidates: &[meta(1, 1)],
            total_orders: 1,
            executions_per_order: 0,
            seed: 0,
            mutators: &[1],
        };
        assert!(b.generate_mutation_plans(&zero_ex).is_err());
        // Budget with no candidates is refused (nothing to distribute).
        let no_cands = PlanBatchRequest {
            candidates: &[],
            total_orders: 5,
            executions_per_order: 1,
            seed: 0,
            mutators: &[1],
        };
        assert!(b.generate_mutation_plans(&no_cands).is_err());
    }

    #[test]
    fn morphology_distance_is_exact_and_symmetric() {
        let b = CpuBackend;
        let a: Vec<u64> = [
            row([0; SIGNATURE_WORDS]),
            row([0xFF; SIGNATURE_WORDS]),
            row([0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ]
        .concat();
        let c: Vec<u64> = [
            row([0; SIGNATURE_WORDS]),
            row([0xFF; SIGNATURE_WORDS]),
            row([0; SIGNATURE_WORDS]),
        ]
        .concat();
        let d = b.morphology_distance(&a, &c).unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(d[0], 0); // identical
        assert_eq!(d[1], 0); // identical
        assert_eq!(d[2], 1); // single bit differs
                             // Self-distance is all zeros.
        let selfd = b.morphology_distance(&a, &a).unwrap();
        assert_eq!(selfd, vec![0, 0, 0]);
        // Symmetric.
        assert_eq!(b.morphology_distance(&c, &a).unwrap(), d);
        // Max distance: zero vs all-ones row = SIGNATURE_WORDS * 64.
        let ones: Vec<u64> = row([u64::MAX; SIGNATURE_WORDS]);
        let zeros: Vec<u64> = row([0; SIGNATURE_WORDS]);
        assert_eq!(
            b.morphology_distance(&zeros, &ones).unwrap()[0],
            (SIGNATURE_WORDS * 64) as u32
        );
    }

    #[test]
    fn morphology_distance_validation() {
        let b = CpuBackend;
        // Length mismatch refused.
        let a = row([0; SIGNATURE_WORDS]);
        let short: Vec<u64> = a[..4].to_vec();
        assert!(b.morphology_distance(&a, &short).is_err());
        // Non-multiple refused.
        let mut odd = row([0; SIGNATURE_WORDS]);
        odd.push(0);
        let mut odd2 = row([0; SIGNATURE_WORDS]);
        odd2.push(0);
        assert!(b.morphology_distance(&odd, &odd2).is_err());
        // Empty batches are valid and return empty.
        assert!(b.morphology_distance(&[], &[]).unwrap().is_empty());
    }

    #[test]
    fn precedent_rank_orders_by_fixed_point_proximity() {
        let b = CpuBackend;
        // Precedent P is close to candidate 0 and far from candidate 1.
        let precedent = row([0xAB; SIGNATURE_WORDS]);
        let c0 = row([0xAB; SIGNATURE_WORDS]); // identical to precedent
        let c1 = row([0x00; SIGNATURE_WORDS]); // far
        let candidates: Vec<u64> = [c0.clone(), c1.clone()].concat();
        let scores = b.precedent_rank(&candidates, &precedent, &[1024]).unwrap();
        assert_eq!(scores.len(), 2);
        assert!(scores[0] > scores[1], "closer candidate must score higher");
        let order = rank_desc(&scores);
        assert_eq!(order, vec![0, 1]);
        // Identical candidates and equal weights tie-break by index.
        let dup: Vec<u64> = [c0.clone(), c0.clone()].concat();
        let dup_scores = b.precedent_rank(&dup, &precedent, &[1024]).unwrap();
        let dup_order = rank_desc(&dup_scores);
        assert_eq!(dup_order, vec![0, 1]);
        // Weight zero contributes nothing.
        let zero_w = b.precedent_rank(&candidates, &precedent, &[0]).unwrap();
        assert_eq!(zero_w, vec![0, 0]);
    }

    #[test]
    fn precedent_rank_validation() {
        let b = CpuBackend;
        let p = row([0xAB; SIGNATURE_WORDS]);
        // Weight/precedent count mismatch refused.
        assert!(b.precedent_rank(&p, &p, &[1, 2]).is_err());
        // Oversized weight refused.
        assert!(b.precedent_rank(&p, &p, &[MAX_WEIGHT + 1]).is_err());
        // Empty precedent set scores everything zero.
        let cands: Vec<u64> = [p.clone(), p.clone()].concat();
        let s = b.precedent_rank(&cands, &[], &[]).unwrap();
        assert_eq!(s, vec![0, 0]);
    }

    #[test]
    fn influence_masks_are_deterministic_and_covered() {
        let b = CpuBackend;
        let m1 = b.influence_masks(&[0, 7, 33], 0x5EED).unwrap();
        let m2 = b.influence_masks(&[0, 7, 33], 0x5EED).unwrap();
        assert_eq!(m1, m2);
        assert_eq!(m1.lens, vec![0, 7, 33]);
        assert_eq!(m1.offsets, vec![0, 0, 7]);
        assert_eq!(m1.data.len(), 40);
        for bts in m1.data.iter() {
            assert!(*bts <= 1);
        }
        // A different seed changes the mask.
        let m3 = b.influence_masks(&[0, 7, 33], 0x5EEC).unwrap();
        assert_ne!(m1, m3);
        // Zero-length input contributes no bytes; empty batch is valid.
        let empty = b.influence_masks(&[], 1).unwrap();
        assert!(empty.lens.is_empty() && empty.data.is_empty());
    }

    #[test]
    fn compact_descriptors_are_deterministic_and_distinct() {
        let b = CpuBackend;
        let data: Vec<u8> = (0..64u8).collect();
        let batch = CompactBatch {
            data: &data,
            offsets: &[0, 16, 48],
        };
        let d1 = b.compact_descriptors(&batch).unwrap();
        let d2 = b.compact_descriptors(&batch).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 3);
        // Different inputs -> different descriptors (no collision on this
        // deterministic sample).
        assert_ne!(d1[0], d1[1]);
        assert_ne!(d1[1], d1[2]);
        // Empty batch is valid.
        assert!(b
            .compact_descriptors(&CompactBatch {
                data: &[],
                offsets: &[]
            })
            .unwrap()
            .is_empty());
    }

    #[test]
    fn compact_batch_validation() {
        let b = CpuBackend;
        let data = vec![0u8; 16];
        // First offset must be zero.
        assert!(b
            .compact_descriptors(&CompactBatch {
                data: &data,
                offsets: &[1]
            })
            .is_err());
        // Offsets must be ascending: a later offset below an earlier one is
        // refused. Equal consecutive offsets are a VALID zero-length input
        // (covered at the end of this test).
        assert!(b
            .compact_descriptors(&CompactBatch {
                data: &data,
                offsets: &[0, 2, 1]
            })
            .is_err());
        // Offsets may not run past the data.
        assert!(b
            .compact_descriptors(&CompactBatch {
                data: &data,
                offsets: &[0, 17]
            })
            .is_err());
        // Over-long single input refused.
        let big = vec![0u8; MAX_COMPACT_INPUT_LEN + 1];
        assert!(b
            .compact_descriptors(&CompactBatch {
                data: &big,
                offsets: &[0]
            })
            .is_err());
        // A zero-length middle input (equal consecutive offsets) is valid.
        let d = b
            .compact_descriptors(&CompactBatch {
                data: &data[..1],
                offsets: &[0, 1, 1],
            })
            .unwrap();
        assert_eq!(d.len(), 3);
    }
}
