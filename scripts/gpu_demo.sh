#!/bin/sh
# Phase-7 batch compute-backend demonstration (CPU oracle).
#
# Runs the deterministic demo that proves the gpu/ batch-compute contract:
# priority-proportional mutation plans, bit-exact morphology distances,
# integer precedent ranking, deterministic masks/descriptors, and the
# recorded CPU-oracle fallback when a CUDA/ROCm backend is requested but no
# device adapter is admitted (I14/I15).
#
# Usage: scripts/gpu_demo.sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo run --quiet --example gpu_backend_demo 2>&1 | tee /tmp/frf-fuzz-gpu-demo.out
grep -q 'GPU BACKEND DEMO PASS' /tmp/frf-fuzz-gpu-demo.out \
  || { echo "FAIL: gpu backend demo"; exit 1; }
echo "GPU DEMO PASS"
