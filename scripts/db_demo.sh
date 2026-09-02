#!/bin/sh
# Phase-6 database regression demonstration (feature `database`).
#
# Runs the deterministic host demo that proves why the REAL dsfb-database
# grammar exists in frf-fuzz: an identical 90 s SQL-telemetry tape through
# two program states (clean rolling baseline vs a baseline frozen at process
# start) is read DIFFERENTLY by the real MotifEngine — a plan_regression
# episode appears only in the regressed revision, while a genuine LockRow
# wait ramp is seen identically by both. Deterministic fingerprints.
#
# Usage: scripts/db_demo.sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo run --quiet --features database --example db_regression_demo 2>&1 | tee /tmp/frf-fuzz-db-demo.out
grep -q 'DB REGRESSION DEMO PASS' /tmp/frf-fuzz-db-demo.out \
  || { echo "FAIL: db regression demo"; exit 1; }
echo "DB DEMO PASS"
