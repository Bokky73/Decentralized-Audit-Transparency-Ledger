#!/usr/bin/env bash
set -euo pipefail

echo "=== Decentralized Audit & Transparency Ledger: Contract Event & SupTech Invariant Gate ==="

echo "[1/4] Checking Rust formatting..."
cargo fmt -- --check

echo "[2/4] Running RBAC gating matrix tests (src/rbac_gating_tests.rs)..."
cargo test rbac_gating_tests -- --nocapture

echo "[3/4] Running SupTech property-based & chaos resilience tests (src/proptest.rs)..."
cargo test proptest -- --nocapture

echo "[4/4] Running SupTech multi-actor concurrency tests (src/concurrent_tests.rs)..."
cargo test concurrent_tests -- --nocapture

echo "=== All contract event, RBAC, and SupTech invariant gates passed ==="
