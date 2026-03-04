#!/bin/bash
set -e

# Finance: High-Integrity Financial Ledger Audit
# This script demonstrates creating immutable secrets and verifying the audit ledger.

BIN="./secretr"
source scripts/usecases/setup_session.sh

# 1. Create Immutable Banking Secret
echo "1. Creating Immutable Banking API Key..."
$BIN --yes secret delete --name "fin/swift/api-key" --force > /dev/null 2>&1 || true
$BIN --yes secret create --name "fin/swift/api-key" --value "sk_live_bank_12345" --immutable

# 2. Periodic Integrity Verification
echo "2. Verifying Audit Ledger Integrity (Merkle Tree + ZK Proofs)..."
$BIN --yes audit verify

# 3. Export Signed Evidence
echo "3. Exporting Audit Evidence for SEC/FINRA..."
$BIN --yes audit export --output "/tmp/q4-audit-evidence.json"

echo "Finance Workflow Demonstration Complete."
