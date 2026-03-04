#!/bin/bash
set -e

# JIT Access Demo Script
export SECRETR_ALLOW_SELF_APPROVAL=true
echo "--- Secretr JIT Access Demo ---"

# Setup: Create resource and ensure no access initially
echo "1. Setting up resource..."
./secretr secret delete -n "jit-db-password" --force || true
./secretr secret create -n "jit-db-password" -v "super-secret-pass"

echo "2. Requesting temporary JIT access..."
REQUEST_OUT=$(./secretr access request \
    --resource "jit-db-password" \
    --type "secret" \
    --justification "Investigating production database latency (Jira-123)" \
    --duration "1h")
echo "$REQUEST_OUT"

REQUEST_ID=$(echo "$REQUEST_OUT" | grep -oE "[a-f0-9]{32}")
echo "Request ID: $REQUEST_ID"

echo "3. Approving access request (Admin action)..."
./secretr access approve --id "$REQUEST_ID"

echo "4. Verifying access..."
./secretr secret get -n "jit-db-password"

echo "--- JIT Access Demo Completed ---"
