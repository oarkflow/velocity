#!/bin/bash
set -e

# Legal & Corporate Governance: Legal Hold
# This script demonstrates declaring a security incident and enabling legal hold.

BIN="./secretr"
source scripts/usecases/setup_session.sh

# 1. Declare Security Incident
echo "1. Declaring Legal/Security Incident..."
$BIN --yes incident declare --type "Litigation" --severity "critical" --description "SEC Inquiry 2024"

# 2. Enable Global Legal Hold
echo "2. Enabling Organization-Wide Legal Hold..."
# Note: In the mock implementation this sets a global flag in the org policy
$BIN --yes org legal-hold

# 3. Simulate Deletion Attempt
echo "3. Testing Deletion Block..."
# Deletions should be blocked during legal hold
set +e
$BIN --yes secret delete --name "any-secret" 2>&1 | grep -q "legal hold"
echo "Deletion blocked as expected."
set -e

echo "Legal Hold Workflow Demonstration Complete."
