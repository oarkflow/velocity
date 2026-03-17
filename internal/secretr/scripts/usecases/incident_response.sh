#!/bin/bash
set -e

# Incident Response: Breach Containment
# This script demonstrates organization freeze and global secret rotation.

BIN="./secretr"
source scripts/usecases/setup_session.sh

# 1. Declare & Freeze Organization
echo "1. Declaring Incident & Freezing Organization Access..."
$BIN --yes incident declare --type "Breach" --severity "critical" --description "Simulated breach"
$BIN --yes incident freeze

# 2. Identify Impacted Resources
echo "2. Identifying Impacted Resources via Monitoring Dash..."
$BIN --yes monitoring dashboard --period 1h

# 3. Global Rotation
echo "3. Triggering Global Secret Rotation..."
$BIN --yes incident rotate --all

# 4. Cleanup
echo "4. Lifting Freeze after Containment..."
$BIN --yes incident freeze --disable

echo "Incident Response Workflow Demonstration Complete."
