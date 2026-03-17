#!/bin/bash
set -e

# Defense & National Security: Targeted Field Intelligence
# This script demonstrates geofenced assets and emergency remote kill.

BIN="./secretr"
source scripts/usecases/setup_session.sh
ASSET_PATH="/tmp/defense_manual.txt"

echo "Classified Intelligence" > "$ASSET_PATH"

# 1. Upload Classified Asset
echo "1. Uploading Classified Asset..."
$BIN --yes file upload --name "op-blue-manual" --path "$ASSET_PATH" --overwrite

# 2. Apply Geofence & Remote Kill
echo "2. Applying Geofence (US, GB) and Enabling Remote Kill..."
$BIN --yes file protect --name "op-blue-manual" --geofence "US,GB" --remote-kill

# 3. Emergency Revocation Simulation
echo "3. Triggering Emergency Remote Kill (Device Compromised)..."
$BIN --yes file kill --name "op-blue-manual" --reason "Personnel MIA / Device Compromised"

# 4. Verification
echo "4. Verifying kill status (download should fail)..."
set +e
$BIN --yes file download --name "op-blue-manual" --output "/tmp/stolen_asset.txt" 2>&1 | grep "remotely killed"
if [ $? -eq 0 ]; then
    echo "Access Blocked Successfully."
else
    echo "FAIL: Access was not blocked."
    exit 1
fi
set -e

echo "Defense Workflow Demonstration Complete."
