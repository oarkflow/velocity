#!/bin/bash
set -e

# Manufacturing: Intellectual Property (IP) Protection
# This script demonstrates protecting proprietary designs using Remote Kill and Geofencing.

# Create dummy CAD file
echo "model_data_v4_bin_hex_0x77" > /tmp/motor-v4.bin

BIN="./secretr"
source scripts/usecases/setup_session.sh
CAD_PATH="/tmp/motor_v4.dwg"
echo "Binary CAD Data" > "$CAD_PATH"

# 1. Upload R&D Asset
echo "1. Uploading Proprietary R&D Design..."
$BIN --yes file delete --name "motor-v4" --force > /dev/null 2>&1 || true
$BIN --yes file upload --name "motor-v4" --path "/tmp/motor-v4.bin" --overwrite

# 2. Apply Multi-Layer Protection
echo "2. Applying Geofence (IN, CN) and Max Downloads (5)..."
$BIN --yes file protect --name "motor-v4" --geofence "IN,CN" --max-downloads 5

# 3. Simulate Monitoring
echo "3. Monitoring Vendor Access Events..."
$BIN --yes monitoring events --actor "$VENDOR_ID" --limit 10

echo "Manufacturing IP Workflow Demonstration Complete."
