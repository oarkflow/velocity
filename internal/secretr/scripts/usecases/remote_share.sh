#!/bin/bash
set -e

# Remote Teams: Secure Time-Value Sharing
# This script demonstrates secure one-time sharing with geographic restrictions.

BIN="./secretr"
source scripts/usecases/setup_session.sh
CONFIG_PATH="/tmp/remote_config.json"
echo '{"api": "v1", "key": "abc"}' > "$CONFIG_PATH"

# 1. Create Secure Share
echo "1. Creating Secure Share (Expires in 2h, One-time only)..."
$BIN --yes share create --type file --resource "freelancer-config" --expires-in 2h --one-time

# 2. Apply Geographic Restriction
echo "2. Applying Geographic Restriction (Germany - DE)..."
$BIN --yes file upload --name "freelancer-config" --path "$CONFIG_PATH" --overwrite
$BIN --yes file protect --name "freelancer-config" --geofence "DE"

echo "Remote Sharing Workflow Demonstration Complete."
