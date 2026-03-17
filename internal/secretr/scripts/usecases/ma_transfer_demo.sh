#!/bin/bash
set -e

# M&A Transfer Demo Script
echo "--- Secretr M&A Transfer Demo ---"

# Step 1: Create Organizations
echo "1. Creating organizations..."
TS=$(date +%s)
ACME_OUT=$(./secretr org create -n "Acme Corp $TS" --slug "acme-$TS")
GLOBEX_OUT=$(./secretr org create -n "Globex Corp $TS" --slug "globex-$TS")

# Get Org IDs from creation output
ACME_ID=$(echo "$ACME_OUT" | grep -oE "[a-f0-9]{32}")
GLOBEX_ID=$(echo "$GLOBEX_OUT" | grep -oE "[a-f0-9]{32}")

echo "Acme ID: $ACME_ID"
echo "Globex ID: $GLOBEX_ID"

# Step 2: Create a resource in Acme
echo "2. Creating project in Acme..."
SECRET_NAME="acquisition-strategy-$TS"
./secretr secret create -n "$SECRET_NAME" -v "buy-low-sell-high"

# Step 3: Initiate Transfer
echo "3. Initiating transfer from Acme to Globex..."
INIT_OUT=$(./secretr org transfer init --source-org "$ACME_ID" --target-org "$GLOBEX_ID")
echo "$INIT_OUT"

TRANSFER_ID=$(echo "$INIT_OUT" | grep -oE "[a-f0-9]{32}")

# Step 4: Approve Transfer
echo "4. Approving transfer..."
./secretr org transfer approve --id "$TRANSFER_ID"

# Step 5: Execute Transfer
echo "5. Executing transfer..."
./secretr org transfer execute --id "$TRANSFER_ID"

# Step 6: Verify
echo "6. Verifying resource exists in Globex..."
./secretr secret get -n "$SECRET_NAME"

echo "--- M&A Transfer Demo Completed ---"
