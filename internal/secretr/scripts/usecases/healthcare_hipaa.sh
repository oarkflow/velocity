#!/bin/bash
set -e

# Healthcare: HIPAA-Compliant Patient Data Sharing
# This script demonstrates uploading a patient record, protecting it with MFA/Max-Downloads,
# and granting access to a specialist.

BIN="./secretr"
source scripts/usecases/setup_session.sh
DEMO_DIR="/tmp/secretr-healthcare"
RECORD_PATH="$DEMO_DIR/patient_labs.pdf"

rm -rf "$DEMO_DIR" && mkdir -p "$DEMO_DIR"

echo "Creating dummy patient record..."
echo "Patient: John Doe, Labs: Normal" > "$RECORD_PATH"

# 1. Initialize Audit for Compliance
echo "1. Initializing Audit Verification..."
$BIN --yes audit verify

# 2. Upload Encrypted Record
echo "2. Uploading Patient Record..."
$BIN --yes file upload --name "patient-001-labs" --path "$RECORD_PATH" --overwrite

# 3. Apply MFA & Download Limits
echo "3. Applying Protection Policy (MFA + Max Downloads = 1)..."
$BIN --yes file protect --name "patient-001-labs" --require-mfa --max-downloads 1

# 4. Grant Access to Specialist (Using a dummy ID for demo)
echo "4. Granting Access to Specialist..."
$BIN --yes access grant --grantee "$SPECIALIST_ID" --resource "patient-001-labs" --type file --expires-in 24h

echo "Healthcare Workflow Demonstration Complete."
