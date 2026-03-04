#!/bin/bash
set -e

BIN="./secretr"
source scripts/usecases/setup_session.sh

# Compliance Report Demo Script
echo "--- Secretr Compliance Report Demo ---"

# Step 1: List Frameworks
echo "1. Listing available compliance frameworks..."
./secretr compliance frameworks

# Step 2: Get Current Score
echo "2. Getting compliance score for current organization..."
./secretr compliance score --standard "SOC2"

# Step 3: Generate Detailed Report
echo "3. Generating SOC2 compliance report..."
./secretr compliance report --standard "SOC2" --output "soc2_report.json"

# Step 4: List Generated Reports
echo "4. Listing recent compliance reports..."
./secretr compliance list-reports

# Step 5: (Optional) DLP Scan
echo "5. Running a DLP scan on the generated report..."
./secretr dlp scan --path "soc2_report.json"

echo "--- Compliance Report Demo Completed ---"
