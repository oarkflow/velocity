#!/bin/bash
source scripts/usecases/setup_session.sh

echo "--- Monitoring & Alerts Use Case ---"

# 1. View recent security events
echo "1. Fetching recent security events..."
./secretr monitoring events --limit 5

# 2. List active alerts
echo "2. Checking for active security alerts..."
./secretr alert list --status active

# 3. Resolve a simulated alert
echo "3. Resolving a simulated alert..."
$BIN --yes alert resolve --id "simulated-id" 2>/dev/null || true

echo "Monitoring & Alerts Use Case completed."
