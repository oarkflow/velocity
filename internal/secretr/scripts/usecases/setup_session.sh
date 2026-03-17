#!/bin/bash
BIN="./secretr"
export SECRETR_YES=true

# Check for session
if $BIN --yes auth status > /dev/null 2>&1; then
    :
else
    echo "Initializing demo session..."
    $BIN --yes auth init --name "Admin" --email "admin@example.com" --password "password123" > /dev/null 2>&1 || true
    $BIN --yes auth login --email "admin@example.com" --password "password123" > /dev/null 2>&1 || true
fi

# The application now automatically creates a "Default" organization during 'auth init'.
# We no longer need to explicitly create it or export ORG_ID for single-org environments.

# Create Dummy Identities for demos if they don't exist
$BIN --yes identity create --name "Dr. Smith" --email "smith@example.com" --password "pass123" > /dev/null 2>&1 || true
$BIN --yes identity create --name "Vendor" --email "vendor@example.com" --password "pass123" > /dev/null 2>&1 || true

export SPECIALIST_ID=$($BIN --yes identity list -f json | jq -r '.[] | select(.name=="Dr. Smith") | .id' | head -n 1)
export VENDOR_ID=$($BIN --yes identity list -f json | jq -r '.[] | select(.name=="Vendor") | .id' | head -n 1)
# Default organization for use cases
export ORG_ID=$($BIN --yes org list -f json | jq -r '.[0].id' | head -n 1)
