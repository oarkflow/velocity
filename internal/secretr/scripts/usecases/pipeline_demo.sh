#!/bin/bash
set -e

echo "--- Secretr Automation Pipeline Demo ---"

# Build the latest version
go build -o secretr ./cmd/secretr

# Setup & session
BIN="./secretr"
source scripts/usecases/setup_session.sh

# The application now automatically uses the default organization if only one exists.

# 1. Apply the onboarding pipeline
echo "1. Applying onboarding pipeline..."
./secretr pipeline apply -f examples/config/onboarding.json

# 2. List pipelines
echo "2. Listing pipelines..."
./secretr pipeline list

# 3. Trigger onboarding for a new user
NEW_USER="jsmith_$(date +%s)"
# Ensure idempotency by removing any pre-existing artifacts for this user
SECRET_NAME="users/$NEW_USER/init_token"
./secretr secret delete --name "$SECRET_NAME" --force > /dev/null 2>&1 || true

echo "3. Triggering onboarding for user: $NEW_USER..."
set +e
TRIGGER_OUT=$(./secretr pipeline trigger --event enrollment --param user_id="$NEW_USER" 2>&1)
RET=$?
set -e
if [ $RET -ne 0 ]; then
    echo "$TRIGGER_OUT" | grep -q "secrets: already exists" && echo "Non-fatal: secret already existed; continuing" || (echo "$TRIGGER_OUT"; exit $RET)
fi
# 4. Verify results
echo "4. Verifying results..."

# Check if secret was created
SECRET_NAME="users/$NEW_USER/init_token"
echo "Checking secret: $SECRET_NAME"
if ./secretr secret get --name "$SECRET_NAME" > /dev/null 2>&1; then
    echo "✓ Secret created successfully"
else
    echo "✗ Secret not found"
    exit 1
fi

# Check if access was granted
echo "Checking access grants..."
./secretr access list --grantee "$NEW_USER"

echo "--- Automation Pipeline Demo Completed Successfully ---"
