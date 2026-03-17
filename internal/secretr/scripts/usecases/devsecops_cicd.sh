#!/bin/bash
set -e

# Software Engineering: Per-Build "Burn-after-read" Secrets
# This script demonstrates OIDC pipeline identity and read-once secrets.

BIN="./secretr"
source scripts/usecases/setup_session.sh

# 1. Register Build Pipeline
echo "1. Registering CI/CD Pipeline (OIDC Federation)..."
$BIN --yes cicd create-pipeline --name "frontend-prod" --provider github --repo "org/app"

# 2. Create Temporary Deployment Key (Burn-after-read)
echo "2. Creating Burn-after-read Deployment Key..."
$BIN --yes secret delete --name "svc/deploy-key" --force > /dev/null 2>&1 || true
$BIN --yes secret create --name "svc/deploy-key" --value "deploy_token_9988" --read-once

# 3. Simulation of Pipeline Injection
echo "3. Simulating Pipeline Intake (OIDC Auth)..."
# In a real pipeline, secretr cicd auth would be called with OIDC token
echo "Pipeline authenticated."

# 4. Use Secret (It should be deleted after this)
echo "4. Reading Secret (Read 1)..."
$BIN --yes secret get --name "svc/deploy-key" > /dev/null
echo "First read successful."

echo "5. Attempting Read 2 (Should Fail)..."
set +e
$BIN --yes secret get --name "svc/deploy-key" 2>&1 | grep -q "not found\|expired\|read once"
if [ $? -eq 0 ]; then
    echo "Secret successfully purged after read."
else
    echo "FAIL: Secret still exists."
    exit 1
fi
set -e

echo "DevSecOps Workflow Demonstration Complete."
