#!/bin/bash
source scripts/usecases/setup_session.sh

echo "--- ACL & Policy Management Use Case ---"

# 1. Create a dynamic policy
echo "1. Creating dynamic policy 'finance-admin'..."
./secretr policy create --name "finance-admin"

# 2. Grant access to an identity
echo "2. Granting access to Specialist..."
./secretr access grant --grantee "$SPECIALIST_ID" --resource "fin/*" --type secret --scopes "secret:*" --expires-in 24h

# 3. Create a secret within the scope
echo "3. Creating finance secret..."
./secretr secret delete --name "fin/payroll/2024" --force > /dev/null 2>&1 || true
./secretr secret create --name "fin/payroll/2024" --value '{"total": 500000}'

# 4. Verify access (simulated by checking grant list)
echo "4. Verifying grants..."
./secretr access list --grantee "$SPECIALIST_ID"

echo "ACL & Policy Management Use Case completed."
