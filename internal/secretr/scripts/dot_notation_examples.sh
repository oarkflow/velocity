#!/bin/bash

# Secretr Dot Notation Examples
# This script demonstrates the enhanced dot notation support for secrets

echo "=== Secretr Dot Notation Examples ==="

# Example 1: Setting JSON as a secret value
echo "1. Setting JSON secret:"
secretr secret create --name TENANT_1_AWS --value '{"secret_key": "key1", "access_key": "val1"}'

# Example 2: Setting nested values using dot notation
echo "2. Setting nested values:"
secretr secret create --name mysql.db --value test1
secretr secret create --name mysql.opts.opt1 --value test2
secretr secret create --name mysql.opts.idle_conn --value 10

# Example 3: Setting complex nested JSON
echo "3. Setting complex nested structure:"
secretr secret create --name mysql.opts --value '{"max_conn": 100, "timeout": 30}'

# Example 4: Getting full JSON secrets
echo "4. Getting full JSON secrets:"
secretr secret get TENANT_1_AWS

# Example 5: Getting specific JSON fields using dot notation
echo "5. Getting specific JSON fields:"
secretr secret get TENANT_1_AWS.secret_key
secretr secret get TENANT_1_AWS.access_key

# Example 6: Getting nested values
echo "6. Getting nested values:"
secretr secret get mysql.opts
secretr secret get mysql.opts.idle_conn
secretr secret get mysql.db

# Example 7: Complex nested structure
echo "7. Complex nested example:"
secretr secret create --name app.config.database.host --value localhost
secretr secret create --name app.config.database.port --value 5432
secretr secret create --name app.config.api.key --value api-key-123

# Get the entire app config
secretr secret get app

# Get specific nested values
secretr secret get app.config.database.host
secretr secret get app.config.api.key

echo "=== Examples completed ==="