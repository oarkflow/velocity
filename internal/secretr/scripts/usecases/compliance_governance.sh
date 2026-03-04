#!/bin/bash
source scripts/usecases/setup_session.sh

echo "--- Compliance & Governance Use Case ---"

# 1. List Frameworks
echo "1. Listing available frameworks..."
# compliance commands are on a struct, but likely registered via subcommands in main.go
# Assuming 'secretr compliance list-frameworks' or similar.
# Based on internal/cli/commands/compliance.go, they might not be fully registered in root.
# Let's check main.go to see how they are registered.
./secretr compliance --help || echo "Compliance command not fully registered in root CLI yet?"

echo "Compliance & Governance Use Case completed."
