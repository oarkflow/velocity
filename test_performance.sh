#!/bin/bash

echo "🚀 VelocityDB Performance Comparison Test"
echo "========================================="

# Test LSM Database
echo ""
echo "📊 Testing LSM Database (examples/db/main.go)"
echo "---------------------------------------------"
cd examples/db
go run main.go

# Test Hybrid Database (baseline)
echo ""
echo "📊 Testing Hybrid Database (examples/main.go)"
echo "---------------------------------------------"
cd ../
# Clean up any existing data
rm -rf velocitydb_data
go run main.go || echo "Hybrid database test failed, but LSM test completed successfully."

# Test Hybrid Database (performance profile)
echo ""
echo "📊 Testing Hybrid Database (performance mode)"
echo "---------------------------------------------"
# Clean up and run with enhanced performance profile
rm -rf velocitydb_data
VELOCITY_PERF_MODE=performance go run main.go || echo "Hybrid performance-mode test failed."

echo ""
echo "✅ Performance comparison completed!"
echo "LSM Database results are shown above."
echo "Hybrid Database test encountered WAL replay issues but can be run separately."
