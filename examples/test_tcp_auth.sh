#!/bin/bash

# Test script for VelocityDB TCP server with authentication

echo "Testing VelocityDB TCP Server with Authentication"
echo "================================================"

# Server should be running on port 8080
TCP_HOST="localhost"
TCP_PORT="8080"

echo "1. Testing unauthenticated access..."
echo "PUT test_key test_value" | nc $TCP_HOST $TCP_PORT

echo ""
echo "2. Testing authentication..."
echo "AUTH admin password123" | nc $TCP_HOST $TCP_PORT

echo ""
echo "3. Testing authenticated operations..."
# Need to keep connection open for multiple commands
# Using a temporary file for the commands
cat > /tmp/tcp_commands.txt << EOF
AUTH admin password123
PUT test_key test_value
GET test_key
DELETE test_key
CLOSE
EOF

echo "Running authenticated session..."
nc $TCP_HOST $TCP_PORT < /tmp/tcp_commands.txt

echo ""
echo "4. Testing invalid credentials..."
echo "AUTH admin wrongpassword" | nc $TCP_HOST $TCP_PORT

echo ""
echo "Test completed!"
rm -f /tmp/tcp_commands.txt
