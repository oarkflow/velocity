#!/bin/bash

# Test script for VelocityDB HTTP API with authentication

echo "Testing VelocityDB HTTP API with JWT Authentication"
echo "=================================================="

# Server should be running on port 8081
BASE_URL="http://localhost:8081"

echo "1. Testing login..."
LOGIN_RESPONSE=$(curl -s -X POST $BASE_URL/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password123"}')

echo "Login response: $LOGIN_RESPONSE"

# Extract token from response
TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "Failed to get token"
    exit 1
fi

echo "Token obtained: ${TOKEN:0:20}..."

echo ""
echo "2. Testing PUT operation..."
PUT_RESPONSE=$(curl -s -X POST $BASE_URL/api/put \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"key":"test_key","value":"test_value"}')

echo "PUT response: $PUT_RESPONSE"

echo ""
echo "3. Testing GET operation..."
GET_RESPONSE=$(curl -s $BASE_URL/api/get/test_key \
  -H "Authorization: Bearer $TOKEN")

echo "GET response: $GET_RESPONSE"

echo ""
echo "4. Testing DELETE operation..."
DELETE_RESPONSE=$(curl -s -X DELETE $BASE_URL/api/delete/test_key \
  -H "Authorization: Bearer $TOKEN")

echo "DELETE response: $DELETE_RESPONSE"

echo ""
echo "5. Testing unauthorized access..."
UNAUTH_RESPONSE=$(curl -s $BASE_URL/api/get/test_key)
echo "Unauthorized response: $UNAUTH_RESPONSE"

echo ""
echo "Test completed!"
