#!/bin/bash

# Test edge function response format
# This simulates what the mobile client sends

# Load env vars
if [ -f .env.local ]; then
  export $(cat .env.local | grep -v '^#' | xargs)
fi

SUPABASE_URL="${NEXT_PUBLIC_SUPABASE_URL}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"

if [ -z "$SUPABASE_URL" ]; then
  echo "❌ NEXT_PUBLIC_SUPABASE_URL not set"
  exit 1
fi

if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
  echo "❌ TELEGRAM_BOT_TOKEN not set"
  exit 1
fi

echo "🧪 Testing Edge Function: POST $SUPABASE_URL/functions/v1/telegram-auth"
echo ""

# Create minimal valid initData (won't actually validate HMAC)
# Format: key1=value1\nkey2=value2...
INIT_DATA="user={\"id\":123456789,\"first_name\":\"Test\",\"username\":\"testuser\",\"language_code\":\"uk\"}
auth_date=1234567890
hash=dummyhash123456"

echo "📤 Sending request:"
echo "  initData: $INIT_DATA"
echo ""

RESPONSE=$(curl -s -X POST \
  "$SUPABASE_URL/functions/v1/telegram-auth" \
  -H "Content-Type: application/json" \
  -d "{\"initData\":\"$(echo "$INIT_DATA" | tr '\n' '&')\"}" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "📥 Response (HTTP $HTTP_CODE):"
echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
echo ""

# Check response structure
if echo "$BODY" | grep -q '"access_token"'; then
  echo "✅ Has access_token field"

  ACCESS_TOKEN=$(echo "$BODY" | jq -r '.access_token' 2>/dev/null)
  if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
    PARTS=$(echo "$ACCESS_TOKEN" | tr '.' '\n' | wc -l)
    if [ "$PARTS" = "3" ]; then
      echo "✅ access_token is valid JWT (3 parts)"
    else
      echo "❌ access_token is NOT valid JWT (has $PARTS parts instead of 3)"
    fi
  fi
else
  echo "❌ Missing access_token field"
fi

if echo "$BODY" | grep -q '"refresh_token"'; then
  echo "✅ Has refresh_token field"
else
  echo "❌ Missing refresh_token field"
fi

if echo "$BODY" | grep -q '"user"'; then
  echo "✅ Has user field"
else
  echo "❌ Missing user field"
fi

echo ""
echo "📋 Expected response format:"
echo "{"
echo '  "access_token": "header.payload.signature",'
echo '  "refresh_token": "header.payload.signature",'
echo '  "user": { "id": "...", "first_name": "...", ... }'
echo "}"
