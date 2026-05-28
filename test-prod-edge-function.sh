#!/bin/bash

# Test production edge function after CORS fix

SUPABASE_URL="https://cjsuuzynpuimgndudzka.supabase.co"
FUNCTION_URL="$SUPABASE_URL/functions/v1/telegram-auth"

echo "🧪 Testing Production Edge Function"
echo "URL: $FUNCTION_URL"
echo ""

# Generate a test initData
test_cases=(
  '{"initData":""}'
  '{"initData":"test=1"}'
  '{"initData":"user={}"}'
)

for i in "${!test_cases[@]}"; do
  echo "Test $((i+1)): ${test_cases[$i]}"

  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$FUNCTION_URL" \
    -H "Content-Type: application/json" \
    -H "Origin: https://telegramprostir-gjyn.vercel.app" \
    -d "${test_cases[$i]}")

  HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
  BODY=$(echo "$RESPONSE" | sed '$d')

  echo "  HTTP: $HTTP_CODE"
  echo "  Response: $BODY"

  # Check CORS headers
  if [ "$HTTP_CODE" != "403" ]; then
    echo "  ✅ CORS is working (not 403 Host not in allowlist)"
  else
    echo "  ❌ Still blocked by CORS"
  fi

  echo ""
done

echo "📋 Expected behaviors:"
echo "- Empty initData → 400 (Missing initData)"
echo "- Invalid initData → 401 (Invalid initData)"
echo "- Valid initData → 401 (Invalid HMAC, but authentication attempted)"
echo "- All responses should NOT be 403"
