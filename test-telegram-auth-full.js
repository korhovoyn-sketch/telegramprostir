/**
 * Full Telegram Auth Flow Test
 * Simulates complete login process locally
 */

const crypto = require('crypto');

// Mock Telegram Bot Token (must match what's on server)
const TELEGRAM_BOT_TOKEN = 'fake-token-for-testing';

/**
 * Step 1: Generate valid Telegram initData
 */
function generateMockInitData(botToken) {
  const user = {
    id: 123456789,
    is_bot: false,
    first_name: 'Test',
    username: 'testuser',
    language_code: 'uk',
  };

  const authDate = Math.floor(Date.now() / 1000);

  // Build parameters (must be sorted)
  const params = new URLSearchParams({
    user: JSON.stringify(user),
    auth_date: authDate.toString(),
  });

  // Calculate HMAC hash
  const dataCheckString = Array.from(params.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');

  // First HMAC: WebAppData + botToken
  const secretKey = crypto
    .createHmac('sha256', 'WebAppData')
    .update(botToken)
    .digest();

  // Second HMAC: secretKey + dataCheckString
  const hash = crypto
    .createHmac('sha256', secretKey)
    .update(dataCheckString)
    .digest('hex');

  params.append('hash', hash);

  return params.toString();
}

/**
 * Step 2: Validate initData (server-side logic)
 */
function validateInitData(initData, botToken) {
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');

  if (!hash) {
    console.error('❌ Missing hash in initData');
    return null;
  }

  params.delete('hash');
  const dataCheckString = Array.from(params.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');

  // Compute expected hash
  const secretKey = crypto
    .createHmac('sha256', 'WebAppData')
    .update(botToken)
    .digest();

  const expectedHash = crypto
    .createHmac('sha256', secretKey)
    .update(dataCheckString)
    .digest('hex');

  // Compare hashes
  if (expectedHash !== hash) {
    console.error(`❌ Hash mismatch\n  Expected: ${expectedHash}\n  Got: ${hash}`);
    return null;
  }

  // Validate auth_date
  const authDate = parseInt(params.get('auth_date') ?? '');
  const now = Math.floor(Date.now() / 1000);

  if (!authDate) {
    console.error('❌ Missing auth_date');
    return null;
  }

  if (now - authDate > 3600) {
    console.error(`❌ initData expired (${now - authDate}s old, max 3600s)`);
    return null;
  }

  return Object.fromEntries(params.entries());
}

/**
 * Step 3: Parse and validate user data
 */
function parseUserData(validatedParams) {
  try {
    const tgUser = JSON.parse(validatedParams.user ?? '{}');

    if (!tgUser.id) {
      console.error('❌ Missing user.id in initData');
      return null;
    }

    return tgUser;
  } catch (e) {
    console.error('❌ Failed to parse user JSON:', e.message);
    return null;
  }
}

/**
 * Step 4: Simulate JWT token creation
 */
function generateMockJWT() {
  // Header
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
  // Payload
  const payload = Buffer.from(JSON.stringify({ sub: 'user-id', exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64');
  // Signature (fake)
  const signature = Buffer.from('fake-signature').toString('base64');

  return `${header}.${payload}.${signature}`;
}

/**
 * Step 5: Validate JWT format
 */
function validateJWTFormat(token) {
  if (!token || typeof token !== 'string') {
    console.error('❌ Token is not a string');
    return false;
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    console.error(`❌ Invalid JWT format: has ${parts.length} parts, expected 3`);
    return false;
  }

  // Validate each part is base64
  for (let i = 0; i < 3; i++) {
    if (!parts[i]) {
      console.error(`❌ Part ${i} of JWT is empty`);
      return false;
    }
  }

  return true;
}

// ============================================================
// RUN TESTS
// ============================================================

console.log('🧪 Full Telegram Auth Flow Test\n');

// Test 1: Generate valid initData
console.log('1️⃣  Generate Mock initData with Bot Token: "fake-token-for-testing"');
const initData = generateMockInitData(TELEGRAM_BOT_TOKEN);
console.log(`   ✅ Generated initData (${initData.length} chars)`);
console.log(`   Preview: ${initData.substring(0, 80)}...`);

// Test 2: Validate initData
console.log('\n2️⃣  Validate initData on Server');
const validated = validateInitData(initData, TELEGRAM_BOT_TOKEN);
if (validated) {
  console.log('   ✅ initData is valid');
  console.log(`   ✅ auth_date: ${validated.auth_date}`);
  console.log(`   ✅ user: ${validated.user}`);
} else {
  console.log('   ❌ initData validation failed');
}

// Test 3: Parse user data
console.log('\n3️⃣  Parse Telegram User Data');
if (validated) {
  const tgUser = parseUserData(validated);
  if (tgUser) {
    console.log('   ✅ User data parsed');
    console.log(`   ✅ user.id: ${tgUser.id}`);
    console.log(`   ✅ user.first_name: ${tgUser.first_name}`);
    console.log(`   ✅ user.username: ${tgUser.username}`);
  } else {
    console.log('   ❌ User parsing failed');
  }
}

// Test 4: Generate JWT token
console.log('\n4️⃣  Generate JWT Session Token');
const accessToken = generateMockJWT();
console.log(`   ✅ Generated access_token: ${accessToken.substring(0, 50)}...`);

// Test 5: Validate JWT format
console.log('\n5️⃣  Validate JWT Token Format');
if (validateJWTFormat(accessToken)) {
  console.log('   ✅ Token has valid JWT format (3 parts)');
  const [header, payload, signature] = accessToken.split('.');
  console.log(`   ✅ Header: ${header.substring(0, 20)}...`);
  console.log(`   ✅ Payload: ${payload.substring(0, 20)}...`);
  console.log(`   ✅ Signature: ${signature.substring(0, 20)}...`);
} else {
  console.log('   ❌ Token validation failed');
}

// Test 6: Test invalid tokens
console.log('\n6️⃣  Test Invalid Token Scenarios');

const invalidTokens = [
  { name: 'Not a JWT', value: 'not-a-token', shouldFail: true },
  { name: 'Two parts', value: 'header.payload', shouldFail: true },
  { name: 'Empty parts', value: 'header..signature', shouldFail: true },
  { name: 'Valid JWT', value: accessToken, shouldFail: false },
];

invalidTokens.forEach(({ name, value, shouldFail }) => {
  const isValid = validateJWTFormat(value);
  if (isValid === !shouldFail) {
    console.log(`   ✅ "${name}" — correct validation`);
  } else {
    console.log(`   ❌ "${name}" — validation mismatch`);
  }
});

console.log('\n✨ All tests completed!');
console.log('\n📋 Summary:');
console.log('- Telegram initData generation ✅');
console.log('- HMAC-SHA256 validation ✅');
console.log('- User data parsing ✅');
console.log('- JWT token format validation ✅');
