/**
 * Manual auth flow test
 * Simulates what happens in useAuth.ts when calling edge function
 */

const testCases = [
  {
    name: 'Valid JWT response',
    response: {
      access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLWlkIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
      refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLWlkIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
      user: { id: 'user-id', role: 'owner', first_name: 'Test' },
    },
    shouldPass: true,
  },
  {
    name: 'Missing access_token',
    response: {
      refresh_token: 'token',
      user: { id: 'user-id' },
    },
    shouldPass: false,
    expectedError: 'No access_token in response',
  },
  {
    name: 'Missing refresh_token',
    response: {
      access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLWlkIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
      user: { id: 'user-id' },
    },
    shouldPass: false,
    expectedError: 'No refresh_token in response',
  },
  {
    name: 'Invalid token format (not JWT)',
    response: {
      access_token: 'not-a-jwt-token',
      refresh_token: 'also-not-jwt',
      user: { id: 'user-id' },
    },
    shouldPass: false,
    expectedError: 'Invalid token format: expected 3 parts',
  },
  {
    name: 'Nested session object (common mistake)',
    response: {
      session: {
        access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLWlkIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
        refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLWlkIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
      },
      user: { id: 'user-id' },
    },
    shouldPass: false,
    expectedError: 'No access_token in response',
  },
]

function validateAuthResponse(body) {
  const access_token = body?.access_token
  const refresh_token = body?.refresh_token
  const user = body?.user

  if (!access_token) throw new Error('No access_token in response')
  if (!refresh_token) throw new Error('No refresh_token in response')
  if (!user) throw new Error('No user in response')

  // Validate JWT format before setSession
  const tokenParts = access_token.split('.')
  if (tokenParts.length !== 3) {
    throw new Error(`Invalid token format: expected 3 parts, got ${tokenParts.length}`)
  }

  return { access_token, refresh_token, user }
}

console.log('🧪 Auth Flow Test Suite\n')

testCases.forEach((testCase) => {
  try {
    const result = validateAuthResponse(testCase.response)
    if (testCase.shouldPass) {
      console.log(`✅ ${testCase.name}`)
    } else {
      console.log(`❌ ${testCase.name} — should have failed`)
    }
  } catch (error) {
    const errorMsg = error.message
    if (!testCase.shouldPass) {
      if (testCase.expectedError && errorMsg.includes(testCase.expectedError)) {
        console.log(`✅ ${testCase.name} — correctly rejected with: "${errorMsg}"`)
      } else {
        console.log(`⚠️  ${testCase.name} — rejected but with unexpected error: "${errorMsg}"`)
      }
    } else {
      console.log(`❌ ${testCase.name} — ${errorMsg}`)
    }
  }
})

console.log('\n📋 Validation Logic:')
console.log('1. access_token must be present')
console.log('2. refresh_token must be present')
console.log('3. user must be present')
console.log('4. access_token must be valid JWT (3 parts: header.payload.signature)')
console.log('5. No nested objects — flat response structure')
