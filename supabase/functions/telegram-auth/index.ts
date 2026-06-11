import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0'
import { z } from 'https://esm.sh/zod@3.23.8'

// Schema for request body — rejects malformed payloads before any processing
const RequestSchema = z.object({
  initData: z.string().min(10).max(4096),
})

// Restrict CORS to the Mini App origin when ALLOWED_ORIGIN is set in
// Supabase → Edge Functions → Secrets (e.g. https://your-app.vercel.app).
// Falls back to '*' so login keeps working until the secret is configured.
const corsHeaders = {
  'Access-Control-Allow-Origin': Deno.env.get('ALLOWED_ORIGIN') ?? '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Max-Age': '86400',
}

// ── Safe error codes (exposed to client — no internal detail) ────────────────
// These let the client show an actionable Ukrainian message without leaking
// stack traces, SQL, or secret names.
type ErrCode =
  | 'INVALID_REQUEST'
  | 'INIT_DATA_INVALID'
  | 'INIT_DATA_EXPIRED'
  | 'RATE_LIMIT'
  | 'DB_SETUP'          // tables not created (run migration)
  | 'TRIGGER_CONFLICT'  // handle_new_user trigger blocks new user creation
  | 'AUTH_CONFLICT'     // auth.users issue not caused by known triggers
  | 'CONFIG_ERROR'      // missing env var
  | 'INTERNAL'

function errResponse(status: number, message: string, code: ErrCode) {
  return new Response(
    JSON.stringify({ error: message, code }),
    { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
  )
}

// DB-backed rate limiter — survives cold starts unlike an in-memory Map.
// Fails open: if the DB is unreachable we allow the request through.
// Keyed by tg:<userId> so it can't be forged and each user gets their own cap.
async function checkRateLimit(
  // deno-lint-ignore no-explicit-any
  adminClient: any,
  key: string,
  maxRequests = 20,
  windowMs = 60_000,
): Promise<boolean> {
  try {
    const now = new Date().toISOString()
    const { data } = await adminClient
      .from('rate_limits')
      .select('count, reset_at')
      .eq('ip', key)
      .maybeSingle()

    if (!data || data.reset_at < now) {
      await adminClient.from('rate_limits').upsert({
        ip: key,
        count: 1,
        reset_at: new Date(Date.now() + windowMs).toISOString(),
      })
      return true
    }

    if (data.count >= maxRequests) return false

    await adminClient
      .from('rate_limits')
      .update({ count: data.count + 1 })
      .eq('ip', key)
    return true
  } catch {
    return true // fail open
  }
}

// Returns { ok, data } on success or { ok: false, code } on failure.
// Splitting HMAC vs expiry lets us return different 401 codes to the client.
async function validateInitData(
  initData: string,
  botToken: string,
): Promise<
  | { ok: true; data: Record<string, string> }
  | { ok: false; code: 'INIT_DATA_INVALID' | 'INIT_DATA_EXPIRED' }
> {
  const params = new URLSearchParams(initData)
  const hash = params.get('hash')
  if (!hash) return { ok: false, code: 'INIT_DATA_INVALID' }

  params.delete('hash')
  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n')

  const encoder = new TextEncoder()
  const keyData = encoder.encode('WebAppData')
  const secretKey = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  )
  const secretKeyBytes = await crypto.subtle.sign('HMAC', secretKey, encoder.encode(botToken))
  const hmacKey = await crypto.subtle.importKey(
    'raw', secretKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  )
  const signature = await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(dataCheckString))
  const expectedHash = Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

  // Constant-time comparison to prevent timing side-channel attacks
  const expectedBytes = encoder.encode(expectedHash)
  const actualBytes   = encoder.encode(hash)
  if (expectedBytes.length !== actualBytes.length) return { ok: false, code: 'INIT_DATA_INVALID' }
  let mismatch = 0
  for (let i = 0; i < expectedBytes.length; i++) mismatch |= expectedBytes[i] ^ actualBytes[i]
  if (mismatch !== 0) return { ok: false, code: 'INIT_DATA_INVALID' }

  const authDate = parseInt(params.get('auth_date') ?? '')
  const age = Date.now() / 1000 - authDate
  // Telegram caches and reuses initData across app restarts; a tight window
  // rejects legitimate returning users on re-open.
  // 24h window + 60s future-drift tolerance for client/server clock skew.
  if (!authDate || age < -60 || age > 86400) {
    console.warn(`[telegram-auth] auth_date rejected: authDate=${authDate} age=${Math.round(age)}s`)
    return { ok: false, code: 'INIT_DATA_EXPIRED' }
  }

  return { ok: true, data: Object.fromEntries(params.entries()) }
}

// Derive a deterministic password from SERVICE_KEY + email.
// Never exposed to users — only used internally for JWT generation.
async function derivePassword(serviceKey: string, email: string): Promise<string> {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(serviceKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(email))
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function serializeError(err: unknown): string {
  if (err instanceof Error) return err.message
  if (typeof err === 'object' && err !== null && 'message' in err) {
    return String((err as { message: unknown }).message)
  }
  return JSON.stringify(err)
}

// Classify a caught error message into a safe ErrCode for the client.
// None of the raw messages are returned to the client — only the code.
function classifyError(msg: string): ErrCode {
  const m = msg.toLowerCase()
  if (m.includes('not configured') || m.includes('missing supabase env')) return 'CONFIG_ERROR'
  if (m.includes('relation') && m.includes('does not exist')) return 'DB_SETUP'
  if (m.includes('database error creating new user') || m.includes('handle_new_user')) return 'TRIGGER_CONFLICT'
  if (m.includes('user insert failed') || m.includes('user update failed')) return 'DB_SETUP'
  if (m.includes('auth user creation failed') || m.includes('auth account recreation failed')) {
    return m.includes('database error') ? 'TRIGGER_CONFLICT' : 'AUTH_CONFLICT'
  }
  if (m.includes('sign in failed') || m.includes('no session')) return 'AUTH_CONFLICT'
  return 'INTERNAL'
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  // ── GET: lightweight health / config check ──────────────────────────────
  // Returns which env vars are configured (not their values).
  // Useful for diagnosing why auth is broken without exposing secrets.
  if (req.method === 'GET') {
    const checks = {
      bot_token:   !!Deno.env.get('TELEGRAM_BOT_TOKEN'),
      supabase_url: !!Deno.env.get('SUPABASE_URL'),
      service_key:  !!Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'),
      anon_key:     !!Deno.env.get('SUPABASE_ANON_KEY'),
    }
    const allOk = Object.values(checks).every(Boolean)

    // Optionally probe DB connectivity when config looks good
    let db = false
    if (allOk) {
      try {
        const admin = createClient(
          Deno.env.get('SUPABASE_URL')!,
          Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
        )
        const { error } = await admin.from('users').select('id').limit(1)
        db = !error
      } catch { /* ignore — db check is best-effort */ }
    }

    return new Response(
      JSON.stringify({ ok: allOk && db, checks: { ...checks, db } }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    )
  }

  // ── POST: auth ───────────────────────────────────────────────────────────
  try {
    const rawBody = await req.json().catch(() => null)
    const parsed = RequestSchema.safeParse(rawBody)
    if (!parsed.success) {
      return errResponse(400, 'Invalid request body', 'INVALID_REQUEST')
    }
    const body = parsed.data

    const botToken = Deno.env.get('TELEGRAM_BOT_TOKEN')
    if (!botToken) throw new Error('TELEGRAM_BOT_TOKEN not configured')

    const SUPABASE_URL  = Deno.env.get('SUPABASE_URL') ?? ''
    const SERVICE_KEY   = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    const ANON_KEY      = Deno.env.get('SUPABASE_ANON_KEY') ?? ''
    if (!SUPABASE_URL || !SERVICE_KEY || !ANON_KEY) {
      throw new Error('Missing Supabase env vars')
    }

    const adminClient = createClient(SUPABASE_URL, SERVICE_KEY)

    // ── Validate Telegram initData (HMAC-SHA256) ─────────────────────────
    const validation = await validateInitData(body.initData, botToken)
    if (!validation.ok) {
      return errResponse(
        401,
        validation.code === 'INIT_DATA_EXPIRED' ? 'Session expired' : 'Invalid initData',
        validation.code,
      )
    }
    const validated = validation.data

    let tgUser: Record<string, string>
    try {
      tgUser = JSON.parse(validated.user ?? '{}')
    } catch {
      return errResponse(400, 'Invalid user data', 'INVALID_REQUEST')
    }
    if (!tgUser.id) {
      return errResponse(400, 'Missing user id', 'INVALID_REQUEST')
    }

    const tgId = parseInt(tgUser.id, 10)
    if (isNaN(tgId)) throw new Error('Invalid Telegram user id')

    // ── Rate limiting (DB-backed, per Telegram user) ──────────────────────
    const allowed = await checkRateLimit(adminClient, `tg:${tgId}`)
    if (!allowed) {
      return errResponse(429, 'Rate limit exceeded', 'RATE_LIMIT')
    }

    // ── Upsert user in public.users ───────────────────────────────────────
    const { data: existing, error: selectErr } = await adminClient
      .from('users')
      .select('id, role')
      .eq('tg_id', tgId)
      .maybeSingle()

    if (selectErr && selectErr.code === '42P01') {
      // "undefined table" — migrations have not been applied yet
      throw new Error(`relation "users" does not exist`)
    }

    const userPayload = {
      tg_id:         tgId,
      tg_username:   tgUser.username ?? null,
      first_name:    tgUser.first_name ?? 'User',
      last_name:     tgUser.last_name ?? null,
      language_code: tgUser.language_code ?? 'uk',
      updated_at:    new Date().toISOString(),
    }

    let userId: string
    if (existing) {
      const { error: updateErr } = await adminClient
        .from('users').update(userPayload).eq('tg_id', tgId)
      if (updateErr) throw new Error(`User update failed: ${updateErr.message}`)
      userId = existing.id
    } else {
      const { data: newUser, error: insertErr } = await adminClient
        .from('users')
        .insert({ ...userPayload, role: 'owner' })
        .select('id')
        .single()
      if (insertErr) throw new Error(`User insert failed: ${insertErr.message}`)
      if (!newUser) throw new Error('User insert returned no data')
      userId = newUser.id
    }

    // ── Create Supabase auth session ──────────────────────────────────────
    // Strategy:
    //   - New users  (existing == null): createUser then signIn
    //   - Returning users (existing != null): skip createUser, go straight to signIn
    //   - Recovery: if signIn fails for a returning user (auth.users deleted externally),
    //     recreate the auth account and retry once
    //   - Recovery 2: if signIn fails due to password mismatch (SERVICE_KEY rotated),
    //     update the password via admin and retry
    const email    = `${tgUser.id}@telegram.propspace.app`
    const password = await derivePassword(SERVICE_KEY, email)

    if (!existing) {
      const { error: createErr } = await adminClient.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
      })
      if (createErr) throw new Error(`Auth user creation failed: ${createErr.message}`)
    }

    const anonClient   = createClient(SUPABASE_URL, ANON_KEY)
    let signInResult   = await anonClient.auth.signInWithPassword({ email, password })

    // Recovery path A: returning user whose auth.users row was deleted externally
    if (signInResult.error && existing) {
      const errMsg = signInResult.error.message ?? ''
      console.warn('[telegram-auth] signIn failed for existing user:', errMsg)

      if (errMsg.toLowerCase().includes('invalid login credentials')) {
        // Could be: (a) auth.users row missing, or (b) password hash mismatch (key rotated).
        // Use schema('auth') to do a targeted email lookup instead of scanning all users.
        // deno-lint-ignore no-explicit-any
        const { data: authRow } = await (adminClient as any)
          .schema('auth')
          .from('users')
          .select('id')
          .eq('email', email)
          .maybeSingle()

        if (authRow?.id) {
          // Row exists but password is wrong (SERVICE_KEY changed) — update password
          await adminClient.auth.admin.updateUserById(authRow.id, { password })
          signInResult = await anonClient.auth.signInWithPassword({ email, password })
        } else {
          // Row truly missing — recreate
          const { error: reCreateErr } = await adminClient.auth.admin.createUser({
            email, password, email_confirm: true,
          })
          if (reCreateErr && !reCreateErr.message?.toLowerCase().includes('already')) {
            throw new Error(`Auth account recreation failed: ${reCreateErr.message}`)
          }
          signInResult = await anonClient.auth.signInWithPassword({ email, password })
        }
      }
    }

    if (signInResult.error) throw new Error(`Sign in failed: ${signInResult.error.message}`)
    if (!signInResult.data?.session) throw new Error('Sign in returned no session')

    const { access_token, refresh_token } = signInResult.data.session
    if (!access_token || access_token.split('.').length !== 3) {
      throw new Error(`Invalid JWT: "${access_token?.substring(0, 20)}"`)
    }

    // ── Return ────────────────────────────────────────────────────────────
    const { data: fullUser } = await adminClient
      .from('users').select('*').eq('id', userId).single()
    if (!fullUser) throw new Error('User not found after session creation')

    return new Response(
      JSON.stringify({ access_token, refresh_token, user: fullUser, is_new: !existing }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    )
  } catch (err) {
    const msg = serializeError(err)
    console.error('[telegram-auth] error:', msg)
    const code = classifyError(msg)
    return errResponse(500, 'Internal error', code)
  }
})
