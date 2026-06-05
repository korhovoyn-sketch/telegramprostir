import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0'
import { z } from 'https://esm.sh/zod@3.23.8'

// Schema for request body — rejects malformed payloads before any processing
const RequestSchema = z.object({
  initData: z.string().min(10).max(4096),
})

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Max-Age': '86400',
}

// DB-backed rate limiter — survives cold starts unlike an in-memory Map.
// Fails open: if the DB is unreachable we allow the request through.
// Rate limit keyed by a caller-supplied identifier (we use the Telegram user id,
// resolved only after HMAC validation, so it can't be forged or shared across users).
// Keying by IP was unsafe: Supabase doesn't always populate x-forwarded-for, so every
// caller collapsed into a single "unknown" bucket and shared one global 10 req/min cap.
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
      // New or expired window — reset counter
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

async function validateInitData(
  initData: string,
  botToken: string,
): Promise<Record<string, string> | null> {
  const params = new URLSearchParams(initData)
  const hash = params.get('hash')
  if (!hash) return null

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

  if (expectedHash !== hash) return null

  const authDate = parseInt(params.get('auth_date') ?? '')
  const age = Date.now() / 1000 - authDate
  // Telegram caches and reuses initData across app restarts, so a tight window
  // rejected legitimate returning users on reopen. Authenticity is already
  // guaranteed by the HMAC check above; auth_date only guards gross replay.
  // 24h window + 60s future-drift tolerance for client/server clock skew.
  if (!authDate || age < -60 || age > 86400) {
    console.warn(`[telegram-auth] auth_date rejected: authDate=${authDate} age=${Math.round(age)}s`)
    return null
  }

  return Object.fromEntries(params.entries())
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

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const rawBody = await req.json().catch(() => null)
    const parsed = RequestSchema.safeParse(rawBody)
    if (!parsed.success) {
      return new Response(JSON.stringify({ error: 'Invalid request body' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }
    const body = parsed.data

    const botToken = Deno.env.get('TELEGRAM_BOT_TOKEN')
    if (!botToken) throw new Error('Bot token not configured')

    const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ?? ''
    const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    const ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY') ?? ''
    if (!SUPABASE_URL || !SERVICE_KEY || !ANON_KEY) {
      throw new Error('Missing Supabase env vars')
    }

    // Admin client needed for rate limiting + user management
    const supabaseAdmin = createClient(SUPABASE_URL, SERVICE_KEY)

    // ── Validate Telegram initData (HMAC-SHA256) ─────────────────────────────
    const validated = await validateInitData(body.initData, botToken)
    if (!validated) {
      return new Response(JSON.stringify({ error: 'Invalid initData' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    let tgUser: Record<string, string>
    try {
      tgUser = JSON.parse(validated.user ?? '{}')
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid user data' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }
    if (!tgUser.id) {
      return new Response(JSON.stringify({ error: 'Missing user id' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const tgId = parseInt(tgUser.id, 10)
    if (isNaN(tgId)) throw new Error('Invalid Telegram user id')

    // ── Rate limiting (DB-backed, per Telegram user, 20 req/min) ─────────────
    const allowed = await checkRateLimit(supabaseAdmin, `tg:${tgId}`)
    if (!allowed) {
      return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
        status: 429,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    // ── Upsert user in public.users ──────────────────────────────────────────
    const { data: existing } = await supabaseAdmin
      .from('users')
      .select('id, role')
      .eq('tg_id', tgId)
      .maybeSingle()

    const userPayload = {
      tg_id: tgId,
      tg_username: tgUser.username ?? null,
      first_name: tgUser.first_name ?? 'User',
      last_name: tgUser.last_name ?? null,
      language_code: tgUser.language_code ?? 'uk',
      updated_at: new Date().toISOString(),
    }

    let userId: string
    if (existing) {
      const { error: updateErr } = await supabaseAdmin
        .from('users').update(userPayload).eq('tg_id', tgId)
      if (updateErr) throw new Error(`User update failed: ${updateErr.message}`)
      userId = existing.id
    } else {
      const { data: newUser, error: insertErr } = await supabaseAdmin
        .from('users')
        .insert({ ...userPayload, role: 'owner' })
        .select('id')
        .single()
      if (insertErr) throw new Error(`User insert failed: ${insertErr.message}`)
      if (!newUser) throw new Error('User insert returned no data')
      userId = newUser.id
    }

    // ── Create Supabase auth session ─────────────────────────────────────────
    // Strategy:
    //   - New users  (existing == null): createUser then signIn
    //   - Returning users (existing != null): skip createUser, go straight to signIn
    //   - Recovery: if signIn fails for a returning user (e.g. auth.users row was
    //     manually deleted), recreate the auth account and retry once
    const email = `${tgUser.id}@telegram.propspace.app`
    const password = await derivePassword(SERVICE_KEY, email)

    if (!existing) {
      const { error: createErr } = await supabaseAdmin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
      })
      if (createErr) throw new Error(`Auth user creation failed: ${createErr.message}`)
    }

    const supabaseAnon = createClient(SUPABASE_URL, ANON_KEY)
    let signInResult = await supabaseAnon.auth.signInWithPassword({ email, password })

    // Recovery path: returning user whose auth.users row was deleted externally
    if (signInResult.error && existing) {
      console.warn('[telegram-auth] sign-in failed for existing user — recreating auth account:', signInResult.error.message)
      const { error: reCreateErr } = await supabaseAdmin.auth.admin.createUser({
        email, password, email_confirm: true,
      })
      if (reCreateErr && !reCreateErr.message?.toLowerCase().includes('already')) {
        throw new Error(`Auth account recreation failed: ${reCreateErr.message}`)
      }
      signInResult = await supabaseAnon.auth.signInWithPassword({ email, password })
    }

    if (signInResult.error) throw new Error(`Sign in failed: ${signInResult.error.message}`)
    if (!signInResult.data?.session) throw new Error('Sign in returned no session')

    const { access_token, refresh_token } = signInResult.data.session
    if (!access_token || access_token.split('.').length !== 3) {
      throw new Error(`Invalid JWT: "${access_token?.substring(0, 20)}"`)
    }

    // ── Return ───────────────────────────────────────────────────────────────
    const { data: fullUser } = await supabaseAdmin
      .from('users').select('*').eq('id', userId).single()
    if (!fullUser) throw new Error('User not found after session creation')

    return new Response(
      JSON.stringify({ access_token, refresh_token, user: fullUser, is_new: !existing }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    )
  } catch (err) {
    const msg = serializeError(err)
    console.error('[telegram-auth] error:', msg)
    // Never expose internal detail to the client in production — log only
    return new Response(
      JSON.stringify({ error: 'Internal error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    )
  }
})
