import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

const RATE_LIMIT = new Map<string, { count: number; reset: number }>()

function checkRateLimit(ip: string): boolean {
  const now = Date.now()
  const entry = RATE_LIMIT.get(ip)
  if (!entry || entry.reset < now) {
    RATE_LIMIT.set(ip, { count: 1, reset: now + 60_000 })
    return true
  }
  if (entry.count >= 10) return false
  entry.count++
  return true
}

async function validateInitData(initData: string, botToken: string): Promise<Record<string, string> | null> {
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
  const secretKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const secretKeyBytes = await crypto.subtle.sign('HMAC', secretKey, encoder.encode(botToken))

  const hmacKey = await crypto.subtle.importKey('raw', secretKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const signature = await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(dataCheckString))
  const expectedHash = Array.from(new Uint8Array(signature)).map((b) => b.toString(16).padStart(2, '0')).join('')

  if (expectedHash !== hash) return null

  const authDate = parseInt(params.get('auth_date') ?? '')
  if (!authDate || Date.now() / 1000 - authDate > 3600) return null

  return Object.fromEntries(params.entries())
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  const ip = req.headers.get('x-forwarded-for') ?? 'unknown'
  if (!checkRateLimit(ip)) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
      status: 429,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }

  try {
    const { initData } = await req.json()
    if (!initData) {
      return new Response(JSON.stringify({ error: 'Missing initData' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const botToken = Deno.env.get('TELEGRAM_BOT_TOKEN')
    if (!botToken) throw new Error('Bot token not configured')

    const validated = await validateInitData(initData, botToken)
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
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
    )

    const { data: existing } = await supabaseAdmin
      .from('users')
      .select('id, role')
      .eq('tg_id', tgUser.id)
      .maybeSingle()

    const userPayload = {
      tg_id: tgUser.id,
      tg_username: tgUser.username ?? null,
      first_name: tgUser.first_name ?? 'User',
      last_name: tgUser.last_name ?? null,
      language_code: tgUser.language_code ?? 'uk',
      updated_at: new Date().toISOString(),
    }

    let userId: string
    if (existing) {
      await supabaseAdmin.from('users').update(userPayload).eq('tg_id', tgUser.id)
      userId = existing.id
    } else {
      const { data: newUser, error } = await supabaseAdmin
        .from('users')
        .insert({ ...userPayload, role: 'owner' })
        .select('id')
        .single()
      if (error || !newUser) throw error
      userId = newUser.id
    }

    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.generateLink({
      type: 'magiclink',
      email: `${tgUser.id}@telegram.propspace.app`,
    })
    if (authError) throw authError
    if (!authData?.properties?.hashed_token) throw new Error('No auth token received')

    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
    )
    const { data: session, error: otpError } = await supabaseClient.auth.verifyOtp({
      token_hash: authData.properties.hashed_token,
      type: 'magiclink',
    })
    if (otpError || !session?.session) throw otpError ?? new Error('Failed to verify OTP')

    const { data: fullUser } = await supabaseAdmin.from('users').select('*').eq('id', userId).single()

    return new Response(
      JSON.stringify({
        access_token: session?.session?.access_token,
        refresh_token: session?.session?.refresh_token,
        user: fullUser,
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    )
  } catch (err) {
    console.error('telegram-auth error:', err)
    return new Response(JSON.stringify({ error: 'Internal error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
