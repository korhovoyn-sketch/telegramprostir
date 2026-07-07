import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0'
import { z } from 'https://esm.sh/zod@3.23.8'
import { allowedOrigin, corsHeadersFor } from '../_shared/cors.ts'

// This function's allowed methods (shared corsHeadersFor takes it as a param).
const CORS_METHODS = 'POST, OPTIONS'

const ValidateUploadSchema = z.object({
  propertyId: z.string().uuid(),
  fileName: z.string().min(1).max(255),
  mimeType: z.enum(['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']),
  fileSize: z.number().min(1).max(20 * 1024 * 1024),
})

function errResponse(cors: Record<string, string>, status: number, message: string) {
  return new Response(
    JSON.stringify({ error: message }),
    { status, headers: { ...cors, 'Content-Type': 'application/json' } }
  )
}

Deno.serve(async (req) => {
  const cors = corsHeadersFor(req.headers.get('Origin'), CORS_METHODS)

  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: cors })
  }

  if (req.method !== 'POST') {
    return errResponse(cors, 405, 'Method not allowed')
  }

  if (!allowedOrigin) {
    return errResponse(cors, 500, 'ALLOWED_ORIGIN not configured')
  }

  try {
    const SUPABASE_URL = Deno.env.get('SUPABASE_URL')
    const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
    const ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY')

    if (!SUPABASE_URL || !SERVICE_KEY || !ANON_KEY) {
      throw new Error('Missing Supabase env vars')
    }

    const rawBody = await req.json().catch(() => null)
    const parsed = ValidateUploadSchema.safeParse(rawBody)

    if (!parsed.success) {
      // Log the schema detail server-side only; return a generic message so the
      // internal validation shape isn't echoed to the client.
      console.error('[validate-upload] invalid request:', parsed.error.errors[0]?.message)
      return errResponse(cors, 400, 'Invalid request')
    }

    const { propertyId, mimeType } = parsed.data

    // Resolve the property AND the caller through the user's JWT so PostgREST
    // verifies the token signature. RLS visibility alone is NOT ownership:
    // props_realtor_select makes subscribed realtors' SELECT succeed here too,
    // which used to hand them signed upload URLs for other owners' properties.
    // The explicit owner_id comparison below is what closes that.
    const userJwt = req.headers.get('Authorization') ?? ''
    const userClient = createClient(SUPABASE_URL, ANON_KEY, {
      global: { headers: { Authorization: userJwt } },
    })

    const { data: prop, error: propErr } = await userClient
      .from('properties')
      .select('owner_id')
      .eq('id', propertyId)
      .single()

    if (propErr || !prop) {
      return errResponse(cors, 403, 'Property not found or access denied')
    }

    // users_own is the only authenticated policy on users (id = caller), so an
    // unfiltered select returns exactly the caller's row.
    const { data: me, error: meErr } = await userClient
      .from('users')
      .select('id')
      .maybeSingle()

    if (meErr || !me || me.id !== prop.owner_id) {
      return errResponse(cors, 403, 'Property not found or access denied')
    }

    // Verify file count (max 10 per property) via userClient to enforce RLS.
    // Using admin client would bypass RLS and allow reading counts for
    // properties the user doesn't own. The database trigger provides final guard.
    const { count, error: countErr } = await userClient
      .from('property_files')
      .select('id', { count: 'exact', head: true })
      .eq('property_id', propertyId)

    // Fail closed: an unreadable count must not admit an 11th file. The DB
    // trigger (trg_enforce_max_files) is the final guard either way.
    if (countErr) {
      return errResponse(cors, 500, 'Server error')
    }

    if ((count ?? 0) >= 10) {
      return errResponse(cors, 429, 'Max 10 files per property')
    }

    // Generate unique storage path — {propertyId} as first segment is required
    // by the storage SELECT policy (SPLIT_PART(name, '/', 1) ownership check).
    const ext = mimeType === 'application/pdf' ? 'pdf'
      : mimeType === 'application/msword' ? 'doc'
      : 'docx'

    const rand = Math.random().toString(36).slice(2, 8)
    const path = `${propertyId}/${Date.now()}_${rand}.${ext}`

    // Use SERVICE_KEY admin client only for storage operations (not RLS-protected)
    const admin = createClient(SUPABASE_URL, SERVICE_KEY)
    const { data: uploadData, error: signErr } = await admin.storage
      .from('property-files')
      .createSignedUploadUrl(path)

    if (signErr || !uploadData) {
      throw new Error(`Storage error: ${signErr?.message ?? 'no data'}`)
    }

    return new Response(
      JSON.stringify({
        ok: true,
        uploadUrl: uploadData.signedUrl,
        storagePath: path,
        token: uploadData.token,
      }),
      { headers: { ...cors, 'Content-Type': 'application/json' } }
    )
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error'
    console.error('[validate-upload]', msg)
    return errResponse(cors, 500, 'Server error')
  }
})
