import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0'
import { z } from 'https://esm.sh/zod@3.23.8'

const corsHeaders = {
  'Access-Control-Allow-Origin': Deno.env.get('ALLOWED_ORIGIN') ?? '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

const ValidateUploadSchema = z.object({
  propertyId: z.string().uuid(),
  fileName: z.string().min(1).max(255),
  mimeType: z.enum(['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']),
  fileSize: z.number().min(1).max(20 * 1024 * 1024),
})

function errResponse(status: number, message: string) {
  return new Response(
    JSON.stringify({ error: message }),
    { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
  )
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  if (req.method !== 'POST') {
    return errResponse(405, 'Method not allowed')
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
      return errResponse(400, 'Invalid request: ' + parsed.error.errors[0]?.message)
    }

    const { propertyId, mimeType } = parsed.data

    // Use user's JWT to verify ownership via RLS — if user doesn't own the
    // property, the select returns nothing (RLS blocks it) and we return 403.
    // This is more secure than using the admin client which bypasses RLS.
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
      return errResponse(403, 'Property not found or access denied')
    }

    // Verify file count (max 10 per property) via userClient to enforce RLS.
    // Using admin client would bypass RLS and allow reading counts for
    // properties the user doesn't own. The database trigger provides final guard.
    const { count } = await userClient
      .from('property_files')
      .select('id', { count: 'exact', head: true })
      .eq('property_id', propertyId)

    if ((count ?? 0) >= 10) {
      return errResponse(429, 'Max 10 files per property')
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
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error'
    console.error('[validate-upload]', msg)
    return errResponse(500, 'Server error')
  }
})
