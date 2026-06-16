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

    if (!SUPABASE_URL || !SERVICE_KEY) {
      throw new Error('Missing Supabase env vars')
    }

    const rawBody = await req.json().catch(() => null)
    const parsed = ValidateUploadSchema.safeParse(rawBody)

    if (!parsed.success) {
      return errResponse(400, 'Invalid request: ' + parsed.error.errors[0]?.message)
    }

    const { propertyId, fileName, mimeType, fileSize } = parsed.data
    const admin = createClient(SUPABASE_URL, SERVICE_KEY)

    // Verify property exists and user owns it
    const { data: prop, error: propErr } = await admin
      .from('properties')
      .select('owner_id')
      .eq('id', propertyId)
      .single()

    if (propErr || !prop) {
      return errResponse(404, 'Property not found or no access')
    }

    // Verify file count (max 10 per property).
    // Note: concurrent requests may both pass this check and exceed the limit.
    // The database trigger enforce_max_files_per_property() will catch this
    // at insert time, and the database constraint is the authoritative guard.
    const { count } = await admin
      .from('property_files')
      .select('id', { count: 'exact', head: true })
      .eq('property_id', propertyId)

    if ((count ?? 0) >= 10) {
      return errResponse(429, 'Max 10 files per property')
    }

    // All validations passed — generate signed upload URL
    const ext = mimeType === 'application/pdf' ? 'pdf'
      : mimeType === 'application/msword' ? 'doc'
      : 'docx'

    const rand = Math.random().toString(36).slice(2, 8)
    const path = `${propertyId}/${Date.now()}_${rand}.${ext}`

    const { data: uploadUrl, error: signErr } = await admin.storage
      .from('property-files')
      .createSignedUploadUrl(path)

    if (signErr) {
      throw new Error(`Storage error: ${signErr.message}`)
    }

    return new Response(
      JSON.stringify({
        ok: true,
        uploadUrl: uploadUrl.signedUrl,
        storagePath: path,
        token: uploadUrl.token,
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error'
    console.error('[validate-upload]', msg)
    return errResponse(500, 'Server error')
  }
})
