import { createClient, type SupabaseClient as SBClient } from '@supabase/supabase-js'

function createSupabaseClient(): SBClient {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
  if (!url || !key) {
    const missing = !url ? 'NEXT_PUBLIC_SUPABASE_URL' : 'NEXT_PUBLIC_SUPABASE_ANON_KEY'
    throw new Error(`[PropSpace] Missing environment variable: ${missing}. Set it in Vercel project settings.`)
  }
  return createClient(url, key, {
    auth: {
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false,
    },
  })
}

let _supabase: SBClient | undefined

export function getSupabase(): SBClient {
  return (_supabase ??= createSupabaseClient())
}

export const supabase = new Proxy({} as SBClient, {
  get(_target, prop) {
    return (getSupabase() as unknown as Record<string | symbol, unknown>)[prop]
  },
})

export type SupabaseClient = SBClient
