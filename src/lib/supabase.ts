import { createClient, type SupabaseClient as SBClient } from '@supabase/supabase-js'

let _supabase: SBClient | null = null

export function getSupabase(): SBClient | null {
  if (_supabase) return _supabase
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? ''
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? ''
  if (!url || !key) return null
  try {
    _supabase = createClient(url, key, {
      auth: {
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: false,
      },
    })
    return _supabase
  } catch {
    return null
  }
}

export const supabase = new Proxy({} as SBClient, {
  get(_target, prop) {
    const client = getSupabase()
    if (!client) return undefined
    return (client as unknown as Record<string | symbol, unknown>)[prop]
  },
})

export type SupabaseClient = SBClient
