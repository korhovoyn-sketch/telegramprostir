import { createClient, type SupabaseClient as SBClient } from '@supabase/supabase-js'

let _supabase: SBClient | null = null

export function getSupabase(): SBClient {
  if (_supabase) return _supabase
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? ''
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? ''
  _supabase = createClient(url, key, {
    auth: {
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false,
    },
  })
  return _supabase
}

export const supabase = new Proxy({} as SBClient, {
  get(_target, prop) {
    return (getSupabase() as unknown as Record<string | symbol, unknown>)[prop]
  },
})

export type SupabaseClient = SBClient
