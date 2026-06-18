import { createClient, type SupabaseClient as SBClient } from '@supabase/supabase-js'
import { waitForSessionGate } from './sessionGate'

let _rawGetSession: SBClient['auth']['getSession'] | undefined

function createSupabaseClient(): SBClient {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
  if (!url || !key) {
    const missing = !url ? 'NEXT_PUBLIC_SUPABASE_URL' : 'NEXT_PUBLIC_SUPABASE_ANON_KEY'
    throw new Error(`[PropSpace] Missing environment variable: ${missing}. Set it in Vercel project settings.`)
  }
  const client = createClient(url, key, {
    auth: {
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false,
    },
  })

  // Every PostgREST/Storage/Realtime request resolves its access token via
  // client.auth.getSession() (see _getAccessToken in supabase-js) before the
  // request is sent. Wrapping it here — rather than the `global.fetch` option —
  // is the only point that can actually delay token resolution: by the time a
  // custom fetch runs, the Authorization header has already been computed from
  // whatever getSession() returned synchronously at call time.
  _rawGetSession = client.auth.getSession.bind(client.auth)
  const rawGetSession = _rawGetSession
  client.auth.getSession = (async () => {
    await waitForSessionGate()
    return rawGetSession()
  }) as typeof client.auth.getSession

  return client
}

let _supabase: SBClient | undefined

export function getSupabase(): SBClient {
  return (_supabase ??= createSupabaseClient())
}

// Bypasses the session gate above — for use only by the session-restore code
// itself (useAuth.ts), which would otherwise deadlock waiting on the gate it
// is responsible for closing.
export function getSessionUngated(): ReturnType<SBClient['auth']['getSession']> {
  getSupabase()
  return _rawGetSession!()
}

export const supabase = new Proxy({} as SBClient, {
  get(_target, prop) {
    return (getSupabase() as unknown as Record<string | symbol, unknown>)[prop]
  },
})

export type SupabaseClient = SBClient
