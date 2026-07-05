// Shared CORS + origin handling for all edge functions.
//
// LOAD-BEARING INVARIANT: the ALLOWED_ORIGIN check MUST stay inside the request
// handler (via corsHeadersFor), NEVER a module-level throw. A top-level throw
// runs before Deno.serve() registers a handler, so every request — including
// the OPTIONS preflight — fails with zero CORS headers. Browsers surface that
// to JS as a bare network error, indistinguishable from "no internet", which
// silently locks out 100% of users whenever the secret is missing/wrong.
//
// When ALLOWED_ORIGIN is set (normal case) we pin CORS to that single origin.
// When it is unset (misconfigured deploy) callers must short-circuit into a
// readable CONFIG_ERROR response BEFORE any token/secret-bearing logic runs;
// this helper then reflects the caller's Origin only on that secret-free
// diagnostic response so the client can show an actionable message.
export const allowedOrigin = Deno.env.get('ALLOWED_ORIGIN') ?? null

export function corsHeadersFor(reqOrigin: string | null, methods: string): Record<string, string> {
  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': methods,
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Max-Age': '86400',
  }
  headers['Access-Control-Allow-Origin'] = allowedOrigin ?? reqOrigin ?? '*'
  return headers
}

// Extract a plain message from any thrown value for server-side logging.
// NEVER return this to the client — map to a coded/generic message instead.
export function serializeError(err: unknown): string {
  if (err instanceof Error) return err.message
  if (typeof err === 'object' && err !== null && 'message' in err) {
    return String((err as { message: unknown }).message)
  }
  return JSON.stringify(err)
}
