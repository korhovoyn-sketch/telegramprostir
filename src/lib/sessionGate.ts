// Lets Supabase REST/Storage requests wait briefly for refreshSessionSilently()
// to finish establishing a real JWT after a fast-path cache restore (see
// useAuth.ts doRestoreSession). Without this, the first queries fired by a
// freshly-mounted screen run with the anon key — RLS silently returns empty
// results instead of an error, which is indistinguishable from "no data".
let resolveGate: (() => void) | null = null
let gatePromise: Promise<void> | null = null

export function openSessionGate(maxWaitMs: number): void {
  resolveGate?.()
  gatePromise = new Promise<void>((resolve) => {
    resolveGate = resolve
    setTimeout(resolve, maxWaitMs)
  })
}

export function closeSessionGate(): void {
  resolveGate?.()
  resolveGate = null
  gatePromise = null
}

export function waitForSessionGate(): Promise<void> {
  return gatePromise ?? Promise.resolve()
}
