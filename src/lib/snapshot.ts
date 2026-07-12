'use client'

// Stale-while-revalidate snapshots for list screens: the last successful
// payload is kept in localStorage so a cold start paints instantly from cache
// while the network refresh runs silently in the background.
//
// Keys are scoped by user id — a different account on the same device never
// sees someone else's cache. Bump VERSION when a cached shape changes.
const VERSION = 1
const TTL_MS = 24 * 3600_000

const keyFor = (name: string, userId: string) => `snap_v${VERSION}:${userId}:${name}`

export function readSnapshot<T>(name: string, userId: string): T | null {
  if (typeof window === 'undefined') return null
  try {
    const raw = localStorage.getItem(keyFor(name, userId))
    if (!raw) return null
    const parsed = JSON.parse(raw) as { t: number; data: T }
    // A day-old snapshot is more misleading than a skeleton.
    if (!parsed?.t || Date.now() - parsed.t > TTL_MS) return null
    return parsed.data
  } catch {
    return null
  }
}

export function writeSnapshot(name: string, userId: string, data: unknown): void {
  if (typeof window === 'undefined') return
  try {
    localStorage.setItem(keyFor(name, userId), JSON.stringify({ t: Date.now(), data }))
  } catch { /* quota/private mode — cache is best-effort */ }
}
