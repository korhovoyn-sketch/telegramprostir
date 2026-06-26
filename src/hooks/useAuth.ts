'use client'

import { useState, useCallback } from 'react'
import { supabase, getSessionUngated } from '@/lib/supabase'
import { openSessionGate, closeSessionGate } from '@/lib/sessionGate'
import { useAppStore } from '@/store/appStore'
import type { User } from '@/types'

const SESSION_KEY     = 'ps_session'
const PROFILE_KEY     = 'ps_user'
const PROFILE_CS_KEY  = 'ps_user_cs'

const USER_COLUMNS = 'id,tg_id,tg_username,first_name,last_name,email,phone,role,language_code,currency,plan,notification_push,notification_weekly,notification_views,created_at,updated_at'

// Set true before calling signOut so the SIGNED_OUT listener doesn't re-navigate
// to welcome and trigger another auto-login cycle.
let _intentionalLogout = false

// Singleton: SplashScreen races restoreSession against a timeout, then navigates
// away — but the restore keeps running. If WelcomeScreen then fired loginViaTelegram
// immediately, two auth flows would interleave setSession calls (Supabase serialises
// them on an internal lock — the visible symptom is a login button that hangs
// forever). Sharing one promise lets the login path await the in-flight restore.
let _restorePromise: Promise<boolean> | null = null
let _restoreStartedAt: number | null = null

// Single shared budget for the whole restore flow — SplashScreen races its timeout
// against this, and loginViaTelegram derives its own wait from however much of this
// budget the in-flight restore has already consumed, instead of guessing a flat number.
export const RESTORE_BUDGET_MS = 12000

// Telegram CloudStorage persists on Telegram's servers, so it survives the
// WebView wiping localStorage between full app restarts (common on iOS). We mirror
// the Supabase session here so returning users restore instantly via setSession()
// instead of re-running the slow Edge Function login on every cold open.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function cloudStorage(): any {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cs = (window as any)?.Telegram?.WebApp?.CloudStorage
  return cs?.getItem ? cs : null
}

function cloudGet(key: string): Promise<string | null> {
  return new Promise((resolve) => {
    const deadline = Date.now() + 2000
    function attempt() {
      const cs = cloudStorage()
      if (!cs) {
        // SDK not ready yet — retry until deadline (cold Telegram start on iOS)
        if (Date.now() < deadline) { setTimeout(attempt, 100); return }
        resolve(null)
        return
      }
      // CloudStorage callback may never fire on some Telegram versions — guard with 3s cap
      const t = setTimeout(() => resolve(null), 3000)
      try {
        cs.getItem(key, (err: unknown, val: string) => {
          clearTimeout(t)
          resolve(err ? null : (val || null))
        })
      } catch { clearTimeout(t); resolve(null) }
    }
    attempt()
  })
}

// One retry after a short delay for the two true single-point-of-failure network
// calls in doRestoreSession — a single transient blip there currently means a hard
// restore failure with no fallback, forcing a full (slow) fresh login.
// Supabase-js resolves network/server errors as `{ error }` rather than rejecting,
// so we check the result's error field instead of relying on a thrown exception.
// PGRST116 ("no rows") is a legitimate empty result, not a transient failure — don't retry it.
async function withRetry<T extends { error: { code?: string } | null }>(
  fn: () => PromiseLike<T>, attempts = 2, delayMs = 400,
): Promise<T> {
  let result: T
  for (let i = 0; i < attempts; i++) {
    result = await fn()
    if (!result.error || result.error.code === 'PGRST116') return result
    if (i < attempts - 1) await new Promise(r => setTimeout(r, delayMs))
  }
  return result!
}

function persistSession(access_token: string, refresh_token: string): void {
  const payload = JSON.stringify({ access_token, refresh_token })
  try { cloudStorage()?.setItem?.(SESSION_KEY, payload, () => {}) } catch { /* unsupported */ }
}

function persistProfile(user: User): void {
  const payload = JSON.stringify(user)
  try { localStorage.setItem(PROFILE_KEY, payload) } catch { /* quota */ }
  // Mirror to CloudStorage so iOS cold-start (localStorage wiped) avoids a DB fetch
  try { cloudStorage()?.setItem?.(PROFILE_CS_KEY, payload, () => {}) } catch { /* unsupported */ }
}

function clearPersistedSession(): void {
  try { localStorage.removeItem(PROFILE_KEY) } catch { /* ignore */ }
  try { cloudStorage()?.removeItem?.(SESSION_KEY, () => {}) } catch { /* unsupported */ }
  try { cloudStorage()?.removeItem?.(PROFILE_CS_KEY, () => {}) } catch { /* unsupported */ }
}

export function useAuth() {
  const [loading, setLoading] = useState(false)
  const { setUser, navigateRoot, showToast } = useAppStore()

  const setupAuthListener = useCallback(() => {
    if (!supabase.auth) return { unsubscribe: () => {} }
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === 'TOKEN_REFRESHED' && session) {
        // Supabase rotates the refresh token on every silent background refresh —
        // without this, our CloudStorage mirror goes stale and the next restore
        // that falls back to it uses an already-invalidated refresh token.
        persistSession(session.access_token, session.refresh_token)
        // GoTrueClient awaits this callback while holding its internal auth lock
        // (the auto-refresh tick acquires it before notifying listeners) — any
        // awaited work here would block concurrent getSession()/setSession() calls
        // elsewhere (e.g. SplashScreen's restoreSession) for up to lockAcquireTimeout
        // (5s default). Defer the DB re-fetch so the callback returns immediately.
        setTimeout(() => {
          void (async () => {
            try {
              const email = session.user.email ?? ''
              const tgIdStr = email.replace('@telegram.propspace.app', '')
              if (!tgIdStr || tgIdStr === email) return
              const tgId = parseInt(tgIdStr, 10)
              if (isNaN(tgId)) return
              const { data, error } = await supabase
                .from('users')
                .select(USER_COLUMNS)
                .eq('tg_id', tgId)
                .single()
              if (!error && data) {
                useAppStore.getState().setUser(data as User)
              }
            } catch {
              // silently ignore token refresh fetch errors
            }
          })()
        }, 0)
      } else if (event === 'SIGNED_OUT') {
        if (_intentionalLogout) { _intentionalLogout = false; return }
        useAppStore.getState().setUser(null)
        useAppStore.getState().navigateRoot('welcome')
      }
    })
    return subscription
  }, [])

  const loginViaTelegram = useCallback(async (initData: string) => {
    setLoading(true)
    try {
      // A restore may still be running after SplashScreen's timeout navigated us
      // here. Wait for it briefly — if it succeeds we already have a session and
      // can skip the slow Edge Function login (and avoid two interleaved setSession
      // flows deadlocking on Supabase's auth lock).
      if (_restorePromise) {
        const remaining = _restoreStartedAt
          ? Math.max(RESTORE_BUDGET_MS - (Date.now() - _restoreStartedAt), 500)
          : 4000
        const restored = await Promise.race([
          _restorePromise.catch(() => false),
          new Promise<false>(r => setTimeout(() => r(false), remaining)),
        ])
        const restoredUser = useAppStore.getState().user
        if (restored && restoredUser) {
          if (!restoredUser.role) {
            navigateRoot('role-select')
          } else if (restoredUser.role === 'owner') {
            navigateRoot('db-list')
          } else if (restoredUser.role === 'realtor') {
            navigateRoot('realtor-dashboard')
          } else {
            navigateRoot('guest-home')
          }
          return
        }
      }

      const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
      const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
      if (!supabaseUrl) throw new Error('Supabase URL not configured')
      if (!supabaseAnonKey) throw new Error('Supabase anon key not configured')

      // Retry up to 2 times on transient 500s (Edge Function cold start)
      const TIMEOUT_MS = 15_000
      const MAX_ATTEMPTS = 2
      let res: Response | null = null

      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS)
        try {
          res = await fetch(`${supabaseUrl}/functions/v1/telegram-auth`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${supabaseAnonKey}`,
              'apikey': supabaseAnonKey,
            },
            body: JSON.stringify({ initData }),
            signal: controller.signal,
          })
          // Retry only on 500-range errors, not 4xx
          if (res.status >= 500 && attempt < MAX_ATTEMPTS) {
            await new Promise(r => setTimeout(r, 1500 * attempt))
            continue
          }
          break
        } catch (fetchErr) {
          if ((fetchErr as Error).name === 'AbortError') {
            throw new Error('Сервер не відповідає (15 сек). Перевірте інтернет і спробуйте ще раз.')
          }
          if (attempt < MAX_ATTEMPTS) {
            await new Promise(r => setTimeout(r, 1500 * attempt))
            continue
          }
          throw new Error('Немає з\'єднання з сервером. Перевірте інтернет.')
        } finally {
          clearTimeout(timeoutId)
        }
      }
      if (!res) throw new Error('Немає відповіді від сервера. Перевірте інтернет.')

      if (!res.ok) {
        const rawText = await res.text().catch(() => '')
        let body: Record<string, string> = {}
        try { body = JSON.parse(rawText) } catch { /* rawText wasn't JSON */ }
        const code = body?.code ?? ''

        if (res.status === 404) {
          throw new Error('Сервіс авторизації не знайдено (404). Функція не задеплоєна на Supabase.')
        }
        if (res.status === 401) {
          if (code === 'INIT_DATA_EXPIRED') {
            throw new Error('Сесія Telegram застаріла. Повністю закрийте додаток і відкрийте його знову з меню бота.')
          }
          throw new Error('Помилка перевірки даних Telegram. Перезапустіть додаток.')
        }
        if (res.status === 429) {
          throw new Error('Забагато спроб входу. Зачекайте хвилину і спробуйте ще раз.')
        }

        // Map safe error codes from the Edge Function to actionable Ukrainian messages
        if (code === 'CONFIG_ERROR') {
          throw new Error('Не налаштовані змінні середовища Edge Function. Додайте TELEGRAM_BOT_TOKEN та SUPABASE_SERVICE_ROLE_KEY в Supabase → Settings → Edge Functions.')
        }
        if (code === 'DB_SETUP') {
          throw new Error('Таблиці бази даних не створені. Запустіть файл 013_master_setup.sql у Supabase → SQL Editor.')
        }
        if (code === 'TRIGGER_CONFLICT') {
          throw new Error('Застарілий тригер handle_new_user блокує реєстрацію. Запустіть 013_master_setup.sql або 003_reconcile.sql у Supabase → SQL Editor.')
        }
        if (code === 'AUTH_CONFLICT') {
          throw new Error('Помилка сесії авторизації. Спробуйте знову або зверніться до адміністратора.')
        }

        // Generic fallback for any other 500
        if (res.status >= 500) {
          throw new Error('Помилка сервера авторизації. Перевірте налаштування Edge Function у Supabase.')
        }

        throw new Error(body?.error || body?.message || `HTTP ${res.status}`)
      }

      const body = await res.json()
      const access_token = body?.access_token
      const refresh_token = body?.refresh_token
      const user = body?.user
      const is_new: boolean = body?.is_new === true

      if (!access_token) throw new Error('No access_token in response')
      if (!refresh_token) throw new Error('No refresh_token in response')
      if (!user) throw new Error('No user in response')

      if (access_token.split('.').length !== 3) {
        throw new Error(`Invalid token format: expected 3 parts, got ${access_token.split('.').length}`)
      }

      try {
        await supabase.auth.setSession({ access_token, refresh_token })
      } catch (sessionErr) {
        throw new Error(`setSession failed: ${(sessionErr as Error).message}`)
      }
      persistSession(access_token, refresh_token)

      const dbUser: User = user
      setUser(dbUser)
      persistProfile(dbUser)

      // If the user arrived via a share link, let useDeepLink handle navigation
      const startParam = typeof window !== 'undefined'
        ? window?.Telegram?.WebApp?.initDataUnsafe?.start_param
        : null
      if (startParam?.startsWith('db_') || startParam?.startsWith('prop_') || startParam?.startsWith('guest_') || startParam?.startsWith('col_')) return

      if (is_new || !dbUser.role) {
        navigateRoot('role-select')
      } else if (dbUser.role === 'owner') {
        navigateRoot('db-list')
      } else if (dbUser.role === 'realtor') {
        navigateRoot('realtor-dashboard')
      } else {
        navigateRoot('guest-home')
      }
    } catch (e) {
      const errorMsg = (e as Error).message || 'Unknown error'
      console.error('[useAuth] loginViaTelegram error:', errorMsg, e)
      showToast({ type: 'error', title: 'Помилка входу', subtitle: errorMsg })
    } finally {
      setLoading(false)
    }
  }, [setUser, navigateRoot, showToast])

  const logout = useCallback(() => {
    _intentionalLogout = true
    _restorePromise = null
    clearPersistedSession()
    setUser(null)
    navigateRoot('welcome', { fromLogout: true })
    // Fire-and-forget — SIGNED_OUT listener is suppressed by _intentionalLogout
    supabase.auth.signOut().catch(() => {})
  }, [setUser, navigateRoot])

  const updateProfile = useCallback(async (updates: Partial<User>, silent = false): Promise<boolean> => {
    setLoading(true)
    try {
      const { data: { user: authUser } } = await supabase.auth.getUser()
      if (!authUser) throw new Error('Not authenticated')

      // auth.users.id !== public.users.id — update by tg_id extracted from email
      const tgIdStr = (authUser.email ?? '').replace('@telegram.propspace.app', '')
      const tgId = parseInt(tgIdStr, 10)
      if (isNaN(tgId) || tgId <= 0) throw new Error('Cannot determine tg_id from session')

      // Strip plan, id, tg_id always. Strip role unless the current user has none
      // (first-time onboarding via RoleSelectScreen). After role is set, only the
      // DB trigger can change it — this is a second layer on top of the trigger.
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { plan: _plan, id: _id, tg_id: _tg_id, role: _role, ...safeUpdates } = updates as Partial<User> & { plan?: string }
      const currentRole = useAppStore.getState().user?.role
      if (!currentRole && _role) (safeUpdates as Partial<User>).role = _role

      const { data, error } = await supabase
        .from('users')
        .update({ ...safeUpdates, updated_at: new Date().toISOString() })
        .eq('tg_id', tgId)
        .select()
        .single()

      if (error) throw error
      setUser(data as User)
      persistProfile(data as User)
      if (!silent) showToast({ type: 'success', title: 'Профіль оновлено' })
      return true
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка збереження', subtitle: (e as Error).message })
      return false
    } finally {
      setLoading(false)
    }
  }, [setUser, showToast])

  const restoreSession = useCallback(() => {
    if (!_restorePromise) {
      _restoreStartedAt = Date.now()
      _restorePromise = doRestoreSession()
      _restorePromise.then(ok => {
        if (!ok) { _restorePromise = null; _restoreStartedAt = null }
        // Clear a successful singleton after a grace delay so it doesn't linger
        // indefinitely, while still letting any near-simultaneous loginViaTelegram
        // calls observe the success first.
        else setTimeout(() => { _restorePromise = null; _restoreStartedAt = null }, 5000)
      }).catch(() => { _restorePromise = null; _restoreStartedAt = null })
    }
    return _restorePromise
  }, [])

  return { loading, loginViaTelegram, logout, updateProfile, restoreSession, setupAuthListener }
}

// Returns the Telegram user ID from initDataUnsafe — does NOT require a valid session.
// initDataUnsafe is NOT HMAC-validated here; only the Edge Function validates it.
// Use only for cache-key matching (fast path), never for access control decisions.
function getTgIdFromInitData(): number {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const user = (window as any)?.Telegram?.WebApp?.initDataUnsafe?.user
    if (user?.id) return parseInt(String(user.id), 10)
  } catch { /* ignore */ }
  return NaN
}

// Silently refresh the Supabase session + DB profile in the background after
// the fast-path profile cache already returned true. Does not affect navigation,
// but closeSessionGate() here unblocks any REST/Storage queries that screens
// mounted in the meantime are waiting on (see openSessionGate in Fast Path 0).
async function refreshSessionSilently(tgId: number): Promise<void> {
  try {
    let session = (await getSessionUngated()).data.session
    if (!session) {
      const stored = await cloudGet(SESSION_KEY)
      if (stored) {
        try {
          const { access_token, refresh_token } = JSON.parse(stored)
          if (access_token && refresh_token) {
            const res = await withRetry(() => supabase.auth.setSession({ access_token, refresh_token }))
            session = res.data.session
            if (session) persistSession(session.access_token, session.refresh_token)
          }
        } catch { /* expired tokens — session stays null */ }
      }
    }
    if (session) {
      const { data } = await supabase.from('users').select('id,tg_id,tg_username,first_name,last_name,email,phone,role,language_code,currency,plan,notification_push,notification_weekly,notification_views,created_at').eq('tg_id', tgId).single()
      if (data) {
        useAppStore.getState().setUser(data as User)
        persistProfile(data as User)
      }
    }
  } catch { /* background — silently ignore */ }
  finally { closeSessionGate() }
}

async function doRestoreSession(): Promise<boolean> {
  const setUser = (u: User | null) => useAppStore.getState().setUser(u)
  try {
    // Fast path 0: Profile cache + identity from initDataUnsafe.user.id.
    // Deliberately does NOT block navigation on supabase.auth.getSession() first —
    // on iOS cold starts, localStorage (where GoTrueClient persists its session by
    // default) is wiped at the same time as our profile cache, so getSession()
    // reliably comes back null in exactly the scenario this fast path exists for,
    // making a navigation-blocking gate dead code and forcing every iOS cold start
    // through the slow CloudStorage restore below (the visible "stuck at 58%"
    // splash stall). Instead, trust a tg_id-matched cached profile immediately for
    // navigation, and separately gate REST/Storage queries (not navigation) behind
    // openSessionGate() below while refreshSessionSilently restores the real
    // session in the background — see src/lib/sessionGate.ts for why a query-level
    // gate is required even though a navigation-level one isn't.
    const tgId0 = getTgIdFromInitData()
    if (!isNaN(tgId0)) {
      // Check localStorage first (warm starts, Android)
      let cached: User | null = null
      try {
        const lsRaw = localStorage.getItem(PROFILE_KEY)
        if (lsRaw) {
          const u = JSON.parse(lsRaw) as User
          if (u.tg_id === tgId0) cached = u
        }
      } catch { /* ignore */ }

      // Check CloudStorage (iOS cold start where localStorage was wiped)
      if (!cached) {
        try {
          const csRaw = await cloudGet(PROFILE_CS_KEY)
          if (csRaw) {
            const u = JSON.parse(csRaw) as User
            if (u.tg_id === tgId0) cached = u
          }
        } catch { /* ignore */ }
      }

      if (cached) {
        setUser(cached)
        // Restore/validate the real session + live DB profile in the background
        // without blocking UX — handles both the localStorage-has-it and the
        // CloudStorage-fallback case. Hold REST/Storage queries (not navigation)
        // for up to 3s so screens that mount right after this returns get a real
        // JWT instead of querying anonymously and having RLS silently return
        // empty results — see src/lib/sessionGate.ts.
        openSessionGate(3000)
        refreshSessionSilently(tgId0).catch(() => {})
        return true
      }
    }

    // Existing token-based restore (first install, or initDataUnsafe unavailable)
    let session = (await getSessionUngated()).data.session

    let csProfile: string | null = null
    if (!session) {
      const [stored, cs] = await Promise.all([
        cloudGet(SESSION_KEY),
        cloudGet(PROFILE_CS_KEY),
      ])
      csProfile = cs

      if (stored) {
        try {
          const { access_token, refresh_token } = JSON.parse(stored)
          if (access_token && refresh_token) {
            const res = await withRetry(() => supabase.auth.setSession({ access_token, refresh_token }))
            session = res.data.session
            if (session) persistSession(session.access_token, session.refresh_token)
          }
        } catch { /* corrupt or expired — fall through to no-session */ }
      }
    }

    if (!session) return false

    const email = session.user.email ?? ''
    const tgIdStr = email.replace('@telegram.propspace.app', '')
    if (!tgIdStr || tgIdStr === email) return false

    const tgId = parseInt(tgIdStr, 10)
    if (isNaN(tgId)) return false

    // Fast path 1: localStorage cache (warm starts, Android)
    try {
      const raw = localStorage.getItem(PROFILE_KEY)
      if (raw) {
        const cached = JSON.parse(raw) as User
        if (cached.tg_id === tgId) {
          setUser(cached)
          supabase.from('users').select('id,tg_id,tg_username,first_name,last_name,email,phone,role,language_code,currency,plan,notification_push,notification_weekly,notification_views,created_at').eq('tg_id', tgId).single()
            .then(({ data }) => { if (data) { useAppStore.getState().setUser(data as User); persistProfile(data as User) } })
          return true
        }
      }
    } catch { /* corrupt — fall through */ }

    // Fast path 2: CloudStorage profile cache
    try {
      const raw = csProfile ?? await cloudGet(PROFILE_CS_KEY)
      if (raw) {
        const cached = JSON.parse(raw) as User
        if (cached.tg_id === tgId) {
          setUser(cached)
          supabase.from('users').select('id,tg_id,tg_username,first_name,last_name,email,phone,role,language_code,currency,plan,notification_push,notification_weekly,notification_views,created_at').eq('tg_id', tgId).single()
            .then(({ data }) => { if (data) { useAppStore.getState().setUser(data as User); persistProfile(data as User) } })
          return true
        }
      }
    } catch { /* corrupt — fall through */ }

    // Last resort: DB fetch (first-ever restore after fresh install)
    const { data } = await withRetry(() => supabase.from('users').select('id,tg_id,tg_username,first_name,last_name,email,phone,role,language_code,currency,plan,notification_push,notification_weekly,notification_views,created_at').eq('tg_id', tgId).single())
    if (!data) return false
    setUser(data as User)
    persistProfile(data as User)
    return true
  } catch {
    return false
  }
}
