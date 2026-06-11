'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { User } from '@/types'

const SESSION_KEY = 'ps_session'
const PROFILE_KEY = 'ps_user'

// Set true before calling signOut so the SIGNED_OUT listener doesn't re-navigate
// to welcome and trigger another auto-login cycle.
let _intentionalLogout = false

// Singleton: SplashScreen races restoreSession against a timeout, then navigates
// away — but the restore keeps running. If WelcomeScreen then fired loginViaTelegram
// immediately, two auth flows would interleave setSession calls (Supabase serialises
// them on an internal lock — the visible symptom is a login button that hangs
// forever). Sharing one promise lets the login path await the in-flight restore.
let _restorePromise: Promise<boolean> | null = null

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

function persistSession(access_token: string, refresh_token: string): void {
  const payload = JSON.stringify({ access_token, refresh_token })
  try { localStorage.setItem(SESSION_KEY, payload) } catch { /* quota */ }
  try { cloudStorage()?.setItem?.(SESSION_KEY, payload, () => {}) } catch { /* unsupported */ }
}

function clearPersistedSession(): void {
  try { localStorage.removeItem(SESSION_KEY) } catch { /* ignore */ }
  try { localStorage.removeItem(PROFILE_KEY) } catch { /* ignore */ }
  try { cloudStorage()?.removeItem?.(SESSION_KEY, () => {}) } catch { /* unsupported */ }
}

export function useAuth() {
  const [loading, setLoading] = useState(false)
  const { setUser, navigateRoot, showToast } = useAppStore()

  const setupAuthListener = useCallback(() => {
    if (!supabase.auth) return { unsubscribe: () => {} }
    const { data: { subscription } } = supabase.auth.onAuthStateChange(async (event, session) => {
      if (event === 'TOKEN_REFRESHED' && session) {
        try {
          const email = session.user.email ?? ''
          const tgIdStr = email.replace('@telegram.propspace.app', '')
          if (!tgIdStr || tgIdStr === email) return
          const tgId = parseInt(tgIdStr, 10)
          if (isNaN(tgId)) return
          const { data, error } = await supabase
            .from('users')
            .select('*')
            .eq('tg_id', tgId)
            .single()
          if (!error && data) {
            useAppStore.getState().setUser(data as User)
          }
        } catch {
          // silently ignore token refresh fetch errors
        }
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
        const restored = await Promise.race([
          _restorePromise.catch(() => false),
          new Promise<false>(r => setTimeout(() => r(false), 4000)),
        ])
        const restoredUser = useAppStore.getState().user
        if (restored && restoredUser) {
          if (!restoredUser.role) {
            navigateRoot('role-select')
          } else {
            navigateRoot(restoredUser.role === 'owner' ? 'db-list' : 'realtor-dashboard')
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
      try { localStorage.setItem(PROFILE_KEY, JSON.stringify(dbUser)) } catch { /* quota */ }

      // If the user arrived via a share link, let useDeepLink handle navigation
      const startParam = typeof window !== 'undefined'
        ? window?.Telegram?.WebApp?.initDataUnsafe?.start_param
        : null
      if (startParam?.startsWith('db_') || startParam?.startsWith('prop_')) return

      if (is_new || !dbUser.role) {
        navigateRoot('role-select')
      } else {
        navigateRoot(dbUser.role === 'owner' ? 'db-list' : 'realtor-dashboard')
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

  const updateProfile = useCallback(async (updates: Partial<User>) => {
    setLoading(true)
    try {
      const { data: { user: authUser } } = await supabase.auth.getUser()
      if (!authUser) throw new Error('Not authenticated')

      // auth.users.id !== public.users.id — update by tg_id extracted from email
      const tgIdStr = (authUser.email ?? '').replace('@telegram.propspace.app', '')
      const tgId = parseInt(tgIdStr, 10)
      if (!tgId) throw new Error('Cannot determine tg_id from session')

      // Strip plan on the client — the DB trigger enforces it server-side too.
      // role is intentionally allowed through so onboarding (role-select) works;
      // the DB trigger blocks realtor→owner escalation.
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { plan: _plan, id: _id, tg_id: _tg_id, ...safeUpdates } = updates as Partial<User> & { plan?: string }

      const { data, error } = await supabase
        .from('users')
        .update({ ...safeUpdates, updated_at: new Date().toISOString() })
        .eq('tg_id', tgId)
        .select()
        .single()

      if (error) throw error
      setUser(data as User)
      try { localStorage.setItem(PROFILE_KEY, JSON.stringify(data)) } catch { /* quota */ }
      showToast({ type: 'success', title: 'Профіль оновлено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [setUser, showToast])

  const restoreSession = useCallback(() => {
    if (!_restorePromise) _restorePromise = doRestoreSession()
    return _restorePromise
  }, [])

  return { loading, loginViaTelegram, logout, updateProfile, restoreSession, setupAuthListener }
}

async function doRestoreSession(): Promise<boolean> {
    const setUser = (u: User | null) => useAppStore.getState().setUser(u)
    try {
      let session = (await supabase.auth.getSession()).data.session

      // Supabase has no session in localStorage. On a full Telegram restart (iOS)
      // localStorage is often wiped, so re-hydrate from our durable copy
      // (CloudStorage first, localStorage second) via setSession. This avoids the
      // slow Edge Function re-login that otherwise hangs the splash at ~90%.
      if (!session) {
        let stored: string | null = null
        try { stored = localStorage.getItem(SESSION_KEY) } catch { /* ignore */ }
        if (!stored) stored = await cloudGet(SESSION_KEY)
        if (stored) {
          try {
            const { access_token, refresh_token } = JSON.parse(stored)
            if (access_token && refresh_token) {
              const res = await supabase.auth.setSession({ access_token, refresh_token })
              session = res.data.session
              // Tokens may have rotated on refresh — persist the fresh pair.
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

      // Fast path: use locally-cached profile so we never block on DB cold-start.
      // The cache is written on every successful login and profile update.
      try {
        const raw = localStorage.getItem(PROFILE_KEY)
        if (raw) {
          const cached = JSON.parse(raw) as User
          if (cached.tg_id === tgId) {
            setUser(cached)
            // Refresh silently in background — update cache when done.
            supabase.from('users').select('*').eq('tg_id', tgId).single()
              .then(({ data }) => {
                if (data) {
                  useAppStore.getState().setUser(data as User)
                  try { localStorage.setItem(PROFILE_KEY, JSON.stringify(data)) } catch { /* quota */ }
                }
              })
            return true
          }
        }
      } catch { /* corrupt cache — fall through to DB fetch */ }

      // No valid cache — fetch from DB (first-ever restore after login).
      const { data } = await supabase
        .from('users')
        .select('*')
        .eq('tg_id', tgId)
        .single()

      if (data) {
        setUser(data as User)
        try { localStorage.setItem(PROFILE_KEY, JSON.stringify(data)) } catch { /* quota */ }
      }
      return true
    } catch {
      return false
    }
}
