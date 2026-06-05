'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { User } from '@/types'

export function useAuth() {
  const [loading, setLoading] = useState(false)
  const { setUser, navigate, showToast } = useAppStore()

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
        useAppStore.getState().setUser(null)
        useAppStore.getState().navigate('welcome')
      }
    })
    return subscription
  }, [])

  const loginViaTelegram = useCallback(async (initData: string) => {
    setLoading(true)
    try {
      const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
      const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
      if (!supabaseUrl) throw new Error('Supabase URL not configured')
      if (!supabaseAnonKey) throw new Error('Supabase anon key not configured')

      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 15000)
      let res: Response
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
      } catch (fetchErr) {
        if ((fetchErr as Error).name === 'AbortError') {
          throw new Error('Сервер не відповідає (15 сек). Перевірте інтернет і спробуйте ще раз.')
        }
        throw new Error('Немає з\'єднання з сервером. Перевірте інтернет.')
      } finally {
        clearTimeout(timeoutId)
      }

      if (!res.ok) {
        if (res.status === 404) {
          throw new Error('Сервіс авторизації не знайдено (404). Функція не задеплоєна на Supabase.')
        }
        if (res.status === 401) {
          // Stale/cached initData — Telegram reused an old launch token.
          throw new Error('Сесія Telegram застаріла. Повністю закрийте додаток і відкрийте його знову з меню бота.')
        }
        if (res.status === 429) {
          throw new Error('Забагато спроб входу. Зачекайте хвилину і спробуйте ще раз.')
        }
        const rawText = await res.text().catch(() => '')
        let errMsg = `HTTP ${res.status}`
        try {
          const parsed = JSON.parse(rawText)
          errMsg = parsed.detail || parsed.message || parsed.error || errMsg
        } catch { /* rawText wasn't JSON */ }
        if (res.status >= 500) {
          errMsg = 'Помилка сервера авторизації. Перевірте налаштування Edge Function у Supabase.'
        }
        throw new Error(errMsg)
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

      const dbUser: User = user
      setUser(dbUser)

      // If the user arrived via a share link, let useDeepLink handle navigation
      const startParam = typeof window !== 'undefined'
        ? window?.Telegram?.WebApp?.initDataUnsafe?.start_param
        : null
      if (startParam?.startsWith('db_') || startParam?.startsWith('prop_')) return

      if (is_new || !dbUser.role) {
        navigate('role-select')
      } else {
        navigate(dbUser.role === 'owner' ? 'db-list' : 'realtor-dashboard')
      }
    } catch (e) {
      const errorMsg = (e as Error).message || 'Unknown error'
      console.error('[useAuth] loginViaTelegram error:', errorMsg, e)
      showToast({ type: 'error', title: 'Помилка входу', subtitle: errorMsg })
    } finally {
      setLoading(false)
    }
  }, [setUser, navigate, showToast])

  const logout = useCallback(async () => {
    try {
      await supabase.auth.signOut()
    } catch {
      // ignore signOut errors — clear local state regardless
    }
    setUser(null)
    navigate('welcome')
  }, [setUser, navigate])

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
      showToast({ type: 'success', title: 'Профіль оновлено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [setUser, showToast])

  const restoreSession = useCallback(async () => {
    try {
      const { data: { session } } = await supabase.auth.getSession()
      if (!session) return false

      // auth.users.id !== public.users.id — link via tg_id from email
      const email = session.user.email ?? ''
      const tgIdStr = email.replace('@telegram.propspace.app', '')
      if (!tgIdStr || tgIdStr === email) return false

      // Parse to number — tg_id column is BIGINT, string comparison silently fails
      const tgId = parseInt(tgIdStr, 10)
      if (isNaN(tgId)) return false

      const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('tg_id', tgId)
        .single()

      if (error || !data) return false

      setUser(data as User)
      return true
    } catch {
      return false
    }
  }, [setUser])

  return { loading, loginViaTelegram, logout, updateProfile, restoreSession, setupAuthListener }
}
