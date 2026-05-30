'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { User } from '@/types'

export function useAuth() {
  const [loading, setLoading] = useState(false)
  const { setUser, navigate, showToast } = useAppStore()

  const loginViaTelegram = useCallback(async (initData: string) => {
    setLoading(true)
    try {
      const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
      if (!supabaseUrl) throw new Error('Supabase URL not configured')

      const res = await fetch(`${supabaseUrl}/functions/v1/telegram-auth`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ initData }),
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Unknown error' }))
        throw new Error(err.error || `HTTP ${res.status}`)
      }

      const body = await res.json()
      const access_token = body?.access_token
      const refresh_token = body?.refresh_token
      const user = body?.user

      if (!access_token) throw new Error('No access_token in response')
      if (!refresh_token) throw new Error('No refresh_token in response')
      if (!user) throw new Error('No user in response')

      // Validate JWT format before setSession
      const tokenParts = access_token.split('.')
      if (tokenParts.length !== 3) {
        throw new Error(`Invalid token format: expected 3 parts, got ${tokenParts.length}`)
      }

      try {
        await supabase.auth.setSession({ access_token, refresh_token })
      } catch (sessionErr) {
        throw new Error(`setSession failed: ${(sessionErr as Error).message}`)
      }

      const dbUser: User = user
      setUser(dbUser)

      if (!dbUser.role) {
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

      const { data, error } = await supabase
        .from('users')
        .update({ ...updates, updated_at: new Date().toISOString() })
        .eq('id', authUser.id)
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

      // auth.users.id !== public.users.id — link via tg_id stored in user metadata
      // The auth user email is `{tgId}@telegram.propspace.app`
      const email = session.user.email ?? ''
      const tgId = email.replace('@telegram.propspace.app', '')
      if (!tgId || tgId === email) return false

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

  return { loading, loginViaTelegram, logout, updateProfile, restoreSession }
}
