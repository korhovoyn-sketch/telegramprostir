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
      const res = await fetch(`${supabaseUrl}/functions/v1/telegram-auth`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ initData }),
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error || 'Auth failed')
      }

      const { access_token, refresh_token, user } = await res.json()

      if (!access_token || !refresh_token) throw new Error('Invalid tokens received')

      await supabase.auth.setSession({ access_token, refresh_token })

      const dbUser: User = user
      setUser(dbUser)

      if (!dbUser.role) {
        navigate('role-select')
      } else {
        navigate(dbUser.role === 'owner' ? 'db-list' : 'realtor-dashboard')
      }
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка входу', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [setUser, navigate, showToast])

  const logout = useCallback(async () => {
    await supabase.auth.signOut()
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

      const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('id', session.user.id)
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
