'use client'

import { useEffect, useRef } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { User } from '@/types'

export function useDeepLink() {
  const user = useAppStore((s) => s.user)
  const navigate = useAppStore((s) => s.navigate)
  const showToast = useAppStore((s) => s.showToast)
  const handled = useRef(false)

  useEffect(() => {
    if (!user || handled.current) return

    const startParam = window.Telegram?.WebApp?.initDataUnsafe?.start_param
    if (!startParam) return

    handled.current = true

    async function process() {
      let effectiveUser: User = user!

      try {
        if (startParam!.startsWith('db_')) {
          const token = startParam!.slice(3)

          const { data: db } = await supabase
            .from('databases')
            .select('id, share_expires_at, owner_id')
            .eq('share_token', token)
            .single()

          if (!db) {
            showToast({ type: 'error', title: 'Базу не знайдено', subtitle: 'Перевірте посилання або QR-код' })
            navigateFallback(effectiveUser)
            return
          }
          if (db.share_expires_at && new Date(db.share_expires_at) < new Date()) {
            showToast({ type: 'error', title: 'Посилання застаріло', subtitle: 'Попросіть власника оновити посилання' })
            navigateFallback(effectiveUser)
            return
          }

          // Owner tapped their own share link
          if (db.owner_id === effectiveUser.id) {
            navigate('db-objects', { dbId: db.id })
            return
          }

          // New user without a role — sharing link implies realtor
          if (!effectiveUser.role) {
            const { error: roleErr } = await supabase
              .from('users')
              .update({ role: 'realtor', updated_at: new Date().toISOString() })
              .eq('id', effectiveUser.id)
            if (!roleErr) {
              effectiveUser = { ...effectiveUser, role: 'realtor' }
              useAppStore.getState().setUser(effectiveUser)
            }
          }

          // Subscribe and open database
          const { error } = await supabase
            .from('realtor_subscriptions')
            .upsert({ realtor_id: effectiveUser.id, db_id: db.id }, { onConflict: 'realtor_id,db_id' })

          if (!error) {
            window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
            showToast({ type: 'success', title: 'Базу підключено! 🎉' })
            navigate('realtor-database', { dbId: db.id })
          } else {
            showToast({ type: 'error', title: 'Помилка підписки', subtitle: error.message })
            navigateFallback(effectiveUser)
          }
        } else {
          navigateFallback(effectiveUser)
        }
      } catch (e) {
        console.error('[useDeepLink]', e)
        navigateFallback(effectiveUser)
      }
    }

    function navigateFallback(u: User) {
      const { screen } = useAppStore.getState()
      // Only navigate if the user is stuck on auth screens
      if (screen === 'splash' || screen === 'welcome' || screen === 'role-select') {
        navigate(u.role === 'owner' ? 'db-list' : 'realtor-dashboard')
      }
    }

    process()
  }, [user]) // eslint-disable-line react-hooks/exhaustive-deps
}
