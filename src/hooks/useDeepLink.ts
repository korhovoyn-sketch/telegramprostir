'use client'

import { useEffect, useRef } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { ScreenName, User } from '@/types'

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
      const effectiveUser: User = user!

      // Determine the home screen for this user (used in fallback + history reset)
      const homeScreen: ScreenName = effectiveUser.role === 'owner' ? 'db-list' : 'realtor-dashboard'

      try {
        if (!startParam!.startsWith('db_')) {
          // Unknown deep link format — nothing to do
          return
        }

        const token = startParam!.slice(3)

        const { data: db } = await supabase
          .from('databases')
          .select('id, share_expires_at, owner_id')
          .eq('share_token', token)
          .single()

        if (!db) {
          showToast({ type: 'error', title: 'Базу не знайдено', subtitle: 'Перевірте посилання або QR-код' })
          navigateFallback(homeScreen)
          return
        }
        if (db.share_expires_at && new Date(db.share_expires_at) < new Date()) {
          showToast({ type: 'error', title: 'Посилання застаріло', subtitle: 'Попросіть власника оновити посилання' })
          navigateFallback(homeScreen)
          return
        }

        // Owner opened their own share link — go to objects list
        if (db.owner_id === effectiveUser.id) {
          navigateFallback('db-list')
          navigate('db-objects', { dbId: db.id })
          return
        }

        // Subscribe the current user to this database
        const { error } = await supabase
          .from('realtor_subscriptions')
          .upsert({ realtor_id: effectiveUser.id, db_id: db.id }, { onConflict: 'realtor_id,db_id' })

        if (error) {
          showToast({ type: 'error', title: 'Помилка підписки', subtitle: error.message })
          navigateFallback(homeScreen)
          return
        }

        window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
        showToast({ type: 'success', title: 'Базу підключено! 🎉' })

        // Reset history so "back" goes to the realtor dashboard, not auth screens
        useAppStore.getState().navigateRoot('realtor-dashboard')
        navigate('realtor-database', { dbId: db.id })
      } catch (e) {
        console.error('[useDeepLink]', e)
        navigateFallback(homeScreen)
      }
    }

    function navigateFallback(home: ScreenName) {
      const { screen } = useAppStore.getState()
      // Only redirect if the user is stuck on an auth screen
      if (screen === 'splash' || screen === 'welcome' || screen === 'role-select') {
        useAppStore.getState().navigateRoot(home)
      }
    }

    process()
  }, [user]) // eslint-disable-line react-hooks/exhaustive-deps
}
