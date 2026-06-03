'use client'

import { useEffect, useRef } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { ScreenName } from '@/types'

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
      const homeScreen: ScreenName = user!.role === 'owner' ? 'db-list' : 'realtor-dashboard'

      // Rescue: if we're stuck on an auth screen, go home first
      function navigateFallback() {
        const { screen } = useAppStore.getState()
        if (screen === 'splash' || screen === 'welcome' || screen === 'role-select') {
          useAppStore.getState().navigateRoot(homeScreen)
        }
      }

      try {
        if (!startParam!.startsWith('db_')) return

        const token = startParam!.slice(3)
        const { data: db, error: dbErr } = await supabase
          .from('databases')
          .select('id, share_expires_at, owner_id')
          .eq('share_token', token)
          .single()

        if (!db) {
          showToast({ type: 'error', title: 'Базу не знайдено', subtitle: dbErr?.message ?? 'Перевірте посилання або QR-код' })
          navigateFallback()
          return
        }
        if (db.share_expires_at && new Date(db.share_expires_at) < new Date()) {
          showToast({ type: 'error', title: 'Посилання застаріло', subtitle: 'Попросіть власника оновити посилання' })
          navigateFallback()
          return
        }

        // Owner tapped their own share link — reset history to db-list then open objects
        if (db.owner_id === user!.id) {
          useAppStore.getState().navigateRoot('db-list')
          navigate('db-objects', { dbId: db.id })
          return
        }

        // Realtor — subscribe then open the database with clean history
        const { error } = await supabase
          .from('realtor_subscriptions')
          .upsert({ realtor_id: user!.id, db_id: db.id }, { onConflict: 'realtor_id,db_id' })

        if (!error) {
          window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
          showToast({ type: 'success', title: 'Базу підключено! 🎉' })
          useAppStore.getState().navigateRoot('realtor-dashboard')
          navigate('realtor-database', { dbId: db.id })
        } else {
          showToast({ type: 'error', title: 'Помилка підписки', subtitle: error.message })
          navigateFallback()
        }
      } catch (e) {
        console.error('[useDeepLink]', e)
        navigateFallback()
      }
    }

    process()
  }, [user]) // eslint-disable-line react-hooks/exhaustive-deps
}
