'use client'

import { useEffect, useRef } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'

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
            return
          }
          if (db.share_expires_at && new Date(db.share_expires_at) < new Date()) {
            showToast({ type: 'error', title: 'Посилання застаріло', subtitle: 'Попросіть власника оновити посилання' })
            return
          }

          // Owner tapped their own share link — go to objects list
          if (db.owner_id === user!.id) {
            navigate('db-objects', { dbId: db.id })
            return
          }

          // Realtor — create subscription, then open the database
          const { error } = await supabase
            .from('realtor_subscriptions')
            .upsert({ realtor_id: user!.id, db_id: db.id }, { onConflict: 'realtor_id,db_id' })

          if (!error) {
            showToast({ type: 'success', title: 'Базу підключено! 🎉' })
            navigate('realtor-database', { dbId: db.id })
          } else {
            showToast({ type: 'error', title: 'Помилка підписки', subtitle: error.message })
          }
        }
      } catch (e) {
        console.error('[useDeepLink]', e)
      }
    }

    process()
  }, [user]) // eslint-disable-line react-hooks/exhaustive-deps
}
