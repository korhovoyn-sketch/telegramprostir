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
      ?? localStorage.getItem('ps_guest_join_token') ?? undefined
    if (!startParam) return

    handled.current = true

    async function process() {
      // Capture user at hook execution time — prevents race condition if store clears user
      const currentUser = useAppStore.getState().user
      if (!currentUser) {
        console.warn('[useDeepLink] User cleared before deep link processed')
        return
      }
      const role = currentUser.role
      const homeScreen: ScreenName = role === 'owner' ? 'db-list' : role === 'realtor' ? 'realtor-dashboard' : 'guest-home'

      function navigateFallback() {
        const { screen } = useAppStore.getState()
        if (screen === 'splash' || screen === 'welcome' || screen === 'role-select') {
          useAppStore.getState().navigateRoot(homeScreen)
        }
      }

      try {
        if (!startParam) {
          navigateFallback()
          return
        }

        // ── guest_<invite_token> — guest invite link ────────────────────────
        if (startParam.startsWith('guest_')) {
          const token = startParam.slice(6)
          const { data, error } = await supabase.rpc('claim_guest_link', { p_token: token })
          const result = (data && typeof data === 'object' && 'property_id' in data) ? data as { property_id?: string; db_id?: string; error?: string } : null

          if (error || !result || result.error) {
            const msg = result?.error === 'revoked' ? 'Запрошення відкликано власником'
              : result?.error === 'already_claimed' ? 'Це запрошення вже використано'
              : result?.error === 'cannot_claim_own_link' ? 'Не можна прийняти власне запрошення'
              : 'Запрошення не знайдено або недійсне'
            showToast({ type: 'error', title: 'Помилка доступу', subtitle: msg })
            navigateFallback()
            return
          }

          // Refresh user in store — claim_guest_link may have set role='guest' in DB
          const { data: freshUser } = await supabase
            .from('users')
            .select('id,tg_id,tg_username,first_name,last_name,email,phone,role,language_code,currency,plan,notification_push,notification_weekly,notification_views,created_at,updated_at')
            .eq('id', currentUser.id)
            .single()
          if (freshUser) useAppStore.getState().setUser(freshUser as User)

          window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
          showToast({ type: 'success', title: 'Доступ отримано! 🎉' })
          useAppStore.getState().navigateRoot('guest-home')
          if (result.property_id) {
            navigate('property-detail', { propertyId: result.property_id, dbId: result.db_id ?? undefined })
          } else if (result.db_id) {
            navigate('db-objects', { dbId: result.db_id })
          }
          return
        }

        // ── prop_<share_token> — property share link ────────────────────────
        // Lookup via SECURITY DEFINER RPC — handles both new share_token (24-char hex)
        // and legacy UUID format for backward compatibility.
        if (startParam.startsWith('prop_')) {
          const token = startParam!.slice(5)
          const { data: rows, error: rpcErr } = await supabase
            .rpc('lookup_shared_property', { p_token: token })
          if (rpcErr) throw rpcErr
          const prop = (Array.isArray(rows) && rows[0] && typeof rows[0] === 'object' && 'id' in rows[0]) ? rows[0] as { id: string; db_id: string } : null

          if (!prop) {
            showToast({ type: 'error', title: 'Об\'єкт не знайдено', subtitle: 'Посилання недійсне або об\'єкт видалено' })
            navigateFallback()
            return
          }

          useAppStore.getState().navigateRoot(homeScreen)
          navigate('property-detail', { propertyId: prop.id, dbId: prop.db_id })
          return
        }

        // ── col_<share_token> — collection share link ───────────────────────
        // Handles both new share_token and legacy UUID.
        if (startParam.startsWith('col_')) {
          const token = startParam!.slice(4)
          const { data: rows, error: rpcErr } = await supabase
            .rpc('lookup_shared_collection', { p_token: token })
          if (rpcErr) throw rpcErr
          const col = (Array.isArray(rows) && rows[0] && typeof rows[0] === 'object' && 'id' in rows[0]) ? rows[0] as { id: string; realtor_id: string } : null

          if (!col) {
            showToast({ type: 'error', title: 'Підбірку не знайдено', subtitle: 'Посилання недійсне або підбірку видалено' })
            navigateFallback()
            return
          }

          const collectionId = col.id
          if (col.realtor_id === currentUser.id) {
            // Current user owns this collection — open it directly
            useAppStore.getState().navigateRoot(homeScreen)
            navigate('collections', { collectionId })
          } else {
            // Another user's collection — show read-only view
            useAppStore.getState().navigateRoot(homeScreen)
            navigate('shared-collection', { collectionId })
          }
          return
        }

        // ── db_<shareToken> — database share link ────────────────────────────
        if (!startParam.startsWith('db_')) {
          navigateFallback()
          return
        }

        localStorage.removeItem('ps_guest_join_token')
        const token = startParam.slice(3)
        const { data: rows, error: dbErr } = await supabase
          .rpc('lookup_shared_db', { p_token: token })
        const db = (Array.isArray(rows) && rows[0] && typeof rows[0] === 'object' && 'id' in rows[0]) ? rows[0] as { id: string; owner_id: string; share_expires_at: string | null } : null

        if (dbErr) {
          showToast({ type: 'error', title: 'Помилка запиту', subtitle: dbErr.message || 'Не вдалося перевірити посилання' })
          navigateFallback()
          return
        }

        if (!db) {
          showToast({ type: 'error', title: 'Базу не знайдено', subtitle: 'Перевірте посилання або QR-код' })
          navigateFallback()
          return
        }
        if (db.share_expires_at && new Date(db.share_expires_at) < new Date()) {
          showToast({ type: 'error', title: 'Посилання застаріло', subtitle: 'Попросіть власника оновити посилання' })
          navigateFallback()
          return
        }

        // Owner tapped their own share link — reset history to db-list then open objects
        if (db.owner_id === currentUser.id) {
          useAppStore.getState().navigateRoot('db-list')
          navigate('db-objects', { dbId: db.id })
          return
        }

        // Realtor — subscribe then open the database with clean history
        const { error } = await supabase
          .from('realtor_subscriptions')
          .upsert({ realtor_id: currentUser.id, db_id: db.id }, { onConflict: 'realtor_id,db_id' })

        if (!error) {
          localStorage.removeItem('ps_guest_join_token')
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
