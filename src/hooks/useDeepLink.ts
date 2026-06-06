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
        // ── prop_<propertyId> — direct property share link ──────────────────
        if (startParam!.startsWith('prop_')) {
          const propertyId = startParam!.slice(5)
          const { data: prop } = await supabase
            .from('properties')
            .select('id, db_id')
            .eq('id', propertyId)
            .single()

          if (!prop) {
            showToast({ type: 'error', title: 'Об\'єкт не знайдено', subtitle: 'Посилання недійсне або об\'єкт видалено' })
            navigateFallback()
            return
          }

          useAppStore.getState().navigateRoot(homeScreen)
          navigate('property-detail', { propertyId: prop.id, dbId: prop.db_id })
          return
        }

        // ── col_<collectionId> — shared collection link ─────────────────────
        if (startParam!.startsWith('col_')) {
          const collectionId = startParam!.slice(4)

          // Check if the current user owns this collection (realtor who shared it)
          const { data: ownCol } = await supabase
            .from('collections')
            .select('id')
            .eq('id', collectionId)
            .maybeSingle()

          if (ownCol) {
            // Open directly in the user's own collections screen
            useAppStore.getState().navigateRoot(homeScreen)
            navigate('collections', { collectionId })
          } else {
            // Show the read-only shared view (works for any logged-in user)
            useAppStore.getState().navigateRoot(homeScreen)
            navigate('shared-collection', { collectionId })
          }
          return
        }

        // ── db_<shareToken> — database share link ────────────────────────────
        if (!startParam!.startsWith('db_')) {
          navigateFallback()
          return
        }

        const token = startParam!.slice(3)
        // Resolve via SECURITY DEFINER RPC — the table has no blanket share_token
        // SELECT policy, so a row only comes back for the exact secret token.
        const { data: rows, error: dbErr } = await supabase
          .rpc('lookup_shared_db', { p_token: token })
        const db = (rows as { id: string; owner_id: string; share_expires_at: string | null }[] | null)?.[0]

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
          // If user came from guest view (share link before registration), set role to realtor
          const isGuestJoin = localStorage.getItem('ps_guest_join') === '1'
          if (isGuestJoin) {
            localStorage.removeItem('ps_guest_join')
            if (user!.role !== 'realtor') {
              await supabase.from('users').update({ role: 'realtor' }).eq('id', user!.id)
              useAppStore.getState().setUser({ ...user!, role: 'realtor' })
            }
          }
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
