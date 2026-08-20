'use client'

import { useEffect, useRef } from 'react'
import { supabase, USER_COLUMNS } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { hapticNotify, parseStartParam } from '@/lib/telegram'
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
        const parsed = parseStartParam(startParam)
        if (!parsed) {
          navigateFallback()
          return
        }

        // ── guest_<invite_token> — guest invite link ────────────────────────
        if (parsed.kind === 'guest') {
          // Consume the stored token up front: whether the claim succeeds or the
          // link is already claimed/revoked, replaying it on every app launch
          // would show the same error toast forever.
          localStorage.removeItem('ps_guest_join_token')
          const token = parsed.token
          const { data, error } = await supabase.rpc('claim_guest_link', { p_token: token })
          // claim_guest_link returns either {property_id, db_id} on success or
          // {error: 'revoked'|'already_claimed'|...} on failure — never both keys
          // together, so the guard must accept either shape, not just the success one.
          const result = (data && typeof data === 'object' && ('property_id' in data || 'error' in data)) ? data as { property_id?: string; db_id?: string; error?: string } : null

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
            .select(USER_COLUMNS)
            .eq('id', currentUser.id)
            .single()
          if (freshUser) useAppStore.getState().setUser(freshUser as User)

          hapticNotify('success')
          showToast({ type: 'success', title: 'Доступ отримано! 🎉' })
          useAppStore.getState().navigateRoot('guest-home')
          if (result.property_id) {
            navigate('property-detail', { propertyId: result.property_id, dbId: result.db_id ?? undefined })
          } else if (result.db_id) {
            navigate('db-objects', { dbId: result.db_id })
          }
          return
        }

        // ── team_<invite_token> — team member (editor) invite ───────────────
        if (parsed.kind === 'team') {
          const token = parsed.token
          const { data, error } = await supabase.rpc('claim_team_invite', { p_token: token })
          // claim_team_invite повертає {db_id} при успіху або {error: 'revoked'|
          // 'already_claimed'|'not_found'|'cannot_claim_own_link'} — ніколи обидва
          // ключі разом (той самий контракт, що й claim_guest_link).
          const result = (data && typeof data === 'object' && ('db_id' in data || 'error' in data)) ? data as { db_id?: string; error?: string } : null

          if (error || !result || result.error) {
            const msg = result?.error === 'revoked' ? 'Запрошення відкликано власником'
              : result?.error === 'already_claimed' ? 'Це запрошення вже використано'
              : result?.error === 'cannot_claim_own_link' ? 'Це ваша власна база'
              : 'Запрошення не знайдено або недійсне'
            showToast({ type: 'error', title: 'Помилка доступу', subtitle: msg })
            navigateFallback()
            return
          }

          hapticNotify('success')
          showToast({ type: 'success', title: 'Ви в команді! 🎉', subtitle: 'База доступна для редагування' })
          // db-list підтягне member-бази через useDatabases (roles не змінюються)
          useAppStore.getState().navigateRoot('db-list')
          if (result.db_id) {
            navigate('db-objects', { dbId: result.db_id })
          }
          return
        }

        // ── prop_<share_token> — property share link ────────────────────────
        // Lookup via SECURITY DEFINER RPC — handles both new share_token (24-char hex)
        // and legacy UUID format for backward compatibility.
        if (parsed.kind === 'prop') {
          const token = parsed.token
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
        if (parsed.kind === 'col') {
          const token = parsed.token
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
            // Токен їде РАЗОМ з id: перегляд авторизується ним, а не самим
            // UUID — інакше ротація посилання нікого не відрізає (IDOR, 049).
            navigate('shared-collection', { collectionId, colToken: token })
          }
          return
        }

        // ── db_<shareToken> — database share link ────────────────────────────
        // parseStartParam only yields known kinds, so anything not handled above
        // is 'db' — no redundant prefix re-check needed.
        localStorage.removeItem('ps_guest_join_token')
        const token = parsed.token

        if (!useAppStore.getState().isOnline) {
          showToast({ type: 'error', title: 'Немає інтернету', subtitle: 'Підключення до бази недоступне офлайн' })
          navigateFallback()
          return
        }

        // Token-validated SECURITY DEFINER RPC: checks token + expiry and creates
        // the subscription server-side (clients can't INSERT subscriptions — 036).
        const { data: rows, error: dbErr } = await supabase
          .rpc('subscribe_to_shared_db', { p_token: token })
        if (dbErr) {
          showToast({ type: 'error', title: 'Помилка запиту', subtitle: 'Не вдалося перевірити посилання' })
          navigateFallback()
          return
        }
        const sub = (Array.isArray(rows) && rows[0] && typeof rows[0] === 'object') ? rows[0] as { db_id: string | null; db_name: string | null; error: string | null } : null

        if (!sub || sub.error === 'not_found') {
          // 036 filters expired tokens server-side — "not found" covers both cases
          showToast({ type: 'error', title: 'Базу не знайдено', subtitle: 'Посилання невірне або застаріло' })
          navigateFallback()
          return
        }

        // Owner tapped their own share link — reset history to db-list then open objects
        if (sub.error === 'own_db' && sub.db_id) {
          useAppStore.getState().navigateRoot('db-list')
          navigate('db-objects', { dbId: sub.db_id })
          return
        }

        if (sub.error || !sub.db_id) {
          showToast({ type: 'error', title: 'Помилка підписки', subtitle: 'Спробуйте ще раз' })
          navigateFallback()
          return
        }

        // subscribe_to_shared_db may have normalised a default-owner (who never
        // created a database) to 'realtor' server-side — re-fetch so the store's
        // role matches the realtor-dashboard home we're about to land on. Best
        // effort: a failed refresh must not abort the (already succeeded)
        // subscription flow, so swallow its error instead of hitting the catch.
        try {
          const { data: freshUser } = await supabase
            .from('users')
            .select(USER_COLUMNS)
            .eq('id', currentUser.id)
            .single()
          if (freshUser) useAppStore.getState().setUser(freshUser as User)
        } catch { /* role refresh is best-effort */ }

        hapticNotify('success')
        showToast({ type: 'success', title: 'Базу підключено! 🎉' })
        useAppStore.getState().navigateRoot('realtor-dashboard')
        navigate('realtor-database', { dbId: sub.db_id })
      } catch (e) {
        console.error('[useDeepLink]', e)
        navigateFallback()
      }
    }

    process()
  }, [user]) // eslint-disable-line react-hooks/exhaustive-deps
}
