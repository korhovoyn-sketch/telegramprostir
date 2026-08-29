'use client'

import { useState, useEffect } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'

/**
 * Довідник орендодавців — ПОХІДНИЙ, а не окрема таблиця.
 *
 * Обсяг даних тут — сама назва (рішення власника). Таблиця `landlords` заради
 * рядка тексту дала б FK, RLS-політики для власника й редактора, CRUD-екран і
 * JOIN у трьох публічних превʼю. Натомість список збирається з уже введених
 * значень — той самий прийом, що вже тримають `useLeaseAlerts`,
 * `useUpcomingPayments` і `useViewerActivity`.
 *
 * Єдину справжню ваду підходу — перейменування в багатьох рядках — знімає
 * `renameLandlord`: один UPDATE по імені замість редагування кожного рядка,
 * тобто перевага нормалізованої таблиці зникає.
 *
 * Помилка тут ТИХА: поле лишається звичайним текстовим, просто без підказок.
 * До міграції 064 колонки немає взагалі (42703), і це рівно той самий стан.
 */
export function useLandlords() {
  const [names, setNames] = useState<string[]>([])
  const user = useAppStore((s) => s.user)

  useEffect(() => {
    if (!user) return
    let stale = false
    ;(async () => {
      const [props, dbs] = await Promise.all([
        supabase.from('properties').select('landlord_name').eq('owner_id', user.id).limit(500),
        supabase.from('databases').select('landlord_name').eq('owner_id', user.id).limit(200),
      ])
      if (stale) return
      const all = [...(props.data ?? []), ...(dbs.data ?? [])]
        .map((r) => (r as { landlord_name?: string | null }).landlord_name?.trim())
        .filter((v): v is string => !!v)
      setNames([...new Set(all)].sort((a, b) => a.localeCompare(b, 'uk')))
    })()
    return () => { stale = true }
  }, [user])

  return { landlords: names }
}
