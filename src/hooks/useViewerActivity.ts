'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'

/**
 * Хто з ІМЕНОВАНИХ користувачів відкривав ваші бази й картки.
 *
 * Третій похідний блок сповіщень після `useLeaseAlerts` і `useUpcomingPayments`,
 * і з тієї ж причини: `notifications` наповнює виключно `send-reminders`, а
 * заводити крон і рядки заради того, що вже лежить у `property_views`, — зайве.
 * Працює без міграції, не дублюється, зникає сам, коли період минув.
 *
 * ЧОМУ ЗГРУПОВАНО ПО ГЛЯДАЧУ, а не стрічкою подій. Записи не мають дедупу на
 * рівні БД, а корисна відповідь тут — «хто з партнерів реально працює», а не
 * «о 14:32 хтось відкрив». Двадцять рядків «Олена переглянула обʼєкт» ховають
 * нагадування про платежі й не додають нічого до одного рядка «Олена · 8
 * обʼєктів · сьогодні».
 *
 * АНОНІМИ СЮДИ НЕ ПОТРАПЛЯЮТЬ (`viewer_id IS NOT NULL`): публічні відкриття
 * `/v` пише `record_public_view` без особи, і рахує їх екран аналітики.
 */
export const VIEWER_ACTIVITY_DAYS = 7

export interface ViewerActivity {
  viewerId: string
  viewerName: string
  /** Скільки РІЗНИХ карток відкрив. */
  properties: number
  /** Скільки разів відкривав базу (рядки без `property_id`). */
  databases: number
  lastAt: string
}

export function useViewerActivity() {
  const [viewers, setViewers] = useState<ViewerActivity[]>([])
  const [loading, setLoading] = useState(false)
  const user = useAppStore((s) => s.user)

  const loadViewerActivity = useCallback(async () => {
    if (!user) return
    setLoading(true)
    try {
      const since = new Date(Date.now() - VIEWER_ACTIVITY_DAYS * 86400000).toISOString()
      const { data, error } = await supabase
        .from('property_views')
        .select('property_id,db_id,viewer_id,viewer_name,created_at')
        .not('viewer_id', 'is', null)
        .gte('created_at', since)
        .order('created_at', { ascending: false })
        .limit(500)

      // Тихо: блок додатковий, екран сповіщень не має падати через нього.
      if (error) { setViewers([]); return }

      // ВЛАСНІ перегляди відсіюються ТУТ, і це не косметика: вставку на картці
      // робить будь-який автентифікований, включно з власником, тож без цього
      // фільтра стрічка складалась би переважно з ваших власних відкриттів.
      const byViewer = new Map<string, { name: string; props: Set<string>; dbs: number; last: string }>()
      for (const r of data ?? []) {
        const row = r as {
          property_id: string | null; db_id: string | null
          viewer_id: string | null; viewer_name: string | null; created_at: string
        }
        if (!row.viewer_id || row.viewer_id === user.id) continue
        const cur = byViewer.get(row.viewer_id)
          ?? { name: row.viewer_name?.trim() || 'Учасник', props: new Set<string>(), dbs: 0, last: row.created_at }
        if (row.property_id) cur.props.add(row.property_id)
        else if (row.db_id) cur.dbs += 1
        // Вибірка відсортована спаданням, тож перший запис глядача і є останній.
        if (row.created_at > cur.last) cur.last = row.created_at
        byViewer.set(row.viewer_id, cur)
      }

      setViewers([...byViewer.entries()]
        .map(([viewerId, v]) => ({
          viewerId, viewerName: v.name, properties: v.props.size, databases: v.dbs, lastAt: v.last,
        }))
        // Рядок без жодної цілі неможливий за побудовою, але порожній глядач у
        // списку виглядав би як дефект — прибираємо явно.
        .filter((v) => v.properties > 0 || v.databases > 0)
        .sort((a, b) => b.lastAt.localeCompare(a.lastAt)))
    } finally {
      setLoading(false)
    }
  }, [user])

  return { viewers, loading, loadViewerActivity }
}
