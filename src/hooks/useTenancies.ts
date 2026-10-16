'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { humanizeDbError, localDay } from '@/lib/utils'
import { fetchAllRows } from '@/lib/fetchAll'
import type { Tenancy } from '@/types'

/** ОДИН літерал, без конкатенації: парсер типів supabase-js не вміє розбирати
 *  список, зібраний у рантаймі, і віддає `GenericStringError[]` замість рядка
 *  (той самий урок, що вже коштував раунду на `PROPERTY_COLUMNS`). */
export const TENANCY_COLUMNS = 'id,owner_id,db_id,property_id,property_name,tenant_name,landlord_name,rent_rate,rent_type,utilities_rate,area_basis,area_useful,area_total,currency,lease_start_date,lease_end_date,started_at,ended_at,created_at,updated_at'

/**
 * Таблиці немає (067 не накочена) — розділ мовчки вимикається, а не падає.
 * Той самий патерн, що `useFolders` для `property_folders`: фронт мусить
 * деплоїтись незалежно від міграції, бо застосувати її звідси неможливо.
 */
const isMissingTable = (e: unknown): boolean => {
  const err = e as { code?: string; message?: string } | null
  return err?.code === '42P01' || /tenancies/i.test(err?.message ?? '')
}

/**
 * АРХІВ ПРАВОВІДНОСИН з орендарями однієї бази.
 *
 * Хук лише ЧИТАЄ. Рядки пише тригер `trg_sync_tenancy` (міграція 067) — саме
 * тому, що орендаря обнуляють три різні шляхи клієнта, і запис в обробнику
 * однієї кнопки покрив би один із трьох.
 *
 * Суми платежів приходять ДРУГИМ запитом і звʼязуються з орендою ПЕРІОДОМ, а
 * не зовнішнім ключем: обʼєкт має рівно один статус, тож дві оренди не можуть
 * перекриватись у часі, і `due_date ∈ [started_at, ended_at)` — правило точне.
 * Воно ще й працює для платежів, ЗАПИСАНИХ ДО появи архіву, чого колонка
 * `tenancy_id` не вміла б.
 */
export function useTenancies(dbId?: string) {
  const [tenancies, setTenancies] = useState<Tenancy[]>([])
  const [loading, setLoading] = useState(false)
  const [unavailable, setUnavailable] = useState(false)
  // Збій ЗАВАНТАЖЕННЯ ≠ «архів порожній». Без цього обрив звʼязку читався б
  // як упевнена відповідь «правовідносин не було» — найгірша неправда саме на
  // екрані історії (той самий урок, що в `AccessList`).
  const [error, setError] = useState<string | null>(null)

  const loadTenancies = useCallback(async (id?: string) => {
    const targetDbId = id || dbId
    if (!targetDbId) return
    setLoading(true)
    setError(null)
    try {
      // Усі сторінки, а не `limit(500)`: обрізаний архів правовідносин — це
      // «оренд було менше», тобто неправда саме на екрані історії.
      let rows: Tenancy[]
      try {
        rows = await fetchAllRows<Tenancy>((from, to, first) => supabase
          .from('tenancies')
          .select(TENANCY_COLUMNS, first ? { count: 'exact' } : undefined)
          .eq('db_id', targetDbId)
          // Відкриті першими (`ended_at IS NULL` → NULLS FIRST), далі найсвіжіші.
          .order('ended_at', { ascending: false, nullsFirst: true })
          .order('started_at', { ascending: false })
          .order('id', { ascending: true })
          .range(from, to))
      } catch (err) {
        if (isMissingTable(err)) { setUnavailable(true); setTenancies([]); return }
        throw err
      }

      setTenancies(rows)
      if (rows.length === 0) return

      // Другий запит: підтверджені платежі по тих самих обʼєктах. Фільтр по
      // періоду — на клієнті: діапазонів стільки ж, скільки оренд, і зліпити
      // їх в один PostgREST-предикат не можна без `or=(...)` на кожну пару.
      const propIds = [...new Set(rows.map(t => t.property_id).filter((v): v is string => !!v))]
      if (propIds.length === 0) return
      // `limit(2000)` тут нічого не гарантував: сервер віддає максимум
      // `max_rows` (1000), тобто суми «Отримано» тихо недораховувались у
      // власника з найдовшою історією. Дочитуємо всі сторінки.
      let recs: { property_id: string; due_date: string; amount: number | null }[]
      try {
        recs = await fetchAllRows<{ property_id: string; due_date: string; amount: number | null }>((from, to, first) => supabase
          .from('rent_payment_records')
          .select('id,property_id,due_date,amount,status', first ? { count: 'exact' } : undefined)
          .in('property_id', propIds)
          // Часткові (071) — теж отримані гроші; без них «Отримано» за оренду
          // недораховувало б саме незакриті місяці.
          .in('status', ['paid', 'partial'])
          .order('id', { ascending: true })
          .range(from, to))
      } catch {
        // Платежі — ДОДАТКОВА інформація: їхній збій не сміє забирати архів.
        // `_paid_total` лишається НЕВИЗНАЧЕНИМ, і картка малює «—», а не $0:
        // нуль — це відповідь «не платили», якої ми не маємо.
        return
      }

      setTenancies(rows.map(t => {
        if (!t.property_id) return t
        // Межі — ЛОКАЛЬНІ дні, як і `due_date`: зріз UTC-мітки зсував межу на
        // день для дій між північчю й 03:00 за Києвом.
        const from = localDay(t.started_at)
        const to = t.ended_at ? localDay(t.ended_at) : null
        let sum = 0
        let count = 0
        for (const r of recs) {
          if (r.property_id !== t.property_id) continue
          if (r.due_date < from) continue
          if (to && r.due_date >= to) continue
          sum += r.amount ?? 0
          count += 1
        }
        return { ...t, _paid_total: sum, _paid_count: count }
      }))
    } catch (e) {
      setError(humanizeDbError(e))
    } finally {
      setLoading(false)
    }
  }, [dbId])

  return { tenancies, loading, unavailable, error, loadTenancies }
}
