'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { basisArea, daysUntil, monthlyRent } from '@/lib/utils'
import { dueDateFor, isOwedUnderLease, owedFrom, trackedFromOffset, ARREARS_MONTHS_MAX, TENANCY_SPAN_COLUMNS, type TenancySpan } from '@/lib/rentPayments'
import { fetchAllRows } from '@/lib/fetchAll'

/**
 * Найближчі платежі для екрана сповіщень.
 *
 * ЧОМУ ЦЕ РАХУЄТЬСЯ НА КЛІЄНТІ, а не читається з `notifications`. Рядки того
 * типу (`rent_reminder`) пише ВИКЛЮЧНО edge-функція `send-reminders`, і лише в
 * той день, на який налаштоване нагадування. Тобто вкладка «Платежі» показувала
 * б щось рівно в цей день, а решту місяця була б порожня — саме те, на що
 * скаржився власник. «Найближчий платіж» — це СТАН розкладу, а не подія:
 *   • працює без крону і без міграцій — одразу;
 *   • не може задублюватись при повторних прогонах функції;
 *   • зникає САМЕ СОБОЮ, щойно платіж підтверджено.
 *
 * Той самий принцип і той самий каркас, що в `useLeaseAlerts` — свідомо, щоб
 * два похідні блоки одного екрана не розʼїхались у поведінці.
 */

/** Скільки днів наперед вважаємо «найближчим». Прострочені входять завжди. */
export const PAYMENT_ALERT_DAYS = 14

export interface PaymentAlert {
  propertyId: string
  dbId: string
  name: string
  tenantName: string | null
  dueDate: string
  amount: number
  days: number                       // <0 — прострочено
  level: 'overdue' | 'critical' | 'soon'
}

function levelFor(days: number): PaymentAlert['level'] {
  if (days < 0) return 'overdue'
  if (days <= 3) return 'critical'
  return 'soon'
}

interface ScheduleRow {
  property_id: string
  due_day: number
  created_at: string | null
  property: {
    id: string
    db_id: string
    name: string
    tenant_name: string | null
    lease_start_date: string | null
    status: string
    rent_type: string
    rent_rate: number | null
    area_useful: number | null
    area_total: number | null
    area_basis: string | null
  } | null
}

export function useUpcomingPayments() {
  const [alerts, setAlerts] = useState<PaymentAlert[]>([])
  const [loading, setLoading] = useState(false)
  const userId = useAppStore((s) => s.user?.id)

  const loadUpcomingPayments = useCallback(async () => {
    if (!userId) return
    setLoading(true)
    try {
      // Один запит замість двох: обʼєкт приходить вкладеним у розклад. Колонки
      // перелічені явно — екран малює саме їх (правило «explicit columns»).
      const { data: schedData, error: schedErr } = await supabase
        .from('rent_payments')
        .select('property_id,due_day,created_at,property:properties(id,db_id,name,tenant_name,lease_start_date,status,rent_type,rent_rate,area_useful,area_total,area_basis)')
        .eq('owner_id', userId)
        .eq('is_active', true)

      // Тихо: екран сповіщень не має падати через цю додаткову вибірку — так
      // само, як `useLeaseAlerts`. Без міграцій/таблиці блок просто не зʼявиться.
      if (schedErr) { setAlerts([]); return }

      const rows = (schedData ?? []) as unknown as ScheduleRow[]
      const active = rows.filter((r) => r.property && r.property.status === 'occupied')
      if (active.length === 0) { setAlerts([]); return }

      // Вікно записів — від найглибшої заборгованості до наступного місяця:
      // найближча НЕсплачена дата може бути й у минулому, і тоді це борг.
      const from = dueDateFor(-ARREARS_MONTHS_MAX, 1)
      const to   = dueDateFor(2, 1)
      const ids = active.map((r) => r.property_id)
      // Відкриті оренди — межа боргу для обʼєкта БЕЗ дати договору (див.
      // `owedFrom`). Додаткове джерело: збій чи відсутність 067 не прибирає блок.
      const spansP = supabase
        .from('tenancies').select(TENANCY_SPAN_COLUMNS)
        .in('property_id', ids).is('ended_at', null)
        .then(({ data, error }) => (error ? null : (data ?? []) as TenancySpan[]), () => null)
      let recData: { property_id: string; due_date: string; status: string }[]
      try {
        // Усі сторінки: сервер мовчки обрізає на 1000, а оплачений платіж за
        // межею сторінки читався б несплаченим.
        recData = await fetchAllRows<{ property_id: string; due_date: string; status: string }>((pFrom, pTo, first) => supabase
          .from('rent_payment_records')
          .select('property_id,due_date,status', first ? { count: 'exact' } : undefined)
          .in('property_id', ids)
          .gte('due_date', from)
          .lte('due_date', to)
          .order('property_id', { ascending: true }).order('due_date', { ascending: true })
          .range(pFrom, pTo))
      } catch {
        // Без записів кожен УЖЕ оплачений платіж читався б як несплачений, тобто
        // збій мережі малював би «Прострочено» там, де все сплачено. Мовчазний
        // пропуск блоку чесніший за хибну тривогу про гроші.
        setAlerts([]); return
      }
      const spans = await spansP

      const paid = new Set(
        recData
          .filter((r) => r.status === 'paid')
          .map((r) => `${r.property_id}|${r.due_date}`))

      const mapped: PaymentAlert[] = []
      for (const row of active) {
        const p = row.property!
        // Перша НЕсплачена дата — від найдавнішого місяця, за який розклад уже
        // існував, і до наступного. Доти перебирались лише поточний і наступний,
        // тож борг за минулий місяць 1-го числа ЗНИКАВ, хоча оплати не було, —
        // рівно всупереч обіцянці «лишається, доки не підтвердять».
        let dueDate: string | null = null
        const owed = owedFrom(p.lease_start_date, p.id, spans)
        for (let offset = trackedFromOffset(row.created_at); offset <= 1; offset++) {
          const d = dueDateFor(offset, row.due_day)
          // До початку оренди боргу немає — тоді найближчий платіж наступний.
          if (!isOwedUnderLease(d, owed)) continue
          if (!paid.has(`${row.property_id}|${d}`)) { dueDate = d; break }
        }
        if (!dueDate) continue
        const days = daysUntil(dueDate)
        if (!Number.isFinite(days) || days > PAYMENT_ALERT_DAYS) continue
        mapped.push({
          propertyId: p.id,
          dbId: p.db_id,
          name: p.name,
          tenantName: p.tenant_name,
          dueDate,
          // Та сама нормалізація, що в календарі: сира `rent_rate` для per_m2 —
          // це ставка за метр, і показувати її як суму до сплати було б брехнею.
          amount: p.rent_rate ? monthlyRent(basisArea(p.area_useful, p.area_total, p.area_basis), p.rent_rate, p.rent_type) : 0,
          days,
          level: levelFor(days),
        })
      }
      mapped.sort((a, b) => a.days - b.days)
      setAlerts(mapped)
    } finally {
      setLoading(false)
    }
  }, [userId])

  return { alerts, loading, loadUpcomingPayments }
}
