'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { daysUntil, monthlyRent } from '@/lib/utils'

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

/** Дата платежу в місяці зі зсувом `offset` від поточного, у форматі ISO. */
function dueDateStr(offset: number, dueDay: number): string {
  const base = new Date()
  const d = new Date(base.getFullYear(), base.getMonth() + offset, 1)
  // Обмеження днем місяця: 31-е число в лютому інакше дало б 3 березня, тобто
  // платіж «поза своїм місяцем» і хибний порядок у списку.
  const last = new Date(d.getFullYear(), d.getMonth() + 1, 0).getDate()
  const day = Math.min(dueDay, last)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`
}

interface ScheduleRow {
  property_id: string
  due_day: number
  property: {
    id: string
    db_id: string
    name: string
    tenant_name: string | null
    status: string
    rent_type: string
    rent_rate: number | null
    area_useful: number | null
  } | null
}

export function useUpcomingPayments() {
  const [alerts, setAlerts] = useState<PaymentAlert[]>([])
  const [loading, setLoading] = useState(false)
  const user = useAppStore((s) => s.user)

  const loadUpcomingPayments = useCallback(async () => {
    if (!user) return
    setLoading(true)
    try {
      // Один запит замість двох: обʼєкт приходить вкладеним у розклад. Колонки
      // перелічені явно — екран малює саме їх (правило «explicit columns»).
      const { data: schedData, error: schedErr } = await supabase
        .from('rent_payments')
        .select('property_id,due_day,property:properties(id,db_id,name,tenant_name,status,rent_type,rent_rate,area_useful)')
        .eq('owner_id', user.id)
        .eq('is_active', true)

      // Тихо: екран сповіщень не має падати через цю додаткову вибірку — так
      // само, як `useLeaseAlerts`. Без міграцій/таблиці блок просто не зʼявиться.
      if (schedErr) { setAlerts([]); return }

      const rows = (schedData ?? []) as unknown as ScheduleRow[]
      const active = rows.filter((r) => r.property && r.property.status === 'occupied')
      if (active.length === 0) { setAlerts([]); return }

      // Вікно записів — поточний і наступний місяць: саме з них береться
      // найближча НЕсплачена дата.
      const from = dueDateStr(0, 1)
      const to   = dueDateStr(2, 1)
      const { data: recData } = await supabase
        .from('rent_payment_records')
        .select('property_id,due_date,status')
        .in('property_id', active.map((r) => r.property_id))
        .gte('due_date', from)
        .lte('due_date', to)

      const paid = new Set(
        ((recData ?? []) as { property_id: string; due_date: string; status: string }[])
          .filter((r) => r.status === 'paid')
          .map((r) => `${r.property_id}|${r.due_date}`))

      const mapped: PaymentAlert[] = []
      for (const row of active) {
        const p = row.property!
        // Перша НЕсплачена дата: цей місяць, інакше наступний. Прострочений
        // платіж таким чином лишається на екрані, доки його не підтвердять —
        // це і є та «незакрита справа», заради якої блок існує.
        let dueDate: string | null = null
        for (const offset of [0, 1]) {
          const d = dueDateStr(offset, row.due_day)
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
          amount: p.rent_rate ? monthlyRent(p.area_useful ?? 0, p.rent_rate, p.rent_type) : 0,
          days,
          level: levelFor(days),
        })
      }
      mapped.sort((a, b) => a.days - b.days)
      setAlerts(mapped)
    } finally {
      setLoading(false)
    }
  }, [user])

  return { alerts, loading, loadUpcomingPayments }
}
