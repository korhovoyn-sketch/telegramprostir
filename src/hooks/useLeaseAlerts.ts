'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { daysUntil } from '@/lib/utils'

// Наближення кінця договору — це СТАН, а не подія. Тому тримаємо його похідним
// від даних, а не рядками в `notifications`:
//   • працює без міграцій і без крону — одразу;
//   • не може задублюватись при повторних прогонах;
//   • зникає саме собою, коли договір продовжили або обʼєкт звільнили.
export const LEASE_ALERT_DAYS = 30

export interface LeaseAlert {
  propertyId: string
  dbId: string
  name: string
  tenantName: string | null
  leaseEnd: string
  days: number                       // <0 — вже прострочено
  level: 'overdue' | 'critical' | 'soon'
}

function levelFor(days: number): LeaseAlert['level'] {
  if (days < 0) return 'overdue'
  if (days <= 7) return 'critical'
  return 'soon'
}

export function useLeaseAlerts() {
  const [alerts, setAlerts] = useState<LeaseAlert[]>([])
  const [loading, setLoading] = useState(false)
  const user = useAppStore((s) => s.user)

  const loadLeaseAlerts = useCallback(async () => {
    if (!user) return
    setLoading(true)
    try {
      // Межа порівняння — календарна дата, тож рахуємо в ISO 'YYYY-MM-DD'.
      const limit = new Date(Date.now() + LEASE_ALERT_DAYS * 86400000)
        .toISOString().slice(0, 10)

      const { data, error } = await supabase
        .from('properties')
        .select('id, db_id, name, tenant_name, lease_end_date')
        .eq('owner_id', user.id)
        .eq('status', 'occupied')
        .not('lease_end_date', 'is', null)
        .lte('lease_end_date', limit)
        .order('lease_end_date', { ascending: true })

      // Тихо: екран сповіщень не має падати через цю додаткову вибірку.
      if (error) { setAlerts([]); return }

      setAlerts((data ?? []).map((p) => {
        const row = p as { id: string; db_id: string; name: string; tenant_name: string | null; lease_end_date: string }
        const days = daysUntil(row.lease_end_date)
        return {
          propertyId: row.id,
          dbId: row.db_id,
          name: row.name,
          tenantName: row.tenant_name,
          leaseEnd: row.lease_end_date,
          days,
          level: levelFor(days),
        }
      }))
    } finally {
      setLoading(false)
    }
  }, [user])

  return { alerts, loading, loadLeaseAlerts }
}
