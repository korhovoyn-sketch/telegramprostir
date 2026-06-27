'use client'

import { useState, useCallback } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import type { RentPayment, RentPaymentRecord } from '@/types'

export function useRentPayments() {
  const [loading, setLoading] = useState(false)
  const [schedule, setSchedule] = useState<RentPayment | null>(null)
  const [records, setRecords] = useState<RentPaymentRecord[]>([])
  const { user, showToast } = useAppStore()

  const loadSchedule = useCallback(async (propertyId: string) => {
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('rent_payments')
        .select('id,property_id,owner_id,due_day,notify_days_before,is_active,created_at,updated_at')
        .eq('property_id', propertyId)
        .single()
      if (error && error.code !== 'PGRST116') throw error
      setSchedule(data as RentPayment | null)
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [showToast])

  const loadRecords = useCallback(async (propertyId: string) => {
    // Load last 3 months + next month
    const start = new Date()
    start.setMonth(start.getMonth() - 2)
    start.setDate(1)
    const end = new Date()
    end.setMonth(end.getMonth() + 2)
    end.setDate(1)
    const { data, error } = await supabase
      .from('rent_payment_records')
      .select('id,property_id,owner_id,due_date,paid_at,amount,status,notes,created_at,updated_at')
      .eq('property_id', propertyId)
      .gte('due_date', start.toISOString().slice(0, 10))
      .lte('due_date', end.toISOString().slice(0, 10))
      .order('due_date', { ascending: false })
    if (error) showToast({ type: 'error', title: 'Помилка завантаження', subtitle: error.message })
    else setRecords((data ?? []) as RentPaymentRecord[])
  }, [showToast])

  const loadSchedulesForDb = useCallback(async (dbId: string) => {
    setLoading(true)
    try {
      const { data: props } = await supabase
        .from('properties')
        .select('id')
        .eq('db_id', dbId)
        .eq('status', 'occupied')
      const ids = (props ?? []).map((p: { id: string }) => p.id)
      if (ids.length === 0) { setLoading(false); return [] }
      const { data } = await supabase
        .from('rent_payments')
        .select('id,property_id,owner_id,due_day,notify_days_before,is_active,created_at,updated_at')
        .in('property_id', ids)
        .eq('is_active', true)
      return (data ?? []) as RentPayment[]
    } finally {
      setLoading(false)
    }
  }, [])

  const loadRecordsForDb = useCallback(async (dbId: string) => {
    const { data: props } = await supabase
      .from('properties')
      .select('id')
      .eq('db_id', dbId)
      .eq('status', 'occupied')
    const ids = (props ?? []).map((p: { id: string }) => p.id)
    if (ids.length === 0) return []
    const start = new Date()
    start.setMonth(start.getMonth() - 2)
    start.setDate(1)
    const end = new Date()
    end.setMonth(end.getMonth() + 2)
    end.setDate(1)
    const { data } = await supabase
      .from('rent_payment_records')
      .select('id,property_id,owner_id,due_date,paid_at,amount,status,notes,created_at,updated_at')
      .in('property_id', ids)
      .gte('due_date', start.toISOString().slice(0, 10))
      .lte('due_date', end.toISOString().slice(0, 10))
      .order('due_date', { ascending: false })
    return (data ?? []) as RentPaymentRecord[]
  }, [])

  const saveSchedule = useCallback(async (propertyId: string, dueDay: number, notifyDaysBefore: number) => {
    if (!user) return
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('rent_payments')
        .upsert(
          { property_id: propertyId, owner_id: user.id, due_day: dueDay, notify_days_before: notifyDaysBefore, is_active: true, updated_at: new Date().toISOString() },
          { onConflict: 'property_id' }
        )
        .select('id,property_id,owner_id,due_day,notify_days_before,is_active,created_at,updated_at')
        .single()
      if (error) throw error
      setSchedule(data as RentPayment)
      showToast({ type: 'success', title: 'Розклад платежів збережено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка збереження', subtitle: (e as Error).message })
    } finally {
      setLoading(false)
    }
  }, [user, showToast])

  const markPaid = useCallback(async (propertyId: string, dueDate: string, amount?: number) => {
    if (!user) return
    try {
      // Upsert the record — idempotent
      const { data, error } = await supabase
        .from('rent_payment_records')
        .upsert(
          {
            property_id: propertyId,
            owner_id: user.id,
            due_date: dueDate,
            paid_at: new Date().toISOString(),
            amount,
            status: 'paid',
            updated_at: new Date().toISOString(),
          },
          { onConflict: 'property_id,due_date' }
        )
        .select('id,property_id,owner_id,due_date,paid_at,amount,status,notes,created_at,updated_at')
        .single()
      if (error) throw error
      window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
      setRecords(prev => {
        const exists = prev.findIndex(r => r.property_id === propertyId && r.due_date === dueDate)
        if (exists >= 0) return prev.map((r, i) => i === exists ? (data as RentPaymentRecord) : r)
        return [data as RentPaymentRecord, ...prev]
      })
      showToast({ type: 'success', title: 'Платіж відмічено ✓' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    }
  }, [user, showToast])

  const deleteSchedule = useCallback(async (propertyId: string) => {
    try {
      await supabase.from('rent_payments').delete().eq('property_id', propertyId)
      setSchedule(null)
      showToast({ type: 'success', title: 'Розклад видалено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    }
  }, [showToast])

  return { loading, schedule, records, loadSchedule, loadRecords, loadSchedulesForDb, loadRecordsForDb, saveSchedule, markPaid, deleteSchedule, setSchedule, setRecords }
}
