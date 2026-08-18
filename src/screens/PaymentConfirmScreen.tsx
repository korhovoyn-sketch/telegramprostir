'use client'

import { useEffect, useState, useCallback } from 'react'
import { useAppStore } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import RetryState from '@/components/ui/RetryState'
import { offlineGuard } from '@/lib/offline'
import { supabase } from '@/lib/supabase'
import { sanitizeDecimal, scrollFocusedIntoView, humanizeDbError } from '@/lib/utils'
import { RENT_PAYMENT_RECORD_COLUMNS, expectedRent, fmtDueDate } from '@/lib/rentPayments'
import type { RentPaymentRecord } from '@/types'

/**
 * Повноекранна форма підтвердження платежу — заміна колишньої `<Modal>` у
 * PaymentCalendarScreen (фаза 2 переробки модалок, atomic-riding-clock.md).
 * Оптимістичний апдейт+rollback старого `handleMarkPaid` тут НЕ потрібен:
 * PaymentCalendarScreen цілком перемонтовується на `back()` і сам перечитує
 * свіжий стан із сервера — миттєвий фідбек тепер дає сам перехід екрана.
 */
export default function PaymentConfirmScreen() {
  const { screenParams, user, showToast, back } = useAppStore()
  const propertyId = screenParams.propertyId as string | undefined
  const dbId = screenParams.dbId as string | undefined
  const dueDate = screenParams.dueDate as string | undefined

  const { properties, loading: propLoading, error: propError, loadSingleProperty } = useProperties(dbId)
  const property = properties.find(p => p.id === propertyId)

  useEffect(() => {
    if (propertyId) loadSingleProperty(propertyId)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [propertyId])

  const [record, setRecord] = useState<RentPaymentRecord | null>(null)
  const [recordLoading, setRecordLoading] = useState(true)
  const [recordError, setRecordError] = useState<string | null>(null)
  const [amount, setAmount] = useState('')
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)

  const loadRecord = useCallback(async () => {
    if (!propertyId || !dueDate) return
    setRecordLoading(true)
    setRecordError(null)
    try {
      const { data, error } = await supabase
        .from('rent_payment_records').select(RENT_PAYMENT_RECORD_COLUMNS)
        .eq('property_id', propertyId).eq('due_date', dueDate).maybeSingle()
      if (error) throw error
      setRecord(data as RentPaymentRecord | null)
    } catch (e) {
      setRecordError(humanizeDbError(e))
    } finally {
      setRecordLoading(false)
    }
  }, [propertyId, dueDate])

  useEffect(() => { loadRecord() }, [loadRecord])

  // Pre-fill: existing amount+notes when editing a paid record, expected rent for new.
  useEffect(() => {
    if (recordLoading || !property) return
    if (record?.status === 'paid') {
      setAmount(String(record.amount ?? ''))
      setNotes(record.notes ?? '')
    } else {
      const expected = expectedRent(property)
      setAmount(expected > 0 ? String(expected) : '')
      setNotes('')
    }
  }, [record, recordLoading, property])

  const amountInvalid = amount.trim() !== '' &&
    !(isFinite(parseFloat(amount)) && parseFloat(amount) > 0)

  async function handleConfirm() {
    if (!property || !user || !dueDate) return
    if (offlineGuard()) return
    const amt = parseFloat(amount)
    const finalAmount = isFinite(amt) && amt > 0 ? amt : (expectedRent(property) || null)
    const trimmedNotes = notes.trim() || null
    setSaving(true)
    try {
      const now = new Date().toISOString()
      const { error } = await supabase
        .from('rent_payment_records')
        .upsert(
          {
            property_id: property.id,
            owner_id: property.owner_id,
            due_date: dueDate,
            paid_at: now,
            amount: finalAmount,
            notes: trimmedNotes,
            status: 'paid' as const,
            updated_at: now,
          },
          { onConflict: 'property_id,due_date' }
        )
        .select(RENT_PAYMENT_RECORD_COLUMNS).single()
      if (error) throw error
      showToast({ type: 'success', title: 'Платіж підтверджено ✓' })
      back()
    } catch (e) {
      showToast({ type: 'error', title: 'Платіж не зберігся', subtitle: humanizeDbError(e) })
    } finally {
      setSaving(false)
    }
  }

  if (!property && propError) return (
    <div className="scr bg-teal">
      <Header title="Платіж" backLabel="Назад" />
      <RetryState
        icon="🏚️"
        title="Об'єкт не знайдено"
        subtitle={propError}
        onRetry={() => propertyId && loadSingleProperty(propertyId)}
      />
    </div>
  )

  if (!property || propLoading || recordLoading) return (
    <div className="scr bg-teal">
      <Header title="Платіж" backLabel="Назад" />
      <div className="loader-wrap">
        <div className="loader" />
      </div>
    </div>
  )

  if (recordError) return (
    <div className="scr bg-teal">
      <Header title="Платіж" subtitle={property.name} backLabel="Назад" />
      <RetryState subtitle={recordError} onRetry={loadRecord} />
    </div>
  )

  const isPaid = record?.status === 'paid'

  return (
    <div className="scr bg-teal">
      <Header
        title={isPaid ? 'Редагувати платіж' : 'Підтвердити отримання'}
        subtitle={dueDate ? `${property.name} · ${fmtDueDate(dueDate)}` : property.name}
        backLabel="Назад"
      />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Сума отриманого платежу</span>
            <input
              aria-label="Сума отриманого платежу"
              className="fr-i"
              type="text" inputMode="decimal"
              placeholder="Введіть суму..."
              value={amount}
              onChange={e => setAmount(sanitizeDecimal(e.target.value))}
            />
          </div>
          <div className="fr">
            <span className="fr-l">Нотатка (необов&apos;язково)</span>
            <input
              aria-label="Нотатка до платежу"
              className="fr-i"
              type="text"
              placeholder="Готівка, переказ, часткова оплата..."
              value={notes}
              onChange={e => setNotes(e.target.value)}
              maxLength={200}
            />
          </div>
        </div>

        <button
          className={`mbtn success mbtn-flow ${amountInvalid || saving ? 'disabled' : ''} ${saving ? 'is-loading' : ''}`}
          onClick={handleConfirm}
          disabled={amountInvalid || saving}
        >
          {!saving && (isPaid ? 'Зберегти зміни' : 'Підтвердити')}
        </button>
      </div>
    </div>
  )
}
