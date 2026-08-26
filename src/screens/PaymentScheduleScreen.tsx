'use client'

import { useEffect, useState, useCallback } from 'react'
import { useAppStore } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import RetryState from '@/components/ui/RetryState'
import { offlineGuard } from '@/lib/offline'
import { supabase } from '@/lib/supabase'
import { sanitizeInt, scrollFocusedIntoView, humanizeDbError } from '@/lib/utils'
import { RENT_PAYMENT_COLUMNS } from '@/lib/rentPayments'
import { IconCalendar, IconBellRing } from '@/components/Icons'
import type { RentPayment } from '@/types'

/**
 * Повноекранна форма розкладу платежів — заміна колишньої `<Modal>` у
 * PaymentCalendarScreen (фаза 2 переробки модалок, atomic-riding-clock.md).
 * Клавіатура тут — глобальний `--keyboard-h` з page.tsx, без жодної власної
 * евристики: той самий скелет, що в CreateDatabaseScreen.
 */
export default function PaymentScheduleScreen() {
  const { screenParams, user, showToast, back } = useAppStore()
  const propertyId = screenParams.propertyId as string | undefined
  const dbId = screenParams.dbId as string | undefined

  const { properties, loading: propLoading, error: propError, loadSingleProperty } = useProperties(dbId)
  const property = properties.find(p => p.id === propertyId)

  useEffect(() => {
    if (propertyId) loadSingleProperty(propertyId)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [propertyId])

  const [schedule, setSchedule] = useState<RentPayment | null>(null)
  const [scheduleLoading, setScheduleLoading] = useState(true)
  const [scheduleError, setScheduleError] = useState<string | null>(null)
  const [dueDay, setDueDay] = useState('5')
  const [notifyDays, setNotifyDays] = useState('3')
  const [saving, setSaving] = useState(false)

  const loadSchedule = useCallback(async () => {
    if (!propertyId) return
    setScheduleLoading(true)
    setScheduleError(null)
    try {
      const { data, error } = await supabase
        .from('rent_payments').select(RENT_PAYMENT_COLUMNS)
        .eq('property_id', propertyId).eq('is_active', true).maybeSingle()
      if (error) throw error
      const row = data as RentPayment | null
      setSchedule(row)
      setDueDay(row ? String(row.due_day) : '5')
      setNotifyDays(row ? String(row.notify_days_before) : '3')
    } catch (e) {
      setScheduleError(humanizeDbError(e))
    } finally {
      setScheduleLoading(false)
    }
  }, [propertyId])

  useEffect(() => { loadSchedule() }, [loadSchedule])

  async function handleSave() {
    if (!property || !user) return
    if (offlineGuard()) return
    const day = parseInt(dueDay, 10)
    const notify = parseInt(notifyDays, 10)
    if (!isFinite(day) || day < 1 || day > 28) {
      showToast({ type: 'error', title: 'День платежу має бути від 1 до 28' })
      return
    }
    setSaving(true)
    try {
      const { error } = await supabase
        .from('rent_payments')
        .upsert(
          {
            property_id: property.id,
            owner_id: property.owner_id,
            due_day: day,
            notify_days_before: isFinite(notify) ? Math.min(14, Math.max(0, notify)) : 3,
            is_active: true,
            updated_at: new Date().toISOString(),
          },
          { onConflict: 'property_id' }
        )
        .select(RENT_PAYMENT_COLUMNS).single()
      if (error) throw error
      showToast({ type: 'success', title: 'Розклад збережено' })
      back()
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка збереження', subtitle: humanizeDbError(e) })
    } finally {
      setSaving(false)
    }
  }

  if (!property && propError) return (
    <div className="scr bg-teal">
      <Header title="Розклад платежів" backLabel="Назад" />
      <RetryState
        icon="🏚️"
        title="Обʼєкт не знайдено"
        subtitle={propError}
        onRetry={() => propertyId && loadSingleProperty(propertyId)}
      />
    </div>
  )

  if (!property || propLoading || scheduleLoading) return (
    <div className="scr bg-teal">
      <Header title="Розклад платежів" backLabel="Назад" />
      <div className="loader-wrap">
        <div className="loader" />
      </div>
    </div>
  )

  if (scheduleError) return (
    <div className="scr bg-teal">
      <Header title="Розклад платежів" subtitle={property.name} backLabel="Назад" />
      <RetryState subtitle={scheduleError} onRetry={loadSchedule} />
    </div>
  )

  return (
    <div className="scr bg-teal">
      <Header title={schedule ? 'Редагувати розклад' : 'Налаштувати розклад'} subtitle={property.name} backLabel="Назад" />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        <div className="fg glass-s" style={{ margin: '0 12px 8px' }}>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconCalendar size={14} color="var(--t3)" />День місяця (1–28)</span>
            <input
              aria-label="День місяця"
              className="fr-i"
              type="text" inputMode="numeric" maxLength={2}
              value={dueDay} onChange={e => setDueDay(sanitizeInt(e.target.value))}
            />
          </div>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconBellRing size={14} color="var(--t3)" />Нагадати за, днів</span>
            <input
              aria-label="Нагадати за, днів"
              className="fr-i"
              type="text" inputMode="numeric" maxLength={2}
              value={notifyDays} onChange={e => { const v = sanitizeInt(e.target.value); setNotifyDays(v && parseInt(v, 10) > 14 ? '14' : v) }}
            />
          </div>
        </div>
        <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', padding: '0 16px 16px' }}>
          Ви отримаєте повідомлення через Telegram за {notifyDays || '3'} дн. до {dueDay || '5'}-го числа кожного місяця.
        </div>

        <button
          className={`mbtn success mbtn-flow ${saving ? 'disabled is-loading' : ''}`}
          onClick={handleSave}
          disabled={saving}
          aria-busy={saving}
        >
          Зберегти
        </button>
      </div>
    </div>
  )
}
