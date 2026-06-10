'use client'

import { useEffect, useState, useMemo, useCallback } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import Header from '@/components/ui/Header'
import Modal from '@/components/ui/Modal'
import { IconCalendar, IconBellRing, IconCheckCircle, IconClock, IconPlus, IconTrash } from '@/components/Icons'
import { formatPrice } from '@/lib/utils'
import type { Property, RentPayment, RentPaymentRecord } from '@/types'

// Format date as "5 червня"
function fmtDueDate(dateStr: string): string {
  const d = new Date(dateStr + 'T00:00:00')
  return d.toLocaleDateString('uk-UA', { day: 'numeric', month: 'long' })
}

// Compute due date string (YYYY-MM-DD) for a given due_day in year/month.
// Must NOT use Date.toISOString() — it converts local midnight to UTC which
// shifts the date by -1 in timezones east of UTC (e.g. Ukraine UTC+3).
function dueDateStr(year: number, month: number, dueDay: number): string {
  return `${year}-${String(month + 1).padStart(2, '0')}-${String(dueDay).padStart(2, '0')}`
}

// Days until a date (negative = overdue)
function daysUntil(dateStr: string): number {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const due = new Date(dateStr + 'T00:00:00')
  return Math.round((due.getTime() - today.getTime()) / 86400000)
}

interface PaymentItem {
  property: Property
  schedule: RentPayment
  dueDate: string
  record: RentPaymentRecord | null
  daysUntilDue: number
  isCurrentMonth: boolean
}

export default function PaymentCalendarScreen() {
  const { screenParams, user, showToast } = useAppStore()
  const [properties, setProperties] = useState<Property[]>([])
  const [schedules, setSchedules] = useState<RentPayment[]>([])
  const [records, setRecords] = useState<RentPaymentRecord[]>([])
  const [loading, setLoading] = useState(true)
  // Setup modal state
  const [setupProp, setSetupProp] = useState<Property | null>(null)
  const [setupDueDay, setSetupDueDay] = useState('5')
  const [setupNotify, setSetupNotify] = useState('3')
  const [setupSaving, setSetupSaving] = useState(false)
  // Delete schedule modal
  const [deleteScheduleProp, setDeleteScheduleProp] = useState<Property | null>(null)

  const propertyId = screenParams.propertyId as string | undefined
  const dbId = screenParams.dbId as string | undefined

  useEffect(() => {
    async function load() {
      if (!user) return
      setLoading(true)
      try {
        // Load occupied properties
        let propsQuery = supabase
          .from('properties')
          .select('id, db_id, owner_id, name, floor, status, rent_type, rent_rate, utilities_rate, tenant_name, lease_start_date, lease_end_date, area_useful, area_total, sort_order, has_parking, parking_spaces, created_at, updated_at')
          .eq('status', 'occupied')
          .eq('owner_id', user.id)

        if (propertyId) {
          propsQuery = propsQuery.eq('id', propertyId)
        } else if (dbId) {
          propsQuery = propsQuery.eq('db_id', dbId)
        } else {
          setLoading(false)
          return
        }

        const { data: propsData } = await propsQuery
        const props = (propsData ?? []) as unknown as Property[]
        setProperties(props)

        if (props.length === 0) { setLoading(false); return }

        const ids = props.map(p => p.id)

        // Load schedules
        const { data: schedData } = await supabase
          .from('rent_payments')
          .select('*')
          .in('property_id', ids)
          .eq('is_active', true)
        setSchedules((schedData ?? []) as RentPayment[])

        // Load records for ±2 months window
        const start = new Date()
        start.setMonth(start.getMonth() - 1)
        start.setDate(1)
        const end = new Date()
        end.setMonth(end.getMonth() + 2)
        end.setDate(1)
        const { data: recsData } = await supabase
          .from('rent_payment_records')
          .select('*')
          .in('property_id', ids)
          .gte('due_date', start.toISOString().slice(0, 10))
          .lte('due_date', end.toISOString().slice(0, 10))
          .order('due_date', { ascending: false })
        setRecords((recsData ?? []) as RentPaymentRecord[])
      } catch (e) {
        showToast({ type: 'error', title: 'Помилка завантаження', subtitle: (e as Error).message })
      } finally {
        setLoading(false)
      }
    }
    load()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [propertyId, dbId, user?.id])

  // Compute payment items for current month + next month
  const paymentItems = useMemo<PaymentItem[]>(() => {
    const today = new Date()
    const thisYear = today.getFullYear()
    const thisMonth = today.getMonth()
    const nextYear = thisMonth === 11 ? thisYear + 1 : thisYear
    const nextMonth = (thisMonth + 1) % 12

    const items: PaymentItem[] = []

    for (const prop of properties) {
      const sched = schedules.find(s => s.property_id === prop.id)
      if (!sched) continue

      // Current month
      const currentDue = dueDateStr(thisYear, thisMonth, sched.due_day)
      const currentRec = records.find(r => r.property_id === prop.id && r.due_date === currentDue) ?? null
      items.push({
        property: prop,
        schedule: sched,
        dueDate: currentDue,
        record: currentRec,
        daysUntilDue: daysUntil(currentDue),
        isCurrentMonth: true,
      })

      // Next month
      const nextDue = dueDateStr(nextYear, nextMonth, sched.due_day)
      const nextRec = records.find(r => r.property_id === prop.id && r.due_date === nextDue) ?? null
      items.push({
        property: prop,
        schedule: sched,
        dueDate: nextDue,
        record: nextRec,
        daysUntilDue: daysUntil(nextDue),
        isCurrentMonth: false,
      })
    }

    // Sort: overdue first, then by due date
    return items.sort((a, b) => {
      const aOk = a.record?.status === 'paid'
      const bOk = b.record?.status === 'paid'
      if (aOk !== bOk) return aOk ? 1 : -1
      return a.daysUntilDue - b.daysUntilDue
    })
  }, [properties, schedules, records])

  const propsWithoutSchedule = useMemo(
    () => properties.filter(p => !schedules.find(s => s.property_id === p.id)),
    [properties, schedules]
  )

  const stats = useMemo(() => {
    const thisMonth = paymentItems.filter(i => i.isCurrentMonth)
    const overdue = thisMonth.filter(i => i.daysUntilDue < 0 && i.record?.status !== 'paid').length
    const paid = thisMonth.filter(i => i.record?.status === 'paid').length
    const upcoming = thisMonth.filter(i => i.daysUntilDue >= 0 && i.record?.status !== 'paid').length
    return { overdue, paid, upcoming }
  }, [paymentItems])

  const handleMarkPaid = useCallback(async (item: PaymentItem) => {
    if (!user) return
    window.Telegram?.WebApp?.HapticFeedback?.impactOccurred('light')
    try {
      const { data, error } = await supabase
        .from('rent_payment_records')
        .upsert(
          {
            property_id: item.property.id,
            owner_id: user.id,
            due_date: item.dueDate,
            paid_at: new Date().toISOString(),
            amount: item.property.rent_rate,
            status: 'paid' as const,
            updated_at: new Date().toISOString(),
          },
          { onConflict: 'property_id,due_date' }
        )
        .select('*')
        .single()
      if (error) throw error
      window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
      setRecords(prev => {
        const idx = prev.findIndex(r => r.property_id === item.property.id && r.due_date === item.dueDate)
        if (idx >= 0) return prev.map((r, i) => i === idx ? (data as RentPaymentRecord) : r)
        return [data as RentPaymentRecord, ...prev]
      })
      showToast({ type: 'success', title: 'Платіж відмічено ✓' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    }
  }, [user, showToast])

  const handleSaveSchedule = useCallback(async () => {
    if (!setupProp || !user) return
    const day = parseInt(setupDueDay, 10)
    const notify = parseInt(setupNotify, 10)
    if (!isFinite(day) || day < 1 || day > 28) {
      showToast({ type: 'error', title: 'День платежу має бути від 1 до 28' })
      return
    }
    setSetupSaving(true)
    try {
      const { data, error } = await supabase
        .from('rent_payments')
        .upsert(
          {
            property_id: setupProp.id,
            owner_id: user.id,
            due_day: day,
            notify_days_before: isFinite(notify) ? Math.min(14, Math.max(0, notify)) : 3,
            is_active: true,
            updated_at: new Date().toISOString(),
          },
          { onConflict: 'property_id' }
        )
        .select('*')
        .single()
      if (error) throw error
      setSchedules(prev => {
        const idx = prev.findIndex(s => s.property_id === setupProp.id)
        if (idx >= 0) return prev.map((s, i) => i === idx ? (data as RentPayment) : s)
        return [...prev, data as RentPayment]
      })
      showToast({ type: 'success', title: 'Розклад збережено' })
      setSetupProp(null)
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка збереження', subtitle: (e as Error).message })
    } finally {
      setSetupSaving(false)
    }
  }, [setupProp, user, setupDueDay, setupNotify, showToast])

  const handleDeleteSchedule = useCallback(async () => {
    if (!deleteScheduleProp) return
    try {
      await supabase.from('rent_payments').delete().eq('property_id', deleteScheduleProp.id)
      setSchedules(prev => prev.filter(s => s.property_id !== deleteScheduleProp.id))
      showToast({ type: 'success', title: 'Розклад видалено' })
      setDeleteScheduleProp(null)
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: (e as Error).message })
    }
  }, [deleteScheduleProp, showToast])

  const title = propertyId && properties[0] ? `Платежі — ${properties[0].name}` : 'Календар платежів'

  function getItemStatusColor(item: PaymentItem): string {
    if (item.record?.status === 'paid') return 'var(--ok)'
    if (item.daysUntilDue < 0) return 'var(--err)'
    if (item.daysUntilDue <= 3) return 'var(--warn)'
    return 'var(--t3)'
  }

  function getItemLabel(item: PaymentItem): string {
    if (item.record?.status === 'paid') return 'Отримано'
    if (item.daysUntilDue < 0) return `Прострочено ${Math.abs(item.daysUntilDue)}д`
    if (item.daysUntilDue === 0) return 'Сьогодні'
    if (item.daysUntilDue === 1) return 'Завтра'
    return `Через ${item.daysUntilDue} дн.`
  }

  const currentItems = paymentItems.filter(i => i.isCurrentMonth)
  const nextItems = paymentItems.filter(i => !i.isCurrentMonth)
  const now = new Date()

  return (
    <div className="scr bg-teal">
      <Header title={title} backLabel="Назад" />

      <div className="body">
        {/* Stats */}
        <div className="stat-g" style={{ gridTemplateColumns: 'repeat(3,1fr)' }}>
          <div className="stat glass-s">
            <div className="stat-n" style={{ color: 'var(--err)' }}>{stats.overdue}</div>
            <div className="stat-l">Прострочено</div>
          </div>
          <div className="stat glass-s">
            <div className="stat-n" style={{ color: 'var(--warn)' }}>{stats.upcoming}</div>
            <div className="stat-l">Очікується</div>
          </div>
          <div className="stat glass-s">
            <div className="stat-n" style={{ color: 'var(--ok)' }}>{stats.paid}</div>
            <div className="stat-l">Отримано</div>
          </div>
        </div>

        {loading ? (
          <div className="loader-wrap" style={{ paddingTop: 40 }}>
            <div className="loader" />
          </div>
        ) : properties.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">📅</div>
            <div className="empty-h">Немає орендованих об&apos;єктів</div>
            <div className="empty-s">Встановіть орендарів для відстеження платежів</div>
          </div>
        ) : (
          <>
            {/* Properties without schedule — prompt to set up */}
            {propsWithoutSchedule.length > 0 && (
              <>
                <div className="over">
                  <span>Немає розкладу</span>
                  <span className="over-a">{propsWithoutSchedule.length} об&apos;єктів</span>
                </div>
                <div className="list" style={{ marginBottom: 12 }}>
                  {propsWithoutSchedule.map(prop => (
                    <div key={prop.id} className="glass-s" style={{ borderRadius: 'var(--r-md)', padding: '12px 14px', display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{prop.name}</div>
                        {prop.tenant_name && <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 2 }}>{prop.tenant_name}</div>}
                      </div>
                      <button
                        onClick={() => { setSetupProp(prop); setSetupDueDay('5'); setSetupNotify('3') }}
                        style={{ flexShrink: 0, display: 'flex', alignItems: 'center', gap: 5, padding: '6px 12px', borderRadius: 'var(--r-pill)', background: 'rgba(122,179,255,.18)', border: '.5px solid rgba(122,179,255,.32)', color: '#7AB3FF', fontSize: 12, fontWeight: 600, cursor: 'pointer', whiteSpace: 'nowrap' }}
                      >
                        <IconPlus size={12} /> Налаштувати
                      </button>
                    </div>
                  ))}
                </div>
              </>
            )}

            {/* Current month */}
            {currentItems.length > 0 && (
              <>
                <div className="over">
                  <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <IconCalendar size={13} color="#7AB3FF" />
                    {now.toLocaleDateString('uk-UA', { month: 'long', year: 'numeric' })}
                  </span>
                </div>
                <div className="list" style={{ marginBottom: 12 }}>
                  {currentItems.map(item => (
                    <PaymentItemCard
                      key={`${item.property.id}-${item.dueDate}`}
                      item={item}
                      statusColor={getItemStatusColor(item)}
                      label={getItemLabel(item)}
                      onMarkPaid={() => handleMarkPaid(item)}
                      onEdit={() => { setSetupProp(item.property); const s = schedules.find(s => s.property_id === item.property.id); setSetupDueDay(String(s?.due_day ?? 5)); setSetupNotify(String(s?.notify_days_before ?? 3)) }}
                      onDeleteSchedule={() => setDeleteScheduleProp(item.property)}
                      userCurrency={user?.currency}
                    />
                  ))}
                </div>
              </>
            )}

            {/* Next month */}
            {nextItems.length > 0 && (
              <>
                <div className="over">
                  <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <IconClock size={13} color="var(--t3)" />
                    {new Date(now.getFullYear(), now.getMonth() + 1, 1).toLocaleDateString('uk-UA', { month: 'long', year: 'numeric' })}
                  </span>
                </div>
                <div className="list" style={{ marginBottom: 12 }}>
                  {nextItems.map(item => (
                    <PaymentItemCard
                      key={`${item.property.id}-${item.dueDate}`}
                      item={item}
                      statusColor={getItemStatusColor(item)}
                      label={getItemLabel(item)}
                      onMarkPaid={() => handleMarkPaid(item)}
                      onEdit={() => { setSetupProp(item.property); const s = schedules.find(s => s.property_id === item.property.id); setSetupDueDay(String(s?.due_day ?? 5)); setSetupNotify(String(s?.notify_days_before ?? 3)) }}
                      onDeleteSchedule={() => setDeleteScheduleProp(item.property)}
                      userCurrency={user?.currency}
                    />
                  ))}
                </div>
              </>
            )}
          </>
        )}

        <div style={{ height: 80 }} />
      </div>

      {/* Setup schedule modal */}
      {setupProp && (
        <Modal
          title="Розклад платежів"
          subtitle={setupProp.name}
          onClose={() => !setupSaving && setSetupProp(null)}
          actions={[
            { label: setupSaving ? 'Збереження...' : 'Зберегти', variant: 'primary', disabled: setupSaving, onClick: handleSaveSchedule },
            { label: 'Скасувати', variant: 'secondary', disabled: setupSaving, onClick: () => setSetupProp(null) },
          ]}
        >
          <div style={{ paddingTop: 4 }}>
            <div className="fld-row">
              <div className="fld">
                <div className="fld-l"><IconCalendar size={11} />День місяця (1–28)</div>
                <input
                  type="number" min={1} max={28} inputMode="numeric"
                  value={setupDueDay}
                  onChange={e => setSetupDueDay(e.target.value)}
                />
              </div>
              <div className="fld">
                <div className="fld-l"><IconBellRing size={11} />Нагадати за, днів</div>
                <input
                  type="number" min={0} max={14} inputMode="numeric"
                  value={setupNotify}
                  onChange={e => setSetupNotify(e.target.value)}
                />
              </div>
            </div>
            <div style={{ fontSize: 12, color: 'var(--t3)', padding: '0 4px' }}>
              Ви отримаєте повідомлення через Telegram за {setupNotify || '3'} дн. до {setupDueDay || '5'}-го числа кожного місяця.
            </div>
          </div>
        </Modal>
      )}

      {/* Delete schedule confirm */}
      {deleteScheduleProp && (
        <Modal
          title="Видалити розклад?"
          subtitle={`Розклад платежів для "${deleteScheduleProp.name}" буде видалено.`}
          onClose={() => setDeleteScheduleProp(null)}
          actions={[
            { label: 'Видалити', variant: 'danger', onClick: handleDeleteSchedule },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setDeleteScheduleProp(null) },
          ]}
        />
      )}
    </div>
  )
}

interface PaymentItemCardProps {
  item: PaymentItem
  statusColor: string
  label: string
  onMarkPaid: () => void
  onEdit: () => void
  onDeleteSchedule: () => void
  userCurrency?: string
}

function PaymentItemCard({ item, statusColor, label, onMarkPaid, onEdit, onDeleteSchedule, userCurrency }: PaymentItemCardProps) {
  const isPaid = item.record?.status === 'paid'
  const rent = item.property.rent_rate ?? 0

  return (
    <div className="glass-s" style={{ borderRadius: 'var(--r-md)', overflow: 'hidden' }}>
      <div style={{ padding: '12px 14px', display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        {/* Left: status dot */}
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: statusColor, marginTop: 5, flexShrink: 0, boxShadow: `0 0 6px ${statusColor}` }} />

        {/* Middle: info */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {item.property.name}
          </div>
          {item.property.tenant_name && (
            <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 1 }}>{item.property.tenant_name}</div>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 5, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: statusColor }}>{label}</span>
            <span style={{ fontSize: 12, color: 'var(--t3)' }}>{fmtDueDate(item.dueDate)}</span>
            {rent > 0 && <span style={{ fontSize: 12, color: 'var(--t2)' }}>{formatPrice(rent, userCurrency)}</span>}
          </div>
        </div>

        {/* Right: action */}
        {!isPaid ? (
          <button
            onClick={onMarkPaid}
            style={{ flexShrink: 0, display: 'flex', alignItems: 'center', gap: 5, padding: '6px 12px', borderRadius: 'var(--r-pill)', background: 'rgba(52,199,89,.18)', border: '.5px solid rgba(52,199,89,.32)', color: '#34c759', fontSize: 12, fontWeight: 600, cursor: 'pointer', whiteSpace: 'nowrap' }}
          >
            <IconCheckCircle size={12} /> Отримано
          </button>
        ) : (
          <div style={{ flexShrink: 0, display: 'flex', alignItems: 'center', gap: 5, padding: '6px 12px', borderRadius: 'var(--r-pill)', background: 'rgba(52,199,89,.1)', border: '.5px solid rgba(52,199,89,.2)', color: '#34c759', fontSize: 12, fontWeight: 600 }}>
            ✓ Сплачено
          </div>
        )}
      </div>

      {/* Bottom actions row */}
      <div style={{ padding: '6px 14px 10px', display: 'flex', gap: 8, borderTop: '.5px solid rgba(255,255,255,.06)' }}>
        <button onClick={onEdit} style={{ fontSize: 11, color: 'var(--t3)', background: 'none', border: 'none', cursor: 'pointer', padding: '2px 0' }}>
          ✏️ Змінити день
        </button>
        <button onClick={onDeleteSchedule} style={{ fontSize: 11, color: 'var(--err)', background: 'none', border: 'none', cursor: 'pointer', padding: '2px 0', marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4 }}>
          <IconTrash size={11} /> Видалити розклад
        </button>
      </div>
    </div>
  )
}
