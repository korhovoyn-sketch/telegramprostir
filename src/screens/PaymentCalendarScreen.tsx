'use client'

import { useEffect, useState, useMemo, useCallback } from 'react'
import { useAppStore } from '@/store/appStore'
import RetryState from '@/components/ui/RetryState'
import { confirmAction } from '@/lib/confirm'
import { offlineGuard } from '@/lib/offline'
import { supabase } from '@/lib/supabase'
import { assertAffected } from '@/lib/dbWrite'
import Header from '@/components/ui/Header'
import { SkeletonList } from '@/components/ui/SkeletonLoader'
import { IconCalendar, IconClock, IconPlus, IconTrash, IconFile, IconCheckCircle, IconArchive, IconLayers, IconCheck, IconX, IconEdit } from '@/components/Icons'
import { formatPrice, humanizeDbError, objectsWord } from '@/lib/utils'
import { RENT_PAYMENT_COLUMNS, RENT_PAYMENT_RECORD_COLUMNS, expectedRent, fmtDueDate } from '@/lib/rentPayments'
import type { Property, RentPayment, RentPaymentRecord } from '@/types'

function dueDateStr(year: number, month: number, dueDay: number): string {
  return `${year}-${String(month + 1).padStart(2, '0')}-${String(dueDay).padStart(2, '0')}`
}

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
  monthOffset: number
}

type MonthCount = 1 | 2 | 3 | 6

export default function PaymentCalendarScreen() {
  const { screenParams, user, showToast, navigate } = useAppStore()
  const [properties, setProperties]   = useState<Property[]>([])
  const [schedules, setSchedules]     = useState<RentPayment[]>([])
  const [records, setRecords]         = useState<RentPaymentRecord[]>([])
  const [loading, setLoading]         = useState(true)
  const [loadError, setLoadError]     = useState<string | null>(null)

  const [monthsAhead, setMonthsAhead] = useState<MonthCount>(2)
  const [activeTab, setActiveTab]     = useState<'current' | 'archive'>('current')

  const [archiveRecords, setArchiveRecords] = useState<RentPaymentRecord[]>([])
  const [archiveLoading, setArchiveLoading] = useState(false)
  const [archiveLoaded, setArchiveLoaded]   = useState(false)

  const [showOnlyUnpaid, setShowOnlyUnpaid]     = useState(false)

  const propertyId = screenParams.propertyId as string | undefined
  const dbId       = screenParams.dbId       as string | undefined

  // ── Initial load ────────────────────────────────────────────────────────────
  const loadCurrent = useCallback(async () => {
    if (!user) return
    setLoading(true)
    setLoadError(null)
    try {
      let propsQuery = supabase
        .from('properties')
        .select('id, db_id, owner_id, name, floor, status, rent_type, rent_rate, utilities_rate, tenant_name, lease_start_date, lease_end_date, area_useful, area_total, area_basis, sort_order, has_parking, parking_spaces, created_at, updated_at')
        .eq('status', 'occupied')
      // Видимість обмежує RLS (власник / член команди / гість) — клієнтський
      // owner_id-фільтр ховав би бази команди від редактора.

      if (propertyId)      propsQuery = propsQuery.eq('id', propertyId)
      else if (dbId)       propsQuery = propsQuery.eq('db_id', dbId)
      else { setLoading(false); return }

      const { data: propsData, error: propsErr } = await propsQuery
      if (propsErr) throw propsErr
      const props = (propsData ?? []) as unknown as Property[]
      setProperties(props)
      if (props.length === 0) { setLoading(false); return }

      const ids = props.map(p => p.id)

      const { data: schedData, error: schedErr } = await supabase
        .from('rent_payments').select(RENT_PAYMENT_COLUMNS).in('property_id', ids).eq('is_active', true)
      if (schedErr) throw schedErr
      setSchedules((schedData ?? []) as RentPayment[])

      await loadRecordsForIds(ids, monthsAhead)
    } catch (e) {
      const msg = humanizeDbError(e)
      setLoadError(msg)
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    } finally {
      setLoading(false)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, propertyId, dbId, showToast])

  useEffect(() => {
    loadCurrent()
    setArchiveLoading(false)
    setArchiveLoaded(false)
    setArchiveRecords([])
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [propertyId, dbId, user?.id])

  async function loadRecordsForIds(ids: string[], ahead: number) {
    const start = new Date(); start.setDate(1)
    const end   = new Date(); end.setMonth(end.getMonth() + ahead); end.setDate(1)
    const { data } = await supabase
      .from('rent_payment_records').select(RENT_PAYMENT_RECORD_COLUMNS)
      .in('property_id', ids)
      .gte('due_date', start.toISOString().slice(0, 10))
      .lte('due_date', end.toISOString().slice(0, 10))
      .order('due_date', { ascending: false })
    setRecords((data ?? []) as RentPaymentRecord[])
  }

  // Reload records when horizon changes (properties already loaded)
  useEffect(() => {
    if (loading || properties.length === 0) return
    loadRecordsForIds(properties.map(p => p.id), monthsAhead)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [monthsAhead])

  // Load archive lazily on tab switch — all paid records regardless of month
  useEffect(() => {
    if (activeTab !== 'archive' || archiveLoaded || archiveLoading || properties.length === 0) return
    let cancelled = false
    const ids = properties.map(p => p.id)
    setArchiveLoading(true)
    supabase
      .from('rent_payment_records').select(RENT_PAYMENT_RECORD_COLUMNS)
      .in('property_id', ids)
      .eq('status', 'paid')
      .order('due_date', { ascending: false })
      .then(({ data }) => {
        if (cancelled) return
        setArchiveRecords((data ?? []) as RentPaymentRecord[])
        setArchiveLoaded(true)
        setArchiveLoading(false)
      }, () => {
        if (cancelled) return
        setArchiveLoading(false)
        showToast({ type: 'error', title: 'Не вдалося завантажити архів' })
      })
    return () => { cancelled = true }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, archiveLoaded, properties])

  // ── Computed ─────────────────────────────────────────────────────────────────
  const paymentItems = useMemo<PaymentItem[]>(() => {
    const today = new Date()
    const items: PaymentItem[] = []
    for (let m = 0; m < monthsAhead; m++) {
      const d = new Date(today.getFullYear(), today.getMonth() + m, 1)
      for (const prop of properties) {
        const sched = schedules.find(s => s.property_id === prop.id)
        if (!sched) continue
        const dueDate = dueDateStr(d.getFullYear(), d.getMonth(), sched.due_day)
        const record  = records.find(r => r.property_id === prop.id && r.due_date === dueDate) ?? null
        items.push({ property: prop, schedule: sched, dueDate, record, daysUntilDue: daysUntil(dueDate), monthOffset: m })
      }
    }
    return items
  }, [properties, schedules, records, monthsAhead])

  const monthSections = useMemo(() => {
    const today = new Date()
    return Array.from({ length: monthsAhead }, (_, i) => {
      const d = new Date(today.getFullYear(), today.getMonth() + i, 1)
      const allItems = paymentItems
        .filter(item => item.monthOffset === i)
        .sort((a, b) => {
          const aOk = a.record?.status === 'paid', bOk = b.record?.status === 'paid'
          if (aOk !== bOk) return aOk ? 1 : -1
          return a.daysUntilDue - b.daysUntilDue
        })
      const paidCount  = allItems.filter(it => it.record?.status === 'paid').length
      const totalCount = allItems.length
      const items = showOnlyUnpaid ? allItems.filter(it => it.record?.status !== 'paid') : allItems
      return { label: d.toLocaleDateString('uk-UA', { month: 'long', year: 'numeric' }), items, isFirst: i === 0, paidCount, totalCount }
    })
  }, [paymentItems, monthsAhead, showOnlyUnpaid])

  const propsWithoutSchedule = useMemo(
    () => properties.filter(p => !schedules.find(s => s.property_id === p.id)),
    [properties, schedules]
  )

  const stats = useMemo(() => {
    const cur = paymentItems.filter(i => i.monthOffset === 0)
    const paidItems = cur.filter(i => i.record?.status === 'paid')
    return {
      overdue:    cur.filter(i => i.daysUntilDue < 0  && i.record?.status !== 'paid').length,
      upcoming:   cur.filter(i => i.daysUntilDue >= 0 && i.record?.status !== 'paid').length,
      paid:       paidItems.length,
      paidAmount: paidItems.reduce((s, i) => s + (i.record?.amount ?? 0), 0),
    }
  }, [paymentItems])

  const archiveByMonth = useMemo(() => {
    const groups = new Map<string, { label: string; records: RentPaymentRecord[]; total: number }>()
    for (const rec of archiveRecords) {
      const [yr, mo] = rec.due_date.split('-').map(Number)
      const key = `${yr}-${mo}`
      if (!groups.has(key)) {
        const d = new Date(yr, mo - 1, 1)
        groups.set(key, { label: d.toLocaleDateString('uk-UA', { month: 'long', year: 'numeric' }), records: [], total: 0 })
      }
      const g = groups.get(key)!
      g.records.push(rec)
      g.total += rec.amount ?? 0
    }
    return Array.from(groups.values())
  }, [archiveRecords])

  const archiveTotal = useMemo(
    () => archiveRecords.reduce((s, r) => s + (r.amount ?? 0), 0),
    [archiveRecords]
  )

  // ── Handlers ─────────────────────────────────────────────────────────────────
  const handleDeleteSchedule = useCallback(async (prop: Property) => {
    const ok = await confirmAction({
      title: 'Видалити розклад?',
      message: `Розклад платежів для «${prop.name}» буде видалено.`,
      confirmLabel: 'Видалити',
      destructive: true,
    })
    if (!ok || offlineGuard()) return
    try {
      // Розклад — не похідні дані: відновити його можна лише руками, тож
      // «видалено» без доказу запису означало б втрату налаштування, про яку
      // власник дізнається наступного місяця.
      const { data, error } = await supabase
        .from('rent_payments').delete().eq('property_id', prop.id).select('id')
      if (error) throw error
      // ОЧІКУВАНЕ береться з ЗАПИТУ, а не з відповіді. `data?.length` тут
      // означало б `got !== got` — перевірка, що не може впасти НІКОЛИ. Один
      // рядок гарантує `UNIQUE(property_id)` у 021.
      assertAffected(data, 1, 'видалення розкладу')
      setSchedules(prev => prev.filter(s => s.property_id !== prop.id))
      showToast({ type: 'success', title: 'Розклад видалено' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    }
  }, [showToast])

  const handleUnpay = useCallback(async (rec: RentPaymentRecord, propName: string) => {
    const ok = await confirmAction({
      title: 'Скасувати платіж?',
      message: `${propName} · ${fmtDueDate(rec.due_date)}`,
      confirmLabel: 'Скасувати платіж',
      destructive: true,
    })
    if (!ok || offlineGuard()) return
    try {
      // ГРОШОВИЙ запис. Мовчазна відмова тут — це «платіж скасовано» на
      // екрані при живому записі в базі, тобто розходження звітності.
      const { data, error } = await supabase
        .from('rent_payment_records').delete().eq('id', rec.id).select('id')
      if (error) throw error
      assertAffected(data, 1, 'скасування платежу')
      setRecords(prev => prev.filter(r => r.id !== rec.id))
      if (archiveLoaded) setArchiveRecords(prev => prev.filter(r => r.id !== rec.id))
      showToast({ type: 'success', title: 'Платіж скасовано' })
    } catch (e) {
      showToast({ type: 'error', title: 'Помилка', subtitle: humanizeDbError(e) })
    }
  }, [archiveLoaded, showToast])

  // ── Helpers ──────────────────────────────────────────────────────────────────
  function getStatusColor(item: PaymentItem): string {
    if (item.record?.status === 'paid') return 'var(--ok)'
    if (item.daysUntilDue < 0)          return 'var(--err)'
    if (item.daysUntilDue <= 3)         return 'var(--warn)'
    return 'var(--t3)'
  }

  function getStatusLabel(item: PaymentItem): string {
    if (item.record?.status === 'paid') return 'Отримано'
    if (item.daysUntilDue < 0)  return `Прострочено ${Math.abs(item.daysUntilDue)}д`
    if (item.daysUntilDue === 0) return 'Сьогодні'
    if (item.daysUntilDue === 1) return 'Завтра'
    return `Через ${item.daysUntilDue} дн.`
  }

  const title = propertyId && properties[0] ? `Платежі — ${properties[0].name}` : 'Календар платежів'

  // ── Render ───────────────────────────────────────────────────────────────────
  return (
    <div className="scr bg-teal">
      <Header title={title} backLabel="Назад" />

      <div className="body">
        {/* Stats row */}
        <div className="stat-g" style={{ gridTemplateColumns: 'repeat(3,1fr)' }}>
          {/* cap3 на всіх трьох лейблах: «ПРОСТРОЧЕНО» на cap2 не влазить у
              третину 375px-екрана і обрізався б трикрапкою */}
          <div className="stat glass-s stat-pop-anim" style={{ animationDelay: '0s' }}>
            <div className="stat-n" style={{ color: 'var(--err)' }}>{stats.overdue}</div>
            <div className="stat-l" style={{ fontSize: 'var(--fs-cap3)' }}>Прострочено</div>
          </div>
          <div className="stat glass-s stat-pop-anim" style={{ animationDelay: '.06s' }}>
            <div className="stat-n" style={{ color: 'var(--warn)' }}>{stats.upcoming}</div>
            <div className="stat-l" style={{ fontSize: 'var(--fs-cap3)' }}>Очікується</div>
          </div>
          <div className="stat glass-s stat-pop-anim" style={{ animationDelay: '.12s' }}>
            <div className="stat-n" style={{ color: 'var(--ok)', fontSize: stats.paidAmount >= 100000 ? 'var(--fs-note)' : undefined }}>
              {stats.paidAmount > 0 ? formatPrice(stats.paidAmount, user?.currency) : stats.paid > 0 ? stats.paid : '—'}
            </div>
            <div className="stat-l" style={{ fontSize: 'var(--fs-cap3)' }}>Отримано</div>
          </div>
        </div>

        {/* Пʼятий інстанс сегментного перемикача, написаний тут інлайном: свій
            радіус (12/10 при падінгу 3 — не концентрика, а майже-концентрика),
            свій розмір шрифту, свій `transition:all`. Тепер це та сама родина
            `.seg`/`.seg-b`, що й фільтр обʼєктів — включно з концентричним
            радіусом і компактною висотою. */}
        <div className="seg">
          {(['current', 'archive'] as const).map(tab => (
            <button
              key={tab}
              type="button"
              className={`seg-b${activeTab === tab ? ' on' : ''}`}
              onClick={() => setActiveTab(tab)}
            >
              {tab === 'current'
                ? <><IconCalendar size={14} />Поточні</>
                : <><IconArchive size={14} />Архів</>}
            </button>
          ))}
        </div>

        {loading ? (
          <SkeletonList count={3} />
        ) : loadError && properties.length === 0 ? (
          <RetryState subtitle={loadError} onRetry={loadCurrent} />
        ) : properties.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">📅</div>
            <div className="empty-h">Немає орендованих обʼєктів</div>
            <div className="empty-s">Встановіть орендарів для відстеження платежів</div>
          </div>

        ) : activeTab === 'current' ? (
          <div key="current" className="tab-content-anim">
            {/* Horizon selector + filter toggle */}
            <div style={{ margin: '0 12px 8px', display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', flexShrink: 0 }}>Показати:</span>
              {([1, 2, 3, 6] as MonthCount[]).map(n => (
                <button
                  key={n}
                  onClick={() => setMonthsAhead(n)}
                  style={{
                    padding: '4px 10px', borderRadius: 8,
                    background: monthsAhead === n ? 'var(--info-bg)' : 'var(--glass-1)',
                    color:      monthsAhead === n ? 'var(--info)' : 'var(--t3)',
                    border:     monthsAhead === n ? '.5px solid rgba(122,179,255,.4)' : 'var(--bd)',
                    fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-semi)', cursor: 'pointer',
                  }}
                >
                  {n} міс
                </button>
              ))}
              <button
                onClick={() => setShowOnlyUnpaid(v => !v)}
                style={{
                  marginLeft: 'auto', padding: '4px 10px', borderRadius: 8,
                  background: showOnlyUnpaid ? 'var(--err-bg)' : 'var(--glass-1)',
                  color:      showOnlyUnpaid ? 'var(--err)'              : 'var(--t3)',
                  border:     showOnlyUnpaid ? '.5px solid rgba(255,107,97,.4)' : 'var(--bd)',
                  fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-semi)', cursor: 'pointer', whiteSpace: 'nowrap',
                }}
              >
                {showOnlyUnpaid
                  ? <><IconClock size={14} />Очікуються</>
                  : <><IconLayers size={14} />Всі</>}
              </button>
            </div>

            {/* Month sections */}
            {monthSections.map(section => (
              (section.items.length > 0 || section.totalCount > 0) && (
                <div key={section.label}>
                  <div className="over">
                    <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {section.isFirst
                        ? <IconCalendar size={14} color="var(--info)" />
                        : <IconClock size={14} color="var(--t3)" />
                      }
                      {section.label}
                    </span>
                    {section.totalCount > 0 && (
                      <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontSize: 'var(--fs-cap2)', color: section.paidCount === section.totalCount ? 'var(--ok)' : 'var(--t3)', fontWeight: 'var(--fw-semi)' }}>
                          {section.paidCount}/{section.totalCount}
                        </span>
                        <span style={{ display: 'flex', gap: 2 }}>
                          {Array.from({ length: section.totalCount }, (_, k) => (
                            <span key={k} style={{ width: 14, height: 4, borderRadius: 2, background: k < section.paidCount ? 'var(--ok)' : 'var(--glass-3)', transition: 'background .35s ease' }} />
                          ))}
                        </span>
                      </span>
                    )}
                  </div>
                  <div className="list" style={{ marginBottom: 12 }}>
                    {section.items.map(item => (
                      <PaymentItemCard
                        key={`${item.property.id}-${item.dueDate}`}
                        item={item}
                        statusColor={getStatusColor(item)}
                        label={getStatusLabel(item)}
                        onMarkPaid={() => navigate('payment-confirm', { propertyId: item.property.id, dbId: item.property.db_id, dueDate: item.dueDate })}
                        onEdit={() => navigate('payment-schedule', { propertyId: item.property.id, dbId: item.property.db_id })}
                        onDeleteSchedule={() => handleDeleteSchedule(item.property)}
                        onEditPaid={() => navigate('payment-confirm', { propertyId: item.property.id, dbId: item.property.db_id, dueDate: item.dueDate })}
                        onUnpay={() => item.record && handleUnpay(item.record, item.property.name)}
                        userCurrency={user?.currency}
                      />
                    ))}
                    {section.items.length === 0 && section.paidCount === section.totalCount && section.totalCount > 0 && (
                      <div style={{ padding: '12px 14px', textAlign: 'center', fontSize: 'var(--fs-foot)', color: 'var(--ok)', fontWeight: 'var(--fw-semi)' }}>
                        <IconCheck size={14} /> Всі платежі за цей місяць підтверджено
                      </div>
                    )}
                  </div>
                </div>
              )
            ))}

            {/* Обʼєкти БЕЗ розкладу — ПІСЛЯ календаря, і це не косметика.
                Екран називається «Календар платежів», тож першим має йти те, що
                в ньому вже є: найближчі платежі. Блок «немає розкладу» — це
                список СПРАВ, а не платежів; угорі він відсував календар за фолд
                і на пристрої читався як «платежів немає взагалі». */}
            {propsWithoutSchedule.length > 0 && (
              <>
                <div className="over">
                  <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconFile size={14} color="#fb923c" />Немає розкладу</span>
                  <span className="over-a">{propsWithoutSchedule.length} {objectsWord(propsWithoutSchedule.length)}</span>
                </div>
                <div className="list" style={{ marginBottom: 12 }}>
                  {propsWithoutSchedule.map(prop => (
                    <div key={prop.id} className="glass-s" style={{ borderRadius: 'var(--r-md)', padding: '12px 14px', display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 'var(--fs-note)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{prop.name}</div>
                        {prop.tenant_name && <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 2 }}>{prop.tenant_name}</div>}
                      </div>
                      <button
                        onClick={() => navigate('payment-schedule', { propertyId: prop.id, dbId: prop.db_id })}
                        style={{ flexShrink: 0, display: 'flex', alignItems: 'center', gap: 5, padding: '6px 12px', borderRadius: 'var(--r-pill)', background: 'var(--info-bg)', border: '.5px solid rgba(122,179,255,.32)', color: 'var(--info)', fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-semi)', cursor: 'pointer', whiteSpace: 'nowrap' }}
                      >
                        <IconPlus size={12} /> Налаштувати
                      </button>
                    </div>
                  ))}
                </div>
              </>
            )}

            {monthSections.every(s => s.items.length === 0 && s.totalCount === 0) && propsWithoutSchedule.length === 0 && (
              <div className="empty-state" style={{ paddingTop: 24 }}>
                <div className="empty-ic">📅</div>
                <div className="empty-h">Платежів немає</div>
                <div className="empty-s">Всі розклади налаштовано — тут зʼявляться майбутні платежі</div>
              </div>
            )}
          </div>

        ) : (
          /* ── Archive tab ── */
          <div key="archive" className="tab-content-anim">
            {archiveLoading ? (
              <SkeletonList count={3} />
            ) : archiveRecords.length === 0 ? (
              <div className="empty-state" style={{ paddingTop: 32 }}>
                <div className="empty-ic">🗂</div>
                <div className="empty-h">Архів порожній</div>
                <div className="empty-s">Підтверджені платежі зʼявляться тут</div>
              </div>
            ) : (
              <>
                {/* Archive total card */}
                {archiveTotal > 0 && (
                  <div style={{ margin: '0 12px 4px', padding: '14px 16px', borderRadius: 'var(--r-md)', background: 'var(--ok-bg)', border: '.5px solid var(--ok-bd)' }}>
                    <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginBottom: 4 }}>Всього отримано за весь час</div>
                    <div style={{ fontSize: 'var(--fs-t2)', fontWeight: 'var(--fw-bold)', color: 'var(--ok-fg)' }}>
                      {formatPrice(archiveTotal, user?.currency)}
                    </div>
                    <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 3 }}>
                      {archiveRecords.length} платежів · {archiveByMonth.length} міс.
                    </div>
                  </div>
                )}

                {/* Groups by month */}
                {archiveByMonth.map(group => (
                  <div key={group.label}>
                    <div className="over">
                      <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconCalendar size={14} color="var(--info)" />{group.label}</span>
                      {group.total > 0 && (
                        <span style={{ fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-bold)', color: 'var(--ok-fg)' }}>
                          {formatPrice(group.total, user?.currency)}
                        </span>
                      )}
                    </div>
                    <div className="list" style={{ marginBottom: 12 }}>
                      {group.records.map(rec => {
                        const prop = properties.find(p => p.id === rec.property_id)
                        return (
                          <div key={rec.id} className="glass-s" style={{ borderRadius: 'var(--r-md)', padding: '12px 14px' }}>
                            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                              <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--ok)', marginTop: 5, flexShrink: 0, boxShadow: '0 0 6px var(--ok)' }} />
                              <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ fontSize: 'var(--fs-note)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {prop?.name ?? '—'}
                                </div>
                                {prop?.tenant_name && (
                                  <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 1 }}>{prop.tenant_name}</div>
                                )}
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 5, flexWrap: 'wrap' }}>
                                  <span style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)' }}>за {fmtDueDate(rec.due_date)}</span>
                                  {rec.paid_at && (
                                    <span style={{ fontSize: 'var(--fs-cap2)', color: 'var(--t4)' }}>
                                      · отримано {new Date(rec.paid_at).toLocaleDateString('uk-UA', { day: 'numeric', month: 'short' })}
                                    </span>
                                  )}
                                </div>
                                {rec.notes && (
                                  <div style={{ fontSize: 'var(--fs-cap2)', color: 'var(--t3)', marginTop: 3, fontStyle: 'italic' }}>{rec.notes}</div>
                                )}
                              </div>
                              {rec.amount != null && rec.amount > 0 && (
                                <div style={{ flexShrink: 0, fontSize: 'var(--fs-sub)', fontWeight: 'var(--fw-bold)', color: 'var(--ok-fg)' }}>
                                  {formatPrice(rec.amount, user?.currency)}
                                </div>
                              )}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </>
            )}
          </div>
        )}

        <div style={{ height: 80 }} />
      </div>

    </div>
  )
}

// ── PaymentItemCard ───────────────────────────────────────────────────────────

interface PaymentItemCardProps {
  item: PaymentItem
  statusColor: string
  label: string
  onMarkPaid: () => void
  onEdit: () => void
  onDeleteSchedule: () => void
  onEditPaid?: () => void
  onUnpay?: () => void
  userCurrency?: string
}

function PaymentItemCard({ item, statusColor, label, onMarkPaid, onEdit, onDeleteSchedule, onEditPaid, onUnpay, userCurrency }: PaymentItemCardProps) {
  const isPaid     = item.record?.status === 'paid'
  // rent_rate — сира ставка ($/м² чи $/добу для per_m2/per_day), не сума до
  // сплати. expectedRent() нормалізує до місяця — той самий шлях, що вже дає
  // дефолт у модалці підтвердження платежу (рядок вище, expectedRent виклик).
  // Без цього картка «Офіс, $18» показувала ставку замість реальних $1 800.
  const displayAmt = isPaid ? (item.record?.amount ?? null) : (expectedRent(item.property) || null)

  return (
    <div className="glass-s" style={{ borderRadius: 'var(--r-md)', overflow: 'hidden' }}>
      <div style={{ padding: '12px 14px', display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: statusColor, marginTop: 5, flexShrink: 0, boxShadow: `0 0 6px ${statusColor}` }} />

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 'var(--fs-note)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {item.property.name}
          </div>
          {item.property.tenant_name && (
            <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 1 }}>{item.property.tenant_name}</div>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 5, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-semi)', color: statusColor }}>{label}</span>
            <span style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)' }}>{fmtDueDate(item.dueDate)}</span>
            {displayAmt != null && displayAmt > 0 && (
              <span style={{ fontSize: 'var(--fs-cap1)', fontWeight: isPaid ? 700 : 400, color: isPaid ? 'var(--ok-fg)' : 'var(--t2)' }}>
                {formatPrice(displayAmt, userCurrency)}
              </span>
            )}
          </div>
          {isPaid && item.record?.notes && (
            <div style={{ fontSize: 'var(--fs-cap2)', color: 'var(--t3)', marginTop: 3, fontStyle: 'italic' }}>{item.record.notes}</div>
          )}
        </div>

        {!isPaid ? (
          <button
            onClick={onMarkPaid}
            style={{ flexShrink: 0, display: 'flex', alignItems: 'center', gap: 5, padding: '6px 12px', borderRadius: 'var(--r-pill)', background: 'var(--ok-bg)', border: '.5px solid var(--ok-bd)', color: 'var(--ok-fg)', fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-semi)', cursor: 'pointer', whiteSpace: 'nowrap' }}
          >
            <IconCheckCircle size={12} /> Отримано
          </button>
        ) : (
          <div style={{ flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4 }}>
            <button
              onClick={onEditPaid}
              style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 10px', borderRadius: 'var(--r-pill)', background: 'var(--ok-bg)', border: '.5px solid var(--ok-bd)', color: 'var(--ok-fg)', fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-semi)', cursor: 'pointer', whiteSpace: 'nowrap' }}
            >
              <IconCheck size={14} /> Сплачено
            </button>
            <button
              onClick={onUnpay}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 26, height: 26, borderRadius: '50%', background: 'var(--err-bg)', border: '.5px solid rgba(255,59,48,.25)', color: 'var(--err)', fontSize: 'var(--fs-note)', cursor: 'pointer', flexShrink: 0 }}
              title="Скасувати платіж"
            >
              <IconX size={14} />
            </button>
          </div>
        )}
      </div>

      {/* Bottom action row */}
      <div style={{ padding: '6px 14px 10px', display: 'flex', gap: 8, borderTop: '.5px solid rgba(255,255,255,.06)' }}>
        <button
          onClick={onEdit}
          style={{ fontSize: 'var(--fs-cap2)', color: 'var(--t3)', background: 'none', border: 'none', cursor: 'pointer', padding: '2px 0' }}
        >
          <IconEdit size={14} /> Редагувати розклад
        </button>
        <button
          onClick={onDeleteSchedule}
          style={{ fontSize: 'var(--fs-cap2)', color: 'var(--err)', background: 'none', border: 'none', cursor: 'pointer', padding: '2px 0', marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4 }}
        >
          <IconTrash size={12} /> Видалити
        </button>
      </div>
    </div>
  )
}
