'use client'

import { useEffect, useState, useCallback } from 'react'
import { z } from 'zod'
import { useAppSlice } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import RetryState from '@/components/ui/RetryState'
import { IconCheckCircle, IconEdit, IconPlus, IconTrash, IconUser } from '@/components/Icons'
import { offlineGuard } from '@/lib/offline'
import { confirmAction } from '@/lib/confirm'
import { assertAffected } from '@/lib/dbWrite'
import { supabase } from '@/lib/supabase'
import { withOptionalColumns } from '@/lib/optionalColumns'
import { sanitizeDecimal, scrollFocusedIntoView, humanizeDbError, currencySymbol, formatPrice, localDay } from '@/lib/utils'
import {
  RENT_PAYMENT_RECORD_COLUMNS, RENT_PAYMENT_RECORD_COLUMNS_PRE, RENT_PAYMENT_PART_COLUMNS, RENT_PAYMENT_PART_COLUMNS_PRE, RENT_TERMS_COLUMNS,
  expectedRentAt, fmtDueDate, isPartsUnavailable, remainingFor, type RentTermsRow,
} from '@/lib/rentPayments'
import type { RentPaymentPart, RentPaymentRecord } from '@/types'
import { locale, tr } from '@/lib/i18n'
import { useClosingConfirmation } from '@/hooks/useTelegram'

// Відповідь `record_rent_payment` (071). Валідуємо, а не довіряємо: від неї
// залежить, ЯКИЙ тост бачить власник — «частково» чи «підтверджено».
const RecordResult = z.object({
  record_id: z.string().uuid().nullable().optional(),
  status: z.string().nullable().optional(),
  error: z.string().nullable().optional(),
})

function rpcErrorText(code: string): string {
  switch (code) {
    case 'invalid_amount': return tr('Некоректна сума')
    case 'invalid_date': return tr('Дата отримання не може бути в майбутньому')
    case 'not_found': return tr('Обʼєкт не знайдено')
    default: return tr('Платіж не зберігся')
  }
}

/**
 * Повноекранна форма підтвердження платежу — заміна колишньої `<Modal>` у
 * PaymentCalendarScreen (фаза 2 переробки модалок, atomic-riding-clock.md).
 * Оптимістичний апдейт+rollback старого `handleMarkPaid` тут НЕ потрібен:
 * PaymentCalendarScreen цілком перемонтовується на `back()` і сам перечитує
 * свіжий стан із сервера — миттєвий фідбек тепер дає сам перехід екрана.
 *
 * ДВА РЕЖИМИ, і вибирає їх БЕКЕНД, а не екран:
 *   • з 071 — період складається з НАДХОДЖЕНЬ: можна записати частину суми,
 *     доплатити пізніше, виправити чи видалити окреме надходження; підсумок
 *     (сума, статус «частково/оплачено») рахує сервер;
 *   • без 071 (`rent_payment_parts` не існує) — як доти: один запис на період,
 *     лише повна оплата. Фронт деплоїться раніше за міграцію, тож цей шлях
 *     мусить лишатись робочим, а не «майже».
 */
export default function PaymentConfirmScreen() {
  useClosingConfirmation()
  const { screenParams, user, showToast, back, navigate } = useAppSlice('screenParams', 'user', 'showToast', 'back', 'navigate')
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
  // `null` — таблиці надходжень немає (071 не накочена), тобто старий режим.
  const [parts, setParts] = useState<RentPaymentPart[] | null>(null)
  // Історія умов (072). `null` — її немає: очікувана сума з поточних умов,
  // і змінити суму періоду ніде (RPC теж із 072).
  const [terms, setTerms] = useState<RentTermsRow[] | null>(null)
  const [recordLoading, setRecordLoading] = useState(true)
  const [recordError, setRecordError] = useState<string | null>(null)
  // Надходження, яке зараз виправляють. `null` — форма додає НОВЕ.
  const [editingId, setEditingId] = useState<string | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [amount, setAmount] = useState('')
  const [notes, setNotes] = useState('')
  // Дата ОТРИМАННЯ — окремий факт від дати платежу за розкладом, і від миті
  // натискання теж: гроші приходять готівкою чи переказом раніше, ніж власник
  // доходить до застосунку. Доти `paid_at` ставився «зараз» ЗАВЖДИ, тож і
  // нове підтвердження фіксувало день запису, а не день грошей, і —
  // гірше — виправлення суми в березневому платежі переписувало його дату
  // отримання на сьогодні.
  const today = localDay(new Date().toISOString())
  const [paidDay, setPaidDay] = useState(today)
  const [saving, setSaving] = useState(false)

  const loadRecord = useCallback(async () => {
    if (!propertyId || !dueDate) return
    setRecordLoading(true)
    setRecordError(null)
    try {
      // Паралельно і без throw: збій історії не забирає форму, лише лишає
      // очікувану суму на поточних умовах (як до 072).
      const termsP = supabase.from('property_rent_terms').select(RENT_TERMS_COLUMNS)
        .eq('property_id', propertyId)
        .then(({ data, error }) => (error ? null : (data ?? []) as RentTermsRow[]), () => null)
      const { data, error } = await withOptionalColumns((pre) => supabase
        .from('rent_payment_records').select(pre ? RENT_PAYMENT_RECORD_COLUMNS_PRE : RENT_PAYMENT_RECORD_COLUMNS)
        .eq('property_id', propertyId).eq('due_date', dueDate).maybeSingle())
      if (error) throw error
      const rec = data as RentPaymentRecord | null

      // Надходження — і заразом перевірка, чи є 071 узагалі. Без періоду
      // питаємо порожньо (`limit(1)`): відповідь потрібна лише як «таблиця є».
      const res = rec
        ? await withOptionalColumns((pre) => supabase.from('rent_payment_parts')
            .select(pre ? RENT_PAYMENT_PART_COLUMNS_PRE : RENT_PAYMENT_PART_COLUMNS)
            .eq('record_id', rec.id)
            .order('paid_at', { ascending: true }).order('id', { ascending: true }))
        : await supabase.from('rent_payment_parts').select('id').limit(1)
      let list: RentPaymentPart[] | null
      if (res.error) {
        if (!isPartsUnavailable(res.error)) throw res.error
        list = null
      } else {
        list = rec ? (res.data ?? []) as RentPaymentPart[] : []
      }
      setRecord(rec)
      setParts(list)
      setTerms(await termsP)
    } catch (e) {
      setRecordError(humanizeDbError(e))
    } finally {
      setRecordLoading(false)
    }
  }, [propertyId, dueDate])

  useEffect(() => { loadRecord() }, [loadRecord])

  const legacy = parts === null
  // За умовами, що діяли на дату ЦЬОГО платежу (072): серпневий борг —
  // за серпневою ставкою, навіть якщо в жовтні оренду підняли. Саме ця сума
  // заморожується в періоді при першому надходженні.
  const expected = property && dueDate ? expectedRentAt(property, terms, dueDate) : 0
  const received = record?.amount ?? 0
  // Скільки ще чекаємо — від ЗАМОРОЖЕНОЇ суми періоду, не від поточної ставки.
  const remaining = remainingFor(record, expected)
  const due = record?.amount_due ?? (expected > 0 ? expected : null)
  const editingPart = parts?.find(p => p.id === editingId) ?? null

  function fillForAdd() {
    setEditingId(null)
    setAmount(remaining > 0 ? String(remaining) : '')
    setNotes('')
    setPaidDay(today)
  }

  function fillForEdit(p: RentPaymentPart) {
    setEditingId(p.id)
    setAmount(String(p.amount))
    setNotes(p.notes ?? '')
    setPaidDay(localDay(p.paid_at))
  }

  // Префіл. Повністю оплачений період відкривається на ОСТАННЬОМУ надходженні
  // — так само, як доти «Редагувати платіж» відкривав єдиний запис; решта
  // (нічого не отримано, частково) — на новому надходженні із залишком.
  useEffect(() => {
    if (recordLoading || !property) return
    if (legacy) {
      if (record?.status === 'paid') {
        setAmount(String(record.amount ?? ''))
        setNotes(record.notes ?? '')
        setPaidDay(record.paid_at ? localDay(record.paid_at) : today)
      } else {
        setAmount(expected > 0 ? String(expected) : '')
        setNotes('')
        setPaidDay(today)
      }
      return
    }
    const last = parts && parts.length > 0 ? parts[parts.length - 1] : null
    if (record?.status === 'paid' && last) fillForEdit(last)
    else fillForAdd()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [record, parts, recordLoading, property, today])

  // Порожня сума — НЕ «візьми очікувану». Доти порожнє поле мовчки зберігало
  // очікувану суму (а без ставки — NULL), тобто «Отримано» без грошей: запис
  // в архіві є, а в «Всього отримано» його немає. Сума — сама суть запису.
  const entered = parseFloat(amount)
  const amountInvalid = !(isFinite(entered) && entered > 0)
  // Майбутня дата отримання — описка, а не факт.
  const dayInvalid = !/^\d{4}-\d{2}-\d{2}$/.test(paidDay) || paidDay > today

  // Мітка часу з обраного ЛОКАЛЬНОГО дня. Незмінений день лишає наявну мітку
  // точно; сьогодні — це «зараз»; інший день — полудень, щоб ±11 год поясу не
  // зсунули його на сусідню дату при показі.
  function paidAtFor(keep: string | null | undefined): string {
    const now = new Date().toISOString()
    if (keep && localDay(keep) === paidDay) return keep
    if (paidDay === today) return now
    const [y, m, d] = paidDay.split('-').map(Number)
    return new Date(y, m - 1, d, 12).toISOString()
  }

  async function handleConfirm() {
    if (!property || !user || !dueDate) return
    if (offlineGuard()) return
    if (amountInvalid || dayInvalid) return
    const trimmedNotes = notes.trim() || null
    setSaving(true)
    try {
      if (legacy) {
        const { error } = await supabase
          .from('rent_payment_records')
          .upsert(
            {
              property_id: property.id,
              owner_id: property.owner_id,
              due_date: dueDate,
              paid_at: paidAtFor(record?.paid_at),
              amount: entered,
              notes: trimmedNotes,
              status: 'paid' as const,
              updated_at: new Date().toISOString(),
            },
            { onConflict: 'property_id,due_date' }
          )
          .select(RENT_PAYMENT_RECORD_COLUMNS_PRE).single()
        if (error) throw error
        showToast({ type: 'success', title: tr('Платіж підтверджено') })
      } else if (editingPart) {
        // ГРОШОВИЙ запис: мовчазна відмова RLS тут дала б «оновлено» при
        // незмінній сумі (правило 8).
        const { data, error } = await supabase
          .from('rent_payment_parts')
          .update({ amount: entered, paid_at: paidAtFor(editingPart.paid_at), notes: trimmedNotes })
          .eq('id', editingPart.id)
          .select('id')
        if (error) throw error
        assertAffected(data, 1, tr('зміна надходження'))
        showToast({ type: 'success', title: tr('Платіж оновлено') })
      } else {
        // Один виклик: створити період (якщо його немає) і вписати
        // надходження — атомарно. Очікувана сума заморожується в періоді
        // саме тут, у мить ПЕРШОГО надходження.
        const { data, error } = await supabase.rpc('record_rent_payment', {
          p_property_id: property.id,
          p_due_date: dueDate,
          p_amount: entered,
          p_paid_at: paidAtFor(null),
          p_notes: trimmedNotes,
          p_amount_due: expected > 0 ? expected : null,
        })
        if (error) throw error
        const res = RecordResult.parse(data)
        if (res.error) {
          showToast({ type: 'error', title: tr('Платіж не зберігся'), subtitle: rpcErrorText(res.error) })
          return
        }
        showToast(res.status === 'partial'
          ? { type: 'success', title: tr('Часткову оплату записано') }
          : { type: 'success', title: tr('Платіж підтверджено') })
      }
      back()
    } catch (e) {
      showToast({ type: 'error', title: tr('Платіж не зберігся'), subtitle: humanizeDbError(e) })
    } finally {
      setSaving(false)
    }
  }

  async function handleDeletePart(p: RentPaymentPart) {
    const ok = await confirmAction({
      title: tr('Видалити надходження?'),
      message: `${formatPrice(p.amount, user?.currency)} · ${new Date(p.paid_at).toLocaleDateString(locale(), { day: 'numeric', month: 'long' })}`,
      confirmLabel: tr('Видалити'),
      destructive: true,
    })
    if (!ok || offlineGuard()) return
    setDeletingId(p.id)
    try {
      const { data, error } = await supabase
        .from('rent_payment_parts').delete().eq('id', p.id).select('id')
      if (error) throw error
      assertAffected(data, 1, tr('видалення надходження'))
      showToast({ type: 'success', title: tr('Надходження видалено') })
      // Лишаємось на екрані: видалення помилкового надходження — це зазвичай
      // ПЕРШИЙ крок виправлення, а не останній. Підсумок перечитується з
      // сервера, бо рахує його тригер.
      await loadRecord()
    } catch (e) {
      showToast({ type: 'error', title: tr('Не вдалося видалити'), subtitle: humanizeDbError(e) })
    } finally {
      setDeletingId(null)
    }
  }

  if (!property && propError) return (
    <div className="scr bg-teal">
      <Header title={tr('Платіж')} backLabel={tr('Назад')} />
      <RetryState
        icon="🏚️"
        title={tr('Обʼєкт не знайдено')}
        subtitle={propError}
        onRetry={() => propertyId && loadSingleProperty(propertyId)}
      />
    </div>
  )

  if (!property || propLoading || recordLoading) return (
    <div className="scr bg-teal">
      <Header title={tr('Платіж')} backLabel={tr('Назад')} />
      <div className="loader-wrap">
        <div className="loader" />
      </div>
    </div>
  )

  if (recordError) return (
    <div className="scr bg-teal">
      <Header title={tr('Платіж')} subtitle={property.name} backLabel={tr('Назад')} />
      <RetryState subtitle={recordError} onRetry={loadRecord} />
    </div>
  )

  const isPaid = record?.status === 'paid'
  // Період, підтверджений СТАРИМ клієнтом після 071: сума є, надходжень немає.
  // Показуємо її рядком без дій — RPC сам перенесе її в надходження при
  // першій доплаті, і гроші не зникнуть із підсумку.
  const legacyReceived = !legacy && parts!.length === 0 && received > 0
  // Змінити суму періоду можна лише з 072 (історія умов і RPC приходять
  // разом): без неї кнопка вела б у відмову сервера.
  const canEditDue = !legacy && terms !== null
  // Підсумок — коли гроші вже є, або коли через нього можна змінити суму
  // періоду: неповний перший місяць правлять саме ДО першого платежу. Тоді
  // лише клітинка очікуваної — «Отримано $0 / Залишок» нічого не додали б.
  const showSummary = !legacy && (received > 0 || canEditDue)
  const overpaid = due != null && received > due ? Math.round((received - due) * 100) / 100 : 0

  // Підказка лише для НОВОГО надходження: власник має бачити, що запише
  // частину, ДО натискання, а не дізнатись із тоста.
  const hint = !legacy && !editingPart && !amountInvalid && remaining > 0
    ? entered < remaining
      ? { text: tr('Часткова оплата — залишиться {0}', formatPrice(Math.round((remaining - entered) * 100) / 100, user?.currency)), color: 'var(--warn-fg)' }
      : entered > remaining
        ? { text: tr('Більше за очікуване на {0}', formatPrice(Math.round((entered - remaining) * 100) / 100, user?.currency)), color: 'var(--t2)' }
        : null
    : null

  // «Підтвердити отримання» не влазило поруч із кнопкою «Назад» — заміряно
  // 204px проти 202px, тобто заголовок обрізався в «…отриман…». Обʼєкт дії
  // і так каже підзаголовок, тож у заголовку лишається коротке.
  const title = legacy
    ? (isPaid ? tr('Редагувати платіж') : tr('Підтвердити платіж'))
    : editingPart ? tr('Редагувати платіж') : received > 0 ? tr('Доплата') : tr('Підтвердити платіж')
  const cta = legacy
    ? (isPaid ? tr('Зберегти зміни') : tr('Підтвердити'))
    : editingPart ? tr('Зберегти зміни') : received > 0 ? tr('Додати оплату') : tr('Підтвердити')

  return (
    <div className="scr bg-teal">
      <Header
        title={title}
        subtitle={dueDate ? `${property.name} · ${fmtDueDate(dueDate)}` : property.name}
        backLabel={tr('Назад')}
      />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        {showSummary && (
          <div className="pay-card pay-sum" style={{ margin: '0 12px 12px' }} aria-label={tr('Підсумок платежу')}>
            {canEditDue ? (
              <button
                type="button"
                className="pay-sum-edit"
                onClick={() => navigate('payment-due', { propertyId, dbId, dueDate })}
                aria-label={tr('Змінити суму за період: {0}', due != null ? formatPrice(due, user?.currency) : '—')}
              >
                {/* span, а не div: вміст кнопки — лише фразовий за специфікацією. */}
                <span className="pay-sum-l">{tr('Очікується')}<IconEdit size={12} /></span>
                <span className="pay-sum-v">{due != null ? formatPrice(due, user?.currency) : '—'}</span>
              </button>
            ) : (
              <div>
                <div className="pay-sum-l">{tr('Очікується')}</div>
                <div className="pay-sum-v">{due != null ? formatPrice(due, user?.currency) : '—'}</div>
              </div>
            )}
            {received > 0 && (<>
            <div>
              <div className="pay-sum-l">{tr('Отримано')}</div>
              <div className="pay-sum-v" style={{ color: 'var(--ok-fg)' }}>{formatPrice(received, user?.currency)}</div>
            </div>
            <div>
              <div className="pay-sum-l">{overpaid > 0 ? tr('Переплата') : tr('Залишок')}</div>
              <div className="pay-sum-v" style={{ color: remaining > 0 ? 'var(--warn-fg)' : 'var(--t1)' }}>
                {formatPrice(overpaid > 0 ? overpaid : remaining, user?.currency)}
              </div>
            </div>
            </>)}
          </div>
        )}

        {/* `.fld` (підпис НАД полем), а не `.fr` (підпис і поле в один рядок), і
            це не смак: у рядковому варіанті довгий підпис зʼїдає ширину, і
            плейсхолдер обрізається — заміряно 287px потрібно проти 116px
            доступно на нотатці, тобто користувач бачив «Готівка, пере» і не
            знав, що від нього хочуть. Той самий клас уже задокументований для
            InviteSheet; шит, який цей екран замінив, теж стояв на `.fld`, і
            перехід на `.fr` у фазі 2 був регресією. */}
        <div style={{ margin: '0 12px 16px' }}>
          <div className="fld">
            <div className="fld-l">{tr('Сума отриманого платежу')}</div>
            {/* Позначка валюти обовʼязкова: це єдине грошове поле застосунку,
                і без неї воно показувало голе число там, де решта поверхонь
                пише «$2 498». Символ — із профілю (`currencySymbol`), а не
                літерал: власник може вести ціни в ₴ або €. */}
            <div className="fld-v">
              <input
                aria-label={tr('Сума отриманого платежу')}
                type="text" inputMode="decimal"
                placeholder={tr('Введіть суму...')}
                value={amount}
                onChange={e => setAmount(sanitizeDecimal(e.target.value))}
              />
              <span className="fld-u">{currencySymbol(user?.currency)}</span>
            </div>
            {hint && (
              <div className="pay-hint" style={{ color: hint.color }} role="status">{hint.text}</div>
            )}
          </div>
          <div className="fld" style={{ marginTop: 10 }}>
            <div className="fld-l">{tr('Дата отримання')}</div>
            <input
              aria-label={tr('Дата отримання')}
              type="date"
              value={paidDay}
              max={today}
              onChange={e => setPaidDay(e.target.value)}
            />
          </div>
          <div className="fld" style={{ marginTop: 10 }}>
            <div className="fld-l">{tr('Нотатка (необовʼязково)')}</div>
            <input
              aria-label={tr('Нотатка до платежу')}
              type="text"
              placeholder={tr('Готівка, переказ, часткова оплата...')}
              value={notes}
              onChange={e => setNotes(e.target.value)}
              maxLength={200}
            />
          </div>
        </div>

        <button
          className={`mbtn success mbtn-flow ${amountInvalid || dayInvalid || saving ? 'disabled' : ''} ${saving ? 'is-loading' : ''}`}
          onClick={handleConfirm}
          disabled={amountInvalid || dayInvalid || saving}
          aria-busy={saving}
        >
          {cta}
        </button>
        {/* Історія надходжень — ПІД кнопкою, і це замір, а не смак. Над формою
            вона зсувала поля й первинну дію вниз по градієнту, що світлішає
            донизу: зелена «Додати оплату» падала до 3.81:1, підпис нотатки —
            до 3.55:1. Підсумок (головна відповідь екрана) лишається вгорі. */}
        {!legacy && (parts!.length > 0 || legacyReceived) && (
          <>
            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconCheckCircle size={14} color="var(--ok)" />{tr('Надходження')}</span></div>
            <div className="pay-card" style={{ margin: '0 12px 16px' }}>
              {legacyReceived && (
                <div className="part-row">
                  <div className="part-main" style={{ cursor: 'default' }}>
                    <PartText
                      day={record?.paid_at ? new Date(record.paid_at).toLocaleDateString(locale(), { day: 'numeric', month: 'long' }) : '—'}
                      note={record?.notes ?? null}
                      amount={formatPrice(received, user?.currency)}
                    />
                  </div>
                </div>
              )}
              {parts!.map(p => (
                <div key={p.id} className="part-row">
                  <button
                    type="button"
                    className="part-main"
                    aria-pressed={p.id === editingId}
                    onClick={() => (p.id === editingId ? fillForAdd() : fillForEdit(p))}
                  >
                    <PartText
                      day={new Date(p.paid_at).toLocaleDateString(locale(), { day: 'numeric', month: 'long' })}
                      // Хто вписав (073) — лише коли це НЕ ти: власнику важливо
                      // бачити гроші, записані редактором, а «ви, ви, ви» під
                      // кожним власним надходженням — шум.
                      who={p.created_by && p.created_by !== user?.id ? (p.created_by_name ?? null) : null}
                      note={p.notes ?? null}
                      amount={formatPrice(p.amount, user?.currency)}
                    />
                  </button>
                  <button
                    type="button"
                    className="part-del"
                    onClick={() => handleDeletePart(p)}
                    disabled={deletingId != null || saving}
                    aria-label={tr('Видалити надходження {0}', formatPrice(p.amount, user?.currency))}
                  >
                    <IconTrash size={16} />
                  </button>
                </div>
              ))}
              {editingPart && (
                <div className="pay-acts">
                  <button type="button" className="pay-act" onClick={fillForAdd}>
                    <IconPlus size={14} /> {tr('Нове надходження')}
                  </button>
                </div>
              )}
            </div>
          </>
        )}

      </div>
    </div>
  )
}

function PartText({ day, who, note, amount }: { day: string; who?: string | null; note: string | null; amount: string }) {
  return (
    <>
      <span style={{ flex: 1, minWidth: 0 }}>
        <span style={{ display: 'block', fontSize: 'var(--fs-note)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)' }}>
          {day}
          {/* Імʼя без дієслова: «вписав/вписала» вимагало б статі, якої ми не знаємо. */}
          {who && <span className="part-who"><IconUser size={12} />{who}</span>}
        </span>
        {note && (
          <span style={{ display: 'block', fontSize: 'var(--fs-cap1)', color: 'var(--t2)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{note}</span>
        )}
      </span>
      <span style={{ flexShrink: 0, fontSize: 'var(--fs-sub)', fontWeight: 'var(--fw-bold)', color: 'var(--ok-fg)' }}>{amount}</span>
    </>
  )
}
