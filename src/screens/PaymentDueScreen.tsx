'use client'

import { useEffect, useState, useCallback } from 'react'
import { z } from 'zod'
import { useAppSlice } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import RetryState from '@/components/ui/RetryState'
import { offlineGuard } from '@/lib/offline'
import { supabase } from '@/lib/supabase'
import { withOptionalColumns } from '@/lib/optionalColumns'
import { sanitizeDecimal, scrollFocusedIntoView, humanizeDbError, currencySymbol, formatPrice } from '@/lib/utils'
import {
  RENT_PAYMENT_RECORD_COLUMNS, RENT_PAYMENT_RECORD_COLUMNS_PRE, RENT_TERMS_COLUMNS,
  expectedRentAt, fmtDueDate, type RentTermsRow,
} from '@/lib/rentPayments'
import type { RentPaymentRecord } from '@/types'
import { tr } from '@/lib/i18n'
import { useClosingConfirmation } from '@/hooks/useTelegram'

const DueResult = z.object({
  record_id: z.string().uuid().nullable().optional(),
  status: z.string().nullable().optional(),
  error: z.string().nullable().optional(),
})

/**
 * Сума до сплати за ОДИН період (072) — без зміни ставки обʼєкта.
 *
 * Потрібна з двох причин, і жодна не рідкісна:
 *   • ЗАКОННО інша сума: неповний перший місяць (заїхав 18-го), знижка,
 *     домовленість. Без цього такий період лишався «частковим» назавжди;
 *   • виправлена описка в ставці. Історія умов (072) не розрізняє «підняв
 *     ставку» і «виправив помилку», тож старий період зберіг би ХИБНУ суму, і
 *     навіть «Скасувати платіж» не допоміг би — повторний запис знову взяв би
 *     її з історії. Це єдиний вихід із того тупика.
 *
 * Підсумок (оплачено/частково) перераховує сервер — тут лише сума.
 */
export default function PaymentDueScreen() {
  useClosingConfirmation()
  const { screenParams, user, showToast, back } = useAppSlice('screenParams', 'user', 'showToast', 'back')
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
  const [terms, setTerms] = useState<RentTermsRow[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [amount, setAmount] = useState('')
  const [prefilled, setPrefilled] = useState(false)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    if (!propertyId || !dueDate) return
    setLoading(true)
    setLoadError(null)
    try {
      const termsP = supabase.from('property_rent_terms').select(RENT_TERMS_COLUMNS)
        .eq('property_id', propertyId)
        .then(({ data, error }) => (error ? null : (data ?? []) as RentTermsRow[]), () => null)
      const { data, error } = await withOptionalColumns((pre) => supabase
        .from('rent_payment_records').select(pre ? RENT_PAYMENT_RECORD_COLUMNS_PRE : RENT_PAYMENT_RECORD_COLUMNS)
        .eq('property_id', propertyId).eq('due_date', dueDate).maybeSingle())
      if (error) throw error
      setRecord(data as RentPaymentRecord | null)
      setTerms(await termsP)
    } catch (e) {
      setLoadError(humanizeDbError(e))
    } finally {
      setLoading(false)
    }
  }, [propertyId, dueDate])

  useEffect(() => { load() }, [load])

  const byTerms = property && dueDate ? expectedRentAt(property, terms, dueDate) : 0
  const current = record?.amount_due ?? (byTerms > 0 ? byTerms : null)
  const received = record?.amount ?? 0

  useEffect(() => {
    if (prefilled || loading || !property) return
    setAmount(current != null ? String(current) : '')
    setPrefilled(true)
  }, [prefilled, loading, property, current])

  const entered = parseFloat(amount)
  const invalid = !(isFinite(entered) && entered > 0)
  const unchanged = !invalid && current != null && Math.round(entered * 100) === Math.round(current * 100)

  async function handleSave() {
    if (!property || !dueDate || invalid || unchanged) return
    if (offlineGuard()) return
    setSaving(true)
    try {
      const { data, error } = await supabase.rpc('set_rent_amount_due', {
        p_property_id: property.id,
        p_due_date: dueDate,
        p_amount_due: entered,
      })
      if (error) throw error
      const res = DueResult.parse(data)
      if (res.error) {
        showToast({
          type: 'error',
          title: tr('Суму не змінено'),
          subtitle: res.error === 'invalid_amount' ? tr('Некоректна сума') : tr('Обʼєкт не знайдено'),
        })
        return
      }
      showToast({ type: 'success', title: tr('Суму за період змінено') })
      back()
    } catch (e) {
      showToast({ type: 'error', title: tr('Суму не змінено'), subtitle: humanizeDbError(e) })
    } finally {
      setSaving(false)
    }
  }

  const subtitle = property ? (dueDate ? `${property.name} · ${fmtDueDate(dueDate)}` : property.name) : undefined

  if (!property && propError) return (
    <div className="scr bg-teal">
      <Header title={tr('Сума за період')} backLabel={tr('Назад')} />
      <RetryState
        icon="🏚️"
        title={tr('Обʼєкт не знайдено')}
        subtitle={propError}
        onRetry={() => propertyId && loadSingleProperty(propertyId)}
      />
    </div>
  )

  if (!property || propLoading || loading) return (
    <div className="scr bg-teal">
      <Header title={tr('Сума за період')} backLabel={tr('Назад')} />
      <div className="loader-wrap">
        <div className="loader" />
      </div>
    </div>
  )

  if (loadError) return (
    <div className="scr bg-teal">
      <Header title={tr('Сума за період')} subtitle={subtitle} backLabel={tr('Назад')} />
      <RetryState subtitle={loadError} onRetry={load} />
    </div>
  )

  // Що станеться з періодом — ДО натискання, а не з тоста.
  const outcome = invalid || received <= 0
    ? null
    : entered <= received
      ? { text: tr('Період стане оплаченим — отримано {0}', formatPrice(received, user?.currency)), color: 'var(--ok-fg)' }
      : { text: tr('Залишиться {0} — отримано {1}', formatPrice(Math.round((entered - received) * 100) / 100, user?.currency), formatPrice(received, user?.currency)), color: 'var(--warn-fg)' }

  return (
    <div className="scr bg-teal">
      <Header title={tr('Сума за період')} subtitle={subtitle} backLabel={tr('Назад')} />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        <div style={{ margin: '0 12px 16px' }}>
          <div className="fld">
            <div className="fld-l">{tr('Сума до сплати за період')}</div>
            <div className="fld-v">
              <input
                aria-label={tr('Сума до сплати за період')}
                type="text" inputMode="decimal"
                placeholder={tr('Введіть суму...')}
                value={amount}
                onChange={e => setAmount(sanitizeDecimal(e.target.value))}
              />
              <span className="fld-u">{currencySymbol(user?.currency)}</span>
            </div>
            {outcome && (
              <div className="pay-hint" style={{ color: outcome.color }} role="status">{outcome.text}</div>
            )}
          </div>
          <p className="pay-note">
            {tr('Змінюється лише цей період — ставка обʼєкта лишається. Для неповного місяця, знижки чи виправлення помилки.')}
          </p>
          {/* Що каже ставка — поруч, щойно введене від неї відрізняється: відхід
              від ставки має бути свідомим, а не одруківкою. */}
          {byTerms > 0 && !invalid && Math.round(byTerms * 100) !== Math.round(entered * 100) && (
            <p className="pay-note">{tr('За ставкою: {0}', formatPrice(byTerms, user?.currency))}</p>
          )}
        </div>

        <button
          className={`mbtn mbtn-flow ${invalid || unchanged || saving ? 'disabled' : ''} ${saving ? 'is-loading' : ''}`}
          onClick={handleSave}
          disabled={invalid || unchanged || saving}
          aria-busy={saving}
        >
          {tr('Зберегти')}
        </button>
      </div>
    </div>
  )
}
