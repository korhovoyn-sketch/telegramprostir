'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import { useDbType } from '@/hooks/useDbType'
import Header from '@/components/ui/Header'
import RetryState from '@/components/ui/RetryState'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import { IconUser, IconCurrencyDollar, IconBolt, IconKey } from '@/components/Icons'
import { offlineGuard } from '@/lib/offline'
import { hapticNotify } from '@/lib/telegram'
import {
  sanitizeDecimal, scrollFocusedIntoView, calcRentUtils,
  currencySymbol, rentUnitLabel, formatPrice,
} from '@/lib/utils'
import { tr } from '@/lib/i18n'

/**
 * Повноекранна форма «Здати в оренду» — заміна останнього `<Modal>` із полями
 * (фаза 5 переробки модалок, atomic-riding-clock.md).
 *
 * Оптимістичного апдейта тут НЕМА, і це не спрощення: `PropertyDetailScreen`
 * цілком перемонтовується на `back()` і сам перечитує свіжий рядок, тож
 * миттєвий фідбек дає сам перехід екрана — той самий висновок, що у фазі 2.
 */
export default function RentPropertyScreen() {
  const { screenParams, user, showToast, back } = useAppStore()
  const propertyId = screenParams.propertyId as string | undefined
  const dbId = screenParams.dbId as string | undefined

  const { properties, loading, error, loadSingleProperty, updateProperty } = useProperties(dbId)
  const property = properties.find(p => p.id === propertyId)
  // ХУК СТОЇТЬ ДО ранніх `return` — інакше порядок хуків між рендерами
  // ламається (`rules-of-hooks`); той самий урок, що з `useFileDrop`.
  const { isParking } = useDbType(property?.db_id ?? dbId)

  useEffect(() => {
    if (propertyId) loadSingleProperty(propertyId)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [propertyId])

  const [tenantName, setTenantName] = useState('')
  const [rentRate, setRentRate] = useState('')
  const [utilitiesRate, setUtilitiesRate] = useState('')
  const [leaseStart, setLeaseStart] = useState('')
  const [leaseEnd, setLeaseEnd] = useState('')
  const [saving, setSaving] = useState(false)
  const [prefilled, setPrefilled] = useState(false)

  // Ставки успадковуються від обʼєкта — але лише ОДИН раз, інакше кожен
  // перерендер затирав би те, що користувач уже набрав.
  useEffect(() => {
    if (prefilled || !property) return
    setRentRate(property.rent_rate != null ? String(property.rent_rate) : '')
    setUtilitiesRate(property.utilities_rate != null ? String(property.utilities_rate) : '')
    setPrefilled(true)
  }, [property, prefilled])

  if (loading && !property) {
    return (
      <div className="scr bg-blue">
        <Header title={tr('Здати в оренду')} onBack={back} />
        <div className="body"><SkeletonLoader rows={3} rowHeight={69} /></div>
      </div>
    )
  }
  if (error || !property) {
    return (
      <div className="scr bg-blue">
        <Header title={tr('Здати в оренду')} onBack={back} />
        <div className="body">
          <RetryState
            title={tr('Не вдалося завантажити обʼєкт')}
            subtitle={error ?? tr('Обʼєкт не знайдено')}
            onRetry={() => { if (propertyId) void loadSingleProperty(propertyId) }}
          />
        </div>
      </div>
    )
  }

  const rateVal = parseFloat(rentRate)
  const utilVal = parseFloat(utilitiesRate)
  // ЄДИНЕ джерело правди по грошах. Раніше превʼю рахувало експлуатаційні
  // самотужки і гейтило одиницю на `property.area_total` — тобто на ХИБНІЙ
  // ЗМІННІЙ: обʼєкт із базою «корисна» і порожньою розрахунковою площею
  // показував пласкі $2,5 замість 50 м² × 2,5 = $125, і картка одразу після
  // збереження суперечила екрану, на якому власник щойно вирішував ціну.
  // Той самий гейт по типу БАЗИ, що й скрізь: `isParking` тепер надійний
  // (`useDbType` довантажує рядок, стор на холодному вході порожній).
  const preview = calcRentUtils(
    property.area_useful, property.area_total,
    isFinite(rateVal) && rateVal > 0 ? rateVal : 0, property.rent_type,
    isFinite(utilVal) && utilVal > 0 ? utilVal : 0, property.area_basis,
    isParking,
  )
  const previewTotal = property.rent_type === 'per_day' ? 0 : preview.total
  const rateUnit = `${currencySymbol(user?.currency)}${rentUnitLabel(property.rent_type)}`
  const utilUnit = tr('{0}{1}', currencySymbol(user?.currency), isParking ? tr('/міс') : tr('/м²'))

  async function handleSubmit() {
    if (!property || !tenantName.trim() || saving) return
    // Те саме правило, що в PropertyFormScreen: договір не може закінчуватись
    // раніше, ніж почався.
    if (leaseStart && leaseEnd && leaseEnd < leaseStart) {
      showToast({ type: 'error', title: tr('Дата закінчення оренди раніше початку') })
      return
    }
    if (offlineGuard()) return
    setSaving(true)
    const parsedRate = parseFloat(rentRate)
    const parsedUtils = parseFloat(utilitiesRate)
    const ok = await updateProperty(property.id, {
      status: 'occupied',
      tenant_name: tenantName.trim(),
      lease_start_date: leaseStart || undefined,
      lease_end_date: leaseEnd || undefined,
      ...(isFinite(parsedRate) && parsedRate >= 0 ? { rent_rate: parsedRate } : {}),
      ...(isFinite(parsedUtils) && parsedUtils >= 0 ? { utilities_rate: parsedUtils } : {}),
    }, { silent: true })
    setSaving(false)
    if (!ok) {
      showToast({ type: 'error', title: tr('Не вдалося здати в оренду') })
      return
    }
    hapticNotify('success')
    showToast({ type: 'success', title: tr('Обʼєкт здано в оренду') })
    back()
  }

  return (
    <div className="scr bg-blue">
      <Header title={tr('Здати в оренду')} subtitle={property.name} onBack={back} />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        <div className="fld-row">
          <div className="fld">
            <div className="fld-l"><IconUser size={12} />{tr('Орендар')}</div>
            <input
              aria-label={tr('Орендар')}
              placeholder={tr('ТОВ «Назва» або ФОП')}
              value={tenantName}
              onChange={e => setTenantName(e.target.value)}
            />
          </div>
        </div>
        <div className="fld-row">
          {/* Одиниця — коло ЗНАЧЕННЯ, а не в підписі: у половинному полі
              «Експлуатаційні, $/м²» не вміщалась і ellipsis зʼїдав саму одиницю,
              тобто користувач не бачив, ЩО вводить. */}
          <div className="fld">
            <div className="fld-l"><IconCurrencyDollar size={12} />{tr('Оренда')}</div>
            <div className="fld-v">
              <input
                aria-label={tr('Орендна ставка')}
                type="text"
                inputMode="decimal"
                placeholder="0"
                value={rentRate}
                onChange={e => setRentRate(sanitizeDecimal(e.target.value))}
              />
              <span className="fld-u">{rateUnit}</span>
            </div>
          </div>
          <div className="fld">
            <div className="fld-l"><IconBolt size={12} />{tr('Експлуатаційні')}</div>
            <div className="fld-v">
              <input
                aria-label={tr('Ставка експлуатаційних')}
                type="text"
                inputMode="decimal"
                placeholder="0"
                value={utilitiesRate}
                onChange={e => setUtilitiesRate(sanitizeDecimal(e.target.value))}
              />
              <span className="fld-u">{utilUnit}</span>
            </div>
          </div>
        </div>
        <div className="fld-row">
          <div className="fld">
            <div className="fld-l"><IconKey size={12} />{tr('Договір з')}</div>
            <input
              aria-label={tr('Договір від')}
              type="date"
              value={leaseStart}
              onChange={e => setLeaseStart(e.target.value)}
              style={{ colorScheme: 'dark' }}
            />
          </div>
          <div className="fld">
            <div className="fld-l"><IconKey size={12} />{tr('Договір до')}</div>
            <input
              aria-label={tr('Договір до')}
              type="date"
              value={leaseEnd}
              onChange={e => setLeaseEnd(e.target.value)}
              style={{ colorScheme: 'dark' }}
            />
          </div>
        </div>

        {previewTotal > 0 && (
          <div className="rent-sum">
            <span>{tr('Разом на місяць')}</span>
            <span className="rent-sum-v">{formatPrice(previewTotal, user?.currency)}</span>
          </div>
        )}

        <button
          className="mbtn success mbtn-flow"
          disabled={!tenantName.trim() || saving}
          aria-busy={saving}
          onClick={() => void handleSubmit()}
        >
          {tr('Здати в оренду')}
        </button>
      </div>
    </div>
  )
}
