'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import RetryState from '@/components/ui/RetryState'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import { IconUser, IconCurrencyDollar, IconBolt, IconKey } from '@/components/Icons'
import { offlineGuard } from '@/lib/offline'
import { hapticNotify } from '@/lib/telegram'
import {
  sanitizeDecimal, scrollFocusedIntoView, calcRent, calcUtilities, basisArea,
  currencySymbol, rentUnitLabel, formatPrice,
} from '@/lib/utils'

/**
 * Повноекранна форма «Здати в оренду» — заміна останнього `<Modal>` із полями
 * (фаза 5 переробки модалок, atomic-riding-clock.md).
 *
 * Оптимістичного апдейта тут НЕМА, і це не спрощення: `PropertyDetailScreen`
 * цілком перемонтовується на `back()` і сам перечитує свіжий рядок, тож
 * миттєвий фідбек дає сам перехід екрана — той самий висновок, що у фазі 2.
 */
export default function RentPropertyScreen() {
  const { screenParams, user, databases, showToast, back } = useAppStore()
  const propertyId = screenParams.propertyId as string | undefined
  const dbId = screenParams.dbId as string | undefined

  const { properties, loading, error, loadSingleProperty, updateProperty } = useProperties(dbId)
  const property = properties.find(p => p.id === propertyId)

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
        <Header title="Здати в оренду" onBack={back} />
        <div className="body"><SkeletonLoader rows={3} rowHeight={69} /></div>
      </div>
    )
  }
  if (error || !property) {
    return (
      <div className="scr bg-blue">
        <Header title="Здати в оренду" onBack={back} />
        <div className="body">
          <RetryState
            title="Не вдалося завантажити обʼєкт"
            subtitle={error ?? 'Обʼєкт не знайдено'}
            onRetry={() => { if (propertyId) void loadSingleProperty(propertyId) }}
          />
        </div>
      </div>
    )
  }

  const isParking = databases.find(d => d.id === property.db_id)?.type === 'parking'
  const rateVal = parseFloat(rentRate)
  const utilVal = parseFloat(utilitiesRate)
  const previewArea = basisArea(property.area_useful, property.area_total, property.area_basis)
  const previewRent = isFinite(rateVal) && rateVal > 0 ? calcRent(previewArea, rateVal, property.rent_type) : 0
  const previewUtils = isFinite(utilVal) && utilVal > 0
    ? (property.area_total ? calcUtilities(previewArea, utilVal) : utilVal)
    : 0
  const previewTotal = property.rent_type === 'per_day' ? 0 : previewRent + previewUtils
  const rateUnit = `${currencySymbol(user?.currency)}${rentUnitLabel(property.rent_type)}`
  const utilUnit = `${currencySymbol(user?.currency)}${isParking ? '/міс' : '/м²'}`

  async function handleSubmit() {
    if (!property || !tenantName.trim() || saving) return
    // Те саме правило, що в PropertyFormScreen: договір не може закінчуватись
    // раніше, ніж почався.
    if (leaseStart && leaseEnd && leaseEnd < leaseStart) {
      showToast({ type: 'error', title: 'Дата закінчення оренди раніше початку' })
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
      showToast({ type: 'error', title: 'Не вдалося здати в оренду' })
      return
    }
    hapticNotify('success')
    showToast({ type: 'success', title: 'Обʼєкт здано в оренду' })
    back()
  }

  return (
    <div className="scr bg-blue">
      <Header title="Здати в оренду" subtitle={property.name} onBack={back} />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        <div className="fld-row">
          <div className="fld">
            <div className="fld-l"><IconUser size={12} />Орендар</div>
            <input
              aria-label="Орендар"
              placeholder="ТОВ «Назва» або ФОП"
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
            <div className="fld-l"><IconCurrencyDollar size={12} />Оренда</div>
            <div className="fld-v">
              <input
                aria-label="Орендна ставка"
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
            <div className="fld-l"><IconBolt size={12} />Експлуатаційні</div>
            <div className="fld-v">
              <input
                aria-label="Ставка експлуатаційних"
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
            <div className="fld-l"><IconKey size={12} />Договір з</div>
            <input
              aria-label="Договір від"
              type="date"
              value={leaseStart}
              onChange={e => setLeaseStart(e.target.value)}
              style={{ colorScheme: 'dark' }}
            />
          </div>
          <div className="fld">
            <div className="fld-l"><IconKey size={12} />Договір до</div>
            <input
              aria-label="Договір до"
              type="date"
              value={leaseEnd}
              onChange={e => setLeaseEnd(e.target.value)}
              style={{ colorScheme: 'dark' }}
            />
          </div>
        </div>

        {previewTotal > 0 && (
          <div className="rent-sum">
            <span>Разом на місяць</span>
            <span className="rent-sum-v">{formatPrice(previewTotal, user?.currency)}</span>
          </div>
        )}

        <button
          className="mbtn success mbtn-flow"
          disabled={!tenantName.trim() || saving}
          aria-busy={saving}
          onClick={() => void handleSubmit()}
        >
          Здати в оренду
        </button>
      </div>
    </div>
  )
}
