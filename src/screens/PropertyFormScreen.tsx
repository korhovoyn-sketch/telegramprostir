'use client'

import { useState, useEffect } from 'react'
import { useAppStore } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import Toggle from '@/components/ui/Toggle'
import Modal from '@/components/ui/Modal'
import { IconRuler, IconLayers, IconActivity, IconBuilding, IconCurrencyDollar, IconBolt, IconCarGarage, IconFile, IconUser, IconKey, IconMapPin } from '@/components/Icons'
import { UTILITY_META } from '@/lib/utilityMeta'
import FilesList from '@/components/ui/FilesList'
import { formatPrice, calcRent, calcUtilities, scrollFocusedIntoView } from '@/lib/utils'
import type { PropertyStatus, RentType } from '@/types'

export default function PropertyFormScreen() {
  const { screenParams, backThenReplace, showToast, user } = useAppStore()
  const { properties, loadProperties, createProperty, updateProperty, deleteProperty, loading } = useProperties(screenParams.dbId)

  const editId = screenParams.propertyId
  const isEdit = !!editId
  const existing = properties.find(p => p.id === editId)

  const [name, setName] = useState('')
  const [floor, setFloor] = useState('')
  const [status, setStatus] = useState<PropertyStatus>('free')
  const [areaUseful, setAreaUseful] = useState('')
  const [areaTotal, setAreaTotal] = useState('')
  const [rentType, setRentType] = useState<RentType>('per_m2')
  const [rentRate, setRentRate] = useState('')
  const [utilitiesRate, setUtilitiesRate] = useState('')
  const [hasParking, setHasParking] = useState(false)
  const [parkingSpaces, setParkingSpaces] = useState('1')
  const [description, setDescription] = useState('')
  const [salePrice, setSalePrice] = useState('')
  const [tenantName, setTenantName] = useState('')
  const [leaseStartDate, setLeaseStartDate] = useState('')
  const [leaseEndDate, setLeaseEndDate] = useState('')
  const [address, setAddress] = useState('')
  const [utilities, setUtilities] = useState<string[]>([])
  const [showDeleteModal, setShowDeleteModal] = useState(false)

  useEffect(() => {
    const tg = window.Telegram?.WebApp
    tg?.enableClosingConfirmation()
    return () => { tg?.disableClosingConfirmation() }
  }, [])

  useEffect(() => {
    if (isEdit && existing) {
      setName(existing.name)
      setFloor(existing.floor ?? '')
      setStatus(existing.status)
      setAreaUseful(String(existing.area_useful ?? ''))
      setAreaTotal(String(existing.area_total ?? ''))
      setRentType(existing.rent_type)
      setRentRate(String(existing.rent_rate ?? ''))
      setUtilitiesRate(String(existing.utilities_rate ?? ''))
      setHasParking(existing.has_parking)
      setParkingSpaces(String(existing.parking_spaces))
      setDescription(existing.description ?? '')
      setAddress(existing.address ?? '')
      setUtilities(existing.utilities ?? [])
      setSalePrice(String(existing.sale_price ?? ''))
      setTenantName(existing.tenant_name ?? '')
      setLeaseStartDate(existing.lease_start_date ?? '')
      setLeaseEndDate(existing.lease_end_date ?? '')
    } else if (isEdit) {
      loadProperties(screenParams.dbId)
    }
  }, [isEdit, existing, screenParams.dbId, loadProperties])

  const rentCalc = (parseFloat(areaUseful) && parseFloat(rentRate))
    ? calcRent(parseFloat(areaUseful), parseFloat(rentRate), rentType)
    : 0
  const utilsCalc = (parseFloat(areaTotal) && parseFloat(utilitiesRate))
    ? calcUtilities(parseFloat(areaTotal), parseFloat(utilitiesRate))
    : 0
  const total = rentCalc + utilsCalc

  function toggleUtility(id: string) {
    window.Telegram?.WebApp?.HapticFeedback?.selectionChanged()
    setUtilities(prev =>
      prev.includes(id) ? prev.filter(u => u !== id) : [...prev, id]
    )
  }

  const canSave = name.trim().length > 0

  // Returns the numeric value, or undefined if string is empty/invalid.
  // Avoids the `parseFloat('0') || undefined` pitfall where 0 is silently dropped.
  function numOrUndef(s: string): number | undefined {
    if (s.trim() === '') return undefined
    const n = parseFloat(s)
    return isNaN(n) ? undefined : n
  }

  async function handleSave() {
    if (!canSave || !screenParams.dbId) return

    // Reject non-numeric values the browser's number input allows on some Android keyboards
    if (areaUseful && numOrUndef(areaUseful) === undefined) {
      showToast({ type: 'error', title: 'Некоректне значення', subtitle: 'Корисна площа — лише число' }); return
    }
    if (areaTotal && numOrUndef(areaTotal) === undefined) {
      showToast({ type: 'error', title: 'Некоректне значення', subtitle: 'Загальна площа — лише число' }); return
    }
    if (rentRate && numOrUndef(rentRate) === undefined) {
      showToast({ type: 'error', title: 'Некоректне значення', subtitle: 'Орендна ставка — лише число' }); return
    }
    if (utilitiesRate && numOrUndef(utilitiesRate) === undefined) {
      showToast({ type: 'error', title: 'Некоректне значення', subtitle: 'Ставка комунальних — лише число' }); return
    }

    const au = numOrUndef(areaUseful) ?? 0
    const at = numOrUndef(areaTotal) ?? 0
    const rr = numOrUndef(rentRate) ?? 0
    const ur = numOrUndef(utilitiesRate) ?? 0
    if (au < 0 || at < 0 || rr < 0 || ur < 0) {
      showToast({ type: 'error', title: 'Значення не може бути від\'ємним' })
      return
    }
    if (au > 0 && at > 0 && au > at) {
      showToast({ type: 'error', title: 'Корисна площа більша за загальну' })
      return
    }
    if (status === 'occupied' && leaseStartDate && leaseEndDate && leaseEndDate < leaseStartDate) {
      showToast({ type: 'error', title: 'Дата закінчення оренди раніше початку' })
      return
    }
    window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
    const payload = {
      db_id: screenParams.dbId!,
      name: name.trim(),
      floor: floor.trim() || undefined,
      address: address.trim() || undefined,
      status,
      area_useful: numOrUndef(areaUseful),
      area_total: numOrUndef(areaTotal),
      rent_type: rentType,
      rent_rate: numOrUndef(rentRate),
      utilities_rate: numOrUndef(utilitiesRate),
      has_parking: hasParking,
      parking_spaces: hasParking ? parseInt(parkingSpaces) : 0,
      utilities: utilities.length > 0 ? utilities : null,
      description: description.trim() || undefined,
      sale_price: status === 'for_sale' ? numOrUndef(salePrice) : null,
      tenant_name: status === 'occupied' ? (tenantName.trim() || undefined) : null,
      lease_start_date: status === 'occupied' ? (leaseStartDate || undefined) : null,
      lease_end_date: status === 'occupied' ? (leaseEndDate || undefined) : null,
    }

    if (isEdit && editId) {
      await updateProperty(editId, payload)
      // backThenReplace: pops the entry that navigated to property-form (property-detail)
      // then lands on property-detail fresh — so back() from detail goes to db-objects,
      // not to a stale duplicate detail entry.
      backThenReplace('property-detail', { propertyId: editId, dbId: screenParams.dbId })
    } else {
      await createProperty(payload)
    }
  }

  return (
    <div className="scr bg-blue">
      <Header
        title={isEdit ? 'Редагування' : 'Новий об\'єкт'}
        backLabel={isEdit ? 'Назад' : 'База'}
        right={
          isEdit ? (
            <button
              className="hdr-a"
              aria-label="Видалити об'єкт"
              onClick={() => setShowDeleteModal(true)}
              style={{ background: 'none', border: 'var(--bd)', color: 'var(--err)' }}
            >
              🗑️
            </button>
          ) : <div className="hdr-sp" />
        }
      />

      <div className="body" onFocusCapture={scrollFocusedIntoView}>
        {/* Basic */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconBuilding size={13} color="#7AB3FF" />Основне</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Назва</span>
            <input className="fr-i" placeholder="Офіс 101" maxLength={100} value={name} onChange={e => setName(e.target.value)} autoFocus={!isEdit} />
          </div>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconLayers size={13} color="var(--t3)" />Поверх</span>
            <input className="fr-i" type="text" inputMode="text" placeholder="1, 2, B-1, МП" maxLength={20} value={floor} onChange={e => setFloor(e.target.value)} />
          </div>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconMapPin size={13} color="var(--t3)" />Адреса</span>
            <input className="fr-i" type="text" placeholder="вул. Хрещатик, 1" maxLength={200} value={address} onChange={e => setAddress(e.target.value)} />
          </div>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconActivity size={13} color="var(--t3)" />Статус</span>
            <div className="fr-seg" style={{ maxWidth: 200 }}>
              {([
                { v: 'free', l: 'Вільно' },
                { v: 'occupied', l: 'Зайнято' },
                { v: 'for_sale', l: 'Продаж' },
              ] as const).map(({ v, l }) => (
                <div key={v} className={`fr-seg-b ${status === v ? 'on' : ''}`} onClick={() => setStatus(v)}>{l}</div>
              ))}
            </div>
          </div>
        </div>

        {/* Sale price — shown only when for_sale */}
        {status === 'for_sale' && (
          <>
            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconCurrencyDollar size={13} color="#fbbf24" />Продаж</span></div>
            <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
              <div className="fr">
                <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconCurrencyDollar size={13} color="var(--t3)" />Ціна продажу</span>
                <input className="fr-i" type="number" min="0" max="999999999" inputMode="decimal" placeholder="150000" value={salePrice} onChange={e => setSalePrice(e.target.value)} />
                <span className="fr-u">$</span>
              </div>
            </div>
          </>
        )}

        {/* Tenant info — shown only when occupied */}
        {status === 'occupied' && (
          <>
            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconUser size={13} color="#a78bfa" />Орендар</span></div>
            <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
              <div className="fr">
                <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconUser size={13} color="var(--t3)" />Найменування</span>
                <input className="fr-i" placeholder="ТОВ «Назва» або ФОП Іванов" maxLength={200} value={tenantName} onChange={e => setTenantName(e.target.value)} />
              </div>
              <div className="fr">
                <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconKey size={13} color="var(--t3)" />Договір з</span>
                <input className="fr-i" type="date" value={leaseStartDate} onChange={e => setLeaseStartDate(e.target.value)}
                  style={{ colorScheme: 'dark' }} />
              </div>
              <div className="fr">
                <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconKey size={13} color="var(--t3)" />Договір до</span>
                <input className="fr-i" type="date" value={leaseEndDate} onChange={e => setLeaseEndDate(e.target.value)}
                  style={{ colorScheme: 'dark' }} />
              </div>
            </div>
          </>
        )}

        {/* Area */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconRuler size={13} color="#7AB3FF" />Площа</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconRuler size={13} color="var(--t3)" />Корисна</span>
            <input className="fr-i" type="number" min="0" inputMode="decimal" placeholder="47" value={areaUseful} onChange={e => setAreaUseful(e.target.value)} />
            <span className="fr-u">м²</span>
          </div>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}><IconRuler size={13} color="var(--t3)" />Загальна</span>
            <input className="fr-i" type="number" min="0" inputMode="decimal" placeholder="52" value={areaTotal} onChange={e => setAreaTotal(e.target.value)} />
            <span className="fr-u">м²</span>
          </div>
        </div>

        {/* Rent */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconCurrencyDollar size={13} color="#c2820a" />Орендна ставка</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Тип</span>
            <div className="fr-seg" style={{ maxWidth: 180 }}>
              <div className={`fr-seg-b ${rentType === 'per_m2' ? 'on' : ''}`} onClick={() => setRentType('per_m2')}>$ за м²</div>
              <div className={`fr-seg-b ${rentType === 'fixed' ? 'on' : ''}`} onClick={() => setRentType('fixed')}>Фікс. сума</div>
            </div>
          </div>
          <div className="fr hi-row">
            <span className="fr-l">{rentType === 'per_m2' ? 'Ставка' : 'Сума'}</span>
            <input className="fr-i" type="number" min="0" inputMode="decimal" placeholder="18" value={rentRate} onChange={e => setRentRate(e.target.value)} />
            <span className="fr-u">{rentType === 'per_m2' ? '$/м²' : '$/міс'}</span>
          </div>
          {rentCalc > 0 && (
            <div className="fr" style={{ background: 'rgba(34,158,217,.08)' }}>
              <span className="fr-l" style={{ color: 'var(--t3)', fontSize: 12 }}>Розрахунок</span>
              <span style={{ flex: 1, textAlign: 'right', fontWeight: 700, fontSize: 15, color: 'var(--info-fg)' }}>
                {formatPrice(rentCalc, user?.currency)}/міс
              </span>
            </div>
          )}
        </div>

        {/* Utilities */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconBolt size={13} color="#fbbf24" />Комунальні</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Ставка</span>
            <input className="fr-i" type="number" min="0" inputMode="decimal" placeholder="2.5" value={utilitiesRate} onChange={e => setUtilitiesRate(e.target.value)} />
            <span className="fr-u">$/м²</span>
          </div>
          {utilsCalc > 0 && (
            <div className="fr" style={{ background: 'rgba(34,158,217,.08)' }}>
              <span className="fr-l" style={{ color: 'var(--t3)', fontSize: 12 }}>Розрахунок</span>
              <span style={{ flex: 1, textAlign: 'right', fontWeight: 700, fontSize: 15, color: 'var(--info-fg)' }}>
                {formatPrice(utilsCalc, user?.currency)}/міс
              </span>
            </div>
          )}
        </div>

        {/* Parking */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconCarGarage size={13} color="#fb923c" />Паркінг</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Є паркінг</span>
            <Toggle value={hasParking} onChange={setHasParking} />
          </div>
          {hasParking && (
            <div className="fr">
              <span className="fr-l">Місць</span>
              <input className="fr-i" type="number" min="1" step="1" inputMode="numeric" value={parkingSpaces} onChange={e => setParkingSpaces(e.target.value)} />
            </div>
          )}
        </div>

        {/* Utilities */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconBolt size={13} color="#fbbf24" />Комунальні послуги</span></div>
        <div className="glass-s" style={{ margin: '0 12px 16px', borderRadius: 'var(--r-md)' }}>
          <div className="util-tags">
            {UTILITY_META.map(({ id, label, Icon, color }) => {
              const on = utilities.includes(id)
              return (
                <button
                  key={id}
                  className={`util-tag${on ? ' on' : ''}`}
                  onClick={() => toggleUtility(id)}
                  style={on ? { color } : undefined}
                >
                  <Icon size={14} />
                  {label}
                </button>
              )
            })}
          </div>
        </div>

        {/* Description */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconFile size={13} color="#a78bfa" />Опис</span></div>
        <div className="glass-s" style={{ margin: '0 12px 16px', borderRadius: 'var(--r-md)', padding: '10px 14px' }}>
          <textarea
            className="fr-textarea"
            placeholder="Додатковий опис об'єкту..."
            value={description}
            onChange={e => setDescription(e.target.value)}
            rows={4}
            maxLength={2000}
            style={{ resize: 'none' }}
          />
        </div>

        {/* Files — only in edit mode (property exists in DB) */}
        {isEdit && editId && (
          <FilesList propertyId={editId} isOwner={true} />
        )}

        {/* Sum */}
        {total > 0 && (
          <div className="sum-bar glass-s" style={{ margin: '0 12px 16px' }}>
            {rentCalc > 0 && (
              <div className="sum-r">
                <span>Оренда</span>
                <span>{formatPrice(rentCalc, user?.currency)}/міс</span>
              </div>
            )}
            {utilsCalc > 0 && (
              <div className="sum-r">
                <span>Комунальні</span>
                <span>{formatPrice(utilsCalc, user?.currency)}/міс</span>
              </div>
            )}
            <div className="sum-tot">
              <span className="sum-tot-l">Разом на місяць</span>
              <span className="sum-tot-v">{formatPrice(total, user?.currency)}</span>
            </div>
          </div>
        )}

        <div style={{ height: 80 }} />
      </div>

      <button
        className={`mbtn success ${!canSave || loading ? 'disabled' : ''} ${loading ? 'is-loading' : ''}`}
        onClick={handleSave}
        disabled={!canSave || loading}
      >
        {!loading && (isEdit ? 'Зберегти зміни' : 'Додати об\'єкт')}
      </button>

      {showDeleteModal && editId && (
        <Modal
          title="Видалити об'єкт?"
          subtitle={`Об'єкт "${name}" буде видалено. Це незворотно.`}
          onClose={() => setShowDeleteModal(false)}
          actions={[
            { label: 'Видалити', variant: 'danger', onClick: async () => { window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('warning'); await deleteProperty(editId, screenParams.dbId!); setShowDeleteModal(false) } },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setShowDeleteModal(false) },
          ]}
        />
      )}
    </div>
  )
}
