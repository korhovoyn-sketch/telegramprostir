'use client'

import { useState, useEffect } from 'react'
import { useAppStore } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import Toggle from '@/components/ui/Toggle'
import Modal from '@/components/ui/Modal'
import { formatPrice, calcRent, calcUtilities } from '@/lib/utils'
import type { PropertyStatus, RentType } from '@/types'

export default function PropertyFormScreen() {
  const { screenParams, navigate, showToast } = useAppStore()
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

  const canSave = name.trim().length > 0

  async function handleSave() {
    if (!canSave || !screenParams.dbId) return
    if (parseFloat(areaUseful) < 0 || parseFloat(areaTotal) < 0 || parseFloat(rentRate) < 0 || parseFloat(utilitiesRate) < 0) {
      showToast({ type: 'error', title: 'Значення не може бути від\'ємним' })
      return
    }
    window.Telegram?.WebApp?.HapticFeedback.notificationOccurred('success')
    const payload = {
      db_id: screenParams.dbId!,
      name: name.trim(),
      floor: floor || undefined,
      status,
      area_useful: parseFloat(areaUseful) || undefined,
      area_total: parseFloat(areaTotal) || undefined,
      rent_type: rentType,
      rent_rate: parseFloat(rentRate) || undefined,
      utilities_rate: parseFloat(utilitiesRate) || undefined,
      has_parking: hasParking,
      parking_spaces: hasParking ? parseInt(parkingSpaces) : 0,
      description: description.trim() || undefined,
    }

    if (isEdit && editId) {
      await updateProperty(editId, payload)
      navigate('property-detail', { propertyId: editId, dbId: screenParams.dbId })
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
              onClick={() => setShowDeleteModal(true)}
              style={{ background: 'none', border: 'var(--bd)', color: 'var(--err)' }}
            >
              🗑️
            </button>
          ) : <div className="hdr-sp" />
        }
      />

      <div className="body">
        {/* Basic */}
        <div className="over">Основне</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Назва</span>
            <input className="fr-i" placeholder="Офіс 101" value={name} onChange={e => setName(e.target.value)} autoFocus={!isEdit} />
          </div>
          <div className="fr">
            <span className="fr-l">Поверх</span>
            <input className="fr-i" type="number" placeholder="1" value={floor} onChange={e => setFloor(e.target.value)} />
          </div>
          <div className="fr">
            <span className="fr-l">Статус</span>
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

        {/* Area */}
        <div className="over">Площа</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Корисна</span>
            <input className="fr-i" type="number" min="0" placeholder="47" value={areaUseful} onChange={e => setAreaUseful(e.target.value)} />
            <span className="fr-u">м²</span>
          </div>
          <div className="fr">
            <span className="fr-l">Загальна</span>
            <input className="fr-i" type="number" min="0" placeholder="52" value={areaTotal} onChange={e => setAreaTotal(e.target.value)} />
            <span className="fr-u">м²</span>
          </div>
        </div>

        {/* Rent */}
        <div className="over">Орендна ставка</div>
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
            <input className="fr-i" type="number" min="0" placeholder="18" value={rentRate} onChange={e => setRentRate(e.target.value)} />
            <span className="fr-u">{rentType === 'per_m2' ? '$/м²' : '$/міс'}</span>
          </div>
          {rentCalc > 0 && (
            <div className="fr" style={{ background: 'rgba(34,158,217,.08)' }}>
              <span className="fr-l" style={{ color: 'var(--t3)', fontSize: 12 }}>Розрахунок</span>
              <span style={{ flex: 1, textAlign: 'right', fontWeight: 700, fontSize: 15, color: 'var(--info-fg)' }}>
                {formatPrice(rentCalc)}/міс
              </span>
            </div>
          )}
        </div>

        {/* Utilities */}
        <div className="over">Комунальні</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Ставка</span>
            <input className="fr-i" type="number" min="0" placeholder="2.5" value={utilitiesRate} onChange={e => setUtilitiesRate(e.target.value)} />
            <span className="fr-u">$/м²</span>
          </div>
          {utilsCalc > 0 && (
            <div className="fr" style={{ background: 'rgba(34,158,217,.08)' }}>
              <span className="fr-l" style={{ color: 'var(--t3)', fontSize: 12 }}>Розрахунок</span>
              <span style={{ flex: 1, textAlign: 'right', fontWeight: 700, fontSize: 15, color: 'var(--info-fg)' }}>
                {formatPrice(utilsCalc)}/міс
              </span>
            </div>
          )}
        </div>

        {/* Parking */}
        <div className="over">Паркінг</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Є паркінг</span>
            <Toggle value={hasParking} onChange={setHasParking} />
          </div>
          {hasParking && (
            <div className="fr">
              <span className="fr-l">Місць</span>
              <input className="fr-i" type="number" min="1" value={parkingSpaces} onChange={e => setParkingSpaces(e.target.value)} />
            </div>
          )}
        </div>

        {/* Description */}
        <div className="over">Опис</div>
        <div className="glass-s" style={{ margin: '0 12px 16px', borderRadius: 'var(--r-md)', padding: '10px 14px' }}>
          <textarea
            className="fr-textarea"
            placeholder="Додатковий опис об'єкту..."
            value={description}
            onChange={e => setDescription(e.target.value)}
            rows={4}
            style={{ resize: 'none' }}
          />
        </div>

        {/* Sum */}
        {total > 0 && (
          <div className="sum-bar glass-s" style={{ margin: '0 12px 16px' }}>
            {rentCalc > 0 && (
              <div className="sum-r">
                <span>Оренда</span>
                <span>{formatPrice(rentCalc)}/міс</span>
              </div>
            )}
            {utilsCalc > 0 && (
              <div className="sum-r">
                <span>Комунальні</span>
                <span>{formatPrice(utilsCalc)}/міс</span>
              </div>
            )}
            <div className="sum-tot">
              <span className="sum-tot-l">Разом на місяць</span>
              <span className="sum-tot-v">{formatPrice(total)}</span>
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
            { label: 'Видалити', variant: 'danger', onClick: async () => { await deleteProperty(editId, screenParams.dbId!); setShowDeleteModal(false) } },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setShowDeleteModal(false) },
          ]}
        />
      )}
    </div>
  )
}
