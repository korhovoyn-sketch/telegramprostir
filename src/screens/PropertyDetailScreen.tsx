'use client'

import { useEffect } from 'react'
import { useAppStore } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import { StatusBadge } from '@/components/ui/Badge'
import { IconEdit, IconShare, IconMapPin, IconPhoto } from '@/components/Icons'
import { formatPrice, calcRent, calcUtilities, STATUS_LABELS } from '@/lib/utils'

export default function PropertyDetailScreen() {
  const { screenParams, navigate } = useAppStore()
  const { properties, loadProperties } = useProperties(screenParams.dbId)

  const property = properties.find(p => p.id === screenParams.propertyId)

  useEffect(() => {
    if (!property && screenParams.dbId) loadProperties(screenParams.dbId)
  }, [property, screenParams.dbId, loadProperties])

  if (!property) return (
    <div className="scr bg-blue">
      <Header title="Об'єкт" backLabel="Назад" />
      <div className="loader-wrap">
        <div className="loader" />
      </div>
    </div>
  )

  const rent = property.rent_rate && property.area_useful
    ? calcRent(property.area_useful, property.rent_rate, property.rent_type)
    : 0
  const utils = property.utilities_rate && property.area_total
    ? calcUtilities(property.area_total, property.utilities_rate)
    : 0
  const total = rent + utils

  return (
    <div className="scr bg-blue">
      <Header
        title={property.name}
        backLabel="Назад"
        right={
          <button
            className="hdr-a"
            onClick={() => navigate('property-form', { propertyId: property.id, dbId: screenParams.dbId, editMode: true })}
            style={{ background: 'none', border: 'var(--bd)' }}
          >
            <IconEdit size={15} />
          </button>
        }
      />

      <div className="body">
        {/* Hero */}
        <div className="obj-hero">
          {property.photos && property.photos.length > 0 ? (
            <div
              style={{ position: 'absolute', inset: 0, background: 'var(--glass-1)', cursor: 'pointer' }}
              onClick={() => navigate('photo-gallery', { propertyId: property.id, photoIndex: 0 })}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', fontSize: 40 }}>
                📷
              </div>
            </div>
          ) : (
            <span>🏢</span>
          )}

          <div className="obj-hero-bdg">
            <span className="fdot" style={{ background: property.status === 'free' ? 'var(--ok)' : property.status === 'occupied' ? 'var(--err)' : 'var(--warn)' }} />
            {STATUS_LABELS[property.status]}
          </div>

          <div className="obj-hero-r">
            <button className="obj-hero-a" onClick={() => navigate('sharing-analytics', { propertyId: property.id, dbId: screenParams.dbId })}>
              <IconShare size={14} />
            </button>
          </div>

          <div className="obj-hero-meta">
            <div>
              <div className="obj-hero-name">{property.name}</div>
              {property.floor && (
                <div className="obj-hero-addr">
                  <IconMapPin size={10} />
                  <span>{property.floor} поверх</span>
                </div>
              )}
            </div>
            {property.photos && property.photos.length > 0 && (
              <div className="obj-hero-photos" onClick={() => navigate('photo-gallery', { propertyId: property.id, photoIndex: 0 })}>
                <IconPhoto size={10} />
                {property.photos.length} фото
              </div>
            )}
          </div>
        </div>

        {/* Details grid */}
        <div className="obj-body">
          <div className="obj-grid">
            {property.area_useful && (
              <div className="obj-f">
                <div className="obj-fl">Корисна площа</div>
                <div className="obj-fv">{property.area_useful} м²</div>
              </div>
            )}
            {property.area_total && (
              <div className="obj-f">
                <div className="obj-fl">Загальна площа</div>
                <div className="obj-fv">{property.area_total} м²</div>
              </div>
            )}
            {property.floor && (
              <div className="obj-f">
                <div className="obj-fl">Поверх</div>
                <div className="obj-fv">{property.floor}</div>
              </div>
            )}
            <div className="obj-f">
              <div className="obj-fl">Статус</div>
              <div className="obj-fv">
                <StatusBadge status={property.status} />
              </div>
            </div>
            {property.has_parking && (
              <div className="obj-f">
                <div className="obj-fl">Паркінг</div>
                <div className="obj-fv">{property.parking_spaces} місць</div>
              </div>
            )}
            {rent > 0 && (
              <div className="obj-f">
                <div className="obj-fl">Оренда</div>
                <div className="obj-fv">{formatPrice(rent)}/міс</div>
              </div>
            )}
          </div>
        </div>

        {/* Total */}
        {total > 0 && (
          <div className="glass-s" style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '11px 14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--t3)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.04em' }}>Разом на місяць</div>
                <div style={{ fontSize: 11, color: 'var(--t4)', marginTop: 2 }}>оренда + комунальні</div>
              </div>
              <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--t1)', letterSpacing: '-.02em' }}>
                {formatPrice(total)}
              </div>
            </div>
          </div>
        )}

        {/* Photo add */}
        <div className="over">Фотографії</div>
        <div className="photos-strip">
          {property.photos?.map((photo, i) => (
            <div
              key={photo.id}
              className="photo-t"
              onClick={() => navigate('photo-gallery', { propertyId: property.id, photoIndex: i })}
            >
              📷
            </div>
          ))}
          <div
            className="photo-t"
            onClick={() => navigate('photo-upload', { propertyId: property.id })}
            style={{ border: '.5px dashed rgba(255,255,255,.28)' }}
          >
            +
          </div>
        </div>

        <div style={{ height: 100 }} />
      </div>

      <button
        className="mbtn"
        onClick={() => navigate('sharing-analytics', { propertyId: property.id, dbId: screenParams.dbId })}
      >
        <IconShare size={18} />
        Поділитись
      </button>
    </div>
  )
}
