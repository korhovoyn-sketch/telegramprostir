'use client'

/* eslint-disable @next/next/no-img-element */
import { useEffect, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import { StatusBadge } from '@/components/ui/Badge'
import { IconEdit, IconShare, IconMapPin, IconPhoto, IconX, IconCamera, IconRuler, IconLayers, IconActivity, IconCurrencyDollar, IconCarGarage } from '@/components/Icons'
import { formatPrice, calcRent, calcUtilities, STATUS_LABELS } from '@/lib/utils'
import { supabase } from '@/lib/supabase'

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL ?? ''

function photoUrl(path: string) {
  return `${SUPABASE_URL}/storage/v1/object/public/photos/${path}`
}

export default function PropertyDetailScreen() {
  const { screenParams, navigate, user } = useAppStore()
  const { properties, loadProperties, deletePhoto } = useProperties(screenParams.dbId)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const property = properties.find(p => p.id === screenParams.propertyId)

  useEffect(() => {
    if (!property && screenParams.dbId) loadProperties(screenParams.dbId)
  }, [property, screenParams.dbId, loadProperties])

  // Record a view once when the property first loads
  useEffect(() => {
    if (!property) return
    supabase.from('property_views').insert({
      property_id: property.id,
      viewer_id: user?.id ?? null,
      viewer_name: user ? `${user.first_name}${user.last_name ? ' ' + user.last_name : ''}` : null,
      action: 'view',
    }).then(() => {})
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [property?.id])

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
  const photos = property.photos ?? []

  function openGallery(index: number) {
    navigate('photo-gallery', { photos, initialIndex: index })
  }

  async function handleDeletePhoto(photoId: string, storagePath: string) {
    await deletePhoto(photoId, storagePath)
  }

  function handleAddPhotos(e: React.ChangeEvent<HTMLInputElement>) {
    const files = Array.from(e.target.files ?? [])
    if (files.length === 0) return
    e.target.value = ''
    navigate('photo-upload', { propertyId: property!.id, files })
  }

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
        <div className="obj-hero" onClick={() => photos.length > 0 && openGallery(0)} style={{ cursor: photos.length > 0 ? 'pointer' : 'default' }}>
          {photos.length > 0 ? (
            <img
              src={photoUrl(photos[0].storage_path)}
              alt={property.name}
              style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover' }}
            />
          ) : (
            <span>🏢</span>
          )}

          <div className="obj-hero-bdg">
            <span className="fdot" style={{ background: property.status === 'free' ? 'var(--ok)' : property.status === 'occupied' ? 'var(--err)' : 'var(--warn)' }} />
            {STATUS_LABELS[property.status]}
          </div>

          <div className="obj-hero-r">
            <button
              className="obj-hero-a"
              onClick={(e) => { e.stopPropagation(); navigate('sharing-analytics', { propertyId: property.id, dbId: screenParams.dbId }) }}
            >
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
            {photos.length > 0 && (
              <div className="obj-hero-photos" onClick={(e) => { e.stopPropagation(); openGallery(0) }}>
                <IconPhoto size={10} />
                {photos.length} фото
              </div>
            )}
          </div>
        </div>

        {/* Details grid */}
        <div className="glass-s" style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '14px' }}>
          <div className="obj-grid">
            {property.area_useful && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconRuler size={11} color="var(--t3)" />Корисна площа
                </div>
                <div className="obj-fv">{property.area_useful} м²</div>
              </div>
            )}
            {property.area_total && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconRuler size={11} color="var(--t3)" />Загальна площа
                </div>
                <div className="obj-fv">{property.area_total} м²</div>
              </div>
            )}
            {property.floor && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconLayers size={11} color="var(--t3)" />Поверх
                </div>
                <div className="obj-fv">{property.floor}</div>
              </div>
            )}
            <div className="obj-f">
              <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <IconActivity size={11} color="var(--t3)" />Статус
              </div>
              <div className="obj-fv">
                <StatusBadge status={property.status} />
              </div>
            </div>
            {property.has_parking && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconCarGarage size={11} color="var(--t3)" />Паркінг
                </div>
                <div className="obj-fv">{property.parking_spaces} місць</div>
              </div>
            )}
            {rent > 0 && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconCurrencyDollar size={11} color="var(--t3)" />Оренда
                </div>
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

        {/* Photo strip with real images + delete + add */}
        <div className="over" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <IconCamera size={13} color="var(--t3)" />
          Фотографії
        </div>
        <div className="photos-strip">
          {photos.map((photo, i) => (
            <div key={photo.id} className="photo-t" style={{ position: 'relative' }}>
              <img
                src={photoUrl(photo.storage_path)}
                alt=""
                style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                onClick={() => openGallery(i)}
              />
              <button
                onClick={(e) => { e.stopPropagation(); handleDeletePhoto(photo.id, photo.storage_path) }}
                style={{
                  position: 'absolute', top: 3, right: 3,
                  width: 20, height: 20, borderRadius: '50%',
                  background: 'rgba(0,0,0,.65)', border: 'none',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: '#fff', cursor: 'pointer', zIndex: 2,
                }}
              >
                <IconX size={10} />
              </button>
            </div>
          ))}
          <div
            className="photo-t"
            onClick={() => fileInputRef.current?.click()}
            style={{ border: '.5px dashed rgba(255,255,255,.28)', fontSize: 28, color: 'rgba(255,255,255,.4)', cursor: 'pointer' }}
          >
            +
          </div>
        </div>

        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          multiple
          style={{ display: 'none' }}
          onChange={handleAddPhotos}
        />

        {property.description && (
          <>
            <div className="over">Опис</div>
            <div className="glass-s" style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '12px 14px' }}>
              <p style={{ margin: 0, fontSize: 14, color: 'var(--t2)', lineHeight: 1.55 }}>
                {property.description}
              </p>
            </div>
          </>
        )}

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
