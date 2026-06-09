'use client'

/* eslint-disable @next/next/no-img-element */
import { useEffect, useRef, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import Modal from '@/components/ui/Modal'
import { StatusBadge } from '@/components/ui/Badge'
import { IconEdit, IconShare, IconMapPin, IconPhoto, IconX, IconCamera, IconRuler, IconBuildingSkyscraper, IconCircleCheck, IconCurrencyDollar, IconCarGarage, IconUser, IconKey, IconBolt, IconDroplet, IconFlame, IconThermometer, IconBatteryCharging, IconCalendar } from '@/components/Icons'
import FilesList from '@/components/ui/FilesList'
import { formatPrice, calcRent, calcUtilities, STATUS_LABELS, formatLeasePeriod } from '@/lib/utils'
import { supabase } from '@/lib/supabase'

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL ?? ''

function photoUrl(path: string) {
  return `${SUPABASE_URL}/storage/v1/object/public/photos/${path}`
}

function Building3DHero() {
  return (
    <svg viewBox="0 0 160 150" width="136" height="126" style={{ overflow: 'visible' }}>
      <style>{`
        @keyframes b3dFloat { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-9px)} }
        @keyframes b3dWinA  { 0%,82%,100%{opacity:.78} 88%{opacity:.15} }
        @keyframes b3dWinB  { 0%,68%,100%{opacity:.48} 74%{opacity:.92} }
        @keyframes b3dWinC  { 0%,56%,100%{opacity:.65} 62%{opacity:.18} }
        @keyframes b3dSpark { 0%,100%{opacity:0} 50%{opacity:1} }
        .b3d-g{animation:b3dFloat 3.8s ease-in-out infinite;transform-origin:80px 112px}
        .b3d-wa{animation:b3dWinA 5.2s .3s ease-in-out infinite}
        .b3d-wb{animation:b3dWinB 5.2s 1.1s ease-in-out infinite}
        .b3d-wc{animation:b3dWinC 5.2s 2.0s ease-in-out infinite}
        .b3d-wd{animation:b3dWinA 5.2s 2.8s ease-in-out infinite}
        .b3d-s1{animation:b3dSpark 2.6s 0s ease-in-out infinite}
        .b3d-s2{animation:b3dSpark 2.6s .9s ease-in-out infinite}
        .b3d-s3{animation:b3dSpark 2.6s 1.7s ease-in-out infinite}
      `}</style>
      <defs>
        <linearGradient id="b3dFr" x1="0" y1="0" x2=".08" y2="1">
          <stop offset="0%" stopColor="#4E87E8"/><stop offset="100%" stopColor="#1C3F8E"/>
        </linearGradient>
        <linearGradient id="b3dSd" x1="0" y1="0" x2="1" y2=".15">
          <stop offset="0%" stopColor="#1C3F8E"/><stop offset="100%" stopColor="#0B2362"/>
        </linearGradient>
        <linearGradient id="b3dTp" x1="0" y1="1" x2="1" y2="0">
          <stop offset="0%" stopColor="#3A70D4"/><stop offset="100%" stopColor="#61A0F0"/>
        </linearGradient>
      </defs>

      <g className="b3d-g">
        {/* Top face */}
        <polygon points="46,50 110,50 132,36 68,36" fill="url(#b3dTp)"/>

        {/* Front face */}
        <rect x="46" y="50" width="64" height="70" fill="url(#b3dFr)"/>

        {/* Right side face */}
        <polygon points="110,50 132,36 132,106 110,120" fill="url(#b3dSd)"/>

        {/* Rooftop antenna */}
        <rect x="83" y="28" width="3.5" height="10" fill="rgba(160,200,255,.65)" rx="1"/>
        <circle cx="84.75" cy="27" r="2.5" fill="rgba(180,220,255,.85)"/>

        {/* Left edge highlight */}
        <line x1="46" y1="50" x2="46" y2="120" stroke="rgba(255,255,255,.2)" strokeWidth="1.5"/>
        <line x1="46" y1="50" x2="110" y2="50" stroke="rgba(255,255,255,.24)" strokeWidth="1"/>

        {/* Front windows — row 1 */}
        <rect className="b3d-wa" x="53" y="59" width="13" height="13" rx="2" fill="rgba(165,215,255,.82)"/>
        <rect className="b3d-wb" x="72" y="59" width="13" height="13" rx="2" fill="rgba(165,215,255,.52)"/>
        <rect className="b3d-wc" x="91" y="59" width="13" height="13" rx="2" fill="rgba(165,215,255,.76)"/>

        {/* Front windows — row 2 */}
        <rect className="b3d-wd" x="53" y="77" width="13" height="13" rx="2" fill="rgba(165,215,255,.44)"/>
        <rect className="b3d-wa" x="72" y="77" width="13" height="13" rx="2" fill="rgba(165,215,255,.86)"/>
        <rect className="b3d-wb" x="91" y="77" width="13" height="13" rx="2" fill="rgba(165,215,255,.38)"/>

        {/* Front windows — row 3 */}
        <rect className="b3d-wc" x="53" y="95" width="13" height="13" rx="2" fill="rgba(165,215,255,.7)"/>
        <rect x="72"  y="95" width="13" height="13" rx="2" fill="rgba(165,215,255,.22)"/>
        <rect className="b3d-wd" x="91" y="95" width="13" height="13" rx="2" fill="rgba(165,215,255,.62)"/>

        {/* Side face windows */}
        <rect className="b3d-wb" x="115" y="55" width="9" height="12" rx="1.5" fill="rgba(120,175,240,.48)"/>
        <rect className="b3d-wc" x="115" y="73" width="9" height="12" rx="1.5" fill="rgba(120,175,240,.62)"/>
        <rect x="115" y="91" width="9" height="12" rx="1.5" fill="rgba(120,175,240,.28)"/>

        {/* Ground floor + door */}
        <rect x="46" y="108" width="64" height="12" fill="rgba(12,28,72,.7)"/>
        <rect x="70" y="108" width="18" height="12" fill="rgba(18,36,90,.9)" rx="1"/>

        {/* Ground floor edge */}
        <line x1="46" y1="120" x2="110" y2="120" stroke="rgba(255,255,255,.07)" strokeWidth="1"/>
      </g>

      {/* Sparkle stars */}
      <g className="b3d-s1">
        <path d="M22,46 L23.4,49.6 L27,50.5 L23.4,51.4 L22,55 L20.6,51.4 L17,50.5 L20.6,49.6Z" fill="#a78bfa"/>
      </g>
      <g className="b3d-s2">
        <path d="M140,60 L141.2,63 L144,63.7 L141.2,64.4 L140,67.4 L138.8,64.4 L136,63.7 L138.8,63Z" fill="#7AB3FF"/>
      </g>
      <g className="b3d-s3">
        <path d="M16,88 L17,90.6 L19.6,91.2 L17,91.8 L16,94.4 L15,91.8 L12.4,91.2 L15,90.6Z" fill="#c4b5fd"/>
      </g>
    </svg>
  )
}

export default function PropertyDetailScreen() {
  const { screenParams, navigate, user, showToast } = useAppStore()
  const { properties, loadSingleProperty, deletePhoto, updateProperty } = useProperties(screenParams.dbId)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [photoToDelete, setPhotoToDelete] = useState<{ id: string; path: string } | null>(null)
  const [showRentModal, setShowRentModal] = useState(false)
  const [rentTenantName, setRentTenantName] = useState('')
  const [rentLeaseStart, setRentLeaseStart] = useState('')
  const [rentLeaseEnd, setRentLeaseEnd] = useState('')
  const [rentRentRate, setRentRentRate] = useState('')
  const [rentUtilitiesRate, setRentUtilitiesRate] = useState('')
  const [rentSaving, setRentSaving] = useState(false)
  const [showFreeModal, setShowFreeModal] = useState(false)
  const [freeSaving, setFreeSaving] = useState(false)

  const property = properties.find(p => p.id === screenParams.propertyId)
  const isOwner = user?.role === 'owner'

  // Fetch only this property on every mount — avoids loading the entire DB for detail view.
  // Component is remounted on every navigation so this fires exactly once per visit.
  useEffect(() => {
    if (screenParams.propertyId) loadSingleProperty(screenParams.propertyId)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [screenParams.propertyId])

  // Record a view exactly once per session mount
  const viewRecorded = useRef(false)
  useEffect(() => {
    if (!property || viewRecorded.current) return
    viewRecorded.current = true
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

  async function handleRentOut() {
    if (!rentTenantName.trim() || !property) return
    setRentSaving(true)
    const parsedRate = parseFloat(rentRentRate)
    const parsedUtils = parseFloat(rentUtilitiesRate)
    await updateProperty(property.id, {
      status: 'occupied',
      tenant_name: rentTenantName.trim(),
      lease_start_date: rentLeaseStart || undefined,
      lease_end_date: rentLeaseEnd || undefined,
      ...(isFinite(parsedRate) && parsedRate >= 0 ? { rent_rate: parsedRate } : {}),
      ...(isFinite(parsedUtils) && parsedUtils >= 0 ? { utilities_rate: parsedUtils } : {}),
    })
    window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
    showToast({ type: 'success', title: 'Об\'єкт здано в оренду' })
    setShowRentModal(false)
    setRentTenantName('')
    setRentLeaseStart('')
    setRentLeaseEnd('')
    setRentRentRate('')
    setRentUtilitiesRate('')
    setRentSaving(false)
  }

  async function handleFreeProperty() {
    if (!property) return
    setFreeSaving(true)
    await updateProperty(property.id, {
      status: 'free',
      tenant_name: null,
      lease_start_date: null,
      lease_end_date: null,
    })
    window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('success')
    showToast({ type: 'success', title: 'Об\'єкт звільнено' })
    setShowFreeModal(false)
    setFreeSaving(false)
  }

  async function confirmDeletePhoto() {
    if (!photoToDelete) return
    try {
      await deletePhoto(photoToDelete.id, photoToDelete.path)
    } catch {
      showToast({ type: 'error', title: 'Не вдалося видалити фото' })
    } finally {
      setPhotoToDelete(null)
    }
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
        right={isOwner ? (
          <button
            className="hdr-a"
            aria-label="Редагувати об'єкт"
            onClick={() => navigate('property-form', { propertyId: property.id, dbId: screenParams.dbId, editMode: true })}
            style={{ background: 'none', border: 'var(--bd)' }}
          >
            <IconEdit size={15} />
          </button>
        ) : <div className="hdr-sp" />}
      />

      <div className="body">
        {/* Hero */}
        <div className="obj-hero" onClick={() => photos.length > 0 && openGallery(0)} style={{ cursor: photos.length > 0 ? 'pointer' : 'default', background: photos.length > 0 ? undefined : 'rgba(255,255,255,.04)', backdropFilter: photos.length > 0 ? undefined : 'blur(28px) saturate(170%)', WebkitBackdropFilter: photos.length > 0 ? undefined : 'blur(28px) saturate(170%)' }}>
          {photos.length > 0 ? (
            <img
              src={photoUrl(photos[0].storage_path)}
              alt={property.name}
              style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover' }}
            />
          ) : (
            <Building3DHero />
          )}

          <div className="obj-hero-bdg">
            <span className="fdot" style={{ background: property.status === 'free' ? 'var(--ok)' : property.status === 'occupied' ? 'var(--err)' : 'var(--warn)' }} />
            {STATUS_LABELS[property.status]}
          </div>

          {isOwner && (
            <div className="obj-hero-r">
              <button
                className="obj-hero-a"
                aria-label="Поділитись об'єктом"
                onClick={(e) => { e.stopPropagation(); navigate('sharing-analytics', { propertyId: property.id, dbId: screenParams.dbId }) }}
              >
                <IconShare size={14} />
              </button>
            </div>
          )}

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
        <div className="glass-s" style={{ margin: '16px 12px 12px', borderRadius: 'var(--r-md)', padding: '14px' }}>
          <div className="obj-grid">
            {property.area_useful && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconRuler size={13} color="#7AB3FF" />Корисна площа
                </div>
                <div className="obj-fv">{property.area_useful} м²</div>
              </div>
            )}
            {property.area_total && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconRuler size={13} color="#7AB3FF" />Загальна площа
                </div>
                <div className="obj-fv">{property.area_total} м²</div>
              </div>
            )}
            {property.floor && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconBuildingSkyscraper size={13} color="#a78bfa" />Поверх
                </div>
                <div className="obj-fv">{property.floor}</div>
              </div>
            )}
            <div className="obj-f">
              <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <IconCircleCheck size={13} color="#4ade80" />Статус
              </div>
              <div className="obj-fv">
                <StatusBadge status={property.status} />
              </div>
            </div>
            {property.has_parking && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconCarGarage size={13} color="#fb923c" />Паркінг
                </div>
                <div className="obj-fv">{property.parking_spaces} місць</div>
              </div>
            )}
            {rent > 0 && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconCurrencyDollar size={13} color="#4ade80" />Оренда
                </div>
                <div className="obj-fv">{formatPrice(rent, user?.currency)}/міс</div>
              </div>
            )}
            {property.sale_price != null && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconCurrencyDollar size={13} color="#fbbf24" />Ціна продажу
                </div>
                <div className="obj-fv">{formatPrice(property.sale_price, user?.currency)}</div>
              </div>
            )}
            {property.tenant_name && (
              <div className="obj-f" style={{ gridColumn: '1 / -1' }}>
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconUser size={13} color="#a78bfa" />Орендар
                </div>
                <div className="obj-fv">{property.tenant_name}</div>
              </div>
            )}
            {(property.lease_start_date || property.lease_end_date) && (
              <div className="obj-f" style={{ gridColumn: '1 / -1' }}>
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <IconKey size={13} color="#a78bfa" />Строк договору
                </div>
                <div className="obj-fv">
                  {formatLeasePeriod(property.lease_start_date, property.lease_end_date)}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Address */}
        {property.address && (
          <div className="glass-s" style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 8 }}>
            <IconMapPin size={14} color="#7AB3FF" />
            <span style={{ fontSize: 13, color: 'var(--t2)' }}>{property.address}</span>
          </div>
        )}

        {/* Utilities */}
        {(property.utilities ?? []).length > 0 && (() => {
          const UTIL_META: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
            electricity: { label: 'Електропостачання', icon: <IconBolt size={13} />, color: '#fbbf24' },
            water:       { label: 'Водопостачання',    icon: <IconDroplet size={13} />, color: '#7AB3FF' },
            heating:     { label: 'Теплопостачання',   icon: <IconThermometer size={13} />, color: '#fb923c' },
            gas:         { label: 'Газопостачання',    icon: <IconFlame size={13} />, color: '#4ade80' },
            backup:      { label: 'Резервне живлення', icon: <IconBatteryCharging size={13} />, color: '#a78bfa' },
          }
          return (
            <div style={{ margin: '0 12px 12px' }}>
              <div style={{ fontSize: 12, color: 'var(--t3)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 8 }}>Комунальні послуги</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {(property.utilities ?? []).map(uid => {
                  const meta = UTIL_META[uid]
                  if (!meta) return null
                  return (
                    <div key={uid} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '5px 12px', borderRadius: 'var(--r-pill)', background: 'var(--glass-2)', border: '.5px solid var(--glass-3)', fontSize: 12, fontWeight: 500, color: meta.color }}>
                      {meta.icon}
                      {meta.label}
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })()}

        {/* Total */}
        {total > 0 && (
          <div className="glass-s" style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '11px 14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: 12, color: 'var(--t3)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.04em' }}>Разом на місяць</div>
                <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 2 }}>оренда + комунальні</div>
              </div>
              <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--t1)', letterSpacing: '-.02em' }}>
                {formatPrice(total, user?.currency)}
              </div>
            </div>
          </div>
        )}

        {/* Payment calendar shortcut — owner only, occupied property */}
        {isOwner && property.status === 'occupied' && (
          <div
            className="glass-s"
            style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '11px 14px', display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}
            onClick={() => navigate('payment-calendar', { propertyId: property.id, dbId: screenParams.dbId })}
          >
            <IconCalendar size={16} color="#7AB3FF" />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--t1)' }}>Календар платежів</div>
              <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 1 }}>Відстежувати та відмічати оплати</div>
            </div>
            <svg width="7" height="12" viewBox="0 0 7 12" fill="none"><path d="M1 1l5 5-5 5" stroke="rgba(255,255,255,.3)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
          </div>
        )}

        {/* Photo strip with real images + delete + add */}
        <div className="over">
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <IconCamera size={14} color="#a78bfa" />
            Фотографії
          </span>
        </div>
        <div className="photos-strip">
          {photos.map((photo, i) => (
            <div key={photo.id} className="photo-t" style={{ position: 'relative' }}>
              <img
                src={photoUrl(photo.storage_path)}
                alt=""
                loading="lazy"
                style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                onClick={() => openGallery(i)}
              />
              {isOwner && (
                <button
                  aria-label="Видалити фото"
                  onClick={(e) => { e.stopPropagation(); setPhotoToDelete({ id: photo.id, path: photo.storage_path }) }}
                  style={{
                    position: 'absolute', top: 3, right: 3,
                    width: 20, height: 20, borderRadius: '50%',
                    background: 'rgba(0,0,0,.65)', border: 'none',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    color: 'var(--t1)', cursor: 'pointer', zIndex: 2,
                  }}
                >
                  <IconX size={10} />
                </button>
              )}
            </div>
          ))}
          {isOwner && (
            <div
              className="photo-t"
              onClick={() => fileInputRef.current?.click()}
              style={{ border: '.5px dashed rgba(255,255,255,.28)', fontSize: 28, color: 'rgba(255,255,255,.4)', cursor: 'pointer' }}
            >
              +
            </div>
          )}
        </div>

        {isOwner && (
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            multiple
            style={{ display: 'none' }}
            onChange={handleAddPhotos}
          />
        )}

        {/* Files section */}
        <FilesList propertyId={property.id} isOwner={isOwner} />

        {property.description && (
          <>
            <div className="over">Опис</div>
            <div className="descr glass-s">
              <div className="descr-t">{property.description}</div>
            </div>
          </>
        )}

        <div style={{ height: 100 }} />
      </div>

      {isOwner && property.status === 'free' && (
        <button
          style={{
            position: 'absolute', bottom: 'calc(14px + var(--safe-bottom))',
            left: '50%', transform: 'translateX(-50%)',
            height: 'var(--btn-h)', padding: '0 32px', minWidth: 200,
            borderRadius: 'var(--r-pill)', whiteSpace: 'nowrap',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            fontSize: 15, fontWeight: 600, color: '#fff', cursor: 'pointer',
            background: 'rgba(74,219,122,.18)',
            border: '.5px solid rgba(74,219,122,.42)',
            backdropFilter: 'blur(16px) saturate(180%)',
            WebkitBackdropFilter: 'blur(16px) saturate(180%)',
            boxShadow: '0 4px 24px rgba(74,219,122,.22), inset 0 1px 0 rgba(255,255,255,.18)',
            zIndex: 20,
          }}
          onClick={() => {
            setRentTenantName('')
            setRentLeaseStart('')
            setRentLeaseEnd('')
            setRentRentRate(property.rent_rate != null ? String(property.rent_rate) : '')
            setRentUtilitiesRate(property.utilities_rate != null ? String(property.utilities_rate) : '')
            setShowRentModal(true)
          }}
        >
          <IconKey size={16} />
          Здати в оренду
        </button>
      )}
      {isOwner && property.status === 'occupied' && (
        <button
          style={{
            position: 'absolute', bottom: 'calc(14px + var(--safe-bottom))',
            left: '50%', transform: 'translateX(-50%)',
            height: 'var(--btn-h)', padding: '0 32px', minWidth: 200,
            borderRadius: 'var(--r-pill)', whiteSpace: 'nowrap',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            fontSize: 15, fontWeight: 600, color: '#fff', cursor: 'pointer',
            background: 'rgba(255,107,97,.16)',
            border: '.5px solid rgba(255,107,97,.38)',
            backdropFilter: 'blur(16px) saturate(180%)',
            WebkitBackdropFilter: 'blur(16px) saturate(180%)',
            boxShadow: '0 4px 24px rgba(255,107,97,.18), inset 0 1px 0 rgba(255,255,255,.15)',
            zIndex: 20,
          }}
          onClick={() => setShowFreeModal(true)}
        >
          <IconCircleCheck size={16} />
          Звільнити об&apos;єкт
        </button>
      )}
      {isOwner && property.status === 'for_sale' && (
        <button
          style={{
            position: 'absolute', bottom: 'calc(14px + var(--safe-bottom))',
            left: '50%', transform: 'translateX(-50%)',
            height: 'var(--btn-h)', padding: '0 32px', minWidth: 200,
            borderRadius: 'var(--r-pill)', whiteSpace: 'nowrap',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            fontSize: 15, fontWeight: 600, color: '#fff', cursor: 'pointer',
            background: 'rgba(42,171,238,.15)',
            border: '.5px solid rgba(42,171,238,.35)',
            backdropFilter: 'blur(16px) saturate(180%)',
            WebkitBackdropFilter: 'blur(16px) saturate(180%)',
            boxShadow: '0 4px 24px rgba(42,171,238,.18), inset 0 1px 0 rgba(255,255,255,.18)',
            zIndex: 20,
          }}
          onClick={() => navigate('sharing-analytics', { propertyId: property.id })}
        >
          <IconShare size={16} />
          Поділитись
        </button>
      )}

      {photoToDelete && (
        <Modal
          title="Видалити фото?"
          subtitle="Фото буде видалено назавжди. Це незворотно."
          onClose={() => setPhotoToDelete(null)}
          actions={[
            { label: 'Видалити', variant: 'danger', onClick: confirmDeletePhoto },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setPhotoToDelete(null) },
          ]}
        />
      )}

      {showFreeModal && (
        <Modal
          title="Звільнити об'єкт?"
          subtitle={property.tenant_name ? `Орендар "${property.tenant_name}" та дати договору будуть видалені.` : 'Об\'єкт отримає статус "Вільно".'}
          onClose={() => !freeSaving && setShowFreeModal(false)}
          actions={[
            { label: freeSaving ? 'Збереження...' : 'Звільнити', variant: 'danger', disabled: freeSaving, onClick: handleFreeProperty },
            { label: 'Скасувати', variant: 'secondary', disabled: freeSaving, onClick: () => setShowFreeModal(false) },
          ]}
        />
      )}

      {showRentModal && (
        <Modal
          title="Здати в оренду"
          subtitle={property.name}
          onClose={() => setShowRentModal(false)}
          actions={[
            {
              label: rentSaving ? 'Збереження...' : 'Здати',
              variant: 'primary',
              disabled: rentSaving || !rentTenantName.trim(),
              onClick: handleRentOut,
            },
            { label: 'Скасувати', variant: 'secondary', disabled: rentSaving, onClick: () => setShowRentModal(false) },
          ]}
        >
          {(() => {
            const rateVal = parseFloat(rentRentRate)
            const utilVal = parseFloat(rentUtilitiesRate)
            const previewRent = isFinite(rateVal) && rateVal > 0 && property.area_useful
              ? calcRent(property.area_useful, rateVal, property.rent_type)
              : 0
            const previewUtils = isFinite(utilVal) && utilVal > 0 && property.area_total
              ? calcUtilities(property.area_total, utilVal)
              : 0
            const previewTotal = previewRent + previewUtils
            const rateLabel = property.rent_type === 'fixed' ? 'Ставка оренди ($/міс)' : 'Ставка оренди ($/м²)'

            return (
              <div className="fg" style={{ margin: '12px 0 4px' }}>
                <div className="fr">
                  <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <IconUser size={13} color="var(--t3)" />Орендар
                  </span>
                  <input
                    className="fr-i"
                    placeholder="ТОВ «Назва» або ФОП Іванов"
                    value={rentTenantName}
                    onChange={e => setRentTenantName(e.target.value)}
                    autoFocus
                  />
                </div>
                <div className="fr">
                  <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <IconCurrencyDollar size={13} color="var(--t3)" />{rateLabel}
                  </span>
                  <input
                    className="fr-i"
                    type="number"
                    inputMode="decimal"
                    placeholder="0"
                    value={rentRentRate}
                    onChange={e => setRentRentRate(e.target.value)}
                  />
                </div>
                <div className="fr">
                  <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <IconBolt size={13} color="var(--t3)" />Комунальні ($/м²)
                  </span>
                  <input
                    className="fr-i"
                    type="number"
                    inputMode="decimal"
                    placeholder="0"
                    value={rentUtilitiesRate}
                    onChange={e => setRentUtilitiesRate(e.target.value)}
                  />
                </div>
                {previewTotal > 0 && (
                  <div style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '8px 12px', borderRadius: 'var(--r-sm)',
                    background: 'rgba(74,222,128,.08)', border: '.5px solid rgba(74,222,128,.2)',
                    marginTop: 4,
                  }}>
                    <span style={{ fontSize: 12, color: 'var(--t3)' }}>
                      Разом на місяць
                      {previewRent > 0 && previewUtils > 0 && (
                        <span style={{ display: 'block', fontSize: 11, color: 'var(--t4)' }}>
                          оренда + комунальні
                        </span>
                      )}
                    </span>
                    <span style={{ fontSize: 18, fontWeight: 700, color: '#4ade80' }}>
                      {formatPrice(previewTotal, user?.currency)}
                    </span>
                  </div>
                )}
                <div className="fr">
                  <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <IconKey size={13} color="var(--t3)" />Договір з
                  </span>
                  <input
                    className="fr-i"
                    type="date"
                    value={rentLeaseStart}
                    onChange={e => setRentLeaseStart(e.target.value)}
                    style={{ colorScheme: 'dark' }}
                  />
                </div>
                <div className="fr">
                  <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <IconKey size={13} color="var(--t3)" />Договір до
                  </span>
                  <input
                    className="fr-i"
                    type="date"
                    value={rentLeaseEnd}
                    onChange={e => setRentLeaseEnd(e.target.value)}
                    style={{ colorScheme: 'dark' }}
                  />
                </div>
              </div>
            )
          })()}
        </Modal>
      )}
    </div>
  )
}
