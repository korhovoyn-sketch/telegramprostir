'use client'

/* eslint-disable @next/next/no-img-element */
import { useEffect, useRef, } from 'react'
import { useAppStore } from '@/store/appStore'
import RetryState from '@/components/ui/RetryState'
import { hapticImpact, hapticNotify } from '@/lib/telegram'
import { offlineGuard } from '@/lib/offline'
import { confirmAction } from '@/lib/confirm'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import { StatusBadge } from '@/components/ui/Badge'
import { IconEdit, IconShare, IconMapPin, IconPhoto, IconX, IconCamera, IconRuler, IconBuildingSkyscraper, IconCircleCheck, IconCurrencyDollar, IconCarGarage, IconUser, IconKey, IconBolt, IconCalendar, IconFile, IconChevronRight } from '@/components/Icons'
import FilesList from '@/components/ui/FilesList'
import FloatingButton from '@/components/ui/FloatingButton'
import SpaceOrb, { type OrbStatus } from '@/components/ui/SpaceOrb'
import { formatPrice, calcRentUtils, computedRentUnit, parkingTypeLabel, STATUS_LABELS, STATUS_COLORS, formatLeasePeriod, photoUrl, daysUntil } from '@/lib/utils'
import { UTILITY_META } from '@/lib/utilityMeta'
import { supabase } from '@/lib/supabase'


export default function PropertyDetailScreen() {
  const { screenParams, navigate, user, showToast, databases } = useAppStore()
  const { properties, loading, error, loadSingleProperty, deletePhoto, updateProperty } = useProperties(screenParams.dbId)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const filesSectionRef = useRef<HTMLDivElement>(null)

  const property = properties.find(p => p.id === screenParams.propertyId)
  const memberDbIds = useAppStore(st => st.memberDbIds)
  // Власність рядка, а не роль акаунта — див. той самий шлюз у
  // DatabaseObjectsScreen. `property` ще може вантажитись: поки його немає,
  // поверхні редагування теж немає.
  const isOwner = (!!property && property.owner_id === user?.id)
    || memberDbIds.includes((screenParams.dbId as string) ?? '')
  const isGuest = user?.role === 'guest'

  // Fetch only this property on every mount — avoids loading the entire DB for detail view.
  // Component is remounted on every navigation so this fires exactly once per visit.
  useEffect(() => {
    if (screenParams.propertyId) loadSingleProperty(screenParams.propertyId)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [screenParams.propertyId])

  // АВТОФОКУСА НЕМА — рішення власника (див. той самий коментар у InviteSheet).
  // Затримка 400мс тут була правильна, але не усувала причини: фокус сам
  // підіймає клавіатуру, а та тягне за собою пробу `kbFallback` і два
  // паралельні transition геометрії шита. Клавіатура тепер зʼявляється лише
  // від явного тапу користувача в поле.

  // Scroll to files section when opened via the card's "Файли" quick action.
  // Delay lets the screen finish its enter animation and the section render.
  useEffect(() => {
    if (screenParams.scrollTo !== 'files' || !property) return
    const t = setTimeout(() => filesSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 350)
    return () => clearTimeout(t)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [property?.id])

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

  if (!property && error) return (
    <div className="scr bg-blue">
      <Header title="Об'єкт" backLabel="Назад" />
      <RetryState
        icon="🏚️"
        title="Об'єкт не знайдено"
        subtitle={<>Можливо, його видалили. {error}</>}
        onRetry={() => screenParams.propertyId && loadSingleProperty(screenParams.propertyId)}
      />
    </div>
  )

  if (!property || loading) return (
    <div className="scr bg-blue">
      <Header title="Об'єкт" backLabel="Назад" />
      <div className="loader-wrap">
        <div className="loader" />
      </div>
    </div>
  )

  const { rent, utils, total } = calcRentUtils(property.area_useful, property.area_total, property.rent_rate, property.rent_type, property.utilities_rate, property.area_basis)
  const isParking = databases.find(d => d.id === property.db_id)?.type === 'parking'
  // A daily rate can't be summed with a monthly utilities charge into a monthly
  // total — for per_day we show the line items but no combined "Разом на місяць".
  const isDaily = property.rent_type === 'per_day'
  const photos = property.photos ?? []

  function openGallery(index: number) {
    navigate('photo-gallery', { photos, initialIndex: index })
  }


  function handleFreeProperty() {
    if (!property) return
    if (offlineGuard()) return
    // Reversible action → no confirm modal: act immediately and offer undo
    // in the toast. Undo restores the exact previous tenant/lease fields.
    const prev = {
      status: property.status,
      tenant_name: property.tenant_name,
      lease_start_date: property.lease_start_date,
      lease_end_date: property.lease_end_date,
    }
    updateProperty(property.id, {
      status: 'free',
      tenant_name: null,
      lease_start_date: null,
      lease_end_date: null,
    }, { optimistic: true, silent: true })
    hapticNotify('success')
    showToast({
      type: 'success',
      title: 'Об\'єкт звільнено',
      actionLabel: 'Скасувати',
      onAction: () => {
        updateProperty(property.id, prev, { optimistic: true, silent: true })
        hapticImpact('light')
      },
    })
  }

  async function askDeletePhoto(photo: { id: string; path: string }) {
    const ok = await confirmAction({
      title: 'Видалити фото?',
      message: 'Фото буде видалено назавжди. Це незворотно.',
      confirmLabel: 'Видалити',
      destructive: true,
    })
    if (!ok || offlineGuard()) return
    try {
      await deletePhoto(photo.id, photo.path)
    } catch {
      showToast({ type: 'error', title: 'Не вдалося видалити фото' })
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
            onClick={() => { hapticImpact('light'); navigate('property-form', { propertyId: property.id, dbId: screenParams.dbId, editMode: true }) }}
            style={{ background: 'none', border: 'var(--bd)' }}
          >
            <IconEdit size={16} />
          </button>
        ) : <div className="hdr-sp" />}
      />

      <div className="body" style={{ animation: 'cascadeIn .2s ease both' }}>
        {/* Hero */}
        <div
          className={`obj-hero${photos.length > 0 ? '' : ' empty'}`}
          onClick={() => photos.length > 0 && openGallery(0)}
          style={{ cursor: photos.length > 0 ? 'pointer' : 'default' }}
        >
          {photos.length > 0 ? (
            <img
              src={photoUrl(photos[0].storage_path)}
              alt={property.name}
              style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover' }}
            />
          ) : (
            <SpaceOrb status={property.status as OrbStatus} />
          )}

          {/* Колір беремо з ЄДИНОГО джерела STATUS_COLORS: раніше пігулка була
              захардкоджено зелена для будь-якого статусу, крапка — з третьої
              палітри, а бейдж у сітці нижче показував ще інший колір. */}
          <div className="obj-hero-bdg" style={{ background: STATUS_COLORS[property.status].bg, color: STATUS_COLORS[property.status].color }}>
            <span className="fdot" style={{ background: STATUS_COLORS[property.status].color }} />
            {STATUS_LABELS[property.status]}
          </div>

          {/* For for_sale the bottom CTA is the share entry point — avoid a second one in the hero.
              Шаринг-аналітика керує токенами — лише справжній власник об'єкта. */}
          {property.owner_id === user?.id && property.status !== 'for_sale' && (
            <div className="obj-hero-r">
              <button
                className="obj-hero-a"
                aria-label="Поділитись об'єктом"
                onClick={(e) => { e.stopPropagation(); hapticImpact('light'); navigate('sharing-analytics', { propertyId: property.id, dbId: screenParams.dbId }) }}
              >
                <IconShare size={14} />
              </button>
            </div>
          )}

          {/* Name overlay is a photo caption; without a photo it only duplicates
              the header title, so show the meta bar only when there's a photo. */}
          {photos.length > 0 && (
            <div className="obj-hero-meta">
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="obj-hero-name">{property.name}</div>
              </div>
              <div className="obj-hero-photos" onClick={(e) => { e.stopPropagation(); openGallery(0) }}>
                <IconPhoto size={12} />
                {photos.length} фото
              </div>
            </div>
          )}
        </div>

        {/* Details grid */}
        <div className="glass-s" style={{ margin: '16px 12px 12px', borderRadius: 'var(--r-md)', padding: '14px' }}>
          <div className="obj-grid">
            {property.area_useful && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <IconRuler size={14} color="var(--info)" />{isParking ? 'Площа місця' : 'Корисна площа'}
                </div>
                <div className="obj-fv">{property.area_useful} м²</div>
              </div>
            )}
            {property.area_total && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <IconRuler size={14} color="var(--info)" />Розрахункова площа
                </div>
                <div className="obj-fv">{property.area_total} м²</div>
              </div>
            )}
            {property.floor && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <IconBuildingSkyscraper size={14} color="var(--violet)" />Поверх
                </div>
                <div className="obj-fv">{property.floor}</div>
              </div>
            )}
            <div className="obj-f">
              <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <IconCircleCheck size={14} color="#4ade80" />Статус
              </div>
              <div className="obj-fv">
                <StatusBadge status={property.status} />
              </div>
            </div>
            {property.has_parking && !isParking && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <IconCarGarage size={14} color="var(--warn)" />Паркінг
                </div>
                <div className="obj-fv">{property.parking_spaces} місць</div>
              </div>
            )}
            {parkingTypeLabel(property.parking_type) && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <IconCarGarage size={14} color="var(--warn)" />Тип місця
                </div>
                <div className="obj-fv">{parkingTypeLabel(property.parking_type)}</div>
              </div>
            )}
            {property.ev_charger && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <IconBolt size={14} color="#4ade80" />Зарядка EV
                </div>
                <div className="obj-fv">Є</div>
              </div>
            )}
            {rent > 0 && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <IconCurrencyDollar size={14} color="var(--ok-fg)" />Оренда
                </div>
                <div className="obj-fv">{formatPrice(rent, user?.currency)}{computedRentUnit(property.rent_type)}</div>
              </div>
            )}
            {property.sale_price != null && (
              <div className="obj-f">
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <IconCurrencyDollar size={14} color="var(--ok-fg)" />Ціна продажу
                </div>
                <div className="obj-fv">{formatPrice(property.sale_price, user?.currency)}</div>
              </div>
            )}
            {property.tenant_name && (
              <div className="obj-f" style={{ gridColumn: '1 / -1' }}>
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <IconUser size={14} color="var(--violet)" />Орендар
                </div>
                <div className="obj-fv">{property.tenant_name}</div>
              </div>
            )}
            {(property.lease_start_date || property.lease_end_date) && (
              // Останній рядок сітки — сидить на найсвітлішій ділянці екранного
              // градієнта (він темнішає догори), backdrop-filter карти семплить
              // саме її: підпис падав нижче WCAG AA (4.17:1). Темніший ґрунт —
              // той самий прийом, що вже підняв .obj-tot-l/v/sub.
              <div className="obj-f" style={{ gridColumn: '1 / -1', background: 'var(--glass-card)', borderRadius: 'var(--r-sm)', padding: '8px 10px', margin: '2px 0 -4px' }}>
                <div className="obj-fl" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <IconKey size={14} color="var(--violet)" />Строк договору
                </div>
                <div className="obj-fv">
                  {formatLeasePeriod(property.lease_start_date, property.lease_end_date)}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Address — tap opens Google Maps */}
        {property.address && (
          <div
            className="glass-s"
            style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}
            onClick={() => {
              const url = `https://maps.google.com/?q=${encodeURIComponent(property.address!)}`
              window.Telegram?.WebApp?.openLink?.(url)
            }}
          >
            <IconMapPin size={14} color="var(--info)" />
            <span style={{ fontSize: 'var(--fs-foot)', color: 'var(--t2)', flex: 1 }}>{property.address}</span>
            <IconChevronRight size={12} color="var(--t4)" />
          </div>
        )}

        {/* Utilities */}
        {(property.utilities ?? []).length > 0 && (
          <div style={{ margin: '0 12px 12px' }}>
            <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', fontWeight: 'var(--fw-semi)', textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 10 }}>Експлуатаційні послуги</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
              {(property.utilities ?? []).map(uid => {
                const meta = UTILITY_META.find(m => m.id === uid)
                if (!meta) return null
                return (
                  <div key={uid} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 13px', borderRadius: 'var(--r-pill)', background: 'var(--glass-2)', border: '.5px solid var(--glass-3)', fontSize: 'var(--fs-cap1)', fontWeight: 'var(--fw-med)', color: meta.color }}>
                    <meta.Icon size={14} />
                    {meta.label}
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Financial breakdown */}
        {total > 0 && (
          <div className="glass-s" style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '12px 14px' }}>
            <div style={{ fontSize: 'var(--fs-cap2)', color: 'var(--t3)', fontWeight: 'var(--fw-semi)', textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
              <IconCurrencyDollar size={12} color="var(--ok-fg)" />Фінанси
            </div>
            {rent > 0 && (
              <div className="cost-row">
                <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 24, height: 24, borderRadius: 8, background: 'var(--ok-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <IconKey size={12} color="var(--ok-fg)" />
                  </span>
                  Оренда
                </span>
                <span style={{ color: 'var(--ok-fg)', fontWeight: 'var(--fw-semi)' }}>{formatPrice(rent, user?.currency)}{computedRentUnit(property.rent_type)}</span>
              </div>
            )}
            {utils > 0 && (
              <div className="cost-row">
                <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 24, height: 24, borderRadius: 8, background: 'var(--warn-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <IconBolt size={12} color="#fbbf24" />
                  </span>
                  Експлуатаційні
                </span>
                <span style={{ color: 'var(--t2)', fontWeight: 'var(--fw-semi)' }}>+{formatPrice(utils, user?.currency)}/міс</span>
              </div>
            )}
            {!isDaily && rent > 0 && utils > 0 && (
              <div className="cost-row" style={{ marginTop: 4 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 'var(--fw-semi)', color: 'var(--t1)' }}>
                  <span style={{ width: 24, height: 24, borderRadius: 8, background: 'var(--info-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <IconCalendar size={12} color="var(--info)" />
                  </span>
                  Разом на місяць
                </span>
                <span className="cost-ttl">{formatPrice(total, user?.currency)}</span>
              </div>
            )}
            {!isDaily && (rent === 0 || utils === 0) && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 4 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--fs-cap1)', color: 'var(--t3)' }}>
                  <span style={{ width: 24, height: 24, borderRadius: 8, background: 'var(--info-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <IconCalendar size={12} color="var(--info)" />
                  </span>
                  Разом на місяць
                </span>
                <span className="cost-ttl">{formatPrice(total, user?.currency)}</span>
              </div>
            )}
          </div>
        )}

        {/* Гості — САМЕ власник рядка, не редактор команди. `isOwner` тут не
            годиться: він дає права й членам команди, а роздача доступу до
            обʼєкта — це рівень власника (так само гейтяться шаринг, гості й
            команда на рівні бази). Раніше редактор бачив цю картку, хоч
            DB-рівневий пункт «Управління гостями» від нього ховали. */}
        {property.owner_id === user?.id && (
          <div
            className="glass-s"
            style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '11px 14px', display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}
            onClick={() => { hapticImpact('light'); navigate('manage-guests', { propertyId: property.id }) }}
          >
            <IconUser size={16} color="var(--violet)" />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 'var(--fs-note)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)' }}>Гості</div>
              <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 1 }}>Запрошення та керування доступом</div>
            </div>
            <IconChevronRight size={12} color="var(--t4)" />
          </div>
        )}

        {/* Payment calendar shortcut — owner and guest, occupied property */}
        {(isOwner || isGuest) && property.status === 'occupied' && (
          <div
            className="glass-s"
            style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '11px 14px', display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}
            onClick={() => { hapticImpact('light'); navigate('payment-calendar', { propertyId: property.id, dbId: screenParams.dbId }) }}
          >
            <IconCalendar size={16} color="var(--info)" />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 'var(--fs-note)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)' }}>Календар платежів</div>
              <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 1 }}>Відстежувати та відмічати оплати</div>
            </div>
            <IconChevronRight size={12} color="var(--t4)" />
          </div>
        )}

        {/* Lease progress bar */}
        {property.status === 'occupied' && property.lease_start_date && property.lease_end_date && (() => {
          const start = new Date(property.lease_start_date).getTime()
          const end = new Date(property.lease_end_date).getTime()
          const now = Date.now()
          const progress = Math.min(100, Math.max(0, ((now - start) / (end - start)) * 100))
          const daysLeft = daysUntil(property.lease_end_date!)
          const barColor = daysLeft < 30 ? 'var(--warn)' : 'var(--ok-light)'
          return (
            <div className="glass-s" style={{ margin: '0 12px 12px', borderRadius: 'var(--r-md)', padding: '12px 14px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <span style={{ fontSize: 'var(--fs-cap2)', color: 'var(--t3)', fontWeight: 'var(--fw-semi)', textTransform: 'uppercase', letterSpacing: '.04em' }}>Договір оренди</span>
                <span style={{ fontSize: 'var(--fs-cap1)', color: daysLeft < 30 ? 'var(--warn)' : 'var(--t3)', fontWeight: 'var(--fw-semi)' }}>
                  {daysLeft > 0 ? `${daysLeft} дн.` : 'Завершено'}
                </span>
              </div>
              <div style={{ height: 4, borderRadius: 'var(--r-pill)', background: 'var(--glass-2)', overflow: 'hidden' }}>
                <div
                  className="anim-progress"
                  style={{ '--pw': `${progress}%`, height: '100%', borderRadius: 'var(--r-pill)', background: barColor } as React.CSSProperties}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6, fontSize: 'var(--fs-cap2)', color: 'var(--t4)' }}>
                <span>{property.lease_start_date}</span>
                <span>{property.lease_end_date}</span>
              </div>
            </div>
          )
        })()}

        {/* Photo strip with real images + delete + add */}
        <div className="over">
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <IconCamera size={14} color="var(--violet)" />
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
                  onClick={(e) => { e.stopPropagation(); hapticImpact('light'); void askDeletePhoto({ id: photo.id, path: photo.storage_path }) }}
                  style={{
                    position: 'absolute', top: 3, right: 3,
                    width: 20, height: 20, borderRadius: '50%',
                    background: 'rgba(0,0,0,.65)', border: 'none',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    color: 'var(--t1)', cursor: 'pointer', zIndex: 'var(--z-content)',
                  }}
                >
                  <IconX size={12} />
                </button>
              )}
            </div>
          ))}
          {isOwner && (
            <div
              className="photo-t"
              onClick={() => fileInputRef.current?.click()}
              style={{ border: '.5px dashed rgba(255,255,255,.28)', fontSize: 'var(--fs-t1)', color: 'var(--t4)', cursor: 'pointer' }}
            >
              +
            </div>
          )}
        </div>

        {isOwner && (
          <input
            aria-label="Додати фото"
            ref={fileInputRef}
            type="file"
            accept="image/*"
            multiple
            style={{ display: 'none' }}
            onChange={handleAddPhotos}
          />
        )}

        {/* Files section */}
        <div ref={filesSectionRef}>
          <FilesList propertyId={property.id} isOwner={isOwner} />
        </div>

        {property.description && (
          <>
            <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconFile size={14} color="var(--violet)" />Опис</span></div>
            <div className="descr glass-s">
              <div className="descr-t">{property.description}</div>
            </div>
          </>
        )}

        <div style={{ height: 100 }} />
      </div>

      {isOwner && property.status === 'free' && (
        <FloatingButton
          variant="success"
          icon={<IconKey size={16} />}
          label="Здати в оренду"
          onClick={() => {
            hapticImpact('light')
            // Префіл ставок робить САМ екран із рядка обʼєкта — передавати їх
            // через screenParams означало б тримати друге джерело правди.
            navigate('rent-property', { propertyId: property.id, dbId: property.db_id })
          }}
        />
      )}
      {isOwner && property.status === 'occupied' && (
        <FloatingButton
          variant="danger"
          icon={<IconCircleCheck size={16} />}
          label="Звільнити об'єкт"
          onClick={() => { hapticImpact('light'); handleFreeProperty() }}
        />
      )}
      {property.owner_id === user?.id && property.status === 'for_sale' && (
        <FloatingButton
          variant="info"
          icon={<IconShare size={16} />}
          label="Поділитись"
          onClick={() => { hapticImpact('light'); navigate('sharing-analytics', { propertyId: property.id, dbId: screenParams.dbId }) }}
        />
      )}


    </div>
  )
}
