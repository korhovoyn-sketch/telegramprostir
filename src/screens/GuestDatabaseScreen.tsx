'use client'

import { useEffect, useState } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { DB_TYPE_LABELS } from '@/lib/utils'
import { IconBuilding, IconRuler, IconCurrencyDollar } from '@/components/Icons'

// Public DB preview (realtor flow)
interface PreviewRow {
  db_id: string
  db_name: string
  db_type: string
  db_color: string
  share_expires_at: string | null
  property_id: string | null
  property_name: string | null
  property_status: string | null
  property_floor: string | null
  property_area_useful: number | null
  property_area_total: number | null
  property_rent_type: string | null
  property_rent_rate: number | null
  property_description: string | null
}

// Guest invite preview (guest flow)
interface GuestPreview {
  type: 'property' | 'database'
  status: 'pending' | 'active' | 'revoked'
  owner_first: string
  property?: {
    id: string
    name: string
    status: string
    floor: string | null
    area_useful: number | null
    area_total: number | null
    description: string | null
    db_name: string
    db_type: string
    db_color: string
  }
  database?: {
    id: string
    name: string
    type: string
    color: string
  }
  properties?: Array<{
    id: string
    name: string
    status: string
    floor: string | null
    area_useful: number | null
    area_total: number | null
  }>
}

const STATUS_LABELS: Record<string, string> = {
  free: 'Вільно',
  occupied: 'Зайнято',
  for_sale: 'Продаж',
}

const STATUS_BADGE_CLS: Record<string, string> = {
  free: 'bdg-ok',
  occupied: 'bdg-busy',
  for_sale: 'bdg-sale',
}

export default function GuestDatabaseScreen() {
  const { screenParams, back } = useAppStore()
  const { loginViaTelegram } = useAuth()
  const token = (screenParams.token as string | undefined) ?? ''
  const guestMode = !!(screenParams.guestMode as boolean | undefined)

  const [rows, setRows] = useState<PreviewRow[]>([])
  const [guestPreview, setGuestPreview] = useState<GuestPreview | null>(null)
  const [loading, setLoading] = useState(true)
  const [ctaLoading, setCtaLoading] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  useEffect(() => {
    if (!token) {
      setErrorMsg('Недійсне посилання')
      setLoading(false)
      return
    }

    async function load() {
      setLoading(true)
      setErrorMsg(null)
      try {
        if (guestMode) {
          // Guest invite preview
          const { data, error } = await supabase.rpc('get_guest_property_preview', { p_token: token })
          if (error) { setErrorMsg('Не вдалося завантажити дані'); return }
          const preview = data as GuestPreview | null
          if (!preview) { setErrorMsg('Запрошення не знайдено або відкликано'); return }
          if (preview.status === 'revoked') { setErrorMsg('Це запрошення відкликано власником'); return }
          setGuestPreview(preview)
        } else {
          // Realtor public DB preview
          const { data, error } = await supabase.rpc('get_public_db_preview', { p_token: token })
          if (error) { setErrorMsg('Не вдалося завантажити дані'); return }
          const result = (data ?? []) as PreviewRow[]
          if (result.length === 0) { setErrorMsg('База не знайдена або посилання застаріло'); return }
          setRows(result)
        }
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [token, guestMode])

  function handleClose() {
    const tg = window.Telegram?.WebApp
    if (tg) tg.close()
    else back()
  }

  async function handleJoin() {
    const initData = window.Telegram?.WebApp?.initData
    if (!initData) return
    setCtaLoading(true)
    if (!guestMode) {
      // Realtor flow: save token to localStorage so useDeepLink picks it up after auth
      localStorage.setItem('ps_guest_join_token', `db_${token}`)
    }
    // Guest flow: start_param is still `guest_<token>` — useDeepLink handles it automatically
    await loginViaTelegram(initData)
    setCtaLoading(false)
  }

  const dbInfo = rows[0] ?? null
  const properties = rows.filter((r) => r.property_id !== null)

  if (loading) {
    return (
      <div className="scr bg-purple" style={{ alignItems: 'center', justifyContent: 'center' }}>
        <div className="loader" />
      </div>
    )
  }

  if (errorMsg) {
    const isLinkProblem = errorMsg.includes('не знайден') || errorMsg.includes('застаріло') || errorMsg.includes('Недійсне') || errorMsg.includes('відкликано')
    return (
      <div className="scr bg-purple">
        <div className="hdr">
          <button className="hdr-back" onClick={handleClose}>✕ Закрити</button>
          <div className="hdr-t">{guestMode ? 'Запрошення' : 'Перегляд бази'}</div>
        </div>
        <div className="empty-state" style={{ paddingTop: 60 }}>
          <div className="empty-ic">{isLinkProblem ? '🔗' : '⚠️'}</div>
          <div className="empty-h">{isLinkProblem ? 'Посилання недійсне' : 'Помилка завантаження'}</div>
          <div className="empty-s">
            {isLinkProblem
              ? 'Посилання застаріло, видалено або відкликано. Зверніться до власника.'
              : 'Не вдалося завантажити дані. Перевірте підключення.'}
          </div>
          <button
            style={{ marginTop: 20, padding: '10px 24px', borderRadius: 'var(--r-pill)', background: 'var(--glass-2)', border: 'var(--bd)', color: 'var(--t2)', fontSize: 14, cursor: 'pointer' }}
            onClick={handleClose}
          >
            Закрити
          </button>
        </div>
      </div>
    )
  }

  // ── Guest invite preview ────────────────────────────────────────────────────
  if (guestMode && guestPreview) {
    const isProperty = guestPreview.type === 'property'
    const p = guestPreview.property
    const d = guestPreview.database
    const dbColor = isProperty ? p?.db_color : d?.color

    return (
      <div className="scr bg-teal">
        <div className="hdr">
          <button className="hdr-back" onClick={handleClose}>✕ Закрити</button>
          <div className="hdr-t">Запрошення</div>
        </div>

        <div className="body" style={{ paddingBottom: 96 }}>
          {/* Invite header */}
          <div className="glass" style={{ margin: '12px 12px 8px', padding: '16px' }}>
            <div style={{ fontSize: 13, color: 'var(--t3)', marginBottom: 6 }}>
              {guestPreview.owner_first} надає вам доступ до:
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 40, height: 40, borderRadius: 12, flexShrink: 0,
                background: dbColor
                  ? `linear-gradient(135deg, ${dbColor}, ${dbColor}99)`
                  : 'linear-gradient(135deg,#0e9c92,#0a7a72)',
              }} />
              <div>
                <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--t1)' }}>
                  {isProperty ? p?.name : d?.name}
                </div>
                <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 2 }}>
                  {isProperty
                    ? (p?.db_type ? (DB_TYPE_LABELS[p.db_type] ?? p.db_type) : '')
                    : (d?.type ? (DB_TYPE_LABELS[d.type] ?? d.type) : '')}
                </div>
              </div>
              <span style={{
                marginLeft: 'auto', fontSize: 11, fontWeight: 600,
                color: '#0e9c92', background: 'rgba(14,156,146,.15)',
                borderRadius: 6, padding: '3px 8px',
              }}>
                Гостьовий доступ
              </span>
            </div>

            {isProperty && p && (
              <div style={{ marginTop: 12, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                {p.floor && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 13, color: 'var(--t2)' }}>
                    <IconBuilding size={13} color="var(--t3)" />{p.floor} поверх
                  </div>
                )}
                {p.area_useful != null && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 13, color: 'var(--t2)' }}>
                    <IconRuler size={13} color="var(--t3)" />{p.area_useful}{p.area_total ? `/${p.area_total}` : ''} м²
                  </div>
                )}
                {p.status && (
                  <span className={`bdg ${STATUS_BADGE_CLS[p.status] ?? ''}`}>
                    {STATUS_LABELS[p.status] ?? p.status}
                  </span>
                )}
              </div>
            )}
          </div>

          {/* What guest gets */}
          <div style={{ margin: '0 12px 12px', padding: '14px 16px', background: 'var(--glass-1)', borderRadius: 'var(--r-md)', border: 'var(--bd)' }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--t1)', marginBottom: 8 }}>Що ви отримаєте:</div>
            {[
              '👁 Перегляд усієї інформації про об\'єкт',
              '📄 Доступ до документів та файлів',
              '💸 Нагадування про строки оплати',
            ].map((item) => (
              <div key={item} style={{ fontSize: 13, color: 'var(--t2)', marginBottom: 6 }}>{item}</div>
            ))}
          </div>

          {/* DB-level: list of properties */}
          {!isProperty && guestPreview.properties && guestPreview.properties.length > 0 && (
            <>
              <div style={{ padding: '0 16px 8px', fontSize: 12, color: 'var(--t3)' }}>
                {guestPreview.properties.length} об&apos;єктів у базі
              </div>
              <div className="list">
                {guestPreview.properties.map((prop) => (
                  <div key={prop.id} className="obj-card glass-s">
                    <div className="obj-hd">
                      <div>
                        <div className="obj-t">{prop.name}</div>
                        {prop.floor && (
                          <div className="obj-s"><IconBuilding size={13} color="var(--t3)" />{prop.floor} поверх</div>
                        )}
                      </div>
                      <span className={`bdg ${STATUS_BADGE_CLS[prop.status] ?? ''}`}>
                        {STATUS_LABELS[prop.status] ?? prop.status}
                      </span>
                    </div>
                    {prop.area_useful != null && (
                      <div className="obj-met">
                        <div className="obj-mt">
                          <IconRuler size={13} color="var(--t3)" />
                          <span>{prop.area_useful}{prop.area_total ? `/${prop.area_total}` : ''} м²</span>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        <button
          className="mbtn"
          onClick={handleJoin}
          disabled={ctaLoading}
          style={{ opacity: ctaLoading ? 0.7 : 1 }}
        >
          {ctaLoading ? 'Підключення...' : 'Прийняти запрошення'}
        </button>
      </div>
    )
  }

  // ── Realtor public DB preview ────────────────────────────────────────────────
  return (
    <div className="scr bg-purple">
      <div className="hdr">
        <button className="hdr-back" onClick={handleClose}>✕ Закрити</button>
        <div className="hdr-t">{dbInfo?.db_name ?? 'База'}</div>
      </div>

      <div className="body" style={{ paddingBottom: 96 }}>
        <div className="glass" style={{ margin: '12px 12px 8px', padding: '14px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: dbInfo?.db_color
                ? `linear-gradient(135deg, ${dbInfo.db_color}, ${dbInfo.db_color}99)`
                : 'linear-gradient(135deg,#7B30EB,#5B1FD4)',
              flexShrink: 0,
            }} />
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--t1)' }}>{dbInfo?.db_name}</div>
              <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 2 }}>
                {dbInfo?.db_type ? (DB_TYPE_LABELS[dbInfo.db_type] ?? dbInfo.db_type) : ''}
              </div>
            </div>
            <div style={{ marginLeft: 'auto' }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent)', background: 'rgba(168,124,255,.15)', borderRadius: 6, padding: '3px 8px' }}>
                Публічний перегляд
              </span>
            </div>
          </div>
        </div>

        <div style={{ padding: '0 16px 8px', fontSize: 12, color: 'var(--t3)' }}>
          {properties.length === 0
            ? 'Об\'єктів поки немає'
            : `${properties.length} об'єкт${properties.length === 1 ? '' : properties.length < 5 ? 'и' : 'ів'}`}
        </div>

        {properties.length > 0 && (
          <div className="list">
            {properties.map((p) => (
              <div key={p.property_id} className="obj-card glass-s">
                <div className="obj-hd">
                  <div>
                    <div className="obj-t">{p.property_name}</div>
                    {p.property_floor && (
                      <div className="obj-s"><IconBuilding size={13} color="var(--t3)" />{p.property_floor} поверх</div>
                    )}
                  </div>
                  {p.property_status && (
                    <span className={`bdg ${STATUS_BADGE_CLS[p.property_status] ?? ''}`}>
                      {STATUS_LABELS[p.property_status] ?? p.property_status}
                    </span>
                  )}
                </div>
                <div className="obj-met">
                  {p.property_area_useful != null && (
                    <div className="obj-mt">
                      <IconRuler size={13} color="var(--t3)" />
                      <span>{p.property_area_useful}{p.property_area_total != null ? `/${p.property_area_total}` : ''} м²</span>
                    </div>
                  )}
                  {p.property_rent_rate != null && (
                    <div className="obj-mt">
                      <IconCurrencyDollar size={13} color="var(--t3)" />
                      <span>{p.property_rent_rate.toLocaleString('uk-UA')}{p.property_rent_type === 'per_m2' ? ' /м²' : ' /міс'}</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <button
        className="mbtn"
        onClick={handleJoin}
        disabled={ctaLoading}
        style={{ opacity: ctaLoading ? 0.7 : 1 }}
      >
        {ctaLoading ? 'Завантаження...' : 'Підключити базу та зареєструватись'}
      </button>
    </div>
  )
}
