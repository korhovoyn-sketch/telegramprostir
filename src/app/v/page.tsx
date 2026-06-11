'use client'

/* eslint-disable @next/next/no-img-element */
import { useEffect, useState } from 'react'
import { supabase } from '@/lib/supabase'
import { TG_BOT, buildDeepLink } from '@/lib/telegram'
import { IconBuilding, IconRuler, IconMapPin, IconCurrencyDollar } from '@/components/Icons'

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL ?? ''

function photoUrl(path: string) {
  return `${SUPABASE_URL}/storage/v1/object/public/photos/${path}`
}

// ── data types returned by the RPCs ──────────────────────────────────────────

interface PropertyPreview {
  property_id: string
  property_name: string
  property_status: 'free' | 'occupied' | 'for_sale'
  property_floor: string | null
  property_area_useful: number | null
  property_area_total: number | null
  property_rent_type: 'per_m2' | 'fixed'
  property_rent_rate: number | null
  property_utilities_rate: number | null
  property_description: string | null
  property_address: string | null
  property_has_parking: boolean
  property_parking_spaces: number
  property_sale_price: number | null
  share_expires_at: string | null
  db_id: string
  db_name: string
  db_type: string
  db_color: string
  owner_first_name: string
  owner_last_name: string | null
  owner_tg_username: string | null
  owner_phone: string | null
  photos: string[]
}

interface DbRow {
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

interface ColRow {
  collection_id: string
  collection_name: string
  share_expires_at: string | null
  realtor_first_name: string
  realtor_last_name: string | null
  realtor_tg_username: string | null
  realtor_phone: string | null
  property_id: string | null
  property_name: string | null
  property_status: string | null
  property_floor: string | null
  property_area_useful: number | null
  property_area_total: number | null
  property_rent_type: string | null
  property_rent_rate: number | null
  property_description: string | null
  db_id: string | null
  db_name: string | null
  db_type: string | null
  db_color: string | null
  first_photo: string | null
}

// ── helpers ───────────────────────────────────────────────────────────────────

const STATUS_LABEL: Record<string, string> = { free: 'Вільно', occupied: 'Зайнято', for_sale: 'Продаж' }
const STATUS_COLOR: Record<string, string> = {
  free: 'rgba(74,222,128,1)',
  occupied: 'rgba(251,191,36,1)',
  for_sale: 'rgba(96,165,250,1)',
}
const STATUS_BG: Record<string, string> = {
  free: 'rgba(74,222,128,.15)',
  occupied: 'rgba(251,191,36,.15)',
  for_sale: 'rgba(96,165,250,.15)',
}
const DB_TYPE_LABEL: Record<string, string> = {
  business_center: 'Бізнес-центр',
  residential: 'Житловий комплекс',
  retail: 'Торговий центр',
  warehouse: 'Склад',
  individual: 'Індивідуальний об\'єкт',
  parking: 'Паркінг',
}

function fmtArea(a: number | null) { return a ? `${a} м²` : null }
function fmtPrice(n: number | null, suffix = '') {
  if (n == null) return null
  return `$${n.toLocaleString('uk-UA')}${suffix}`
}

// ── shared UI pieces ──────────────────────────────────────────────────────────

const s = {
  wrap: {
    height: '100%',
    overflowY: 'auto',
    WebkitOverflowScrolling: 'touch',
    background: 'linear-gradient(160deg,#0d0521 0%,#0a0a14 50%,#050d1a 100%)',
    fontFamily: '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif',
    color: '#fff',
    WebkitFontSmoothing: 'antialiased',
  } as React.CSSProperties,
  hdr: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '14px 16px 10px',
    borderBottom: '.5px solid rgba(255,255,255,.08)',
    position: 'sticky', top: 0, zIndex: 10,
    background: 'rgba(10,10,20,.88)',
    backdropFilter: 'blur(20px)',
    WebkitBackdropFilter: 'blur(20px)',
  } as React.CSSProperties,
  logo: {
    display: 'flex', alignItems: 'center', gap: 8,
  } as React.CSSProperties,
  logoBox: {
    width: 32, height: 32, borderRadius: 9,
    background: 'linear-gradient(135deg,#7AB3FF 0%,#A87CFF 50%,#FF7AB8 100%)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    fontSize: 16, fontWeight: 700, color: '#fff',
  } as React.CSSProperties,
  logoName: { fontSize: 15, fontWeight: 700, letterSpacing: '-.02em' } as React.CSSProperties,
  tgBtn: {
    display: 'flex', alignItems: 'center', gap: 6,
    padding: '7px 14px', borderRadius: 20,
    background: 'linear-gradient(135deg,#2AABEE,#229ED9)',
    color: '#fff', fontSize: 13, fontWeight: 600,
    textDecoration: 'none', border: 'none', cursor: 'pointer',
    boxShadow: '0 3px 12px rgba(34,158,217,.35)',
    whiteSpace: 'nowrap',
  } as React.CSSProperties,
  card: {
    margin: '12px', borderRadius: 16,
    background: 'rgba(255,255,255,.06)',
    border: '.5px solid rgba(255,255,255,.12)',
    backdropFilter: 'blur(20px)',
    WebkitBackdropFilter: 'blur(20px)',
    overflow: 'hidden',
  } as React.CSSProperties,
  pad: { padding: '14px 16px' } as React.CSSProperties,
  sectionTitle: {
    fontSize: 11, fontWeight: 700, color: 'rgba(255,255,255,.4)',
    letterSpacing: '.08em', textTransform: 'uppercase',
    marginBottom: 10,
  } as React.CSSProperties,
  divider: {
    height: .5, background: 'rgba(255,255,255,.08)', margin: '0 16px',
  } as React.CSSProperties,
  bottomCta: {
    padding: '12px 16px calc(24px + env(safe-area-inset-bottom))',
    position: 'sticky', bottom: 0,
    background: 'rgba(10,10,20,.92)',
    backdropFilter: 'blur(20px)',
    WebkitBackdropFilter: 'blur(20px)',
    borderTop: '.5px solid rgba(255,255,255,.08)',
  } as React.CSSProperties,
  mainBtn: {
    display: 'block', width: '100%',
    padding: '14px 24px', borderRadius: 14,
    background: 'linear-gradient(135deg,#2AABEE,#229ED9)',
    color: '#fff', fontSize: 16, fontWeight: 700,
    textDecoration: 'none', textAlign: 'center',
    boxShadow: '0 6px 24px rgba(34,158,217,.4)',
    letterSpacing: '-.01em',
  } as React.CSSProperties,
  contactBtn: {
    flex: 1, padding: '11px 16px', borderRadius: 12,
    fontSize: 14, fontWeight: 600, textAlign: 'center',
    textDecoration: 'none', display: 'flex',
    alignItems: 'center', justifyContent: 'center', gap: 6,
  } as React.CSSProperties,
}

// ── PhotoGallery component ────────────────────────────────────────────────────

function PhotoGallery({ paths }: { paths: string[] }) {
  const [active, setActive] = useState(0)
  if (paths.length === 0) return null

  return (
    <div style={{ background: 'rgba(0,0,0,.4)', overflow: 'hidden', borderRadius: '0 0 0 0' }}>
      <div style={{ position: 'relative', width: '100%', paddingTop: '62%', overflow: 'hidden' }}>
        <img
          src={photoUrl(paths[active])}
          alt=""
          style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover' }}
        />
        {paths.length > 1 && (
          <>
            <div style={{
              position: 'absolute', bottom: 10, right: 12,
              background: 'rgba(0,0,0,.55)', backdropFilter: 'blur(8px)',
              borderRadius: 10, padding: '3px 9px',
              fontSize: 12, fontWeight: 600, color: '#fff',
            }}>
              {active + 1}/{paths.length}
            </div>
            <button
              onClick={() => setActive(a => Math.max(0, a - 1))}
              style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', background: 'rgba(0,0,0,.5)', border: 'none', borderRadius: '50%', width: 32, height: 32, color: '#fff', fontSize: 18, cursor: 'pointer', display: active === 0 ? 'none' : 'flex', alignItems: 'center', justifyContent: 'center' }}
            >‹</button>
            <button
              onClick={() => setActive(a => Math.min(paths.length - 1, a + 1))}
              style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'rgba(0,0,0,.5)', border: 'none', borderRadius: '50%', width: 32, height: 32, color: '#fff', fontSize: 18, cursor: 'pointer', display: active === paths.length - 1 ? 'none' : 'flex', alignItems: 'center', justifyContent: 'center' }}
            >›</button>
          </>
        )}
      </div>
      {paths.length > 1 && (
        <div style={{ display: 'flex', gap: 6, padding: '8px 12px', overflowX: 'auto' }}>
          {paths.map((p, i) => (
            <button key={i} onClick={() => setActive(i)} style={{
              flexShrink: 0, width: 52, height: 40, borderRadius: 8,
              overflow: 'hidden', border: active === i ? '2px solid #2AABEE' : '2px solid transparent',
              padding: 0, cursor: 'pointer', background: 'none',
            }}>
              <img src={photoUrl(p)} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ── page header ───────────────────────────────────────────────────────────────

function PageHeader({ deepLink }: { deepLink: string }) {
  return (
    <header style={s.hdr}>
      <div style={s.logo}>
        <div style={s.logoBox}>P</div>
        <span style={s.logoName}>prostir</span>
      </div>
      <a href={deepLink} style={s.tgBtn}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12L6.88 13.47l-2.967-.924c-.643-.204-.657-.643.136-.953l11.57-4.461c.537-.194 1.006.131.275.089z"/>
        </svg>
        Відкрити в Telegram
      </a>
    </header>
  )
}

// ── contact row ───────────────────────────────────────────────────────────────

function ContactRow({ firstName, lastName, phone, tgUsername, label }: {
  firstName: string; lastName?: string | null
  phone?: string | null; tgUsername?: string | null; label: string
}) {
  const fullName = [firstName, lastName].filter(Boolean).join(' ')
  return (
    <div style={{ ...s.card, ...s.pad }}>
      <div style={s.sectionTitle}>{label}</div>
      <div style={{ fontSize: 15, fontWeight: 600, color: 'rgba(255,255,255,.9)', marginBottom: 12 }}>
        {fullName}
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        {phone && (
          <a href={`tel:${phone}`} style={{
            ...s.contactBtn,
            background: 'rgba(74,222,128,.12)',
            border: '.5px solid rgba(74,222,128,.3)',
            color: '#4ade80',
          }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.07 9.8 19.79 19.79 0 01.22 1.22 2 2 0 012.18 0h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.91 7.91a16 16 0 006.72 6.72l1.06-1.06a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z"/>
            </svg>
            Зателефонувати
          </a>
        )}
        {tgUsername && (
          <a href={`https://t.me/${tgUsername}`} target="_blank" rel="noreferrer" style={{
            ...s.contactBtn,
            background: 'rgba(42,171,238,.12)',
            border: '.5px solid rgba(42,171,238,.3)',
            color: '#2AABEE',
          }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12L6.88 13.47l-2.967-.924c-.643-.204-.657-.643.136-.953l11.57-4.461c.537-.194 1.006.131.275.089z"/>
            </svg>
            @{tgUsername}
          </a>
        )}
        {!phone && !tgUsername && (
          <span style={{ fontSize: 13, color: 'rgba(255,255,255,.4)' }}>Контакти не вказані</span>
        )}
      </div>
    </div>
  )
}

// ── Property view ─────────────────────────────────────────────────────────────

function PropertyView({ data, token }: { data: PropertyPreview; token: string }) {
  const deepLink = buildDeepLink(`prop_${token}`)
  const status = data.property_status

  const rentTotal = (() => {
    const rate = data.property_rent_rate
    const utils = data.property_utilities_rate
    const area = data.property_area_useful ?? data.property_area_total
    if (!rate) return null
    const rent = data.property_rent_type === 'fixed' ? rate : rate * (area ?? 0)
    const u = utils && area ? utils * area : 0
    return rent + u
  })()

  return (
    <div style={s.wrap}>
      <PageHeader deepLink={deepLink} />

      {data.photos.length > 0 && (
        <div style={{ margin: 12, borderRadius: 16, overflow: 'hidden' }}>
          <PhotoGallery paths={data.photos} />
        </div>
      )}

      {/* Status + title */}
      <div style={{ ...s.card, ...s.pad }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
          <span style={{
            fontSize: 12, fontWeight: 700, padding: '4px 10px', borderRadius: 8,
            background: STATUS_BG[status] ?? STATUS_BG.free,
            color: STATUS_COLOR[status] ?? STATUS_COLOR.free,
          }}>
            {STATUS_LABEL[status] ?? status}
          </span>
          {data.property_floor && (
            <span style={{ fontSize: 13, color: 'rgba(255,255,255,.55)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <IconBuilding size={12} color="rgba(255,255,255,.55)" />{data.property_floor} поверх
            </span>
          )}
        </div>
        <div style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-.02em', marginBottom: 6 }}>
          {data.property_name}
        </div>
        <div style={{ fontSize: 13, color: 'rgba(255,255,255,.5)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <IconMapPin size={13} color="rgba(255,255,255,.5)" />
          {[data.db_name, DB_TYPE_LABEL[data.db_type]].filter(Boolean).join(' • ')}
        </div>
        {data.property_address && (
          <div style={{ fontSize: 13, color: 'rgba(255,255,255,.5)', marginTop: 4 }}>
            {data.property_address}
          </div>
        )}
      </div>

      {/* Area */}
      {(data.property_area_useful || data.property_area_total) && (
        <div style={{ ...s.card }}>
          <div style={{ display: 'flex' }}>
            {data.property_area_useful && (
              <div style={{ flex: 1, padding: '12px 16px', borderRight: '.5px solid rgba(255,255,255,.08)' }}>
                <div style={{ fontSize: 11, color: 'rgba(255,255,255,.4)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4 }}>Корисна площа</div>
                <div style={{ fontSize: 20, fontWeight: 700 }}>{data.property_area_useful} <span style={{ fontSize: 14 }}>м²</span></div>
              </div>
            )}
            {data.property_area_total && (
              <div style={{ flex: 1, padding: '12px 16px' }}>
                <div style={{ fontSize: 11, color: 'rgba(255,255,255,.4)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4 }}>Загальна площа</div>
                <div style={{ fontSize: 20, fontWeight: 700 }}>{data.property_area_total} <span style={{ fontSize: 14 }}>м²</span></div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Price */}
      {status === 'for_sale' && data.property_sale_price ? (
        <div style={{ ...s.card, ...s.pad }}>
          <div style={s.sectionTitle}>Ціна продажу</div>
          <div style={{ fontSize: 28, fontWeight: 800, color: '#60a5fa', letterSpacing: '-.03em' }}>
            {fmtPrice(data.property_sale_price)}
          </div>
        </div>
      ) : data.property_rent_rate ? (
        <div style={{ ...s.card, ...s.pad }}>
          <div style={s.sectionTitle}>Орендна ставка</div>
          <div style={{ fontSize: 13, color: 'rgba(255,255,255,.5)', marginBottom: 6 }}>
            {data.property_rent_type === 'fixed' ? 'Фіксована оплата' : 'За м²'}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 13, color: 'rgba(255,255,255,.6)' }}>Оренда</span>
              <span style={{ fontSize: 17, fontWeight: 700 }}>
                {data.property_rent_type === 'fixed'
                  ? fmtPrice(data.property_rent_rate, '/міс')
                  : fmtPrice(data.property_rent_rate, '/м²')}
              </span>
            </div>
            {data.property_utilities_rate && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 13, color: 'rgba(255,255,255,.6)' }}>Комунальні</span>
                <span style={{ fontSize: 17, fontWeight: 700 }}>
                  {fmtPrice(data.property_utilities_rate, '/м²')}
                </span>
              </div>
            )}
            {rentTotal && rentTotal > 0 && (
              <>
                <div style={{ height: .5, background: 'rgba(255,255,255,.1)', margin: '4px 0' }} />
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 14, fontWeight: 600, color: 'rgba(255,255,255,.8)' }}>Разом / місяць</span>
                  <span style={{ fontSize: 22, fontWeight: 800, color: '#4ade80', letterSpacing: '-.02em' }}>
                    {fmtPrice(rentTotal)}
                  </span>
                </div>
              </>
            )}
          </div>
        </div>
      ) : null}

      {/* Description */}
      {data.property_description && (
        <div style={{ ...s.card, ...s.pad }}>
          <div style={s.sectionTitle}>Опис</div>
          <div style={{ fontSize: 14, color: 'rgba(255,255,255,.75)', lineHeight: 1.55, whiteSpace: 'pre-wrap' }}>
            {data.property_description}
          </div>
        </div>
      )}

      {/* Parking */}
      {data.property_has_parking && data.property_parking_spaces > 0 && (
        <div style={{ ...s.card, ...s.pad }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, color: 'rgba(255,255,255,.75)' }}>
            <span style={{ fontSize: 18 }}>🅟</span>
            Паркінг: {data.property_parking_spaces} {data.property_parking_spaces === 1 ? 'місце' : data.property_parking_spaces < 5 ? 'місця' : 'місць'}
          </div>
        </div>
      )}

      <ContactRow
        firstName={data.owner_first_name}
        lastName={data.owner_last_name}
        phone={data.owner_phone}
        tgUsername={data.owner_tg_username}
        label="Власник"
      />

      {/* Bottom CTA */}
      <div style={s.bottomCta}>
        <a href={deepLink} style={s.mainBtn}>
          Відкрити в Telegram →
        </a>
      </div>

      <div style={{ height: 8 }} />
    </div>
  )
}

// ── Database view ─────────────────────────────────────────────────────────────

function DatabaseView({ rows, token }: { rows: DbRow[]; token: string }) {
  const deepLink = buildDeepLink(`db_${token}`)
  const info = rows[0]
  if (!info) return null
  const properties = rows.filter(r => r.property_id !== null)

  return (
    <div style={s.wrap}>
      <PageHeader deepLink={deepLink} />

      <div style={{ ...s.card, ...s.pad }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
          <div style={{
            width: 40, height: 40, borderRadius: 11, flexShrink: 0,
            background: `linear-gradient(135deg,${info.db_color || '#7B30EB'},${info.db_color || '#7B30EB'}88)`,
          }} />
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: '-.02em' }}>{info.db_name}</div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,.5)', marginTop: 2 }}>
              {DB_TYPE_LABEL[info.db_type] ?? info.db_type}
              {properties.length > 0 && ` • ${properties.length} об'єкт${properties.length === 1 ? '' : properties.length < 5 ? 'и' : 'ів'}`}
            </div>
          </div>
          <span style={{
            marginLeft: 'auto', fontSize: 11, fontWeight: 700,
            color: 'rgba(168,124,255,.9)', background: 'rgba(168,124,255,.15)',
            borderRadius: 8, padding: '3px 9px', letterSpacing: '.04em',
          }}>Публічний перегляд</span>
        </div>
      </div>

      {properties.length > 0 && (
        <div style={{ margin: '0 12px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {properties.map(p => (
            <div key={p.property_id} style={{ ...s.card }}>
              <div style={{ ...s.pad, paddingBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                  <div style={{ fontSize: 15, fontWeight: 600, flex: 1 }}>{p.property_name}</div>
                  {p.property_status && (
                    <span style={{
                      fontSize: 11, fontWeight: 700, padding: '3px 8px', borderRadius: 7, flexShrink: 0,
                      background: STATUS_BG[p.property_status] ?? STATUS_BG.free,
                      color: STATUS_COLOR[p.property_status] ?? STATUS_COLOR.free,
                    }}>
                      {STATUS_LABEL[p.property_status] ?? p.property_status}
                    </span>
                  )}
                </div>
                <div style={{ display: 'flex', gap: 12, marginTop: 6, flexWrap: 'wrap' }}>
                  {p.property_floor && <span style={{ fontSize: 12, color: 'rgba(255,255,255,.5)', display: 'inline-flex', alignItems: 'center', gap: 3 }}><IconBuilding size={11} color="rgba(255,255,255,.5)" />{p.property_floor} пов.</span>}
                  {p.property_area_useful && <span style={{ fontSize: 12, color: 'rgba(255,255,255,.5)', display: 'inline-flex', alignItems: 'center', gap: 3 }}><IconRuler size={11} color="rgba(255,255,255,.5)" />{p.property_area_useful} м²</span>}
                  {p.property_rent_rate && (
                    <span style={{ fontSize: 12, color: 'rgba(255,255,255,.5)', display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                      <IconCurrencyDollar size={11} color="rgba(255,255,255,.5)" />{p.property_rent_rate.toLocaleString('uk-UA')}{p.property_rent_type === 'per_m2' ? '/м²' : '/міс'}
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <div style={s.bottomCta}>
        <a href={deepLink} style={s.mainBtn}>
          Підключити базу в Telegram →
        </a>
      </div>
      <div style={{ height: 8 }} />
    </div>
  )
}

// ── Collection view ───────────────────────────────────────────────────────────

function CollectionView({ rows, token }: { rows: ColRow[]; token: string }) {
  const deepLink = buildDeepLink(`col_${token}`)
  const info = rows[0]
  if (!info) return null
  const properties = rows.filter(r => r.property_id !== null)

  return (
    <div style={s.wrap}>
      <PageHeader deepLink={deepLink} />

      <div style={{ ...s.card, ...s.pad }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'rgba(255,255,255,.4)', letterSpacing: '.08em', textTransform: 'uppercase', marginBottom: 6 }}>Підбірка</div>
        <div style={{ fontSize: 20, fontWeight: 700, letterSpacing: '-.02em', marginBottom: 6 }}>{info.collection_name}</div>
        <div style={{ fontSize: 13, color: 'rgba(255,255,255,.5)' }}>
          {[info.realtor_first_name, info.realtor_last_name].filter(Boolean).join(' ')} •{' '}
          {properties.length} об&apos;єкт{properties.length === 1 ? '' : properties.length < 5 ? 'и' : 'ів'}
        </div>
      </div>

      {properties.length > 0 && (
        <div style={{ margin: '0 12px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {properties.map(p => (
            <div key={p.property_id} style={{ ...s.card }}>
              <div style={{ display: 'flex', gap: 0, overflow: 'hidden' }}>
                {p.first_photo && (
                  <div style={{ width: 90, flexShrink: 0 }}>
                    <img
                      src={photoUrl(p.first_photo)}
                      alt=""
                      style={{ width: 90, height: 90, objectFit: 'cover', display: 'block' }}
                    />
                  </div>
                )}
                <div style={{ flex: 1, padding: '10px 12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 6, marginBottom: 4 }}>
                    <div style={{ fontSize: 14, fontWeight: 600 }}>{p.property_name}</div>
                    {p.property_status && (
                      <span style={{
                        fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 6, flexShrink: 0,
                        background: STATUS_BG[p.property_status] ?? STATUS_BG.free,
                        color: STATUS_COLOR[p.property_status] ?? STATUS_COLOR.free,
                      }}>
                        {STATUS_LABEL[p.property_status] ?? p.property_status}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 12, color: 'rgba(255,255,255,.5)' }}>
                    {[
                      p.property_floor ? `${p.property_floor} пов.` : null,
                      fmtArea(p.property_area_useful),
                      p.property_rent_rate ? fmtPrice(p.property_rent_rate, p.property_rent_type === 'per_m2' ? '/м²' : '/міс') : null,
                    ].filter(Boolean).join(' • ')}
                  </div>
                  {p.db_name && (
                    <div style={{ fontSize: 11, color: 'rgba(255,255,255,.35)', marginTop: 4 }}>{p.db_name}</div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <ContactRow
        firstName={info.realtor_first_name}
        lastName={info.realtor_last_name}
        phone={info.realtor_phone}
        tgUsername={info.realtor_tg_username}
        label="Рієлтор"
      />

      <div style={s.bottomCta}>
        <a href={deepLink} style={s.mainBtn}>
          Відкрити підбірку в Telegram →
        </a>
      </div>
      <div style={{ height: 8 }} />
    </div>
  )
}

// ── Error / Loading states ────────────────────────────────────────────────────

function Loader() {
  return (
    <div style={{ ...s.wrap, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh' }}>
      <div style={{ width: 44, height: 44, borderRadius: 14, background: 'linear-gradient(135deg,#7AB3FF,#A87CFF,#FF7AB8)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22, fontWeight: 700, marginBottom: 20 }}>P</div>
      <div style={{ fontSize: 14, color: 'rgba(255,255,255,.5)' }}>Завантаження...</div>
    </div>
  )
}

function ErrorView({ msg }: { msg: string }) {
  return (
    <div style={{ ...s.wrap, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: 24, textAlign: 'center' }}>
      <div style={{ fontSize: 48, marginBottom: 16 }}>🔗</div>
      <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Посилання недійсне</div>
      <div style={{ fontSize: 14, color: 'rgba(255,255,255,.5)', lineHeight: 1.5 }}>{msg}</div>
      {TG_BOT && (
        <a href={`https://t.me/${TG_BOT}`} style={{ ...s.tgBtn, marginTop: 24 }}>
          Відкрити prostir
        </a>
      )}
    </div>
  )
}

// ── Root page ─────────────────────────────────────────────────────────────────

export default function ViewerPage() {
  const [state, setState] = useState<
    | { status: 'loading' }
    | { status: 'error'; msg: string }
    | { status: 'prop'; data: PropertyPreview; token: string }
    | { status: 'db'; rows: DbRow[]; token: string }
    | { status: 'col'; rows: ColRow[]; token: string }
  >({ status: 'loading' })

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const prop = params.get('prop')
    const db = params.get('db')
    const col = params.get('col')

    if (!prop && !db && !col) {
      setState({ status: 'error', msg: 'Параметри перегляду не вказані. Перевірте посилання.' })
      return
    }

    async function load() {
      if (prop) {
        const { data, error } = await supabase.rpc('get_public_property_preview', { p_token: prop })
        if (error || !data?.length) {
          setState({ status: 'error', msg: 'Об\'єкт не знайдено або посилання застаріло.' })
          return
        }
        setState({ status: 'prop', data: (data as PropertyPreview[])[0], token: prop })

        // Record view (fire-and-forget, best-effort)
        const row = (data as PropertyPreview[])[0]
        if (row) {
          supabase.from('property_views').insert({
            property_id: row.property_id,
            viewer_name: 'Веб-перегляд',
            action: 'view',
          }).then(() => {/* ignore */})
        }
        return
      }

      if (db) {
        const { data, error } = await supabase.rpc('get_public_db_preview', { p_token: db })
        if (error || !data?.length) {
          setState({ status: 'error', msg: 'Базу не знайдено або посилання застаріло.' })
          return
        }
        setState({ status: 'db', rows: data as DbRow[], token: db })
        return
      }

      if (col) {
        const { data, error } = await supabase.rpc('get_public_collection_preview', { p_token: col })
        if (error || !data?.length) {
          setState({ status: 'error', msg: 'Підбірку не знайдено або посилання застаріло.' })
          return
        }
        setState({ status: 'col', rows: data as ColRow[], token: col })
      }
    }

    load()
  }, [])

  if (state.status === 'loading') return <Loader />
  if (state.status === 'error') return <ErrorView msg={state.msg} />
  if (state.status === 'prop') return <PropertyView data={state.data} token={state.token} />
  if (state.status === 'db') return <DatabaseView rows={state.rows} token={state.token} />
  if (state.status === 'col') return <CollectionView rows={state.rows} token={state.token} />
  return null
}
