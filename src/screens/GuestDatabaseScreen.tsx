'use client'

import { useEffect, useState } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { DB_TYPE_LABELS } from '@/lib/utils'

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

  const [rows, setRows] = useState<PreviewRow[]>([])
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
      const { data, error } = await supabase.rpc('get_public_db_preview', { p_token: token })
      if (error) {
        setErrorMsg('Не вдалося завантажити дані')
        setLoading(false)
        return
      }
      const result = (data ?? []) as PreviewRow[]
      if (result.length === 0) {
        setErrorMsg('База не знайдена або посилання застаріло')
        setLoading(false)
        return
      }
      setRows(result)
      setLoading(false)
    }

    load()
  }, [token])

  function handleClose() {
    const tg = window.Telegram?.WebApp
    if (tg) {
      tg.close()
    } else {
      back()
    }
  }

  async function handleJoin() {
    const initData = window.Telegram?.WebApp?.initData
    if (!initData) return
    setCtaLoading(true)
    localStorage.setItem('ps_guest_join', '1')
    await loginViaTelegram(initData)
    // loginViaTelegram navigates on success; if it fails it shows a toast
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
    return (
      <div className="scr bg-purple">
        <div className="hdr">
          <button className="hdr-back" onClick={handleClose}>✕ Закрити</button>
          <div className="hdr-t">Перегляд бази</div>
        </div>
        <div className="empty-state" style={{ paddingTop: 60 }}>
          <div className="empty-ic">⚠️</div>
          <div className="empty-h">{errorMsg}</div>
          <div className="empty-s">Перевірте посилання або зверніться до власника</div>
        </div>
      </div>
    )
  }

  return (
    <div className="scr bg-purple">
      <div className="hdr">
        <button className="hdr-back" onClick={handleClose}>✕ Закрити</button>
        <div className="hdr-t">{dbInfo?.db_name ?? 'База'}</div>
      </div>

      <div className="body" style={{ paddingBottom: 96 }}>
        {/* DB info header */}
        <div className="glass" style={{ margin: '12px 12px 8px', padding: '14px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: dbInfo?.db_color
                ? `linear-gradient(135deg, ${dbInfo.db_color}, ${dbInfo.db_color}99)`
                : 'linear-gradient(135deg,#7B30EB,#5B1FD4)',
              flexShrink: 0,
            }} />
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--t1)' }}>
                {dbInfo?.db_name}
              </div>
              <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 2 }}>
                {dbInfo?.db_type ? (DB_TYPE_LABELS[dbInfo.db_type] ?? dbInfo.db_type) : ''}
              </div>
            </div>
            <div style={{ marginLeft: 'auto' }}>
              <span style={{
                fontSize: 11,
                fontWeight: 600,
                color: 'var(--accent)',
                background: 'rgba(168,124,255,.15)',
                borderRadius: 6,
                padding: '3px 8px',
                letterSpacing: '.02em',
              }}>
                Публічний перегляд
              </span>
            </div>
          </div>
        </div>

        {/* Property count */}
        <div style={{ padding: '0 16px 8px', fontSize: 12, color: 'var(--t3)' }}>
          {properties.length === 0
            ? 'Об\'єктів поки немає'
            : `${properties.length} об'єкт${properties.length === 1 ? '' : properties.length < 5 ? 'и' : 'ів'}`}
        </div>

        {/* Property list */}
        {properties.length > 0 && (
          <div className="list">
            {properties.map((p) => (
              <div key={p.property_id} className="obj-card glass-s">
                <div className="obj-hd">
                  <div>
                    <div className="obj-t">{p.property_name}</div>
                    {p.property_floor && (
                      <div className="obj-s">🏢 {p.property_floor} поверх</div>
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
                      📐 {p.property_area_useful}
                      {p.property_area_total != null ? `/${p.property_area_total}` : ''} м²
                    </div>
                  )}
                  {p.property_rent_rate != null && (
                    <div className="obj-mt">
                      💰 {p.property_rent_rate.toLocaleString('uk-UA')}
                      {p.property_rent_type === 'per_m2' ? ' /м²' : ' /міс'}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Bottom CTA */}
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
