'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import Header from '@/components/ui/Header'
import { IconShare, IconEye, IconChartLine } from '@/components/Icons'
import { formatDate, daysSince } from '@/lib/utils'
import { buildPublicUrl, sharePublicUrl } from '@/lib/telegram'
import type { PropertyView } from '@/types'
import QRCode from 'react-qr-code'

const WEEKDAY = ['Нд', 'Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб']

// Last 7 days labels, oldest first (index 0 = 6 days ago, index 6 = today)
function last7DayLabels(): string[] {
  const now = new Date()
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(now)
    d.setDate(now.getDate() - (6 - i))
    return WEEKDAY[d.getDay()]
  })
}

export default function SharingAnalyticsScreen() {
  const { screenParams, user, showToast } = useAppStore()
  const [views, setViews] = useState<PropertyView[]>([])
  const [loading, setLoading] = useState(true)
  const [chartData, setChartData] = useState<number[]>(Array(7).fill(0))
  const [dbShareToken, setDbShareToken] = useState<string>('')
  const [propShareToken, setPropShareToken] = useState<string>('')

  useEffect(() => {
    async function load() {
      if (!screenParams.propertyId && !screenParams.dbId) return
      setLoading(true)
      try {
        // Fetch share_tokens for QR / copy-link URL
        if (screenParams.dbId) {
          const { data: dbData } = await supabase
            .from('databases').select('share_token').eq('id', screenParams.dbId).single()
          if (dbData?.share_token) setDbShareToken(dbData.share_token)
        }
        if (screenParams.propertyId) {
          const { data: propData } = await supabase
            .from('properties').select('share_token').eq('id', screenParams.propertyId).single()
          if (propData?.share_token) setPropShareToken(propData.share_token)
        }

        // Use a 30-day window for the viewer list; chart is last 7 days
        const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString()
        let viewData: PropertyView[] = []

        if (screenParams.propertyId) {
          // Property-level: filter directly by property_id
          const { data, error } = await supabase
            .from('property_views')
            .select('id,property_id,viewer_id,viewer_name,action,created_at')
            .eq('property_id', screenParams.propertyId)
            .gte('created_at', thirtyDaysAgo)
            .order('created_at', { ascending: false })
            .limit(200)
          if (error) throw error
          viewData = (data ?? []) as PropertyView[]
        } else if (screenParams.dbId) {
          // DB-level: resolve property IDs first, then filter views
          const { data: props, error: propsErr } = await supabase
            .from('properties')
            .select('id')
            .eq('db_id', screenParams.dbId)
          if (propsErr) throw propsErr
          const propIds = (props ?? []).map((p: { id: string }) => p.id)

          if (propIds.length > 0) {
            const { data, error } = await supabase
              .from('property_views')
              .select('id,property_id,viewer_id,viewer_name,action,created_at')
              .in('property_id', propIds)
              .gte('created_at', thirtyDaysAgo)
              .order('created_at', { ascending: false })
              .limit(200)
            if (error) throw error
            viewData = (data ?? []) as PropertyView[]
          }
        }

        setViews(viewData)

        // Chart: count per day for the last 7 days only
        const dayData = Array(7).fill(0)
        viewData.forEach((v) => {
          const diff = daysSince(v.created_at)
          if (diff >= 0 && diff < 7) dayData[6 - diff]++
        })
        setChartData(dayData)
      } catch (e) {
        showToast({ type: 'error', title: 'Помилка аналітики', subtitle: (e as Error).message })
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [screenParams.propertyId, screenParams.dbId, showToast])

  const maxVal = Math.max(...chartData, 1)

  // Stats are based on the last 7 days only (matches chart label)
  const last7Views = views.filter((v) => daysSince(v.created_at) < 7)
  const todayViews = views.filter((v) => daysSince(v.created_at) === 0)

  const isPropertyShare = Boolean(screenParams.propertyId)

  // Build the public /v URL — what QR codes, copy, and Telegram share all use.
  // Falls back to id if share_token hasn't loaded yet (edge case on slow network).
  function getPublicUrl(): string {
    if (isPropertyShare) {
      const token = propShareToken || (screenParams.propertyId as string)
      return buildPublicUrl('prop', token)
    }
    const token = dbShareToken || (screenParams.dbId as string) || ''
    return buildPublicUrl('db', token)
  }

  function handleShare() {
    if (!user) return
    const text = isPropertyShare ? 'Перегляньте цей об\'єкт нерухомості' : 'Перегляньте базу нерухомості'
    if (isPropertyShare) {
      sharePublicUrl('prop', propShareToken || (screenParams.propertyId as string), text)
    } else {
      sharePublicUrl('db', dbShareToken || (screenParams.dbId as string) || '', text)
    }
  }

  const shareLink = getPublicUrl()

  return (
    <div className="scr bg-pink">
      <Header title={isPropertyShare ? 'Поділитись об\'єктом' : 'Аналітика бази'} backLabel="Назад" />

      <div className="body">
        {/* Views count */}
        <div className="stat-g">
          <div className="stat glass-s" style={{ gridColumn: 'span 2' }}>
            <div className="stat-n">{last7Views.length}</div>
            <div className="stat-l">Переглядів за 7 днів</div>
          </div>
          <div className="stat glass-s">
            <div className="stat-n">{todayViews.length}</div>
            <div className="stat-l">Сьогодні</div>
          </div>
        </div>

        {/* Chart */}
        <div className="chart-box glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="chart-h">
            <span className="chart-t">
              <IconChartLine size={14} color="var(--info-fg)" />
              {' '}Перегляди
            </span>
            <span className="chart-s">Останні 7 днів</span>
          </div>

          <svg width="100%" height="80" viewBox="0 0 280 80" style={{ display: 'block' }}>
            {[0, 1, 2, 3].map(i => (
              <line key={i} x1="0" y1={i * 20 + 10} x2="280" y2={i * 20 + 10} stroke="rgba(255,255,255,.06)" strokeWidth="1" />
            ))}
            <polyline
              fill="none"
              stroke="url(#chartGrad)"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              points={chartData.map((v, i) => {
                const x = (i / 6) * 260 + 10
                const y = 70 - (v / maxVal) * 55
                return `${x},${y}`
              }).join(' ')}
            />
            <polygon
              fill="url(#areaGrad)"
              points={[
                ...chartData.map((v, i) => {
                  const x = (i / 6) * 260 + 10
                  const y = 70 - (v / maxVal) * 55
                  return `${x},${y}`
                }),
                '270,70', '10,70'
              ].join(' ')}
            />
            {chartData.map((v, i) => {
              const x = (i / 6) * 260 + 10
              const y = 70 - (v / maxVal) * 55
              return v > 0 ? <circle key={i} cx={x} cy={y} r="3" fill="#7AB3FF" /> : null
            })}
            <defs>
              <linearGradient id="chartGrad" x1="0" y1="0" x2="280" y2="0" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#7AB3FF" />
                <stop offset="100%" stopColor="#A87CFF" />
              </linearGradient>
              <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="80" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="rgba(122,179,255,.22)" />
                <stop offset="100%" stopColor="rgba(122,179,255,.02)" />
              </linearGradient>
            </defs>
          </svg>

          <div className="dl-row">
            {last7DayLabels().map((d, i) => (
              <span key={i} className="dl-x">{d}</span>
            ))}
          </div>
        </div>

        {/* QR + share link */}
        <div className="qr-hero glass-s">
          <div className="qr-wrap">
            {!loading ? (
              <QRCode
                value={shareLink}
                size={124}
                bgColor="#ffffff"
                fgColor="#000000"
                style={{ borderRadius: 6, display: 'block' }}
              />
            ) : (
              <div style={{ width: 124, height: 124, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <div className="loader" />
              </div>
            )}
          </div>
          <div className="qr-meta">
            <div className="qr-name">{isPropertyShare ? 'QR-код об\'єкта' : 'QR-код для ріелтора'}</div>
            <div className="qr-link" style={{ wordBreak: 'break-all' }}>{shareLink}</div>
          </div>
          <button
            className="glass-s"
            style={{ marginTop: 8, padding: '8px 20px', borderRadius: 20, fontSize: 13, fontWeight: 600, color: 'var(--t1)', border: '.5px solid rgba(255,255,255,.2)', cursor: 'pointer', background: 'rgba(255,255,255,.08)' }}
            onClick={() => {
              navigator.clipboard?.writeText(shareLink)
              showToast({ type: 'success', title: 'Посилання скопійовано' })
            }}
          >
            Скопіювати посилання
          </button>
        </div>

        {/* Recent viewers */}
        <div className="over">
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconEye size={13} color="#7AB3FF" />Останні перегляди</span>
          <span className="over-a">
            <IconEye size={12} /> {last7Views.length} за 7 днів
          </span>
        </div>

        {loading ? (
          <div className="loader-wrap" style={{ paddingTop: 24 }}>
            <div className="loader" />
          </div>
        ) : views.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 24 }}>
            <div className="empty-ic">👁️</div>
            <div className="empty-h">Немає переглядів</div>
            <div className="empty-s">Поділись посиланням, щоб ріелтори побачили об&apos;єкти</div>
          </div>
        ) : (
          <div className="view-l glass-s" style={{ margin: '0 12px 16px' }}>
            {views.slice(0, 15).map((v) => (
              <div key={v.id} className="view-i">
                <div className="view-av av-grad-2">
                  {(v.viewer_name ?? '?').charAt(0).toUpperCase()}
                </div>
                <div className="view-mn">
                  <div className="view-n">{v.viewer_name ?? 'Анонім'}</div>
                  <div className="view-a">
                    {v.action === 'photo' ? 'переглянув фото' :
                     v.action === 'document' ? 'завантажив документ' :
                     v.action === 'share' ? 'поділився посиланням' :
                     v.action === 'favorite' ? 'додав до обраних' :
                     'переглянув'}
                  </div>
                </div>
                <div className="view-r">
                  <div
                    className="view-dot"
                    style={{
                      color: daysSince(v.created_at) === 0
                        ? 'var(--ok)' : 'var(--t4)'
                    }}
                  />
                  <span className="view-t">{formatDate(v.created_at)}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        <div style={{ height: 80 }} />
      </div>

      <button className="mbtn" onClick={handleShare}>
        <IconShare size={18} />
        Поділитись у Telegram
      </button>
    </div>
  )
}
