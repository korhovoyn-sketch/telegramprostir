'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import Header from '@/components/ui/Header'
import { IconShare, IconEye, IconChartLine } from '@/components/Icons'
import { formatDate } from '@/lib/utils'
import type { PropertyView } from '@/types'

const DAYS = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Нд']

export default function SharingAnalyticsScreen() {
  const { screenParams, user } = useAppStore()
  const [views, setViews] = useState<PropertyView[]>([])
  const [loading, setLoading] = useState(true)
  const [chartData, setChartData] = useState<number[]>(Array(7).fill(0))

  useEffect(() => {
    async function load() {
      if (!screenParams.propertyId && !screenParams.dbId) return
      setLoading(true)
      try {
        let query = supabase.from('property_views').select('*').order('created_at', { ascending: false }).limit(20)

        if (screenParams.propertyId) {
          query = query.eq('property_id', screenParams.propertyId)
        }

        const { data } = await query
        setViews((data ?? []) as PropertyView[])

        // Build chart data (last 7 days)
        const now = Date.now()
        const dayData = Array(7).fill(0)
        ;(data ?? []).forEach((v: PropertyView) => {
          const diff = Math.floor((now - new Date(v.created_at).getTime()) / 86400000)
          if (diff < 7) dayData[6 - diff]++
        })
        setChartData(dayData)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [screenParams.propertyId, screenParams.dbId])

  const maxVal = Math.max(...chartData, 1)
  const totalViews = views.length

  function handleShare() {
    if (!user) return
    const shareToken = screenParams.dbId ? 'db_' + screenParams.dbId?.slice(0, 8) : 'prop_' + screenParams.propertyId?.slice(0, 8)
    const link = `https://t.me/propspacebot?start=${shareToken}`

    if (typeof window !== 'undefined' && window.Telegram?.WebApp) {
      window.Telegram.WebApp.openTelegramLink(`https://t.me/share/url?url=${encodeURIComponent(link)}`)
    }
  }

  return (
    <div className="scr bg-teal">
      <Header title="Аналітика" backLabel="Назад" />

      <div className="body">
        {/* Views count */}
        <div className="stat-g">
          <div className="stat glass-s" style={{ gridColumn: 'span 2' }}>
            <div className="stat-n">{totalViews}</div>
            <div className="stat-l">Переглядів за 7 днів</div>
          </div>
          <div className="stat glass-s">
            <div className="stat-n">{views.filter(v => {
              const d = Math.floor((Date.now() - new Date(v.created_at).getTime()) / 86400000)
              return d === 0
            }).length}</div>
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
            {/* Grid lines */}
            {[0, 1, 2, 3].map(i => (
              <line key={i} x1="0" y1={i * 20 + 10} x2="280" y2={i * 20 + 10} stroke="rgba(255,255,255,.06)" strokeWidth="1" />
            ))}

            {/* Line */}
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

            {/* Area fill */}
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

            {/* Dots */}
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
            {DAYS.map((d) => (
              <span key={d} className="dl-x">{d}</span>
            ))}
          </div>
        </div>

        {/* Recent viewers */}
        <div className="over">
          <span>Останні перегляди</span>
          <span className="over-a">
            <IconEye size={12} /> {totalViews} всього
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
            <div className="empty-s">Поділись посиланням, щоб ріелтори побачили об&apos;єкт</div>
          </div>
        ) : (
          <div className="view-l glass-s" style={{ margin: '0 12px 16px' }}>
            {views.slice(0, 10).map((v) => (
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
                      color: Math.floor((Date.now() - new Date(v.created_at).getTime()) / 86400000) === 0
                        ? '#34C759' : 'var(--t4)'
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
