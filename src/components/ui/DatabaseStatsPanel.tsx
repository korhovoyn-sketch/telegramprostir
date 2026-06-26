'use client'

import { useEffect, useRef, useState, useMemo, type ReactNode } from 'react'
import { calcRent, calcUtilities, formatPrice } from '@/lib/utils'
import type { Property } from '@/types'

interface Props {
  properties: Property[]
  currency?: string
}

interface CardData {
  icon: ReactNode
  label: string
  value: string
  sub?: string
  accentBg: string
  accentBorder: string
  bar?: number
  barColor?: string
}

function useCountUp(target: number, duration = 620): number {
  const [val, setVal] = useState(0)
  const rafRef = useRef(0)
  const fromRef = useRef(0)

  useEffect(() => {
    cancelAnimationFrame(rafRef.current)
    const from = fromRef.current
    let startTs = 0
    const tick = (ts: number) => {
      if (!startTs) startTs = ts
      const p = Math.min((ts - startTs) / duration, 1)
      const ease = 1 - Math.pow(1 - p, 3)
      const next = Math.round(from + (target - from) * ease)
      fromRef.current = next
      setVal(next)
      if (p < 1) rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [target, duration])

  return val
}

function GradientIcon({ from, to, glow, children }: {
  from: string
  to: string
  glow: string
  children: ReactNode
}) {
  return (
    <div style={{
      width: 32,
      height: 32,
      borderRadius: 9,
      background: `linear-gradient(135deg, ${from}, ${to})`,
      boxShadow: `0 4px 12px ${glow}, inset 0 1px 0 rgba(255,255,255,.28)`,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      flexShrink: 0,
    }}>
      <svg
        width="16" height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="rgba(255,255,255,.95)"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {children}
      </svg>
    </div>
  )
}

const ICON_ACTIVITY = (
  <GradientIcon from="#4F8EF7" to="#7AB3FF" glow="rgba(79,142,247,.42)">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
  </GradientIcon>
)

const ICON_DOLLAR = (
  <GradientIcon from="#2CC459" to="#4ADB7A" glow="rgba(44,196,89,.42)">
    <line x1="12" y1="1" x2="12" y2="23"/>
    <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>
  </GradientIcon>
)

const ICON_ZAP = (
  <GradientIcon from="#FF9500" to="#FFB340" glow="rgba(255,149,0,.42)">
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
  </GradientIcon>
)

const ICON_EXPAND = (
  <GradientIcon from="#A855F7" to="#C084FC" glow="rgba(168,85,247,.42)">
    <polyline points="15 3 21 3 21 9"/>
    <polyline points="9 21 3 21 3 15"/>
    <line x1="21" y1="3" x2="14" y2="10"/>
    <line x1="3" y1="21" x2="10" y2="14"/>
  </GradientIcon>
)

const ICON_LAYERS = (
  <GradientIcon from="#6366F1" to="#818CF8" glow="rgba(99,102,241,.42)">
    <polygon points="12 2 2 7 12 12 22 7 12 2"/>
    <polyline points="2 17 12 22 22 17"/>
    <polyline points="2 12 12 17 22 12"/>
  </GradientIcon>
)

const ICON_CHECK = (
  <GradientIcon from="#06B6D4" to="#22D3EE" glow="rgba(6,182,212,.42)">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
    <polyline points="22 4 12 14.01 9 11.01"/>
  </GradientIcon>
)

function StatCard({ icon, label, value, sub, accentBg, accentBorder, bar, barColor, delay }: CardData & { delay: number }) {
  const [on, setOn] = useState(false)

  useEffect(() => {
    const t = setTimeout(() => setOn(true), delay)
    return () => clearTimeout(t)
  }, [delay])

  return (
    <div
      className="dash-card"
      style={{
        background: accentBg,
        borderColor: accentBorder,
        opacity: on ? 1 : 0,
        transform: on ? 'translateY(0) scale(1)' : 'translateY(12px) scale(0.96)',
        transition: 'opacity .38s ease, transform .42s cubic-bezier(.16,1,.3,1)',
      }}
    >
      <div className="dash-ic">{icon}</div>
      <div className="dash-n">{value}</div>
      {bar !== undefined ? (
        <div className="dash-bar">
          <div
            className="dash-bar-fill"
            style={{
              width: on ? `${Math.round(bar * 100)}%` : '0%',
              background: barColor ?? 'rgba(255,255,255,.6)',
              transition: 'width .9s cubic-bezier(.16,1,.3,1)',
            }}
          />
        </div>
      ) : (
        <div style={{ height: 6 }} />
      )}
      <div className="dash-l">{label}</div>
      {sub && <div className="dash-sub">{sub}</div>}
    </div>
  )
}

export default function DatabaseStatsPanel({ properties, currency = 'USD' }: Props) {
  const stats = useMemo(() => {
    const occupied = properties.filter(p => p.status === 'occupied')
    const forSale = properties.filter(p => p.status === 'for_sale')
    const free = properties.filter(p => p.status === 'free')

    const totalRent = occupied.reduce((sum, p) =>
      sum + (p.rent_rate && p.area_useful ? calcRent(p.area_useful, p.rent_rate, p.rent_type) : 0), 0)

    const totalUtils = occupied.reduce((sum, p) =>
      sum + (p.utilities_rate && p.area_total ? calcUtilities(p.area_total, p.utilities_rate) : 0), 0)

    const occupiedUseful = occupied.reduce((sum, p) => sum + (p.area_useful ?? 0), 0)
    const occupiedTotal = occupied.reduce((sum, p) => sum + (p.area_total ?? 0), 0)
    const totalUseful = properties.reduce((sum, p) => sum + (p.area_useful ?? 0), 0)
    const totalArea = properties.reduce((sum, p) => sum + (p.area_total ?? 0), 0)
    const freeUseful = free.reduce((sum, p) => sum + (p.area_useful ?? 0), 0)

    return {
      occupiedCount: occupied.length,
      forSaleCount: forSale.length,
      freeCount: free.length,
      total: properties.length,
      totalRent,
      totalUtils,
      occupiedUseful: Math.round(occupiedUseful),
      occupiedTotal: Math.round(occupiedTotal),
      totalUseful: Math.round(totalUseful),
      totalArea: Math.round(totalArea),
      freeUseful: Math.round(freeUseful),
      ratio: properties.length > 0 ? occupied.length / properties.length : 0,
    }
  }, [properties])

  const animRent = useCountUp(stats.totalRent)
  const animUtils = useCountUp(stats.totalUtils)
  const animOccupiedUseful = useCountUp(stats.occupiedUseful)
  const animTotalUseful = useCountUp(stats.totalUseful)
  const animFree = useCountUp(stats.freeUseful)

  if (properties.length === 0) return null

  const cards: CardData[] = [
    {
      icon: ICON_ACTIVITY,
      label: 'Зайнятість',
      value: `${stats.occupiedCount} / ${stats.total}`,
      sub: stats.forSaleCount > 0
        ? `${Math.round(stats.ratio * 100)}% · ${stats.forSaleCount} на продаж`
        : `${Math.round(stats.ratio * 100)}% заповнено`,
      accentBg: 'rgba(122,179,255,.13)',
      accentBorder: 'rgba(122,179,255,.26)',
      bar: stats.ratio,
      barColor: '#7AB3FF',
    },
    ...(stats.totalRent > 0 ? [{
      icon: ICON_DOLLAR,
      label: 'Оренда / міс',
      value: formatPrice(animRent, currency),
      sub: `${stats.occupiedCount} об'єктів`,
      accentBg: 'rgba(52,199,89,.13)',
      accentBorder: 'rgba(52,199,89,.26)',
    } satisfies CardData] : []),
    ...(stats.totalUtils > 0 ? [{
      icon: ICON_ZAP,
      label: 'Комунальні / міс',
      value: formatPrice(animUtils, currency),
      sub: 'від зайнятих',
      accentBg: 'rgba(255,149,0,.13)',
      accentBorder: 'rgba(255,149,0,.26)',
    } satisfies CardData] : []),
    ...(stats.occupiedUseful > 0 ? [{
      icon: ICON_EXPAND,
      label: 'Площа зайнятих',
      value: `${animOccupiedUseful.toLocaleString('uk-UA')} м²`,
      sub: stats.occupiedTotal > 0 ? `заг: ${stats.occupiedTotal.toLocaleString('uk-UA')} м²` : undefined,
      accentBg: 'rgba(168,85,247,.13)',
      accentBorder: 'rgba(168,85,247,.26)',
    } satisfies CardData] : []),
    ...(stats.totalUseful > 0 ? [{
      icon: ICON_LAYERS,
      label: 'Вся корисна площа',
      value: `${animTotalUseful.toLocaleString('uk-UA')} м²`,
      sub: stats.totalArea > 0 ? `заг: ${stats.totalArea.toLocaleString('uk-UA')} м²` : undefined,
      accentBg: 'rgba(99,102,241,.13)',
      accentBorder: 'rgba(99,102,241,.26)',
    } satisfies CardData] : []),
    ...(stats.freeUseful > 0 ? [{
      icon: ICON_CHECK,
      label: 'Вільна площа',
      value: `${animFree.toLocaleString('uk-UA')} м²`,
      sub: `${stats.freeCount} вільних`,
      accentBg: 'rgba(6,182,212,.13)',
      accentBorder: 'rgba(6,182,212,.26)',
    } satisfies CardData] : []),
  ]

  return (
    <div className="dash-panel">
      {cards.map((card, i) => (
        <StatCard key={card.label} {...card} delay={i * 70} />
      ))}
    </div>
  )
}
