'use client'

import { useEffect, useRef, useState, useMemo } from 'react'
import { calcRent, calcUtilities, formatPrice } from '@/lib/utils'
import type { Property } from '@/types'

interface Props {
  properties: Property[]
  currency?: string
}

interface CardData {
  icon: string
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
    const occupied = properties.filter(p => p.status === 'occupied' || p.status === 'for_sale')
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
      icon: '📊',
      label: 'Зайнятість',
      value: `${stats.occupiedCount} / ${stats.total}`,
      sub: `${Math.round(stats.ratio * 100)}% заповнено`,
      accentBg: 'rgba(122,179,255,.13)',
      accentBorder: 'rgba(122,179,255,.26)',
      bar: stats.ratio,
      barColor: '#7AB3FF',
    },
    ...(stats.totalRent > 0 ? [{
      icon: '💰',
      label: 'Оренда / міс',
      value: formatPrice(animRent, currency),
      sub: `${stats.occupiedCount} об'єктів`,
      accentBg: 'rgba(52,199,89,.13)',
      accentBorder: 'rgba(52,199,89,.26)',
    } satisfies CardData] : []),
    ...(stats.totalUtils > 0 ? [{
      icon: '🔧',
      label: 'Комунальні / міс',
      value: formatPrice(animUtils, currency),
      sub: 'від зайнятих',
      accentBg: 'rgba(255,149,0,.13)',
      accentBorder: 'rgba(255,149,0,.26)',
    } satisfies CardData] : []),
    ...(stats.occupiedUseful > 0 ? [{
      icon: '📐',
      label: 'Площа зайнятих',
      value: `${animOccupiedUseful.toLocaleString('uk-UA')} м²`,
      sub: stats.occupiedTotal > 0 ? `заг: ${stats.occupiedTotal.toLocaleString('uk-UA')} м²` : undefined,
      accentBg: 'rgba(180,80,240,.13)',
      accentBorder: 'rgba(180,80,240,.26)',
    } satisfies CardData] : []),
    ...(stats.totalUseful > 0 ? [{
      icon: '🏢',
      label: 'Вся корисна площа',
      value: `${animTotalUseful.toLocaleString('uk-UA')} м²`,
      sub: stats.totalArea > 0 ? `заг: ${stats.totalArea.toLocaleString('uk-UA')} м²` : undefined,
      accentBg: 'rgba(90,90,200,.13)',
      accentBorder: 'rgba(90,90,200,.26)',
    } satisfies CardData] : []),
    ...(stats.freeUseful > 0 ? [{
      icon: '✅',
      label: 'Вільна площа',
      value: `${animFree.toLocaleString('uk-UA')} м²`,
      sub: `${stats.freeCount} вільних`,
      accentBg: 'rgba(90,200,250,.13)',
      accentBorder: 'rgba(90,200,250,.26)',
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
