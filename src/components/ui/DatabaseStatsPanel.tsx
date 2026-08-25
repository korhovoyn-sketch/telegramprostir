'use client'

import { useEffect, useRef, useState, useMemo, type ReactNode } from 'react'
import { monthlyRent, calcUtilities, basisArea, formatPrice, objectsWord } from '@/lib/utils'
import { IconActivity, IconCurrencyDollar, IconBolt, IconRuler, IconLayers, IconCircleCheck } from '@/components/Icons'
import { prefersReducedMotion } from '@/lib/motion'
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
  // З вимкненим рухом стартуємо ВІДРАЗУ з цілі, а не з нуля: інакше лишався б
  // кадр «$0» до першого ефекту — і саме він робив кадр бейслайна лотереєю.
  const [val, setVal] = useState(() => (prefersReducedMotion() ? target : 0))
  const rafRef = useRef(0)
  const fromRef = useRef(prefersReducedMotion() ? target : 0)

  useEffect(() => {
    cancelAnimationFrame(rafRef.current)
    // Лічильник крутить rAF, тож CSS-блок reduced-motion його не спиняє —
    // виходимо в кінцеве значення СИНХРОННО. Це не лише a11y: кадр бейслайна
    // інакше ловить довільну мить відліку, і `db-objects` двічі поспіль дав
    // «$4 660» проти «$4 657» на тих самих фікстурах і замороженому годиннику.
    if (prefersReducedMotion()) {
      fromRef.current = target
      setVal(target)
      return
    }
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

/**
 * Кольорова плитка під іконку. Сама іконка — з єдиної бібліотеки Icons.tsx:
 * раніше панель тримала ВЛАСНИЙ набір SVG-шляхів (інша геометрія, інша товщина
 * обведення 2.5), і дашборд читався як третій стиль поруч із картками й
 * модалками.
 */
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
      borderRadius: 'var(--r-xs)',
      background: `linear-gradient(135deg, ${from}, ${to})`,
      boxShadow: `0 4px 12px ${glow}, inset 0 1px 0 rgba(255,255,255,.28)`,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      flexShrink: 0,
    }}>
      {children}
    </div>
  )
}

const CHIP = 'rgba(255,255,255,.95)'

const ICON_ACTIVITY = (
  <GradientIcon from="#4F8EF7" to="#7AB3FF" glow="rgba(79,142,247,.42)"><IconActivity size={16} color={CHIP} /></GradientIcon>
)
const ICON_DOLLAR = (
  <GradientIcon from="#2CC459" to="#4ADB7A" glow="rgba(44,196,89,.42)"><IconCurrencyDollar size={16} color={CHIP} /></GradientIcon>
)
const ICON_ZAP = (
  <GradientIcon from="#FF9500" to="#FFB340" glow="rgba(255,149,0,.42)"><IconBolt size={16} color={CHIP} /></GradientIcon>
)
const ICON_EXPAND = (
  <GradientIcon from="#A855F7" to="#C084FC" glow="rgba(168,85,247,.42)"><IconRuler size={16} color={CHIP} /></GradientIcon>
)
const ICON_LAYERS = (
  <GradientIcon from="#6366F1" to="#818CF8" glow="rgba(99,102,241,.42)"><IconLayers size={16} color={CHIP} /></GradientIcon>
)
const ICON_CHECK = (
  <GradientIcon from="#06B6D4" to="#22D3EE" glow="rgba(6,182,212,.42)"><IconCircleCheck size={16} color={CHIP} /></GradientIcon>
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
              background: barColor ?? 'var(--t2)',
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
      sum + (p.rent_rate ? monthlyRent(basisArea(p.area_useful, p.area_total, p.area_basis), p.rent_rate, p.rent_type) : 0), 0)

    // Expenses are $/m² on the chosen basis area, otherwise a flat charge (parking).
    const totalUtils = occupied.reduce((sum, p) => {
      const a = basisArea(p.area_useful, p.area_total, p.area_basis)
      return sum + (p.utilities_rate ? (a ? calcUtilities(a, p.utilities_rate) : p.utilities_rate) : 0)
    }, 0)

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
      accentBg: 'var(--dv-blue-bg)',
      accentBorder: 'var(--dv-blue-bd)',
      bar: stats.ratio,
      barColor: 'var(--dv-blue)',
    },
    ...(stats.totalRent > 0 ? [{
      icon: ICON_DOLLAR,
      label: 'Оренда / міс',
      value: formatPrice(animRent, currency),
      sub: `${stats.occupiedCount} ${objectsWord(stats.occupiedCount)}`,
      accentBg: 'var(--dv-green-bg)',
      accentBorder: 'var(--dv-green-bd)',
    } satisfies CardData] : []),
    ...(stats.totalUtils > 0 ? [{
      icon: ICON_ZAP,
      label: 'Експлуатаційні / міс',
      value: formatPrice(animUtils, currency),
      sub: 'від зайнятих',
      accentBg: 'var(--dv-amber-bg)',
      accentBorder: 'var(--dv-amber-bd)',
    } satisfies CardData] : []),
    ...(stats.occupiedUseful > 0 ? [{
      icon: ICON_EXPAND,
      label: 'Площа зайнятих',
      value: `${animOccupiedUseful.toLocaleString('uk-UA')} м²`,
      sub: stats.occupiedTotal > 0 ? `заг: ${stats.occupiedTotal.toLocaleString('uk-UA')} м²` : undefined,
      accentBg: 'var(--dv-purple-bg)',
      accentBorder: 'var(--dv-purple-bd)',
    } satisfies CardData] : []),
    ...(stats.totalUseful > 0 ? [{
      icon: ICON_LAYERS,
      label: 'Вся корисна площа',
      value: `${animTotalUseful.toLocaleString('uk-UA')} м²`,
      sub: stats.totalArea > 0 ? `заг: ${stats.totalArea.toLocaleString('uk-UA')} м²` : undefined,
      accentBg: 'var(--dv-indigo-bg)',
      accentBorder: 'var(--dv-indigo-bd)',
    } satisfies CardData] : []),
    ...(stats.freeUseful > 0 ? [{
      icon: ICON_CHECK,
      label: 'Вільна площа',
      value: `${animFree.toLocaleString('uk-UA')} м²`,
      sub: `${stats.freeCount} вільних`,
      accentBg: 'var(--dv-cyan-bg)',
      accentBorder: 'var(--dv-cyan-bd)',
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
