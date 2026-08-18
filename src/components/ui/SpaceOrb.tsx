'use client'

import { useEffect, useRef, useState } from 'react'

/**
 * Персонаж порожнього героя картки обʼєкта — замість колишнього будинку.
 *
 * Референс власника (GIF): темна СКЛЯНА сфера, всередині світиться
 * LED-екран, на ньому очі, що змінюють вираз, а згори злітають дрібні
 * частинки. Розібрано покадрово: сітка «пікселів» СТОЇТЬ, а під нею повзе
 * кольоровий градієнт — саме тому перелив читається як екран, а не як пляма.
 *
 * ЩО ТУТ ПРИНЦИПОВО ДЛЯ ПРОДУКТИВНОСТІ (правила проєкту):
 *  • рухаються ЛИШЕ `transform`/`opacity`. Градієнт екрана НЕ анімується
 *    через `background-position` — це перемальовування щокадру; замість цього
 *    під нерухомою сіткою їздять кольорові плями (`translate3d`), що для
 *    композитора безкоштовно;
 *  • `backdrop-filter` немає ніде — блюр на поверхні, що рухається щокадру,
 *    це рівно та патологія WebKit, через яку його вимикають у шитах;
 *  • `will-change` тримається тільки поки палець на сцені (`orb-live`);
 *  • `prefers-reduced-motion` читається В JS: CSS-блок не спиняє ні rAF, ні
 *    інлайновий transform.
 *
 * Механіка взаємодії (rAF на pointermove, зняття transition під час ведення,
 * спалах на ключі стану) перенесена з попереднього `Building3D` — вона вже
 * була перевірена на пристрої, тож переписувати її наново не було потреби.
 */

export type OrbStatus = 'free' | 'occupied' | 'for_sale'

/**
 * Палітра екрана й ореолу за статусом. Тон береться з тієї ж логіки, що й
 * бейдж над ілюстрацією (`STATUS_COLORS` в utils): вільно — зелений акцент,
 * зайнято — бурштин, продаж — синь. Самі стопи екрана свідомо не рівні
 * бейджу: на LED-панелі потрібні ДВА кольори, що переливаються один в одний.
 */
const PALETTE: Record<OrbStatus, { a: string; b: string; halo: string; eye: string }> = {
  free:     { a: '#2ee6d0', b: '#7b5cff', halo: 'rgba(52,199,89,.30)',   eye: '#eafffb' },
  occupied: { a: '#ffb03a', b: '#ff5c8a', halo: 'rgba(255,159,10,.30)',  eye: '#fff3e0' },
  for_sale: { a: '#5ac8ff', b: '#7b5cff', halo: 'rgba(122,179,255,.30)', eye: '#eaf4ff' },
}

/** Пауза між блиманнями. Нерегулярність і є тим, що читається як «живий». */
const BLINK_MIN = 2600
const BLINK_MAX = 6200

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

export default function SpaceOrb({ status = 'free' }: { status?: OrbStatus }) {
  const stageRef = useRef<HTMLDivElement>(null)
  const rafRef = useRef(0)
  const [burst, setBurst] = useState(0)
  const [blink, setBlink] = useState(false)
  const [squint, setSquint] = useState(false)
  const burstTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const squintTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const blinkTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const pal = PALETTE[status] ?? PALETTE.free

  // Блимання за випадковим інтервалом. Ланцюг таймерів, а не setInterval:
  // рівний ритм читається як індикатор, а не як живі очі.
  useEffect(() => {
    if (prefersReducedMotion()) return
    let alive = true
    const schedule = () => {
      const wait = BLINK_MIN + Math.random() * (BLINK_MAX - BLINK_MIN)
      blinkTimer.current = setTimeout(() => {
        if (!alive) return
        setBlink(true)
        setTimeout(() => { if (alive) setBlink(false) }, 130)
        schedule()
      }, wait)
    }
    schedule()
    return () => { alive = false; clearTimeout(blinkTimer.current) }
  }, [])

  useEffect(() => () => {
    cancelAnimationFrame(rafRef.current)
    clearTimeout(burstTimer.current)
    clearTimeout(squintTimer.current)
  }, [])

  // JS віддає лише два числа −1..1; куди саме вони рухають шари — вирішує CSS.
  const setTilt = (nx: number, ny: number) => {
    cancelAnimationFrame(rafRef.current)
    rafRef.current = requestAnimationFrame(() => {
      const el = stageRef.current
      if (!el) return
      el.style.setProperty('--nx', nx.toFixed(3))
      el.style.setProperty('--ny', ny.toFixed(3))
    })
  }

  const onMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (prefersReducedMotion()) return
    const el = stageRef.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const nx = Math.max(-1.4, Math.min(1.4, ((e.clientX - r.left) / r.width - 0.5) * 2))
    const ny = Math.max(-1.4, Math.min(1.4, ((e.clientY - r.top) / r.height - 0.5) * 2))
    setTilt(nx, ny)
  }

  const release = () => {
    stageRef.current?.classList.remove('orb-live')
    setTilt(0, 0)
  }

  const onDown = (e: React.PointerEvent<HTMLDivElement>) => {
    stageRef.current?.classList.add('orb-live')
    onMove(e)
    if (prefersReducedMotion()) return
    // Примружився і бризнув частинками — реакція на дотик.
    setSquint(true)
    clearTimeout(squintTimer.current)
    squintTimer.current = setTimeout(() => setSquint(false), 420)
    setBurst((n) => n + 1)
    clearTimeout(burstTimer.current)
    burstTimer.current = setTimeout(() => setBurst(0), 900)
  }

  const eyeCls = `orb-eye${blink ? ' blink' : ''}${squint ? ' squint' : ''}`

  return (
    <div
      ref={stageRef}
      className="orb-stage"
      style={{ '--orb-a': pal.a, '--orb-b': pal.b, '--orb-halo': pal.halo, '--orb-eye': pal.eye } as React.CSSProperties}
      onPointerMove={onMove}
      onPointerDown={onDown}
      onPointerUp={release}
      onPointerCancel={release}
      onPointerLeave={release}
      aria-hidden="true"
    >
      <div className="orb-tilt">
        <span className="orb-halo" />

        <div className="orb-body">
          <div className="orb-screen">
            {/* Плями їздять ПІД сіткою — саме так перелив читається як екран */}
            <span className="orb-blob a" />
            <span className="orb-blob b" />
            <span className="orb-grid" />
            <span className="orb-eyes">
              <i className={eyeCls} />
              <i className={eyeCls} />
            </span>
          </div>
        </div>

        <span className={`orb-dust${burst ? ' orb-burst' : ''}`} key={burst}>
          <i style={{ '--sx': '-30px', '--sy': '-96px', '--sd': '0ms' } as React.CSSProperties} />
          <i style={{ '--sx': '18px', '--sy': '-112px', '--sd': '90ms' } as React.CSSProperties} />
          <i style={{ '--sx': '-6px', '--sy': '-128px', '--sd': '180ms' } as React.CSSProperties} />
          <i style={{ '--sx': '38px', '--sy': '-88px', '--sd': '260ms' } as React.CSSProperties} />
          <i style={{ '--sx': '-44px', '--sy': '-74px', '--sd': '340ms' } as React.CSSProperties} />
          <i style={{ '--sx': '8px', '--sy': '-146px', '--sd': '120ms' } as React.CSSProperties} />
        </span>
      </div>
    </div>
  )
}
