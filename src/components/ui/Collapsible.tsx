'use client'

import { useEffect, useRef, useState } from 'react'
import { prefersReducedMotion } from '@/lib/motion'

// Height-animated accordion body.
//
// Why the Web Animations API and not a CSS transition on a React state value:
// the collapse path needs two committed styles in a row (auto → current px → 0).
// React batches those updates, so the browser only ever saw the final value and
// snapped — the reveal looked torn (content popped to full size, then faded).
// el.animate() takes explicit from/to keyframes, so the animation always runs
// and `finished` tells us exactly when to hand height back to the layout.
//
// Cost: the list can hold 24+ glass cards, each with backdrop-filter: blur(28px).
// Re-blurring all of them on every animation frame is what made it stutter, so
// the wrapper carries `.fold-anim` while moving — that switches the blur off for
// the duration (invisible at speed, dramatically cheaper).
const DURATION = 300
const EASE = 'cubic-bezier(.16,1,.3,1)'

/**
 * `prefers-reduced-motion` мусимо читати ТУТ, у JS.
 *
 * Блок `@media (prefers-reduced-motion: reduce)` у globals.css гасить
 * `animation`/`transition` — але Web Animations API (`el.animate()`) він не
 * зупиняє в принципі: це не CSS-анімація. Тобто акордеон рухався 300 мс навіть
 * тоді, коли користувач вимкнув рух у налаштуваннях системи — єдине місце
 * застосунку, що обходило власне ж правило.
 */

export default function Collapsible({ open, className, children }: {
  open: boolean
  className?: string
  children: React.ReactNode
}) {
  const outerRef = useRef<HTMLDivElement>(null)
  const innerRef = useRef<HTMLDivElement>(null)
  const animRef = useRef<Animation | null>(null)
  const firstRef = useRef(true)
  // Only used for the very first paint; afterwards the element's inline style is
  // driven imperatively so React re-renders can't fight the running animation.
  const [initialOpen] = useState(open)

  useEffect(() => {
    const outer = outerRef.current
    const inner = innerRef.current
    if (!outer || !inner) return

    // Mount just syncs to the current state — never animate on first paint.
    if (firstRef.current) {
      firstRef.current = false
      outer.style.height = open ? 'auto' : '0px'
      outer.style.opacity = open ? '1' : '0'
      outer.style.visibility = open ? 'visible' : 'hidden'
      return
    }

    animRef.current?.cancel()

    // Рух вимкнено — стрибаємо в кінцевий стан тим самим кодом, що й після
    // завершення анімації. Кінцевий стан ОДИН, тож розходження станів між
    // шляхами неможливе.
    if (prefersReducedMotion()) {
      outer.classList.remove('fold-anim')
      outer.style.height = open ? 'auto' : '0px'
      outer.style.opacity = open ? '1' : '0'
      outer.style.visibility = open ? 'visible' : 'hidden'
      return
    }

    const from = outer.getBoundingClientRect().height
    const to = open ? inner.getBoundingClientRect().height : 0

    // Fix the start height so the animation has a concrete origin (height:auto
    // is not interpolable), and make sure a collapsing section stays painted
    // until it has finished shrinking.
    outer.style.height = `${from}px`
    outer.style.visibility = 'visible'
    outer.classList.add('fold-anim')

    // Рухається ЛИШЕ висота. Фейд звідси прибрано: `opacity < 1` на обгортці
    // змушує браузер щокадру рендерити все піддерево папки (до 24 карток) в
    // офскрін-буфер і композитувати з альфою — заради переходу, який і так
    // схований `overflow:hidden`. Вміст лишається непрозорим НА ВЕСЬ рух — і
    // коли росте, і коли стискається; нуль для згорнутої секції виставляє
    // хвіст `anim.finished` нижче, тобто у спокої, а не покадрово.
    outer.style.opacity = '1'
    const anim = outer.animate(
      [{ height: `${from}px` }, { height: `${to}px` }],
      { duration: DURATION, easing: EASE, fill: 'forwards' },
    )
    animRef.current = anim

    anim.finished
      .then(() => {
        if (animRef.current !== anim) return // superseded by a newer toggle
        anim.cancel() // drop fill:forwards so inline styles take over cleanly
        outer.classList.remove('fold-anim')
        // Release to auto so later content changes (rename, move) aren't clipped.
        outer.style.height = open ? 'auto' : '0px'
        outer.style.opacity = open ? '1' : '0'
        outer.style.visibility = open ? 'visible' : 'hidden'
      })
      .catch(() => { /* cancelled by a newer toggle — nothing to clean up */ })

    return () => { anim.cancel() }
  }, [open])

  return (
    <div
      ref={outerRef}
      className="fold-wrap"
      style={initialOpen
        ? { height: 'auto', opacity: 1 }
        : { height: 0, opacity: 0, visibility: 'hidden' }}
    >
      <div ref={innerRef} className={className}>{children}</div>
    </div>
  )
}
