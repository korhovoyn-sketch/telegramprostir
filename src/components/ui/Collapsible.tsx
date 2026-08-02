'use client'

import { useEffect, useRef, useState } from 'react'

// Height-animated accordion body. We measure scrollHeight and transition the
// px height (not CSS grid 0fr↔1fr — that fr-interpolation needs Safari 16+ and
// simply snaps in older Telegram WebViews, so the reveal looked instant).
// Once open we release to height:auto so late content changes don't clip.
export default function Collapsible({ open, className, children }: {
  open: boolean
  className?: string
  children: React.ReactNode
}) {
  const innerRef = useRef<HTMLDivElement>(null)
  const [height, setHeight] = useState<number | 'auto'>(open ? 'auto' : 0)
  const firstRef = useRef(true)

  useEffect(() => {
    const el = innerRef.current
    if (!el) return
    // First run only syncs to the initial state — no animation on mount.
    if (firstRef.current) { firstRef.current = false; return }

    if (open) {
      setHeight(el.scrollHeight)
      const t = setTimeout(() => setHeight('auto'), 340)
      return () => clearTimeout(t)
    }
    // Collapse: go from auto → current px, then to 0 on the next frame so the
    // browser has a concrete start value to interpolate from.
    setHeight(el.scrollHeight)
    let raf2 = 0
    const raf1 = requestAnimationFrame(() => {
      void el.offsetHeight // force reflow so the px height commits
      raf2 = requestAnimationFrame(() => setHeight(0))
    })
    return () => { cancelAnimationFrame(raf1); cancelAnimationFrame(raf2) }
  }, [open])

  return (
    <div
      style={{
        height: height === 'auto' ? 'auto' : `${height}px`,
        overflow: 'hidden',
        opacity: open ? 1 : 0,
        visibility: open ? 'visible' : 'hidden',
        transitionProperty: 'height, opacity, visibility',
        transitionDuration: '.32s, .26s, 0s',
        transitionTimingFunction: 'cubic-bezier(.16,1,.3,1), ease, linear',
        // Keep it visible through the collapse, then hide (a11y + hit-testing).
        transitionDelay: open ? '0s' : '0s, 0s, .32s',
        willChange: 'height',
      }}
    >
      <div ref={innerRef} className={className}>{children}</div>
    </div>
  )
}
