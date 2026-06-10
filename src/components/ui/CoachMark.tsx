'use client'

import { useEffect, useState } from 'react'
import { skipAllOnboarding } from '@/hooks/useOnboarding'

interface CoachMarkProps {
  title: string
  body: string
  targetRef: React.RefObject<HTMLElement | null>
  /** 'above' | 'below' | 'auto' (auto picks based on space) */
  placement?: 'above' | 'below' | 'auto'
  onDone: () => void
}

interface Rect { top: number; left: number; width: number; height: number }

const PAD = 10     // padding around the spotlight hole
const BUBBLE_W = 256
const GAP = 14     // gap between spotlight edge and bubble

export default function CoachMark({ title, body, targetRef, placement = 'auto', onDone }: CoachMarkProps) {
  const [rect, setRect] = useState<Rect | null>(null)

  useEffect(() => {
    // Slight delay so any entrance animations settle before we measure
    const t = setTimeout(() => {
      const el = targetRef.current
      if (!el) return
      const r = el.getBoundingClientRect()
      setRect({ top: r.top, left: r.left, width: r.width, height: r.height })
    }, 450)
    return () => clearTimeout(t)
  }, [targetRef])

  if (!rect) return null

  const vpH = typeof window !== 'undefined' ? window.innerHeight : 800
  const vpW = typeof window !== 'undefined' ? window.innerWidth : 390

  // Spotlight rect (padded)
  const sTop = Math.max(0, rect.top - PAD)
  const sLeft = Math.max(0, rect.left - PAD)
  const sW = rect.width + PAD * 2
  const sH = rect.height + PAD * 2

  // Determine bubble direction
  const spaceBelow = vpH - (sTop + sH)
  const above = placement === 'above' || (placement === 'auto' && spaceBelow < 210)

  // Bubble horizontal position — centred over target, clamped to viewport
  const bLeft = Math.max(16, Math.min(
    rect.left + rect.width / 2 - BUBBLE_W / 2,
    vpW - BUBBLE_W - 16,
  ))
  // Arrow X relative to bubble left — points at target centre
  const arrowX = Math.max(18, Math.min(rect.left + rect.width / 2 - bLeft - 7, BUBBLE_W - 32))

  const bubbleStyle: React.CSSProperties = above
    ? { position: 'absolute', bottom: vpH - sTop + GAP, left: bLeft, width: BUBBLE_W }
    : { position: 'absolute', top: sTop + sH + GAP, left: bLeft, width: BUBBLE_W }

  function dismiss() { onDone() }
  function skipAll() { skipAllOnboarding(); onDone() }

  return (
    <div className="cmark-root" role="dialog" aria-modal="true" aria-label={title}>
      {/* 4 dark panels covering everything outside the spotlight.
          pointer-events:none on root — each panel gets its own pointer-events:auto. */}

      {/* Top panel */}
      {sTop > 0 && (
        <div className="cmark-panel" style={{ top: 0, left: 0, right: 0, height: sTop }} onClick={dismiss} />
      )}
      {/* Bottom panel */}
      <div className="cmark-panel" style={{ top: sTop + sH, left: 0, right: 0, bottom: 0 }} onClick={dismiss} />
      {/* Left panel */}
      {sLeft > 0 && (
        <div className="cmark-panel" style={{ top: sTop, left: 0, width: sLeft, height: sH }} onClick={dismiss} />
      )}
      {/* Right panel */}
      <div className="cmark-panel" style={{ top: sTop, left: sLeft + sW, right: 0, height: sH }} onClick={dismiss} />

      {/* Animated glow ring around the target — draws attention without blocking it */}
      <div className="cmark-ring" style={{ top: sTop, left: sLeft, width: sW, height: sH }} />

      {/* Tooltip bubble */}
      <div className="cmark-bubble" style={bubbleStyle} onClick={e => e.stopPropagation()}>
        {!above && <div className="cmark-arr cmark-arr-up" style={{ left: arrowX }} />}
        <div className="cmark-ttl">{title}</div>
        <div className="cmark-bdy">{body}</div>
        <div className="cmark-acts">
          <button className="cmark-skip" onClick={skipAll}>Пропустити все</button>
          <button className="cmark-ok" onClick={dismiss}>Зрозуміло 👍</button>
        </div>
        {above && <div className="cmark-arr cmark-arr-dn" style={{ left: arrowX }} />}
      </div>
    </div>
  )
}
