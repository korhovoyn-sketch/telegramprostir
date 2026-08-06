'use client'

import { useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { scrollFocusedIntoView } from '@/lib/utils'

// Mounted-modal stack: Escape must close only the TOPMOST modal (a confirm
// nested inside ShareSheet must not tear the sheet down too — backdrop taps
// never did).
const modalStack: symbol[] = []

// Консервативна висота клавіатури для платформ, які її НЕ повідомляють (iOS у
// Telegram часто не ресайзить webview: і viewportChanged, і visualViewport
// показують 0). Шит прив'язаний до низу екрана, тож без цього поля вводу
// опиняються ПІД клавіатурою. Ліфт застосовуємо тим самим `--keyboard-h`, лише
// локально на оверлеї — щоб працювали наявні клампи padding і max-height.
const KB_FALLBACK_PX = 320
// Скільком px звітованої висоти вже можна вірити (0–2px трапляються як шум).
const KB_TRUSTED_PX = 100
// Скільки чекати після фокуса, щоб клавіатура встигла відрапортуватись.
const KB_PROBE_MS = 350

interface ModalProps {
  title: string
  subtitle?: string
  onClose: () => void
  children?: React.ReactNode
  actions?: Array<{
    label: string
    variant: 'primary' | 'danger' | 'secondary'
    onClick: () => void
    disabled?: boolean
  }>
}

export default function Modal({ title, subtitle, onClose, children, actions }: ModalProps) {
  const idRef = useRef<symbol | null>(null)
  if (idRef.current === null) idRef.current = Symbol('modal')
  const titleId = useId()
  const descId = useId()
  const modalRef = useRef<HTMLDivElement>(null)
  const overlayRef = useRef<HTMLDivElement>(null)
  // Exit animation: dismiss gestures set `closing`, the slide-down/​fade plays,
  // then onClose actually unmounts us (open slid up but close used to just pop).
  const [closing, setClosing] = useState(false)
  const firedRef = useRef(false)
  // Portal target only exists in the browser (static export prerenders on Node).
  const [mounted, setMounted] = useState(false)
  useEffect(() => { setMounted(true) }, [])
  // Re-entry guard: a destructive action is usually async and leaves the modal
  // up while it flies, so a fast double-tap fired it twice (double DELETE).
  const [busy, setBusy] = useState(false)
  // Ліфт шита, коли платформа не повідомляє висоту клавіатури (див. константи).
  const [kbFallback, setKbFallback] = useState(false)
  const kbProbeRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const kbDropRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  function reportedKeyboardPx(): number {
    const css = parseFloat(
      getComputedStyle(document.documentElement).getPropertyValue('--keyboard-h'),
    )
    const vv = window.visualViewport
    const measured = vv ? Math.max(0, Math.round(window.innerHeight - vv.height)) : 0
    return Math.max(Number.isFinite(css) ? css : 0, measured)
  }

  function onFieldFocus(e: React.FocusEvent<HTMLElement>) {
    scrollFocusedIntoView(e)
    const tag = (e.target as HTMLElement).tagName
    if (tag !== 'INPUT' && tag !== 'TEXTAREA') return
    clearTimeout(kbDropRef.current)
    clearTimeout(kbProbeRef.current)
    // Тільки для тач-пристроїв: на десктопі клавіатура фізична, ліфт лишив би
    // порожню діру під шитом.
    const touch = navigator.maxTouchPoints > 0 || window.matchMedia('(pointer: coarse)').matches
    if (!touch) return
    kbProbeRef.current = setTimeout(() => {
      if (reportedKeyboardPx() < KB_TRUSTED_PX) setKbFallback(true)
    }, KB_PROBE_MS)
  }

  function onFieldBlur() {
    clearTimeout(kbProbeRef.current)
    // Перехід між сусідніми полями — це blur+focus; пауза не дає шиту стрибати.
    clearTimeout(kbDropRef.current)
    kbDropRef.current = setTimeout(() => setKbFallback(false), 180)
  }

  useEffect(() => () => {
    clearTimeout(kbProbeRef.current)
    clearTimeout(kbDropRef.current)
  }, [])

  const requestClose = () => {
    if (firedRef.current) return
    setClosing(true)
  }
  const finishClose = () => {
    if (firedRef.current) return
    firedRef.current = true
    onClose()
  }

  // ── Swipe-down-to-dismiss (from the header/grabber only, so it never fights
  // the scrollable body). Follows the finger, dims the backdrop, and on release
  // either flings the sheet away or snaps it back. ──────────────────────────────
  const drag = useRef({ startY: 0, dy: 0, active: false })

  function onDragStart(e: React.TouchEvent) {
    if (firedRef.current) return
    drag.current = { startY: e.touches[0].clientY, dy: 0, active: true }
    const el = modalRef.current
    if (el) el.style.transition = 'none'
  }
  function onDragMove(e: React.TouchEvent) {
    if (!drag.current.active) return
    const dy = e.touches[0].clientY - drag.current.startY
    if (dy <= 0) { // dragged back up — reset
      drag.current.dy = 0
      const el = modalRef.current
      if (el) el.style.transform = ''
      return
    }
    drag.current.dy = dy
    const el = modalRef.current
    if (el) el.style.transform = `translateY(${dy}px)`
    const ov = overlayRef.current
    if (ov) ov.style.opacity = String(Math.max(0.35, 1 - dy / 480))
  }
  function onDragEnd() {
    if (!drag.current.active) return
    const dy = drag.current.dy
    drag.current.active = false
    const el = modalRef.current
    const ov = overlayRef.current
    if (dy > 96) {
      // Fling away — continue from the current offset to fully off-screen.
      if (el) {
        el.style.transition = 'transform .2s cubic-bezier(.4,0,1,1)'
        el.style.transform = 'translateY(100%)'
        el.addEventListener('transitionend', (ev) => { if ((ev as TransitionEvent).propertyName === 'transform') finishClose() }, { once: true })
      }
      if (ov) { ov.style.transition = 'opacity .2s ease'; ov.style.opacity = '0' }
      setTimeout(finishClose, 260) // fallback if transitionend is missed
    } else {
      // Snap back to rest.
      if (el) {
        el.style.transition = 'transform .24s var(--ease-out)'
        el.style.transform = ''
        el.addEventListener('transitionend', () => { el.style.transition = '' }, { once: true })
      }
      if (ov) { ov.style.transition = 'opacity .24s ease'; ov.style.opacity = '' }
    }
  }

  useEffect(() => {
    const id = idRef.current!
    modalStack.push(id)
    return () => {
      const i = modalStack.indexOf(id)
      if (i !== -1) modalStack.splice(i, 1)
    }
  }, [])

  // Desktop Telegram / web: Escape mirrors the backdrop tap — topmost only.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && modalStack[modalStack.length - 1] === idRef.current) requestClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Lock background scroll while open (nesting-safe: each restores the prior value).
  useEffect(() => {
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = prev }
  }, [])

  // Return focus to whatever opened the dialog when it closes (APG dialog).
  // Captured before the initial-focus effect below steals it.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null
    return () => { opener?.focus?.() }
  }, [])

  // Move focus into the dialog for a11y — unless an inner input already grabbed
  // it (e.g. an autoFocus rename field), which we must not steal.
  useEffect(() => {
    const el = modalRef.current
    if (el && !el.contains(document.activeElement)) el.focus()
  }, [])

  // Focus trap: keep Tab / Shift+Tab cycling inside the topmost dialog so focus
  // never lands on the background behind the backdrop (aria-modal hides it from
  // AT, but doesn't stop keyboard Tab on its own).
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return
      if (modalStack[modalStack.length - 1] !== idRef.current) return
      const el = modalRef.current
      if (!el) return
      const nodes = el.querySelectorAll<HTMLElement>(
        'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])',
      )
      if (nodes.length === 0) { e.preventDefault(); el.focus(); return }
      const first = nodes[0]
      const last = nodes[nodes.length - 1]
      const active = document.activeElement
      if (e.shiftKey) {
        if (active === first || active === el || !el.contains(active)) { e.preventDefault(); last.focus() }
      } else if (active === last || !el.contains(active)) {
        e.preventDefault(); first.focus()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  // Safety net: if the exit animation never fires (reduced-motion edge cases,
  // interrupted paint), still unmount shortly after a close was requested.
  useEffect(() => {
    if (!closing) return
    const t = setTimeout(finishClose, 320)
    return () => clearTimeout(t)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [closing])

  if (!mounted) return null

  // Portal to <body>: .modal uses backdrop-filter, which makes it a containing
  // block for position:fixed descendants — a nested confirm rendered in-tree was
  // clipped to the parent sheet (floated mid-screen, backdrop covered only it).
  return createPortal(
    <div
      ref={overlayRef}
      className={`modal-overlay${closing ? ' closing' : ''}`}
      style={kbFallback ? ({ '--keyboard-h': `${KB_FALLBACK_PX}px` } as React.CSSProperties) : undefined}
      onClick={(e) => { if (e.target === e.currentTarget) requestClose() }}
    >
      <div
        ref={modalRef}
        className={`modal${closing ? ' closing' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={subtitle ? descId : undefined}
        tabIndex={-1}
        onAnimationEnd={(e) => { if (closing && e.target === modalRef.current) finishClose() }}
      >
        {/* Fixed header — never scrolls; also the swipe-to-dismiss grab area */}
        <div
          className="modal-head"
          onTouchStart={onDragStart}
          onTouchMove={onDragMove}
          onTouchEnd={onDragEnd}
          onTouchCancel={onDragEnd}
        >
          <div className="modal-h" id={titleId}>{title}</div>
          {subtitle && <div className="modal-s" id={descId}>{subtitle}</div>}
        </div>

        {/* Scrollable body — inputs scroll freely; action buttons are sticky at the bottom
            so they never overlap inputs when the keyboard is open */}
        {(children || actions) && (
          <div
            className="modal-body"
            onFocusCapture={onFieldFocus}
            onBlurCapture={onFieldBlur}
          >
            {children}
            {actions && (
              <div className={`modal-actions ${actions.length === 2 ? 'two' : ''}`}>
                {actions.map((a) => (
                  <button
                    key={a.label}
                    className={`modal-btn ${a.variant}`}
                    onClick={async () => {
                      if (busy) return
                      setBusy(true)
                      try { await a.onClick() } finally { setBusy(false) }
                    }}
                    disabled={a.disabled || busy}
                  >
                    {a.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>,
    document.body,
  )
}
