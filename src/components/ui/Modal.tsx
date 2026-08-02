'use client'

import { useEffect, useId, useRef, useState } from 'react'
import { scrollFocusedIntoView } from '@/lib/utils'

// Mounted-modal stack: Escape must close only the TOPMOST modal (a confirm
// nested inside ShareSheet must not tear the sheet down too — backdrop taps
// never did).
const modalStack: symbol[] = []

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
  const modalRef = useRef<HTMLDivElement>(null)
  // Exit animation: dismiss gestures set `closing`, the slide-down/​fade plays,
  // then onClose actually unmounts us (open slid up but close used to just pop).
  const [closing, setClosing] = useState(false)
  const firedRef = useRef(false)

  const requestClose = () => {
    if (firedRef.current) return
    setClosing(true)
  }
  const finishClose = () => {
    if (firedRef.current) return
    firedRef.current = true
    onClose()
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

  // Move focus into the dialog for a11y — unless an inner input already grabbed
  // it (e.g. an autoFocus rename field), which we must not steal.
  useEffect(() => {
    const el = modalRef.current
    if (el && !el.contains(document.activeElement)) el.focus()
  }, [])

  // Safety net: if the exit animation never fires (reduced-motion edge cases,
  // interrupted paint), still unmount shortly after a close was requested.
  useEffect(() => {
    if (!closing) return
    const t = setTimeout(finishClose, 320)
    return () => clearTimeout(t)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [closing])

  return (
    <div
      className={`modal-overlay${closing ? ' closing' : ''}`}
      onClick={(e) => { if (e.target === e.currentTarget) requestClose() }}
    >
      <div
        ref={modalRef}
        className={`modal${closing ? ' closing' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onAnimationEnd={(e) => { if (closing && e.target === modalRef.current) finishClose() }}
      >
        {/* Fixed header — never scrolls */}
        <div className="modal-head">
          <div className="modal-h" id={titleId}>{title}</div>
          {subtitle && <div className="modal-s">{subtitle}</div>}
        </div>

        {/* Scrollable body — inputs scroll freely; action buttons are sticky at the bottom
            so they never overlap inputs when the keyboard is open */}
        {(children || actions) && (
          <div className="modal-body" onFocusCapture={scrollFocusedIntoView}>
            {children}
            {actions && (
              <div className={`modal-actions ${actions.length === 2 ? 'two' : ''}`}>
                {actions.map((a) => (
                  <button
                    key={a.label}
                    className={`modal-btn ${a.variant}`}
                    onClick={a.onClick}
                    disabled={a.disabled}
                  >
                    {a.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
