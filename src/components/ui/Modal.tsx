'use client'

import { useEffect, useRef } from 'react'
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

  useEffect(() => {
    const id = idRef.current!
    modalStack.push(id)
    return () => {
      const i = modalStack.indexOf(id)
      if (i !== -1) modalStack.splice(i, 1)
    }
  }, [])

  // Desktop Telegram / web: Escape mirrors the backdrop tap — but only for
  // the topmost modal.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && modalStack[modalStack.length - 1] === idRef.current) onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="modal">
        {/* Fixed header — never scrolls */}
        <div className="modal-head">
          <div className="modal-h">{title}</div>
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
