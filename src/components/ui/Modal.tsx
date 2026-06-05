'use client'

import { scrollFocusedIntoView } from '@/lib/utils'

interface ModalProps {
  title: string
  subtitle?: string
  onClose: () => void
  children?: React.ReactNode
  actions?: Array<{
    label: string
    variant: 'primary' | 'danger' | 'secondary'
    onClick: () => void
  }>
}

export default function Modal({ title, subtitle, onClose, children, actions }: ModalProps) {
  return (
    <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="modal" onFocusCapture={scrollFocusedIntoView}>
        <div className="modal-h">{title}</div>
        {subtitle && <div className="modal-s">{subtitle}</div>}
        {children}
        {actions && (
          <div className="modal-actions">
            {actions.map((a) => (
              <button
                key={a.label}
                className={`modal-btn ${a.variant}`}
                onClick={a.onClick}
              >
                {a.label}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
