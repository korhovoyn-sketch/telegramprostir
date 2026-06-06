'use client'

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
  return (
    <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="modal">
        {/* Fixed header — never scrolls */}
        <div className="modal-head">
          <div className="modal-h">{title}</div>
          {subtitle && <div className="modal-s">{subtitle}</div>}
        </div>

        {/* Scrollable body — form fields, lists, etc. */}
        {children && (
          <div className="modal-body">
            {children}
          </div>
        )}

        {/* Fixed footer — action buttons always visible */}
        <div className="modal-foot">
          {actions && (
            <div className="modal-actions">
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
      </div>
    </div>
  )
}
