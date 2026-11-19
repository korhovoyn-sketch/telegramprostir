'use client'

import { useAppSlice } from '@/store/appStore'
import { tr } from '@/lib/i18n'
import { IconCheck, IconX, IconAlertTriangle } from '@/components/Icons'

export default function Toast() {
  const { toast, hideToast } = useAppSlice('toast', 'hideToast')
  if (!toast) return null

  const isErr = toast.type === 'error'

  return (
    <div className={`toast${isErr ? ' err' : ''}`} role="alert" aria-live="polite" aria-atomic="true">
      <div className="toast-ic">
        {isErr ? <IconAlertTriangle size={14} /> : <IconCheck size={14} />}
      </div>
      <div className="toast-mn">
        <div className="toast-t">{toast.title}</div>
        {toast.subtitle && <div className="toast-s">{toast.subtitle}</div>}
      </div>
      {toast.actionLabel && toast.onAction && (
        <button
          className="toast-act"
          onClick={() => { toast.onAction?.(); hideToast() }}
        >
          {toast.actionLabel}
        </button>
      )}
      <button
        className="toast-close"
        onClick={hideToast}
        aria-label={tr('Закрити')}
        style={{ background: 'none', border: 'none', cursor: 'pointer' }}
      >
        <IconX size={14} />
      </button>
    </div>
  )
}
