'use client'

import type { ReactNode } from 'react'

interface RetryStateProps {
  onRetry: () => void
  /** Heading — defaults to the common "Не вдалося завантажити". */
  title?: string
  /** Optional detail line (e.g. the humanized error). */
  subtitle?: ReactNode
  /** Leading emoji — defaults to the 📡 network glyph. */
  icon?: string
}

/**
 * The shared network-error / retry panel. Replaces the identical
 * `<div className="retry-wrap">…<button className="retry-btn">Спробувати ще
 * раз</button></div>` block that was copy-pasted across 8 screens. CSS lives in
 * globals.css (.retry-wrap/.retry-ic/.retry-h/.retry-s/.retry-btn).
 */
export default function RetryState({ onRetry, title = 'Не вдалося завантажити', subtitle, icon = '📡' }: RetryStateProps) {
  return (
    <div className="retry-wrap">
      <div className="retry-ic">{icon}</div>
      <div className="retry-h">{title}</div>
      {subtitle != null && subtitle !== '' && <div className="retry-s">{subtitle}</div>}
      <button className="retry-btn" onClick={onRetry}>Спробувати ще раз</button>
    </div>
  )
}
