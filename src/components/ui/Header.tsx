'use client'

import { useAppStore } from '@/store/appStore'
import { IconChevronLeft } from '@/components/Icons'

interface HeaderProps {
  title?: string
  subtitle?: string
  backLabel?: string
  onBack?: () => void
  right?: React.ReactNode
  hideBack?: boolean
}

export default function Header({ title, subtitle, backLabel = 'Назад', onBack, right, hideBack }: HeaderProps) {
  const back = useAppStore((s) => s.back)

  function handleBack() {
    if (onBack) onBack()
    else back()
  }

  return (
    <div className="hdr">
      {!hideBack ? (
        <button className="hdr-back" onClick={handleBack}>
          <IconChevronLeft size={18} />
          {backLabel}
        </button>
      ) : (
        <div className="hdr-sp" />
      )}

      {title && (
        <div className="hdr-t">
          {title}
          {subtitle && <div className="hdr-t-sub">{subtitle}</div>}
        </div>
      )}

      {right ? right : <div className="hdr-sp" />}
    </div>
  )
}
