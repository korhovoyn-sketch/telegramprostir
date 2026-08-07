'use client'

/**
 * Плаваюча дія над списком: «Здати в оренду», «Звільнити об'єкт», «Поділитись».
 * Стиль — спільний Liquid Glass (.btn-glass у globals.css); раніше тут лежали
 * три власні НЕПРОЗОРІ заливки (.94 альфи), і кнопки були єдиними суцільними
 * плямами в скляному інтерфейсі.
 */
const TONE = { success: 'ok', danger: 'err', info: 'info' } as const

interface FloatingButtonProps {
  variant: keyof typeof TONE
  icon: React.ReactNode
  label: string
  onClick: () => void
}

export default function FloatingButton({ variant, icon, label, onClick }: FloatingButtonProps) {
  return (
    <button className={`btn-glass fbtn ${TONE[variant]}`} onClick={onClick}>
      {icon}
      {label}
    </button>
  )
}
