'use client'

import { forwardRef } from 'react'

/**
 * Плаваюча дія над списком: «Здати в оренду», «Звільнити обʼєкт», «Поділитись»,
 * і (за проханням, щоб не було двох різних стилів FAB в застосунку) «Додати
 * обʼєкт», «Створити базу», «Створити підбірку». Стиль — спільний Liquid Glass
 * (.btn-glass у globals.css); раніше тут лежали три власні НЕПРОЗОРІ заливки
 * (.94 альфи), і кнопки були єдиними суцільними плямами в скляному інтерфейсі.
 */
const TONE = { success: 'ok', danger: 'err', info: 'info', create: 'pink' } as const

interface FloatingButtonProps {
  variant: keyof typeof TONE
  icon: React.ReactNode
  label: string
  onClick: () => void
  /** Екрани з таббаром (db-list/db-objects/collections) — вище, щоб не лягати
      під нього; екрани-деталі (property-detail, collection-detail) — стандартна
      позиція над самим низом. */
  raised?: boolean
  /** Ховає кнопку зсувом вниз під час гортання — той самий приховуваний FAB,
      що раніше малював `.fab.fab-off`. */
  hidden?: boolean
  /** Менша пігулка для дій «створити нове»: вони висять над списком, який
      користувач читає, тож не мають важити стільки, скільки первинна дія
      екрана-деталі. Розмір НЕ виводиться з `variant` навмисно — колір несе
      семантику дії, а не габарит. */
  compact?: boolean
}

const FloatingButton = forwardRef<HTMLButtonElement, FloatingButtonProps>(
  function FloatingButton({ variant, icon, label, onClick, raised, hidden, compact }, ref) {
    return (
      <button
        ref={ref}
        // aria-label дублює видимий текст, а не замінює: старіші тести
        // (`getByLabel`) виникли ще для іконкових .fab без підпису і лишились
        // не мігрованими на getByRole/getByText — обидва шляхи мають працювати.
        aria-label={label}
        className={`btn-glass fbtn ${TONE[variant]}${compact ? ' compact' : ''}${raised ? ' raised' : ''}${hidden ? ' fab-off' : ''}`}
        onClick={onClick}
      >
        {icon}
        {label}
      </button>
    )
  }
)

export default FloatingButton
