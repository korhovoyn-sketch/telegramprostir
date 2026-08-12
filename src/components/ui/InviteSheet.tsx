'use client'

import { useEffect, useRef } from 'react'
import Modal from '@/components/ui/Modal'

interface Props {
  title: string
  subtitle: string
  /** Підпис кнопки створення. Тримай КОРОТКИМ: половинна кнопка при 375px вміщує ~167px, а «Створити посилання» вже шириться за неї. */
  confirmLabel: string
  /** Доступна назва поля: гість і член команди — різні сутності для читалки. */
  fieldLabel: string
  placeholder: string
  value: string
  onChange: (v: string) => void
  onConfirm: () => void
  onClose: () => void
}

/**
 * Шит створення запрошення — спільний для команди бази і гостьових лінків.
 * Обидва екрани мали власну копію цих ~28 рядків із розбіжністю лише в текстах,
 * і саме через це той самий зламаний гард закриття довелось правити двічі.
 *
 * Гарда «не закривай, поки летить запит» тут свідомо НЕМА: він живе в
 * `Modal.requestClose` (див. коментар там).
 */
export default function InviteSheet({
  title, subtitle, confirmLabel, fieldLabel, placeholder, value, onChange, onConfirm, onClose,
}: Props) {
  const inputRef = useRef<HTMLInputElement>(null)

  // Фокус — ПІСЛЯ виїзду шита (.38s): раніше клавіатура починає підніматись
  // назустріч анімації, і обидві геометрії конкурують. Ефект живе тут, разом із
  // самим полем, а не в кожному екрані, що відкриває цей шит.
  useEffect(() => {
    const t = setTimeout(() => inputRef.current?.focus(), 400)
    return () => clearTimeout(t)
  }, [])

  return (
    <Modal
      title={title}
      subtitle={subtitle}
      onClose={onClose}
      actions={[
        { label: confirmLabel, variant: 'primary', onClick: onConfirm },
        { label: 'Скасувати', variant: 'secondary', onClick: onClose },
      ]}
    >
      {/* `.fld` (підпис НАД полем), а не `.fr` (підпис і поле в один рядок), і це
          не смак: у рядковому варіанті на підпис «Підпис (необовʼязково)» лишалось
          менше половини ширини, і плейсхолдер обрізався посеред слова —
          «напр. Оренд». Плюс поле без рамки читалось як звичайний текст, а не як
          поле вводу. Той самий `.fld` уживають шити оренди, розкладу й платежу. */}
      <div style={{ paddingTop: 4 }}>
        <div className="fld">
          <div className="fld-l">Підпис (необов&apos;язково)</div>
          <input
            aria-label={fieldLabel}
            ref={inputRef}
            type="text"
            placeholder={placeholder}
            value={value}
            onChange={e => onChange(e.target.value)}
            maxLength={100}
          />
        </div>
      </div>
    </Modal>
  )
}
