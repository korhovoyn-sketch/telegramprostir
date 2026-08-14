'use client'

import { useState } from 'react'
import { IconPlus } from '@/components/Icons'

interface Props {
  /** Доступна назва поля — «Назва нової папки» / «Назва нової бази». */
  fieldLabel: string
  placeholder: string
  confirmLabel: string
  maxLength: number
  /**
   * Створює сутність. `true` — вдалося: поле очищується (шит лишається
   * відкритим, бо викликач сам вирішує, чи закриватись).
   */
  onCreate: (name: string) => Promise<boolean>
  /** Розкривається тапом по «+ …» замість того, щоб стояти розкритим завжди. */
  collapsedLabel?: string
}

/**
 * Рядок створення в шиті — спільний для пікера папок, пікера баз і керування
 * папками. Усі три тримали власну копію стану (`newName` + `busy`), власний
 * `handleCreate` з тим самим гардом і ту саму розмітку; третя копія до того ж
 * перейменувала `busy` на `creating`.
 *
 * Стоїть ЗВЕРХУ шита у всіх трьох, і це навмисно: на iOS клавіатура Telegram
 * накриває webview не ресайзячи його, тож поле знизу було б під клавіатурою.
 *
 * Поле НЕ фокусується саме — навіть коли зʼявилось від тапу по «+ …». Тап
 * розкриття міняє висоту самого шита (кнопка замінюється рядком із полем), і
 * фокус у той самий момент запускає ще три геометрії: пробу `kbFallback`
 * (350+200мс), `padding-bottom .25s` оверлея і `max-height .25s` шита — усе це
 * поверх 48px-блюру. Саме це власник описав як «відразу клавіатура перекриває
 * або піджимає». Ціна рішення — один зайвий тап по полю, і вона прийнята
 * свідомо. Гард: `design-tokens.test.ts` → «клавіатура в модалках».
 */
export default function SheetCreateRow({
  fieldLabel, placeholder, confirmLabel, maxLength, onCreate, collapsedLabel,
}: Props) {
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState(!collapsedLabel)

  async function submit() {
    const trimmed = name.trim()
    if (!trimmed || busy) return
    setBusy(true)
    try {
      if (await onCreate(trimmed)) setName('')
    } finally {
      setBusy(false)
    }
  }

  if (!open) {
    return (
      <button type="button" className="fold-pick-new" onClick={() => setOpen(true)}>
        <IconPlus size={16} /> {collapsedLabel}
      </button>
    )
  }

  return (
    <div className="fold-mng-new">
      <span className="fold-mng-ic"><IconPlus size={16} /></span>
      <input
        className="fold-mng-input"
        value={name}
        aria-label={fieldLabel}
        placeholder={placeholder}
        onChange={(e) => setName(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter') void submit() }}
        maxLength={maxLength}
      />
      <button type="button" className="fold-mng-add" disabled={!name.trim() || busy} onClick={() => void submit()}>
        {confirmLabel}
      </button>
    </div>
  )
}
