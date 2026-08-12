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
  autoFocus?: boolean
}

/**
 * Рядок створення в шиті — спільний для пікера папок, пікера баз і керування
 * папками. Усі три тримали власну копію стану (`newName` + `busy`), власний
 * `handleCreate` з тим самим гардом і ту саму розмітку; третя копія до того ж
 * перейменувала `busy` на `creating`.
 *
 * Стоїть ЗВЕРХУ шита у всіх трьох, і це навмисно: на iOS клавіатура Telegram
 * накриває webview не ресайзячи його, тож поле знизу було б під клавіатурою.
 */
export default function SheetCreateRow({
  fieldLabel, placeholder, confirmLabel, maxLength, onCreate, collapsedLabel, autoFocus,
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
        autoFocus={autoFocus ?? !!collapsedLabel}
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
