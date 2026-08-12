'use client'

import { useState } from 'react'
import Modal from '@/components/ui/Modal'
import SheetCreateRow from '@/components/ui/SheetCreateRow'
import { IconFolder, IconEdit, IconTrash, IconChevronUp, IconChevronDown, IconCheck, IconX } from '@/components/Icons'
import { hapticSelection, hapticNotify } from '@/lib/telegram'
import { objectsWord } from '@/lib/utils'
import { confirmAction } from '@/lib/confirm'
import type { PropertyFolder } from '@/types'

interface Props {
  folders: PropertyFolder[]
  // folderId → number of objects inside (для попередження при видаленні)
  counts: Map<string, number>
  onCreate: (name: string) => Promise<PropertyFolder | null>
  onRename: (id: string, name: string) => void
  onDelete: (id: string) => Promise<boolean>
  onReorder: (id: string, direction: 'up' | 'down') => void
  onClose: () => void
}

export default function FolderManageModal({ folders, counts, onCreate, onRename, onDelete, onReorder, onClose }: Props) {
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')
  // Видалення непорожньої папки лише ungroup-ає об'єкти — але це варто підтвердити.

  function startEdit(f: PropertyFolder) {
    setEditingId(f.id)
    setEditName(f.name)
  }
  function commitEdit() {
    if (editingId && editName.trim()) onRename(editingId, editName)
    setEditingId(null)
  }
  async function askDelete(folder: PropertyFolder) {
    const n = counts.get(folder.id) ?? 0
    const ok = await confirmAction({
      title: `Видалити папку «${folder.name}»?`,
      // Папка не тягне за собою обʼєкти — вони лишаються в базі без групи,
      // і це головне, що користувач мусить розуміти перед підтвердженням.
      message: n > 0
        ? `${n} ${objectsWord(n)} залишаться в базі, але без папки.`
        : 'Порожня папка буде видалена.',
      confirmLabel: 'Видалити',
      destructive: true,
    })
    if (!ok) return
    await onDelete(folder.id)
  }

  return (
    <Modal
      title="Папки"
      subtitle="Групуйте об'єкти всередині бази"
      onClose={onClose}
      // Шит без `actions` не отримує клавіатурної корекції взагалі:
      // `clearStickyActions` у Modal виходить одразу, якщо `.modal-actions` немає.
      // Саме ця модалка й була скаргою користувача, а вона — з полем вводу.
      actions={[{ label: 'Готово', variant: 'secondary', onClick: onClose }]}
    >
      <div className="fold-mng">
        {/* Рядок створення ПЕРШИЙ — див. коментар у SheetCreateRow: на iOS
            клавіатура накриває webview не ресайзячи його. Тут він, на відміну від
            пікерів, розкритий завжди і шит НЕ закриває. */}
        <SheetCreateRow
          fieldLabel="Назва нової папки"
          placeholder="Нова папка…"
          confirmLabel="Додати"
          maxLength={40}
          onCreate={async (name) => {
            const created = await onCreate(name)
            if (created) hapticNotify('success')
            return !!created
          }}
        />

        {folders.length === 0 && (
          <div className="sheet-empty">
            Ще немає папок. Введіть назву вгорі й натисніть «Додати».
          </div>
        )}
        {folders.map((f, i) => {
          const n = counts.get(f.id) ?? 0
          return (
            <div key={f.id} className="fold-mng-row">
              <span className="fold-mng-ic"><IconFolder size={16} /></span>
              {editingId === f.id ? (
                <input
                  className="fold-mng-input"
                  value={editName}
                  autoFocus
                  onChange={(e) => setEditName(e.target.value)}
                  // stopPropagation обовʼязковий: Modal слухає Escape на window
                  // і закриває верхній шит стеку, тож без цього Escape під час
                  // перейменування зносив УСЮ модалку папок замість того, щоб
                  // просто скасувати редагування рядка.
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') commitEdit()
                    if (e.key === 'Escape') { e.stopPropagation(); setEditingId(null) }
                  }}
                  maxLength={40}
                />
              ) : (
                <div className="fold-mng-mn">
                  <span className="fold-mng-name">{f.name}</span>
                  <span className="fold-mng-cnt">{n} {objectsWord(n)}</span>
                </div>
              )}
              <div className="fold-mng-act">
                {editingId === f.id ? (
                  <>
                    <button aria-label="Зберегти" onClick={commitEdit}><IconCheck size={16} /></button>
                    <button aria-label="Скасувати" onClick={() => setEditingId(null)}><IconX size={16} /></button>
                  </>
                ) : (
                  <>
                    <button aria-label="Вгору" disabled={i === 0} onClick={() => { hapticSelection(); onReorder(f.id, 'up') }}><IconChevronUp size={16} /></button>
                    <button aria-label="Вниз" disabled={i === folders.length - 1} onClick={() => { hapticSelection(); onReorder(f.id, 'down') }}><IconChevronDown size={16} /></button>
                    <button aria-label="Перейменувати" onClick={() => startEdit(f)}><IconEdit size={16} /></button>
                    <button aria-label="Видалити" className="danger" onClick={() => void askDelete(f)}><IconTrash size={16} /></button>
                  </>
                )}
              </div>
            </div>
          )
        })}
      </div>

    </Modal>
  )
}
