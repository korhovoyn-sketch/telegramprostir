'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useFolders } from '@/hooks/useFolders'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import { IconFolder, IconEdit, IconTrash, IconChevronUp, IconChevronDown, IconCheck, IconX, IconPlus } from '@/components/Icons'
import { hapticSelection, hapticNotify } from '@/lib/telegram'
import { objectsWord, scrollFocusedIntoView } from '@/lib/utils'
import { confirmAction } from '@/lib/confirm'
import type { PropertyFolder } from '@/types'

/**
 * Повноекранне керування папками — заміна колишньої `<Modal>` (фаза 4
 * переробки модалок). Клавіатура тут глобальна (`--keyboard-h` з page.tsx),
 * тож увесь клавіатурний блок `Modal.tsx` цьому екрану не потрібен у принципі.
 *
 * Поле створення — ЗВИЧАЙНИЙ рядок форми, а не `SheetCreateRow`: той ховався
 * під `collapsedLabel` саме тому, що в шиті монтування поля міняло висоту
 * шита. На екрані висота не рухається, тож ховати нема від чого.
 */
export default function FolderManageScreen() {
  const { screenParams, back } = useAppStore()
  const dbId = screenParams.dbId as string | undefined

  const { folders, loadFolders, createFolder, renameFolder, deleteFolder, reorderFolder } = useFolders(dbId)
  const { properties, loadProperties } = useProperties(dbId)

  useEffect(() => {
    loadFolders()
    loadProperties()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dbId])

  const counts = new Map<string, number>()
  for (const p of properties) {
    if (p.folder_id) counts.set(p.folder_id, (counts.get(p.folder_id) ?? 0) + 1)
  }

  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')

  async function handleCreate() {
    const name = newName.trim()
    if (!name || creating) return
    setCreating(true)
    try {
      const created = await createFolder(name)
      if (created) { hapticNotify('success'); setNewName('') }
    } finally {
      setCreating(false)
    }
  }

  function startEdit(f: PropertyFolder) {
    setEditingId(f.id)
    setEditName(f.name)
  }
  function commitEdit() {
    if (editingId && editName.trim()) renameFolder(editingId, editName)
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
    await deleteFolder(folder.id)
  }

  return (
    <div className="scr bg-blue">
      <Header title="Папки" subtitle="Групуйте об&apos;єкти бази" onBack={back} />

      <div className="body has-flow-cta" onFocusCapture={scrollFocusedIntoView}>
        <div className="fg glass-s">
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <IconPlus size={14} color="var(--t3)" />Нова
            </span>
            <input
              className="fr-i"
              aria-label="Назва нової папки"
              placeholder="Назва папки…"
              value={newName}
              maxLength={40}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void handleCreate() }}
            />
          </div>
        </div>

        <div className="fold-mng">
          {folders.length === 0 && (
            <div className="sheet-empty">
              Ще немає папок. Введіть назву вгорі й натисніть «Додати папку».
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
                    aria-label={`Нова назва папки «${f.name}»`}
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') commitEdit()
                      if (e.key === 'Escape') setEditingId(null)
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
                      <button aria-label="Вгору" disabled={i === 0} onClick={() => { hapticSelection(); reorderFolder(f.id, 'up') }}><IconChevronUp size={16} /></button>
                      <button aria-label="Вниз" disabled={i === folders.length - 1} onClick={() => { hapticSelection(); reorderFolder(f.id, 'down') }}><IconChevronDown size={16} /></button>
                      <button aria-label="Перейменувати" onClick={() => startEdit(f)}><IconEdit size={16} /></button>
                      <button aria-label="Видалити" className="danger" onClick={() => void askDelete(f)}><IconTrash size={16} /></button>
                    </>
                  )}
                </div>
              </div>
            )
          })}
        </div>

        <button
          className="mbtn mbtn-flow"
          disabled={!newName.trim() || creating}
          aria-busy={creating}
          onClick={() => void handleCreate()}
        >
          Додати папку
        </button>
      </div>
    </div>
  )
}
