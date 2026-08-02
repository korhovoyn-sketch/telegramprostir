'use client'

import { useState } from 'react'
import Modal from '@/components/ui/Modal'
import { IconFolder, IconEdit, IconTrash, IconChevronUp, IconChevronDown, IconCheck, IconX, IconPlus } from '@/components/Icons'
import { hapticSelection } from '@/lib/telegram'
import { objectsWord } from '@/lib/utils'
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
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)
  // Видалення непорожньої папки лише ungroup-ає об'єкти — але це варто підтвердити.
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)

  function startEdit(f: PropertyFolder) {
    setEditingId(f.id)
    setEditName(f.name)
  }
  function commitEdit() {
    if (editingId && editName.trim()) onRename(editingId, editName)
    setEditingId(null)
  }
  async function handleCreate() {
    const name = newName.trim()
    if (!name || creating) return
    setCreating(true)
    const created = await onCreate(name)
    setCreating(false)
    if (created) setNewName('')
  }

  return (
    <Modal title="Папки" subtitle="Групуйте об'єкти всередині бази" onClose={onClose}>
      <div className="fold-mng">
        {/* Create row FIRST — on iOS Telegram the keyboard overlays the webview
            without resizing it (--keyboard-h reads 0), so a bottom-anchored input
            would be hidden. Kept near the header, it stays in the visible upper
            band above the keyboard. */}
        <div className="fold-mng-new">
          <span className="fold-mng-ic"><IconPlus size={16} /></span>
          <input
            className="fold-mng-input"
            value={newName}
            placeholder="Нова папка…"
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleCreate() }}
            maxLength={40}
          />
          <button className="fold-mng-add" disabled={!newName.trim() || creating} onClick={handleCreate}>Додати</button>
        </div>

        {folders.length === 0 && (
          <div style={{ padding: '20px 4px', textAlign: 'center', color: 'var(--t3)', fontSize: 'var(--fs-foot)' }}>
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
                  onKeyDown={(e) => { if (e.key === 'Enter') commitEdit(); if (e.key === 'Escape') setEditingId(null) }}
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
                    <button aria-label="Вгору" disabled={i === 0} onClick={() => { hapticSelection(); onReorder(f.id, 'up') }}><IconChevronUp size={15} /></button>
                    <button aria-label="Вниз" disabled={i === folders.length - 1} onClick={() => { hapticSelection(); onReorder(f.id, 'down') }}><IconChevronDown size={15} /></button>
                    <button aria-label="Перейменувати" onClick={() => startEdit(f)}><IconEdit size={15} /></button>
                    <button aria-label="Видалити" className="danger" onClick={() => setConfirmDeleteId(f.id)}><IconTrash size={15} /></button>
                  </>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {confirmDeleteId && (
        <Modal
          title="Видалити папку?"
          subtitle={
            (counts.get(confirmDeleteId) ?? 0) > 0
              ? `${counts.get(confirmDeleteId)} ${objectsWord(counts.get(confirmDeleteId) ?? 0)} залишаться в базі, але без папки.`
              : 'Порожня папка буде видалена.'
          }
          onClose={() => setConfirmDeleteId(null)}
          actions={[
            { label: 'Видалити', variant: 'danger', onClick: async () => { const id = confirmDeleteId; setConfirmDeleteId(null); await onDelete(id) } },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setConfirmDeleteId(null) },
          ]}
        />
      )}
    </Modal>
  )
}
